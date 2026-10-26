//! XHTTP packet-up session lifetime, end to end: our own client box (mixed
//! inbound -> vless over xhttp) against our own server box (vless over xhttp
//! -> direct), both in this process.
//!
//! Packet-up has no "upload finished" signal on the wire, so a local client
//! that closes its socket never reaches the upstream as a FIN. These tests
//! check that such a session still ends -- through the half-close idle limit
//! on the client and the cancelled download on the server -- while a client
//! that half-closes and then reads still gets the whole response.
//!
//! What is measured is the open fd count of this process (both boxes and the
//! test upstreams live here) and the live connection count of the upstreams,
//! not RSS.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

/// The half-close idle limit these tests run with, in milliseconds. The
/// production default is longer; the knob is read once per process.
const IDLE_MS: u64 = 1000;

/// Tests in this binary count the fds of the whole process, so they run one
/// at a time.
async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    static ENV: std::sync::Once = std::sync::Once::new();
    ENV.call_once(|| {
        // SAFETY: set once, before any box of this binary is started; every
        // test takes this guard first.
        unsafe {
            std::env::set_var("XRUST_XHTTP_HALF_CLOSE_IDLE_MS", IDLE_MS.to_string());
        }
    });
    LOCK.lock().await
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd")
        .map(|dir| dir.count())
        .unwrap_or(0)
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("port")
        .local_addr()
        .expect("addr")
        .port()
}

fn inbound_addr(instance: &core_runtime::BoxInstance, tag: &str) -> SocketAddr {
    instance
        .inbound_addrs()
        .iter()
        .find(|(t, _)| t == tag)
        .map(|(_, a)| *a)
        .unwrap_or_else(|| panic!("no inbound {tag}"))
}

fn cert_file(name: &str) -> String {
    format!(
        "{}/../../tests/golden/certs/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

#[derive(Clone, Copy, Debug)]
enum Http {
    H1,
    H2,
}

struct Stand {
    client: core_runtime::BoxInstance,
    server: core_runtime::BoxInstance,
    socks: SocketAddr,
}

/// A server box and a client box speaking vless over xhttp `mode` to each
/// other, plain HTTP/1.1 or HTTP/2 over TLS.
async fn stand(mode: &str, http: Http) -> Stand {
    let mut server_in = json!({
        "type": "vless",
        "tag": "vless-in",
        "listen": "127.0.0.1",
        "listen_port": free_port(),
        "users": [{"name": "alice", "uuid": UUID}],
        "transport": {"type": "xhttp", "path": "/bench"}
    });
    let mut client_out = json!({
        "type": "vless",
        "tag": "out",
        "uuid": UUID,
        "transport": {"type": "xhttp", "path": "/bench", "mode": mode}
    });
    if let Http::H2 = http {
        server_in["tls"] = json!({
            "enabled": true,
            "certificate_path": cert_file("localhost.crt"),
            "key_path": cert_file("localhost.key"),
            "alpn": ["h2"]
        });
        client_out["tls"] = json!({
            "enabled": true,
            "server_name": "localhost",
            "insecure": true,
            "alpn": ["h2"]
        });
    }
    let server = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [server_in],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .expect("start server");
    let server_addr = inbound_addr(&server, "vless-in");
    client_out["server"] = json!("127.0.0.1");
    client_out["server_port"] = json!(server_addr.port());
    let client = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": free_port()
        }],
        "outbounds": [client_out],
        "route": {"final": "out"}
    }))
    .await
    .expect("start client");
    let socks = inbound_addr(&client, "mixed-in");
    Stand {
        client,
        server,
        socks,
    }
}

/// A SOCKS5 CONNECT through the client box.
async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let (stream, code) = socks_request(socks, target).await?;
    assert_eq!(code, 0x00, "socks connect refused: {code}");
    Ok(stream)
}

/// The SOCKS5 CONNECT and its reply code, refused or not.
async fn socks_request(socks: SocketAddr, target: SocketAddr) -> std::io::Result<(TcpStream, u8)> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    assert_eq!(greeting, [0x05, 0x00], "socks greeting");
    let mut request = vec![0x05, 0x01, 0x00, 1];
    match target.ip() {
        IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        IpAddr::V6(_) => panic!("v4 target"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    Ok((stream, reply[1]))
}

/// Live connections of one test upstream.
#[derive(Clone, Default)]
struct Live(Arc<AtomicUsize>);

impl Live {
    fn get(&self) -> usize {
        self.0.load(Ordering::SeqCst)
    }
}

struct LiveGuard(Live);

impl LiveGuard {
    fn new(live: &Live) -> Self {
        live.0.fetch_add(1, Ordering::SeqCst);
        Self(live.clone())
    }
}

impl Drop for LiveGuard {
    fn drop(&mut self) {
        self.0.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// An echo that, like most servers, closes once it reads EOF. Over packet-up
/// that EOF never arrives, which is the leak this file is about.
async fn spawn_echo() -> (SocketAddr, Live) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    let live = Live::default();
    let counted = live.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let guard = LiveGuard::new(&counted);
            tokio::spawn(async move {
                let _guard = guard;
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, live)
}

/// A request/response server: it reads one request line, and only then --
/// after the client may already have half-closed -- answers in `parts`
/// pieces `gap` apart, then closes.
async fn spawn_slow_responder(parts: usize, gap: Duration) -> (SocketAddr, Live) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let live = Live::default();
    let counted = live.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let guard = LiveGuard::new(&counted);
            tokio::spawn(async move {
                let _guard = guard;
                let mut line = Vec::new();
                let mut byte = [0u8; 1];
                while !line.ends_with(b"\n") {
                    match stream.read(&mut byte).await {
                        Ok(0) | Err(_) => return,
                        Ok(_) => line.push(byte[0]),
                    }
                }
                for i in 0..parts {
                    tokio::time::sleep(gap).await;
                    let part = format!("part-{i};");
                    if stream.write_all(part.as_bytes()).await.is_err() {
                        return;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    (addr, live)
}

/// A server that takes a request and then never says anything and never
/// closes on its own -- not even on EOF. Only the proxy dropping its side
/// (a write would fail then) ends it, so its sockets are held for the test.
async fn spawn_silent_sink() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                while let Ok(n) = stream.read(&mut buf).await
                    && n > 0
                {}
                // hold the socket, EOF or not
                std::future::pending::<()>().await;
                drop(stream);
            });
        }
    });
    addr
}

/// Poll `probe` until it holds or `within` passes; the last value either way.
async fn settle(within: Duration, mut probe: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if probe() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// How long a closed session may take to go away: the idle limit plus room.
fn release_window() -> Duration {
    Duration::from_millis(IDLE_MS) + Duration::from_secs(4)
}

/// Pooled upload connections may stay parked on both boxes after the
/// sessions end; that is bounded and is not what is measured here.
const FD_SLACK: usize = 12;

async fn closed_clients_leave_nothing_behind(mode: &str, http: Http, rounds: usize) {
    let (echo, live) = spawn_echo().await;
    let stand = stand(mode, http).await;
    // one warm-up session so lazily created pieces (pools, h2 connection)
    // are part of the baseline
    {
        let mut s = socks_connect(stand.socks, echo).await.expect("connect");
        s.write_all(b"warm-up").await.unwrap();
        let mut got = [0u8; 7];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
            .await
            .expect("warm-up echo timed out")
            .unwrap();
    }
    // the warm-up must not be counted as a leak of its own: wait for it,
    // but on a build that leaks it simply stays part of the baseline
    let _ = settle(release_window(), || live.get() == 0).await;
    let base = open_fds();
    let base_live = live.get();

    let mut failed = Vec::new();
    for i in 0..rounds {
        let payload = format!("round-{i}");
        let round = async {
            let (mut s, code) = socks_request(stand.socks, echo).await.ok()?;
            if code != 0x00 {
                return None;
            }
            s.write_all(payload.as_bytes()).await.ok()?;
            let mut got = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(3), s.read_exact(&mut got))
                .await
                .ok()?
                .ok()?;
            // the client is done and closes, the way a browser drops a
            // keep-alive connection
            Some(got)
        };
        if round.await.as_deref() != Some(payload.as_bytes()) {
            failed.push(i);
        }
    }
    let peak = open_fds();
    let peak_live = live.get();

    let released = settle(release_window(), || {
        live.get() <= base_live && open_fds() <= base + FD_SLACK
    })
    .await;
    let after = open_fds();
    eprintln!(
        "{mode} {http:?}: {rounds} closed sessions ({} failed): fds base={base} peak={peak} \
         after={after}, upstream live peak={peak_live} after={}",
        failed.len(),
        live.get()
    );
    assert!(
        failed.is_empty(),
        "{mode} {http:?}: rounds {failed:?} of {rounds} got no echo"
    );
    assert!(
        released,
        "{mode} {http:?}: closed sessions linger: fds base={base} after={after} \
         upstream still live={}",
        live.get()
    );
    drop(stand.client);
    drop(stand.server);
}

/// Many short sessions, each closed by the client: none may linger, and the
/// upstream must see every one of them end. (CN-02 / MEM-01.)
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_packet_up_sessions_leave_no_fds_or_upstreams_h1() {
    let _guard = test_guard().await;
    closed_clients_leave_nothing_behind("packet-up", Http::H1, 40).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_packet_up_sessions_leave_no_fds_or_upstreams_h2() {
    let _guard = test_guard().await;
    closed_clients_leave_nothing_behind("packet-up", Http::H2, 40).await;
}

/// `auto` is packet-up here, and it is the default a subscription brings.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closed_auto_sessions_leave_no_fds_or_upstreams() {
    let _guard = test_guard().await;
    closed_clients_leave_nothing_behind("auto", Http::H1, 20).await;
}

/// A client that sends its request, half-closes, and only then reads gets
/// the whole response -- even one that starts after the half-close and takes
/// longer in total than the idle limit, as long as it keeps moving.
async fn half_close_then_read(http: Http) {
    let gap = Duration::from_millis(IDLE_MS * 2 / 5);
    let parts = 6; // 6 * 0.4 * idle: longer than the idle limit in total
    let (target, live) = spawn_slow_responder(parts, gap).await;
    let stand = stand("packet-up", http).await;
    let base = open_fds();

    let mut s = socks_connect(stand.socks, target).await.expect("connect");
    s.write_all(b"GET /thing\n").await.unwrap();
    s.shutdown().await.expect("half-close");
    let mut got = Vec::new();
    tokio::time::timeout(Duration::from_secs(15), s.read_to_end(&mut got))
        .await
        .expect("the response never ended")
        .expect("read after half-close");
    let want: String = (0..parts).map(|i| format!("part-{i};")).collect();
    assert_eq!(String::from_utf8_lossy(&got), want, "{http:?}");
    drop(s);

    let released = settle(release_window(), || {
        live.get() == 0 && open_fds() <= base + FD_SLACK
    })
    .await;
    assert!(
        released,
        "{http:?}: a completed session lingers: fds base={base} now={}",
        open_fds()
    );
    drop(stand.client);
    drop(stand.server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_closed_packet_up_client_still_gets_the_whole_response_h1() {
    let _guard = test_guard().await;
    half_close_then_read(Http::H1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_closed_packet_up_client_still_gets_the_whole_response_h2() {
    let _guard = test_guard().await;
    half_close_then_read(Http::H2).await;
}

/// The client goes away hard (RST): the client box drops the session at
/// once, and the server box has to notice the cancelled download and let go
/// of its upstream too, even one that never closes by itself.
async fn client_reset_frees_both_sides(http: Http) {
    let sink = spawn_silent_sink().await;
    let stand = stand("packet-up", http).await;
    let rounds = 30;
    let base = open_fds();
    for i in 0..rounds {
        let mut s = socks_connect(stand.socks, sink).await.expect("connect");
        s.write_all(format!("request-{i}\n").as_bytes())
            .await
            .unwrap();
        // let the request reach the sink before pulling the plug
        tokio::time::sleep(Duration::from_millis(50)).await;
        let std = s.into_std().unwrap();
        socket2::SockRef::from(&std)
            .set_linger(Some(Duration::ZERO))
            .unwrap();
        drop(std);
    }
    let peak = open_fds();
    // the sink holds its own end of each upstream connection by design: one
    // fd per round is expected to stay
    let expected = base + rounds + FD_SLACK;
    let released = settle(release_window(), || open_fds() <= expected).await;
    let after = open_fds();
    eprintln!(
        "{http:?}: {rounds} reset sessions to a silent upstream: fds base={base} peak={peak} \
         after={after} (sink keeps {rounds})"
    );
    assert!(
        released,
        "{http:?}: reset sessions linger: fds base={base} after={after}, allowed {expected}"
    );
    drop(stand.client);
    drop(stand.server);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_reset_frees_the_session_on_both_sides_h1() {
    let _guard = test_guard().await;
    client_reset_frees_both_sides(Http::H1).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn client_reset_frees_the_session_on_both_sides_h2() {
    let _guard = test_guard().await;
    client_reset_frees_both_sides(Http::H2).await;
}

/// What a fake XHTTP server does wrong once the session is up.
#[derive(Clone, Copy, Debug)]
enum Fault {
    /// Every upload after the request head is answered with a 500, while
    /// the download stays open and silent.
    RefuseUploads,
    /// The download connection is dropped shortly after its 200.
    DropDownload,
}

/// A bare HTTP/1.1 XHTTP server for `fault`. Returns its address and the
/// number of download connections it still holds open.
async fn spawn_faulty_server(fault: Fault) -> (SocketAddr, Live) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let live = Live::default();
    let downloads = live.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let downloads = downloads.clone();
            tokio::spawn(async move {
                let mut pending = Vec::new();
                loop {
                    let Some(head) = read_head(&mut stream, &mut pending).await else {
                        return;
                    };
                    let line = head.lines().next().unwrap_or("").to_string();
                    if line.starts_with("GET ") {
                        let _guard = LiveGuard::new(&downloads);
                        if stream.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
                            return;
                        }
                        match fault {
                            Fault::DropDownload => {
                                tokio::time::sleep(Duration::from_millis(300)).await;
                                return;
                            }
                            Fault::RefuseUploads => {
                                // silent until the client goes away
                                let mut buf = [0u8; 64];
                                while let Ok(n) = stream.read(&mut buf).await
                                    && n > 0
                                {}
                                return;
                            }
                        }
                    }
                    let len = head
                        .lines()
                        .find_map(|l| {
                            let (k, v) = l.split_once(':')?;
                            k.trim()
                                .eq_ignore_ascii_case("content-length")
                                .then(|| v.trim().parse::<usize>().ok())?
                        })
                        .unwrap_or(0);
                    while pending.len() < len {
                        let mut buf = [0u8; 4096];
                        match stream.read(&mut buf).await {
                            Ok(0) | Err(_) => return,
                            Ok(n) => pending.extend_from_slice(&buf[..n]),
                        }
                    }
                    pending.drain(..len);
                    let path = line.split(' ').nth(1).unwrap_or("");
                    let head_packet = path.ends_with("/0");
                    let refuse = matches!(fault, Fault::RefuseUploads) && !head_packet;
                    let answer: &[u8] = if refuse {
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    } else {
                        b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"
                    };
                    if stream.write_all(answer).await.is_err() || refuse {
                        return;
                    }
                }
            });
        }
    });
    (addr, live)
}

/// One request head off `stream`, with whatever followed it left in `pending`.
async fn read_head(stream: &mut TcpStream, pending: &mut Vec<u8>) -> Option<String> {
    loop {
        if let Some(end) = pending.windows(4).position(|w| w == b"\r\n\r\n") {
            let head = String::from_utf8_lossy(&pending[..end]).into_owned();
            pending.drain(..end + 4);
            return Some(head);
        }
        let mut buf = [0u8; 4096];
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => pending.extend_from_slice(&buf[..n]),
        }
    }
}

/// The server fails the session while the client waits for a response: the
/// client connection has to end, and the download has to be let go of.
async fn server_fault_ends_the_session(fault: Fault) {
    let (server, downloads) = spawn_faulty_server(fault).await;
    let client = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
            "listen_port": free_port()}],
        "outbounds": [{"type": "vless", "tag": "out", "uuid": UUID,
            "server": "127.0.0.1", "server_port": server.port(),
            "transport": {"type": "xhttp", "path": "/bench", "mode": "packet-up"}}],
        "route": {"final": "out"}
    }))
    .await
    .expect("start client");
    let socks = inbound_addr(&client, "mixed-in");
    // any address will do: the fake server never dials it
    let target: SocketAddr = "127.0.0.1:9".parse().unwrap();
    let base = open_fds();
    let mut s = socks_connect(socks, target).await.expect("connect");
    s.write_all(b"request\n").await.unwrap();
    let mut buf = [0u8; 64];
    let end = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
        .await
        .unwrap_or_else(|_| panic!("{fault:?}: the client connection outlived the failed session"));
    assert!(
        matches!(end, Ok(0) | Err(_)),
        "{fault:?}: unexpected data: {end:?}"
    );
    drop(s);
    let released = settle(release_window(), || {
        downloads.get() == 0 && open_fds() <= base + FD_SLACK
    })
    .await;
    assert!(
        released,
        "{fault:?}: the failed session lingers: downloads open={} fds base={base} now={}",
        downloads.get(),
        open_fds()
    );
    drop(client);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_upload_ends_the_session() {
    let _guard = test_guard().await;
    server_fault_ends_the_session(Fault::RefuseUploads).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropped_download_ends_the_session() {
    let _guard = test_guard().await;
    server_fault_ends_the_session(Fault::DropDownload).await;
}

/// The server refuses the session (wrong path): the client connection ends
/// promptly and leaves nothing behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn refused_session_ends_and_releases() {
    let _guard = test_guard().await;
    let (echo, _live) = spawn_echo().await;
    let server = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "vless", "tag": "vless-in", "listen": "127.0.0.1",
            "listen_port": free_port(),
            "users": [{"name": "alice", "uuid": UUID}],
            "transport": {"type": "xhttp", "path": "/bench"}
        }],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .expect("start server");
    let port = inbound_addr(&server, "vless-in").port();
    let client: Value = json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1",
            "listen_port": free_port()}],
        "outbounds": [{"type": "vless", "tag": "out", "uuid": UUID,
            "server": "127.0.0.1", "server_port": port,
            "transport": {"type": "xhttp", "path": "/other", "mode": "packet-up"}}],
        "route": {"final": "out"}
    });
    let client = core_runtime::start(&client).await.expect("start client");
    let socks = inbound_addr(&client, "mixed-in");
    let base = open_fds();
    for _ in 0..10 {
        let Ok((mut s, code)) = socks_request(socks, echo).await else {
            continue;
        };
        if code != 0x00 {
            // refused while connecting: the session never started
            continue;
        }
        let _ = s.write_all(b"hello").await;
        let mut buf = [0u8; 64];
        let end = tokio::time::timeout(Duration::from_secs(5), s.read(&mut buf))
            .await
            .expect("a refused session must end");
        assert!(matches!(end, Ok(0) | Err(_)), "got data: {end:?}");
    }
    assert!(
        settle(release_window(), || open_fds() <= base + FD_SLACK).await,
        "refused sessions linger: fds base={base} now={}",
        open_fds()
    );
    drop(client);
    drop(server);
}
