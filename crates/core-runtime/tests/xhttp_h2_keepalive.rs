//! XHTTP over HTTP/2: liveness of pooled connections, end to end. Our own
//! client box (mixed inbound -> vless over xhttp, TLS + h2) talks to our own
//! server box through a TCP relay in this process. The relay can go silent
//! on a connection (stops forwarding both ways, keeps the sockets open), the
//! way a NAT timeout or a server reboot without RST looks to the client, or
//! reset it.
//!
//! The keep-alive period is shortened through `xmux.h_keep_alive_period`;
//! the PING timeout is the production one.

use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

/// Keep-alive period the tests run with, seconds.
const PERIOD_SECS: u64 = 1;

/// PING timeout of the client (same as Xray's HTTP/2 default).
const PING_TIMEOUT: Duration = Duration::from_secs(15);

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

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Link {
    Run,
    Silent,
    Reset,
}

/// A TCP relay in front of the server box. Every accepted connection gets
/// its own control, so silencing the current ones leaves new ones working.
#[derive(Clone, Default)]
struct Relay {
    links: Arc<Mutex<Vec<watch::Sender<Link>>>>,
    accepted: Arc<AtomicUsize>,
    /// bytes forwarded client -> server
    up_bytes: Arc<AtomicU64>,
}

impl Relay {
    async fn spawn(target: SocketAddr) -> (Self, SocketAddr) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind relay");
        let addr = listener.local_addr().expect("relay addr");
        let relay = Self::default();
        let this = relay.clone();
        tokio::spawn(async move {
            while let Ok((client, _)) = listener.accept().await {
                let Ok(server) = TcpStream::connect(target).await else {
                    continue;
                };
                this.accepted.fetch_add(1, Ordering::SeqCst);
                let (tx, rx) = watch::channel(Link::Run);
                this.links.lock().unwrap().push(tx);
                tokio::spawn(pump(client, server, rx, this.up_bytes.clone()));
            }
        });
        (relay, addr)
    }

    fn set_all(&self, state: Link) {
        for link in self.links.lock().unwrap().iter() {
            let _ = link.send(state);
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::SeqCst)
    }

    fn up_bytes(&self) -> u64 {
        self.up_bytes.load(Ordering::SeqCst)
    }
}

async fn pump(
    mut client: TcpStream,
    mut server: TcpStream,
    mut rx: watch::Receiver<Link>,
    up_bytes: Arc<AtomicU64>,
) {
    let mut up = vec![0u8; 16 * 1024];
    let mut down = vec![0u8; 16 * 1024];
    loop {
        let state = *rx.borrow_and_update();
        match state {
            Link::Run => {}
            Link::Silent => {
                // hold both sockets and read nothing, until told otherwise
                if rx.changed().await.is_err() {
                    std::future::pending::<()>().await;
                }
                continue;
            }
            Link::Reset => {
                // drop with SO_LINGER 0: an RST both ways
                let _ = socket2::SockRef::from(&client).set_linger(Some(Duration::ZERO));
                let _ = socket2::SockRef::from(&server).set_linger(Some(Duration::ZERO));
                return;
            }
        }
        tokio::select! {
            changed = rx.changed() => {
                if changed.is_err() {
                    return;
                }
            }
            read = client.read(&mut up) => match read {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    up_bytes.fetch_add(n as u64, Ordering::SeqCst);
                    if server.write_all(&up[..n]).await.is_err() {
                        return;
                    }
                }
            },
            read = server.read(&mut down) => match read {
                Ok(0) | Err(_) => return,
                Ok(n) => {
                    if client.write_all(&down[..n]).await.is_err() {
                        return;
                    }
                }
            },
        }
    }
}

struct Stand {
    _client: core_runtime::BoxInstance,
    _server: core_runtime::BoxInstance,
    socks: SocketAddr,
    relay: Relay,
}

/// Server box <- relay <- client box, vless over xhttp `mode`, TLS + h2.
async fn stand(mode: &str, xmux: Value) -> Stand {
    static ENV: std::sync::Once = std::sync::Once::new();
    ENV.call_once(|| {
        // closed packet-up sessions end quickly, so idle means idle
        // SAFETY: set once, before any box of this binary is started
        unsafe {
            std::env::set_var("TACHYON_XHTTP_HALF_CLOSE_IDLE_MS", "500");
        }
    });
    let server_in = json!({
        "type": "vless",
        "tag": "vless-in",
        "listen": "127.0.0.1",
        "listen_port": free_port(),
        "users": [{"name": "alice", "uuid": UUID}],
        "transport": {"type": "xhttp", "path": "/ka"},
        "tls": {
            "enabled": true,
            "certificate_path": cert_file("localhost.crt"),
            "key_path": cert_file("localhost.key"),
            "alpn": ["h2"]
        }
    });
    let server = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [server_in],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .expect("start server");
    let (relay, relay_addr) = Relay::spawn(inbound_addr(&server, "vless-in")).await;
    let client_out = json!({
        "type": "vless",
        "tag": "out",
        "uuid": UUID,
        "server": "127.0.0.1",
        "server_port": relay_addr.port(),
        "transport": {"type": "xhttp", "path": "/ka", "mode": mode, "xmux": xmux},
        "tls": {
            "enabled": true,
            "server_name": "localhost",
            "insecure": true,
            "alpn": ["h2"]
        }
    });
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
        _client: client,
        _server: server,
        socks,
        relay,
    }
}

fn keepalive_xmux() -> Value {
    json!({"max_connections": 1, "h_keep_alive_period": PERIOD_SECS})
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(socks).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    let mut request = vec![0x05, 0x01, 0x00, 1];
    match target.ip() {
        IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        IpAddr::V6(_) => panic!("v4 target"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await?;
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await?;
    if reply[1] != 0 {
        return Err(std::io::Error::other(format!("socks reply {}", reply[1])));
    }
    Ok(stream)
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
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
    addr
}

/// One echo round trip through the client box within `within`.
async fn echo_once(socks: SocketAddr, echo: SocketAddr, within: Duration) -> Result<(), String> {
    let run = async {
        let mut s = socks_connect(socks, echo)
            .await
            .map_err(|e| format!("connect: {e}"))?;
        s.write_all(b"ping-through")
            .await
            .map_err(|e| format!("write: {e}"))?;
        let mut got = [0u8; 12];
        s.read_exact(&mut got)
            .await
            .map_err(|e| format!("read: {e}"))?;
        if &got != b"ping-through" {
            return Err("echo mismatch".to_string());
        }
        Ok(())
    };
    match tokio::time::timeout(within, run).await {
        Ok(result) => result,
        Err(_) => Err(format!("timed out after {within:?}")),
    }
}

/// Sessions after the link went silent: the first one is expected to wait
/// out at most one detection window, the rest must be prompt.
async fn recovers_after_silent_loss(mode: &str) {
    let echo = spawn_echo().await;
    let stand = stand(mode, keepalive_xmux()).await;
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("first session");
    assert_eq!(stand.relay.accepted(), 1);

    stand.relay.set_all(Link::Silent);
    let lost = Instant::now();
    // detection needs one idle period plus the PING timeout
    let window = Duration::from_secs(PERIOD_SECS) + PING_TIMEOUT + Duration::from_secs(3);
    let mut attempts = Vec::new();
    let mut recovered = None;
    while lost.elapsed() < window + Duration::from_secs(10) {
        let started = Instant::now();
        let result = echo_once(stand.socks, echo, Duration::from_secs(5)).await;
        attempts.push(format!(
            "t={:.1}s {:?} conns={}",
            lost.elapsed().as_secs_f64(),
            result,
            stand.relay.accepted()
        ));
        if result.is_ok() {
            recovered = Some(lost.elapsed());
            break;
        }
        if started.elapsed() < Duration::from_secs(1) {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }
    let recovered = recovered
        .unwrap_or_else(|| panic!("no session succeeded after silent loss: {attempts:#?}"));
    assert!(
        recovered <= window,
        "recovered only after {recovered:?}: {attempts:#?}"
    );
    assert_eq!(
        stand.relay.accepted(),
        2,
        "the dead connection was replaced: {attempts:#?}"
    );
    // and the new connection keeps serving
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("session after recovery");
    eprintln!("{mode}: recovered after {recovered:?}; {attempts:#?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_pooled_connection_is_evicted_packet_up() {
    recovers_after_silent_loss("packet-up").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_pooled_connection_is_evicted_stream_one() {
    recovers_after_silent_loss("stream-one").await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_pooled_connection_is_evicted_with_default_xmux() {
    // no h_keep_alive_period: the 45 s default applies, so only check that
    // the pool does not hand the dead connection out forever within the
    // default window (45 s + 15 s)
    let echo = spawn_echo().await;
    let stand = stand("packet-up", json!({"max_connections": 1})).await;
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("first session");
    stand.relay.set_all(Link::Silent);
    tokio::time::sleep(Duration::from_secs(45) + PING_TIMEOUT + Duration::from_secs(3)).await;
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("session after the default detection window");
    assert_eq!(stand.relay.accepted(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reset_pooled_connection_is_replaced() {
    let echo = spawn_echo().await;
    let stand = stand("packet-up", keepalive_xmux()).await;
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("first session");
    stand.relay.set_all(Link::Reset);
    tokio::time::sleep(Duration::from_millis(300)).await;
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("session after reset");
    assert_eq!(stand.relay.accepted(), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn healthy_idle_connection_is_pinged_and_reused() {
    let echo = spawn_echo().await;
    let stand = stand("packet-up", keepalive_xmux()).await;
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("first session");
    // let the session wind down, then measure idle traffic
    tokio::time::sleep(Duration::from_secs(3)).await;
    let before = stand.relay.up_bytes();
    // longer than period + PING timeout: a broken liveness check would have
    // dropped the connection by now
    tokio::time::sleep(Duration::from_secs(PERIOD_SECS) + PING_TIMEOUT + Duration::from_secs(2))
        .await;
    let pinged = stand.relay.up_bytes() - before;
    assert!(pinged > 0, "no keep-alive traffic while idle");
    echo_once(stand.socks, echo, Duration::from_secs(5))
        .await
        .expect("session on the idle connection");
    assert_eq!(
        stand.relay.accepted(),
        1,
        "idle healthy connection was kept"
    );
}

/// A server that answers one byte every `gap`, `parts` times.
async fn spawn_trickle(parts: usize, gap: Duration) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut first = [0u8; 1];
                if stream.read_exact(&mut first).await.is_err() {
                    return;
                }
                for _ in 0..parts {
                    tokio::time::sleep(gap).await;
                    if stream.write_all(b"x").await.is_err() {
                        return;
                    }
                }
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn slow_transfer_outlives_the_ping_timeout() {
    // gaps longer than the keep-alive period, for longer than period + PING
    // timeout in total: PINGs go out in between and must not cut the session
    let parts = 8;
    let gap = Duration::from_millis(2500);
    let trickle = spawn_trickle(parts, gap).await;
    let stand = stand("packet-up", keepalive_xmux()).await;
    let mut s = socks_connect(stand.socks, trickle).await.expect("connect");
    s.write_all(b"go").await.unwrap();
    let mut got = Vec::new();
    let read = tokio::time::timeout(gap * (parts as u32 + 4), s.read_to_end(&mut got)).await;
    assert!(
        read.is_ok(),
        "slow transfer stalled after {} bytes",
        got.len()
    );
    assert_eq!(got.len(), parts, "slow transfer cut short");
    assert_eq!(stand.relay.accepted(), 1);
}
