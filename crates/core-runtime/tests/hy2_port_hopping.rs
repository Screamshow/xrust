//! hysteria2 `server_ports`: startup without `server_port`, and port hopping
//! on one QUIC connection. A loopback front stands in for the server's
//! port-range DNAT: every front port forwards to one hy2 inbound, keyed by
//! the client's source address.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use core_runtime::inbound::Target;
use core_runtime::outbound::hysteria2::Hysteria2;
use core_runtime::route::Router;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");
const PASSWORD: &str = "hop-pass";

// fd counts are process wide, so the tests take turns
static SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Our fds minus the hy2 server's own UDP sessions to `udp_echo`: those
/// belong to the inbound and live until its UDP timeout.
fn client_fd_count(udp_echo: SocketAddr) -> usize {
    let peer = format!("0100007F:{:04X}", udp_echo.port());
    let table = std::fs::read_to_string("/proc/self/net/udp").unwrap_or_default();
    let server_side: std::collections::HashSet<String> = table
        .lines()
        .filter_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            (f.len() > 9 && f[2] == peer).then(|| format!("socket:[{}]", f[9]))
        })
        .collect();
    fds().values().filter(|t| !server_side.contains(*t)).count()
}

/// Open fds with what they point at, for failure messages.
fn fds() -> std::collections::BTreeMap<u32, String> {
    std::fs::read_dir("/proc/self/fd")
        .map(|d| {
            d.filter_map(Result::ok)
                .filter_map(|e| {
                    let fd = e.file_name().to_str()?.parse().ok()?;
                    let to = std::fs::read_link(e.path()).ok()?;
                    Some((fd, to.display().to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

async fn spawn_server() -> SocketAddr {
    let router =
        Router::new(&json!({"outbounds": [{"type": "direct", "tag": "direct"}]})).expect("router");
    let cfg = json!({
        "type": "hysteria2", "tag": "hy2-in", "listen": "127.0.0.1", "listen_port": 0,
        "users": [{"name": "u", "password": PASSWORD}],
        "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
    });
    let server = core_runtime::inbound::hysteria2::Hysteria2::bind(&cfg, router)
        .await
        .expect("bind hy2 inbound");
    let addr = server.local_addr().expect("server addr");
    tokio::spawn(server.serve());
    addr
}

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut s, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 64 * 1024];
                loop {
                    match s.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if s.write_all(&buf[..n]).await.is_err() {
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

async fn spawn_udp_echo() -> SocketAddr {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = sock.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65_535];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let _ = sock.send_to(&buf[..n], from).await;
        }
    });
    addr
}

/// Port-range front: several UDP ports, all forwarded to one server.
struct Front {
    ports: Vec<u16>,
    socks: Arc<Mutex<HashMap<u16, Arc<UdpSocket>>>>,
    recv_tasks: Mutex<HashMap<u16, tokio::task::JoinHandle<()>>>,
    /// packets received per front port
    hits: Arc<Mutex<HashMap<u16, u64>>>,
    /// last front port the client used
    current: Arc<AtomicU16>,
    /// distinct client source addresses (one per client QUIC socket)
    mappings: Arc<AtomicUsize>,
    tasks: Arc<Mutex<Vec<tokio::task::JoinHandle<()>>>>,
}

type Mapping = (Arc<UdpSocket>, Arc<AtomicU16>);

impl Front {
    async fn spawn(server: SocketAddr, n: usize) -> Arc<Self> {
        let mut socks = HashMap::new();
        let mut ports = Vec::new();
        for _ in 0..n {
            let s = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("bind front"));
            let port = s.local_addr().expect("front addr").port();
            ports.push(port);
            socks.insert(port, s);
        }
        let front = Arc::new(Self {
            ports: ports.clone(),
            socks: Arc::new(Mutex::new(socks)),
            recv_tasks: Mutex::new(HashMap::new()),
            hits: Arc::new(Mutex::new(HashMap::new())),
            current: Arc::new(AtomicU16::new(0)),
            mappings: Arc::new(AtomicUsize::new(0)),
            tasks: Arc::new(Mutex::new(Vec::new())),
        });
        let clients: Arc<Mutex<HashMap<SocketAddr, Mapping>>> =
            Arc::new(Mutex::new(HashMap::new()));
        for port in ports {
            let sock = Arc::clone(front.socks.lock().unwrap().get(&port).unwrap());
            let f = Arc::clone(&front);
            let clients = Arc::clone(&clients);
            let task = tokio::spawn(async move {
                let mut buf = vec![0u8; 65_535];
                while let Ok((n, client)) = sock.recv_from(&mut buf).await {
                    *f.hits.lock().unwrap().entry(port).or_default() += 1;
                    f.current.store(port, Ordering::Relaxed);
                    let existing = clients.lock().unwrap().get(&client).cloned();
                    let (up, last) = match existing {
                        Some(m) => m,
                        None => {
                            let up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                            up.connect(server).await.unwrap();
                            let last = Arc::new(AtomicU16::new(port));
                            clients
                                .lock()
                                .unwrap()
                                .insert(client, (Arc::clone(&up), Arc::clone(&last)));
                            f.mappings.fetch_add(1, Ordering::Relaxed);
                            let socks = Arc::clone(&f.socks);
                            let (up_r, last_r) = (Arc::clone(&up), Arc::clone(&last));
                            let back = tokio::spawn(async move {
                                let mut buf = vec![0u8; 65_535];
                                while let Ok(n) = up_r.recv(&mut buf).await {
                                    // reply from the port the client last used, or any live one
                                    let out = {
                                        let socks = socks.lock().unwrap();
                                        socks
                                            .get(&last_r.load(Ordering::Relaxed))
                                            .or_else(|| socks.values().next())
                                            .cloned()
                                    };
                                    if let Some(out) = out {
                                        let _ = out.send_to(&buf[..n], client).await;
                                    }
                                }
                            });
                            f.tasks.lock().unwrap().push(back);
                            (up, last)
                        }
                    };
                    last.store(port, Ordering::Relaxed);
                    let _ = up.send(&buf[..n]).await;
                }
            });
            front.recv_tasks.lock().unwrap().insert(port, task);
        }
        front
    }

    /// Close a front port for good: later packets to it get ICMP unreachable.
    fn close_port(&self, port: u16) {
        if let Some(t) = self.recv_tasks.lock().unwrap().remove(&port) {
            t.abort();
        }
        self.socks.lock().unwrap().remove(&port);
    }

    fn ports_hit(&self) -> usize {
        self.hits.lock().unwrap().len()
    }

    fn hits(&self) -> HashMap<u16, u64> {
        self.hits.lock().unwrap().clone()
    }

    fn port_list(&self) -> Value {
        Value::Array(
            self.ports
                .iter()
                .map(|p| Value::String(format!("{p}:{p}")))
                .collect(),
        )
    }
}

impl Drop for Front {
    fn drop(&mut self) {
        for (_, t) in self.recv_tasks.lock().unwrap().drain() {
            t.abort();
        }
        for t in self.tasks.lock().unwrap().drain(..) {
            t.abort();
        }
    }
}

fn client(extra: Value) -> Hysteria2 {
    let mut cfg = json!({
        "type": "hysteria2", "tag": "hy2-out", "server": "127.0.0.1",
        "password": PASSWORD,
        "tls": {"enabled": true, "insecure": true, "server_name": "localhost"}
    });
    for (k, v) in extra.as_object().unwrap() {
        cfg[k] = v.clone();
    }
    Hysteria2::build(cfg.as_object().unwrap(), "outbounds[0]").expect("build hy2 outbound")
}

async fn roundtrip(out: &Hysteria2, echo: SocketAddr, payload: &[u8]) -> std::io::Result<()> {
    let mut s = out.connect(&Target::Ip(echo)).await?;
    s.write_all(payload).await?;
    let mut got = vec![0u8; payload.len()];
    s.read_exact(&mut got).await?;
    assert_eq!(got, payload, "echo payload");
    Ok(())
}

fn pattern(offset: u64, buf: &mut [u8]) {
    for (i, b) in buf.iter_mut().enumerate() {
        let x = offset + i as u64;
        *b = (x.wrapping_mul(31).wrapping_add(x >> 9) % 251) as u8;
    }
}

/// One TCP stream that keeps sending for `secs`; returns bytes echoed back
/// intact and the longest pause in the echo.
async fn long_stream(out: &Hysteria2, echo: SocketAddr, secs: f64) -> std::io::Result<(u64, f64)> {
    let s = out.connect(&Target::Ip(echo)).await?;
    let (mut rd, mut wr) = tokio::io::split(s);
    let writer = tokio::spawn(async move {
        let mut chunk = vec![0u8; 16 * 1024];
        let start = Instant::now();
        let mut off = 0u64;
        while start.elapsed().as_secs_f64() < secs {
            pattern(off, &mut chunk);
            wr.write_all(&chunk).await?;
            off += chunk.len() as u64;
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        // half-close: the echo then closes and the reader sees EOF
        wr.shutdown().await?;
        Ok::<_, std::io::Error>(off)
    });
    let mut got = 0u64;
    let mut buf = vec![0u8; 64 * 1024];
    let mut want = vec![0u8; 64 * 1024];
    let mut last = Instant::now();
    let mut max_gap = 0f64;
    loop {
        let n = tokio::time::timeout(Duration::from_secs(10), rd.read(&mut buf))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "echo stalled"))??;
        if n == 0 {
            break;
        }
        pattern(got, &mut want[..n]);
        assert_eq!(&buf[..n], &want[..n], "stream data corrupted at {got}");
        got += n as u64;
        max_gap = max_gap.max(last.elapsed().as_secs_f64());
        last = Instant::now();
    }
    let sent = writer.await.expect("writer")?;
    if got != sent {
        return Err(std::io::Error::new(
            std::io::ErrorKind::UnexpectedEof,
            format!("stream closed after {got} of {sent} bytes"),
        ));
    }
    Ok((got, max_gap))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn server_ports_without_server_port_transfers() {
    no_kernel_crypto();
    let _g = SERIAL.lock().await;
    let server = spawn_server().await;
    let echo = spawn_tcp_echo().await;
    let front = Front::spawn(server, 3).await;
    let out = client(json!({"server_ports": front.port_list()}));
    roundtrip(&out, echo, b"ports only")
        .await
        .expect("roundtrip");
    // the string form of one range works as well
    let p = front.ports[0];
    let out = client(json!({"server_ports": format!("{p}:{p}")}));
    roundtrip(&out, echo, b"one range")
        .await
        .expect("roundtrip");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tcp_stream_survives_hops() {
    no_kernel_crypto();
    let _g = SERIAL.lock().await;
    let server = spawn_server().await;
    let echo = spawn_tcp_echo().await;
    let front = Front::spawn(server, 3).await;
    let out = Arc::new(client(json!({
        "server_port": front.ports[0], "server_ports": front.port_list(),
        "hop_interval": "300ms", "network": "tcp"
    })));
    // short requests alongside, as a browser would make them
    let side = {
        let out = Arc::clone(&out);
        tokio::spawn(async move {
            let mut errors = 0;
            for _ in 0..12 {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if roundtrip(&out, echo, b"side").await.is_err() {
                    errors += 1;
                }
            }
            errors
        })
    };
    let res = long_stream(&out, echo, 3.0).await;
    let side_errors = side.await.expect("side");
    eprintln!(
        "long stream: {res:?}; side errors {side_errors}; front mappings {}; ports hit {:?}",
        front.mappings.load(Ordering::Relaxed),
        front.hits()
    );
    let (bytes, _gap) = res.expect("long stream must survive hops");
    assert!(bytes > 1_000_000, "transferred {bytes}");
    assert_eq!(side_errors, 0);
    assert!(front.ports_hit() >= 2, "the client must have hopped");
    assert_eq!(
        front.mappings.load(Ordering::Relaxed),
        1,
        "hops keep one connection"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hops_release_resources() {
    no_kernel_crypto();
    let _g = SERIAL.lock().await;
    let server = spawn_server().await;
    let echo = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let front = Front::spawn(server, 3).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let base = client_fd_count(udp_echo);
    let out = client(json!({
        "server_port": front.ports[0], "server_ports": front.port_list(),
        "hop_interval": "300ms"
    }));
    roundtrip(&out, echo, b"warm").await.expect("warm");
    let warm = client_fd_count(udp_echo);
    // requests keep coming while the client hops
    let start = Instant::now();
    let mut requests = 0;
    while start.elapsed() < Duration::from_secs(4) {
        roundtrip(&out, echo, b"req").await.expect("request");
        requests += 1;
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
    // UDP still flows after the hops
    let udp = out.connect_udp(&Target::Ip(udp_echo)).await.expect("udp");
    udp.send(b"datagram").await.expect("udp send");
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut buf))
        .await
        .expect("udp echo timeout")
        .expect("udp recv");
    assert_eq!(&buf[..n], b"datagram");
    drop(udp);
    let busy = client_fd_count(udp_echo);
    let mappings = front.mappings.load(Ordering::Relaxed);
    drop(out);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = client_fd_count(udp_echo);
    eprintln!(
        "fds: base {base}, warm {warm}, after {requests} requests {busy}, after drop {after}; \
         client sockets seen by the server {mappings}; ports hit {:?}",
        front.hits()
    );
    assert!(front.ports_hit() >= 2, "the client must have hopped");
    assert_eq!(mappings, 1, "hops must not open new connections");
    assert!(busy <= warm + 3, "fds grew from {warm} to {busy}");
    // the harness keeps one upstream socket per client socket it saw
    assert!(
        after <= base + mappings,
        "client fds not released: base {base}, after drop {after}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hop_onto_closed_port_recovers() {
    no_kernel_crypto();
    let _g = SERIAL.lock().await;
    let server = spawn_server().await;
    let echo = spawn_tcp_echo().await;
    let front = Front::spawn(server, 3).await;
    let out = Arc::new(client(json!({
        "server_ports": front.port_list(), "hop_interval": "300ms", "network": "tcp"
    })));
    let killer = {
        let front = Arc::clone(&front);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(1000)).await;
            // the port in use goes away; later hops may land on it again
            let port = front.current.load(Ordering::Relaxed);
            front.close_port(port);
            port
        })
    };
    let res = long_stream(&out, echo, 4.0).await;
    let closed = killer.await.expect("killer");
    let hits_at_close = front.hits();
    eprintln!(
        "closed port {closed}; long stream {res:?}; ports hit {hits_at_close:?}; mappings {}",
        front.mappings.load(Ordering::Relaxed)
    );
    let (bytes, gap) = res.expect("stream must recover after the closed port");
    assert!(bytes > 1_000_000, "transferred {bytes}");
    // one hop interval plus QUIC loss recovery
    assert!(gap < 3.0, "stalled for {gap:.2}s");
    // new connections still work, whatever port they start on
    for _ in 0..3 {
        tokio::time::timeout(Duration::from_secs(10), roundtrip(&out, echo, b"after"))
            .await
            .expect("timeout after close")
            .expect("roundtrip after close");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn single_port_unchanged() {
    no_kernel_crypto();
    let _g = SERIAL.lock().await;
    let server = spawn_server().await;
    let echo = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let base_fds = fds();
    let base = client_fd_count(udp_echo);
    let out = client(json!({"server_port": server.port()}));
    for _ in 0..5 {
        roundtrip(&out, echo, b"single").await.expect("roundtrip");
    }
    let (bytes, _) = long_stream(&out, echo, 1.0).await.expect("long stream");
    assert!(bytes > 100_000);
    let udp = out.connect_udp(&Target::Ip(udp_echo)).await.expect("udp");
    udp.send(b"single-udp").await.expect("udp send");
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(Duration::from_secs(5), udp.recv(&mut buf))
        .await
        .expect("udp timeout")
        .expect("udp recv");
    assert_eq!(&buf[..n], b"single-udp");
    drop(udp);
    drop(out);
    tokio::time::sleep(Duration::from_millis(500)).await;
    let after = client_fd_count(udp_echo);
    let extra: Vec<_> = fds()
        .into_iter()
        .filter(|(fd, _)| !base_fds.contains_key(fd))
        .collect();
    eprintln!(
        "single port fds: base {base}, after drop {after}; new {extra:?}; udp echo {udp_echo}"
    );
    assert!(
        after <= base,
        "fds not released: {base} -> {after}: {extra:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn check_agrees_with_start() {
    no_kernel_crypto();
    let _g = SERIAL.lock().await;
    let tls = json!({"enabled": true, "insecure": true, "server_name": "localhost"});
    let cases = [
        ("ports only", json!({"server_ports": ["20000:20010"]})),
        ("ports string", json!({"server_ports": "20000:30000"})),
        (
            "two ranges",
            json!({"server_ports": ["20000:20010", "30000:30010"]}),
        ),
        (
            "port and ports",
            json!({"server_port": 443, "server_ports": ["20000:20010"]}),
        ),
        ("port only", json!({"server_port": 443})),
        ("neither", json!({})),
        ("empty list", json!({"server_ports": []})),
        ("reversed range", json!({"server_ports": ["30000:20000"]})),
    ];
    for (name, extra) in cases {
        let mut ob = json!({"type": "hysteria2", "tag": "hy", "server": "127.0.0.1",
            "password": "p", "tls": tls});
        for (k, v) in extra.as_object().unwrap() {
            ob[k] = v.clone();
        }
        let cfg = json!({
            "log": {"level": "error"},
            "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
            "outbounds": [ob]
        });
        let check = core_config::check_str(&cfg.to_string());
        let start = core_runtime::start(&cfg).await;
        eprintln!(
            "{name}: check {:?}, start {:?}",
            check.as_ref().err(),
            start.as_ref().err().map(|e| e.to_string())
        );
        assert_eq!(
            check.is_ok(),
            start.is_ok(),
            "{name}: check and start disagree"
        );
        if let Ok(instance) = start {
            instance.shutdown();
        }
    }
}

/// Kernel AES-GCM (`AF_ALG`) keeps two sockets per live key; the descriptor
/// counts in this file are about our own sockets, so it stays off here. Every
/// test calls this first, before any key exists.
fn no_kernel_crypto() {
    #[cfg(target_os = "linux")]
    assert!(
        core_crypto::afalg::disable_for_process(),
        "kernel AES-GCM was chosen before the test could turn it off"
    );
}
