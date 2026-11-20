//! hysteria2 outbound interop: our box dials the reference sing-box
//! acting as hy2 server (test cert fixture, insecure client, TCP path).
//! The restart test uses an independent Xray server. Reference tests require
//! SING_BOX_REF or XRAY_REF, respectively.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
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

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("probe addr")
        .port()
}

struct RefServer(Child);

impl Drop for RefServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_ref(ref_bin: &str, config: &Value) -> RefServer {
    let path = std::env::temp_dir().join(format!(
        "tc-hy2-ref-{}-{}.json",
        std::process::id(),
        free_port()
    ));
    std::fs::write(
        &path,
        serde_json::to_string(config).expect("serialize config"),
    )
    .expect("write ref config");
    let child = Command::new(ref_bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn reference sing-box");
    RefServer(child)
}

async fn wait_listening(port: u16) -> bool {
    // hy2 is a UDP/QUIC inbound — a TCP probe never succeeds.
    // One datagram + a short pause: enough for the ref process to bind UDP.
    let Ok(sock) = tokio::net::UdpSocket::bind("127.0.0.1:0").await else {
        return false;
    };
    if sock.connect(("127.0.0.1", port)).await.is_err() {
        return false;
    }
    if sock.send(b"ping").await.is_err() {
        return false;
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    true
}

async fn socks_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    eprintln!("{label}: socks connect");
    let mut stream = TcpStream::connect(proxy).await.expect("connect inbound");
    eprintln!("{label}: greeting");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    eprintln!("{label}: auth {auth:?}");
    assert_eq!(auth, [0x05, 0x00]);

    let std::net::IpAddr::V4(v4) = echo.ip() else {
        panic!("expected v4 echo addr");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    eprintln!("{label}: connect request");
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 4];
    stream.read_exact(&mut reply).await.expect("connect reply");
    eprintln!("{label}: reply {reply:?}");
    let mut bnd = [0u8; 6];
    stream.read_exact(&mut bnd).await.expect("bnd");
    assert_eq!(reply[1], 0x00, "{label}: CONNECT must succeed");

    stream.write_all(b"roundtrip").await.expect("write");
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"roundtrip", "{label}: payload must echo");
}

async fn assert_outbound(
    ref_bin: &str,
    inbound_type: &str,
    label: &str,
    make_ref_inbound: impl Fn(u16) -> Value,
    make_outbound: impl Fn(u16) -> Value,
) {
    eprintln!("{label}: starting ref");
    let ref_port = free_port();
    let echo = spawn_echo().await;
    let _server = start_ref(
        ref_bin,
        &json!({
            "log": {"level": "error"},
            "inbounds": [make_ref_inbound(ref_port)],
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }),
    );
    assert!(
        wait_listening(ref_port).await,
        "{label}: reference server did not start"
    );
    eprintln!("{label}: ref up on {ref_port}");

    eprintln!("{label}: starting box");
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [make_outbound(ref_port)],
        "route": {"final": "up"}
    }))
    .await
    .expect("start xrust");
    let proxy = instance.inbound_addrs()[0].1;
    eprintln!("{label}: box up, proxy {proxy}");

    eprintln!("{label}: socks roundtrip");
    let result =
        tokio::time::timeout(Duration::from_secs(20), socks_roundtrip(proxy, echo, label)).await;
    eprintln!("{label}: roundtrip result ok={}", result.is_ok());
    assert!(result.is_ok(), "{label}: timed out");
    eprintln!("{label}: roundtrip ok, shutting down");

    instance.shutdown();
    eprintln!("{label}: done");
    let _ = inbound_type;
}

#[tokio::test]
async fn interop_hysteria2() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    assert_outbound(
        &ref_bin.to_string_lossy(),
        "hysteria2",
        "hysteria2",
        |port| {
            json!({
                "type": "hysteria2", "listen": "127.0.0.1", "listen_port": port,
                "users": [{"password": "interop-pass"}],
                "up_mbps": 10, "down_mbps": 10,
                "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
            })
        },
        |port| {
            json!({
                "type": "hysteria2", "tag": "up", "server": "127.0.0.1", "server_port": port,
                "up_mbps": 10, "down_mbps": 10, "password": "interop-pass",
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            })
        },
    )
    .await;
}

async fn socks_udp_associate(proxy: SocketAddr) -> (TcpStream, UdpSocket) {
    let mut control = TcpStream::connect(proxy).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut auth = [0; 2];
    control.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.connect(relay).await.unwrap();
    (control, udp)
}

async fn udp_roundtrip(
    udp: &UdpSocket,
    target: SocketAddr,
    payload: &[u8],
    wait: Duration,
) -> bool {
    let std::net::IpAddr::V4(addr) = target.ip() else {
        panic!("expected IPv4 UDP echo");
    };
    let mut request = vec![0, 0, 0, 1];
    request.extend_from_slice(&addr.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    request.extend_from_slice(payload);
    udp.send(&request).await.unwrap();
    let mut reply = vec![0; request.len() + 1];
    let Ok(received) = tokio::time::timeout(wait, udp.recv(&mut reply)).await else {
        return false;
    };
    assert_eq!(&reply[..received.unwrap()], request);
    true
}

#[tokio::test]
async fn existing_socks_udp_flow_recovers_after_xray_restart() {
    let Some(bin) = std::env::var_os("XRAY_REF") else {
        return;
    };
    let bin = bin.to_string_lossy();
    let port = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let mut buf = [0; 8192];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });
    let certs = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/certs");
    let peer_config = json!({
        "log": {"loglevel": "error"},
        "inbounds": [{"protocol": "hysteria", "listen": "127.0.0.1", "port": port,
            "settings": {"version": 2, "users": [{"auth": "interop-pass"}]},
            "streamSettings": {"network": "hysteria", "security": "tls",
                "hysteriaSettings": {"version": 2},
                "tlsSettings": {"alpn": ["h3"], "certificates": [{
                    "certificateFile": format!("{certs}/localhost.crt"),
                    "keyFile": format!("{certs}/localhost.key")
                }]}}}],
        "outbounds": [{"protocol": "freedom", "settings": {
            "finalRules": [{"action": "allow", "ip": ["127.0.0.1/32"]}]
        }}]
    });
    let server = start_ref(&bin, &peer_config);
    assert!(wait_listening(port).await);
    let client = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "hysteria2", "tag": "up", "server": "127.0.0.1", "server_port": port,
            "password": "interop-pass", "idle_timeout": "3s", "keep_alive_period": "1s",
            "tls": {"enabled": true, "server_name": "localhost", "certificate": CERT_PEM}}],
        "route": {"final": "up"}
    }))
    .await
    .unwrap();
    let proxy = client.inbound_addrs()[0].1;
    let (_original_associate, original) = socks_udp_associate(proxy).await;
    let wait = Duration::from_secs(3);
    assert!(udp_roundtrip(&original, target, b"first", wait).await);
    let fragmented: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
    assert!(udp_roundtrip(&original, target, &fragmented, wait).await);

    drop(server);
    let offline = Duration::from_millis(4500);
    assert!(!udp_roundtrip(&original, target, b"offline", offline).await);
    let _server = start_ref(&bin, &peer_config);
    assert!(wait_listening(port).await);
    let (_new_associate, new) = socks_udp_associate(proxy).await;
    assert!(udp_roundtrip(&new, target, b"fresh channel", wait).await);
    assert!(
        udp_roundtrip(&original, target, b"same UDP socket", wait).await,
        "the existing SOCKS UDP flow stayed attached to the closed QUIC connection"
    );
    assert!(udp_roundtrip(&original, target, b"next datagram", wait).await);
    client.shutdown();
    echo_task.abort();
}

async fn loopback_hy2_server(listen: &str, obfs: bool) -> SocketAddr {
    let router = core_runtime::route::Router::new(
        &json!({"outbounds": [{"type": "direct", "tag": "direct"}]}),
    )
    .unwrap();
    let mut cfg = json!({
        "type": "hysteria2", "tag": "hy2-in", "listen": listen, "listen_port": 0,
        "users": [{"password": "interop-pass"}],
        "tls": {"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM}
    });
    if obfs {
        cfg["obfs"] = json!({"type": "salamander", "password": "loopback-fixture"});
    }
    let server = core_runtime::inbound::hysteria2::Hysteria2::bind(&cfg, router)
        .await
        .unwrap();
    let addr = server.local_addr().unwrap();
    tokio::spawn(server.serve());
    addr
}

fn loopback_hy2_client(
    server: SocketAddr,
    obfs: bool,
) -> core_runtime::outbound::hysteria2::Hysteria2 {
    let mut cfg = json!({
        "type": "hysteria2", "tag": "hy2-out", "server": server.ip().to_string(),
        "server_port": server.port(), "password": "interop-pass", "connect_timeout": "2s",
        "tls": {"enabled": true, "server_name": "localhost", "certificate": CERT_PEM}
    });
    if obfs {
        cfg["obfs"] = json!({"type": "salamander", "password": "loopback-fixture"});
    }
    core_runtime::outbound::hysteria2::Hysteria2::build(cfg.as_object().unwrap(), "test").unwrap()
}

async fn loopback_hy2_udp_echo() -> SocketAddr {
    let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = echo.local_addr().unwrap();
    tokio::spawn(async move {
        let mut bytes = vec![0; 65_535];
        while let Ok((len, peer)) = echo.recv_from(&mut bytes).await {
            if echo.send_to(&bytes[..len], peer).await.is_err() {
                break;
            }
        }
    });
    addr
}

async fn loopback_hy2_exchange(flow: &UdpSocket, data: &[u8]) {
    assert_eq!(flow.send(data).await.unwrap(), data.len());
    let mut reply = vec![0; data.len() + 1];
    let len = tokio::time::timeout(Duration::from_secs(3), flow.recv(&mut reply))
        .await
        .unwrap_or_else(|_| panic!("HY2 {}-byte UDP reply timed out", data.len()))
        .unwrap();
    assert_eq!(&reply[..len], data);
}

#[tokio::test]
async fn loopback_hy2_inbound_sends_fragmented_udp_replies() {
    use core_runtime::inbound::Target;

    let server = loopback_hy2_server("127.0.0.1", false).await;
    let client = loopback_hy2_client(server, false);
    let target = Target::Ip(loopback_hy2_udp_echo().await);
    let flow = client.connect_udp(&target).await.unwrap();
    loopback_hy2_exchange(&flow, b"plain short").await;
    let data: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
    loopback_hy2_exchange(&flow, &data).await;
    loopback_hy2_exchange(&flow, &[]).await;
    loopback_hy2_exchange(&flow, b"plain after fragments").await;
}

async fn loopback_hy2_salamander_clients(listen: &str) {
    use core_runtime::inbound::Target;

    let server = loopback_hy2_server(listen, true).await;
    let a = loopback_hy2_client(server, true);
    let b = loopback_hy2_client(server, true);
    let target = Target::Ip(loopback_hy2_udp_echo().await);
    let (flow_a, flow_b) = tokio::try_join!(a.connect_udp(&target), b.connect_udp(&target))
        .expect("both concurrent Salamander clients connect");
    tokio::join!(
        loopback_hy2_exchange(&flow_a, b"salamander first"),
        loopback_hy2_exchange(&flow_b, b"salamander second")
    );
    let data: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
    tokio::join!(
        loopback_hy2_exchange(&flow_a, &data),
        loopback_hy2_exchange(&flow_b, b"salamander second again")
    );

    let tcp = Target::Ip(spawn_echo().await);
    let mut stream = a.connect(&tcp).await.unwrap();
    stream.write_all(b"tcp echo").await.unwrap();
    let mut reply = [0; 8];
    tokio::time::timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"tcp echo");
}

#[tokio::test]
async fn loopback_hy2_salamander_inbound_keeps_ipv4_clients_distinct() {
    loopback_hy2_salamander_clients("127.0.0.1").await;
}

#[tokio::test]
async fn loopback_hy2_salamander_inbound_keeps_ipv6_clients_distinct() {
    loopback_hy2_salamander_clients("::1").await;
}

#[tokio::test]
async fn loopback_hy2_salamander_inbound_accepts_xray_client() {
    let Some(bin) = std::env::var_os("XRAY_REF") else {
        return;
    };
    let server = loopback_hy2_server("127.0.0.1", true).await;
    let target = loopback_hy2_udp_echo().await;
    let port = free_port();
    let certs = concat!(env!("CARGO_MANIFEST_DIR"), "/../../tests/golden/certs");
    let _client = start_ref(
        &bin.to_string_lossy(),
        &json!({
            "log": {"loglevel": "error"},
            "inbounds": [{"protocol": "socks", "listen": "127.0.0.1", "port": port,
                "settings": {"auth": "noauth", "udp": true}}],
            "outbounds": [{"protocol": "hysteria",
                "settings": {"version": 2, "address": server.ip().to_string(), "port": server.port()},
                "streamSettings": {"network": "hysteria", "security": "tls",
                    "hysteriaSettings": {"version": 2, "auth": "interop-pass"},
                    "tlsSettings": {"serverName": "localhost", "alpn": ["h3"],
                        "certificates": [{"certificateFile": format!("{certs}/localhost.crt"),
                                          "usage": "verify"}]},
                    "finalmask": {"udp": [{"type": "salamander",
                                           "settings": {"password": "loopback-fixture"}}]}}}]
        }),
    );
    let proxy = SocketAddr::from(([127, 0, 0, 1], port));
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if TcpStream::connect(proxy).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("Xray SOCKS listener did not start");
    let (_associate, udp) = socks_udp_associate(proxy).await;
    let timeout = Duration::from_secs(3);
    assert!(udp_roundtrip(&udp, target, b"Xray Salamander UDP", timeout).await);
    let data: Vec<u8> = (0..4097).map(|i| (i % 251) as u8).collect();
    assert!(udp_roundtrip(&udp, target, &data, timeout).await);
}
