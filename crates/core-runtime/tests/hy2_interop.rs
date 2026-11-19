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
