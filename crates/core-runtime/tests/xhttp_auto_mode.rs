//! XHTTP `mode: auto`, end to end: our own client box (mixed inbound ->
//! vless over xhttp) against our own server box (vless over xhttp -> direct),
//! both in this process.
//!
//! Xray resolves `auto` to stream-one under REALITY and to packet-up
//! otherwise (splithttp/dialer.go). The two are told apart on the far side by
//! the client's half-close: stream-one ends its request body, so the upstream
//! reads EOF; packet-up has no end-of-upload on the wire, so it never does.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use base64::Engine;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const SHORT_ID: &str = "1234abcd";
const PRIVATE: [u8; 32] = [0x42; 32];

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("port")
        .local_addr()
        .expect("addr")
        .port()
}

fn cert_file(name: &str) -> String {
    format!(
        "{}/../../tests/golden/certs/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

fn key_b64(key: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key)
}

fn reality_public() -> String {
    let secret = x25519_dalek::StaticSecret::from(PRIVATE);
    key_b64(x25519_dalek::PublicKey::from(&secret).as_bytes())
}

fn inbound_addr(instance: &core_runtime::BoxInstance, tag: &str) -> SocketAddr {
    instance
        .inbound_addrs()
        .iter()
        .find(|(t, _)| t == tag)
        .map(|(_, a)| *a)
        .unwrap_or_else(|| panic!("no inbound {tag}"))
}

#[derive(Clone, Copy, Debug)]
enum Security {
    Reality,
    Tls,
}

struct Stand {
    _client: core_runtime::BoxInstance,
    _server: core_runtime::BoxInstance,
    socks: SocketAddr,
}

async fn stand(mode: &str, security: Security) -> Stand {
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
    match security {
        Security::Reality => {
            server_in["tls"] = json!({
                "enabled": true,
                "server_name": "www.example.com",
                "reality": {
                    "enabled": true,
                    "private_key": key_b64(&PRIVATE),
                    "short_id": [SHORT_ID]
                }
            });
            client_out["tls"] = json!({
                "enabled": true,
                "server_name": "www.example.com",
                "utls": {"enabled": true, "fingerprint": "chrome"},
                "reality": {
                    "enabled": true,
                    "public_key": reality_public(),
                    "short_id": SHORT_ID
                }
            });
        }
        Security::Tls => {
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
        _client: client,
        _server: server,
        socks,
    }
}

async fn socks_connect(socks: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(socks).await.expect("socks");
    stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await.unwrap();
    assert_eq!(greeting, [0x05, 0x00], "socks greeting");
    let mut request = vec![0x05, 0x01, 0x00, 1];
    match target.ip() {
        IpAddr::V4(ip) => request.extend_from_slice(&ip.octets()),
        IpAddr::V6(_) => panic!("v4 target"),
    }
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0x00, "socks connect refused");
    stream
}

/// Echoes what it reads, and once it reads EOF writes `|eof` and closes.
async fn spawn_eof_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => {
                            let _ = stream.write_all(b"|eof").await;
                            let _ = stream.shutdown().await;
                            return;
                        }
                        Err(_) => return,
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

/// Send `hello`, read the echo, half-close, and report whether the upstream
/// saw the EOF within `wait`.
async fn half_close_reaches_upstream(stand: &Stand, wait: Duration) -> bool {
    let echo = spawn_eof_echo().await;
    let mut s = socks_connect(stand.socks, echo).await;
    s.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .expect("echo timed out")
        .expect("echo");
    assert_eq!(&got, b"hello");
    s.shutdown().await.expect("half-close");
    let mut rest = Vec::new();
    match tokio::time::timeout(wait, s.read_to_end(&mut rest)).await {
        Ok(Ok(_)) => rest == b"|eof",
        Ok(Err(_)) | Err(_) => false,
    }
}

#[tokio::test]
async fn auto_over_reality_is_stream_one() {
    let stand = stand("auto", Security::Reality).await;
    // well inside the 10 s half-close idle limit packet-up would fall back on
    assert!(
        half_close_reaches_upstream(&stand, Duration::from_secs(5)).await,
        "auto over REALITY must run stream-one: the half-close never reached the upstream"
    );
}

#[tokio::test]
async fn explicit_stream_one_over_reality_carries_the_half_close() {
    let stand = stand("stream-one", Security::Reality).await;
    assert!(half_close_reaches_upstream(&stand, Duration::from_secs(5)).await);
}

#[tokio::test]
async fn explicit_packet_up_over_reality_stays_packet_up() {
    let stand = stand("packet-up", Security::Reality).await;
    assert!(
        !half_close_reaches_upstream(&stand, Duration::from_millis(1500)).await,
        "packet-up has no end of upload, so the upstream must not see EOF"
    );
}

#[tokio::test]
async fn auto_over_plain_tls_stays_packet_up() {
    let stand = stand("auto", Security::Tls).await;
    assert!(
        !half_close_reaches_upstream(&stand, Duration::from_millis(1500)).await,
        "auto without REALITY is packet-up, which has no end of upload"
    );
}
