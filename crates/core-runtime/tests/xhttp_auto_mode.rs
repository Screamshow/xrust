//! XHTTP `mode: auto`, end to end: our own client box (mixed inbound ->
//! vless over xhttp) against our own server box (vless over xhttp -> direct),
//! both in this process.
//!
//! Xray resolves `auto` to stream-one under REALITY and to packet-up
//! otherwise (splithttp/dialer.go). The two are told apart by the TCP
//! connections the client opens to the server over HTTP/1.1: stream-one
//! carries the session in one request on one connection, packet-up opens its
//! download GET and its upload POSTs on connections of their own.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
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
    /// TCP connections the client opened to the server
    connections: Arc<AtomicUsize>,
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
                "alpn": ["http/1.1"],
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
                "alpn": ["http/1.1"]
            });
            client_out["tls"] = json!({
                "enabled": true,
                "server_name": "localhost",
                "insecure": true,
                "alpn": ["http/1.1"]
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
    let (front, connections) = counting_forwarder(server_addr).await;
    client_out["server"] = json!("127.0.0.1");
    client_out["server_port"] = json!(front.port());
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
        connections,
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

/// Echoes what it reads.
async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

/// A TCP forwarder in front of `to` that counts the connections it takes.
async fn counting_forwarder(to: SocketAddr) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let count = Arc::new(AtomicUsize::new(0));
    let seen = Arc::clone(&count);
    tokio::spawn(async move {
        while let Ok((mut inbound, _)) = listener.accept().await {
            seen.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let Ok(mut outbound) = TcpStream::connect(to).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
            });
        }
    });
    (addr, count)
}

/// One echo exchange through the stand: how many connections it took.
async fn connections_for_one_session(stand: &Stand) -> usize {
    let echo = spawn_echo().await;
    let mut s = socks_connect(stand.socks, echo).await;
    s.write_all(b"hello").await.unwrap();
    let mut got = [0u8; 5];
    tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut got))
        .await
        .expect("echo timed out")
        .expect("echo");
    assert_eq!(&got, b"hello");
    stand.connections.load(Ordering::SeqCst)
}

#[tokio::test]
async fn auto_over_reality_is_stream_one() {
    let stand = stand("auto", Security::Reality).await;
    assert_eq!(
        connections_for_one_session(&stand).await,
        1,
        "auto over REALITY must run stream-one: one request on one connection"
    );
}

#[tokio::test]
async fn explicit_stream_one_over_reality_is_one_connection() {
    let stand = stand("stream-one", Security::Reality).await;
    assert_eq!(connections_for_one_session(&stand).await, 1);
}

#[tokio::test]
async fn explicit_packet_up_over_reality_stays_packet_up() {
    let stand = stand("packet-up", Security::Reality).await;
    assert!(
        connections_for_one_session(&stand).await >= 2,
        "packet-up opens its download and its uploads apart"
    );
}

#[tokio::test]
async fn auto_over_plain_tls_stays_packet_up() {
    let stand = stand("auto", Security::Tls).await;
    assert!(
        connections_for_one_session(&stand).await >= 2,
        "auto without REALITY is packet-up"
    );
}
