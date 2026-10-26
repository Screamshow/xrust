//! What the VLESS client's first application-data record carries, and that the
//! servers it talks to still accept it.
//!
//! - Against our own TLS server (REALITY, or a certificate), which opens every
//!   record on its own: the request head shares the first record with the first
//!   payload, a client that stays silent sends it alone after Xray's 500 ms
//!   wait, and a client that leaves before its first byte sends nothing --
//!   the shapes the Xray 26.10.21 binary puts on the wire.
//! - Against Xray as the server when `XRAY_REF` names its binary: REALITY with
//!   Vision, TLS with ws and gRPC, XHTTP packet-up, stream-up and stream-one.
//! - Against the reference sing-box as the server when `SING_BOX_REF` names its
//!   binary: REALITY with Vision, TLS, ws and gRPC.
//!
//! Each case moves a client-first exchange, a destination that talks first, a
//! bulk transfer and UDP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use core_runtime::inbound::Target;
use core_tls::record::ContentType;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const UUID: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];
const SHORT_ID: &str = "1234abcd";
const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");

fn certs_dir() -> String {
    format!("{}/../../tests/golden/certs", env!("CARGO_MANIFEST_DIR"))
}

fn reality_public(private: &[u8; 32]) -> String {
    let secret = x25519_dalek::StaticSecret::from(*private);
    let public = x25519_dalek::PublicKey::from(&secret);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes())
}

fn reality_private(private: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(private)
}

// ---- what the first record carries ----

/// A TLS server of our own, opening one record at a time: returns the
/// plaintext of each application-data record, in order, and answers the first
/// one with `answer`.
fn record_server(
    listener: TcpListener,
    config: core_tls::server::Config,
    answer: Vec<u8>,
) -> tokio::task::JoinHandle<Vec<(Duration, Vec<u8>)>> {
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut handshake = core_tls::server::Handshake::new(config).unwrap();
        handshake.run(&mut socket).await.expect("handshake");
        let started = Instant::now();
        let (mut sealer, mut opener) = handshake.application.take().unwrap();
        let mut records = Vec::new();
        loop {
            let mut head = [0u8; 5];
            let read = tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut head));
            if !matches!(read.await, Ok(Ok(_))) {
                break;
            }
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            if socket.read_exact(&mut record[5..]).await.is_err() {
                break;
            }
            let Ok((kind, data)) = opener.open(&record) else {
                break;
            };
            if kind == ContentType::ApplicationData && !data.is_empty() {
                if records.is_empty() {
                    let sealed = sealer.seal(ContentType::ApplicationData, &answer).unwrap();
                    let _ = socket.write_all(&sealed).await;
                }
                records.push((started.elapsed(), data.to_vec()));
            }
        }
        records
    })
}

fn reality_config(private: [u8; 32]) -> core_tls::server::Config {
    core_tls::server::Config {
        chain: Vec::new(),
        key: None,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        cipher_suites: Vec::new(),
        reality: Some(core_tls::server::ServerReality {
            private_key: private,
            short_ids: vec![vec![0x12, 0x34, 0xab, 0xcd]],
            max_time_difference: Some(600),
        }),
    }
}

/// An ordinary certificate server: any Ed25519 leaf does for an `insecure`
/// client.
fn certificate_config() -> core_tls::server::Config {
    let (signing, public) = core_crypto::sign::Ed25519SigningKey::generate();
    let leaf = core_tls::reality::build_reality_certificate(&public, &[0x33; 32]);
    core_tls::server::Config {
        chain: vec![leaf],
        key: Some(Arc::new(signing)),
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        cipher_suites: Vec::new(),
        reality: None,
    }
}

fn vless(port: u16, tls: Value, flow: &str) -> core_runtime::outbound::secure::Vless {
    let mut outbound = json!({
        "type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port,
        "uuid": UUID_TEXT, "tls": tls
    });
    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }
    core_runtime::outbound::secure::Vless::build(outbound.as_object().unwrap(), "up").unwrap()
}

fn reality_tls(private: &[u8; 32]) -> Value {
    json!({
        "enabled": true, "server_name": "www.example.com",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": reality_public(private), "short_id": SHORT_ID}
    })
}

fn certificate_tls() -> Value {
    json!({
        "enabled": true, "server_name": "www.example.com", "insecure": true,
        "utls": {"enabled": true, "fingerprint": "chrome"}
    })
}

/// `[0x00][uuid][addons][command 1][port][2][len][name]`
fn expected_head(vision: bool, host: &str, port: u16) -> Vec<u8> {
    let mut head = vec![0x00];
    head.extend_from_slice(&UUID);
    if vision {
        head.extend_from_slice(&[18, 0x0a, 16]);
        head.extend_from_slice(b"xtls-rprx-vision");
    } else {
        head.push(0);
    }
    head.push(0x01);
    head.extend_from_slice(&port.to_be_bytes());
    head.extend_from_slice(&[0x02, host.len() as u8]);
    head.extend_from_slice(host.as_bytes());
    head
}

/// The VLESS answer head and a Vision frame that ends the padding with `pong`.
fn vision_answer() -> Vec<u8> {
    let mut answer = vec![0x00, 0x00];
    answer.extend_from_slice(&UUID);
    answer.extend_from_slice(&[0x01, 0x00, 0x04, 0x00, 0x00]);
    answer.extend_from_slice(b"pong");
    answer
}

/// One Vision frame at the start of `data`: (command, content, padding length).
fn vision_frame(data: &[u8]) -> (u8, &[u8], usize) {
    let content = u16::from_be_bytes([data[1], data[2]]) as usize;
    let padding = u16::from_be_bytes([data[3], data[4]]) as usize;
    assert_eq!(
        data.len(),
        5 + content + padding,
        "one frame, nothing behind it"
    );
    assert!(
        data[5 + content..].iter().all(|b| *b == 0),
        "padding is zeros"
    );
    (data[0], &data[5..5 + content], padding)
}

/// Client first, REALITY with Vision: the head, the UUID and the Vision frame
/// of the payload are one record, the frame long-padded as Xray pads a TLS
/// hello (content and padding together 900 to 1399 bytes).
#[tokio::test]
async fn reality_vision_sends_head_and_first_frame_in_one_record() {
    let private = [9u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = record_server(listener, reality_config(private), vision_answer());
    let client = vless(port, reality_tls(&private), "xtls-rprx-vision");
    let target = Target::Domain("example.com".to_string(), 443);
    let mut stream = client.connect(&target).await.expect("connect");
    let hello = b"\x16\x03\x01\x02\x00client hello bytes";
    stream.write_all(hello).await.unwrap();
    stream.flush().await.unwrap();
    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong).await.unwrap();
    assert_eq!(&pong, b"pong");
    stream.write_all(b"second").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream);
    let records = server.await.unwrap();
    assert_eq!(records.len(), 2, "two writes, two records");
    let first = &records[0].1;
    let head = expected_head(true, "example.com", 443);
    assert_eq!(&first[..head.len()], &head[..], "the request head");
    assert_eq!(&first[head.len()..head.len() + 16], &UUID, "then the UUID");
    let (command, content, padding) = vision_frame(&first[head.len() + 16..]);
    assert_eq!(command, 0x00, "CommandPaddingContinue");
    assert_eq!(content, hello);
    assert!(
        (900..1400).contains(&(content.len() + padding)),
        "{padding}"
    );
    let (command, content, _) = vision_frame(&records[1].1);
    assert_eq!((command, content), (0x00, &b"second"[..]), "no UUID again");
}

/// A destination that talks first, REALITY with Vision: after 500 ms the head
/// goes alone, as the Xray binary sends it (a 61-byte record for an IPv4
/// target in its capture), and the UUID rides with the first frame after it.
#[tokio::test]
async fn reality_vision_silent_client_sends_the_bare_head_after_the_wait() {
    let private = [11u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = record_server(listener, reality_config(private), vision_answer());
    let client = vless(port, reality_tls(&private), "xtls-rprx-vision");
    let target = Target::Domain("smtp.example".to_string(), 25);
    let mut stream = client.connect(&target).await.expect("connect");
    let started = Instant::now();
    let mut pong = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut pong))
        .await
        .expect("the head goes out without a payload")
        .unwrap();
    assert_eq!(&pong, b"pong");
    assert!(started.elapsed() >= Duration::from_millis(450));
    stream.write_all(b"EHLO\r\n").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream);
    let records = server.await.unwrap();
    assert_eq!(records.len(), 2);
    assert!(records[0].0 >= Duration::from_millis(450), "{records:?}");
    assert_eq!(records[0].1, expected_head(true, "smtp.example", 25));
    let second = &records[1].1;
    assert_eq!(&second[..16], &UUID, "the UUID with the first frame");
    let (command, content, padding) = vision_frame(&second[16..]);
    assert_eq!((command, content), (0x00, &b"EHLO\r\n"[..]));
    assert!(padding < 256, "no TLS seen: short padding, {padding}");
}

/// Every record our REALITY server opens after the handshake, alerts too,
/// answering the first application-data record with `answer`.
fn all_records_server(
    listener: TcpListener,
    private: [u8; 32],
    answer: Vec<u8>,
) -> tokio::task::JoinHandle<Vec<(ContentType, Vec<u8>)>> {
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut handshake = core_tls::server::Handshake::new(reality_config(private)).unwrap();
        handshake.run(&mut socket).await.expect("handshake");
        let (mut sealer, mut opener) = handshake.application.take().unwrap();
        let mut records = Vec::new();
        loop {
            let mut head = [0u8; 5];
            let read = tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut head));
            if !matches!(read.await, Ok(Ok(_))) {
                break;
            }
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            if socket.read_exact(&mut record[5..]).await.is_err() {
                break;
            }
            let Ok((kind, data)) = opener.open(&record) else {
                break;
            };
            if kind == ContentType::ApplicationData
                && !records
                    .iter()
                    .any(|(k, _)| *k == ContentType::ApplicationData)
            {
                let sealed = sealer.seal(ContentType::ApplicationData, &answer).unwrap();
                let _ = socket.write_all(&sealed).await;
            }
            records.push((kind, data.to_vec()));
        }
        records
    })
}

/// A client that leaves before its first byte: no application data at all,
/// as with Xray, whose request returns before the buffered head is flushed;
/// only close_notify, which Go's `tls.Conn.Close` sends.
#[tokio::test]
async fn a_client_that_leaves_before_its_first_byte_sends_no_head() {
    let private = [12u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = all_records_server(listener, private, vision_answer());
    let client = vless(port, reality_tls(&private), "xtls-rprx-vision");
    let mut stream = client
        .connect(&Target::Domain("example.com".to_string(), 443))
        .await
        .expect("connect");
    stream.shutdown().await.unwrap();
    drop(stream);
    let records = server.await.unwrap();
    assert_eq!(records, vec![(ContentType::Alert, vec![1, 0])]);
}

/// A connection that ends without a shutdown still says close_notify last,
/// as Xray's client does on close (a 19-byte record on the wire).
#[tokio::test]
async fn a_dropped_connection_ends_with_close_notify() {
    let private = [14u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = all_records_server(listener, private, b"\x00\x00pong".to_vec());
    let client = vless(port, reality_tls(&private), "");
    let mut stream = client
        .connect(&Target::Domain("example.com".to_string(), 80))
        .await
        .expect("connect");
    stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let mut pong = [0u8; 4];
    stream.read_exact(&mut pong).await.unwrap();
    drop(stream);
    let records = server.await.unwrap();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0].0, ContentType::ApplicationData);
    assert_eq!(records[1], (ContentType::Alert, vec![1, 0]));
}

/// Plain VLESS over TLS and over REALITY: head and payload share a record when
/// the client talks first, and the head goes alone after the wait otherwise.
#[tokio::test]
async fn plain_vless_head_rides_with_the_first_payload() {
    let private = [13u8; 32];
    for (label, reality) in [("tls", false), ("reality", true)] {
        let (config, tls) = if reality {
            (reality_config(private), reality_tls(&private))
        } else {
            (certificate_config(), certificate_tls())
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = record_server(listener, config, b"\x00\x00pong".to_vec());
        let client = vless(port, tls, "");
        let mut stream = client
            .connect(&Target::Domain("example.com".to_string(), 80))
            .await
            .expect("connect");
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        let mut pong = [0u8; 4];
        stream.read_exact(&mut pong).await.unwrap();
        stream.write_all(b"second").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
        let records: Vec<Vec<u8>> = server.await.unwrap().into_iter().map(|r| r.1).collect();
        let mut first = expected_head(false, "example.com", 80);
        first.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(records, vec![first, b"second".to_vec()], "{label}");

        let (config, tls) = if reality {
            (reality_config(private), reality_tls(&private))
        } else {
            (certificate_config(), certificate_tls())
        };
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = record_server(listener, config, b"\x00\x00220 ".to_vec());
        let client = vless(port, tls, "");
        let mut stream = client
            .connect(&Target::Domain("example.com".to_string(), 22))
            .await
            .expect("connect");
        let mut banner = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut banner))
            .await
            .expect("the head goes out without a payload")
            .unwrap();
        stream.write_all(b"SSH-2.0-x\r\n").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
        let records = server.await.unwrap();
        assert!(records[0].0 >= Duration::from_millis(450), "{label}");
        let records: Vec<Vec<u8>> = records.into_iter().map(|r| r.1).collect();
        assert_eq!(
            records,
            vec![
                expected_head(false, "example.com", 22),
                b"SSH-2.0-x\r\n".to_vec()
            ],
            "{label}"
        );
    }
}

// ---- the references as the server ----

async fn spawn_tcp_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

/// A destination that talks first, like SSH or SMTP: a banner on accept, then
/// an echo.
async fn spawn_banner() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind banner");
    let addr = listener.local_addr().expect("banner addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                if stream.write_all(b"220 banner\r\n").await.is_err() {
                    return;
                }
                let (mut rd, mut wr) = stream.split();
                let _ = tokio::io::copy(&mut rd, &mut wr).await;
            });
        }
    });
    addr
}

async fn spawn_udp_echo() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
    let addr = socket.local_addr().expect("udp echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 65536];
        loop {
            let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                return;
            };
            let _ = socket.send_to(&buf[..n], from).await;
        }
    });
    addr
}

async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.expect("connect inbound");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [5, 0]);
    let IpAddr::V4(v4) = target.ip() else {
        panic!("expected a v4 target");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[1], 0, "CONNECT must succeed");
    stream
}

/// A small echo, then 1 MB both ways at once.
async fn tcp_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    let mut stream = socks_connect(proxy, echo).await;
    stream.write_all(b"roundtrip").await.expect("write");
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"roundtrip", "{label}: payload must echo");

    let payload: Vec<u8> = (0..1_000_000u32).map(|i| (i * 7 + i / 251) as u8).collect();
    let (mut rd, mut wr) = stream.into_split();
    let sent = payload.clone();
    let writer = tokio::spawn(async move { wr.write_all(&sent).await.map(|_| wr) });
    let mut echoed = vec![0u8; payload.len()];
    rd.read_exact(&mut echoed).await.expect("bulk read");
    let _ = writer.await;
    assert!(echoed == payload, "{label}: bulk payload must echo intact");
}

/// The destination speaks first; nothing is written until its banner is in.
async fn banner_roundtrip(proxy: SocketAddr, banner: SocketAddr, label: &str) {
    let mut stream = socks_connect(proxy, banner).await;
    let started = Instant::now();
    let mut buf = [0u8; 12];
    stream.read_exact(&mut buf).await.expect("banner read");
    assert_eq!(&buf, b"220 banner\r\n", "{label}: the banner");
    eprintln!("{label}: banner after {:?}", started.elapsed());
    stream.write_all(b"HELO x\r\n").await.expect("write");
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"HELO x\r\n", "{label}: echo after the banner");
}

/// SOCKS5 UDP ASSOCIATE, two datagrams there and back.
async fn udp_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    let mut control = TcpStream::connect(proxy).await.expect("connect inbound");
    control.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut auth = [0u8; 2];
    control.read_exact(&mut auth).await.expect("auth reply");
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .expect("associate");
    let mut reply = [0u8; 10];
    control
        .read_exact(&mut reply)
        .await
        .expect("associate reply");
    assert_eq!(reply[1], 0, "{label}: associate refused");
    let relay = SocketAddr::new(
        IpAddr::V4(Ipv4Addr::new(reply[4], reply[5], reply[6], reply[7])),
        u16::from_be_bytes([reply[8], reply[9]]),
    );
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let IpAddr::V4(v4) = echo.ip() else {
        panic!("expected v4 echo addr");
    };
    for payload in [&b"first datagram"[..], &[0x42u8; 1200][..]] {
        let mut datagram = vec![0, 0, 0, 1];
        datagram.extend_from_slice(&v4.octets());
        datagram.extend_from_slice(&echo.port().to_be_bytes());
        datagram.extend_from_slice(payload);
        socket.send_to(&datagram, relay).await.expect("send");
        let mut buf = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), socket.recv(&mut buf))
            .await
            .unwrap_or_else(|_| panic!("{label}: no udp answer"))
            .expect("recv");
        assert_eq!(&buf[10..n], payload, "{label}: datagram must echo");
    }
    drop(control);
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("probe addr")
        .port()
}

async fn wait_listening(port: u16) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

struct RefServer(Child);

impl Drop for RefServer {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_ref(bin: &str, config: &Value) -> RefServer {
    let path = std::env::temp_dir().join(format!(
        "xrust-vless-first-{}-{}.json",
        std::process::id(),
        free_port()
    ));
    std::fs::write(&path, serde_json::to_string(config).expect("config")).expect("write");
    let child = Command::new(bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn the reference");
    RefServer(child)
}

async fn start_client(outbound: Value) -> (core_runtime::BoxInstance, SocketAddr) {
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [
            {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 0}
        ],
        "outbounds": [outbound],
        "route": {"final": "up"}
    }))
    .await
    .expect("start xrust");
    let proxy = instance.inbound_addrs()[0].1;
    (instance, proxy)
}

struct Echoes {
    tcp: SocketAddr,
    banner: SocketAddr,
    udp: SocketAddr,
}

async fn echoes() -> Echoes {
    Echoes {
        tcp: spawn_tcp_echo().await,
        banner: spawn_banner().await,
        udp: spawn_udp_echo().await,
    }
}

/// Every exchange through our client against a server already listening.
async fn exercise(outbound: Value, echoes: &Echoes, label: &str, udp: bool) {
    core_config::check_str(&json!({"outbounds": [outbound.clone()]}).to_string())
        .unwrap_or_else(|e| panic!("{label}: check refuses the client: {e}"));
    let (instance, proxy) = start_client(outbound).await;
    let within = |what: &'static str| {
        let label = label.to_string();
        move |_| panic!("{label}: {what} timed out")
    };
    tokio::time::timeout(
        Duration::from_secs(30),
        tcp_roundtrip(proxy, echoes.tcp, label),
    )
    .await
    .unwrap_or_else(within("tcp"));
    tokio::time::timeout(
        Duration::from_secs(10),
        banner_roundtrip(proxy, echoes.banner, label),
    )
    .await
    .unwrap_or_else(within("server-first"));
    if udp {
        tokio::time::timeout(
            Duration::from_secs(20),
            udp_roundtrip(proxy, echoes.udp, label),
        )
        .await
        .unwrap_or_else(within("udp"));
    }
    instance.shutdown();
    eprintln!("{label}: pass");
}

fn xray_tls() -> Value {
    let certs = certs_dir();
    json!({"serverName": "localhost", "alpn": ["h2", "http/1.1"], "certificates": [{
        "certificateFile": format!("{certs}/localhost.crt"),
        "keyFile": format!("{certs}/localhost.key")
    }]})
}

#[tokio::test]
async fn interop_with_xray_as_the_server() {
    let Some(bin) = std::env::var_os("XRAY_REF") else {
        return;
    };
    let bin = bin.to_string_lossy().into_owned();
    let echoes = echoes().await;
    let private = [21u8; 32];
    let chrome = json!({"enabled": true, "server_name": "localhost", "insecure": true,
        "utls": {"enabled": true, "fingerprint": "chrome"}});
    let reality = json!({"enabled": true, "server_name": "localhost",
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": reality_public(&private), "short_id": SHORT_ID}});
    let allow = json!([{"protocol": "freedom",
        "settings": {"finalRules": [{"action": "allow"}]}}]);

    // label, flow, server streamSettings, client tls, client transport
    let mut cases: Vec<(String, &str, Value, Value, Option<Value>)> = Vec::new();
    for flow in ["xtls-rprx-vision", ""] {
        cases.push((
            format!("reality flow={flow:?}"),
            flow,
            json!({"network": "raw", "security": "reality", "realitySettings": {
                "dest": "127.0.0.1:DECOY", "serverNames": ["localhost"],
                "privateKey": reality_private(&private), "shortIds": [SHORT_ID]}}),
            reality.clone(),
            None,
        ));
    }
    cases.push((
        "tls flow=\"xtls-rprx-vision\"".to_string(),
        "xtls-rprx-vision",
        json!({"network": "raw", "security": "tls", "tlsSettings": xray_tls()}),
        chrome.clone(),
        None,
    ));
    cases.push((
        "ws+tls".to_string(),
        "",
        // the server offers h2 too: a client that asks for it gets it and
        // the upgrade request fails, so ours asks for http/1.1 only
        json!({"network": "ws", "security": "tls", "tlsSettings": xray_tls(),
            "wsSettings": {"path": "/ws"}}),
        chrome.clone(),
        Some(json!({"type": "ws", "path": "/ws"})),
    ));
    cases.push((
        "httpupgrade+tls".to_string(),
        "",
        json!({"network": "httpupgrade", "security": "tls", "tlsSettings": xray_tls(),
            "httpupgradeSettings": {"path": "/up"}}),
        chrome.clone(),
        Some(json!({"type": "httpupgrade", "path": "/up"})),
    ));
    cases.push((
        "grpc+tls".to_string(),
        "",
        json!({"network": "grpc", "security": "tls", "tlsSettings": xray_tls(),
            "grpcSettings": {"serviceName": "svc"}}),
        chrome.clone(),
        Some(json!({"type": "grpc", "service_name": "svc"})),
    ));
    for mode in ["packet-up", "stream-up", "stream-one"] {
        for (security, client_tls) in [("tls", chrome.clone()), ("reality", reality.clone())] {
            let mut stream = json!({"network": "xhttp", "security": security,
                "xhttpSettings": {"path": "/xh", "mode": mode}});
            if security == "tls" {
                stream["tlsSettings"] = xray_tls();
            } else {
                stream["realitySettings"] = json!({
                    "dest": "127.0.0.1:DECOY", "serverNames": ["localhost"],
                    "privateKey": reality_private(&private), "shortIds": [SHORT_ID]});
            }
            cases.push((
                format!("xhttp {mode}+{security}"),
                "",
                stream,
                client_tls,
                Some(json!({"type": "xhttp", "path": "/xh", "mode": mode})),
            ));
        }
    }

    // packet-up with the Xray 26 extras a provider's nodes carry: the
    // session in a header, uploads as GET with the data in headers, padding
    // in obfs mode, sized and paced uploads
    for (label, xray_extra, ours) in [
        (
            "session in a header",
            json!({"sessionIDPlacement": "header"}),
            json!({"session_placement": "header"}),
        ),
        (
            "GET uploads",
            json!({"uplinkHTTPMethod": "GET"}),
            json!({"uplink_http_method": "GET"}),
        ),
        (
            "all extras",
            json!({"uplinkHTTPMethod": "GET", "sessionIDPlacement": "header",
                "xPaddingObfsMode": true, "scMaxEachPostBytes": 32768,
                "scMinPostsIntervalMs": 30}),
            json!({"uplink_http_method": "GET", "session_placement": "header",
                "x_padding_obfs_mode": true, "sc_max_each_post_bytes": "32768",
                "sc_min_posts_interval_ms": "30"}),
        ),
    ] {
        let mut settings = json!({"path": "/xh", "mode": "packet-up"});
        let mut transport = json!({"type": "xhttp", "path": "/xh", "mode": "packet-up"});
        for (k, v) in xray_extra.as_object().unwrap() {
            settings[k] = v.clone();
        }
        for (k, v) in ours.as_object().unwrap() {
            transport[k] = v.clone();
        }
        cases.push((
            format!("xhttp packet-up+tls, {label}"),
            "",
            json!({"network": "xhttp", "security": "tls", "tlsSettings": xray_tls(),
                "xhttpSettings": settings}),
            chrome.clone(),
            Some(transport),
        ));
    }

    for (label, flow, mut stream, client_tls, transport) in cases {
        let port = free_port();
        let decoy = free_port();
        if let Some(settings) = stream.get_mut("realitySettings") {
            settings["dest"] = json!(format!("127.0.0.1:{decoy}"));
        }
        let mut client = json!({"id": UUID_TEXT});
        if !flow.is_empty() {
            client["flow"] = json!(flow);
        }
        let _server = start_ref(
            &bin,
            &json!({
                "log": {"loglevel": "none"},
                "inbounds": [
                    {"listen": "127.0.0.1", "port": port, "protocol": "vless",
                     "settings": {"clients": [client], "decryption": "none"},
                     "streamSettings": stream},
                    // the site REALITY borrows its handshake from
                    {"listen": "127.0.0.1", "port": decoy, "protocol": "vless",
                     "settings": {"clients": [{"id": UUID_TEXT}], "decryption": "none"},
                     "streamSettings": {"security": "tls", "tlsSettings": xray_tls()}}
                ],
                "outbounds": allow.clone()
            }),
        );
        assert!(wait_listening(port).await, "{label}: xray did not start");
        let mut outbound = json!({"type": "vless", "tag": "up", "server": "127.0.0.1",
            "server_port": port, "uuid": UUID_TEXT, "tls": client_tls});
        if !flow.is_empty() {
            outbound["flow"] = json!(flow);
        }
        if let Some(transport) = transport {
            outbound["transport"] = transport;
        }
        exercise(outbound, &echoes, &format!("xray {label}"), true).await;
    }
}

#[tokio::test]
async fn interop_with_sing_box_as_the_server() {
    let Some(bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    let bin = bin.to_string_lossy().into_owned();
    let echoes = echoes().await;
    let private = [23u8; 32];
    let cert_tls = json!({"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM});
    let chrome = json!({"enabled": true, "server_name": "localhost", "insecure": true,
        "utls": {"enabled": true, "fingerprint": "chrome"}});
    let ws = json!({"type": "ws", "path": "/ws"});
    let grpc = json!({"type": "grpc", "service_name": "svc"});
    // label, flow, server tls (None: REALITY), client tls, transport
    type Case<'a> = (&'a str, &'a str, Option<Value>, Value, Option<Value>);
    let cases: Vec<Case> = vec![
        (
            "reality vision",
            "xtls-rprx-vision",
            None,
            Value::Null,
            None,
        ),
        ("reality", "", None, Value::Null, None),
        (
            "tls vision",
            "xtls-rprx-vision",
            Some(cert_tls.clone()),
            chrome.clone(),
            None,
        ),
        ("tls", "", Some(cert_tls.clone()), chrome.clone(), None),
        (
            "ws+tls",
            "",
            Some(cert_tls.clone()),
            chrome.clone(),
            Some(ws),
        ),
        (
            "grpc+tls",
            "",
            Some(cert_tls.clone()),
            chrome.clone(),
            Some(grpc),
        ),
    ];
    for (label, flow, server_tls, client_tls, transport) in cases {
        let port = free_port();
        let decoy = free_port();
        let mut inbounds = Vec::new();
        let (server_tls, client_tls) = match server_tls {
            Some(tls) => (tls, client_tls),
            None => {
                inbounds.push(
                    json!({"type": "http", "tag": "decoy", "listen": "127.0.0.1",
                    "listen_port": decoy, "tls": cert_tls.clone()}),
                );
                (
                    json!({"enabled": true, "server_name": "localhost",
                        "reality": {"enabled": true, "private_key": reality_private(&private),
                            "short_id": [SHORT_ID],
                            "handshake": {"server": "127.0.0.1", "server_port": decoy}}}),
                    json!({"enabled": true, "server_name": "localhost",
                        "utls": {"enabled": true, "fingerprint": "chrome"},
                        "reality": {"enabled": true, "public_key": reality_public(&private),
                            "short_id": SHORT_ID}}),
                )
            }
        };
        let mut inbound = json!({"type": "vless", "tag": "in", "listen": "127.0.0.1",
            "listen_port": port, "users": [{"uuid": UUID_TEXT, "flow": flow}],
            "tls": server_tls});
        let mut outbound = json!({"type": "vless", "tag": "up", "server": "127.0.0.1",
            "server_port": port, "uuid": UUID_TEXT, "tls": client_tls});
        if !flow.is_empty() {
            outbound["flow"] = json!(flow);
        }
        if let Some(transport) = transport {
            inbound["transport"] = transport.clone();
            outbound["transport"] = transport;
        }
        inbounds.push(inbound);
        let _server = start_ref(
            &bin,
            &json!({
                "log": {"level": "error"},
                "inbounds": inbounds,
                "outbounds": [{"type": "direct", "tag": "direct"}]
            }),
        );
        assert!(
            wait_listening(port).await,
            "{label}: sing-box did not start"
        );
        exercise(outbound, &echoes, &format!("sing-box {label}"), true).await;
    }
}

// ---- what the hello offers ----

/// The ALPN protocols a ClientHello offers.
fn hello_alpn(hello: &[u8]) -> Vec<String> {
    // record header, handshake header, version, random
    let mut at = 5 + 4 + 2 + 32;
    at += 1 + hello[at] as usize;
    at += 2 + u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
    at += 1 + hello[at] as usize;
    let end = at + 2 + u16::from_be_bytes([hello[at], hello[at + 1]]) as usize;
    at += 2;
    while at + 4 <= end {
        let kind = u16::from_be_bytes([hello[at], hello[at + 1]]);
        let len = u16::from_be_bytes([hello[at + 2], hello[at + 3]]) as usize;
        let body = &hello[at + 4..at + 4 + len];
        if kind == 16 {
            let mut names = Vec::new();
            let mut i = 2;
            while i < body.len() {
                let n = body[i] as usize;
                names.push(String::from_utf8_lossy(&body[i + 1..i + 1 + n]).into_owned());
                i += 1 + n;
            }
            return names;
        }
        at += 4 + len;
    }
    Vec::new()
}

/// The ClientHello our client sends for an outbound, read off a listener
/// that never answers.
async fn first_hello(outbound: Value) -> Vec<u8> {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let mut outbound = outbound;
    outbound["server_port"] = json!(port);
    let vless =
        core_runtime::outbound::secure::Vless::build(outbound.as_object().unwrap(), "up").unwrap();
    let dial = tokio::spawn(async move {
        let _ = tokio::time::timeout(
            Duration::from_secs(2),
            vless.connect(&Target::Domain("example.com".to_string(), 443)),
        )
        .await;
    });
    let (mut socket, _) = listener.accept().await.unwrap();
    let mut head = [0u8; 5];
    socket.read_exact(&mut head).await.unwrap();
    let mut hello = head.to_vec();
    hello.resize(5 + u16::from_be_bytes([head[3], head[4]]) as usize, 0);
    socket.read_exact(&mut hello[5..]).await.unwrap();
    drop(socket);
    let _ = dial.await;
    hello
}

/// ws and httpupgrade over TLS offer `http/1.1` alone when the config names
/// no ALPN, as sing-box and Xray do; gRPC keeps `h2`, plain TLS the
/// fingerprint's own pair, and a configured ALPN wins.
#[tokio::test]
async fn upgrade_transports_offer_http1_alone() {
    let tls = json!({"enabled": true, "server_name": "localhost", "insecure": true,
        "utls": {"enabled": true, "fingerprint": "chrome"}});
    let cases = [
        (
            Some(json!({"type": "ws", "path": "/ws"})),
            None,
            vec!["http/1.1"],
        ),
        (
            Some(json!({"type": "ws", "path": "/ws", "max_early_data": 2048})),
            None,
            vec!["http/1.1"],
        ),
        (
            Some(json!({"type": "httpupgrade", "path": "/up"})),
            None,
            vec!["http/1.1"],
        ),
        (
            Some(json!({"type": "grpc", "service_name": "svc"})),
            None,
            vec!["h2"],
        ),
        (None, None, vec!["h2", "http/1.1"]),
        (
            Some(json!({"type": "ws", "path": "/ws"})),
            Some(json!(["h2", "http/1.1"])),
            vec!["h2", "http/1.1"],
        ),
    ];
    for (transport, alpn, want) in cases {
        for fingerprinted in [true, false] {
            let mut tls = tls.clone();
            if !fingerprinted {
                tls.as_object_mut().unwrap().remove("utls");
            }
            if let Some(alpn) = &alpn {
                tls["alpn"] = alpn.clone();
            }
            let mut outbound = json!({"type": "vless", "tag": "up", "server": "127.0.0.1",
                "server_port": 1, "uuid": UUID_TEXT, "tls": tls});
            if let Some(transport) = &transport {
                outbound["transport"] = transport.clone();
            }
            let hello = first_hello(outbound).await;
            let label = format!("{transport:?} alpn={alpn:?} utls={fingerprinted}");
            if !fingerprinted && transport.is_none() && alpn.is_none() {
                // rustls with nothing configured sends no ALPN at all
                assert!(hello_alpn(&hello).is_empty(), "{label}");
                continue;
            }
            assert_eq!(hello_alpn(&hello), want, "{label}");
        }
    }
}

// ---- the end of the upload ----

/// A local application that half-closes its upload: like Xray's client we do
/// not pass that on (no close_notify, no FIN), a response that comes after it
/// is still delivered, and the connection closes with close_notify once the
/// download has been quiet for the relay's idle limit (Xray's `downlinkOnly`,
/// 1 s), not at the half-close.
#[tokio::test]
async fn a_half_closed_upload_is_not_passed_on() {
    let private = [15u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut handshake = core_tls::server::Handshake::new(reality_config(private)).unwrap();
        handshake.run(&mut socket).await.expect("handshake");
        let (mut sealer, mut opener) = handshake.application.take().unwrap();
        let mut records = Vec::new();
        let mut first_at = None;
        loop {
            let mut head = [0u8; 5];
            let read = tokio::time::timeout(Duration::from_secs(5), socket.read_exact(&mut head));
            if !matches!(read.await, Ok(Ok(_))) {
                break;
            }
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            if socket.read_exact(&mut record[5..]).await.is_err() {
                break;
            }
            let Ok((kind, data)) = opener.open(&record) else {
                break;
            };
            let at = *first_at.get_or_insert_with(Instant::now);
            records.push((at.elapsed(), kind, data.to_vec()));
            if records.len() == 1 {
                let pong = sealer
                    .seal(ContentType::ApplicationData, b"\x00\x00pong")
                    .unwrap();
                socket.write_all(&pong).await.unwrap();
                // the answer's tail comes well after the client half-closed
                tokio::time::sleep(Duration::from_millis(300)).await;
                let late = sealer.seal(ContentType::ApplicationData, b"late").unwrap();
                socket.write_all(&late).await.unwrap();
            }
        }
        // whatever follows the last record: the FIN
        let mut rest = Vec::new();
        let _ = socket.read_to_end(&mut rest).await;
        (records, first_at.map(|at| at.elapsed()))
    });
    let (instance, proxy) = start_client(json!({
        "type": "vless", "tag": "up", "server": "127.0.0.1", "server_port": port,
        "uuid": UUID_TEXT, "tls": reality_tls(&private)
    }))
    .await;
    let mut stream = socks_connect(proxy, "127.0.0.1:9".parse().unwrap()).await;
    stream.write_all(b"GET").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
        .await
        .expect("the session ends")
        .unwrap();
    assert_eq!(answer, b"ponglate", "the response after the half-close");
    let (records, closed_at) = server.await.unwrap();
    instance.shutdown();
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0].1, ContentType::ApplicationData);
    let (alert_at, kind, data) = &records[1];
    assert_eq!((kind, &data[..]), (&ContentType::Alert, &[1u8, 0][..]));
    // the half-close itself sent nothing: the alert comes a quiet second
    // after the late answer, not right after "GET"
    assert!(
        *alert_at >= Duration::from_millis(1200),
        "close_notify at {alert_at:?}"
    );
    assert!(closed_at.unwrap() >= *alert_at);
}
