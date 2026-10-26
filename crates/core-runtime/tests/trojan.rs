//! The trojan client end to end.
//!
//! - Against a minimal trojan server written here (TLS by rustls): TCP and UDP
//!   through the client's mixed inbound, always on.
//! - Against our own TLS server with REALITY, which opens every record on its
//!   own: what the first application-data record carries.
//! - Against the reference sing-box as the trojan server when `SING_BOX_REF`
//!   names its binary: plain TLS, uTLS, REALITY, ws and gRPC, TCP and UDP.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use core_runtime::inbound::Target;
use core_tls::record::ContentType;
use serde_json::{Value, json};
use sha2::Digest;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");
const PASSWORD: &str = "trojan-secret";

fn key(password: &str) -> String {
    sha2::Sha224::digest(password.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

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

/// SOCKS5 CONNECT through the mixed inbound, then a small and a bulk echo.
async fn tcp_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    let mut stream = TcpStream::connect(proxy).await.expect("connect inbound");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [5, 0]);
    let IpAddr::V4(v4) = echo.ip() else {
        panic!("expected v4 echo addr");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[1], 0, "{label}: CONNECT must succeed");

    stream.write_all(b"roundtrip").await.expect("write");
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"roundtrip", "{label}: payload must echo");

    let payload: Vec<u8> = (0..100_000u32).map(|i| (i * 7) as u8).collect();
    let (mut rd, mut wr) = stream.into_split();
    let sent = payload.clone();
    let writer = tokio::spawn(async move { wr.write_all(&sent).await.map(|_| wr) });
    let mut echoed = vec![0u8; payload.len()];
    rd.read_exact(&mut echoed).await.expect("bulk read");
    let _ = writer.await;
    assert!(echoed == payload, "{label}: bulk payload must echo");
}

/// SOCKS5 UDP ASSOCIATE through the mixed inbound, two datagrams there and back.
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
    for payload in [&b"first datagram"[..], &[0x42u8; 1400][..]] {
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

async fn read_socksaddr<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<SocketAddr> {
    let family = stream.read_u8().await?;
    let ip: IpAddr = match family {
        1 => {
            let mut o = [0u8; 4];
            stream.read_exact(&mut o).await?;
            o.into()
        }
        4 => {
            let mut o = [0u8; 16];
            stream.read_exact(&mut o).await?;
            o.into()
        }
        3 => {
            let len = stream.read_u8().await?;
            let mut name = vec![0u8; len.into()];
            stream.read_exact(&mut name).await?;
            assert_eq!(name, b"localhost", "the only name this server resolves");
            Ipv4Addr::LOCALHOST.into()
        }
        other => panic!("address family {other}"),
    };
    let port = stream.read_u16().await?;
    Ok(SocketAddr::new(ip, port))
}

fn socksaddr(addr: SocketAddr) -> Vec<u8> {
    let mut out = Vec::new();
    match addr.ip() {
        IpAddr::V4(v4) => {
            out.push(1);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(4);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&addr.port().to_be_bytes());
    out
}

/// A trojan server as small as the protocol allows, over rustls.
async fn spawn_trojan_server() -> SocketAddr {
    let cert = rustls_pemfile::certs(&mut CERT_PEM.as_bytes())
        .next()
        .unwrap()
        .unwrap();
    let key_der = rustls_pemfile::private_key(&mut KEY_PEM.as_bytes())
        .unwrap()
        .unwrap();
    let config =
        core_tls::rustls::ServerConfig::builder_with_provider(Arc::new(core_crypto::provider()))
            .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key_der)
            .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let want = key(PASSWORD);
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            let want = want.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let mut head = [0u8; 56 + 2 + 1];
                if tls.read_exact(&mut head).await.is_err() {
                    return;
                }
                assert_eq!(&head[..56], want.as_bytes(), "password key");
                assert_eq!(&head[56..58], b"\r\n");
                let command = head[58];
                let Ok(target) = read_socksaddr(&mut tls).await else {
                    return;
                };
                let mut crlf = [0u8; 2];
                if tls.read_exact(&mut crlf).await.is_err() {
                    return;
                }
                assert_eq!(&crlf, b"\r\n");
                match command {
                    1 => {
                        let Ok(mut upstream) = TcpStream::connect(target).await else {
                            return;
                        };
                        let _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream).await;
                    }
                    3 => {
                        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
                        let (mut rd, mut wr) = tokio::io::split(tls);
                        let back = Arc::clone(&udp);
                        tokio::spawn(async move {
                            let mut buf = vec![0u8; 65536];
                            while let Ok((n, from)) = back.recv_from(&mut buf).await {
                                let mut packet = socksaddr(from);
                                packet.extend_from_slice(&(n as u16).to_be_bytes());
                                packet.extend_from_slice(b"\r\n");
                                packet.extend_from_slice(&buf[..n]);
                                if wr.write_all(&packet).await.is_err() {
                                    return;
                                }
                            }
                        });
                        loop {
                            let Ok(dest) = read_socksaddr(&mut rd).await else {
                                return;
                            };
                            let Ok(len) = rd.read_u16().await else {
                                return;
                            };
                            let mut crlf = [0u8; 2];
                            if rd.read_exact(&mut crlf).await.is_err() {
                                return;
                            }
                            assert_eq!(&crlf, b"\r\n");
                            let mut payload = vec![0u8; len.into()];
                            if rd.read_exact(&mut payload).await.is_err() {
                                return;
                            }
                            let _ = udp.send_to(&payload, dest).await;
                        }
                    }
                    other => panic!("trojan command {other}"),
                }
            });
        }
    });
    addr
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

#[tokio::test]
async fn trojan_carries_tcp_and_udp_over_tls() {
    let server = spawn_trojan_server().await;
    let tcp_echo = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    for fingerprint in [None, Some("chrome")] {
        let mut tls = json!({"enabled": true, "server_name": "localhost", "insecure": true});
        if let Some(fingerprint) = fingerprint {
            tls["utls"] = json!({"enabled": true, "fingerprint": fingerprint});
        }
        let (instance, proxy) = start_client(json!({
            "type": "trojan", "tag": "up", "server": "127.0.0.1",
            "server_port": server.port(), "password": PASSWORD, "tls": tls
        }))
        .await;
        let label = format!("trojan, fingerprint {fingerprint:?}");
        tokio::time::timeout(
            Duration::from_secs(20),
            tcp_roundtrip(proxy, tcp_echo, &label),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: tcp timed out"));
        tokio::time::timeout(
            Duration::from_secs(20),
            udp_roundtrip(proxy, udp_echo, &label),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: udp timed out"));
        instance.shutdown();
    }
}

// ---- what the first record carries ----

const SHORT_ID: &str = "1234abcd";

fn reality_public(private: &[u8; 32]) -> String {
    let secret = x25519_dalek::StaticSecret::from(*private);
    let public = x25519_dalek::PublicKey::from(&secret);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes())
}

/// Our REALITY server, opening one record at a time: returns the plaintext of
/// each application-data record, in order. Answers the first with `pong`.
fn record_server(
    listener: TcpListener,
    private: [u8; 32],
) -> tokio::task::JoinHandle<Vec<Vec<u8>>> {
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut handshake = core_tls::server::Handshake::new(core_tls::server::Config {
            chain: Vec::new(),
            key: None,
            alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
            cipher_suites: Vec::new(),
            reality: Some(core_tls::server::ServerReality {
                private_key: private,
                short_ids: vec![vec![0x12, 0x34, 0xab, 0xcd]],
                max_time_difference: Some(600),
            }),
        })
        .unwrap();
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
            if kind == ContentType::ApplicationData && !data.is_empty() {
                if records.is_empty() {
                    let pong = sealer.seal(ContentType::ApplicationData, b"pong").unwrap();
                    let _ = socket.write_all(&pong).await;
                }
                records.push(data.to_vec());
            }
        }
        records
    })
}

fn reality_trojan(port: u16, private: &[u8; 32]) -> core_runtime::outbound::secure::Trojan {
    let outbound = json!({
        "type": "trojan", "tag": "up", "server": "127.0.0.1", "server_port": port,
        "password": PASSWORD,
        "tls": {
            "enabled": true, "server_name": "www.example.com",
            "utls": {"enabled": true, "fingerprint": "chrome"},
            "reality": {"enabled": true, "public_key": reality_public(private), "short_id": SHORT_ID}
        }
    });
    core_runtime::outbound::secure::Trojan::build(outbound.as_object().unwrap(), "up").unwrap()
}

fn expected_head(target: &Target) -> Vec<u8> {
    let mut head = key(PASSWORD).into_bytes();
    head.extend_from_slice(b"\r\n\x01");
    match target {
        Target::Domain(host, port) => {
            head.extend_from_slice(&[3, host.len() as u8]);
            head.extend_from_slice(host.as_bytes());
            head.extend_from_slice(&port.to_be_bytes());
        }
        Target::Ip(addr) => head.extend_from_slice(&socksaddr(*addr)),
    }
    head.extend_from_slice(b"\r\n");
    head
}

/// The head is not a record of its own when the client talks first: it shares
/// the first application-data record with the payload, as with both references.
#[tokio::test]
async fn the_first_record_carries_the_head_and_the_payload() {
    let private = [9u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = record_server(listener, private);
    let trojan = reality_trojan(port, &private);
    let target = Target::Domain("example.com".to_string(), 443);
    let mut stream = trojan.connect(&target).await.expect("connect");
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
    let mut first = expected_head(&target);
    first.extend_from_slice(hello);
    assert_eq!(records, vec![first, b"second".to_vec()]);
}

/// A destination that speaks first: the head goes alone after the short wait,
/// and the server's answer comes back.
#[tokio::test]
async fn a_silent_client_sends_the_head_alone_after_the_wait() {
    let private = [11u8; 32];
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = record_server(listener, private);
    let trojan = reality_trojan(port, &private);
    let target = Target::Ip("192.0.2.1:25".parse().unwrap());
    let mut stream = trojan.connect(&target).await.expect("connect");
    let started = std::time::Instant::now();
    let mut pong = [0u8; 4];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut pong))
        .await
        .expect("the head goes out without a payload")
        .unwrap();
    assert_eq!(&pong, b"pong");
    assert!(started.elapsed() >= Duration::from_millis(90));
    stream.write_all(b"EHLO\r\n").await.unwrap();
    stream.flush().await.unwrap();
    drop(stream);
    let records = server.await.unwrap();
    assert_eq!(records, vec![expected_head(&target), b"EHLO\r\n".to_vec()]);
}

// ---- the reference as the server ----

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
        "xrust-trojan-ref-{}-{}.json",
        std::process::id(),
        free_port()
    ));
    std::fs::write(&path, serde_json::to_string(config).expect("config")).expect("write");
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
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

fn ref_reality_keypair(ref_bin: &str) -> (String, String) {
    let out = Command::new(ref_bin)
        .args(["generate", "reality-keypair"])
        .output()
        .expect("generate reality-keypair");
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let field = |name: &str| {
        text.lines()
            .find_map(|l| l.strip_prefix(name))
            .expect("keypair line")
            .trim()
            .to_string()
    };
    (field("PrivateKey:"), field("PublicKey:"))
}

#[tokio::test]
async fn interop_trojan_with_the_reference_server() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    let ref_bin = ref_bin.to_string_lossy().to_string();
    let (private, public) = ref_reality_keypair(&ref_bin);
    let tcp_echo = spawn_tcp_echo().await;
    let udp_echo = spawn_udp_echo().await;
    let cert_tls = json!({"enabled": true, "certificate": CERT_PEM, "key": KEY_PEM});
    let plain = json!({"enabled": true, "server_name": "localhost", "insecure": true});
    let chrome = json!({"enabled": true, "server_name": "localhost", "insecure": true,
        "utls": {"enabled": true, "fingerprint": "chrome"}});
    let ws = json!({"type": "ws", "path": "/ws"});
    let ws_ed = json!({"type": "ws", "path": "/ws", "max_early_data": 2048,
        "early_data_header_name": "Sec-WebSocket-Protocol"});
    let grpc = json!({"type": "grpc", "service_name": "svc"});
    let httpupgrade = json!({"type": "httpupgrade", "path": "/up"});
    // label, server tls, client tls, transport
    let cases: Vec<(&str, Value, Value, Option<Value>)> = vec![
        ("tls", cert_tls.clone(), plain.clone(), None),
        ("utls chrome", cert_tls.clone(), chrome.clone(), None),
        ("ws+tls", cert_tls.clone(), chrome.clone(), Some(ws)),
        (
            "ws early data+tls",
            cert_tls.clone(),
            chrome.clone(),
            Some(ws_ed),
        ),
        ("grpc+tls", cert_tls.clone(), chrome.clone(), Some(grpc)),
        (
            "httpupgrade+tls",
            cert_tls.clone(),
            chrome.clone(),
            Some(httpupgrade),
        ),
        ("reality", Value::Null, Value::Null, None),
    ];
    for (label, server_tls, client_tls, transport) in cases {
        let port = free_port();
        let decoy_port = free_port();
        let (server_tls, client_tls, mut inbounds) = if label == "reality" {
            (
                json!({"enabled": true, "server_name": "localhost",
                    "reality": {"enabled": true, "private_key": private,
                        "short_id": [SHORT_ID],
                        "handshake": {"server": "127.0.0.1", "server_port": decoy_port}}}),
                json!({"enabled": true, "server_name": "localhost",
                    "utls": {"enabled": true, "fingerprint": "chrome"},
                    "reality": {"enabled": true, "public_key": public, "short_id": SHORT_ID}}),
                // the site REALITY borrows its handshake from
                vec![
                    json!({"type": "http", "tag": "decoy", "listen": "127.0.0.1",
                    "listen_port": decoy_port, "tls": cert_tls.clone()}),
                ],
            )
        } else {
            (server_tls, client_tls, Vec::new())
        };
        let mut inbound = json!({"type": "trojan", "tag": "in", "listen": "127.0.0.1",
            "listen_port": port, "users": [{"password": PASSWORD}], "tls": server_tls});
        let mut outbound = json!({"type": "trojan", "tag": "up", "server": "127.0.0.1",
            "server_port": port, "password": PASSWORD, "tls": client_tls});
        if let Some(transport) = transport {
            inbound["transport"] = transport.clone();
            outbound["transport"] = transport;
        }
        inbounds.push(inbound);
        let _server = start_ref(
            &ref_bin,
            &json!({
                "log": {"level": "error"},
                "inbounds": inbounds,
                "outbounds": [{"type": "direct", "tag": "direct"}]
            }),
        );
        assert!(
            wait_listening(port).await,
            "{label}: reference did not start"
        );
        core_config::check_str(&json!({"outbounds": [outbound.clone()]}).to_string())
            .unwrap_or_else(|e| panic!("{label}: check refuses the client: {e}"));
        let (instance, proxy) = start_client(outbound).await;
        let label = format!("trojan {label}");
        tokio::time::timeout(
            Duration::from_secs(20),
            tcp_roundtrip(proxy, tcp_echo, &label),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: tcp timed out"));
        tokio::time::timeout(
            Duration::from_secs(20),
            udp_roundtrip(proxy, udp_echo, &label),
        )
        .await
        .unwrap_or_else(|_| panic!("{label}: udp timed out"));
        instance.shutdown();
        eprintln!("{label}: tcp and udp pass");
    }
}
