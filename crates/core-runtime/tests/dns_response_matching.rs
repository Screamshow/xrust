//! Upstream DNS answers must answer the query that was sent: the same ID
//! (udp / tcp / tls) and the same question. Anything else is dropped, and the
//! caller gets its own ID back.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use core_runtime::dns::codec;
use core_runtime::dns::transport::{Dialer, ServerConfig, exchange};
use core_runtime::dns::{DnsService, QueryMeta};
use hickory_proto::op::Message;
use hickory_proto::rr::RecordType;
use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");
const REAL: Ipv4Addr = Ipv4Addr::new(203, 0, 113, 7);
const EVIL: Ipv4Addr = Ipv4Addr::new(6, 6, 6, 6);

#[derive(Clone, Copy, Debug)]
enum Forge {
    WrongId,
    OtherName,
    OtherType,
    OtherClass,
    NotReply,
}

const ALL_FORGES: [Forge; 5] = [
    Forge::WrongId,
    Forge::OtherName,
    Forge::OtherType,
    Forge::OtherClass,
    Forge::NotReply,
];

/// Offset just past the first question name.
fn name_end(msg: &[u8]) -> usize {
    let mut pos = 12;
    while msg[pos] != 0 {
        pos += 1 + msg[pos] as usize;
    }
    pos + 1
}

fn answer(raw_query: &[u8], ip: Ipv4Addr) -> Vec<u8> {
    let query = Message::from_vec(raw_query).expect("parse query");
    codec::synth_address(&query, ip.into(), 60).expect("encode answer")
}

/// A well-formed answer carrying EVIL that differs from the real reply in one way.
fn forged(raw_query: &[u8], kind: Forge) -> Vec<u8> {
    let mut evil = answer(raw_query, EVIL);
    let end = name_end(&evil);
    match kind {
        Forge::WrongId => {
            evil[0] ^= 0x12;
            evil[1] ^= 0x34;
        }
        // first letter of the name, still a lowercase letter
        Forge::OtherName => evil[13] ^= 0x01,
        Forge::OtherType => evil[end..end + 2].copy_from_slice(&28u16.to_be_bytes()),
        Forge::OtherClass => evil[end + 2..end + 4].copy_from_slice(&3u16.to_be_bytes()),
        Forge::NotReply => evil[2] &= !0x80,
    }
    evil
}

fn ips(raw: &[u8]) -> Vec<IpAddr> {
    codec::answer_ips(raw).expect("decode answer")
}

fn id_of(raw: &[u8]) -> u16 {
    u16::from_be_bytes([raw[0], raw[1]])
}

fn udp_client(port: u16, timeout: &str) -> ServerConfig {
    ServerConfig::build(
        &json!({"type": "udp", "tag": "up", "server": "127.0.0.1",
                "server_port": port, "timeout": timeout}),
        "dns.servers[0]",
    )
    .expect("udp server config")
}

fn tcp_client(port: u16, timeout: &str) -> ServerConfig {
    ServerConfig::build(
        &json!({"type": "tcp", "tag": "up", "server": "127.0.0.1",
                "server_port": port, "timeout": timeout}),
        "dns.servers[0]",
    )
    .expect("tcp server config")
}

type WireIds = Arc<Mutex<Vec<u16>>>;

/// A udp upstream that answers each query with `forges` first (from its own
/// address, as a spoofer would) and then, when `real`, the true answer.
async fn spawn_udp(forges: Vec<Forge>, real: bool) -> (SocketAddr, WireIds) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    let ids: WireIds = Arc::default();
    let seen = Arc::clone(&ids);
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let query = buf[..n].to_vec();
            seen.lock().unwrap().push(id_of(&query));
            for kind in &forges {
                let _ = sock.send_to(&forged(&query, *kind), from).await;
            }
            if real {
                let _ = sock.send_to(&answer(&query, REAL), from).await;
            }
        }
    });
    (addr, ids)
}

async fn udp_exchange(addr: SocketAddr, timeout: &str, query: &[u8]) -> std::io::Result<Vec<u8>> {
    let server = udp_client(addr.port(), timeout);
    exchange(&server, addr, query, &Dialer { router: None }).await
}

fn a_query(id: u16, name: &str) -> Vec<u8> {
    codec::build_query(id, name, RecordType::A).expect("build query")
}

#[tokio::test]
async fn udp_matching_answer_is_accepted_with_the_caller_id() {
    let (addr, _) = spawn_udp(Vec::new(), true).await;
    let raw = udp_exchange(addr, "2s", &a_query(0x4242, "ok.test"))
        .await
        .expect("exchange");
    assert_eq!(ips(&raw), vec![IpAddr::from(REAL)]);
    assert_eq!(id_of(&raw), 0x4242, "caller id restored");
}

#[tokio::test]
async fn udp_forged_reply_is_dropped_and_the_real_one_returned() {
    for kind in ALL_FORGES {
        let (addr, _) = spawn_udp(vec![kind], true).await;
        let raw = udp_exchange(addr, "2s", &a_query(0x4242, "victim.test"))
            .await
            .unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!(ips(&raw), vec![IpAddr::from(REAL)], "{kind:?} accepted");
        assert_eq!(id_of(&raw), 0x4242, "{kind:?}: caller id restored");
    }
    // all of them in one burst before the real answer
    let (addr, _) = spawn_udp(ALL_FORGES.to_vec(), true).await;
    let raw = udp_exchange(addr, "2s", &a_query(7, "victim.test"))
        .await
        .expect("exchange");
    assert_eq!(ips(&raw), vec![IpAddr::from(REAL)]);
}

#[tokio::test]
async fn udp_only_forged_replies_end_in_the_usual_timeout() {
    let mut tasks = tokio::task::JoinSet::new();
    for kind in ALL_FORGES {
        tasks.spawn(async move {
            let (addr, _) = spawn_udp(vec![kind], false).await;
            let started = Instant::now();
            let result = udp_exchange(addr, "800ms", &a_query(0x4242, "victim.test")).await;
            (kind, result, started.elapsed())
        });
    }
    while let Some(joined) = tasks.join_next().await {
        let (kind, result, elapsed) = joined.expect("task");
        let error = match result {
            Ok(raw) => panic!("{kind:?}: forged reply accepted: {:?}", ips(&raw)),
            Err(error) => error,
        };
        assert!(error.to_string().contains("timeout"), "{kind:?}: {error}");
        assert!(
            elapsed >= Duration::from_millis(700) && elapsed < Duration::from_secs(3),
            "{kind:?}: {elapsed:?}"
        );
    }
}

#[tokio::test]
async fn udp_question_name_case_does_not_matter() {
    // a reply that echoes the name in another case, as 0x20 servers do
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let mut reply = answer(&buf[..n], REAL);
            let end = name_end(&reply);
            reply[13..end].make_ascii_uppercase();
            let _ = sock.send_to(&reply, from).await;
        }
    });
    let raw = udp_exchange(addr, "2s", &a_query(1, "MiXeD.case.test"))
        .await
        .expect("exchange");
    assert_eq!(ips(&raw), vec![IpAddr::from(REAL)]);
}

#[tokio::test]
async fn udp_wire_ids_are_random_and_never_the_caller_id() {
    let (addr, wire_ids) = spawn_udp(Vec::new(), true).await;
    for _ in 0..8 {
        let raw = udp_exchange(addr, "2s", &a_query(0x4242, "id.test"))
            .await
            .expect("exchange");
        assert_eq!(id_of(&raw), 0x4242, "caller id restored");
    }
    let wire_ids = wire_ids.lock().unwrap().clone();
    assert_eq!(wire_ids.len(), 8);
    assert!(
        wire_ids.iter().any(|id| *id != 0x4242),
        "the caller id went to the wire: {wire_ids:?}"
    );
    let sequential = wire_ids.windows(2).all(|w| w[1] == w[0].wrapping_add(1));
    assert!(!sequential, "wire ids are sequential: {wire_ids:?}");
}

#[tokio::test]
async fn udp_parallel_queries_each_get_their_own_answer() {
    // the upstream first hands every query the previous query's answer
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        let mut previous: Option<Vec<u8>> = None;
        while let Ok((n, from)) = sock.recv_from(&mut buf).await {
            let query = Message::from_vec(&buf[..n]).expect("parse query");
            let name = query.queries[0].name().to_string();
            let index: u8 = name
                .trim_start_matches("host")
                .split('.')
                .next()
                .and_then(|i| i.parse().ok())
                .expect("host index");
            let reply = codec::synth_address(&query, Ipv4Addr::new(10, 0, 0, index).into(), 60)
                .expect("encode answer");
            if let Some(other) = &previous {
                let _ = sock.send_to(other, from).await;
            }
            let _ = sock.send_to(&reply, from).await;
            previous = Some(reply);
        }
    });
    let server = Arc::new(udp_client(addr.port(), "3s"));
    let mut tasks = tokio::task::JoinSet::new();
    for index in 1..=16u8 {
        let server = Arc::clone(&server);
        tasks.spawn(async move {
            let query = a_query(1000 + u16::from(index), &format!("host{index}.test"));
            let raw = exchange(&server, addr, &query, &Dialer { router: None })
                .await
                .expect("exchange");
            (index, raw)
        });
    }
    while let Some(joined) = tasks.join_next().await {
        let (index, raw) = joined.expect("task");
        assert_eq!(
            ips(&raw),
            vec![IpAddr::from(Ipv4Addr::new(10, 0, 0, index))],
            "host{index} got another query's answer"
        );
        assert_eq!(id_of(&raw), 1000 + u16::from(index));
    }
}

#[tokio::test]
async fn service_restores_the_client_id_after_a_forged_reply() {
    let (addr, wire_ids) = spawn_udp(vec![Forge::WrongId, Forge::OtherName], true).await;
    let svc: Arc<DnsService> = DnsService::build(&json!({"dns": {
        "servers": [{"type": "udp", "tag": "up", "server": "127.0.0.1", "server_port": addr.port()}],
        "final": "up"
    }}))
    .expect("dns builds")
    .expect("dns present");
    let raw = svc
        .exchange(&QueryMeta::default(), &a_query(0x5151, "svc.test"), true)
        .await
        .expect("exchange");
    assert_eq!(ips(&raw), vec![IpAddr::from(REAL)]);
    assert_eq!(id_of(&raw), 0x5151);
    // the cached answer is the real one as well
    let cached = svc
        .exchange(&QueryMeta::default(), &a_query(0x5152, "svc.test"), true)
        .await
        .expect("cached exchange");
    assert_eq!(ips(&cached), vec![IpAddr::from(REAL)]);
    assert_eq!(id_of(&cached), 0x5152);
    assert_eq!(wire_ids.lock().unwrap().len(), 1, "one upstream query");
}

async fn read_framed(stream: &mut (impl AsyncReadExt + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

fn framed(msg: &[u8]) -> Vec<u8> {
    let mut out = (msg.len() as u16).to_be_bytes().to_vec();
    out.extend_from_slice(msg);
    out
}

/// A tcp upstream that writes `forges` and then, when `real`, the true answer
/// on the same connection, and keeps it open.
async fn spawn_tcp(forges: Vec<Forge>, real: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("tcp addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let forges = forges.clone();
            tokio::spawn(async move {
                let Ok(query) = read_framed(&mut stream).await else {
                    return;
                };
                for kind in forges {
                    let _ = stream.write_all(&framed(&forged(&query, kind))).await;
                }
                if real {
                    let _ = stream.write_all(&framed(&answer(&query, REAL))).await;
                }
                let mut rest = [0u8; 64];
                let _ = stream.read(&mut rest).await;
            });
        }
    });
    addr
}

#[tokio::test]
async fn tcp_forged_messages_are_skipped() {
    let addr = spawn_tcp(ALL_FORGES.to_vec(), true).await;
    let server = tcp_client(addr.port(), "2s");
    let raw = exchange(
        &server,
        addr,
        &a_query(0x4242, "tcp.test"),
        &Dialer { router: None },
    )
    .await
    .expect("exchange");
    assert_eq!(ips(&raw), vec![IpAddr::from(REAL)]);
    assert_eq!(id_of(&raw), 0x4242);
}

#[tokio::test]
async fn tcp_only_forged_messages_end_in_the_usual_timeout() {
    let addr = spawn_tcp(ALL_FORGES.to_vec(), false).await;
    let server = tcp_client(addr.port(), "800ms");
    let started = Instant::now();
    let error = exchange(
        &server,
        addr,
        &a_query(0x4242, "tcp.test"),
        &Dialer { router: None },
    )
    .await
    .expect_err("forged answer accepted");
    assert!(error.to_string().contains("timeout"), "{error}");
    assert!(started.elapsed() >= Duration::from_millis(700));
}

fn tls_acceptor() -> tokio_rustls::TlsAcceptor {
    core_tls::install_default_provider();
    let certs: Vec<_> = rustls_pemfile::certs(&mut CERT_PEM.as_bytes())
        .collect::<Result<_, _>>()
        .expect("parse cert");
    let key = rustls_pemfile::private_key(&mut KEY_PEM.as_bytes())
        .expect("key read")
        .expect("key present");
    let cfg = core_tls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert");
    tokio_rustls::TlsAcceptor::from(Arc::new(cfg))
}

/// DoH over HTTP/1.1 (no ALPN offered back): answers with `forge` when set.
async fn spawn_doh_h1(forge: Option<Forge>, wire_ids: WireIds) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind doh");
    let addr = listener.local_addr().expect("doh addr");
    let acceptor = tls_acceptor();
    tokio::spawn(async move {
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let wire_ids = Arc::clone(&wire_ids);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut raw = Vec::new();
                let mut tmp = [0u8; 4096];
                let head_end = loop {
                    let Ok(n) = stream.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&tmp[..n]);
                    if let Some(pos) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
                        break pos + 4;
                    }
                };
                let head = String::from_utf8_lossy(&raw[..head_end]).to_lowercase();
                let len: usize = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|v| v.trim().parse().ok())
                    .expect("content-length");
                while raw.len() < head_end + len {
                    let Ok(n) = stream.read(&mut tmp).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    raw.extend_from_slice(&tmp[..n]);
                }
                let query = raw[head_end..head_end + len].to_vec();
                wire_ids.lock().unwrap().push(id_of(&query));
                let body = match forge {
                    Some(kind) => forged(&query, kind),
                    None => answer(&query, REAL),
                };
                let mut reply = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                )
                .into_bytes();
                reply.extend_from_slice(&body);
                let _ = stream.write_all(&reply).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    addr
}

fn doh_client(port: u16) -> ServerConfig {
    ServerConfig::build(
        &json!({"type": "https", "tag": "doh", "server": "127.0.0.1", "server_port": port,
                "timeout": "3s",
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}}),
        "dns.servers[0]",
    )
    .expect("doh server config")
}

#[tokio::test]
async fn doh_answer_must_match_the_question() {
    let wire_ids: WireIds = Arc::default();
    let addr = spawn_doh_h1(None, Arc::clone(&wire_ids)).await;
    let raw = exchange(
        &doh_client(addr.port()),
        addr,
        &a_query(0x4242, "doh.test"),
        &Dialer { router: None },
    )
    .await
    .expect("matching DoH answer");
    assert_eq!(ips(&raw), vec![IpAddr::from(REAL)]);
    assert_eq!(id_of(&raw), 0x4242, "caller id restored");
    assert_eq!(wire_ids.lock().unwrap().as_slice(), &[0], "DoH sends ID 0");

    for kind in [
        Forge::OtherName,
        Forge::OtherType,
        Forge::OtherClass,
        Forge::NotReply,
    ] {
        let addr = spawn_doh_h1(Some(kind), Arc::default()).await;
        let error = exchange(
            &doh_client(addr.port()),
            addr,
            &a_query(0x4242, "doh.test"),
            &Dialer { router: None },
        )
        .await
        .expect_err("forged DoH answer accepted");
        assert!(
            error.to_string().contains("does not match"),
            "{kind:?}: {error}"
        );
    }
}
