//! DNS service integration tests: local udp/tcp/tls/h2 responders exercising
//! the rule walk, cache, fakeip, transports, `resolve` and `connect_tcp`.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use core_runtime::dns::{DnsService, QueryMeta};
use hickory_proto::op::Message;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const CERT_PEM: &str = include_str!("../../../tests/golden/certs/localhost.crt");
const KEY_PEM: &str = include_str!("../../../tests/golden/certs/localhost.key");
const ROUTER_MAIN: &str = include_str!("../../../tests/golden/live/router-main.json");

#[tokio::test]
async fn remote_ruleset_is_shared_with_dns_after_fetch() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = [0; 2048];
        let mut used = 0;
        loop {
            assert!(used < buf.len(), "HTTP request headers exceed test buffer");
            let count = stream.read(&mut buf[used..]).await.unwrap();
            assert!(count > 0, "HTTP request ended before headers were complete");
            used += count;
            if buf[..used].windows(4).any(|bytes| bytes == b"\r\n\r\n") {
                break;
            }
        }
        let body = r#"{"version":1,"rules":[{"domain_suffix":["remote.example"]}]}"#;
        stream
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let root = json!({"outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"final":"direct","rule_set":[{"type":"remote","tag":"remote","format":"source",
            "url":format!("http://{addr}/rules.json"),"download_detour":"direct"}]},
        "dns":{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15"},
            {"type":"hosts","tag":"real","path":[],"predefined":{"remote.example":["203.0.113.7"],"updated.example":["203.0.113.8"]}}],
            "rules":[{"rule_set":"remote","action":"route","server":"fake"}],"final":"real"}});
    let instance = core_runtime::start(&root).await.unwrap();
    server.await.unwrap();
    let dns = instance.dns().unwrap();
    let query = core_runtime::dns::codec::build_query(
        123,
        "remote.example",
        hickory_proto::rr::RecordType::A,
    )
    .unwrap();
    let raw = dns
        .exchange(&QueryMeta::default(), &query, true)
        .await
        .unwrap();
    assert!(
        core_runtime::dns::codec::answer_ips(&raw).unwrap()[0]
            .to_string()
            .starts_with("198.18.")
    );
    instance.shutdown();
}

#[tokio::test]
async fn udp_dns_connected_socket_with_and_without_router() {
    let (addr, hits) = spawn_udp_dns(Ipv4Addr::new(203, 0, 113, 7)).await;
    let router = core_runtime::route::Router::new(&json!({
        "outbounds":[{"type":"direct", "tag":"direct"}]
    }))
    .unwrap();
    let server = core_runtime::dns::transport::ServerConfig::build(
        &json!({
            "type":"udp", "tag":"test", "server":"127.0.0.1", "server_port":addr.port()
        }),
        "dns.servers[0]",
    )
    .unwrap();
    let query =
        core_runtime::dns::codec::build_query(123, "example.com", hickory_proto::rr::RecordType::A)
            .unwrap();
    for router in [None, Some(router)] {
        let dialer = core_runtime::dns::transport::Dialer { router };
        let raw = core_runtime::dns::transport::exchange(&server, addr, &query, &dialer)
            .await
            .unwrap();
        assert_eq!(
            core_runtime::dns::codec::answer_ips(&raw).unwrap(),
            vec![ip(203, 0, 113, 7)]
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 2);
}

type Hits = Arc<AtomicUsize>;

fn ip(a: u8, b: u8, c: u8, d: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(a, b, c, d))
}

fn build_answer(query: &Message, ip: Ipv4Addr) -> Vec<u8> {
    core_runtime::dns::codec::synth_address(query, ip.into(), 60).expect("encode answer")
}

/// A udp responder that takes its time, so a test can order a failure and an
/// answer deliberately.
async fn spawn_udp_dns_after(answer_ip: Ipv4Addr, delay: Duration) -> (SocketAddr, Hits) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            hits2.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(delay).await;
            let resp = build_answer(&query, answer_ip);
            if sock.send_to(&resp, from).await.is_err() {
                return;
            }
        }
    });
    (addr, hits)
}

async fn spawn_udp_dns(answer_ip: Ipv4Addr) -> (SocketAddr, Hits) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            hits2.fetch_add(1, Ordering::SeqCst);
            let resp = build_answer(&query, answer_ip);
            if sock.send_to(&resp, from).await.is_err() {
                return;
            }
        }
    });
    (addr, hits)
}

async fn read_framed(stream: &mut (impl tokio::io::AsyncRead + Unpin)) -> std::io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    stream.read_exact(&mut len).await?;
    let mut body = vec![0u8; u16::from_be_bytes(len) as usize];
    stream.read_exact(&mut body).await?;
    Ok(body)
}

async fn spawn_tcp_dns(answer_ip: Ipv4Addr) -> (SocketAddr, Hits) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind tcp");
    let addr = listener.local_addr().expect("tcp addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let hits = Arc::clone(&hits2);
            tokio::spawn(async move {
                loop {
                    let Ok(query_raw) = read_framed(&mut stream).await else {
                        return;
                    };
                    let Ok(query) = Message::from_vec(&query_raw) else {
                        return;
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                    let resp = build_answer(&query, answer_ip);
                    let mut framed = Vec::with_capacity(2 + resp.len());
                    framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&resp);
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, hits)
}

fn server_tls_config(alpn: &[&str]) -> Arc<core_tls::rustls::ServerConfig> {
    core_tls::install_default_provider();
    let certs: Vec<_> = rustls_pemfile::certs(&mut CERT_PEM.as_bytes())
        .collect::<Result<_, _>>()
        .expect("parse cert");
    let key = rustls_pemfile::private_key(&mut KEY_PEM.as_bytes())
        .expect("key read")
        .expect("key present");
    let mut cfg = core_tls::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("server cert");
    cfg.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    Arc::new(cfg)
}

/// Plain framed DNS over TLS (DoT), answered inside the TLS session.
async fn spawn_dot_dns(answer_ip: Ipv4Addr) -> (SocketAddr, Hits) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind dot");
    let addr = listener.local_addr().expect("dot addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    tokio::spawn(async move {
        let tls_cfg = server_tls_config(&[]);
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let hits = Arc::clone(&hits2);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                loop {
                    let Ok(query_raw) = read_framed(&mut stream).await else {
                        return;
                    };
                    let Ok(query) = Message::from_vec(&query_raw) else {
                        return;
                    };
                    hits.fetch_add(1, Ordering::SeqCst);
                    let resp = build_answer(&query, answer_ip);
                    let mut framed = Vec::with_capacity(2 + resp.len());
                    framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
                    framed.extend_from_slice(&resp);
                    if stream.write_all(&framed).await.is_err() {
                        return;
                    }
                }
            });
        }
    });
    (addr, hits)
}

/// DNS-over-HTTPS with h2: one request/response per stream.
async fn spawn_doh_h2_dns(answer_ip: Ipv4Addr) -> (SocketAddr, Hits) {
    let (addr, hits, _) = spawn_doh_h2_dns_counted(answer_ip).await;
    (addr, hits)
}

async fn spawn_doh_h2_dns_counted(answer_ip: Ipv4Addr) -> (SocketAddr, Hits, Hits) {
    spawn_doh_h2_dns_stalling(answer_ip, None).await
}

async fn spawn_doh_h2_dns_stalling(
    answer_ip: Ipv4Addr,
    stall_first_connection_after: Option<usize>,
) -> (SocketAddr, Hits, Hits) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind doh");
    let addr = listener.local_addr().expect("doh addr");
    let hits = Arc::new(AtomicUsize::new(0));
    let hits2 = Arc::clone(&hits);
    let connections = Arc::new(AtomicUsize::new(0));
    let accepted_count = connections.clone();
    tokio::spawn(async move {
        let tls_cfg = server_tls_config(&["h2"]);
        let acceptor = tokio_rustls::TlsAcceptor::from(tls_cfg);
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let connection_number = accepted_count.fetch_add(1, Ordering::SeqCst) + 1;
            let hits = Arc::clone(&hits2);
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let Ok(mut conn) = h2::server::handshake(stream).await else {
                    return;
                };
                eprintln!("[doh-debug] server h2 up");
                let queries = Arc::new(AtomicUsize::new(0));
                while let Some(accepted) = conn.accept().await {
                    let Ok((request, mut respond)) = accepted else {
                        return;
                    };
                    // The connection future must keep being polled while a
                    // request body is read — handle each request in its own
                    // task so `accept()` stays live.
                    let hits = Arc::clone(&hits);
                    let queries = Arc::clone(&queries);
                    tokio::spawn(async move {
                        let mut body = request.into_parts().1;
                        let mut query_raw = Vec::new();
                        while let Some(Ok(chunk)) = body.data().await {
                            query_raw.extend_from_slice(&chunk);
                            let _ = body.flow_control().release_capacity(chunk.len());
                        }
                        let Ok(query) = Message::from_vec(&query_raw) else {
                            respond.send_reset(h2::Reason::PROTOCOL_ERROR);
                            return;
                        };
                        hits.fetch_add(1, Ordering::SeqCst);
                        let query_number = queries.fetch_add(1, Ordering::SeqCst);
                        if connection_number == 1
                            && stall_first_connection_after.is_some_and(|n| query_number >= n)
                        {
                            let _ = std::future::poll_fn(|cx| respond.poll_reset(cx)).await;
                            return;
                        }
                        let resp = build_answer(&query, answer_ip);
                        let head = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/dns-message")
                            .body(())
                            .expect("response head");
                        let Ok(mut send) = respond.send_response(head, false) else {
                            return;
                        };
                        let _ = send.send_data(bytes::Bytes::from(resp), true);
                    });
                }
            });
        }
    });
    (addr, hits, connections)
}

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

fn udp_service_config(port: u16) -> Value {
    json!({
        "dns": {
            "servers": [
                {"type": "udp", "tag": "local", "server": "127.0.0.1", "server_port": port}
            ],
            "final": "local"
        }
    })
}

fn service(root: &Value) -> Arc<DnsService> {
    DnsService::build(root)
        .expect("dns section builds")
        .expect("dns section present")
}

fn query(name: &str, qtype: &str) -> Vec<u8> {
    let rt = core_runtime::dns::codec::parse_record_type(qtype).expect("record type");
    core_runtime::dns::codec::build_query(0x4242, name, rt).expect("build query")
}

async fn exchange_ok(svc: &Arc<DnsService>, raw: &[u8]) -> Vec<u8> {
    svc.exchange(&QueryMeta::default(), raw, true)
        .await
        .expect("exchange")
}

/// A udp responder that keeps the raw query, so a test can look at the bytes
/// that actually went out.
async fn spawn_udp_dns_capture(
    answer_ip: Ipv4Addr,
) -> (SocketAddr, Arc<std::sync::Mutex<Vec<u8>>>) {
    let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp");
    let addr = sock.local_addr().expect("udp addr");
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let sink = Arc::clone(&seen);
    tokio::spawn(async move {
        let mut buf = [0u8; 4096];
        loop {
            let Ok((n, from)) = sock.recv_from(&mut buf).await else {
                return;
            };
            let Ok(query) = Message::from_vec(&buf[..n]) else {
                continue;
            };
            if let Ok(mut guard) = sink.lock() {
                *guard = buf[..n].to_vec();
            }
            let resp = build_answer(&query, answer_ip);
            if sock.send_to(&resp, from).await.is_err() {
                return;
            }
        }
    });
    (addr, seen)
}

/// The OPT record the reference builds for `client_subnet`: payload size 0,
/// no DO bit, and a single SUBNET option carrying the masked address.
fn subnet_record(family: u16, netmask: u8, address: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::new();
    rdata.extend_from_slice(&8u16.to_be_bytes());
    rdata.extend_from_slice(&((4 + address.len()) as u16).to_be_bytes());
    rdata.extend_from_slice(&family.to_be_bytes());
    rdata.push(netmask);
    rdata.push(0);
    rdata.extend_from_slice(address);
    let mut record = vec![0x00];
    record.extend_from_slice(&41u16.to_be_bytes()); // TYPE = OPT
    record.extend_from_slice(&0u16.to_be_bytes()); // CLASS
    record.extend_from_slice(&0u32.to_le_bytes()); // TTL
    record.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    record.extend_from_slice(&rdata);
    record
}

/// A TCP listener that accepts and hangs up: the client's framed write lands in
/// a closed socket, so the exchange fails at once on every platform — a port
/// that was bound and dropped would be handed to another test in between, and a
/// UDP port nobody listens on only times out on Linux.
async fn spawn_refusing_tcp() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind dead");
    let port = listener.local_addr().expect("dead addr").port();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            drop(stream);
        }
    });
    port
}

#[tokio::test]
async fn a_group_answers_from_the_member_that_is_alive() {
    // The dead member hangs up on connect; the live one answers late, so the
    // failure is recorded while the query is still running — a result that
    // arrives after the answer is not evidence about the server, which is the
    // reference's rule.
    let (live, hits) =
        spawn_udp_dns_after(Ipv4Addr::new(10, 4, 4, 4), Duration::from_millis(200)).await;
    let dead_port = spawn_refusing_tcp().await;
    let config = json!({
        "dns": {
            "servers": [
                {"type": "tcp", "tag": "dead", "server": "127.0.0.1", "server_port": dead_port},
                {"type": "udp", "tag": "live", "server": "127.0.0.1", "server_port": live.port()},
                {"type": "group", "tag": "grp", "servers": ["dead", "live"],
                 "mode": "parallel", "error_ttl": "1s", "timeout": "5s"}
            ],
            "final": "grp",
            "disable_cache": true
        }
    });
    let svc = service(&config);

    let resp = exchange_ok(&svc, &query("grouped.test", "A")).await;
    assert_eq!(
        core_runtime::dns::codec::answer_ips(&resp).expect("decode"),
        vec![ip(10, 4, 4, 4)],
        "the answer came from the member that answered"
    );
    // the refused member is dirty now, so the second query goes straight to the
    // live one instead of fanning again
    let group = svc
        .server("grp")
        .and_then(|cfg| cfg.group.clone())
        .expect("the group runtime");
    let state = group.snapshot();
    assert!(
        !state
            .iter()
            .find(|m| m.tag == "dead")
            .expect("the dead member")
            .clean,
        "a refused connection is an error record"
    );
    let before = hits.load(Ordering::SeqCst);
    exchange_ok(&svc, &query("grouped.test", "A")).await;
    assert_eq!(
        hits.load(Ordering::SeqCst),
        before + 1,
        "the clean member answered alone"
    );
}

#[tokio::test]
async fn a_group_refuses_what_the_reference_refuses() {
    // a member that does not exist
    let config = json!({
        "dns": {"servers": [{"type": "group", "tag": "grp", "servers": ["nope"]}], "final": "grp"}
    });
    let error = DnsService::build(&config).err().expect("unknown member");
    assert!(
        error
            .to_string()
            .contains("group[grp]: DNS server not found: nope"),
        "{error}"
    );
    // fakeip cannot fail over, so it is not a legal member
    let config = json!({
        "dns": {
            "servers": [
                {"type": "fakeip", "tag": "fp", "inet4_range": "198.18.0.0/15"},
                {"type": "group", "tag": "grp", "servers": ["fp"]}
            ],
            "final": "grp"
        }
    });
    let error = DnsService::build(&config).err().expect("fakeip member");
    assert!(
        error
            .to_string()
            .contains("group[grp]: server type fakeip is not allowed in a group: fp"),
        "{error}"
    );
    // a cycle is reported with the start loop's own text
    let config = json!({
        "dns": {"servers": [
            {"type": "group", "tag": "g1", "servers": ["g2"]},
            {"type": "group", "tag": "g2", "servers": ["g1"]}
        ], "final": "g1"}
    });
    let error = DnsService::build(&config).err().expect("cycle");
    assert!(
        error
            .to_string()
            .starts_with("circular server dependency: "),
        "{error}"
    );
}

#[tokio::test]
async fn client_subnet_rides_along_on_upstream_queries() {
    let (addr, seen) = spawn_udp_dns_capture(Ipv4Addr::new(10, 0, 0, 9)).await;
    let mut config = udp_service_config(addr.port());
    config["dns"]["client_subnet"] = json!("1.2.3.4/24");
    let svc = service(&config);

    let resp = exchange_ok(&svc, &query("ecs.test", "A")).await;
    assert_eq!(
        core_runtime::dns::codec::answer_ips(&resp).expect("decode"),
        vec![ip(10, 0, 0, 9)],
        "the query still resolves"
    );
    let raw = seen.lock().expect("captured").clone();
    let want = subnet_record(1, 24, &[1, 2, 3, 0]);
    assert_eq!(
        &raw[raw.len() - want.len()..],
        want.as_slice(),
        "the masked prefix rides along as an EDNS0 option"
    );
}

#[tokio::test]
async fn a_bare_client_subnet_is_a_host_prefix() {
    let (addr, seen) = spawn_udp_dns_capture(Ipv4Addr::new(10, 0, 0, 8)).await;
    let mut config = udp_service_config(addr.port());
    config["dns"]["client_subnet"] = json!("198.51.100.7");
    let svc = service(&config);

    exchange_ok(&svc, &query("bare.test", "A")).await;
    let raw = seen.lock().expect("captured").clone();
    let want = subnet_record(1, 32, &[198, 51, 100, 7]);
    assert_eq!(&raw[raw.len() - want.len()..], want.as_slice());
}

#[tokio::test]
async fn an_ipv6_client_subnet_is_carried_whole() {
    let (addr, seen) = spawn_udp_dns_capture(Ipv4Addr::new(10, 0, 0, 7)).await;
    let mut config = udp_service_config(addr.port());
    config["dns"]["client_subnet"] = json!("2001:db8::/48");
    let svc = service(&config);

    exchange_ok(&svc, &query("v6.test", "A")).await;
    let raw = seen.lock().expect("captured").clone();
    let mut address = [0u8; 16];
    address[0] = 0x20;
    address[1] = 0x01;
    address[2] = 0x0d;
    address[3] = 0xb8;
    let want = subnet_record(2, 48, &address);
    assert_eq!(&raw[raw.len() - want.len()..], want.as_slice());
}

#[tokio::test]
async fn without_client_subnet_no_opt_is_added() {
    let (addr, seen) = spawn_udp_dns_capture(Ipv4Addr::new(10, 0, 0, 6)).await;
    let svc = service(&udp_service_config(addr.port()));
    let sent = query("plain.test", "A");

    exchange_ok(&svc, &sent).await;
    let raw = seen.lock().expect("captured").clone();
    // the transport puts its own random ID on the wire
    assert_eq!(raw[2..], sent[2..], "the query goes out untouched");
}

#[tokio::test]
async fn udp_exchange_caches_single_uplink() {
    let (addr, hits) = spawn_udp_dns(Ipv4Addr::new(10, 9, 8, 7)).await;
    let svc = service(&udp_service_config(addr.port()));

    let first = exchange_ok(&svc, &query("cache.test", "A")).await;
    let ips = core_runtime::dns::codec::answer_ips(&first).expect("decode");
    assert_eq!(ips, vec![ip(10, 9, 8, 7)]);
    assert_eq!(hits.load(Ordering::SeqCst), 1, "first query hits the wire");

    // different id, same name/type → cache hit, no second wire query
    let second = svc
        .exchange(
            &QueryMeta::default(),
            &core_runtime::dns::codec::build_query(
                7,
                "cache.test",
                core_runtime::dns::codec::parse_record_type("A").unwrap(),
            )
            .unwrap(),
            true,
        )
        .await
        .expect("second exchange");
    let msg = core_runtime::dns::codec::parse_message(&second).expect("parse");
    assert_eq!(
        msg.metadata.id, 7,
        "response id rewritten to the client query"
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        1,
        "second query served from cache"
    );
}

#[tokio::test]
async fn tcp_transport_framing() {
    let (addr, hits) = spawn_tcp_dns(Ipv4Addr::new(10, 0, 0, 1)).await;
    let root = json!({
        "dns": {
            "servers": [
                {"type": "tcp", "tag": "t", "server": "127.0.0.1", "server_port": addr.port()}
            ],
            "final": "t",
            "disable_cache": true
        }
    });
    let svc = service(&root);
    let resp = exchange_ok(&svc, &query("tcp.test", "A")).await;
    let ips = core_runtime::dns::codec::answer_ips(&resp).expect("decode");
    assert_eq!(ips, vec![ip(10, 0, 0, 1)]);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dot_transport_tls_exchange() {
    let (addr, hits) = spawn_dot_dns(Ipv4Addr::new(10, 0, 0, 2)).await;
    let root = json!({
        "dns": {
            "servers": [{
                "type": "tls", "tag": "dot", "server": "127.0.0.1",
                "server_port": addr.port(),
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            }],
            "final": "dot",
            "disable_cache": true
        }
    });
    let svc = service(&root);
    let resp = exchange_ok(&svc, &query("dot.test", "A")).await;
    let ips = core_runtime::dns::codec::answer_ips(&resp).expect("decode");
    assert_eq!(ips, vec![ip(10, 0, 0, 2)]);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn doh_h2_transport_exchange() {
    let (addr, hits) = spawn_doh_h2_dns(Ipv4Addr::new(10, 0, 0, 3)).await;
    let root = json!({
        "dns": {
            "servers": [{
                "type": "https", "tag": "doh", "server": "127.0.0.1",
                "server_port": addr.port(),
                "tls": {"enabled": true, "server_name": "localhost", "insecure": true}
            }],
            "final": "doh",
            "disable_cache": true
        }
    });
    let svc = service(&root);
    let resp = exchange_ok(&svc, &query("doh.test", "A")).await;
    let ips = core_runtime::dns::codec::answer_ips(&resp).expect("decode");
    assert_eq!(ips, vec![ip(10, 0, 0, 3)]);
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fakeip_synth_reverse_and_bypass() {
    let (addr, _hits) = spawn_udp_dns(Ipv4Addr::new(10, 0, 0, 9)).await;
    let root = json!({
        "dns": {
            "servers": [
                {"type": "fakeip", "tag": "fp", "inet4_range": "198.18.0.0/15"},
                {"type": "udp", "tag": "local", "server": "127.0.0.1", "server_port": addr.port()}
            ],
            "rules": [
                {"action": "route", "server": "fp", "domain_suffix": ["fake.test"]}
            ],
            "final": "local",
            "disable_cache": true
        }
    });
    let svc = service(&root);

    let resp = exchange_ok(&svc, &query("x.fake.test", "A")).await;
    let ips = core_runtime::dns::codec::answer_ips(&resp).expect("decode");
    assert_eq!(ips, vec![ip(198, 18, 0, 2)]);
    assert_eq!(svc.fakeip_domain(ips[0]).as_deref(), Some("x.fake.test"));

    // stable allocation for the same domain
    let again = exchange_ok(&svc, &query("x.fake.test", "A")).await;
    let ips2 = core_runtime::dns::codec::answer_ips(&again).expect("decode");
    assert_eq!(ips, ips2);

    // address lookups (outbound server resolution) bypass fakeip → real answer
    let real = svc
        .exchange(&QueryMeta::default(), &query("x.fake.test", "A"), false)
        .await
        .expect("bypass exchange");
    let real_ips = core_runtime::dns::codec::answer_ips(&real).expect("decode");
    assert_eq!(real_ips, vec![ip(10, 0, 0, 9)]);
}

#[tokio::test]
async fn reject_rule_replies_refused() {
    let (addr, hits) = spawn_udp_dns(Ipv4Addr::new(10, 0, 0, 4)).await;
    let root = json!({
        "dns": {
            "servers": [
                {"type": "udp", "tag": "local", "server": "127.0.0.1", "server_port": addr.port()}
            ],
            "rules": [
                {"action": "reject", "query_type": ["HTTPS", "SVCB"]}
            ],
            "final": "local",
            "disable_cache": true
        }
    });
    let svc = service(&root);

    let refused = exchange_ok(&svc, &query("x.test", "HTTPS")).await;
    let msg = core_runtime::dns::codec::parse_message(&refused).expect("parse");
    assert_eq!(
        msg.metadata.response_code,
        hickory_proto::op::ResponseCode::Refused
    );
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "reject never reaches the wire"
    );

    let ok = exchange_ok(&svc, &query("x.test", "A")).await;
    let msg = core_runtime::dns::codec::parse_message(&ok).expect("parse");
    assert_eq!(
        msg.metadata.response_code,
        hickory_proto::op::ResponseCode::NoError
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
}

/// Global service wiring: `start()` installs it, `BoxInstance::dns()` exposes
/// it, `connect_tcp` resolves hostnames through it, and a dns-less config
/// clears it. Single test to avoid cross-test races on the process-global slot.
#[tokio::test]
async fn instance_getter_and_connect_tcp_via_service() {
    // with dns section → Some(...)
    let with_dns = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "m", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"},
        "dns": {
            "servers": [{"type": "udp", "tag": "u", "server": "127.0.0.1"}],
            "final": "u"
        }
    }))
    .await
    .expect("start with dns");
    assert!(
        with_dns.dns().is_some(),
        "dns section must surface on the instance"
    );
    with_dns.shutdown();

    // without dns section → None
    let without_dns = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "m", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .expect("start without dns");
    assert!(without_dns.dns().is_none(), "no dns section → None");
    without_dns.shutdown();

    // connect_tcp resolves the hostname through the installed service
    let (addr, _hits) = spawn_udp_dns(Ipv4Addr::new(127, 0, 0, 1)).await;
    let svc = service(&udp_service_config(addr.port()));
    core_runtime::dns::set_service(Some(svc));
    let echo = spawn_echo().await;
    let mut stream =
        core_runtime::outbound::dial::connect_tcp("echo.test", echo.port(), &Default::default())
            .await
            .expect("connect via dns service");
    stream.write_all(b"ping").await.expect("write");
    let mut buf = [0u8; 4];
    stream.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"ping");
    core_runtime::dns::set_service(None);
}

#[test]
fn router_main_dns_section_builds() {
    let mut root: Value = serde_json::from_str(ROUTER_MAIN).expect("parse router-main");
    // the captured config points at rule-set files of the reference host; the
    // dns build now loads them, so give every local set a real one
    let compiled = core_config::srs::compile(
        &serde_json::json!({"rules": [{"domain_suffix": ["example.invalid"]}]}),
        2,
    )
    .expect("compile rule-set");
    let dir = std::env::temp_dir().join("xrust-dns-rule-set-test");
    std::fs::create_dir_all(&dir).expect("create rule-set dir");
    let path = dir.join("ruleset.srs");
    std::fs::write(&path, &compiled).expect("write rule-set");
    let path = path.to_string_lossy().replace('\\', "/");
    if let Some(entries) = root
        .get_mut("route")
        .and_then(|route| route.get_mut("rule_set"))
        .and_then(Value::as_array_mut)
    {
        for entry in entries.iter_mut() {
            if entry.get("type").and_then(Value::as_str) == Some("local")
                && let Some(object) = entry.as_object_mut()
            {
                object.insert("path".into(), Value::String(path.clone()));
                object.insert("format".into(), Value::String("binary".into()));
            }
        }
    }
    let svc = DnsService::build(&root)
        .expect("router-main dns section must build")
        .expect("dns present");
    assert_eq!(svc.strategy(), core_runtime::dns::Strategy::PreferIPv4);
    assert!(!svc.fakeip_stores().is_empty(), "router config uses fakeip");
}

#[tokio::test]
async fn tcp_transport_uses_the_detour_outbound() {
    // a TCP DNS responder behind the `direct` outbound: the detour plumbing is
    // what is under test
    let (addr, _hits) = spawn_tcp_dns(Ipv4Addr::new(127, 0, 0, 1)).await;
    let router = core_runtime::route::Router::new(&serde_json::json!({
        "log": {"level": "error"},
        "outbounds": [
            {"type": "direct", "tag": "direct"},
            {"type": "http", "tag": "unused", "server": "127.0.0.1", "server_port": 1}
        ]
    }))
    .expect("router");
    let dialer = core_runtime::dns::transport::Dialer {
        router: Some(Arc::clone(&router)),
    };
    let server = core_runtime::dns::transport::ServerConfig::build(
        &serde_json::json!({
            "type": "tcp",
            "tag": "detoured",
            "server": "127.0.0.1",
            "server_port": addr.port(),
            "detour": "direct"
        }),
        "dns.servers[0]",
    )
    .expect("server");
    assert_eq!(server.detour.as_deref(), Some("direct"));
    let query = core_runtime::dns::codec::build_query(
        0x2222,
        "detour.test",
        hickory_proto::rr::RecordType::A,
    )
    .expect("query");
    let raw = core_runtime::dns::transport::exchange(&server, addr, &query, &dialer)
        .await
        .expect("detoured exchange");
    let message = core_runtime::dns::codec::parse_message(&raw).expect("response");
    assert_eq!(message.answers.len(), 1);

    // an unknown detour tag fails the query instead of going direct
    let server = core_runtime::dns::transport::ServerConfig::build(
        &serde_json::json!({
            "type": "tcp",
            "tag": "bad",
            "server": "127.0.0.1",
            "server_port": 53,
            "detour": "missing"
        }),
        "dns.servers[1]",
    )
    .expect("server");
    let error = core_runtime::dns::transport::exchange(&server, addr, &query, &dialer)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("detour"), "{error}");
}

#[tokio::test]
async fn doh_reuses_connection_and_separates_same_tag_configurations() {
    let (addr, hits, connections) = spawn_doh_h2_dns_counted(Ipv4Addr::new(10, 0, 0, 3)).await;
    let config = |addr: SocketAddr| json!({"dns": {"servers": [{"type":"https","tag":"same","server":"127.0.0.1","server_port":addr.port(),"tls":{"enabled":true,"server_name":"localhost","insecure":true}}],"final":"same","disable_cache":true}});
    let svc = service(&config(addr));
    for n in 0..3 {
        let raw = exchange_ok(&svc, &query(&format!("reuse-{n}.test"), "A")).await;
        assert_eq!(
            core_runtime::dns::codec::answer_ips(&raw).unwrap(),
            vec![ip(10, 0, 0, 3)]
        );
    }
    assert_eq!(hits.load(Ordering::SeqCst), 3);
    assert_eq!(connections.load(Ordering::SeqCst), 1);
    let (other, _, other_connections) = spawn_doh_h2_dns_counted(Ipv4Addr::new(10, 0, 0, 4)).await;
    let replacement = service(&config(other));
    let raw = exchange_ok(&replacement, &query("changed.test", "A")).await;
    assert_eq!(
        core_runtime::dns::codec::answer_ips(&raw).unwrap(),
        vec![ip(10, 0, 0, 4)]
    );
    assert_eq!(other_connections.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn doh_timeout_recovers_without_reload_on_fresh_and_reused_connections() {
    for warmup in [false, true] {
        let (addr, hits, connections) =
            spawn_doh_h2_dns_stalling(Ipv4Addr::new(10, 0, 0, 3), Some(usize::from(warmup))).await;
        let svc = service(&json!({"dns": {
            "servers": [{"type":"https", "tag":"doh", "server":"127.0.0.1",
                "server_port":addr.port(),
                "tls":{"enabled":true,"server_name":"localhost","insecure":true}}],
            "final":"doh", "disable_cache":true
        }}));
        if warmup {
            exchange_ok(&svc, &query("warmup.test", "A")).await;
        }
        let error = tokio::time::timeout(
            Duration::from_secs(7),
            svc.exchange(&QueryMeta::default(), &query("stalled.test", "A"), true),
        )
        .await
        .expect("core deadline must fire")
        .unwrap_err();
        assert!(error.to_string().contains("timeout"), "{error}");
        assert_eq!(connections.load(Ordering::SeqCst), 1);
        for name in ["recovered.test", "still-reused.test"] {
            let answer = tokio::time::timeout(
                Duration::from_secs(3),
                svc.exchange(&QueryMeta::default(), &query(name, "A"), true),
            )
            .await
            .expect("replacement connection must answer promptly")
            .unwrap();
            assert_eq!(
                core_runtime::dns::codec::answer_ips(&answer).unwrap(),
                vec![ip(10, 0, 0, 3)]
            );
        }
        assert_eq!(connections.load(Ordering::SeqCst), 2);
        assert_eq!(hits.load(Ordering::SeqCst), 3 + usize::from(warmup));
    }
}
