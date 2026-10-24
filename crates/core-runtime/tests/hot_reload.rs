//! Tests for in-place hot reload without connection dropping or port closing.

#[tokio::test]
async fn failed_remote_download_keeps_previous_router() {
    let root =
        serde_json::json!({"outbounds":[{"type":"direct","tag":"old"}],"route":{"final":"old"}});
    let mut instance = core_runtime::start(&root).await.unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await.unwrap();
    });
    let next = serde_json::json!({"outbounds":[{"type":"direct","tag":"new"}],"route":{"final":"new","rule_set":[{"type":"remote","tag":"remote","format":"source","url":format!("http://{addr}/rules.json"),"download_detour":"new"}]}});
    assert!(instance.reload_in_place(&next).await.is_err());
    assert_eq!(instance.router().default_tag(), "old");
    server.await.unwrap();
    instance.shutdown_wait().await;
}

use std::net::SocketAddr;
use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

const T: Duration = Duration::from_secs(5);

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut s, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
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

async fn socks5_handshake(stream: &mut TcpStream, target: SocketAddr) {
    // SOCKS5 greeting: no auth
    stream.write_all(&[5, 1, 0]).await.expect("socks5 greeting");
    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await.expect("socks5 method");
    assert_eq!(resp, [5, 0]);

    // Connect request
    let mut req = vec![5, 1, 0, 1]; // IPv4
    let SocketAddr::V4(v4) = target else {
        panic!("need v4")
    };
    req.extend_from_slice(&v4.ip().octets());
    req.extend_from_slice(&v4.port().to_be_bytes());
    stream.write_all(&req).await.expect("socks5 req");

    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.expect("socks5 reply");
    assert_eq!(reply[0], 5);
    assert_eq!(reply[1], 0, "status succeeded");
}

#[tokio::test]
async fn hot_reload_preserves_live_tcp_connections() {
    let echo = spawn_echo().await;

    // 1. Initial config with mixed inbound
    let root1 = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"}
        ],
        "route": {"final": "direct-out"}
    });

    let mut instance = core_runtime::start(&root1).await.expect("start box");
    let in_addr = instance.inbound_addrs()[0].1;

    // 2. Open a TCP connection through SOCKS5 before reload
    let mut client = TcpStream::connect(in_addr)
        .await
        .expect("connect to inbound");
    socks5_handshake(&mut client, echo).await;

    // Send and receive bytes
    client.write_all(b"hello_before_reload").await.unwrap();
    let mut buf = vec![0u8; "hello_before_reload".len()];
    timeout(T, client.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"hello_before_reload");

    // 3. New config: inbounds IDENTICAL (same port and type), but routes/outbounds modified
    let root2 = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "mixed-in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "d1"},
            {"type": "direct", "tag": "direct-out"},
            {"type": "selector", "tag": "sel", "outbounds": ["direct-out", "d1"]}
        ],
        "route": {
            "rules": [
                {"port": [echo.port()], "outbound": "direct-out"}
            ],
            "final": "direct-out"
        }
    });

    // 4. Perform hot reload in-place
    instance
        .reload_in_place(&root2)
        .await
        .expect("reload in place");

    // 5. Assert the EXISTING connection was NOT dropped and is still fully alive!
    client.write_all(b"hello_after_reload").await.unwrap();
    let mut buf2 = vec![0u8; "hello_after_reload".len()];
    timeout(T, client.read_exact(&mut buf2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf2, b"hello_after_reload");

    // 6. Assert a NEW connection works through the updated routes
    let mut client2 = TcpStream::connect(in_addr).await.expect("connect client 2");
    socks5_handshake(&mut client2, echo).await;
    client2.write_all(b"new_connection_ok").await.unwrap();
    let mut buf3 = vec![0u8; "new_connection_ok".len()];
    timeout(T, client2.read_exact(&mut buf3))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf3, b"new_connection_ok");

    instance.shutdown();
}

#[tokio::test]
async fn hot_reload_preserves_selector_urltest_and_dns_cache() {
    let _echo = spawn_echo().await;

    // Keep background probes pending locally while checking migration of the
    // seeded history. A WAN failure must not race and invalidate that record.
    let _probe_peer = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let probe_url = format!("http://{}/", _probe_peer.local_addr().unwrap());

    let root1 = json!({
        "log": {"level": "error"},
        "dns": {
            "servers": [
                {"tag": "fakedns", "type": "fakeip", "inet4_range": "198.18.0.0/15"}
            ]
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "d1"},
            {"type": "direct", "tag": "d2"},
            {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2"]},
            {"type": "urltest", "tag": "ut", "outbounds": ["d1", "d2"], "interval": "10m", "url": probe_url}
        ],
        "route": {"final": "sel"}
    });

    let mut instance = core_runtime::start(&root1).await.expect("start box");
    let router = instance.router();
    // Record delay on d2, select d2 in selector
    let d2 = router.index_of("d2").unwrap();
    router.record_delay(d2, 88);
    router.select_member("sel", "d2").unwrap();

    // Check DNS fakeip allocation
    let dns = instance.dns().expect("dns configured");
    let fake_addr = dns.resolve("example.com").await.expect("resolve fakeip");
    assert!(!fake_addr.is_empty());
    let fake_ip = fake_addr[0];
    assert_eq!(dns.fakeip_domain(fake_ip), Some("example.com".to_string()));

    // Hot reload with new config keeping inbounds
    let root2 = json!({
        "log": {"level": "error"},
        "dns": {
            "servers": [
                {"tag": "fakedns", "type": "fakeip", "inet4_range": "198.18.0.0/15"}
            ]
        },
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "d3"},
            {"type": "direct", "tag": "d2"},
            {"type": "direct", "tag": "d1"},
            {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2", "d3"]},
            {"type": "urltest", "tag": "ut", "outbounds": ["d1", "d2", "d3"], "interval": "10m", "url": probe_url}
        ],
        "route": {"final": "d2"}
    });

    instance
        .reload_in_place(&root2)
        .await
        .expect("reload in place");

    // 1. Selector preserved
    let sel_idx = router.index_of("sel").unwrap();
    assert_eq!(router.delay_history(sel_idx).unwrap().1, 88);

    // 2. Delay history on d2 preserved despite reordering
    let new_d2 = router.index_of("d2").unwrap();
    assert_eq!(router.delay_history(new_d2).unwrap().1, 88);

    // 3. FakeIP state preserved across reload
    let new_dns = instance.dns().expect("new dns configured");
    assert_eq!(
        new_dns.fakeip_domain(fake_ip),
        Some("example.com".to_string())
    );

    instance.shutdown();
}

#[tokio::test]
async fn hot_reload_failure_keeps_running_instance_untouched() {
    let echo = spawn_echo().await;

    let root1 = json!({
        "log": {"level": "error"},
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "outbounds": [
            {"type": "direct", "tag": "direct-out"}
        ],
        "route": {"final": "direct-out"}
    });

    let mut instance = core_runtime::start(&root1).await.expect("start box");
    let in_addr = instance.inbound_addrs()[0].1;

    let mut client = TcpStream::connect(in_addr).await.expect("connect client");
    socks5_handshake(&mut client, echo).await;
    client.write_all(b"working_before").await.unwrap();
    let mut buf = vec![0u8; "working_before".len()];
    timeout(T, client.read_exact(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf, b"working_before");

    // Invalid config with broken dns / unknown outbound reference
    let invalid_root = json!({
        "inbounds": [{
            "type": "mixed",
            "tag": "in",
            "listen": "127.0.0.1",
            "listen_port": 0
        }],
        "dns": {
            "servers": [
                {"tag": "remote", "type": "udp", "server": "8.8.8.8"}
            ],
            "final": "non_existent_dns_server"
        },
        "outbounds": [
            {"type": "direct", "tag": "direct-out"}
        ],
        "route": {"final": "direct-out"}
    });

    // Reload must fail cleanly
    let err = instance.reload_in_place(&invalid_root).await.unwrap_err();
    assert!(
        err.to_string().contains("dns") || err.to_string().contains("server"),
        "expected dns error: {err:#}"
    );

    // The existing connection was NOT touched and still functions!
    client
        .write_all(b"still_working_after_failure")
        .await
        .unwrap();
    let mut buf2 = vec![0u8; "still_working_after_failure".len()];
    timeout(T, client.read_exact(&mut buf2))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf2, b"still_working_after_failure");

    instance.shutdown();
}

#[tokio::test]
async fn reload_acknowledges_only_success_and_rejects_listener_changes() {
    let root = json!({"inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":0}],
        "outbounds":[{"type":"direct","tag":"old"}],"route":{"final":"old"}});
    let mut instance = core_runtime::start(&root).await.unwrap();
    let router = instance.router();
    let before = router.applied_config();
    assert_eq!(before["generation"], 1);
    let mut next = root.clone();
    next["inbounds"][0]["listen_port"] = json!(12345);
    assert!(instance.reload_in_place(&next).await.is_err());
    assert_eq!(router.applied_config(), before);
    next = root.clone();
    next["route"]["final"] = json!("missing");
    assert!(instance.reload_in_place(&next).await.is_err());
    assert_eq!(router.applied_config(), before);
    next = root.clone();
    next["outbounds"][0]["tag"] = json!("new");
    next["route"]["final"] = json!("new");
    instance.reload_in_place(&next).await.unwrap();
    let after = router.applied_config();
    assert_eq!(after["generation"], 2);
    assert_ne!(after["config_sha256"], before["config_sha256"]);
    assert_eq!(after["pid"], before["pid"]);
    assert_eq!(router.default_tag(), "new");
    assert!(!core_runtime::can_reload_in_place(
        &next,
        &json!({"experimental":{"cache_file":{"enabled":true}}})
    ));
    instance.shutdown_wait().await;
}

#[tokio::test]
async fn changed_dns_server_with_same_tag_does_not_reuse_old_answer() {
    let root = json!({
        "dns":{"servers":[{"type":"hosts","tag":"main","path":[],
            "predefined":{"reload.example":["203.0.113.7"]}}],"final":"main"},
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}
    });
    let mut instance = core_runtime::start(&root).await.unwrap();
    let before = instance
        .dns()
        .unwrap()
        .resolve("reload.example")
        .await
        .unwrap();
    assert_eq!(before[0].to_string(), "203.0.113.7");
    let mut next = root.clone();
    next["dns"]["servers"][0]["predefined"]["reload.example"] = json!(["203.0.113.8"]);
    instance.reload_in_place(&next).await.unwrap();
    let after = instance
        .dns()
        .unwrap()
        .resolve("reload.example")
        .await
        .unwrap();
    assert_eq!(after[0].to_string(), "203.0.113.8");
    instance.shutdown_wait().await;
}

#[tokio::test]
async fn changed_udp_resolver_does_not_migrate_cached_answer() {
    async fn responder(ip: [u8; 4]) -> (u16, tokio::task::JoinHandle<()>) {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let port = socket.local_addr().unwrap().port();
        let task = tokio::spawn(async move {
            let mut buf = [0; 512];
            while let Ok((n, peer)) = socket.recv_from(&mut buf).await {
                let mut reply = buf[..n].to_vec();
                reply[2..4].copy_from_slice(&0x8180u16.to_be_bytes());
                let a = reply[n - 4..n - 2] == [0, 1];
                reply[6..8].copy_from_slice(&(u16::from(a)).to_be_bytes());
                if a {
                    reply.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 1, 44, 0, 4]);
                    reply.extend_from_slice(&ip);
                }
                socket.send_to(&reply, peer).await.unwrap();
            }
        });
        (port, task)
    }
    let (first, task1) = responder([203, 0, 113, 7]).await;
    let (second, task2) = responder([203, 0, 113, 8]).await;
    let root = json!({"dns":{"servers":[{"type":"udp","tag":"main","server":"127.0.0.1","server_port":first}],"final":"main","strategy":"ipv4_only"},
        "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}});
    let mut instance = core_runtime::start(&root).await.unwrap();
    assert_eq!(
        instance
            .dns()
            .unwrap()
            .resolve("reload.example")
            .await
            .unwrap()[0]
            .to_string(),
        "203.0.113.7"
    );
    let mut next = root.clone();
    next["dns"]["servers"][0]["server_port"] = json!(second);
    instance.reload_in_place(&next).await.unwrap();
    assert_eq!(
        instance
            .dns()
            .unwrap()
            .resolve("reload.example")
            .await
            .unwrap()[0]
            .to_string(),
        "203.0.113.8"
    );
    instance.shutdown_wait().await;
    task1.abort();
    task2.abort();
}

#[tokio::test]
async fn changed_local_ruleset_applies_to_new_connections_and_keeps_live_tcp() {
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "rust-x-hot-list-{}-{nonce}.json",
        std::process::id()
    ));
    let _cleanup = Cleanup(path.clone());
    std::fs::write(
        &path,
        r#"{"version":3,"rules":[{"ip_cidr":["192.0.2.0/24"]}]}"#,
    )
    .unwrap();
    let echo = spawn_echo().await;
    let root = json!({
        "inbounds":[{"type":"mixed","listen":"127.0.0.1","listen_port":0}],
        "outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"final":"direct","rule_set":[{"type":"local","tag":"list","format":"source","path":path}],
            "rules":[{"rule_set":["list"],"action":"reject"}]}
    });
    let mut instance = core_runtime::start(&root).await.unwrap();
    let addr = instance.inbound_addrs()[0].1;
    let mut live = TcpStream::connect(addr).await.unwrap();
    socks5_handshake(&mut live, echo).await;
    std::fs::write(
        &path,
        r#"{"version":3,"rules":[{"ip_cidr":["127.0.0.1/32"]}]}"#,
    )
    .unwrap();
    instance.reload_in_place(&root).await.unwrap();
    live.write_all(b"still-live").await.unwrap();
    let mut received = [0; 10];
    timeout(T, live.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"still-live");
    let mut next = TcpStream::connect(addr).await.unwrap();
    next.write_all(&[5, 1, 0]).await.unwrap();
    let mut method = [0; 2];
    next.read_exact(&mut method).await.unwrap();
    assert_eq!(method, [5, 0]);
    let mut req = vec![5, 1, 0, 1, 127, 0, 0, 1];
    req.extend_from_slice(&echo.port().to_be_bytes());
    next.write_all(&req).await.unwrap();
    let mut reply = [0; 10];
    timeout(T, next.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(reply[1], 0, "new connection bypassed updated rule set");
    let before = instance.router().applied_config();
    std::fs::write(&path, "{broken").unwrap();
    assert!(instance.reload_in_place(&root).await.is_err());
    assert_eq!(instance.router().applied_config(), before);
    instance.shutdown_wait().await;
}

#[tokio::test]
async fn connection_revalidation_handles_domains_cidrs_and_changed_list_entries() {
    use core_runtime::{
        clash_state::{self, ConnHandle},
        inbound::clash_meta,
        route::{ConnContext, Router, Target},
    };
    use std::sync::Arc;
    let path = std::env::temp_dir().join(format!("rust-x-revalidate-{}.json", std::process::id()));
    std::fs::write(
        &path,
        r#"{"version":1,"rules":[{"domain":["gone-list.test","keep-list.test"]}]}"#,
    )
    .unwrap();
    let root = json!({"outbounds":[{"type":"direct","tag":"chosen"},{"type":"direct","tag":"fallback"}], "route":{"final":"fallback","rule_set":[{"type":"local","tag":"same-list","format":"source","path":path}],"rules":[{"domain":["gone.test","keep.test"],"outbound":"chosen"},{"ip_cidr":["198.51.100.0/24","203.0.113.0/24"],"outbound":"chosen"},{"rule_set":["same-list"],"outbound":"chosen"}]}});
    let mut instance = core_runtime::start(&root).await.unwrap();
    let router: Arc<Router> = instance.router();
    let mut handles = Vec::new();
    for target in [
        Target::Domain("gone.test".into(), 443),
        Target::Domain("keep.test".into(), 443),
        Target::Ip("198.51.100.5:443".parse().unwrap()),
        Target::Ip("203.0.113.5:443".parse().unwrap()),
        Target::Domain("gone-list.test".into(), 443),
        Target::Domain("keep-list.test".into(), 443),
    ] {
        let mut ctx = ConnContext::new("mixed", "192.0.2.1:3000".parse().unwrap(), target, "tcp");
        let core_runtime::route::Decision::Outbound(index) =
            router.route_raw(&mut ctx).await.unwrap()
        else {
            panic!()
        };
        handles.push(ConnHandle::open_with_context(
            clash_meta(&ctx, &router, index),
            &ctx,
            &router,
        ));
    }
    std::fs::write(
        &path,
        r#"{"version":1,"rules":[{"domain":["keep-list.test"]}]}"#,
    )
    .unwrap();
    let mut next = root.clone();
    next["route"]["rules"][0]["domain"] = json!(["keep.test"]);
    next["route"]["rules"][1]["ip_cidr"] = json!(["203.0.113.0/24"]);
    instance.reload_in_place(&next).await.unwrap();
    let result = clash_state::close_invalid_routes(&router).await;
    assert_eq!(result["closed"], 3);
    assert_eq!(result["skipped"], 0);
    for (i, h) in handles.iter().enumerate() {
        let closed = timeout(Duration::from_millis(10), h.close_signal().wait())
            .await
            .is_ok();
        assert_eq!(closed, i % 2 == 0, "connection {i}");
    }
    drop(handles);
    instance.shutdown_wait().await;
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn domain_regex_rule_set_reload_and_bad_regex_keeps_running_state() {
    use core_runtime::inbound::Target;
    use core_runtime::route::{ConnContext, Decision};
    struct Cleanup(std::path::PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "rust-x-hot-regex-{}-{nonce}.json",
        std::process::id()
    ));
    let _cleanup = Cleanup(path.clone());
    let write = |regex: &str| {
        let body = json!({"version": 3, "rules": [{"domain_regex": [regex]}]});
        std::fs::write(&path, body.to_string()).unwrap();
    };
    write("^foo\\.example$");
    let root = json!({
        "outbounds":[{"type":"direct","tag":"hit"},{"type":"direct","tag":"miss"}],
        "route":{"final":"miss","rule_set":[{"type":"local","tag":"list","format":"source","path":path}],
            "rules":[{"rule_set":["list"],"outbound":"hit"}]}
    });
    let mut instance = core_runtime::start(&root).await.unwrap();
    async fn routed(instance: &core_runtime::BoxInstance, target: Target) -> String {
        let router = instance.router();
        let mut ctx = ConnContext::new("in", "10.0.0.2:1234".parse().unwrap(), target, "tcp");
        let Decision::Outbound(index) = router.route_raw(&mut ctx).await.unwrap() else {
            panic!("outbound expected")
        };
        if Some(index) == router.index_of("hit") {
            "hit".into()
        } else {
            "miss".into()
        }
    }
    let foo = || Target::Domain("foo.example".into(), 443);
    let bar = || Target::Domain("bar.test".into(), 443);
    let ip = || Target::Ip("8.8.8.8:443".parse().unwrap());
    assert_eq!(routed(&instance, foo()).await, "hit");
    assert_eq!(routed(&instance, bar()).await, "miss");
    assert_eq!(routed(&instance, ip()).await, "miss");

    // a bad expression fails the reload and keeps the running router
    let before = instance.router().applied_config();
    write("(unclosed");
    let error = instance.reload_in_place(&root).await.unwrap_err();
    assert!(format!("{error:#}").contains("domain_regex"), "{error:#}");
    assert_eq!(instance.router().applied_config(), before);
    assert_eq!(routed(&instance, foo()).await, "hit");
    assert_eq!(routed(&instance, bar()).await, "miss");

    // a good one applies
    write("^bar\\.test$");
    instance.reload_in_place(&root).await.unwrap();
    assert_eq!(routed(&instance, foo()).await, "miss");
    assert_eq!(routed(&instance, bar()).await, "hit");
    assert_eq!(routed(&instance, ip()).await, "miss");
    instance.shutdown_wait().await;
}

#[tokio::test]
async fn mmap_local_set_switches_to_memory_when_reloaded_with_regex() {
    use core_runtime::inbound::Target;
    use core_runtime::route::{ConnContext, Decision};
    struct Cleanup(Vec<std::path::PathBuf>);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            for path in &self.0 {
                let _ = std::fs::remove_file(path);
            }
        }
    }
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = format!("rust-x-hot-mmap-{}-{nonce}", std::process::id());
    let path = std::env::temp_dir().join(format!("{base}.json"));
    let tsrs = std::env::temp_dir().join(format!("{base}.tsrs"));
    let _cleanup = Cleanup(vec![path.clone(), tsrs.clone()]);
    std::fs::write(
        &path,
        json!({"version": 3, "rules": [{"domain": ["plain.com"]}]}).to_string(),
    )
    .unwrap();
    let root = json!({
        "outbounds":[{"type":"direct","tag":"hit"},{"type":"direct","tag":"miss"}],
        "route":{"final":"miss","rule_set":[{"type":"local","tag":"list","format":"source","path":path,
            "mmap":true,"cache_file":tsrs}],
            "rules":[{"rule_set":["list"],"outbound":"hit"}]}
    });
    let mut instance = core_runtime::start(&root).await.unwrap();
    async fn routed(instance: &core_runtime::BoxInstance, host: &str) -> bool {
        let router = instance.router();
        let mut ctx = ConnContext::new(
            "in",
            "10.0.0.2:1234".parse().unwrap(),
            Target::Domain(host.into(), 443),
            "tcp",
        );
        let Decision::Outbound(index) = router.route_raw(&mut ctx).await.unwrap() else {
            panic!("outbound expected")
        };
        Some(index) == router.index_of("hit")
    }
    assert!(tsrs.exists(), "plain set compiled to TSRS");
    assert!(routed(&instance, "plain.com").await);
    assert!(!routed(&instance, "foo.example").await);

    std::fs::write(
        &path,
        json!({"version": 3, "rules": [{"domain_regex": ["^foo\\.example$"]}]}).to_string(),
    )
    .unwrap();
    instance.reload_in_place(&root).await.unwrap();
    assert!(routed(&instance, "foo.example").await);
    assert!(!routed(&instance, "bar.test").await);
    assert!(!routed(&instance, "plain.com").await);
    instance.shutdown_wait().await;
}
