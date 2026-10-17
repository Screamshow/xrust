use core_runtime::{
    clash_state::{ConnHandle, ConnMeta},
    inbound::Target,
    route::{ConnContext, Router},
};
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::{io::AsyncReadExt, net::TcpListener};

fn router(interrupt: bool) -> Arc<Router> {
    Router::new(&json!({"outbounds":[{"type":"direct","tag":"a"},{"type":"direct","tag":"b"},{"type":"selector","tag":"group","outbounds":["a","b"],"interrupt_exist_connections":interrupt}]})).unwrap()
}
fn tracked(router: &Router, network: &'static str, group: &str) -> ConnHandle {
    let ctx = ConnContext::new(
        "test",
        "127.0.0.1:12345".parse().unwrap(),
        Target::Domain("example.com".into(), 443),
        network,
    );
    ConnHandle::open_with_context(
        ConnMeta {
            network,
            inbound: "test".into(),
            source: "127.0.0.1:12345".into(),
            host: "example.com".into(),
            destination: "example.com:443".into(),
            chains: vec![group.into(), "a".into()],
            rule: String::new(),
            rule_payload: String::new(),
        },
        &ctx,
        router,
    )
}
#[tokio::test]
async fn selector_interruption_is_scoped_and_respects_policy() {
    for interrupt in [false, true] {
        let router = router(interrupt);
        let other = crate::router(true);
        let tcp = tracked(&router, "tcp", "group");
        let udp = tracked(&router, "udp", "group");
        let unrelated = tracked(&router, "tcp", "other");
        let foreign = tracked(&other, "tcp", "group");
        assert!(router.select_member("group", "missing").is_err());
        router.select_member("group", "a").unwrap();
        assert!(!tcp.is_closed());
        router.select_member("group", "b").unwrap();
        assert_eq!(tcp.is_closed(), interrupt);
        assert_eq!(udp.is_closed(), interrupt);
        assert!(!unrelated.is_closed());
        assert!(!foreign.is_closed());
        let fresh = tracked(&router, "tcp", "group");
        router.select_member("group", "b").unwrap();
        assert!(!fresh.is_closed());
    }
}
#[tokio::test]
async fn tls_setup_is_bounded_for_tcp_and_udp() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let peer = tokio::spawn(async move {
        loop {
            let (mut s, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut bytes = [0; 4096];
                let _ = s.read(&mut bytes).await;
                tokio::time::sleep(Duration::from_secs(40)).await;
            });
        }
    });
    let router=Router::new(&json!({"outbounds":[{"type":"vless","tag":"node","server":"127.0.0.1","server_port":port,"uuid":"00000000-0000-0000-0000-000000000001","tls":{"enabled":true,"server_name":"localhost","insecure":true}}]})).unwrap();
    let idx = router.index_of("node").unwrap();
    let target = Target::Domain("example.com".into(), 443);
    let start = std::time::Instant::now();
    let (tcp, udp) = tokio::time::timeout(Duration::from_secs(18), async {
        tokio::join!(
            router.connect_index(idx, &target),
            router.connect_udp_index(idx, &target)
        )
    })
    .await
    .expect("setup must end without caller cancellation");
    assert_eq!(tcp.err().unwrap().kind(), std::io::ErrorKind::TimedOut);
    assert_eq!(udp.err().unwrap().kind(), std::io::ErrorKind::TimedOut);
    assert!(start.elapsed() >= Duration::from_secs(14));
    peer.abort();
}
#[tokio::test]
async fn xhttp_setup_timeout_releases_the_only_pool_slot() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let router=Router::new(&json!({"outbounds":[{"type":"vless","tag":"node","server":"127.0.0.1","server_port":listener.local_addr().unwrap().port(),"uuid":"00000000-0000-0000-0000-000000000001","tls":{"enabled":true,"server_name":"localhost","insecure":true},"transport":{"type":"xhttp","mode":"stream-one","xmux":{"max_connections":1}}}]})).unwrap();
    let idx = router.index_of("node").unwrap();
    let target = Target::Domain("example.com".into(), 443);
    let first = router.connect_index(idx, &target);
    tokio::pin!(first);
    let socket = tokio::select! { accepted=listener.accept()=>accepted.unwrap().0, _=&mut first=>panic!("must reach peer") };
    let result = tokio::time::timeout(Duration::from_secs(18), &mut first)
        .await
        .unwrap();
    assert_eq!(result.err().unwrap().kind(), std::io::ErrorKind::TimedOut);
    let retry = router.connect_index(idx, &target);
    tokio::pin!(retry);
    tokio::time::timeout(Duration::from_secs(2),async {
        tokio::select! { accepted=listener.accept()=>{let _=accepted.unwrap();}, _=&mut retry=>panic!("must dial again") }
    }).await.expect("timed-out TLS dial must release the only XHTTP pool slot");
    drop(socket);
}
#[tokio::test]
async fn selector_switch_ends_an_established_tcp_relay() {
    use tokio::io::AsyncWriteExt;
    let router = router(true);
    let (client, mut caller) = tokio::io::duplex(1024);
    let (upstream, mut server) = tokio::io::duplex(1024);
    let tracker = tracked(&router, "tcp", "group");
    let relay = tokio::spawn(async move {
        core_runtime::inbound::pump_conn_tracked(
            client,
            core_runtime::inbound::Conn::Plain(Box::new(upstream)),
            &[],
            Some(&tracker),
        )
        .await
    });
    caller.write_all(b"request").await.unwrap();
    let mut buf = [0; 7];
    server.read_exact(&mut buf).await.unwrap();
    router.select_member("group", "b").unwrap();
    let result = tokio::time::timeout(Duration::from_secs(2), relay)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    assert_eq!(caller.read(&mut buf).await.unwrap(), 0);
}
#[tokio::test]
async fn selector_switch_interrupts_a_blocked_prefix_write() {
    let router = router(true);
    let (client, _caller) = tokio::io::duplex(1);
    let (upstream, _server) = tokio::io::duplex(1);
    let tracker = tracked(&router, "tcp", "group");
    let relay = tokio::spawn(async move {
        core_runtime::inbound::pump_conn_tracked(
            client,
            core_runtime::inbound::Conn::Plain(Box::new(upstream)),
            b"blocked prefix",
            Some(&tracker),
        )
        .await
    });
    tokio::task::yield_now().await;
    router.select_member("group", "b").unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}
#[tokio::test]
async fn long_configured_setup_survives_fifteen_seconds_but_group_switch_cancels_it() {
    use tokio::{io::AsyncWriteExt, net::TcpStream};
    let silent = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let destination = echo.local_addr().unwrap();
    let instance = core_runtime::start(&json!({
        "log":{"level":"error"},
        "inbounds":[{"type":"mixed","tag":"in","listen":"127.0.0.1","listen_port":0}],
        "outbounds":[
            {"type":"vless","tag":"old","server":"127.0.0.1","server_port":silent.local_addr().unwrap().port(),"uuid":"00000000-0000-0000-0000-000000000001","connect_timeout":"30s","tls":{"enabled":true,"server_name":"localhost","insecure":true}},
            {"type":"direct","tag":"new"},
            {"type":"selector","tag":"group","outbounds":["old","new"],"interrupt_exist_connections":true}
        ],"route":{"final":"group"}
    })).await.unwrap();
    let proxy = instance.inbound_addrs()[0].1;
    let request = format!("CONNECT {destination} HTTP/1.1\r\nHost: {destination}\r\n\r\n");
    let mut old_client = TcpStream::connect(proxy).await.unwrap();
    old_client.write_all(request.as_bytes()).await.unwrap();
    // HTTP CONNECT acknowledges its tunnel before outbound setup completes.
    let mut initial_head = Vec::new();
    while !initial_head.ends_with(b"\r\n\r\n") {
        initial_head.push(old_client.read_u8().await.unwrap());
    }
    assert!(String::from_utf8(initial_head).unwrap().contains("200"));
    let (_silent_socket, _) = tokio::time::timeout(Duration::from_secs(2), silent.accept())
        .await
        .unwrap()
        .unwrap();
    let mut buf = [0; 1024];
    assert!(
        tokio::time::timeout(Duration::from_secs(16), old_client.read(&mut buf))
            .await
            .is_err(),
        "configured long dial must not hit a fixed 15s cap"
    );
    instance.router().select_member("group", "new").unwrap();
    tokio::time::timeout(Duration::from_secs(2), old_client.read(&mut buf))
        .await
        .expect("old setup must be cancelled by switching")
        .unwrap();
    let mut fresh = TcpStream::connect(proxy).await.unwrap();
    fresh.write_all(request.as_bytes()).await.unwrap();
    let (mut server, _) = tokio::time::timeout(Duration::from_secs(2), echo.accept())
        .await
        .unwrap()
        .unwrap();
    let mut head = Vec::new();
    tokio::time::timeout(Duration::from_secs(2), async {
        while !head.ends_with(b"\r\n\r\n") {
            head.push(fresh.read_u8().await.unwrap());
        }
    })
    .await
    .unwrap();
    assert!(String::from_utf8(head).unwrap().contains("200"));
    fresh.write_all(b"ok").await.unwrap();
    let mut data = [0; 2];
    server.read_exact(&mut data).await.unwrap();
    server.write_all(&data).await.unwrap();
    fresh.read_exact(&mut data).await.unwrap();
    assert_eq!(&data, b"ok");
    instance.shutdown_wait().await;
}
