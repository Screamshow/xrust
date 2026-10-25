//! `hijack-dns` on a direct UDP inbound while the upstream never answers: a
//! flood of queries must not turn into a task, a socket and a buffer each.

use std::time::Duration;

use core_runtime::dns::codec::build_query;
use hickory_proto::rr::RecordType;
use serde_json::json;
use tokio::net::UdpSocket;

/// `MAX_DNS_HIJACKS` of a hub.
const SLOTS: usize = 256;

async fn alive_tasks() -> usize {
    tokio::time::sleep(Duration::from_millis(300)).await;
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

#[tokio::test]
async fn hijacked_dns_exchanges_in_flight_are_bounded() {
    // takes every query, answers none: each exchange waits out its timeout
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("upstream");
    let upstream = silent.local_addr().expect("upstream addr");
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "direct", "tag": "dns-in", "listen": "127.0.0.1",
            "listen_port": 0, "network": "udp"}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"rules": [{"inbound": "dns-in", "action": "hijack-dns"}], "final": "direct"},
        "dns": {
            "servers": [{"type": "udp", "tag": "up", "server": "127.0.0.1",
                "server_port": upstream.port()}],
            "final": "up"
        }
    }))
    .await
    .expect("start");
    let inbound = instance
        .inbound_addrs()
        .iter()
        .find(|(tag, _)| tag == "dns-in")
        .map(|(_, addr)| *addr)
        .expect("dns inbound addr");

    let before = alive_tasks().await;
    const QUERIES: usize = 600;
    for i in 0..QUERIES {
        // a fresh source port per query, as dnsmasq and stub resolvers use
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let query =
            build_query(i as u16, &format!("q{i}.flood.test"), RecordType::A).expect("query");
        client.send_to(&query, inbound).await.expect("send");
        if i % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    let in_flight = alive_tasks().await.saturating_sub(before);
    println!("PROBE dns_queries={QUERIES} tasks_in_flight={in_flight}");
    assert!(
        in_flight <= SLOTS + 32,
        "{QUERIES} unanswered queries left {in_flight} tasks running (limit {SLOTS})"
    );
    assert!(
        in_flight >= SLOTS / 2,
        "only {in_flight} exchanges started; the flood did not reach the upstream"
    );
    instance.shutdown();
    drop(silent);
}
