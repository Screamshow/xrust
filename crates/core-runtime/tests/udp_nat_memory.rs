//! UDP NAT through a real direct inbound: an open flow must not pin a 64 KiB
//! receive buffer, and the flow table must stay at its cap however many
//! sources show up. Counts live Rust heap bytes and the process's open fds.
#![cfg(target_os = "linux")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicIsize, AtomicUsize, Ordering};
use std::time::Duration;

use core_runtime::inbound::direct::Direct;
use core_runtime::route::Router;
use serde_json::json;
use tokio::net::UdpSocket;

struct CountAlloc;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) };
    }
}
#[global_allocator]
static ALLOC: CountAlloc = CountAlloc;

/// The default `MAX_UDP_FLOWS` of a hub.
const CAP: usize = 1024;

/// A direct UDP inbound whose every datagram goes to `target`.
async fn inbound_to(target: SocketAddr) -> SocketAddr {
    let router = Router::new(&json!({
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .expect("router");
    let inbound = Direct::bind(
        &json!({"type": "direct", "tag": "d", "listen": "127.0.0.1", "listen_port": 0,
            "network": "udp", "override_address": target.ip().to_string(),
            "override_port": target.port()}),
        router,
    )
    .await
    .expect("direct inbound");
    let addr = inbound.local_addr().expect("inbound addr");
    tokio::spawn(inbound.serve());
    addr
}

/// One new flow: a fresh source sends `payload` and waits for the echo.
async fn echoed_flow(inbound: SocketAddr, payload: &[u8]) -> UdpSocket {
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
    client.send_to(payload, inbound).await.expect("send");
    let mut buf = [0u8; 2048];
    let n = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("echo in time")
        .expect("echo");
    assert_eq!(&buf[..n], payload);
    client
}

fn open_fds() -> usize {
    std::fs::read_dir("/proc/self/fd").expect("fds").count()
}

/// Room for the uncapped table, so that a missing cap shows up as fds and
/// not as failing opens.
fn raise_fd_limit(want: u64) -> bool {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain get/setrlimit on a local struct.
    unsafe {
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 || limit.rlim_max < want {
            return false;
        }
        limit.rlim_cur = limit.rlim_cur.max(want);
        libc::setrlimit(libc::RLIMIT_NOFILE, &limit) == 0
    }
}

#[tokio::test]
async fn udp_flows_keep_no_receive_buffer_and_stay_at_the_cap() {
    let echo = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("echo"));
    let echo_addr = echo.local_addr().expect("echo addr");
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        while let Ok((n, peer)) = echo.recv_from(&mut buf).await {
            let _ = echo.send_to(&buf[..n], peer).await;
        }
    });
    let inbound = inbound_to(echo_addr).await;

    // warm the inbound, the runtime and any per-thread buffer first
    let mut clients = Vec::new();
    for _ in 0..8 {
        clients.push(echoed_flow(inbound, &[7; 100]).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let before = LIVE.load(Ordering::Relaxed);
    const FLOWS: usize = 64;
    for _ in 0..FLOWS {
        clients.push(echoed_flow(inbound, &[7; 100]).await);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    let per_flow = (LIVE.load(Ordering::Relaxed) - before) / FLOWS as isize;
    println!("PROBE live_heap_per_open_udp_flow={per_flow}");
    let small_flows = per_flow < 16 * 1024;

    if !raise_fd_limit(4096) {
        eprintln!("skipping the cap half: RLIMIT_NOFILE hard limit below 4096");
        assert!(
            small_flows,
            "an open UDP flow holds {per_flow} bytes of heap"
        );
        return;
    }
    let sink = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("sink"));
    let sink_addr = sink.local_addr().expect("sink addr");
    let reached = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&reached);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        while sink.recv_from(&mut buf).await.is_ok() {
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let inbound = inbound_to(sink_addr).await;
    tokio::time::sleep(Duration::from_millis(100)).await;
    let fds_before = open_fds();
    const SOURCES: usize = CAP + 300;
    for i in 0..SOURCES {
        // a source that sends once and goes away, as a P2P peer does
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        client.send_to(&[1; 64], inbound).await.expect("send");
        if i % 8 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
    let _ = tokio::time::timeout(Duration::from_secs(5), async {
        while reached.load(Ordering::Relaxed) < SOURCES - 20 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    let opened = reached.load(Ordering::Relaxed);
    let held = open_fds().saturating_sub(fds_before);
    println!("PROBE udp_sources={SOURCES} reached_sink={opened} extra_fds={held}");
    assert!(
        opened >= SOURCES - 20,
        "only {opened} flows reached the sink"
    );
    assert!(
        small_flows && held <= CAP + 16,
        "an open UDP flow holds {per_flow} bytes of heap (want < 16 KiB); \
         {SOURCES} sources left {held} sockets open (cap {CAP})"
    );
}
