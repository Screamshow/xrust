//! Isolated allocation probe: borrowed-prefix lifetime versus owned-prefix relay.
//! System allocator on both modes; no network listeners or router services.
use core_runtime::inbound::{Conn, pump_conn_tracked, pump_conn_tracked_owned};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct CountAlloc;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOC: CountAlloc = CountAlloc;

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let borrowed = match args.get(1).map(String::as_str) {
        Some("borrowed") => true,
        Some("owned") => false,
        _ => panic!("usage: sniff_prefix_memory borrowed|owned [connections] [prefix_bytes]"),
    };
    let count: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(80);
    let bytes: usize = args.get(3).map(|s| s.parse().unwrap()).unwrap_or(2048);
    assert!((1..=1000).contains(&count) && (1..=65536).contains(&bytes));
    let mut peers = Vec::with_capacity(count);
    let mut tasks = Vec::with_capacity(count);
    let before = LIVE.load(Ordering::Relaxed);
    for _ in 0..count {
        let prefix = vec![0x5a; bytes];
        let (client, caller) = tokio::io::duplex(1024);
        let (upstream, mut server) = tokio::io::duplex(1024);
        tasks.push(tokio::spawn(async move {
            let conn = Conn::Plain(Box::new(upstream));
            if borrowed {
                // Keep the original allocation borrowed as the former inbound did.
                pump_conn_tracked(client, conn, &prefix, None)
                    .await
                    .unwrap();
            } else {
                pump_conn_tracked_owned(client, conn, prefix, None)
                    .await
                    .unwrap();
            }
        }));
        let mut received = vec![0; bytes];
        server.read_exact(&mut received).await.unwrap();
        assert!(received.iter().all(|b| *b == 0x5a));
        peers.push((caller, server));
    }
    tokio::task::yield_now().await;
    let held = LIVE.load(Ordering::Relaxed) - before;
    println!(
        "mode={} connections={count} prefix_bytes={bytes} held_live_delta={held}",
        args[1]
    );
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines().filter(|line| {
            ["VmRSS:", "RssAnon:", "VmHWM:"]
                .iter()
                .any(|key| line.starts_with(key))
        }) {
            println!("{line}");
        }
    }
    for (mut caller, mut server) in peers {
        caller.write_all(b"after prefix").await.unwrap();
        let mut received = [0; 12];
        server.read_exact(&mut received).await.unwrap();
        assert_eq!(&received, b"after prefix");
        caller.shutdown().await.unwrap();
        assert_eq!(server.read(&mut received).await.unwrap(), 0);
        server.shutdown().await.unwrap();
    }
    for task in tasks {
        task.await.unwrap();
    }
    println!("all_connections_completed=true");
}
