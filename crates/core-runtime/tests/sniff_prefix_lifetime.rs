//! The sniff allocation must be gone while the connection is still usable.
use core_runtime::inbound::{Conn, pump_conn_tracked_owned};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

struct WatchAlloc;
static WATCH: AtomicUsize = AtomicUsize::new(0);
static FREED: AtomicBool = AtomicBool::new(false);
unsafe impl GlobalAlloc for WatchAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCH
            .compare_exchange(ptr as usize, 0, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            FREED.store(true, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOC: WatchAlloc = WatchAlloc;

async fn exercise<S>(client: S, upstream: S, mut caller: S, mut server: S)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut prefix = Vec::with_capacity(64 * 1024);
    prefix.extend_from_slice(b"sniffed bytes");
    FREED.store(false, Ordering::SeqCst);
    WATCH.store(prefix.as_ptr() as usize, Ordering::SeqCst);
    let relay = tokio::spawn(pump_conn_tracked_owned(
        client,
        Conn::Plain(Box::new(upstream)),
        prefix,
        None,
    ));
    let mut got = [0; 13];
    server.read_exact(&mut got).await.unwrap();
    assert_eq!(&got, b"sniffed bytes");
    tokio::time::timeout(Duration::from_secs(2), async {
        while !FREED.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("prefix allocation retained by a live relay");
    assert!(!relay.is_finished(), "connection must still be open");
    caller.write_all(b"next").await.unwrap();
    let mut next = [0; 4];
    server.read_exact(&mut next).await.unwrap();
    assert_eq!(&next, b"next");
    caller.shutdown().await.unwrap();
    assert_eq!(server.read(&mut next).await.unwrap(), 0);
    server.write_all(b"response after EOF").await.unwrap();
    server.shutdown().await.unwrap();
    let mut response = Vec::new();
    caller.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response after EOF");
    relay.await.unwrap().unwrap();
}

#[tokio::test]
async fn prefix_is_freed_before_userspace_and_splice_relays_finish() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (client, caller) = tokio::io::duplex(1024);
        let (upstream, server) = tokio::io::duplex(1024);
        exercise(client, upstream, caller, server).await;
        #[cfg(target_os = "linux")]
        {
            async fn pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let caller = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
                    .await
                    .unwrap();
                (listener.accept().await.unwrap().0, caller)
            }
            let (client, caller) = pair().await;
            let (upstream, server) = pair().await;
            exercise(client, upstream, caller, server).await;
        }
    })
    .await
    .expect("relay lifecycle timed out");
}
