//! SEC-18: the controller drops clients that never finish a request head and
//! keeps accepting after a transient `accept` error (`EMFILE`).

use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{Mutex, MutexGuard};

const HEADER_TIMEOUT_MS: u64 = 300;

/// The tests share process-wide state (the environment, `RLIMIT_NOFILE`),
/// so they run one at a time.
async fn guard() -> MutexGuard<'static, ()> {
    static LOCK: Mutex<()> = Mutex::const_new(());
    static ENV: std::sync::Once = std::sync::Once::new();
    ENV.call_once(|| {
        // SAFETY: set once, before any box of this binary is started; every
        // test takes this guard first.
        unsafe {
            std::env::set_var(
                "TACHYON_CLASH_API_HEADER_TIMEOUT_MS",
                HEADER_TIMEOUT_MS.to_string(),
            );
        }
    });
    LOCK.lock().await
}

async fn start() -> core_runtime::BoxInstance {
    core_runtime::start(&json!({
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}},
        "outbounds": [{"type": "direct", "tag": "direct"}]
    }))
    .await
    .expect("start")
}

/// Status of `GET /version`, or `None` when the controller does not answer
/// within five seconds.
async fn version(addr: std::net::SocketAddr) -> Option<u16> {
    let request = async {
        let mut stream = TcpStream::connect(addr).await.ok()?;
        stream
            .write_all(b"GET /version HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .await
            .ok()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.ok()?;
        String::from_utf8_lossy(&response)
            .split_whitespace()
            .nth(1)?
            .parse()
            .ok()
    };
    tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .ok()
        .flatten()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn silent_client_is_closed_after_header_timeout() {
    let _guard = guard().await;
    let instance = start().await;
    let addr = instance.clash_api_addr().unwrap();

    // Connected, nothing sent.
    let mut silent = TcpStream::connect(addr).await.unwrap();
    // A request line that never ends.
    let mut partial = TcpStream::connect(addr).await.unwrap();
    partial.write_all(b"GET /version HTTP/1.1\r\nHo").await.unwrap();

    for stream in [&mut silent, &mut partial] {
        let mut buf = [0u8; 64];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        assert!(
            matches!(read, Ok(Ok(0)) | Ok(Err(_))),
            "connection still open: {read:?}"
        );
    }
    // Complete requests are unaffected.
    assert_eq!(version(addr).await, Some(200));
    instance.shutdown_wait().await;
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn accept_error_does_not_stop_the_controller() {
    let _guard = guard().await;
    let instance = start().await;
    let addr = instance.clash_api_addr().unwrap();
    assert_eq!(version(addr).await, Some(200));

    let mut saved = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: plain libc calls on descriptors this test owns.
    let (probe, fillers, errno, connected) = unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut saved), 0);
        let probe = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
        assert!(probe >= 0);
        // The soft limit sits right above `probe`; the free slots below it
        // are filled, so the controller's next `accept` fails with EMFILE.
        let tight = libc::rlimit {
            rlim_cur: probe as libc::rlim_t + 1,
            rlim_max: saved.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &tight), 0);
        let mut fillers = Vec::new();
        let errno = loop {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0);
            if fd < 0 {
                break std::io::Error::last_os_error().raw_os_error();
            }
            fillers.push(fd);
        };
        let addr_in = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: addr.port().to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from(std::net::Ipv4Addr::LOCALHOST).to_be(),
            },
            sin_zero: [0; 8],
        };
        let connected = libc::connect(
            probe,
            (&addr_in as *const libc::sockaddr_in).cast(),
            std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
        );
        (probe, fillers, errno, connected)
    };
    // Give the accept loop time to hit the error.
    tokio::time::sleep(Duration::from_millis(500)).await;
    // SAFETY: as above.
    unsafe {
        for fd in fillers {
            libc::close(fd);
        }
        libc::close(probe);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &saved), 0);
        assert_eq!(errno, Some(libc::EMFILE));
        assert_eq!(connected, 0);
    }

    assert_eq!(
        version(addr).await,
        Some(200),
        "controller stopped accepting after EMFILE"
    );
    instance.shutdown_wait().await;
}
