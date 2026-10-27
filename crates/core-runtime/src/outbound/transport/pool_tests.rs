//! Pooled HTTP/2 connections for the gRPC and HTTP/2 transports: several
//! tunnels of one outbound share a connection, as the reference clients' do,
//! and a connection that has gone bad leaves the pool.
//!
//! The server here speaks plaintext HTTP/2, which is the shape gRPC takes
//! without TLS (prior knowledge); the HTTP/2 transport pools only over TLS, so
//! its pooled path is covered by the stream test at the bottom and by the
//! decision test, not by a TLS rig.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use super::*;

/// What a connection of the test server does once it has served a stream.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Serve {
    /// Keep accepting streams for as long as the client wants them.
    Streams,
    /// Serve one stream, then send GOAWAY and drain.
    Goaway,
    /// Serve one stream, then close the socket.
    Close,
    /// Serve every stream but reset the second one.
    ResetSecond,
}

/// Echoes everything written to a tunnel back to it.
async fn echo(mut stream: AnyStream) {
    let mut buf = vec![0u8; 4096];
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
}

async fn serve_connection(io: TcpStream, mode: Serve) {
    let mut conn = match super::h2io::server_builder().handshake(io).await {
        Ok(conn) => conn,
        Err(_) => return,
    };
    let mut served = 0usize;
    while let Some(accepted) = conn.accept().await {
        let Ok((request, mut respond)) = accepted else {
            return;
        };
        served += 1;
        if mode == Serve::ResetSecond && served == 2 {
            respond.send_reset(h2::Reason::CANCEL);
            continue;
        }
        let response = ::http::Response::builder()
            .status(200)
            .header("content-type", "application/grpc")
            .body(())
            .expect("response");
        let Ok(send) = respond.send_response(response, false) else {
            return;
        };
        let echoing = tokio::spawn(echo(super::grpc::server(request.into_body(), send)));
        match mode {
            Serve::Goaway if served == 1 => {
                conn.graceful_shutdown();
                // Keep polling so the GOAWAY leaves and the connection drains.
                while conn.accept().await.is_some() {}
                return;
            }
            Serve::Close if served == 1 => {
                // The tunnel is done when the client lets go of it; the socket
                // goes right after, which is the peer close under test. The
                // connection has to keep being polled meanwhile, or the stream
                // the echo runs on never progresses.
                tokio::select! {
                    _ = echoing => {}
                    _ = async { while conn.accept().await.is_some() {} } => {}
                }
                return;
            }
            _ => {}
        }
    }
}

/// A server on localhost, with the number of TCP connections it has accepted.
async fn spawn_server(mode: Serve) -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let accepts = Arc::new(AtomicUsize::new(0));
    let counted = accepts.clone();
    tokio::spawn(async move {
        loop {
            let Ok((io, _)) = listener.accept().await else {
                return;
            };
            counted.fetch_add(1, Ordering::Relaxed);
            tokio::spawn(serve_connection(io, mode));
        }
    });
    (port, accepts)
}

fn grpc_transport() -> Transport {
    let obj = serde_json::json!({"transport": {"type": "grpc", "service_name": "GunService"}});
    Transport::parse(obj.as_object().expect("an object"), "outbounds[0]").expect("parse")
}

async fn dial(transport: &Transport, port: u16) -> io::Result<AnyStream> {
    transport
        .connect_or_dial(
            None,
            "127.0.0.1",
            port,
            &crate::outbound::dial::DialOptions::default(),
        )
        .await
}

/// A tunnel is alive both ways.
async fn roundtrip(stream: &mut AnyStream, payload: &[u8]) {
    stream.write_all(payload).await.expect("write");
    let mut back = vec![0u8; payload.len()];
    stream.read_exact(&mut back).await.expect("read back");
    assert_eq!(back, payload);
}

/// Three tunnels, one TLS/TCP connection and one HTTP/2 handshake: what Xray's
/// gRPC dialer does with its single `ClientConn`, where a connection per
/// tunnel showed a handshake each.
#[tokio::test]
async fn three_grpc_tunnels_share_one_connection() {
    let (port, accepts) = spawn_server(Serve::Streams).await;
    let transport = grpc_transport();
    let mut tunnels = Vec::new();
    for _ in 0..3 {
        tunnels.push(dial(&transport, port).await.expect("dial"));
    }
    // every tunnel carries its own traffic while the others are open
    for (i, tunnel) in tunnels.iter_mut().enumerate() {
        roundtrip(tunnel, format!("tunnel {i}").as_bytes()).await;
    }
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        1,
        "one connection accepted"
    );
    for (i, tunnel) in tunnels.iter_mut().enumerate().rev() {
        roundtrip(tunnel, format!("again {i}").as_bytes()).await;
    }
    assert_eq!(accepts.load(Ordering::Relaxed), 1);
    assert_eq!(transport.pooled_connections(), 1);
}

/// A tunnel that ends gives its slot back without taking the connection with
/// it: the next dial reuses it.
#[tokio::test]
async fn a_finished_tunnel_leaves_the_connection_pooled() {
    let (port, accepts) = spawn_server(Serve::Streams).await;
    let transport = grpc_transport();
    {
        let mut first = dial(&transport, port).await.expect("first dial");
        roundtrip(&mut first, b"first").await;
    }
    let mut second = dial(&transport, port).await.expect("second dial");
    roundtrip(&mut second, b"second").await;
    assert_eq!(accepts.load(Ordering::Relaxed), 1, "the pool was reused");
}

/// A GOAWAY ends the connection's life in the pool; the next dial opens a
/// fresh one and works.
#[tokio::test]
async fn a_goaway_evicts_the_pooled_connection() {
    let (port, accepts) = spawn_server(Serve::Goaway).await;
    let transport = grpc_transport();
    let mut first = dial(&transport, port).await.expect("first dial");
    roundtrip(&mut first, b"before goaway").await;
    drop(first);

    let mut second = dial(&transport, port).await.expect("dial after goaway");
    roundtrip(&mut second, b"after goaway").await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        2,
        "the spent connection was not reused"
    );
}

/// The same when the peer simply closes the socket: the spent connection is
/// not handed to the next tunnel, which gets one of its own.
#[tokio::test]
async fn a_peer_close_evicts_the_pooled_connection() {
    let (port, accepts) = spawn_server(Serve::Close).await;
    let transport = grpc_transport();
    let mut first = dial(&transport, port).await.expect("first dial");
    roundtrip(&mut first, b"before close").await;
    // the server closes the socket once this tunnel is gone
    drop(first);
    tokio::time::sleep(Duration::from_millis(100)).await;

    // The first dial after the close may still be handed the spent
    // connection; opening a stream on it fails, the pool drops it, and the
    // dial after that one makes a connection of its own.
    let mut second = None;
    for _ in 0..10 {
        if let Ok(mut stream) = dial(&transport, port).await {
            let mut back = [0u8; 11];
            if stream.write_all(b"after close").await.is_ok()
                && stream.read_exact(&mut back).await.is_ok()
            {
                assert_eq!(&back, b"after close");
                second = Some(stream);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    assert!(second.is_some(), "no tunnel after the peer close");
    let accepted = accepts.load(Ordering::Relaxed);
    assert!(
        (2..=4).contains(&accepted),
        "{accepted} connections for two tunnels"
    );
}

/// A connection with no tunnel on it is closed after the idle limit, Go's
/// `net.ConnIdleTimeout`, and is not handed out again.
#[tokio::test]
async fn an_idle_pooled_connection_is_closed() {
    let (port, accepts) = spawn_server(Serve::Streams).await;
    // the limit is 300 s in a release; the test injects one it can wait for
    let transport = grpc_transport().with_h2_idle(Some(Duration::from_millis(150)));
    {
        let mut tunnel = dial(&transport, port).await.expect("dial");
        tunnel.write_all(b"hello").await.expect("write");
        let mut back = [0u8; 5];
        tunnel.read_exact(&mut back).await.expect("read back");
    }
    assert_eq!(transport.pooled_connections(), 1);
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(
        transport.pooled_connections(),
        0,
        "the idle connection left the pool"
    );
    let mut fresh = dial(&transport, port).await.expect("dial after the close");
    roundtrip(&mut fresh, b"fresh").await;
    assert_eq!(accepts.load(Ordering::Relaxed), 2);
}

/// One tunnel the server resets does not take its siblings with it: they are
/// streams on the same connection, not connections of their own.
#[tokio::test]
async fn a_reset_tunnel_leaves_its_siblings_alone() {
    let (port, accepts) = spawn_server(Serve::ResetSecond).await;
    let transport = grpc_transport();
    let mut first = dial(&transport, port).await.expect("first dial");
    let mut doomed = dial(&transport, port).await.expect("second dial");
    let mut third = dial(&transport, port).await.expect("third dial");

    roundtrip(&mut first, b"first").await;
    assert_eq!(accepts.load(Ordering::Relaxed), 1);
    // the reset arrives as an error on the stream the server refused
    let _ = doomed.write_all(b"doomed").await;
    let mut sink = [0u8; 8];
    assert!(
        doomed.read(&mut sink).await.is_err(),
        "a reset stream must report it"
    );
    drop(doomed);

    roundtrip(&mut third, b"third").await;
    roundtrip(&mut first, b"first again").await;
    assert_eq!(accepts.load(Ordering::Relaxed), 1);
}

/// With every connection at its stream limit the pool opens another one
/// instead of queueing, which is what Go's client does once a connection
/// reaches the server's `MAX_CONCURRENT_STREAMS`.
#[tokio::test]
async fn the_pool_opens_a_second_connection_at_the_concurrency_limit() {
    let (port, accepts) = spawn_server(Serve::Streams).await;
    let transport = grpc_transport().with_h2_limits(2, 1);
    let mut first = dial(&transport, port).await.expect("first dial");
    let mut second = dial(&transport, port).await.expect("second dial");
    roundtrip(&mut first, b"first").await;
    roundtrip(&mut second, b"second").await;
    assert_eq!(
        accepts.load(Ordering::Relaxed),
        2,
        "the second tunnel got a connection of its own"
    );
    assert_eq!(transport.pooled_connections(), 2);
}

/// Which transports pool: gRPC always, the HTTP/2 transport over TLS (its
/// plaintext form is HTTP/1.1), and nothing else -- ws, httpupgrade and raw
/// streams are not HTTP/2 at all, and XHTTP has its own pool.
#[test]
fn only_the_http2_transports_pool() {
    let kind = |transport: serde_json::Value| {
        let obj = serde_json::json!({"transport": transport});
        Transport::parse(obj.as_object().expect("an object"), "outbounds[0]").expect("parse")
    };
    let grpc = kind(serde_json::json!({"type": "grpc", "service_name": "s"}));
    assert!(grpc.pools_h2(true) && grpc.pools_h2(false));
    let h2 = kind(serde_json::json!({"type": "http", "path": "/h"}));
    assert!(h2.pools_h2(true), "the h2 transport pools over TLS");
    assert!(!h2.pools_h2(false), "plaintext http is HTTP/1.1");
    for bare in [
        serde_json::json!({"type": "ws", "path": "/w"}),
        serde_json::json!({"type": "httpupgrade", "path": "/u"}),
        serde_json::json!({"type": "xhttp", "path": "/x"}),
    ] {
        let transport = kind(bare.clone());
        assert!(
            !transport.pools_h2(true) && !transport.pools_h2(false),
            "{bare}"
        );
    }
    assert!(!Transport::default().pools_h2(true));
}

/// The HTTP/2 transport's pooled request: a tunnel opened on a connection the
/// pool owns, with the method, path and host the config asked for.
#[tokio::test]
async fn the_http2_transport_opens_a_tunnel_on_a_shared_connection() {
    let (client_io, server_io) = tokio::io::duplex(64 * 1024);
    let server = tokio::spawn(async move {
        let mut conn = super::h2io::server_builder()
            .handshake::<_, bytes::Bytes>(server_io)
            .await
            .expect("server handshake");
        let (request, mut respond) = conn.accept().await.expect("a request").expect("accepted");
        let (parts, _body) = request.into_parts();
        let send = respond
            .send_response(
                ::http::Response::builder()
                    .status(200)
                    .body(())
                    .expect("body"),
                false,
            )
            .expect("respond");
        drop(send);
        tokio::spawn(async move { while conn.accept().await.is_some() {} });
        parts
    });

    let (send_request, connection) = super::h2io::client_builder()
        .handshake::<_, bytes::Bytes>(client_io)
        .await
        .expect("client handshake");
    tokio::spawn(async move {
        let _ = connection.await;
    });
    let mut send_req = send_request.ready().await.expect("ready");
    let hosts = vec!["cdn.example.com".to_string()];
    let headers = vec![("X-Test".to_string(), "1".to_string())];
    let _tunnel = super::http::open_pooled_h2(&mut send_req, &hosts, "/h2", "PUT", &headers)
        .expect("open pooled");
    let parts = server.await.expect("server task");
    assert_eq!(parts.method, ::http::Method::PUT);
    assert_eq!(parts.uri.path(), "/h2");
    assert_eq!(
        parts.uri.authority().map(|a| a.as_str()),
        Some("cdn.example.com")
    );
    assert_eq!(
        parts
            .headers
            .get("x-test")
            .map(|v| v.to_str().expect("ascii")),
        Some("1")
    );
}

/// What the pool saves on connection setup: twenty tunnels over pooled
/// connections against twenty that each handshake for themselves, which is
/// what the gRPC transport did before. Plaintext HTTP/2 against a local
/// server, so it leaves out the TLS handshake the saving is mostly about.
/// Run with `--ignored --nocapture`.
#[tokio::test]
#[ignore = "throughput probe"]
async fn pooling_cost_of_opening_tunnels() {
    const TUNNELS: usize = 20;
    let (port, accepts) = spawn_server(Serve::Streams).await;
    let transport = grpc_transport();

    let pooled_start = std::time::Instant::now();
    let mut pooled = Vec::new();
    for _ in 0..TUNNELS {
        pooled.push(dial(&transport, port).await.expect("pooled dial"));
    }
    for tunnel in pooled.iter_mut() {
        roundtrip(tunnel, b"probe").await;
    }
    let pooled_took = pooled_start.elapsed();
    let pooled_conns = accepts.load(Ordering::Relaxed);

    let own_start = std::time::Instant::now();
    let mut own = Vec::new();
    for _ in 0..TUNNELS {
        let tcp = TcpStream::connect(("127.0.0.1", port)).await.expect("tcp");
        own.push(
            transport
                .connect(
                    tcp,
                    None,
                    "127.0.0.1",
                    port,
                    &crate::outbound::dial::DialOptions::default(),
                )
                .await
                .expect("own dial"),
        );
    }
    for tunnel in own.iter_mut() {
        roundtrip(tunnel, b"probe").await;
    }
    let own_took = own_start.elapsed();

    println!(
        "{TUNNELS} tunnels: pooled {pooled_took:?} over {pooled_conns} connection(s), \
         one connection each {own_took:?} over {} connection(s)",
        accepts.load(Ordering::Relaxed) - pooled_conns
    );
}
