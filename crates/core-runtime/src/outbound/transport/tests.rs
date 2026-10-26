//! Websocket transport tests. The early-data path rewrites the upgrade request,
//! so the wire format is what matters here.

use super::*;
use std::future::poll_fn;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::AsyncReadExt;

/// Reads the upgrade request, replies 101 and hands the request head back.
async fn ws_server(listener: tokio::net::TcpListener) -> String {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        socket.read_exact(&mut byte).await.expect("read head");
        head.push(byte[0]);
    }
    let key = String::from_utf8_lossy(&head)
        .lines()
        .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: ").map(str::to_string))
        .expect("key");
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    hash.update(WS_GUID);
    let accept = base64_std(&hash.finalize());
    socket
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("reply");
    String::from_utf8_lossy(&head).into_owned()
}

fn ws_transport(max_early_data: usize, header_name: &str) -> Transport {
    Transport {
        kind: Kind::Ws {
            path: "/t".into(),
            host: None,
            headers: vec![("X-Test".into(), "1".into())],
            max_early_data,
            early_data_header_name: header_name.into(),
        },
    }
}

async fn connect_transport(
    listener: tokio::net::TcpListener,
    transport: Transport,
    early: &[u8],
) -> (String, usize) {
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move { ws_server(listener).await });
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    let lazy = matches!(transport.kind, Kind::Ws { max_early_data, .. } if max_early_data > 0);
    let mut stream = transport
        .connect(
            tcp,
            None,
            "example.com",
            port,
            &crate::outbound::dial::DialOptions::default(),
        )
        .await
        .expect("handshake");
    // with early data the upgrade request goes out with the first write
    let consumed = if lazy {
        tokio::io::AsyncWriteExt::write(&mut stream, early)
            .await
            .expect("first write")
    } else {
        0
    };
    drop(stream);
    (server.await.expect("join"), consumed)
}

async fn connect_with(max_early_data: usize, header_name: &str, early: &[u8]) -> (String, usize) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    connect_transport(listener, ws_transport(max_early_data, header_name), early).await
}

fn raw_url(data: &[u8]) -> String {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(data)
}

const SWP: &str = "Sec-WebSocket-Protocol";

#[tokio::test]
async fn early_data_rides_in_the_named_header() {
    let payload = b"the first protocol write".to_vec();
    let (head, consumed) = connect_with(2048, SWP, &payload).await;
    assert_eq!(consumed, payload.len(), "the whole write went early");
    assert!(head.starts_with("GET /t HTTP/1.1\r\n"), "got:\n{head}");
    assert!(head.contains("X-Test: 1\r\n"), "other headers survive");
    assert!(
        head.contains(&format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            raw_url(&payload)
        )),
        "got:\n{head}"
    );
}

/// base64url without padding, as sing-box and Xray write it: these bytes are
/// `+/8=` in standard base64.
#[tokio::test]
async fn early_data_is_base64url_without_padding() {
    let (head, consumed) = connect_with(2048, SWP, &[0xfb, 0xff]).await;
    assert_eq!(consumed, 2);
    assert!(
        head.contains("Sec-WebSocket-Protocol: -_8\r\n"),
        "got:\n{head}"
    );
    // lengths 1 and 2 mod 3 are the ones standard base64 pads
    for len in [1usize, 2, 4, 5, 26] {
        let payload: Vec<u8> = (0..len as u8).map(|i| i.wrapping_mul(97) | 0x80).collect();
        let (head, _) = connect_with(2048, SWP, &payload).await;
        let line = head
            .lines()
            .find_map(|l| l.strip_prefix("Sec-WebSocket-Protocol: "))
            .expect("header");
        assert_eq!(line, raw_url(&payload), "len {len}");
        assert!(!line.contains(['=', '+', '/']), "len {len}: {line}");
    }
}

#[tokio::test]
async fn early_data_rides_in_a_custom_header() {
    let (head, consumed) = connect_with(2048, "X-Early", b"abcd").await;
    assert_eq!(consumed, 4);
    assert!(head.starts_with("GET /t HTTP/1.1\r\n"), "got:\n{head}");
    assert!(head.contains(&format!("X-Early: {}\r\n", raw_url(b"abcd"))));
    assert!(!head.contains(SWP), "got:\n{head}");
}

/// No header name means `Sec-WebSocket-Protocol`, as Xray sends it and as
/// Forkop X's `ed=` configs expect -- not sing-box's path mode: the path is
/// left alone.
#[tokio::test]
async fn without_a_header_name_early_data_rides_in_sec_websocket_protocol() {
    let (head, consumed) = connect_with(2048, "", b"abcd").await;
    assert_eq!(consumed, 4);
    assert!(head.starts_with("GET /t HTTP/1.1\r\n"), "got:\n{head}");
    assert!(
        head.contains(&format!("Sec-WebSocket-Protocol: {}\r\n", raw_url(b"abcd"))),
        "got:\n{head}"
    );
}

#[tokio::test]
async fn without_the_budget_nothing_rides_along() {
    for name in [SWP, ""] {
        let (head, consumed) = connect_with(0, name, b"ignored").await;
        assert_eq!(consumed, 0);
        assert!(head.starts_with("GET /t HTTP/1.1\r\n"), "got:\n{head}");
        assert!(!head.contains(SWP), "got:\n{head}");
    }
}

/// A first write over the budget goes as a frame after a plain upgrade, as
/// Xray's client sends it: a server that reads the protocol head from the
/// first read alone would get a cut-off one from a split.
#[tokio::test]
async fn a_first_write_over_the_budget_rides_in_no_header() {
    let payload = b"0123456789abcdef";
    for (max, early) in [(10, false), (15, false), (16, true), (17, true)] {
        for name in [SWP, ""] {
            let (head, consumed) = connect_with(max, name, payload).await;
            assert_eq!(consumed, payload.len(), "max {max}");
            assert!(head.starts_with("GET /t HTTP/1.1\r\n"), "got:\n{head}");
            assert_eq!(
                head.contains(&format!("Sec-WebSocket-Protocol: {}\r\n", raw_url(payload))),
                early,
                "max {max}, got:\n{head}"
            );
            if !early {
                assert!(!head.contains(SWP), "max {max}, got:\n{head}");
            }
        }
    }
}

async fn connect_configured(header_name: &str, configured: &str) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let transport = Transport {
        kind: Kind::Ws {
            path: "/".into(),
            host: None,
            headers: vec![(configured.into(), "chat".into())],
            max_early_data: 2048,
            early_data_header_name: header_name.into(),
        },
    };
    connect_transport(listener, transport, b"payload").await.0
}

#[tokio::test]
async fn a_configured_header_of_the_same_name_is_replaced() {
    let head = connect_configured(SWP, "sec-websocket-protocol").await;
    assert!(!head.contains(": chat"), "got:\n{head}");
    assert_eq!(head.matches("ocket-Protocol:").count(), 1, "got:\n{head}");
    let head = connect_configured("X-Early", "x-early").await;
    assert!(!head.contains(": chat"), "got:\n{head}");
    assert!(head.contains(&format!("X-Early: {}\r\n", raw_url(b"payload"))));
    // with no name the early data takes Sec-WebSocket-Protocol over too
    let head = connect_configured("", SWP).await;
    assert!(!head.contains(": chat"), "got:\n{head}");
    assert_eq!(head.matches("ocket-Protocol:").count(), 1, "got:\n{head}");
    // a different header stays when the early data goes elsewhere
    let head = connect_configured("X-Early", SWP).await;
    assert!(
        head.contains("Sec-WebSocket-Protocol: chat\r\n"),
        "got:\n{head}"
    );
}

/// Our client against our server over a pipe: every budget and placement must
/// hand the server the exact bytes, early part first, and carry bytes back.
#[tokio::test]
async fn early_data_reaches_our_server_intact() {
    use crate::inbound::transport::{Accepted, Transport as Inbound};
    let payload: Vec<u8> = (0..64u8).map(|i| i.wrapping_mul(37) ^ 0xa5).collect();
    for name in [SWP, "X-Early", ""] {
        for max in [0usize, 1, 2, 3, 26, 63, 64, 65, 2048] {
            for len in [0usize, 1, 2, 26, 64] {
                let label = format!("header {name:?} max {max} len {len}");
                let mut config = serde_json::json!({"type": "ws", "path": "/t"});
                if max > 0 {
                    config["max_early_data"] = max.into();
                }
                if !name.is_empty() {
                    config["early_data_header_name"] = name.into();
                }
                let inbound =
                    Inbound::from_inbound(&serde_json::json!({"transport": config}), "in")
                        .expect("parse")
                        .expect("present");
                let (client, server) = tokio::io::duplex(1 << 16);
                let accept = tokio::spawn(async move {
                    let Accepted::Once(mut stream) =
                        inbound.accept(Box::new(server)).await.expect("accept")
                    else {
                        panic!("expected one session");
                    };
                    let mut got = vec![0u8; len];
                    stream.read_exact(&mut got).await.expect("server read");
                    stream.write_all(&got).await.expect("server write");
                    stream.flush().await.expect("flush");
                    got
                });
                let first = &payload[..len];
                let (mut stream, consumed) = ws_handshake(
                    Box::new(client),
                    "/t",
                    "example.com",
                    &[],
                    first,
                    EarlyData {
                        max,
                        header_name: name,
                    },
                )
                .await
                .expect("handshake");
                assert_eq!(consumed, len.min(max), "{label}");
                stream.write_all(&first[consumed..]).await.expect("rest");
                stream.flush().await.expect("flush");
                let mut back = vec![0u8; len];
                stream.read_exact(&mut back).await.expect("client read");
                assert_eq!(accept.await.expect("join"), first, "{label}: upstream");
                assert_eq!(back, first, "{label}: downstream");
            }
        }
    }
}

/// What our server makes of a raw upgrade request: the early data it hands
/// the protocol, or the refusal.
async fn server_takes(config: serde_json::Value, request: &str) -> Result<Vec<u8>, String> {
    use crate::inbound::transport::{Accepted, Transport as Inbound};
    let inbound = Inbound::from_inbound(&serde_json::json!({"transport": config}), "in")
        .expect("parse")
        .expect("present");
    let (mut client, server) = tokio::io::duplex(1 << 16);
    client.write_all(request.as_bytes()).await.expect("write");
    // closing the client side ends the session right after the early data
    client.shutdown().await.expect("shutdown");
    let accepted = inbound.accept(Box::new(server)).await;
    let Accepted::Once(mut stream) = accepted.map_err(|e| e.to_string())? else {
        panic!("expected one session");
    };
    drop(client);
    let mut got = Vec::new();
    let _ = stream.read_to_end(&mut got).await;
    Ok(got)
}

fn upgrade(target: &str, extra: &str) -> String {
    format!(
        "GET {target} HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{extra}\r\n"
    )
}

#[tokio::test]
async fn our_server_reads_early_data_where_it_was_configured() {
    let header = serde_json::json!({"type": "ws", "path": "/t",
        "max_early_data": 2048, "early_data_header_name": SWP});
    let custom = serde_json::json!({"type": "ws", "path": "/t",
        "max_early_data": 2048, "early_data_header_name": "X-Early"});
    // the shape Forkop X writes: a budget and no header name
    let unnamed = serde_json::json!({"type": "ws", "path": "/t", "max_early_data": 2048});
    let plain = serde_json::json!({"type": "ws", "path": "/t"});
    let ed = raw_url(&[0xfb, 0xff, 0x00, 0x01]);
    let swp = format!("Sec-WebSocket-Protocol: {ed}\r\n");

    let got = server_takes(header.clone(), &upgrade("/t", &swp)).await;
    assert_eq!(got.as_deref(), Ok(&[0xfb, 0xff, 0x00, 0x01][..]));
    let got = server_takes(
        custom.clone(),
        &upgrade("/t", &format!("x-early: {ed}\r\n")),
    )
    .await;
    assert_eq!(got.as_deref(), Ok(&[0xfb, 0xff, 0x00, 0x01][..]));
    let got = server_takes(unnamed.clone(), &upgrade("/t", &swp)).await;
    assert_eq!(got.as_deref(), Ok(&[0xfb, 0xff, 0x00, 0x01][..]));
    // no early data at all is fine everywhere
    for config in [&header, &custom, &unnamed, &plain] {
        let got = server_takes(config.clone(), &upgrade("/t", "")).await;
        assert_eq!(got.as_deref(), Ok(&[][..]), "{config}");
    }
    // the header is only read when it is the configured one
    let got = server_takes(custom.clone(), &upgrade("/t", &swp)).await;
    assert_eq!(got.as_deref(), Ok(&[][..]));
    let got = server_takes(unnamed.clone(), &upgrade("/t", "x-early: AAAA\r\n")).await;
    assert_eq!(got.as_deref(), Ok(&[][..]));
    // a plain inbound leaves a real subprotocol alone
    let got = server_takes(plain.clone(), &upgrade("/t", &swp)).await;
    assert_eq!(got.as_deref(), Ok(&[][..]));
    // no path mode: early data after the path is a wrong path everywhere
    for config in [&header, &custom, &unnamed, &plain] {
        let got = server_takes(config.clone(), &upgrade(&format!("/t{ed}"), "")).await;
        assert!(got.is_err(), "{config}: {got:?}");
    }
}

/// The reference decodes strictly (`base64.RawURLEncoding`): padding and the
/// standard alphabet are refused, which is what used to break our client.
#[tokio::test]
async fn our_server_refuses_early_data_that_is_not_base64url() {
    let header = serde_json::json!({"type": "ws", "path": "/t",
        "max_early_data": 2048, "early_data_header_name": SWP});
    let unnamed = serde_json::json!({"type": "ws", "path": "/t", "max_early_data": 2048});
    for bad in ["+/8=", "-_8=", "+/8", "a"] {
        let got = server_takes(
            header.clone(),
            &upgrade("/t", &format!("Sec-WebSocket-Protocol: {bad}\r\n")),
        )
        .await;
        assert!(got.is_err(), "header {bad:?}: {got:?}");
        let got = server_takes(
            unnamed.clone(),
            &upgrade("/t", &format!("Sec-WebSocket-Protocol: {bad}\r\n")),
        )
        .await;
        assert!(got.is_err(), "no name {bad:?}: {got:?}");
    }
}

#[test]
fn our_server_refuses_mistyped_early_data_options() {
    use crate::inbound::transport::Transport as Inbound;
    for bad in [
        serde_json::json!({"type": "ws", "max_early_data": -1}),
        serde_json::json!({"type": "ws", "max_early_data": 4294967296u64}),
        serde_json::json!({"type": "ws", "max_early_data": "2048"}),
        serde_json::json!({"type": "ws", "early_data_header_name": 1}),
    ] {
        let parsed = Inbound::from_inbound(&serde_json::json!({"transport": bad}), "in");
        assert!(parsed.is_err(), "{bad} must be refused");
    }
    let ok = serde_json::json!({"transport": {"type": "ws", "max_early_data": 4294967295u64,
        "early_data_header_name": ""}});
    assert!(Inbound::from_inbound(&ok, "in").is_ok());
}

/// The reference leaves a single Host line on the wire (Go write-excludes
/// Header["Host"]); a second one makes picky servers answer 400 and the
/// whole node reads as dead in the clash UI.
#[tokio::test]
async fn a_host_header_is_written_once() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move { ws_server(listener).await });
    let transport = Transport {
        kind: Kind::Ws {
            path: "/p".into(),
            host: None,
            headers: vec![("Host".into(), "cdn.example.com".into())],
            max_early_data: 0,
            early_data_header_name: String::new(),
        },
    };
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect");
    drop(
        transport
            .connect(
                tcp,
                None,
                "example.com",
                port,
                &crate::outbound::dial::DialOptions::default(),
            )
            .await
            .expect("handshake"),
    );
    let head = server.await.expect("join");
    assert_eq!(
        head.matches("Host:").count(),
        1,
        "exactly one Host line, got:\n{head}"
    );
    assert!(
        head.contains("Host: cdn.example.com\r\n"),
        "the configured Host wins, got:\n{head}"
    );
}

/// A socket that hands out at most `piece` bytes per read, so a websocket frame
/// is guaranteed to land across many reads. `widest` records the largest buffer
/// a read was ever asked for: that is how the direct path is told apart from
/// the staging one, which can only ever ask for `WS_READ`.
struct Trickle {
    data: Vec<u8>,
    at: usize,
    piece: usize,
    widest: Arc<AtomicUsize>,
}

impl AsyncRead for Trickle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = &mut *self;
        me.widest.fetch_max(out.remaining(), Ordering::Relaxed);
        let n = (me.data.len() - me.at).min(me.piece).min(out.remaining());
        out.put_slice(&me.data[me.at..me.at + n]);
        me.at += n;
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Trickle {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Once a frame is known and nothing is left to unmask, `poll_read` hands the
/// caller's own buffer to the socket instead of staging the payload and copying
/// it out. `poll_more` reserves exactly `WS_READ` and reads into whatever is
/// spare, so a read through it can never ask for more than that -- which makes
/// "asked for more than WS_READ" proof that the direct path ran. Without this
/// the widest request stays at WS_READ and the payload pays a memmove per read.
#[tokio::test]
async fn an_unmasked_payload_is_read_straight_into_the_callers_buffer() {
    const LEN: usize = 200_000;
    let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let mut wire = vec![0x82, 127];
    wire.extend_from_slice(&(LEN as u64).to_be_bytes());
    wire.extend_from_slice(&payload);
    let widest = Arc::new(AtomicUsize::new(0));
    let stream: crate::inbound::AnyStream = Box::new(Trickle {
        data: wire,
        at: 0,
        piece: 64 * 1024,
        widest: widest.clone(),
    });
    let mut ws = WsStream::new(stream);
    let mut out = vec![0u8; 1 << 20];
    let mut got = 0;
    while got < out.len() {
        // one big caller buffer: that is what makes a wide socket read possible
        let mut buf = ReadBuf::new(&mut out[got..]);
        poll_fn(|cx| Pin::new(&mut ws).poll_read(cx, &mut buf))
            .await
            .expect("read frame");
        let filled = buf.filled().len();
        if filled == 0 {
            break;
        }
        got += filled;
    }
    assert_eq!(got, LEN, "a split frame must come back whole");
    assert!(out[..got] == payload, "and in order");
    assert!(
        widest.load(Ordering::Relaxed) > WS_READ,
        "no read ever asked for more than {WS_READ} bytes, so the payload was staged"
    );
}

/// A masked frame still has to be unmasked, so it cannot take the direct path:
/// the payload has to be staged, which is the one case where the read buffer
/// outgrows its allocation. Sized past `WS_READ` so that growth is what is
/// being tested, not a payload that happens to fit.
#[tokio::test]
async fn a_masked_frame_bigger_than_the_buffer_still_reads_out_whole() {
    const LEN: usize = WS_READ + 1000;
    let payload: Vec<u8> = (0..LEN).map(|i| (i % 251) as u8).collect();
    let key = [0xde, 0xad, 0xbe, 0xef];
    let mut wire = vec![0x82, 127 | 0x80];
    wire.extend_from_slice(&(LEN as u64).to_be_bytes());
    wire.extend_from_slice(&key);
    wire.extend(
        payload
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 4])
            .collect::<Vec<u8>>(),
    );
    let stream: crate::inbound::AnyStream = Box::new(Trickle {
        data: wire,
        at: 0,
        piece: 4096,
        widest: Arc::new(AtomicUsize::new(0)),
    });
    let mut ws = WsStream::new(stream);
    let mut got = Vec::new();
    ws.read_to_end(&mut got).await.expect("read frame");
    assert_eq!(got.len(), LEN, "the masking key must still be applied");
    assert!(got == payload, "and the payload must come back in order");
}

/// A websocket waiting for its socket holds no buffers: an empty read buffer
/// and an empty write queue go back to the pool, and the stream takes them
/// again when traffic resumes, with every byte arriving whole and in order.
#[tokio::test]
async fn an_idle_stream_parks_its_buffers_and_traffic_resumes_intact() {
    use tokio::io::AsyncWriteExt;
    let (client, server) = tokio::io::duplex(512 * 1024);
    let mut ws = WsStream::new(Box::new(client));
    let mut peer = WsStream::server(Box::new(server));
    for round in 0..3u8 {
        let big: Vec<u8> = (0..150_000usize).map(|i| (i % 253) as u8 ^ round).collect();
        ws.write_all(&big).await.expect("write");
        ws.flush().await.expect("flush");
        let mut got = vec![0u8; big.len()];
        peer.read_exact(&mut got).await.expect("read");
        assert!(got == big, "round {round}: upload differs");
        peer.write_all(&big[..70_000]).await.expect("reply");
        peer.flush().await.expect("flush reply");
        let mut back = vec![0u8; 70_000];
        ws.read_exact(&mut back).await.expect("read reply");
        assert!(back[..] == big[..70_000], "round {round}: download differs");

        let mut one = [0u8; 1];
        for end in [&mut ws, &mut peer] {
            let idle =
                tokio::time::timeout(std::time::Duration::from_millis(20), end.read(&mut one))
                    .await;
            assert!(idle.is_err(), "nothing was sent, the read must wait");
            assert_eq!(end.rbuf.capacity(), 0, "idle stream kept its read buffer");
            assert_eq!(end.wbuf.capacity(), 0, "idle stream kept its write queue");
        }
    }
}

fn lazy_request(max: usize) -> WsRequest {
    WsRequest {
        path: "/t".to_string(),
        host: "example.com".to_string(),
        headers: Vec::new(),
        max_early_data: max,
        early_data_header_name: String::new(),
    }
}

/// Reads one upgrade request off `server`, answers 101 and returns the
/// request head with the early data it carried.
async fn answer_upgrade(server: &mut tokio::io::DuplexStream) -> (String, Vec<u8>) {
    use base64::Engine as _;
    use tokio::io::AsyncWriteExt;
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        if server.read(&mut byte).await.expect("read request") == 0 {
            break;
        }
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).expect("utf8");
    let key = head
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Key: "))
        .expect("key")
        .to_string();
    let early = head
        .lines()
        .find_map(|l| l.strip_prefix("Sec-WebSocket-Protocol: "))
        .map(|v| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(v)
                .expect("base64url")
        })
        .unwrap_or_default();
    let mut hash = Sha1::new();
    hash.update(key.as_bytes());
    hash.update(WS_GUID);
    let accept = base64_std(&hash.finalize());
    server
        .write_all(
            format!(
                "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                 Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("answer");
    (head, early)
}

/// One masked client frame off `server`: its payload.
async fn read_frame(server: &mut tokio::io::DuplexStream) -> Vec<u8> {
    let mut head = [0u8; 2];
    server.read_exact(&mut head).await.expect("frame head");
    let mut len = usize::from(head[1] & 0x7f);
    if len == 126 {
        let mut ext = [0u8; 2];
        server.read_exact(&mut ext).await.expect("len");
        len = usize::from(u16::from_be_bytes(ext));
    }
    let mut mask = [0u8; 4];
    server.read_exact(&mut mask).await.expect("mask");
    let mut payload = vec![0u8; len];
    server.read_exact(&mut payload).await.expect("payload");
    for (i, b) in payload.iter_mut().enumerate() {
        *b ^= mask[i % 4];
    }
    payload
}

/// With early data the upgrade request waits for the first write and carries
/// it when it fits the budget; a longer one follows as a frame. Nothing goes
/// out before that write.
#[tokio::test]
async fn early_data_upgrade_waits_for_the_first_write() {
    use tokio::io::AsyncWriteExt;
    for (max, len) in [(2048usize, 300usize), (299, 300), (300, 300)] {
        let (client, mut server) = tokio::io::duplex(1 << 16);
        let mut ws = LazyWs::new(Box::new(client), lazy_request(max));
        let mut probe = [0u8; 1];
        let quiet = tokio::time::timeout(Duration::from_millis(100), server.read(&mut probe)).await;
        assert!(quiet.is_err(), "no request before the first write");
        let first: Vec<u8> = (0..len).map(|i| (i * 7) as u8).collect();
        let write = {
            let first = first.clone();
            async move {
                ws.write_all(&first).await.expect("first write");
                ws.flush().await.expect("flush");
                ws
            }
        };
        let serve = async {
            let (head, early) = answer_upgrade(&mut server).await;
            assert!(head.starts_with("GET /t HTTP/1.1\r\n"), "{head}");
            let rest = if early.len() < len {
                read_frame(&mut server).await
            } else {
                Vec::new()
            };
            (early, rest)
        };
        let (_ws, (early, rest)) = tokio::join!(write, serve);
        // all of the first write or none of it
        let carried = if len <= max { len } else { 0 };
        assert_eq!(early, &first[..carried], "max {max}");
        assert_eq!(rest, &first[carried..], "max {max}");
    }
}

/// A read before the first write waits for it, then sees the server's bytes.
#[tokio::test]
async fn a_read_waits_for_the_upgrade() {
    use tokio::io::AsyncWriteExt;
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let ws = LazyWs::new(Box::new(client), lazy_request(2048));
    let (mut rd, mut wr) = tokio::io::split(ws);
    let reader = tokio::spawn(async move {
        let mut got = [0u8; 2];
        rd.read_exact(&mut got).await.expect("read");
        got
    });
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(!reader.is_finished());
    let (written, (_, early)) = tokio::join!(wr.write_all(b"head"), answer_upgrade(&mut server));
    written.expect("write");
    assert_eq!(early, b"head");
    server
        .write_all(&[0x82, 2, b'o', b'k'])
        .await
        .expect("frame");
    assert_eq!(&reader.await.expect("join"), b"ok");
}

/// Closed before any write: no upgrade request, the transport just ends.
#[tokio::test]
async fn closing_before_the_first_write_sends_no_request() {
    use tokio::io::AsyncWriteExt;
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let mut ws = LazyWs::new(Box::new(client), lazy_request(2048));
    ws.shutdown().await.expect("shutdown");
    let mut got = Vec::new();
    server.read_to_end(&mut got).await.expect("read");
    assert!(got.is_empty());
}

/// A refused upgrade fails the write that carried it, and later reads.
#[tokio::test]
async fn a_refused_upgrade_fails_the_first_write() {
    use tokio::io::AsyncWriteExt;
    let (client, mut server) = tokio::io::duplex(1 << 16);
    let mut ws = LazyWs::new(Box::new(client), lazy_request(2048));
    let serve = async move {
        let mut buf = [0u8; 1024];
        let _ = server.read(&mut buf).await;
        let _ = server
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await;
        server
    };
    let (result, _server) = tokio::join!(ws.write_all(b"head"), serve);
    assert!(result.is_err());
    let mut buf = [0u8; 4];
    assert!(ws.read(&mut buf).await.is_err());
}
