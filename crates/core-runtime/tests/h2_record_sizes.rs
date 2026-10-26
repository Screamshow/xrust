//! TLS record lengths of a bulk upload over the HTTP/2 transports (gRPC and
//! XHTTP stream-one), our client against our server, with a forwarder in
//! between that reads the record headers the client sends. Both copy what
//! Xray's client puts on the wire, which differs between the two.
//!
//! Go's crypto/tls cuts what Xray's http2 framer buffers into full records:
//! 16401 bytes on the wire (16384 of plaintext, the type byte and the tag),
//! back to back. Our h2 used to hand each 16 KiB DATA frame over in two writes
//! -- the frame header with the first kilobyte, then the rest -- and the TLS
//! stack sealed each write into a record, so the upload was pairs of 1041 and
//! 15386 bytes, a pattern neither Chrome nor Go produces.

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn cert_file(name: &str) -> String {
    format!(
        "{}/../../tests/golden/certs/{name}",
        env!("CARGO_MANIFEST_DIR")
    )
}

/// Reads and drops everything, then answers one byte once `total` came in.
async fn spawn_sink(total: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind sink");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1 << 16];
                let mut seen = 0;
                while seen < total {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => seen += n,
                    }
                }
                let _ = stream.write_all(b"k").await;
            });
        }
    });
    addr
}

/// Forwards to `to`, logging the length field of every TLS record the
/// client sends.
async fn record_forwarder(to: SocketAddr) -> (SocketAddr, Arc<Mutex<Vec<(u8, usize)>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let records = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&records);
    tokio::spawn(async move {
        while let Ok((inbound, _)) = listener.accept().await {
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let Ok(outbound) = TcpStream::connect(to).await else {
                    return;
                };
                let (mut client_rd, mut client_wr) = inbound.into_split();
                let (mut server_rd, mut server_wr) = outbound.into_split();
                tokio::spawn(async move {
                    let _ = tokio::io::copy(&mut server_rd, &mut client_wr).await;
                });
                let mut pending = Vec::new();
                let mut buf = vec![0u8; 1 << 16];
                loop {
                    let n = match client_rd.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    if server_wr.write_all(&buf[..n]).await.is_err() {
                        return;
                    }
                    pending.extend_from_slice(&buf[..n]);
                    while pending.len() >= 5 {
                        let len = usize::from(u16::from_be_bytes([pending[3], pending[4]]));
                        if pending.len() < 5 + len {
                            break;
                        }
                        log.lock().unwrap().push((pending[0], len));
                        pending.drain(..5 + len);
                    }
                }
            });
        }
    });
    (addr, records)
}

async fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).await.expect("connect inbound");
    stream.write_all(&[5, 1, 0]).await.expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    let std::net::IpAddr::V4(v4) = target.ip() else {
        panic!("v4");
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[1], 0, "CONNECT must succeed");
    stream
}

fn inbound_addr(instance: &core_runtime::BoxInstance, tag: &str) -> SocketAddr {
    instance
        .inbound_addrs()
        .iter()
        .find(|(t, _)| t == tag)
        .map(|(_, a)| *a)
        .expect("inbound")
}

/// The application-data record lengths of an 8 MiB upload over `transport`.
async fn upload_records(transport: Value) -> Vec<usize> {
    const TOTAL: usize = 8 << 20;
    let server = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": 0,
            "users": [{"uuid": UUID}], "transport": transport,
            "tls": {"enabled": true, "certificate_path": cert_file("localhost.crt"),
                "key_path": cert_file("localhost.key"), "alpn": ["h2"]}}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .expect("start server");
    let (front, records) = record_forwarder(inbound_addr(&server, "in")).await;
    let client = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "vless", "tag": "up", "server": "127.0.0.1",
            "server_port": front.port(), "uuid": UUID, "transport": transport,
            "tls": {"enabled": true, "server_name": "localhost", "insecure": true,
                "alpn": ["h2"], "utls": {"enabled": true, "fingerprint": "chrome"}}}],
        "route": {"final": "up"}
    }))
    .await
    .expect("start client");
    let sink = spawn_sink(TOTAL).await;
    let mut stream = socks_connect(inbound_addr(&client, "mixed"), sink).await;
    let chunk = vec![0x5au8; 1 << 16];
    for _ in 0..TOTAL / chunk.len() {
        stream.write_all(&chunk).await.expect("upload");
    }
    let mut done = [0u8; 1];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut done))
        .await
        .expect("the sink has it all")
        .expect("read");
    client.shutdown();
    server.shutdown();
    let records = records.lock().unwrap().clone();
    records
        .into_iter()
        .filter(|(kind, _)| *kind == 23)
        .map(|(_, len)| len)
        .collect()
}

fn assert_full_records(label: &str, lengths: &[usize]) {
    let big: Vec<usize> = lengths.iter().copied().filter(|l| *l >= 1000).collect();
    let full = big.iter().filter(|l| **l == 16401).count();
    assert!(
        !lengths.contains(&1041),
        "{label}: a frame header sealed apart from its payload: {lengths:?}"
    );
    // 8 MiB is 512 records' worth; flush boundaries cut a few short
    assert!(
        full >= 400 && full * 10 >= big.len() * 9,
        "{label}: {full} full records of {} large ones: {lengths:?}",
        big.len()
    );
}

#[tokio::test]
async fn grpc_uploads_in_full_records() {
    let lengths = upload_records(json!({"type": "grpc", "service_name": "svc"})).await;
    assert_full_records("grpc", &lengths);
}

/// XHTTP is Go's x/net http2 client in Xray, which writes the streamed body
/// as it reads it -- 8 KiB at a time from Xray -- one DATA frame a write:
/// 8218-byte records, not full ones.
#[tokio::test]
async fn xhttp_stream_one_uploads_in_8_kib_frames() {
    let lengths =
        upload_records(json!({"type": "xhttp", "path": "/xh", "mode": "stream-one"})).await;
    let big: Vec<usize> = lengths.iter().copied().filter(|l| *l >= 1000).collect();
    let frames = big.iter().filter(|l| **l == 8218).count();
    assert!(
        frames >= 900 && frames * 10 >= big.len() * 9,
        "{frames} 8 KiB frames of {} large records: {lengths:?}",
        big.len()
    );
}

/// Reads two bytes from whoever connects, sends `total` bytes, then closes.
async fn spawn_source(total: usize) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind source");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                // take the client's first bytes, or the close resets
                let mut go = [0u8; 2];
                if stream.read_exact(&mut go).await.is_err() {
                    return;
                }
                let chunk = vec![0x33u8; 1 << 16];
                let mut left = total;
                while left > 0 {
                    let n = left.min(chunk.len());
                    if stream.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    left -= n;
                }
            });
        }
    });
    addr
}

/// The client's records while it downloads 2 MiB over XHTTP `mode`.
async fn download_records(mode: &str) -> Vec<usize> {
    const TOTAL: usize = 2 << 20;
    let transport = json!({"type": "xhttp", "path": "/xh", "mode": mode});
    let server = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "vless", "tag": "in", "listen": "127.0.0.1", "listen_port": 0,
            "users": [{"uuid": UUID}], "transport": transport,
            "tls": {"enabled": true, "certificate_path": cert_file("localhost.crt"),
                "key_path": cert_file("localhost.key"), "alpn": ["h2"]}}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .expect("start server");
    let (front, records) = record_forwarder(inbound_addr(&server, "in")).await;
    let client = core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "mixed", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "vless", "tag": "up", "server": "127.0.0.1",
            "server_port": front.port(), "uuid": UUID, "transport": transport,
            "tls": {"enabled": true, "server_name": "localhost", "insecure": true,
                "utls": {"enabled": true, "fingerprint": "chrome"}}}],
        "route": {"final": "up"}
    }))
    .await
    .expect("start client");
    let source = spawn_source(TOTAL).await;
    let mut stream = socks_connect(inbound_addr(&client, "mixed"), source).await;
    stream.write_all(b"go").await.expect("first bytes");
    let mut got = vec![0u8; TOTAL];
    tokio::time::timeout(Duration::from_secs(30), stream.read_exact(&mut got))
        .await
        .expect("the download")
        .expect("read");
    client.shutdown();
    server.shutdown();
    let records = records.lock().unwrap().clone();
    records
        .into_iter()
        .filter(|(kind, _)| *kind == 23)
        .map(|(_, len)| len)
        .collect()
}

/// Go's x/net http2 client, Xray's on XHTTP: the preface, a SETTINGS frame
/// of four entries and the connection WINDOW_UPDATE leave in the first
/// record after the handshake (87 bytes: 24 + 33 + 13, the type byte and the
/// tag); while it downloads, it acknowledges with a WINDOW_UPDATE for the
/// connection and one for the stream in one record (43 bytes), not one alone.
/// How often depends on the server's frames: Xray's give one every 8 KiB.
#[tokio::test]
async fn xhttp_starts_and_acknowledges_like_go() {
    for mode in ["stream-one", "packet-up"] {
        let lengths = download_records(mode).await;
        // the client's Finished, then the h2 start
        assert_eq!(&lengths[..2], &[53, 87], "{mode}: {lengths:?}");
        // past the start, what the client sends while it downloads: window
        // updates, in pairs; once the stream is over only the connection's is
        // left, as with Go
        let acks: Vec<usize> = lengths[2..]
            .iter()
            .copied()
            .filter(|l| *l == 30 || *l == 43)
            .collect();
        let pairs = acks.iter().filter(|l| **l == 43).count();
        assert!(
            pairs * 2 > acks.len(),
            "{mode}: window updates mostly alone: {lengths:?}"
        );
    }
}
