//! The Vision download through the kernel: our own client stack (VLESS,
//! Vision, our TLS over TCP) against a scripted server that speaks Vision
//! inside TLS 1.3 and goes Direct the way Xray does. The server reads the
//! outer TLS one record at a time, so it knows exactly where TLS ends and
//! the raw bytes begin, in both directions.

use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use core_tls::rustls;
use serde_json::json;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::clash_state;
use crate::inbound::{AnyStream, Conn, Target};

const UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const UUID: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];
const CONTINUE: u8 = 0;
const END: u8 = 1;
const DIRECT: u8 = 2;
/// `[0][uuid][18][flow addon][command][port][atyp][v4]`
const HEAD: usize = 1 + 16 + 1 + 18 + 1 + 2 + 1 + 4;
const LIMIT: Duration = Duration::from_secs(30);

const CERT: &str = include_str!("../../../../../tests/golden/certs/localhost.crt");
const KEY: &str = include_str!("../../../../../tests/golden/certs/localhost.key");

fn server_config() -> Arc<rustls::ServerConfig> {
    core_tls::install_default_provider();
    let certs = rustls_pemfile::certs(&mut CERT.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("cert");
    let key = rustls_pemfile::private_key(&mut KEY.as_bytes())
        .expect("key")
        .expect("a key");
    Arc::new(
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .expect("server config"),
    )
}

/// Deterministic, non-repeating bytes, so a lost, reordered or duplicated
/// chunk cannot hide behind a constant fill.
fn pattern(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2_654_435_761).wrapping_add(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 11) as u8
        })
        .collect()
}

fn record(kind: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![kind, 3, 3];
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// The inner client's first flight, as Vision sees it: a handshake record.
fn client_hello() -> Vec<u8> {
    let mut body = vec![1, 0, 0, 60];
    body.extend_from_slice(&[0x33; 60]);
    record(0x16, &body)
}

/// The inner ServerHello, TLS 1.3 (`[3, 4]`) or TLS 1.2 (`[3, 3]`).
fn server_hello(version: [u8; 2]) -> Vec<u8> {
    let mut body = vec![3, 3];
    body.extend_from_slice(&[0x42; 32]);
    body.push(0);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.extend_from_slice(&[0, 0, 6, 0, 43, 0, 2]);
    body.extend_from_slice(&version);
    let mut handshake = vec![2, 0, 0, body.len() as u8];
    handshake.extend_from_slice(&body);
    record(0x16, &handshake)
}

fn server_app_data() -> Vec<u8> {
    record(0x17, &[0xa5; 32])
}

fn client_app_data() -> Vec<u8> {
    record(0x17, &[0x5c; 48])
}

/// What the server sends right behind its last outer record.
fn tail() -> Vec<u8> {
    pattern(3000, 9)
}

fn frame(command: u8, content: &[u8], padding: usize) -> Vec<u8> {
    let mut out = vec![command];
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding, 0);
    out
}

async fn read_record<R: AsyncRead + Unpin>(from: &mut R) -> Option<Vec<u8>> {
    let mut record = vec![0u8; 5];
    from.read_exact(&mut record).await.ok()?;
    let len = usize::from(u16::from_be_bytes([record[3], record[4]]));
    record.resize(5 + len, 0);
    from.read_exact(&mut record[5..])
        .await
        .expect("record body");
    Some(record)
}

fn feed(conn: &mut rustls::ServerConnection, record: &[u8], plain: &mut Vec<u8>) {
    let mut input = record;
    while !input.is_empty() {
        conn.read_tls(&mut input).expect("read_tls");
    }
    conn.process_new_packets().expect("outer records");
    let mut chunk = [0u8; 16 * 1024];
    loop {
        match conn.reader().read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => plain.extend_from_slice(&chunk[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("outer plaintext: {e}"),
        }
    }
}

fn sealed(conn: &mut rustls::ServerConnection) -> Vec<u8> {
    let mut out = Vec::new();
    while conn.wants_write() {
        conn.write_tls(&mut out).expect("write_tls");
    }
    out
}

/// The server's outer TLS and the plaintext it has opened but not parsed.
struct Outer {
    conn: rustls::ServerConnection,
    plain: Vec<u8>,
}

impl Outer {
    async fn accept(tcp: &mut TcpStream) -> Self {
        let mut conn = rustls::ServerConnection::new(server_config()).expect("server");
        let mut plain = Vec::new();
        while conn.is_handshaking() {
            tcp.write_all(&sealed(&mut conn))
                .await
                .expect("handshake write");
            let record = read_record(tcp).await.expect("handshake record");
            feed(&mut conn, &record, &mut plain);
        }
        tcp.write_all(&sealed(&mut conn)).await.expect("tickets");
        assert!(plain.is_empty());
        Self { conn, plain }
    }

    async fn fill(&mut self, tcp: &mut TcpStream, len: usize) {
        while self.plain.len() < len {
            let record = read_record(tcp).await.expect("record");
            feed(&mut self.conn, &record, &mut self.plain);
        }
    }

    async fn frame(&mut self, tcp: &mut TcpStream) -> (u8, Vec<u8>) {
        self.fill(tcp, 5).await;
        let content = usize::from(u16::from_be_bytes([self.plain[1], self.plain[2]]));
        let padding = usize::from(u16::from_be_bytes([self.plain[3], self.plain[4]]));
        self.fill(tcp, 5 + content + padding).await;
        let command = self.plain[0];
        let body = self.plain[5..5 + content].to_vec();
        self.plain.drain(..5 + content + padding);
        (command, body)
    }
}

/// Up to the server's answer: the request head, the inner client hello, then
/// the response head, the inner server hello and the first inner app record,
/// which ends the padding with Direct (or End), and the tail behind it.
async fn serve_start(listener: TcpListener, version: [u8; 2], direct: bool) -> (TcpStream, Outer) {
    let (mut tcp, _) = listener.accept().await.expect("accept");
    let mut outer = Outer::accept(&mut tcp).await;
    outer.fill(&mut tcp, HEAD + 16).await;
    assert_eq!(outer.plain[0], 0, "vless version");
    assert_eq!(&outer.plain[1..17], &UUID[..]);
    assert_eq!(&outer.plain[20..36], b"xtls-rprx-vision");
    assert_eq!(outer.plain[36], 1, "tcp command");
    assert_eq!(&outer.plain[HEAD..HEAD + 16], &UUID[..], "vision uuid");
    outer.plain.drain(..HEAD + 16);
    let mut content = Vec::new();
    while content.len() < client_hello().len() {
        let (command, body) = outer.frame(&mut tcp).await;
        assert_eq!(command, CONTINUE);
        content.extend(body);
    }
    assert_eq!(content, client_hello());

    let mut answer = vec![0, 0];
    answer.extend_from_slice(&UUID);
    answer.extend(frame(CONTINUE, &server_hello(version), 7));
    answer.extend(frame(
        if direct { DIRECT } else { END },
        &server_app_data(),
        3,
    ));
    if !direct {
        answer.extend(tail());
    }
    outer.conn.writer().write_all(&answer).expect("answer");
    let mut wire = sealed(&mut outer.conn);
    if direct {
        // raw bytes in the same segment as the last outer record: the client
        // reads them into its TLS buffer before it knows they are raw
        wire.extend(tail());
    }
    tcp.write_all(&wire).await.expect("answer write");
    (tcp, outer)
}

/// The rest: the client's inner app record ends its padding, then `down`
/// goes out raw (or inside TLS) while the upload is read to its end. Returns
/// the client's ending command and everything it sent after its hello: the
/// last frame may carry more than the app record when the relay read it
/// together with the first upload bytes.
async fn serve_rest(
    mut tcp: TcpStream,
    mut outer: Outer,
    down_direct: bool,
    down: Vec<u8>,
) -> (u8, Vec<u8>) {
    let mut content = Vec::new();
    let command = loop {
        let (command, body) = outer.frame(&mut tcp).await;
        content.extend(body);
        if command != CONTINUE {
            break command;
        }
    };
    let up_direct = command == DIRECT;
    if up_direct {
        assert!(outer.plain.is_empty(), "no TLS payload after Direct");
    }
    content.append(&mut outer.plain);
    let conn = Arc::new(Mutex::new(outer.conn));
    let (mut rd, mut wr) = tcp.into_split();
    let read = {
        let conn = Arc::clone(&conn);
        async move {
            let mut got = content;
            if up_direct {
                rd.read_to_end(&mut got).await.expect("raw upload");
            } else {
                while let Some(record) = read_record(&mut rd).await {
                    feed(&mut conn.lock().expect("conn"), &record, &mut got);
                }
            }
            got
        }
    };
    let write = async move {
        if down_direct {
            wr.write_all(&down).await.expect("raw download");
        } else {
            for chunk in down.chunks(16 * 1024) {
                let out = {
                    let mut conn = conn.lock().expect("conn");
                    conn.writer().write_all(chunk).expect("seal");
                    sealed(&mut conn)
                };
                wr.write_all(&out).await.expect("tls download");
            }
        }
        wr.shutdown().await.expect("server shutdown");
    };
    let (got, ()) = tokio::join!(read, write);
    (command, got)
}

async fn vision_upstream(port: u16) -> AnyStream {
    let outbound = json!({
        "type": "vless",
        "tag": "out",
        "server": "127.0.0.1",
        "server_port": port,
        "uuid": UUID_TEXT,
        "flow": "xtls-rprx-vision",
        "tls": {"enabled": true, "server_name": "localhost", "certificate": CERT}
    });
    let vless = crate::outbound::secure::Vless::build(
        outbound.as_object().expect("object"),
        "outbounds[0]",
    )
    .expect("build");
    vless
        .connect(&Target::Ip("127.0.0.1:443".parse().expect("addr")))
        .await
        .expect("connect")
}

/// A connected loopback pair: `(accepted, connected)`.
async fn pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("addr");
    let (connected, accepted) = tokio::join!(TcpStream::connect(addr), listener.accept());
    (accepted.expect("accept").0, connected.expect("connect"))
}

fn meta() -> clash_state::ConnMeta {
    clash_state::ConnMeta {
        network: "tcp",
        inbound: "redirect-in".into(),
        source: "192.168.1.10:5000".into(),
        host: "example.com".into(),
        destination: "example.com:443".into(),
        chains: vec!["out".into()],
        rule: "final".into(),
        rule_payload: String::new(),
    }
}

/// One whole connection: inner hello both ways, the inner app records that
/// end the padding, then `up` and `down` at once, every byte and both
/// counters checked. Returns the client's ending command and whether the
/// download was spliced.
async fn run(version: [u8; 2], direct: bool, up: Vec<u8>, down: Vec<u8>) -> (u8, bool) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn({
        let down = down.clone();
        async move {
            let (tcp, outer) = serve_start(listener, version, direct).await;
            serve_rest(tcp, outer, direct, down).await
        }
    });
    let mut upstream = vision_upstream(port).await;
    assert!(crate::inbound::vision_splice_candidate(&mut upstream));

    let (relay_client, lan) = pair().await;
    let tracker = clash_state::ConnHandle::open(meta());
    let id = tracker.id().to_string();
    let relay = tokio::spawn(async move {
        let mut relay_client = relay_client;
        let result = super::relay_vision(&mut relay_client, &mut upstream, Some(&tracker)).await;
        let counted = clash_state::snapshot()
            .0
            .into_iter()
            .find(|view| view.id == id)
            .map(|view| (view.upload, view.download))
            .expect("entry");
        (result, counted)
    });

    let (mut lan_r, mut lan_w) = lan.into_split();
    lan_w.write_all(&client_hello()).await.expect("hello");
    let mut want_first = server_hello(version);
    want_first.extend(server_app_data());
    let mut first = vec![0u8; want_first.len()];
    tokio::time::timeout(LIMIT, lan_r.read_exact(&mut first))
        .await
        .expect("first answer in time")
        .expect("first answer");
    assert_eq!(first, want_first);
    lan_w.write_all(&client_app_data()).await.expect("app data");

    // Our TLS stops reading once its write side is shut, so with the outer
    // TLS still on the upload closes only after the whole download is in.
    // Direct reads do not depend on it: there the upload half-closes at once.
    let write = {
        let up = up.clone();
        async move {
            lan_w.write_all(&up).await.expect("upload");
            if direct {
                lan_w.shutdown().await.expect("lan shutdown");
            }
            lan_w
        }
    };
    let read = async move {
        let mut got = Vec::new();
        lan_r.read_to_end(&mut got).await.expect("download");
        got
    };
    let (mut lan_w, got_down) = tokio::time::timeout(LIMIT, async { tokio::join!(write, read) })
        .await
        .expect("lan side in time");
    if !direct {
        lan_w.shutdown().await.expect("lan shutdown");
    }
    let (command, got_up) = tokio::time::timeout(LIMIT, server)
        .await
        .expect("server in time")
        .expect("server task");
    let mut want_up = client_app_data();
    want_up.extend_from_slice(&up);
    let mut want_down = tail();
    want_down.extend_from_slice(&down);
    assert_eq!(got_up.len(), want_up.len());
    assert!(got_up == want_up, "upload corrupted");
    assert_eq!(got_down.len(), want_down.len());
    assert!(got_down == want_down, "download corrupted");

    let (result, counted) = tokio::time::timeout(LIMIT, relay)
        .await
        .expect("relay in time")
        .expect("relay task");
    let spliced = result.expect("relay result");
    let want_up = client_hello().len() + want_up.len();
    let want_down = want_first.len() + want_down.len();
    assert_eq!(counted, (want_up as u64, want_down as u64), "counters");
    (command, spliced)
}

#[tokio::test]
async fn a_direct_download_moves_to_the_kernel_with_every_byte_in_order() {
    let (command, spliced) = run(
        [3, 4],
        true,
        pattern(4 * 1024 * 1024 + 3, 1),
        pattern(8 * 1024 * 1024 + 5, 2),
    )
    .await;
    assert_eq!(
        command, DIRECT,
        "the client goes Direct on its own side too"
    );
    assert!(spliced, "the Direct download must leave userspace");
}

#[tokio::test]
async fn without_direct_the_relay_stays_in_userspace() {
    let (command, spliced) = run(
        [3, 3],
        false,
        pattern(1024 * 1024 + 3, 3),
        pattern(1024 * 1024 + 5, 4),
    )
    .await;
    assert_eq!(command, END, "TLS 1.2 inside keeps the outer TLS");
    assert!(!spliced, "End must keep the download in userspace");
}

#[tokio::test]
async fn the_api_still_closes_a_spliced_download() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let (mut tcp, _outer) = serve_start(listener, [3, 4], true).await;
        // hold the connection open until the relay drops it
        let mut sink = Vec::new();
        let _ = tcp.read_to_end(&mut sink).await;
    });
    let upstream = vision_upstream(port).await;
    let (relay_client, lan) = pair().await;
    let tracker = clash_state::ConnHandle::open(meta());
    let id = tracker.id();
    let relay = tokio::spawn(async move {
        crate::inbound::pump_conn_tracked(relay_client, Conn::Plain(upstream), &[], Some(&tracker))
            .await
    });

    let (mut lan_r, mut lan_w) = lan.into_split();
    lan_w.write_all(&client_hello()).await.expect("hello");
    let mut want = server_hello([3, 4]);
    want.extend(server_app_data());
    want.extend(tail());
    let mut got = vec![0u8; want.len()];
    tokio::time::timeout(LIMIT, lan_r.read_exact(&mut got))
        .await
        .expect("answer in time")
        .expect("answer");
    assert_eq!(got, want);
    tokio::time::sleep(Duration::from_millis(50)).await;

    assert!(clash_state::close(id));
    let result = tokio::time::timeout(LIMIT, relay)
        .await
        .expect("relay ends after the close")
        .expect("relay task");
    assert!(result.is_err(), "a closed connection reports it");
    tokio::time::timeout(LIMIT, server)
        .await
        .expect("server sees the close")
        .expect("server task");
    let mut rest = Vec::new();
    let _ = lan_r.read_to_end(&mut rest).await;
    assert!(
        rest.is_empty(),
        "nothing after the close: {} bytes",
        rest.len()
    );
}
