//! The vless outbound must apply the flow it was configured with: a plain
//! outbound sends the payload straight through, Vision frames it.

use std::time::Duration;

use serde_json::json;
use tokio::io::AsyncReadExt;

use super::Vless;

/// The flow has to be *announced*: a server with `flow` on the user answers a
/// request without it with `flow mismatch: expected xtls-rprx-vision, but got
/// none`, which is what the reference did to us until the addon went out.
#[test]
fn the_flow_travels_in_the_request_addons() {
    use crate::inbound::Target;
    let uuid = [0x11u8; 16];
    let target = Target::Ip("127.0.0.1:443".parse().expect("addr"));

    let plain = super::request_head(&uuid, 0x01, &target, false).expect("plain head");
    assert_eq!(plain[17], 0, "a plain request carries no addons");
    assert_eq!(plain.len(), 17 + 1 + 1 + 7);

    let vision = super::request_head(&uuid, 0x01, &target, true).expect("vision head");
    assert_eq!(vision[17], 18, "1 tag + 1 length + 16 bytes of flow");
    assert_eq!(&vision[18..36], b"\x0a\x10xtls-rprx-vision");
    assert_eq!(vision[36], 0x01, "the command follows the addons");
    assert_eq!(vision.len(), 36 + 1 + 7);

    let mux = super::request_head(&uuid, 3, &target, true).expect("vision mux head");
    assert_eq!(mux.len(), 37, "Xray Mux header ends at the command");
    assert_eq!(&mux[..36], &vision[..36]);
    assert_eq!(mux[36], 3);
}

/// trojan's destination block is `M.SocksaddrSerializer`, whose family bytes
/// are 1 = IPv4, 4 = IPv6 and 3 = FQDN (sing's `common/metadata/family.go`).
/// A domain written as 2 is what every trojan server on the wire rejects, and
/// this pins the byte so it cannot come back.
#[test]
fn trojan_writes_the_socksaddr_family_bytes() {
    use crate::inbound::Target;
    let domain = Target::Domain("example.com".to_string(), 443);
    let block = crate::outbound::proxy::encode_target_with(&domain, 0x03).expect("encode domain");
    assert_eq!(
        block,
        [
            0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb
        ],
        "domain, then port 443"
    );
    // and the IPv4 and IPv6 bytes are the ones the serializer uses
    let v4 = Target::Ip("1.2.3.4:80".parse().expect("addr"));
    assert_eq!(
        crate::outbound::proxy::encode_target_with(&v4, 0x03).expect("encode v4"),
        [0x01, 1, 2, 3, 4, 0x00, 0x50]
    );
    let v6 = Target::Ip("[2001:db8::1]:80".parse().expect("addr"));
    let encoded = crate::outbound::proxy::encode_target_with(&v6, 0x03).expect("encode v6");
    assert_eq!(encoded[0], 0x04, "IPv6 keeps 4, not 3");
    assert_eq!(encoded.len(), 1 + 16 + 2);
    assert_eq!(&encoded[17..], &[0x00, 0x50]);
}

use crate::inbound::Target;

/// b831381d-6324-4d53-ad4f-8cda48b30811
const UUID: [u8; 16] = [
    0xb8, 0x31, 0x38, 0x1d, 0x63, 0x24, 0x4d, 0x53, 0xad, 0x4f, 0x8c, 0xda, 0x48, 0xb3, 0x08, 0x11,
];
const UUID_TEXT: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";

fn config(port: u16, flow: &str) -> serde_json::Map<String, serde_json::Value> {
    let mut outbound = json!({
        "type": "vless",
        "tag": "v",
        "server": "127.0.0.1",
        "server_port": port,
        "uuid": UUID_TEXT,
    });
    if !flow.is_empty() {
        outbound["flow"] = json!(flow);
    }
    outbound.as_object().expect("object").clone()
}

/// Serves one connection and returns everything the client sent.
async fn serve(listener: tokio::net::TcpListener) -> Vec<u8> {
    let (mut socket, _) = listener.accept().await.expect("accept");
    let mut seen = vec![0u8; 4096];
    let mut filled = 0;
    while filled < seen.len() {
        // the head and the first payload bytes arrive together
        match tokio::time::timeout(Duration::from_millis(300), socket.read(&mut seen[filled..]))
            .await
        {
            Ok(Ok(0)) | Err(_) => break,
            Ok(Ok(n)) => filled += n,
            Ok(Err(_)) => break,
        }
    }
    seen.truncate(filled);
    seen
}

/// `[0x00][uuid][addons][command][port:u16][addr_type][len][addr]`
fn request_head_with(command: u8) -> Vec<u8> {
    let mut head = vec![0x00];
    head.extend_from_slice(&UUID);
    head.extend_from_slice(&[0x00, command]);
    head.extend_from_slice(&(80u16).to_be_bytes());
    head.extend_from_slice(&[0x02, 11]);
    head.extend_from_slice(b"example.com");
    head
}

fn request_head() -> Vec<u8> {
    request_head_with(1)
}

/// The same head with the flow addon in it, which is what a Vision outbound
/// sends: `[0x00][uuid][18 addons][command]...`
fn vision_request_head() -> Vec<u8> {
    let mut head = vec![0x00];
    head.extend_from_slice(&UUID);
    head.extend_from_slice(&[18, 0x0a, 16]);
    head.extend_from_slice(b"xtls-rprx-vision");
    head.push(0x01);
    head.extend_from_slice(&(80u16).to_be_bytes());
    head.extend_from_slice(&[0x02, 11]);
    head.extend_from_slice(b"example.com");
    head
}

#[tokio::test]
async fn plain_flow_sends_the_payload_unframed() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(serve(listener));

    let vless = Vless::build(&config(port, ""), "outbounds[0]").expect("build");
    let mut stream = vless
        .connect(&Target::Domain("example.com".into(), 80))
        .await
        .expect("connect");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");
    drop(stream);

    let seen = server.await.expect("join");
    let head = request_head();
    assert_eq!(&seen[..head.len()], &head[..], "the request head");
    assert_eq!(&seen[head.len()..], b"GET / HTTP/1.1\r\n\r\n", "no framing");
}

#[tokio::test]
async fn vision_frames_the_payload_behind_the_uuid() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(serve(listener));

    let vless = Vless::build(&config(port, "xtls-rprx-vision"), "outbounds[0]").expect("build");
    let mut stream = vless
        .connect(&Target::Domain("example.com".into(), 80))
        .await
        .expect("connect");
    tokio::io::AsyncWriteExt::write_all(&mut stream, b"GET / HTTP/1.1\r\n\r\n")
        .await
        .expect("write");
    drop(stream);

    let seen = server.await.expect("join");
    let head = vision_request_head();
    assert_eq!(&seen[..head.len()], &head[..], "the request head");

    // the payload arrives as [uuid][command][content_len][pad_len][content][pad]
    let payload = b"GET / HTTP/1.1\r\n\r\n";
    let start = head.len();
    assert_eq!(
        &seen[start..start + 16],
        &UUID[..],
        "the vision prefix repeats the uuid"
    );
    let frame = &seen[start + 16..];
    // the first frame of the padding phase is Continue: End means "the framing
    // stops here", so a client would read this header as payload
    assert_eq!(frame[0], 0, "commandPaddingContinue");
    let content = u16::from_be_bytes([frame[1], frame[2]]) as usize;
    assert_eq!(content, payload.len(), "the whole write is one block");
    assert_eq!(&frame[5..5 + content], &payload[..]);
}

#[test]
fn an_unknown_flow_is_rejected() {
    let err = match Vless::build(&config(443, "xtls-rprx-direct"), "outbounds[0]") {
        Ok(_) => panic!("an unknown flow must be rejected"),
        Err(error) => error.to_string(),
    };
    assert!(err.contains("xtls-rprx-direct"), "got {err}");
}

/// A vless udp relay: the request head carries the `Mux` command and the
/// no destination, and each datagram then rides the stream framed by xudp.
#[tokio::test]
async fn udp_relay_frames_datagrams_over_one_stream() {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let port = listener.local_addr().expect("addr").port();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("accept");
        let mut head = vec![0u8; 19];
        socket.read_exact(&mut head).await.expect("request head");
        // the first xudp frame names the destination
        let mut meta_len = [0u8; 2];
        socket.read_exact(&mut meta_len).await.expect("meta len");
        let mut meta = vec![0u8; u16::from_be_bytes(meta_len) as usize];
        socket.read_exact(&mut meta).await.expect("meta");
        let mut data_len = [0u8; 2];
        socket.read_exact(&mut data_len).await.expect("data len");
        let mut data = vec![0u8; u16::from_be_bytes(data_len) as usize];
        socket.read_exact(&mut data).await.expect("data");
        // answer: the vless response head, then an xudp keep frame
        let mut reply = vec![0x00, 0x00];
        reply.extend_from_slice(&4u16.to_be_bytes());
        reply.extend_from_slice(&[0, 0, 2, 1]);
        let echoed = data.iter().rev().copied().collect::<Vec<u8>>();
        reply.extend_from_slice(&(echoed.len() as u16).to_be_bytes());
        reply.extend_from_slice(&echoed);
        socket.write_all(&reply).await.expect("reply");
        (head, meta, data)
    });

    let mut outbound = config(port, "");
    outbound.insert("packet_encoding".into(), json!("xudp"));
    let vless = Vless::build(&outbound, "outbounds[0]").expect("build");
    let sock = vless
        .connect_udp(&Target::Domain("example.com".into(), 53))
        .await
        .expect("udp relay");
    sock.send(b"ping").await.expect("send");

    let mut buf = [0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(5), sock.recv(&mut buf))
        .await
        .expect("answer in time")
        .expect("recv");
    assert_eq!(
        &buf[..read],
        b"gnip",
        "the relay echoes what the server sent"
    );

    let (head, meta, data) = server.await.expect("join");
    let mut expected = vec![0];
    expected.extend_from_slice(&UUID);
    expected.extend_from_slice(&[0, 3]);
    assert_eq!(head, expected, "Mux has no destination in the VLESS head");
    assert_eq!(&meta[..5], &[0, 0, 1, 1, 2], "new, opt, udp");
    assert_eq!(&meta[5..7], &53u16.to_be_bytes());
    assert_eq!(&meta[7..9], &[0x02, 11], "domain with its length");
    assert_eq!(&meta[9..20], b"example.com");
    assert_eq!(&data, b"ping");
}

mod trojan {
    use std::pin::Pin;
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll};
    use std::time::Duration;

    use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

    use super::super::{Trojan, TrojanStream, trojan_request_head};
    use crate::inbound::Target;
    use crate::outbound::packet::{PacketEncoding, PacketReader, PacketWriter};

    /// sha224("password"), hex
    const KEY: &str = "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01";

    /// Keeps every write call apart, so a head that went out on its own shows
    /// up as a chunk of its own. Reads hand out `answer` once, then wait.
    pub(super) struct Wire {
        pub(super) writes: Arc<Mutex<Vec<Vec<u8>>>>,
        pub(super) answer: Vec<u8>,
        pub(super) shut: Arc<Mutex<bool>>,
    }

    impl AsyncRead for Wire {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            if self.answer.is_empty() {
                return Poll::Pending;
            }
            let take = self.answer.len().min(buf.remaining());
            buf.put_slice(&self.answer[..take]);
            self.answer.drain(..take);
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for Wire {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            // one TLS record per call at most, like the real stream under it
            let take = buf.len().min(core_tls::record::MAX_FRAGMENT);
            self.writes.lock().unwrap().push(buf[..take].to_vec());
            Poll::Ready(Ok(take))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            *self.shut.lock().unwrap() = true;
            Poll::Ready(Ok(()))
        }
    }

    type Writes = Arc<Mutex<Vec<Vec<u8>>>>;

    fn stream(answer: &[u8], wait: Duration) -> (TrojanStream, Vec<u8>, Writes, Arc<Mutex<bool>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let shut = Arc::new(Mutex::new(false));
        let head = trojan_request_head(KEY, 0x01, &Target::Domain("example.com".to_string(), 443))
            .unwrap();
        let wire = Wire {
            writes: Arc::clone(&writes),
            answer: answer.to_vec(),
            shut: Arc::clone(&shut),
        };
        (
            TrojanStream::with_wait(Box::new(wire), head.clone(), wait),
            head,
            writes,
            shut,
        )
    }

    /// `[56 hex][CRLF][cmd][socksaddr][CRLF]`, sing-box `ClientHandshake`.
    #[test]
    fn the_request_head_is_key_crlf_command_address_crlf() {
        let head = trojan_request_head(KEY, 0x01, &Target::Domain("example.com".to_string(), 443))
            .unwrap();
        let mut want = KEY.as_bytes().to_vec();
        want.extend_from_slice(b"\r\n\x01\x03\x0bexample.com\x01\xbb\r\n");
        assert_eq!(head, want);
        let udp =
            trojan_request_head(KEY, 0x03, &Target::Ip("1.2.3.4:53".parse().unwrap())).unwrap();
        assert_eq!(&udp[56..], b"\r\n\x03\x01\x01\x02\x03\x04\x00\x35\r\n");
    }

    /// The key is what sing-box's `trojan.Key` makes of the password.
    #[test]
    fn the_key_is_hex_sha224_of_the_password() {
        let obj = serde_json::json!({
            "type": "trojan", "tag": "t", "server": "127.0.0.1", "server_port": 443,
            "password": "password", "tls": {"enabled": true, "server_name": "example.com"}
        });
        let trojan = Trojan::build(obj.as_object().unwrap(), "t").unwrap();
        assert_eq!(trojan.password_hash, KEY);
    }

    /// The first payload goes out in the head's write -- one TLS record -- the
    /// way both references send it; nothing waits for the timer.
    #[tokio::test]
    async fn the_first_payload_rides_with_the_head() {
        let (mut stream, head, writes, _) = stream(b"", Duration::from_secs(30));
        let started = tokio::time::Instant::now();
        stream.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
        stream.flush().await.unwrap();
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "no wait with a payload at hand"
        );
        stream.write_all(b"more").await.unwrap();
        let writes = writes.lock().unwrap().clone();
        let mut first = head.clone();
        first.extend_from_slice(b"GET / HTTP/1.1\r\n\r\n");
        assert_eq!(writes, vec![first, b"more".to_vec()]);
    }

    /// A destination that talks first never sees a payload from us; the head
    /// goes out alone once the wait is over and the answer comes back.
    #[tokio::test]
    async fn a_server_first_destination_gets_the_head_after_the_wait() {
        let (mut stream, head, writes, _) = stream(b"220 ready\r\n", Duration::from_millis(100));
        let started = tokio::time::Instant::now();
        let mut banner = [0u8; 11];
        stream.read_exact(&mut banner).await.unwrap();
        assert_eq!(&banner, b"220 ready\r\n");
        assert!(started.elapsed() >= Duration::from_millis(100));
        assert_eq!(writes.lock().unwrap().clone(), vec![head]);
        stream.write_all(b"EHLO x\r\n").await.unwrap();
        assert_eq!(writes.lock().unwrap()[1], b"EHLO x\r\n");
    }

    /// A payload larger than a record: the head and as much as fits share the
    /// first record, and nothing is lost or repeated.
    #[tokio::test]
    async fn a_large_first_payload_fills_the_first_record() {
        let (mut stream, head, writes, _) = stream(b"", Duration::from_millis(100));
        let payload: Vec<u8> = (0..40_000u32).map(|i| i as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let writes = writes.lock().unwrap().clone();
        assert_eq!(writes[0].len(), core_tls::record::MAX_FRAGMENT);
        assert_eq!(&writes[0][..head.len()], &head[..]);
        let sent: Vec<u8> = writes.concat();
        assert_eq!(&sent[head.len()..], &payload[..]);
    }

    /// A client that closes without a byte gets nothing sent: Xray's
    /// `CopyOnceTimeout` returns the end of stream as an error before the
    /// buffered head is flushed (`proxy/trojan/client.go`). The end of the
    /// upload is not passed on either: the transport stays open.
    #[tokio::test]
    async fn closing_before_any_payload_sends_nothing() {
        let (mut stream, _, writes, shut) = stream(b"", Duration::from_millis(100));
        stream.shutdown().await.unwrap();
        assert!(writes.lock().unwrap().is_empty());
        assert!(!*shut.lock().unwrap());
    }

    /// The end of the upload after a payload is not passed on either, as with
    /// Xray's client: the transport is not shut down and reads go on.
    #[tokio::test]
    async fn the_end_of_the_upload_is_not_passed_on() {
        let (mut stream, head, writes, shut) = stream(b"answer", Duration::from_millis(100));
        stream.write_all(b"request").await.unwrap();
        stream.shutdown().await.unwrap();
        assert!(!*shut.lock().unwrap());
        let mut answer = [0u8; 6];
        stream.read_exact(&mut answer).await.unwrap();
        assert_eq!(&answer, b"answer");
        let mut first = head;
        first.extend_from_slice(b"request");
        assert_eq!(writes.lock().unwrap().clone(), vec![first]);
    }

    /// `trojan.WritePacket`/`ReadPacket`: socksaddr, length, CRLF, payload.
    #[tokio::test]
    async fn udp_packets_carry_address_length_and_crlf() {
        let mut writer = PacketWriter::new(PacketEncoding::Trojan);
        let target = Target::Ip("1.2.3.4:53".parse().unwrap());
        let framed = writer.frame(&target, b"query").unwrap();
        assert_eq!(framed, b"\x01\x01\x02\x03\x04\x00\x35\x00\x05\r\nquery");
        let named = writer
            .frame(&Target::Domain("dns.example".to_string(), 53), b"q")
            .unwrap();
        assert_eq!(named, b"\x03\x0bdns.example\x00\x35\x00\x01\r\nq");

        // what a server sends back, from IPv4, IPv6 and a name
        let mut wire = framed.clone();
        wire.extend_from_slice(b"\x04");
        wire.extend_from_slice(&[0u8; 15]);
        wire.extend_from_slice(b"\x01\x00\x35\x00\x02\r\nv6");
        wire.extend_from_slice(&named);
        let mut reader = PacketReader::new(PacketEncoding::Trojan);
        let mut input = &wire[..];
        assert_eq!(reader.read(&mut input).await.unwrap(), b"query");
        assert_eq!(reader.read(&mut input).await.unwrap(), b"v6");
        assert_eq!(reader.read(&mut input).await.unwrap(), b"q");
        let mut bad = &b"\x01\x01\x02\x03\x04\x00\x35\x00\x01XXq"[..];
        assert!(reader.read(&mut bad).await.is_err(), "the CRLF is checked");
    }

    /// The client has no mux and no plain mode, and says so.
    #[test]
    fn multiplex_and_plain_trojan_are_refused() {
        let base = serde_json::json!({
            "type": "trojan", "tag": "t", "server": "127.0.0.1", "server_port": 443,
            "password": "p", "tls": {"enabled": true, "server_name": "example.com"}
        });
        let mut mux = base.clone();
        mux["multiplex"] = serde_json::json!({"enabled": true});
        let err = Trojan::build(mux.as_object().unwrap(), "t").err().unwrap();
        assert!(err.to_string().contains("multiplex"), "{err}");
        let mut off = base.clone();
        off["multiplex"] = serde_json::json!({"enabled": false, "protocol": "h2mux"});
        assert!(Trojan::build(off.as_object().unwrap(), "t").is_ok());
        let mut plain = base.clone();
        plain["tls"] = serde_json::json!({"enabled": false});
        let err = Trojan::build(plain.as_object().unwrap(), "t")
            .err()
            .unwrap();
        assert!(err.to_string().contains("requires TLS"), "{err}");
    }
}

/// The VLESS request head over a stream that keeps every write apart.
mod vless_head {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::super::{PendingHead, VLESS_FIRST_WRITE, VlessStream};
    use super::UUID;
    use super::trojan::Wire;
    use crate::outbound::vision::VisionStream;

    type Writes = Arc<Mutex<Vec<Vec<u8>>>>;

    /// What `Vless::dial` builds for Vision: the head waits in the VLESS
    /// stream, and the Vision stream above it writes the UUID with its first
    /// frame.
    fn vision(answer: &[u8], wait: Duration) -> (VisionStream, Vec<u8>, Writes, Arc<Mutex<bool>>) {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let shut = Arc::new(Mutex::new(false));
        let wire = Wire {
            writes: Arc::clone(&writes),
            answer: answer.to_vec(),
            shut: Arc::clone(&shut),
        };
        let head = super::vision_request_head();
        let vless = VlessStream {
            inner: Box::new(wire),
            request: PendingHead::new(head.clone(), wait, VLESS_FIRST_WRITE),
            header_pending: true,
            need: 2,
            buf: Vec::new(),
        };
        (VisionStream::new(Box::new(vless), UUID), head, writes, shut)
    }

    /// `[command][content:u16][padding:u16][content][zeros]`, all of `data`
    fn frame(data: &[u8]) -> (u8, Vec<u8>, usize) {
        let content = u16::from_be_bytes([data[1], data[2]]) as usize;
        let padding = u16::from_be_bytes([data[3], data[4]]) as usize;
        assert_eq!(data.len(), 5 + content + padding);
        assert!(data[5 + content..].iter().all(|b| *b == 0));
        (data[0], data[5..5 + content].to_vec(), padding)
    }

    /// The first payload: head, UUID and its frame in one write.
    #[tokio::test]
    async fn a_vision_client_sends_head_uuid_and_frame_in_one_write() {
        let (mut stream, head, writes, _) = vision(b"", Duration::from_secs(30));
        stream
            .write_all(b"\x16\x03\x01\x00\x05hello")
            .await
            .unwrap();
        let writes = writes.lock().unwrap().clone();
        assert_eq!(writes.len(), 1);
        assert_eq!(&writes[0][..head.len()], &head[..]);
        assert_eq!(&writes[0][head.len()..head.len() + 16], &UUID);
        let (command, content, _) = frame(&writes[0][head.len() + 16..]);
        assert_eq!(
            (command, &content[..]),
            (0x00, &b"\x16\x03\x01\x00\x05hello"[..])
        );
    }

    /// Nothing written within the wait: the head goes alone, as the Xray
    /// binary sends it, and the UUID rides with the first frame after it.
    #[tokio::test]
    async fn a_silent_vision_client_sends_the_bare_head_after_the_wait() {
        let mut answer = vec![0x00, 0x00];
        answer.extend_from_slice(&UUID);
        answer.extend_from_slice(&[0x01, 0x00, 0x03, 0x00, 0x00]);
        answer.extend_from_slice(b"220");
        let (mut stream, head, writes, _) = vision(&answer, Duration::from_millis(50));
        let started = tokio::time::Instant::now();
        let mut banner = [0u8; 3];
        stream.read_exact(&mut banner).await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(50));
        assert_eq!(&banner, b"220");
        stream.write_all(b"EHLO").await.unwrap();
        let writes = writes.lock().unwrap().clone();
        assert_eq!(writes.len(), 2);
        assert_eq!(writes[0], head);
        assert_eq!(&writes[1][..16], &UUID);
        let (command, content, _) = frame(&writes[1][16..]);
        assert_eq!((command, &content[..]), (0x00, &b"EHLO"[..]));
    }

    /// A client that closes without a byte: nothing is sent and the
    /// transport is not shut down, as with Xray.
    #[tokio::test]
    async fn closing_a_vision_client_before_any_payload_sends_nothing() {
        let (mut stream, _, writes, shut) = vision(b"", Duration::from_secs(30));
        stream.shutdown().await.unwrap();
        assert!(writes.lock().unwrap().is_empty());
        assert!(!*shut.lock().unwrap());
    }

    /// A first payload larger than Xray's 8 KiB write buffer: the head and as
    /// much as fits leave in one 8192-byte write, the rest after it.
    #[tokio::test]
    async fn a_large_first_payload_fills_one_xray_sized_write() {
        let writes = Arc::new(Mutex::new(Vec::new()));
        let wire = Wire {
            writes: Arc::clone(&writes),
            answer: Vec::new(),
            shut: Arc::new(Mutex::new(false)),
        };
        let head = super::request_head();
        let mut stream = VlessStream {
            inner: Box::new(wire),
            request: PendingHead::new(head.clone(), Duration::from_secs(30), VLESS_FIRST_WRITE),
            header_pending: true,
            need: 2,
            buf: Vec::new(),
        };
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let writes = writes.lock().unwrap().clone();
        assert_eq!(writes[0].len(), 8192);
        assert_eq!(&writes[0][..head.len()], &head[..]);
        assert_eq!(&writes.concat()[head.len()..], &payload[..]);
    }
}
