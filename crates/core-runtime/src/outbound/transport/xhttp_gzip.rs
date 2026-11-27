//! Streaming transparent response decoding for XHTTP's HTTP transports.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use flate2::{Crc, Decompress, FlushDecompress, Status};
use http::header::{ACCEPT_ENCODING, CONTENT_ENCODING, RANGE};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

const CHUNK: usize = 8192;

/// Whether the transport, rather than the configured headers, requested gzip.
pub(crate) fn request(req: &mut http::Request<()>) -> bool {
    request_with(req, http::HeaderMap::contains_key)
}

/// net/http's HTTP/1 transport checks the first header value for emptiness.
pub(crate) fn request_h1(req: &mut http::Request<()>) -> bool {
    request_with(req, |headers, name| {
        headers.get(name).is_some_and(|value| !value.is_empty())
    })
}

/// quic-go uses the same first-value checks as net/http's HTTP/1 client.
pub(crate) fn request_h3(req: &mut http::Request<()>) -> bool {
    request_h1(req)
}

fn request_with(
    req: &mut http::Request<()>,
    is_set: impl Fn(&http::HeaderMap, http::HeaderName) -> bool,
) -> bool {
    if req.method() == http::Method::HEAD
        || is_set(req.headers(), ACCEPT_ENCODING)
        || is_set(req.headers(), RANGE)
    {
        return false;
    }
    req.headers_mut()
        .append(ACCEPT_ENCODING, http::HeaderValue::from_static("gzip"));
    true
}

pub(crate) fn encoded(headers: &http::HeaderMap) -> bool {
    headers
        .get(CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes().eq_ignore_ascii_case(b"gzip"))
}

pub(crate) fn encoded_h3(headers: &http::HeaderMap) -> bool {
    headers
        .get(CONTENT_ENCODING)
        .is_some_and(|value| value.as_bytes() == b"gzip")
}

#[derive(Clone, Copy)]
enum Phase {
    Header,
    ExtraLength,
    Extra(usize),
    Name(usize),
    Comment(usize),
    HeaderCrc,
    Deflate,
    Trailer,
}

enum Decode {
    Data(usize),
    End,
    NeedInput,
    Yield,
}

/// Decode concatenated gzip members, retaining at most one input chunk.
/// Drive the raw inflater even with empty input: miniz can have output in its
/// dictionary after using all the available bytes. Waiting for another HTTP
/// DATA frame in that case can deadlock a duplex stream after a sync flush.
pub(crate) struct Decoder {
    phase: Phase,
    input: Bytes,
    eof: bool,
    scratch: [u8; 10],
    scratch_len: usize,
    flags: u8,
    crc: Crc,
    inflate: Decompress,
}

impl Decoder {
    pub(crate) fn new() -> Self {
        Self {
            phase: Phase::Header,
            input: Bytes::new(),
            eof: false,
            scratch: [0; 10],
            scratch_len: 0,
            flags: 0,
            crc: Crc::new(),
            inflate: Decompress::new(false),
        }
    }

    fn fill(&mut self, size: usize) -> bool {
        let n = (size - self.scratch_len).min(self.input.len());
        self.scratch[self.scratch_len..self.scratch_len + n].copy_from_slice(&self.input[..n]);
        self.input.advance(n);
        self.scratch_len += n;
        if self.scratch_len != size {
            return false;
        }
        self.scratch_len = 0;
        true
    }

    fn take_header(&mut self, n: usize) {
        self.crc.update(&self.input[..n]);
        self.input.advance(n);
    }

    fn read(&mut self, dst: &mut [u8]) -> io::Result<Decode> {
        const FHCRC: u8 = 2;
        const FEXTRA: u8 = 4;
        const FNAME: u8 = 8;
        const FCOMMENT: u8 = 16;
        let mut steps = 0;
        loop {
            // One HTTP DATA frame can contain many empty gzip members.
            if steps == 64 {
                return Ok(Decode::Yield);
            }
            steps += 1;
            match self.phase {
                Phase::Header => {
                    if self.eof && self.input.is_empty() && self.scratch_len == 0 {
                        return Ok(Decode::End);
                    }
                    if !self.fill(10) {
                        break;
                    }
                    if self.scratch[..3] != [0x1f, 0x8b, 8] {
                        return Err(invalid("invalid gzip header"));
                    }
                    self.flags = self.scratch[3];
                    self.crc.reset();
                    self.crc.update(&self.scratch);
                    self.phase = Phase::ExtraLength;
                }
                Phase::ExtraLength => {
                    if self.flags & FEXTRA == 0 {
                        self.phase = Phase::Name(0);
                        continue;
                    }
                    if !self.fill(2) {
                        break;
                    }
                    self.crc.update(&self.scratch[..2]);
                    self.phase = Phase::Extra(
                        u16::from_le_bytes([self.scratch[0], self.scratch[1]]) as usize,
                    );
                }
                Phase::Extra(left) => {
                    let n = left.min(self.input.len());
                    self.take_header(n);
                    if n == left {
                        self.phase = Phase::Name(0);
                    } else {
                        self.phase = Phase::Extra(left - n);
                        break;
                    }
                }
                Phase::Name(seen) | Phase::Comment(seen) => {
                    let (flag, next) = if matches!(self.phase, Phase::Name(_)) {
                        (FNAME, Phase::Comment(0))
                    } else {
                        (FCOMMENT, Phase::HeaderCrc)
                    };
                    if self.flags & flag == 0 {
                        self.phase = next;
                        continue;
                    }
                    // Go's gzip reader allows at most 512 bytes including
                    // the terminator in either optional string.
                    let available = (512 - seen).min(self.input.len());
                    if let Some(nul) = self.input[..available].iter().position(|&b| b == 0) {
                        self.take_header(nul + 1);
                        self.phase = next;
                    } else if seen + available == 512 {
                        return Err(invalid("gzip header string too long"));
                    } else {
                        self.take_header(available);
                        self.phase = if flag == FNAME {
                            Phase::Name(seen + available)
                        } else {
                            Phase::Comment(seen + available)
                        };
                        break;
                    }
                }
                Phase::HeaderCrc => {
                    if self.flags & FHCRC != 0 {
                        if !self.fill(2) {
                            break;
                        }
                        let expected = u16::from_le_bytes([self.scratch[0], self.scratch[1]]);
                        if self.crc.sum() as u16 != expected {
                            return Err(invalid("invalid gzip header checksum"));
                        }
                    }
                    self.crc.reset();
                    self.inflate.reset(false);
                    self.phase = Phase::Deflate;
                }
                Phase::Deflate => {
                    let before_in = self.inflate.total_in();
                    let before_out = self.inflate.total_out();
                    let status = self
                        .inflate
                        .decompress(&self.input, dst, FlushDecompress::None)
                        .map_err(|_| invalid("invalid gzip deflate payload"))?;
                    let used = (self.inflate.total_in() - before_in) as usize;
                    let produced = (self.inflate.total_out() - before_out) as usize;
                    self.input.advance(used);
                    if status == Status::StreamEnd {
                        self.phase = Phase::Trailer;
                    }
                    if produced != 0 {
                        self.crc.update(&dst[..produced]);
                        return Ok(Decode::Data(produced));
                    }
                    if status != Status::StreamEnd && used == 0 {
                        if !self.input.is_empty() {
                            return Err(invalid("gzip inflater made no progress"));
                        }
                        break;
                    }
                }
                Phase::Trailer => {
                    if !self.fill(8) {
                        break;
                    }
                    let (checksum, size) = self.scratch[..8].split_at(4);
                    if self.crc.sum() != u32::from_le_bytes(checksum.try_into().unwrap())
                        || self.crc.amount() != u32::from_le_bytes(size.try_into().unwrap())
                    {
                        return Err(invalid("invalid gzip trailer checksum or size"));
                    }
                    self.phase = Phase::Header;
                }
            }
        }
        if self.eof {
            Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated gzip response",
            ))
        } else {
            Ok(Decode::NeedInput)
        }
    }

    fn poll_read_with(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
        mut source: impl FnMut(&mut Context<'_>) -> Poll<io::Result<Option<Bytes>>>,
    ) -> Poll<io::Result<()>> {
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        // Bound work if a peer supplies a long sequence of empty members.
        for _ in 0..16 {
            let len = out.remaining().min(CHUNK);
            match self.read(out.initialize_unfilled_to(len))? {
                Decode::Data(n) => {
                    out.advance(n);
                    return Poll::Ready(Ok(()));
                }
                Decode::End => return Poll::Ready(Ok(())),
                Decode::NeedInput => match ready!(source(cx))? {
                    Some(input) => self.input = input,
                    None => self.eof = true,
                },
                Decode::Yield => break,
            }
        }
        cx.waker().wake_by_ref();
        Poll::Pending
    }

    pub(crate) async fn write_chunk(
        &mut self,
        input: Bytes,
        sink: &mut (impl AsyncWrite + Unpin),
    ) -> io::Result<()> {
        self.input = input;
        self.copy_to(sink).await
    }

    pub(crate) async fn finish_to(
        &mut self,
        sink: &mut (impl AsyncWrite + Unpin),
    ) -> io::Result<()> {
        self.eof = true;
        self.copy_to(sink).await
    }

    async fn copy_to(&mut self, sink: &mut (impl AsyncWrite + Unpin)) -> io::Result<()> {
        let mut out = [0; CHUNK];
        loop {
            match self.read(&mut out)? {
                Decode::End | Decode::NeedInput => return Ok(()),
                Decode::Data(n) => sink.write_all(&out[..n]).await?,
                Decode::Yield => tokio::task::yield_now().await,
            }
        }
    }
}

fn invalid(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

pub(crate) struct Reader<R> {
    input: R,
    decoder: Decoder,
}

impl<R> Reader<R> {
    pub(crate) fn new(input: R) -> Self {
        Self {
            input,
            decoder: Decoder::new(),
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for Reader<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let Self { input, decoder } = self.get_mut();
        decoder.poll_read_with(cx, out, |cx| {
            let mut buf = [0; CHUNK];
            let mut read = ReadBuf::new(&mut buf);
            ready!(Pin::new(&mut *input).poll_read(cx, &mut read))?;
            Poll::Ready(Ok(
                (!read.filled().is_empty()).then(|| Bytes::copy_from_slice(read.filled()))
            ))
        })
    }
}

pub(crate) struct H2Decoder {
    decoder: Decoder,
    encoded_credit: usize,
}

impl H2Decoder {
    pub(crate) fn new() -> Self {
        Self {
            decoder: Decoder::new(),
            encoded_credit: 0,
        }
    }

    pub(crate) fn poll_read(
        &mut self,
        cx: &mut Context<'_>,
        body: &mut h2::RecvStream,
        out: &mut ReadBuf<'_>,
        exact: bool,
    ) -> Poll<io::Result<()>> {
        let credit = &mut self.encoded_credit;
        self.decoder.poll_read_with(cx, out, |cx| {
            // The decoder asks for another chunk only after it consumed the
            // previous compressed bytes. Never credit the expanded length.
            if *credit != 0 {
                let flow = body.flow_control();
                let result = if exact {
                    ready!(flow.poll_release_capacity_exact(cx, *credit))
                } else {
                    flow.release_capacity(*credit)
                };
                result.map_err(io::Error::other)?;
                *credit = 0;
            }
            let Some(data) = ready!(body.poll_data(cx)) else {
                if exact {
                    ready!(body.flow_control().poll_exact_credit_flushed(cx));
                }
                return Poll::Ready(Ok(None));
            };
            let data = data.map_err(io::Error::other)?;
            *credit = data.len();
            Poll::Ready(Ok(Some(data)))
        })
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write as _;
    use std::sync::Arc;

    use flate2::{Compression, GzBuilder};
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, BufReader};

    use super::super::xhttp::{self, Dialer, XhttpConfig};
    use super::*;

    fn no_dial() -> Arc<Dialer> {
        Arc::new(|| Box::pin(async { Err(io::Error::other("unexpected extra dial")) }))
    }

    fn member(plain: &[u8]) -> Vec<u8> {
        let mut writer = GzBuilder::new()
            .extra([1, 2, 3])
            .filename("probe")
            .comment("xhttp")
            .write(Vec::new(), Compression::fast());
        writer.write_all(plain).unwrap();
        writer.finish().unwrap()
    }

    fn config(mode: &str, explicit: bool) -> XhttpConfig {
        let mut value = serde_json::json!({ "mode": mode });
        if explicit {
            value["headers"] = serde_json::json!({ "accept-encoding": "gzip" });
        }
        XhttpConfig::parse(value.as_object().unwrap()).unwrap()
    }

    #[test]
    fn compression_negotiation_respects_explicit_headers() {
        let mut req = http::Request::new(());
        assert!(request(&mut req));
        assert_eq!(req.headers()[ACCEPT_ENCODING], "gzip");
        assert!(!request(&mut req));

        let mut range = http::Request::get("/")
            .header(RANGE, "bytes=0-2")
            .body(())
            .unwrap();
        assert!(!request(&mut range));
        assert!(!request_h1(&mut range));

        let mut head = http::Request::head("/").body(()).unwrap();
        assert!(!request(&mut head));
        assert!(!request_h1(&mut head));

        let mut empty = http::Request::get("/")
            .header(ACCEPT_ENCODING, "")
            .body(())
            .unwrap();
        assert!(!request(&mut empty));
        assert!(request_h1(&mut empty));
        let encodings = empty.headers().get_all(ACCEPT_ENCODING);
        assert_eq!(
            encodings
                .iter()
                .map(|value| value.to_str().unwrap())
                .collect::<Vec<_>>(),
            ["", "gzip"]
        );
    }

    #[tokio::test]
    async fn fragmented_gzip_members_and_bad_trailer() {
        let mut raw = member(b"first");
        raw.extend(member(b"second"));
        let (mut wire, read) = tokio::io::duplex(1);
        let receive = async {
            let mut found = Vec::new();
            Reader::new(read).read_to_end(&mut found).await.unwrap();
            assert_eq!(&found, b"firstsecond");
        };
        let send = async {
            wire.write_all(&raw).await.unwrap();
            wire.shutdown().await.unwrap();
        };
        tokio::join!(send, receive);

        raw.truncate(raw.len() - 1);
        let error = Reader::new(raw.as_slice())
            .read_to_end(&mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
        let mut raw = member(b"content");
        *raw.last_mut().unwrap() ^= 1;
        let error = Reader::new(raw.as_slice())
            .read_to_end(&mut Vec::new())
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn decoder_delivers_flushed_payload_before_gzip_trailer() {
        let plain = vec![b'a'; 128 * 1024];
        let mut gzip = flate2::write::GzEncoder::new(Vec::new(), Compression::fast());
        gzip.write_all(&plain).unwrap();
        gzip.flush().unwrap();
        let flushed = gzip.get_ref().len();
        let wire = gzip.finish().unwrap();

        let mut reader = Decoder::new();
        let mut decoded = Vec::new();
        reader
            .write_chunk(Bytes::copy_from_slice(&wire[..flushed]), &mut decoded)
            .await
            .unwrap();
        assert_eq!(decoded, plain);
        reader
            .write_chunk(Bytes::copy_from_slice(&wire[flushed..]), &mut decoded)
            .await
            .unwrap();
        reader.finish_to(&mut decoded).await.unwrap();
        assert_eq!(decoded, plain);
    }

    #[tokio::test]
    async fn wire_h1_stream_one_only_decodes_automatically_requested_gzip() {
        for explicit in [false, true] {
            let plain = vec![b'x'; 48 * 1024];
            let encoded = member(&plain);
            let (client, peer) = tokio::io::duplex(8192);
            let response = encoded.clone();
            let server = tokio::spawn(async move {
                let mut peer = BufReader::new(peer);
                let mut request = String::new();
                loop {
                    let old_len = request.len();
                    assert_ne!(peer.read_line(&mut request).await.unwrap(), 0);
                    if &request[old_len..] == "\r\n" {
                        break;
                    }
                }
                assert!(request.contains("accept-encoding: gzip\r\n"));
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Encoding: GZip\r\nContent-Length: {}\r\n\r\n",
                    response.len(),
                );
                peer.get_mut().write_all(head.as_bytes()).await.unwrap();
                peer.get_mut().write_all(&response).await.unwrap();
            });
            let mut io = xhttp::connect(
                Box::new(client),
                false,
                false,
                "peer",
                80,
                &config("stream-one", explicit),
                no_dial(),
            )
            .await
            .unwrap();
            let mut found = Vec::new();
            io.read_to_end(&mut found).await.unwrap();
            assert_eq!(found, if explicit { encoded } else { plain });
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn wire_h2_gzip_decodes_stream_one_and_split_downloads() {
        for (mode, explicit) in [
            ("stream-one", false),
            ("stream-up", false),
            ("stream-one", true),
        ] {
            let plain = vec![b'x'; 96 * 1024];
            let encoded = member(&plain);
            let response = Bytes::copy_from_slice(&encoded);
            let (client, peer) = tokio::io::duplex(64 * 1024);
            let server = tokio::spawn(async move {
                let mut server = h2::server::handshake(peer).await.unwrap();
                while let Some(Ok((request, mut reply))) = server.accept().await {
                    assert_eq!(request.headers()[ACCEPT_ENCODING], "gzip");
                    if mode == "stream-one" || request.method() == http::Method::GET {
                        let headers = http::Response::builder()
                            .header(CONTENT_ENCODING, "gzip")
                            .body(())
                            .unwrap();
                        reply
                            .send_response(headers, false)
                            .unwrap()
                            .send_data(response.clone(), true)
                            .unwrap();
                    } else {
                        reply.send_response(http::Response::new(()), true).unwrap();
                    }
                }
            });
            let cfg = config(mode, explicit);
            let mut io = xhttp::connect(Box::new(client), true, true, "peer", 443, &cfg, no_dial())
                .await
                .unwrap();
            let mut found = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                io.read_to_end(&mut found),
            )
            .await
            .unwrap()
            .unwrap();
            assert_eq!(found, if explicit { encoded } else { plain });
            server.abort();
        }
    }
}
