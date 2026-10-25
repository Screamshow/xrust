//! Server-side transports.
//!
//! A transport takes the request off the front of the stream and leaves the
//! protocol bytes where the protocol expects to find them: after a websocket
//! handshake the rest of the connection is frames, after an httpupgrade `101`
//! it is raw, after gRPC it is the request body of one `POST` stream, and
//! XHTTP is the one that is not one connection at all -- a download `GET`, the
//! sequenced upload `POST`s, and one bidirectional `POST` for `stream-one`,
//! all stitched into one byte stream through a session table. Nothing above
//! this module knows a transport exists -- `handle` gets an
//! `AsyncRead + AsyncWrite` either way.
//!
//! Only what a listener can actually serve lives here. `http` and `quic` are
//! still refused by the config validator with a message saying so, because a
//! listener that binds a port and then hangs on every connection is worse than
//! one that refuses to start. XHTTP shares its split-session table across
//! HTTP/1.1 connections and HTTP/2 streams.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, ready};

use bytes::Bytes;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;

use super::AnyStream;
use crate::outbound::transport::WsStream;

/// Enough for any request line plus headers, and no more: a handshake is a few
/// hundred bytes, and a peer that sends more than this is not one.
const MAX_HEAD: usize = 8 * 1024;

/// What a listener wraps the connection in before the protocol reads it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Kind {
    Ws,
    HttpUpgrade,
    Http,
    Grpc,
    Xhttp,
}

impl Kind {
    fn parse(at: &str, ty: &str) -> anyhow::Result<Self> {
        Ok(match ty {
            "ws" => Kind::Ws,
            "httpupgrade" => Kind::HttpUpgrade,
            "http" | "h2" => Kind::Http,
            "grpc" => Kind::Grpc,
            "xhttp" => Kind::Xhttp,
            other => anyhow::bail!(
                "{at}: server transport {other} is not implemented yet (ws, \
                 httpupgrade, http, grpc and xhttp are; quic is not)"
            ),
        })
    }
}

/// Every live XHTTP session of this listener, keyed by session id. One
/// session spans several connections, so it cannot live on any of them.
type SessionTable = Arc<Mutex<HashMap<String, Arc<XhttpSession>>>>;

#[derive(Clone, Debug)]
pub(crate) struct Transport {
    kind: Kind,
    /// Path the request line must carry. `/` when the config gave none, which is
    /// also what the reference treats an absent path as.
    path: String,
    /// `service_name` for gRPC, empty for the transports that have none.
    service: String,
    /// XHTTP only: where the session id lives and under which key. The
    /// placement engine is the reference's (`session_placement`), and the
    /// default keys are its too: `x_session` everywhere but in a header, where
    /// it is `X-Session`.
    session: Place,
    session_key: String,
    /// Where the packet sequence number lives. A `GET` with a session and no
    /// sequence is the download stream, and with one it is an upload written
    /// with `uplink_http_method: GET`. Packet-up bodies are delivered in
    /// sequence order.
    seq: Place,
    seq_key: String,
    /// `sc_max_buffered_posts`: packets a session queues, POSTs that may
    /// wait for room, and how far ahead of the next seq a POST may be.
    max_buffered_posts: usize,
    /// `sc_max_each_post_bytes`, upper bound: the largest packet-up body.
    max_each_post: usize,
    /// Every live XHTTP session of this listener, keyed by session id.
    sessions: SessionTable,
    /// ws only: `max_early_data` and `early_data_header_name`; see
    /// [`Transport::ws_early_data`].
    max_early_data: u64,
    early_data_header_name: String,
}

impl Transport {
    /// Read `transport` off a server inbound. `None` when it has none, which is
    /// the plain-TCP case every protocol has always used.
    pub(crate) fn from_inbound(obj: &Value, at: &str) -> anyhow::Result<Option<Self>> {
        let Some(transport) = obj.get("transport").filter(|t| !t.is_null()) else {
            return Ok(None);
        };
        let transport = transport
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}.transport: must be an object"))?;
        let ty = transport
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}.transport: missing type"))?;
        let kind = Kind::parse(at, ty)?;
        let path = match transport.get("path").and_then(Value::as_str) {
            None => "/".to_string(),
            Some(p) => {
                if !p.starts_with('/') {
                    anyhow::bail!("{at}.transport.path: must start with a slash, got {p:?}");
                }
                p.to_string()
            }
        };
        let service = transport
            .get("service_name")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // The placement fields are XHTTP's; the other transports read the
        // object above for their one field and never look at these. Their
        // defaults are the reference's (`metaConfig`), and an unsupported
        // value refuses at startup rather than after the first connection.
        let place = |key: &str, what: &str| -> anyhow::Result<Place> {
            let raw = transport.get(key).and_then(Value::as_str).unwrap_or("");
            Place::parse(at, what, raw)
        };
        let session = place("session_placement", "session placement")?;
        let seq = place("seq_placement", "seq placement")?;
        let session_key = match transport.get("session_key").and_then(Value::as_str) {
            Some(key) if !key.is_empty() => key.to_string(),
            _ => match session {
                Place::Header => "X-Session".to_string(),
                _ => "x_session".to_string(),
            },
        };
        let seq_key = match transport.get("seq_key").and_then(Value::as_str) {
            Some(key) if !key.is_empty() => key.to_string(),
            _ => match seq {
                Place::Header => "X-Seq".to_string(),
                _ => "x_seq".to_string(),
            },
        };
        if kind == Kind::Xhttp
            && let Some(raw) = transport
                .get("uplink_data_placement")
                .and_then(Value::as_str)
            && !matches!(raw, "" | "body" | "auto")
        {
            anyhow::bail!(
                "{at}.transport: uplink_data_placement {raw:?} is not served yet, \
                 only the payload in the body"
            );
        }
        let max_buffered_posts = match transport.get("sc_max_buffered_posts") {
            None | Some(Value::Null) => DEFAULT_MAX_BUFFERED_POSTS,
            Some(v) => match v.as_u64() {
                Some(0) => DEFAULT_MAX_BUFFERED_POSTS,
                Some(n) if n <= MAX_BUFFERED_POSTS_LIMIT as u64 => n as usize,
                _ => anyhow::bail!(
                    "{at}.transport.sc_max_buffered_posts: must be 0..={MAX_BUFFERED_POSTS_LIMIT}, got {v}"
                ),
            },
        };
        let max_each_post = parse_max_each_post(at, transport.get("sc_max_each_post_bytes"))?;
        // ws only; the other transports have no such fields
        let ws_field = |key: &str| {
            transport
                .get(key)
                .filter(|v| kind == Kind::Ws && !v.is_null())
        };
        let max_early_data = match ws_field("max_early_data") {
            None => 0,
            Some(v) => v
                .as_u64()
                .filter(|&n| n <= u32::MAX as u64)
                .ok_or_else(|| {
                    anyhow::anyhow!("{at}.transport.max_early_data: must be a uint32, got {v}")
                })?,
        };
        let early_data_header_name = match ws_field("early_data_header_name") {
            None => String::new(),
            Some(Value::String(name)) => name.clone(),
            Some(v) => {
                anyhow::bail!("{at}.transport.early_data_header_name: must be a string, got {v}")
            }
        };
        Ok(Some(Self {
            kind,
            path,
            service,
            session,
            session_key,
            seq,
            seq_key,
            max_buffered_posts,
            max_each_post,
            sessions: Arc::new(Mutex::new(HashMap::new())),
            max_early_data,
            early_data_header_name,
        }))
    }

    /// Unwrap the request off `stream`, leaving protocol bytes behind.
    pub(crate) async fn accept(&self, stream: AnyStream) -> anyhow::Result<Accepted> {
        // gRPC does not read an HTTP/1.1 request head at all: the stream
        // already IS the HTTP/2 request, preface and all, so everything
        // happens inside the h2 handshake.
        if self.kind == Kind::Grpc {
            return Accepted::grpc(stream, &self.service).await;
        }
        if self.kind == Kind::Xhttp {
            if crate::inbound::stream_alpn(&stream) == Some(b"h2") {
                return Accepted::xhttp_h2(stream, self).await;
            }
            return self.xhttp_accept(stream).await.map(Accepted::Once);
        }
        if self.kind == Kind::Http {
            if crate::inbound::stream_alpn(&stream) == Some(b"h2") {
                return Accepted::http_h2(stream, &self.path).await;
            }
            let mut stream = stream;
            let (head, leftover) = read_head_split(&mut stream).await?;
            if head.starts_with(b"PRI * HTTP/2.0\r\n") {
                let mut combined = head;
                combined.extend_from_slice(&leftover);
                let pref_stream: AnyStream = Box::new(PrefixStream {
                    prefix: combined,
                    prefix_pos: 0,
                    inner: stream,
                });
                return Accepted::http_h2(pref_stream, &self.path).await;
            }
            let (_method, target, _headers) = parse_head(&head)?;
            if !path_matches(&target, &self.path) {
                anyhow::bail!("http: path {target:?} does not match {:?}", self.path);
            }
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nConnection: close\r\n\r\n")
                .await?;
            stream.flush().await?;
            let body_stream: AnyStream = if leftover.is_empty() {
                stream
            } else {
                Box::new(PrefixStream {
                    prefix: leftover,
                    prefix_pos: 0,
                    inner: stream,
                })
            };
            return Ok(Accepted::Once(body_stream));
        }
        let mut stream = stream;
        let (head, leftover) = read_head_split(&mut stream).await?;
        let (method, target, headers) = parse_head(&head)?;
        if !path_matches(&target, &self.path) {
            anyhow::bail!("ws: path {target:?} does not match {:?}", self.path);
        }
        let early_data = if self.kind == Kind::Ws {
            self.ws_early_data(&headers)?
        } else {
            Vec::new()
        };
        let mut stream: AnyStream = if leftover.is_empty() {
            stream
        } else {
            Box::new(PrefixStream {
                prefix: leftover,
                prefix_pos: 0,
                inner: stream,
            })
        };
        match self.kind {
            Kind::Ws => {
                let key = match crate::ws::validate(&headers) {
                    Ok(key) => key,
                    Err(rejection) => {
                        // The status the reference answers with, so a browser or a
                        // scanner sees the same thing it would from sing-box.
                        use tokio::io::AsyncWriteExt as _;
                        stream.write_all(rejection.response().as_bytes()).await?;
                        stream.flush().await?;
                        anyhow::bail!("ws: {}", rejection.reason());
                    }
                };
                let _ = method;
                crate::ws::accept(&mut stream, &key).await?;
                let ws: AnyStream = Box::new(WsStream::server(stream));
                if early_data.is_empty() {
                    return Ok(Accepted::Once(ws));
                }
                Ok(Accepted::Once(Box::new(PrefixStream {
                    prefix: early_data,
                    prefix_pos: 0,
                    inner: ws,
                })))
            }
            Kind::HttpUpgrade => {
                use tokio::io::AsyncWriteExt as _;
                // httpupgrade is the same 101 with no frames after it: the rest of
                // the connection is the protocol, byte for byte.
                stream
                    .write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\n\
                          Connection: Upgrade\r\n\
                          Upgrade: websocket\r\n\r\n",
                    )
                    .await?;
                stream.flush().await?;
                Ok(Accepted::Once(stream))
            }
            // returned before the request head above
            Kind::Http => unreachable!("http returns before the request head"),
            Kind::Grpc => unreachable!("grpc returns before the request head"),
            Kind::Xhttp => unreachable!("xhttp returns before the request head"),
        }
    }
}

impl Transport {
    /// Take the early data off a ws upgrade request: base64url without
    /// padding, in the `early_data_header_name` header, or in
    /// `Sec-WebSocket-Protocol` when that is empty or absent (Xray's place for
    /// it, and where Forkop X's `ed=` configs put it). Unlike sing-box, an
    /// empty name never means "at the end of the path": the path always has
    /// to match exactly. Nothing is read unless `max_early_data` or a header
    /// name is set, so a plain inbound keeps real subprotocols untouched. A
    /// value that does not decode refuses the request, as sing-box does. The
    /// decoded size is not checked against `max_early_data`; neither
    /// reference checks it.
    fn ws_early_data(&self, headers: &[(String, String)]) -> anyhow::Result<Vec<u8>> {
        if self.max_early_data == 0 && self.early_data_header_name.is_empty() {
            return Ok(Vec::new());
        }
        let name = if self.early_data_header_name.is_empty() {
            "Sec-WebSocket-Protocol"
        } else {
            self.early_data_header_name.as_str()
        };
        let encoded = headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
            .unwrap_or("");
        if encoded.is_empty() {
            return Ok(Vec::new());
        }
        decode_early_data(encoded).map_err(|e| anyhow::anyhow!("ws: decode early data: {e}"))
    }
}

/// Go's `base64.RawURLEncoding`: url alphabet, no padding, stray low bits of
/// the last character ignored.
fn decode_early_data(encoded: &str) -> Result<Vec<u8>, base64::DecodeError> {
    use base64::Engine as _;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    const RAW_URL: GeneralPurpose = GeneralPurpose::new(
        &base64::alphabet::URL_SAFE,
        GeneralPurposeConfig::new()
            .with_encode_padding(false)
            .with_decode_padding_mode(DecodePaddingMode::RequireNone)
            .with_decode_allow_trailing_bits(true),
    );
    RAW_URL.decode(encoded)
}

/// Read up to the end of the request head, inclusive of the blank line,
/// and return unconsumed bytes that arrived in the same chunk.
async fn read_head_split<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> anyhow::Result<(Vec<u8>, Vec<u8>)> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            anyhow::bail!("http: connection closed inside the request head");
        }
        buf.extend_from_slice(&chunk[..n]);
        let end = if let Some(pos) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            Some(pos + 4)
        } else {
            buf.windows(2).position(|w| w == b"\n\n").map(|pos| pos + 2)
        };
        if let Some(pos) = end {
            let leftover = buf.split_off(pos);
            return Ok((buf, leftover));
        }
        if buf.len() > MAX_HEAD {
            anyhow::bail!("http: request head over {MAX_HEAD} bytes");
        }
    }
}

/// The method, the request target and the headers. Header names are kept as they
/// arrived; [`crate::ws::validate`] compares them case-insensitively.
type RequestHead = (String, String, Vec<(String, String)>);

fn parse_head(bytes: &[u8]) -> anyhow::Result<RequestHead> {
    let text = String::from_utf8_lossy(bytes);
    let mut lines = text.split("\r\n").flat_map(|l| l.split('\n'));
    let request = lines
        .next()
        .ok_or_else(|| anyhow::anyhow!("http: empty request"))?;
    let mut parts = request.split_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("http: no method in {request:?}"))?
        .to_string();
    let target = parts
        .next()
        .ok_or_else(|| anyhow::anyhow!("http: no target in {request:?}"))?
        .to_string();
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }
    Ok((method, target, headers))
}

/// The request target against the configured path, query and all. A config path
/// may or may not carry a query itself; when it does, the incoming query has to
/// match too, which is what sing-box does.
fn path_matches(target: &str, configured: &str) -> bool {
    let (path, query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    match configured.split_once('?') {
        Some((p, q)) => path == p && query == Some(q),
        None => path == configured && query.is_none(),
    }
}

/// What [`Transport::accept`] hands to the protocol: one session, or a
/// connection that hands out a session per stream.
pub(crate) enum Accepted {
    /// The single session this connection carries -- every transport except
    /// gRPC. When the session ends, so does the connection.
    Once(AnyStream),
    /// A gRPC connection: one session per stream, the connection outliving
    /// them. Clients pool these -- sing-box reuses the TCP a finished session
    /// ran on for the next one -- so closing the connection together with the
    /// first session breaks every later session: the client writes into the
    /// pooled corpse and fails with a closed pipe before it ever reaches us.
    /// Boxed: an h2 `Connection` is far bigger than the pipe it wraps.
    Grpc(Box<GrpcAccept>),
    /// A v2ray HTTP/2 connection: one session per request stream.
    HttpH2(Box<HttpH2Accept>),
    /// An XHTTP HTTP/2 connection: one session per stream (stream-one), or multiplexed.
    XhttpH2(Box<XhttpH2Accept>),
}

impl Accepted {
    /// The gRPC half: the h2 handshake, preface and all, once per connection.
    async fn grpc(stream: AnyStream, service: &str) -> anyhow::Result<Self> {
        let conn = crate::outbound::transport::h2io::server_builder()
            .handshake(stream)
            .await
            .map_err(|e| anyhow::anyhow!("grpc: h2 handshake: {e}"))?;
        Ok(Self::Grpc(Box::new(GrpcAccept {
            conn: Some(conn),
            service: service.to_string(),
            first: true,
        })))
    }

    /// The v2ray HTTP/2 transport half: handshake, and accept streams on the path.
    async fn http_h2(stream: AnyStream, path: &str) -> anyhow::Result<Self> {
        let conn = crate::outbound::transport::h2io::server_builder()
            .handshake(stream)
            .await
            .map_err(|e| anyhow::anyhow!("http: h2 handshake: {e}"))?;
        Ok(Self::HttpH2(Box::new(HttpH2Accept {
            conn: Some(conn),
            path: path.to_string(),
            first: true,
        })))
    }

    /// The XHTTP HTTP/2 half: handshake, and accept streams on the path.
    async fn xhttp_h2(stream: AnyStream, transport: &Transport) -> anyhow::Result<Self> {
        let conn = crate::outbound::transport::h2io::server_builder()
            .handshake(stream)
            .await
            .map_err(|e| anyhow::anyhow!("xhttp h2: handshake: {e}"))?;
        Ok(Self::XhttpH2(Box::new(XhttpH2Accept {
            conn: Some(conn),
            transport: transport.clone(),
            first: true,
        })))
    }
}

/// The accept half of a gRPC connection: one stream at a time, each on the
/// reference's wire -- `transport/v2raygrpclite/server.go` (and, when
/// `force_lite` is off, its grpc-go server): same checks, same status, same
/// framing, and like grpc-go every stream is a session of the one connection.
pub(crate) struct GrpcAccept {
    conn: Option<h2::server::Connection<AnyStream, Bytes>>,
    service: String,
    /// No stream handed out yet. The failures that can still happen before
    /// the first one belong to the connection itself and to the caller's log;
    /// after the first stream a dead connection just ends the loop, and the
    /// sessions already running go down with their own stream.
    first: bool,
}

impl GrpcAccept {
    /// The next stream, as protocol bytes. `None` means the connection is
    /// over.
    async fn next(&mut self) -> anyhow::Result<Option<AnyStream>> {
        loop {
            let Some(conn) = self.conn.as_mut() else {
                return Ok(None);
            };
            let (request, mut responder) = match conn.accept().await {
                Some(Ok(pair)) => pair,
                Some(Err(err)) if self.first => anyhow::bail!("grpc: h2 accept: {err}"),
                Some(Err(_)) => return Ok(None),
                None if self.first => {
                    anyhow::bail!("grpc: the connection ended before a request")
                }
                None => return Ok(None),
            };
            let first = std::mem::replace(&mut self.first, false);
            let path = request.uri().path().to_string();
            let method = request.method().as_str().to_string();
            let content_type = request
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_string();
            if let Some(reason) = grpc_rejection(&path, &method, &content_type, &self.service) {
                // The status the reference answers a bad request with, so a scanner
                // sees the same thing it would from sing-box.
                let _ = responder.send_response(grpc_rejection_response(), true);
                if first {
                    // The status is queued on the connection and only a driver
                    // flushes it, and the reference lets the client hang up on a
                    // rejection: drive the connection until it does, 404ing
                    // anything else that gets asked in the meantime.
                    let conn = self
                        .conn
                        .take()
                        .expect("grpc: the connection is there before the first stream");
                    let _ = grpc_drive(conn).await;
                    anyhow::bail!("grpc: {reason} (path {path:?}, method {method})");
                }
                // Past the first stream a bad request is one 404'd stream, not
                // the end of the connection: the next one may still be good.
                continue;
            }
            // The 200 goes out before the protocol reads a byte of the body, the same
            // way `ServeHTTP` writes its header before it hands the connection over:
            // the far end waits for initial metadata before it will deliver messages.
            let send = responder
                .send_response(grpc_accept_response(), false)
                .map_err(|e| anyhow::anyhow!("grpc: response: {e}"))?;
            let recv = request.into_body();
            return Ok(Some(crate::outbound::transport::grpc::server(recv, send)));
        }
    }
}

pub(crate) struct HttpH2Accept {
    conn: Option<h2::server::Connection<AnyStream, Bytes>>,
    path: String,
    first: bool,
}

impl HttpH2Accept {
    async fn next(&mut self) -> anyhow::Result<Option<AnyStream>> {
        loop {
            let Some(conn) = self.conn.as_mut() else {
                return Ok(None);
            };
            let (request, mut responder) = match conn.accept().await {
                Some(Ok(pair)) => pair,
                Some(Err(err)) if self.first => anyhow::bail!("http: h2 accept: {err}"),
                Some(Err(_)) => return Ok(None),
                None if self.first => {
                    anyhow::bail!("http: the connection ended before a request")
                }
                None => return Ok(None),
            };
            let first = std::mem::replace(&mut self.first, false);
            let path = request.uri().path().to_string();
            if !path_matches(&path, &self.path) {
                let response = http::Response::builder()
                    .status(http::StatusCode::NOT_FOUND)
                    .body(())
                    .unwrap();
                let _ = responder.send_response(response, true);
                if first {
                    anyhow::bail!("http: path {path:?} does not match {:?}", self.path);
                }
                continue;
            }
            let response = http::Response::builder()
                .status(http::StatusCode::OK)
                .header("content-type", "application/octet-stream")
                .body(())
                .map_err(|e| anyhow::anyhow!("http: response: {e}"))?;
            let send = responder
                .send_response(response, false)
                .map_err(|e| anyhow::anyhow!("http: send response: {e}"))?;
            let recv = request.into_body();
            let h2_stream = crate::outbound::transport::h2io::H2Stream::server(recv, send);
            let stream: AnyStream =
                Box::new(crate::outbound::transport::h2io::H2Io { h2: h2_stream });
            return Ok(Some(stream));
        }
    }
}

struct PrefixStream {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: AnyStream,
}

impl AsyncRead for PrefixStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.prefix_pos < this.prefix.len() {
            let left = &this.prefix[this.prefix_pos..];
            let take = left.len().min(buf.remaining());
            buf.put_slice(&left[..take]);
            this.prefix_pos += take;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for PrefixStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Run the sessions [`Transport::accept`] gave out. Everything but gRPC
/// carries one session and awaits it right here; a gRPC connection is driven
/// by `accept` itself -- flow control, window updates and everything already
/// queued go out under it -- so its sessions run as tasks while the loop keeps
/// taking the next stream off the connection.
pub(crate) async fn serve_sessions<F, Fut>(accepted: Accepted, make: F) -> io::Result<()>
where
    F: Fn(AnyStream) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = ()> + Send + 'static,
{
    match accepted {
        Accepted::Once(stream) => {
            make(stream).await;
            Ok(())
        }
        Accepted::Grpc(mut grpc) => {
            let mut sessions = Vec::new();
            while let Some(stream) = grpc.next().await.map_err(io::Error::other)? {
                sessions.push(tokio::spawn(make(stream)));
            }
            for session in sessions {
                let _ = session.await;
            }
            Ok(())
        }
        Accepted::HttpH2(mut http) => {
            let mut sessions = Vec::new();
            while let Some(stream) = http.next().await.map_err(io::Error::other)? {
                sessions.push(tokio::spawn(make(stream)));
            }
            for session in sessions {
                let _ = session.await;
            }
            Ok(())
        }
        Accepted::XhttpH2(mut xhttp) => {
            let mut sessions = Vec::new();
            while let Some(stream) = xhttp.next().await.map_err(io::Error::other)? {
                sessions.push(tokio::spawn(make(stream)));
            }
            for session in sessions {
                let _ = session.await;
            }
            Ok(())
        }
    }
}

pub(crate) struct XhttpH2Accept {
    conn: Option<h2::server::Connection<AnyStream, Bytes>>,
    transport: Transport,
    first: bool,
}

impl XhttpH2Accept {
    async fn next(&mut self) -> anyhow::Result<Option<AnyStream>> {
        loop {
            let Some(conn) = self.conn.as_mut() else {
                return Ok(None);
            };
            let (request, mut responder) = match conn.accept().await {
                Some(Ok(pair)) => pair,
                Some(Err(err)) if self.first => anyhow::bail!("xhttp h2: accept: {err}"),
                Some(Err(_)) => return Ok(None),
                None if self.first => {
                    anyhow::bail!("xhttp h2: the connection ended before a request")
                }
                None => return Ok(None),
            };
            let first = std::mem::replace(&mut self.first, false);
            let req_path = request.uri().path().to_string();
            let method = request.method().as_str().to_string();

            let query = request.uri().query();
            let headers = request
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect::<Vec<_>>();
            let rest = req_path.strip_prefix(&self.transport.path).unwrap_or("");
            let trimmed = rest.trim_matches('/');
            let segments = if trimmed.is_empty() {
                vec![]
            } else {
                trimmed.split('/').collect::<Vec<_>>()
            };
            let sid = self.transport.session_id(&segments, query, &headers);
            let seq_raw = self.transport.seq_value(&segments, query, &headers);
            let seq = seq_raw.is_some();
            if !xhttp_h2_path_matches(&req_path, &self.transport.path)
                || (sid.is_none() && (method != "POST" || !segments.is_empty()))
            {
                let response = http::Response::builder().status(404).body(()).unwrap();
                let _ = responder.send_response(response, true);
                if first {
                    let conn = self
                        .conn
                        .take()
                        .expect("xhttp: connection exists before first stream");
                    let _ = xhttp_h2_drive(conn).await;
                    anyhow::bail!(
                        "xhttp h2: rejected {method} {req_path:?} (expected POST {})",
                        self.transport.path
                    );
                }
                continue;
            }

            if let Some(sid) = sid {
                // The shared table belongs to the listener, not this h2
                // connection: upload and download may arrive on either one.
                let (session, protocol) = {
                    let mut table = self
                        .transport
                        .sessions
                        .lock()
                        .expect("xhttp table poisoned");
                    if let Some(session) = table.get(&sid) {
                        (Arc::clone(session), None)
                    } else {
                        let (session, uplink, down_tx) =
                            XhttpSession::new(self.transport.max_buffered_posts);
                        let protocol = Box::new(XhttpStream {
                            inner: xhttp_bridge(uplink, down_tx, Arc::downgrade(&session)),
                            listed: Some((Arc::clone(&self.transport.sessions), sid.clone())),
                            session: Arc::clone(&session),
                        }) as AnyStream;
                        table.insert(sid, Arc::clone(&session));
                        (session, Some(protocol))
                    }
                };
                if method == "GET" && !seq {
                    if let Some(down) = session.take_down() {
                        let response = http::Response::builder()
                            .status(200)
                            .header("content-type", "application/octet-stream")
                            .body(())
                            .unwrap();
                        let send = responder.send_response(response, false)?;
                        tokio::spawn(xhttp_h2_download_task(send, down, session));
                    } else {
                        let _ = responder.send_response(
                            http::Response::builder().status(409).body(()).unwrap(),
                            true,
                        );
                    }
                } else {
                    tokio::spawn(xhttp_h2_upload_task(
                        request.into_body(),
                        responder,
                        session,
                        seq_raw,
                        self.transport.max_each_post,
                    ));
                }
                if protocol.is_some() {
                    return Ok(protocol);
                }
                continue;
            }

            let response = http::Response::builder()
                .status(200)
                .header("content-type", "application/grpc")
                .body(())
                .unwrap();
            let send = responder
                .send_response(response, false)
                .map_err(|e| anyhow::anyhow!("xhttp h2: response: {e}"))?;
            let recv = request.into_body();
            let h2_stream = crate::outbound::transport::h2io::H2Stream::server(recv, send);
            return Ok(Some(Box::new(crate::outbound::transport::h2io::H2Io {
                h2: h2_stream,
            })));
        }
    }
}

async fn xhttp_h2_download_task(
    mut send: h2::SendStream<Bytes>,
    mut down: mpsc::Receiver<Vec<u8>>,
    session: Arc<XhttpSession>,
) {
    let ended = async {
        loop {
            let chunk = tokio::select! {
                // the client reset the GET: the session has nowhere to go
                _ = std::future::poll_fn(|cx|send.poll_reset(cx)) => {
                    return Err(io::Error::other("xhttp: h2 download reset"));
                }
                // the session failed on the upload side
                _ = session.wait_aborted() => {
                    return Err(io::Error::other("xhttp: the session failed"));
                }
                chunk = down.recv() => match chunk {Some(chunk)=>chunk,None=>break},
            };
            let mut chunk = Bytes::from(chunk);
            while !chunk.is_empty() {
                send.reserve_capacity(chunk.len());
                let capacity = std::future::poll_fn(|cx| send.poll_capacity(cx))
                    .await
                    .ok_or_else(|| io::Error::other("xhttp: h2 download closed"))?
                    .map_err(io::Error::other)?;
                if capacity == 0 {
                    continue;
                }
                let n = capacity.min(chunk.len());
                send.send_data(chunk.split_to(n), false)
                    .map_err(io::Error::other)?;
            }
        }
        send.send_data(Bytes::new(), true).map_err(io::Error::other)
    }
    .await;
    if ended.is_err() {
        session.cancel();
    } else {
        session.close_up();
    }
}

async fn xhttp_h2_upload_task(
    mut recv: h2::RecvStream,
    mut responder: h2::server::SendResponse<Bytes>,
    session: Arc<XhttpSession>,
    seq: Option<String>,
    max_each_post: usize,
) {
    let Some(raw) = seq else {
        // Stream-up needs response headers before EOF.
        if responder
            .send_response(http::Response::new(()), true)
            .is_err()
        {
            return;
        }
        while let Some(chunk) = recv.data().await {
            let Ok(chunk) = chunk else {
                session.close_up();
                return;
            };
            let size = chunk.len();
            if session.push(chunk.to_vec()).await.is_err() {
                return;
            }
            if recv.flow_control().release_capacity(size).is_err() {
                session.close_up();
                return;
            }
        }
        return;
    };
    // Packet-up: a permit before the body is read, so a waiting POST keeps
    // its body in the client's flow-control window; then the whole body,
    // queued by its seq, then the answer (Xray hub.go answers after
    // `uploadQueue.Push`). A body that breaks off is dropped as Xray drops it.
    let Ok(_permit) = session.packet_permit(&raw).await else {
        let _ = responder.send_response(
            http::Response::builder().status(500).body(()).unwrap(),
            true,
        );
        return;
    };
    let mut body = Vec::new();
    while let Some(chunk) = recv.data().await {
        let Ok(chunk) = chunk else {
            return;
        };
        let size = chunk.len();
        if body.len() + size > max_each_post {
            crate::logging::debug(format_args!(
                "xhttp upload: packet-up body over sc_max_each_post_bytes ({max_each_post})"
            ));
            let _ = responder.send_response(
                http::Response::builder().status(413).body(()).unwrap(),
                true,
            );
            return;
        }
        body.extend_from_slice(&chunk);
        if recv.flow_control().release_capacity(size).is_err() {
            return;
        }
    }
    let status: u16 = match packet_status(&session, &raw, body).await {
        PacketStatus::Ok => 200,
        PacketStatus::Failed => 500,
    };
    let _ = responder.send_response(
        http::Response::builder().status(status).body(()).unwrap(),
        true,
    );
}

fn xhttp_h2_path_matches(target: &str, configured: &str) -> bool {
    let (path, _query) = match target.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (target, None),
    };
    match path.strip_prefix(configured) {
        Some(rest) => rest.is_empty() || rest.starts_with('/'),
        None => false,
    }
}

fn xhttp_h2_drive(
    mut conn: h2::server::Connection<AnyStream, Bytes>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(next) = conn.accept().await {
            match next {
                Ok((_, mut responder)) => {
                    let response = http::Response::builder().status(404).body(()).unwrap();
                    let _ = responder.send_response(response, true);
                }
                Err(_) => return,
            }
        }
    })
}

/// Keep a rejected connection running until the far end gives up on it.
/// `accept` drives the whole state machine while it waits -- flow control,
/// window updates and everything already queued go out under it -- so the
/// queued 404 leaves under this loop, and anything else asked for on the way
/// gets the same answer.
fn grpc_drive(mut conn: h2::server::Connection<AnyStream, Bytes>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(next) = conn.accept().await {
            match next {
                Ok((request, mut responder)) => {
                    crate::logging::debug(format_args!(
                        "grpc: rejected connection, {} -> 404",
                        request.uri().path()
                    ));
                    let _ = responder.send_response(grpc_rejection_response(), true);
                }
                Err(_) => return,
            }
        }
    })
}

/// What the reference answers a bad request with: a bare 404 and the end of
/// the stream (`invalidRequest`).
fn grpc_rejection_response() -> http::Response<()> {
    http::Response::builder()
        .status(404)
        .body(())
        .expect("a 404 builds")
}

/// The headers `ServeHTTP` writes before it hands the connection over.
fn grpc_accept_response() -> http::Response<()> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
        .expect("a 200 builds")
}

/// The three checks `ServeHTTP` makes, first failure named. `None` means serve.
fn grpc_rejection(
    path: &str,
    method: &str,
    content_type: &str,
    service: &str,
) -> Option<&'static str> {
    // the reference compares the decoded `:path` against `grpcname.Path`, and
    // the client may send the escaped form (the plain-form wire escapes the
    // service segment, `a%2Fb`)
    let decoded = path_unescape(path).unwrap_or_else(|| path.to_string());
    if decoded != grpc_service_path(service) {
        return Some("path does not match the service name");
    }
    if method != "POST" {
        return Some("not a POST");
    }
    if !content_type.starts_with("application/grpc") {
        return Some("content type is not application/grpc");
    }
    None
}

/// The decoded `:path` a gRPC request must carry for `service` -- the
/// reference's `grpcname.Path`: the plain form is `/service/Tun`, and a
/// leading `/` in `service_name` is Xray's custom path where everything up to
/// the last `/` is the service and the tail is the stream name minus a
/// `|multi` suffix (SPEC 093).
fn grpc_service_path(service: &str) -> String {
    if !service.starts_with('/') {
        return format!("/{service}/Tun");
    }
    // Go clamps the split index to 1 but takes the stream from the original
    // last slash, so `/` is `//` and `/Tun` is `//Tun`.
    let last = service.rfind('/').unwrap_or(0);
    let body_last = last.max(1);
    let body = &service[1..body_last];
    let ending = &service[(last + 1).min(service.len())..];
    let stream = ending.split('|').next().unwrap_or(ending);
    format!("/{body}/{stream}")
}

/// Go's `url.PathUnescape`: `None` when a `%` is not followed by two hex
/// digits, which is where the reference falls back to the raw string too.
fn path_unescape(path: &str) -> Option<String> {
    if !path.contains('%') {
        return Some(path.to_string());
    }
    let bytes = path.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hi = hex(*bytes.get(i + 1)?)?;
            let lo = hex(*bytes.get(i + 2)?)?;
            out.push(hi << 4 | lo);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Where a value lives when the reference's placement engine puts it somewhere
/// other than in the path. The names and the defaults are its (`metaConfig`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Place {
    Path,
    Query,
    Header,
    Cookie,
}

impl Place {
    fn parse(at: &str, what: &str, raw: &str) -> anyhow::Result<Self> {
        Ok(match raw {
            "" | "path" => Place::Path,
            "query" => Place::Query,
            "header" => Place::Header,
            "cookie" => Place::Cookie,
            other => anyhow::bail!("{at}: unsupported {what}: {other}"),
        })
    }
}

/// How many messages each direction of a session may hold. Backpressure, not
/// a buffer: a stalled download stops the protocol writing instead of eating
/// memory, and a stalled protocol stops the uploads instead of queueing them.
const XHTTP_QUEUE: usize = 64;

/// Xray `GetNormalizedScMaxBufferedPosts` (splithttp/config.go): 0 means 30.
const DEFAULT_MAX_BUFFERED_POSTS: usize = 30;
/// A sane ceiling for `sc_max_buffered_posts`; it sizes a channel.
const MAX_BUFFERED_POSTS_LIMIT: usize = 1 << 20;
/// Xray `GetNormalizedScMaxEachPostBytes` (splithttp/config.go): 1000000
/// when unset or 0.
const DEFAULT_MAX_EACH_POST: usize = 1_000_000;

/// `sc_max_each_post_bytes`: a number or an `"N"` / `"N-M"` range, of which
/// the server uses the upper bound (Xray hub.go, `.To`).
fn parse_max_each_post(at: &str, raw: Option<&Value>) -> anyhow::Result<usize> {
    let bad = |v: &Value| anyhow::anyhow!("{at}.transport.sc_max_each_post_bytes: bad value {v}");
    let upper = match raw {
        None | Some(Value::Null) => 0,
        Some(v @ Value::Number(n)) => n.as_u64().ok_or_else(|| bad(v))?,
        Some(v @ Value::String(text)) => {
            let text = text.trim();
            if text.is_empty() {
                0
            } else {
                let upper = text.rsplit('-').next().unwrap_or(text).trim();
                upper.parse::<u64>().map_err(|_| bad(v))?
            }
        }
        Some(v) => return Err(bad(v)),
    };
    Ok(match upper {
        0 => DEFAULT_MAX_EACH_POST,
        n => usize::try_from(n).unwrap_or(usize::MAX),
    })
}

/// A packet-up sequence number: decimal digits only, as Go's
/// `strconv.ParseUint(seq, 10, 64)` takes them (Xray hub.go).
fn parse_seq(raw: &str) -> Option<u64> {
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// One packet-up POST body and its place in the upload.
#[derive(Debug)]
struct Packet {
    seq: u64,
    payload: Vec<u8>,
}

/// Puts packet-up bodies back in sequence order, as Xray's `uploadQueue`
/// (splithttp/upload_queue.go) does.
#[derive(Debug)]
struct Reorder {
    next: u64,
    held: std::collections::BTreeMap<u64, Vec<u8>>,
    max: usize,
}

/// More than `max + 1` packets wait behind a missing seq (Xray's "packet
/// queue is too large"); ends the session.
#[derive(Debug, PartialEq, Eq)]
struct ReorderOverflow;

impl Reorder {
    fn new(max: usize) -> Self {
        Self {
            next: 0,
            held: std::collections::BTreeMap::new(),
            max,
        }
    }

    /// Take one packet. A sequence number already delivered or already held
    /// is a duplicate and is dropped, keeping the first copy (Xray drops a
    /// packet below `nextSeq`, upload_queue.go:84-118).
    ///
    /// Only the held count is limited, as in Xray (upload_queue.go:103-111):
    /// with `nextSeq` missing it pops the lowest packet and fails when
    /// `len(h.heap) > h.maxPackets` for the rest, so `maxPackets + 1` may
    /// wait and the `maxPackets + 2`-th ends the session. `waiting` counts
    /// all of them, the popped one included, hence `> max + 1` here. Any seq
    /// is held, however far ahead.
    fn insert(&mut self, packet: Packet) -> Result<(), ReorderOverflow> {
        if packet.seq < self.next {
            return Ok(());
        }
        if let std::collections::btree_map::Entry::Vacant(slot) = self.held.entry(packet.seq) {
            slot.insert(packet.payload);
        }
        if self.waiting() > self.max + 1 {
            return Err(ReorderOverflow);
        }
        Ok(())
    }

    /// Packets held behind a missing seq.
    fn waiting(&self) -> usize {
        self.held.len() - usize::from(self.held.contains_key(&self.next))
    }

    /// The next body in order, once it is here.
    fn pop_ready(&mut self) -> Option<Vec<u8>> {
        let payload = self.held.remove(&self.next)?;
        self.next = self.next.wrapping_add(1);
        Some(payload)
    }
}

/// Where the reorder buffer stands, for the logs of the upload side.
#[derive(Debug, Default)]
struct OrderStats {
    next: std::sync::atomic::AtomicU64,
    held: std::sync::atomic::AtomicUsize,
}

/// What the upload side of a session hands its bridge: streamed chunks
/// (stream-up, stream-one) and sequenced packets (packet-up).
struct Uplink {
    stream: mpsc::Receiver<Vec<u8>>,
    packets: mpsc::Receiver<Packet>,
    max_buffered: usize,
    stats: Arc<OrderStats>,
    /// Set when the session is cancelled or failed: the bridge stops.
    aborted: tokio::sync::watch::Receiver<bool>,
}

/// One XHTTP session. It outlives the connections that carry it -- that is
/// the whole point of the transport: the download is one connection, each
/// upload packet is a request on another, and the protocol above sees one
/// byte stream.
#[derive(Debug)]
struct XhttpSession {
    /// `None` once the session is over: that is what ends the protocol's read
    /// side, and what an upload has to find before it attaches.
    up: Mutex<Option<mpsc::Sender<Vec<u8>>>>,
    /// Packet-up bodies, to be put in order by the bridge. Bounded by
    /// `sc_max_buffered_posts` like Xray's `pushedPackets` channel: when it
    /// is full an upload waits, and its POST is not answered yet.
    packets: Mutex<Option<mpsc::Sender<Packet>>>,
    /// One per packet-up POST between reading its body and queueing it:
    /// `sc_max_buffered_posts` (W) of them. A POST waits for one before its
    /// body is read; closed when the session ends.
    ///
    /// Bounds per session: at most W permit holders and W POSTs waiting for
    /// a permit (`waiters`); one more is an explicit error that ends the
    /// session. Data: W queued, W bodies of permit holders, at most W + 1
    /// held out of order and one in the bridge -- about (3W + 2) x
    /// `sc_max_each_post_bytes` -- plus the 64 KiB pipe.
    permits: tokio::sync::Semaphore,
    /// Slots for POSTs waiting for a permit, W of them, taken without waiting.
    waiters: tokio::sync::Semaphore,
    /// W, for the logs.
    max_buffered: usize,
    stats: Arc<OrderStats>,
    /// Set once the session is over, so an upload waiting for room stops.
    ended: tokio::sync::watch::Sender<bool>,
    /// Set when the session is cancelled or failed: the bridge and the
    /// download stop at once.
    aborted: tokio::sync::watch::Sender<bool>,
    /// Set when the packet order could not be restored.
    overflowed: AtomicBool,
    /// handed to the download (or stream-one) connection when it takes the
    /// session; a second one finds it already taken.
    down: Mutex<Option<mpsc::Receiver<Vec<u8>>>>,
    /// Set when the download went away before the session ended it: the
    /// client cancelled its GET or its connection died. Nothing can reach
    /// the client any more, so the protocol's reads and writes fail instead
    /// of seeing a half-close.
    cancelled: AtomicBool,
}

impl XhttpSession {
    /// The session plus the two ends: the receiver for [`XhttpStream`]'s read
    /// half, the sender for its write half.
    fn new(max_buffered: usize) -> (Arc<Self>, Uplink, mpsc::Sender<Vec<u8>>) {
        let (up_tx, up_rx) = mpsc::channel(XHTTP_QUEUE);
        let (packet_tx, packet_rx) = mpsc::channel(max_buffered.max(1));
        let (down_tx, down_rx) = mpsc::channel(XHTTP_QUEUE);
        let stats = Arc::new(OrderStats::default());
        let aborted = tokio::sync::watch::Sender::new(false);
        let aborted_rx = aborted.subscribe();
        (
            Arc::new(Self {
                up: Mutex::new(Some(up_tx)),
                packets: Mutex::new(Some(packet_tx)),
                permits: tokio::sync::Semaphore::new(max_buffered.max(1)),
                waiters: tokio::sync::Semaphore::new(max_buffered.max(1)),
                max_buffered,
                stats: Arc::clone(&stats),
                ended: tokio::sync::watch::Sender::new(false),
                aborted,
                overflowed: AtomicBool::new(false),
                down: Mutex::new(Some(down_rx)),
                cancelled: AtomicBool::new(false),
            }),
            Uplink {
                stream: up_rx,
                packets: packet_rx,
                max_buffered,
                stats,
                aborted: aborted_rx,
            },
            down_tx,
        )
    }

    /// The right to read one packet-up body and queue it. Waits while W
    /// POSTs hold one, as one of at most W waiting; one more POST ends the
    /// session with an error. Fails once the session is over.
    async fn packet_permit(&self, seq: &str) -> io::Result<tokio::sync::SemaphorePermit<'_>> {
        use tokio::sync::TryAcquireError;
        let over = || io::Error::other("xhttp: the session is over");
        match self.permits.try_acquire() {
            Ok(permit) => return Ok(permit),
            Err(TryAcquireError::Closed) => return Err(over()),
            Err(TryAcquireError::NoPermits) => {}
        }
        let _slot = match self.waiters.try_acquire() {
            Ok(slot) => slot,
            Err(TryAcquireError::Closed) => return Err(over()),
            Err(TryAcquireError::NoPermits) => {
                crate::logging::warn(format_args!(
                    "xhttp: packet-up seq {seq}: {w} POSTs already wait for room: next {}, held {}, waiting {w}; ending the session",
                    self.stats.next.load(Ordering::Acquire),
                    self.stats.held.load(Ordering::Acquire),
                    w = self.max_buffered,
                ));
                self.fail();
                return Err(over());
            }
        };
        self.permits.acquire().await.map_err(|_| over())
    }

    /// One packet-up body towards the bridge. Waits only while the queue is
    /// full and fails once the session is over, as Xray's `uploadQueue.Push`
    /// (upload_queue.go:40-53).
    async fn push_packet(&self, packet: Packet) -> io::Result<()> {
        let over = || io::Error::other("xhttp: the session is over");
        let mut ended = self.ended.subscribe();
        let sender = self.packets.lock().expect("xhttp session poisoned").clone();
        let Some(tx) = sender else {
            return Err(over());
        };
        tokio::select! {
            sent = tx.send(packet) => sent.map_err(|_| over())?,
            _ = async {
                let _ = ended.wait_for(|ended| *ended).await;
            } => return Err(over()),
        }
        // Xray reports a queue closed meanwhile even after the send
        if *self.ended.borrow() {
            return Err(over());
        }
        Ok(())
    }

    /// One upload chunk towards the protocol. The lock is held only to clone
    /// the sender; the await must not sit on it.
    async fn push(&self, chunk: Vec<u8>) -> io::Result<()> {
        let sender = self.up.lock().expect("xhttp session poisoned").clone();
        match sender {
            Some(tx) => tx
                .send(chunk)
                .await
                .map_err(|_| io::Error::other("xhttp: the session is over")),
            None => Err(io::Error::other("xhttp: the session is over")),
        }
    }

    fn close_up(&self) {
        *self.up.lock().expect("xhttp session poisoned") = None;
        *self.packets.lock().expect("xhttp session poisoned") = None;
        self.permits.close();
        self.waiters.close();
        self.ended.send_replace(true);
    }

    /// Resolves once the session is cancelled or failed.
    async fn wait_aborted(&self) {
        let mut aborted = self.aborted.subscribe();
        let _ = aborted.wait_for(|aborted| *aborted).await;
    }

    /// The packet order cannot be restored: end the session as an error.
    fn fail(&self) {
        self.overflowed.store(true, Ordering::Release);
        self.cancel();
    }

    /// Why a cancelled session's reads and writes fail.
    fn abort_error(&self) -> io::Error {
        if self.overflowed.load(Ordering::Acquire) {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "xhttp: packet-up POSTs out of order beyond sc_max_buffered_posts",
            )
        } else {
            download_cancelled()
        }
    }

    /// The download is gone: end the session for the protocol as well.
    fn cancel(&self) {
        self.cancelled.store(true, Ordering::Release);
        self.close_up();
        self.aborted.send_replace(true);
    }

    fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::Acquire)
    }

    fn take_down(&self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.down.lock().expect("xhttp session poisoned").take()
    }
}

/// The byte stream the protocol sees. One in-memory pipe: the read half is
/// everything the upload connections delivered, the write half is handed to
/// the download connection through the bridge task.
struct XhttpStream {
    inner: tokio::io::DuplexStream,
    /// the table entry to drop when this ends. `None` for a session nothing
    /// can attach to (stream-one), which never enters the table.
    listed: Option<(SessionTable, String)>,
    session: Arc<XhttpSession>,
}

fn download_cancelled() -> io::Error {
    io::Error::new(
        io::ErrorKind::ConnectionAborted,
        "xhttp: the client cancelled the download",
    )
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = out.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, out))?;
        // EOF on a cancelled session is not the client's half-close
        if out.filled().len() == before && self.session.is_cancelled() {
            return Poll::Ready(Err(self.session.abort_error()));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.session.is_cancelled() {
            return Poll::Ready(Err(self.session.abort_error()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for XhttpStream {
    fn drop(&mut self) {
        if let Some((table, sid)) = &self.listed
            && let Ok(mut table) = table.lock()
        {
            table.remove(sid);
        }
    }
}

impl Transport {
    /// Serve one XHTTP connection. Three shapes arrive here: the download
    /// `GET` that takes the session, an upload `POST` that attaches to one
    /// (or births it, if the upload wins the race), and the single
    /// bidirectional `POST` of stream-one, whose session nothing attaches to.
    async fn xhttp_accept(&self, mut stream: AnyStream) -> anyhow::Result<AnyStream> {
        let (raw, pending) = read_head_split(&mut stream).await?;
        let (method, target, headers) = parse_head(&raw)?;

        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (target.as_str(), None),
        };
        let rest = match path.strip_prefix(self.path.as_str()) {
            Some(rest) if rest.is_empty() || rest.starts_with('/') => rest,
            _ => {
                return xhttp_reject(
                    stream,
                    format!(
                        "path {path:?} does not match the configured {:?}",
                        self.path
                    ),
                )
                .await;
            }
        };
        let trimmed = rest.trim_matches('/');
        let segments: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };
        let sid = self.session_id(&segments, query, &headers);
        let seq_raw = self.seq_value(&segments, query, &headers);
        let seq = seq_raw.is_some();

        match (&method[..], sid) {
            // the download stream: a GET with a session and no packet number.
            // A GET that carries a sequence is an upload sent with
            // `uplink_http_method: GET`, which falls through below.
            ("GET", Some(sid)) if !seq => self.xhttp_download(stream, sid).await,
            // a GET with no session is a request nothing serves
            ("GET", None) if segments.is_empty() => {
                xhttp_reject(stream, "a GET needs a session id".to_string()).await
            }
            // stream-one: the whole session on one POST to the bare path
            (_, None) if segments.is_empty() => {
                let (session, uplink, down_tx) = XhttpSession::new(self.max_buffered_posts);
                let protocol_end = xhttp_bridge(uplink, down_tx, Arc::downgrade(&session));
                tokio::spawn(xhttp_stream_one_task(
                    stream,
                    pending,
                    headers,
                    Arc::clone(&session),
                ));
                // never listed: a stream-one session lives on this one
                // connection and nothing can attach to it
                Ok(Box::new(XhttpStream {
                    inner: protocol_end,
                    listed: None,
                    session,
                }))
            }
            // an upload: attach to the session, or birth it when the client
            // sent its POST before its GET
            (_, Some(sid)) => {
                self.xhttp_upload(stream, pending, headers, sid, seq_raw)
                    .await
            }
            _ => xhttp_reject(stream, format!("no XHTTP session at {path:?}")).await,
        }
    }

    /// The session id and the sequence number a request names, when its path
    /// is under this listener's.
    fn request_ids(
        &self,
        target: &str,
        headers: &[(String, String)],
    ) -> Option<(String, Option<String>)> {
        let (path, query) = match target.split_once('?') {
            Some((path, query)) => (path, Some(query)),
            None => (target, None),
        };
        let rest = path
            .strip_prefix(self.path.as_str())
            .filter(|rest| rest.is_empty() || rest.starts_with('/'))?;
        let trimmed = rest.trim_matches('/');
        let segments: Vec<&str> = if trimmed.is_empty() {
            Vec::new()
        } else {
            trimmed.split('/').collect()
        };
        let sid = self.session_id(&segments, query, headers)?;
        Some((sid, self.seq_value(&segments, query, headers)))
    }

    /// The live session `sid`. A request on a reused upload connection can
    /// beat its session's download to the table, so wait for it briefly.
    async fn find_session(&self, sid: &str) -> Option<Arc<XhttpSession>> {
        let deadline = tokio::time::Instant::now() + REUSED_UPLOAD_WAIT;
        loop {
            if let Some(session) = self.sessions.lock().expect("xhttp table poisoned").get(sid) {
                return Some(Arc::clone(session));
            }
            if tokio::time::Instant::now() >= deadline {
                return None;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    }

    /// The session id, wherever this listener's placement says it lives.
    fn session_id(
        &self,
        segments: &[&str],
        query: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<String> {
        match self.session {
            Place::Path => segments.first().map(|id| id.to_string()),
            Place::Query => query.and_then(|q| lookup_param(q, &self.session_key)),
            Place::Header => lookup_header(headers, &self.session_key),
            Place::Cookie => lookup_cookie(headers, &self.session_key),
        }
    }

    /// The packet sequence number as the request carries it, unparsed.
    fn seq_value(
        &self,
        segments: &[&str],
        query: Option<&str>,
        headers: &[(String, String)],
    ) -> Option<String> {
        match self.seq {
            // session in the path: the sequence is the segment after it
            Place::Path => segments
                .get(if self.session == Place::Path { 1 } else { 0 })
                .map(|seq| seq.to_string()),
            Place::Query => query.and_then(|q| lookup_param(q, &self.seq_key)),
            Place::Header => lookup_header(headers, &self.seq_key),
            Place::Cookie => lookup_cookie(headers, &self.seq_key),
        }
    }

    /// The download `GET`: birth the session and hand its response side to
    /// this connection. A second GET for a session that already has one is
    /// refused by the task -- the first one owns the response body.
    async fn xhttp_download(&self, conn: AnyStream, sid: String) -> anyhow::Result<AnyStream> {
        let mut table = self.sessions.lock().expect("xhttp table poisoned");
        if let Some(existing) = table.get(&sid) {
            // the upload arrived first; the tunnel is already running on that
            // connection's stream and this one only feeds it down
            let session = Arc::clone(existing);
            drop(table);
            tokio::spawn(xhttp_download_task(conn, session));
            anyhow::bail!("xhttp: a download attached to session {sid:?}");
        }
        let (session, uplink, down_tx) = XhttpSession::new(self.max_buffered_posts);
        let bridge = xhttp_bridge(uplink, down_tx, Arc::downgrade(&session));
        table.insert(sid.clone(), Arc::clone(&session));
        drop(table);
        tokio::spawn(xhttp_download_task(conn, Arc::clone(&session)));
        Ok(Box::new(XhttpStream {
            inner: bridge,
            listed: Some((Arc::clone(&self.sessions), sid)),
            session,
        }))
    }

    /// An upload connection: the 200, the body into the session, the next
    /// request if the pooled connection carries one, and the end when it does
    /// not. An attach returns no stream -- the caller's task ends here and
    /// the bytes go to the session that returned a stream earlier.
    async fn xhttp_upload(
        &self,
        conn: AnyStream,
        pending: Vec<u8>,
        headers: Vec<(String, String)>,
        sid: String,
        seq: Option<String>,
    ) -> anyhow::Result<AnyStream> {
        let mut table = self.sessions.lock().expect("xhttp table poisoned");
        if let Some(existing) = table.get(&sid) {
            let session = Arc::clone(existing);
            drop(table);
            tokio::spawn(xhttp_upload_task(
                conn,
                pending,
                headers,
                seq,
                session,
                self.clone(),
            ));
            // the tunnel lives on the connection that returned the stream;
            // this one only carries bytes into it
            anyhow::bail!("xhttp: an upload attached to session {sid:?}");
        }
        let (session, uplink, down_tx) = XhttpSession::new(self.max_buffered_posts);
        let bridge = xhttp_bridge(uplink, down_tx, Arc::downgrade(&session));
        table.insert(sid.clone(), Arc::clone(&session));
        drop(table);
        tokio::spawn(xhttp_upload_task(
            conn,
            pending,
            headers,
            seq,
            Arc::clone(&session),
            self.clone(),
        ));
        Ok(Box::new(XhttpStream {
            inner: bridge,
            listed: Some((Arc::clone(&self.sessions), sid)),
            session,
        }))
    }
}

/// The in-memory pipe one session runs on: enough for a few writes in each
/// direction without waiting for the far end of the room.
const XHTTP_PIPE: usize = 64 * 1024;

/// The session's moving parts: one end of a pipe for the protocol, and two
/// tasks -- this bridge between the pipe and the session channels, and the
/// connection task that was spawned with it.
fn xhttp_bridge(
    uplink: Uplink,
    down_tx: mpsc::Sender<Vec<u8>>,
    session: std::sync::Weak<XhttpSession>,
) -> tokio::io::DuplexStream {
    let (protocol_end, bridge_end) = tokio::io::duplex(XHTTP_PIPE);
    let mut aborted = uplink.aborted.clone();
    tokio::spawn(async move {
        let (mut rd, mut wr) = tokio::io::split(bridge_end);
        let up = async {
            let Uplink {
                mut stream,
                mut packets,
                max_buffered,
                stats,
                aborted: _,
            } = uplink;
            let mut order = Reorder::new(max_buffered);
            let (mut stream_open, mut packets_open) = (true, true);
            while stream_open || packets_open {
                tokio::select! {
                    chunk = stream.recv(), if stream_open => match chunk {
                        Some(chunk) => {
                            if wr.write_all(&chunk).await.is_err() {
                                break;
                            }
                        }
                        None => stream_open = false,
                    },
                    packet = packets.recv(), if packets_open => match packet {
                        Some(packet) => {
                            let seq = packet.seq;
                            let inserted = order.insert(packet);
                            stats.held.store(order.waiting(), Ordering::Release);
                            if inserted.is_err() {
                                crate::logging::warn(format_args!(
                                    "xhttp: packet-up seq {seq} overflows the queue: next {}, held {}; ending the session",
                                    order.next,
                                    order.waiting(),
                                ));
                                if let Some(session) = session.upgrade() {
                                    session.fail();
                                }
                                return;
                            }
                            // a full pipe stops this loop, which fills the
                            // packet queue and holds the next POSTs
                            while let Some(payload) = order.pop_ready() {
                                stats.next.store(order.next, Ordering::Release);
                                stats.held.store(order.waiting(), Ordering::Release);
                                if wr.write_all(&payload).await.is_err() {
                                    return;
                                }
                            }
                        }
                        None => packets_open = false,
                    },
                }
            }
            // no more uploads: half-close the half the protocol reads, which
            // is its EOF. The write half stays open for the download.
            let _ = wr.shutdown().await;
        };
        let down = async move {
            let mut buf = vec![0u8; 16 * 1024];
            loop {
                match rd.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => {
                        if down_tx.send(buf[..n].to_vec()).await.is_err() {
                            return;
                        }
                    }
                }
            }
        };
        // Either direction ending ends the bridge and drops the other half of
        // it: a closed download must stop the uploads feeding it, and a
        // closed upload side must end the download task's read.
        // A cancelled or failed session stops at once, releasing what it
        // holds; a session dropped without either ends with its pipe.
        let aborted = async move {
            if aborted.wait_for(|aborted| *aborted).await.is_err() {
                std::future::pending::<()>().await;
            }
        };
        tokio::select! {
            _ = up => {}
            _ = down => {}
            _ = aborted => {}
        }
    });
    protocol_end
}

/// The 404 a request nothing serves gets, so a scanner sees the status before
/// the connection ends.
async fn xhttp_reject(mut conn: AnyStream, reason: String) -> anyhow::Result<AnyStream> {
    let _ = conn
        .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
        .await;
    let _ = conn.flush().await;
    anyhow::bail!("xhttp: {reason}")
}

/// The download connection: the 200, then everything the protocol writes, in
/// order, until the session or the connection ends. The connection is also
/// read: a client that vanished sends nothing but a FIN, and writing is how a
/// server learns about that only when it happens to have data.
async fn xhttp_download_task(conn: AnyStream, session: Arc<XhttpSession>) {
    let Some(mut down) = session.take_down() else {
        // the session already has a download; the first one owns the response
        let mut conn = conn;
        let _ = conn
            .write_all(b"HTTP/1.1 409 Conflict\r\nContent-Length: 0\r\n\r\n")
            .await;
        let _ = conn.flush().await;
        return;
    };
    let (mut rd, mut wr) = tokio::io::split(conn);
    if wr.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() || wr.flush().await.is_err() {
        session.cancel();
        return;
    }
    // `true` when the client side ended the download rather than the session
    let cancelled = tokio::select! {
        cancelled = async {
            while let Some(chunk) = down.recv().await {
                if wr.write_all(&chunk).await.is_err() || wr.flush().await.is_err() {
                    return true;
                }
            }
            let _ = wr.shutdown().await;
            false
        } => cancelled,
        _ = async {
            // the client should send nothing on a download connection; what
            // it does send is stray, and the EOF at the end is the session's
            // lifeline ending
            let mut scratch = [0u8; 1];
            while let Ok(n) = rd.read(&mut scratch).await && n > 0 {}
        } => true,
        // the session failed on the upload side
        _ = session.wait_aborted() => true,
    };
    drop(down);
    if cancelled {
        session.cancel();
    } else {
        session.close_up();
    }
    let _ = wr.shutdown().await;
}

/// How long a request on a reused upload connection waits for the session it
/// names to appear.
const REUSED_UPLOAD_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// One upload connection's life: answer, deliver the body, answer the next
/// request, until the connection closes. A pooled packet-up connection ends
/// like this every time the reference closes it, which is not an error. A
/// pooled connection is shared by every session of the client, so each
/// request is delivered to the session it names, not the first one.
///
/// When an answer cannot be written (Xray's HTTP/1.1 client pipelines
/// packets and may reset the connection without reading them), the packets
/// whose requests are already complete in `pending` are still delivered,
/// unanswered; nothing more is read from the socket, and a packet that is
/// not complete there is dropped. A packet lost on the way leaves a gap the
/// session waits on until the client closes the GET, as Xray does
/// (hub.go:350-355, :392-398; upload_queue.go:72-82, :112-117).
async fn xhttp_upload_task(
    mut conn: AnyStream,
    mut pending: Vec<u8>,
    mut headers: Vec<(String, String)>,
    mut seq: Option<String>,
    mut session: Arc<XhttpSession>,
    transport: Transport,
) {
    // set once an answer could not be written: only `pending` is used after
    let mut dead = false;
    loop {
        let framing = match request_framing(&headers) {
            Ok(framing) => framing,
            Err(err) => {
                crate::logging::debug(format_args!("xhttp upload: {err}"));
                return;
            }
        };
        match seq.take() {
            // a streamed body cannot be complete in what is buffered
            None if dead => return,
            // stream-up
            None => {
                // The 200 first, before a byte of the body is read: a streamed
                // upload reads its response head while the body is still going
                // up, and an answer that waited for the body to end would
                // deadlock stream-up against itself.
                if conn
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                if conn.flush().await.is_err() {
                    return;
                }
                if let Err(err) =
                    pump_request_body(&mut conn, &mut pending, framing, &session).await
                {
                    crate::logging::debug(format_args!("xhttp upload: {err}"));
                    return;
                }
            }
            // packet-up: a permit, the whole body, queued by its seq, then
            // the answer (Xray hub.go answers after `uploadQueue.Push`). The
            // connection is not read while it waits for the permit.
            Some(raw) => {
                let Ok(_permit) = session.packet_permit(&raw).await else {
                    if !dead {
                        let _ = conn
                            .write_all(b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        let _ = conn.flush().await;
                    }
                    return;
                };
                let mut sink = BodySink::Packet {
                    body: Vec::new(),
                    limit: transport.max_each_post,
                    too_large: false,
                };
                // a dead connection reads nothing: a body not complete in
                // `pending` ends here, undelivered
                let pumped = if dead {
                    pump_body(&mut tokio::io::empty(), &mut pending, framing, &mut sink).await
                } else {
                    pump_body(&mut conn, &mut pending, framing, &mut sink).await
                };
                if let Err(err) = pumped {
                    if sink.too_large() && !dead {
                        let _ = conn
                            .write_all(b"HTTP/1.1 413 Payload Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                        let _ = conn.flush().await;
                    }
                    crate::logging::debug(format_args!("xhttp upload: {err}"));
                    return;
                }
                let answer: &[u8] = match packet_status(&session, &raw, sink.into_body()).await {
                    PacketStatus::Ok => b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
                    PacketStatus::Failed => {
                        b"HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n"
                    }
                };
                if !dead && (conn.write_all(answer).await.is_err() || conn.flush().await.is_err()) {
                    crate::logging::debug(format_args!(
                        "xhttp upload: the answer could not be written; delivering what is buffered"
                    ));
                    dead = true;
                }
            }
        }
        let next = if dead {
            Ok(take_buffered_request(&mut pending))
        } else {
            next_request(&mut conn, &mut pending).await
        };
        match next {
            Ok(Some(head)) => {
                let end = match head_end(&head) {
                    Some(end) => end,
                    None => return,
                };
                match parse_head(&head[..end]) {
                    Ok((_method, target, parsed)) => {
                        let ids = transport.request_ids(&target, &parsed);
                        let found = match &ids {
                            Some((sid, _)) => transport.find_session(sid).await,
                            None => None,
                        };
                        let Some(found) = found else {
                            crate::logging::debug(format_args!(
                                "xhttp upload: no session for {target:?}"
                            ));
                            if !dead {
                                let _ = conn
                                    .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                    .await;
                                let _ = conn.flush().await;
                            }
                            return;
                        };
                        session = found;
                        headers = parsed;
                        seq = ids.and_then(|(_, seq)| seq);
                    }
                    Err(err) => {
                        crate::logging::debug(format_args!("xhttp upload: {err}"));
                        return;
                    }
                }
            }
            // the pooled connection was closed: the normal end of an upload
            // connection, not a failure
            Ok(None) => return,
            Err(err) => {
                crate::logging::debug(format_args!("xhttp upload: {err}"));
                return;
            }
        }
    }
}

/// How a packet-up POST is answered.
#[derive(Debug, PartialEq, Eq)]
enum PacketStatus {
    Ok,
    /// 500, as Xray answers a seq it cannot parse and a push that failed.
    Failed,
}

/// Parse the seq and queue the body.
async fn packet_status(session: &XhttpSession, raw: &str, payload: Vec<u8>) -> PacketStatus {
    let Some(seq) = parse_seq(raw) else {
        crate::logging::debug(format_args!("xhttp upload: bad seq {raw:?}"));
        return PacketStatus::Failed;
    };
    match session.push_packet(Packet { seq, payload }).await {
        Ok(()) => PacketStatus::Ok,
        Err(err) => {
            crate::logging::debug(format_args!("xhttp upload: {err}"));
            PacketStatus::Failed
        }
    }
}

/// The stream-one connection: the 200 goes out before the body is read (the
/// response IS the download, so waiting for the upload to end first would
/// deadlock both halves against each other), then the body feeds the
/// protocol's read side while its writes go back down the response.
async fn xhttp_stream_one_task(
    conn: AnyStream,
    mut pending: Vec<u8>,
    headers: Vec<(String, String)>,
    session: Arc<XhttpSession>,
) {
    let framing = match request_framing(&headers) {
        Ok(framing) => framing,
        Err(err) => {
            crate::logging::debug(format_args!("xhttp stream-one: {err}"));
            return;
        }
    };
    let mut down = match session.take_down() {
        Some(down) => down,
        None => return,
    };
    let (mut rd, mut wr) = tokio::io::split(conn);
    if wr.write_all(b"HTTP/1.1 200 OK\r\n\r\n").await.is_err() {
        session.close_up();
        return;
    }
    if wr.flush().await.is_err() {
        session.close_up();
        return;
    }
    tokio::select! {
        _ = async {
            if let Err(err) = pump_request_body(&mut rd, &mut pending, framing, &session).await {
                crate::logging::debug(format_args!("xhttp stream-one: {err}"));
            }
            // the client is done sending: that is its half-close, and the
            // protocol above is what has to see it
            session.close_up();
        } => {}
        _ = async {
            while let Some(chunk) = down.recv().await {
                if wr.write_all(&chunk).await.is_err() {
                    break;
                }
                if wr.flush().await.is_err() {
                    break;
                }
            }
            let _ = wr.shutdown().await;
        } => {}
    }
    session.close_up();
    let _ = wr.shutdown().await;
}

/// The body of one request, delivered to the session as it arrives. Reads
/// stop exactly at the body's end: whatever came after it -- the next
/// request on a pooled connection -- stays in `pending` for
/// [`next_request`].
async fn pump_request_body<R: AsyncRead + Unpin>(
    conn: &mut R,
    pending: &mut Vec<u8>,
    state: ReqBody,
    session: &XhttpSession,
) -> io::Result<()> {
    pump_body(conn, pending, state, &mut BodySink::Session(session)).await
}

/// Where a request body goes: streamed into the session, or collected as
/// one packet-up body of at most `limit` bytes.
enum BodySink<'a> {
    Session(&'a XhttpSession),
    Packet {
        body: Vec<u8>,
        limit: usize,
        too_large: bool,
    },
}

impl BodySink<'_> {
    async fn take(&mut self, chunk: Vec<u8>) -> io::Result<()> {
        match self {
            BodySink::Session(session) => session.push(chunk).await,
            BodySink::Packet {
                body,
                limit,
                too_large,
            } => {
                if body.len() + chunk.len() > *limit {
                    *too_large = true;
                    return Err(io::Error::other(format!(
                        "xhttp: packet-up body over sc_max_each_post_bytes ({limit})"
                    )));
                }
                body.extend_from_slice(&chunk);
                Ok(())
            }
        }
    }

    fn too_large(&self) -> bool {
        matches!(
            self,
            BodySink::Packet {
                too_large: true,
                ..
            }
        )
    }

    fn into_body(self) -> Vec<u8> {
        match self {
            BodySink::Packet { body, .. } => body,
            BodySink::Session(_) => Vec::new(),
        }
    }
}

async fn pump_body<R: AsyncRead + Unpin>(
    conn: &mut R,
    pending: &mut Vec<u8>,
    mut state: ReqBody,
    sink: &mut BodySink<'_>,
) -> io::Result<()> {
    loop {
        match state {
            ReqBody::Done => return Ok(()),
            ReqBody::Length(0) => state = ReqBody::Done,
            ReqBody::Length(remaining) => {
                pull(conn, pending, 1).await?;
                let take = (remaining as usize).min(pending.len());
                let chunk: Vec<u8> = pending.drain(..take).collect();
                let remaining = remaining - take as u64;
                sink.take(chunk).await?;
                state = if remaining == 0 {
                    ReqBody::Done
                } else {
                    ReqBody::Length(remaining)
                };
            }
            ReqBody::ChunkSize => {
                let line = read_line(conn, pending).await?;
                let text = String::from_utf8_lossy(&line);
                let size = text.split(';').next().unwrap_or("").trim();
                let size = u64::from_str_radix(size, 16)
                    .map_err(|_| io::Error::other(format!("xhttp: bad chunk size {text:?}")))?;
                state = if size == 0 {
                    ReqBody::ChunkTrailer
                } else {
                    ReqBody::ChunkData(size)
                };
            }
            ReqBody::ChunkData(remaining) => {
                pull(conn, pending, 1).await?;
                let take = (remaining as usize).min(pending.len());
                let chunk: Vec<u8> = pending.drain(..take).collect();
                let remaining = remaining - take as u64;
                sink.take(chunk).await?;
                state = if remaining == 0 {
                    ReqBody::ChunkCrlf
                } else {
                    ReqBody::ChunkData(remaining)
                };
            }
            ReqBody::ChunkCrlf => {
                let line = read_line(conn, pending).await?;
                if !line.is_empty() {
                    return Err(io::Error::other("xhttp: junk between a chunk and its CRLF"));
                }
                state = ReqBody::ChunkSize;
            }
            ReqBody::ChunkTrailer => {
                // the trailer has to be consumed even though nobody reads it:
                // on a keep-alive connection it sits in front of the next
                // request
                loop {
                    let line = read_line(conn, pending).await?;
                    if line.is_empty() {
                        state = ReqBody::Done;
                        break;
                    }
                }
            }
        }
    }
}

/// How the request body is delimited on the way in: RFC 9112 §6, the three
/// framings, decided off the headers the way the reference's client writes
/// them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReqBody {
    Done,
    Length(u64),
    /// chunked: reading a size line
    ChunkSize,
    /// chunked: reading `n` more bytes of the current chunk
    ChunkData(u64),
    /// chunked: reading the CRLF that closes a chunk
    ChunkCrlf,
    /// chunked: past the zero chunk, reading the trailer fields
    ChunkTrailer,
}

fn request_framing(headers: &[(String, String)]) -> io::Result<ReqBody> {
    if let Some(te) = lookup_header(headers, "transfer-encoding")
        && te
            .to_ascii_lowercase()
            .split(',')
            .any(|token| token.trim() == "chunked")
    {
        return Ok(ReqBody::ChunkSize);
    }
    match lookup_header(headers, "content-length") {
        Some(cl) => {
            let n: u64 = cl
                .parse()
                .map_err(|_| io::Error::other(format!("xhttp: bad content-length {cl:?}")))?;
            Ok(if n == 0 {
                ReqBody::Done
            } else {
                ReqBody::Length(n)
            })
        }
        None => Ok(ReqBody::Done),
    }
}

/// Make sure `pending` holds at least `want` bytes, reading from the socket
/// for the rest. More than `want` may arrive -- the overread is the next
/// request's bytes and stays in `pending`.
async fn pull<R: AsyncRead + Unpin>(
    conn: &mut R,
    pending: &mut Vec<u8>,
    want: usize,
) -> io::Result<()> {
    let mut buf = [0u8; 8 * 1024];
    while pending.len() < want {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::other("xhttp: connection closed inside a body"));
        }
        pending.extend_from_slice(&buf[..n]);
    }
    Ok(())
}

/// One CRLF-delimited line, without the CRLF.
async fn read_line<R: AsyncRead + Unpin>(
    conn: &mut R,
    pending: &mut Vec<u8>,
) -> io::Result<Vec<u8>> {
    let mut buf = [0u8; 1];
    loop {
        if let Some(end) = pending.windows(2).position(|w| w == b"\r\n") {
            let line: Vec<u8> = pending.drain(..end).collect();
            let _ = pending.drain(..2);
            return Ok(line);
        }
        if pending.len() > MAX_HEAD {
            return Err(io::Error::other("xhttp: line too long"));
        }
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Err(io::Error::other("xhttp: connection closed inside a line"));
        }
        pending.push(buf[0]);
    }
}

/// The next request head if it is already complete in `pending`; nothing is
/// read.
fn take_buffered_request(pending: &mut Vec<u8>) -> Option<Vec<u8>> {
    let end = head_end(pending)?;
    let rest = pending.split_off(end);
    Some(std::mem::replace(pending, rest))
}

/// The next request head: from what the previous body left behind first, then
/// from the socket. `Ok(None)` is the clean close of a pooled connection.
async fn next_request(conn: &mut AnyStream, pending: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    let mut buf = [0u8; 1024];
    loop {
        if let Some(end) = head_end(pending) {
            let rest = pending.split_off(end);
            let head = std::mem::take(pending);
            *pending = rest;
            return Ok(Some(head));
        }
        if pending.len() > MAX_HEAD {
            return Err(io::Error::other("http: request head over {MAX_HEAD} bytes"));
        }
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            return Ok(None);
        }
        pending.extend_from_slice(&buf[..n]);
    }
}

/// Where the request head ends, blank line inclusive.
fn head_end(buf: &[u8]) -> Option<usize> {
    if let Some(end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        return Some(end + 4);
    }
    buf.windows(2).position(|w| w == b"\n\n").map(|end| end + 2)
}

/// A query parameter: `key=value`, raw, because the reference's own client
/// writes it without escaping.
fn lookup_param(query: &str, key: &str) -> Option<String> {
    query.split('&').find_map(|pair| {
        let (name, value) = pair.split_once('=')?;
        (name == key && !value.is_empty()).then(|| value.to_string())
    })
}

fn lookup_header(headers: &[(String, String)], key: &str) -> Option<String> {
    headers
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case(key))
        .and_then(|(_, value)| (!value.is_empty()).then(|| value.clone()))
}

/// One `name=value` inside a `cookie` header.
fn lookup_cookie(headers: &[(String, String)], key: &str) -> Option<String> {
    let cookie = lookup_header(headers, "cookie")?;
    cookie.split(';').find_map(|pair| {
        let pair = pair.trim();
        let (name, value) = pair.split_once('=')?;
        (name.trim() == key && !value.is_empty()).then(|| value.trim().to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ws_request(path: &str) -> String {
        format!(
            "GET {path} HTTP/1.1\r\n\
             Host: 127.0.0.1:18443\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Version: 13\r\n\r\n"
        )
    }

    #[test]
    fn a_request_head_is_split_into_method_target_and_headers() {
        let (method, target, headers) =
            parse_head(ws_request("/bench").as_bytes()).expect("parsed");
        assert_eq!(method, "GET");
        assert_eq!(target, "/bench");
        let find = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_str())
        };
        assert_eq!(find("upgrade"), Some("websocket"));
        assert_eq!(find("sec-websocket-key"), Some("dGhlIHNhbXBsZSBub25jZQ=="));
        assert_eq!(find("host"), Some("127.0.0.1:18443"));
    }

    #[test]
    fn the_path_has_to_match_the_configured_one() {
        assert!(path_matches("/bench", "/bench"));
        assert!(path_matches("/", "/"));
        assert!(!path_matches("/bench", "/"));
        assert!(!path_matches("/other", "/bench"));
        assert!(!path_matches("/bench/", "/bench"));
        // a query on either side has to agree
        assert!(path_matches("/bench?ed=2048", "/bench?ed=2048"));
        assert!(!path_matches("/bench?ed=2048", "/bench"));
        assert!(!path_matches("/bench", "/bench?ed=2048"));
    }

    #[test]
    fn a_listener_reads_its_transport_out_of_the_config() {
        let obj = serde_json::json!({"transport": {"type": "ws", "path": "/bench"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]").expect("read");
        let t = t.expect("present");
        assert_eq!(t.kind, Kind::Ws);
        assert_eq!(t.path, "/bench");

        // no transport at all is the plain-TCP case, not an error
        assert!(
            Transport::from_inbound(&serde_json::json!({}), "inbounds[0]")
                .expect("none")
                .is_none()
        );

        // grpc is served now, with its service name
        let obj = serde_json::json!({"transport": {"type": "grpc", "service_name": "bench"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]").expect("read");
        let t = t.expect("present");
        assert_eq!(t.kind, Kind::Grpc);
        assert_eq!(t.service, "bench");

        // xhttp is served now, on its default placements
        let obj = serde_json::json!({"transport": {"type": "xhttp", "path": "/bench"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]").expect("read");
        let t = t.expect("present");
        assert_eq!(t.kind, Kind::Xhttp);
        assert_eq!(t.path, "/bench");
        assert_eq!(t.session, Place::Path);
        assert_eq!(t.session_key, "x_session");
        assert_eq!(t.seq, Place::Path);
        assert_eq!(t.seq_key, "x_seq");

        // http is served now
        let obj = serde_json::json!({"transport": {"type": "http", "path": "/bench"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]").expect("read");
        let t = t.expect("present");
        assert_eq!(t.kind, Kind::Http);
        assert_eq!(t.path, "/bench");

        // the ones we cannot serve are refused, by name
        let ty = "quic";
        let obj = serde_json::json!({"transport": {"type": ty}});
        let err = Transport::from_inbound(&obj, "inbounds[0]")
            .expect_err("not implemented")
            .to_string();
        assert!(err.contains(ty), "{ty}: {err}");
        assert!(err.contains("not implemented yet"), "{ty}: {err}");

        // an xhttp value the reference does not have either refuses at startup
        let obj =
            serde_json::json!({"transport": {"type": "xhttp", "session_placement": "nowhere"}});
        assert!(
            Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("unsupported placement")
                .to_string()
                .contains("unsupported session placement")
        );
        // ...and so does an uplink payload this server cannot read
        let obj =
            serde_json::json!({"transport": {"type": "xhttp", "uplink_data_placement": "header"}});
        assert!(
            Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("body only")
                .to_string()
                .contains("uplink_data_placement")
        );

        // a path without a leading slash is a typo worth catching at startup
        let obj = serde_json::json!({"transport": {"type": "ws", "path": "bench"}});
        assert!(
            Transport::from_inbound(&obj, "inbounds[0]")
                .expect_err("no slash")
                .to_string()
                .contains("must start with a slash")
        );
    }

    /// The placement engine, the way the reference's client writes requests:
    /// the session id in the path (default), in a query parameter, in a
    /// header, in a cookie -- and the sequence number counted wherever its own
    /// placement says, which is how a `GET` is told apart from an upload.
    #[test]
    fn xhttp_session_ids_follow_the_configured_placement() {
        let at = "inbounds[0]";
        let transport = |extra: serde_json::Value| {
            let mut obj = serde_json::json!({"transport": {"type": "xhttp", "path": "/bench"}});
            obj["transport"] = match extra {
                serde_json::Value::Object(map) => {
                    let mut base = serde_json::json!({"type": "xhttp", "path": "/bench"});
                    for (k, v) in map {
                        base[k] = v;
                    }
                    base
                }
                other => other,
            };
            Transport::from_inbound(&obj, at)
                .expect("read")
                .expect("present")
        };
        let no_headers: Vec<(String, String)> = Vec::new();
        let header = |name: &str, value: &str| vec![(name.to_string(), value.to_string())];

        // default: path placement, sid is the segment under the path
        let t = transport(serde_json::json!({}));
        assert_eq!(
            t.session_id(&["8f14e45f-ceea-467f-a1d6-1f6ef4b7f8f4"], None, &no_headers),
            Some("8f14e45f-ceea-467f-a1d6-1f6ef4b7f8f4".to_string())
        );
        assert_eq!(
            t.session_id(&["sid", "7"], None, &no_headers),
            Some("sid".to_string()),
            "the sequence segment does not eat the session id"
        );
        assert!(t.seq_value(&["sid", "7"], None, &no_headers).is_some());
        assert!(t.seq_value(&["sid"], None, &no_headers).is_none());
        assert_eq!(t.session_id(&[], None, &no_headers), None);

        // query placement: the session comes from its key, and with the
        // sequence in the path its segment is everything under the path --
        // there is no session segment to skip
        let t = transport(serde_json::json!({"session_placement": "query"}));
        assert_eq!(
            t.session_id(&[], Some("x_session=sid&x=1"), &no_headers),
            Some("sid".to_string())
        );
        assert_eq!(t.session_id(&[], Some("x_session="), &no_headers), None);
        assert!(
            t.seq_value(&[], Some("x_session=sid"), &no_headers)
                .is_none()
        );
        assert!(
            t.seq_value(&["3"], Some("x_session=sid"), &no_headers)
                .is_some()
        );

        // ...and a sequence in the query is found under its own key
        let t =
            transport(serde_json::json!({"session_placement": "query", "seq_placement": "query"}));
        assert!(
            t.seq_value(&[], Some("x_session=sid"), &no_headers)
                .is_none()
        );
        assert!(
            t.seq_value(&[], Some("x_session=sid&x_seq=3"), &no_headers)
                .is_some()
        );

        // header placement: the default key is the canonical X-Session
        let t = transport(
            serde_json::json!({"session_placement": "header", "seq_placement": "header"}),
        );
        assert_eq!(
            t.session_id(&[], None, &header("X-Session", "sid")),
            Some("sid".to_string())
        );
        assert_eq!(
            t.session_id(&[], None, &header("x-session", "sid")),
            Some("sid".to_string()),
            "header names are case-insensitive, as on the wire"
        );
        assert_eq!(t.session_id(&[], None, &no_headers), None);
        assert!(t.seq_value(&[], None, &header("X-Seq", "3")).is_some());

        // cookie placement, and a configured key beats the default one
        let t = transport(serde_json::json!({
            "session_placement": "cookie",
            "session_key": "tok"
        }));
        assert_eq!(
            t.session_id(&[], None, &header("cookie", "a=1; tok=sid; b=2")),
            Some("sid".to_string())
        );
        assert_eq!(t.session_id(&[], None, &header("cookie", "a=1")), None);
    }

    /// The body of a request comes in three framings, and the boundary has to
    /// be exact: what follows the body belongs to the next request on a
    /// pooled connection.
    #[tokio::test]
    async fn xhttp_request_bodies_stop_at_their_framing() {
        async fn read_body(raw: Vec<u8>, headers: Vec<(&str, &str)>) -> Vec<u8> {
            let headers: Vec<(String, String)> = headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect();
            let framing = request_framing(&headers).expect("framing");
            let (session, _uplink, _down_tx) = XhttpSession::new(DEFAULT_MAX_BUFFERED_POSTS);
            let mut pending = raw;
            let mut conn = std::io::Cursor::new(Vec::new());
            pump_request_body(&mut conn, &mut pending, framing, &session)
                .await
                .expect("pumped");
            // whatever was behind the body is still there, unparsed
            pending
        }

        // content-length stops after n bytes and leaves the rest alone
        assert_eq!(
            read_body(
                b"helloHTTP/1.1 102 Continue\r\n\r\n".to_vec(),
                vec![("content-length", "5")],
            )
            .await,
            b"HTTP/1.1 102 Continue\r\n\r\n"
        );

        // chunked: chunks until the zero chunk, trailer included
        assert_eq!(
            read_body(
                b"5\r\nhello\r\n6\r\n world\r\n0\r\nx-t: 1\r\n\r\nNEXT".to_vec(),
                vec![("transfer-encoding", "chunked")],
            )
            .await,
            b"NEXT"
        );

        // no framing header is no body, not a body to the close
        assert_eq!(read_body(b"as-is".to_vec(), vec![]).await, b"as-is");
    }

    /// The reference's `grpcname` form table, verbatim: what the decoded
    /// `:path` has to be for each shape of `service_name`.
    #[test]
    fn grpc_service_paths_follow_the_reference_table() {
        for (service, path) in [
            ("TunService", "/TunService/Tun"),
            ("a/b", "/a/b/Tun"),
            ("/a/b/Tun", "/a/b/Tun"),
            ("/a/b/Stream", "/a/b/Stream"),
            ("/a b/Tun", "/a b/Tun"),
            ("/a/b/Tun|TunMulti", "/a/b/Tun"),
            ("/Tun", "//Tun"),
            ("", "//Tun"),
            ("/", "//"),
        ] {
            assert_eq!(grpc_service_path(service), path, "service {service:?}");
        }
    }

    #[test]
    fn a_grpc_request_is_checked_the_way_serve_http_checks_it() {
        assert_eq!(
            grpc_rejection("/bench/Tun", "POST", "application/grpc", "bench"),
            None
        );
        // the plain-form wire escapes the service segment; both spellings decode
        // to what the reference compares against
        assert_eq!(
            grpc_rejection("/a%2Fb/Tun", "POST", "application/grpc", "a/b"),
            None
        );
        assert_eq!(
            grpc_rejection("/a/b/Tun", "POST", "application/grpc", "a/b"),
            None
        );
        assert_eq!(
            grpc_rejection("//Tun", "POST", "application/grpc", ""),
            None
        );
        // content type is a prefix check, as in Go
        assert_eq!(
            grpc_rejection("/bench/Tun", "POST", "application/grpc+proto", "bench"),
            None
        );

        assert!(
            grpc_rejection("/other/Tun", "POST", "application/grpc", "bench").is_some(),
            "wrong path must be refused"
        );
        assert!(
            grpc_rejection("/bench/Tun", "GET", "application/grpc", "bench").is_some(),
            "GET must be refused"
        );
        assert!(
            grpc_rejection("/bench/Tun", "POST", "text/plain", "bench").is_some(),
            "wrong content type must be refused"
        );
        // a broken escape is compared raw, like the reference's fallback
        assert_eq!(path_unescape("%zz"), None);
        assert_eq!(path_unescape("/a%2Fb").as_deref(), Some("/a/b"));
        assert_eq!(path_unescape("/plain").as_deref(), Some("/plain"));
    }

    #[tokio::test]
    async fn http_transport_h1_accept() {
        let obj = serde_json::json!({"transport": {"type": "http", "path": "/tunnel"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]")
            .expect("read")
            .expect("present");
        let (client, server) = tokio::io::duplex(1024);
        let accept_task = tokio::spawn(async move { t.accept(Box::new(server)).await });
        let mut client = client;
        client
            .write_all(b"PUT /tunnel HTTP/1.1\r\nHost: example.com\r\n\r\nhello")
            .await
            .unwrap();
        let mut resp = [0u8; 17];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(&resp, b"HTTP/1.1 200 OK\r\n");
        let accepted = accept_task.await.unwrap().unwrap();
        match accepted {
            Accepted::Once(mut s) => {
                let mut body = [0u8; 5];
                s.read_exact(&mut body).await.unwrap();
                assert_eq!(&body, b"hello");
            }
            _ => panic!("expected Accepted::Once"),
        }
    }

    #[tokio::test]
    async fn http_transport_h2_roundtrip() {
        let obj = serde_json::json!({"transport": {"type": "http", "path": "/tunnel"}});
        let t = Transport::from_inbound(&obj, "inbounds[0]")
            .expect("read")
            .expect("present");
        let (client, server) = tokio::io::duplex(1024);
        let accept_task = tokio::spawn(async move {
            let accepted = t.accept(Box::new(server)).await.unwrap();
            serve_sessions(accepted, |mut stream| async move {
                let mut buf = [0u8; 5];
                stream.read_exact(&mut buf).await.unwrap();
                assert_eq!(&buf, b"ping!");
                stream.write_all(b"pong!").await.unwrap();
                stream.flush().await.unwrap();
                stream.shutdown().await.unwrap();
            })
            .await
            .unwrap();
        });

        let (send_request, connection) = crate::outbound::transport::h2io::client_builder()
            .handshake(client)
            .await
            .unwrap();
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut send_request = send_request.ready().await.unwrap();
        let request = http::Request::builder()
            .method("PUT")
            .uri("https://example.com/tunnel")
            .body(())
            .unwrap();
        let (response, mut send) = send_request.send_request(request, false).unwrap();
        send.send_data(bytes::Bytes::from_static(b"ping!"), false)
            .unwrap();
        let resp = response.await.unwrap();
        assert_eq!(resp.status(), http::StatusCode::OK);
        let mut recv = resp.into_body();
        let chunk = recv.data().await.unwrap().unwrap();
        assert_eq!(&chunk[..], b"pong!");

        drop(send);
        drop(recv);
        drop(send_request);
        let _ = accept_task.await;
    }
    fn xhttp_transport() -> Transport {
        let obj = serde_json::json!({"transport": {"type": "xhttp", "path": "/bench"}});
        Transport::from_inbound(&obj, "inbounds[0]")
            .expect("read")
            .expect("present")
    }

    /// Open a download GET for `sid` and return the protocol's stream with
    /// the client end of the GET connection, past its response head.
    async fn xhttp_download_session(
        t: &Transport,
        sid: &str,
    ) -> (AnyStream, tokio::io::DuplexStream) {
        let (mut client, server) = tokio::io::duplex(1 << 16);
        client
            .write_all(format!("GET /bench/{sid} HTTP/1.1\r\nHost: x\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let stream = match t.accept(Box::new(server)).await.expect("accept") {
            Accepted::Once(stream) => stream,
            _ => panic!("expected Accepted::Once"),
        };
        let mut head = [0u8; 19];
        client.read_exact(&mut head).await.unwrap();
        assert_eq!(&head, b"HTTP/1.1 200 OK\r\n\r\n");
        (stream, client)
    }

    /// A client that cancels its download (closes the GET connection) ends
    /// the session: the protocol's read fails rather than looking like a
    /// half-close, so its relay stops instead of waiting on the upstream,
    /// and the session leaves the table.
    #[tokio::test]
    async fn a_cancelled_xhttp_download_fails_the_protocol_and_frees_the_session() {
        let t = xhttp_transport();
        let (mut stream, get) = xhttp_download_session(&t, "s1").await;
        assert_eq!(t.sessions.lock().unwrap().len(), 1);
        drop(get);
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("the protocol never heard of the cancel");
        let err = read.expect_err("a cancelled session is not a clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        assert!(stream.write_all(b"late").await.is_err());
        drop(stream);
        assert!(t.sessions.lock().unwrap().is_empty());
    }

    /// The download finishing on the session's own terms is not a cancel:
    /// the protocol shut its write side down, and its read side still works.
    #[tokio::test]
    async fn a_finished_xhttp_download_is_not_a_cancel() {
        let t = xhttp_transport();
        let (mut stream, mut get) = xhttp_download_session(&t, "s1").await;
        stream.write_all(b"bye").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut body = Vec::new();
        get.read_to_end(&mut body).await.unwrap();
        assert_eq!(body, b"bye");
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("read");
        assert_eq!(read.expect("a finished download is a clean EOF"), 0);
    }

    /// A pooled keep-alive upload connection carries packets of different
    /// sessions; each request goes to the session it names.
    #[tokio::test]
    async fn a_reused_upload_connection_feeds_the_session_each_request_names() {
        let t = xhttp_transport();
        let (mut a, _get_a) = xhttp_download_session(&t, "sa").await;
        let (mut b, _get_b) = xhttp_download_session(&t, "sb").await;
        let (mut up, server) = tokio::io::duplex(1 << 16);
        up.write_all(b"POST /bench/sa/0 HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\na0")
            .await
            .unwrap();
        // an upload that attaches hands out no stream of its own
        assert!(t.accept(Box::new(server)).await.is_err());
        let mut got = [0u8; 2];
        a.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"a0");
        up.write_all(b"POST /bench/sb/0 HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nb0")
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), b.read_exact(&mut got))
            .await
            .expect("the second session never got its packet")
            .unwrap();
        assert_eq!(&got, b"b0");
        // ...and none of it went to the first one
        let mut extra = [0u8; 2];
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(200), a.read(&mut extra))
                .await
                .is_err()
        );
    }

    // ---- packet-up order (Xray splithttp/upload_queue.go) ----

    fn packet(seq: u64, payload: &[u8]) -> Packet {
        Packet {
            seq,
            payload: payload.to_vec(),
        }
    }

    fn drain(order: &mut Reorder) -> Vec<u8> {
        let mut out = Vec::new();
        while let Some(payload) = order.pop_ready() {
            out.extend_from_slice(&payload);
        }
        out
    }

    #[test]
    fn reorder_delivers_by_seq() {
        let mut order = Reorder::new(30);
        order.insert(packet(2, b"c")).unwrap();
        assert_eq!(drain(&mut order), b"", "seq 0 is missing");
        order.insert(packet(1, b"b")).unwrap();
        assert_eq!(drain(&mut order), b"");
        order.insert(packet(0, b"a")).unwrap();
        assert_eq!(drain(&mut order), b"abc");
        // an empty body still takes its place
        order.insert(packet(4, b"e")).unwrap();
        order.insert(packet(3, b"")).unwrap();
        assert_eq!(drain(&mut order), b"e");
    }

    #[test]
    fn reorder_drops_duplicates_and_keeps_the_first_copy() {
        let mut order = Reorder::new(30);
        order.insert(packet(0, b"a")).unwrap();
        assert_eq!(drain(&mut order), b"a");
        // already delivered
        order.insert(packet(0, b"A")).unwrap();
        // held twice
        order.insert(packet(2, b"c")).unwrap();
        order.insert(packet(2, b"C")).unwrap();
        order.insert(packet(1, b"b")).unwrap();
        assert_eq!(drain(&mut order), b"bc");
        assert!(order.held.is_empty());
    }

    /// Xray's limit (upload_queue.go:103-111, `len(h.heap) > maxPackets`
    /// after popping one): `max + 1` may wait behind a gap, the
    /// `max + 2`-th fails, however far ahead the seqs are. A duplicate of a
    /// held seq does not count twice.
    #[test]
    fn reorder_fails_when_more_than_max_plus_one_wait() {
        let mut order = Reorder::new(2);
        for seq in [1, 50, u64::MAX, 50] {
            order.insert(packet(seq, b"x")).unwrap();
        }
        assert_eq!(order.waiting(), 3);
        assert_eq!(order.insert(packet(7, b"x")), Err(ReorderOverflow));
        // the next one in order is never counted as waiting
        let mut order = Reorder::new(2);
        for seq in [1, 2, 3, 0] {
            order.insert(packet(seq, b"x")).unwrap();
        }
        assert_eq!(drain(&mut order).len(), 4);
    }

    #[test]
    fn reorder_takes_the_largest_seq_without_overflowing() {
        let mut order = Reorder::new(30);
        order.next = u64::MAX - 1;
        order.insert(packet(u64::MAX, b"z")).unwrap();
        order.insert(packet(u64::MAX - 1, b"y")).unwrap();
        assert_eq!(drain(&mut order), b"yz");
        assert_eq!(order.next, 0);
    }

    #[test]
    fn a_seq_is_decimal_digits_as_parse_uint_takes_them() {
        assert_eq!(parse_seq("0"), Some(0));
        assert_eq!(parse_seq("007"), Some(7));
        assert_eq!(parse_seq("18446744073709551615"), Some(u64::MAX));
        for bad in ["", "-1", "+1", "1a", " 1", "18446744073709551616"] {
            assert_eq!(parse_seq(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn packet_buffer_settings_default_as_xray() {
        let t = xhttp_transport();
        assert_eq!(t.max_buffered_posts, 30);
        assert_eq!(t.max_each_post, 1_000_000);
        let t = xhttp_transport_with(
            serde_json::json!({"sc_max_buffered_posts": 0, "sc_max_each_post_bytes": "0"}),
        );
        assert_eq!((t.max_buffered_posts, t.max_each_post), (30, 1_000_000));
        let t = xhttp_transport_with(
            serde_json::json!({"sc_max_buffered_posts": 5, "sc_max_each_post_bytes": "1000-2000"}),
        );
        assert_eq!((t.max_buffered_posts, t.max_each_post), (5, 2000));
        let t = xhttp_transport_with(serde_json::json!({"sc_max_each_post_bytes": 4096}));
        assert_eq!(t.max_each_post, 4096);
        for bad in [
            serde_json::json!({"sc_max_buffered_posts": -1}),
            serde_json::json!({"sc_max_buffered_posts": "5"}),
            serde_json::json!({"sc_max_each_post_bytes": "lots"}),
        ] {
            let mut transport = serde_json::json!({"type": "xhttp", "path": "/bench"});
            for (k, v) in bad.as_object().unwrap() {
                transport[k] = v.clone();
            }
            let obj = serde_json::json!({ "transport": transport });
            assert!(
                Transport::from_inbound(&obj, "inbounds[0]").is_err(),
                "{bad}"
            );
        }
    }

    fn xhttp_transport_with(extra: serde_json::Value) -> Transport {
        let mut transport = serde_json::json!({"type": "xhttp", "path": "/bench"});
        for (k, v) in extra.as_object().expect("object") {
            transport[k] = v.clone();
        }
        let obj = serde_json::json!({ "transport": transport });
        Transport::from_inbound(&obj, "inbounds[0]")
            .expect("read")
            .expect("present")
    }

    const SHORT: std::time::Duration = std::time::Duration::from_millis(300);
    const LONG: std::time::Duration = std::time::Duration::from_secs(5);

    /// One HTTP/1.1 packet-up POST on a connection of its own, attached to a
    /// session that already has its download. The client end, for the answer.
    async fn h1_post(t: &Transport, sid: &str, seq: &str, body: &[u8]) -> tokio::io::DuplexStream {
        let (mut client, server) = tokio::io::duplex(1 << 20);
        let mut request = format!(
            "POST /bench/{sid}/{seq} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        client.write_all(&request).await.unwrap();
        // an upload that attaches hands out no stream of its own
        assert!(t.accept(Box::new(server)).await.is_err());
        client
    }

    /// The status of the answer on `client`, or `None` when none came in `wait`.
    async fn h1_status(
        client: &mut tokio::io::DuplexStream,
        wait: std::time::Duration,
    ) -> Option<u16> {
        let mut head = Vec::new();
        let got = tokio::time::timeout(wait, async {
            let mut byte = [0u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                match client.read(&mut byte).await {
                    Ok(1) => head.push(byte[0]),
                    _ => return false,
                }
            }
            true
        })
        .await;
        if !matches!(got, Ok(true)) {
            return None;
        }
        let text = String::from_utf8_lossy(&head);
        text.split(' ').nth(1).and_then(|code| code.parse().ok())
    }

    async fn read_some(stream: &mut AnyStream, n: usize) -> Vec<u8> {
        let mut buf = vec![0u8; n];
        tokio::time::timeout(LONG, stream.read_exact(&mut buf))
            .await
            .expect("the protocol got too little")
            .expect("read");
        buf
    }

    async fn nothing_to_read(stream: &mut AnyStream) -> bool {
        let mut buf = [0u8; 1];
        tokio::time::timeout(SHORT, stream.read(&mut buf))
            .await
            .is_err()
    }

    /// POSTs that arrive out of order reach the protocol in seq order; a
    /// missing seq holds the ones behind it (Xray waits for it as well), and
    /// every POST is answered once it is queued, before it is delivered.
    #[tokio::test]
    async fn h1_packet_up_posts_are_delivered_in_seq_order() {
        let t = xhttp_transport();
        let (mut stream, _get) = xhttp_download_session(&t, "s1").await;
        let mut c2 = h1_post(&t, "s1", "2", b"c").await;
        assert_eq!(h1_status(&mut c2, LONG).await, Some(200));
        let mut c1 = h1_post(&t, "s1", "1", b"b").await;
        assert_eq!(h1_status(&mut c1, LONG).await, Some(200));
        assert!(nothing_to_read(&mut stream).await, "seq 0 is still missing");
        let mut c0 = h1_post(&t, "s1", "0", b"a").await;
        assert_eq!(h1_status(&mut c0, LONG).await, Some(200));
        assert_eq!(read_some(&mut stream, 3).await, b"abc");
    }

    #[tokio::test]
    async fn h1_packet_up_duplicates_are_dropped() {
        let t = xhttp_transport();
        let (mut stream, _get) = xhttp_download_session(&t, "s1").await;
        for (seq, body) in [
            ("0", b"a"),
            ("0", b"A"),
            ("2", b"c"),
            ("2", b"C"),
            ("1", b"b"),
        ] {
            let mut c = h1_post(&t, "s1", seq, body).await;
            assert_eq!(h1_status(&mut c, LONG).await, Some(200), "seq {seq}");
        }
        assert_eq!(read_some(&mut stream, 3).await, b"abc");
        assert!(
            nothing_to_read(&mut stream).await,
            "a duplicate was delivered"
        );
    }

    /// A seq that is not a uint64 gets 500 (Xray: ParseUint failed) and
    /// leaves the session alone.
    #[tokio::test]
    async fn h1_packet_up_bad_seq_is_refused() {
        let t = xhttp_transport();
        let (mut stream, _get) = xhttp_download_session(&t, "s1").await;
        for seq in ["x", "-1", "18446744073709551616"] {
            let mut c = h1_post(&t, "s1", seq, b"junk").await;
            assert_eq!(h1_status(&mut c, LONG).await, Some(500), "seq {seq}");
        }
        let mut c = h1_post(&t, "s1", "0", b"ok").await;
        assert_eq!(h1_status(&mut c, LONG).await, Some(200));
        assert_eq!(read_some(&mut stream, 2).await, b"ok");
    }

    /// A body over `sc_max_each_post_bytes` gets 413, as in Xray.
    #[tokio::test]
    async fn h1_packet_up_body_over_the_limit_is_refused() {
        let t = xhttp_transport_with(serde_json::json!({"sc_max_each_post_bytes": 8}));
        let (mut stream, _get) = xhttp_download_session(&t, "s1").await;
        let mut c = h1_post(&t, "s1", "0", b"123456789").await;
        assert_eq!(h1_status(&mut c, LONG).await, Some(413));
        let mut c = h1_post(&t, "s1", "0", b"12345678").await;
        assert_eq!(h1_status(&mut c, LONG).await, Some(200));
        assert_eq!(read_some(&mut stream, 8).await, b"12345678");
    }

    const PACKET: usize = 16 * 1024;

    fn packet_body(i: usize) -> Vec<u8> {
        vec![i as u8; PACKET]
    }

    /// Send `n` packets, each on its own connection, without waiting.
    async fn h1_flood(t: &Transport, sid: &str, n: usize) -> Vec<tokio::io::DuplexStream> {
        let mut clients = Vec::new();
        for i in 0..n {
            clients.push(h1_post(t, sid, &i.to_string(), &packet_body(i)).await);
            tokio::task::yield_now().await;
        }
        clients
    }

    /// Which POSTs have their answer, by index; `None` when still held.
    async fn h1_answers(clients: &mut [tokio::io::DuplexStream]) -> Vec<Option<u16>> {
        let mut out = Vec::new();
        for client in clients.iter_mut() {
            out.push(h1_status(client, std::time::Duration::from_millis(50)).await);
        }
        out
    }

    /// More than `max + 1` packets behind a gap end the session with an
    /// explicit error (Xray's "packet queue is too large"), and that
    /// releases everything waiting: every POST is answered (200 if it was
    /// queued first, else 500), the protocol's read fails and the GET ends.
    #[tokio::test]
    async fn h1_packet_up_too_many_behind_a_gap_end_the_session_and_release_all() {
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 2}));
        let (mut stream, mut get) = xhttp_download_session(&t, "s1").await;
        let settle = std::time::Duration::from_millis(50);
        let mut clients = Vec::new();
        // 0..=3 fill the pipe and 4 is stuck in the bridge (next is 5); 5
        // never comes: 6 and 7 are queued, 8 and 9 hold the permits, 10 and
        // 11 wait for one
        for seq in [0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11] {
            clients.push((
                seq,
                h1_post(&t, "s1", &seq.to_string(), &packet_body(seq)).await,
            ));
            tokio::time::sleep(settle).await;
        }
        tokio::time::sleep(SHORT).await;
        for (seq, client) in clients.iter_mut() {
            let want = if *seq <= 7 { Some(200) } else { None };
            assert_eq!(
                h1_status(client, std::time::Duration::from_millis(50)).await,
                want,
                "POST {seq}"
            );
        }
        // reading lets the bridge take 6, 7, 8, 9...: the fourth behind the
        // gap ends the session
        let mut got = Vec::new();
        let err = tokio::time::timeout(LONG, async {
            let mut buf = vec![0u8; PACKET];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => panic!("an overflow is not a clean EOF"),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(err) => return err,
                }
            }
        })
        .await
        .expect("stalled: the protocol never heard of the error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let delivered: Vec<u8> = (0..=4).flat_map(packet_body).collect();
        assert_eq!(got, delivered, "only the packets in order before the gap");
        for (seq, client) in clients.iter_mut() {
            if *seq >= 8 {
                let status = h1_status(client, LONG).await;
                assert!(
                    matches!(status, Some(200 | 500)),
                    "POST {seq} was left waiting: {status:?}"
                );
            }
        }
        let mut rest = Vec::new();
        tokio::time::timeout(LONG, get.read_to_end(&mut rest))
            .await
            .expect("stalled: the GET outlived the session")
            .unwrap();
        drop(stream);
        assert!(t.sessions.lock().unwrap().is_empty());
    }

    /// A connection whose writes all fail and whose reads hand out the given
    /// chunks, one per read, then EOF; it counts the reads that returned data.
    struct DeadWrites {
        chunks: std::collections::VecDeque<Vec<u8>>,
        reads: Arc<std::sync::atomic::AtomicUsize>,
    }

    impl AsyncRead for DeadWrites {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            out: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            if let Some(mut chunk) = self.chunks.pop_front() {
                let n = chunk.len().min(out.remaining());
                out.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    self.chunks.push_front(chunk.split_off(n));
                }
                self.reads.fetch_add(1, Ordering::SeqCst);
            }
            Poll::Ready(Ok(()))
        }
    }

    impl AsyncWrite for DeadWrites {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Err(io::ErrorKind::ConnectionReset.into()))
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn small_post(seq: u64, body: &[u8]) -> Vec<u8> {
        let mut request = format!(
            "POST /bench/s1/{seq} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        request.extend_from_slice(body);
        request
    }

    /// Several POSTs arrive in one read and the first answer cannot be
    /// written: the complete ones already buffered are still delivered, in
    /// seq order; the incomplete one after them is not, and the socket is
    /// not read again.
    #[tokio::test]
    async fn h1_packet_up_buffered_posts_survive_a_failed_answer() {
        let t = xhttp_transport();
        let (mut stream, _get) = xhttp_download_session(&t, "s1").await;
        let mut first = Vec::new();
        for (seq, body) in [(1, &b"b"[..]), (0, b"a"), (3, b"d"), (2, b"c")] {
            first.extend_from_slice(&small_post(seq, body));
        }
        // seq 4 announces five bytes and only two are in this read
        let incomplete = small_post(4, b"eeeee");
        let cut = incomplete.len() - 3;
        first.extend_from_slice(&incomplete[..cut]);
        let mut rest = incomplete[cut..].to_vec();
        rest.extend_from_slice(&small_post(5, b"f"));
        assert!(first.len() <= 1024, "one read of the head buffer");
        let reads = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let conn = DeadWrites {
            chunks: [first, rest].into_iter().collect(),
            reads: Arc::clone(&reads),
        };
        // an upload that attaches hands out no stream of its own
        assert!(t.accept(Box::new(conn)).await.is_err());
        assert_eq!(read_some(&mut stream, 4).await, b"abcd");
        assert!(
            nothing_to_read(&mut stream).await,
            "an incomplete POST was delivered"
        );
        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "the dead connection was read again"
        );
    }

    /// Packets held behind a gap are released when the client closes the
    /// GET: the protocol's read ends as a cancel, nothing is delivered, the
    /// session leaves the table and a later POST finds none. Waiting POSTs
    /// are covered by `h1_packet_up_cancel_releases_waiting_posts`.
    #[tokio::test]
    async fn h1_packet_up_held_behind_a_gap_are_released_when_the_get_closes() {
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 2}));
        let (mut stream, get) = xhttp_download_session(&t, "s1").await;
        for seq in ["1", "2", "3"] {
            let mut c = h1_post(&t, "s1", seq, b"x").await;
            assert_eq!(h1_status(&mut c, LONG).await, Some(200), "seq {seq}");
        }
        assert!(nothing_to_read(&mut stream).await, "seq 0 is missing");
        drop(get);
        let mut buf = [0u8; 8];
        let err = tokio::time::timeout(LONG, stream.read(&mut buf))
            .await
            .expect("stalled: the GET closed and the protocol never heard")
            .expect_err("a cancelled session is not a clean EOF");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        drop(stream);
        assert!(t.sessions.lock().unwrap().is_empty());
    }

    /// With the consumer blocked: W POSTs queued, W holding permits, W
    /// waiting for one -- and one more ends the session with an explicit
    /// error. Every waiter gets 500, the GET ends, the protocol's read fails.
    #[tokio::test]
    async fn h1_packet_up_one_waiter_too_many_ends_the_session_and_releases_all() {
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 2}));
        let (mut stream, mut get) = xhttp_download_session(&t, "s1").await;
        let settle = std::time::Duration::from_millis(50);
        let mut clients = Vec::new();
        // 0..=3 fill the pipe, 4 is stuck in the bridge, 5 and 6 are queued,
        // 7 and 8 hold the permits, 9 and 10 wait for one
        for seq in 0..=10 {
            clients.push(h1_post(&t, "s1", &seq.to_string(), &packet_body(seq)).await);
            tokio::time::sleep(settle).await;
        }
        tokio::time::sleep(SHORT).await;
        let first = h1_answers(&mut clients).await;
        let want: Vec<Option<u16>> = (0..=10)
            .map(|seq| if seq <= 6 { Some(200) } else { None })
            .collect();
        assert_eq!(first, want);
        let mut over = h1_post(&t, "s1", "11", &packet_body(11)).await;
        assert_eq!(h1_status(&mut over, LONG).await, Some(500), "POST 11");
        for (seq, client) in clients.iter_mut().enumerate().skip(7) {
            assert_eq!(h1_status(client, LONG).await, Some(500), "POST {seq}");
        }
        let mut rest = Vec::new();
        tokio::time::timeout(LONG, get.read_to_end(&mut rest))
            .await
            .expect("stalled: the GET outlived the session")
            .unwrap();
        let mut got = Vec::new();
        let err = tokio::time::timeout(LONG, async {
            let mut buf = vec![0u8; PACKET];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => panic!("an overflow is not a clean EOF"),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(err) => return err,
                }
            }
        })
        .await
        .expect("stalled: the protocol never heard of the error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let piped: Vec<u8> = (0..=3).flat_map(packet_body).collect();
        assert_eq!(got, piped, "what was in the pipe, nothing more");
        drop(stream);
        assert!(t.sessions.lock().unwrap().is_empty());
    }

    /// Xray's HTTP/1.1 client pipelines POSTs on pooled connections and may
    /// reset one, which can lose packets for good; the session may then wait
    /// on that gap, as Xray's does, until the client closes the GET. This
    /// proves only that closing the GET releases the session -- it does not
    /// prove the absence of stalls. The timeouts only detect a hang.
    #[tokio::test]
    async fn h1_packet_up_a_reset_upload_connection_is_released_when_the_get_closes() {
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 2}));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, mut sessions) = mpsc::unbounded_channel::<AnyStream>();
        let server = t.clone();
        tokio::spawn(async move {
            while let Ok((conn, _)) = listener.accept().await {
                let t = server.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    if let Ok(Accepted::Once(stream)) = t.accept(Box::new(conn)).await {
                        let _ = tx.send(stream);
                    }
                });
            }
        });
        let post = |seq: u64| {
            let body = vec![seq as u8; 1024];
            let mut request = format!(
                "POST /bench/s1/{seq} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\n\r\n",
                body.len()
            )
            .into_bytes();
            request.extend_from_slice(&body);
            request
        };

        let mut get = tokio::net::TcpStream::connect(addr).await.unwrap();
        get.write_all(b"GET /bench/s1 HTTP/1.1\r\nHost: x\r\n\r\n")
            .await
            .unwrap();
        let mut head = [0u8; 19];
        get.read_exact(&mut head).await.unwrap();
        let mut stream = tokio::time::timeout(LONG, sessions.recv())
            .await
            .expect("no session")
            .expect("session");
        let original = Arc::clone(t.sessions.lock().unwrap().get("s1").expect("listed"));
        let reader = tokio::spawn(async move {
            let mut buf = vec![0u8; 4096];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => return None,
                    Ok(_) => {}
                    Err(err) => return Some(err.kind()),
                }
            }
        });

        // connection C: a far-ahead seq, then pipelined POSTs until the
        // socket takes no more, then RST
        let c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let _ = socket2::SockRef::from(&c).set_send_buffer_size(4096);
        c.writable().await.unwrap();
        for seq in 2..64 {
            let request = post(seq);
            match c.try_write(&request) {
                Ok(n) if n == request.len() => {}
                _ => break,
            }
        }
        socket2::SockRef::from(&c)
            .set_linger(Some(std::time::Duration::ZERO))
            .unwrap();
        drop(c);

        // connection D: the gap
        let mut d = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut gap = post(0);
        gap.extend_from_slice(&post(1));
        let _ = d.write_all(&gap).await;

        // the session may end on its own (complete, or an overflow), or wait
        // on a lost seq; then the client closes the GET
        tokio::time::sleep(SHORT).await;
        drop(get);
        let ended = tokio::time::timeout(LONG, reader)
            .await
            .expect("hung: closing the GET did not release the session")
            .unwrap();
        assert!(
            matches!(
                ended,
                Some(io::ErrorKind::InvalidData | io::ErrorKind::ConnectionAborted)
            ),
            "an explicit end, got {ended:?}"
        );
        // the stream was dropped with the reader task, before it resolved:
        // the session it listed is gone
        assert!(
            !t.sessions
                .lock()
                .unwrap()
                .values()
                .any(|session| Arc::ptr_eq(session, &original)),
            "the ended session is still listed"
        );
        // A POST that arrived after that births a new session of the same
        // id (upload before GET); its stream waits in `sessions`, and is
        // released with it.
        drop(sessions);
        tokio::time::timeout(LONG, async {
            while !t.sessions.lock().unwrap().is_empty() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("a session born of a late POST outlived its stream");
    }

    /// A protocol that does not read holds the uploads: POSTs past what the
    /// pipe and the packet queue keep are not answered, nothing is dropped,
    /// and once the protocol reads, everything arrives in order.
    #[tokio::test]
    async fn h1_packet_up_a_full_queue_holds_further_posts() {
        const N: usize = 16;
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 4}));
        let (mut stream, _get) = xhttp_download_session(&t, "s1").await;
        let mut clients = h1_flood(&t, "s1", N).await;
        tokio::time::sleep(SHORT).await;
        let first = h1_answers(&mut clients).await;
        let answered = first.iter().filter(|s| s.is_some()).count();
        assert!(first.iter().flatten().all(|&s| s == 200), "{first:?}");
        // the pipe (4 packets), the one being written and the queue (4)
        assert!(answered < N, "nothing held the uploads: {first:?}");
        assert!(
            answered <= 4 + 1 + 4,
            "more queued than the limit: {first:?}"
        );
        for i in 0..N {
            assert_eq!(
                read_some(&mut stream, PACKET).await,
                packet_body(i),
                "packet {i}"
            );
        }
        for (i, client) in clients.iter_mut().enumerate() {
            if first[i].is_none() {
                assert_eq!(h1_status(client, LONG).await, Some(200), "POST {i}");
            }
        }
    }

    /// The client cancelling its download releases the POSTs waiting for
    /// room (500, like Xray's Push on a closed queue), and the protocol's
    /// read fails as a cancel.
    #[tokio::test]
    async fn h1_packet_up_cancel_releases_waiting_posts() {
        const N: usize = 16;
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 4}));
        let (mut stream, get) = xhttp_download_session(&t, "s1").await;
        let mut clients = h1_flood(&t, "s1", N).await;
        tokio::time::sleep(SHORT).await;
        let first = h1_answers(&mut clients).await;
        assert!(
            first.iter().any(Option::is_none),
            "nothing waits: {first:?}"
        );
        drop(get);
        for (i, client) in clients.iter_mut().enumerate() {
            if first[i].is_none() {
                assert_eq!(h1_status(client, LONG).await, Some(500), "POST {i}");
            }
        }
        let err = tokio::time::timeout(LONG, async {
            let mut buf = vec![0u8; PACKET];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => panic!("a cancelled session is not a clean EOF"),
                    Ok(_) => continue,
                    Err(err) => return err,
                }
            }
        })
        .await
        .expect("the protocol never heard of the cancel");
        assert_eq!(err.kind(), io::ErrorKind::ConnectionAborted);
        drop(stream);
        assert!(t.sessions.lock().unwrap().is_empty());
    }

    /// Stream-up is not reordered: its 200 goes out before the body, and
    /// the body is streamed as it comes.
    #[tokio::test]
    async fn h1_stream_up_is_streamed_as_before() {
        let t = xhttp_transport();
        let (mut stream, _get) = xhttp_download_session(&t, "s1").await;
        let (mut up, server) = tokio::io::duplex(1 << 16);
        up.write_all(b"POST /bench/s1 HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        assert!(t.accept(Box::new(server)).await.is_err());
        assert_eq!(h1_status(&mut up, LONG).await, Some(200));
        up.write_all(b"5\r\nhello\r\n").await.unwrap();
        assert_eq!(read_some(&mut stream, 5).await, b"hello");
        up.write_all(b"6\r\n world\r\n").await.unwrap();
        assert_eq!(read_some(&mut stream, 6).await, b" world");
    }

    /// An HTTP/2 XHTTP connection: the client half, and the protocol
    /// streams of the sessions it opens.
    async fn h2_stand(
        t: Transport,
    ) -> (
        h2::client::SendRequest<Bytes>,
        mpsc::UnboundedReceiver<AnyStream>,
    ) {
        let (client, server) = tokio::io::duplex(1 << 20);
        let (tx, rx) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            let accepted = Accepted::xhttp_h2(Box::new(server), &t)
                .await
                .expect("h2 accept");
            let _ = serve_sessions(accepted, move |stream| {
                let tx = tx.clone();
                async move {
                    let _ = tx.send(stream);
                }
            })
            .await;
        });
        let (send_request, connection) = crate::outbound::transport::h2io::client_builder()
            .handshake::<_, Bytes>(client)
            .await
            .expect("h2 handshake");
        tokio::spawn(async move {
            let _ = connection.await;
        });
        (send_request, rx)
    }

    async fn h2_request(
        send: &mut h2::client::SendRequest<Bytes>,
        method: &str,
        path: &str,
        body: Option<Vec<u8>>,
    ) -> h2::client::ResponseFuture {
        let ready = send.clone().ready().await.expect("h2 ready");
        *send = ready;
        let request = http::Request::builder()
            .method(method)
            .uri(format!("https://x{path}"))
            .body(())
            .unwrap();
        let (response, mut stream) = send
            .send_request(request, body.is_none())
            .expect("send request");
        if let Some(body) = body {
            stream
                .send_data(Bytes::from(body), true)
                .expect("send body");
        }
        response
    }

    /// The download GET for `sid` and the protocol stream it opens. The GET's
    /// body is kept: dropping it would reset the stream, which is a cancel.
    async fn h2_open_session(
        send: &mut h2::client::SendRequest<Bytes>,
        sessions: &mut mpsc::UnboundedReceiver<AnyStream>,
        sid: &str,
    ) -> (AnyStream, h2::RecvStream) {
        let get = h2_request(send, "GET", &format!("/bench/{sid}"), None).await;
        let response = tokio::time::timeout(LONG, get)
            .await
            .expect("no answer to the GET")
            .expect("GET");
        assert_eq!(response.status(), http::StatusCode::OK);
        let stream = tokio::time::timeout(LONG, sessions.recv())
            .await
            .expect("no session")
            .expect("session");
        (stream, response.into_body())
    }

    async fn h2_status(
        response: &mut h2::client::ResponseFuture,
        wait: std::time::Duration,
    ) -> Option<u16> {
        match tokio::time::timeout(wait, response).await {
            Ok(Ok(response)) => Some(response.status().as_u16()),
            _ => None,
        }
    }

    #[tokio::test]
    async fn h2_packet_up_posts_are_delivered_in_seq_order() {
        let (mut send, mut sessions) = h2_stand(xhttp_transport()).await;
        let (mut stream, _get) = h2_open_session(&mut send, &mut sessions, "s1").await;
        for (seq, body) in [("2", b"c"), ("1", b"b"), ("1", b"B")] {
            let mut post = h2_request(
                &mut send,
                "POST",
                &format!("/bench/s1/{seq}"),
                Some(body.to_vec()),
            )
            .await;
            assert_eq!(h2_status(&mut post, LONG).await, Some(200), "seq {seq}");
        }
        assert!(nothing_to_read(&mut stream).await, "seq 0 is still missing");
        let mut bad = h2_request(&mut send, "POST", "/bench/s1/x", Some(b"junk".to_vec())).await;
        assert_eq!(h2_status(&mut bad, LONG).await, Some(500));
        let mut post = h2_request(&mut send, "POST", "/bench/s1/0", Some(b"a".to_vec())).await;
        assert_eq!(h2_status(&mut post, LONG).await, Some(200));
        assert_eq!(read_some(&mut stream, 3).await, b"abc");
        assert!(
            nothing_to_read(&mut stream).await,
            "a duplicate was delivered"
        );
    }

    /// The W = 1 capacity of an HTTP/2 session with its consumer blocked:
    /// the pipe (4), the bridge (1), the queue (1), one permit holder whose
    /// body is read and one waiter whose body stays in the client. Each POST
    /// goes out after the one before was taken: the permit is taken before
    /// the body is read, so a burst would count bodies still on the way.
    const H2_FULL: usize = 8;

    async fn h2_fill(
        send: &mut h2::client::SendRequest<Bytes>,
        n: usize,
    ) -> Vec<h2::client::ResponseFuture> {
        let mut posts = Vec::new();
        for i in 0..n {
            posts.push(
                h2_request(
                    send,
                    "POST",
                    &format!("/bench/s1/{i}"),
                    Some(packet_body(i)),
                )
                .await,
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        tokio::time::sleep(SHORT).await;
        posts
    }

    /// Over HTTP/2 a full queue holds the POST answers the same way, and
    /// reading lets them all through, in order.
    #[tokio::test]
    async fn h2_packet_up_a_full_queue_holds_further_posts() {
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 1}));
        let (mut send, mut sessions) = h2_stand(t).await;
        let (mut stream, _get) = h2_open_session(&mut send, &mut sessions, "s1").await;
        let mut posts = h2_fill(&mut send, H2_FULL).await;
        let mut first = Vec::new();
        for post in posts.iter_mut() {
            first.push(h2_status(post, std::time::Duration::from_millis(50)).await);
        }
        let want: Vec<Option<u16>> = (0..H2_FULL)
            .map(|i| if i <= 5 { Some(200) } else { None })
            .collect();
        assert_eq!(first, want, "the holder and the waiter are not answered");
        for i in 0..H2_FULL {
            assert_eq!(
                read_some(&mut stream, PACKET).await,
                packet_body(i),
                "packet {i}"
            );
        }
        for (i, post) in posts.iter_mut().enumerate() {
            if first[i].is_none() {
                assert_eq!(h2_status(post, LONG).await, Some(200), "POST {i}");
            }
        }
    }

    /// One POST past that capacity ends the session with an explicit error:
    /// it and the waiting ones get 500, the GET is reset, the protocol's
    /// read fails after what was in the pipe.
    #[tokio::test]
    async fn h2_packet_up_one_waiter_too_many_ends_the_session_and_releases_all() {
        let t = xhttp_transport_with(serde_json::json!({"sc_max_buffered_posts": 1}));
        let (mut send, mut sessions) = h2_stand(t.clone()).await;
        let (mut stream, mut get) = h2_open_session(&mut send, &mut sessions, "s1").await;
        let mut posts = h2_fill(&mut send, H2_FULL).await;
        let mut over = h2_request(
            &mut send,
            "POST",
            &format!("/bench/s1/{H2_FULL}"),
            Some(packet_body(H2_FULL)),
        )
        .await;
        assert_eq!(
            h2_status(&mut over, LONG).await,
            Some(500),
            "the POST too many"
        );
        for (i, post) in posts.iter_mut().enumerate().skip(6) {
            assert_eq!(h2_status(post, LONG).await, Some(500), "POST {i}");
        }
        tokio::time::timeout(LONG, async {
            while let Some(chunk) = get.data().await {
                if chunk.is_err() {
                    break;
                }
            }
        })
        .await
        .expect("stalled: the GET outlived the session");
        let mut got = Vec::new();
        let err = tokio::time::timeout(LONG, async {
            let mut buf = vec![0u8; PACKET];
            loop {
                match stream.read(&mut buf).await {
                    Ok(0) => panic!("an overflow is not a clean EOF"),
                    Ok(n) => got.extend_from_slice(&buf[..n]),
                    Err(err) => return err,
                }
            }
        })
        .await
        .expect("stalled: the protocol never heard of the error");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        let piped: Vec<u8> = (0..=3).flat_map(packet_body).collect();
        assert_eq!(got, piped, "what was in the pipe, nothing more");
        drop(stream);
        assert!(t.sessions.lock().unwrap().is_empty());
    }
}
