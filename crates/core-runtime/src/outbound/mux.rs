//! Mux.Cool multiplexing over a vmess stream (reference `sing-mux`).
//!
//! The session is a CONNECT request to the magic destination
//! `sp.mux.sing-box.arpa:444`, in front of which sits the protocol handshake
//! `[version][protocol]`, and each multiplexed stream is another CONNECT whose
//! body is the tunnel. A stream's own request `[flags][addr][port]` and the
//! one-byte response are handled transparently.
//!
//! Only `h2mux` (the reference default) is implemented; `smux` and `yamux` are
//! separate session formats and are refused rather than half-emulated.

use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

use crate::inbound::{AnyStream, Target};

/// `mux.Destination`
pub const MUX_DESTINATION: &str = "sp.mux.sing-box.arpa";
pub const MUX_PORT: u16 = 444;

const PROTOCOL_H2MUX: u8 = 2;
const PROTOCOL_SMUX: u8 = 0;
const PROTOCOL_YAMUX: u8 = 1;

const VERSION0: u8 = 0;

const STATUS_SUCCESS: u8 = 0;

/// `padConn` writes this many padded frames before going plain.
const FIRST_PADDINGS: u32 = 16;
const TCP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

#[derive(Debug, Clone, Default)]
pub struct MuxOptions {
    pub protocol: String,
    pub max_connections: usize,
    pub min_streams: usize,
    pub max_streams: usize,
    pub padding: bool,
}

impl MuxOptions {
    /// `option.MultiplexOptions`; the reference defaults `min_streams` to 8
    /// when neither stream nor connection count is bounded.
    pub fn parse(value: &serde_json::Value, at: &str) -> anyhow::Result<Self> {
        let Some(map) = value.as_object() else {
            anyhow::bail!("{at}: multiplex must be an object");
        };
        if map.get("enabled").and_then(serde_json::Value::as_bool) != Some(true) {
            return Ok(Self::default());
        }
        let protocol = map
            .get("protocol")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("")
            .to_string();
        if !matches!(protocol.as_str(), "" | "h2mux" | "smux" | "yamux") {
            anyhow::bail!("{at}: unknown protocol: {protocol}");
        }
        let number = |name: &str| -> usize {
            map.get(name)
                .and_then(serde_json::Value::as_u64)
                .unwrap_or(0) as usize
        };
        let max_connections = number("max_connections");
        let min_streams = number("min_streams");
        let max_streams = number("max_streams");
        let min_streams = if max_streams == 0 && max_connections == 0 && min_streams == 0 {
            8
        } else {
            min_streams
        };
        Ok(Self {
            protocol,
            max_connections,
            min_streams,
            max_streams,
            padding: map
                .get("padding")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
        })
    }

    fn protocol_id(&self) -> anyhow::Result<u8> {
        match self.protocol.as_str() {
            "" | "h2mux" => Ok(PROTOCOL_H2MUX),
            "smux" => Ok(PROTOCOL_SMUX),
            "yamux" => Ok(PROTOCOL_YAMUX),
            other => anyhow::bail!("unknown protocol: {other}"),
        }
    }
}

/// How a new session is dialled: the vmess outbound hands over a closure that
/// opens the underlying stream to the magic destination.
pub type Dialer = dyn Fn() -> std::pin::Pin<Box<dyn std::future::Future<Output = io::Result<AnyStream>> + Send>>
    + Send
    + Sync;

/// One multiplexed stream, seen by the router as a plain byte pipe.
pub struct MuxStream {
    inner: AnyStream,
    /// the stream request goes out with the first write
    request: Option<Vec<u8>>,
    /// the one-byte response is consumed on the first read
    response_pending: bool,
    eof: bool,
    client: Arc<Client>,
    session: Arc<Session>,
    /// keeps the shared connection task alive for as long as the stream is
    _conn_task: Arc<ConnectionTask>,
}

impl MuxStream {
    fn new(
        inner: AnyStream,
        request: Vec<u8>,
        client: Arc<Client>,
        session: Arc<Session>,
        conn_task: Arc<ConnectionTask>,
    ) -> Self {
        Self {
            inner,
            request: Some(request),
            response_pending: true,
            eof: false,
            client,
            session,
            _conn_task: conn_task,
        }
    }
}

impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        if this.response_pending {
            let mut status = [0u8; 1];
            let mut read = ReadBuf::new(&mut status);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                std::task::Poll::Pending => return std::task::Poll::Pending,
                std::task::Poll::Ready(Err(e)) => {
                    return std::task::Poll::Ready(Err(e));
                }
                std::task::Poll::Ready(Ok(())) => {
                    if read.filled().is_empty() {
                        this.eof = true;
                        return std::task::Poll::Ready(Ok(()));
                    }
                    if status[0] != STATUS_SUCCESS {
                        // the reference reads a varbin message here and
                        // only puts it in the error text
                        return std::task::Poll::Ready(Err(io::Error::other("mux: remote error")));
                    }
                    this.response_pending = false;
                }
            }
        }
        if this.eof {
            return std::task::Poll::Ready(Ok(()));
        }
        let before = out.filled().len();
        match std::pin::Pin::new(&mut this.inner).poll_read(cx, out) {
            std::task::Poll::Ready(Ok(())) => {
                // a zero-copy read: the h2 stream hands its bytes straight
                // into the caller's buffer, and an empty fill is the end
                if out.filled().len() == before {
                    this.eof = true;
                }
                std::task::Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

// Header progress belongs to the stream, payload progress to the caller.
// Continue after a header-only write: returning Ok(0) here would make
// write_all report WriteZero even though the underlying stream made progress.
fn poll_request_write<W: AsyncWrite + Unpin>(
    inner: &mut W,
    request: &mut Option<Vec<u8>>,
    cx: &mut std::task::Context<'_>,
    buf: &[u8],
) -> std::task::Poll<io::Result<usize>> {
    use std::task::Poll;
    if buf.is_empty() {
        return Poll::Ready(Ok(0));
    }
    while let Some(header) = request.take() {
        let header_len = header.len();
        let mut first = header;
        first.extend_from_slice(buf);
        match std::pin::Pin::new(&mut *inner).poll_write(cx, &first) {
            Poll::Ready(Ok(0)) => {
                first.truncate(header_len);
                *request = Some(first);
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            Poll::Ready(Ok(n)) if n <= header_len => {
                first.truncate(header_len);
                first.drain(..n);
                if !first.is_empty() {
                    *request = Some(first);
                }
            }
            Poll::Ready(Ok(n)) => return Poll::Ready(Ok(n - header_len)),
            Poll::Ready(Err(error)) => {
                first.truncate(header_len);
                *request = Some(first);
                return Poll::Ready(Err(error));
            }
            Poll::Pending => {
                first.truncate(header_len);
                *request = Some(first);
                return Poll::Pending;
            }
        }
    }
    std::pin::Pin::new(inner).poll_write(cx, buf)
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        poll_request_write(&mut this.inner, &mut this.request, cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Drop for MuxStream {
    fn drop(&mut self) {
        self.client.release(&self.session);
    }
}

/// One h2 session plus its live stream count.
struct Session {
    /// h2 needs `&mut` to open a stream, so the client handle is behind a lock
    send: Mutex<h2::client::SendRequest<Bytes>>,
    /// the task is shared by every stream of the session, so the last stream to
    /// go closes it
    conn_task: Arc<ConnectionTask>,
    streams: AtomicU32,
    closed: AtomicBool,
}

/// Aborts the h2 connection task when the last reference goes away.
struct ConnectionTask(Option<tokio::task::JoinHandle<()>>);

impl ConnectionTask {
    fn new(handle: tokio::task::JoinHandle<()>) -> Self {
        Self(Some(handle))
    }
}

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        if let Some(handle) = self.0.take() {
            handle.abort();
        }
    }
}

impl Session {
    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

/// `padConn`: the first [`FIRST_PADDINGS`] frames carry
/// `[data_len:u16][pad_len:u16][data][pad]`, then the stream goes plain.
pub(crate) struct PadStream {
    inner: AnyStream,
    write_padding: u32,
    read_padding: u32,
    /// bytes of the current frame's data still to hand out
    read_remaining: usize,
    /// padding bytes of the current frame still to skip
    padding_remaining: usize,
    read_header: [u8; 4],
    read_header_len: usize,
    write_frame: Vec<u8>,
    write_pos: usize,
    write_report: usize,
}

impl PadStream {
    pub(crate) fn new(inner: AnyStream) -> Self {
        Self {
            inner,
            write_padding: 0,
            read_padding: 0,
            read_remaining: 0,
            padding_remaining: 0,
            read_header: [0; 4],
            read_header_len: 0,
            write_frame: Vec::new(),
            write_pos: 0,
            write_report: 0,
        }
    }

    /// 256..=767 random bytes, like the reference.
    fn pad_len() -> usize {
        256 + random_below(512)
    }

    fn poll_drain(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<io::Result<()>> {
        while self.write_pos < self.write_frame.len() {
            let n = std::task::ready!(
                std::pin::Pin::new(&mut self.inner)
                    .poll_write(cx, &self.write_frame[self.write_pos..])
            )?;
            if n == 0 {
                return std::task::Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            self.write_pos += n;
        }
        self.write_frame.clear();
        self.write_pos = 0;
        std::task::Poll::Ready(Ok(()))
    }
}

impl AsyncRead for PadStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        if out.remaining() == 0 {
            return std::task::Poll::Ready(Ok(()));
        }
        loop {
            if this.read_remaining > 0 {
                let n = out.remaining().min(this.read_remaining);
                let mut read = ReadBuf::new(out.initialize_unfilled_to(n));
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(())) => {
                        let filled = read.filled().len();
                        if filled == 0 {
                            return std::task::Poll::Ready(
                                Err(io::ErrorKind::UnexpectedEof.into()),
                            );
                        }
                        out.advance(filled);
                        this.read_remaining -= filled;
                        return std::task::Poll::Ready(Ok(()));
                    }
                }
            }
            if this.padding_remaining > 0 {
                let mut scratch = [0u8; 4096];
                let mut read = ReadBuf::new(&mut scratch[..this.padding_remaining.min(4096)]);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(())) => {
                        let filled = read.filled().len();
                        if filled == 0 {
                            return std::task::Poll::Ready(
                                Err(io::ErrorKind::UnexpectedEof.into()),
                            );
                        }
                        this.padding_remaining -= filled;
                    }
                }
                continue;
            }
            if this.read_padding >= FIRST_PADDINGS {
                return std::pin::Pin::new(&mut this.inner).poll_read(cx, out);
            }
            while this.read_header_len < this.read_header.len() {
                let mut read = ReadBuf::new(&mut this.read_header[this.read_header_len..]);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read) {
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                    std::task::Poll::Ready(Err(e)) => return std::task::Poll::Ready(Err(e)),
                    std::task::Poll::Ready(Ok(())) => {
                        let filled = read.filled().len();
                        if filled == 0 && this.read_header_len > 0 {
                            return std::task::Poll::Ready(
                                Err(io::ErrorKind::UnexpectedEof.into()),
                            );
                        }
                        if filled == 0 {
                            return std::task::Poll::Ready(Ok(()));
                        }
                        this.read_header_len += filled;
                    }
                }
            }
            this.read_padding += 1;
            let header = this.read_header;
            this.read_header_len = 0;
            this.read_remaining = usize::from(u16::from_be_bytes([header[0], header[1]]));
            this.padding_remaining = usize::from(u16::from_be_bytes([header[2], header[3]]));
        }
    }
}

impl AsyncWrite for PadStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = &mut *self;
        std::task::ready!(this.poll_drain(cx))?;
        if this.write_report > 0 {
            return std::task::Poll::Ready(Ok(std::mem::take(&mut this.write_report)));
        }
        if buf.is_empty() {
            return std::task::Poll::Ready(Ok(0));
        }
        if this.write_padding >= FIRST_PADDINGS {
            return std::pin::Pin::new(&mut this.inner).poll_write(cx, buf);
        }
        let pad = Self::pad_len();
        let take = buf.len().min(u16::MAX as usize);
        this.write_frame
            .extend_from_slice(&(take as u16).to_be_bytes());
        this.write_frame
            .extend_from_slice(&(pad as u16).to_be_bytes());
        this.write_frame.extend_from_slice(&buf[..take]);
        this.write_frame.resize(4 + take + pad, 0);
        this.write_padding += 1;
        this.write_report = take;
        std::task::ready!(this.poll_drain(cx))?;
        std::task::Poll::Ready(Ok(std::mem::take(&mut this.write_report)))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::ready!(self.poll_drain(cx))?;
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::task::ready!(self.poll_drain(cx))?;
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// The multiplexed client: a session pool over the vmess stream.
pub struct Client {
    options: MuxOptions,
    /// dials the underlying stream, used to open a new session
    dialer: Mutex<Option<Arc<Dialer>>>,
    sessions: Mutex<Vec<Arc<Session>>>,
}

impl Client {
    pub fn new(options: MuxOptions) -> anyhow::Result<Arc<Self>> {
        options.protocol_id()?;
        Ok(Arc::new(Self {
            options,
            dialer: Mutex::new(None),
            sessions: Mutex::new(Vec::new()),
        }))
    }

    /// The vmess outbound hands over how to open the underlying stream.
    pub async fn set_dialer(&self, dialer: Arc<Dialer>) {
        *self.dialer.lock().await = Some(dialer);
    }

    pub async fn has_dialer(&self) -> bool {
        self.dialer.lock().await.is_some()
    }

    /// `Client.openStream`: pick a session, or open one.
    pub async fn open(self: &Arc<Self>, target: &Target) -> io::Result<MuxStream> {
        if self.options.protocol != "h2mux" && !self.options.protocol.is_empty() {
            return Err(io::Error::other(format!(
                "vmess: multiplex protocol {:?} is not supported",
                self.options.protocol
            )));
        }
        let mut guard = self.sessions.lock().await;
        guard.retain(|session| !session.is_closed());
        let picked = self.select_session(&guard);
        let session = match picked {
            Some(session) => session,
            None => self.open_session(&mut guard).await?,
        };
        let conn_task = Arc::clone(&session.conn_task);

        let request = http::Request::builder()
            .method("CONNECT")
            .uri(format!(
                "https://{}",
                crate::outbound::quic::dest_string(target)
            ))
            .header("version", VERSION0.to_string())
            .body(())
            .map_err(|e| io::Error::other(format!("vmess: mux request: {e}")))?;
        let (response, send) = session
            .send
            .lock()
            .await
            .send_request(request, false)
            .map_err(|e| io::Error::other(format!("vmess: mux send: {e}")))?;
        // Count only a successfully opened stream. Cancellation while waiting
        // for the sender lock must not leak the session's load counter.
        session.streams.fetch_add(1, Ordering::SeqCst);
        let stream: AnyStream = Box::new(crate::outbound::transport::h2io::H2Io {
            h2: crate::outbound::transport::h2io::H2Stream::shared(response, send),
        });
        Ok(MuxStream::new(
            stream,
            encode_stream_request(target),
            Arc::clone(self),
            session,
            conn_task,
        ))
    }

    /// `Client.selectSession`: the least-loaded session that can take a new
    /// request. Without bounds a busy session does not take a second stream --
    /// the reference only packs streams onto one session when
    /// `max_connections` (and then `min_streams`) says so, which is why the
    /// default opens one session per concurrent stream.
    fn select_session(&self, sessions: &[Arc<Session>]) -> Option<Arc<Session>> {
        let session = sessions
            .iter()
            .filter(|session| {
                // h2 reports the flow-control window; a closed one cannot take
                // more work
                !session.is_closed()
            })
            .min_by_key(|session| session.streams.load(Ordering::SeqCst))?;
        let streams = session.streams.load(Ordering::SeqCst);
        if streams == 0 {
            return Some(Arc::clone(session));
        }
        if self.options.max_connections > 0 {
            if sessions.len() >= self.options.max_connections
                || (streams as usize) < self.options.min_streams
            {
                return Some(Arc::clone(session));
            }
        } else if self.options.max_streams > 0 && (streams as usize) < self.options.max_streams {
            return Some(Arc::clone(session));
        }
        None
    }

    async fn open_session(&self, guard: &mut Vec<Arc<Session>>) -> io::Result<Arc<Session>> {
        let dialer = {
            let transport = self.dialer.lock().await;
            transport.clone()
        }
        .ok_or_else(|| io::Error::other("vmess: multiplex has no transport"))?;
        let stream = dialer().await?;
        let mut stream: AnyStream = stream;
        // the session handshake rides in front of the h2 preface
        let mut request = vec![u8::from(self.options.padding), PROTOCOL_H2MUX];
        if self.options.padding {
            request.push(1);
            let pad = 256 + random_below(512);
            request.extend_from_slice(&(pad as u16).to_be_bytes());
            request.resize(request.len() + pad, 0);
        }
        stream.write_all(&request).await?;
        // Padding wraps the session transport (including the H2 preface),
        // not each individual multiplexed stream.
        if self.options.padding {
            stream = Box::new(PadStream::new(stream));
        }

        let (send_request, connection) = tokio::time::timeout(
            TCP_TIMEOUT,
            crate::outbound::transport::h2io::client_builder().handshake(stream),
        )
        .await
        .map_err(|_| io::Error::other("vmess: mux h2 handshake timeout"))?
        .map_err(|e| io::Error::other(format!("vmess: mux h2 handshake: {e}")))?;
        let conn_task = Arc::new(ConnectionTask::new(tokio::spawn(async move {
            let _ = connection.await;
        })));
        let session = Arc::new(Session {
            send: Mutex::new(
                send_request
                    .ready()
                    .await
                    .map_err(|e| io::Error::other(format!("vmess: mux h2 ready: {e}")))?,
            ),
            conn_task,
            streams: AtomicU32::new(0),
            closed: AtomicBool::new(false),
        });
        guard.push(Arc::clone(&session));
        Ok(session)
    }

    fn release(&self, session: &Arc<Session>) {
        session.streams.fetch_sub(1, Ordering::SeqCst);
    }
}

/// `EncodeStreamRequest`: flags, then the destination. `ReadStreamRequest`
/// starts straight at the flags -- the version byte belongs to the session
/// handshake, not to a stream, and a TCP stream carries no flags at all.
fn encode_stream_request(target: &Target) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + 24);
    out.extend_from_slice(&0u16.to_be_bytes());
    put_sing_addr_port(&mut out, target);
    out
}

/// `M.SocksaddrSerializer.WriteAddrPort`: sing's own family bytes --
/// 0x01 ipv4, 0x04 ipv6, 0x03 fqdn -- address first, port last. The
/// vless-style codes in `packet::put_addr_port` (1/2/3) are a different
/// serializer and would make the server read the address from the wrong
/// offset.
fn put_sing_addr_port(out: &mut Vec<u8>, target: &Target) {
    match target {
        Target::Domain(host, port) => {
            out.push(0x03);
            out.push(host.len() as u8);
            out.extend_from_slice(host.as_bytes());
            out.extend_from_slice(&port.to_be_bytes());
        }
        Target::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
                out.extend_from_slice(&addr.port().to_be_bytes());
            }
        },
    }
}

fn random_below(limit: usize) -> usize {
    if limit <= 1 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    (u64::from_le_bytes(bytes) % limit as u64) as usize
}

/// The address the session is opened against.
pub fn mux_target() -> Target {
    let _ = MUX_PORT;
    Target::Domain(MUX_DESTINATION.to_string(), MUX_PORT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn padded_stream_survives_fragmented_headers_backpressure_and_large_writes() {
        use tokio::io::AsyncReadExt;
        for capacity in [3, 127] {
            let (left, right) = tokio::io::duplex(capacity);
            let writer = tokio::spawn(async move {
                let mut stream = PadStream::new(Box::new(left));
                assert_eq!(stream.write(&[]).await.unwrap(), 0);
                assert_eq!(stream.write_padding, 0);
                // Exercise u16 length splitting, then cross the boundary from
                // the sixteen padded frames to unframed bytes.
                stream.write_all(&vec![0x5a; 70_000]).await.unwrap();
                for _ in 0..20 {
                    stream.write_all(b"tail").await.unwrap();
                    stream.flush().await.unwrap();
                }
                stream.shutdown().await.unwrap();
            });
            let mut reader = PadStream::new(Box::new(right));
            let mut received = Vec::new();
            tokio::time::timeout(
                std::time::Duration::from_secs(10),
                reader.read_to_end(&mut received),
            )
            .await
            .unwrap()
            .unwrap();
            writer.await.unwrap();
            let mut expected = vec![0x5a; 70_000];
            expected.extend_from_slice(&b"tail".repeat(20));
            assert_eq!(received, expected);
        }
    }

    #[tokio::test]
    async fn padded_stream_rejects_truncated_header() {
        use tokio::io::AsyncReadExt;
        let (mut left, right) = tokio::io::duplex(8);
        left.write_all(&[0, 5]).await.unwrap();
        left.shutdown().await.unwrap();
        let mut stream = PadStream::new(Box::new(right));
        let mut byte = [0];
        assert_eq!(
            stream.read(&mut byte).await.unwrap_err().kind(),
            io::ErrorKind::UnexpectedEof
        );
    }

    struct ShortWriter {
        steps: std::collections::VecDeque<Option<usize>>,
        bytes: Vec<u8>,
    }
    impl AsyncWrite for ShortWriter {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            match self.steps.pop_front().unwrap_or(Some(buf.len())) {
                None => {
                    cx.waker().wake_by_ref();
                    std::task::Poll::Pending
                }
                Some(n) => {
                    let n = n.min(buf.len());
                    self.bytes.extend_from_slice(&buf[..n]);
                    std::task::Poll::Ready(Ok(n))
                }
            }
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn first_request_survives_short_header_payload_and_pending_writes() {
        for steps in [
            vec![Some(1), None, Some(3), Some(2)],
            vec![Some(4), None, Some(1)],
            vec![None, Some(6)],
        ] {
            let mut writer = ShortWriter {
                steps: steps.into(),
                bytes: vec![],
            };
            let mut header = Some(b"HEAD".to_vec());
            let mut payload = &b"payload"[..];
            while !payload.is_empty() {
                let n = std::future::poll_fn(|cx| {
                    poll_request_write(&mut writer, &mut header, cx, payload)
                })
                .await
                .unwrap();
                assert!(n > 0 && n <= payload.len());
                payload = &payload[n..];
            }
            assert_eq!(writer.bytes, b"HEADpayload");
            assert!(header.is_none());
        }
    }

    #[test]
    fn zero_write_is_an_error_and_empty_write_preserves_header() {
        let mut writer = ShortWriter {
            steps: [Some(0)].into(),
            bytes: vec![],
        };
        let mut header = Some(b"HEAD".to_vec());
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        assert!(matches!(
            poll_request_write(&mut writer, &mut header, &mut cx, b""),
            std::task::Poll::Ready(Ok(0))
        ));
        assert_eq!(header.as_deref(), Some(&b"HEAD"[..]));
        match poll_request_write(&mut writer, &mut header, &mut cx, b"payload") {
            std::task::Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::WriteZero),
            _ => panic!("zero write must be rejected"),
        }
        assert_eq!(header.as_deref(), Some(&b"HEAD"[..]));
    }

    #[test]
    fn options_default_to_eight_streams_per_session() {
        let options = MuxOptions::parse(&serde_json::json!({"enabled": true}), "at").expect("ok");
        assert_eq!(options.min_streams, 8);
        assert_eq!(options.protocol, "");
        assert!(!options.padding);
        assert_eq!(options.protocol_id().expect("h2mux"), PROTOCOL_H2MUX);
    }

    #[test]
    fn an_explicit_bound_replaces_the_default() {
        let options = MuxOptions::parse(
            &serde_json::json!({"enabled": true, "max_streams": 4}),
            "at",
        )
        .expect("ok");
        assert_eq!(options.max_streams, 4);
        assert_eq!(options.min_streams, 0);
    }

    #[test]
    fn disabled_multiplex_carries_nothing() {
        let options = MuxOptions::parse(&serde_json::json!({"enabled": false}), "at").expect("ok");
        assert_eq!(options.min_streams, 0);
        assert_eq!(options.max_connections, 0);
    }

    #[test]
    fn an_unknown_protocol_is_refused() {
        let err = MuxOptions::parse(
            &serde_json::json!({"enabled": true, "protocol": "mptcp"}),
            "at",
        )
        .map(|_| ())
        .expect_err("unknown protocol")
        .to_string();
        assert!(err.contains("unknown protocol: mptcp"), "got {err}");
        assert_eq!(
            MuxOptions::parse(
                &serde_json::json!({"enabled": true, "protocol": "smux"}),
                "at"
            )
            .expect("ok")
            .protocol_id()
            .expect("smux"),
            PROTOCOL_SMUX
        );
    }

    #[test]
    fn the_stream_request_names_the_destination() {
        let target = Target::Domain("example.com".into(), 443);
        let request = encode_stream_request(&target);
        assert_eq!(
            &request[0..2],
            &0u16.to_be_bytes(),
            "a tcp stream carries no flags"
        );
        assert_eq!(
            &request[2..4],
            &[0x03, 11],
            "sing's fqdn family byte and the length"
        );
        assert_eq!(&request[4..15], b"example.com");
        assert_eq!(&request[15..], &443u16.to_be_bytes());

        let target = Target::Ip("10.0.0.1:80".parse().unwrap());
        let request = encode_stream_request(&target);
        assert_eq!(&request[2..3], &[0x01], "sing's ipv4 family byte");
        assert_eq!(&request[3..7], &[10, 0, 0, 1]);
        assert_eq!(&request[7..], &80u16.to_be_bytes());
    }

    #[tokio::test]
    async fn smux_and_yamux_are_refused_rather_than_half_done() {
        let options = MuxOptions::parse(
            &serde_json::json!({"enabled": true, "protocol": "yamux"}),
            "at",
        )
        .expect("ok");
        let client = Client::new(options).expect("client");
        let err = match client
            .open(&Target::Domain("example.com".into(), 443))
            .await
        {
            Ok(_) => panic!("yamux is not implemented and must say so"),
            Err(error) => error.to_string(),
        };
        assert!(err.contains("not supported"), "got {err}");
    }
}
