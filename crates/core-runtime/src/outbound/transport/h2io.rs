//! Shared HTTP/2 client plumbing for the grpc and http transports:
//! handshake + connection task, response-status gate on first read,
//! flow-controlled writes, and receive-buffer management.

use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h2::RecvStream;
use h2::client::ResponseFuture;
use http::Response;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::task::JoinHandle;

/// Receive window per stream and per connection a server this side runs
/// advertises: 8 MiB a stream, 32 MiB a connection, sized to sustain 10+ Gbps
/// transfers without ballooning RSS across concurrent connections. The window
/// is also the memory ceiling for whatever a fast peer has in flight to a slow
/// reader.
const STREAM_WINDOW: u32 = 8 << 20;
const CONN_WINDOW: u32 = 32 << 20;
/// Largest DATA frame a server this side runs asks the peer to send.
const MAX_FRAME: u32 = 256 * 1024;

/// What a client's opening SETTINGS and connection WINDOW_UPDATE say, byte for
/// byte what Go's `x/net/http2` Transport sends, because the reference clients
/// are Go clients and this set is part of their HTTP/2 fingerprint:
/// `transportDefaultStreamFlow` 4 MiB per stream, `transportDefaultConnFlow`
/// 1 GiB a connection (the opening WINDOW_UPDATE is that minus the protocol's
/// own 65535), `MaxReadFrameSize` 16 KiB and `maxHeaderListSize` 10 MiB. Push
/// off, and nothing else: a HEADER_TABLE_SIZE or MAX_CONCURRENT_STREAMS
/// setting would be one entry more than Go sends.
///
/// The connection window is pure flow-control credit -- no buffer is sized
/// from it -- so what a peer can hold in our buffers stays bounded by the
/// per-stream window times the streams on the connection.
const GO_STREAM_WINDOW: u32 = 4 << 20;
const GO_CONN_WINDOW: u32 = 1 << 30;
const GO_MAX_FRAME: u32 = 16 << 10;
const GO_MAX_HEADER_LIST: u32 = 10 << 20;

/// The smallest window the protocol starts every connection with; a smaller
/// override would mean advertising a shrink, so it is the floor.
const MIN_WINDOW: u32 = 65_535;

/// `XRUST_H2_STREAM_WINDOW` / `XRUST_H2_CONN_WINDOW`, in bytes: the escape
/// hatch for a deployment that would rather have a tighter receive brake than
/// the Go windows (the old values here were 8 MiB and 32 MiB). Either one is
/// visible on the wire and takes the client's HTTP/2 fingerprint away from the
/// reference, so neither is set by default.
fn window_from_env(name: &str, fallback: u32) -> u32 {
    crate::env_var(name)
        .and_then(|v| v.trim().parse::<u32>().ok())
        .filter(|v| *v >= MIN_WINDOW)
        .unwrap_or(fallback)
}

fn client_stream_window() -> u32 {
    static WINDOW: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *WINDOW.get_or_init(|| window_from_env("H2_STREAM_WINDOW", GO_STREAM_WINDOW))
}

fn client_conn_window() -> u32 {
    static WINDOW: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *WINDOW.get_or_init(|| window_from_env("H2_CONN_WINDOW", GO_CONN_WINDOW))
}

/// Bound each owned upload allocation, including gRPC framing overhead.
/// Partial AsyncWrite writes preserve backpressure without retaining an
/// arbitrarily large caller buffer while an H2 stream has no send capacity.
/// 48 KiB also stays below musl's large-allocation threshold.
pub(super) const WRITE_CHUNK: usize = 48 * 1024;

/// The client handshake the h2-based transports share: the SETTINGS set Go
/// sends, the preface and window update in one write, a window update per
/// 4 KiB read, and the request pseudo-headers in Go's order -- what the
/// reference's HTTP/2 client (`x/net/http2`) does, which is what XHTTP, the
/// HTTP/2 transport and the h2 mux run on. The order the settings go on the
/// wire is by identifier, not by the calls below.
pub(crate) fn client_builder() -> h2::client::Builder {
    let mut builder = base_client_builder();
    builder.pseudo_header_order(h2::PseudoOrder::AuthorityMethodPathScheme);
    builder
}

/// The same, for the gRPC transport: grpc-go sends the pseudo-headers in its
/// own order (`createHeaderFields`), not `net/http`'s.
pub(crate) fn grpc_client_builder() -> h2::client::Builder {
    let mut builder = base_client_builder();
    builder.pseudo_header_order(h2::PseudoOrder::MethodSchemePathAuthority);
    builder
}

fn base_client_builder() -> h2::client::Builder {
    let mut builder = h2::client::Builder::new();
    builder
        .enable_push(false)
        .initial_window_size(client_stream_window())
        .initial_connection_window_size(client_conn_window())
        .max_frame_size(GO_MAX_FRAME)
        .max_header_list_size(GO_MAX_HEADER_LIST)
        .go_client_writes(true)
        .window_update_min_refresh(Some(4 << 10));
    builder
}

/// The server half, with the throughput windows above: a server this side runs
/// is not imitating anyone's client.
pub(crate) fn server_builder() -> h2::server::Builder {
    let mut builder = h2::server::Builder::new();
    builder
        .initial_window_size(STREAM_WINDOW)
        .initial_connection_window_size(CONN_WINDOW)
        .max_frame_size(MAX_FRAME);
    builder
}

/// One HTTP/2 request/response stream wrapped as raw byte pipes.
pub(crate) struct H2Stream {
    send: Option<h2::SendStream<Bytes>>,
    response: Option<Pin<Box<ResponseFuture>>>,
    recv: Option<RecvStream>,
    /// Received bytes not yet handed to the caller, chunk by chunk. A new
    /// h2 DATA chunk is pushed as it arrives: the receive path never joins
    /// chunks into one buffer, which used to allocate and copy both sides
    /// of the join whenever a frame header straddled two chunks -- on a
    /// bulk transfer that is a megabyte copied and freed per boundary.
    pub(crate) pending: VecDeque<Bytes>,
    /// Total bytes across `pending`; kept so the readers do not walk the
    /// deque for a length.
    pub(crate) pending_len: usize,
    /// Encoded bytes waiting on flow-control capacity.
    out: Bytes,
    /// the most a write stages at once, and so the largest DATA frame it makes
    write_chunk: usize,
    report: usize,
    eof: bool,
    /// `None` when a shared owner drives the connection, as mux does
    conn_task: Option<JoinHandle<()>>,
}

impl H2Stream {
    pub(crate) fn new(
        response: ResponseFuture,
        send: h2::SendStream<Bytes>,
        conn_task: JoinHandle<()>,
    ) -> Self {
        Self::build(response, send, Some(conn_task))
    }

    /// A stream that borrows a connection task owned by a session pool.
    /// Stage at most `chunk` bytes per write, so each DATA frame carries no
    /// more than that.
    pub(crate) fn with_write_chunk(mut self, chunk: usize) -> Self {
        self.write_chunk = chunk.clamp(1, WRITE_CHUNK);
        self
    }

    pub(crate) fn shared(response: ResponseFuture, send: h2::SendStream<Bytes>) -> Self {
        Self::build(response, send, None)
    }

    /// Write-only stream borrow for XHTTP `stream-up` over HTTP/2, where the
    /// response status and body are watched by a separate ack task.
    pub(crate) fn upload_only(send: h2::SendStream<Bytes>) -> Self {
        Self {
            send: Some(send),
            response: None,
            recv: None,
            pending: VecDeque::new(),
            pending_len: 0,
            out: Bytes::new(),
            write_chunk: WRITE_CHUNK,
            report: 0,
            eof: true,
            conn_task: None,
        }
    }

    /// The same, for a caller that has already read the head -- naive does, so
    /// that a refused CONNECT is reported as itself rather than as a stream that
    /// happens to be closed. The body is left live even if the head came with an
    /// end-of-stream flag: a CONNECT response that says so is the server's
    /// mistake, and treating it as EOF would drop a tunnel that is still open.
    pub(crate) fn from_response(
        response: Response<RecvStream>,
        send: h2::SendStream<Bytes>,
        conn_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            send: Some(send),
            response: None,
            recv: Some(response.into_body()),
            pending: VecDeque::new(),
            pending_len: 0,
            out: Bytes::new(),
            write_chunk: WRITE_CHUNK,
            report: 0,
            eof: false,
            conn_task,
        }
    }

    /// The server side of a stream: the request body arrived with the request
    /// and the response side is already open, so there is no response future to
    /// wait for -- the status gate in [`H2Stream::poll_recv_more`] never runs.
    /// There is no connection task to own either: the connection outlives the
    /// stream (a client that pools connections comes back for the next one), and
    /// the accept loop that hands these out is what drives it, so dropping a
    /// session must not take the connection down with it.
    pub(crate) fn server(recv: RecvStream, send: h2::SendStream<Bytes>) -> Self {
        Self::from_response(Response::new(recv), send, None)
    }

    fn build(
        response: ResponseFuture,
        send: h2::SendStream<Bytes>,
        conn_task: Option<JoinHandle<()>>,
    ) -> Self {
        Self {
            send: Some(send),
            response: Some(Box::pin(response)),
            recv: None,
            pending: VecDeque::new(),
            pending_len: 0,
            out: Bytes::new(),
            write_chunk: WRITE_CHUNK,
            report: 0,
            eof: false,
            conn_task,
        }
    }

    pub(crate) fn has_out(&self) -> bool {
        !self.out.is_empty()
    }

    /// Copy up to `max` pending bytes into `out` and return how many went.
    pub(crate) fn serve(&mut self, out: &mut ReadBuf<'_>, max: usize) -> usize {
        let mut left = out.remaining().min(max).min(self.pending_len);
        let want = left;
        while left > 0 {
            let Some(front) = self.pending.front_mut() else {
                break;
            };
            let take = front.len().min(left);
            out.put_slice(&front[..take]);
            front.advance(take);
            self.pending_len -= take;
            left -= take;
            if front.is_empty() {
                self.pending.pop_front();
            }
        }
        let went = want - left;
        self.release(went);
        went
    }

    /// Repay `n` bytes that left `pending`. The window is only repaid when
    /// bytes actually leave our buffer: advertising buffered-but-unread data
    /// tells the peer it may keep sending into a reader that stopped, and
    /// the connection half of the window is shared with the pooled session.
    pub(crate) fn release(&mut self, n: usize) {
        if n > 0
            && let Some(recv) = self.recv.as_mut()
        {
            let _ = recv.flow_control().release_capacity(n);
        }
    }

    /// Drop `n` pending bytes without copying them.
    pub(crate) fn skip_pending(&mut self, mut n: usize) {
        let start = n;
        while n > 0 {
            let Some(front) = self.pending.front_mut() else {
                break;
            };
            let take = front.len().min(n);
            front.advance(take);
            self.pending_len -= take;
            n -= take;
            if front.is_empty() {
                self.pending.pop_front();
            }
        }
        self.release(start - n);
    }

    /// Queue `frame` bytes for transmission; `report` is returned to the
    /// AsyncWrite caller once the whole frame has been accepted.
    ///
    /// The `Vec -> Bytes` here is the borrowed-to-owned boundary of
    /// `AsyncWrite`, not a join: `poll_write` receives `&[u8]` and the h2
    /// layer needs an owned `Bytes` for `SendStream`. Taking `Bytes` in
    /// this signature would save nothing (the caller would build the same
    /// `Bytes` at the same cost); removing the copy altogether needs an
    /// owned `send_bytes` path through the relay layer, which is a relay
    /// rewrite for about one percent of CPU. Keep this comment honest
    /// instead of "optimizing" the call site.
    pub(crate) fn stage(&mut self, frame: Vec<u8>, report: usize) {
        debug_assert!(!self.has_out());
        self.out = Bytes::from(frame);
        self.report = report;
    }

    pub(crate) fn stage_bytes(&mut self, frame: Bytes, report: usize) {
        debug_assert!(!self.has_out());
        self.out = frame;
        self.report = report;
    }

    pub(crate) fn take_report(&mut self) -> usize {
        std::mem::replace(&mut self.report, 0)
    }

    /// Flush staged bytes as flow control allows; clears `out` when done.
    pub(crate) fn poll_flush_out(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if self.out.is_empty() {
                return Poll::Ready(Ok(()));
            }
            let Some(send) = self.send.as_mut() else {
                return Poll::Ready(Err(io::Error::other("h2: stream send side closed")));
            };
            let remaining = self.out.len();
            send.reserve_capacity(remaining);
            // poll_capacity notifies about capacity *changes*, not every
            // write. Spend already assigned credit before waiting for more.
            let cap = if send.capacity() > 0 {
                send.capacity()
            } else {
                match send.poll_capacity(cx) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready(Some(Ok(cap))) => cap,
                    Poll::Ready(Some(Err(e))) => {
                        return Poll::Ready(Err(io::Error::other(format!("h2: capacity: {e}"))));
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(io::Error::other("h2: stream closed for writing")));
                    }
                }
            };
            if cap == 0 {
                continue;
            }
            let chunk = self.out.split_to(cap.min(remaining));
            send.send_data(chunk, false)
                .map_err(|e| io::Error::other(format!("h2: send_data: {e}")))?;
        }
    }

    /// Wait for the next received chunk into `pending`.
    /// `Ok(false)` means the response body ended (EOF latched).
    pub(crate) fn poll_recv_more(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        if self.recv.is_none() {
            let Some(response) = self.response.as_mut() else {
                // Response already consumed; recv stream exhausted.
                self.eof = true;
                return Poll::Ready(Ok(false));
            };
            let resp = match ready!(response.as_mut().poll(cx)) {
                Ok(resp) => resp,
                Err(e) => {
                    return Poll::Ready(Err(io::Error::other(format!("h2: response: {e}"))));
                }
            };
            if resp.status().as_u16() != 200 {
                return Poll::Ready(Err(io::Error::other(format!(
                    "h2: unexpected status: {}",
                    resp.status()
                ))));
            }
            self.recv = Some(resp.into_body());
            self.response = None;
        }
        let recv = self.recv.as_mut().expect("recv set above");
        match recv.poll_data(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Some(Ok(chunk))) => {
                let len = chunk.len();
                // pushed as it arrived: no join, no copy of either side.
                // Capacity is repaid when the bytes leave `pending`, not
                // while we are still holding them.
                self.pending.push_back(chunk);
                self.pending_len += len;
                Poll::Ready(Ok(true))
            }
            Poll::Ready(Some(Err(e))) => {
                Poll::Ready(Err(io::Error::other(format!("h2: recv: {e}"))))
            }
            Poll::Ready(None) => {
                self.eof = true;
                Poll::Ready(Ok(false))
            }
        }
    }

    pub(crate) fn is_eof(&self) -> bool {
        self.eof
    }

    /// Read into `out`, draining `pending` and pulling all available chunks
    /// from `recv` without blocking before returning. Returns `Ready(Ok(()))` if any
    /// bytes were placed into `out` or if EOF was reached. Returns `Pending` only if
    /// no bytes could be read and the stream is not at EOF.
    pub(crate) fn poll_read_into(
        &mut self,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let initial_filled = out.filled().len();
        loop {
            if !self.pending.is_empty() {
                self.serve(out, usize::MAX);
                if out.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }

            if self.eof {
                return Poll::Ready(Ok(()));
            }

            if self.recv.is_none() {
                let Some(response) = self.response.as_mut() else {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                };
                let resp = match ready!(response.as_mut().poll(cx)) {
                    Ok(resp) => resp,
                    Err(e) => {
                        return Poll::Ready(Err(io::Error::other(format!("h2: response: {e}"))));
                    }
                };
                if resp.status().as_u16() != 200 {
                    return Poll::Ready(Err(io::Error::other(format!(
                        "h2: unexpected status: {}",
                        resp.status()
                    ))));
                }
                self.recv = Some(resp.into_body());
                self.response = None;
            }

            let recv = self.recv.as_mut().expect("recv set above");
            match recv.poll_data(cx) {
                Poll::Ready(Some(Ok(mut chunk))) => {
                    let len = chunk.len();
                    let want = out.remaining();
                    // Only what reaches the caller right now is repaid; the
                    // tail waits in `pending` and is repaid by `serve`.
                    let served = want.min(len);
                    if served > 0 {
                        let _ = recv.flow_control().release_capacity(served);
                    }
                    if want >= len {
                        out.put_slice(&chunk);
                    } else if want > 0 {
                        out.put_slice(&chunk[..want]);
                        chunk.advance(want);
                        self.pending_len += chunk.len();
                        self.pending.push_back(chunk);
                        return Poll::Ready(Ok(()));
                    } else {
                        self.pending_len += len;
                        self.pending.push_back(chunk);
                        return Poll::Ready(Ok(()));
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(format!("h2: recv: {e}"))));
                }
                Poll::Ready(None) => {
                    self.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => {
                    if out.filled().len() > initial_filled {
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    /// Half-close: flush staged bytes, then END_STREAM on the send side.
    pub(crate) fn poll_shutdown(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_flush_out(cx))?;
        if let Some(mut send) = self.send.take()
            && let Err(e) = send.send_data(Bytes::new(), true)
        {
            return Poll::Ready(Err(io::Error::other(format!("h2: end stream: {e}"))));
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for H2Stream {
    fn drop(&mut self) {
        // Whatever is still in `pending` was counted against the shared
        // connection window: repay it, or a stream dropped with an unread
        // body shrinks the window the pooled session runs on for good.
        let unread = self.pending_len;
        self.release(unread);
        if let Some(mut send) = self.send.take() {
            send.send_reset(h2::Reason::CANCEL);
        }
        if let Some(task) = self.conn_task.take() {
            task.abort();
        }
    }
}

/// Serve `buf`-style state machines over [`H2Stream`]: reads drain `pending`,
/// writes go through stage + flush. Used directly by the http (h2) transport.
pub(crate) struct H2Io {
    pub(crate) h2: H2Stream,
}

impl AsyncRead for H2Io {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.h2.poll_read_into(cx, out)
    }
}

impl AsyncWrite for H2Io {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if !self.h2.has_out() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            let take = buf.len().min(self.h2.write_chunk);
            self.h2
                .stage_bytes(Bytes::copy_from_slice(&buf[..take]), take);
        }
        ready!(self.h2.poll_flush_out(cx))?;
        Poll::Ready(Ok(self.h2.take_report()))
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.h2.poll_flush_out(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.h2.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod backpressure_tests {
    use super::*;
    use std::sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    };
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn assigned_capacity_does_not_require_another_window_update() {
        use tokio::io::AsyncWriteExt;
        let (client, server) = tokio::io::duplex(1024);
        let server_task = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            let (request, mut respond) = conn.accept().await.unwrap().unwrap();
            let _send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let _recv = request.into_body();
            while conn.accept().await.is_some() {}
        });
        let (mut send, connection) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let (_, mut stream) = send.send_request(http::Request::new(()), false).unwrap();
        stream.reserve_capacity(8192);
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .unwrap()
            .unwrap();
        assert!(capacity >= 3);
        let mut writer = H2Io {
            h2: H2Stream::upload_only(stream),
        };
        tokio::time::timeout(Duration::from_secs(1), writer.write_all(b"abc"))
            .await
            .expect("already assigned capacity must be spendable")
            .unwrap();
        drop(writer);
        drop(send);
        driver.abort();
        server_task.abort();
    }

    #[tokio::test]
    async fn large_uploads_use_bounded_writes_and_preserve_payload() {
        use tokio::io::AsyncWriteExt;
        for grpc in [false, true] {
            let (client, server) = tokio::io::duplex(1024);
            let server_task = tokio::spawn(async move {
                let mut conn = h2::server::handshake(server).await.unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                let send = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let mut writer: crate::inbound::AnyStream = if grpc {
                    super::super::grpc::server(request.into_body(), send)
                } else {
                    Box::new(H2Io {
                        h2: H2Stream::server(request.into_body(), send),
                    })
                };
                let upload = tokio::spawn(async move {
                    let payload = vec![0x5a; 1024 * 1024];
                    let n = writer.write(&payload).await.unwrap();
                    assert!(n > 0 && n <= WRITE_CHUNK);
                    writer.write_all(&payload[n..]).await.unwrap();
                    writer.shutdown().await.unwrap();
                });
                while conn.accept().await.is_some() {}
                upload.await.unwrap();
            });
            let (mut send, connection) = h2::client::handshake(client).await.unwrap();
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (response, stream) = send.send_request(http::Request::new(()), true).unwrap();
            let mut reader = H2Io {
                h2: H2Stream::new(response, stream, driver),
            };
            let mut raw = Vec::new();
            tokio::time::timeout(Duration::from_secs(10), reader.read_to_end(&mut raw))
                .await
                .unwrap()
                .unwrap();
            if grpc {
                let mut payload_len = 0;
                let mut wire = raw.as_slice();
                while !wire.is_empty() {
                    assert_eq!(wire[0], 0);
                    let frame_len = u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize;
                    assert!(frame_len + 5 <= WRITE_CHUNK);
                    assert_eq!(wire[5], 0x0a);
                    let mut at = 6;
                    let mut len = 0usize;
                    let mut shift = 0;
                    loop {
                        let b = wire[at];
                        at += 1;
                        len |= usize::from(b & 0x7f) << shift;
                        if b & 0x80 == 0 {
                            break;
                        }
                        shift += 7;
                    }
                    assert_eq!(at + len, frame_len + 5);
                    assert!(wire[at..at + len].iter().all(|b| *b == 0x5a));
                    payload_len += len;
                    wire = &wire[frame_len + 5..];
                }
                assert_eq!(payload_len, 1024 * 1024);
            } else {
                assert_eq!(raw, vec![0x5a; 1024 * 1024]);
            }
            drop(reader);
            drop(send);
            tokio::time::timeout(Duration::from_secs(3), server_task)
                .await
                .unwrap()
                .unwrap();
        }
    }

    #[tokio::test]
    async fn unread_body_stops_sender_and_drain_reopens_the_window() {
        const WINDOW: usize = 32 * 1024;
        const BODY: usize = WINDOW * 8;
        let (client, server) = tokio::io::duplex(128 * 1024);
        let sent = Arc::new(AtomicUsize::new(0));
        let count = sent.clone();
        let server_task = tokio::spawn(async move {
            let mut conn = h2::server::handshake(server).await.unwrap();
            let (_, mut respond) = conn.accept().await.unwrap().unwrap();
            let mut stream = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let sender = tokio::spawn(async move {
                let mut remaining = BODY;
                while remaining > 0 {
                    stream.reserve_capacity(remaining);
                    let capacity = if stream.capacity() > 0 {
                        stream.capacity()
                    } else {
                        std::future::poll_fn(|cx| stream.poll_capacity(cx))
                            .await
                            .unwrap()
                            .unwrap()
                    };
                    if capacity == 0 {
                        continue;
                    }
                    let len = capacity.min(remaining).min(16 * 1024);
                    remaining -= len;
                    stream
                        .send_data(Bytes::from(vec![0x5a; len]), remaining == 0)
                        .unwrap();
                    count.fetch_add(len, Ordering::SeqCst);
                }
            });
            while conn.accept().await.is_some() {}
            sender.await.unwrap();
        });
        let (mut send, connection) = h2::client::Builder::new()
            .initial_window_size(WINDOW as u32)
            .initial_connection_window_size((WINDOW * 2) as u32)
            .handshake(client)
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let (response, stream) = send.send_request(http::Request::new(()), true).unwrap();
        let mut io = H2Io {
            h2: H2Stream::new(response, stream, driver),
        };
        let mut first = [0u8; 1];
        tokio::time::timeout(Duration::from_secs(3), io.read_exact(&mut first))
            .await
            .expect("first byte deadline")
            .unwrap();
        assert_eq!(first, [0x5a]);
        // Poll without consuming, as gRPC's header parser does while buffering.
        tokio::time::timeout(
            Duration::from_secs(3),
            std::future::poll_fn(|cx| io.h2.poll_recv_more(cx)),
        )
        .await
        .expect("buffer second frame deadline")
        .unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        assert!(sent.load(Ordering::SeqCst) <= WINDOW + 1);
        let mut rest = Vec::new();
        tokio::time::timeout(Duration::from_secs(3), io.read_to_end(&mut rest))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rest.len() + 1, BODY);
        assert!(rest.iter().all(|byte| *byte == 0x5a));
        drop(io);
        drop(send);
        server_task.abort();
    }
}

#[cfg(test)]
mod settings_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Reads one HTTP/2 frame: `(type, flags, stream id, payload)`.
    async fn read_frame<R: AsyncRead + Unpin>(io: &mut R) -> (u8, u8, u32, Vec<u8>) {
        let mut head = [0u8; 9];
        io.read_exact(&mut head).await.expect("frame header");
        let len = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
        let stream = u32::from_be_bytes([head[5] & 0x7f, head[6], head[7], head[8]]);
        let mut payload = vec![0u8; len];
        io.read_exact(&mut payload).await.expect("frame payload");
        (head[3], head[4], stream, payload)
    }

    fn settings_of(payload: &[u8]) -> Vec<(u16, u32)> {
        payload
            .chunks(6)
            .map(|c| {
                (
                    u16::from_be_bytes([c[0], c[1]]),
                    u32::from_be_bytes([c[2], c[3], c[4], c[5]]),
                )
            })
            .collect()
    }

    /// What Go's HTTP/2 client opens with, which is what we must open with:
    /// the preface, a SETTINGS frame holding exactly ENABLE_PUSH 0,
    /// INITIAL_WINDOW_SIZE 4 MiB, MAX_FRAME_SIZE 16 KiB and
    /// MAX_HEADER_LIST_SIZE 10 MiB in identifier order, then a connection
    /// WINDOW_UPDATE raising the window to 1 GiB -- all before the server has
    /// said anything.
    #[tokio::test]
    async fn the_client_opens_with_gos_settings() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let handshake = tokio::spawn(async move {
            let _ = client_builder().handshake::<_, Bytes>(client_io).await;
        });

        let mut preface = [0u8; 24];
        server_io.read_exact(&mut preface).await.expect("preface");
        assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");

        let (kind, flags, stream, payload) = read_frame(&mut server_io).await;
        assert_eq!((kind, flags, stream), (0x4, 0, 0), "SETTINGS frame");
        assert_eq!(
            settings_of(&payload),
            vec![
                (0x2, 0),
                (0x4, GO_STREAM_WINDOW),
                (0x5, GO_MAX_FRAME),
                (0x6, GO_MAX_HEADER_LIST),
            ]
        );

        let (kind, _, stream, payload) = read_frame(&mut server_io).await;
        assert_eq!((kind, stream), (0x8, 0), "connection WINDOW_UPDATE");
        assert_eq!(
            u32::from_be_bytes(payload.try_into().expect("4-byte delta")),
            GO_CONN_WINDOW - MIN_WINDOW
        );

        handshake.abort();
        let _ = server_io.shutdown().await;
    }

    /// The names of the header fields of the first HEADERS frame a client
    /// sends, in the order they are encoded, decoded with a plain HPACK
    /// decoder (the fields here are all literal, never indexed away).
    async fn first_header_names(builder: h2::client::Builder, uri: &str) -> Vec<&'static str> {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let uri = uri.to_string();
        let handshake = tokio::spawn(async move {
            let Ok((send, connection)) = builder.handshake::<_, Bytes>(client_io).await else {
                return;
            };
            tokio::spawn(async move {
                let _ = connection.await;
            });
            let mut send = match send.ready().await {
                Ok(send) => send,
                Err(_) => return,
            };
            let request = http::Request::builder()
                .method("POST")
                .uri(uri)
                .body(())
                .expect("request");
            let _ = send.send_request(request, false);
            std::future::pending::<()>().await;
        });

        let mut preface = [0u8; 24];
        server_io.read_exact(&mut preface).await.expect("preface");
        // our SETTINGS and WINDOW_UPDATE, then the server's SETTINGS so the
        // client may open a stream
        let _ = read_frame(&mut server_io).await;
        let _ = read_frame(&mut server_io).await;
        server_io
            .write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
            .await
            .expect("server settings");
        let names = loop {
            let (kind, _, stream, payload) = read_frame(&mut server_io).await;
            // skip the SETTINGS ack and anything else before the request
            if kind == 0x1 && stream != 0 {
                break payload;
            }
        };

        handshake.abort();
        pseudo_names(&names)
    }

    /// The pseudo-header names of an HPACK block, in encoding order. The first
    /// HEADERS frame of a connection starts with an empty dynamic table, so
    /// every pseudo-header is either an indexed static entry (1..=7) or a
    /// literal naming one of those indices -- enough to read their order
    /// without a full HPACK decoder.
    fn pseudo_names(block: &[u8]) -> Vec<&'static str> {
        fn static_name(index: u8) -> Option<&'static str> {
            Some(match index {
                1 => ":authority",
                2 | 3 => ":method",
                4 | 5 => ":path",
                6 | 7 => ":scheme",
                _ => return None,
            })
        }
        /// An integer with an `n`-bit prefix (RFC 7541 section 5.1).
        fn integer(block: &[u8], at: &mut usize, mask: u8) -> usize {
            let mut value = usize::from(block[*at] & mask);
            *at += 1;
            if value == usize::from(mask) {
                let mut shift = 0;
                loop {
                    let byte = block[*at];
                    *at += 1;
                    value += usize::from(byte & 0x7f) << shift;
                    shift += 7;
                    if byte & 0x80 == 0 {
                        break;
                    }
                }
            }
            value
        }
        /// Skips one length-prefixed string (Huffman coded or not).
        fn skip_string(block: &[u8], at: &mut usize) {
            let len = integer(block, at, 0x7f);
            *at += len;
        }

        let mut names = Vec::new();
        let mut at = 0;
        while at < block.len() {
            let first = block[at];
            if first & 0x80 != 0 {
                // indexed header field: name and value both from the table
                let index = integer(block, &mut at, 0x7f);
                if let Some(name) = static_name(index as u8) {
                    names.push(name);
                }
                continue;
            }
            if first & 0xe0 == 0x20 {
                // dynamic table size update: no field follows
                integer(block, &mut at, 0x1f);
                continue;
            }
            // literal header field; the prefix width depends on the form
            let mask = if first & 0x40 != 0 { 0x3f } else { 0x0f };
            let index = integer(block, &mut at, mask);
            if index == 0 {
                // the name is spelled out
                skip_string(block, &mut at);
            } else if let Some(name) = static_name(index as u8) {
                names.push(name);
            }
            skip_string(block, &mut at);
        }
        names
    }

    /// XHTTP, the HTTP/2 transport and the h2 mux imitate Go's `net/http`
    /// client, which encodes `:authority`, `:method`, `:path`, `:scheme`.
    #[tokio::test]
    async fn the_client_sends_pseudo_headers_in_gos_order() {
        let names = first_header_names(client_builder(), "https://example.com/tunnel").await;
        assert_eq!(
            &names[..4],
            [":authority", ":method", ":path", ":scheme"],
            "{names:?}"
        );
    }

    /// The gRPC transport imitates grpc-go, which encodes `:method`,
    /// `:scheme`, `:path`, `:authority`.
    #[tokio::test]
    async fn the_grpc_client_sends_pseudo_headers_in_grpc_gos_order() {
        let names = first_header_names(grpc_client_builder(), "https://example.com/svc/Tun").await;
        assert_eq!(
            &names[..4],
            [":method", ":scheme", ":path", ":authority"],
            "{names:?}"
        );
    }

    #[tokio::test]
    #[ignore = "throughput probe"]
    async fn throughput_probe() {
        use crate::inbound::AnyStream;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        const TOTAL: usize = 512 * 1024 * 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await.unwrap();
            let mut conn = server_builder().handshake::<_, Bytes>(tcp).await.unwrap();
            let (request, mut respond) = conn.accept().await.unwrap().unwrap();
            let send = respond
                .send_response(http::Response::new(()), false)
                .unwrap();
            let upload = tokio::spawn(async move {
                let mut writer: AnyStream = Box::new(H2Io {
                    h2: H2Stream::server(request.into_body(), send),
                });
                let chunk = vec![0x5a; 256 * 1024];
                let mut left = TOTAL;
                while left > 0 {
                    let n = chunk.len().min(left);
                    writer.write_all(&chunk[..n]).await.unwrap();
                    left -= n;
                }
                writer.shutdown().await.unwrap();
            });
            while conn.accept().await.is_some() {}
            upload.await.unwrap();
        });
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let (mut send, connection) = client_builder().handshake(tcp).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let (response, stream) = send.send_request(http::Request::new(()), true).unwrap();
        let mut reader = H2Io {
            h2: H2Stream::new(response, stream, driver),
        };
        let started = std::time::Instant::now();
        let mut buf = vec![0u8; 256 * 1024];
        let mut got = 0usize;
        loop {
            let n = reader.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            got += n;
        }
        let took = started.elapsed();
        assert_eq!(got, TOTAL);
        println!(
            "stream window {} conn window {} max frame {}: {:.2} Gbit/s ({:?})",
            client_stream_window(),
            client_conn_window(),
            GO_MAX_FRAME,
            (got as f64 * 8.0) / took.as_secs_f64() / 1e9,
            took
        );
        server.abort();
    }

    /// The server half keeps the throughput windows: it is not imitating a
    /// client, and a 16 KiB frame cap there would cost downloads.
    #[tokio::test]
    async fn the_server_keeps_its_own_windows() {
        let (server_side, mut client_side) = tokio::io::duplex(64 * 1024);
        let handshake = tokio::spawn(async move {
            let _ = server_builder().handshake::<_, Bytes>(server_side).await;
        });
        client_side
            .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
            .await
            .expect("preface");
        // an empty client SETTINGS, so the server may send its own
        client_side
            .write_all(&[0, 0, 0, 0x4, 0, 0, 0, 0, 0])
            .await
            .expect("client settings");
        let (kind, _, _, payload) = read_frame(&mut client_side).await;
        assert_eq!(kind, 0x4, "SETTINGS frame");
        let settings = settings_of(&payload);
        assert!(
            settings.contains(&(0x4, STREAM_WINDOW)) && settings.contains(&(0x5, MAX_FRAME)),
            "server settings changed: {settings:?}"
        );
        handshake.abort();
    }
}
