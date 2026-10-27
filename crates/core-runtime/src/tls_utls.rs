//! A stream whose TLS is ours: a captured fingerprint's ClientHello, our own
//! handshake, and application data through our own record layer.
//!
//! The adapter is thin on purpose. `core_tls::client::Connection` works on
//! bytes -- plaintext in, one record out -- so all this has to do is move bytes
//! between the socket and those two calls without ever blocking inside a poll.
//! The blocking parts of the TLS live in core-tls, where they can be tested
//! against a real server; here there is only a buffer and two state flags.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::bufpool::Pool;
use core_tls::client::{Connection, Record};

/// How much the raw buffer grows by when it needs room. A record is at most
/// 2^14 + 256 bytes with its tag, so one read fills several of them on any socket
/// that is not pathological.
const CHUNK: usize = 64 * 1024;

/// Read buffers (`CHUNK` each) and sealed-record buffers (one record each).
static READ_POOL: Pool = Pool::new();
static WRITE_POOL: Pool = Pool::new();

/// TLS over `S`, established by us rather than by a library.
pub struct FingerprintStream<S: AsyncWrite + Unpin> {
    inner: S,
    connection: Connection,
    /// transport bytes, and where the opened plaintext of the record at the front
    /// of them starts and ends
    raw: Vec<u8>,
    /// how far into `raw` the bytes already handed over run. A 64 KiB read holds
    /// four records, and shifting what is left down after each one moves three
    /// times the payload it just finished reading: a second pass over every byte
    /// on the hottest path in the tree. The cursor costs nothing, and the buffer
    /// is compacted only when it is actually full.
    rpos: usize,
    /// `raw[plain_at..plain_end]` has been opened and not handed over yet, and
    /// the record it came from runs to `plain_end` no further: `raw[..record_end]`
    /// is what a caller drops once it is done with the plaintext
    plain_at: usize,
    plain_end: usize,
    record_end: usize,
    /// the sealed record waiting to go out, kept from record to record:
    /// sealing used to allocate a fresh Vec per record, which on the hot
    /// path is steady churn for bytes that land in the same 16 KiB slot
    wbuf: Vec<u8>,
    /// how far into `wbuf` the socket has taken; `None` between records
    out: Option<usize>,
    /// Plaintext length of the sealed record, independent of later input growth.
    pending_plaintext: usize,
    /// the peer's stream ended: a read hands back nothing more
    eof: bool,
    /// our side was shut down; the peer may still be sending
    write_closed: bool,
    direct_read: bool,
    direct_write: bool,
    /// Hand over every record already buffered in one read, not only the
    /// first. Off under Vision: there the peer can stop outer TLS after any
    /// record, and the bytes behind it must not be opened as one.
    batch_reads: bool,
    /// a record error met after plaintext was already handed over in the same
    /// call, kept for the next read
    read_error: Option<io::Error>,
    /// our close_notify went out (or is on its way in `wbuf`)
    close_notify_sent: bool,
    /// Go's `bytesSent` and `packetsSent`, for its record sizes at the start
    /// of a connection (see `record_limit`)
    bytes_sent: u64,
    packets_sent: u64,
    /// The most plaintext a record may carry once the connection is past the
    /// growth at its start: what the transport above this one would hand a
    /// reference client in one write (see [`FingerprintStream::with_record_cap`]).
    record_cap: usize,
}

/// Records at the start of a connection grow by this much
/// ([`core_tls::record::BOOST_STEP`], derived there from Go's segment
/// estimate).
const BOOST_STEP: usize = core_tls::record::BOOST_STEP;
/// Go's `recordSizeBoostThreshold`: after this many bytes, full records.
const BOOST_UNTIL: u64 = 128 * 1024;

/// `XRUST_TLS_MAX_RECORD` sets the steady-state record size for every
/// connection, whatever the transport asked for. The reference's size costs
/// one write and one record's framing per 8 KiB instead of per 16 KiB, which
/// measured ~10% of a multi-gigabit bulk upload and nothing at a router's
/// link rate; this is the way out if that ever turns out to matter on a slow
/// CPU, without touching the growth at the start of a connection.
fn max_record_override() -> Option<usize> {
    static OVERRIDE: std::sync::OnceLock<Option<usize>> = std::sync::OnceLock::new();
    *OVERRIDE.get_or_init(|| {
        crate::env_var("TLS_MAX_RECORD")
            .and_then(|val| val.parse::<usize>().ok())
            .filter(|cap| *cap > 0)
    })
}

impl<S: AsyncWrite + Unpin> FingerprintStream<S> {
    /// Wrap a transport whose handshake is already finished.
    pub fn new(inner: S, connection: Connection) -> Self {
        Self::with_record_cap(inner, connection, core_tls::record::MAX_FRAGMENT)
    }

    /// The same, with the steady-state record size of the transport that will
    /// run on top.
    ///
    /// A record is as big as the write that seals it, so the sizes on the wire
    /// are the sizes of the reference client's writes. Xray relays raw, ws and
    /// httpupgrade streams through `buf.Size` buffers and so never writes more
    /// than 8192 bytes at a time, which is 8214 bytes of record; its h2
    /// transports (xhttp, grpc, h2) write whole frames and reach the fragment
    /// limit. A relay here reads up to 128 KiB in one go, so without this the
    /// first group would run at 16384 and stand out by length alone.
    pub fn with_record_cap(inner: S, connection: Connection, record_cap: usize) -> Self {
        FingerprintStream {
            inner,
            raw: Vec::new(),
            rpos: 0,
            plain_at: 0,
            plain_end: 0,
            record_end: 0,
            wbuf: Vec::new(),
            out: None,
            pending_plaintext: 0,
            eof: false,
            write_closed: false,
            direct_read: false,
            direct_write: false,
            batch_reads: true,
            read_error: None,
            close_notify_sent: false,
            bytes_sent: connection.handshake_bytes(),
            packets_sent: 0,
            record_cap: max_record_override()
                .unwrap_or(record_cap)
                .clamp(1, core_tls::record::MAX_FRAGMENT),
            connection,
        }
    }

    /// The most plaintext the next record may carry. Go's `crypto/tls` (and
    /// uTLS, which Xray's client runs) starts a connection with records the
    /// size of one TCP segment and lets them grow by a segment each, until
    /// 128 KiB have gone out (`maxPayloadSizeForWrite`): a record of 1186
    /// bytes of plaintext, then up to 2372, 3558 and so on to 16384. A bulk
    /// transfer, or a first write bigger than a segment -- the Vision head
    /// with a client hello -- is cut that way at the start, and the same here.
    /// Past the growth the limit is the transport's own steady-state size
    /// (`record_cap`), so a raw or ws stream keeps writing the 8192 bytes a
    /// reference client's relay buffer holds instead of twice that.
    fn record_limit(&mut self) -> usize {
        let max = self.record_cap;
        if self.bytes_sent >= BOOST_UNTIL {
            return max;
        }
        let packet = self.packets_sent;
        self.packets_sent += 1;
        if packet > 1000 {
            return max;
        }
        (BOOST_STEP * (packet as usize + 1)).min(max)
    }

    /// Whether closing our side should say close_notify first. Go's
    /// `tls.Conn` does on `Close` and `CloseWrite`; Xray suppresses it once
    /// Vision went Direct either way (`proxy.go` `SuppressOuterCloseNotify`),
    /// since the outer TLS no longer frames what follows.
    fn owes_close_notify(&self) -> bool {
        !self.close_notify_sent && !self.write_closed && !self.direct_read && !self.direct_write
    }

    /// Write out what `wbuf` holds from `out` on.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(pos) = self.out {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            let pos = pos + n;
            self.out = (pos < self.wbuf.len()).then_some(pos);
        }
        Poll::Ready(Ok(()))
    }

    /// Seal `parts` into one record and write it out; ready with the
    /// plaintext it carried once the whole record is with the transport.
    /// A record left half way out by an earlier call goes first, and its
    /// count is what that call is owed.
    fn poll_seal(&mut self, cx: &mut Context<'_>, parts: &[&[u8]]) -> Poll<io::Result<usize>> {
        loop {
            let Some(pos) = self.out else {
                if self.wbuf.capacity() == 0 {
                    self.wbuf = WRITE_POOL.take();
                }
                self.wbuf.clear();
                self.connection
                    .write_record_parts_into(parts, &mut self.wbuf)?;
                self.bytes_sent += self.wbuf.len() as u64;
                self.out = Some(0);
                self.pending_plaintext = parts.iter().map(|p| p.len()).sum();
                continue;
            };
            match Pin::new(&mut self.inner).poll_write(cx, &self.wbuf[pos..]) {
                Poll::Ready(Ok(n)) => {
                    let pos = pos + n;
                    if pos == self.wbuf.len() {
                        self.out = None;
                        let written = std::mem::take(&mut self.pending_plaintext);
                        return Poll::Ready(Ok(written));
                    }
                    self.out = Some(pos);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    /// Seal close_notify into `wbuf`, to go out with `poll_drain`.
    fn queue_close_notify(&mut self) -> io::Result<()> {
        self.close_notify_sent = true;
        self.connection.close_notify_into(&mut self.wbuf)?;
        self.out = Some(0);
        self.pending_plaintext = 0;
        Ok(())
    }

    /// Return from a read after one record, as Vision needs: it decides
    /// between records whether the next bytes are still TLS.
    pub(crate) fn disable_read_batching(&mut self) {
        self.batch_reads = false;
    }

    pub fn get_ref(&self) -> &S {
        &self.inner
    }

    pub fn get_mut(&mut self) -> &mut S {
        &mut self.inner
    }

    pub(crate) fn enable_direct_read(&mut self) {
        self.batch_reads = false;
        self.direct_read = true;
        self.release_direct_read_buffer();
    }

    pub(crate) fn enable_direct_write(&mut self) -> bool {
        if self.out.is_some() {
            return false;
        }
        self.direct_write = true;
        self.wbuf = Vec::new();
        true
    }

    /// The transport, once reads are raw and every byte taken off it before
    /// the switch has been handed over: what it yields next is payload as is.
    #[cfg(target_os = "linux")]
    pub(crate) fn direct_read_transport(&self) -> Option<&S> {
        let drained = self.plain_at == self.plain_end
            && self.rpos == self.raw.len()
            && self.read_error.is_none();
        (self.direct_read && drained).then_some(&self.inner)
    }

    /// While the socket has nothing to read, hand back whatever buffer holds
    /// nothing: no record partly read, no plaintext not yet handed over, no
    /// sealed record partly written.
    fn park_buffers(&mut self) {
        let drained = self.rpos == self.raw.len()
            && self.plain_at == self.plain_end
            && self.read_error.is_none();
        if drained {
            READ_POOL.give(std::mem::take(&mut self.raw));
            self.rpos = 0;
        }
        if self.out.is_none() {
            WRITE_POOL.give(std::mem::take(&mut self.wbuf));
        }
    }

    fn release_direct_read_buffer(&mut self) {
        if self.direct_read && self.plain_at == self.plain_end {
            release_drained_raw(&mut self.raw, &mut self.rpos);
        }
    }
}

fn release_drained_raw(raw: &mut Vec<u8>, rpos: &mut usize) {
    if *rpos == raw.len() {
        *raw = Vec::new();
        *rpos = 0;
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for FingerprintStream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        // whether this call already put plaintext into `buf`: then it returns
        // before the socket is asked again, and an error waits for the next call
        let mut produced = false;
        if let Some(e) = me.read_error.take() {
            return Poll::Ready(Err(e));
        }
        loop {
            // plaintext the reader's buffer could not take whole
            if me.plain_at < me.plain_end {
                let take = (me.plain_end - me.plain_at).min(buf.remaining());
                buf.put_slice(&me.raw[me.plain_at..me.plain_at + take]);
                me.plain_at += take;
                if me.plain_at == me.plain_end {
                    // the record is out of the caller's hands: its transport bytes
                    // are behind the cursor, and the buffer keeps its room
                    me.rpos = me.record_end;
                    me.plain_at = 0;
                    me.plain_end = 0;
                    me.record_end = 0;
                    me.release_direct_read_buffer();
                    // A socket read holds several records. Handing over one per
                    // call made the relay write each 16 KiB record on its own.
                    if me.batch_reads && buf.remaining() > 0 {
                        produced = true;
                        continue;
                    }
                }
                return Poll::Ready(Ok(()));
            }
            if me.direct_read {
                // The last decrypted record may share a socket read with the
                // first raw Vision records. Drain those bytes before the socket.
                let take = (me.raw.len() - me.rpos).min(buf.remaining());
                if take > 0 {
                    buf.put_slice(&me.raw[me.rpos..me.rpos + take]);
                    me.rpos += take;
                    me.release_direct_read_buffer();
                    return Poll::Ready(Ok(()));
                }
                me.release_direct_read_buffer();
                return Pin::new(&mut me.inner).poll_read(cx, buf);
            }
            if me.eof || me.connection.is_closed() {
                return Poll::Ready(Ok(()));
            }
            // Whatever we already hold comes first, and only then the socket.
            // The order matters: a socket hands us half a record all the time, so
            // "five bytes buffered" says nothing about whether a record is whole.
            // Asking the socket only when the buffer was *short* meant a split
            // record left us spinning over the same bytes forever, never reading
            // the rest of it -- which is what a REALITY server's post-handshake
            // ticket is.
            match me.connection.read_record_in_place(&mut me.raw[me.rpos..]) {
                Ok(Some(Record::Data {
                    start,
                    end,
                    record_end,
                })) => {
                    me.plain_at = me.rpos + start;
                    me.plain_end = me.rpos + end;
                    me.record_end = me.rpos + record_end;
                    continue;
                }
                Ok(Some(Record::Skip { record_end })) => {
                    me.rpos += record_end;
                    continue;
                }
                Ok(None) if produced => return Poll::Ready(Ok(())),
                Ok(None) => {}
                // close_notify is the end of the stream, as rustls and Go's
                // crypto/tls report it, not a failure; later reads see
                // `is_closed` and return end of stream too
                Err(_) if me.connection.is_closed() => return Poll::Ready(Ok(())),
                // the plaintext already handed over goes out first, and the
                // error with the next call
                Err(e) if produced => {
                    me.read_error = Some(e);
                    return Poll::Ready(Ok(()));
                }
                Err(e) => return Poll::Ready(Err(e)),
            }
            // Read straight into the buffer's spare room: a zeroed stack array per
            // read is 18 KiB of memset plus a copy out of it, on every read. The
            // cursor is folded away here and nowhere else, because this is the one
            // place that needs the room.
            if me.raw.len() == me.raw.capacity() {
                if me.rpos > 0 {
                    let left = me.raw.len() - me.rpos;
                    me.raw.copy_within(me.rpos.., 0);
                    me.raw.truncate(left);
                    me.rpos = 0;
                }
                if me.raw.capacity() == 0 {
                    me.raw = READ_POOL.take();
                }
                if me.raw.len() == me.raw.capacity() {
                    me.raw.reserve(CHUNK);
                }
            }
            let have = me.raw.len();
            let got = {
                let mut read = ReadBuf::uninit(me.raw.spare_capacity_mut());
                match Pin::new(&mut me.inner).poll_read(cx, &mut read) {
                    Poll::Ready(Ok(())) => read.filled().len(),
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => {
                        me.park_buffers();
                        return Poll::Pending;
                    }
                }
            };
            if got == 0 {
                me.eof = true;
                return Poll::Ready(Ok(()));
            }
            // SAFETY: the reader initialised exactly `got` bytes of the spare
            // capacity, starting at `have`
            unsafe { me.raw.set_len(have + got) };
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for FingerprintStream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        // A writer that reports writing a 22-byte tag has not written is lying
        // about its input, and every caller that respects the contract -- tokio's
        // `write_all` above all -- slices its buffer by the number it is given.
        // An empty write is nothing to seal: reporting zero for it is the honest
        // answer, and it keeps a caller from sealing an empty record.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if me.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if me.direct_write {
            return Pin::new(&mut me.inner).poll_write(cx, buf);
        }
        // one record per call, so the sequence number moves with each record
        // rather than with each call. A caller with more than a record's worth
        // writes it in pieces: `write_record` refuses more, and the number handed
        // back has to be what really left.
        let room = if me.out.is_none() {
            me.record_limit()
        } else {
            core_tls::record::MAX_FRAGMENT
        };
        let take = buf.len().min(room);
        me.poll_seal(cx, &[&buf[..take]])
    }

    /// The pieces go into one record up to a record's worth, as Go's
    /// `crypto/tls` puts one buffered write into one: h2 hands over a frame
    /// header and its payload apart (`vendor/h2` `FramedWrite::flush`), and
    /// sealed one by one they made pairs of 1041 and 15386 bytes where Xray
    /// sends 16401.
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        if bufs.iter().all(|b| b.is_empty()) {
            return Poll::Ready(Ok(0));
        }
        if me.write_closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if me.direct_write {
            return Pin::new(&mut me.inner).poll_write_vectored(cx, bufs);
        }
        const MOST: usize = 16;
        let mut parts: [&[u8]; MOST] = [&[]; MOST];
        let mut count = 0;
        let mut room = if me.out.is_none() {
            me.record_limit()
        } else {
            core_tls::record::MAX_FRAGMENT
        };
        for buf in bufs {
            if count == MOST || room == 0 {
                break;
            }
            let take = buf.len().min(room);
            if take == 0 {
                continue;
            }
            parts[count] = &buf[..take];
            count += 1;
            room -= take;
        }
        me.poll_seal(cx, &parts[..count])
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // poll_write only returns Ready once a record is whole, so there is
        // never a part-written record to flush around
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Only our direction ends here. A client that half-closes its upload
        // still expects the rest of the download: close_notify ends our
        // direction only, and the peer may go on sending (RFC 8446 6.1), as
        // after Go's `CloseWrite`.
        let me = self.get_mut();
        if !me.write_closed {
            // a record a write left half way out goes first
            ready!(me.poll_drain(cx))?;
            if me.owes_close_notify() {
                me.queue_close_notify()?;
                ready!(me.poll_drain(cx))?;
            }
            ready!(Pin::new(&mut me.inner).poll_flush(cx))?;
            me.write_closed = true;
        }
        Pin::new(&mut me.inner).poll_shutdown(cx)
    }
}

/// A stream dropped without a shutdown still says close_notify, as Go's
/// `tls.Conn.Close` does (it is what Xray's client sends when a connection
/// ends: a 19-byte encrypted alert record before the FIN). There is no
/// waiting in a drop, so this is one attempt: whatever the socket takes now.
impl<S: AsyncWrite + Unpin> Drop for FingerprintStream<S> {
    fn drop(&mut self) {
        if !self.owes_close_notify() {
            return;
        }
        let mut cx = Context::from_waker(std::task::Waker::noop());
        if !matches!(self.poll_drain(&mut cx), Poll::Ready(Ok(()))) {
            // a record still half way out: an alert behind it would not parse
            return;
        }
        if self.queue_close_notify().is_ok() {
            let _ = self.poll_drain(&mut cx);
            let _ = Pin::new(&mut self.inner).poll_flush(&mut cx);
        }
    }
}

/// One read has to be able to hold a whole record, or every record costs two
/// syscalls: 2^14 of plaintext, a type byte, a 16-byte tag, a 5-byte header.
/// A compile-time check, because a runtime one would only ever be a comment.
const _: () = assert!(CHUNK > 16384 + 1 + 16 + 5);

#[cfg(test)]
mod memory_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    struct PauseWriteOnce {
        inner: tokio::io::DuplexStream,
        pause: bool,
    }

    impl AsyncRead for PauseWriteOnce {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for PauseWriteOnce {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.pause {
                self.pause = false;
                cx.waker().wake_by_ref();
                return Poll::Pending;
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

    #[tokio::test]
    async fn direct_read_preserves_pending_plaintext_and_tail_without_disabling_tls_write() {
        use core_tls::client::{Config, Handshake};
        use core_tls::rustls::{RootCertStore, ServerConfig};
        use core_tls::verify::WebpkiVerifier;
        use std::sync::Arc;

        core_tls::install_default_provider();
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.crt")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.key")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let verifier = WebpkiVerifier::new(Arc::new(roots)).unwrap();
        let template = core_tls::fingerprints::by_name("chrome").unwrap();
        let (mut client, peer) = tokio::io::duplex(CHUNK);
        let (ready_send, ready_recv) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(peer)
                .await
                .unwrap();
            let mut request = [0; 2];
            tls.read_exact(&mut request).await.unwrap();
            assert_eq!(&request, b"hi");
            ready_send.send(()).unwrap();
            let (mut raw, _) = tls.into_inner();
            let mut tail = [0; 3];
            raw.read_exact(&mut tail).await.unwrap();
            assert_eq!(&tail, b"RAW");
        });
        let mut handshake = Handshake::new(Config {
            template: &template,
            server_name: "localhost",
            alpn: &[],
            verifier: &verifier,
            reality: None,
            fragment: false,
            cipher_suites: Vec::new(),
        })
        .unwrap();
        handshake.run(&mut client).await.unwrap();
        let connection = Connection::new(&mut handshake).unwrap();
        let mut stream = FingerprintStream::new(
            PauseWriteOnce {
                inner: client,
                pause: true,
            },
            connection,
        );
        // State at the transition: decrypted plaintext followed by raw peer bytes.
        stream.raw = Vec::with_capacity(CHUNK);
        stream.raw.extend_from_slice(b"plainRAW");
        stream.plain_at = 0;
        stream.plain_end = 5;
        stream.record_end = 5;
        stream.enable_direct_read();
        assert_eq!(stream.raw.capacity(), CHUNK);
        let mut plaintext = [0; 5];
        stream.read_exact(&mut plaintext).await.unwrap();
        assert_eq!(&plaintext, b"plain");
        assert_eq!(stream.raw.capacity(), CHUNK);
        let mut tail = [0; 3];
        stream.read_exact(&mut tail).await.unwrap();
        assert_eq!(&tail, b"RAW");
        assert_eq!(stream.raw.capacity(), 0);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            Pin::new(&mut stream)
                .poll_write(&mut cx, b"hi")
                .is_pending()
        );
        assert!(
            !stream.enable_direct_write(),
            "pending ciphertext must drain first"
        );
        // The relay may append input while its writer is pending. Only the
        // original record's plaintext was consumed, even if this slice grew.
        let written = std::future::poll_fn(|cx| Pin::new(&mut stream).poll_write(cx, b"hiEXTRA"))
            .await
            .unwrap();
        assert_eq!(
            written, 2,
            "must report the pending record's original length"
        );
        ready_recv.await.unwrap();
        assert!(stream.enable_direct_write());
        assert_eq!(stream.wbuf.capacity(), 0);
        tokio::io::AsyncWriteExt::write_all(&mut stream, b"RAW")
            .await
            .unwrap();
        server.await.unwrap();
    }

    #[test]
    fn direct_read_keeps_unread_tail_and_releases_only_when_drained() {
        let mut raw = Vec::with_capacity(CHUNK);
        raw.extend_from_slice(b"encryptedraw tail");
        let mut rpos = 9;
        release_drained_raw(&mut raw, &mut rpos);
        assert_eq!(&raw[rpos..], b"raw tail");
        assert_eq!(raw.capacity(), CHUNK);
        rpos += 3;
        release_drained_raw(&mut raw, &mut rpos);
        assert_eq!(&raw[rpos..], b" tail");
        rpos = raw.len();
        release_drained_raw(&mut raw, &mut rpos);
        assert_eq!(raw.capacity(), 0);
        assert_eq!(rpos, 0);
        release_drained_raw(&mut raw, &mut rpos);
        assert_eq!(raw.capacity(), 0);
    }
}

#[cfg(test)]
mod read_batching_tests {
    use super::*;
    use core_tls::client::{Config, Handshake};
    use core_tls::rustls::{RootCertStore, ServerConfig};
    use core_tls::verify::WebpkiVerifier;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    const RECORD: usize = core_tls::record::MAX_FRAGMENT;

    type ServerStream = tokio_rustls::server::TlsStream<DuplexStream>;

    /// Our client over a duplex to a rustls server that runs `serve` once
    /// the handshake is done.
    async fn connected<F, Fut>(serve: F) -> FingerprintStream<DuplexStream>
    where
        F: FnOnce(ServerStream) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        core_tls::install_default_provider();
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.crt")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.key")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let verifier = WebpkiVerifier::new(Arc::new(roots)).unwrap();
        let template = core_tls::fingerprints::by_name("chrome").unwrap();
        let (mut client, peer) = tokio::io::duplex(4 * CHUNK);
        tokio::spawn(async move {
            let tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(peer)
                .await
                .unwrap();
            serve(tls).await;
        });
        let mut handshake = Handshake::new(Config {
            template: &template,
            server_name: "localhost",
            alpn: &[],
            verifier: &verifier,
            reality: None,
            fragment: false,
            cipher_suites: Vec::new(),
        })
        .unwrap();
        handshake.run(&mut client).await.unwrap();
        let connection = Connection::new(&mut handshake).unwrap();
        FingerprintStream::new(client, connection)
    }

    /// The server writes three full records, then `tail` straight onto the
    /// transport, and holds the connection open until the returned sender
    /// fires.
    async fn three_records_then(
        tail: &'static [u8],
    ) -> (
        FingerprintStream<DuplexStream>,
        tokio::sync::oneshot::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (ready_send, ready_recv) = tokio::sync::oneshot::channel();
        let (done_send, done_recv) = tokio::sync::oneshot::channel::<()>();
        let mut stream = connected(move |mut tls| async move {
            let mut hello = [0; 2];
            tls.read_exact(&mut hello).await.unwrap();
            tls.write_all(&vec![0x5a; 3 * RECORD]).await.unwrap();
            tls.flush().await.unwrap();
            let (mut raw, _) = tls.into_inner();
            raw.write_all(tail).await.unwrap();
            ready_send.send(()).unwrap();
            let _ = done_recv.await;
        })
        .await;
        stream.write_all(b"hi").await.unwrap();
        (stream, ready_recv, done_send)
    }

    /// The server reads the request up to the client's EOF, then answers
    /// with three full records and closes.
    async fn answer_after_eof() -> FingerprintStream<DuplexStream> {
        connected(|mut tls| async move {
            let mut request = Vec::new();
            loop {
                let mut chunk = [0; 64];
                match tls.read(&mut chunk).await {
                    Ok(0) => break,
                    Ok(n) => request.extend_from_slice(&chunk[..n]),
                    // a clean end: our shutdown says close_notify first, so
                    // rustls does not report a truncation
                    Err(e) => panic!("{e}"),
                }
            }
            assert_eq!(request, b"GET");
            tls.write_all(&vec![0x5a; 3 * RECORD]).await.unwrap();
            tls.shutdown().await.unwrap();
        })
        .await
    }

    /// Shutting down the upload must not end the download: the answer the
    /// server sends after seeing our EOF still arrives in full.
    #[tokio::test]
    async fn shutdown_ends_only_the_write_side() {
        let mut stream = answer_after_eof().await;
        stream.write_all(b"GET").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response.len(), 3 * RECORD);
        assert!(response.iter().all(|b| *b == 0x5a));
    }

    /// How the server's read of our upload ends: `Ok` for a clean end after
    /// close_notify, the error kind for a bare TCP EOF.
    async fn upload_end() -> (
        FingerprintStream<DuplexStream>,
        tokio::sync::oneshot::Receiver<Result<Vec<u8>, io::ErrorKind>>,
    ) {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut stream = connected(|mut tls| async move {
            // the server is past its handshake writes before the client goes
            tls.write_all(b"go").await.unwrap();
            let mut got = Vec::new();
            let end = tls.read_to_end(&mut got).await;
            let _ = tx.send(end.map(|_| got).map_err(|e| e.kind()));
        })
        .await;
        let mut go = [0u8; 2];
        stream.read_exact(&mut go).await.unwrap();
        (stream, rx)
    }

    /// Dropped without a shutdown, the stream still says close_notify, as
    /// Go's `tls.Conn.Close` does: the server sees a clean end of stream.
    #[tokio::test]
    async fn a_dropped_stream_says_close_notify() {
        let (mut stream, end) = upload_end().await;
        stream.write_all(b"bye").await.unwrap();
        drop(stream);
        assert_eq!(end.await.unwrap(), Ok(b"bye".to_vec()));
    }

    /// Once Vision went Direct the outer TLS frames nothing any more, and no
    /// close_notify goes out, as with Xray (`SuppressOuterCloseNotify`).
    #[tokio::test]
    async fn no_close_notify_after_direct() {
        for write in [true, false] {
            let (mut stream, end) = upload_end().await;
            stream.write_all(b"bye").await.unwrap();
            if write {
                assert!(stream.enable_direct_write());
            } else {
                stream.enable_direct_read();
            }
            drop(stream);
            assert_eq!(
                end.await.unwrap(),
                Err(io::ErrorKind::UnexpectedEof),
                "direct write: {write}"
            );
        }
    }

    /// A vectored write puts its pieces into one record, up to a record's
    /// worth: an h2 frame header and its 16375-byte payload leave as one
    /// 16401-byte record, as from Go's `crypto/tls`, not as two.
    #[tokio::test]
    async fn vectored_pieces_share_one_record() {
        let (tx, rx) = tokio::sync::oneshot::channel();
        let mut stream = connected(|mut tls| async move {
            tls.write_all(b"go").await.unwrap();
            let mut warm = vec![0u8; BOOST_UNTIL as usize];
            tls.read_exact(&mut warm).await.unwrap();
            let mut got = vec![0u8; 9 + 16375 + 100];
            tls.read_exact(&mut got).await.unwrap();
            let _ = tx.send(got);
        })
        .await;
        let mut go = [0u8; 2];
        stream.read_exact(&mut go).await.unwrap();
        assert!(stream.is_write_vectored());
        // past the small records a connection starts with
        stream
            .write_all(&vec![0u8; BOOST_UNTIL as usize])
            .await
            .unwrap();
        let header = [1u8; 9];
        let payload = vec![2u8; 16375];
        let tail = vec![3u8; 100];
        let bufs = [
            io::IoSlice::new(&header),
            io::IoSlice::new(&payload),
            io::IoSlice::new(&tail),
        ];
        let n = stream.write_vectored(&bufs).await.unwrap();
        assert_eq!(n, 16384, "one record's worth");
        assert_eq!(stream.wbuf.len(), 5 + 16384 + 1 + 16, "one full record");
        assert_eq!(u16::from_be_bytes([stream.wbuf[3], stream.wbuf[4]]), 16401);
        // the rest of the last piece follows in the next record
        stream
            .write_all(&tail[100 - (9 + 16375 + 100 - n)..])
            .await
            .unwrap();
        let got = rx.await.unwrap();
        let mut want = header.to_vec();
        want.extend_from_slice(&payload);
        want.extend_from_slice(&tail);
        assert_eq!(got, want);
    }

    /// The records a connection starts with grow like Go's: 1186 bytes of
    /// plaintext, then 2372, 3558 and on by 1186 to 16384, until 128 KiB went
    /// out, and full records from there (`maxPayloadSizeForWrite`).
    #[tokio::test]
    async fn records_grow_like_gos_at_the_start() {
        let mut stream = connected(|mut tls| async move {
            let mut sink = vec![0u8; 1 << 16];
            while tls.read(&mut sink).await.map(|n| n > 0).unwrap_or(false) {}
        })
        .await;
        let mut sizes = Vec::new();
        let chunk = vec![7u8; 1 << 16];
        let mut sent = 0usize;
        while sent < 300 * 1024 {
            let n = stream.write(&chunk).await.unwrap();
            sizes.push(n);
            sent += n;
        }
        let step = 1208 - 5 - 16 - 1;
        let start: Vec<usize> = (1..=13).map(|k| (step * k).min(16384)).collect();
        assert_eq!(&sizes[..13], &start[..], "{sizes:?}");
        // the handshake counts too, so the boost ends a little before
        // 128 KiB of payload; from then on, full records
        let boosted: usize = sizes.iter().take_while(|n| **n < 16384).sum();
        assert!(
            sizes[sizes.len() - 5..].iter().all(|n| *n == 16384),
            "{sizes:?}"
        );
        assert!(boosted < 128 * 1024, "{boosted}");
    }

    /// A write after shutdown is refused and puts nothing on the wire; the
    /// download still runs to its end.
    #[tokio::test]
    async fn a_write_after_shutdown_is_refused() {
        let mut stream = answer_after_eof().await;
        stream.write_all(b"GET").await.unwrap();
        stream.shutdown().await.unwrap();
        let err = stream
            .write(b"late")
            .await
            .expect_err("write after shutdown");
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe, "{err}");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response.len(), 3 * RECORD);
    }

    /// Poll one read with a waker that never fires: Pending when the socket
    /// has nothing more for now.
    fn read_now(stream: &mut FingerprintStream<DuplexStream>) -> Poll<usize> {
        let mut buf = vec![0u8; 8 * RECORD];
        let mut read = ReadBuf::new(&mut buf);
        let mut cx = Context::from_waker(std::task::Waker::noop());
        match Pin::new(stream).poll_read(&mut cx, &mut read) {
            Poll::Ready(r) => {
                r.unwrap();
                Poll::Ready(read.filled().len())
            }
            Poll::Pending => Poll::Pending,
        }
    }

    /// Once everything received is handed over and the socket is quiet, the
    /// connection holds no buffer; the next answer still arrives whole.
    #[tokio::test]
    async fn a_waiting_connection_holds_no_buffers() {
        let (mut stream, ready, _done) = three_records_then(b"").await;
        ready.await.unwrap();
        let mut got = 0;
        while got < 3 * RECORD {
            match read_now(&mut stream) {
                Poll::Ready(n) => got += n,
                Poll::Pending => tokio::task::yield_now().await,
            }
        }
        assert_eq!(got, 3 * RECORD);
        assert!(read_now(&mut stream).is_pending());
        assert_eq!(stream.raw.capacity(), 0, "read buffer kept while waiting");
        assert_eq!(stream.wbuf.capacity(), 0, "write buffer kept while waiting");
        // writing takes a buffer again and the bytes still go out
        stream.write_all(b"more").await.unwrap();
    }

    /// A socket that stops in the middle of a record keeps the part already
    /// read: the buffer holding it is not handed back.
    #[tokio::test]
    async fn a_partial_record_keeps_its_buffer() {
        const PARTIAL: &[u8] = &[0x17, 0x03, 0x03, 0x00, 0x40, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
        let (mut stream, ready, _done) = three_records_then(PARTIAL).await;
        ready.await.unwrap();
        let mut got = 0;
        while got < 3 * RECORD {
            match read_now(&mut stream) {
                Poll::Ready(n) => got += n,
                Poll::Pending => tokio::task::yield_now().await,
            }
        }
        assert!(read_now(&mut stream).is_pending());
        assert!(stream.raw.capacity() > 0, "partial record dropped");
        assert_eq!(&stream.raw[stream.rpos..], PARTIAL);
    }

    /// Everything the server sent is buffered before the first read, so one
    /// read hands over all three records instead of the first one only.
    #[tokio::test]
    async fn one_read_hands_over_every_buffered_record() {
        let (mut stream, ready, _done) = three_records_then(b"").await;
        ready.await.unwrap();
        let mut buf = vec![0; 8 * RECORD];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(n, 3 * RECORD);
        assert!(buf[..n].iter().all(|b| *b == 0x5a));
    }

    /// Vision decides after each record whether the next bytes are still
    /// TLS, so with batching off a read stops at the record boundary.
    #[tokio::test]
    async fn without_batching_a_read_stops_after_one_record() {
        let (mut stream, ready, _done) = three_records_then(b"").await;
        stream.disable_read_batching();
        ready.await.unwrap();
        let mut buf = vec![0; 8 * RECORD];
        for _ in 0..3 {
            assert_eq!(stream.read(&mut buf).await.unwrap(), RECORD);
        }
    }

    /// A broken record behind good ones: the plaintext before it is handed
    /// over first, and the error comes with the next read.
    #[tokio::test]
    async fn a_bad_record_after_good_ones_fails_the_next_read() {
        const BAD: &[u8] = &[
            0x17, 0x03, 0x03, 0x00, 0x20, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
            17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let (mut stream, ready, _done) = three_records_then(BAD).await;
        ready.await.unwrap();
        let mut buf = vec![0; 8 * RECORD];
        assert_eq!(stream.read(&mut buf).await.unwrap(), 3 * RECORD);
        let err = stream.read(&mut buf).await.expect_err("the bad record");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData, "{err}");
    }

    /// A small reader still gets whole records in order, split at its size.
    #[tokio::test]
    async fn a_small_reader_gets_every_byte() {
        let (mut stream, ready, _done) = three_records_then(b"").await;
        ready.await.unwrap();
        let mut total = 0;
        let mut buf = vec![0; 10_000];
        while total < 3 * RECORD {
            let n = stream.read(&mut buf).await.unwrap();
            assert!(n > 0 && n <= buf.len());
            assert!(buf[..n].iter().all(|b| *b == 0x5a));
            total += n;
        }
        assert_eq!(total, 3 * RECORD);
    }
}

#[cfg(test)]
mod close_notify_tests {
    use super::*;
    use core_tls::client::{Config, Handshake};
    use core_tls::rustls::{RootCertStore, ServerConfig};
    use core_tls::verify::WebpkiVerifier;
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A server that answers and closes properly (close_notify, then the
    /// socket) ends our read stream cleanly instead of failing it.
    #[tokio::test]
    async fn close_notify_is_a_clean_end_of_stream() {
        core_tls::install_default_provider();
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.crt")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.key")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let verifier = WebpkiVerifier::new(Arc::new(roots)).unwrap();
        let template = core_tls::fingerprints::by_name("chrome").unwrap();
        let (mut client, peer) = tokio::io::duplex(4 * CHUNK);
        tokio::spawn(async move {
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(peer)
                .await
                .unwrap();
            let mut hello = [0; 2];
            tls.read_exact(&mut hello).await.unwrap();
            tls.write_all(b"answer").await.unwrap();
            // close_notify, then the transport closes
            tls.shutdown().await.unwrap();
        });
        let mut handshake = Handshake::new(Config {
            template: &template,
            server_name: "localhost",
            alpn: &[],
            verifier: &verifier,
            reality: None,
            fragment: false,
            cipher_suites: Vec::new(),
        })
        .unwrap();
        handshake.run(&mut client).await.unwrap();
        let connection = Connection::new(&mut handshake).unwrap();
        let mut stream = FingerprintStream::new(client, connection);
        stream.write_all(b"hi").await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, b"answer");
        // and it stays ended
        let mut more = [0u8; 8];
        assert_eq!(stream.read(&mut more).await.unwrap(), 0);
    }
}

#[cfg(test)]
mod record_shape_tests {
    use super::*;
    use core_tls::client::{Config, Connection, Handshake};
    use core_tls::rustls::{RootCertStore, ServerConfig};
    use core_tls::verify::WebpkiVerifier;
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt, DuplexStream};

    const RECORD: usize = core_tls::record::MAX_FRAGMENT;
    /// A sealed record is its plaintext, the content type byte and the tag,
    /// behind a five-byte header.
    const OVERHEAD: usize = 5 + 1 + 16;

    /// A transport that records the length of every write that reaches it.
    /// One record leaves in one write -- Go writes a record per `conn.Write`
    /// as well, which is what keeps record boundaries and segment boundaries
    /// together -- so these lengths are the records on the wire.
    ///
    /// Once `capture` is on the bytes stop here: a long upload then needs no
    /// reader on the other end, and every write is taken whole, so one record
    /// is one entry.
    struct RecordTap {
        inner: DuplexStream,
        capture: bool,
        writes: Vec<usize>,
    }

    impl RecordTap {
        fn payloads(&self) -> Vec<usize> {
            self.writes.iter().map(|n| n - OVERHEAD).collect()
        }
    }

    impl AsyncRead for RecordTap {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for RecordTap {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            let me = self.get_mut();
            if me.capture {
                me.writes.push(buf.len());
                return Poll::Ready(Ok(buf.len()));
            }
            Pin::new(&mut me.inner).poll_write(cx, buf)
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let me = self.get_mut();
            if me.capture {
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut me.inner).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let me = self.get_mut();
            if me.capture {
                return Poll::Ready(Ok(()));
            }
            Pin::new(&mut me.inner).poll_shutdown(cx)
        }
    }

    /// A handshaked stream whose transport is a tap, with `cap` as the
    /// steady-state record size. The server side only has to finish the
    /// handshake: what the test writes afterwards is captured, not delivered.
    /// The handshake runs through the tap so that `bytes_sent` starts where a
    /// real connection's does.
    async fn tapped(cap: usize) -> FingerprintStream<RecordTap> {
        core_tls::install_default_provider();
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.crt")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.key")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let verifier = WebpkiVerifier::new(Arc::new(roots)).unwrap();
        let template = core_tls::fingerprints::by_name("chrome").unwrap();
        let (client, peer) = tokio::io::duplex(4 * CHUNK);
        tokio::spawn(async move {
            let _tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(peer)
                .await
                .unwrap();
            std::future::pending::<()>().await;
        });
        let mut tap = RecordTap {
            inner: client,
            capture: false,
            writes: Vec::new(),
        };
        let mut handshake = Handshake::new(Config {
            template: &template,
            server_name: "localhost",
            alpn: &[],
            verifier: &verifier,
            reality: None,
            fragment: false,
            cipher_suites: Vec::new(),
        })
        .unwrap();
        handshake.run(&mut tap).await.unwrap();
        let connection = Connection::new(&mut handshake).unwrap();
        let mut stream = FingerprintStream::with_record_cap(tap, connection, cap);
        stream.get_mut().capture = true;
        stream
    }

    /// The growth at the start of a connection is covered by
    /// `records_grow_like_gos_at_the_start`, which checks the plaintext each
    /// write takes. What only the wire shows is the length that growth is
    /// there for: the first record is one segment, 1208 bytes, the figure
    /// Go's `tcpMSSEstimate` is named after.
    #[tokio::test]
    async fn the_first_record_is_one_segment_on_the_wire() {
        let mut stream = tapped(RECORD).await;
        stream.write_all(&vec![0x5a; 64 * 1024]).await.unwrap();
        assert_eq!(stream.get_mut().writes[0], BOOST_STEP + OVERHEAD);
        assert_eq!(stream.get_mut().writes[0], 1208);
    }

    /// A transport whose reference writes at most `buf.Size` keeps that size
    /// after the ramp instead of the fragment limit: Xray relays raw, ws and
    /// httpupgrade streams through 8192-byte buffers, so its steady-state
    /// record is 8214 bytes on the wire, not 16406.
    #[tokio::test]
    async fn a_capped_transport_keeps_the_reference_record_size() {
        let mut stream = tapped(8192).await;
        stream.write_all(&vec![0x5a; 256 * 1024]).await.unwrap();
        let got = stream.get_mut().payloads();
        assert_eq!(got[..6], [1186, 2372, 3558, 4744, 5930, 7116], "the ramp");
        // past the ramp, every record but the write's remainder is the cap
        let capped = &got[6..got.len() - 1];
        assert!(
            capped.iter().all(|n| *n == 8192),
            "capped at the reference's write size: {:?}",
            &capped[..capped.len().min(4)]
        );
        let wire = &stream.get_mut().writes[6..got.len() - 1];
        assert!(wire.iter().all(|n| *n == 8214), "8214 bytes on the wire");
        assert!(capped.len() > 20, "a long enough run: {}", capped.len());
    }

    /// The cap holds for vectored writes too, and the pieces still share one
    /// record: h2 hands over a frame header and its payload apart, and sealed
    /// one by one they made the 1041-byte pairs no reference client sends.
    #[tokio::test]
    async fn vectored_pieces_fill_one_capped_record() {
        let mut stream = tapped(8192).await;
        stream
            .write_all(&vec![0u8; BOOST_UNTIL as usize])
            .await
            .unwrap();
        stream.get_mut().writes.clear();
        let header = [1u8; 9];
        let payload = vec![2u8; 16375];
        let bufs = [io::IoSlice::new(&header), io::IoSlice::new(&payload)];
        let n = stream.write_vectored(&bufs).await.unwrap();
        assert_eq!(n, 8192, "one capped record's worth");
        assert_eq!(stream.get_mut().writes, vec![8214], "one record, one write");
    }

    /// A handshaked stream over a loopback socket, with `cap` as the
    /// steady-state record size and a server that reads and drops: the record
    /// count then shows up as write syscalls, which the tap hides.
    async fn over_loopback(cap: usize) -> FingerprintStream<tokio::net::TcpStream> {
        core_tls::install_default_provider();
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.crt")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.key")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let server_config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs.clone(), key)
            .unwrap();
        let mut roots = RootCertStore::empty();
        roots.add(certs[0].clone()).unwrap();
        let verifier = WebpkiVerifier::new(Arc::new(roots)).unwrap();
        let template = core_tls::fingerprints::by_name("chrome").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let mut tls = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
                .accept(socket)
                .await
                .unwrap();
            let mut sink = vec![0u8; 256 * 1024];
            while tokio::io::AsyncReadExt::read(&mut tls, &mut sink)
                .await
                .unwrap_or(0)
                > 0
            {}
        });
        let mut socket = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut handshake = Handshake::new(Config {
            template: &template,
            server_name: "localhost",
            alpn: &[],
            verifier: &verifier,
            reality: None,
            fragment: false,
            cipher_suites: Vec::new(),
        })
        .unwrap();
        handshake.run(&mut socket).await.unwrap();
        let connection = Connection::new(&mut handshake).unwrap();
        FingerprintStream::with_record_cap(socket, connection, cap)
    }

    /// What the smaller steady-state record costs: the same bytes at 8192 and
    /// at 16384, once with the transport's cost taken out (so what is left is
    /// the sealing) and once over a loopback socket (so the extra record is
    /// also an extra write). Ignored by default, as the other microbenchmarks
    /// here are: run with `--ignored --nocapture`.
    #[tokio::test]
    #[ignore = "microbenchmark"]
    async fn the_capped_record_size_costs_little() {
        const BYTES: usize = 256 * 1024 * 1024;
        let payload = vec![0x5a; 256 * 1024];
        for cap in [RECORD, 8192] {
            let mut stream = tapped(cap).await;
            stream.get_mut().writes = Vec::new();
            let start = std::time::Instant::now();
            for _ in 0..BYTES / payload.len() {
                stream.write_all(&payload).await.unwrap();
            }
            let secs = start.elapsed().as_secs_f64();
            let records = stream.get_mut().writes.len();
            println!(
                "sealing only, cap {cap}: {:.0} MiB/s, {records} records",
                BYTES as f64 / secs / (1024.0 * 1024.0)
            );
        }
        for cap in [RECORD, 8192] {
            let mut stream = over_loopback(cap).await;
            let start = std::time::Instant::now();
            for _ in 0..BYTES / payload.len() {
                stream.write_all(&payload).await.unwrap();
            }
            stream.flush().await.unwrap();
            let secs = start.elapsed().as_secs_f64();
            println!(
                "loopback, cap {cap}: {:.0} MiB/s",
                BYTES as f64 / secs / (1024.0 * 1024.0)
            );
        }
    }

    /// One record per write, as from Go: 64 KiB past the ramp is four full
    /// records in four writes, not a header write and a payload write each.
    #[tokio::test]
    async fn a_record_leaves_in_one_write() {
        let mut stream = tapped(RECORD).await;
        stream
            .write_all(&vec![0u8; BOOST_UNTIL as usize])
            .await
            .unwrap();
        stream.get_mut().writes.clear();
        stream.write_all(&vec![7u8; 4 * RECORD]).await.unwrap();
        assert_eq!(
            stream.get_mut().writes,
            vec![RECORD + OVERHEAD; 4],
            "four records, four writes"
        );
    }
}
