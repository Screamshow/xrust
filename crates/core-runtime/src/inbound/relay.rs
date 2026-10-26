//! Kernel-side relay for plain TCP <-> TCP connections (Linux).
//!
//! `copy_bidirectional` and the tracked loop both move every byte through a
//! userspace buffer: a `read` into it, a `write` out of it, two copies across the
//! syscall boundary plus a pair of zeroed buffers per connection that stay
//! resident for as long as the connection lives. `splice(2)` moves the pages
//! between the two sockets inside the kernel instead, so the relay costs two
//! syscalls per chunk, no copy and no per-connection buffer.
//!
//! A direction takes its pipe only when the first byte shows up, so an idle
//! connection costs two sockets and nothing else. When a pipe cannot be had
//! (fd limit) that one direction drops to a small buffered loop instead of
//! failing the connection.
//!
//! A Vision upstream on TLS over TCP joins once its download is Direct: see
//! `relay_vision`.

use std::io;
use std::os::fd::{AsRawFd, RawFd};
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, Interest, ReadBuf};
use tokio::net::TcpStream;

use super::{
    AnyStream, Counted, HalfOpen, PooledBuffer, TransferState, take_buf, transfer_one_direction,
};
use crate::clash_state::ConnHandle;

/// Largest bytes asked from one splice, and the size a busy pipe grows to. One
/// stream needs this much in flight to keep both sockets fed: 256 KiB measured
/// 15-21 Gbit/s on a single stream, 1 MiB measured 51.
const CHUNK: usize = 1024 * 1024;
/// What a fresh pipe asks for: starts at 1 MiB so single-stream and short
/// transfers immediately hit line rate without a 4-splice ramp.
const PIPE_START: usize = 1024 * 1024;
/// Chunk of the buffered fallback, deliberately small: it only runs when fds
/// are scarce, and so is memory.
const FALLBACK_CHUNK: usize = 16 * 1024;

/// A non-blocking pipe pair that closes with its owner.
struct Pipe {
    read: RawFd,
    write: RawFd,
}

impl Pipe {
    fn new() -> io::Result<Self> {
        let mut fds = [0 as RawFd; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let pipe = Self {
            read: fds[0],
            write: fds[1],
        };
        let _ = unsafe { libc::fcntl(pipe.write, libc::F_SETPIPE_SZ, PIPE_START as libc::c_int) };
        Ok(pipe)
    }
}

impl Drop for Pipe {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.read);
            libc::close(self.write);
        }
    }
}

/// One `splice(2)` between two fds, one of which is a pipe. `EAGAIN` becomes
/// `WouldBlock`, which is what `async_io` waits on.
fn splice(from: RawFd, to: RawFd, len: usize) -> io::Result<usize> {
    let n = unsafe {
        libc::splice(
            from,
            std::ptr::null_mut(),
            to,
            std::ptr::null_mut(),
            len,
            libc::SPLICE_F_NONBLOCK | libc::SPLICE_F_MOVE,
        )
    };
    if n < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(n as usize)
    }
}

fn shutdown_write(stream: &TcpStream) {
    // the peer may already be gone; the half-close is a courtesy, not a duty
    let _ = socket2::SockRef::from(stream).shutdown(std::net::Shutdown::Write);
}

/// Write all of `data` to a non-blocking socket without needing `&mut`.
async fn write_all(stream: &TcpStream, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let n = match stream.try_write(data) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                stream
                    .async_io(Interest::WRITABLE, || stream.try_write(data))
                    .await?
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }
        data = &data[n..];
    }
    Ok(())
}

/// Consume a vless response head (`[version][addonsLen][addons]`) off a
/// non-blocking socket, reading exactly its bytes and no more so the rest stays
/// for the splice.
async fn skip_vless_head(from: &TcpStream) -> io::Result<()> {
    async fn fill(from: &TcpStream, buf: &mut [u8]) -> io::Result<()> {
        let mut got = 0;
        while got < buf.len() {
            let n = match from.try_read(&mut buf[got..]) {
                Ok(n) => n,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    from.async_io(Interest::READABLE, || from.try_read(&mut buf[got..]))
                        .await?
                }
                Err(e) => return Err(e),
            };
            if n == 0 {
                return Err(io::Error::other("vless: connection closed before response"));
            }
            got += n;
        }
        Ok(())
    }
    let mut head = [0u8; 2];
    fill(from, &mut head).await?;
    if head[0] != 0x00 {
        return Err(io::Error::other("bad vless response version"));
    }
    let mut addons = vec![0u8; usize::from(head[1])];
    fill(from, &mut addons).await
}

/// Move bytes `from` -> `to` until `from` reaches EOF, then half-close `to`.
/// With `head` the source first owes a vless response head, which is dropped.
/// `close` passes the end of `from` on to `to` as a FIN; without it `to`
/// is left open (a VLESS upstream, see `relay`).
async fn one_way(
    from: &TcpStream,
    to: &TcpStream,
    head: bool,
    close: bool,
    count: impl Fn(u64),
) -> io::Result<()> {
    if head {
        skip_vless_head(from).await?;
    }
    // an idle connection takes no pipe: wait for the first byte
    from.readable().await?;
    let Ok(pipe) = Pipe::new() else {
        return one_way_buffered(from, to, close, count).await;
    };
    let (from_fd, to_fd) = (from.as_raw_fd(), to.as_raw_fd());
    loop {
        let n = match splice(from_fd, pipe.write, CHUNK) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                from.async_io(Interest::READABLE, || splice(from_fd, pipe.write, CHUNK))
                    .await?
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            if close {
                shutdown_write(to);
            }
            return Ok(());
        }
        let mut left = n;
        while left > 0 {
            let m = match splice(pipe.read, to_fd, left) {
                Ok(m) => m,
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                    to.async_io(Interest::WRITABLE, || splice(pipe.read, to_fd, left))
                        .await?
                }
                Err(e) => return Err(e),
            };
            if m == 0 {
                return Err(io::ErrorKind::WriteZero.into());
            }
            left -= m;
        }
        count(n as u64);
    }
}

/// The same direction through a small userspace buffer.
async fn one_way_buffered(
    from: &TcpStream,
    to: &TcpStream,
    close: bool,
    count: impl Fn(u64),
) -> io::Result<()> {
    let mut buf = vec![0u8; FALLBACK_CHUNK];
    loop {
        let n = match from.try_read(&mut buf) {
            Ok(n) => n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {
                from.async_io(Interest::READABLE, || from.try_read(&mut buf))
                    .await?
            }
            Err(e) => return Err(e),
        };
        if n == 0 {
            if close {
                shutdown_write(to);
            }
            return Ok(());
        }
        write_all(to, &buf[..n]).await?;
        count(n as u64);
    }
}

/// Relay both directions of an established connection until both sides are
/// done. `prefix` is what the sniffer already read off the client: it goes
/// upstream first. `vless_head` says the upstream still owes a vless response
/// head. A `tracker` feeds the Clash view and makes `DELETE
/// /connections/{id}` end the relay; without one the loop just moves the bytes
/// — the kernel path must not cost the connection its `splice(2)` because the
/// connection registry happens to be off.
pub(crate) async fn relay(
    client: &TcpStream,
    upstream: &TcpStream,
    prefix: &[u8],
    tracker: Option<&ConnHandle>,
    vless_head: bool,
    half: &HalfOpen,
) -> io::Result<()> {
    if !prefix.is_empty() {
        write_all(upstream, prefix).await?;
        if let Some(tracker) = tracker {
            tracker.add_upload(prefix.len() as u64);
        }
    }
    let both = async {
        tokio::try_join!(
            async {
                // a VLESS upstream is not told the upload ended, as Xray's
                // client does not tell it (see `VlessStream::poll_shutdown`)
                one_way(client, upstream, false, !vless_head, |n| {
                    if let Some(tracker) = tracker {
                        tracker.add_upload(n)
                    }
                })
                .await
                .inspect(|()| half.finish())
            },
            async {
                one_way(upstream, client, vless_head, true, |n| {
                    if let Some(tracker) = tracker {
                        tracker.add_download(n)
                    }
                })
                .await
                .inspect(|()| half.finish())
            },
        )
        .map(|_| ())
    };
    let Some(tracker) = tracker else {
        return both.await;
    };
    let signal = tracker.close_signal();
    tokio::select! {
        biased;
        result = both => result,
        _ = signal.wait() => Err(super::closed_by_api()),
    }
}

/// Download of a Vision connection. Vision lets the server stop outer TLS
/// ("Direct"); after that the upstream socket carries the payload as is, and
/// once every byte read off it before the switch has reached the client the
/// kernel can take over. Xray splices this direction only, and so do we.
enum Down {
    /// userspace, until the upstream reports its reads raw and drained
    Watch(PooledBuffer, bool),
    /// userspace for good: no pipe could be had
    Copy(PooledBuffer),
    /// the kernel, with how much of the last chunk is still in the pipe
    Splice(Option<Pipe>, usize),
    /// download over, the write half to the client is being shut
    Closing,
    Done,
}

/// Reads the upstream until its Vision reads are Direct with nothing left in
/// any buffer above the socket, then reports end of stream and sets `switch`.
struct UntilRaw<'a> {
    inner: &'a mut AnyStream,
    switch: &'a mut bool,
}

impl AsyncRead for UntilRaw<'_> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if *this.switch || super::vision_direct_socket((**this.inner).as_any()).is_some() {
            *this.switch = true;
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut *this.inner).poll_read(cx, buf)
    }
}

/// `one_way` as a poll: socket -> pipe -> socket until `from` reaches EOF,
/// then half-close `to`. `left` is what the pipe still holds.
fn poll_spliced(
    cx: &mut Context<'_>,
    pipe: &Pipe,
    left: &mut usize,
    from: &TcpStream,
    to: &TcpStream,
    count: impl Fn(u64),
) -> Poll<io::Result<()>> {
    let (from_fd, to_fd) = (from.as_raw_fd(), to.as_raw_fd());
    loop {
        while *left > 0 {
            ready!(to.poll_write_ready(cx))?;
            let want = *left;
            match to.try_io(Interest::WRITABLE, || splice(pipe.read, to_fd, want)) {
                Ok(0) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Ok(m) => {
                    *left -= m;
                    count(m as u64);
                }
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        // the pipe is empty here, so EAGAIN means the socket has nothing
        ready!(from.poll_read_ready(cx))?;
        match from.try_io(Interest::READABLE, || splice(from_fd, pipe.write, CHUNK)) {
            Ok(0) => {
                shutdown_write(to);
                return Poll::Ready(Ok(()));
            }
            Ok(n) => *left = n,
            Err(ref e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => return Poll::Ready(Err(e)),
        }
    }
}

fn poll_down<S>(
    cx: &mut Context<'_>,
    state: &mut Down,
    client: &mut S,
    upstream: &mut AnyStream,
    tracker: Option<&ConnHandle>,
    spliced: &mut bool,
) -> Poll<io::Result<()>>
where
    S: AsyncRead + AsyncWrite + Unpin + std::any::Any,
{
    loop {
        match state {
            Down::Watch(buf, switch) => {
                let mut reader = UntilRaw {
                    inner: &mut *upstream,
                    switch: &mut *switch,
                };
                let mut writer = Counted {
                    inner: &mut *client,
                    tracker,
                };
                ready!(buf.poll_copy(cx, Pin::new(&mut reader), Pin::new(&mut writer)))?;
                // the buffer is empty and flushed: everything read so far is
                // with the client
                let switched = *switch;
                *state = if switched {
                    Down::Splice(None, 0)
                } else {
                    Down::Closing
                };
            }
            Down::Copy(buf) => {
                let mut writer = Counted {
                    inner: &mut *client,
                    tracker,
                };
                ready!(buf.poll_copy(cx, Pin::new(&mut *upstream), Pin::new(&mut writer)))?;
                *state = Down::Closing;
            }
            Down::Splice(pipe, left) => {
                let from = super::vision_direct_socket((**upstream).as_any());
                let to = super::client_raw_tcp(&*client);
                let (Some(from), Some(to)) = (from, to) else {
                    return Poll::Ready(Err(io::Error::other("vision splice lost its socket")));
                };
                if pipe.is_none() {
                    // an idle download takes no pipe until its next byte
                    ready!(from.poll_read_ready(cx))?;
                    match Pipe::new() {
                        Ok(new) => *pipe = Some(new),
                        Err(_) => {
                            // nothing was taken off the socket: the stream
                            // reads it straight through from here
                            *state = Down::Copy(PooledBuffer::new(take_buf()));
                            continue;
                        }
                    }
                    *spliced = true;
                }
                let Some(pipe) = pipe.as_ref() else {
                    continue;
                };
                ready!(poll_spliced(cx, pipe, left, from, to, |n| {
                    if let Some(tracker) = tracker {
                        tracker.add_download(n)
                    }
                }))?;
                *state = Down::Done;
            }
            Down::Closing => {
                let mut writer = Counted {
                    inner: &mut *client,
                    tracker,
                };
                ready!(Pin::new(&mut writer).poll_shutdown(cx))?;
                *state = Down::Done;
            }
            Down::Done => return Poll::Ready(Ok(())),
        }
    }
}

/// Relay a client socket and a Vision upstream until both directions are
/// done. The upload stays in userspace (Vision writes raw by itself once
/// Direct). The download is copied like `copy_bidirectional_pooled` until the
/// upstream's reads are Direct and every buffered byte is with the client,
/// then moves socket to socket in the kernel. Returns whether it did.
///
/// Counters and half-close follow the userspace relay; `DELETE
/// /connections/{id}` is the caller's `select!`.
pub(crate) async fn relay_vision<S>(
    client: &mut S,
    upstream: &mut AnyStream,
    tracker: Option<&ConnHandle>,
    half: &HalfOpen,
) -> io::Result<bool>
where
    S: AsyncRead + AsyncWrite + Unpin + std::any::Any,
{
    let mut up = TransferState::Running(PooledBuffer::new(take_buf()));
    let mut down = Down::Watch(PooledBuffer::new(take_buf()), false);
    let mut spliced = false;
    std::future::poll_fn(|cx| {
        let res_up = {
            let mut counted = Counted {
                inner: &mut *client,
                tracker,
            };
            transfer_one_direction(cx, &mut up, &mut counted, &mut *upstream)?
        };
        let res_down = poll_down(
            cx,
            &mut down,
            &mut *client,
            &mut *upstream,
            tracker,
            &mut spliced,
        )?;
        if res_up.is_ready() || res_down.is_ready() {
            half.finish();
        }
        ready!(res_up);
        ready!(res_down);
        Poll::Ready(Ok::<(), io::Error>(()))
    })
    .await?;
    Ok(spliced)
}

#[cfg(test)]
mod vision_tests;
