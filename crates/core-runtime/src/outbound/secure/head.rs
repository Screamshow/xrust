//! A request head that waits for the first payload, so both leave in one write.
//!
//! Over TLS one write is one record, so a head written and flushed on its own
//! is an application-data record of a few dozen bytes that no browser sends.
//! Xray's clients never do that while the client talks first: the head goes into
//! a `BufferedWriter`, the first payload read within a short wait is written
//! behind it, and one flush sends both. When nothing comes in time -- a
//! destination that speaks first, such as SSH or SMTP -- the head goes alone.
//! When the client is gone before it sent anything, Xray sends nothing at all.
//!
//! The streams that use this keep it next to the transport they write to and
//! drive it from all four poll functions: a write joins the head, a read
//! waits out the deadline (nothing can come back before the server has the
//! head), a flush sends the head if the deadline already let it go, and a
//! shutdown before any payload drops it.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};
use std::time::Duration;

use tokio::io::AsyncWrite;

enum State {
    /// Not written yet; joins the first payload, or goes alone at the deadline.
    Waiting(Vec<u8>),
    /// On its way: `buf[pos..]` is left, and `claimed` bytes of it are the
    /// caller's payload (0 when the head went alone).
    Writing {
        buf: Vec<u8>,
        pos: usize,
        claimed: usize,
    },
    /// Written, or dropped because the client left first: every call passes
    /// straight through.
    Done,
}

pub(crate) struct PendingHead {
    state: State,
    /// the most bytes the head's write may carry, head included
    first_write: usize,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    /// the head went out from the read side and still needs a flush
    flush_head: bool,
}

impl PendingHead {
    /// `head` waits up to `wait` for the first payload. An empty `head` (ws
    /// early data carried all of it) means there is nothing left to send.
    pub(crate) fn new(head: Vec<u8>, wait: Duration, first_write: usize) -> Self {
        if head.is_empty() {
            return Self::sent();
        }
        Self {
            state: State::Waiting(head),
            first_write,
            deadline: Some(Box::pin(tokio::time::sleep(wait))),
            flush_head: false,
        }
    }

    /// Nothing to send: every call passes straight through.
    pub(crate) fn sent() -> Self {
        Self {
            state: State::Done,
            first_write: 0,
            deadline: None,
            flush_head: false,
        }
    }

    pub(crate) fn is_sent(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// The head is still waiting for its payload, and when it stops waiting.
    #[cfg(target_os = "linux")]
    pub(crate) fn waiting_until(&self) -> Option<tokio::time::Instant> {
        match (&self.state, &self.deadline) {
            (State::Waiting(_), Some(deadline)) => Some(deadline.deadline()),
            _ => None,
        }
    }

    /// Write out the head in flight; ready with the payload bytes it carried.
    fn poll_head<S>(&mut self, inner: &mut S, cx: &mut Context<'_>) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        let State::Writing { buf, pos, claimed } = &mut self.state else {
            return Poll::Ready(Ok(0));
        };
        while *pos < buf.len() {
            let n = ready!(Pin::new(&mut *inner).poll_write(cx, &buf[*pos..]))?;
            if n == 0 {
                return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
            }
            *pos += n;
        }
        let claimed = *claimed;
        self.state = State::Done;
        self.deadline = None;
        Poll::Ready(Ok(claimed))
    }

    /// Send the head without a payload: the wait is over.
    pub(crate) fn start_alone(&mut self) {
        if let State::Waiting(head) = &mut self.state {
            let buf = std::mem::take(head);
            self.state = State::Writing {
                buf,
                pos: 0,
                claimed: 0,
            };
        }
    }

    /// The client left before its first byte: like Xray, which returns from
    /// the request without flushing the buffered head, nothing is sent.
    pub(crate) fn abandon(&mut self) {
        if matches!(self.state, State::Waiting(_)) {
            self.state = State::Done;
            self.deadline = None;
        }
    }

    /// Before a read: wait out the deadline and send the head alone if no
    /// payload came, then flush it.
    pub(crate) fn poll_before_read<S>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            match &self.state {
                // nothing can come back before the server has the head
                State::Waiting(_) => {
                    if let Some(deadline) = self.deadline.as_mut() {
                        ready!(deadline.as_mut().poll(cx));
                    }
                    self.start_alone();
                }
                State::Writing { claimed: 0, .. } => {
                    ready!(self.poll_head(inner, cx))?;
                    self.flush_head = true;
                }
                // a write is carrying the head with its payload: that write
                // finishes it, and reading meanwhile is fine
                _ => break,
            }
        }
        if self.flush_head {
            ready!(Pin::new(&mut *inner).poll_flush(cx))?;
            self.flush_head = false;
        }
        Poll::Ready(Ok(()))
    }

    pub(crate) fn poll_write<S>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        loop {
            match &mut self.state {
                State::Done => return Pin::new(&mut *inner).poll_write(cx, buf),
                State::Waiting(head) => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let take = buf
                        .len()
                        .min(self.first_write.saturating_sub(head.len()).max(1));
                    let mut joined = std::mem::take(head);
                    joined.extend_from_slice(&buf[..take]);
                    self.state = State::Writing {
                        buf: joined,
                        pos: 0,
                        claimed: take,
                    };
                }
                State::Writing { .. } => {
                    let claimed = ready!(self.poll_head(inner, cx))?;
                    if claimed > 0 {
                        // this write's payload went out with the head
                        return Poll::Ready(Ok(claimed));
                    }
                    // the head went alone; `buf` follows it as usual
                }
            }
        }
    }

    pub(crate) fn poll_flush<S>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        if matches!(self.state, State::Writing { claimed: 0, .. }) {
            ready!(self.poll_head(inner, cx))?;
        }
        self.flush_head = false;
        Pin::new(&mut *inner).poll_flush(cx)
    }

    /// Before a shutdown: a head still waiting for its payload is dropped, one
    /// already on its way is finished.
    pub(crate) fn poll_before_shutdown<S>(
        &mut self,
        inner: &mut S,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>>
    where
        S: AsyncWrite + Unpin + ?Sized,
    {
        self.abandon();
        if matches!(self.state, State::Writing { .. }) {
            ready!(self.poll_head(inner, cx))?;
        }
        Poll::Ready(Ok(()))
    }
}
