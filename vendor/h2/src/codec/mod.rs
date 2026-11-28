mod error;
mod framed_read;
mod framed_write;
mod payload_pool;

pub use self::error::{SendError, UserError};

use self::framed_read::FramedRead;
use self::framed_write::FramedWrite;

use crate::frame::{self, Data, Frame};
use crate::proto::Error;

use bytes::Buf;
use futures_core::Stream;
use futures_sink::Sink;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::{self, Sleep};
use tokio_util::codec::length_delimited;
use tokio_util::codec::FramedRead as InnerFramedRead;

use std::io;

const INITIAL_BUFFER_CAPACITY: usize = 32 * 1024;
const BUFFER_IDLE_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug)]
pub struct Codec<T, B> {
    inner: FramedRead<FramedWrite<T, B>>,
    buffer_idle: Option<Pin<Box<Sleep>>>,
}

impl<T, B> Codec<T, B>
where
    T: AsyncRead + AsyncWrite + Unpin,
    B: Buf,
{
    /// Returns a new `Codec` with the default max frame size
    #[inline]
    pub fn new(io: T) -> Self {
        Self::with_max_recv_frame_size(io, frame::DEFAULT_MAX_FRAME_SIZE as usize)
    }

    /// Returns a new `Codec` with the given maximum frame size
    pub fn with_max_recv_frame_size(io: T, max_frame_size: usize) -> Self {
        // Wrap with writer
        let framed_write = FramedWrite::new(io);

        let codec = length_delimited::Builder::new()
            .big_endian()
            .length_field_length(3)
            .length_adjustment(9)
            .num_skip(0) // Don't skip the header
            .new_codec();
        let delimited =
            InnerFramedRead::with_capacity(framed_write, codec, INITIAL_BUFFER_CAPACITY);

        let mut inner = FramedRead::new(delimited);

        // Use FramedRead's method since it checks the value is within range.
        inner.set_max_frame_size(max_frame_size);

        Codec {
            inner,
            buffer_idle: None,
        }
    }
}

impl<T, B> Codec<T, B> {
    pub(crate) fn set_recycle_data(&mut self, enabled: bool) {
        self.inner.set_recycle_data(enabled);
    }

    /// Updates the max received frame size.
    ///
    /// The change takes effect the next time a frame is decoded. In other
    /// words, if a frame is currently in process of being decoded with a frame
    /// size greater than `val` but less than the max frame size in effect
    /// before calling this function, then the frame will be allowed.
    #[inline]
    pub fn set_max_recv_frame_size(&mut self, val: usize) {
        self.inner.set_max_frame_size(val)
    }

    /// Returns the current max received frame size setting.
    ///
    /// This is the largest size this codec will accept from the wire. Larger
    /// frames will be rejected.
    #[cfg(feature = "unstable")]
    #[inline]
    pub fn max_recv_frame_size(&self) -> usize {
        self.inner.max_frame_size()
    }

    /// Returns the max frame size that can be sent to the peer.
    pub fn max_send_frame_size(&self) -> usize {
        self.inner.get_ref().max_frame_size()
    }

    /// Set the peer's max frame size.
    pub fn set_max_send_frame_size(&mut self, val: usize) {
        self.framed_write().set_max_frame_size(val)
    }

    /// Set the peer's header table size size.
    pub fn set_send_header_table_size(&mut self, val: usize) {
        self.framed_write().set_header_table_size(val)
    }

    /// Set the decoder header table size size.
    pub fn set_recv_header_table_size(&mut self, val: usize) {
        self.inner.set_header_table_size(val)
    }

    /// Set the max header list size that can be received.
    pub fn set_max_recv_header_list_size(&mut self, val: usize) {
        self.inner.set_max_header_list_size(val);
    }

    /// Get a reference to the inner stream.
    #[cfg(feature = "unstable")]
    pub fn get_ref(&self) -> &T {
        self.inner.get_ref().get_ref()
    }

    /// Get a mutable reference to the inner stream.
    pub fn get_mut(&mut self) -> &mut T {
        self.inner.get_mut().get_mut()
    }

    /// Takes the data payload value that was fully written to the socket
    pub(crate) fn take_last_data_frame(&mut self) -> Option<Data<B>> {
        self.framed_write().take_last_data_frame()
    }

    fn framed_write(&mut self) -> &mut FramedWrite<T, B> {
        self.inner.get_mut()
    }
}

impl<T, B> Codec<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    /// Called after the connection has finished flushing all pending writes.
    pub(crate) fn poll_idle_buffers(
        &mut self,
        cx: &mut Context<'_>,
        has_streams: impl FnOnce() -> bool,
    ) {
        let trim_read = self.inner.can_trim_buffer();
        let trim_write = self.framed_write().can_trim_buffer();
        if !(trim_read || trim_write) || has_streams() {
            self.buffer_idle = None;
            return;
        }

        let timer = self
            .buffer_idle
            .get_or_insert_with(|| Box::pin(time::sleep(BUFFER_IDLE_TIMEOUT)));
        if timer.as_mut().poll(cx).is_ready() {
            if trim_read {
                self.inner.trim_buffer();
            }
            if trim_write {
                self.framed_write().trim_buffer();
            }
            self.buffer_idle = None;
        }
    }

    /// Returns `Ready` when the codec can buffer a frame
    pub fn poll_ready(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.framed_write().poll_ready(cx)
    }

    /// Returns whether the codec can buffer a frame without flushing the
    /// underlying I/O object.
    pub(crate) fn has_send_capacity(&mut self) -> bool {
        self.framed_write().has_capacity()
    }

    /// xrust: see `FramedWrite::set_frame_per_write`.
    pub(crate) fn set_frame_per_write(&mut self, on: bool) {
        self.framed_write().set_frame_per_write(on)
    }

    pub(crate) fn finish_credit_pair(&mut self) {
        self.framed_write().finish_credit_pair();
    }

    pub(crate) fn prepare_credit_pair(&mut self) -> bool {
        self.framed_write().prepare_credit_pair()
    }

    /// xrust: see `FramedWrite::buffer_raw`.
    pub(crate) fn buffer_raw(&mut self, data: &[u8]) {
        self.framed_write().buffer_raw(data)
    }

    /// Buffer a frame.
    ///
    /// `poll_ready` must be called first to ensure that a frame may be
    /// accepted.
    ///
    /// TODO: Rename this to avoid conflicts with Sink::buffer
    pub fn buffer(&mut self, item: Frame<B>) -> Result<(), UserError> {
        if self.buffer_idle.is_some()
            && matches!(
                item,
                Frame::Headers(_) | Frame::Data(_) | Frame::PushPromise(_)
            )
        {
            self.buffer_idle = None;
        }
        self.framed_write().buffer(item)
    }

    /// Flush buffered data to the wire
    pub fn flush(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.framed_write().flush(cx)
    }

    /// Shutdown the send half
    pub fn shutdown(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        self.framed_write().shutdown(cx)
    }
}

impl<T, B> Stream for Codec<T, B>
where
    T: AsyncRead + Unpin,
{
    type Item = Result<Frame, Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let result = Pin::new(&mut self.inner).poll_next(cx);
        if self.buffer_idle.is_some()
            && matches!(
                result,
                Poll::Ready(Some(Ok(Frame::Headers(_)
                    | Frame::Data(_)
                    | Frame::PushPromise(_))))
            )
        {
            self.buffer_idle = None;
        }
        result
    }
}

impl<T, B> Sink<Frame<B>> for Codec<T, B>
where
    T: AsyncWrite + Unpin,
    B: Buf,
{
    type Error = SendError;

    fn start_send(mut self: Pin<&mut Self>, item: Frame<B>) -> Result<(), Self::Error> {
        Codec::buffer(&mut self, item)?;
        Ok(())
    }
    /// Returns `Ready` when the codec can buffer a frame
    fn poll_ready(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.framed_write().poll_ready(cx).map_err(Into::into)
    }

    /// Flush buffered data to the wire
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.framed_write().flush(cx).map_err(Into::into)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        ready!(self.shutdown(cx))?;
        Poll::Ready(Ok(()))
    }
}

// TODO: remove (or improve) this
impl<T> From<T> for Codec<T, bytes::Bytes>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    fn from(src: T) -> Self {
        Self::new(src)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::future::poll_fn;
    use tokio::io::{duplex, AsyncWriteExt};

    #[tokio::test]
    async fn idle_buffer_trim_preserves_partial_frame_and_write_batching() {
        let (io, mut peer) = duplex(256 * 1024);
        let mut codec = Codec::<_, Bytes>::with_max_recv_frame_size(io, 96 * 1024);
        let stream = frame::StreamId::from(1);
        let payload = Bytes::from(vec![0x42; 96 * 1024]);
        // Write a valid DATA frame in two pieces, stopping partway through its
        // payload. The frame exceeds the initial read buffer.
        peer.write_all(&[1, 128, 0, 0, 0, 0, 0, 0, 1])
            .await
            .unwrap();
        peer.write_all(&payload[..4096]).await.unwrap();
        poll_fn(|cx| {
            assert!(Pin::new(&mut codec).poll_next(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        assert!(!codec.inner.can_trim_buffer());
        peer.write_all(&payload[4096..]).await.unwrap();
        let frame = poll_fn(|cx| Pin::new(&mut codec).poll_next(cx)).await;
        assert!(matches!(frame, Some(Ok(Frame::Data(data))) if data.payload() == &payload));
        assert!(codec.inner.can_trim_buffer());

        // A 32 KiB backing allocation still accepts the same batch as 128 KiB.
        for _ in 0..6 {
            assert!(codec.has_send_capacity());
            codec
                .buffer(Frame::Data(Data::new(stream, payload.slice(..16 * 1024))))
                .unwrap();
        }
        assert!(!codec.has_send_capacity());
        assert!(!codec.framed_write().can_trim_buffer());
        poll_fn(|cx| codec.flush(cx)).await.unwrap();
        assert!(codec.framed_write().can_trim_buffer());

        poll_fn(|cx| {
            codec.poll_idle_buffers(cx, || true);
            assert!(codec.buffer_idle.is_none());
            codec.poll_idle_buffers(cx, || false);
            assert!(codec.buffer_idle.is_some());
            Poll::Ready(())
        })
        .await;
        assert!(codec.inner.can_trim_buffer());
        assert!(codec.framed_write().can_trim_buffer());
        let elapsed = time::Instant::now() - BUFFER_IDLE_TIMEOUT;
        codec.buffer_idle.as_mut().unwrap().as_mut().reset(elapsed);
        poll_fn(|cx| {
            codec.poll_idle_buffers(cx, || false);
            if codec.buffer_idle.is_none() {
                Poll::Ready(())
            } else {
                Poll::Pending
            }
        })
        .await;
        assert!(!codec.inner.can_trim_buffer());
        assert!(!codec.framed_write().can_trim_buffer());
    }
}
