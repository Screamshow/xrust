//! The caller owns both pumps and a lifetime signal independent of receive EOF.
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{Notify, mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

use super::stack::{CallerState, Cmd, TcpSignals};
use crate::inbound::AnyStream;

pub(super) fn bridge(
    id: u32,
    commands: mpsc::Sender<Cmd>,
    wake: Arc<Notify>,
    local: DuplexStream,
    remote: DuplexStream,
    mut replies: mpsc::Receiver<Vec<u8>>,
    signals: Arc<TcpSignals>,
) -> AnyStream {
    let (mut read, mut write) = tokio::io::split(local);
    let upload = tokio::spawn(async move {
        let mut buffer = vec![0; super::SCRATCH_BUF];
        loop {
            let result = tokio::select! {
                biased;
                _ = commands.closed() => return Err(stack_stopped()),
                result = read.read(&mut buffer) => result,
            };
            match result {
                Ok(0) => {
                    commands
                        .send(Cmd::TcpClose { id })
                        .await
                        .map_err(|_| stack_stopped())?;
                    return Ok(());
                }
                Err(error) => {
                    let _ = commands.send(Cmd::TcpClose { id }).await;
                    return Err(error);
                }
                Ok(n) => {
                    let (consumed, accepted) = oneshot::channel();
                    if commands
                        .send(Cmd::TcpData {
                            id,
                            bytes: buffer[..n].to_vec(),
                            consumed,
                        })
                        .await
                        .is_err()
                        || accepted.await.is_err()
                    {
                        return Err(stack_stopped());
                    }
                }
            }
        }
    });
    let download_signals = Arc::clone(&signals);
    let download_wake = Arc::clone(&wake);
    let download = tokio::spawn(async move {
        while let Some(bytes) = replies.recv().await {
            if download_signals.read_stalled.swap(false, Ordering::SeqCst) {
                download_wake.notify_one();
            }
            if write.write_all(&bytes).await.is_err() {
                break;
            }
        }
        let _ = write.shutdown().await;
    })
    .abort_handle();
    Box::new(CallerStream {
        inner: remote,
        upload: Some(upload),
        download,
        signals,
        wake,
        write_shutdown: false,
    })
}

struct CallerStream {
    inner: DuplexStream,
    upload: Option<JoinHandle<io::Result<()>>>,
    download: AbortHandle,
    signals: Arc<TcpSignals>,
    wake: Arc<Notify>,
    write_shutdown: bool,
}

impl Drop for CallerStream {
    fn drop(&mut self) {
        self.signals.set_caller_state(if self.write_shutdown {
            CallerState::Draining
        } else {
            CallerState::Cancelled
        });
        self.wake.notify_one();
        if let Some(upload) = &self.upload {
            upload.abort();
        }
        self.download.abort();
    }
}

impl AsyncRead for CallerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CallerStream {
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
        std::task::ready!(Pin::new(&mut self.inner).poll_shutdown(cx))?;
        if let Some(upload) = &mut self.upload {
            // Duplex shutdown only marks its ring EOF. The relay may drop us
            // immediately afterwards (the receive half can already be closed).
            // Wait until all bytes were accepted and TcpClose was enqueued.
            let result = std::task::ready!(Pin::new(upload).poll(cx));
            self.upload.take();
            let result = result.unwrap_or_else(|error| Err(io::Error::other(error)));
            self.write_shutdown = result.is_ok();
            return Poll::Ready(result);
        }
        Poll::Ready(if self.write_shutdown {
            Ok(())
        } else {
            Err(stack_stopped())
        })
    }
}

fn stack_stopped() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "masque: stack task stopped")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::time::timeout;

    #[tokio::test]
    async fn shutdown_waits_for_accepted_upload_before_normal_drop() {
        let (tx, mut rx) = mpsc::channel(1);
        let (_replies, reply_rx) = mpsc::channel(1);
        let (local, remote) = tokio::io::duplex(32);
        let mut stream = bridge(
            1,
            tx,
            Arc::new(Notify::new()),
            local,
            remote,
            reply_rx,
            Arc::new(TcpSignals::default()),
        );
        stream.write_all(b"write after receive EOF").await.unwrap();
        let mut shutdown = tokio::spawn(async move {
            stream.shutdown().await.unwrap();
            stream
        });
        let Cmd::TcpData { consumed, .. } = rx.recv().await.unwrap() else {
            panic!("expected data")
        };
        assert!(
            timeout(Duration::from_millis(30), &mut shutdown)
                .await
                .is_err(),
            "shutdown completed before stack acceptance"
        );
        consumed.send(()).unwrap();
        assert!(matches!(rx.recv().await, Some(Cmd::TcpClose { id: 1 })));
        let stream = timeout(Duration::from_secs(1), shutdown)
            .await
            .unwrap()
            .unwrap();
        drop(stream);
    }

    #[tokio::test]
    async fn full_stack_queue_and_stack_exit_release_the_writer() {
        let (tx, mut rx) = mpsc::channel(1);
        let (replies, reply_rx) = mpsc::channel(1);
        let (local, remote) = tokio::io::duplex(32);
        let mut stream = bridge(
            1,
            tx,
            Arc::new(Notify::new()),
            local,
            remote,
            reply_rx,
            Arc::new(TcpSignals::default()),
        );
        stream.write_all(&[7; 32]).await.unwrap();
        // One block is awaiting actual stack acceptance. The next write must
        // backpressure instead of feeding an unbounded per-connection queue.
        let first = timeout(Duration::from_secs(1), rx.recv())
            .await
            .unwrap()
            .unwrap();
        let Cmd::TcpData { consumed, .. } = first else {
            panic!("expected upload")
        };
        stream.write_all(&[8; 32]).await.unwrap();
        assert!(
            timeout(Duration::from_millis(30), stream.write_all(&[9; 32]))
                .await
                .is_err()
        );
        drop(consumed);
        drop(rx);
        drop(replies);
        assert!(
            timeout(Duration::from_secs(1), stream.write_all(&[9; 32]))
                .await
                .unwrap()
                .is_err()
        );
        let mut byte = [0];
        assert_eq!(
            timeout(Duration::from_secs(1), stream.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    }

    #[tokio::test]
    async fn dropping_the_caller_releases_both_pumps() {
        let (tx, mut rx) = mpsc::channel(1);
        let (replies, reply_rx) = mpsc::channel(1);
        let (local, remote) = tokio::io::duplex(32);
        let mut stream = bridge(
            1,
            tx,
            Arc::new(Notify::new()),
            local,
            remote,
            reply_rx,
            Arc::new(TcpSignals::default()),
        );
        stream.write_all(b"queued").await.unwrap();
        let first = rx.recv().await.unwrap();
        drop(stream);
        timeout(Duration::from_secs(1), replies.closed())
            .await
            .unwrap();
        let Cmd::TcpData { mut consumed, .. } = first else {
            panic!("expected upload")
        };
        timeout(Duration::from_secs(1), consumed.closed())
            .await
            .unwrap();
    }
}
