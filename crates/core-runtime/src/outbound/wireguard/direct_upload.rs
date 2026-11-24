//! Give the endpoint owned writes directly. Local acknowledgements bound
//! admission by both bytes and block count when the peer stops reading.
use super::*;
type CmdPermit = Result<mpsc::OwnedPermit<Cmd>, mpsc::error::SendError<()>>;

pub(super) struct Writer {
    id: u32,
    tx: mpsc::Sender<Cmd>,
    reserve: Option<Pin<Box<dyn Future<Output = CmdPermit> + Send>>>,
    outstanding: VecDeque<(usize, oneshot::Receiver<()>)>,
    bytes: usize,
    busy: Arc<AtomicBool>,
    closed: bool,
    runtime: tokio::runtime::Handle,
}
impl Writer {
    pub(super) fn new(id: u32, tx: mpsc::Sender<Cmd>, busy: Arc<AtomicBool>) -> Self {
        Self {
            id,
            tx,
            reserve: None,
            outstanding: VecDeque::new(),
            bytes: 0,
            busy,
            closed: false,
            runtime: tokio::runtime::Handle::current(),
        }
    }
    fn permit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<mpsc::OwnedPermit<Cmd>>> {
        if self.reserve.is_none() {
            match self.tx.clone().try_reserve_owned() {
                Ok(p) => return Poll::Ready(Ok(p)),
                Err(mpsc::error::TrySendError::Full(tx)) => {
                    self.reserve = Some(Box::pin(tx.reserve_owned()))
                }
                Err(mpsc::error::TrySendError::Closed(_)) => {
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
            }
        }
        let result = ready!(self.reserve.as_mut().unwrap().as_mut().poll(cx));
        self.reserve = None;
        Poll::Ready(result.map_err(|_| io::ErrorKind::BrokenPipe.into()))
    }
}
impl AsyncWrite for Writer {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        while let Some((_, accepted)) = self.outstanding.front_mut() {
            match Pin::new(accepted).poll(cx) {
                Poll::Ready(Ok(())) => {
                    self.bytes -= self.outstanding.pop_front().unwrap().0;
                }
                Poll::Ready(Err(_)) => return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into())),
                Poll::Pending => break,
            }
        }
        let busy = self.busy.load(Ordering::Acquire);
        if (busy || data.len() < 4096) && !self.outstanding.is_empty() {
            return Poll::Pending;
        }
        let budget = if busy { SCRATCH_BUF } else { 2 * CALLER_BUF };
        if self.bytes >= budget || self.outstanding.len() >= 8 {
            return Poll::Pending;
        }
        let n = data.len().min(budget - self.bytes).min(CALLER_BUF);
        let permit = ready!(self.permit(cx))?;
        let (consumed, accepted) = oneshot::channel();
        permit.send(Cmd::TcpData {
            id: self.id,
            bytes: data[..n].to_vec(),
            consumed,
        });
        self.bytes += n;
        self.outstanding.push_back((n, accepted));
        Poll::Ready(Ok(n))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.closed {
            let p = ready!(self.permit(cx))?;
            p.send(Cmd::TcpClose { id: self.id });
            self.closed = true;
        }
        Poll::Ready(Ok(()))
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        if self.closed {
            return;
        }
        self.reserve = None;
        if let Err(mpsc::error::TrySendError::Full(cmd)) =
            self.tx.try_send(Cmd::TcpClose { id: self.id })
        {
            let tx = self.tx.clone();
            self.runtime.spawn(async move {
                let _ = tx.send(cmd).await;
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn stopped_receiver_bounds_admission_and_shutdown_orders_fin() {
        let (tx, mut rx) = mpsc::channel(16);
        let busy = Arc::new(AtomicBool::new(false));
        let mut writer = Writer::new(71, tx, busy.clone());
        let payload = vec![91; CALLER_BUF];
        writer.write_all(&payload).await.unwrap();
        writer.write_all(&payload).await.unwrap();
        let mut acks = Vec::new();
        for _ in 0..2 {
            let Cmd::TcpData {
                id,
                bytes,
                consumed,
            } = rx.recv().await.unwrap()
            else {
                panic!("expected TCP data")
            };
            assert_eq!(id, 71);
            assert_eq!(bytes, payload);
            acks.push(consumed);
        }
        let too_soon = std::time::Duration::from_millis(10);
        assert!(
            tokio::time::timeout(too_soon, writer.write(&payload))
                .await
                .is_err()
        );
        busy.store(true, Ordering::Release);
        acks.pop().unwrap().send(()).unwrap();
        assert!(
            tokio::time::timeout(too_soon, writer.write(&payload))
                .await
                .is_err()
        );
        acks.pop().unwrap().send(()).unwrap();
        assert_eq!(writer.write(&payload).await.unwrap(), SCRATCH_BUF);
        writer.shutdown().await.unwrap();
        drop(writer);
        assert!(matches!(rx.recv().await, Some(Cmd::TcpData { id: 71, .. })));
        assert!(matches!(rx.recv().await, Some(Cmd::TcpClose { id: 71 })));
        assert!(rx.recv().await.is_none());
    }
}
