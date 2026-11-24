//! Keep encryption and UDP writes ordered while the endpoint polls smoltcp.
//! At most two batches are in flight. Control traffic and the serial path
//! drain earlier submissions before writing to either socket.
use super::*;
type Wire = (SocketAddr, Vec<u8>);
struct Job {
    key: noise::PreparedSeal,
    padded_len: usize,
    reserved: [u8; 3],
    packet: Vec<u8>,
}
#[derive(Default)]
struct Batch {
    jobs: Vec<Job>,
    wire: Vec<Wire>,
    plain: Vec<Vec<u8>>,
}

pub(super) struct Sender {
    send: std::sync::mpsc::SyncSender<Batch>,
    done: std::sync::mpsc::Receiver<Batch>,
    pending: std::cell::Cell<u8>,
    spare: std::cell::RefCell<Vec<Batch>>,
}
impl Sender {
    fn new(sock: Arc<UdpSocket>, tag: String) -> Option<Self> {
        let (send, work) = std::sync::mpsc::sync_channel::<Batch>(2);
        let (wire, sealed) = std::sync::mpsc::sync_channel::<Batch>(1);
        let (done, recv) = std::sync::mpsc::sync_channel(2);
        std::thread::Builder::new()
            .name("xrust-wg-send".into())
            .spawn(move || {
                let mut gso = UdpGso::Equal;
                while let Ok(b) = sealed.recv() {
                    send_datagrams(&sock, &b.wire, &tag, &mut gso);
                    if done.send(b).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        std::thread::Builder::new()
            .name("xrust-wg-seal".into())
            .spawn(move || {
                while let Ok(mut b) = work.recv() {
                    for (job, (_, msg)) in b.jobs.drain(..).zip(&mut b.wire) {
                        job.key.seal(&job.packet, job.padded_len, 0, msg);
                        msg[1..4].copy_from_slice(&job.reserved);
                        b.plain.push(job.packet);
                    }
                    if wire.send(b).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Self {
            send,
            done: recv,
            pending: 0.into(),
            spare: Default::default(),
        })
    }
    fn collect(&self, limit: u8) {
        while self.pending.get() > 0 {
            let b = if self.pending.get() >= limit {
                match self.done.recv() {
                    Ok(batch) => batch,
                    Err(_) => {
                        self.pending.set(0);
                        break;
                    }
                }
            } else if let Ok(b) = self.done.try_recv() {
                b
            } else {
                break;
            };
            self.pending.set(self.pending.get() - 1);
            self.spare.borrow_mut().push(b);
        }
    }
    pub(super) fn fence(&self) {
        self.collect(1);
    }
}

#[derive(Default)]
pub(super) struct Load {
    start: Option<Instant>,
    bytes: usize,
    enabled: bool,
}
impl Load {
    fn observe(&mut self, bytes: usize) -> bool {
        let now = Instant::now();
        let elapsed = now.duration_since(*self.start.get_or_insert(now));
        self.bytes += bytes;
        if elapsed >= std::time::Duration::from_millis(8) {
            self.enabled = (self.bytes as u128) * 8 >= elapsed.as_micros() * 200;
            self.start = Some(now);
            self.bytes = 0;
        }
        self.enabled
    }
}
impl Stack {
    pub(super) fn offload_transport(&mut self) -> bool {
        if !self.threaded_upload
            || self
                .receive_activity
                .as_ref()
                .is_some_and(handoff::ReceiveActivity::active)
            || self.cfg.awg.is_some()
            || self.device.tx.len() < 8
            || self.peers.len() != 1
        {
            return false;
        }
        let Some(addr @ SocketAddr::V4(_)) = self.peers[0].resolved else {
            return false;
        };
        let count = self.device.tx.len().min(SEND_BATCH);
        let bytes = self
            .device
            .tx
            .iter()
            .take(count)
            .map(Vec::len)
            .sum::<usize>();
        if bytes < 8192
            || !self.tx_load.observe(bytes)
            || !self
                .device
                .tx
                .iter()
                .take(count)
                .all(|p| ip_dst(p).and_then(|d| self.lpm(d)) == Some(0))
        {
            return false;
        }
        let peer = &mut self.peers[0];
        let Some(session) = peer.session.as_mut() else {
            return false;
        };
        if !session.can_seal_transport() {
            return false;
        }
        if self.tx_sender.is_none() {
            self.tx_sender = Sender::new(self.sock.clone(), self.cfg.tag.clone());
            if self.tx_sender.is_none() {
                self.threaded_upload = false;
            }
        }
        let Some(worker) = &mut self.tx_sender else {
            return false;
        };
        worker.collect(2);
        let mut batch = worker.spare.get_mut().pop().unwrap_or_default();
        for pkt in batch.plain.drain(..) {
            if self.device.free.get_mut().len() < 64 {
                self.device.free.get_mut().push(pkt);
            }
        }
        self.wire_buffers
            .extend(batch.wire.drain(..).map(|(_, msg)| msg));
        for _ in 0..count {
            let Some(key) = session.reserve_seal() else {
                break;
            };
            let packet = self.device.tx.pop_front().expect("count from queue");
            let padded_len =
                packet.len() + awg::normal_transport_padding(packet.len(), self.cfg.mtu);
            batch.jobs.push(Job {
                key,
                packet,
                padded_len,
                reserved: peer.endpoint.reserved,
            });
            batch
                .wire
                .push((addr, self.wire_buffers.pop().unwrap_or_default()));
        }
        peer.reactive_keepalive = None;
        peer.another_keepalive = false;
        peer.last_sent = Some(Instant::now());
        if let Err(error) = worker.send.send(batch) {
            // No worker accepted this batch. Its counters have already been
            // reserved, so retire them and let TCP recover any lost data.
            for job in error.0.jobs {
                self.recycle(job.packet);
            }
            self.threaded_upload = false;
            self.tx_sender = None;
            return true;
        }
        worker.pending.set(worker.pending.get() + 1);
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn two_batches_reach_udp_in_counter_order_before_control() {
        let (mut stack, sink) = super::super::tests::compat_stack(serde_json::json!({})).await;
        let mut peer = super::super::tests::compat_session(&mut stack);
        stack.threaded_upload = true;
        let src = Ipv4Addr::new(10, 66, 66, 2);
        let dst = Ipv4Addr::new(10, 66, 66, 1);
        for start in [0u8, 12] {
            for i in start..start + 12 {
                stack
                    .device
                    .tx
                    .push_back(build_ipv4_udp(src, dst, 1234, 4321, &[i; 1100]));
            }
            stack.tx_load.start = Some(Instant::now() - Duration::from_millis(10));
            stack.tx_load.bytes = 2 * 1024 * 1024;
            assert!(stack.offload_transport());
        }
        stack.send_raw(0, b"done");
        let mut expected = 0u8;
        let mut last = None;
        tokio::time::timeout(Duration::from_secs(2), async {
            let mut wire = [0u8; 2048];
            loop {
                let n = sink.recv(&mut wire).await.unwrap();
                if &wire[..n] == b"done" {
                    break;
                }
                if n < 32 || wire[0] != 4 {
                    continue;
                }
                let counter = u64::from_le_bytes(wire[8..16].try_into().unwrap());
                let inner = peer.open(&wire[..n]).unwrap();
                if inner.is_empty() {
                    continue;
                }
                if let Some(last) = last {
                    assert_eq!(counter, last + 1);
                }
                last = Some(counter);
                assert_eq!(&inner[28..1128], &[expected; 1100]);
                expected += 1;
            }
        })
        .await
        .unwrap();
        assert_eq!(expected, 24);
    }
}
