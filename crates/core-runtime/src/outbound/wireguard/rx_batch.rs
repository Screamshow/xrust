//! Authenticate ready IPv4 transport batches while preserving peer arrival order.

use std::io;
use std::mem;
use std::net::SocketAddr;
use std::sync::{Arc, mpsc};

use core_crypto::fastchacha::ChaChaPoly;
use tokio::sync::oneshot;

use super::{Stack, awg, noise};

const BATCH_SIZE: usize = 32;
const MAX_PACKET: usize = 2048;

struct Packet {
    src: SocketAddr,
    wire_len: usize,
    counter: u64,
    tag: [u8; 16],
    plaintext: Vec<u8>,
    authenticated: bool,
}

impl Packet {
    fn authenticate(&mut self, key: &ChaChaPoly) {
        self.authenticated =
            noise::authenticate_transport(key, self.counter, &mut self.plaintext, &self.tag);
    }
}

struct Work {
    key: Arc<ChaChaPoly>,
    packets: Vec<Packet>,
    reply: oneshot::Sender<Vec<Packet>>,
}

struct Worker {
    sender: mpsc::SyncSender<Work>,
    staging: Vec<Packet>,
}

impl Worker {
    fn start() -> io::Result<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Work>(1);
        std::thread::Builder::new()
            .name("xrust-wg-rx".into())
            .spawn(move || {
                for mut work in receiver {
                    for packet in &mut work.packets {
                        packet.authenticate(&work.key);
                    }
                    let _ = work.reply.send(work.packets);
                }
            })?;
        Ok(Self {
            sender,
            staging: Vec::with_capacity(BATCH_SIZE / 2),
        })
    }
}

pub(super) struct Receiver {
    try_worker: bool,
    worker: Option<Worker>,
    pending: Vec<Packet>,
}

impl Receiver {
    pub(super) fn new() -> Self {
        Self {
            try_worker: true,
            worker: None,
            pending: Vec::with_capacity(BATCH_SIZE),
        }
    }

    pub(super) async fn drain_ready(
        &mut self,
        stack: &mut Stack,
        buffer: &mut [u8],
    ) -> io::Result<()> {
        for _ in 0..64 {
            let Ok((length, src)) = stack.sock.try_recv_from(buffer) else {
                break;
            };
            let wire = &buffer[..length];
            if let Some(packet) = prepare(stack, wire, src) {
                self.pending.push(packet);
                if self.pending.len() == BATCH_SIZE {
                    self.flush(stack).await?;
                }
            } else {
                self.flush(stack).await?;
                stack.process_inbound(wire, src);
            }
        }
        self.flush(stack).await
    }

    async fn flush(&mut self, stack: &mut Stack) -> io::Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let key = Arc::clone(
            &stack.peers[0]
                .session
                .as_ref()
                .expect("prepared under current session")
                .recv_cipher,
        );
        let large = self
            .pending
            .iter()
            .map(|p| p.plaintext.len())
            .sum::<usize>()
            >= 16 * 1024;
        if large && self.try_worker && self.worker.is_none() {
            self.try_worker = false;
            self.worker = Worker::start().ok();
        }
        if large && let Some(worker) = &mut self.worker {
            let mut staging = mem::take(&mut worker.staging);
            staging.extend(self.pending.drain(self.pending.len().div_ceil(2)..));
            let (reply, result) = oneshot::channel();
            // The actor flushes at most one batch at a time. Keep ownership if the worker exited.
            match worker.sender.try_send(Work {
                key: Arc::clone(&key),
                packets: staging,
                reply,
            }) {
                Ok(()) => {
                    for packet in &mut self.pending {
                        packet.authenticate(&key);
                    }
                    match result.await {
                        Ok(done) => worker.staging = done,
                        Err(_) => {
                            for packet in self.pending.drain(..) {
                                commit(stack, &key, packet);
                            }
                            self.worker = None;
                            return Ok(());
                        }
                    }
                    for packet in self.pending.drain(..).chain(worker.staging.drain(..)) {
                        commit(stack, &key, packet);
                    }
                    return Ok(());
                }
                Err(mpsc::TrySendError::Full(work) | mpsc::TrySendError::Disconnected(work)) => {
                    worker.staging = work.packets;
                    self.pending.append(&mut worker.staging);
                }
            }
        }
        for mut packet in self.pending.drain(..) {
            packet.authenticate(&key);
            commit(stack, &key, packet);
        }
        Ok(())
    }
}

fn prepare(stack: &mut Stack, wire: &[u8], src: SocketAddr) -> Option<Packet> {
    if wire.len() > MAX_PACKET || (stack.cfg.awg.is_none() && wire.get(1..4) != Some(&[0, 0, 0])) {
        return None;
    }
    let (kind, prefix) = awg::demux(stack.cfg.awg.as_deref(), wire, &|index| {
        stack.index_peer.contains_key(&index)
    })?;
    if kind != noise::MSG_TRANSPORT {
        return None;
    }
    let message = &wire[prefix..];
    let session = stack.peers[0].session.as_ref()?;
    let (counter, ciphertext, tag) = session.transport_parts(message)?;
    let mut plaintext = stack.device.free.get_mut().pop().unwrap_or_default();
    plaintext.clear();
    plaintext.extend_from_slice(ciphertext);
    Some(Packet {
        src,
        wire_len: message.len(),
        counter,
        tag: *tag,
        plaintext,
        authenticated: false,
    })
}

fn commit(stack: &mut Stack, key: &Arc<ChaChaPoly>, packet: Packet) {
    let accepted = packet.authenticated
        && stack.peers[0].session.as_mut().is_some_and(|session| {
            Arc::ptr_eq(key, &session.recv_cipher) && session.accept_counter(packet.counter)
        });
    if accepted {
        stack.accepted_transport(0, packet.wire_len, packet.src, packet.plaintext);
    } else {
        stack.recycle(packet.plaintext);
    }
}

#[cfg(test)]
mod epoch_tests {
    use super::super::tests::{compat_session, compat_stack};
    use super::*;

    #[tokio::test]
    async fn old_key_completion_cannot_advance_replacement_session() {
        let (mut stack, _) = compat_stack(serde_json::json!({})).await;
        let mut peer = compat_session(&mut stack);
        let src = stack.peers[0].resolved.unwrap();
        let old = Arc::clone(&stack.peers[0].session.as_ref().unwrap().recv_cipher);
        let mut wire = Vec::new();
        assert!(peer.seal_into(&[], 0, 0, &mut wire));
        let mut packet = prepare(&mut stack, &wire, src).unwrap();
        packet.authenticate(&old);
        assert!(packet.authenticated);
        let (mut replacement, _) = compat_stack(serde_json::json!({})).await;
        let mut new_peer = compat_session(&mut replacement);
        stack.peers[0].session = replacement.peers[0].session.take();
        stack.peers[0].last_recv = None;
        commit(&mut stack, &old, packet);
        assert!(stack.peers[0].last_recv.is_none());
        // Counter zero is still available to the replacement session.
        let mut new_wire = Vec::new();
        assert!(new_peer.seal_into(&[], 0, 0, &mut new_wire));
        let msg_counter = u64::from_le_bytes(new_wire[8..16].try_into().unwrap());
        let old_counter = u64::from_le_bytes(wire[8..16].try_into().unwrap());
        assert_eq!(msg_counter, old_counter);
        let mut plain = Vec::new();
        assert!(
            stack.peers[0]
                .session
                .as_mut()
                .unwrap()
                .open_into(&new_wire, &mut plain)
        );
    }
}
