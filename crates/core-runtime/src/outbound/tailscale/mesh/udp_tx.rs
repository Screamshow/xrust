use super::{DirectMesh, Path, REKEY, TUN_TX_BATCH, noise, send_datagram};
use crate::outbound::wireguard::{UdpGso, send_some};
use std::{io, net::SocketAddr, sync::Arc};
use tokio::{net::UdpSocket, task::JoinHandle};

#[cfg(test)]
#[path = "udp_tx_tests.rs"]
mod tests;

const MIN_PARALLEL_BYTES: usize = 16 * 1024;
const MIN_PARALLEL_PACKETS: usize = 16;

struct SealJob {
    nonce: noise::PreparedSeal,
    packet: Vec<u8>,
}

type WireBatch = Vec<(SocketAddr, Vec<u8>)>;

fn seal_batch(endpoint: SocketAddr, jobs: Vec<SealJob>) -> WireBatch {
    jobs.into_iter()
        .map(|job| {
            let mut wire = Vec::new();
            // Match Session::seal's padding and transport header exactly.
            job.nonce.seal(
                &job.packet,
                job.packet.len().next_multiple_of(16),
                0,
                &mut wire,
            );
            (endpoint, wire)
        })
        .collect()
}

struct BatchOutcome {
    gso: UdpGso,
    failed_packets: usize,
}

struct PendingBatch {
    task: JoinHandle<BatchOutcome>,
    packet_count: usize,
}

pub(super) struct UdpTx {
    gso: UdpGso,
    pending: Option<PendingBatch>,
    failed_packets: usize,
}

impl Default for UdpTx {
    fn default() -> Self {
        Self {
            gso: UdpGso::ShortTail,
            pending: None,
            failed_packets: 0,
        }
    }
}

impl UdpTx {
    pub(super) async fn finish(&mut self) {
        let Some(pending) = &mut self.pending else {
            return;
        };
        // Keep ownership of the handle if the caller is cancelled.
        match (&mut pending.task).await {
            Ok(outcome) => {
                self.gso = outcome.gso;
                self.failed_packets += outcome.failed_packets;
            }
            Err(error) => {
                crate::logging::warn(format_args!("tailscale: UDP send task: {error}"));
                self.failed_packets += pending.packet_count;
            }
        }
        self.pending = None;
    }

    pub(super) fn take_failures(&mut self) -> usize {
        std::mem::take(&mut self.failed_packets)
    }

    async fn submit(
        &mut self,
        socket: &Arc<UdpSocket>,
        first: WireBatch,
        second_len: usize,
        second: JoinHandle<WireBatch>,
    ) {
        // Sealing the next batch can overlap the previous send. Wait before
        // giving another task write access to the socket or the GSO mode.
        self.finish().await;
        let socket = Arc::clone(socket);
        let packet_count = first.len() + second_len;
        let mut gso = std::mem::replace(&mut self.gso, UdpGso::ShortTail);
        let task = tokio::spawn(async move {
            send_sealed_batch(&socket, &first, &mut gso).await;
            let failed_packets = match second.await {
                Ok(wire) => {
                    send_sealed_batch(&socket, &wire, &mut gso).await;
                    0
                }
                Err(error) => {
                    crate::logging::warn(format_args!("tailscale: UDP seal worker: {error}"));
                    second_len
                }
            };
            BatchOutcome {
                gso,
                failed_packets,
            }
        });
        self.pending = Some(PendingBatch { task, packet_count });
    }
}

impl Drop for UdpTx {
    fn drop(&mut self) {
        if let Some(pending) = &self.pending {
            pending.task.abort();
        }
    }
}

impl DirectMesh {
    /// Bulk forwarding for one established direct peer. Keep the ordinary
    /// path for control traffic, DERP, rekeys and mixed destinations.
    pub(super) async fn send_direct_batch(&mut self, packets: &mut Vec<Vec<u8>>) -> Option<usize> {
        if !(4..=TUN_TX_BATCH).contains(&packets.len()) {
            return None;
        }
        let (destination, _) = self.packet_route(&packets[0]).ok()?;
        let mut bytes = 0;
        let mut lengths = [0; TUN_TX_BATCH];
        for (packet, len) in packets.iter().zip(&mut lengths) {
            let (dest, length) = self.packet_route(packet).ok()?;
            if dest != destination {
                return None;
            }
            *len = length;
            bytes += length;
        }
        let (_, peer) = self
            .peers
            .iter_mut()
            .find(|(_, p)| p.addresses.contains(&destination))?;
        if !peer.confirmed
            || !peer.pending.is_empty()
            || peer.initiation.is_some()
            || peer.established.is_none_or(|time| time.elapsed() >= REKEY)
        {
            return None;
        }
        peer.payload();
        peer.fallback();
        let (Some(Path::Udp(endpoint)), Some(session)) = (peer.active, peer.session.as_mut())
        else {
            return None;
        };
        if !session.can_reserve_seals(packets.len()) {
            return None;
        }
        if let (Some(relay), Some(region)) = (self.relay.as_mut(), peer.derp_region) {
            relay.prepare(region);
        }

        // Allocate nonces on the mesh task. Workers only own already assigned
        // counters and immutable keys. Emit the first half while the second
        // seals. Non-bulk writes and mesh transitions fence the pending send.
        let jobs: Vec<_> = packets
            .drain(..)
            .zip(lengths)
            .map(|(mut packet, length)| {
                packet.truncate(length);
                SealJob {
                    nonce: session.reserve_seal().expect("batch counters checked"),
                    packet,
                }
            })
            .collect();
        if jobs.len() >= MIN_PARALLEL_PACKETS
            && bytes >= MIN_PARALLEL_BYTES
            && tokio::runtime::Handle::current().metrics().num_workers() > 1
        {
            let mut first = jobs;
            let second = first.split_off(first.len() / 2);
            let second_len = second.len();
            let worker = tokio::task::spawn_blocking(move || seal_batch(endpoint, second));
            let wire = seal_batch(endpoint, first);
            self.udp_tx
                .submit(&self.socket, wire, second_len, worker)
                .await;
        } else {
            let wire = seal_batch(endpoint, jobs);
            self.finish_udp_tx().await;
            send_sealed_batch(&self.socket, &wire, &mut self.udp_tx.gso).await;
        }
        Some(0)
    }
}

async fn send_sealed_batch(
    socket: &UdpSocket,
    mut wire: &[(SocketAddr, Vec<u8>)],
    gso: &mut UdpGso,
) {
    while let Some((endpoint, _)) = wire.first() {
        match send_some(socket, wire, gso) {
            // The helper reports the exact datagrams submitted from this
            // slice. Its try_io call clears Tokio readiness on EAGAIN.
            Ok(count) => wire = &wire[count.max(1)..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if socket.writable().await.is_err() {
                    break;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) if matches!(error.raw_os_error(), Some(libc::ENOSYS | libc::EPERM)) => {
                for (endpoint, packet) in wire {
                    send_datagram(socket, packet, *endpoint).await;
                }
                break;
            }
            Err(error) => {
                crate::logging::debug(format_args!("tailscale: send to {endpoint}: {error}"));
                wire = &wire[1..];
            }
        }
    }
}
