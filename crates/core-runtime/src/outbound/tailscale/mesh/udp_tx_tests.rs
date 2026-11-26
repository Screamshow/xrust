use super::*;
use crate::outbound::tailscale::control::{PeerObj, node_key_str};
use std::{
    future::{Future, poll_fn},
    net::Ipv4Addr,
    pin::{Pin, pin},
    task::Poll,
    time::{Duration, Instant},
};
use tokio::{sync::oneshot, time::timeout};
use x25519_dalek::{PublicKey, StaticSecret};

const TIMEOUT: Duration = Duration::from_secs(2);
const LEFT: [u8; 4] = [100, 64, 0, 1];
const RIGHT: [u8; 4] = [100, 64, 0, 2];
const LOOPBACK: Ipv4Addr = Ipv4Addr::LOCALHOST;

fn peer(key: [u8; 32], address: [u8; 4], port: u16) -> PeerObj {
    PeerObj {
        disco_key: None,
        is_wireguard_only: true,
        home_derp: None,
        id: 1,
        key: node_key_str(&PublicKey::from(key)),
        name: None,
        addresses: vec![format!("{}/32", Ipv4Addr::from(address))],
        allowed_ips: None,
        endpoints: Some(vec![format!("{LOOPBACK}:{port}")]),
        derp: None,
        online: Some(true),
    }
}

fn packet(source: [u8; 4], destination: [u8; 4], marker: u8) -> Vec<u8> {
    let mut packet = vec![marker; 1200];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&1200u16.to_be_bytes());
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet
}

async fn open_pair() -> (DirectMesh, DirectMesh) {
    let mut left = DirectMesh::bind(StaticSecret::from([11; 32]), vec![LEFT.into()], 0)
        .await
        .unwrap();
    let mut right = DirectMesh::bind(StaticSecret::from([12; 32]), vec![RIGHT.into()], 0)
        .await
        .unwrap();
    left.update_peers(&[peer(
        right.public,
        RIGHT,
        right.local_addr().unwrap().port(),
    )]);
    right.update_peers(&[peer(left.public, LEFT, left.local_addr().unwrap().port())]);
    let initial = packet(LEFT, RIGHT, 250);
    left.send(initial.clone()).await.unwrap();
    timeout(TIMEOUT, async {
        loop {
            left.poll().await.unwrap();
            if let Some(received) = right.poll().await.unwrap().pop() {
                assert_eq!(received, initial);
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    (left, right)
}

fn delayed_send(sender: &mut DirectMesh, peer: [u8; 32], packet: &[u8]) -> oneshot::Sender<()> {
    let peer = sender.peers.get_mut(&peer).unwrap();
    let Some(Path::Udp(endpoint)) = peer.active else {
        panic!("direct path required")
    };
    let wire = peer.session.as_mut().unwrap().seal(packet).unwrap();
    let socket = Arc::clone(&sender.socket);
    let (release, gate) = oneshot::channel();
    assert!(sender.udp_tx.pending.is_none());
    sender.udp_tx.pending = Some(PendingBatch {
        packet_count: 1,
        task: tokio::spawn(async move {
            gate.await.unwrap();
            socket.send_to(&wire, endpoint).await.unwrap();
            BatchOutcome {
                gso: UdpGso::ShortTail,
                failed_packets: 0,
            }
        }),
    });
    release
}

async fn assert_waits<T>(mut operation: Pin<&mut impl Future<Output = T>>) {
    poll_fn(|cx| {
        assert!(operation.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn receive(receiver: &mut DirectMesh, count: usize) -> Vec<Vec<u8>> {
    timeout(TIMEOUT, async {
        let mut packets = Vec::new();
        while packets.len() < count {
            receiver.readable().await.unwrap();
            packets.extend(receiver.poll().await.unwrap());
        }
        packets
    })
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_consecutive_background_batches_before_inline_packet() {
    let (mut left, mut right) = open_pair().await;
    let expected: Vec<_> = (0..49).map(|id| packet(LEFT, RIGHT, id)).collect();
    for packets in expected[..48].as_chunks::<24>().0 {
        let mut batch = packets.to_vec();
        assert_eq!(left.send_direct_batch(&mut batch).await, Some(0));
        assert!(batch.is_empty());
        assert!(left.udp_tx.pending.is_some());
    }
    left.send(expected[48].clone()).await.unwrap();
    assert!(left.udp_tx.pending.is_none());
    assert_eq!(receive(&mut right, expected.len()).await, expected);
}

#[tokio::test]
async fn single_worker_sends_bulk_batch_inline() {
    let (mut left, mut right) = open_pair().await;
    let expected: Vec<_> = (0..24).map(|id| packet(LEFT, RIGHT, id)).collect();
    let mut batch = expected.clone();
    assert_eq!(left.send_direct_batch(&mut batch).await, Some(0));
    assert!(batch.is_empty());
    assert!(left.udp_tx.pending.is_none());
    assert_eq!(receive(&mut right, expected.len()).await, expected);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drains_old_transport_before_sending_rekey() {
    let (mut left, mut right) = open_pair().await;
    let old = packet(LEFT, RIGHT, 11);
    let release = delayed_send(&mut left, right.public, &old);
    let left_peer = left.peers.get_mut(&right.public).unwrap();
    left_peer.established = Some(Instant::now() - super::super::REKEY);
    left_peer.last_attempt = None;
    let old_epoch = right.peers[&left.public].established.unwrap();

    {
        let mut operation = pin!(left.poll());
        assert_waits(operation.as_mut()).await;
        release.send(()).unwrap();
        timeout(TIMEOUT, operation).await.unwrap().unwrap();
    }
    assert!(left.udp_tx.pending.is_none());
    assert!(left.peers[&right.public].initiation.is_some());

    let received = timeout(TIMEOUT, async {
        let mut packets = Vec::new();
        while right.peers[&left.public].established == Some(old_epoch) {
            right.readable().await.unwrap();
            packets.extend(right.poll().await.unwrap());
        }
        packets
    })
    .await
    .unwrap();
    assert_eq!(received, [old]);

    timeout(TIMEOUT, left.readable()).await.unwrap().unwrap();
    left.poll().await.unwrap();
    assert!(left.peers[&right.public].initiation.is_none());
    let next = packet(LEFT, RIGHT, 12);
    left.send(next.clone()).await.unwrap();
    assert_eq!(receive(&mut right, 1).await, [next]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drains_old_path_before_accepting_authenticated_roaming() {
    let (mut left, mut right) = open_pair().await;
    let old = packet(LEFT, RIGHT, 21);
    let release = delayed_send(&mut left, right.public, &old);
    let new_socket = UdpSocket::bind((LOOPBACK, 0)).await.unwrap();
    let move_packet = packet(RIGHT, LEFT, 22);
    let sealed = right
        .peers
        .get_mut(&left.public)
        .unwrap()
        .session
        .as_mut()
        .unwrap()
        .seal(&move_packet)
        .unwrap();
    new_socket
        .send_to(&sealed, (LOOPBACK, left.local_addr().unwrap().port()))
        .await
        .unwrap();
    // Ensure the inbound packet is available before polling the mesh. A
    // missing fence would otherwise be masked by socket readiness.
    timeout(TIMEOUT, left.readable()).await.unwrap().unwrap();
    {
        let mut operation = pin!(left.poll());
        assert_waits(operation.as_mut()).await;
    }
    // Cancelling a poll must not detach the old send and let the next poll
    // advance the peer path before the old batch finishes.
    assert!(left.udp_tx.pending.is_some());
    let received = {
        let mut operation = pin!(left.poll());
        assert_waits(operation.as_mut()).await;
        release.send(()).unwrap();
        timeout(TIMEOUT, operation).await.unwrap().unwrap()
    };
    assert_eq!(received, [move_packet]);
    assert_eq!(receive(&mut right, 1).await, [old]);
    assert_eq!(
        left.peers[&right.public].active,
        Some(Path::Udp(new_socket.local_addr().unwrap())),
    );

    let next = packet(LEFT, RIGHT, 23);
    left.send(next.clone()).await.unwrap();
    let mut datagram = [0; 2048];
    let (len, _) = timeout(TIMEOUT, new_socket.recv_from(&mut datagram))
        .await
        .unwrap()
        .unwrap();
    let mut plain = right
        .peers
        .get_mut(&left.public)
        .unwrap()
        .session
        .as_mut()
        .unwrap()
        .open(&datagram[..len])
        .unwrap();
    plain.truncate(next.len());
    assert_eq!(plain, next);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drains_pending_direct_transport_before_derp_fallback() {
    let (mut left, mut right) = open_pair().await;
    let old = packet(LEFT, RIGHT, 31);
    let release = delayed_send(&mut left, right.public, &old);
    let peer = left.peers.get_mut(&right.public).unwrap();
    peer.derp_region = Some(22);
    peer.direct_seen = Some(Instant::now() - Duration::from_secs(7));

    {
        let mut operation = pin!(left.poll());
        assert_waits(operation.as_mut()).await;
        release.send(()).unwrap();
        timeout(TIMEOUT, operation).await.unwrap().unwrap();
    }
    assert!(left.udp_tx.pending.is_none());
    assert_eq!(left.peers[&right.public].active, Some(Path::Derp(22)));
    assert_eq!(receive(&mut right, 1).await, [old]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dropping_mesh_cancels_a_pending_send_and_releases_udp_port() {
    let (mut left, right) = open_pair().await;
    let address = left.local_addr().unwrap();
    let mut release = delayed_send(&mut left, right.public, &packet(LEFT, RIGHT, 41));
    drop(left);
    timeout(TIMEOUT, async {
        release.closed().await;
        loop {
            match UdpSocket::bind(address).await {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::AddrInUse => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                }
                Err(error) => panic!("cannot rebind released UDP port: {error}"),
            }
        }
    })
    .await
    .unwrap();
}
