//! Local encrypted peer for the WG and Tailscale outbound lifecycle tests.
//! No control-plane credentials, TUN device, routing or external peer is needed.
use std::collections::VecDeque;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpCidr};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::inbound::AnyStream;
use crate::outbound::wireguard::noise;

pub(crate) const CLIENT_KEY: [u8; 32] = [91; 32];
const SERVER_KEY: [u8; 32] = [73; 32];

pub(crate) fn public(key: [u8; 32]) -> [u8; 32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(key)).to_bytes()
}

pub(crate) fn b64(key: [u8; 32]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(key)
}

#[derive(Default)]
pub(crate) struct Evidence {
    pub tcp_bytes: usize,
    pub client_fin: bool,
    pub udp_sent: u64,
    pub udp_requests: u64,
}

pub(crate) struct Peer {
    pub address: SocketAddr,
    pub stats: Arc<Mutex<Evidence>>,
    pub paused: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}

impl Peer {
    pub fn public_key(&self) -> [u8; 32] {
        public(SERVER_KEY)
    }
}

impl Drop for Peer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[derive(Default)]
struct PacketDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
}

struct PacketRx(Vec<u8>);
impl RxToken for PacketRx {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct PacketTx<'a>(&'a mut VecDeque<Vec<u8>>);
impl TxToken for PacketTx<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut packet = vec![0; len];
        let result = f(&mut packet);
        self.0.push_back(packet);
        result
    }
}

impl Device for PacketDevice {
    type RxToken<'a> = PacketRx;
    type TxToken<'a> = PacketTx<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1280;
        caps
    }

    fn receive(&mut self, _: SmolInstant) -> Option<(PacketRx, PacketTx<'_>)> {
        self.rx
            .pop_front()
            .map(|packet| (PacketRx(packet), PacketTx(&mut self.tx)))
    }

    fn transmit(&mut self, _: SmolInstant) -> Option<PacketTx<'_>> {
        Some(PacketTx(&mut self.tx))
    }
}

pub(crate) async fn peer(ip: &str, wait_for_client_fin: bool, response: Vec<u8>) -> Peer {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let stats = Arc::new(Mutex::new(Evidence::default()));
    let evidence = stats.clone();
    let paused = Arc::new(AtomicBool::new(false));
    let pause = paused.clone();
    let ip: IpAddr = ip.parse().unwrap();
    let task = tokio::spawn(async move {
        let mut device = PacketDevice::default();
        let mut iface = Interface::new(
            Config::new(HardwareAddress::Ip),
            &mut device,
            SmolInstant::now(),
        );
        iface.update_ip_addrs(|ips| ips.push(IpCidr::new(ip.into(), 32)).unwrap());
        iface
            .routes_mut()
            .add_default_ipv4_route(std::net::Ipv4Addr::UNSPECIFIED)
            .unwrap();
        let mut sockets = SocketSet::new(vec![]);
        let mut tcp = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 65536]),
            tcp::SocketBuffer::new(vec![0; 65536]),
        );
        tcp.listen(4321).unwrap();
        let th = sockets.add(tcp);
        let mut udp = udp::Socket::new(
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65536]),
            udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 65536]),
        );
        udp.bind(1234).unwrap();
        let uh = sockets.add(udp);
        let mut session: Option<noise::Session> = None;
        let mut endpoint = None;
        let mut rx = [0; 65536];
        let mut requested = false;
        let mut written = 0;
        let mut udp_to = None;
        let mut udp_at = Instant::now();
        loop {
            for _ in 0..64 {
                let Ok((n, source)) = socket.try_recv_from(&mut rx) else {
                    break;
                };
                match noise::type_word(&rx[..n]) {
                    Some(1) => {
                        let init =
                            noise::process_initiation(&SERVER_KEY, &public(SERVER_KEY), &rx[..n])
                                .unwrap();
                        assert_eq!(init.sender_static_pub, public(CLIENT_KEY));
                        let (response, next) = noise::build_response(&init, &SERVER_KEY, None, 2);
                        socket.send_to(&response, source).await.unwrap();
                        session = Some(next);
                        endpoint = Some(source);
                    }
                    Some(4) => {
                        if let Some(plain) = session.as_mut().and_then(|s| s.open(&rx[..n]))
                            && !plain.is_empty()
                        {
                            device.rx.push_back(plain);
                        }
                    }
                    _ => {}
                }
            }
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            let tcp = sockets.get_mut::<tcp::Socket>(th);
            while tcp.can_recv() {
                let mut bytes = [0; 4096];
                let n = tcp.recv_slice(&mut bytes).unwrap();
                evidence.lock().unwrap().tcp_bytes += n;
                requested = true;
            }
            let client_fin = requested && !tcp.may_recv();
            evidence.lock().unwrap().client_fin |= client_fin;
            if requested && (!wait_for_client_fin || client_fin) && tcp.can_send() {
                if written < response.len() {
                    written += tcp.send_slice(&response[written..]).unwrap();
                }
                if written == response.len() {
                    tcp.close();
                }
            }
            let udp = sockets.get_mut::<udp::Socket>(uh);
            while let Ok((_, metadata)) = udp.recv() {
                udp_to = Some(metadata.endpoint);
                evidence.lock().unwrap().udp_requests += 1;
            }
            if let Some(to) = udp_to
                && !pause.load(Ordering::Relaxed)
                && udp_at.elapsed() >= Duration::from_millis(100)
            {
                let sequence = evidence.lock().unwrap().udp_sent + 1;
                udp.send_slice(&sequence.to_be_bytes(), to).unwrap();
                evidence.lock().unwrap().udp_sent = sequence;
                udp_at = Instant::now();
            }
            iface.poll(SmolInstant::now(), &mut device, &mut sockets);
            while let Some(packet) = device.tx.pop_front() {
                if let (Some(s), Some(to)) = (&mut session, endpoint)
                    && let Some(sealed) = s.seal(&packet)
                {
                    socket.send_to(&sealed, to).await.unwrap();
                }
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    });
    Peer {
        address,
        stats,
        paused,
        task,
    }
}

pub(crate) async fn tcp_eof(mut stream: AnyStream, peer: &Peer, local_fin: bool, expected: &[u8]) {
    stream.write_all(b"request").await.unwrap();
    if local_fin {
        stream.shutdown().await.unwrap();
    }
    // Exercise the receive queue/stash before allowing the application to drain it.
    tokio::time::sleep(Duration::from_millis(150)).await;
    let mut actual = Vec::new();
    tokio::time::timeout(Duration::from_secs(8), stream.read_to_end(&mut actual))
        .await
        .expect("remote FIN must reach the application as EOF")
        .unwrap();
    assert_eq!(actual, expected);
    if !local_fin {
        stream.write_all(b"after-eof").await.unwrap();
        stream.shutdown().await.unwrap();
    }
    let expected_request = if local_fin { 7 } else { 16 };
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            {
                let stats = peer.stats.lock().unwrap();
                if stats.tcp_bytes == expected_request && stats.client_fin {
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("write half must remain usable after receive EOF and send its FIN");
}

pub(crate) async fn udp_receive_only(socket: UdpSocket, peer: &Peer) {
    socket.send(b"start").await.unwrap();
    let started = Instant::now();
    let mut received = 0;
    let mut last = 0;
    while started.elapsed() < Duration::from_secs(3) {
        let mut bytes = [0; 64];
        let n = tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut bytes))
            .await
            .expect("incoming traffic must keep the one-second session alive")
            .unwrap();
        assert_eq!(n, 8, "UDP payload must exclude tunnel padding");
        let sequence = u64::from_be_bytes(bytes[..8].try_into().unwrap());
        assert!(sequence > last);
        last = sequence;
        received += 1;
    }
    assert!(received >= 20);
    assert_eq!(peer.stats.lock().unwrap().udp_requests, 1);

    peer.paused.store(true, Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(1600)).await;
    let sent = peer.stats.lock().unwrap().udp_sent;
    peer.paused.store(false, Ordering::Relaxed);
    let mut bytes = [0; 64];
    assert!(
        tokio::time::timeout(Duration::from_millis(700), socket.recv(&mut bytes))
            .await
            .is_err(),
        "a genuinely idle session must still expire"
    );
    assert!(peer.stats.lock().unwrap().udp_sent > sent);
}

pub(crate) async fn udp_send_only(socket: UdpSocket, peer: &Peer) {
    peer.paused.store(true, Ordering::Relaxed);
    for _ in 0..7 {
        socket.send(b"keep-active").await.unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
    assert!(peer.stats.lock().unwrap().udp_requests >= 6);
    peer.paused.store(false, Ordering::Relaxed);
    let mut bytes = [0; 64];
    let n = tokio::time::timeout(Duration::from_millis(500), socket.recv(&mut bytes))
        .await
        .expect("outgoing traffic must also keep the session alive")
        .unwrap();
    assert_eq!(n, 8);
}
