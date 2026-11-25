//! Bounded WireGuard mesh with direct UDP, disco and DERP.
mod tsmp;

use super::control::{PeerObj, parse_key_hex};
use super::derp_client::RelayManager;
use crate::outbound::wireguard::noise;
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::net::UdpSocket;
use x25519_dalek::{PublicKey, StaticSecret};

const MAX_PENDING: usize = 32;
const MAX_PEERS: usize = 1024;
const MAX_IP_PACKET: usize = 1280;
const RETRY: Duration = Duration::from_secs(5);
const GIVE_UP: Duration = Duration::from_secs(90);
const REKEY: Duration = Duration::from_secs(120);
const EXPIRE: Duration = Duration::from_secs(180);
const COOKIE_TTL: Duration = Duration::from_secs(115);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    Udp(SocketAddr),
    Derp(u16),
}

impl Path {
    fn is_target(self, endpoints: &[SocketAddr], derp: Option<u16>) -> bool {
        match self {
            Self::Udp(endpoint) => endpoints.contains(&endpoint),
            Self::Derp(region) => derp == Some(region),
        }
    }
}

struct Peer {
    name: Option<String>,
    disco: Option<[u8; 32]>,
    control_disco: Option<[u8; 32]>,
    tsmp_disco: Option<[u8; 32]>,
    wireguard_only: bool,
    addresses: Vec<IpAddr>,
    endpoints: Vec<SocketAddr>,
    active: Option<Path>,
    derp_region: Option<u16>,
    session: Option<noise::Session>,
    established: Option<Instant>,
    confirmed: bool,
    initiation: Option<noise::Handshake>,
    cookies: Vec<PathCookie>,
    first_attempt: Option<Instant>,
    last_attempt: Option<Instant>,
    latest_timestamp: Option<[u8; 12]>,
    pending: VecDeque<Vec<u8>>,
    direct_seen: Option<Instant>,
    probe_at: Option<Instant>,
    probes: VecDeque<([u8; 12], SocketAddr, Instant)>,
    direct_rtt: Option<Duration>,
    next_probe: Option<Instant>,
    probe_failures: u8,
    last_payload: Option<Instant>,
    last_fallback: Option<Instant>,
    candidate: Option<(SocketAddr, Instant)>,
}

struct PathCookie {
    path: Path,
    key: [u8; 16],
    expires: Instant,
}

impl Peer {
    fn set_active_disco(&mut self, key: Option<[u8; 32]>) {
        if self.disco != key {
            self.disco = key;
            self.probes.clear();
            self.probe_at = None;
            self.next_probe = None;
            self.probe_failures = 0;
            self.direct_rtt = None;
            self.candidate = None;
        }
    }

    fn set_control_disco(&mut self, key: Option<[u8; 32]>) {
        let use_tsmp =
            self.tsmp_disco.is_some() && (self.disco == self.tsmp_disco || key.is_none());
        self.control_disco = key;
        self.set_active_disco(if use_tsmp { self.tsmp_disco } else { key });
    }

    fn disco_advertisement(&self, local: &[IpAddr], secret: &StaticSecret) -> Option<Vec<u8>> {
        if self.wireguard_only {
            return None;
        }
        tsmp::disco_advertisement(local, &self.addresses, PublicKey::from(secret).to_bytes())
    }

    fn payload(&mut self) {
        if !self.busy() {
            self.next_probe = None;
            self.probe_failures = 0;
        }
        self.last_payload = Some(Instant::now());
    }
    fn busy(&self) -> bool {
        self.last_payload
            .is_some_and(|t| t.elapsed() < Duration::from_secs(30))
    }
    fn direct_fresh(&self) -> bool {
        self.direct_seen
            .is_some_and(|t| t.elapsed() < Duration::from_secs(if self.busy() { 6 } else { 75 }))
    }
    fn fallback(&mut self) {
        if matches!(self.active, Some(Path::Udp(_)))
            && !self.direct_fresh()
            && let Some(region) = self.derp_region
        {
            self.active = Some(Path::Derp(region));
            self.last_fallback = Some(Instant::now());
            self.direct_rtt = None;
            self.next_probe = None;
            self.probe_failures = 0;
            self.candidate = None;
        }
    }
    fn probe_delay(&self) -> Duration {
        let seconds = if matches!(self.active, Some(Path::Udp(_))) {
            if self.busy() { 15 } else { 60 }
        } else if !self.busy() && self.probe_failures >= 3 {
            180
        } else {
            [5, 15, 30, 60][usize::from(self.probe_failures.min(3))]
        };
        Duration::from_secs(seconds)
    }
    fn begin_probe(&mut self) -> bool {
        if self.next_probe.is_some_and(|t| t > Instant::now()) {
            return false;
        }
        if self
            .probe_at
            .is_some_and(|round| self.direct_seen.is_none_or(|seen| seen < round))
        {
            self.probe_failures = self.probe_failures.saturating_add(1);
        }
        let delay = self.probe_delay();
        let mut random = [0; 1];
        let _ = getrandom::fill(&mut random);
        self.next_probe = Some(
            Instant::now()
                + delay
                + Duration::from_millis(delay.as_millis() as u64 * u64::from(random[0]) / 2550),
        );
        self.probe_at = Some(Instant::now());
        true
    }
    fn confirm_probe(&mut self, addr: SocketAddr, rtt: Duration) {
        if self
            .last_fallback
            .is_some_and(|t| t.elapsed() < Duration::from_secs(60))
            && !matches!(self.active, Some(Path::Udp(_)))
            && !self.candidate.is_some_and(|(candidate, seen)| {
                candidate == addr && seen.elapsed() >= Duration::from_millis(200)
            })
        {
            self.candidate = Some((addr, Instant::now()));
            self.next_probe = Some(Instant::now() + Duration::from_millis(500));
            return;
        }
        self.note_path(Path::Udp(addr));
        self.direct_rtt = Some(rtt);
        self.candidate = None;
    }

    fn learn(&mut self, addr: SocketAddr) {
        if addr.is_ipv4()
            && addr.port() != 0
            && !addr.ip().is_unspecified()
            && !addr.ip().is_multicast()
            && addr.ip() != IpAddr::V4(Ipv4Addr::BROADCAST)
            && !self.endpoints.contains(&addr)
            && self.endpoints.len() < 32
        {
            self.endpoints.push(addr);
        }
    }
    fn note_path(&mut self, path: Path) {
        match path {
            Path::Udp(addr) => {
                self.direct_seen = Some(Instant::now());
                self.probe_failures = 0;
                self.active = Some(path);
                self.learn(addr);
            }
            Path::Derp(region) => {
                if !self.direct_fresh() {
                    self.active = Some(Path::Derp(self.derp_region.unwrap_or(region)));
                }
            }
        }
    }
}
fn disco_packet(private: &StaticSecret, public: [u8; 32], plain: &[u8]) -> io::Result<Vec<u8>> {
    use crypto_box::{SalsaBox, aead::Aead};
    if !private
        .diffie_hellman(&PublicKey::from(public))
        .was_contributory()
    {
        return Err(io::Error::other("tailscale: invalid disco key"));
    }
    let cipher = SalsaBox::new(
        &crypto_box::PublicKey::from(public),
        &crypto_box::SecretKey::from(private.to_bytes()),
    );
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| io::Error::other("tailscale: entropy unavailable"))?;
    let encrypted = cipher
        .encrypt((&nonce).into(), plain)
        .map_err(|_| io::Error::other("tailscale: disco encrypt"))?;
    let mut packet = b"TS\xf0\x9f\x92\xac".to_vec();
    packet.extend(PublicKey::from(private).as_bytes());
    packet.extend(nonce);
    packet.extend(encrypted);
    Ok(packet)
}
pub struct DirectMesh {
    disco: StaticSecret,
    socket: UdpSocket,
    private: StaticSecret,
    public: [u8; 32],
    local: Vec<IpAddr>,
    local_routes: Vec<smoltcp::wire::IpCidr>,
    peers: HashMap<[u8; 32], Peer>,
    relay: Option<RelayManager>,
    connectivity: Option<super::connectivity::Connectivity>,
    more_work: bool,
    network_endpoints: Vec<SocketAddr>,
}

// Linux reports twice the requested SO_RCVBUF (including kernel accounting).
// Bound the per-socket queue; never change router-wide sysctls or the send queue.
const RECEIVE_BUFFER_BYTES: usize = 2 * 1024 * 1024;

fn configure_receive_buffer(socket: &socket2::SockRef<'_>) -> io::Result<usize> {
    let before = socket.recv_buffer_size()?;
    if before >= RECEIVE_BUFFER_BYTES {
        return Ok(before);
    }
    let requested = if cfg!(target_os = "linux") {
        RECEIVE_BUFFER_BYTES / 2
    } else {
        RECEIVE_BUFFER_BYTES
    };
    // The ordinary operation may be capped by rmem_max. Retain the existing
    // queue if that operation fails, and still try the privileged Linux option.
    let _ = socket.set_recv_buffer_size(requested);
    #[cfg(target_os = "linux")]
    if socket.recv_buffer_size()? < RECEIVE_BUFFER_BYTES {
        use std::os::fd::AsRawFd;
        let value = requested as libc::c_int;
        // Only this socket is affected. EPERM (unprivileged operation) leaves
        // the ordinary, kernel-capped buffer usable; startup must still work.
        unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_RCVBUFFORCE,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            );
        }
    }
    socket.recv_buffer_size()
}

impl DirectMesh {
    pub fn set_local_routes(&mut self, routes: Vec<smoltcp::wire::IpCidr>) {
        self.local_routes = routes;
    }
    pub async fn bind(private: StaticSecret, local: Vec<IpAddr>, port: u16) -> io::Result<Self> {
        let mut disco = [0; 32];
        getrandom::fill(&mut disco)
            .map_err(|_| io::Error::other("tailscale: entropy unavailable"))?;
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await?;
        match configure_receive_buffer(&socket2::SockRef::from(&socket)) {
            Ok(actual) if actual >= RECEIVE_BUFFER_BYTES => {}
            Ok(actual) => crate::logging::warn(format_args!(
                "tailscale: UDP receive buffer limited to {actual} bytes (target {RECEIVE_BUFFER_BYTES}); burst traffic may drop"
            )),
            Err(error) => crate::logging::warn(format_args!(
                "tailscale: cannot verify UDP receive buffer: {error}"
            )),
        }
        Ok(Self {
            disco: StaticSecret::from(disco),
            socket,
            public: PublicKey::from(&private).to_bytes(),
            private,
            local,
            local_routes: vec![],
            peers: HashMap::new(),
            relay: None,
            connectivity: None,
            more_work: false,
            network_endpoints: vec![],
        })
    }

    pub fn more_work(&self) -> bool {
        self.more_work
    }
    pub async fn readable(&self) -> io::Result<()> {
        if let Some(relay) = &self.relay {
            if !relay.rx.is_empty() {
                return Ok(());
            }
            tokio::select! {ready=self.socket.readable()=>ready,_=relay.notify.notified()=>Ok(())}
        } else {
            self.socket.readable().await
        }
    }
    pub fn diagnostics(&self) -> serde_json::Value {
        let peers:Vec<_>=self.peers.values().filter(|p|p.active.is_some()).map(|p| {
            let (path,region)=match p.active {Some(Path::Udp(_))=>("direct",None),Some(Path::Derp(id))=>("derp",Some(id)),None=>("pending",None)};
            serde_json::json!({"name":p.name,"addresses":p.addresses,"path":path,"derp_region":region,"direct_rtt_ms":p.direct_rtt.map(|r|r.as_millis() as u64)})
        }).collect();
        serde_json::json!({"network":self.connectivity.as_ref().map(|c|c.info.borrow().clone()),"peers":peers})
    }
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
    pub fn local_ips(&self) -> &[IpAddr] {
        &self.local
    }
    pub fn set_local_ips(&mut self, addresses: Vec<IpAddr>) {
        self.local = addresses;
        for peer in self.peers.values_mut() {
            peer.pending.clear();
        }
    }
    pub fn disco_public(&self) -> [u8; 32] {
        PublicKey::from(&self.disco).to_bytes()
    }

    pub async fn discover(
        &mut self,
        map: super::derp::DerpMap,
    ) -> io::Result<tokio::sync::watch::Receiver<super::connectivity::NetworkInfo>> {
        let connectivity = super::connectivity::Connectivity::start(&self.socket, map).await?;
        let rx = connectivity.info.subscribe();
        self.connectivity = Some(connectivity);
        Ok(rx)
    }
    pub fn set_relay(&mut self, relay: RelayManager) {
        self.relay = Some(relay);
    }
    pub fn update_relay_map(&mut self, map: super::derp::DerpMap) {
        self.update_discovery_map(map.clone());
        if let Some(relay) = &mut self.relay {
            relay.update_map(map.clone());
        }
    }

    pub fn update_discovery_map(&mut self, map: super::derp::DerpMap) {
        if let Some(c) = &mut self.connectivity {
            c.update_map(map);
        }
    }
    pub fn update_peers(&mut self, nodes: &[PeerObj]) {
        let mut next = HashMap::new();
        for node in nodes.iter().take(MAX_PEERS) {
            let Some(key) = parse_key_hex(&node.key) else {
                continue;
            };
            // A known peer passed the low-order check when it was added;
            // only a new key pays for the X25519 operation.
            if key == self.public
                || (!self.peers.contains_key(&key)
                    && !self
                        .private
                        .diffie_hellman(&PublicKey::from(key))
                        .was_contributory())
            {
                continue;
            }
            let addresses: Vec<IpAddr> = node
                .addresses
                .iter()
                .filter_map(|address| address.parse::<smoltcp::wire::IpCidr>().ok())
                .filter(|address| {
                    node.allowed_ips().iter().any(|prefix| {
                        prefix
                            .parse::<smoltcp::wire::IpCidr>()
                            .is_ok_and(|prefix| prefix.contains_addr(&address.address()))
                    })
                })
                .map(|address| address.address().into())
                .collect();
            let endpoints: Vec<SocketAddr> = node
                .endpoints
                .iter()
                .flatten()
                .filter_map(|e| e.parse::<SocketAddr>().ok())
                .filter(|e| {
                    e.is_ipv4()
                        && e.port() != 0
                        && !e.ip().is_unspecified()
                        && !e.ip().is_multicast()
                })
                .take(16)
                .collect();
            let mut peer = self.peers.remove(&key).unwrap_or(Peer {
                name: None,
                disco: None,
                control_disco: None,
                tsmp_disco: None,
                wireguard_only: node.is_wireguard_only,
                addresses: vec![],
                endpoints: vec![],
                active: None,
                derp_region: None,
                session: None,
                established: None,
                confirmed: false,
                initiation: None,
                cookies: vec![],
                first_attempt: None,
                last_attempt: None,
                latest_timestamp: None,
                pending: VecDeque::new(),
                direct_seen: None,
                probe_at: None,
                probes: VecDeque::new(),
                direct_rtt: None,
                next_probe: None,
                probe_failures: 0,
                last_payload: None,
                last_fallback: None,
                candidate: None,
            });
            if peer.endpoints != endpoints {
                peer.next_probe = None;
                peer.probe_failures = 0;
            }
            peer.addresses = addresses;
            peer.name = node.name.clone();
            peer.wireguard_only = node.is_wireguard_only;
            if peer.wireguard_only {
                peer.tsmp_disco = None;
            }
            peer.set_control_disco(
                node.disco_key
                    .as_deref()
                    .and_then(|s| parse_key_hex(s.strip_prefix("discokey:").unwrap_or(s)))
                    .filter(|key| *key != [0; 32]),
            );
            peer.endpoints = endpoints;
            let region = node.home_derp.filter(|id| *id != 0).or_else(|| {
                node.derp.as_ref().and_then(|value| {
                    value
                        .as_u64()
                        .and_then(|id| u16::try_from(id).ok())
                        .or_else(|| {
                            value
                                .as_str()?
                                .parse::<SocketAddr>()
                                .ok()
                                .map(|address| address.port())
                        })
                })
            });
            if peer.derp_region != region && matches!(peer.active, Some(Path::Derp(_))) {
                peer.active = region.map(Path::Derp);
            }
            peer.derp_region = region;
            next.insert(key, peer);
        }
        self.peers = next;
    }

    pub async fn send(&mut self, packet: Vec<u8>) -> io::Result<()> {
        let (source, dest, length) = packet_ips(&packet).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "tailscale: invalid IP packet")
        })?;
        if length > MAX_IP_PACKET {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tailscale: packet exceeds MTU 1280",
            ));
        }
        if !self.local.contains(&source)
            && !self
                .local_routes
                .iter()
                .any(|r| r.contains_addr(&source.into()))
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tailscale: invalid source address",
            ));
        }
        let Some((key, peer)) = self
            .peers
            .iter_mut()
            .find(|(_, p)| p.addresses.contains(&dest))
        else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "tailscale: no mapped peer",
            ));
        };
        peer.payload();
        if peer.pending.len() >= MAX_PENDING {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "tailscale: peer queue full",
            ));
        }
        peer.pending.push_back(packet[..length].to_vec());
        Self::flush(
            &self.socket,
            &mut self.relay,
            &self.private,
            &self.public,
            key,
            peer,
        )
        .await
    }

    async fn flush(
        socket: &UdpSocket,
        relay: &mut Option<RelayManager>,
        private: &StaticSecret,
        public: &[u8; 32],
        key: &[u8; 32],
        peer: &mut Peer,
    ) -> io::Result<()> {
        if peer.established.is_some_and(|t| t.elapsed() >= EXPIRE) {
            peer.session = None;
            peer.confirmed = false;
            peer.established = None;
        }
        peer.fallback();
        if peer.busy()
            && let (Some(relay), Some(region)) = (relay.as_mut(), peer.derp_region)
        {
            relay.prepare(region);
        }
        // A responder cannot send application data until the initiator proves
        // possession of the new session key with its first transport packet.
        if peer.session.is_some()
            && !peer.confirmed
            && peer.established.is_some_and(|t| t.elapsed() < RETRY)
        {
            return Ok(());
        }
        if peer.confirmed
            && let (Some(session), Some(endpoint)) = (&mut peer.session, peer.active)
        {
            while let Some(packet) = peer.pending.pop_front() {
                if let Some(sealed) = session.seal(&packet) {
                    Self::transmit(socket, relay, endpoint, *key, &sealed).await?;
                }
            }
        }
        let needs_handshake = !peer.pending.is_empty()
            || peer.established.is_some_and(|t| t.elapsed() >= REKEY)
            || peer.initiation.is_some();
        if needs_handshake && peer.last_attempt.is_none_or(|t| t.elapsed() >= RETRY) {
            if peer.first_attempt.is_some_and(|t| t.elapsed() >= GIVE_UP) {
                peer.pending.clear();
                peer.initiation = None;
                peer.first_attempt = None;
                peer.last_attempt = None;
                return Ok(());
            }
            // Every retry is a new initiation (new ephemeral key and timestamp),
            // as WireGuard's REKEY_TIMEOUT does: a responder drops a repeated
            // timestamp, so resending the first one could never succeed once
            // its response was lost.
            let mut handshake = noise::build_initiation(
                &private.to_bytes(),
                public,
                key,
                None,
                &noise::tai64n_now(),
                1,
            );
            let now = Instant::now();
            peer.cookies.retain(|cookie| {
                cookie.expires > now && cookie.path.is_target(&peer.endpoints, peer.derp_region)
            });
            for endpoint in &peer.endpoints {
                if !peer
                    .cookies
                    .iter()
                    .any(|cookie| cookie.path == Path::Udp(*endpoint))
                {
                    send_datagram(socket, handshake.initiation(), *endpoint).await;
                }
            }
            if let (Some(relay), Some(region)) = (relay.as_mut(), peer.derp_region)
                && !peer
                    .cookies
                    .iter()
                    .any(|cookie| cookie.path == Path::Derp(region))
            {
                relay.send(region, *key, handshake.initiation());
            }
            for cookie in &peer.cookies {
                handshake.set_cookie(&cookie.key);
                Self::transmit(socket, relay, cookie.path, *key, handshake.initiation()).await?;
            }
            peer.initiation = Some(handshake);
            peer.first_attempt.get_or_insert(Instant::now());
            peer.last_attempt = Some(Instant::now());
        }
        Ok(())
    }

    async fn transmit(
        socket: &UdpSocket,
        relay: &mut Option<RelayManager>,
        path: Path,
        destination: [u8; 32],
        packet: &[u8],
    ) -> io::Result<()> {
        match path {
            Path::Udp(endpoint) => send_datagram(socket, packet, endpoint).await,
            Path::Derp(region) => {
                if let Some(relay) = relay {
                    relay.send(region, destination, packet);
                }
            }
        }
        Ok(())
    }

    /// Drain a bounded number of UDP messages; called by the endpoint's stack task.
    pub async fn poll(&mut self) -> io::Result<Vec<Vec<u8>>> {
        self.more_work = false;
        if let Some(c) = &mut self.connectivity {
            if let Some(relay) = &mut self.relay {
                while let Ok(health) = relay.health_rx.try_recv() {
                    c.relay_health(health);
                }
            }
            let active = self.peers.values().any(Peer::busy);
            c.tick(&self.socket, active).await;
            let endpoints = c.info.borrow().endpoints.clone();
            if endpoints != self.network_endpoints {
                self.network_endpoints = endpoints;
                for peer in self.peers.values_mut() {
                    peer.next_probe = None;
                    peer.probe_failures = 0;
                }
            }
            if let Some(relay) = &mut self.relay {
                relay.set_home(c.info.borrow().home_derp);
            }
        }
        let mut packets = Vec::new();
        // Anything over 2048 bytes is dropped below; a longer datagram reads
        // truncated to 2049 and is dropped the same way. Zeroing 64 KiB on
        // every poll cost more than the receive itself.
        let mut buffer = [0; 2049];
        let mut inbound = Vec::new();
        for index in 0..256 {
            let (length, endpoint) = match self.socket.try_recv_from(&mut buffer) {
                Ok(value) => value,
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                Err(e) => return Err(e),
            };
            if index == 255 {
                self.more_work = true;
            }
            if length > 2048 {
                continue;
            }
            if self
                .connectivity
                .as_mut()
                .is_some_and(|c| c.receive(&buffer[..length], endpoint))
            {
                continue;
            }
            inbound.push((buffer[..length].to_vec(), Path::Udp(endpoint), None));
        }
        if let Some(relay) = &mut self.relay {
            relay.release_idle();
            for index in 0..256 {
                let Ok((region, packet)) = relay.rx.try_recv() else {
                    break;
                };
                if index == 255 {
                    self.more_work = true;
                }
                if packet.packet.len() <= 2048 {
                    inbound.push((packet.packet, Path::Derp(region), Some(packet.source)));
                }
            }
        }
        for (bytes, endpoint, relay_source) in inbound {
            if bytes.starts_with(b"TS\xf0\x9f\x92\xac") && bytes.len() >= 78 {
                let source: [u8; 32] = bytes[6..38].try_into().unwrap();
                let Some((node, peer)) = self.peers.iter_mut().find(|(node, peer)| {
                    relay_source.is_none_or(|sender| sender == **node)
                        && (peer.disco == Some(source)
                            || peer.control_disco == Some(source)
                            || peer.tsmp_disco == Some(source))
                }) else {
                    continue;
                };
                if !self
                    .disco
                    .diffie_hellman(&PublicKey::from(source))
                    .was_contributory()
                {
                    continue;
                }
                use crypto_box::{SalsaBox, aead::Aead};
                let cipher = SalsaBox::new(
                    &crypto_box::PublicKey::from(source),
                    &crypto_box::SecretKey::from(self.disco.to_bytes()),
                );
                let Ok(plain) =
                    cipher.decrypt(crypto_box::Nonce::from_slice(&bytes[38..62]), &bytes[62..])
                else {
                    continue;
                };
                if plain.len() >= 14 && plain[0..2] == [1, 0] {
                    peer.set_active_disco(Some(source));
                    let mut response = vec![2, 0];
                    response.extend_from_slice(&plain[2..14]);
                    let observed = match endpoint {
                        Path::Udp(addr) => addr,
                        Path::Derp(region) => SocketAddr::from(([127, 3, 3, 40], region)),
                    };
                    let ip = match observed.ip() {
                        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                        IpAddr::V6(ip) => ip,
                    };
                    response.extend_from_slice(&ip.octets());
                    response.extend_from_slice(&observed.port().to_be_bytes());
                    let mut nonce = [0; 24];
                    getrandom::fill(&mut nonce)
                        .map_err(|_| io::Error::other("tailscale: entropy unavailable"))?;
                    let encrypted = cipher
                        .encrypt((&nonce).into(), response.as_slice())
                        .map_err(|_| io::Error::other("tailscale: disco encrypt"))?;
                    let mut packet = b"TS\xf0\x9f\x92\xac".to_vec();
                    packet.extend_from_slice(PublicKey::from(&self.disco).as_bytes());
                    packet.extend_from_slice(&nonce);
                    packet.extend(encrypted);
                    let node = *node;
                    if let Path::Udp(addr) = endpoint {
                        peer.learn(addr);
                    }
                    let _ = peer;
                    Self::transmit(&self.socket, &mut self.relay, endpoint, node, &packet).await?;
                } else if plain.len() >= 32 && plain[..2] == [2, 0] {
                    if let Path::Udp(addr) = endpoint {
                        let tx: [u8; 12] = plain[2..14].try_into().unwrap();
                        let answered = peer
                            .probes
                            .iter()
                            .position(|(id, target, sent)| {
                                *id == tx
                                    && *target == addr
                                    && sent.elapsed() < Duration::from_secs(10)
                            })
                            .and_then(|index| peer.probes.remove(index));
                        // A key swap invalidates the remaining probes. Preserve
                        // the matched transaction so this Pong can confirm its path.
                        peer.set_active_disco(Some(source));
                        if let Some((_, _, sent)) = answered {
                            let rtt = sent.elapsed();
                            if !matches!(peer.active,Some(Path::Udp(old)) if old!=addr && peer.direct_seen.is_some_and(|t|t.elapsed()<Duration::from_secs(20)) && peer.direct_rtt.is_some_and(|old|old<=rtt+Duration::from_millis(5)))
                            {
                                peer.confirm_probe(addr, rtt);
                            }
                        }
                    }
                } else if matches!(endpoint, Path::Derp(_))
                    && plain.len() >= 2
                    && plain[..2] == [3, 0]
                    && (plain.len() - 2) % 18 == 0
                    && plain.len() <= 2 + 32 * 18
                {
                    peer.set_active_disco(Some(source));
                    for entry in plain[2..].as_chunks::<18>().0 {
                        let ip = Ipv6Addr::from(<[u8; 16]>::try_from(&entry[..16]).unwrap());
                        if let Some(ip) = ip.to_ipv4_mapped() {
                            peer.learn((ip, u16::from_be_bytes([entry[16], entry[17]])).into());
                        }
                    }
                    if peer
                        .probe_at
                        .is_none_or(|t| t.elapsed() >= Duration::from_secs(1))
                    {
                        peer.next_probe = None;
                    }
                }
                continue;
            }
            let packet = &bytes[..];
            let length = packet.len();
            match noise::type_word(packet) {
                Some(1) if length == noise::INITIATION_LEN => {
                    crate::logging::debug(format_args!("tailscale: received WireGuard initiation"));
                    let Ok(init) =
                        noise::process_initiation(&self.private.to_bytes(), &self.public, packet)
                    else {
                        continue;
                    };
                    let Some(peer) = self.peers.get_mut(&init.sender_static_pub) else {
                        continue;
                    };
                    if relay_source.is_some_and(|source| source != init.sender_static_pub) {
                        continue;
                    }
                    if peer
                        .latest_timestamp
                        .is_some_and(|last| init.timestamp <= last)
                    {
                        continue;
                    }
                    if peer.initiation.is_some() {
                        if self.public < init.sender_static_pub {
                            continue;
                        }
                        peer.initiation = None;
                        peer.first_attempt = None;
                        peer.last_attempt = None;
                    }
                    peer.latest_timestamp = Some(init.timestamp);
                    let (response, session) =
                        noise::build_response(&init, &self.private.to_bytes(), None, 2);
                    Self::transmit(
                        &self.socket,
                        &mut self.relay,
                        endpoint,
                        init.sender_static_pub,
                        &response,
                    )
                    .await?;
                    peer.session = Some(session);
                    peer.established = Some(Instant::now());
                    peer.note_path(endpoint);
                    peer.confirmed = false;
                }
                Some(2) if length == noise::RESPONSE_LEN => {
                    crate::logging::debug(format_args!("tailscale: received WireGuard response"));
                    let index = u32::from_le_bytes(packet[8..12].try_into().unwrap());
                    let Some((key, peer)) = self.peers.iter_mut().find(|(_, p)| {
                        p.initiation
                            .as_ref()
                            .is_some_and(|h| h.sender_index == index)
                    }) else {
                        continue;
                    };
                    if relay_source.is_some_and(|source| source != *key) {
                        continue;
                    }
                    let Ok(mut session) = noise::process_response(
                        peer.initiation.as_ref().unwrap(),
                        packet,
                        &self.public,
                        None,
                    ) else {
                        continue;
                    };
                    let advertisement = peer.disco_advertisement(&self.local, &self.disco);
                    let confirm = session
                        .seal(advertisement.as_deref().unwrap_or_default())
                        .unwrap();
                    Self::transmit(&self.socket, &mut self.relay, endpoint, *key, &confirm).await?;
                    peer.session = Some(session);
                    peer.established = Some(Instant::now());
                    peer.note_path(endpoint);
                    peer.confirmed = true;
                    peer.initiation = None;
                    peer.first_attempt = None;
                    peer.last_attempt = None;
                }
                Some(4) if length >= 32 => {
                    let index = u32::from_le_bytes(packet[4..8].try_into().unwrap());
                    let Some((key, peer)) = self.peers.iter_mut().find(|(_, p)| {
                        p.session.as_ref().is_some_and(|s| s.local_index == index)
                            && p.established.is_some_and(|t| t.elapsed() < EXPIRE)
                    }) else {
                        continue;
                    };
                    if relay_source.is_some_and(|source| source != *key) {
                        continue;
                    }
                    let Some(mut plain) = peer.session.as_mut().unwrap().open(packet) else {
                        continue;
                    };
                    peer.note_path(endpoint);
                    if !std::mem::replace(&mut peer.confirmed, true)
                        && let Some(advertisement) =
                            peer.disco_advertisement(&self.local, &self.disco)
                        && let Some(sealed) = peer.session.as_mut().unwrap().seal(&advertisement)
                    {
                        Self::transmit(&self.socket, &mut self.relay, endpoint, *key, &sealed)
                            .await?;
                    }
                    if plain.is_empty() {
                        continue;
                    }
                    if let Some((source, dest, length)) = packet_ips(&plain)
                        && length <= MAX_IP_PACKET
                        && peer.addresses.contains(&source)
                        && (self.local.contains(&dest)
                            || self
                                .local_routes
                                .iter()
                                .any(|r| r.contains_addr(&dest.into())))
                    {
                        plain.truncate(length);
                        if let Some(payload) = tsmp::payload(&plain)
                            && (payload.is_empty() || tsmp::is_disco_advertisement(payload))
                        {
                            if !peer.wireguard_only
                                && self.local.contains(&dest)
                                && let Some(disco) = tsmp::disco_key(payload)
                                && peer.tsmp_disco != Some(disco)
                                && self
                                    .disco
                                    .diffie_hellman(&PublicKey::from(disco))
                                    .was_contributory()
                            {
                                peer.tsmp_disco = Some(disco);
                                peer.set_active_disco(Some(disco));
                            }
                            continue;
                        }
                        peer.payload();
                        packets.push(plain);
                    }
                }
                Some(3) if length == noise::COOKIE_REPLY_LEN => {
                    let index = u32::from_le_bytes(packet[4..8].try_into().unwrap());
                    for (key, peer) in &mut self.peers {
                        if relay_source.is_none_or(|sender| sender == *key)
                            && endpoint.is_target(&peer.endpoints, peer.derp_region)
                            && let Some(hs) = &peer.initiation
                            && hs.sender_index == index
                            && let Ok(cookie) =
                                noise::decrypt_cookie(packet, key, &hs.mac1(), index)
                        {
                            let now = Instant::now();
                            peer.cookies.retain(|old| {
                                old.path != endpoint
                                    && old.expires > now
                                    && old.path.is_target(&peer.endpoints, peer.derp_region)
                            });
                            peer.cookies.push(PathCookie {
                                path: endpoint,
                                key: cookie,
                                expires: now + COOKIE_TTL,
                            });
                            break;
                        }
                    }
                }
                _ => {}
            }
        }
        let advertised = self
            .connectivity
            .as_ref()
            .map(|c| c.info.borrow().endpoints.clone())
            .unwrap_or_default();
        for (key, peer) in &mut self.peers {
            peer.fallback();
            if peer.begin_probe() {
                peer.probes
                    .retain(|(_, _, t)| t.elapsed() < Duration::from_secs(10));
                if let Some(disco) = peer.disco {
                    let mut endpoints = if matches!(peer.active, Some(Path::Udp(_))) {
                        vec![]
                    } else {
                        peer.endpoints.clone()
                    };
                    if let Some(Path::Udp(addr)) = peer.active
                        && !endpoints.contains(&addr)
                    {
                        endpoints.push(addr);
                    }
                    for addr in endpoints.into_iter().take(32) {
                        let mut tx = [0; 12];
                        getrandom::fill(&mut tx)
                            .map_err(|_| io::Error::other("tailscale: entropy unavailable"))?;
                        let mut plain = vec![1, 0];
                        plain.extend(tx);
                        plain.extend(self.public);
                        if let Ok(packet) = disco_packet(&self.disco, disco, &plain)
                            && self.socket.send_to(&packet, addr).await.is_ok()
                        {
                            if peer.probes.len() >= 64 {
                                peer.probes.pop_front();
                            }
                            peer.probes.push_back((tx, addr, Instant::now()));
                        }
                    }
                    if !matches!(peer.active, Some(Path::Udp(_)))
                        && let (Some(relay), Some(region)) = (&mut self.relay, peer.derp_region)
                    {
                        let mut plain = vec![3, 0];
                        for addr in advertised.iter().take(32) {
                            let ip = match addr.ip() {
                                IpAddr::V4(ip) => ip.to_ipv6_mapped(),
                                IpAddr::V6(ip) => ip,
                            };
                            plain.extend(ip.octets());
                            plain.extend(addr.port().to_be_bytes());
                        }
                        if let Ok(packet) = disco_packet(&self.disco, disco, &plain) {
                            relay.send(region, *key, &packet);
                        }
                    }
                }
            }
            Self::flush(
                &self.socket,
                &mut self.relay,
                &self.private,
                &self.public,
                key,
                peer,
            )
            .await?;
        }
        Ok(packets)
    }
}

/// A failed datagram send (no route while the WAN is down, a firewall
/// refusal) is a lost packet, as on any UDP path. It must not fail the poll:
/// that would drop the packets already decrypted in it and skip the other
/// peers, including ones still reachable on the LAN.
async fn send_datagram(socket: &UdpSocket, packet: &[u8], endpoint: SocketAddr) {
    if let Err(error) = socket.send_to(packet, endpoint).await {
        crate::logging::debug(format_args!("tailscale: send to {endpoint}: {error}"));
    }
}

pub(crate) fn packet_ips(packet: &[u8]) -> Option<(IpAddr, IpAddr, usize)> {
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let header = (packet[0] & 15) as usize * 4;
            let length = u16::from_be_bytes([packet[2], packet[3]]) as usize;
            if header < 20 || length < header || length > packet.len() {
                return None;
            }
            Some((
                Ipv4Addr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?).into(),
                Ipv4Addr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?).into(),
                length,
            ))
        }
        6 if packet.len() >= 40 => {
            let length = 40 + u16::from_be_bytes([packet[4], packet[5]]) as usize;
            if length > packet.len() {
                return None;
            }
            Some((
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?).into(),
                Ipv6Addr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?).into(),
                length,
            ))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn peer(key: [u8; 32], address: &str, port: u16) -> PeerObj {
        PeerObj {
            disco_key: None,
            is_wireguard_only: false,
            home_derp: None,
            id: 1,
            key: format!("nodekey:{}", super::super::control::to_hex(&key)),
            name: None,
            addresses: vec![format!("{address}/32")],
            allowed_ips: None,
            endpoints: Some(vec![format!("127.0.0.1:{port}")]),
            derp: None,
            online: Some(true),
        }
    }

    fn packet(source: [u8; 4], dest: [u8; 4], value: u8) -> Vec<u8> {
        let mut packet = vec![0; 21];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&21u16.to_be_bytes());
        packet[12..16].copy_from_slice(&source);
        packet[16..20].copy_from_slice(&dest);
        packet[20] = value;
        packet
    }

    async fn pair() -> (DirectMesh, DirectMesh) {
        let mut a = DirectMesh::bind(
            StaticSecret::from([1; 32]),
            vec!["100.64.0.1".parse().unwrap()],
            0,
        )
        .await
        .unwrap();
        let mut b = DirectMesh::bind(
            StaticSecret::from([2; 32]),
            vec!["100.64.0.2".parse().unwrap()],
            0,
        )
        .await
        .unwrap();
        a.update_peers(&[peer(b.public, "100.64.0.2", b.local_addr().unwrap().port())]);
        b.update_peers(&[peer(a.public, "100.64.0.1", a.local_addr().unwrap().port())]);
        (a, b)
    }

    async fn receive(a: &mut DirectMesh, b: &mut DirectMesh) -> Vec<u8> {
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                a.poll().await.unwrap();
                if let Some(packet) = b.poll().await.unwrap().pop() {
                    return packet;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn explicit_empty_allowed_ips_disables_the_peer_address() {
        let (mut a, mut b) = pair().await;
        let mut remote = peer(b.public, "100.64.0.2", b.local_addr().unwrap().port());
        let payload = packet([100, 64, 0, 1], [100, 64, 0, 2], 42);
        remote.allowed_ips = Some(vec![]);
        a.update_peers(std::slice::from_ref(&remote));
        assert_eq!(
            a.send(payload.clone()).await.unwrap_err().kind(),
            io::ErrorKind::NotFound
        );
        remote.allowed_ips = None;
        a.update_peers(&[remote]);
        a.send(payload.clone()).await.unwrap();
        assert_eq!(receive(&mut a, &mut b).await, payload);
    }

    #[tokio::test]
    async fn established_sessions_exchange_disco_keys_and_keep_them_on_map_refresh() {
        let (mut a, mut b) = pair().await;
        let a_disco = a.disco_public();
        let b_disco = b.disco_public();
        let payload = packet([100, 64, 0, 1], [100, 64, 0, 2], 42);
        a.send(payload.clone()).await.unwrap();
        assert_eq!(receive(&mut a, &mut b).await, payload);
        assert_eq!(b.peers[&a.public].tsmp_disco, Some(a_disco));
        tokio::time::timeout(Duration::from_secs(1), async {
            while a.peers[&b.public].tsmp_disco.is_none() {
                assert!(a.poll().await.unwrap().is_empty());
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert_eq!(a.peers[&b.public].disco, Some(b_disco));
        let mut node = peer(b.public, "100.64.0.2", b.local_addr().unwrap().port());
        a.update_peers(std::slice::from_ref(&node));
        assert_eq!(a.peers[&b.public].disco, Some(b_disco));
        node.is_wireguard_only = true;
        a.update_peers(&[node]);
        assert!(a.peers[&b.public].disco.is_none());
        assert!(
            a.peers[&b.public]
                .disco_advertisement(&a.local, &a.disco)
                .is_none()
        );
    }

    #[tokio::test]
    async fn wireguard_cookie_is_reused_only_on_the_challenging_udp_path() {
        use blake2::{Blake2s256, Digest};
        use chacha20poly1305::{
            KeyInit, XChaCha20Poly1305, XNonce,
            aead::{Aead, Payload},
        };

        let (mut a, b) = pair().await;
        let alternate = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut node = peer(b.public, "100.64.0.2", b.local_addr().unwrap().port());
        node.endpoints
            .as_mut()
            .unwrap()
            .push(alternate.local_addr().unwrap().to_string());
        a.update_peers(&[node]);
        let data = packet([100, 64, 0, 1], [100, 64, 0, 2], 42);
        a.send(data).await.unwrap();

        let mut first = [0; noise::INITIATION_LEN];
        let mut alt = [0; noise::INITIATION_LEN];
        let (_, a_addr) = b.socket.recv_from(&mut first).await.unwrap();
        alternate.recv_from(&mut alt).await.unwrap();
        assert_eq!(alt, first);
        let handshake = a.peers[&b.public].initiation.as_ref().unwrap();
        let nonce = [8; 24];
        let cookie = [9; 16];
        let cookie_key = Blake2s256::digest([b"cookie--".as_slice(), &b.public].concat());
        let cipher = XChaCha20Poly1305::new_from_slice(&cookie_key).unwrap();
        let encrypted = cipher
            .encrypt(
                XNonce::from_slice(&nonce),
                Payload {
                    msg: &cookie,
                    aad: &handshake.mac1(),
                },
            )
            .unwrap();
        let mut reply = 3u32.to_le_bytes().to_vec();
        reply.extend(handshake.sender_index.to_le_bytes());
        reply.extend(nonce);
        reply.extend(encrypted);
        b.socket.send_to(&reply, a_addr).await.unwrap();

        a.socket.readable().await.unwrap();
        a.poll().await.unwrap();
        let state = a.peers.get_mut(&b.public).unwrap();
        assert_eq!(state.cookies.len(), 1);
        assert_eq!(state.cookies[0].key, cookie);
        state.last_attempt = Some(Instant::now() - RETRY);
        a.poll().await.unwrap();
        let mut retry = [0; noise::INITIATION_LEN];
        b.socket.recv_from(&mut retry).await.unwrap();
        alternate.recv_from(&mut alt).await.unwrap();
        let mac_offset = noise::INITIATION_LEN - 16;
        assert_ne!(retry[4..8], first[4..8]);
        assert_eq!(retry[..mac_offset], alt[..mac_offset]);
        assert_eq!(alt[mac_offset..], [0; 16]);
        assert_ne!(retry[mac_offset..], [0; 16]);
    }

    #[tokio::test]
    async fn disco_promotes_direct_without_wireguard_traffic_and_keeps_it_over_derp() {
        let (mut a, mut b) = pair().await;
        a.peers.get_mut(&b.public).unwrap().disco = Some(b.disco_public());
        b.peers.get_mut(&a.public).unwrap().disco = Some(a.disco_public());
        a.peers.get_mut(&b.public).unwrap().active = Some(Path::Derp(22));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                a.poll().await.unwrap();
                b.poll().await.unwrap();
                if matches!(a.peers[&b.public].active, Some(Path::Udp(_))) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        let p = a.peers.get_mut(&b.public).unwrap();
        assert!(p.direct_rtt.is_some());
        p.note_path(Path::Derp(1));
        assert!(matches!(p.active, Some(Path::Udp(_))));
        p.direct_seen = Some(Instant::now() - Duration::from_secs(76));
        p.derp_region = Some(22);
        p.note_path(Path::Derp(1));
        assert!(matches!(p.active, Some(Path::Derp(22))));
    }

    #[tokio::test]
    async fn unsolicited_authenticated_pong_cannot_select_a_direct_path() {
        let (mut a, b) = pair().await;
        a.peers.get_mut(&b.public).unwrap().disco = Some(b.disco_public());
        let mut plain = vec![2, 0];
        plain.extend([9; 12]);
        plain.extend([0; 18]);
        let p = disco_packet(&b.disco, a.disco_public(), &plain).unwrap();
        b.socket
            .send_to(&p, (Ipv4Addr::LOCALHOST, a.local_addr().unwrap().port()))
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        a.poll().await.unwrap();
        assert!(a.peers[&b.public].active.is_none());
    }

    #[tokio::test]
    async fn probes_back_off_and_new_payload_wakes_an_idle_peer() {
        let (mut mesh, other) = pair().await;
        let peer = mesh.peers.get_mut(&other.public).unwrap();
        peer.payload();
        for seconds in [5, 15, 30, 60] {
            peer.next_probe = None;
            assert!(peer.begin_probe());
            assert_eq!(peer.probe_delay(), Duration::from_secs(seconds));
        }
        peer.last_payload = Some(Instant::now() - Duration::from_secs(31));
        assert_eq!(peer.probe_delay(), Duration::from_secs(180));
        assert!(!peer.begin_probe());
        peer.payload();
        assert_eq!(peer.probe_failures, 0);
        assert!(peer.next_probe.is_none());
        assert!(peer.begin_probe());
    }

    #[tokio::test]
    async fn fallback_preserves_wireguard_and_requires_two_probes_to_return() {
        let (mut a, mut b) = pair().await;
        a.send(packet([100, 64, 0, 1], [100, 64, 0, 2], 42))
            .await
            .unwrap();
        receive(&mut a, &mut b).await;
        let peer = a.peers.get_mut(&b.public).unwrap();
        let Some(Path::Udp(address)) = peer.active else {
            panic!("direct session required")
        };
        peer.derp_region = Some(22);
        peer.direct_seen = Some(Instant::now() - Duration::from_secs(7));
        peer.fallback();
        assert_eq!(peer.active, Some(Path::Derp(22)));
        assert!(peer.session.is_some() && peer.confirmed);
        peer.confirm_probe(address, Duration::from_millis(10));
        assert_eq!(peer.active, Some(Path::Derp(22)));
        peer.candidate = Some((address, Instant::now() - Duration::from_millis(250)));
        peer.confirm_probe(address, Duration::from_millis(10));
        assert_eq!(peer.active, Some(Path::Udp(address)));
    }

    #[tokio::test]
    async fn encrypted_bidirectional_ip_exchange() {
        let (mut a, mut b) = pair().await;
        let request = packet([100, 64, 0, 1], [100, 64, 0, 2], 42);
        a.send(request.clone()).await.unwrap();
        assert_eq!(receive(&mut a, &mut b).await, request);
        let response = packet([100, 64, 0, 2], [100, 64, 0, 1], 43);
        b.send(response.clone()).await.unwrap();
        assert_eq!(receive(&mut b, &mut a).await, response);
    }

    #[tokio::test]
    async fn handshake_retry_after_a_lost_response_is_accepted() {
        let (mut a, mut b) = pair().await;
        let request = packet([100, 64, 0, 1], [100, 64, 0, 2], 7);
        a.send(request.clone()).await.unwrap();
        // b answers the first initiation; the answer is lost on the way
        tokio::time::timeout(Duration::from_secs(2), async {
            while b.peers[&a.public].latest_timestamp.is_none() {
                b.poll().await.unwrap();
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(20)).await;
        let mut lost = [0; 2048];
        let mut responses = 0;
        while let Ok((length, _)) = a.socket.try_recv_from(&mut lost) {
            responses += usize::from(noise::type_word(&lost[..length]) == Some(2));
        }
        assert_eq!(responses, 1);
        // a retries after RETRY; b must not take it for a replay
        a.peers.get_mut(&b.public).unwrap().last_attempt = Some(Instant::now() - RETRY);
        assert_eq!(receive(&mut a, &mut b).await, request);
    }

    #[tokio::test]
    async fn a_failed_send_to_one_endpoint_does_not_fail_the_peer() {
        let (mut a, mut b) = pair().await;
        let mut unsendable = peer(b.public, "100.64.0.2", b.local_addr().unwrap().port());
        // a broadcast address without SO_BROADCAST: the send fails with EACCES
        let reachable = unsendable.endpoints.take().unwrap();
        unsendable.endpoints = Some([vec!["255.255.255.255:9".to_string()], reachable].concat());
        a.update_peers(&[unsendable]);
        let request = packet([100, 64, 0, 1], [100, 64, 0, 2], 9);
        a.send(request.clone()).await.unwrap();
        assert_eq!(receive(&mut a, &mut b).await, request);
    }

    #[tokio::test]
    async fn removed_peer_and_spoofed_source_are_rejected() {
        let (mut a, _) = pair().await;
        assert_eq!(
            a.send(packet([1, 2, 3, 4], [100, 64, 0, 2], 0))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::PermissionDenied
        );
        a.update_peers(&[]);
        assert_eq!(
            a.send(packet([100, 64, 0, 1], [100, 64, 0, 2], 0))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::NotFound
        );
    }

    #[tokio::test]
    async fn authenticated_peer_cannot_spoof_another_nodes_ip() {
        let (mut a, mut b) = pair().await;
        a.send(packet([100, 64, 0, 1], [100, 64, 0, 2], 42))
            .await
            .unwrap();
        receive(&mut a, &mut b).await;
        let malicious = packet([100, 64, 0, 99], [100, 64, 0, 2], 0);
        let state = a.peers.get_mut(&b.public).unwrap();
        let encrypted = state.session.as_mut().unwrap().seal(&malicious).unwrap();
        let Path::Udp(endpoint) = state.active.unwrap() else {
            panic!("expected direct path")
        };
        a.socket.send_to(&encrypted, endpoint).await.unwrap();
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(b.poll().await.unwrap().is_empty());
    }

    #[test]
    fn malformed_ip_packet_is_rejected() {
        assert!(packet_ips(&[0; 10]).is_none());
        let mut invalid = packet([100, 64, 0, 1], [100, 64, 0, 2], 0);
        invalid[2..4].copy_from_slice(&100u16.to_be_bytes());
        assert!(packet_ips(&invalid).is_none());
    }
}

#[cfg(test)]
mod receive_buffer_tests {
    use super::*;
    #[test]
    fn receive_queue_tuning_preserves_send_queue_and_datagrams() {
        let a = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let b = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        a.set_read_timeout(Some(Duration::from_secs(1))).unwrap();
        let socket = socket2::SockRef::from(&a);
        let send_before = socket.send_buffer_size().unwrap();
        let receive_before = socket.recv_buffer_size().unwrap();
        let actual = configure_receive_buffer(&socket).unwrap();
        assert!(actual >= receive_before);
        assert_eq!(socket.send_buffer_size().unwrap(), send_before);
        b.send_to(b"queue-test", a.local_addr().unwrap()).unwrap();
        let mut bytes = [0; 32];
        let (n, _) = a.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[..n], b"queue-test");
    }
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "requires CAP_NET_ADMIN to exceed rmem_max"]
    fn privileged_receive_queue_reaches_target() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let reference = socket2::SockRef::from(&socket);
        assert!(configure_receive_buffer(&reference).unwrap() >= RECEIVE_BUFFER_BYTES);
    }

    #[test]
    fn tuning_is_idempotent_under_kernel_limits() {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let reference = socket2::SockRef::from(&socket);
        let first = configure_receive_buffer(&reference).unwrap();
        assert_eq!(configure_receive_buffer(&reference).unwrap(), first);
    }
}
