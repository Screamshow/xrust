//! Bounded WireGuard mesh with direct UDP and DERP. Disco and tailnet filter enforcement
//! remain separate work; this transport exposes no listeners or LAN forwarding.
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Path {
    Udp(SocketAddr),
    Derp(u16),
}

struct Peer {
    name: Option<String>,
    disco: Option<[u8; 32]>,
    addresses: Vec<IpAddr>,
    endpoints: Vec<SocketAddr>,
    active: Option<Path>,
    derp_region: Option<u16>,
    session: Option<noise::Session>,
    established: Option<Instant>,
    confirmed: bool,
    initiation: Option<noise::Handshake>,
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

impl Peer {
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

impl DirectMesh {
    pub fn set_local_routes(&mut self, routes: Vec<smoltcp::wire::IpCidr>) {
        self.local_routes = routes;
    }
    pub async fn bind(private: StaticSecret, local: Vec<IpAddr>, port: u16) -> io::Result<Self> {
        let mut disco = [0; 32];
        getrandom::fill(&mut disco)
            .map_err(|_| io::Error::other("tailscale: entropy unavailable"))?;
        Ok(Self {
            disco: StaticSecret::from(disco),
            socket: UdpSocket::bind((Ipv4Addr::UNSPECIFIED, port)).await?,
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
            if key == self.public
                || !self
                    .private
                    .diffie_hellman(&PublicKey::from(key))
                    .was_contributory()
            {
                continue;
            }
            let addresses: Vec<IpAddr> = node
                .addresses
                .iter()
                .filter_map(|a| a.split('/').next()?.parse().ok())
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
                addresses: vec![],
                endpoints: vec![],
                active: None,
                derp_region: None,
                session: None,
                established: None,
                confirmed: false,
                initiation: None,
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
            peer.disco = node.disco_key.as_deref().and_then(|s| {
                super::control::parse_key_hex(s.strip_prefix("discokey:").unwrap_or(s))
            });
            peer.endpoints = endpoints;
            peer.derp_region = node.home_derp.filter(|id| *id != 0).or_else(|| {
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
            let handshake = peer.initiation.get_or_insert_with(|| {
                noise::build_initiation(
                    &private.to_bytes(),
                    public,
                    key,
                    None,
                    &noise::tai64n_now(),
                    1,
                )
            });
            for endpoint in &peer.endpoints {
                socket.send_to(handshake.initiation(), endpoint).await?;
            }
            if let (Some(relay), Some(region)) = (relay.as_mut(), peer.derp_region) {
                relay.send(region, *key, handshake.initiation());
            }
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
            Path::Udp(endpoint) => {
                socket.send_to(packet, endpoint).await?;
            }
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
            c.tick(&self.socket).await;
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
        let mut buffer = [0; 65536];
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
                let Some((node, peer)) =
                    self.peers.iter_mut().find(|(_, p)| p.disco == Some(source))
                else {
                    continue;
                };
                if relay_source.is_some_and(|src| src != *node) {
                    continue;
                }
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
                } else if plain.len() == 32 && plain[..2] == [2, 0] {
                    if let Path::Udp(addr) = endpoint {
                        let tx: [u8; 12] = plain[2..14].try_into().unwrap();
                        if let Some(i) = peer.probes.iter().position(|(id, target, sent)| {
                            *id == tx && *target == addr && sent.elapsed() < Duration::from_secs(10)
                        }) {
                            let (_, _, sent) = peer.probes.remove(i).unwrap();
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
                    let confirm = session.seal(&[]).unwrap();
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
                    if !plain.is_empty() {
                        peer.payload();
                    }
                    peer.note_path(endpoint);
                    peer.confirmed = true;
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
                        packets.push(plain);
                    }
                }
                Some(3) if length == noise::COOKIE_REPLY_LEN => {
                    let index = u32::from_le_bytes(packet[4..8].try_into().unwrap());
                    for (key, peer) in &mut self.peers {
                        if let Some(hs) = &mut peer.initiation
                            && hs.sender_index == index
                            && let Ok(cookie) =
                                noise::decrypt_cookie(packet, key, &hs.mac1(), index)
                        {
                            hs.set_cookie(&cookie);
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
            home_derp: None,
            id: 1,
            key: format!("nodekey:{}", super::super::control::to_hex(&key)),
            name: None,
            addresses: vec![format!("{address}/32")],
            allowed_ips: vec![],
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
