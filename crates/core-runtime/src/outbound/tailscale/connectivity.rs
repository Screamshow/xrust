//! Bounded endpoint discovery and DERP selection. STUN uses the data socket,
//! so the advertised mapping is the one peers can actually reach.
use super::derp::DerpMap;
use serde::Serialize;
use std::{
    collections::HashMap,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::{Duration, Instant},
};
use tokio::{
    net::{TcpStream, UdpSocket},
    sync::watch,
    task::{JoinHandle, JoinSet},
};

const COOKIE: u32 = 0x2112a442;
const PROBE_TIMEOUT: Duration = Duration::from_millis(1500);

#[derive(Clone, Debug, Default, Serialize, PartialEq)]
pub struct NetworkInfo {
    pub endpoints: Vec<SocketAddr>,
    pub udp_available: bool,
    pub mapping_varies: bool,
    pub home_derp: Option<u16>,
    pub derp_region: Option<String>,
    pub derp_latency_ms: Option<u64>,
    pub derp_latencies: Vec<(u16, u64)>,
}

fn local_endpoints(port: u16) -> Vec<SocketAddr> {
    let mut out: Vec<_> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|i| match i.ip() {
            IpAddr::V4(ip)
                if !ip.is_loopback()
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_link_local() =>
            {
                Some(SocketAddr::from((ip, port)))
            }
            _ => None,
        })
        .take(32)
        .collect();
    out.sort();
    out.dedup();
    out
}

pub fn stun_request(tx: [u8; 12]) -> [u8; 40] {
    // Tailscale's public STUN service requires SOFTWARE=tailnode and FINGERPRINT.
    // Wire format follows net/stun (Tailscale Inc & contributors, BSD-3-Clause).
    let mut out = [0; 40];
    out[..2].copy_from_slice(&1u16.to_be_bytes());
    out[2..4].copy_from_slice(&20u16.to_be_bytes());
    out[4..8].copy_from_slice(&COOKIE.to_be_bytes());
    out[8..20].copy_from_slice(&tx);
    out[20..24].copy_from_slice(&[0x80, 0x22, 0, 8]);
    out[24..32].copy_from_slice(b"tailnode");
    let mut crc = 0xffffffffu32;
    for byte in &out[..32] {
        crc ^= *byte as u32;
        for _ in 0..8 {
            crc = (crc >> 1) ^ if crc & 1 != 0 { 0xedb88320 } else { 0 };
        }
    }
    let fingerprint = (!crc) ^ 0x5354554e;
    out[32..36].copy_from_slice(&[0x80, 0x28, 0, 4]);
    out[36..40].copy_from_slice(&fingerprint.to_be_bytes());
    out
}

pub fn stun_response(bytes: &[u8], tx: &[u8; 12]) -> Option<SocketAddr> {
    if bytes.len() < 20
        || bytes[..2] != [1, 1]
        || bytes[4..8] != COOKIE.to_be_bytes()
        || bytes[8..20] != *tx
    {
        return None;
    }
    let end = 20 + u16::from_be_bytes(bytes[2..4].try_into().ok()?) as usize;
    if end > bytes.len() {
        return None;
    }
    let mut p = 20;
    while p + 4 <= end {
        let kind = u16::from_be_bytes(bytes[p..p + 2].try_into().ok()?);
        let n = u16::from_be_bytes(bytes[p + 2..p + 4].try_into().ok()?) as usize;
        p += 4;
        if p + n > end {
            return None;
        }
        if matches!(kind, 0x0020 | 0x0001) && n == 8 && bytes[p + 1] == 1 {
            let xor = if kind == 0x0020 { COOKIE } else { 0 };
            let port =
                u16::from_be_bytes(bytes[p + 2..p + 4].try_into().ok()?) ^ (xor >> 16) as u16;
            let ip = Ipv4Addr::from(u32::from_be_bytes(bytes[p + 4..p + 8].try_into().ok()?) ^ xor);
            if port != 0 && !ip.is_unspecified() && !ip.is_multicast() && !ip.is_broadcast() {
                return Some((ip, port).into());
            }
        }
        p += (n + 3) & !3;
    }
    None
}

async fn relay_scores(map: &DerpMap) -> Vec<(u16, u64)> {
    let mut jobs = JoinSet::new();
    for region in map.regions.values().take(64) {
        let id = region.region_id;
        let nodes: Vec<_> = region
            .nodes
            .iter()
            .filter(|n| !n.stun_only)
            .take(2)
            .cloned()
            .collect();
        jobs.spawn(async move {
            let start = Instant::now();
            for node in nodes {
                let address = node
                    .ipv4
                    .as_deref()
                    .and_then(|s| s.parse::<Ipv4Addr>().ok());
                let result = tokio::time::timeout(PROBE_TIMEOUT, async {
                    if let Some(ip) = address {
                        TcpStream::connect((ip, node.port)).await
                    } else {
                        TcpStream::connect((node.host_name.as_str(), node.port)).await
                    }
                })
                .await;
                if let Ok(Ok(_)) = result {
                    return Some((id, start.elapsed().as_millis().max(1) as u64));
                }
            }
            None
        });
    }
    let mut scores = vec![];
    while let Some(result) = jobs.join_next().await {
        if let Ok(Some(score)) = result {
            scores.push(score);
        }
    }
    scores.sort_by_key(|&(id, ms)| (ms, id));
    // Verify only a short list: a fast TCP accept is not proof of a working DERP.
    let mut verified = JoinSet::new();
    for (id, _) in scores.into_iter().take(4) {
        let Some(region) = map.regions.get(&id.to_string()).cloned() else {
            continue;
        };
        verified.spawn(async move {
            tokio::time::timeout(Duration::from_secs(4), async move {
                for node in region.nodes.iter().filter(|n| !n.stun_only).take(2) {
                    let mut secret = [0; 32];
                    if getrandom::fill(&mut secret).is_err() {
                        return None;
                    }
                    if let Ok(client) = super::derp_client::DerpClient::connect(
                        node,
                        x25519_dalek::StaticSecret::from(secret),
                        false,
                    )
                    .await
                    {
                        if let Ok(rtt) = client.ping().await {
                            return Some((id, rtt.as_millis().max(1) as u64));
                        }
                    }
                }
                None
            })
            .await
            .ok()
            .flatten()
        });
    }
    let mut scores = vec![];
    while let Some(result) = verified.join_next().await {
        if let Ok(Some(score)) = result {
            scores.push(score);
        }
    }
    scores.sort_by_key(|&(id, ms)| (ms, id));
    scores
}

fn select_home(info: &mut NetworkInfo, map: &DerpMap, scores: Vec<(u16, u64)>) {
    let best = scores.first().copied();
    // Keep a healthy home if the difference is just measurement noise.
    let selected = info
        .home_derp
        .and_then(|id| scores.iter().copied().find(|s| s.0 == id))
        .filter(|&(_, ms)| best.is_some_and(|(_, best)| ms <= best + 5 || ms <= best * 12 / 10))
        .or(best);
    info.home_derp = selected.map(|s| s.0);
    info.derp_latency_ms = selected.map(|s| s.1);
    info.derp_region = selected
        .and_then(|s| map.regions.get(&s.0.to_string()))
        .map(|r| r.region_name.clone());
    info.derp_latencies = scores;
}

fn apply_measurement(
    info: &mut NetworkInfo,
    map: &DerpMap,
    scores: Vec<(u16, u64)>,
    failures: &mut u8,
) -> Duration {
    if scores.is_empty() {
        *failures = failures.saturating_add(1);
        // An interrupted short-list probe must not erase a working connection.
        // Connection health reports remove a home when it actually fails.
        Duration::from_secs([5, 15, 30][usize::from(failures.saturating_sub(1).min(2))])
    } else {
        *failures = 0;
        select_home(info, map, scores);
        Duration::from_secs(180)
    }
}

struct Transaction {
    target: SocketAddr,
    sent: Instant,
}

pub struct Connectivity {
    pub info: watch::Sender<NetworkInfo>,
    map_tx: watch::Sender<DerpMap>,
    tcp_task: JoinHandle<()>,
    pending: HashMap<[u8; 12], Transaction>,
    observations: HashMap<SocketAddr, (SocketAddr, Instant)>,
    targets: Vec<SocketAddr>,
    last_stun: Instant,
    port: u16,
    recheck_tx: watch::Sender<u64>,
    last_recheck: Instant,
    last_local_check: Instant,
    locals: Vec<SocketAddr>,
}
impl Drop for Connectivity {
    fn drop(&mut self) {
        self.tcp_task.abort();
    }
}

impl Connectivity {
    pub async fn start(socket: &UdpSocket, map: DerpMap) -> io::Result<Self> {
        let port = socket.local_addr()?.port();
        let (info, _) = watch::channel(NetworkInfo {
            endpoints: local_endpoints(port),
            ..Default::default()
        });
        let (map_tx, mut map_rx) = watch::channel(map.clone());
        let task_info = info.clone();
        let (recheck_tx, mut recheck_rx) = watch::channel(0u64);
        let tcp_task = tokio::spawn(async move {
            let mut failures = 0;
            loop {
                let map = map_rx.borrow().clone();
                let scores = relay_scores(&map).await;
                let mut delay = Duration::from_secs(180);
                task_info.send_modify(|info| {
                    delay = apply_measurement(info, &map, scores, &mut failures)
                });
                tokio::select! {
                    _=tokio::time::sleep(delay)=>{},
                    result=recheck_rx.changed()=>{if result.is_err(){break;}},
                    result=map_rx.changed()=>{if result.is_err(){break;}},
                }
            }
        });
        let mut this = Self {
            info,
            map_tx,
            tcp_task,
            pending: HashMap::new(),
            observations: HashMap::new(),
            targets: vec![],
            last_stun: Instant::now() - Duration::from_secs(31),
            port,
            recheck_tx,
            last_recheck: Instant::now() - Duration::from_secs(11),
            last_local_check: Instant::now(),
            locals: local_endpoints(port),
        };
        this.update_map(map);
        this.tick(socket).await;
        // Only this code reads the socket before the engine starts.
        let deadline = tokio::time::Instant::now() + PROBE_TIMEOUT;
        let mut bytes = [0; 2048];
        while let Ok(Ok((n, source))) =
            tokio::time::timeout_at(deadline, socket.recv_from(&mut bytes)).await
        {
            this.receive(&bytes[..n], source);
        }
        // TCP probes have a bounded second-node retry; don't pick a hardcoded region.
        if this.info.borrow().home_derp.is_none() {
            let mut rx = this.info.subscribe();
            let _ = tokio::time::timeout(PROBE_TIMEOUT, rx.changed()).await;
        }
        Ok(this)
    }
    pub fn update_map(&mut self, map: DerpMap) {
        self.targets = map
            .regions
            .values()
            .take(64)
            .filter_map(|r| {
                r.nodes
                    .iter()
                    .find(|n| {
                        n.stun_port >= 0
                            && n.ipv4
                                .as_deref()
                                .is_some_and(|s| s.parse::<Ipv4Addr>().is_ok())
                    })
                    .and_then(|n| {
                        Some(
                            (
                                n.ipv4.as_ref()?.parse::<Ipv4Addr>().ok()?,
                                if n.stun_port == 0 {
                                    3478
                                } else {
                                    n.stun_port as u16
                                },
                            )
                                .into(),
                        )
                    })
            })
            .collect();
        // Identical keepalive maps must not cause continuous probing.
        if serde_json::to_value(&*self.map_tx.borrow()).ok() != serde_json::to_value(&map).ok() {
            self.map_tx.send_replace(map);
        }
    }
    pub fn relay_health(&mut self, health: super::derp_client::RelayHealth) {
        let current = self.info.borrow().clone();
        if let Some(ms) = health.latency_ms {
            if current.home_derp.is_none() {
                let map = self.map_tx.borrow().clone();
                if map.regions.contains_key(&health.region.to_string()) {
                    self.info
                        .send_modify(|info| select_home(info, &map, vec![(health.region, ms)]));
                }
            } else if current.home_derp == Some(health.region) {
                self.info.send_if_modified(|info| {
                    if info.derp_latency_ms == Some(ms) {
                        false
                    } else {
                        info.derp_latency_ms = Some(ms);
                        true
                    }
                });
            }
        } else if current.home_derp == Some(health.region) {
            let map = self.map_tx.borrow().clone();
            let scores = current
                .derp_latencies
                .into_iter()
                .filter(|s| s.0 != health.region)
                .collect();
            self.info
                .send_modify(|info| select_home(info, &map, scores));
            self.recheck();
        }
    }
    fn recheck(&mut self) {
        if self.last_recheck.elapsed() >= Duration::from_secs(10) {
            self.last_recheck = Instant::now();
            self.recheck_tx.send_modify(|n| *n = n.wrapping_add(1));
        }
    }
    pub async fn tick(&mut self, socket: &UdpSocket) {
        if self.last_local_check.elapsed() >= Duration::from_secs(2) {
            self.last_local_check = Instant::now();
            let locals = local_endpoints(self.port);
            if locals != self.locals {
                self.locals = locals;
                self.observations.clear();
                self.pending.clear();
                self.last_stun = Instant::now() - Duration::from_secs(31);
                self.recheck();
            }
        }
        if self.last_stun.elapsed() < Duration::from_secs(30) {
            return;
        }
        self.last_stun = Instant::now();
        self.pending
            .retain(|_, t| t.sent.elapsed() < Duration::from_secs(5));
        self.observations
            .retain(|_, (_, seen)| seen.elapsed() < Duration::from_secs(90));
        self.publish_endpoints();
        for &target in self.targets.iter().take(64) {
            let mut tx = [0; 12];
            if getrandom::fill(&mut tx).is_err() {
                continue;
            }
            if socket.send_to(&stun_request(tx), target).await.is_ok() {
                self.pending.insert(
                    tx,
                    Transaction {
                        target,
                        sent: Instant::now(),
                    },
                );
            }
        }
    }
    pub fn receive(&mut self, bytes: &[u8], source: SocketAddr) -> bool {
        if bytes.len() < 20 || bytes[4..8] != COOKIE.to_be_bytes() {
            return false;
        }
        let tx: [u8; 12] = bytes[8..20].try_into().unwrap();
        if let Some(pending) = self.pending.get(&tx) {
            if pending.target == source && pending.sent.elapsed() < Duration::from_secs(5) {
                if let Some(mapped) = stun_response(bytes, &tx) {
                    self.pending.remove(&tx);
                    self.observations.insert(source, (mapped, Instant::now()));
                    self.publish_endpoints();
                }
            }
        }
        true
    }
    fn publish_endpoints(&self) {
        let mut mapped: Vec<_> = self.observations.values().map(|x| x.0).collect();
        mapped.sort();
        mapped.dedup();
        let varies = mapped.len() > 1;
        let udp = !mapped.is_empty();
        let mut endpoints = local_endpoints(self.port);
        endpoints.extend(mapped);
        endpoints.sort();
        endpoints.dedup();
        self.info.send_if_modified(|info| {
            if info.endpoints == endpoints
                && info.udp_available == udp
                && info.mapping_varies == varies
            {
                return false;
            }
            info.endpoints = endpoints;
            info.udp_available = udp;
            info.mapping_varies = varies;
            true
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn interrupted_measurements_retry_soon_without_erasing_a_working_home() {
        let mut info = NetworkInfo {
            home_derp: Some(22),
            ..Default::default()
        };
        let map = DerpMap::default();
        let mut failures = 0;
        for seconds in [5, 15, 30, 30] {
            assert_eq!(
                apply_measurement(&mut info, &map, vec![], &mut failures),
                Duration::from_secs(seconds)
            );
            assert_eq!(info.home_derp, Some(22));
        }
        assert_eq!(
            apply_measurement(&mut info, &map, vec![(22, 45)], &mut failures),
            Duration::from_secs(180)
        );
        assert_eq!(failures, 0);
    }
    #[test]
    fn request_matches_tailscale_software_and_fingerprint() {
        let p = stun_request([7; 12]);
        assert_eq!(&p[..8], &[0, 1, 0, 20, 0x21, 0x12, 0xa4, 0x42]);
        assert_eq!(&p[20..36], b"\x80\x22\x00\x08tailnode\x80\x28\x00\x04");
        // Independently checked with Python zlib.crc32(header+SOFTWARE)^0x5354554e.
        assert_eq!(&p[36..], &0x759f50d3u32.to_be_bytes());
    }
    #[test]
    fn stun_xor_mapping_is_bound_to_transaction_and_length() {
        let tx = [7; 12];
        let mut p = stun_request(tx)[..20].to_vec();
        p[..2].copy_from_slice(&0x0101u16.to_be_bytes());
        p[2..4].copy_from_slice(&12u16.to_be_bytes());
        p.extend([0, 0x20, 0, 8, 0, 1]);
        p.extend((41642u16 ^ 0x2112).to_be_bytes());
        p.extend((u32::from(Ipv4Addr::new(203, 0, 113, 7)) ^ COOKIE).to_be_bytes());
        assert_eq!(
            stun_response(&p, &tx),
            Some("203.0.113.7:41642".parse().unwrap())
        );
        assert!(stun_response(&p, &[8; 12]).is_none());
        p.pop();
        assert!(stun_response(&p, &tx).is_none());
    }
    #[test]
    fn measured_relay_selection_has_no_region_id_preference() {
        let map = DerpMap::default();
        let mut info = NetworkInfo::default();
        select_home(&mut info, &map, vec![(22, 30), (1, 150)]);
        assert_eq!(info.home_derp, Some(22));
        select_home(&mut info, &map, vec![(4, 28), (22, 30)]);
        assert_eq!(info.home_derp, Some(22));
        select_home(&mut info, &map, vec![(4, 20)]);
        assert_eq!(info.home_derp, Some(4));
        select_home(&mut info, &map, vec![]);
        assert_eq!(info.home_derp, None);
    }

    #[tokio::test]
    async fn authenticated_connection_can_bootstrap_home_after_probe_failure() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let map:DerpMap=serde_json::from_value(serde_json::json!({"Regions":{"22":{"RegionID":22,"RegionCode":"waw","RegionName":"Warsaw","Nodes":[]}}})).unwrap();
        let mut c = Connectivity::start(&socket, map).await.unwrap();
        assert!(c.info.borrow().home_derp.is_none());
        c.relay_health(super::super::derp_client::RelayHealth {
            region: 22,
            latency_ms: Some(47),
        });
        assert_eq!(c.info.borrow().home_derp, Some(22));
        assert_eq!(c.info.borrow().derp_region.as_deref(), Some("Warsaw"));
        c.relay_health(super::super::derp_client::RelayHealth {
            region: 22,
            latency_ms: None,
        });
        assert!(c.info.borrow().home_derp.is_none());
    }

    #[tokio::test]
    async fn stun_response_requires_the_original_source_socket() {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let mut c = Connectivity::start(&socket, DerpMap::default())
            .await
            .unwrap();
        let tx = [7; 12];
        let target = "127.0.0.1:3478".parse().unwrap();
        c.pending.insert(
            tx,
            Transaction {
                target,
                sent: Instant::now(),
            },
        );
        let mut p = stun_request(tx)[..20].to_vec();
        p[..2].copy_from_slice(&0x0101u16.to_be_bytes());
        p[2..4].copy_from_slice(&12u16.to_be_bytes());
        p.extend([0, 0x20, 0, 8, 0, 1]);
        p.extend((41642u16 ^ 0x2112).to_be_bytes());
        p.extend((u32::from(Ipv4Addr::new(203, 0, 113, 7)) ^ COOKIE).to_be_bytes());
        c.receive(&p, "127.0.0.1:9999".parse().unwrap());
        assert!(!c.info.borrow().udp_available);
        c.receive(&p, target);
        assert!(c.info.borrow().udp_available);
        assert!(
            c.info
                .borrow()
                .endpoints
                .contains(&"203.0.113.7:41642".parse().unwrap())
        );
    }
}
