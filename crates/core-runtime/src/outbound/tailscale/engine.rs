//! Tailscale network engine: WireGuard peer mesh, smoltcp userspace stack,
//! and DERP relay integration.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::{Duration, Instant};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{
    ChecksumCapabilities, Device, DeviceCapabilities, Medium, RxToken as PhyRxToken,
    TxToken as PhyTxToken,
};
use smoltcp::socket::tcp::State as TcpState;
use smoltcp::socket::tcp::{Socket as TcpSock, SocketBuffer as TcpBuffer};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};
use tokio::sync::{mpsc, oneshot};

use super::mesh::DirectMesh;
use crate::inbound::Target;
use crate::logging;
use crate::outbound::tailscale::config::TailscaleConfig;
use crate::outbound::tailscale::control::PeerObj;
use crate::outbound::tailscale::derp::DerpMap;
use smoltcp::socket::udp::{PacketBuffer, PacketMetadata, Socket as UdpSock};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

pub enum Cmd {
    UpdateForwardingReady {
        ready: bool,
    },
    UpdateLocalAddresses {
        addresses: Vec<IpAddr>,
        resp: oneshot::Sender<io::Result<()>>,
    },
    UpdateLanApproval {
        approved: bool,
        exit_approved: bool,
    },
    UpdateAccess {
        rules: Vec<super::access::Rule>,
    },
    TcpConnect {
        id: u32,
        dst: SocketAddr,
        to_caller: mpsc::Sender<Vec<u8>>,
        resp: oneshot::Sender<Result<(), String>>,
    },
    TcpData {
        id: u32,
        bytes: Vec<u8>,
    },
    TcpEof {
        id: u32,
    },
    TcpClose {
        id: u32,
    },
    #[allow(clippy::type_complexity)]
    UdpOpen {
        target: SocketAddr,
        resp: oneshot::Sender<Result<(u16, mpsc::Receiver<Vec<u8>>), String>>,
    },
    UdpSend {
        port: u16,
        bytes: Vec<u8>,
    },
    UdpClose {
        port: u16,
    },
    UpdatePeers {
        peers: Vec<PeerObj>,
        derp_map: Option<DerpMap>,
    },
}

pub struct TailscaleShared {
    pub transport: std::sync::RwLock<serde_json::Value>,
    pub cmd_tx: mpsc::Sender<Cmd>,
    pub next_id: AtomicU32,
    local_ip: std::sync::RwLock<IpAddr>,
    pub control_connected: std::sync::atomic::AtomicBool,
    pub routes_approved: std::sync::atomic::AtomicBool,
    pub exit_approved: std::sync::atomic::AtomicBool,
}

impl TailscaleShared {
    pub fn local_ip(&self) -> IpAddr {
        *self.local_ip.read().unwrap()
    }
}

pub struct TailscaleDevice {
    rx: VecDeque<Vec<u8>>,
    tx: VecDeque<Vec<u8>>,
    free: Vec<Vec<u8>>,
    mtu: usize,
}

impl TailscaleDevice {
    pub fn new(mtu: usize) -> Self {
        Self {
            rx: VecDeque::new(),
            tx: VecDeque::new(),
            free: Vec::new(),
            mtu,
        }
    }
}

pub struct TsRxToken {
    buffer: Vec<u8>,
}

impl PhyRxToken for TsRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.buffer)
    }
}

pub struct TsTxToken<'a> {
    queue: &'a mut VecDeque<Vec<u8>>,
    free: &'a mut Vec<Vec<u8>>,
}

impl PhyTxToken for TsTxToken<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut buffer = match self.free.pop() {
            Some(mut b) => {
                b.resize(len, 0);
                b
            }
            None => vec![0; len],
        };
        let result = f(&mut buffer);
        self.queue.push_back(buffer);
        result
    }
}

impl Device for TailscaleDevice {
    type RxToken<'a> = TsRxToken;
    type TxToken<'a> = TsTxToken<'a>;

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu;
        caps.medium = Medium::Ip;
        caps.checksum = ChecksumCapabilities::default();
        caps
    }

    fn receive(
        &mut self,
        _timestamp: SmolInstant,
    ) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        self.rx.pop_front().map(move |buffer| {
            let rx = TsRxToken { buffer };
            let tx = TsTxToken {
                queue: &mut self.tx,
                free: &mut self.free,
            };
            (rx, tx)
        })
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(TsTxToken {
            queue: &mut self.tx,
            free: &mut self.free,
        })
    }
}

struct TcpConn {
    handle: SocketHandle,
    #[allow(dead_code)]
    dst: SocketAddr,
    to_caller: mpsc::Sender<Vec<u8>>,
    resp: Option<oneshot::Sender<Result<(), String>>>,
    from_caller: VecDeque<Vec<u8>>,
    created: Instant,
    caller_eof: bool,
}

pub fn spawn_tailscale_engine(
    cfg: TailscaleConfig,
    local_ip: IpAddr,
    cmd_rx: mpsc::Receiver<Cmd>,
) -> Arc<TailscaleShared> {
    spawn_tailscale_engine_with_mesh(cfg, local_ip, cmd_rx, None)
}

pub fn spawn_tailscale_engine_with_mesh(
    cfg: TailscaleConfig,
    local_ip: IpAddr,
    cmd_rx: mpsc::Receiver<Cmd>,
    mesh: Option<DirectMesh>,
) -> Arc<TailscaleShared> {
    spawn_tailscale_engine_with_tun(cfg, local_ip, cmd_rx, mesh, None)
}
pub fn spawn_tailscale_engine_with_tun(
    cfg: TailscaleConfig,
    local_ip: IpAddr,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    mut mesh: Option<DirectMesh>,
    tun: Option<super::lan::LanTun>,
) -> Arc<TailscaleShared> {
    let (cmd_tx, mut internal_cmd_rx) = mpsc::channel(128);

    // Forwarder from external commands to internal loop
    let cmd_tx_clone = cmd_tx.clone();
    tokio::spawn(async move {
        while let Some(cmd) = cmd_rx.recv().await {
            if cmd_tx_clone.send(cmd).await.is_err() {
                break;
            }
        }
    });

    let shared = Arc::new(TailscaleShared {
        transport: std::sync::RwLock::new(serde_json::Value::Null),
        local_ip: std::sync::RwLock::new(local_ip),
        control_connected: std::sync::atomic::AtomicBool::new(false),
        routes_approved: std::sync::atomic::AtomicBool::new(false),
        exit_approved: std::sync::atomic::AtomicBool::new(false),
        cmd_tx,
        next_id: AtomicU32::new(1),
    });

    let weak = Arc::downgrade(&shared);
    tokio::spawn(async move {
        let mtu = cfg.system_interface_mtu.unwrap_or(1280).min(1280) as usize;
        let mut lan_rules = vec![];
        let mut lan_approved = false;
        let mut exit_approved = false;
        let mut forwarding_ready = tun.is_none();
        let mut device = TailscaleDevice::new(mtu);

        let local_cidr = match local_ip {
            IpAddr::V4(ip) => IpCidr::new(IpAddress::from(ip), 32),
            IpAddr::V6(ip) => IpCidr::new(IpAddress::from(ip), 128),
        };

        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand_seed();
        let mut iface = Interface::new(iface_cfg, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(local_cidr);
            if let Some(mesh) = &mesh {
                for ip in mesh.local_ips() {
                    if *ip != local_ip {
                        let _ = addrs.push(IpCidr::new(
                            IpAddress::from(*ip),
                            if ip.is_ipv4() { 32 } else { 128 },
                        ));
                    }
                }
            }
        });
        let _ = iface
            .routes_mut()
            .add_default_ipv4_route(std::net::Ipv4Addr::UNSPECIFIED);
        let _ = iface
            .routes_mut()
            .add_default_ipv6_route(std::net::Ipv6Addr::UNSPECIFIED);

        let mut sockets = SocketSet::new(vec![]);
        let mut web = cfg
            .luci_access
            .then(|| super::web::WebBridge::with_exit(cfg.ssh_access, cfg.advertise_exit_node));
        let mut tcp_conns: HashMap<u32, TcpConn> = HashMap::new();
        type UdpSession = (SocketHandle, SocketAddr, mpsc::Sender<Vec<u8>>, Instant);
        let mut udp_sessions: HashMap<u16, UdpSession> = HashMap::new();
        let mut _peers: Vec<PeerObj> = Vec::new();

        let mut next_ephemeral_port: u16 = 40000;
        let poll_interval = Duration::from_millis(5);
        let mut tun_read_packets = 0u64;
        let mut tun_write_errors = 0u64;
        let mut tun_send_errors = 0u64;
        let mut busy_cycles = 0u64;
        let mut transport_updated = Instant::now() - Duration::from_secs(2);

        loop {
            let now = SmolInstant::now();
            let mut queued_work = false;
            let mut tun_read_healthy = true;

            // 1. Drain commands
            while let Ok(cmd) = internal_cmd_rx.try_recv() {
                match cmd {
                    Cmd::UpdateForwardingReady { ready } => forwarding_ready = ready,
                    Cmd::UpdateLocalAddresses { addresses, resp } => {
                        if addresses.is_empty()
                            || addresses.len() > 2
                            || addresses
                                .iter()
                                .any(|ip| ip.is_unspecified() || ip.is_multicast())
                        {
                            let _ = resp.send(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "tailscale: invalid assigned addresses",
                            )));
                            continue;
                        }
                        // Existing sessions belong to the old local address. Drop
                        // them before permitting any packets for the new identity.
                        tcp_conns.clear();
                        udp_sessions.clear();
                        web = cfg.luci_access.then(|| {
                            let mut bridge = super::web::WebBridge::new(cfg.ssh_access);
                            bridge.update_rules(lan_rules.clone());
                            bridge
                        });
                        sockets = SocketSet::new(vec![]);
                        device.rx.clear();
                        device.tx.clear();
                        iface.update_ip_addrs(|ips| {
                            ips.clear();
                            for ip in &addresses {
                                ips.push(IpCidr::new(
                                    (*ip).into(),
                                    if ip.is_ipv4() { 32 } else { 128 },
                                ))
                                .unwrap();
                            }
                        });
                        if let Some(mesh) = &mut mesh {
                            mesh.set_local_ips(addresses.clone());
                        }
                        if let Some(shared) = weak.upgrade() {
                            *shared.local_ip.write().unwrap() = addresses[0];
                        }
                        let _ = resp.send(Ok(()));
                    }
                    Cmd::UpdateLanApproval {
                        approved,
                        exit_approved: exit,
                    } => {
                        lan_approved = approved;
                        exit_approved = exit;
                        if let Some(web) = &mut web {
                            web.set_exit_approved(exit);
                        }
                    }
                    Cmd::UpdateAccess { rules } => {
                        lan_rules = rules.clone();
                        if let Some(web) = &mut web {
                            web.update_rules(rules);
                        }
                    }
                    Cmd::TcpConnect {
                        id,
                        dst,
                        to_caller,
                        resp,
                    } => {
                        let rx_buf = TcpBuffer::new(vec![0; 65536]);
                        let tx_buf = TcpBuffer::new(vec![0; 65536]);
                        let mut socket = TcpSock::new(rx_buf, tx_buf);

                        let local_port = next_ephemeral_port;
                        next_ephemeral_port = if next_ephemeral_port >= 65000 {
                            40000
                        } else {
                            next_ephemeral_port + 1
                        };

                        let smol_addr = match dst.ip() {
                            IpAddr::V4(v4) => IpAddress::Ipv4(v4),
                            IpAddr::V6(v6) => IpAddress::Ipv6(v6),
                        };

                        match socket.connect(iface.context(), (smol_addr, dst.port()), local_port) {
                            Ok(()) => {
                                let handle = sockets.add(socket);
                                tcp_conns.insert(
                                    id,
                                    TcpConn {
                                        handle,
                                        dst,
                                        to_caller,
                                        resp: Some(resp),
                                        from_caller: VecDeque::new(),
                                        created: Instant::now(),
                                        caller_eof: false,
                                    },
                                );
                            }
                            Err(e) => {
                                let _ = resp.send(Err(format!("smoltcp connect: {e:?}")));
                            }
                        }
                    }
                    Cmd::TcpData { id, bytes } => {
                        if let Some(conn) = tcp_conns.get_mut(&id) {
                            conn.from_caller.push_back(bytes);
                        }
                    }
                    Cmd::TcpEof { id } => {
                        if let Some(conn) = tcp_conns.get_mut(&id) {
                            conn.caller_eof = true;
                        }
                    }
                    Cmd::TcpClose { id } => {
                        if let Some(conn) = tcp_conns.remove(&id) {
                            let socket = sockets.get_mut::<TcpSock>(conn.handle);
                            socket.abort();
                            sockets.remove(conn.handle);
                        }
                    }
                    Cmd::UdpOpen { target, resp } => {
                        let local_port = next_ephemeral_port;
                        next_ephemeral_port = if next_ephemeral_port >= 65000 {
                            40000
                        } else {
                            next_ephemeral_port + 1
                        };
                        let (tx, rx) = mpsc::channel(64);
                        let mut socket = UdpSock::new(
                            PacketBuffer::new(vec![PacketMetadata::EMPTY; 16], vec![0; 65536]),
                            PacketBuffer::new(vec![PacketMetadata::EMPTY; 16], vec![0; 65536]),
                        );
                        if socket.bind(local_port).is_err() {
                            let _ = resp.send(Err("tailscale: UDP bind failed".into()));
                            continue;
                        }
                        udp_sessions.insert(
                            local_port,
                            (sockets.add(socket), target, tx, Instant::now()),
                        );
                        let _ = resp.send(Ok((local_port, rx)));
                    }
                    Cmd::UdpSend { port, bytes } => {
                        if let Some((handle, target, _, activity)) = udp_sessions.get_mut(&port) {
                            let _ = sockets
                                .get_mut::<UdpSock>(*handle)
                                .send_slice(&bytes, *target);
                            *activity = Instant::now();
                        }
                    }
                    Cmd::UdpClose { port } => {
                        if let Some((handle, _, _, _)) = udp_sessions.remove(&port) {
                            sockets.remove(handle);
                        }
                    }
                    Cmd::UpdatePeers {
                        peers: new_peers,
                        derp_map,
                    } => {
                        _peers = new_peers;
                        if let Some(mesh) = &mut mesh {
                            mesh.update_peers(&_peers);
                            if let Some(map) = derp_map {
                                mesh.update_relay_map(map);
                            }
                        }
                        logging::debug(format_args!(
                            "tailscale[{}]: updated peer table with {} nodes",
                            cfg.tag,
                            _peers.len()
                        ));
                    }
                }
            }

            // 2. Pump TCP data from caller to smoltcp sockets
            for conn in tcp_conns.values_mut() {
                let socket = sockets.get_mut::<TcpSock>(conn.handle);
                if socket.state() == TcpState::Established {
                    #[allow(clippy::collapsible_if)]
                    if let Some(resp) = conn.resp.take() {
                        let _ = resp.send(Ok(()));
                    }
                }

                while let Some(front) = conn.from_caller.front_mut() {
                    if front.is_empty() {
                        conn.from_caller.pop_front();
                        continue;
                    }
                    if socket.can_send() {
                        match socket.send_slice(front) {
                            Ok(n) => {
                                front.drain(..n);
                            }
                            Err(_) => break,
                        }
                    } else {
                        break;
                    }
                }

                if conn.caller_eof && conn.from_caller.is_empty() && socket.can_send() {
                    socket.close();
                }
            }

            if let Some(mesh) = &mut mesh {
                if transport_updated.elapsed() >= Duration::from_secs(1) {
                    if let Some(shared) = weak.upgrade() {
                        let mut diagnostics = mesh.diagnostics();
                        diagnostics["counters"] = serde_json::json!({"tun_read_packets":tun_read_packets,"tun_write_errors":tun_write_errors,"tun_send_errors":tun_send_errors,"busy_cycles":busy_cycles});
                        *shared.transport.write().unwrap() = diagnostics;
                    }
                    transport_updated = Instant::now();
                }
                if let Ok(packets) = mesh.poll().await {
                    queued_work |= mesh.more_work();
                    for packet in packets {
                        if forwarding_ready
                            && let Some(tun) = &tun
                            && !super::mesh::packet_ips(&packet)
                                .is_some_and(|(_, dst, _)| mesh.local_ips().contains(&dst))
                            && ((lan_approved
                                && super::lan::permitted(
                                    &packet,
                                    &cfg.advertise_routes,
                                    &lan_rules,
                                ))
                                || (exit_approved
                                    && super::lan::exit_permitted(&packet, &lan_rules)))
                        {
                            if tun.write(&packet).is_err() {
                                tun_write_errors += 1;
                            }
                            continue;
                        }
                        if super::mesh::packet_ips(&packet)
                            .is_some_and(|(_, dst, _)| mesh.local_ips().contains(&dst))
                        {
                            device.rx.push_back(packet);
                        }
                    }
                }
                if forwarding_ready && let Some(tun) = &tun {
                    for index in 0..256 {
                        match tun.read() {
                            Ok(Some(packet)) => {
                                tun_read_packets += 1;
                                if index == 255 {
                                    queued_work = true;
                                }
                                if mesh.send(packet).await.is_err() {
                                    tun_send_errors += 1;
                                }
                            }
                            Ok(None) => break,
                            Err(_) => {
                                tun_read_healthy = false;
                                break;
                            }
                        }
                    }
                }
            }
            // 3. Poll smoltcp stack
            if let Some(web) = &mut web {
                web.poll(&mut sockets);
            }
            let _ = iface.poll(now, &mut device, &mut sockets);

            // 4. Pump TCP data from smoltcp sockets to callers
            let mut closed_ids = Vec::new();
            for (id, conn) in tcp_conns.iter_mut() {
                let socket = sockets.get_mut::<TcpSock>(conn.handle);
                while socket.can_recv() {
                    let accepted = socket.recv(|data| {
                        let size = data.len().min(8192);
                        if conn.to_caller.try_send(data[..size].to_vec()).is_ok() {
                            (size, true)
                        } else {
                            (0, false)
                        }
                    });
                    if !matches!(accepted, Ok(true)) {
                        break;
                    }
                }

                match socket.state() {
                    TcpState::Closed | TcpState::TimeWait => {
                        closed_ids.push(*id);
                    }
                    TcpState::SynSent if conn.created.elapsed() > CONNECT_TIMEOUT => {
                        if let Some(resp) = conn.resp.take() {
                            let _ = resp.send(Err("connect timed out".to_string()));
                        }
                        closed_ids.push(*id);
                    }
                    _ => {}
                }
            }

            for id in closed_ids {
                if let Some(conn) = tcp_conns.remove(&id) {
                    sockets.remove(conn.handle);
                }
            }

            let mut expired = Vec::new();
            for (port, (handle, target, replies, activity)) in &mut udp_sessions {
                let socket = sockets.get_mut::<UdpSock>(*handle);
                while let Ok((bytes, metadata)) = socket.recv() {
                    if metadata.endpoint.addr == IpAddress::from(target.ip())
                        && metadata.endpoint.port == target.port()
                    {
                        let _ = replies.try_send(bytes.to_vec());
                        *activity = Instant::now();
                    }
                }
                if replies.is_closed() || activity.elapsed() >= cfg.udp_timeout {
                    expired.push(*port);
                }
            }
            for port in expired {
                if let Some((handle, _, _, _)) = udp_sessions.remove(&port) {
                    sockets.remove(handle);
                }
            }

            // Encrypt and send stack output through the mapped WireGuard peer.
            while let Some(packet) = device.tx.pop_front() {
                if let Some(mesh) = &mut mesh {
                    let _ = mesh.send(packet).await;
                }
            }

            if internal_cmd_rx.is_closed() && internal_cmd_rx.is_empty() {
                break;
            }

            if queued_work {
                busy_cycles += 1;
                tokio::task::yield_now().await;
            } else {
                let network = async {
                    if let Some(mesh) = &mesh {
                        if mesh.readable().await.is_err() {
                            tokio::time::sleep(poll_interval).await;
                        }
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                let forwarding = async {
                    if forwarding_ready
                        && tun_read_healthy
                        && let Some(tun) = &tun
                    {
                        if tun.readable().await.is_err() {
                            tokio::time::sleep(poll_interval).await;
                        }
                    } else {
                        std::future::pending::<()>().await;
                    }
                };
                tokio::select! {_=tokio::time::sleep(poll_interval)=>{},_=network=>{},_=forwarding=>{}}
            }
        }
    });

    shared
}

fn rand_seed() -> u64 {
    let mut b = [0u8; 8];
    getrandom::fill(&mut b).expect("getrandom seed");
    u64::from_le_bytes(b)
}

async fn resolve_host(host: &str, port: u16) -> io::Result<SocketAddr> {
    let s = format!("{host}:{port}");
    tokio::net::lookup_host(&s)
        .await?
        .next()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "domain lookup failed"))
}

pub async fn resolve_target(target: &Target) -> io::Result<SocketAddr> {
    match target {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => resolve_host(host, *port).await,
    }
}

#[cfg(test)]
mod mesh_tests {
    use super::*;
    use x25519_dalek::StaticSecret;

    fn node(secret: &StaticSecret, ip: &str, port: u16) -> PeerObj {
        PeerObj {
            disco_key: None,
            home_derp: None,
            id: 1,
            key: super::super::control::node_key_str(&x25519_dalek::PublicKey::from(secret)),
            name: None,
            addresses: vec![format!("{ip}/32")],
            allowed_ips: vec![],
            endpoints: Some(vec![format!("127.0.0.1:{port}")]),
            derp: None,
            online: Some(true),
        }
    }

    #[tokio::test]
    async fn tcp_and_udp_roundtrip_through_encrypted_mesh() {
        mesh_roundtrip(false).await;
    }

    #[tokio::test]
    async fn reassigned_local_ip_restores_encrypted_tcp_and_udp() {
        mesh_roundtrip(true).await;
    }

    async fn mesh_roundtrip(reassign: bool) {
        let left_key = StaticSecret::from([3; 32]);
        let right_key = StaticSecret::from([4; 32]);
        let mut left = DirectMesh::bind(left_key.clone(), vec!["100.64.0.1".parse().unwrap()], 0)
            .await
            .unwrap();
        let mut right = DirectMesh::bind(right_key.clone(), vec!["100.64.0.2".parse().unwrap()], 0)
            .await
            .unwrap();
        left.update_peers(&[node(
            &right_key,
            "100.64.0.2",
            right.local_addr().unwrap().port(),
        )]);
        right.update_peers(&[node(
            &left_key,
            "100.64.0.1",
            left.local_addr().unwrap().port(),
        )]);
        let left_port = left.local_addr().unwrap().port();
        let (changes, mut changed) = mpsc::channel::<(String, oneshot::Sender<()>)>(1);
        let server = tokio::spawn(async move {
            let mut device = TailscaleDevice::new(1280);
            let mut iface = Interface::new(
                IfaceConfig::new(HardwareAddress::Ip),
                &mut device,
                SmolInstant::now(),
            );
            iface.update_ip_addrs(|ips| {
                ips.push("100.64.0.2/32".parse().unwrap()).unwrap();
            });
            iface
                .routes_mut()
                .add_default_ipv4_route(std::net::Ipv4Addr::UNSPECIFIED)
                .unwrap();
            let mut sockets = SocketSet::new(vec![]);
            let mut udp = UdpSock::new(
                PacketBuffer::new(vec![PacketMetadata::EMPTY; 16], vec![0; 65536]),
                PacketBuffer::new(vec![PacketMetadata::EMPTY; 16], vec![0; 65536]),
            );
            udp.bind(1234).unwrap();
            let udp_handle = sockets.add(udp);
            let mut tcp = TcpSock::new(
                TcpBuffer::new(vec![0; 65536]),
                TcpBuffer::new(vec![0; 65536]),
            );
            tcp.listen(4321).unwrap();
            let tcp_handle = sockets.add(tcp);
            loop {
                if let Ok((address, done)) = changed.try_recv() {
                    right.update_peers(&[node(&left_key, &address, left_port)]);
                    let tcp = sockets.get_mut::<TcpSock>(tcp_handle);
                    tcp.abort();
                    tcp.listen(4321).unwrap();
                    let _ = done.send(());
                }
                device.rx.extend(right.poll().await.unwrap());
                iface.poll(SmolInstant::now(), &mut device, &mut sockets);
                let udp = sockets.get_mut::<UdpSock>(udp_handle);
                if let Ok((bytes, metadata)) = udp.recv() {
                    let bytes = bytes.to_vec();
                    udp.send_slice(&bytes, metadata.endpoint).unwrap();
                }
                let tcp = sockets.get_mut::<TcpSock>(tcp_handle);
                if tcp.can_recv() && tcp.can_send() {
                    let mut bytes = [0; 1024];
                    let n = tcp.recv_slice(&mut bytes).unwrap();
                    tcp.send_slice(&bytes[..n]).unwrap();
                }
                while let Some(packet) = device.tx.pop_front() {
                    right.send(packet).await.unwrap();
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        struct Abort(tokio::task::JoinHandle<()>);
        impl Drop for Abort {
            fn drop(&mut self) {
                self.0.abort();
            }
        }
        let _server = Abort(server);
        let config = serde_json::json!({"type":"tailscale", "tag":"test", "ephemeral":true});
        let cfg = TailscaleConfig::parse(config.as_object().unwrap(), "test").unwrap();
        let (_tx, rx) = mpsc::channel(1);
        let shared =
            spawn_tailscale_engine_with_mesh(cfg, "100.64.0.1".parse().unwrap(), rx, Some(left));
        let addresses = if reassign {
            vec!["100.64.0.1", "100.64.0.3", "100.64.0.1"]
        } else {
            vec!["100.64.0.1"]
        };
        for (i, address) in addresses.into_iter().enumerate() {
            if i > 0 {
                let (done, wait) = oneshot::channel();
                changes.send((address.into(), done)).await.unwrap();
                wait.await.unwrap();
                let (resp, wait) = oneshot::channel();
                shared
                    .cmd_tx
                    .send(Cmd::UpdateLocalAddresses {
                        addresses: vec![address.parse().unwrap()],
                        resp,
                    })
                    .await
                    .unwrap();
                wait.await.unwrap().unwrap();
                assert_eq!(shared.local_ip(), address.parse::<IpAddr>().unwrap());
            }
            tokio::time::timeout(Duration::from_secs(3), async {
                let (result, wait) = oneshot::channel();
                shared
                    .cmd_tx
                    .send(Cmd::UdpOpen {
                        target: "100.64.0.2:1234".parse().unwrap(),
                        resp: result,
                    })
                    .await
                    .unwrap();
                let (port, mut replies) = wait.await.unwrap().unwrap();
                shared
                    .cmd_tx
                    .send(Cmd::UdpSend {
                        port,
                        bytes: b"UDP test".to_vec(),
                    })
                    .await
                    .unwrap();
                assert_eq!(replies.recv().await.unwrap(), b"UDP test");
                shared.cmd_tx.send(Cmd::UdpClose { port }).await.unwrap();
                let (result, wait) = oneshot::channel();
                let (to_caller, mut data) = mpsc::channel(16);
                shared
                    .cmd_tx
                    .send(Cmd::TcpConnect {
                        id: 1,
                        dst: "100.64.0.2:4321".parse().unwrap(),
                        to_caller,
                        resp: result,
                    })
                    .await
                    .unwrap();
                wait.await.unwrap().unwrap();
                shared
                    .cmd_tx
                    .send(Cmd::TcpData {
                        id: 1,
                        bytes: b"TCP test".to_vec(),
                    })
                    .await
                    .unwrap();
                assert_eq!(data.recv().await.unwrap(), b"TCP test");
                shared.cmd_tx.send(Cmd::TcpClose { id: 1 }).await.unwrap();
            })
            .await
            .unwrap();
        }
        drop(_tx);
        drop(shared);
    }
}
