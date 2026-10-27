//! Tailscale endpoint outbound implementation.
//!
//! Native TS2021 registration and initial network map over authenticated Noise.
//! Direct WireGuard UDP and DERP are connected to the stack. Discovery and incoming
//! router-service access remain unfinished.

pub mod access;
pub mod config;
pub mod connectivity;
pub mod control;
pub mod derp;
pub mod derp_client;
pub mod engine;
pub mod lan;
pub mod mesh;
pub mod noise;
pub mod peer_dns;
pub mod service;
pub mod session;
pub mod web;

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use serde_json::{Map, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};

use crate::inbound::{AnyStream, Target};

use crate::outbound::quic::udp_loopback_pair;
use crate::outbound::tailscale::config::TailscaleConfig;
use crate::outbound::tailscale::control::{
    Hostinfo, RegisterRequest, RegisterResponse, load_or_create_keys, node_key_str,
};
use crate::outbound::tailscale::engine::{Cmd, TailscaleShared, resolve_target};
use crate::outbound::tailscale::session::{CAPABILITY_VERSION, ControlSession};

const CALLER_BUF: usize = 65_536;
const REPLY_QUEUE: usize = 32;
const SCRATCH_BUF: usize = 16_384;

/// Seconds before the next control attempt. A success sets the delay to 0
/// so the stream reads on at once; a failure after it must still wait.
fn retry_delay(previous: u64) -> u64 {
    (previous * 2).clamp(1, 30)
}
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

fn assigned_addresses(node: &control::NodeObj) -> io::Result<Vec<IpAddr>> {
    let mut addresses = node
        .addresses
        .iter()
        .map(|address| {
            let cidr = address.parse::<smoltcp::wire::IpCidr>().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tailscale: invalid assigned address",
                )
            })?;
            let ip: IpAddr = cidr.address().into();
            if cidr.prefix_len() != if ip.is_ipv4() { 32 } else { 128 }
                || ip.is_unspecified()
                || ip.is_multicast()
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "tailscale: invalid assigned address",
                ));
            }
            Ok(ip)
        })
        .collect::<io::Result<Vec<_>>>()?;
    addresses.sort();
    addresses.dedup();
    if addresses.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "tailscale: server returned no assigned address",
        ));
    }
    if addresses.len() > 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tailscale: missing or excessive assigned addresses",
        ));
    }
    Ok(addresses)
}

/// Tailscale endpoint outbound.
#[derive(Clone)]
pub struct Tailscale {
    cfg: TailscaleConfig,
    shared: Arc<AsyncMutex<Option<Arc<TailscaleShared>>>>,
}

impl std::fmt::Debug for Tailscale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tailscale")
            .field("tag", &self.cfg.tag)
            .field("control_url", &self.cfg.control_url)
            .finish()
    }
}

impl Tailscale {
    pub fn build(obj: &Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let cfg = TailscaleConfig::parse(obj, at)?;
        Ok(Self {
            cfg,
            shared: Arc::new(AsyncMutex::new(None)),
        })
    }

    /// Register this identity. AuthURL is returned to the caller for browser login;
    /// an authorized registration is not evidence that the data plane is ready.
    pub async fn register(&self) -> io::Result<RegisterResponse> {
        self.register_followup(None).await
    }

    /// Complete browser authorization with the previously returned AuthURL.
    /// Persistent state is required so follow-up uses the same node identity.
    pub async fn register_followup(&self, followup: Option<&str>) -> io::Result<RegisterResponse> {
        self.register_context(followup)
            .await
            .map(|(response, _, _, _)| response)
    }

    async fn register_context(
        &self,
        followup: Option<&str>,
    ) -> io::Result<(
        RegisterResponse,
        Option<super::tailscale::control::MapResponse>,
        x25519_dalek::StaticSecret,
        x25519_dalek::StaticSecret,
    )> {
        if followup.is_some() && (self.cfg.ephemeral || self.cfg.state_directory.is_none()) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tailscale: browser follow-up requires persistent identity",
            ));
        }
        let (machine, node) =
            load_or_create_keys(self.cfg.state_directory.as_deref(), self.cfg.ephemeral)?;
        let mut session = ControlSession::connect(&self.cfg.control_url, machine.clone()).await?;
        let node_key = node_key_str(&x25519_dalek::PublicKey::from(&node));
        let mut response =
            session
                .register(&RegisterRequest {
                    version: CAPABILITY_VERSION,
                    node_key: node_key.clone(),
                    auth: self.cfg.auth_key.as_ref().map(|key| {
                        super::tailscale::control::AuthObj {
                            auth_key: key.clone(),
                        }
                    }),
                    hostinfo: Hostinfo::new(
                        self.cfg.hostname.as_deref().unwrap_or("rust-x"),
                        &self
                            .cfg
                            .offered_routes()
                            .iter()
                            .map(ToString::to_string)
                            .collect::<Vec<_>>(),
                    ),
                    ephemeral: self.cfg.ephemeral,
                    followup: followup.map(ToString::to_string),
                })
                .await?;
        let map = if response.machine_authorized == Some(true) {
            let map = session
                .initial_map(&node_key, self.cfg.hostname.as_deref().unwrap_or("rust-x"))
                .await?;
            response.node = map.node.clone();
            Some(map)
        } else {
            None
        };
        Ok((response, map, node, machine))
    }

    pub async fn shared(&self) -> io::Result<Arc<TailscaleShared>> {
        let mut guard = self.shared.lock().await;
        if let Some(shared) = &*guard {
            return Ok(Arc::clone(shared));
        }

        let (response, map, node_key, machine) = self.register_context(None).await?;
        if response.machine_authorized != Some(true) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tailscale: authorization required; retrieve AuthURL through register()",
            ));
        }
        let local_ips =
            assigned_addresses(response.node.as_ref().ok_or_else(|| {
                io::Error::other("tailscale: registration has no assigned address")
            })?)?;
        let local_vip = local_ips[0];
        let mut expected_addresses = local_ips.clone();
        let (_cmd_tx, cmd_rx) = mpsc::channel(128);
        let mut mesh =
            mesh::DirectMesh::bind(node_key.clone(), local_ips, self.cfg.listen_port).await?;
        let (network_tx, mut network_rx) =
            tokio::sync::watch::channel(connectivity::NetworkInfo::default());
        let mut home = None;
        if let Some(derp_map) = map.as_ref().and_then(|m| m.derp_map.clone()) {
            network_rx = mesh.discover(derp_map.clone()).await?;
            home = network_rx.borrow().home_derp;
            mesh.set_relay(derp_client::RelayManager::new(
                node_key.clone(),
                derp_map,
                home,
            ));
        }
        mesh.update_peers(map.as_ref().and_then(|m| m.peers.as_deref()).unwrap_or(&[]));
        crate::logging::debug(format_args!("tailscale: selected home relay {:?}", home));
        let disco = mesh.disco_public();
        let tun = if self.cfg.system_interface && !self.cfg.offered_routes().is_empty() {
            Some(lan::LanTun::open()?)
        } else {
            None
        };
        if tun.is_some() {
            mesh.set_local_routes(self.cfg.offered_routes());
        }
        let shared = engine::spawn_tailscale_engine_with_tun(
            self.cfg.clone(),
            local_vip,
            cmd_rx,
            Some(mesh),
            tun,
        );
        let weak = Arc::downgrade(&shared);
        let cfg = self.cfg.clone();
        let node = node_key_str(&x25519_dalek::PublicKey::from(&node_key));
        tokio::spawn(async move {
            // Without a DERP map nothing else holds the sender; a dropped one
            // would end every map stream at once.
            let _network_tx = network_tx;
            let mut session = None;
            let mut delay = 1;
            let mut stream = None;
            let mut peers = std::collections::HashMap::new();
            let mut rules = vec![];
            let mut named_rules = std::collections::HashMap::new();
            let mut addresses_valid = true;
            let mut network = network_rx.borrow_and_update().clone();
            loop {
                if weak.strong_count() == 0 {
                    break;
                }
                let result = async {
                    if session.is_none() {
                        session =
                            Some(ControlSession::connect(&cfg.control_url, machine.clone()).await?);
                    }
                    if stream.is_none() {
                        stream = Some(
                            session
                                .as_mut()
                                .unwrap()
                                .map_stream_with_network(
                                    &node,
                                    cfg.hostname.as_deref().unwrap_or("rust-x"),
                                    disco,
                                    &cfg.offered_routes()
                                        .iter()
                                        .map(ToString::to_string)
                                        .collect::<Vec<_>>(),
                                    &network,
                                )
                                .await?,
                        );
                    }
                    loop {
                        tokio::select! {
                            result=stream.as_mut().unwrap().next()=>break result,
                            result=network_rx.changed()=>{
                                if result.is_err() {return Err(io::Error::other("tailscale: connectivity monitor stopped"));}
                                let next=network_rx.borrow_and_update().clone();
                                let changed=next.home_derp!=network.home_derp || next.endpoints!=network.endpoints || next.udp_available!=network.udp_available || next.mapping_varies!=network.mapping_varies;
                                network=next;
                                if changed {return Ok(None);}
                            }
                        }
                    }.map(Some)
                }
                .await;
                let Some(shared) = weak.upgrade() else {
                    break;
                };
                match result {
                    Ok(None) => {
                        stream = None;
                        named_rules.clear();
                        continue;
                    }
                    Ok(Some(map)) => {
                        if let Some(filter) = map.packet_filter.clone() {
                            named_rules.insert("base".to_string(), filter);
                        }
                        if let Some(filters) = &map.packet_filters {
                            if filters.get("*").is_some_and(Option::is_none) {
                                named_rules.clear();
                            }
                            for (name, value) in filters {
                                if let Some(value) = value {
                                    named_rules.insert(name.clone(), value.clone());
                                } else {
                                    named_rules.remove(name);
                                }
                            }
                        }
                        rules = named_rules.values().flatten().cloned().collect();
                        if let Some(full) = &map.peers {
                            peers.clear();
                            for peer in full {
                                peers.insert(peer.id, peer.clone());
                            }
                        }
                        if let Some(changed) = &map.peers_changed {
                            for peer in changed {
                                peers.insert(peer.id, peer.clone());
                            }
                        }
                        if let Some(removed) = &map.peers_removed {
                            for id in removed {
                                peers.remove(id);
                            }
                        }
                        if shared
                            .cmd_tx
                            .send(Cmd::UpdateAccess {
                                rules: rules.clone(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                        // A map may reassign our IP while retaining the node key.
                        // Wait for the data plane to apply it before reporting ready.
                        if let Some(local) = &map.node {
                            let next = assigned_addresses(local);
                            addresses_valid = false;
                            if let Ok(next) = next {
                                if next != expected_addresses {
                                    shared.control_connected.store(false, Ordering::Relaxed);
                                    let (resp, wait) = oneshot::channel();
                                    if shared
                                        .cmd_tx
                                        .send(Cmd::UpdateLocalAddresses {
                                            addresses: next.clone(),
                                            resp,
                                        })
                                        .await
                                        .is_err()
                                    {
                                        break;
                                    }
                                    if matches!(wait.await, Ok(Ok(()))) {
                                        expected_addresses = next;
                                        addresses_valid = true;
                                    }
                                } else {
                                    addresses_valid = true;
                                }
                            }
                            let (lan, exit) = cfg.route_approvals(&local.allowed_ips);
                            shared
                                .exit_approved
                                .store(addresses_valid && exit, Ordering::Relaxed);
                            shared
                                .routes_approved
                                .store(addresses_valid && lan, Ordering::Relaxed);
                        }
                        let peers = if addresses_valid {
                            peers.values().cloned().collect()
                        } else {
                            vec![]
                        };
                        let _ = shared
                            .cmd_tx
                            .send(Cmd::UpdateLanApproval {
                                approved: addresses_valid
                                    && shared.routes_approved.load(Ordering::Relaxed),
                                exit_approved: addresses_valid
                                    && shared.exit_approved.load(Ordering::Relaxed),
                            })
                            .await;
                        if shared
                            .cmd_tx
                            .send(Cmd::UpdatePeers {
                                peers,
                                derp_map: map.derp_map,
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                        delay = 0;
                        shared
                            .control_connected
                            .store(addresses_valid, std::sync::atomic::Ordering::Relaxed);
                    }
                    Err(error) => {
                        // Like the reference client, keep the last network map
                        // while control is away: peers, WireGuard sessions,
                        // access rules and route approvals stay as they were,
                        // so tailnet SSH/LuCI sessions survive a control
                        // reconnect. The next stream starts with a full map
                        // that replaces all of it.
                        shared
                            .control_connected
                            .store(false, std::sync::atomic::Ordering::Relaxed);
                        crate::logging::warn(format_args!(
                            "tailscale: map synchronization failed: {}",
                            error
                        ));
                        session = None;
                        stream = None;
                        // Filters arrive as deltas within one stream; a new
                        // stream must not inherit names the old one set.
                        named_rules.clear();
                        delay = retry_delay(delay);
                    }
                }
                drop(shared);
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
        });
        *guard = Some(Arc::clone(&shared));
        Ok(shared)
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let dst = resolve_target(target).await?;
        let shared = self.shared().await?;
        let id = shared.next_id.fetch_add(1, Ordering::Relaxed);
        let (local, remote) = tokio::io::duplex(CALLER_BUF);
        let (caller_read, caller_write) = tokio::io::split(local);
        let (to_caller_tx, mut to_caller_rx) = mpsc::channel(REPLY_QUEUE);
        let (resp_tx, resp_rx) = oneshot::channel();

        let credit = Arc::new(tokio::sync::Semaphore::new(engine::CALLER_QUEUE_BYTES));
        shared
            .cmd_tx
            .send(Cmd::TcpConnect {
                id,
                dst,
                to_caller: to_caller_tx,
                resp: resp_tx,
                credit: Arc::clone(&credit),
            })
            .await
            .map_err(|_| io::Error::other("tailscale: engine task stopped"))?;

        // caller → stack
        let cmd_tx = shared.cmd_tx.clone();
        tokio::spawn(async move {
            let mut read = caller_read;
            let mut buf = vec![0u8; SCRATCH_BUF];
            loop {
                match read.read(&mut buf).await {
                    Ok(0) => {
                        let _ = cmd_tx.send(Cmd::TcpEof { id }).await;
                        break;
                    }
                    Ok(n) => {
                        // Closed once the stack dropped the connection.
                        match credit.acquire_many(n as u32).await {
                            Ok(permits) => permits.forget(),
                            Err(_) => break,
                        }
                        if cmd_tx
                            .send(Cmd::TcpData {
                                id,
                                bytes: buf[..n].to_vec(),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(_) => {
                        let _ = cmd_tx.send(Cmd::TcpClose { id }).await;
                        break;
                    }
                }
            }
        });

        // stack → caller
        tokio::spawn(async move {
            let mut write = caller_write;
            while let Some(bytes) = to_caller_rx.recv().await {
                if write.write_all(&bytes).await.is_err() {
                    break;
                }
                let _ = write.flush().await;
            }
        });

        match tokio::time::timeout(CONNECT_TIMEOUT, resp_rx).await {
            Ok(Ok(Ok(()))) => Ok(Box::new(remote)),
            Ok(Ok(Err(e))) => Err(io::Error::other(format!("tailscale: {e}"))),
            Ok(Err(_)) => Err(io::Error::other("tailscale: engine task stopped")),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "tailscale: connect timeout",
            )),
        }
    }

    pub async fn connect_udp(&self, target: &Target) -> io::Result<UdpSocket> {
        let dst = resolve_target(target).await?;
        let shared = self.shared().await?;
        let (local, peer) = udp_loopback_pair().await?;
        let (resp_tx, resp_rx) = oneshot::channel();

        shared
            .cmd_tx
            .send(Cmd::UdpOpen {
                target: dst,
                resp: resp_tx,
            })
            .await
            .map_err(|_| io::Error::other("tailscale: engine task stopped"))?;

        let (port, mut replies) = match tokio::time::timeout(Duration::from_secs(10), resp_rx).await
        {
            Ok(Ok(Ok(v))) => v,
            Ok(Ok(Err(e))) => return Err(io::Error::other(format!("tailscale: {e}"))),
            Ok(Err(_)) => return Err(io::Error::other("tailscale: engine task stopped")),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tailscale: udp session timeout",
                ));
            }
        };

        let peer = Arc::new(peer);
        let cmd_tx = shared.cmd_tx.clone();
        let udp_timeout = self.cfg.udp_timeout;

        // replies: engine → loopback peer socket
        {
            let peer = Arc::clone(&peer);
            tokio::spawn(async move {
                while let Some(bytes) = replies.recv().await {
                    if peer.send(&bytes).await.is_err() {
                        break;
                    }
                }
            });
        }

        // sends: loopback peer socket → engine
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            while let Ok(Ok(n)) = tokio::time::timeout(udp_timeout, peer.recv(&mut buf)).await {
                if cmd_tx
                    .send(Cmd::UdpSend {
                        port,
                        bytes: buf[..n].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
            let _ = cmd_tx.send(Cmd::UdpClose { port }).await;
        });

        Ok(local)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn control_retry_waits_after_a_success() {
        // after a success the delay is 0: the first failure still waits
        assert_eq!(super::retry_delay(0), 1);
        assert_eq!(super::retry_delay(1), 2);
        assert_eq!(super::retry_delay(16), 30);
        assert_eq!(super::retry_delay(30), 30);
    }

    use super::*;

    #[test]
    fn assigned_addresses_normalize_order_and_reject_subnets() {
        let node = |addresses: serde_json::Value| {
            serde_json::from_value::<control::NodeObj>(
                serde_json::json!({"ID":1,"Key":"nodekey:test","Addresses":addresses}),
            )
            .unwrap()
        };
        let a = node(serde_json::json!([
            "fd7a:115c:a1e0::1/128",
            "100.64.0.1/32"
        ]));
        let b = node(serde_json::json!([
            "100.64.0.1/32",
            "fd7a:115c:a1e0::1/128"
        ]));
        assert_eq!(
            assigned_addresses(&a).unwrap(),
            assigned_addresses(&b).unwrap()
        );
        let unavailable = node(serde_json::Value::Null);
        assert_eq!(
            assigned_addresses(&unavailable).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        for addresses in [
            serde_json::json!([]),
            serde_json::json!(["100.64.0.0/24"]),
            serde_json::json!(["bad"]),
        ] {
            assert!(assigned_addresses(&node(addresses)).is_err());
        }
    }

    #[tokio::test]
    async fn test_tailscale_build_and_engine_start() {
        let json_cfg = serde_json::json!({
            "type": "tailscale",
            "tag": "ts-out",
            "auth_key": "tskey-auth-test-key",
            "control_url": "https://controlplane.tailscale.com",
            "ephemeral": true,
            "hostname": "test-box",
            "listen_port": 41641
        });

        let map = json_cfg.as_object().unwrap();
        let ts = Tailscale::build(map, "endpoints[0]").unwrap();
        assert_eq!(ts.cfg.tag, "ts-out");
        assert_eq!(ts.cfg.hostname.as_deref(), Some("test-box"));
        assert!(ts.cfg.ephemeral);

        // Test engine startup
        let (_tx, rx) = mpsc::channel(128);
        let shared =
            engine::spawn_tailscale_engine(ts.cfg.clone(), "100.64.0.1".parse().unwrap(), rx);
        assert_eq!(shared.next_id.load(Ordering::Relaxed), 1);
    }
}
