//! Live DERP transport probe using local node state; no private keys are printed.
use core_runtime::outbound::tailscale::{
    control::{load_or_create_keys, node_key_str},
    derp_client::DerpClient,
    session::ControlSession,
};
use std::{path::Path, time::Duration};
use x25519_dalek::{PublicKey, StaticSecret};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let state = std::env::args().nth(1).ok_or("state directory required")?;
    let (machine, node) = load_or_create_keys(Some(Path::new(&state)), false)?;
    let mut control =
        ControlSession::connect("https://controlplane.tailscale.com", machine).await?;
    let map = control
        .initial_map(&node_key_str(&PublicKey::from(&node)), "rust-x-native-test")
        .await?;
    let regions =
        core_runtime::outbound::tailscale::derp::DerpMap::from(map.derp_map.ok_or("no DERP map")?);
    let region = regions
        .regions
        .values()
        .min_by_key(|r| r.region_id)
        .ok_or("no regions")?;
    let server = region.nodes.first().ok_or("no DERP server")?;
    let mut other = [0; 32];
    getrandom::fill(&mut other).map_err(|_| "entropy unavailable")?;
    let other = StaticSecret::from(other);
    let own_public = PublicKey::from(&node).to_bytes();
    let other_public = PublicKey::from(&other).to_bytes();
    let mut left = DerpClient::connect(server, node.clone(), true).await?;
    let mut right = DerpClient::connect(server, other.clone(), true).await?;
    left.send(other_public, b"rust-x-derp-probe")?;
    let packet = tokio::time::timeout(Duration::from_secs(15), right.rx.recv())
        .await?
        .ok_or("relay closed")?;
    if packet.source != own_public || packet.packet != b"rust-x-derp-probe" {
        return Err("relay packet mismatch".into());
    }
    right.send(own_public, b"rust-x-derp-reply")?;
    let packet = tokio::time::timeout(Duration::from_secs(15), left.rx.recv())
        .await?
        .ok_or("relay closed")?;
    if packet.source != other_public || packet.packet != b"rust-x-derp-reply" {
        return Err("relay reply mismatch".into());
    }
    println!(
        "DERP region {}: authenticated two clients; bidirectional packet relay passed",
        region.region_id
    );
    drop(left);
    drop(right);
    use core_runtime::outbound::tailscale::{
        control::PeerObj, derp_client::RelayManager, mesh::DirectMesh,
    };
    let peer = |key: [u8; 32], address: &str| PeerObj {
        disco_key: None,
        is_wireguard_only: false,
        id: 1,
        home_derp: Some(region.region_id),
        key: format!(
            "nodekey:{}",
            core_runtime::outbound::tailscale::control::to_hex(&key)
        ),
        name: None,
        addresses: vec![format!("{address}/32")],
        allowed_ips: None,
        endpoints: None,
        derp: None,
        online: Some(true),
    };
    let mut a = DirectMesh::bind(node.clone(), vec!["100.64.0.1".parse()?], 0).await?;
    let mut b = DirectMesh::bind(other.clone(), vec!["100.64.0.2".parse()?], 0).await?;
    a.set_relay(RelayManager::new(
        node,
        regions.clone(),
        Some(region.region_id),
    ));
    b.set_relay(RelayManager::new(
        other,
        regions.clone(),
        Some(region.region_id),
    ));
    a.update_peers(&[peer(other_public, "100.64.0.2")]);
    b.update_peers(&[peer(own_public, "100.64.0.1")]);
    let mut packet = vec![0; 21];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&21u16.to_be_bytes());
    packet[12..16].copy_from_slice(&[100, 64, 0, 1]);
    packet[16..20].copy_from_slice(&[100, 64, 0, 2]);
    packet[20] = 42;
    a.send(packet.clone()).await?;
    tokio::time::timeout(Duration::from_secs(25), async {
        loop {
            a.poll().await?;
            if let Some(received) = b.poll().await?.pop() {
                if received != packet {
                    return Err(std::io::Error::other("WireGuard relay mismatch"));
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    packet[12..16].copy_from_slice(&[100, 64, 0, 2]);
    packet[16..20].copy_from_slice(&[100, 64, 0, 1]);
    packet[20] = 43;
    b.send(packet.clone()).await?;
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            b.poll().await?;
            if let Some(received) = a.poll().await?.pop() {
                if received != packet {
                    return Err(std::io::Error::other("WireGuard relay reply mismatch"));
                }
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        Ok::<_, std::io::Error>(())
    })
    .await??;
    println!(
        "WireGuard over public DERP: bidirectional encrypted IP exchange passed (no direct endpoints)"
    );
    Ok(())
}
