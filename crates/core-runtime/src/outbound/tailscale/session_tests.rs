use super::*;
use crate::tunnel_session_tests as fixture;
use serde_json::json;

async fn client(peer: &fixture::Peer) -> Tailscale {
    let value =
        json!({"type":"tailscale", "tag":"session-test", "ephemeral":true, "udp_timeout":"1s"});
    let cfg = TailscaleConfig::parse(value.as_object().unwrap(), "session-test").unwrap();
    let mut mesh = mesh::DirectMesh::bind(
        x25519_dalek::StaticSecret::from(fixture::CLIENT_KEY),
        vec!["100.64.0.1".parse().unwrap()],
        0,
    )
    .await
    .unwrap();
    mesh.update_peers(&[control::PeerObj {
        disco_key: None,
        home_derp: None,
        id: 1,
        key: control::node_key_str(&x25519_dalek::PublicKey::from(peer.public_key())),
        name: None,
        addresses: vec!["100.64.0.2/32".into()],
        allowed_ips: vec![],
        endpoints: Some(vec![peer.address.to_string()]),
        derp: None,
        online: Some(true),
    }]);
    // Inject a ready local mesh, bypassing only control/authentication.
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    let shared = engine::spawn_tailscale_engine_with_mesh(
        cfg.clone(),
        "100.64.0.1".parse().unwrap(),
        rx,
        Some(mesh),
    );
    Tailscale {
        cfg,
        shared: Arc::new(AsyncMutex::new(Some(shared))),
    }
}

#[tokio::test]
async fn tcp_fin_delivers_all_bytes_and_preserves_the_write_half() {
    for (local_fin, size) in [(false, 17), (true, 17), (false, 2 * 1024 * 1024)] {
        let response: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
        let peer = fixture::peer("100.64.0.2", local_fin, response.clone()).await;
        let ts = client(&peer).await;
        let stream = tokio::time::timeout(
            Duration::from_secs(4),
            ts.connect(&Target::Ip("100.64.0.2:4321".parse().unwrap())),
        )
        .await
        .unwrap()
        .unwrap();
        fixture::tcp_eof(stream, &peer, local_fin, &response).await;
    }
}

#[tokio::test]
async fn udp_activity_in_either_direction_prevents_idle_expiry() {
    for receive_only in [true, false] {
        let peer = fixture::peer("100.64.0.2", false, vec![]).await;
        let ts = client(&peer).await;
        let socket = ts
            .connect_udp(&Target::Ip("100.64.0.2:1234".parse().unwrap()))
            .await
            .unwrap();
        if receive_only {
            fixture::udp_receive_only(socket, &peer).await;
        } else {
            fixture::udp_send_only(socket, &peer).await;
        }
    }
}
