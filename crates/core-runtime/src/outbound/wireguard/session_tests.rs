use super::*;
use crate::tunnel_session_tests as fixture;
use serde_json::json;

fn client(peer: &fixture::Peer) -> WireGuard {
    let value = json!({
        "private_key": fixture::b64(fixture::CLIENT_KEY),
        "address": ["10.66.66.2/24"],
        "udp_timeout": "1s",
        "peers": [{
            "address": "127.0.0.1", "port": peer.address.port(),
            "public_key": fixture::b64(peer.public_key()),
            "allowed_ips": ["0.0.0.0/0"]
        }]
    });
    WireGuard::build(value.as_object().unwrap(), "session-test").unwrap()
}

async fn connect(wg: &WireGuard) -> AnyStream {
    // Allow the normal handshake retry on a cold, not-yet-writable UDP socket.
    tokio::time::timeout(
        Duration::from_secs(12),
        wg.connect(&Target::Ip("10.66.66.1:4321".parse().unwrap())),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn tcp_fin_delivers_all_bytes_and_preserves_the_write_half() {
    for (local_fin, size) in [(false, 17), (true, 17), (false, 2 * 1024 * 1024)] {
        let response: Vec<_> = (0..size).map(|n| (n % 251) as u8).collect();
        let peer = fixture::peer("10.66.66.1", local_fin, response.clone()).await;
        let wg = client(&peer);
        let stream = connect(&wg).await;
        fixture::tcp_eof(stream, &peer, local_fin, &response).await;
    }
}

#[tokio::test]
async fn udp_activity_in_either_direction_prevents_idle_expiry() {
    for receive_only in [true, false] {
        let peer = fixture::peer("10.66.66.1", false, vec![]).await;
        let wg = client(&peer);
        let _warm = connect(&wg).await;
        let socket = wg
            .connect_udp(&Target::Ip("10.66.66.1:1234".parse().unwrap()))
            .await
            .unwrap();
        if receive_only {
            fixture::udp_receive_only(socket, &peer).await;
        } else {
            fixture::udp_send_only(socket, &peer).await;
        }
    }
}
