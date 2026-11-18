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

#[test]
fn reserved_and_awg_options_agree_at_check_and_endpoint_build() {
    let mut root = json!({"endpoints": [{
        "type": "wireguard", "tag": "wg", "private_key": fixture::b64(fixture::CLIENT_KEY),
        "address": ["10.66.66.2/24"],
        "peers": [{"address": "127.0.0.1", "port": 9,
            "public_key": fixture::b64(fixture::public([73; 32])),
            "allowed_ips": ["0.0.0.0/0"], "reserved": [19, 81, 203]}]
    }]});
    let build = |root: &Value| WireGuard::build(root["endpoints"][0].as_object().unwrap(), "wg");
    let check_plain = |root: &Value| {
        core_config::check_str(&root.to_string()).unwrap();
        let wg = build(root).unwrap();
        assert!(wg.cfg.awg.is_none(), "{root}");
        assert_eq!(wg.cfg.peers[0].reserved, [19, 81, 203]);
    };
    check_plain(&root);
    for key in ["h1", "rekey_after_time"] {
        for value in [
            json!(0),
            json!("0"),
            json!("0-0"),
            json!(" 00 - 0 "),
            json!(""),
            Value::Null,
            json!({}),
        ] {
            root["endpoints"][0][key] = value;
            check_plain(&root);
        }
        root["endpoints"][0].as_object_mut().unwrap().remove(key);
    }
    for key in ["header_protection_key", "i1", "ip"] {
        root["endpoints"][0][key] = json!(" \t ");
    }
    check_plain(&root);

    root["endpoints"][0]["rekey_after_time"] = json!("120-130");
    let error = "nonzero reserved cannot be combined with AmneziaWG obfuscation";
    assert!(
        core_config::check_str(&root.to_string())
            .unwrap_err()
            .contains(error)
    );
    assert!(build(&root).unwrap_err().to_string().contains(error));

    root["endpoints"][0]["peers"][0]["reserved"] = json!([0, 0, 0]);
    core_config::check_str(&root.to_string()).unwrap();
    assert_eq!(
        build(&root).unwrap().cfg.awg.unwrap().rekey_after_time,
        Some((120, 130))
    );

    root["endpoints"][0]["rekey_after_time"] = json!("130-120");
    assert!(
        core_config::check_str(&root.to_string())
            .unwrap_err()
            .contains("range start > end")
    );
    assert!(
        build(&root)
            .unwrap_err()
            .to_string()
            .contains("range start > end")
    );
}

#[tokio::test]
async fn reserved_bytes_reach_the_handshake_socket() {
    let sink = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let wg = Arc::new(
        WireGuard::build(
            json!({
                "private_key": fixture::b64(fixture::CLIENT_KEY),
                "address": ["10.66.66.2/24"],
                "peers": [{"address": "127.0.0.1", "port": sink.local_addr().unwrap().port(),
                    "public_key": fixture::b64(fixture::public([73; 32])),
                    "allowed_ips": ["0.0.0.0/0"], "reserved": [19, 81, 203]}]
            })
            .as_object()
            .unwrap(),
            "reserved-test",
        )
        .unwrap(),
    );
    let task = tokio::spawn(async move {
        wg.connect(&Target::Ip("10.66.66.1:4321".parse().unwrap()))
            .await
    });
    let mut wire = [0; 2048];
    let received = tokio::time::timeout(Duration::from_secs(8), sink.recv_from(&mut wire))
        .await
        .unwrap()
        .unwrap()
        .0;
    task.abort();
    assert_eq!(received, noise::INITIATION_LEN);
    assert_eq!(&wire[1..4], &[19, 81, 203]);
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
