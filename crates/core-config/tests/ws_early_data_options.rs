//! `max_early_data` and `early_data_header_name` on a ws transport, both on
//! a client and on a server, as sing-box types them.

use core_config::check_str;
use serde_json::{Value, json};

fn outbound(transport: Value) -> String {
    json!({
        "outbounds": [{
            "type": "vless",
            "tag": "proxy",
            "server": "127.0.0.1",
            "server_port": 443,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "transport": transport
        }]
    })
    .to_string()
}

fn inbound(transport: Value) -> String {
    json!({
        "inbounds": [{
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": 18443,
            "users": [{"uuid": "00000000-0000-0000-0000-000000000001"}],
            "transport": transport
        }],
        "outbounds": []
    })
    .to_string()
}

#[test]
fn ws_early_data_options_are_accepted() {
    for transport in [
        json!({"type": "ws", "path": "/ed", "max_early_data": 2048}),
        json!({"type": "ws", "path": "/ed", "max_early_data": 0}),
        json!({"type": "ws", "path": "/ed", "max_early_data": 4294967295u64}),
        json!({"type": "ws", "path": "/ed", "max_early_data": 2048,
               "early_data_header_name": "Sec-WebSocket-Protocol"}),
        json!({"type": "ws", "path": "/ed", "early_data_header_name": ""}),
    ] {
        for config in [outbound(transport.clone()), inbound(transport.clone())] {
            check_str(&config).unwrap_or_else(|e| panic!("{transport}: {e}"));
        }
    }
}

#[test]
fn ws_early_data_options_are_typed() {
    for transport in [
        json!({"type": "ws", "max_early_data": -1}),
        json!({"type": "ws", "max_early_data": 4294967296u64}),
        json!({"type": "ws", "max_early_data": "2048"}),
        json!({"type": "ws", "early_data_header_name": 1}),
    ] {
        // server transports are not typed by the checker yet; the runtime
        // refuses these when it reads the inbound
        let config = outbound(transport.clone());
        assert!(check_str(&config).is_err(), "{config} must be refused");
    }
}
