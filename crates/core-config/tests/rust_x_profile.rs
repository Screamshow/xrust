use core_config::check_str;

#[test]
fn rust_x_rejects_removed_protocols_at_check_time() {
    for protocol in [
        "naive",
        "vmess",
        "trojan",
        "shadowsocks",
        "tuic",
        "anytls",
        "snell",
        "shadowtls",
        "fptn",
        "openvpn",
        "openvpn-client",
    ] {
        for section in ["inbounds", "outbounds", "endpoints"] {
            let config = serde_json::json!({section: [{"type": protocol}]});
            let error = check_str(&config.to_string()).unwrap_err();
            assert!(
                error.contains("excluded from Rust X"),
                "{protocol}: {error}"
            );
        }
    }
    let error = check_str(r#"{"outbounds":[{"type":"socks"}]}"#).unwrap_err();
    assert!(error.contains("excluded from Rust X"));
}

#[test]
fn rust_x_keeps_direct_proxy_config() {
    check_str(r#"{"inbounds":[{"type":"mixed","tag":"direct-proxy-in","listen":"127.0.0.1","listen_port":2080}],"outbounds":[{"type":"direct","tag":"direct-proxy-out"}],"route":{"rules":[{"inbound":"direct-proxy-in","action":"route","outbound":"direct-proxy-out"}]}}"#).unwrap();
}

#[test]
fn rust_x_accepts_forkop_xhttp_options() {
    for table in [Some("hex"), None] {
        let mut transport = serde_json::json!({"type":"xhttp", "mode":"packet-up",
            "session_id_length":"16-32", "sc_max_each_post_bytes":32768,
            "sc_min_posts_interval_ms":10, "uplink_chunk_size":0,
            "xmux":{"max_concurrency":"8-32", "max_connections":0}});
        if let Some(table) = table {
            transport["session_id_table"] = table.into();
        }
        let config = serde_json::json!({"outbounds":[{"type":"vless","tag":"proxy",
            "server":"127.0.0.1", "server_port":443,
            "uuid":"00000000-0000-0000-0000-000000000001", "transport":transport}]});
        check_str(&config.to_string()).unwrap();
    }
    assert_eq!(core_config::xhttp_session_table("hex"), "0123456789abcdef");
}
