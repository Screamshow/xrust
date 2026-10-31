use core_config::check_str;

#[test]
fn reality_pq_preference_passes_the_full_config_check() {
    let mut config = serde_json::json!({"outbounds":[{"type":"vless","tag":"node",
        "server":"127.0.0.1","server_port":443,"uuid":"00000000-0000-0000-0000-000000000001",
        "flow":"xtls-rprx-vision","tls":{"enabled":true,"server_name":"example.test",
        "utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,
        "public_key":"IiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiIiI","short_id":"1234abcd"}}}]});
    check_str(&config.to_string()).unwrap();
    for value in [serde_json::json!(false), serde_json::json!(true)] {
        config["outbounds"][0]["tls"]["reality"]["support_x25519mlkem768"] = value;
        check_str(&config.to_string()).unwrap();
    }
    config["outbounds"][0]["tls"]["reality"]["support_x25519mlkem768"] = serde_json::json!("false");
    assert!(check_str(&config.to_string()).is_err());
}

#[test]
fn rust_x_rejects_removed_protocols_at_check_time() {
    for protocol in [
        "naive",
        "vmess",
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
    // the trojan client is in, a trojan server is not
    for section in ["inbounds", "endpoints"] {
        let config = serde_json::json!({section: [{"type": "trojan"}]});
        let error = check_str(&config.to_string()).unwrap_err();
        assert!(
            error.contains("protocol \"trojan\" is excluded from Rust X"),
            "{error}"
        );
    }
}

/// Every shape Forkop X writes for a trojan link: TLS, uTLS, REALITY, and the
/// same transports VLESS gets.
#[test]
fn rust_x_accepts_forkop_trojan_outbounds() {
    let tls_variants = [
        serde_json::json!({"enabled": true, "server_name": "example.com"}),
        serde_json::json!({"enabled": true, "server_name": "example.com", "insecure": true,
            "alpn": ["h2", "http/1.1"]}),
        serde_json::json!({"enabled": true, "server_name": "example.com",
            "utls": {"enabled": true, "fingerprint": "chrome"}}),
        serde_json::json!({"enabled": true, "server_name": "www.microsoft.com",
            "utls": {"enabled": true, "fingerprint": "chrome"},
            "reality": {"enabled": true,
                "public_key": "jNXHt1yRo0vDuchQlIP6Z0ZvjT3KtzVI-T4E7RoLJS0",
                "short_id": "0123abcd"}}),
    ];
    let transports = [
        None,
        Some(serde_json::json!({"type": "ws", "path": "/ws",
            "headers": {"Host": "example.com"}, "max_early_data": 2048,
            "early_data_header_name": "Sec-WebSocket-Protocol"})),
        Some(serde_json::json!({"type": "grpc", "service_name": "svc"})),
        Some(serde_json::json!({"type": "httpupgrade", "path": "/up", "host": "example.com"})),
        Some(serde_json::json!({"type": "http", "path": "/h2", "host": ["example.com"]})),
        Some(
            serde_json::json!({"type": "xhttp", "mode": "auto", "path": "/",
            "x_padding_bytes": "100-1000", "no_grpc_header": false,
            "sc_max_each_post_bytes": 1000000}),
        ),
    ];
    for tls in &tls_variants {
        for transport in &transports {
            let mut outbound = serde_json::json!({"type": "trojan", "tag": "proxy",
                "server": "example.com", "server_port": 443, "password": "secret",
                "tls": tls});
            if let Some(transport) = transport {
                outbound["transport"] = transport.clone();
            }
            let config = serde_json::json!({"outbounds": [outbound]});
            check_str(&config.to_string()).unwrap_or_else(|e| panic!("{outbound}: {e}"));
        }
    }
}

/// A trojan outbound the client could not run is refused at check time.
#[test]
fn rust_x_refuses_trojan_without_tls_or_with_multiplex() {
    for tls in [None, Some(serde_json::json!({"enabled": false}))] {
        let mut outbound = serde_json::json!({"type": "trojan", "tag": "proxy",
            "server": "example.com", "server_port": 443, "password": "secret"});
        if let Some(tls) = tls {
            outbound["tls"] = tls;
        }
        let error =
            check_str(&serde_json::json!({"outbounds": [outbound]}).to_string()).unwrap_err();
        assert!(
            error.contains("outbounds[0]: trojan requires TLS"),
            "{error}"
        );
    }
    let outbound = serde_json::json!({"type": "trojan", "tag": "proxy",
        "server": "example.com", "server_port": 443, "password": "secret",
        "tls": {"enabled": true, "server_name": "example.com"},
        "multiplex": {"enabled": true, "protocol": "h2mux"}});
    let error = check_str(&serde_json::json!({"outbounds": [outbound]}).to_string()).unwrap_err();
    assert!(
        error.contains("multiplex is not supported on the trojan outbound"),
        "{error}"
    );
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
