use core_config::check_str;

#[test]
fn xhttp_session_id_space_counts_the_whole_range() {
    for (table, length, accepted) in [
        ("Base62", "4-8", true),
        ("Base62", "5-6", true),
        ("Base62", "6", true),
        ("Base62", "4", false),
        ("Base62", "5", false),
        ("Base62", "4-5", false),
        ("hex", "4-8", true),
        ("hex", "4-7", false),
        ("number", "4-10", true),
        ("number", "4-9", false),
        ("ab", "31", true),
        ("ab", "1-30", false),
        ("a", "1-100", false),
        ("Base62", "0-8", false),
        ("Base62", "8-4", true),
        ("яф", "32", false),
        ("Base62", "4-bad", false),
    ] {
        for (table_key, length_key) in [
            ("session_id_table", "session_id_length"),
            ("session_table", "session_length"),
        ] {
            let mut transport = serde_json::json!({"type":"xhttp", "mode":"packet-up"});
            transport[table_key] = table.into();
            transport[length_key] = length.into();
            let config = serde_json::json!({"outbounds":[{
                "type":"vless", "tag":"proxy", "server":"127.0.0.1",
                "server_port":443, "uuid":"00000000-0000-0000-0000-000000000001",
                "transport":transport
            }]});
            let result = check_str(&config.to_string());
            assert_eq!(
                result.is_ok(),
                accepted,
                "{table_key}={table}, {length_key}={length}: {result:?}"
            );
        }
    }
}

#[test]
fn xhttp_accepts_extended_options_and_numbers() {
    for table in [Some("hex"), None] {
        let mut transport = serde_json::json!({
            "type": "xhttp",
            "mode": "packet-up",
            "session_id_length": "16-32",
            "sc_max_each_post_bytes": 32768,
            "sc_min_posts_interval_ms": 10,
            "uplink_chunk_size": 0,
            "xmux": {
                "max_concurrency": "8-32",
                "max_connections": 0
            }
        });
        if let Some(table) = table {
            transport["session_id_table"] = table.into();
        }
        let config = serde_json::json!({
            "outbounds": [{
                "type": "vless",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "transport": transport
            }]
        });
        check_str(&config.to_string()).unwrap();
    }
    assert_eq!(core_config::xhttp_session_table("hex"), "0123456789abcdef");
    assert_eq!(
        core_config::xhttp_session_table("ALPHABET"),
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    );
    assert_eq!(core_config::xhttp_session_table("number"), "0123456789");
}

#[test]
fn xhttp_accepts_http3_only_on_upload_and_download() {
    for alpn in [serde_json::json!("h3"), serde_json::json!(["h3"])] {
        let mut config = serde_json::json!({
            "outbounds": [{
                "type": "vless",
                "tag": "proxy",
                "server": "127.0.0.1",
                "server_port": 443,
                "uuid": "00000000-0000-0000-0000-000000000001",
                "tls": {"enabled": true, "alpn": alpn},
                "transport": {"type": "xhttp"}
            }]
        });
        check_str(&config.to_string()).unwrap();
        config["outbounds"][0]["tls"]["max_version"] = serde_json::json!("1.2");
        let error = check_str(&config.to_string()).unwrap_err();
        assert!(
            error.contains("XHTTP over HTTP/3 requires TLS 1.3"),
            "{error}"
        );
        config["outbounds"][0]["tls"]
            .as_object_mut()
            .unwrap()
            .remove("max_version");
        let outbound = &mut config["outbounds"][0];
        let tls = outbound["tls"].take();
        outbound["transport"]["download_settings"] = serde_json::json!({
            "server": "127.0.0.1",
            "server_port": 443,
            "tls": tls,
            "transport": {"type": "xhttp"}
        });
        check_str(&config.to_string()).unwrap();
    }
}
