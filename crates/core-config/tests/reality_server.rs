//! `check` of a REALITY server inbound, matched against sing-box 1.14.3
//! (`common/tls.NewRealityServer`): the server takes no certificate or key of
//! its own, so their absence is fine and their presence is an error.

use serde_json::{Value, json};

const PRIVATE_KEY: &str = "UuMBgl7MXTPx9inmQp2UC7Jcnwc6XYbwDNebonM-FCc";

fn reality_tls() -> Value {
    json!({
        "enabled": true,
        "server_name": "www.google.com",
        "reality": {
            "enabled": true,
            "handshake": {"server": "www.google.com", "server_port": 443},
            "private_key": PRIVATE_KEY,
            "short_id": ["0123456789abcdef"]
        }
    })
}

fn config(ty: &str, tls: Value) -> String {
    let mut inbound = json!({
        "type": ty,
        "listen": "127.0.0.1",
        "listen_port": 4433,
        "tls": tls
    });
    if ty == "vless" {
        inbound["users"] = json!([{"uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"}]);
    }
    json!({"inbounds": [inbound], "outbounds": [{"type": "direct"}]}).to_string()
}

fn check(ty: &str, edit: impl FnOnce(&mut Value)) -> Result<(), String> {
    let mut tls = reality_tls();
    edit(&mut tls);
    core_config::check_str(&config(ty, tls))
}

fn check_err(edit: impl FnOnce(&mut Value)) -> String {
    check("vless", edit).expect_err("check must fail")
}

#[test]
fn reality_server_needs_no_certificate() {
    for ty in ["vless", "mixed", "http"] {
        check(ty, |_| {}).unwrap_or_else(|e| panic!("{ty}: {e}"));
    }
}

#[test]
fn reality_server_short_id_shapes() {
    for short_id in [json!("abcd"), json!(""), json!([]), json!([""])] {
        check("vless", |tls| tls["reality"]["short_id"] = short_id.clone())
            .unwrap_or_else(|e| panic!("{short_id}: {e}"));
    }
    check("vless", |tls| {
        tls["reality"].as_object_mut().unwrap().remove("short_id");
    })
    .expect("no short_id");
}

#[test]
fn reality_server_bad_short_id() {
    let err = check_err(|tls| tls["reality"]["short_id"] = json!(["abc"]));
    assert!(
        err.ends_with("decode short_id[0]: abc: encoding/hex: odd length hex string"),
        "{err}"
    );
    let err = check_err(|tls| tls["reality"]["short_id"] = json!(["ab", "zz1"]));
    assert!(
        err.ends_with("decode short_id[1]: zz1: encoding/hex: invalid byte: U+007A 'z'"),
        "{err}"
    );
    // the reference panics here (index out of range in hex.Decode)
    let err = check_err(|tls| tls["reality"]["short_id"] = json!("0123456789abcdef01"));
    assert!(
        err.ends_with("invalid short_id[0]: 0123456789abcdef01"),
        "{err}"
    );
}

#[test]
fn reality_server_bad_private_key() {
    for key in [json!(""), json!("AAAA")] {
        let err = check_err(|tls| tls["reality"]["private_key"] = key.clone());
        assert!(err.ends_with("invalid private key"), "{key}: {err}");
    }
    let err = check_err(|tls| {
        tls["reality"]
            .as_object_mut()
            .unwrap()
            .remove("private_key");
    });
    assert!(err.ends_with("invalid private key"), "{err}");
    let err = check_err(|tls| tls["reality"]["private_key"] = json!(format!("{PRIVATE_KEY}=")));
    assert!(
        err.ends_with("decode private key: illegal base64 data at input byte 43"),
        "{err}"
    );
}

#[test]
fn reality_server_refuses_certificate_sources() {
    let cases: &[(&str, Value, &str)] = &[
        (
            "certificate",
            json!(["x"]),
            "certificate is unavailable in reality",
        ),
        (
            "certificate",
            json!(""),
            "certificate is unavailable in reality",
        ),
        (
            "certificate_path",
            json!("/nonexistent"),
            "certificate is unavailable in reality",
        ),
        (
            "client_certificate_public_key_sha256",
            json!(["AAAA"]),
            "certificate is unavailable in reality",
        ),
        ("key", json!(""), "key is unavailable in reality"),
        (
            "key_path",
            json!("/nonexistent"),
            "key is unavailable in reality",
        ),
        (
            "acme",
            json!({"domain": ["a.com"]}),
            "acme is unavailable in reality",
        ),
        (
            "certificate_provider",
            json!({"type": "acme", "domain": ["a.com"]}),
            "certificate_provider is unavailable in reality",
        ),
        (
            "curve_preferences",
            json!(["x25519"]),
            "curve preferences is unavailable in reality",
        ),
        (
            "ech",
            json!({"enabled": true}),
            "Reality is conflict with ECH",
        ),
        (
            "min_version",
            json!("9.9"),
            "parse min_version: unknown tls version:9.9",
        ),
        (
            "cipher_suites",
            json!(["NOPE"]),
            "unknown cipher_suite: NOPE",
        ),
    ];
    for (field, value, message) in cases {
        let err = check_err(|tls| tls[*field] = value.clone());
        assert!(err.ends_with(message), "{field}={value}: {err}");
    }
}

#[test]
fn reality_server_empty_fields_are_absent() {
    let cases: &[(&str, Value)] = &[
        ("certificate", json!([])),
        ("certificate_path", json!("")),
        ("key", json!([])),
        ("client_certificate_public_key_sha256", json!([])),
        ("acme", json!({})),
        ("acme", json!({"domain": []})),
        ("certificate_provider", json!({})),
        ("certificate_provider", Value::Null),
        ("curve_preferences", json!([])),
        ("ech", json!({"enabled": false})),
        ("insecure", json!(true)),
    ];
    for (field, value) in cases {
        check("vless", |tls| tls[*field] = value.clone())
            .unwrap_or_else(|e| panic!("{field}={value}: {e}"));
    }
}

#[test]
fn disabled_reality_still_needs_a_certificate() {
    let err = check_err(|tls| tls["reality"]["enabled"] = json!(false));
    assert!(err.ends_with("missing certificate"), "{err}");
}
