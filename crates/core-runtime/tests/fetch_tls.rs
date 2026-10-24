//! The runtime's own HTTPS downloads (remote rule-set, external_ui) verify the
//! server certificate: chain to a trusted root, server name and validity.
//! The trusted roots are the embedded Mozilla set plus the top-level
//! `certificate` option, the same as for URLTest probes.

#[path = "support/https_fixture.rs"]
mod https_fixture;

use https_fixture::{EXPIRED, UNTRUSTED, VALID, WRONG_NAME, ok_response, serve_https};
use serde_json::{Value, json};

/// A source-format rule-set holding one domain rule.
fn rule_set_body() -> Vec<u8> {
    json!({"version": 1, "rules": [{"domain": ["rule.example"]}]})
        .to_string()
        .into_bytes()
}

fn rule_set_config(url: &str, trust_ca: bool) -> Value {
    let mut config = json!({
        "log": {"level": "error"},
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {
            "final": "direct",
            "rule_set": [{"type": "remote", "tag": "remote", "format": "source", "url": url}],
            "rules": [{"rule_set": "remote", "outbound": "direct"}]
        }
    });
    if trust_ca {
        config["certificate"] = json!({"certificate_path": [https_fixture::CA_PATH]});
    }
    config
}

#[tokio::test]
async fn remote_rule_set_over_https_is_verified() {
    let server = serve_https(VALID, ok_response(&rule_set_body())).await;
    let url = server.url("/rules.json");
    let instance = core_runtime::start(&rule_set_config(&url, true))
        .await
        .expect("trusted CA and matching name");
    instance.shutdown();
    assert_eq!(server.served(), 1);

    // Each failure is the initial download, which is fatal for start, as
    // for a 404 or a timeout.
    for (label, cert, trust_ca, expected) in [
        ("unknown CA", VALID, false, "UnknownIssuer"),
        ("bad signature", UNTRUSTED, true, "BadSignature"),
        ("wrong name", WRONG_NAME, true, "not valid for name"),
        ("expired", EXPIRED, true, "certificate expired"),
    ] {
        let server = serve_https(cert, ok_response(&rule_set_body())).await;
        let url = server.url("/rules.json");
        let error = match core_runtime::start(&rule_set_config(&url, trust_ca)).await {
            Ok(instance) => {
                instance.shutdown();
                panic!("{label}: the rule-set was downloaded");
            }
            Err(error) => format!("{error:#}"),
        };
        assert!(
            error.contains("initial rule-set: remote"),
            "{label}: {error}"
        );
        assert!(error.contains(expected), "{label}: {error}");
        assert_eq!(server.served(), 0, "{label}: the request was sent");
    }
}

/// A stored (uncompressed) zip with one file.
fn ui_bundle() -> Vec<u8> {
    let (name, body) = ("index.html", b"<title>downloaded</title>".as_slice());
    let mut out = Vec::new();
    let mut central = Vec::new();
    out.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 10]); // version, flags, method, time, date
    out.extend_from_slice(&0u32.to_le_bytes()); // crc (not checked)
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(name.as_bytes());
    out.extend_from_slice(body);
    central.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    central.extend_from_slice(&[0u8; 12]); // made by, needed, flags, method, time, date
    central.extend_from_slice(&0u32.to_le_bytes()); // crc
    central.extend_from_slice(&(body.len() as u32).to_le_bytes());
    central.extend_from_slice(&(body.len() as u32).to_le_bytes());
    central.extend_from_slice(&(name.len() as u16).to_le_bytes());
    central.extend_from_slice(&[0u8; 12]); // extra, comment, disk, attrs
    central.extend_from_slice(&0u32.to_le_bytes()); // offset
    central.extend_from_slice(name.as_bytes());
    let central_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    out.extend_from_slice(&[0u8; 4]);
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&1u16.to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&central_offset.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

fn ui_dir(label: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("xrust-fetch-tls-ui-{}-{label}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn ui_config(dir: &std::path::Path, url: &str, trust_ca: bool) -> Value {
    let mut config = json!({
        "log": {"level": "error"},
        "experimental": {"clash_api": {
            "external_controller": "127.0.0.1:0",
            "external_ui": dir.to_string_lossy(),
            "external_ui_download_url": url,
            "external_ui_download_detour": "direct"
        }},
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    });
    if trust_ca {
        config["certificate"] = json!({"certificate_path": [https_fixture::CA_PATH]});
    }
    config
}

fn entries(dir: &std::path::Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .expect("ui directory")
        .map(|entry| {
            entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn external_ui_over_https_is_verified() {
    // trusted CA and matching name: the bundle is installed
    let server = serve_https(VALID, ok_response(&ui_bundle())).await;
    let dir = ui_dir("trusted");
    let instance = core_runtime::start(&ui_config(&dir, &server.url("/ui.zip"), true))
        .await
        .expect("start");
    instance.shutdown();
    assert_eq!(
        std::fs::read(dir.join("index.html")).expect("installed"),
        b"<title>downloaded</title>"
    );
    let _ = std::fs::remove_dir_all(&dir);

    // A certificate that does not verify: nothing is installed, and the core
    // still starts (the dashboard is optional).
    for (label, cert, trust_ca) in [
        ("unknown-ca", VALID, false),
        ("bad-signature", UNTRUSTED, true),
        ("wrong-name", WRONG_NAME, true),
        ("expired", EXPIRED, true),
    ] {
        let server = serve_https(cert, ok_response(&ui_bundle())).await;
        let dir = ui_dir(label);
        let instance = core_runtime::start(&ui_config(&dir, &server.url("/ui.zip"), trust_ca))
            .await
            .expect("a failed dashboard download does not stop the core");
        instance.shutdown();
        assert!(entries(&dir).is_empty(), "{label}: {:?}", entries(&dir));
        assert_eq!(server.served(), 0, "{label}: the request was sent");
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[tokio::test]
async fn external_ui_tls_failure_keeps_an_existing_ui() {
    let dir = ui_dir("existing");
    std::fs::create_dir_all(dir.join("static")).expect("ui dir");
    std::fs::write(dir.join("index.html"), b"<title>installed</title>").expect("index");
    std::fs::write(dir.join("static/app.js"), b"app();").expect("asset");
    let server = serve_https(EXPIRED, ok_response(&ui_bundle())).await;
    let instance = core_runtime::start(&ui_config(&dir, &server.url("/ui.zip"), true))
        .await
        .expect("start");
    instance.shutdown();
    assert_eq!(entries(&dir), ["index.html", "static"]);
    assert_eq!(
        std::fs::read(dir.join("index.html")).expect("index"),
        b"<title>installed</title>"
    );
    assert_eq!(
        std::fs::read(dir.join("static/app.js")).expect("asset"),
        b"app();"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
