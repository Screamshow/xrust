use base64::{Engine, engine::general_purpose::STANDARD};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn imported_certificate_pin_controls_tls_handshake_and_payload() {
    let cert = rustls_pemfile::certs(
        &mut include_bytes!("../../../tests/golden/certs/urltest-valid.crt").as_slice(),
    )
    .next()
    .unwrap()
    .unwrap();
    let expected = STANDARD.encode(Sha256::digest(cert.as_ref()));
    let imported: Value = match std::env::var("FORKOP_PINNED_IMPORT") {
        Ok(path) => serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap(),
        Err(_) => {
            json!({"tls":{"enabled":true,"server_name":"localhost","certificate_sha256":[expected]}})
        }
    };
    assert_eq!(
        imported["tls"]["certificate_sha256"],
        json!([expected]),
        "parser lost pin"
    );
    for stack in ["rustls", "core"] {
        for correct in [true, false] {
            let key = rustls_pemfile::private_key(
                &mut include_bytes!("../../../tests/golden/certs/localhost.key").as_slice(),
            )
            .unwrap()
            .unwrap();
            let config = core_tls::rustls::ServerConfig::builder_with_provider(Arc::new(
                core_crypto::provider(),
            ))
            .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key)
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    let mut bytes = [0; 4];
                    stream.read_exact(&mut bytes).await.unwrap();
                    assert_eq!(&bytes, b"ping");
                    stream.write_all(b"pong").await.unwrap();
                }
            });
            let mut outbound = imported.clone();
            outbound["tls"]["certificate"] =
                json!(include_str!("../../../tests/golden/certs/urltest-ca.crt"));
            outbound["tls"]["stack"] = json!(stack);
            if !correct {
                outbound["tls"]["certificate_sha256"] = json!([STANDARD.encode([0u8; 32])]);
            }
            let options = core_runtime::tls_client::TlsOptions::from_outbound(
                outbound.as_object().unwrap(),
                "127.0.0.1",
                "test",
            )
            .unwrap()
            .unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                options.wrap(TcpStream::connect(addr).await.unwrap()),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), correct, "pin enforcement in {stack}");
            if let Ok(mut stream) = result {
                stream.write_all(b"ping").await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"pong");
            }
            server.await.unwrap();
        }
    }
}

#[tokio::test]
async fn xray_pin_and_verify_name_policies_preserve_sni() {
    let parse_cert = |pem: &[u8]| {
        rustls_pemfile::certs(&mut &pem[..])
            .next()
            .unwrap()
            .unwrap()
    };
    let ca_pem = include_str!("../../../tests/golden/certs/urltest-ca.crt");
    let ca = parse_cert(ca_pem.as_bytes());
    let leaf = parse_cert(include_bytes!(
        "../../../tests/golden/certs/urltest-valid.crt"
    ));
    let non_ca = parse_cert(include_bytes!(
        "../../../tests/golden/certs/urltest-wrong-name.crt"
    ));
    let digest = |cert: &core_tls::rustls::pki_types::CertificateDer<'_>| {
        STANDARD.encode(Sha256::digest(cert.as_ref()))
    };
    let cases = [
        (
            "leaf accepts its exact digest before checking names",
            json!({
                "xray_pinned_peer_cert_sha256": [digest(&leaf)], "verify_server_name": "wrong.example"
            }),
            vec![],
            true,
        ),
        (
            "wrong pin is rejected even with insecure",
            json!({
                "xray_pinned_peer_cert_sha256": STANDARD.encode([0u8; 32]), "insecure": true
            }),
            vec![ca.clone()],
            false,
        ),
        (
            "pinned CA accepts an alternate name",
            json!({
                "xray_pinned_peer_cert_sha256": [digest(&ca)], "verify_server_name": ["first.example", "localhost"]
            }),
            vec![ca.clone()],
            true,
        ),
        (
            "pinned CA still checks the name",
            json!({
                "xray_pinned_peer_cert_sha256": [digest(&ca)], "verify_server_name": "first.example"
            }),
            vec![ca.clone()],
            false,
        ),
        (
            "configured CA does not substitute for an absent peer CA",
            json!({
                "xray_pinned_peer_cert_sha256": [digest(&ca)], "verify_server_name": "localhost", "certificate": ca_pem
            }),
            vec![],
            false,
        ),
        (
            "a certificate without CA constraints is not an anchor",
            json!({
                "xray_pinned_peer_cert_sha256": [digest(&non_ca)], "verify_server_name": "localhost"
            }),
            vec![non_ca, ca.clone()],
            false,
        ),
        (
            "verification name selects a SAN without replacing SNI",
            json!({
                "verify_server_name": ["first.example", "localhost"], "certificate": ca_pem
            }),
            vec![],
            true,
        ),
        (
            "verification name still needs a trusted chain",
            json!({
                "verify_server_name": "localhost"
            }),
            vec![],
            false,
        ),
        (
            "verification name is mandatory even with insecure",
            json!({
                "verify_server_name": "first.example", "insecure": true, "certificate": ca_pem
            }),
            vec![],
            false,
        ),
        (
            "native pin still needs a trusted chain",
            json!({
                "certificate_sha256": [digest(&leaf)]
            }),
            vec![],
            false,
        ),
    ];
    for stack in ["rustls", "core"] {
        for (label, tls, extras, expected) in &cases {
            let mut chain = vec![leaf.clone()];
            chain.extend_from_slice(extras);
            let key = rustls_pemfile::private_key(
                &mut include_bytes!("../../../tests/golden/certs/localhost.key").as_slice(),
            )
            .unwrap()
            .unwrap();
            let config = core_tls::rustls::ServerConfig::builder_with_provider(Arc::new(
                core_crypto::provider(),
            ))
            .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(chain, key)
            .unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                if let Ok(mut stream) = acceptor.accept(socket).await {
                    assert_eq!(stream.get_ref().1.server_name(), Some("outer.example"));
                    let mut bytes = [0; 4];
                    stream.read_exact(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                }
            });
            let mut outbound = json!({"tls": tls});
            outbound["tls"]["enabled"] = json!(true);
            outbound["tls"]["server_name"] = json!("outer.example");
            outbound["tls"]["stack"] = json!(stack);
            let options = core_runtime::tls_client::TlsOptions::from_outbound(
                outbound.as_object().unwrap(),
                "127.0.0.1",
                "test",
            )
            .unwrap()
            .unwrap();
            let result = tokio::time::timeout(
                Duration::from_secs(3),
                options.wrap(TcpStream::connect(addr).await.unwrap()),
            )
            .await
            .unwrap();
            assert_eq!(result.is_ok(), *expected, "{stack}: {label}");
            if let Ok(mut stream) = result {
                stream.write_all(b"ping").await.unwrap();
                let mut bytes = [0; 4];
                stream.read_exact(&mut bytes).await.unwrap();
                assert_eq!(&bytes, b"ping");
            }
            server.await.unwrap();
        }
    }
}
