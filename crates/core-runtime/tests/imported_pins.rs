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
