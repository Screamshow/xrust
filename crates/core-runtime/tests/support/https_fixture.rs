// Local HTTPS server for the fetch tests (remote rule-set, external_ui).
//
// Shared by the integration tests (`#[path]` module) and the unit tests in
// `src/route/rule_set_remote.rs` (`include!`), so it has no inner attributes.
//
// Every leaf certificate in tests/golden/certs is issued for
// `localhost.key` with the SANs `localhost` and `127.0.0.1`, except
// `urltest-wrong-name.crt` (only `wrong.example`). `urltest-ca.crt` is the
// test CA; `urltest-untrusted.crt` names it as issuer but is signed by
// another key; `urltest-expired.crt` expired on 2021-01-01.

use core_tls::rustls::{self, ServerConfig, pki_types::CertificateDer};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

pub const VALID: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/certs/urltest-valid.crt"
));
pub const UNTRUSTED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/certs/urltest-untrusted.crt"
));
pub const EXPIRED: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/certs/urltest-expired.crt"
));
pub const WRONG_NAME: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/certs/urltest-wrong-name.crt"
));
const LEAF_KEY: &[u8] = include_bytes!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/certs/localhost.key"
));

/// The test CA, as a path for the top-level `certificate.certificate_path`.
pub const CA_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../tests/golden/certs/urltest-ca.crt"
);

/// A complete `200 OK` response carrying `body`.
pub fn ok_response(body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

pub struct HttpsServer {
    pub port: u16,
    /// Requests that completed the TLS handshake and were answered.
    pub served: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl HttpsServer {
    pub fn url(&self, path: &str) -> String {
        format!("https://127.0.0.1:{}{path}", self.port)
    }

    pub fn served(&self) -> usize {
        self.served.load(Ordering::SeqCst)
    }
}

impl Drop for HttpsServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Serve `response` to every connection over TLS with the certificate
/// `cert_pem`. A client that refuses the certificate never gets a response.
pub async fn serve_https(cert_pem: &[u8], response: Vec<u8>) -> HttpsServer {
    // the runtime installs the process provider at start; unit tests do not
    // go through start, so do it here as well
    core_tls::install_default_provider();
    let mut pem = cert_pem;
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem)
        .collect::<Result<_, _>>()
        .expect("test certificate");
    let key = rustls_pemfile::private_key(&mut &LEAF_KEY[..])
        .expect("test key")
        .expect("a private key");
    let provider = core_crypto::provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .expect("signing key");
    let certified = rustls::sign::CertifiedKey::new(certs, signing_key);
    let config = ServerConfig::builder_with_provider(Arc::new(provider))
        .with_safe_default_protocol_versions()
        .expect("protocol versions")
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(rustls::sign::SingleCertAndKey::from(certified)));
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind https fixture");
    let port = listener.local_addr().expect("fixture address").port();
    let served = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&served);
    let response = Arc::new(response);
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            let response = Arc::clone(&response);
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buffer = [0u8; 1024];
                while !head.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => head.extend_from_slice(&buffer[..n]),
                    }
                }
                counter.fetch_add(1, Ordering::SeqCst);
                let _ = stream.write_all(&response).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    HttpsServer { port, served, task }
}
