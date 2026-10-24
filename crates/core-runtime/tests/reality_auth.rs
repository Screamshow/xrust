//! A REALITY client talks to the node it named or to nobody.
//!
//! Each server here sits behind a relay that records every byte the client
//! sends. When the REALITY check fails, the client must stop before its own
//! Finished: no application-data record leaves it, so neither a UUID nor a
//! request reaches whoever answered, and `insecure` changes nothing about it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine;
use core_tls::record::ContentType;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const SHORT_ID: &str = "1234abcd";
/// What a VLESS client would send first: version, UUID, then the request.
const USER_DATA: &[u8] = b"\x00\x11\x11\x11\x11\x22\x22\x33\x33\x44\x44\x55\x55\x55\x55\x55\x55\
GET /secret-path HTTP/1.1\r\n";

fn reality_public(private: &[u8; 32]) -> String {
    let secret = x25519_dalek::StaticSecret::from(*private);
    let public = x25519_dalek::PublicKey::from(&secret);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(public.as_bytes())
}

fn client(public_key: &str, short_id: &str, server_name: &str, extra: Value) -> Value {
    let mut tls = json!({
        "enabled": true,
        "server_name": server_name,
        "utls": {"enabled": true, "fingerprint": "chrome"},
        "reality": {"enabled": true, "public_key": public_key, "short_id": short_id}
    });
    for (k, v) in extra.as_object().unwrap() {
        tls[k] = v.clone();
    }
    json!({ "tls": tls })
}

/// Every record the client sent, by content type.
fn record_types(bytes: &[u8]) -> Vec<u8> {
    let mut types = Vec::new();
    let mut rest = bytes;
    while rest.len() >= 5 {
        let len = u16::from_be_bytes([rest[3], rest[4]]) as usize;
        types.push(rest[0]);
        rest = &rest[(5 + len).min(rest.len())..];
    }
    types
}

/// A relay to `upstream` that keeps what the client sent.
async fn recording_relay(upstream: std::net::SocketAddr) -> (std::net::SocketAddr, Recorder) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let record = Arc::clone(&seen);
    let task = tokio::spawn(async move {
        let (client, _) = listener.accept().await.unwrap();
        let server = TcpStream::connect(upstream).await.unwrap();
        let (mut client_rd, mut client_wr) = client.into_split();
        let (mut server_rd, mut server_wr) = server.into_split();
        let back = tokio::spawn(async move {
            let _ = tokio::io::copy(&mut server_rd, &mut client_wr).await;
        });
        let mut buf = vec![0u8; 16 * 1024];
        loop {
            match client_rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    record.lock().unwrap().extend_from_slice(&buf[..n]);
                    if server_wr.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
        let _ = server_wr.shutdown().await;
        let _ = tokio::time::timeout(Duration::from_secs(2), back).await;
    });
    (addr, Recorder { seen, task })
}

struct Recorder {
    seen: Arc<Mutex<Vec<u8>>>,
    task: tokio::task::JoinHandle<()>,
}

impl Recorder {
    async fn finish(self) -> Vec<u8> {
        let _ = tokio::time::timeout(Duration::from_secs(5), self.task).await;
        self.seen.lock().unwrap().clone()
    }
}

/// Our own TLS server, with REALITY or with a fixed chain. Returns the
/// plaintext it received after the handshake, or `None` when the handshake
/// did not complete. Answers the first record with `pong`.
fn core_server(
    listener: TcpListener,
    config: core_tls::server::Config,
) -> tokio::task::JoinHandle<Option<Vec<u8>>> {
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut handshake = core_tls::server::Handshake::new(config).unwrap();
        handshake.run(&mut socket).await.ok()?;
        let (mut sealer, mut opener) = handshake.application.take()?;
        let mut plaintext = Vec::new();
        loop {
            let mut head = [0u8; 5];
            let read = tokio::time::timeout(Duration::from_secs(3), socket.read_exact(&mut head));
            if !matches!(read.await, Ok(Ok(_))) {
                break;
            }
            let len = u16::from_be_bytes([head[3], head[4]]) as usize;
            let mut record = head.to_vec();
            record.resize(5 + len, 0);
            if socket.read_exact(&mut record[5..]).await.is_err() {
                break;
            }
            let Ok((kind, data)) = opener.open(&record) else {
                break;
            };
            if kind == ContentType::ApplicationData && !data.is_empty() {
                if plaintext.is_empty() {
                    let pong = sealer.seal(ContentType::ApplicationData, b"pong").unwrap();
                    let _ = socket.write_all(&pong).await;
                }
                plaintext.extend_from_slice(&data);
            }
        }
        Some(plaintext)
    })
}

fn reality_server_config(private: [u8; 32]) -> core_tls::server::Config {
    core_tls::server::Config {
        chain: Vec::new(),
        key: None,
        alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
        cipher_suites: Vec::new(),
        reality: Some(core_tls::server::ServerReality {
            private_key: private,
            short_ids: vec![vec![0x12, 0x34, 0xab, 0xcd]],
            max_time_difference: Some(600),
        }),
    }
}

/// An ordinary TLS 1.3 server -- the site a REALITY server fronts, or
/// somebody in the middle -- with a certificate that chains to `urltest-ca`.
fn rustls_server(listener: TcpListener) -> tokio::task::JoinHandle<Option<Vec<u8>>> {
    let cert = rustls_pemfile::certs(
        &mut include_bytes!("../../../tests/golden/certs/urltest-valid.crt").as_slice(),
    )
    .next()
    .unwrap()
    .unwrap();
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../../../tests/golden/certs/localhost.key").as_slice(),
    )
    .unwrap()
    .unwrap();
    let mut config =
        core_tls::rustls::ServerConfig::builder_with_provider(Arc::new(core_crypto::provider()))
            .with_protocol_versions(&[&core_tls::rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(socket).await.ok()?;
        let mut plaintext = Vec::new();
        let _ =
            tokio::time::timeout(Duration::from_secs(3), stream.read_to_end(&mut plaintext)).await;
        Some(plaintext)
    })
}

struct Outcome {
    connected: Result<(), String>,
    client_records: Vec<u8>,
    server_plaintext: Option<Vec<u8>>,
}

/// Connect through the relay and, if the handshake is accepted, send what a
/// VLESS client would send.
async fn run_client(
    outbound: Value,
    server: tokio::task::JoinHandle<Option<Vec<u8>>>,
    upstream: std::net::SocketAddr,
) -> Outcome {
    let (relay, recorder) = recording_relay(upstream).await;
    let options = core_runtime::tls_client::TlsOptions::from_outbound(
        outbound.as_object().unwrap(),
        "127.0.0.1",
        "test",
    )
    .unwrap()
    .unwrap();
    let socket = TcpStream::connect(relay).await.unwrap();
    let result = tokio::time::timeout(Duration::from_secs(5), options.establish(socket, &[]))
        .await
        .expect("the handshake does not hang");
    let connected = match result {
        Ok(mut stream) => {
            stream.write_all(USER_DATA).await.unwrap();
            stream.flush().await.unwrap();
            let mut pong = [0u8; 4];
            let _ =
                tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut pong)).await;
            drop(stream);
            Ok(())
        }
        Err(e) => Err(e.to_string()),
    };
    let client_records = record_types(&recorder.finish().await);
    let server_plaintext = tokio::time::timeout(Duration::from_secs(5), server)
        .await
        .expect("the server finishes")
        .unwrap();
    Outcome {
        connected,
        client_records,
        server_plaintext,
    }
}

/// Nothing but the ClientHello left the client, and the server got nothing.
fn assert_nothing_sent(what: &str, outcome: &Outcome) {
    let err = outcome
        .connected
        .as_ref()
        .expect_err(&format!("{what}: the connection must be refused"));
    assert!(
        err.contains("REALITY"),
        "{what}: the error names REALITY: {err}"
    );
    assert!(
        !outcome
            .client_records
            .contains(&(ContentType::ApplicationData as u8)),
        "{what}: the client sent encrypted records: {:?}",
        outcome.client_records
    );
    assert_eq!(
        outcome.client_records.first(),
        Some(&(ContentType::Handshake as u8)),
        "{what}: the ClientHello went out"
    );
    if let Some(plaintext) = &outcome.server_plaintext {
        assert!(
            plaintext.is_empty(),
            "{what}: the server received {} bytes of user data",
            plaintext.len()
        );
    }
}

#[tokio::test]
async fn a_reality_server_that_recognises_us_is_accepted() {
    // insecure and pins play no part in REALITY, so they do not break it either
    for extra in [
        json!({}),
        json!({"insecure": true}),
        json!({"certificate_sha256": [base64::engine::general_purpose::STANDARD.encode([0u8; 32])]}),
    ] {
        let private = [7u8; 32];
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let server = core_server(listener, reality_server_config(private));
        let outbound = client(
            &reality_public(&private),
            SHORT_ID,
            "example.com",
            extra.clone(),
        );
        let outcome = run_client(outbound, server, upstream).await;
        assert!(
            outcome.connected.is_ok(),
            "{extra}: {:?}",
            outcome.connected
        );
        assert_eq!(
            outcome.server_plaintext.as_deref(),
            Some(USER_DATA),
            "{extra}: the data arrived"
        );
    }
}

/// A REALITY server that does not recognise us -- wrong key, wrong short id --
/// does not answer as the node.
#[tokio::test]
async fn a_wrong_reality_key_or_short_id_is_refused() {
    let private = [7u8; 32];
    for insecure in [false, true] {
        for (what, public, short_id) in [
            ("wrong public key", reality_public(&[8u8; 32]), SHORT_ID),
            ("wrong short id", reality_public(&private), "deadbeef"),
        ] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let upstream = listener.local_addr().unwrap();
            let server = core_server(listener, reality_server_config(private));
            let outbound = client(
                &public,
                short_id,
                "example.com",
                json!({ "insecure": insecure }),
            );
            let outcome = run_client(outbound, server, upstream).await;
            let what = format!("{what}, insecure={insecure}");
            assert!(outcome.connected.is_err(), "{what}");
            assert!(
                !outcome
                    .client_records
                    .contains(&(ContentType::ApplicationData as u8)),
                "{what}: {:?}",
                outcome.client_records
            );
            assert_eq!(outcome.server_plaintext, None, "{what}");
        }
    }
}

/// The audit's case: an ordinary TLS server whose certificate is valid for the
/// name (the site REALITY fronts, or a redirect there). It completes the
/// handshake gladly; the client must not.
#[tokio::test]
async fn an_ordinary_tls_server_with_a_valid_certificate_gets_no_user_data() {
    for insecure in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let server = rustls_server(listener);
        let outbound = client(
            &reality_public(&[7u8; 32]),
            SHORT_ID,
            "localhost",
            json!({
                "insecure": insecure,
                "certificate": include_str!("../../../tests/golden/certs/urltest-ca.crt"),
            }),
        );
        let outcome = run_client(outbound, server, upstream).await;
        let what = format!("ordinary TLS server, insecure={insecure}");
        assert_nothing_sent(&what, &outcome);
        let err = outcome.connected.unwrap_err();
        assert!(err.contains("carries no Ed25519 key"), "{what}: {err}");
    }
}

/// Somebody in the middle with a certificate shaped like a REALITY one -- an
/// Ed25519 leaf, a valid handshake signature -- but not made under our auth
/// key. With `insecure` this used to be accepted.
#[tokio::test]
async fn an_ed25519_certificate_under_another_auth_key_is_refused() {
    for insecure in [false, true] {
        let (signing, public) = core_crypto::sign::Ed25519SigningKey::generate();
        let leaf = core_tls::reality::build_reality_certificate(&public, &[0x33; 32]);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream = listener.local_addr().unwrap();
        let server = core_server(
            listener,
            core_tls::server::Config {
                chain: vec![leaf],
                key: Some(Arc::new(signing)),
                alpn: vec![b"h2".to_vec(), b"http/1.1".to_vec()],
                cipher_suites: Vec::new(),
                reality: None,
            },
        );
        let outbound = client(
            &reality_public(&[7u8; 32]),
            SHORT_ID,
            "example.com",
            json!({ "insecure": insecure }),
        );
        let outcome = run_client(outbound, server, upstream).await;
        let what = format!("foreign Ed25519 leaf, insecure={insecure}");
        assert_nothing_sent(&what, &outcome);
        let err = outcome.connected.unwrap_err();
        assert!(
            err.contains("not signed under our auth key"),
            "{what}: {err}"
        );
    }
}

/// The rustls paths cannot do REALITY; they refuse rather than fall back to
/// plain TLS.
#[tokio::test]
async fn the_rustls_paths_refuse_reality() {
    let outbound = client(
        &reality_public(&[7u8; 32]),
        SHORT_ID,
        "localhost",
        json!({"insecure": true, "stack": "rustls"}),
    );
    let options = core_runtime::tls_client::TlsOptions::from_outbound(
        outbound.as_object().unwrap(),
        "127.0.0.1",
        "test",
    )
    .unwrap()
    .unwrap();
    assert!(options.quic_config(&[b"h3"]).is_err());

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let server = rustls_server(listener);
    let (relay, recorder) = recording_relay(upstream).await;
    let socket = TcpStream::connect(relay).await.unwrap();
    let err = options
        .connect_stream(socket, &[])
        .await
        .expect_err("no plain TLS in place of REALITY");
    assert!(err.to_string().contains("REALITY"), "{err}");
    assert!(recorder.finish().await.is_empty(), "nothing was sent");
    server.abort();

    // and `establish` takes our own stack for it even when asked for rustls
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let server = rustls_server(listener);
    let outcome = run_client(outbound, server, upstream).await;
    assert_nothing_sent("stack rustls", &outcome);
}
