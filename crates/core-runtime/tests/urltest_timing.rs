//! Delay excludes TLS setup, while setup failures still obey the full budget.
use core_tls::rustls::{ServerConfig, pki_types::CertificateDer};
use serde_json::{Value, json};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

#[tokio::test]
async fn background_probe_accepts_headers_followed_by_body_without_waiting_for_eof() {
    use std::sync::atomic::{AtomicUsize, Ordering};

    for split in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/health", listener.local_addr().unwrap());
        let requests = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&requests);
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut request = [0u8; 1024];
                let _ = stream.read(&mut request).await;
                count.fetch_add(1, Ordering::SeqCst);
                let head = b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\n\r\n";
                let mut tail = Vec::new();
                if split {
                    stream.write_all(&head[..head.len() - 2]).await.unwrap();
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    tail.extend_from_slice(&head[head.len() - 2..]);
                } else {
                    tokio::time::sleep(Duration::from_millis(20)).await;
                    tail.extend_from_slice(head);
                }
                tail.extend_from_slice(b"healthy!");
                stream.write_all(&tail).await.unwrap();
                // A complete response is enough; the probe must not wait for EOF.
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        let instance = core_runtime::start(&json!({
            "log": {"level": "error"},
            "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}},
            "outbounds": [
                {"type": "direct", "tag": "node"},
                {"type": "urltest", "tag": "provider", "outbounds": ["node"], "url": url, "interval": "1h"}
            ], "route": {"final": "node"}
        })).await.unwrap();
        let addr = instance.clash_api_addr().unwrap();
        let result = tokio::time::timeout(Duration::from_millis(800), async {
            loop {
                let (_, node) = api(addr, "/proxies/node").await;
                if let Some(delay) = node["history"].as_array().unwrap().last() {
                    break delay["delay"].as_u64().unwrap();
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await;
        instance.shutdown_wait().await;
        server.abort();
        let delay = result.expect("a body after the headers must not turn a live node into N/A");
        assert!((1..800).contains(&delay), "unexpected delay {delay}");
        assert_eq!(
            requests.load(Ordering::SeqCst),
            1,
            "a valid response needs no retry"
        );
    }
}

async fn tls_server(mut pem: &[u8], setup: Duration) -> (String, tokio::task::JoinHandle<()>) {
    core_tls::install_default_provider();
    let certs: Vec<CertificateDer<'static>> = rustls_pemfile::certs(&mut pem)
        .collect::<Result<_, _>>()
        .unwrap();
    let key = rustls_pemfile::private_key(
        &mut include_bytes!("../../../tests/golden/certs/localhost.key").as_slice(),
    )
    .unwrap()
    .unwrap();
    let cfg = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!(
        "https://127.0.0.1:{}/generate_204",
        listener.local_addr().unwrap().port()
    );
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                tokio::time::sleep(setup).await;
                let Ok(mut stream) = acceptor.accept(socket).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buffer = [0; 1024];
                while !head.ends_with(b"\r\n\r\n") {
                    let Ok(n) = stream.read(&mut buffer).await else {
                        return;
                    };
                    if n == 0 {
                        return;
                    }
                    head.extend_from_slice(&buffer[..n]);
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                // Single-request URLs remain supported.
                let _ = stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await;
                let _ = stream.flush().await;
            });
        }
    });
    (url, task)
}

async fn api(addr: std::net::SocketAddr, path: &str) -> (u16, Value) {
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    let mut byte = [0];
    while !response.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
    }
    let head = String::from_utf8(response).unwrap();
    let size: usize = head
        .lines()
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().unwrap())
        })
        .unwrap();
    let mut body = vec![0; size];
    stream.read_exact(&mut body).await.unwrap();
    (
        head.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_slice(&body).unwrap(),
    )
}

#[tokio::test]
async fn manual_group_and_background_tests_exclude_tls_but_keep_timeout() {
    let (url, server) = tls_server(
        include_bytes!("../../../tests/golden/certs/urltest-valid.crt"),
        Duration::from_millis(350),
    )
    .await;
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "certificate": {"certificate": include_str!("../../../tests/golden/certs/urltest-ca.crt")},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}},
        "outbounds": [
            {"type": "direct", "tag": "node"},
            {"type": "urltest", "tag": "provider", "outbounds": ["node"], "url": url, "interval": "1h"}
        ],
        "route": {"final": "provider"}
    })).await.unwrap();
    let addr = instance.clash_api_addr().unwrap();
    tokio::time::sleep(Duration::from_millis(650)).await;
    let (_, node) = api(addr, "/proxies/node").await;
    let background = node["history"].as_array().unwrap().last().unwrap()["delay"]
        .as_u64()
        .unwrap();
    assert!(
        (40..250).contains(&background),
        "background included TLS: {background}"
    );
    for path in ["/proxies/node/delay", "/group/provider/delay"] {
        let start = std::time::Instant::now();
        let (status, result) = api(addr, &format!("{path}?timeout=2000&url={url}")).await;
        assert_eq!(status, 200);
        assert!(start.elapsed() >= Duration::from_millis(350));
        // `/group` answers member → delay.
        let key = if path.starts_with("/group/") {
            "node"
        } else {
            "delay"
        };
        let ms = result[key].as_u64().unwrap();
        assert!(
            (40..250).contains(&ms),
            "manual included TLS or lost response delay: {ms}"
        );
    }
    let (status, _) = api(addr, &format!("/proxies/node/delay?timeout=100&url={url}")).await;
    assert_eq!(status, 504, "TLS setup must obey the original deadline");
    let (_, node) = api(addr, "/proxies/node").await;
    assert_eq!(
        node["history"],
        json!([]),
        "timeout must invalidate success"
    );
    instance.shutdown();
    server.abort();
}

#[tokio::test]
async fn failed_manual_and_background_probes_clear_previous_success() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let url = format!("http://{endpoint}/generate_204");
    let server = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let mut buf = [0; 1024];
            let _ = stream.read(&mut buf).await;
            tokio::time::sleep(Duration::from_millis(20)).await;
            let _ = stream
                .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                .await;
        }
    });
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}},
        "outbounds": [
            {"type": "direct", "tag": "node"},
            {"type": "selector", "tag": "selector", "outbounds": ["node"]},
            {"type": "urltest", "tag": "provider", "outbounds": ["node"], "url": url, "interval": "1h"}
        ],
        "route": {"final": "provider"}
    })).await.unwrap();
    let addr = instance.clash_api_addr().unwrap();
    // A closed target models the old port left behind in a subscription.
    let closed = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let dead_url = format!("http://{}/", closed.local_addr().unwrap());
    drop(closed);
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, info) = api(addr, "/proxies/node").await;
            if !info["history"].as_array().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    for path in [
        "/proxies/node/delay",
        "/group/provider/delay",
        "/proxies/selector/delay",
    ] {
        assert_eq!(
            api(addr, &format!("{path}?timeout=2000&url={url}")).await.0,
            200
        );
        let (status, result) = api(addr, &format!("{path}?timeout=2000&url={dead_url}")).await;
        if path.starts_with("/group/") {
            // `/group` answers 200 and lists only the members that passed.
            assert_eq!((status, result), (200, json!({})));
        } else {
            assert_eq!(status, 503);
        }
        for tag in ["node", "selector", "provider"] {
            let (_, info) = api(addr, &format!("/proxies/{tag}")).await;
            assert_eq!(info["history"], json!([]), "stale success for {tag}");
        }
    }
    instance.shutdown_wait().await;
    // A separate instance lets the background loop own both transitions.
    let instance = core_runtime::start(&json!({
        "log": {"level": "error"},
        "experimental": {"clash_api": {"external_controller": "127.0.0.1:0"}},
        "outbounds": [
            {"type": "direct", "tag": "node"},
            {"type": "urltest", "tag": "provider", "outbounds": ["node"], "url": url, "interval": "100ms"}
        ],
        "route": {"final": "provider"}
    })).await.unwrap();
    let addr = instance.clash_api_addr().unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let (_, info) = api(addr, "/proxies/node").await;
            if !info["history"].as_array().unwrap().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    server.abort();
    let _ = server.await;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            let (_, info) = api(addr, "/proxies/node").await;
            if info["history"] == json!([]) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("failed background round must clear the successful history");
    let (_, group) = api(addr, "/proxies/provider").await;
    assert_eq!(group["history"], json!([]));
    instance.shutdown_wait().await;
}
