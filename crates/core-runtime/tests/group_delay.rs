use serde_json::{Value, json};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

async fn head(stream: &mut TcpStream) -> String {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let Ok(byte) = stream.read_u8().await else {
            return String::new();
        };
        bytes.push(byte);
    }
    String::from_utf8(bytes).unwrap()
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
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        bytes.push(stream.read_u8().await.unwrap());
    }
    let text = String::from_utf8(bytes).unwrap();
    let length: usize = text
        .lines()
        .find_map(|line| {
            line.to_ascii_lowercase()
                .strip_prefix("content-length:")
                .map(|v| v.trim().parse().unwrap())
        })
        .unwrap();
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    (
        text.split_whitespace().nth(1).unwrap().parse().unwrap(),
        serde_json::from_slice(&body).unwrap(),
    )
}
async fn proxy(delay: u64, hits: Arc<AtomicUsize>) -> (u16, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let hits = hits.clone();
            tokio::spawn(async move {
                if head(&mut stream).await.is_empty() {
                    return;
                }
                if stream
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .is_err()
                {
                    return;
                }
                let request = head(&mut stream).await;
                if request.is_empty() {
                    return;
                }
                // Background URLTest may have started before its task was aborted.
                // Count only requests made by the manual group probe.
                if request.contains("Host: example.test") {
                    hits.fetch_add(1, Ordering::SeqCst);
                }
                tokio::time::sleep(Duration::from_millis(delay)).await;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
            });
        }
    });
    (port, task)
}
async fn stop_background(instance: &core_runtime::BoxInstance) {
    for task in instance.router().take_probe_tasks() {
        task.abort();
        let _ = task.await;
    }
}

#[tokio::test]
async fn group_probes_all_leaves_deduplicates_and_preserves_selector() {
    let slow_hits = Arc::new(AtomicUsize::new(0));
    let fast_hits = Arc::new(AtomicUsize::new(0));
    let (slow, slow_task) = proxy(160, slow_hits.clone()).await;
    let (fast, fast_task) = proxy(20, fast_hits.clone()).await;
    let instance=core_runtime::start(&json!({
        "experimental":{"clash_api":{"external_controller":"127.0.0.1:0"}},
        "outbounds":[
            {"type":"http","tag":"slow","server":"127.0.0.1","server_port":slow},
            {"type":"http","tag":"fast","server":"127.0.0.1","server_port":fast},
            {"type":"selector","tag":"child","outbounds":["slow","fast"],"default":"slow"},
            {"type":"urltest","tag":"group","outbounds":["child","fast"],"tolerance":50,"url":"http://127.0.0.1:1/","interval":"1h"}
        ],"route":{"final":"group"}
    })).await.unwrap();
    stop_background(&instance).await;
    let addr = instance.clash_api_addr().unwrap();
    let (status, result) = api(
        addr,
        "/group/group/delay?timeout=2000&url=http://example.test/",
    )
    .await;
    // Reference `getGroupDelay`: member → delay; a nested group reports the
    // delay of its selected member.
    assert_eq!(status, 200, "{result}");
    let members = result.as_object().unwrap();
    assert_eq!(members.len(), 2, "{result}");
    let fast_ms = result["fast"].as_u64().unwrap();
    assert!(fast_ms < 120, "{result}");
    assert!(result["child"].as_u64().unwrap() > fast_ms, "{result}");
    assert_eq!(slow_hits.load(Ordering::SeqCst), 1);
    assert_eq!(fast_hits.load(Ordering::SeqCst), 1);
    assert_eq!(api(addr, "/proxies/group").await.1["now"], "fast");
    assert_eq!(api(addr, "/proxies/child").await.1["now"], "slow");
    for tag in ["slow", "fast"] {
        assert!(
            !api(addr, &format!("/proxies/{tag}")).await.1["history"]
                .as_array()
                .unwrap()
                .is_empty()
        );
    }
    instance.shutdown_wait().await;
    slow_task.abort();
    fast_task.abort();
}

#[tokio::test]
async fn group_keeps_success_when_another_leaf_times_out() {
    let (fast, task) = proxy(20, Arc::new(AtomicUsize::new(0))).await;
    let (slow, slow_task) = proxy(5000, Arc::new(AtomicUsize::new(0))).await;
    let instance=core_runtime::start(&json!({
        "experimental":{"clash_api":{"external_controller":"127.0.0.1:0"}},
        "outbounds":[
            {"type":"http","tag":"slow","server":"127.0.0.1","server_port":slow},
            {"type":"http","tag":"fast","server":"127.0.0.1","server_port":fast},
            {"type":"urltest","tag":"group","outbounds":["slow","fast"],"url":"http://127.0.0.1:1/","interval":"1h"}
        ],"route":{"final":"group"}
    })).await.unwrap();
    stop_background(&instance).await;
    let addr = instance.clash_api_addr().unwrap();
    instance
        .router()
        .record_delay(instance.router().index_of("slow").unwrap(), 1);
    let (status, result) = api(
        addr,
        "/group/group/delay?timeout=250&url=http://example.test/",
    )
    .await;
    assert_eq!(status, 200, "{result}");
    // Only the members that answered in time are listed.
    assert_eq!(
        result.as_object().unwrap().keys().collect::<Vec<_>>(),
        ["fast"],
        "{result}"
    );
    assert!(result["fast"].as_u64().unwrap() > 0);
    assert_eq!(api(addr, "/proxies/group").await.1["now"], "fast");
    // `/group` serves groups only.
    assert_eq!(
        api(
            addr,
            "/group/fast/delay?timeout=250&url=http://example.test/"
        )
        .await
        .0,
        404
    );
    assert_eq!(api(addr, "/proxies/slow").await.1["history"], json!([]));
    instance.shutdown_wait().await;
    task.abort();
    slow_task.abort();
}

#[tokio::test]
async fn group_limits_parallel_probes_to_eight() {
    let active = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/", listener.local_addr().unwrap());
    let (a, p, h) = (active.clone(), peak.clone(), hits.clone());
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            let (a, p, h) = (a.clone(), p.clone(), h.clone());
            tokio::spawn(async move {
                head(&mut stream).await;
                h.fetch_add(1, Ordering::SeqCst);
                let n = a.fetch_add(1, Ordering::SeqCst) + 1;
                p.fetch_max(n, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(80)).await;
                a.fetch_sub(1, Ordering::SeqCst);
                let _=stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await;
            });
        }
    });
    let tags: Vec<_> = (0..12).map(|i| format!("node{i}")).collect();
    let mut outbounds: Vec<_> = tags
        .iter()
        .map(|tag| json!({"type":"direct","tag":tag}))
        .collect();
    outbounds.push(json!({"type":"selector","tag":"group","outbounds":tags}));
    let instance=core_runtime::start(&json!({"experimental":{"clash_api":{"external_controller":"127.0.0.1:0"}},"outbounds":outbounds,"route":{"final":"group"}})).await.unwrap();
    let (status, result) = api(
        instance.clash_api_addr().unwrap(),
        &format!("/group/group/delay?timeout=2000&url={url}"),
    )
    .await;
    assert_eq!(status, 200, "{result}");
    assert_eq!(result.as_object().unwrap().len(), 12, "{result}");
    assert_eq!(hits.load(Ordering::SeqCst), 12);
    assert!(peak.load(Ordering::SeqCst) <= 8);
    assert!(peak.load(Ordering::SeqCst) > 1);
    instance.shutdown_wait().await;
    task.abort();
}

/// A target that answers as fast as it can still answers, so the endpoint owes
/// a delay and not an error. How fast loopback actually is varies by machine,
/// so the floor that makes a sub-millisecond answer report 1 ms is pinned by
/// the unit test on `delay_ms`; what this one guards is the whole path: a
/// probe that was answered comes back 200 with a delay in it.
#[tokio::test]
async fn an_instant_answer_is_a_delay_and_not_an_error() {
    let hits = Arc::new(AtomicUsize::new(0));
    let (instant, task) = proxy(0, hits.clone()).await;
    let instance = core_runtime::start(&json!({
        "experimental":{"clash_api":{"external_controller":"127.0.0.1:0"}},
        "outbounds":[{"type":"http","tag":"instant","server":"127.0.0.1","server_port":instant}],
        "route":{"final":"instant"}
    }))
    .await
    .unwrap();
    stop_background(&instance).await;
    let addr = instance.clash_api_addr().unwrap();
    let (status, result) = api(
        addr,
        "/proxies/instant/delay?timeout=2000&url=http://example.test/",
    )
    .await;
    assert_eq!(status, 200, "{result}");
    assert!(
        result["delay"].as_u64().is_some_and(|ms| ms >= 1),
        "an answered probe reports a delay: {result}"
    );
    assert_eq!(hits.load(Ordering::SeqCst), 1);
    instance.shutdown_wait().await;
    task.abort();
}
