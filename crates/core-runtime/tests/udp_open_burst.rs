//! A UDP flow whose outbound is slow to open: the datagrams that arrive in the
//! meantime must not each start a task and a dial of their own.
//!
//! The outbound is VLESS over WebSocket against a scripted server that holds
//! every upgrade until the test answers it, so the open stays in flight for
//! exactly as long as the test wants and every dial is counted.

use std::net::SocketAddr;
use std::time::Duration;

use core_runtime::inbound::direct::Direct;
use core_runtime::route::Router;
use serde_json::json;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};

/// One held dial; `true` lets it open, `false` fails it.
type Decision = oneshot::Sender<bool>;

struct HeldProxy {
    port: u16,
    requests: mpsc::UnboundedReceiver<Decision>,
    datagrams: mpsc::UnboundedReceiver<Vec<u8>>,
    opened: usize,
}

impl HeldProxy {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy bind");
        let port = listener.local_addr().expect("proxy addr").port();
        let (request_tx, requests) = mpsc::unbounded_channel();
        let (datagram_tx, datagrams) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(serve_held(stream, request_tx.clone(), datagram_tx.clone()));
            }
        });
        Self {
            port,
            requests,
            datagrams,
            opened: 0,
        }
    }

    /// Wait until `count` dials in total have reached the server.
    async fn wait_requests(&mut self, count: usize, held: &mut Vec<Decision>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while self.opened < count {
                let request = self.requests.recv().await.expect("proxy server");
                self.opened += 1;
                held.push(request);
            }
        })
        .await
        .unwrap_or_else(|_| panic!("saw {} of {count} dials", self.opened));
    }

    /// Collect dials that arrive within `window`.
    async fn drain_requests(&mut self, window: Duration, held: &mut Vec<Decision>) {
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Some(request)) = tokio::time::timeout_at(deadline, self.requests.recv()).await
        {
            self.opened += 1;
            held.push(request);
        }
    }

    /// Payloads that reached the server within `window`.
    async fn datagrams(&mut self, window: Duration) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let deadline = tokio::time::Instant::now() + window;
        while let Ok(Some(payload)) = tokio::time::timeout_at(deadline, self.datagrams.recv()).await
        {
            out.push(payload);
        }
        out
    }
}

/// One VLESS-over-WebSocket connection: hold the upgrade until the test
/// decides, then forward the `[len][payload]` datagrams it carries.
async fn serve_held(
    mut stream: TcpStream,
    requests: mpsc::UnboundedSender<oneshot::Sender<bool>>,
    datagrams: mpsc::UnboundedSender<Vec<u8>>,
) -> Option<()> {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).await.ok()?;
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).ok()?;
    let key = head.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("sec-websocket-key")
            .then(|| value.trim().to_string())
    })?;
    let (answer, decided) = oneshot::channel();
    requests.send(answer).ok()?;
    if decided.await != Ok(true) {
        return None; // closing before the upgrade fails the open
    }
    core_runtime::ws::accept(&mut stream, &key).await.ok()?;
    let mut data = Vec::new();
    // VLESS head for an IPv4 target: version, uuid, addons, command, port,
    // address type, address
    let mut head_left = 26;
    loop {
        let mut frame = [0u8; 2];
        stream.read_exact(&mut frame).await.ok()?;
        let len = match frame[1] & 0x7f {
            126 => {
                let mut len = [0u8; 2];
                stream.read_exact(&mut len).await.ok()?;
                u64::from(u16::from_be_bytes(len))
            }
            127 => {
                let mut len = [0u8; 8];
                stream.read_exact(&mut len).await.ok()?;
                u64::from_be_bytes(len)
            }
            len => u64::from(len),
        };
        let mut mask = [0u8; 4];
        if frame[1] & 0x80 != 0 {
            stream.read_exact(&mut mask).await.ok()?;
        }
        let mut payload = vec![0u8; usize::try_from(len).ok()?];
        stream.read_exact(&mut payload).await.ok()?;
        for (i, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[i % 4];
        }
        match frame[0] & 0x0f {
            0..=2 => data.extend_from_slice(&payload),
            8 => return None,
            _ => continue,
        }
        let skip = head_left.min(data.len());
        data.drain(..skip);
        head_left -= skip;
        while data.len() >= 2 {
            let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
            if data.len() < 2 + n {
                break;
            }
            datagrams.send(data[2..2 + n].to_vec()).ok()?;
            data.drain(..2 + n);
        }
    }
}

async fn direct_udp_inbound(proxy_port: u16) -> SocketAddr {
    let router = Router::new(&json!({
        "outbounds": [{"type": "vless", "tag": "slow", "server": "127.0.0.1",
            "server_port": proxy_port, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
            "packet_encoding": "", "transport": {"type": "ws", "path": "/"}}],
        "route": {"final": "slow"}
    }))
    .expect("router");
    let inbound = Direct::bind(
        &json!({"type": "direct", "tag": "d", "listen": "127.0.0.1", "listen_port": 0,
            "network": "udp", "override_address": "192.0.2.1", "override_port": 9}),
        router,
    )
    .await
    .expect("direct inbound");
    let addr = inbound.local_addr().expect("inbound addr");
    tokio::spawn(inbound.serve());
    addr
}

/// Let the runtime settle and return the number of live tasks.
async fn settled_tasks() -> usize {
    tokio::time::sleep(Duration::from_millis(200)).await;
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

fn datagram(flow: u8, sequence: u16) -> Vec<u8> {
    let [hi, lo] = sequence.to_be_bytes();
    vec![flow, hi, lo]
}

/// Send datagrams of one flow, pausing now and then so the inbound keeps up
/// and nothing is lost before it reaches the proxy.
async fn burst(client: &UdpSocket, inbound: SocketAddr, flow: u8, range: std::ops::Range<u16>) {
    for sequence in range {
        client
            .send_to(&datagram(flow, sequence), inbound)
            .await
            .expect("send");
        if sequence % 25 == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_burst_on_an_opening_flow_dials_once_and_spawns_no_task_per_datagram() {
    let mut proxy = HeldProxy::start().await;
    let inbound = direct_udp_inbound(proxy.port).await;
    let baseline = settled_tasks().await;

    let busy = UdpSocket::bind("127.0.0.1:0").await.expect("busy client");
    let mut quiet = Vec::new();
    for _ in 0..3 {
        quiet.push(UdpSocket::bind("127.0.0.1:0").await.expect("quiet client"));
    }
    burst(&busy, inbound, 0, 0..500).await;
    for (flow, client) in quiet.iter().enumerate() {
        burst(client, inbound, flow as u8 + 1, 0..1).await;
    }

    let mut held = Vec::new();
    proxy.wait_requests(4, &mut held).await;
    proxy
        .drain_requests(Duration::from_millis(200), &mut held)
        .await;
    let opening = settled_tasks().await;
    eprintln!(
        "while opening: dials={} tasks {baseline}->{opening}",
        proxy.opened
    );
    assert_eq!(proxy.opened, 4, "one dial per flow while it opens");
    assert!(
        opening - baseline < 50,
        "tasks grew by {} for 4 opening flows",
        opening - baseline
    );

    // every open fails: the queued datagrams must not dial again
    for request in held.drain(..) {
        let _ = request.send(false);
    }
    proxy
        .drain_requests(Duration::from_millis(500), &mut held)
        .await;
    for request in held.drain(..) {
        let _ = request.send(false);
    }
    let failed = settled_tasks().await;
    eprintln!(
        "after failure: dials={} tasks {baseline}->{failed}",
        proxy.opened
    );
    assert_eq!(
        proxy.opened, 4,
        "a failed open is not retried by queued datagrams"
    );
    assert!(
        failed <= baseline + 5,
        "tasks left after failure: {baseline}->{failed}"
    );

    // the next datagram of the busy flow opens it again
    burst(&busy, inbound, 0, 500..501).await;
    proxy.wait_requests(5, &mut held).await;
    let _ = held.pop().expect("retry").send(true);
    let got = proxy.datagrams(Duration::from_millis(500)).await;
    assert_eq!(got, vec![datagram(0, 500)]);
    assert_eq!(proxy.opened, 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn datagrams_queued_during_the_open_are_sent_first_and_capped() {
    let mut proxy = HeldProxy::start().await;
    let inbound = direct_udp_inbound(proxy.port).await;
    let baseline = settled_tasks().await;
    let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");

    burst(&client, inbound, 7, 0..100).await;
    let mut held = Vec::new();
    proxy.wait_requests(1, &mut held).await;
    // let the inbound read the whole burst while the open is held
    tokio::time::sleep(Duration::from_millis(200)).await;
    let _ = held.pop().expect("open").send(true);
    let got = proxy.datagrams(Duration::from_millis(500)).await;
    let expected: Vec<Vec<u8>> = (0..=16).map(|seq| datagram(7, seq)).collect();
    eprintln!("sent 100 during the open, delivered {}", got.len());
    assert_eq!(got, expected, "first datagram plus 16 queued, in order");

    burst(&client, inbound, 7, 100..103).await;
    let later = proxy.datagrams(Duration::from_millis(300)).await;
    let expected: Vec<Vec<u8>> = (100..103).map(|seq| datagram(7, seq)).collect();
    assert_eq!(later, expected, "an open flow forwards directly");
    proxy
        .drain_requests(Duration::from_millis(100), &mut held)
        .await;
    assert_eq!(proxy.opened, 1);
    let done = settled_tasks().await;
    // the open flow keeps its reverse pump and the packet bridge
    assert!(
        done <= baseline + 6,
        "tasks after the open: {baseline}->{done}"
    );
}
