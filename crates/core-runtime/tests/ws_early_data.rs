//! WebSocket early data: our client and server against each other, against
//! the reference sing-box (SING_BOX_REF) and against Xray (XRAY_REF); the
//! reference cases are skipped unless the variable is set.
//!
//! An empty `early_data_header_name` means `Sec-WebSocket-Protocol` here, as
//! in Xray. sing-box reads it as "append to the path" instead, so the
//! unnamed shape is checked against Xray and our server only, and the
//! sing-box cases always name the header.
//!
//! The VLESS request for an IPv4 target is 26 bytes, which is what rides
//! early: 26 is not a multiple of 3, so standard base64 would pad it, and the
//! budgets below land just under, on and over it.

use std::net::SocketAddr;
use std::process::{Child, Command};
use std::time::Duration;

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const UUID: &str = "b831381d-6324-4d53-ad4f-8cda48b30811";
const SWP: &str = "Sec-WebSocket-Protocol";

/// (label, max_early_data, early_data_header_name), every one with the header
/// named: what sing-box and our side share.
const NAMED_CASES: &[(&str, u64, Option<&str>)] = &[
    ("no early data", 0, None),
    ("protocol header", 2048, Some(SWP)),
    ("protocol header, budget under", 25, Some(SWP)),
    ("protocol header, budget exact", 26, Some(SWP)),
    ("protocol header, budget over", 27, Some(SWP)),
    ("custom header", 2048, Some("X-Early-Data")),
    ("custom header, budget 1", 1, Some("X-Early-Data")),
];

/// The shape Forkop X writes for an `ed=N` link: `max_early_data` and no
/// header name (`subscription/parser.uc` add_transport, `singbox/generator.uc`
/// apply_link_transport).
const FORKOP_CASES: &[(&str, u64)] = &[
    ("forkop ed=2048", 2048),
    ("forkop ed=25", 25),
    ("forkop ed=26", 26),
    ("forkop ed=27", 27),
    ("forkop ed=1", 1),
];

fn ws(max_early_data: u64, header: Option<&str>) -> Value {
    let mut t = json!({"type": "ws", "path": "/ed"});
    if max_early_data > 0 {
        t["max_early_data"] = json!(max_early_data);
    }
    if let Some(name) = header {
        t["early_data_header_name"] = json!(name);
    }
    t
}

/// Exactly what Forkop X generates from
/// `vless://...?type=ws&path=/ed&host=example.com&ed=N`.
fn forkop_ws(max_early_data: u64) -> Value {
    json!({"type": "ws", "path": "/ed", "headers": {"Host": "example.com"},
           "max_early_data": max_early_data})
}

async fn spawn_echo() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind echo");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            tokio::spawn(async move {
                let mut buf = [0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind probe")
        .local_addr()
        .expect("probe addr")
        .port()
}

async fn wait_listening(port: u16) -> bool {
    for _ in 0..50 {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

struct RefProcess(Child);

impl Drop for RefProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn start_ref(ref_bin: &str, config: &Value) -> RefProcess {
    let path = std::env::temp_dir().join(format!(
        "tc-ws-early-{}-{}.json",
        std::process::id(),
        free_port()
    ));
    std::fs::write(&path, serde_json::to_string(config).expect("serialize"))
        .expect("write ref config");
    let child = Command::new(ref_bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn reference sing-box");
    RefProcess(child)
}

/// SOCKS CONNECT to the echo, then exact bytes both ways: a short write that
/// has to come back first, then a bulk one with every byte value in it.
async fn socks_roundtrip(proxy: SocketAddr, echo: SocketAddr, label: &str) {
    let mut stream = TcpStream::connect(proxy).await.expect("connect proxy");
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .expect("greeting");
    let mut auth = [0u8; 2];
    stream.read_exact(&mut auth).await.expect("auth reply");
    assert_eq!(auth, [0x05, 0x00], "{label}: socks greeting");
    let std::net::IpAddr::V4(v4) = echo.ip() else {
        panic!("expected a v4 echo address");
    };
    let mut request = vec![0x05, 0x01, 0x00, 0x01];
    request.extend_from_slice(&v4.octets());
    request.extend_from_slice(&echo.port().to_be_bytes());
    stream.write_all(&request).await.expect("socks request");
    let mut reply = [0u8; 10];
    stream.read_exact(&mut reply).await.expect("connect reply");
    assert_eq!(reply[1], 0x00, "{label}: CONNECT must succeed");

    stream.write_all(b"roundtrip").await.expect("write");
    let mut buf = [0u8; 9];
    stream.read_exact(&mut buf).await.expect("echo read");
    assert_eq!(&buf, b"roundtrip", "{label}: payload must echo");

    let payload: Vec<u8> = (0..40_000u32).map(|i| (i * 31 + 7) as u8).collect();
    stream.write_all(&payload).await.expect("bulk write");
    let mut echoed = vec![0u8; payload.len()];
    stream.read_exact(&mut echoed).await.expect("bulk read");
    assert_eq!(echoed, payload, "{label}: bulk payload must echo");
}

async fn start_client(server_port: u16, transport: Value) -> core_runtime::BoxInstance {
    core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 0}],
        "outbounds": [{"type": "vless", "tag": "up", "server": "127.0.0.1",
                       "server_port": server_port, "uuid": UUID, "transport": transport}],
        "route": {"final": "up"}
    }))
    .await
    .expect("start client")
}

async fn start_server(port: u16, transport: Value) -> core_runtime::BoxInstance {
    core_runtime::start(&json!({
        "log": {"level": "error"},
        "inbounds": [{"type": "vless", "tag": "server-in", "listen": "127.0.0.1",
                      "listen_port": port, "users": [{"name": "u", "uuid": UUID}],
                      "transport": transport}],
        "outbounds": [{"type": "direct", "tag": "direct"}],
        "route": {"final": "direct"}
    }))
    .await
    .expect("start server")
}

/// One case; a failure is collected so every case gets reported.
async fn run(label: &str, proxy: SocketAddr, echo: SocketAddr, failed: &mut Vec<String>) {
    let owned = label.to_string();
    let task = tokio::spawn(async move {
        tokio::time::timeout(
            Duration::from_secs(15),
            socks_roundtrip(proxy, echo, &owned),
        )
        .await
    });
    match task.await {
        Ok(Ok(())) => {}
        Ok(Err(_)) => failed.push(format!("{label}: timed out")),
        Err(_) => failed.push(format!("{label}: failed")),
    }
}

fn report(failed: &[String]) {
    assert!(failed.is_empty(), "failing cases:\n{}", failed.join("\n"));
}

#[tokio::test]
async fn our_client_against_our_server() {
    let echo = spawn_echo().await;
    let mut failed = Vec::new();
    let named = NAMED_CASES
        .iter()
        .map(|&(label, max, header)| (label, ws(max, header)));
    let forkop = FORKOP_CASES
        .iter()
        .map(|&(label, max)| (label, forkop_ws(max)));
    for (label, transport) in named.chain(forkop) {
        let label = format!("ours->ours {label}");
        let server = start_server(0, transport.clone()).await;
        let port = server.inbound_addrs()[0].1.port();
        let client = start_client(port, transport).await;
        run(&label, client.inbound_addrs()[0].1, echo, &mut failed).await;
        client.shutdown();
        server.shutdown();
    }
    report(&failed);
}

#[tokio::test]
async fn our_client_against_the_reference_server() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    let ref_bin = ref_bin.to_string_lossy().into_owned();
    let echo = spawn_echo().await;
    let mut failed = Vec::new();
    for &(label, max, header) in NAMED_CASES {
        let label = format!("ours->sing-box {label}");
        let port = free_port();
        let _server = start_ref(
            &ref_bin,
            &json!({
                "log": {"level": "error"},
                "inbounds": [{"type": "vless", "tag": "in", "listen": "127.0.0.1",
                              "listen_port": port, "users": [{"uuid": UUID}],
                              "transport": ws(max, header)}],
                "outbounds": [{"type": "direct", "tag": "direct"}]
            }),
        );
        assert!(
            wait_listening(port).await,
            "{label}: reference did not start"
        );
        let client = start_client(port, ws(max, header)).await;
        run(&label, client.inbound_addrs()[0].1, echo, &mut failed).await;
        client.shutdown();
    }
    report(&failed);
}

#[tokio::test]
async fn the_reference_client_against_our_server() {
    let Some(ref_bin) = std::env::var_os("SING_BOX_REF") else {
        return;
    };
    let ref_bin = ref_bin.to_string_lossy().into_owned();
    let echo = spawn_echo().await;
    let mut failed = Vec::new();
    for &(label, max, header) in NAMED_CASES {
        let label = format!("sing-box->ours {label}");
        let server = start_server(0, ws(max, header)).await;
        let server_port = server.inbound_addrs()[0].1.port();
        let front = free_port();
        let _client = start_ref(
            &ref_bin,
            &json!({
                "log": {"level": "error"},
                "inbounds": [{"type": "mixed", "tag": "front", "listen": "127.0.0.1",
                              "listen_port": front}],
                "outbounds": [{"type": "vless", "tag": "up", "server": "127.0.0.1",
                               "server_port": server_port, "uuid": UUID,
                               "transport": ws(max, header)}],
                "route": {"final": "up"}
            }),
        );
        assert!(
            wait_listening(front).await,
            "{label}: reference did not start"
        );
        run(
            &label,
            SocketAddr::from(([127, 0, 0, 1], front)),
            echo,
            &mut failed,
        )
        .await;
        server.shutdown();
    }
    report(&failed);
}

/// Xray reads and writes the early data only in `Sec-WebSocket-Protocol`
/// (`hub.go`, `dialer.go`) and has no header-name setting, so the custom
/// header cases do not apply to it. Its side takes the budget from `?ed=`.
/// (label, max_early_data, our transport)
fn xray_cases() -> Vec<(String, u64, Value)> {
    let mut cases = vec![("no early data".to_string(), 0, ws(0, None))];
    for max in [2048, 25, 26, 27] {
        cases.push((
            format!("protocol header, budget {max}"),
            max,
            ws(max, Some(SWP)),
        ));
    }
    for &(label, max) in FORKOP_CASES {
        cases.push((label.to_string(), max, forkop_ws(max)));
    }
    cases
}

fn xray_ws(max_early_data: u64) -> Value {
    let path = if max_early_data > 0 {
        format!("/ed?ed={max_early_data}")
    } else {
        "/ed".to_string()
    };
    json!({"network": "ws", "wsSettings": {"path": path}})
}

fn start_xray(xray_bin: &str, config: &Value) -> RefProcess {
    let path = std::env::temp_dir().join(format!(
        "tc-ws-early-xray-{}-{}.json",
        std::process::id(),
        free_port()
    ));
    std::fs::write(&path, serde_json::to_string(config).expect("serialize"))
        .expect("write xray config");
    let child = Command::new(xray_bin)
        .args(["run", "-c"])
        .arg(&path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn xray");
    RefProcess(child)
}

/// Includes the regression for Forkop X's `ed=` config against an
/// independent Xray server.
#[tokio::test]
async fn our_client_against_xray() {
    let Some(xray_bin) = std::env::var_os("XRAY_REF") else {
        return;
    };
    let xray_bin = xray_bin.to_string_lossy().into_owned();
    let echo = spawn_echo().await;
    let mut failed = Vec::new();
    for (label, max, transport) in xray_cases() {
        let label = format!("ours->xray {label}");
        let port = free_port();
        let _server = start_xray(
            &xray_bin,
            &json!({
                "log": {"loglevel": "none"},
                "inbounds": [{"listen": "127.0.0.1", "port": port, "protocol": "vless",
                              "settings": {"clients": [{"id": UUID}], "decryption": "none"},
                              "streamSettings": xray_ws(max)}],
                "outbounds": [{"protocol": "freedom",
                               "settings": {"finalRules": [{"action": "allow"}]}}]
            }),
        );
        assert!(wait_listening(port).await, "{label}: xray did not start");
        let client = start_client(port, transport).await;
        run(&label, client.inbound_addrs()[0].1, echo, &mut failed).await;
        client.shutdown();
    }
    report(&failed);
}

#[tokio::test]
async fn xray_against_our_server() {
    let Some(xray_bin) = std::env::var_os("XRAY_REF") else {
        return;
    };
    let xray_bin = xray_bin.to_string_lossy().into_owned();
    let echo = spawn_echo().await;
    let mut failed = Vec::new();
    for (label, max, transport) in xray_cases() {
        let label = format!("xray->ours {label}");
        let server = start_server(0, transport).await;
        let server_port = server.inbound_addrs()[0].1.port();
        let front = free_port();
        let _client = start_xray(
            &xray_bin,
            &json!({
                "log": {"loglevel": "none"},
                "inbounds": [{"listen": "127.0.0.1", "port": front, "protocol": "socks",
                              "settings": {"udp": false}}],
                "outbounds": [{"protocol": "vless",
                               "settings": {"vnext": [{"address": "127.0.0.1", "port": server_port,
                                            "users": [{"id": UUID, "encryption": "none"}]}]},
                               "streamSettings": xray_ws(max)}]
            }),
        );
        assert!(wait_listening(front).await, "{label}: xray did not start");
        run(
            &label,
            SocketAddr::from(([127, 0, 0, 1], front)),
            echo,
            &mut failed,
        )
        .await;
        server.shutdown();
    }
    report(&failed);
}
