//! TS2021 registration transport. Wire framing follows Tailscale controlbase
//! and ts2021 (BSD-3-Clause); implementation uses the existing Rust primitives.
use super::control::{MapResponse, RegisterRequest, RegisterResponse, parse_key_hex};
use super::noise::{CipherState, NoiseIkInitiator};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use std::{io, sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use x25519_dalek::{PublicKey, StaticSecret};

pub const CAPABILITY_VERSION: u32 = 111;
const LIMIT: usize = 1024 * 1024;
fn map_hostinfo(hostname: &str, routes: &[String], home: Option<u16>) -> serde_json::Value {
    map_network_hostinfo(
        hostname,
        routes,
        &super::connectivity::NetworkInfo {
            home_derp: home,
            ..Default::default()
        },
    )
}
fn map_network_hostinfo(
    hostname: &str,
    routes: &[String],
    network: &super::connectivity::NetworkInfo,
) -> serde_json::Value {
    let latencies: serde_json::Map<String, serde_json::Value> = network
        .derp_latencies
        .iter()
        .map(|(id, ms)| (format!("{}-v4", id), serde_json::json!(*ms as f64 / 1000.0)))
        .collect();
    let mut info = serde_json::to_value(super::control::Hostinfo::new(hostname, routes))
        .expect("Hostinfo serialization is infallible");
    info["Userspace"] = true.into();
    info["UserspaceRouter"] = true.into();
    info["NetInfo"] = serde_json::json!({"PreferredDERP":network.home_derp.unwrap_or(0),"WorkingUDP":network.udp_available,"WorkingIPv6":false,"MappingVariesByDestIP":network.mapping_varies,"DERPLatency":latencies});
    info
}
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

struct Tasks(Vec<JoinHandle<()>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

pub struct ControlSession {
    send: h2::client::SendRequest<Bytes>,
    _tasks: Tasks,
    origin: String,
}

fn control_uri(url: &str) -> io::Result<http::Uri> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| bad("tailscale: invalid control URL"))?;
    if uri.scheme_str() != Some("https")
        || uri.host().is_none()
        || uri.authority().unwrap().as_str().contains('@')
        || !matches!(uri.path_and_query().map(|p| p.as_str()), None | Some("/"))
    {
        return Err(bad("tailscale: control URL must be an HTTPS origin"));
    }
    Ok(uri)
}

pub(crate) async fn tls(
    uri: &http::Uri,
    alpn: &[u8],
) -> io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let host = uri.host().ok_or_else(|| bad("tailscale: missing host"))?;
    let tcp = TcpStream::connect((host, uri.port_u16().unwrap_or(443))).await?;
    tcp.set_nodelay(true)?;
    let mut cfg =
        core_tls::rustls::ClientConfig::builder_with_provider(Arc::new(core_crypto::provider()))
            .with_safe_default_protocol_versions()
            .map_err(io::Error::other)?
            .with_root_certificates(core_tls::verify::WebpkiVerifier::mozilla_store())
            .with_no_client_auth();
    cfg.alpn_protocols = vec![alpn.to_vec()];
    let name = core_tls::rustls::pki_types::ServerName::try_from(host.to_owned())
        .map_err(|_| bad("tailscale: invalid TLS name"))?;
    tokio_rustls::TlsConnector::from(Arc::new(cfg))
        .connect(name, tcp)
        .await
}

async fn body(response: http::Response<h2::RecvStream>) -> io::Result<Vec<u8>> {
    if !response.status().is_success() {
        return Err(io::Error::other(format!(
            "tailscale: control HTTP {}",
            response.status().as_u16()
        )));
    }
    let mut recv = response.into_body();
    let mut out = Vec::new();
    while let Some(chunk) = recv.data().await {
        let chunk = chunk.map_err(io::Error::other)?;
        if out.len() + chunk.len() > LIMIT {
            return Err(bad("tailscale: control response too large"));
        }
        out.extend_from_slice(&chunk);
        recv.flow_control()
            .release_capacity(chunk.len())
            .map_err(io::Error::other)?;
    }
    Ok(out)
}

async fn server_key(uri: &http::Uri) -> io::Result<PublicKey> {
    let stream = tls(uri, b"h2").await?;
    let (send, connection) = h2::client::handshake(stream)
        .await
        .map_err(io::Error::other)?;
    let _tasks = Tasks(vec![tokio::spawn(async move {
        let _ = connection.await;
    })]);
    let mut send = send.ready().await.map_err(io::Error::other)?;
    let origin = format!("https://{}", uri.authority().unwrap());
    let req = http::Request::builder()
        .uri(format!("{origin}/key?v={CAPABILITY_VERSION}"))
        .body(())
        .map_err(io::Error::other)?;
    let (response, _) = send.send_request(req, true).map_err(io::Error::other)?;
    let bytes = body(response.await.map_err(io::Error::other)?).await?;
    parse_server_key(&bytes)
}

fn parse_server_key(bytes: &[u8]) -> io::Result<PublicKey> {
    let value: serde_json::Value = serde_json::from_slice(bytes)
        .map_err(|_| bad("tailscale: invalid control key response"))?;
    let key = value
        .get("publicKey")
        .and_then(|v| v.as_str())
        .and_then(parse_key_hex)
        .ok_or_else(|| bad("tailscale: missing Noise public key"))?;
    if key == [0; 32] {
        return Err(bad("tailscale: zero control key"));
    }
    Ok(PublicKey::from(key))
}

impl ControlSession {
    pub async fn map_stream(
        &mut self,
        node: &str,
        hostname: &str,
        home: Option<u16>,
        disco: [u8; 32],
    ) -> io::Result<MapStream> {
        self.map_stream_with_routes(node, hostname, home, disco, &[])
            .await
    }
    pub async fn map_stream_with_routes(
        &mut self,
        node: &str,
        hostname: &str,
        home: Option<u16>,
        disco: [u8; 32],
        routes: &[String],
    ) -> io::Result<MapStream> {
        self.map_stream_with_network(
            node,
            hostname,
            disco,
            routes,
            &super::connectivity::NetworkInfo {
                home_derp: home,
                ..Default::default()
            },
        )
        .await
    }
    pub async fn map_stream_with_network(
        &mut self,
        node: &str,
        hostname: &str,
        disco: [u8; 32],
        routes: &[String],
        network: &super::connectivity::NetworkInfo,
    ) -> io::Result<MapStream> {
        tokio::time::timeout(
            Duration::from_secs(30),
            self.announce(node, hostname, disco, routes, network),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tailscale: announce timeout"))??;
        // A half-open control connection must not hold the loop: bound the
        // request the way announce and the stream reads are bounded.
        let timed_out = || {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "tailscale: map stream start timeout",
            )
        };
        self.send = tokio::time::timeout(Duration::from_secs(30), self.send.clone().ready())
            .await
            .map_err(|_| timed_out())?
            .map_err(io::Error::other)?;
        let payload=serde_json::to_vec(&serde_json::json!({"Version":CAPABILITY_VERSION,"NodeKey":node,"DiscoKey":format!("discokey:{}",super::control::to_hex(&disco)),
            "Stream":true,"KeepAlive":true,"Compress":"","Endpoints":network.endpoints.iter().map(ToString::to_string).collect::<Vec<_>>(),"Hostinfo":map_network_hostinfo(hostname,routes,network)})).map_err(io::Error::other)?;
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("{}/machine/map", self.origin))
            .header("Ts-Lb", node)
            .header("content-type", "application/json")
            .body(())
            .map_err(io::Error::other)?;
        let (response, mut send) = self
            .send
            .send_request(request, false)
            .map_err(io::Error::other)?;
        send.send_data(Bytes::from(payload), true)
            .map_err(io::Error::other)?;
        let response = tokio::time::timeout(Duration::from_secs(30), response)
            .await
            .map_err(|_| timed_out())?
            .map_err(io::Error::other)?;
        if !response.status().is_success() {
            return Err(bad("tailscale: map stream rejected"));
        }
        Ok(MapStream {
            recv: response.into_body(),
            pending: vec![],
        })
    }

    async fn announce(
        &mut self,
        node: &str,
        hostname: &str,
        disco: [u8; 32],
        routes: &[String],
        network: &super::connectivity::NetworkInfo,
    ) -> io::Result<()> {
        self.send = self.send.clone().ready().await.map_err(io::Error::other)?;
        let payload=serde_json::to_vec(&serde_json::json!({"Version":CAPABILITY_VERSION,"NodeKey":node,"DiscoKey":format!("discokey:{}",super::control::to_hex(&disco)),
            "Stream":false,"OmitPeers":true,"Endpoints":network.endpoints.iter().map(ToString::to_string).collect::<Vec<_>>(),"Hostinfo":map_network_hostinfo(hostname,routes,network)})).map_err(io::Error::other)?;
        let request = http::Request::builder()
            .method("POST")
            .uri(format!("{}/machine/map", self.origin))
            .header("Ts-Lb", node)
            .header("content-type", "application/json")
            .body(())
            .map_err(io::Error::other)?;
        let (response, mut send) = self
            .send
            .send_request(request, false)
            .map_err(io::Error::other)?;
        send.send_data(Bytes::from(payload), true)
            .map_err(io::Error::other)?;
        body(response.await.map_err(io::Error::other)?).await?;
        Ok(())
    }
    /// Fetch an uncompressed initial map without advertising LAN or endpoints.
    pub async fn initial_map(&mut self, node_key: &str, hostname: &str) -> io::Result<MapResponse> {
        self.refresh_map(node_key, hostname, None).await
    }

    /// Obtain a complete snapshot and announce the preferred relay.
    pub async fn refresh_map(
        &mut self,
        node_key: &str,
        hostname: &str,
        home: Option<u16>,
    ) -> io::Result<MapResponse> {
        tokio::time::timeout(Duration::from_secs(30), async {
            self.send = self.send.clone().ready().await.map_err(io::Error::other)?;
            let payload = serde_json::to_vec(&serde_json::json!({
                "Version": CAPABILITY_VERSION, "NodeKey": node_key,
                "ReadOnly": false, "Stream": false, "KeepAlive": false, "Compress": "",
                "Hostinfo": map_hostinfo(hostname, &[], home)
            }))
            .map_err(io::Error::other)?;
            let req = http::Request::builder()
                .method("POST")
                .uri(format!("{}/machine/map", self.origin))
                .header("content-type", "application/json")
                .body(())
                .map_err(io::Error::other)?;
            let (response, mut stream) = self
                .send
                .send_request(req, false)
                .map_err(io::Error::other)?;
            stream
                .send_data(Bytes::from(payload), true)
                .map_err(io::Error::other)?;
            let bytes = body(response.await.map_err(io::Error::other)?).await?;
            decode_map(&bytes)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tailscale: map timeout"))?
    }

    pub async fn connect(url: &str, machine: StaticSecret) -> io::Result<Self> {
        tokio::time::timeout(Duration::from_secs(30), Self::connect_inner(url, machine))
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    "tailscale: control connect timeout",
                )
            })?
    }

    async fn connect_inner(url: &str, machine: StaticSecret) -> io::Result<Self> {
        let uri = control_uri(url)?;
        let key = server_key(&uri).await?;
        if !machine.diffie_hellman(&key).was_contributory() {
            return Err(bad("tailscale: invalid control public key"));
        }
        let prologue = format!("Tailscale Control Protocol v{CAPABILITY_VERSION}");
        let mut noise = NoiseIkInitiator::new(machine, key, prologue.as_bytes());
        let initial = noise.write_msg1(&[]);
        let mut frame = (CAPABILITY_VERSION as u16).to_be_bytes().to_vec();
        frame.push(1);
        frame.extend_from_slice(&(initial.len() as u16).to_be_bytes());
        frame.extend(initial);
        let mut stream = tls(&uri, b"http/1.1").await?;
        let request = format!(
            "POST /ts2021 HTTP/1.1\r\nHost: {}\r\nConnection: upgrade\r\nUpgrade: tailscale-control-protocol\r\nX-Tailscale-Handshake: {}\r\nContent-Length: 0\r\n\r\n",
            uri.authority().unwrap(),
            STANDARD.encode(frame)
        );
        stream.write_all(request.as_bytes()).await?;
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= 16384 {
                return Err(bad("tailscale: upgrade headers too large"));
            }
            header.push(stream.read_u8().await?);
        }
        let header =
            std::str::from_utf8(&header).map_err(|_| bad("tailscale: invalid upgrade response"))?;
        if !header
            .lines()
            .next()
            .is_some_and(|l| l.split_whitespace().nth(1) == Some("101"))
            || !header.lines().any(|l| {
                l.split_once(':').is_some_and(|(k, v)| {
                    k.eq_ignore_ascii_case("upgrade")
                        && v.trim().eq_ignore_ascii_case("tailscale-control-protocol")
                })
            })
        {
            return Err(bad("tailscale: control upgrade refused"));
        }
        let mut hdr = [0; 3];
        stream.read_exact(&mut hdr).await?;
        if hdr != [2, 0, 48] {
            return Err(bad("tailscale: invalid Noise handshake response"));
        }
        let mut response = [0; 48];
        stream.read_exact(&mut response).await?;
        let (_, (tx, rx)) = noise.read_msg2(&response).map_err(io::Error::other)?;
        let (plain, bridge) = tokio::io::duplex(65536);
        let (reader, writer) = tokio::io::split(stream);
        let (plain_reader, plain_writer) = tokio::io::split(bridge);
        let mut tasks = Tasks(vec![
            tokio::spawn(async move {
                let _ = decrypt_records(reader, plain_writer, rx.into_transport()).await;
            }),
            tokio::spawn(async move {
                let _ = encrypt_records(plain_reader, writer, tx.into_transport()).await;
            }),
        ]);
        let (send, connection) = h2::client::handshake(plain)
            .await
            .map_err(io::Error::other)?;
        tasks.0.push(tokio::spawn(async move {
            let _ = connection.await;
        }));
        Ok(Self {
            send,
            _tasks: tasks,
            origin: format!("https://{}", uri.authority().unwrap()),
        })
    }

    pub async fn register(&mut self, request: &RegisterRequest) -> io::Result<RegisterResponse> {
        tokio::time::timeout(Duration::from_secs(30), async {
            let payload = serde_json::to_vec(request).map_err(io::Error::other)?;
            if payload.len() > 16384 {
                return Err(bad("tailscale: registration request too large"));
            }
            self.send = self.send.clone().ready().await.map_err(io::Error::other)?;
            let req = http::Request::builder()
                .method("POST")
                .uri(format!("{}/machine/register", self.origin))
                .header("content-type", "application/json")
                .body(())
                .map_err(io::Error::other)?;
            let (response, mut send) = self
                .send
                .send_request(req, false)
                .map_err(io::Error::other)?;
            send.send_data(Bytes::from(payload), true)
                .map_err(io::Error::other)?;
            let bytes = body(response.await.map_err(io::Error::other)?).await?;
            let result: RegisterResponse = serde_json::from_slice(&bytes)
                .map_err(|_| bad("tailscale: invalid registration response"))?;
            // Do not echo server errors: they may contain authentication material.
            if result.error.as_ref().is_some_and(|e| !e.is_empty()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "tailscale: registration rejected",
                ));
            }
            Ok(result)
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "tailscale: registration timeout"))?
    }
}

pub struct MapStream {
    recv: h2::RecvStream,
    pending: Vec<u8>,
}
impl MapStream {
    pub async fn next(&mut self) -> io::Result<super::control::MapResponse> {
        tokio::time::timeout(Duration::from_secs(120), async {
            loop {
                if self.pending.len() >= 4 {
                    let length = u32::from_le_bytes(self.pending[..4].try_into().unwrap()) as usize;
                    if length > LIMIT {
                        return Err(bad("tailscale: map stream frame too large"));
                    }
                    if self.pending.len() >= 4 + length {
                        let result = decode_map(&self.pending[..4 + length]);
                        self.pending.drain(..4 + length);
                        return result;
                    }
                }
                let chunk = self
                    .recv
                    .data()
                    .await
                    .ok_or_else(|| bad("tailscale: map stream ended"))?
                    .map_err(io::Error::other)?;
                if self.pending.len() + chunk.len() > LIMIT + 65536 {
                    return Err(bad("tailscale: map stream buffer exceeded"));
                }
                self.pending.extend_from_slice(&chunk);
                self.recv
                    .flow_control()
                    .release_capacity(chunk.len())
                    .map_err(io::Error::other)?;
            }
        })
        .await
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "tailscale: map stream timeout",
            )
        })?
    }
}

fn decode_map(bytes: &[u8]) -> io::Result<MapResponse> {
    if bytes.len() < 4 {
        return Err(bad("tailscale: truncated map header"));
    }
    let size = u32::from_le_bytes(bytes[..4].try_into().unwrap()) as usize;
    if size != bytes.len() - 4 {
        return Err(bad("tailscale: invalid map frame length"));
    }
    serde_json::from_slice(&bytes[4..]).map_err(|error| {
        // Keep only JSON structure and locations, never peer addresses, keys,
        // names or other string values from the control response.
        #[cfg(target_os = "linux")]
        if let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes[4..]) {
            use std::{io::Write, os::unix::fs::OpenOptionsExt};
            let diagnostic = serde_json::json!({"line":error.line(), "column":error.column(), "shape":map_shape(&value, 0)});
            if let Ok(mut file) = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600)
                .open("/var/run/forkop/ui-state/tailscale-map-failure.json") {
                let _ = file.write_all(diagnostic.to_string().as_bytes());
            }
        }
        bad("tailscale: invalid map response")
    })
}

fn map_shape(value: &serde_json::Value, depth: usize) -> serde_json::Value {
    use serde_json::Value;
    if depth > 8 {
        return Value::String("nested".into());
    }
    match value {
        Value::Object(fields) => Value::Object(
            fields
                .iter()
                .map(|(key, value)| (key.clone(), map_shape(value, depth + 1)))
                .collect(),
        ),
        Value::Array(items) => Value::Array(
            items
                .iter()
                .take(3)
                .map(|v| map_shape(v, depth + 1))
                .collect(),
        ),
        Value::Null => Value::Null,
        Value::String(_) => Value::String("string".into()),
        Value::Bool(_) => Value::String("boolean".into()),
        Value::Number(_) => Value::String("number".into()),
    }
}

async fn encrypt_records<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut input: R,
    mut output: W,
    mut cipher: CipherState,
) -> io::Result<()> {
    let mut buffer = [0; 4077];
    loop {
        let n = input.read(&mut buffer).await?;
        if n == 0 {
            return output.shutdown().await;
        }
        let encrypted = cipher.encrypt_with_ad(&[], &buffer[..n]);
        output
            .write_all(&[4, (encrypted.len() >> 8) as u8, encrypted.len() as u8])
            .await?;
        output.write_all(&encrypted).await?;
        output.flush().await?;
    }
}

async fn decrypt_records<R: tokio::io::AsyncRead + Unpin, W: tokio::io::AsyncWrite + Unpin>(
    mut input: R,
    mut output: W,
    mut cipher: CipherState,
) -> io::Result<()> {
    let mut early = true;
    let mut pending = Vec::new();
    loop {
        let mut header = [0; 3];
        input.read_exact(&mut header).await?;
        let size = u16::from_be_bytes([header[1], header[2]]) as usize;
        if header[0] != 4 || !(16..=4093).contains(&size) {
            return Err(bad("tailscale: invalid Noise record"));
        }
        let mut packet = vec![0; size];
        input.read_exact(&mut packet).await?;
        let bytes = cipher
            .decrypt_with_ad(&[], &packet)
            .map_err(io::Error::other)?;
        if early {
            pending.extend(bytes);
            if pending.len() < 9 {
                continue;
            }
            if &pending[..5] == b"\xff\xff\xffTS" {
                let size = u32::from_be_bytes(pending[5..9].try_into().unwrap()) as usize;
                if size > LIMIT {
                    return Err(bad("tailscale: early payload too large"));
                }
                if pending.len() < 9 + size {
                    continue;
                }
                serde_json::from_slice::<serde_json::Value>(&pending[9..9 + size])
                    .map_err(|_| bad("tailscale: invalid early payload"))?;
                pending.drain(..9 + size);
            }
            early = false;
            output.write_all(&pending).await?;
            pending.clear();
        } else {
            output.write_all(&bytes).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_failure_shape_retains_nulls_without_string_values() {
        let value = serde_json::json!({"Node":{"Key":"private-test-value", "Addresses":null}});
        let shape = map_shape(&value, 0);
        assert_eq!(shape["Node"]["Addresses"], serde_json::Value::Null);
        assert_eq!(shape["Node"]["Key"], "string");
        assert!(!shape.to_string().contains("private-test-value"));
    }

    #[tokio::test]
    async fn stream_preserves_fragmented_and_coalesced_frames() {
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (_, mut response) = connection.accept().await.unwrap().unwrap();
            let mut send = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            let first = br#"{"PeersRemoved":[42]}"#;
            let second = br#"{"KeepAlive":true}"#;
            let mut bytes = (first.len() as u32).to_le_bytes().to_vec();
            bytes.extend(first);
            bytes.extend_from_slice(&(second.len() as u32).to_le_bytes());
            bytes.extend(second);
            send.send_data(Bytes::copy_from_slice(&bytes[..2]), false)
                .unwrap();
            send.send_data(Bytes::copy_from_slice(&bytes[2..]), true)
                .unwrap();
            while connection.accept().await.is_some() {}
        });
        let (send, connection) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let mut send = send.ready().await.unwrap();
        let (response, _) = send
            .send_request(
                http::Request::builder()
                    .uri("https://example.com/machine/map")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let mut stream = MapStream {
            recv: response.await.unwrap().into_body(),
            pending: vec![],
        };
        assert_eq!(
            stream.next().await.unwrap().peers_removed.unwrap(),
            vec![42]
        );
        assert_eq!(stream.next().await.unwrap().keep_alive, Some(true));
        assert!(stream.next().await.is_err());
        task.abort();
        driver.abort();
    }

    #[tokio::test]
    async fn refresh_announces_home_derp_and_returns_full_snapshot() {
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/machine/map");
            let bytes = body(http::Response::new(request.into_body()))
                .await
                .unwrap();
            let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(value["Hostinfo"]["NetInfo"]["PreferredDERP"], 7);
            assert_eq!(
                value["Hostinfo"]["IPNVersion"],
                concat!("1.80.0-rustx", env!("CARGO_PKG_VERSION"))
            );
            assert_eq!(value["Stream"], false);
            let json = br#"{"Node":{"ID":1,"Key":"nodekey:test","Addresses":["100.64.0.1/32"]},"Peers":[]}"#;
            let mut frame = (json.len() as u32).to_le_bytes().to_vec();
            frame.extend(json);
            let mut stream = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            stream.send_data(Bytes::from(frame), true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let (send, connection) = h2::client::handshake(client).await.unwrap();
        let mut session = ControlSession {
            send,
            origin: "https://example.com".into(),
            _tasks: Tasks(vec![
                task,
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            ]),
        };
        let map = session
            .refresh_map("nodekey:test", "router", Some(7))
            .await
            .unwrap();
        assert_eq!(map.node.unwrap().addresses, ["100.64.0.1/32"]);
        assert!(map.peers.unwrap().is_empty());
    }

    #[test]
    fn control_origin_validation() {
        assert!(control_uri("https://controlplane.tailscale.com").is_ok());
        assert!(control_uri("https://headscale.example:8443/").is_ok());
        for url in [
            "http://example.com",
            "https://user@example.com",
            "https://example.com/path",
            "https://example.com/?token=secret",
        ] {
            assert!(control_uri(url).is_err());
        }
    }

    #[tokio::test]
    async fn stream_and_announcement_preserve_client_hostinfo() {
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            for streaming in [false, true] {
                let (request, mut response) = connection.accept().await.unwrap().unwrap();
                let bytes = body(http::Response::new(request.into_body()))
                    .await
                    .unwrap();
                let value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(value["Stream"], streaming);
                let info = &value["Hostinfo"];
                assert_eq!(
                    info["IPNVersion"],
                    concat!("1.80.0-rustx", env!("CARGO_PKG_VERSION"))
                );
                assert!(info.get("Distro").is_some());
                assert!(info.get("DistroVersion").is_some());
                assert_eq!(info["RoutableIPs"][0], "192.168.1.0/24");
                response
                    .send_response(http::Response::new(()), true)
                    .unwrap();
            }
            while connection.accept().await.is_some() {}
        });
        let (send, connection) = h2::client::handshake(client).await.unwrap();
        let mut session = ControlSession {
            send,
            origin: "https://example.com".into(),
            _tasks: Tasks(vec![
                task,
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
            ]),
        };
        session
            .map_stream_with_routes(
                "nodekey:test",
                "router",
                Some(7),
                [1; 32],
                &["192.168.1.0/24".into()],
            )
            .await
            .unwrap();
    }

    #[test]
    fn map_framing_and_assigned_addresses() {
        let json = br#"{"Node":{"ID":123,"Key":"nodekey:test","Addresses":["100.64.0.2/32"]}}"#;
        let mut frame = (json.len() as u32).to_le_bytes().to_vec();
        frame.extend(json);
        let map = decode_map(&frame).unwrap();
        assert_eq!(map.node.unwrap().addresses, ["100.64.0.2/32"]);
        assert!(decode_map(&frame[..frame.len() - 1]).is_err());
        assert!(decode_map(&[0; 3]).is_err());
    }

    #[test]
    fn health_map_without_assigned_addresses_is_valid_protocol() {
        let json = br#"{"Node":{"ID":123,"Key":"nodekey:test","Addresses":null,"AllowedIPs":null,"Endpoints":null},"Health":["device is not ready"]}"#;
        let mut frame = (json.len() as u32).to_le_bytes().to_vec();
        frame.extend_from_slice(json);
        let map = decode_map(&frame).unwrap();
        assert!(map.node.unwrap().addresses.is_empty());
    }

    #[test]
    fn discovers_noise_key_from_real_response_shape() {
        let bytes = [42; 32];
        let json = serde_json::json!({"legacyPublicKey": "mkey:invalid",
            "publicKey": format!("mkey:{}", super::super::control::to_hex(&bytes))});
        assert_eq!(
            parse_server_key(&serde_json::to_vec(&json).unwrap())
                .unwrap()
                .to_bytes(),
            bytes
        );
        assert!(parse_server_key(br#"{"legacyPublicKey":"mkey:00"}"#).is_err());
        assert!(parse_server_key(br#"{"publicKey":"mkey:0000000000000000000000000000000000000000000000000000000000000000"}"#).is_err());
    }

    #[test]
    fn transport_nonce_matches_controlbase() {
        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, aead::Aead};
        let key = [7; 32];
        let mut cipher = CipherState::new(Some(key)).into_transport();
        cipher.encrypt_with_ad(&[], b"first");
        let actual = cipher.encrypt_with_ad(&[], b"second");
        let mut nonce = [0; 12];
        nonce[11] = 1;
        let expected = ChaCha20Poly1305::new((&key).into())
            .encrypt((&nonce).into(), b"second".as_ref())
            .unwrap();
        assert_eq!(actual, expected);
    }

    #[tokio::test]
    async fn strips_fragmented_early_payload_and_preserves_h2() {
        let mut cipher = CipherState::new(Some([9; 32])).into_transport();
        let mut plaintext = b"\xff\xff\xffTS".to_vec();
        plaintext.extend_from_slice(&2u32.to_be_bytes());
        plaintext.extend_from_slice(b"{}HTTP2");
        let mut wire = Vec::new();
        for chunk in plaintext.chunks(4) {
            let packet = cipher.encrypt_with_ad(&[], chunk);
            wire.push(4);
            wire.extend_from_slice(&(packet.len() as u16).to_be_bytes());
            wire.extend(packet);
        }
        let (out, mut reader) = tokio::io::duplex(128);
        let task = tokio::spawn(async move {
            decrypt_records(
                wire.as_slice(),
                out,
                CipherState::new(Some([9; 32])).into_transport(),
            )
            .await
        });
        let mut result = Vec::new();
        reader.read_to_end(&mut result).await.unwrap();
        assert_eq!(result, b"HTTP2");
        assert!(task.await.unwrap().is_err()); // EOF closes the bridge.
    }

    #[tokio::test]
    async fn bad_record_is_rejected() {
        let (out, _) = tokio::io::duplex(128);
        let result = decrypt_records(
            &b"\x04\xff\xff"[..],
            out,
            CipherState::new(Some([1; 32])).into_transport(),
        )
        .await;
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn register_returns_authorization_url_over_h2() {
        let (client, server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server).await.unwrap();
            let (request, mut response) = connection.accept().await.unwrap().unwrap();
            assert_eq!(request.uri().path(), "/machine/register");
            let bytes = body(http::Response::new(request.into_body()))
                .await
                .unwrap();
            let request: RegisterRequest = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(request.version, CAPABILITY_VERSION);
            let mut stream = response
                .send_response(http::Response::new(()), false)
                .unwrap();
            stream.send_data(Bytes::from_static(b"{\"MachineAuthorized\":false,\"AuthURL\":\"https://login.tailscale.com/a/test\"}"), true).unwrap();
            while connection.accept().await.is_some() {}
        });
        let (send, connection) = h2::client::handshake(client).await.unwrap();
        let mut session = ControlSession {
            send,
            origin: "https://control.example".into(),
            _tasks: Tasks(vec![
                tokio::spawn(async move {
                    let _ = connection.await;
                }),
                task,
            ]),
        };
        let response = session
            .register(&RegisterRequest {
                version: CAPABILITY_VERSION,
                node_key: "nodekey:test".into(),
                auth: None,
                hostinfo: super::super::control::Hostinfo::new("test", &[]),
                ephemeral: false,
                followup: None,
            })
            .await
            .unwrap();
        assert_eq!(response.machine_authorized, Some(false));
        assert_eq!(
            response.auth_url.as_deref(),
            Some("https://login.tailscale.com/a/test")
        );
    }
}
