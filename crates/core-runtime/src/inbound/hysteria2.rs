//! Hysteria2 server inbound: accepts QUIC connections with HTTP/3 auth (status 233),
//! forwards TCP streams (FRAME_TCP_REQUEST 0x401), and handles UDP datagrams
//! with reassembly and response routing.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicU32;
use std::time::Duration;

use serde_json::Value;

use super::tls::ServerTls;
use super::udp::{DatagramFrame, Hy2Reply, Reply, UdpHub};
use crate::inbound::{AnyStream, ClientConn, Target, drive_framed, parse_listen};
use crate::logging;
use crate::outbound::hysteria2::{
    AUTH_STATUS_OK, FRAME_TCP_REQUEST, MAX_ADDRESS, MAX_PADDING, parse_hy2_packet,
    read_bounded_length, read_exact_vec, read_varint_stream, send_hy2_datagram,
};
use crate::outbound::quic::{Defragger, QuicStream, SalamanderSocket};
use crate::route::Router;

const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);

pub struct Hysteria2 {
    tag: String,
    router: Arc<Router>,
    endpoint: quinn::Endpoint,
    users: Arc<HashMap<String, String>>, // password -> username
    hub: Arc<UdpHub>,
    local_addr: SocketAddr,
}

impl Hysteria2 {
    pub async fn bind(obj: &Value, router: Arc<Router>) -> anyhow::Result<Self> {
        let at = "inbounds[hysteria2]";
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();

        let map = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let (ip, port) = parse_listen(map, at)?;
        let addr = SocketAddr::new(ip, port);

        let mut users = HashMap::new();
        if let Some(list) = obj.get("users").and_then(Value::as_array) {
            for (i, u) in list.iter().enumerate() {
                let password = u
                    .get("password")
                    .and_then(Value::as_str)
                    .ok_or_else(|| anyhow::anyhow!("{at}.users[{i}]: missing password"))?
                    .to_string();
                let name = u
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                users.insert(password, if name.is_empty() { i.to_string() } else { name });
            }
        } else if let Some(pw) = obj.get("password").and_then(Value::as_str) {
            users.insert(pw.to_string(), "default".to_string());
        } else {
            anyhow::bail!("{at}: missing users or password");
        }

        let obfs_password = match obj.get("obfs") {
            None | Some(Value::Null) => None,
            Some(Value::Object(m)) => {
                let ty = m.get("type").and_then(Value::as_str).unwrap_or("");
                match ty {
                    "salamander" => {
                        let pw = m.get("password").and_then(Value::as_str).unwrap_or("");
                        if pw.is_empty() {
                            anyhow::bail!("{at}: missing obfs password");
                        }
                        Some(pw.as_bytes().to_vec())
                    }
                    other => anyhow::bail!("{at}: unsupported obfs type: {other}"),
                }
            }
            Some(_) => anyhow::bail!("{at}: obfs must be an object"),
        };

        let tls_obj = obj
            .get("tls")
            .ok_or_else(|| anyhow::anyhow!("{at}: tls is required for hysteria2"))?;
        let server_config = ServerTls::build_quic_server_config(tls_obj, &[b"h3"], at)?;

        let runtime =
            quinn::default_runtime().ok_or_else(|| anyhow::anyhow!("{at}: no quinn runtime"))?;

        let socket = std::net::UdpSocket::bind(addr)?;
        let ep_config =
            quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[9u8; 32])));
        let endpoint = if let Some(password) = obfs_password {
            let socket = SalamanderSocket::listen(&*runtime, socket, password)?;
            quinn::Endpoint::new_with_abstract_socket(
                ep_config,
                Some(server_config),
                Arc::new(socket),
                runtime,
            )?
        } else {
            quinn::Endpoint::new(ep_config, Some(server_config), socket, runtime)?
        };
        let local_addr = endpoint.local_addr()?;

        let hub = UdpHub::new(Arc::clone(&router), DEFAULT_UDP_TIMEOUT, DatagramFrame::Raw);

        Ok(Self {
            tag,
            router,
            endpoint,
            users: Arc::new(users),
            hub,
            local_addr,
        })
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    pub async fn serve(self) {
        let tag = self.tag.clone();
        logging::info(format_args!(
            "hysteria2[{tag}] listening on {}",
            self.local_addr
        ));

        let mut next_connection_id = 0_u64;
        while let Some(incoming) = self.endpoint.accept().await {
            let connection_id = next_connection_id;
            next_connection_id = next_connection_id.wrapping_add(1);
            let router = Arc::clone(&self.router);
            let users = Arc::clone(&self.users);
            let hub = Arc::clone(&self.hub);
            let tag = self.tag.clone();
            let local_addr = self.local_addr;

            tokio::spawn(async move {
                let conn = match incoming.await {
                    Ok(c) => c,
                    Err(e) => {
                        logging::debug(format_args!("hysteria2[{tag}] handshake failed: {e}"));
                        return;
                    }
                };
                handle_hy2_connection(conn, connection_id, router, users, hub, tag, local_addr)
                    .await;
            });
        }
    }
}

async fn handle_hy2_connection(
    conn: quinn::Connection,
    connection_id: u64,
    router: Arc<Router>,
    users: Arc<HashMap<String, String>>,
    hub: Arc<UdpHub>,
    tag: String,
    local_addr: SocketAddr,
) {
    let peer = conn.remote_address();

    // Authenticate via HTTP/3 session
    let (user_name, h3_driver) =
        match tokio::time::timeout(DEFAULT_AUTH_TIMEOUT, authenticate_hy2(&conn, &users)).await {
            Ok(Ok(name)) => name,
            Ok(Err(e)) => {
                logging::debug(format_args!("hysteria2[{tag}] {peer} auth failed: {e}"));
                conn.close(quinn::VarInt::from_u32(0), b"auth failed");
                return;
            }
            Err(_) => {
                logging::debug(format_args!("hysteria2[{tag}] {peer} auth timed out"));
                conn.close(quinn::VarInt::from_u32(0), b"auth timeout");
                return;
            }
        };

    logging::info(format_args!(
        "hysteria2[{tag}] {peer} authenticated as {user_name}"
    ));

    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::channel::<Hy2Reply>(128);

    // UDP reply sender back to QUIC datagrams
    let conn_udp_send = conn.clone();
    let reply_handle = tokio::spawn(async move {
        let packet_counter = AtomicU32::new(0);
        while let Some(reply) = reply_rx.recv().await {
            let _ = send_hy2_datagram(
                &conn_udp_send,
                reply.session_id,
                &reply.src,
                &reply.payload,
                &packet_counter,
            );
        }
    });

    // Accept bidirectional streams (TCP requests)
    let conn_bi = conn.clone();
    let router_bi = Arc::clone(&router);
    let tag_bi = tag.clone();
    let user_bi = user_name.clone();
    let bi_handle = tokio::spawn(async move {
        loop {
            let (send, mut recv) = match conn_bi.accept_bi().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let router = Arc::clone(&router_bi);
            let tag = tag_bi.clone();
            let _user = user_bi.clone();
            tokio::spawn(async move {
                let frame_type = match read_varint_stream(&mut recv).await {
                    Ok(v) => v,
                    Err(_) => return,
                };
                if frame_type != FRAME_TCP_REQUEST {
                    return;
                }
                let dest_len = match read_bounded_length(&mut recv, MAX_ADDRESS, "address").await {
                    Ok(len) if len > 0 => len,
                    _ => return,
                };
                let dest_bytes = match read_exact_vec(&mut recv, dest_len).await {
                    Ok(b) => b,
                    Err(_) => return,
                };
                let dest_str = match std::str::from_utf8(&dest_bytes) {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let pad_len = match read_bounded_length(&mut recv, MAX_PADDING, "padding").await {
                    Ok(len) => len,
                    Err(_) => return,
                };
                let _pad = match read_exact_vec(&mut recv, pad_len).await {
                    Ok(p) => p,
                    Err(_) => return,
                };

                let target = match parse_target_str(dest_str) {
                    Some(t) => t,
                    None => return,
                };

                // Send TCP response: status 0, msg_len 0, pad_len 0
                let mut send = send;
                let resp = [0u8, 0, 0];
                if send.write_all(&resp).await.is_err() {
                    return;
                }

                let stream: AnyStream = Box::new(QuicStream::new(send, recv));
                let client = ClientConn::framed(stream, local_addr);
                let _ = drive_framed(client, peer, target, &tag, &router).await;
            });
        }
    });

    // Accept datagrams (UDP)
    let conn_dg = conn.clone();
    let hub_dg = Arc::clone(&hub);
    let tag_dg = tag.clone();
    let dg_handle = tokio::spawn(async move {
        let mut defragger = Defragger::new();
        loop {
            let data = match conn_dg.read_datagram().await {
                Ok(d) => d,
                Err(_) => break,
            };
            let Some((session_id, pid, frag_id, frag_total, dest, payload)) =
                parse_hy2_packet(&data)
            else {
                continue;
            };
            let complete = defragger.feed(
                (session_id, pid),
                frag_id,
                frag_total,
                bytes::Bytes::copy_from_slice(payload),
            );
            if let Some(pkt) = complete {
                let target = match parse_target_str(dest) {
                    Some(t) => t,
                    None => continue,
                };
                let dest_addr = match &target {
                    Target::Ip(a) => *a,
                    // Raw HY2 replies and flow keys carry the full named destination.
                    // Only socket-based inbounds need a concrete IP for framing.
                    Target::Domain(_, port) => SocketAddr::from(([0, 0, 0, 0], *port)),
                };
                let _ = hub_dg
                    .handle_routed(
                        Reply::Hy2 {
                            connection_id,
                            session_id,
                            destination: Arc::from(dest),
                            sender: reply_tx.clone(),
                        },
                        peer,
                        dest_addr,
                        &pkt,
                        &tag_dg,
                        &target,
                    )
                    .await;
            }
        }
    });

    // Wait until connection closes
    let _ = conn.closed().await;
    drop(h3_driver);
    bi_handle.abort();
    dg_handle.abort();
    reply_handle.abort();
    logging::info(format_args!("hysteria2[{tag}] {peer} disconnected"));
}

async fn authenticate_hy2(
    conn: &quinn::Connection,
    users: &HashMap<String, String>,
) -> io::Result<(
    String,
    h3::server::Connection<h3_quinn::Connection, bytes::Bytes>,
)> {
    let h3 = h3_quinn::Connection::new(conn.clone());
    let mut h3_conn: h3::server::Connection<_, bytes::Bytes> = h3::server::builder()
        .build(h3)
        .await
        .map_err(|e| io::Error::other(format!("h3 handshake failed: {e}")))?;

    let resolver = h3_conn
        .accept()
        .await
        .map_err(io::Error::other)?
        .ok_or_else(|| io::Error::other("no request on h3"))?;

    let (request, mut stream) = resolver.resolve_request().await.map_err(io::Error::other)?;
    let auth_header = request
        .headers()
        .get("Hysteria-Auth")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    while let Some(_chunk) = stream.recv_data().await.map_err(io::Error::other)? {}

    let user_name = if let Some(name) = users.get(auth_header) {
        name.clone()
    } else {
        let resp = http::Response::builder()
            .status(401)
            .body(())
            .map_err(io::Error::other)?;
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return Err(io::Error::other("invalid hysteria2 auth"));
    };

    let response = http::Response::builder()
        .status(AUTH_STATUS_OK)
        .header("Hysteria-UDP", "true")
        .body(())
        .map_err(io::Error::other)?;

    stream
        .send_response(response)
        .await
        .map_err(io::Error::other)?;
    stream.finish().await.map_err(io::Error::other)?;

    // In Hysteria 2, HTTP/3 is only used for the initial handshake; proxy data is sent
    // over raw QUIC bi-streams and datagrams. If `h3_conn` is dropped, its Drop impl sends
    // an ApplicationClose (H3_NO_ERROR) frame over the entire QUIC connection.
    // The session owns the driver until the transport has closed.
    Ok((user_name, h3_conn))
}

fn parse_target_str(s: &str) -> Option<Target> {
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Some(Target::Ip(addr));
    }
    let (host, port_str) = s.rsplit_once(':')?;
    let port = port_str.parse::<u16>().ok()?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Some(Target::Ip(SocketAddr::new(ip, port)))
    } else {
        Some(Target::Domain(host.to_string(), port))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::Mutex;

    static TEST_MUTEX: Mutex<()> = Mutex::const_new(());

    const CERT_PEM: &str = include_str!("../../../../tests/golden/certs/localhost.crt");
    const KEY_PEM: &str = include_str!("../../../../tests/golden/certs/localhost.key");

    #[tokio::test]
    async fn test_hysteria2_server_inbound_flow() {
        let _guard = TEST_MUTEX.lock().await;

        let cfg = serde_json::json!({
            "type": "hysteria2",
            "tag": "hy2-test",
            "listen": "127.0.0.1",
            "listen_port": 0,
            "users": [
                {
                    "name": "alice",
                    "password": "secret_password"
                }
            ],
            "tls": {
                "enabled": true,
                "certificate": CERT_PEM,
                "key": KEY_PEM
            }
        });

        // Target TCP echo server
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            if let Ok((mut s, _)) = listener.accept().await {
                let mut buf = [0u8; 64];
                if let Ok(n) = s.read(&mut buf).await {
                    let _ = s.write_all(&buf[..n]).await;
                }
            }
        });

        let router = Router::new(&serde_json::json!({
            "outbounds": [{ "type": "direct", "tag": "direct" }],
            "route": {"rules": [
                {"domain": "hy2-target.invalid", "outbound": "direct", "override_address": "127.0.0.1"},
                {"network": "udp", "action": "reject"}
            ]}
        }))
        .unwrap();

        let server = Hysteria2::bind(&cfg, router).await.unwrap();
        let srv_addr = server.local_addr().unwrap();
        tokio::spawn(server.serve());

        // Now connect using Hysteria2 outbound client!
        let client_cfg = serde_json::json!({
            "type": "hysteria2",
            "tag": "hy2-out",
            "server": "127.0.0.1",
            "server_port": srv_addr.port(),
            "password": "secret_password",
            "tls": {
                "enabled": true,
                "insecure": true,
                "server_name": "localhost"
            }
        });

        let map = client_cfg.as_object().unwrap();
        let client = crate::outbound::hysteria2::Hysteria2::build(map, "outbounds[0]").unwrap();

        let target = Target::Ip(target_addr);
        let mut stream = client.connect(&target).await.unwrap();

        stream.write_all(b"hello hy2").await.unwrap();
        let mut buf = [0u8; 64];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello hy2");

        // The first rule permits the hostname. Losing it before routing
        // would hit the following UDP rejection even for this local endpoint.
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = Target::Domain(
            "hy2-target.invalid".to_owned(),
            receiver.local_addr().unwrap().port(),
        );
        let sender = client.connect_udp(&target).await.unwrap();
        sender.send(b"named datagram").await.unwrap();
        let (n, peer) = tokio::time::timeout(Duration::from_secs(3), receiver.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"named datagram");
        receiver.send_to(b"named reply", peer).await.unwrap();
        let n = tokio::time::timeout(Duration::from_secs(3), sender.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"named reply");
    }
}
