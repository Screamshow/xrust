//! Authenticated DERP v2 client over verified HTTPS. Inner packets remain
//! WireGuard encrypted; relay authentication uses the node's NaCl box key.
use super::derp::*;
use crypto_box::{PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey, aead::Aead};
use std::{io, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::{mpsc, watch},
    task::JoinHandle,
};
use x25519_dalek::{PublicKey, StaticSecret};

pub struct RelayPacket {
    pub source: [u8; 32],
    pub packet: Vec<u8>,
}
pub struct DerpClient {
    tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<RelayPacket>,
    tasks: Vec<JoinHandle<()>>,
    pong: watch::Receiver<Option<[u8; 8]>>,
}
impl Drop for DerpClient {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}
fn frame(kind: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![kind];
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn node_box(private: &StaticSecret, public: [u8; 32]) -> io::Result<SalsaBox> {
    if !private
        .diffie_hellman(&PublicKey::from(public))
        .was_contributory()
    {
        return Err(bad("derp: invalid server key"));
    }
    Ok(SalsaBox::new(
        &BoxPublicKey::from(public),
        &BoxSecretKey::from(private.to_bytes()),
    ))
}
fn seal(cipher: &SalsaBox, plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let mut nonce = [0; 24];
    getrandom::fill(&mut nonce).map_err(|_| io::Error::other("derp: entropy unavailable"))?;
    let encrypted = cipher
        .encrypt((&nonce).into(), plaintext)
        .map_err(|_| bad("derp: box encryption failed"))?;
    let mut out = nonce.to_vec();
    out.extend(encrypted);
    Ok(out)
}
fn open(cipher: &SalsaBox, payload: &[u8]) -> io::Result<Vec<u8>> {
    if payload.len() < 40 {
        return Err(bad("derp: truncated authentication box"));
    }
    cipher
        .decrypt(
            crypto_box::Nonce::from_slice(&payload[..24]),
            &payload[24..],
        )
        .map_err(|_| bad("derp: authentication failed"))
}

impl DerpClient {
    pub async fn connect(
        node: &DerpNode,
        private: StaticSecret,
        preferred: bool,
    ) -> io::Result<Self> {
        tokio::time::timeout(Duration::from_secs(20), async {
            let uri: http::Uri = format!(
                "https://{}:{}",
                node.host_name,
                if node.port == 0 { 443 } else { node.port }
            )
            .parse()
            .map_err(|_| bad("derp: invalid server name"))?;
            let mut stream = super::session::tls(&uri, b"http/1.1").await?;
            let request = format!(
                "GET /derp HTTP/1.1\r\nHost: {}\r\nConnection: Upgrade\r\nUpgrade: DERP\r\n\r\n",
                uri.authority().unwrap()
            );
            stream.write_all(request.as_bytes()).await?;
            let mut header = Vec::new();
            while !header.ends_with(b"\r\n\r\n") {
                if header.len() >= 16384 {
                    return Err(bad("derp: HTTP headers too large"));
                }
                header.push(stream.read_u8().await?);
            }
            let header =
                std::str::from_utf8(&header).map_err(|_| bad("derp: invalid upgrade headers"))?;
            if header
                .lines()
                .next()
                .and_then(|l| l.split_whitespace().nth(1))
                != Some("101")
                || !header.lines().any(|l| {
                    l.split_once(':').is_some_and(|(k, v)| {
                        k.eq_ignore_ascii_case("upgrade") && v.trim().eq_ignore_ascii_case("derp")
                    })
                })
            {
                return Err(bad("derp: HTTPS upgrade refused"));
            }
            Self::authenticate(stream, private, preferred).await
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "derp: connection timeout"))?
    }

    async fn authenticate<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(
        mut stream: S,
        private: StaticSecret,
        preferred: bool,
    ) -> io::Result<Self> {
        let greeting = read_derp_frame(&mut stream).await?;
        let DerpFrame::Other {
            frame_type: FRAME_SERVER_KEY,
            data,
        } = greeting
        else {
            return Err(bad("derp: missing server greeting"));
        };
        if data.len() < 40 || data.len() > 1024 || &data[..8] != DERP_MAGIC {
            return Err(bad("derp: invalid server greeting"));
        }
        let cipher = node_box(&private, data[8..40].try_into().unwrap())?;
        let info = seal(
            &cipher,
            br#"{"version":2,"CanAckPings":true,"AppName":"rust-x"}"#,
        )?;
        let public = PublicKey::from(&private).to_bytes();
        stream
            .write_all(&encode_client_info(&public, &info))
            .await?;
        let DerpFrame::ServerInfo(info) = read_derp_frame(&mut stream).await? else {
            return Err(bad("derp: missing server info"));
        };
        let info: serde_json::Value = serde_json::from_slice(&open(&cipher, &info)?)
            .map_err(|_| bad("derp: invalid server info"))?;
        if info.get("version").and_then(|v| v.as_u64()) != Some(2) {
            return Err(bad("derp: unsupported server version"));
        }
        stream.write_all(&encode_note_preferred(preferred)).await?;
        let (mut read, mut write) = tokio::io::split(stream);
        let (tx, mut outbound) = mpsc::channel::<Vec<u8>>(64);
        let (to_client, rx) = mpsc::channel::<RelayPacket>(64);
        let control = tx.clone();
        let (pong_tx, pong) = watch::channel(None);
        let (writer_stopped, mut writer_status) = tokio::sync::oneshot::channel::<()>();
        let reader = tokio::spawn(async move {
            loop {
                let message = tokio::select! {
                    result = tokio::time::timeout(Duration::from_secs(120), read_derp_frame(&mut read)) => {
                        match result { Ok(Ok(message)) => message, _ => break }
                    }
                    _ = &mut writer_status => break,
                };
                match message {
                    DerpFrame::RecvPacket { src_key, data } => {
                        if to_client
                            .try_send(RelayPacket {
                                source: src_key,
                                packet: data,
                            })
                            .is_err()
                            && to_client.is_closed()
                        {
                            break;
                        }
                    }
                    DerpFrame::Other {
                        frame_type: FRAME_PONG,
                        data,
                    } if data.len() == 8 => {
                        pong_tx.send_replace(Some(data[..].try_into().unwrap()));
                    }
                    DerpFrame::Other {
                        frame_type: FRAME_PING,
                        data,
                    } if data.len() == 8 => {
                        if control.try_send(frame(FRAME_PONG, &data)).is_err() {
                            break;
                        }
                    }
                    DerpFrame::Other {
                        frame_type: 0x14,
                        data,
                    } if !data.is_empty() => break,
                    DerpFrame::Other {
                        frame_type: 0x15, ..
                    } => break,
                    _ => {}
                }
            }
        });
        let writer = tokio::spawn(async move {
            while let Some(packet) = outbound.recv().await {
                if !matches!(
                    tokio::time::timeout(Duration::from_secs(10), write.write_all(&packet)).await,
                    Ok(Ok(()))
                ) {
                    break;
                }
            }
            let _ = writer_stopped.send(());
        });
        Ok(Self {
            tx,
            rx,
            tasks: vec![reader, writer],
            pong,
        })
    }

    pub async fn ping(&self) -> io::Result<Duration> {
        ping_channel(self.tx.clone(), self.pong.clone(), Duration::ZERO).await
    }
    pub fn send(&self, destination: [u8; 32], packet: &[u8]) -> io::Result<()> {
        if self.rx.is_closed() {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "derp: connection closed",
            ));
        }
        if packet.len() > 65536 {
            return Err(bad("derp: packet too large"));
        }
        self.tx
            .try_send(encode_send_packet(&destination, packet))
            .map_err(|e| {
                io::Error::new(
                    if self.tx.is_closed() {
                        io::ErrorKind::BrokenPipe
                    } else {
                        io::ErrorKind::WouldBlock
                    },
                    e.to_string(),
                )
            })
    }
}

async fn ping_channel(
    tx: mpsc::Sender<Vec<u8>>,
    mut pong: watch::Receiver<Option<[u8; 8]>>,
    delay: Duration,
) -> io::Result<Duration> {
    tokio::time::sleep(delay).await;
    let mut token = [0; 8];
    getrandom::fill(&mut token).map_err(|_| bad("derp: entropy unavailable"))?;
    pong.borrow_and_update();
    let start = std::time::Instant::now();
    tx.try_send(frame(FRAME_PING, &token))
        .map_err(|_| io::Error::other("derp: ping queue unavailable"))?;
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            pong.changed()
                .await
                .map_err(|_| io::Error::other("derp: ping connection closed"))?;
            if *pong.borrow_and_update() == Some(token) {
                return Ok(start.elapsed());
            }
        }
    })
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "derp: ping timed out"))?
}
#[derive(Clone, Copy)]
pub struct RelayHealth {
    pub region: u16,
    pub latency_ms: Option<u64>,
}
struct RegionTask {
    tx: mpsc::Sender<([u8; 32], Vec<u8>)>,
    task: JoinHandle<()>,
    preferred: watch::Sender<bool>,
    last_used: std::time::Instant,
}
impl Drop for RegionTask {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// Nonblocking region connections. Reconnection happens off the stack task.
pub struct RelayManager {
    pub notify: std::sync::Arc<tokio::sync::Notify>,
    private: StaticSecret,
    map: DerpMap,
    home: Option<u16>,
    regions: std::collections::HashMap<u16, RegionTask>,
    to_mesh: mpsc::Sender<(u16, RelayPacket)>,
    pub rx: mpsc::Receiver<(u16, RelayPacket)>,
    health_tx: mpsc::Sender<RelayHealth>,
    pub health_rx: mpsc::Receiver<RelayHealth>,
}

impl RelayManager {
    pub fn set_home(&mut self, home: Option<u16>) {
        if self.home == home {
            return;
        }
        for (id, task) in &self.regions {
            task.preferred.send_replace(home == Some(*id));
        }
        self.home = home;
        if let Some(home) = home {
            self.ensure(home);
        }
    }
    pub fn update_map(&mut self, map: DerpMap) {
        self.regions.retain(|id, _| {
            let old = self.map.regions.get(&id.to_string());
            let new = map.regions.get(&id.to_string());
            matches!((old, new), (Some(old), Some(new)) if serde_json::to_vec(old).ok() == serde_json::to_vec(new).ok())
        });
        self.map = map;
        if let Some(home) = self.home {
            self.ensure(home);
        }
    }
    pub fn new(private: StaticSecret, map: DerpMap, home: Option<u16>) -> Self {
        let (to_mesh, rx) = mpsc::channel(256);
        let (health_tx, health_rx) = mpsc::channel(64);
        let mut manager = Self {
            notify: std::sync::Arc::new(tokio::sync::Notify::new()),
            private,
            map,
            home,
            regions: Default::default(),
            to_mesh,
            rx,
            health_tx,
            health_rx,
        };
        if let Some(home) = home {
            manager.ensure(home);
        }
        manager
    }
    fn ensure(&mut self, region: u16) {
        if self.regions.contains_key(&region) {
            return;
        }
        if self.regions.len() >= 8 {
            if let Some(evict) = self
                .regions
                .iter()
                .filter(|(id, _)| Some(**id) != self.home)
                .min_by_key(|(_, task)| task.last_used)
                .map(|(id, _)| *id)
            {
                self.regions.remove(&evict);
            } else {
                return;
            }
        }
        let Some(nodes) = self.map.regions.get(&region.to_string()).map(|r| {
            r.nodes
                .iter()
                .filter(|n| !n.stun_only)
                .cloned()
                .collect::<Vec<_>>()
        }) else {
            return;
        };
        if nodes.is_empty() {
            return;
        }
        let private = self.private.clone();
        let to_mesh = self.to_mesh.clone();
        let notify = self.notify.clone();
        let preferred = self.home == Some(region);
        let (preferred_tx, mut preferred_rx) = watch::channel(preferred);
        let health_tx = self.health_tx.clone();
        let (tx, mut outbound) = mpsc::channel::<([u8; 32], Vec<u8>)>(64);
        let task = tokio::spawn(async move {
            let mut backoff = 1u64;
            loop {
                if outbound.is_closed() || to_mesh.is_closed() {
                    break;
                }
                let preferred = *preferred_rx.borrow_and_update();
                let mut connected = None;
                for node in nodes.iter().take(3) {
                    match DerpClient::connect(node, private.clone(), preferred).await {
                        Ok(client) => {
                            connected = Some(client);
                            break;
                        }
                        Err(error) => crate::logging::debug(format_args!(
                            "tailscale: DERP region {} connection error: {}",
                            region, error
                        )),
                    }
                }
                if let Some(mut client) = connected {
                    crate::logging::debug(format_args!(
                        "tailscale: DERP region {} connected",
                        region
                    ));
                    let connected_at = std::time::Instant::now();
                    let _ = client.tx.try_send(
                        encode_note_preferred(*preferred_rx.borrow_and_update()).to_vec(),
                    );
                    let mut health = Box::pin(ping_channel(
                        client.tx.clone(),
                        client.pong.clone(),
                        Duration::ZERO,
                    ));
                    loop {
                        tokio::select! {
                            result=preferred_rx.changed()=>{
                                if result.is_err(){return;}
                                if client.tx.try_send(encode_note_preferred(*preferred_rx.borrow_and_update()).to_vec()).is_err(){break;}
                            }
                            result=&mut health=>{
                                match result {
                                    Ok(rtt)=>{let _=health_tx.try_send(RelayHealth{region,latency_ms:Some(rtt.as_millis().max(1) as u64)});},
                                    Err(_)=>break,
                                }
                                health=Box::pin(ping_channel(client.tx.clone(),client.pong.clone(),Duration::from_secs(30)));
                            }
                            packet = outbound.recv() => {
                                let Some((destination, packet)) = packet else { return; };
                                if let Err(error) = client.send(destination, &packet)
                                    && error.kind() != io::ErrorKind::WouldBlock {
                                    break;
                                }
                            }
                            packet = client.rx.recv() => {
                                let Some(packet) = packet else { break; };
                                if to_mesh.try_send((region, packet)).is_ok() {notify.notify_one();}
                            }
                        }
                    }
                    // Only a connection that stayed up resets the backoff; a
                    // server that accepts and drops at once is not retried
                    // every second.
                    if connected_at.elapsed() >= Duration::from_secs(30) {
                        backoff = 1;
                    }
                }
                let _ = health_tx.try_send(RelayHealth {
                    region,
                    latency_ms: None,
                });
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(30);
            }
        });
        self.regions.insert(
            region,
            RegionTask {
                tx,
                task,
                preferred: preferred_tx,
                last_used: std::time::Instant::now(),
            },
        );
    }
    pub fn prepare(&mut self, region: u16) {
        self.ensure(region);
    }
    pub fn send(&mut self, region: u16, destination: [u8; 32], packet: &[u8]) {
        self.ensure(region);
        if let Some(task) = self.regions.get_mut(&region) {
            task.last_used = std::time::Instant::now();
            let _ = task.tx.try_send((destination, packet.to_vec()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn home_change_preserves_existing_region_connections() {
        let map = DerpMap::default();
        let mut manager = RelayManager::new(StaticSecret::from([9; 32]), map, None);
        let (tx, _) = mpsc::channel(1);
        let (preferred, _) = watch::channel(false);
        manager.regions.insert(
            1,
            RegionTask {
                tx,
                preferred,
                task: tokio::spawn(std::future::pending()),
                last_used: std::time::Instant::now(),
            },
        );
        manager.set_home(Some(1));
        assert!(*manager.regions[&1].preferred.borrow());
        manager.set_home(Some(22));
        assert_eq!(manager.home, Some(22));
        assert!(manager.regions.contains_key(&1));
        assert!(!*manager.regions[&1].preferred.borrow());
        assert!(!manager.regions[&1].task.is_finished());
    }

    #[tokio::test]
    async fn ping_requires_its_own_token_and_ignores_an_unrelated_pong() {
        let (tx, mut packets) = mpsc::channel::<Vec<u8>>(4);
        let (pongs, pong) = watch::channel(None);
        let server = tokio::spawn(async move {
            let packet = packets.recv().await.unwrap();
            assert_eq!(packet[0], FRAME_PING);
            pongs.send_replace(Some([0; 8]));
            tokio::task::yield_now().await;
            pongs.send_replace(Some(packet[5..13].try_into().unwrap()));
        });
        assert!(ping_channel(tx, pong, Duration::ZERO).await.is_ok());
        server.await.unwrap();
    }

    #[test]
    fn nacl_box_rejects_tampering_and_low_order_keys() {
        let left = StaticSecret::from([10; 32]);
        let right = StaticSecret::from([11; 32]);
        let left_box = node_box(&left, PublicKey::from(&right).to_bytes()).unwrap();
        let right_box = node_box(&right, PublicKey::from(&left).to_bytes()).unwrap();
        let mut boxed = seal(&left_box, b"test info").unwrap();
        assert_eq!(open(&right_box, &boxed).unwrap(), b"test info");
        boxed[24] ^= 1;
        assert!(open(&right_box, &boxed).is_err());
        assert!(open(&right_box, &[0; 24]).is_err());
        assert!(node_box(&left, [0; 32]).is_err());
    }

    #[tokio::test]
    async fn authenticated_client_answers_ping_and_receives_packet() {
        let (client, mut server) = tokio::io::duplex(8192);
        let task = tokio::spawn(async move {
            let private = StaticSecret::from([42; 32]);
            let mut greeting = DERP_MAGIC.to_vec();
            greeting.extend_from_slice(PublicKey::from(&private).as_bytes());
            server
                .write_all(&frame(FRAME_SERVER_KEY, &greeting))
                .await
                .unwrap();
            let DerpFrame::Other {
                frame_type: FRAME_CLIENT_INFO,
                data,
            } = read_derp_frame(&mut server).await.unwrap()
            else {
                panic!("client info required");
            };
            let public = data[..32].try_into().unwrap();
            let cipher = node_box(&private, public).unwrap();
            let info: serde_json::Value =
                serde_json::from_slice(&open(&cipher, &data[32..]).unwrap()).unwrap();
            assert_eq!(info["version"], 2);
            assert_eq!(info["CanAckPings"], true);
            server
                .write_all(&frame(
                    FRAME_SERVER_INFO,
                    &seal(&cipher, br#"{"version":2}"#).unwrap(),
                ))
                .await
                .unwrap();
            assert!(matches!(
                read_derp_frame(&mut server).await.unwrap(),
                DerpFrame::Other {
                    frame_type: FRAME_NOTE_PREFERRED,
                    ..
                }
            ));
            server
                .write_all(&frame(FRAME_PING, b"12345678"))
                .await
                .unwrap();
            let mut received = false;
            let mut pong = false;
            while !received || !pong {
                match read_derp_frame(&mut server).await.unwrap() {
                    DerpFrame::Other {
                        frame_type: FRAME_PONG,
                        data,
                    } => {
                        assert_eq!(data, b"12345678");
                        pong = true;
                    }
                    DerpFrame::Other {
                        frame_type: FRAME_SEND_PACKET,
                        data,
                    } => {
                        assert_eq!(&data[..32], &[9; 32]);
                        assert_eq!(&data[32..], b"WG ciphertext");
                        received = true;
                    }
                    _ => panic!("unexpected client frame"),
                }
            }
            let mut packet = vec![9; 32];
            packet.extend_from_slice(b"WG reply");
            server
                .write_all(&frame(FRAME_RECV_PACKET, &packet))
                .await
                .unwrap();
        });
        let mut client = DerpClient::authenticate(client, StaticSecret::from([5; 32]), true)
            .await
            .unwrap();
        client.send([9; 32], b"WG ciphertext").unwrap();
        let packet = tokio::time::timeout(Duration::from_secs(2), client.rx.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(packet.source, [9; 32]);
        assert_eq!(packet.packet, b"WG reply");
        task.await.unwrap();
    }

    #[tokio::test]
    async fn false_greeting_is_rejected() {
        let (client, mut server) = tokio::io::duplex(128);
        server
            .write_all(&frame(FRAME_SERVER_KEY, &[0; 40]))
            .await
            .unwrap();
        assert!(
            DerpClient::authenticate(client, StaticSecret::from([5; 32]), false)
                .await
                .is_err()
        );
    }
}
