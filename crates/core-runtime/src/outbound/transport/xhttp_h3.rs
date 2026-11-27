//! Native HTTP/3 client for XHTTP. HTTP request construction and the XHTTP
//! upload/download session identifiers belong to the common transport.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::task::{Context, Poll, ready};
use std::time::Duration;

use bytes::{Buf, Bytes};
use core_config::xhttp_quic::{Congestion, Params};
use portable_atomic::AtomicU64;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::Notify;

use super::{xhttp_gzip, xmux};
use crate::inbound::AnyStream;
use crate::outbound::dial::{DialOptions, connect_udp, resolve_with};
use crate::outbound::quic::{
    CongestionKind, QuicTunnelOptions, quic_go_client_shape, xhttp_brutal_controller,
};
use crate::tls_client::TlsOptions;

type Sender = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ReceiveBody = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

const CHUNK: usize = 8 * 1024;
const IDLE_TIMEOUT: Duration = Duration::from_secs(300);

pub(crate) fn selected(tls: Option<&TlsOptions>) -> bool {
    tls.is_some_and(|tls| tls.reality().is_none() && matches!(tls.alpn(), [alpn] if alpn == b"h3"))
}

fn protocol_error(operation: &str, err: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("xhttp: h3 {operation}: {err}"))
}

pub(crate) struct Pool {
    xmux: Arc<xmux::Pool>,
    shared: Arc<PoolShared>,
    params: Params,
}

#[derive(Default)]
struct PoolState {
    clients: Vec<Arc<Client>>,
    dialing: usize,
}

#[derive(Default)]
struct PoolShared {
    state: Mutex<PoolState>,
    changed: Notify,
}

/// Cancelled or failed dials release their slot without waiting for a lock
/// held across network I/O.
struct DialReservation<'a>(&'a PoolShared);

impl Drop for DialReservation<'_> {
    fn drop(&mut self) {
        self.0.state.lock().expect("xhttp H3 pool").dialing -= 1;
        self.0.changed.notify_waiters();
    }
}

impl Pool {
    pub(crate) fn new(xmux: Arc<xmux::Pool>, params: Params) -> Self {
        Self {
            xmux,
            shared: Arc::new(PoolShared::default()),
            params,
        }
    }

    pub(crate) async fn acquire(
        &self,
        tls: &TlsOptions,
        server: &str,
        port: u16,
        dial: &DialOptions,
    ) -> io::Result<Lease> {
        loop {
            let changed = self.shared.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if let Some(reservation) = self.reserve() {
                match reservation {
                    Reservation::Ready(lease) => return Ok(lease),
                    Reservation::Dial(_slot) => {
                        let client = self.dial(tls, server, port, dial).await?;
                        let lease = Lease::new(client.clone())
                            .ok_or_else(|| protocol_error("pool", "connection already idle"))?;
                        self.shared
                            .state
                            .lock()
                            .expect("xhttp H3 pool")
                            .clients
                            .push(client);
                        return Ok(lease);
                    }
                }
            }
            changed.await;
        }
    }

    fn reserve(&self) -> Option<Reservation<'_>> {
        let mut state = self.shared.state.lock().expect("xhttp H3 pool");
        state.clients.retain(|client| client.can_reuse());
        let concurrency = self.xmux.max_concurrency();
        let has_dial_slot = state.clients.len() + state.dialing < self.xmux.max_connections();
        if concurrency > 0 || !has_dial_slot {
            let eligible: Vec<_> = state
                .clients
                .iter()
                .filter(|client| concurrency == 0 || client.activity.running() < concurrency)
                .collect();
            if !eligible.is_empty()
                && let Some(lease) = Lease::new(eligible[xmux::pick(eligible.len())].clone())
            {
                return Some(Reservation::Ready(lease));
            }
        }
        if has_dial_slot {
            state.dialing += 1;
            return Some(Reservation::Dial(DialReservation(&self.shared)));
        }
        None
    }

    async fn dial(
        &self,
        tls: &TlsOptions,
        server: &str,
        port: u16,
        dial: &DialOptions,
    ) -> io::Result<Arc<Client>> {
        let addresses = resolve_with(server, port, dial.domain_strategy).await?;
        let mut last = None;
        for address in addresses {
            match Client::connect(
                tls,
                server,
                address,
                dial,
                &self.xmux,
                Arc::downgrade(&self.shared),
                self.params,
            )
            .await
            {
                Ok(client) => return Ok(Arc::new(client)),
                Err(err) => last = Some(err),
            }
        }
        Err(last.unwrap_or_else(|| protocol_error("resolve", "no server address")))
    }
}

enum Reservation<'a> {
    Ready(Lease),
    Dial(DialReservation<'a>),
}

struct Activity {
    state: Mutex<ActivityState>,
    changed: Notify,
}

struct ActivityState {
    running: usize,
    idle_since: tokio::time::Instant,
    expired: bool,
}

impl Activity {
    fn new() -> Self {
        Self {
            state: Mutex::new(ActivityState {
                running: 0,
                idle_since: tokio::time::Instant::now(),
                expired: false,
            }),
            changed: Notify::new(),
        }
    }

    fn running(&self) -> usize {
        self.state.lock().expect("xhttp H3 activity").running
    }

    fn expired(&self) -> bool {
        self.state.lock().expect("xhttp H3 activity").expired
    }

    fn acquire(&self) -> bool {
        let mut state = self.state.lock().expect("xhttp H3 activity");
        if state.expired {
            return false;
        }
        state.running += 1;
        if state.running == 1 {
            self.changed.notify_one();
        }
        true
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("xhttp H3 activity");
        state.running -= 1;
        if state.running == 0 {
            state.idle_since = tokio::time::Instant::now();
            self.changed.notify_one();
        }
    }

    /// A QUIC PING can keep the wire connection active even when no tunnel
    /// is using it. Base pool retirement on actual tunnel activity.
    async fn wait_idle(&self) {
        loop {
            let changed = self.changed.notified();
            let idle_since = {
                let state = self.state.lock().expect("xhttp H3 activity");
                (state.running == 0).then_some(state.idle_since)
            };
            if let Some(idle_since) = idle_since {
                tokio::select! {
                    _ = changed => {}
                    _ = tokio::time::sleep_until(idle_since + IDLE_TIMEOUT) => {
                        let mut state = self.state.lock().expect("xhttp H3 activity");
                        if state.running == 0 && state.idle_since == idle_since {
                            state.expired = true;
                            return;
                        }
                    }
                }
            } else {
                changed.await;
            }
        }
    }
}

fn configure(
    tls: &TlsOptions,
    xmux: &xmux::Pool,
    params: Params,
) -> io::Result<(quinn::EndpointConfig, quinn::ClientConfig)> {
    let options = QuicTunnelOptions {
        idle_timeout: Some(Duration::from_secs(params.idle_seconds)),
        keep_alive_period: params
            .keep_alive_seconds
            .map(Duration::from_secs)
            .or_else(|| xmux.h3_keep_alive()),
        stream_receive_window: Some(params.stream_window),
        connection_receive_window: Some(params.connection_window),
        max_concurrent_streams: Some(params.incoming_bidi_streams),
        initial_packet_size: params.chrome.then_some(1250),
        disable_path_mtu_discovery: params.disable_pmtud
            || !cfg!(any(
                target_os = "linux",
                target_os = "windows",
                target_os = "macos"
            )),
    };
    let uni_streams = if params.chrome { 103 } else { 100 };
    let (mut endpoint, mut transport) =
        options.build_configs(CongestionKind::Bbr, Some(uni_streams), params.chrome);
    transport
        .ack_frequency_config(None)
        .enable_segmentation_offload(!params.disable_gso)
        .receive_window_limits(
            quinn::VarInt::from_u64(params.max_stream_window).expect("validated stream window"),
            quinn::VarInt::from_u64(params.max_connection_window)
                .expect("validated connection window"),
        );
    match params.congestion {
        Congestion::Bbr => {}
        Congestion::Reno => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
        }
        Congestion::Brutal {
            up_bytes_per_second,
            compensate_loss,
        } => {
            transport.congestion_controller_factory(xhttp_brutal_controller(
                up_bytes_per_second,
                compensate_loss,
            ));
        }
    };
    let mut tls = tls.xhttp_quic_config()?;
    if params.chrome {
        endpoint
            .max_udp_payload_size(1472)
            .expect("valid QUIC receive size");
        transport.chrome_initial(true);
        transport.datagram_receive_buffer_size(Some(u16::MAX as usize));
        // The existing Chrome QUIC TLS template retains the configured CA,
        // pin verifier and ALPN and is also used for Xray's HY2 profile.
        tls = tls.with_hy2_chrome()?;
    }
    let mut client = quinn::ClientConfig::new(Arc::new(tls));
    client.transport_config(Arc::new(transport));
    quic_go_client_shape(&mut endpoint, &mut client);
    if !params.chrome {
        // Transport.DialEarly on an explicit quic-go Transport uses a
        // four-byte SCID in its ordinary profile.
        endpoint.cid_generator(|| Box::new(quinn_proto::RandomConnectionIdGenerator::new(4)));
    }
    Ok((endpoint, client))
}

struct Client {
    endpoint: quinn::Endpoint,
    connection: quinn::Connection,
    sender: Sender,
    driver: tokio::task::JoinHandle<()>,
    lifetime: xmux::Lifetime,
    activity: Arc<Activity>,
}

impl Client {
    fn can_reuse(&self) -> bool {
        self.lifetime.can_reuse()
            && self.connection.close_reason().is_none()
            && !self.driver.is_finished()
            && !self.activity.expired()
    }

    async fn connect(
        tls: &TlsOptions,
        server: &str,
        address: SocketAddr,
        dial: &DialOptions,
        xmux: &xmux::Pool,
        pool: Weak<PoolShared>,
        params: Params,
    ) -> io::Result<Self> {
        let socket = connect_udp(address, dial).await?.into_std()?;
        crate::outbound::quic::size_network_udp_buffers(socket2::SockRef::from(&socket));
        let (endpoint_config, client_config) = configure(tls, xmux, params)?;
        let runtime =
            quinn::default_runtime().ok_or_else(|| protocol_error("connect", "no QUIC runtime"))?;
        let mut endpoint = quinn::Endpoint::new(endpoint_config, None, socket, runtime)?;
        endpoint.set_default_client_config(client_config);
        let server_name = if tls.server_name().is_empty() {
            server
        } else {
            tls.server_name()
        };
        let connecting = endpoint
            .connect(address, server_name)
            .map_err(|err| protocol_error("connect", err))?;
        let (connection, mut h3, sender) = tokio::time::timeout(dial.connect_timeout(), async {
            let connection = connecting
                .await
                .map_err(|err| protocol_error("QUIC handshake", err))?;
            let (h3, sender) = h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(|err| protocol_error("HTTP handshake", err))?;
            Ok::<_, io::Error>((connection, h3, sender))
        })
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "xhttp: h3 handshake timed out"))??;
        let activity = Arc::new(Activity::new());
        let activity_task = activity.clone();
        let quic = connection.clone();
        let driver = tokio::spawn(async move {
            tokio::select! {
                _ = std::future::poll_fn(|cx| h3.poll_close(cx)) => {}
                _ = activity_task.wait_idle() => {
                    quic.close(quinn::VarInt::from_u32(0x100), b"");
                }
            }
            if let Some(pool) = pool.upgrade() {
                pool.state
                    .lock()
                    .expect("xhttp H3 pool")
                    .clients
                    .retain(|client| client.connection.stable_id() != quic.stable_id());
                pool.changed.notify_waiters();
            }
        });
        Ok(Self {
            endpoint,
            connection,
            sender,
            driver,
            lifetime: xmux.lifetime(),
            activity,
        })
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        self.driver.abort();
        self.endpoint.close(quinn::VarInt::from_u32(0x100), b"");
    }
}

struct Usage {
    client: Arc<Client>,
}

impl Drop for Usage {
    fn drop(&mut self) {
        self.client.activity.release();
    }
}

/// Clones refer to the same tunnel handout, including independent upload and
/// download requests on one client and request tasks keeping a retired
/// client alive until their active streams finish.
#[derive(Clone)]
pub(crate) struct Lease(Arc<Usage>);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Mode {
    Duplex,
    Download,
    Upload,
}

impl Lease {
    fn new(client: Arc<Client>) -> Option<Self> {
        if !client.activity.acquire() {
            return None;
        }
        client.lifetime.take_use();
        Some(Self(Arc::new(Usage { client })))
    }

    pub(crate) fn take_requests(&self, count: i32) {
        self.client().lifetime.take_requests(count);
    }

    pub(crate) fn try_take_packet(&self) -> bool {
        let client = self.client();
        client.connection.close_reason().is_none()
            && !client.driver.is_finished()
            && client.lifetime.try_take_packet()
    }

    fn client(&self) -> &Client {
        &self.0.client
    }

    async fn request(
        &self,
        req: http::Request<()>,
    ) -> io::Result<h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>> {
        self.client()
            .sender
            .clone()
            .send_request(req)
            .await
            .map_err(|err| protocol_error("request", err))
    }

    pub(crate) async fn start_post(
        &self,
        mut req: http::Request<()>,
        payload: Bytes,
    ) -> io::Result<impl Future<Output = io::Result<()>> + Send + 'static + use<>> {
        if !payload.is_empty() || matches!(req.method().as_str(), "POST" | "PUT" | "PATCH") {
            req.headers_mut()
                .insert(http::header::CONTENT_LENGTH, payload.len().into());
        }
        let (mut send, mut recv) = self.request(req).await?.split();
        if !payload.is_empty() {
            send.send_data(payload)
                .await
                .map_err(|err| protocol_error("POST body", err))?;
        }
        send.finish()
            .await
            .map_err(|err| protocol_error("finish POST", err))?;
        let lease = self.clone();
        Ok(async move {
            let _lease = lease;
            download(&mut recv, &mut tokio::io::sink(), false).await
        })
    }

    pub(crate) async fn open(
        &self,
        mut req: http::Request<()>,
        mode: Mode,
    ) -> io::Result<AnyStream> {
        let auto_gzip = xhttp_gzip::request_h3(&mut req) && req.method() != http::Method::CONNECT;
        let (mut send, mut recv) = self.request(req).await?.split();
        let (app, driver) = tokio::io::duplex(CHUNK);
        let (mut source, mut sink) = tokio::io::split(driver);
        let progress = Arc::new(Progress::default());
        let task_progress = progress.clone();
        let lease = self.clone();
        let task = tokio::spawn(async move {
            let upload = async {
                if mode != Mode::Download {
                    let mut block = [0u8; CHUNK];
                    loop {
                        let len = source.read(&mut block).await?;
                        if len == 0 {
                            break;
                        }
                        send.send_data(Bytes::copy_from_slice(&block[..len]))
                            .await
                            .map_err(|err| protocol_error("upload", err))?;
                        task_progress.sent.fetch_add(len as u64, Ordering::Release);
                        task_progress.changed.notify_one();
                    }
                }
                send.finish()
                    .await
                    .map_err(|err| protocol_error("finish upload", err))?;
                task_progress.finished.store(true, Ordering::Release);
                task_progress.changed.notify_one();
                Ok(())
            };
            let receive = async {
                if mode == Mode::Upload {
                    download(&mut recv, &mut tokio::io::sink(), false).await
                } else {
                    download(&mut recv, &mut sink, auto_gzip).await?;
                    sink.shutdown().await
                }
            };
            let result = tokio::try_join!(upload, receive);
            if let Err(error) = result {
                *task_progress.error.lock().expect("HTTP/3 stream error") = Some(error);
                task_progress.changed.notify_one();
            }
            drop(lease);
        });
        Ok(Box::new(Stream {
            app,
            task,
            progress,
            mode,
            accepted: 0,
            wait: None,
        }))
    }
}

async fn download(
    recv: &mut ReceiveBody,
    sink: &mut (impl AsyncWrite + Unpin),
    auto_gzip: bool,
) -> io::Result<()> {
    let mut gzip = loop {
        let response = recv
            .recv_response()
            .await
            .map_err(|err| protocol_error("response headers", err))?;
        if !response.status().is_informational() {
            if response.status() != http::StatusCode::OK {
                return Err(protocol_error("response status", response.status()));
            }
            break (auto_gzip && xhttp_gzip::encoded_h3(response.headers()))
                .then(xhttp_gzip::Decoder::new);
        }
    };

    while let Some(mut data) = recv
        .recv_data()
        .await
        .map_err(|err| protocol_error("response body", err))?
    {
        if let Some(decoder) = &mut gzip {
            decoder
                .write_chunk(data.copy_to_bytes(data.remaining()), sink)
                .await?;
        } else {
            sink.write_all_buf(&mut data).await?;
        }
    }
    let _ = recv
        .recv_trailers()
        .await
        .map_err(|err| protocol_error("response trailers", err))?;
    if let Some(decoder) = &mut gzip {
        decoder.finish_to(sink).await?;
    }
    Ok(())
}

#[derive(Default)]
struct Progress {
    sent: AtomicU64,
    finished: AtomicBool,
    error: Mutex<Option<io::Error>>,
    changed: Arc<Notify>,
}

struct Stream {
    app: DuplexStream,
    task: tokio::task::JoinHandle<()>,
    progress: Arc<Progress>,
    mode: Mode,
    accepted: u64,
    wait: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
}

impl Stream {
    fn error(&self) -> Option<io::Error> {
        self.progress
            .error
            .lock()
            .expect("HTTP/3 stream error")
            .as_ref()
            .map(|err| io::Error::new(err.kind(), err.to_string()))
    }

    /// DuplexStream's local flush can complete before QUIC accepted the
    /// bytes. Wait for the pump to submit them before reporting success.
    fn poll_progress(&mut self, cx: &mut Context<'_>, finish: bool) -> Poll<io::Result<()>> {
        loop {
            if let Some(err) = self.error() {
                return Poll::Ready(Err(err));
            }
            let done = if finish {
                self.progress.finished.load(Ordering::Acquire)
            } else {
                self.progress.sent.load(Ordering::Acquire) >= self.accepted
            };
            if done {
                self.wait = None;
                return Poll::Ready(Ok(()));
            }
            let wait = self
                .wait
                .get_or_insert_with(|| Box::pin(self.progress.changed.clone().notified_owned()));
            ready!(wait.as_mut().poll(cx));
            self.wait = None;
        }
    }
}

impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.mode == Mode::Upload || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.app).poll_read(cx, buf))?;
        if buf.filled().len() == before
            && let Some(error) = self.error()
        {
            return Poll::Ready(Err(error));
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.mode == Mode::Download {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "xhttp: h3 download has no upload body",
            )));
        }
        if let Some(err) = self.error() {
            return Poll::Ready(Err(err));
        }
        let len = ready!(Pin::new(&mut self.app).poll_write(cx, buf))?;
        self.accepted += len as u64;
        Poll::Ready(Ok(len))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_progress(cx, false)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(Pin::new(&mut self.app).poll_shutdown(cx))?;
        self.poll_progress(cx, true)
    }
}

impl Drop for Stream {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(test)]
mod tests {
    use base64::Engine as _;
    use core_tls::rustls;
    use serde_json::json;
    use sha2::{Digest, Sha256};

    use super::*;

    #[tokio::test]
    async fn stream_one_reads_response_before_finishing_upload() {
        stream_one_roundtrip(Params::default(), false).await;
    }

    #[tokio::test]
    async fn stream_one_decodes_gzip_using_explicit_quic_settings() {
        let options = json!({
            "disable_chrome_parrot": true,
            "congestion": "reno",
            "init_stream_receive_window": 32768,
            "max_stream_receive_window": 65536,
            "init_connection_receive_window": 49152,
            "max_connection_receive_window": 98304,
            "max_idle_timeout": 12,
            "keep_alive_period": 3,
            "disable_gso": true,
        });
        stream_one_roundtrip(Params::parse(Some(&options), "quic").unwrap(), true).await;
    }

    async fn stream_one_roundtrip(params: Params, gzip: bool) {
        const CERT: &str = include_str!("../../../../../tests/golden/certs/localhost.crt");
        const KEY: &str = include_str!("../../../../../tests/golden/certs/localhost.key");
        core_tls::install_default_provider();
        let certs: Vec<_> = rustls_pemfile::certs(&mut CERT.as_bytes())
            .collect::<Result<_, _>>()
            .unwrap();
        let pin = base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&certs[0]));
        let key = rustls_pemfile::private_key(&mut KEY.as_bytes())
            .unwrap()
            .unwrap();
        let mut tls =
            rustls::ServerConfig::builder_with_provider(core_tls::quic::configured_provider())
                .with_protocol_versions(&[&rustls::version::TLS13])
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let server = quinn::ServerConfig::new(
            Arc::new(core_tls::quic::QuicServerConfig::try_from(tls).unwrap()),
            Arc::new(core_tls::quic::HandshakeTokenKeyRustCrypto::new([17; 64])),
        );
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[19; 32]))),
            Some(server),
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            quinn::default_runtime().unwrap(),
        )
        .unwrap();
        let address = endpoint.local_addr().unwrap();
        let (done, hold) = tokio::sync::oneshot::channel::<()>();
        let peer = tokio::spawn(async move {
            let quic = endpoint.accept().await.unwrap().await.unwrap();
            let mut h3: h3::server::Connection<_, Bytes> = h3::server::builder()
                .build(h3_quinn::Connection::new(quic))
                .await
                .unwrap();
            let (request, mut stream) = h3
                .accept()
                .await
                .unwrap()
                .unwrap()
                .resolve_request()
                .await
                .unwrap();
            assert_eq!(request.method(), http::Method::POST);
            let mut data = stream.recv_data().await.unwrap().unwrap();
            assert_eq!(data.copy_to_bytes(data.remaining()).as_ref(), b"ping");
            let mut response = http::Response::new(());
            let payload = if gzip {
                use std::io::Write as _;
                assert_eq!(request.headers()[http::header::ACCEPT_ENCODING], "gzip");
                response.headers_mut().insert(
                    http::header::CONTENT_ENCODING,
                    http::HeaderValue::from_static("gzip"),
                );
                let mut encoder =
                    flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
                encoder.write_all(b"pong").unwrap();
                Bytes::from(encoder.finish().unwrap())
            } else {
                Bytes::from_static(b"pong")
            };
            stream.send_response(response).await.unwrap();
            stream.send_data(payload).await.unwrap();
            assert!(stream.recv_data().await.unwrap().is_none());
            stream.finish().await.unwrap();
            let _ = hold.await;
        });

        tokio::time::timeout(Duration::from_secs(5), async {
            let config = json!({"tls": {
                "enabled": true, "server_name": "localhost", "alpn": ["h3"],
                "xray_pinned_peer_cert_sha256": pin,
            }});
            let tls = TlsOptions::from_outbound(config.as_object().unwrap(), "127.0.0.1", "test")
                .unwrap()
                .unwrap();
            let pool = Pool::new(xmux::Pool::new(xmux::XmuxConfig::default()), params);
            let lease = pool
                .acquire(&tls, "127.0.0.1", address.port(), &DialOptions::default())
                .await
                .unwrap();
            let req = http::Request::post("https://localhost/stream-one")
                .body(())
                .unwrap();
            let mut io = lease.open(req, Mode::Duplex).await.unwrap();
            io.write_all(b"ping").await.unwrap();
            io.flush().await.unwrap();
            let mut out = [0; 4];
            io.read_exact(&mut out).await.unwrap();
            assert_eq!(&out, b"pong");
            io.shutdown().await.unwrap();
            assert_eq!(io.read(&mut out).await.unwrap(), 0);
        })
        .await
        .unwrap();
        drop(done);
        peer.await.unwrap();
    }
}
