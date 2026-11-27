//! XHTTP (Xray "splithttp") client transport over HTTP/1.1, HTTP/2 or HTTP/3.
//!
//! Wire semantics ported from the reference client (sing-box-lx
//! `transport/v2rayxhttp`, SPEC 002 / PARAM_MAP): a per-dial session id
//! targets `<path>/<sessionId>` (download GET) and packet-up uploads POST to
//! `<path>/<sessionId>/<seq>`; placement/keys move session/seq/payload into
//! query/header/cookie; every request carries X-Padding (Referer legacy or
//! the configurable obfs placements, `repeat-x`/`tokenish`).
//!
//! Modes: packet-up (GET download + sequential POST packets), stream-up
//! (streamed POST upload + GET download), stream-one (one bidirectional
//! stream). Auto preserves packet-up; all modes can use pooled HTTP/2
//! connections when negotiated.
//!
//! The split modes use a `Connection: close` HTTP/1.1 download GET and pooled
//! keep-alive upload POSTs. Their separate connections are provided by the
//! transport dialer. On HTTP/2, GET and upload requests share the session pool.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use bytes::{Bytes, BytesMut};
use serde_json::{Map, Value};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use super::h2io::{
    CounterGuard, H2_PING_TIMEOUT, H2Acquire, H2Connection, H2Counter, H2KeepAlive, H2Pool,
    ReadClock, TrackedStream, drive_h2_connection, h2_conn_idle, h2_handshake,
};
use super::{h1io, xhttp_gzip, xhttp_h3};
use crate::inbound::AnyStream;
use crate::outbound::dial::{DialOptions, connect_tcp};
use crate::tls_client::TlsOptions;

/// Opens one more connection to the same server, with the same TCP options, the
/// same TLS and the same ALPN as the first.
pub(crate) type Dialer =
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send>> + Send + Sync;

/// Xray's checked XHTTP SETTINGS and opening connection credit. Scoped to
/// XHTTP: ordinary H2 and gRPC builders retain their existing policy. Explicit
/// receive-window overrides remain authoritative.
fn xhttp_h2_builder() -> h2::client::Builder {
    let mut builder = super::h2io::client_builder();
    builder.recycle_received_data(true);
    apply_xhttp_h2_settings(&mut builder, crate::env_var("H2_CONN_WINDOW").is_some());
    builder
}

async fn handshake_h2(
    stream: AnyStream,
    paired_settings_timeout: Option<std::time::Duration>,
) -> io::Result<super::h2io::H2Fresh> {
    let mut builder = xhttp_h2_builder();
    if paired_settings_timeout.is_some() {
        // Wait for the peer's allowance only before placing two dependent
        // requests on this connection. An initial SETTINGS without a stream
        // limit makes the allowance unlimited in h2.
        builder.initial_max_send_streams(0);
    }
    let (sender, mut connection, clock) = h2_handshake(stream, &builder, "xhttp").await?;
    if let Some(timeout) = paired_settings_timeout {
        tokio::time::timeout(
            timeout,
            std::future::poll_fn(|cx| {
                if let Poll::Ready(result) = Pin::new(&mut connection).poll(cx) {
                    return Poll::Ready(Err(io::Error::other(match result {
                        Ok(()) => "xhttp: h2 closed before peer allowed request streams".to_owned(),
                        Err(error) => format!("xhttp: h2 peer SETTINGS: {error}"),
                    })));
                }
                if sender.current_max_send_streams() == 0 {
                    Poll::Pending
                } else {
                    Poll::Ready(Ok(()))
                }
            }),
        )
        .await
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::TimedOut,
                "xhttp: h2 peer did not allow request streams before deadline",
            )
        })??;
    }
    Ok((sender, connection, clock))
}

fn apply_xhttp_h2_settings(builder: &mut h2::client::Builder, connection_override_present: bool) {
    builder.max_frame_size(1 << 20);
    if !connection_override_present {
        // Go gives 1 GiB beyond the protocol's existing 65535 bytes;
        // h2's API takes the final target, rather than the increment.
        builder.initial_connection_window_size((1 << 30) + 65_535);
    }
}

/// How long a packet-up session may go without download traffic once the
/// local side has half-closed it. Packet-up cannot tell the server that the
/// upload ended, so an upstream that waits for EOF never answers and never
/// closes; without a limit the session, its download request and the local
/// socket live until the server gives up. Every download chunk restarts the
/// limit, so a response that keeps moving is read to its end. Xray ends the
/// same case with its `downlinkOnly` policy timer (1 s by default); this is
/// ten times that. `XRUST_XHTTP_HALF_CLOSE_IDLE_MS` overrides it.
const HALF_CLOSE_IDLE: std::time::Duration = std::time::Duration::from_secs(10);

fn half_close_idle() -> std::time::Duration {
    static IDLE: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *IDLE.get_or_init(|| {
        if let Some(val) = crate::env_var("XHTTP_HALF_CLOSE_IDLE_MS")
            && let Ok(ms) = val.parse::<u64>()
            && ms > 0
        {
            return std::time::Duration::from_millis(ms);
        }
        HALF_CLOSE_IDLE
    })
}

/// Hop-by-hop headers: connection-scoped in HTTP/2 and HTTP/1.1 alike, so none
/// of them may be copied from the config onto the wire.
const HOP_BY_HOP: &[&str] = &[
    "host",
    "connection",
    "keep-alive",
    "proxy-connection",
    "transfer-encoding",
    "upgrade",
    "te",
    "trailer",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    Auto,
    PacketUp,
    StreamUp,
    StreamOne,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Placement {
    Path,
    Query,
    Header,
    Cookie,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XPlacement {
    Cookie,
    Header,
    Query,
    QueryInHeader,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PadMethod {
    RepeatX,
    Tokenish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Range(pub u64, pub u64);

impl Range {
    fn parse(s: &str, def: Range) -> anyhow::Result<Self> {
        if s.is_empty() {
            return Ok(def);
        }
        let (lo, hi) = core_config::xhttp_int_range(s)
            .ok_or_else(|| anyhow::anyhow!("invalid range {s:?}"))?;
        anyhow::ensure!(lo >= 0, "invalid negative range {s:?}");
        Ok(Range(lo as u64, hi as u64))
    }

    fn config(t: &Map<String, Value>, key: &str, default: Range) -> anyhow::Result<Self> {
        let value = match t.get(key) {
            Some(Value::String(value)) => std::borrow::Cow::Borrowed(value.as_str()),
            Some(Value::Number(value)) => std::borrow::Cow::Owned(value.to_string()),
            _ => return Ok(default),
        };
        if value.is_empty() {
            return Ok(default);
        }
        let (lo, hi) = core_config::xhttp_int_range(&value)
            .ok_or_else(|| anyhow::anyhow!("{key}: invalid range {value:?}"))?;
        if hi == 0 {
            return Ok(default);
        }
        if key == "sc_min_posts_interval_ms" && lo <= 0 {
            return Ok(Range(0, 0));
        }
        anyhow::ensure!(lo > 0, "{key}: expected a positive range");
        Ok(Range(lo as u64, hi as u64))
    }

    fn rand(&self) -> u64 {
        if self.0 == self.1 {
            return self.0;
        }
        let mut b = [0u8; 8];
        let _ = crate::util::random_bytes(&mut b);
        self.0 + u64::from_le_bytes(b) % (self.1 - self.0 + 1)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum UplinkPlacement {
    Body,
    Header,
    Cookie,
}

/// Normalized placement/key/method selection (reference `metaConfig`).
#[derive(Debug, Clone)]
struct Meta {
    session_placement: Placement,
    session_key: String,
    seq_placement: Placement,
    seq_key: String,
    session_table: String,
    session_len: Range,
    uplink_data: UplinkPlacement,
    uplink_key: String,
    uplink_chunk: Range,
    uplink_method: String,
    x_obfs: bool,
    x_key: String,
    x_header: String,
    x_placement: XPlacement,
    x_method: PadMethod,
    sc_max_each_post: Range,
    sc_min_interval_ms: Range,
}

impl Meta {
    fn resolve(t: &Map<String, Value>, mode: Mode) -> anyhow::Result<Self> {
        let s = |k: &str| match t.get(k) {
            Some(Value::String(value)) => value.trim().to_string(),
            Some(Value::Number(value)) => value.to_string(),
            _ => String::new(),
        };
        let placement = |k: &str, what: &str| -> anyhow::Result<Placement> {
            match s(k).as_str() {
                "" | "path" => Ok(Placement::Path),
                "query" => Ok(Placement::Query),
                "header" => Ok(Placement::Header),
                "cookie" => Ok(Placement::Cookie),
                other => anyhow::bail!("v2ray-xhttp: unsupported {what}: {other}"),
            }
        };
        let session_placement = placement("session_placement", "session placement")?;
        let seq_placement = placement("seq_placement", "seq placement")?;
        let uplink_raw = s("uplink_data_placement");
        let uplink_data = match uplink_raw.as_str() {
            "" | "auto" | "body" => UplinkPlacement::Body,
            "header" => UplinkPlacement::Header,
            "cookie" => UplinkPlacement::Cookie,
            other => anyhow::bail!("v2ray-xhttp: unsupported uplink data placement: {other}"),
        };
        // header/cookie payload is a packet-up-only shape (hard gate).
        if !matches!(uplink_data, UplinkPlacement::Body) && mode != Mode::PacketUp {
            anyhow::bail!(
                "v2ray-xhttp: uplink_data_placement can be {uplink_raw} only in packet-up mode"
            );
        }
        let x_placement = match s("x_padding_placement").as_str() {
            "" | "queryInHeader" => XPlacement::QueryInHeader,
            "cookie" => XPlacement::Cookie,
            "header" => XPlacement::Header,
            "query" => XPlacement::Query,
            other => anyhow::bail!("v2ray-xhttp: unsupported x padding placement: {other}"),
        };
        let x_method = match s("x_padding_method").as_str() {
            "" | "repeat-x" => PadMethod::RepeatX,
            "tokenish" => PadMethod::Tokenish,
            other => anyhow::bail!("v2ray-xhttp: unsupported x padding method: {other}"),
        };
        // Key defaults are placement-asymmetric: canonical `X-*` for headers,
        // lowercase `x_*` for query/cookie (PARAM_MAP §2).
        let session_key = match s("session_key") {
            v if !v.is_empty() => v,
            _ => match session_placement {
                Placement::Header => "X-Session".to_string(),
                _ => "x_session".to_string(),
            },
        };
        let seq_key = match s("seq_key") {
            v if !v.is_empty() => v,
            _ => match seq_placement {
                Placement::Header => "X-Seq".to_string(),
                _ => "x_seq".to_string(),
            },
        };
        let uplink_key = match s("uplink_data_key") {
            v if !v.is_empty() => v,
            _ => match uplink_data {
                UplinkPlacement::Cookie => "x_data".to_string(),
                _ => "X-Data".to_string(),
            },
        };
        let sc_max_each_post =
            Range::config(t, "sc_max_each_post_bytes", Range(1_000_000, 1_000_000))?;
        let uplink_chunk = Range::parse(&s("uplink_chunk_size"), Range(0, 0))?;
        let uplink_chunk = if uplink_chunk.1 == 0 {
            match uplink_data {
                UplinkPlacement::Cookie => Range(2048, 3072),
                UplinkPlacement::Header => Range(3000, 4000),
                UplinkPlacement::Body => sc_max_each_post,
            }
        } else {
            Range(uplink_chunk.0.max(64), uplink_chunk.1.max(64))
        };
        // lx soft fallback: GET only makes sense for packet-up uploads; a
        // non-GET method must carry a body in stream modes.
        let mut uplink_method = s("uplink_http_method").to_uppercase();
        if uplink_method.is_empty() {
            uplink_method = "POST".to_string();
        }
        if uplink_method == "GET" && mode != Mode::PacketUp {
            crate::logging::warn(format_args!(
                "v2ray-xhttp: uplink_http_method GET outside packet-up mode; falling back to POST"
            ));
            uplink_method = "POST".to_string();
        }
        Ok(Self {
            session_placement,
            session_key,
            seq_placement,
            seq_key,
            session_table: if t.contains_key("session_table") {
                s("session_table")
            } else {
                s("session_id_table")
            },
            session_len: Range::parse(
                &if t.contains_key("session_length") {
                    s("session_length")
                } else {
                    s("session_id_length")
                },
                Range(0, 0),
            )?,
            uplink_data,
            uplink_key,
            uplink_chunk,
            uplink_method,
            x_obfs: t.get("x_padding_obfs_mode").and_then(Value::as_bool) == Some(true),
            x_key: match s("x_padding_key") {
                v if !v.is_empty() => v,
                _ => "x_padding".to_string(),
            },
            x_header: match s("x_padding_header") {
                v if !v.is_empty() => v,
                _ => "X-Padding".to_string(),
            },
            x_placement,
            x_method,
            sc_max_each_post,
            sc_min_interval_ms: Range::config(t, "sc_min_posts_interval_ms", Range(30, 30))?,
        })
    }
}

/// How much of a streamed body (stream-one, stream-up) goes into one DATA
/// frame: Xray hands its HTTP client the upload in 8 KiB buffers, and Go
/// writes each read of the body as a frame of its own, so every chunk of a
/// bulk upload is an 8201-byte frame and an 8218-byte TLS record.
const GO_BODY_CHUNK: usize = 8 * 1024;

#[derive(Clone)]
pub(crate) struct XhttpConfig {
    host: Option<String>,
    path: String,
    query: String,
    mode: Mode,
    headers: Vec<(String, String)>,
    padding: Range,
    no_grpc_header: bool,
    meta: Meta,
    /// keep-alive connections shared by the upload POSTs of every dial of this
    /// transport
    pool: std::sync::Arc<super::xmux::Pool>,
    h2_pool: std::sync::Arc<H2Pool>,
    h3_pool: std::sync::Arc<std::sync::OnceLock<xhttp_h3::Pool>>,
    quic_params: Option<std::sync::Arc<core_config::xhttp_quic::Params>>,
    /// see [`HALF_CLOSE_IDLE`]
    half_close_idle: std::time::Duration,
    /// see [`super::h2io::H2_CONN_IDLE`]; `None` keeps pooled connections forever
    h2_idle: Option<std::time::Duration>,
    download: Option<std::sync::Arc<DownloadSettings>>,
}

struct DownloadSettings {
    server: String,
    port: u16,
    tls: Option<TlsOptions>,
    transport: XhttpConfig,
}

impl DownloadSettings {
    fn parse(value: &Value) -> anyhow::Result<Self> {
        let at = "v2ray-xhttp.download_settings";
        let settings = value
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: expected an object"))?;
        let server = settings
            .get("server")
            .and_then(Value::as_str)
            .filter(|server| !server.trim().is_empty())
            .ok_or_else(|| anyhow::anyhow!("{at}.server: expected a nonempty address"))?;
        let port = settings
            .get("server_port")
            .and_then(Value::as_u64)
            .and_then(|port| u16::try_from(port).ok())
            .filter(|port| *port != 0)
            .ok_or_else(|| anyhow::anyhow!("{at}.server_port: expected a port from 1 to 65535"))?;
        let transport = settings
            .get("transport")
            .and_then(Value::as_object)
            .ok_or_else(|| anyhow::anyhow!("{at}.transport: expected an XHTTP transport object"))?;
        if transport.get("type").and_then(Value::as_str) != Some("xhttp") {
            anyhow::bail!("{at}.transport.type: expected xhttp");
        }
        if transport.contains_key("download_settings") {
            anyhow::bail!("{at}.transport.download_settings: nested downloads are unsupported");
        }
        Ok(Self {
            server: server.to_string(),
            port,
            tls: TlsOptions::from_outbound(settings, server, at)?,
            transport: XhttpConfig::parse(transport)?,
        })
    }
}

impl XhttpConfig {
    pub(crate) fn parse(t: &Map<String, Value>) -> anyhow::Result<Self> {
        let mode = match t.get("mode").and_then(Value::as_str).unwrap_or("") {
            "" | "auto" => Mode::Auto,
            "packet-up" => Mode::PacketUp,
            "stream-up" => Mode::StreamUp,
            "stream-one" => Mode::StreamOne,
            other => anyhow::bail!("v2ray-xhttp: unknown mode: {other}"),
        };
        let resource = t.get("path").and_then(Value::as_str).unwrap_or("/");
        let (path, query) = resource.split_once('?').unwrap_or((resource, ""));
        let meta = Meta::resolve(t, mode)?;
        let mut escaped_path = String::with_capacity(path.len() + 2);
        if !path.starts_with('/') {
            escaped_path.push('/');
        }
        escape_url_component(&mut escaped_path, path.as_bytes(), true);
        if !escaped_path.ends_with('/')
            && (meta.session_placement == Placement::Path || meta.seq_placement == Placement::Path)
        {
            escaped_path.push('/');
        }
        let host = t
            .get("host")
            .and_then(Value::as_str)
            .filter(|h| !h.is_empty())
            .map(str::to_string);
        let mut headers = Vec::new();
        if let Some(Value::Object(map)) = t.get("headers") {
            for (k, v) in map {
                let v = v.as_str().ok_or_else(|| {
                    anyhow::anyhow!("v2ray-xhttp: transport header {k:?} must be a string")
                })?;
                headers.push((k.clone(), v.to_string()));
            }
        }
        let download = t
            .get("download_settings")
            .map(DownloadSettings::parse)
            .transpose()?
            .map(std::sync::Arc::new);
        if mode == Mode::StreamOne && download.is_some() {
            anyhow::bail!("v2ray-xhttp.download_settings: stream-one has no separate download");
        }
        let xmux = super::xmux::XmuxConfig::parse(t.get("xmux"), "v2ray-xhttp.xmux")?;
        Ok(Self {
            host,
            path: escaped_path,
            query: query.to_owned(),
            mode,
            headers,
            padding: Range::config(t, "x_padding_bytes", Range(100, 1000))?,
            no_grpc_header: t.get("no_grpc_header").and_then(Value::as_bool) == Some(true),
            meta,
            h3_pool: Default::default(),
            quic_params: t
                .get("quic_params")
                .map(|v| core_config::xhttp_quic::Params::parse(Some(v), "v2ray-xhttp.quic_params"))
                .transpose()
                .map_err(anyhow::Error::msg)?
                .map(std::sync::Arc::new),
            pool: super::xmux::Pool::new(xmux),
            h2_pool: std::sync::Arc::new(H2Pool::new_xmux(xmux)),
            half_close_idle: half_close_idle(),
            h2_idle: h2_conn_idle(),
            download,
        })
    }
}

enum Connection {
    H1(AnyStream),
    H2(h2::client::SendRequest<Bytes>, CounterGuard),
    H3(xhttp_h3::Lease),
}

impl XhttpConfig {
    fn authority_for(&self, sni: &str, server: &str, _port: u16) -> String {
        let host = self
            .host
            .as_deref()
            .unwrap_or(if sni.is_empty() { server } else { sni });
        // Stock Xray's native dialer uses the configured host, TLS server
        // name, or dial address without appending the dial port.
        if host.parse::<std::net::Ipv6Addr>().is_ok() {
            format!("[{host}]")
        } else {
            host.to_owned()
        }
    }

    async fn open_h2_session(
        &self,
        mut send_req: h2::client::SendRequest<Bytes>,
        guard: CounterGuard,
        scheme: &str,
        authority: &str,
        mode: Mode,
        redial: Option<std::sync::Arc<Dialer>>,
    ) -> io::Result<AnyStream> {
        if mode == Mode::StreamOne {
            let mut request = self.build_request(
                scheme,
                authority,
                &self.meta.uplink_method,
                None,
                None,
                true,
            )?;
            let gzip = xhttp_gzip::request(&mut request);
            let (response, send) = send_req
                .send_request(request, false)
                .map_err(|e| io::Error::other(format!("xhttp: send_request: {e}")))?;
            let stream: AnyStream = Box::new(super::h2io::H2Io {
                h2: super::h2io::H2Stream::shared(response, send)
                    .with_write_chunk(GO_BODY_CHUNK)
                    .with_gzip(gzip),
            });
            return Ok(Box::new(TrackedStream::new(stream, guard.into_inner())));
        }

        let mut this = SplitConn::new(self);
        self.open_h2_download(&mut this, &mut send_req, scheme, authority)?;
        // Go's HTTP/2 transport can open another physical connection for
        // the same XMUX client when active GETs leave no room for uploads.
        // Reserve up to two streams per paired tunnel when deciding whether
        // to use a tunnel-owned connection for this upload.
        let tunnels = guard.counter().load(std::sync::atomic::Ordering::Relaxed);
        if send_req.current_max_send_streams() < tunnels.saturating_mul(2) {
            let dial = redial.as_ref().ok_or_else(|| {
                io::Error::other("xhttp: h2 peer requires a second connection for upload")
            })?;
            let (upload, connection, clock) = handshake_h2(dial().await?, None).await?;
            this.h2_upload_driver = Some(tokio::spawn(drive_h2_connection(
                connection,
                clock,
                self.pool
                    .h2_keep_alive()
                    .map(|period| H2KeepAlive::always(period, H2_PING_TIMEOUT)),
                std::sync::Weak::new(),
                guard.counter().clone(),
                self.h2_idle,
                "xhttp upload",
            )));
            send_req = upload;
        }
        self.open_h2_upload(
            &mut this,
            send_req,
            scheme,
            authority,
            mode,
            redial.map(|dial| (guard.counter().clone(), dial)),
        )
        .await?;
        Ok(Box::new(TrackedStream::new(
            Box::new(XhttpConn {
                split: Box::new(this),
            }),
            guard.into_inner(),
        )))
    }

    fn open_h2_download(
        &self,
        this: &mut SplitConn,
        send_req: &mut h2::client::SendRequest<Bytes>,
        scheme: &str,
        authority: &str,
    ) -> io::Result<()> {
        let mut get_req = self.build_request(
            scheme,
            authority,
            "GET",
            Some(&this.session_id),
            None,
            false,
        )?;
        let gzip = xhttp_gzip::request(&mut get_req);
        let (get_resp, _get_send) = send_req
            .send_request(get_req, true)
            .map_err(|e| io::Error::other(format!("xhttp: h2 GET send_request: {e}")))?;
        this.set_h2_download_stream(get_resp, gzip);
        Ok(())
    }

    async fn open_h2_upload(
        &self,
        this: &mut SplitConn,
        send_req: h2::client::SendRequest<Bytes>,
        scheme: &str,
        authority: &str,
        mode: Mode,
        redial: Option<H2Redial>,
    ) -> io::Result<()> {
        match mode {
            Mode::StreamUp => {
                let mut up_req = self.build_request(
                    scheme,
                    authority,
                    &self.meta.uplink_method,
                    Some(&this.session_id),
                    None,
                    true,
                )?;
                let mut up_client = send_req
                    .ready()
                    .await
                    .map_err(|e| io::Error::other(format!("xhttp: h2 upload ready: {e}")))?;
                xhttp_gzip::request(&mut up_req);
                let (up_resp, up_send) = up_client
                    .send_request(up_req, false)
                    .map_err(|e| io::Error::other(format!("xhttp: h2 upload send_request: {e}")))?;
                let failure = Failure::default();
                this.up = Up::H2Stream(Box::new(H2StreamUp {
                    io: super::h2io::H2Io {
                        h2: super::h2io::H2Stream::upload_only(up_send)
                            .with_write_chunk(GO_BODY_CHUNK),
                    },
                    failure: failure.clone(),
                }));
                this.spawn_h2_upload_ack(up_resp, failure);
            }
            _ => {
                let writer = PostWriter {
                    cfg: self.clone(),
                    scheme: scheme.to_string(),
                    authority: authority.to_string(),
                    session_id: this.session_id.clone(),
                    seq: 0,
                    dialer: no_h1_dialer(),
                    h2_client: Some(H2PacketClient {
                        sender: send_req,
                        redial,
                        replacement: None,
                    }),
                    first_connection: None,
                    h1_client: None,
                    h3_client: None,
                };
                this.spawn_packets_up(writer);
            }
        }
        Ok(())
    }

    pub(crate) async fn connect_h2_stream(
        &self,
        tls: &TlsOptions,
        server: &str,
        port: u16,
        dial: &DialOptions,
    ) -> io::Result<AnyStream> {
        let mode = self.resolved_mode(tls.reality().is_some());
        let authority = self.authority_for(tls.server_name(), server, port);
        let (send_req, guard) = self
            .pooled_connection(
                initial_requests(mode),
                (mode != Mode::StreamOne).then(|| dial.connect_timeout()),
                dial_tls(tls, server, port, dial),
            )
            .await?;
        let counter = guard.counter().clone();
        let result = self
            .open_h2_session(
                send_req,
                guard,
                "https",
                &authority,
                mode,
                (mode != Mode::StreamOne).then(|| h2_dialer(tls, server, port, dial)),
            )
            .await;
        if result.is_err() {
            self.h2_pool.evict(&counter).await;
        }
        result
    }

    async fn pooled_connection(
        &self,
        requests: i32,
        paired_settings_timeout: Option<std::time::Duration>,
        open: impl Future<Output = io::Result<AnyStream>>,
    ) -> io::Result<(h2::client::SendRequest<Bytes>, CounterGuard)> {
        let max_conns = self.pool.max_connections();
        match self
            .h2_pool
            .acquire_requests(max_conns, self.pool.max_concurrency(), requests)
            .await
        {
            H2Acquire::Ready(send_req, counter) => Ok((send_req, CounterGuard::new(counter))),
            H2Acquire::NeedDial(dial_guard) => {
                let (send_request, connection, clock) =
                    handshake_h2(open.await?, paired_settings_timeout).await?;
                let counter = self
                    .register_h2(send_request.clone(), connection, clock, max_conns, requests)
                    .await;
                drop(dial_guard);
                let guard = CounterGuard::new(counter.clone());
                match send_request.ready().await {
                    Ok(req) => Ok((req, guard)),
                    Err(e) => {
                        drop(guard);
                        self.h2_pool.evict(&counter).await;
                        Err(io::Error::other(format!("xhttp: h2 ready: {e}")))
                    }
                }
            }
        }
    }

    async fn connect_endpoint(
        &self,
        tls: Option<&TlsOptions>,
        server: &str,
        port: u16,
        dial: &DialOptions,
        requests: i32,
    ) -> io::Result<Connection> {
        if let Some(tls) = tls.filter(|tls| xhttp_h3::selected(Some(tls))) {
            let lease = self.h3_pool().acquire(tls, server, port, dial).await?;
            lease.take_requests(requests);
            return Ok(Connection::H3(lease));
        }
        if let Some(tls) = tls.filter(|tls| !self.h1_only(Some(tls))) {
            let (sender, guard) = self
                .pooled_connection(requests, None, dial_tls(tls, server, port, dial))
                .await?;
            return Ok(Connection::H2(sender, guard));
        }
        let tcp = connect_tcp(server, port, dial).await?;
        let stream = match tls {
            Some(tls) => tls.wrap_with_defaults(tcp, &[b"http/1.1"]).await?,
            None => Box::new(tcp),
        };
        Ok(Connection::H1(stream))
    }

    pub(crate) fn has_download_settings(&self) -> bool {
        self.download.is_some()
    }

    pub(crate) async fn connect_split(
        &self,
        tls: Option<&TlsOptions>,
        server: &str,
        port: u16,
        dial: &DialOptions,
        dialer: std::sync::Arc<Dialer>,
    ) -> io::Result<AnyStream> {
        let down = self.download.as_deref().expect("separate XHTTP download");
        let mode = self.resolved_mode(tls.and_then(TlsOptions::reality).is_some());
        let (upload, download) = tokio::try_join!(
            self.connect_endpoint(tls, server, port, dial, i32::from(mode == Mode::StreamUp)),
            down.transport
                .connect_endpoint(down.tls.as_ref(), &down.server, down.port, dial, 1),
        )?;
        let mut session = SplitConn::new(self);
        let authority = self.authority_for(tls.map_or("", TlsOptions::server_name), server, port);
        let down_authority = down.transport.authority_for(
            down.tls.as_ref().map_or("", TlsOptions::server_name),
            &down.server,
            down.port,
        );
        let down_scheme = if down.tls.is_some() { "https" } else { "http" };
        let down_guard = match download {
            Connection::H1(stream) => {
                down.transport
                    .open_h1_download(&mut session, stream, down_scheme, &down_authority)
                    .await?;
                None
            }
            Connection::H2(mut send_req, guard) => {
                down.transport.open_h2_download(
                    &mut session,
                    &mut send_req,
                    down_scheme,
                    &down_authority,
                )?;
                Some(guard)
            }
            Connection::H3(lease) => {
                down.transport
                    .open_h3_download(&mut session, &lease, &down_authority)
                    .await?;
                None
            }
        };
        let scheme = if tls.is_some() { "https" } else { "http" };
        let up_guard = match upload {
            Connection::H1(stream) => {
                self.open_h1_upload(&mut session, scheme, &authority, mode, dialer, Some(stream))
                    .await?;
                None
            }
            Connection::H2(send_req, guard) => {
                let redial = tls
                    .filter(|_| mode == Mode::PacketUp)
                    .map(|tls| (guard.counter().clone(), h2_dialer(tls, server, port, dial)));
                self.open_h2_upload(&mut session, send_req, scheme, &authority, mode, redial)
                    .await?;
                Some(guard)
            }
            Connection::H3(lease) => {
                let tls = tls.expect("H3 upload uses TLS");
                let endpoint = || H3Endpoint::new(tls, server, port, dial);
                self.open_h3_upload(&mut session, lease, &authority, mode, endpoint)
                    .await?;
                None
            }
        };
        let mut tunnel: AnyStream = Box::new(XhttpConn {
            split: Box::new(session),
        });
        for guard in [down_guard, up_guard].into_iter().flatten() {
            tunnel = Box::new(TrackedStream::new(tunnel, guard.into_inner()));
        }
        Ok(tunnel)
    }

    fn h3_pool(&self) -> &xhttp_h3::Pool {
        self.h3_pool.get_or_init(|| {
            xhttp_h3::Pool::new(
                self.pool.clone(),
                self.quic_params.as_deref().copied().unwrap_or_default(),
            )
        })
    }

    pub(crate) async fn connect_h3(
        &self,
        tls: &TlsOptions,
        server: &str,
        port: u16,
        dial: &DialOptions,
    ) -> io::Result<AnyStream> {
        let mode = self.resolved_mode(false);
        let authority = self.authority_for(tls.server_name(), server, port);
        let lease = self.h3_pool().acquire(tls, server, port, dial).await?;
        lease.take_requests(initial_requests(mode));
        if mode == Mode::StreamOne {
            let request = self.build_request(
                "https",
                &authority,
                &self.meta.uplink_method,
                None,
                None,
                true,
            )?;
            return lease.open(request, xhttp_h3::Mode::Duplex).await;
        }
        let mut session = SplitConn::new(self);
        self.open_h3_download(&mut session, &lease, &authority)
            .await?;
        self.open_h3_upload(&mut session, lease, &authority, mode, || {
            H3Endpoint::new(tls, server, port, dial)
        })
        .await?;
        Ok(Box::new(XhttpConn {
            split: Box::new(session),
        }))
    }

    async fn open_h3_download(
        &self,
        session: &mut SplitConn,
        lease: &xhttp_h3::Lease,
        authority: &str,
    ) -> io::Result<()> {
        let request = self.build_request(
            "https",
            authority,
            "GET",
            Some(&session.session_id),
            None,
            false,
        )?;
        let mut io = lease.open(request, xhttp_h3::Mode::Download).await?;
        let (tx, rx) = mpsc::channel(4);
        session.dl = rx;
        session.dl_task = Some(tokio::spawn(async move {
            loop {
                let mut data = BytesMut::with_capacity(8192);
                let next = match tokio::io::AsyncReadExt::read_buf(&mut io, &mut data).await {
                    Ok(0) => break,
                    Ok(_) => Ok(data.freeze()),
                    Err(err) => {
                        let _ = tx.send(Err(err)).await;
                        break;
                    }
                };
                if tx.send(next).await.is_err() {
                    break;
                }
            }
        }));
        Ok(())
    }

    async fn open_h3_upload(
        &self,
        session: &mut SplitConn,
        lease: xhttp_h3::Lease,
        authority: &str,
        mode: Mode,
        endpoint: impl FnOnce() -> H3Endpoint,
    ) -> io::Result<()> {
        if mode == Mode::StreamUp {
            let request = self.build_request(
                "https",
                authority,
                &self.meta.uplink_method,
                Some(&session.session_id),
                None,
                true,
            )?;
            let io = lease.open(request, xhttp_h3::Mode::Upload).await?;
            session.up = Up::H3(io);
        } else {
            session.spawn_packets_up(PostWriter {
                cfg: self.clone(),
                scheme: "https".into(),
                authority: authority.into(),
                session_id: session.session_id.clone(),
                seq: 0,
                dialer: no_h1_dialer(),
                h2_client: None,
                h3_client: Some(Box::new(H3PacketClient {
                    lease,
                    endpoint: endpoint(),
                })),
                h1_client: None,
                first_connection: None,
            });
        }
        Ok(())
    }

    /// Put a fresh HTTP/2 connection into the pool and start driving it,
    /// with the xmux keep-alive.
    async fn register_h2(
        &self,
        send_request: h2::client::SendRequest<Bytes>,
        connection: H2Connection,
        clock: std::sync::Arc<ReadClock>,
        max_conns: usize,
        requests: i32,
    ) -> std::sync::Arc<H2Counter> {
        let counter = self
            .h2_pool
            .finish_dial_requests(Some(send_request), max_conns, requests)
            .await
            .expect("counter present");
        tokio::spawn(drive_h2_connection(
            connection,
            clock,
            self.pool
                .h2_keep_alive()
                .map(|period| H2KeepAlive::always(period, H2_PING_TIMEOUT)),
            std::sync::Arc::downgrade(&self.h2_pool),
            counter.clone(),
            self.h2_idle,
            "xhttp",
        ));
        counter
    }

    /// The mode a session runs in. `auto` follows Xray (splithttp/dialer.go,
    /// `mode == "auto"`): packet-up, or stream-one under REALITY. Xray picks
    /// stream-up for REALITY when the download uses a separate endpoint.
    fn resolved_mode(&self, has_reality: bool) -> Mode {
        match self.mode {
            Mode::Auto if has_reality && self.download.is_some() => Mode::StreamUp,
            Mode::Auto if has_reality => Mode::StreamOne,
            Mode::Auto => Mode::PacketUp,
            other => other,
        }
    }

    /// True when the transport must run its HTTP/1.1 request paths: plaintext
    /// HTTP, or TLS with `alpn` explicitly pinned to `["http/1.1"]`.
    pub(crate) fn h1_only(&self, tls: Option<&crate::tls_client::TlsOptions>) -> bool {
        let Some(tls) = tls else {
            return true;
        };
        tls.reality().is_none() && matches!(tls.alpn(), [alpn] if alpn == b"http/1.1")
    }
}

/// One xhttp tunnel: a download source and an upload sink. Over HTTP/1.1 those
/// are two connections, not two streams on one.
pub(crate) struct XhttpConn {
    split: Box<SplitConn>,
}

fn initial_requests(mode: Mode) -> i32 {
    if mode == Mode::StreamUp { 2 } else { 1 }
}

pub(crate) fn uses_h2(stream: &AnyStream, reality: bool) -> bool {
    let alpn = crate::inbound::stream_alpn(stream);
    // Xray REALITY can omit ALPN while serving HTTP/2 on the inner listener.
    reality || alpn == Some(b"h2")
}

async fn dial_tls(
    tls: &TlsOptions,
    server: &str,
    port: u16,
    dial: &DialOptions,
) -> io::Result<AnyStream> {
    let tcp = connect_tcp(server, port, dial).await?;
    tls.wrap_with_defaults(tcp, &[b"h2", b"http/1.1"]).await
}

pub(crate) fn h2_dialer(
    tls: &TlsOptions,
    server: &str,
    port: u16,
    dial: &DialOptions,
) -> std::sync::Arc<Dialer> {
    let server = server.to_owned();
    let dial = dial.clone();
    let tls = tls.clone();
    std::sync::Arc::new(move || {
        let tls = tls.clone();
        let server = server.clone();
        let dial = dial.clone();
        Box::pin(async move { dial_tls(&tls, &server, port, &dial).await })
    })
}

pub(crate) async fn connect(
    stream: AnyStream,
    secure: bool,
    has_reality: bool,
    server: &str,
    port: u16,
    cfg: &XhttpConfig,
    dialer: std::sync::Arc<Dialer>,
) -> io::Result<AnyStream> {
    let is_h2 = uses_h2(&stream, has_reality);
    let authority = cfg.authority_for("", server, port);
    let scheme = if secure { "https" } else { "http" };
    let mode = cfg.resolved_mode(has_reality);
    crate::logging::debug(format_args!(
        "xhttp: connect {server}:{port} secure={secure} is_h2={is_h2} mode={mode:?}"
    ));

    // Over HTTP/2, stream-one, stream-up, and packet-up all multiplex streams
    // over the pooled HTTP/2 connection.
    if is_h2 {
        let paired = (mode != Mode::StreamOne).then(|| DialOptions::default().connect_timeout());
        let (send_request, connection, clock) = handshake_h2(stream, paired).await?;
        let max_conns = cfg.pool.max_connections();
        let counter = cfg
            .register_h2(
                send_request.clone(),
                connection,
                clock,
                max_conns,
                initial_requests(mode),
            )
            .await;
        let guard = CounterGuard::new(counter.clone());
        let send_req = match send_request.ready().await {
            Ok(req) => req,
            Err(e) => {
                drop(guard);
                cfg.h2_pool.evict(&counter).await;
                return Err(io::Error::other(format!("xhttp: h2 ready: {e}")));
            }
        };
        return cfg
            .open_h2_session(send_req, guard, scheme, &authority, mode, Some(dialer))
            .await;
    }

    let mut this = SplitConn::new(cfg);

    // stream-one is one bidirectional request on one connection: the body goes
    // up and the response comes back down it, so there is no separate download.
    if mode == Mode::StreamOne {
        let client = cfg.pool.h1_session().await;
        client.take_request();
        this.h1_download = Some(client);
        let mut request = cfg.build_request(
            scheme,
            &authority,
            &cfg.meta.uplink_method,
            None,
            None,
            true,
        )?;
        let gzip = xhttp_gzip::request_h1(&mut request);
        let (io, resp) = h1io::Stream::start(stream, &request, &authority, true).await?;
        let failure = Failure::default();
        this.up = Up::Stream(Box::new(StreamUp {
            io,
            failure: failure.clone(),
        }));
        this.spawn_upload_download(resp, failure, gzip);
        return Ok(Box::new(XhttpConn {
            split: Box::new(this),
        }));
    }

    // The download GET uses a dedicated HTTP/1.1 connection.
    cfg.open_h1_download(&mut this, stream, scheme, &authority)
        .await?;
    cfg.open_h1_upload(&mut this, scheme, &authority, mode, dialer, None)
        .await?;
    Ok(Box::new(XhttpConn {
        split: Box::new(this),
    }))
}

impl XhttpConfig {
    async fn open_h1_download(
        &self,
        this: &mut SplitConn,
        mut io: AnyStream,
        scheme: &str,
        authority: &str,
    ) -> io::Result<()> {
        let client = self.pool.h1_session().await;
        client.take_request();
        this.h1_download = Some(client);
        let mut request = self.build_request(
            scheme,
            authority,
            "GET",
            Some(&this.session_id),
            None,
            false,
        )?;
        let gzip = xhttp_gzip::request_h1(&mut request);
        let mut head_bytes = Vec::with_capacity(256);
        h1io::write_head(
            &mut head_bytes,
            &request,
            authority,
            h1io::Framing::None,
            true,
        );
        io.write_all(&head_bytes).await?;
        io.flush().await?;
        this.spawn_download_stream(io, gzip);
        Ok(())
    }

    async fn open_h1_upload(
        &self,
        this: &mut SplitConn,
        scheme: &str,
        authority: &str,
        mode: Mode,
        dialer: std::sync::Arc<Dialer>,
        first_connection: Option<AnyStream>,
    ) -> io::Result<()> {
        let client = if self.download.is_some() {
            self.pool.h1_session().await
        } else {
            this.h1_download
                .as_ref()
                .expect("shared H1 download reserved first")
                .clone()
        };
        this._h1_upload = Some(client.clone());
        if mode == Mode::StreamUp {
            client.take_request();
            let mut request = self.build_request(
                scheme,
                authority,
                &self.meta.uplink_method,
                Some(&this.session_id),
                None,
                true,
            )?;
            let io = match first_connection {
                Some(io) => io,
                None => (dialer)().await?,
            };
            xhttp_gzip::request_h1(&mut request);
            let (io, resp) = h1io::Stream::start(io, &request, authority, true).await?;
            let failure = Failure::default();
            this.up = Up::Stream(Box::new(StreamUp {
                io,
                failure: failure.clone(),
            }));
            this.spawn_upload_ack(resp, failure);
        } else {
            this.spawn_packets_up(PostWriter {
                cfg: self.clone(),
                scheme: scheme.to_string(),
                authority: authority.to_string(),
                session_id: this.session_id.clone(),
                seq: 0,
                dialer,
                h2_client: None,
                h3_client: None,
                h1_client: Some(client),
                first_connection,
            });
        }
        Ok(())
    }
}

/// What an upload request's response said, once the task behind it has seen it.
///
/// The error lives behind a lock rather than in the write path because it
/// arrives on somebody else's task. Failure is terminal and remains visible
/// to later writes and flushes.
#[derive(Clone, Default)]
struct Failure(std::sync::Arc<std::sync::Mutex<Option<io::Error>>>);

impl Failure {
    fn set(&self, e: io::Error) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(e);
        }
    }

    fn error(&self) -> Option<io::Error> {
        self.0.lock().ok().and_then(|slot| {
            slot.as_ref()
                .map(|error| io::Error::new(error.kind(), error.to_string()))
        })
    }
}

/// One streamed upload POST over HTTP/1.1: the request body goes up while a
/// task reads the response.
struct StreamUp {
    io: h1io::Stream,
    failure: Failure,
}

/// One streamed upload POST over HTTP/2: the request body goes up on an H2
/// stream while an ack task checks the response status and drains any body.
struct H2StreamUp {
    io: super::h2io::H2Io,
    failure: Failure,
}

type H2Redial = (std::sync::Arc<H2Counter>, std::sync::Arc<Dialer>);

struct H2PacketClient {
    sender: h2::client::SendRequest<Bytes>,
    redial: Option<H2Redial>,
    replacement: Option<std::sync::Arc<CounterGuard>>,
}

impl H2PacketClient {
    async fn next(&mut self, cfg: &XhttpConfig) -> io::Result<h2::client::SendRequest<Bytes>> {
        let Some((counter, dialer)) = &mut self.redial else {
            return Ok(self.sender.clone());
        };
        if !counter.try_take_packet() {
            let (sender, guard) = cfg.pooled_connection(1, None, dialer()).await?;
            *counter = guard.counter().clone();
            self.replacement = Some(std::sync::Arc::new(guard));
            self.sender = sender;
        }
        Ok(self.sender.clone())
    }
}

fn no_h1_dialer() -> std::sync::Arc<Dialer> {
    std::sync::Arc::new(|| {
        Box::pin(async { Err(io::Error::other("xhttp: unexpected HTTP/1.1 packet dial")) })
    })
}

struct H3Endpoint {
    tls: TlsOptions,
    server: String,
    port: u16,
    dial: DialOptions,
}

impl H3Endpoint {
    fn new(tls: &TlsOptions, server: &str, port: u16, dial: &DialOptions) -> Self {
        Self {
            tls: tls.clone(),
            server: server.into(),
            port,
            dial: dial.clone(),
        }
    }
}

struct H3PacketClient {
    lease: xhttp_h3::Lease,
    endpoint: H3Endpoint,
}

impl H3PacketClient {
    async fn start(
        &mut self,
        cfg: &XhttpConfig,
        mut request: http::Request<()>,
        payload: Bytes,
    ) -> io::Result<PacketResponse> {
        if !self.lease.try_take_packet() {
            let ep = &self.endpoint;
            self.lease = cfg
                .h3_pool()
                .acquire(&ep.tls, &ep.server, ep.port, &ep.dial)
                .await?;
            self.lease.take_requests(1);
        }
        super::xhttp_gzip::request_h3(&mut request);
        Ok(Box::pin(self.lease.start_post(request, payload).await?))
    }
}

type PacketResponse = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;

struct PostWriter {
    cfg: XhttpConfig,
    scheme: String,
    authority: String,
    session_id: String,
    seq: u64,
    dialer: std::sync::Arc<Dialer>,
    h2_client: Option<H2PacketClient>,
    h3_client: Option<Box<H3PacketClient>>,
    first_connection: Option<AnyStream>,
    h1_client: Option<super::xmux::H1Session>,
}

impl PostWriter {
    /// Reserve the next packet on the selected XMUX client, then borrow an
    /// idle socket from that client. A busy or empty socket pool can dial
    /// another socket without creating a new logical XMUX client.
    async fn h1_connection(&mut self) -> io::Result<AnyStream> {
        if !self
            .h1_client
            .as_ref()
            .is_some_and(super::xmux::H1Session::try_take_packet)
        {
            let client = self.cfg.pool.h1_session().await;
            client.take_request();
            self.h1_client = Some(client);
        }
        let client = self.h1_client.as_ref().expect("H1 packet client selected");
        match self
            .first_connection
            .take()
            .or_else(|| client.take_socket())
        {
            Some(io) => Ok(io),
            None => (self.dialer)().await,
        }
    }

    /// Submit the request body as H2 flow control permits, then leave the
    /// response running independently of the next POST.
    async fn start_packet_h2(
        client: h2::client::SendRequest<Bytes>,
        mut req: http::Request<()>,
        payload: Bytes,
        lease: Option<std::sync::Arc<CounterGuard>>,
    ) -> io::Result<PacketResponse> {
        let mut client = client
            .ready()
            .await
            .map_err(|e| io::Error::other(format!("xhttp: h2 post ready: {e}")))?;
        let end_of_stream = payload.is_empty();
        super::xhttp_gzip::request(&mut req);
        if !end_of_stream || matches!(req.method().as_str(), "POST" | "PUT" | "PATCH") {
            // Go's client states the length of a body it knows
            req.headers_mut()
                .insert(http::header::CONTENT_LENGTH, payload.len().into());
        }
        let (response, mut send) = client
            .send_request(req, end_of_stream)
            .map_err(|e| io::Error::other(format!("xhttp: h2 post send_request: {e}")))?;
        if !end_of_stream {
            let mut data = payload;
            while !data.is_empty() {
                let rem = data.len();
                send.reserve_capacity(rem);
                let cap = if send.capacity() > 0 {
                    send.capacity()
                } else {
                    std::future::poll_fn(|cx| send.poll_capacity(cx))
                        .await
                        .ok_or_else(|| io::Error::other("xhttp: h2 post stream closed"))?
                        .map_err(|e| io::Error::other(format!("xhttp: h2 post capacity: {e}")))?
                };
                if cap == 0 {
                    continue;
                }
                let n = cap.min(rem);
                let chunk = data.split_to(n);
                let eos = data.is_empty();
                send.send_data(chunk, eos)
                    .map_err(|e| io::Error::other(format!("xhttp: h2 post send_data: {e}")))?;
            }
        }
        Ok(Box::pin(async move {
            // A later packet may rotate XMUX while this response still needs
            // the old connection's driver.
            let _lease = lease;
            let resp = response
                .await
                .map_err(|e| io::Error::other(format!("xhttp: h2 post response: {e}")))?;
            if resp.status().as_u16() != 200 {
                return Err(io::Error::other(format!(
                    "xhttp: h2 post status: {}",
                    resp.status()
                )));
            }
            let mut body = resp.into_body();
            while let Some(chunk) = body.data().await {
                let bytes =
                    chunk.map_err(|e| io::Error::other(format!("xhttp: h2 post body: {e}")))?;
                let _ = body.flow_control().release_capacity(bytes.len());
            }
            Ok(())
        }))
    }

    /// Send one upload chunk as a single sequenced POST (reference
    /// `packetConn.sendPacket`).
    #[cfg(test)]
    async fn send_packet(&mut self, chunk: &[u8]) -> io::Result<()> {
        self.start_packet(chunk, None).await?.await
    }

    /// `body` may share the worker's immutable buffer for H2 Body uploads.
    /// Borrowed callers and header/cookie placements keep their existing path.
    async fn start_packet(
        &mut self,
        chunk: &[u8],
        body: Option<Bytes>,
    ) -> io::Result<PacketResponse> {
        let seq = self.seq;
        self.seq += 1;
        // One line per packet-up POST: which sequence number went out and how much
        // of the caller's stream it carried. XHTTP turns every write into a packet,
        // so this is the only place that can say whether what left matches what was
        // handed in -- and a server that reads one buffer and parses the request out
        // of it is very sensitive to a head arriving twice.
        crate::logging::debug(format_args!(
            "xhttp POST seq={seq} session={} bytes={} placement={:?}",
            self.session_id,
            chunk.len(),
            self.cfg.meta.uplink_data
        ));
        let payload = match self.cfg.meta.uplink_data {
            UplinkPlacement::Body => Some(body.unwrap_or_else(|| Bytes::copy_from_slice(chunk))),
            UplinkPlacement::Header | UplinkPlacement::Cookie => None,
        };
        let mut req = self.cfg.build_request(
            &self.scheme,
            &self.authority,
            &self.cfg.meta.uplink_method,
            Some(&self.session_id),
            Some(&seq.to_string()),
            payload.is_some(),
        )?;
        // header/cookie payload: base64url chunks under <key>-<i> / <key>_<i>.
        // Only when the payload is not in the body: with `Body` placement the same
        // bytes in a header as well reach the far end twice, and Xray 26.9 reads
        // both (25.9 only reads the body, which is why this looked healthy).
        let mut pieces: Vec<&str> = Vec::new();
        let b64 = if payload.is_none() {
            base64_url(chunk)
        } else {
            String::new()
        };
        if payload.is_none() {
            let bytes = b64.as_bytes();
            let mut at = 0;
            while at < bytes.len() {
                let chunk_size = self.cfg.meta.uplink_chunk.rand().max(1) as usize;
                let end = (at + chunk_size).min(bytes.len());
                pieces.push(std::str::from_utf8(&bytes[at..end]).expect("base64 ascii"));
                at = end;
            }
            if pieces.is_empty() {
                pieces.push("");
            }
        }
        for (i, piece) in pieces.iter().enumerate() {
            let name = match self.cfg.meta.uplink_data {
                UplinkPlacement::Cookie => format!("{}_{}", self.cfg.meta.uplink_key, i),
                _ => format!("{}-{}", self.cfg.meta.uplink_key, i),
            };
            let hname = http::HeaderName::try_from(name.as_str())
                .map_err(|e| io::Error::other(format!("xhttp: header name: {e}")))?;
            if let UplinkPlacement::Cookie = self.cfg.meta.uplink_data {
                if let Some(h) = req.headers_mut().get_mut("cookie") {
                    let mut v = h.as_bytes().to_vec();
                    v.extend_from_slice(format!("; {}={}", name, piece).as_bytes());
                    *h = v
                        .try_into()
                        .map_err(|e| io::Error::other(format!("xhttp: cookie: {e}")))?;
                    continue;
                }
                let value = http::HeaderValue::from_str(&format!("{name}={piece}"))
                    .map_err(|e| io::Error::other(format!("xhttp: cookie: {e}")))?;
                req.headers_mut().insert("cookie", value);
            } else {
                let hvalue = http::HeaderValue::try_from(*piece)
                    .map_err(|e| io::Error::other(format!("xhttp: header value: {e}")))?;
                req.headers_mut().insert(hname, hvalue);
            }
        }
        let payload = payload.unwrap_or_default();

        if let Some(h2_client) = &mut self.h2_client {
            let sender = h2_client.next(&self.cfg).await?;
            return Self::start_packet_h2(sender, req, payload, h2_client.replacement.clone())
                .await;
        }

        if let Some(h3_client) = &mut self.h3_client {
            return h3_client.start(&self.cfg, req, payload).await;
        }

        let mut io = self.h1_connection().await?;
        h1io::write_request(&mut io, &req, &self.authority, &payload, false)
            .await
            .map_err(|e| io::Error::other(format!("xhttp: send packet: {e}")))?;
        let client = self
            .h1_client
            .as_ref()
            .expect("H1 packet client selected")
            .clone();
        // Never replay a POST after an ambiguous response failure: the peer
        // may already have accepted this sequence and its payload.
        Ok(Box::pin(async move {
            let (head, pending) = h1io::read_head(&mut io).await?;
            h1io::expect_ok(&head, "upload")?;
            let mut body = h1io::Body::new(io, &head, pending);
            body.drain().await?;
            if let Some(io) = body.into_inner() {
                client.return_socket(io);
            }
            Ok(())
        }))
    }
}

struct SplitConn {
    h1_download: Option<super::xmux::H1Session>,
    _h1_upload: Option<super::xmux::H1Session>,
    /// The rest of the last download chunk.
    pending: Bytes,
    /// A download error met by a read that already returned data; the next
    /// read reports it.
    dl_error: Option<io::Error>,
    dl: mpsc::Receiver<io::Result<Bytes>>,
    direct_h2: Option<DirectH2Download>,
    dl_task: Option<JoinHandle<()>>,
    ack_task: Option<JoinHandle<()>>,
    h2_upload_driver: Option<JoinHandle<()>>,
    up: Up,
    session_id: String,
    /// Armed when a packet-up upload is shut down; see [`HALF_CLOSE_IDLE`].
    half_closed: Option<HalfClosed>,
    half_close_limit: std::time::Duration,
    /// The read that last returned Pending without a limit armed. Shutdown
    /// may run in another task; arming the limit wakes this read so that it
    /// starts polling the timer.
    read_waker: Option<std::task::Waker>,
}

/// The GET response is driven by its consumer. The shared H2 connection still
/// sends the request immediately, so an upload can precede response headers.
/// Keep chunks as Bytes without a pump task/channel. Credit follows actual
/// consumption, in at most Xray-sized 8 KiB reads, with bounded exact updates.
struct DirectH2Download {
    response: Option<Pin<Box<h2::client::ResponseFuture>>>,
    body: Option<h2::RecvStream>,
    /// One consumed quantum awaiting space in H2's bounded control queue.
    credit_due: usize,
    request_gzip: bool,
    gzip: Option<Box<xhttp_gzip::H2Decoder>>,
}

impl DirectH2Download {
    fn poll_credit(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.credit_due == 0 {
            return Poll::Ready(Ok(()));
        }
        let body = self.body.as_mut().expect("consumed DATA retains its body");
        ready!(
            body.flow_control()
                .poll_release_capacity_exact(cx, self.credit_due)
        )
        .map_err(|e| io::Error::other(format!("xhttp: h2 consumed credit: {e}")))?;
        self.credit_due = 0;
        Poll::Ready(Ok(()))
    }

    fn poll_next(&mut self, cx: &mut Context<'_>) -> Poll<Option<io::Result<Bytes>>> {
        if let Some(response) = &mut self.response {
            let result = ready!(response.as_mut().poll(cx));
            self.response = None;
            match result {
                Ok(response) if response.status().as_u16() == 200 => {
                    if self.request_gzip
                        && xhttp_gzip::encoded(response.headers())
                        && !response.body().is_end_stream()
                    {
                        self.gzip = Some(Box::new(xhttp_gzip::H2Decoder::new()));
                    }
                    self.body = Some(response.into_body());
                }
                Ok(response) => {
                    return Poll::Ready(Some(Err(io::Error::other(format!(
                        "xhttp: h2 download status: {}",
                        response.status()
                    )))));
                }
                Err(e) => {
                    return Poll::Ready(Some(Err(io::Error::other(format!(
                        "xhttp: h2 download response: {e}"
                    )))));
                }
            }
        }
        let Some(body) = &mut self.body else {
            return Poll::Ready(None);
        };
        if let Some(gzip) = &mut self.gzip {
            let mut buf = [0; GO_BODY_CHUNK];
            let mut out = ReadBuf::new(&mut buf);
            let next = match ready!(gzip.poll_read(cx, body, &mut out, true)) {
                Ok(()) if !out.filled().is_empty() => {
                    return Poll::Ready(Some(Ok(Bytes::copy_from_slice(out.filled()))));
                }
                Ok(()) => None,
                Err(error) => Some(Err(error)),
            };
            self.body = None;
            return Poll::Ready(next);
        }
        loop {
            match ready!(body.poll_data(cx)) {
                Some(Ok(bytes)) => {
                    if !bytes.is_empty() {
                        return Poll::Ready(Some(Ok(bytes)));
                    }
                }
                Some(Err(e)) => {
                    self.body = None;
                    return Poll::Ready(Some(Err(io::Error::other(format!(
                        "xhttp: h2 download body: {e}"
                    )))));
                }
                None => {
                    // Retain the stream until consumed credit reaches the wire;
                    // dropping it first could suppress the final queued updates.
                    ready!(body.flow_control().poll_exact_credit_flushed(cx));
                    self.body = None;
                    return Poll::Ready(None);
                }
            }
        }
    }
}

/// The idle limit of a half-closed packet-up session. The timer is re-armed
/// lazily from `last_rx` when it fires, not on every chunk.
struct HalfClosed {
    timer: Pin<Box<tokio::time::Sleep>>,
    last_rx: tokio::time::Instant,
    limit: std::time::Duration,
}

impl HalfClosed {
    fn new(limit: std::time::Duration) -> Self {
        let now = tokio::time::Instant::now();
        Self {
            timer: Box::pin(tokio::time::sleep_until(now + limit)),
            last_rx: now,
            limit,
        }
    }

    /// Ready once `limit` has passed with no download traffic.
    fn poll_expired(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        loop {
            ready!(self.timer.as_mut().poll(cx));
            let due = self.last_rx + self.limit;
            if due <= tokio::time::Instant::now() {
                return Poll::Ready(());
            }
            self.timer.as_mut().reset(due);
        }
    }
}

/// One packet-up upload stream: pipe into background upload worker.
struct PacketsUp {
    io: tokio::io::DuplexStream,
    failure: Failure,
    bytes_written: std::sync::Arc<portable_atomic::AtomicU64>,
    bytes_flushed: std::sync::Arc<portable_atomic::AtomicU64>,
    flush_notify: std::sync::Arc<tokio::sync::Notify>,
    flush_wait: Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
    task: tokio::task::JoinHandle<()>,
}

enum Up {
    Stream(Box<StreamUp>),
    H2Stream(Box<H2StreamUp>),
    H3(AnyStream),
    Packets(Box<PacketsUp>),
    None,
}

impl SplitConn {
    fn new(cfg: &XhttpConfig) -> Self {
        let session_id = new_session_id(&cfg.meta);
        let (_, dl) = mpsc::channel(4);
        Self {
            h1_download: None,
            _h1_upload: None,
            pending: Bytes::new(),
            dl_error: None,
            dl,
            direct_h2: None,
            dl_task: None,
            ack_task: None,
            h2_upload_driver: None,
            up: Up::None,
            session_id,
            half_closed: None,
            half_close_limit: cfg.half_close_idle,
            read_waker: None,
        }
    }

    fn spawn_packets_up(&mut self, writer: PostWriter) {
        let (io, worker_read) = tokio::io::duplex(128 * 1024);
        let failure = Failure::default();
        let bytes_written = std::sync::Arc::new(portable_atomic::AtomicU64::new(0));
        let bytes_flushed = std::sync::Arc::new(portable_atomic::AtomicU64::new(0));
        let flush_notify = std::sync::Arc::new(tokio::sync::Notify::new());
        let task = tokio::spawn(packet_upload_worker(
            worker_read,
            writer,
            failure.clone(),
            std::sync::Arc::clone(&bytes_flushed),
            std::sync::Arc::clone(&flush_notify),
        ));
        self.up = Up::Packets(Box::new(PacketsUp {
            io,
            failure,
            bytes_written,
            bytes_flushed,
            flush_notify,
            flush_wait: None,
            task,
        }));
    }

    /// End the whole session: cancel the download request (an HTTP/1.1
    /// download connection is closed, an HTTP/2 stream is reset) and stop
    /// the upload. The caller can still read the retained download chunk.
    fn finish(&mut self) {
        self.direct_h2 = None;
        if let Some(task) = self.dl_task.take() {
            task.abort();
        }
        if let Some(ack) = self.ack_task.take() {
            ack.abort();
        }
        if let Some(driver) = self.h2_upload_driver.take() {
            driver.abort();
        }
        if let Up::Packets(state) = &mut self.up {
            state.task.abort();
        }
        self.dl.close();
        self.half_closed = None;
    }

    /// Read GET headers concurrently with upload; a server may await the
    /// first VLESS payload before answering the download request.
    fn spawn_download_stream(&mut self, mut io: AnyStream, gzip: bool) {
        let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(4);
        self.dl = rx;
        self.dl_task = Some(tokio::spawn(async move {
            let (head, pending) = match h1io::read_head(&mut io).await {
                Ok(response) => response,
                Err(error) => {
                    let _ = tx
                        .send(Err(io::Error::other(format!(
                            "xhttp: download head: {error}"
                        ))))
                        .await;
                    return;
                }
            };
            if let Err(error) = h1io::expect_ok(&head, "download") {
                let _ = tx.send(Err(error)).await;
                return;
            }
            pump_h1(h1io::Body::new(io, &head, pending), tx, gzip).await;
        }));
    }

    fn set_h2_download_stream(&mut self, response: h2::client::ResponseFuture, gzip: bool) {
        self.direct_h2 = Some(DirectH2Download {
            response: Some(Box::pin(response)),
            body: None,
            credit_due: 0,
            request_gzip: gzip,
            gzip: None,
        });
    }

    /// The upload request's response when it *is* the download stream, which is
    /// what stream-one does: one request, body up and body down.
    fn spawn_upload_download(&mut self, response: h1io::Response, failure: Failure, gzip: bool) {
        let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(4);
        self.dl = rx;
        self.dl_task = Some(tokio::spawn(async move {
            match response.read().await {
                Ok(body) => pump_h1(body, tx, gzip).await,
                Err(e) => {
                    failure.set(io::Error::new(e.kind(), e.to_string()));
                    let _ = tx.send(Err(e)).await;
                }
            }
        }));
    }

    /// The upload request's response when nothing comes back through it, which
    /// is stream-up: the download has a connection of its own, so this response
    /// only says whether the server took the request. Drain it and keep a
    /// failure for the next write.
    fn spawn_upload_ack(&mut self, response: h1io::Response, failure: Failure) {
        if let Some(old) = self.ack_task.take() {
            old.abort();
        }
        self.ack_task = Some(tokio::spawn(async move {
            let mut body = match response.read().await {
                Ok(body) => body,
                Err(e) => {
                    failure.set(e);
                    return;
                }
            };
            if let Err(e) = body.drain().await {
                failure.set(e);
            }
        }));
    }

    /// Watch an HTTP/2 `stream-up` upload stream's response status and drain its body.
    fn spawn_h2_upload_ack(&mut self, response: h2::client::ResponseFuture, failure: Failure) {
        if let Some(old) = self.ack_task.take() {
            old.abort();
        }
        self.ack_task = Some(tokio::spawn(async move {
            let resp = match response.await {
                Ok(r) => r,
                Err(e) => {
                    failure.set(io::Error::other(format!("xhttp: h2 upload: {e}")));
                    return;
                }
            };
            if resp.status().as_u16() != 200 {
                failure.set(io::Error::other(format!(
                    "xhttp: h2 upload status: {}",
                    resp.status()
                )));
                return;
            }
            let mut body = resp.into_body();
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(bytes) => {
                        let _ = body.flow_control().release_capacity(bytes.len());
                    }
                    Err(e) => {
                        failure.set(io::Error::other(format!("xhttp: h2 upload body: {e}")));
                        return;
                    }
                }
            }
        }));
    }
}

/// Read a response body into the download channel. Channel close is EOF.
async fn pump_h1(body: h1io::Body, tx: mpsc::Sender<io::Result<Bytes>>, gzip: bool) {
    if gzip && body.is_gzip() {
        pump(xhttp_gzip::Reader::new(body), tx).await;
    } else {
        pump(body, tx).await;
    }
}

async fn pump(mut body: impl AsyncRead + Unpin, tx: mpsc::Sender<io::Result<Bytes>>) {
    const READ: usize = 16 * 1024;
    let mut buf = BytesMut::new();
    loop {
        buf.reserve(READ);
        let mut room = bytes::BufMut::limit(&mut buf, READ);
        match body.read_buf(&mut room).await {
            Ok(0) => break,
            Ok(_) => {}
            Err(e) => {
                let _ = tx.send(Err(e)).await;
                return;
            }
        }
        if tx.send(Ok(buf.split().freeze())).await.is_err() {
            return;
        }
    }
}

impl AsyncRead for XhttpConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let split = &mut *self.split;
        if out.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if let Some(e) = split.dl_error.take() {
            return Poll::Ready(Err(e));
        }
        // Fill the buffer from the chunks already queued; whatever ends the
        // download after some data waits for the next read.
        let mut filled = false;
        loop {
            let credit_ready = match &mut split.direct_h2 {
                Some(download) => match download.poll_credit(cx) {
                    Poll::Ready(Ok(())) => true,
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => false,
                },
                None => true,
            };
            if credit_ready && !split.pending.is_empty() {
                let mut n = out.remaining().min(split.pending.len());
                if split.direct_h2.is_some() {
                    n = n.min(8192);
                }
                out.put_slice(&split.pending[..n]);
                bytes::Buf::advance(&mut split.pending, n);
                filled = true;
                if let Some(download) = &mut split.direct_h2 {
                    if download.gzip.is_none() {
                        download.credit_due = n;
                        if let Poll::Ready(Err(e)) = download.poll_credit(cx) {
                            split.dl_error = Some(e);
                        }
                    }
                    // A full control queue stalls the NEXT read, never bytes
                    // already copied. Pending below still polls half-close time.
                    return Poll::Ready(Ok(()));
                }
                if out.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            let next = match &mut split.direct_h2 {
                Some(_) if !credit_ready => Poll::Pending,
                Some(download) => download.poll_next(cx),
                None => split.dl.poll_recv(cx),
            };
            match next {
                Poll::Ready(Some(Ok(chunk))) => {
                    if let Some(idle) = &mut split.half_closed {
                        idle.last_rx = tokio::time::Instant::now();
                    }
                    split.pending = chunk;
                }
                Poll::Ready(Some(Err(e))) => {
                    if filled {
                        split.dl_error = Some(e);
                        return Poll::Ready(Ok(()));
                    }
                    return Poll::Ready(Err(e));
                }
                // EOF; a closed channel stays closed for the next read
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending if filled => return Poll::Ready(Ok(())),
                Poll::Pending => {
                    let Some(idle) = &mut split.half_closed else {
                        if !split
                            .read_waker
                            .as_ref()
                            .is_some_and(|waker| waker.will_wake(cx.waker()))
                        {
                            split.read_waker = Some(cx.waker().clone());
                        }
                        return Poll::Pending;
                    };
                    ready!(idle.poll_expired(cx));
                    crate::logging::debug(format_args!(
                        "xhttp: session {} half-closed and idle for {:?}, closing",
                        split.session_id, idle.limit
                    ));
                    split.finish();
                    if split.pending.is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    // Credit backpressure may have stopped a partial H2 read.
                    // The canceled stream no longer needs credit to drain it.
                }
            }
        }
    }
}

impl AsyncWrite for XhttpConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let split = &mut *self.split;
        match &mut split.up {
            Up::Stream(state) => {
                // a refused upload POST is reported here, not on the write that
                // was already in flight when the answer came back
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                Pin::new(&mut state.io).poll_write(cx, buf)
            }
            Up::H2Stream(state) => {
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                Pin::new(&mut state.io).poll_write(cx, buf)
            }
            Up::H3(io) => Pin::new(io).poll_write(cx, buf),
            Up::Packets(state) => {
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                let res = Pin::new(&mut state.io).poll_write(cx, buf);
                if let Poll::Ready(Ok(n)) = &res {
                    state
                        .bytes_written
                        .fetch_add(*n as u64, std::sync::atomic::Ordering::Relaxed);
                }
                res
            }
            Up::None => Poll::Ready(Err(io::Error::other("xhttp: no upload stream"))),
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let split = &mut *self.split;
        match &mut split.up {
            Up::Stream(state) => {
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                Pin::new(&mut state.io).poll_flush(cx)
            }
            Up::H2Stream(state) => {
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                Pin::new(&mut state.io).poll_flush(cx)
            }
            Up::H3(io) => Pin::new(io).poll_flush(cx),
            Up::Packets(state) => {
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                let written = state
                    .bytes_written
                    .load(std::sync::atomic::Ordering::Relaxed);
                let flushed = state
                    .bytes_flushed
                    .load(std::sync::atomic::Ordering::Relaxed);
                if flushed >= written {
                    state.flush_wait = None;
                    return Pin::new(&mut state.io).poll_flush(cx);
                }
                if state.flush_wait.is_none() {
                    let notify = std::sync::Arc::clone(&state.flush_notify);
                    state.flush_wait = Some(Box::pin(async move {
                        notify.notified().await;
                    }));
                }
                if let Some(fut) = &mut state.flush_wait {
                    let notified = fut.as_mut().poll(cx);
                    // The worker can complete (or fail) between the first
                    // counter check and registration of this notification.
                    // Recheck after polling, when the waiter is registered.
                    if let Some(e) = state.failure.error() {
                        return Poll::Ready(Err(e));
                    }
                    if state
                        .bytes_flushed
                        .load(std::sync::atomic::Ordering::Acquire)
                        >= written
                    {
                        state.flush_wait = None;
                        return Pin::new(&mut state.io).poll_flush(cx);
                    }
                    match notified {
                        Poll::Ready(()) => {
                            state.flush_wait = None;
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                        Poll::Pending => Poll::Pending,
                    }
                } else {
                    Poll::Pending
                }
            }
            Up::None => Poll::Ready(Ok(())),
        }
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if matches!(self.split.up, Up::Packets(_)) {
            ready!(self.as_mut().poll_flush(cx))?;
        }
        let split = &mut *self.split;
        match &mut split.up {
            Up::Stream(state) => {
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                ready!(Pin::new(&mut state.io).poll_shutdown(cx))?;
            }
            Up::H2Stream(state) => {
                if let Some(e) = state.failure.error() {
                    return Poll::Ready(Err(e));
                }
                ready!(Pin::new(&mut state.io).poll_shutdown(cx))?;
            }
            Up::H3(io) => ready!(Pin::new(io).poll_shutdown(cx))?,
            Up::Packets(state) => {
                ready!(Pin::new(&mut state.io).poll_shutdown(cx))?;
                // Nothing on the wire says the upload ended, so the download
                // may never end by itself. Keep reading it while it moves.
                if split.half_closed.is_none() {
                    split.half_closed = Some(HalfClosed::new(split.half_close_limit));
                    if let Some(waker) = split.read_waker.take() {
                        waker.wake();
                    }
                }
            }
            Up::None => {}
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for SplitConn {
    fn drop(&mut self) {
        if let Some(task) = self.dl_task.take() {
            task.abort();
        }
        if let Some(ack) = self.ack_task.take() {
            ack.abort();
        }
        if let Some(driver) = self.h2_upload_driver.take() {
            driver.abort();
        }
        if let Up::Packets(state) = &mut self.up {
            state.task.abort();
        }
    }
}

/// Recover only uniquely owned storage. An early response can leave H2 holding
/// DATA references; fall back to copying for the rest of this session rather
/// than accumulating full-size shared buffers on subsequent small POSTs.
fn reclaim_upload_buffer(owner: Bytes, size: usize, reuse: &mut bool) -> BytesMut {
    match owner.try_into_mut() {
        Ok(buf) => buf,
        Err(_) => {
            *reuse = false;
            BytesMut::zeroed(size)
        }
    }
}

type PendingPacket = Pin<Box<dyn Future<Output = PacketAck> + Send>>;

struct PacketAck {
    seq: u64,
    len: usize,
    buffer: Option<Bytes>,
    result: io::Result<()>,
}

struct PacketAcks<'a> {
    responses: Vec<PendingPacket>,
    ordered: std::collections::VecDeque<Option<usize>>,
    first_seq: u64,
    buffer: Option<BytesMut>,
    reuse_h2_body: bool,
    max_packet: usize,
    bytes_flushed: &'a portable_atomic::AtomicU64,
    flush_notify: &'a tokio::sync::Notify,
}

impl PacketAcks<'_> {
    fn push(&mut self, len: usize, buffer: Option<Bytes>, response: PacketResponse) {
        let seq = self.first_seq + self.ordered.len() as u64;
        self.ordered.push_back(None);
        self.responses.push(Box::pin(async move {
            let result = response.await;
            PacketAck {
                seq,
                len,
                buffer,
                result,
            }
        }));
    }

    fn acknowledge(&mut self, ack: PacketAck) -> io::Result<()> {
        ack.result?;
        if let Some(buffer) = ack.buffer
            && self.buffer.is_none()
        {
            self.buffer = Some(reclaim_upload_buffer(
                buffer,
                self.max_packet,
                &mut self.reuse_h2_body,
            ));
        }
        self.ordered[(ack.seq - self.first_seq) as usize] = Some(ack.len);

        // Responses can complete out of order. Flush only covers the
        // contiguous prefix acknowledged by the peer.
        let mut confirmed = 0;
        while let Some(Some(len)) = self.ordered.front() {
            confirmed += *len as u64;
            self.ordered.pop_front();
            self.first_seq += 1;
        }
        if confirmed != 0 {
            self.bytes_flushed
                .fetch_add(confirmed, std::sync::atomic::Ordering::Release);
            self.flush_notify.notify_waiters();
        }
        Ok(())
    }

    fn poll_ack(&mut self, cx: &mut Context<'_>) -> Poll<PacketAck> {
        // At most eight responses share the upload worker's waker.
        for (index, response) in self.responses.iter_mut().enumerate() {
            if let Poll::Ready(ack) = response.as_mut().poll(cx) {
                drop(self.responses.swap_remove(index));
                return Poll::Ready(ack);
            }
        }
        Poll::Pending
    }

    async fn advance(&mut self) -> io::Result<()> {
        let ack = std::future::poll_fn(|cx| self.poll_ack(cx)).await;
        self.acknowledge(ack)
    }

    /// Keep draining responses during input reads, pacing and submitting the
    /// next request. A later error can stop the upload even if an older
    /// response is still pending.
    async fn while_waiting<T>(
        &mut self,
        operation: impl Future<Output = io::Result<T>>,
    ) -> io::Result<T> {
        tokio::pin!(operation);
        loop {
            tokio::select! {
                biased;
                ack = std::future::poll_fn(|cx| self.poll_ack(cx)) => self.acknowledge(ack)?,
                result = &mut operation => return result,
            }
        }
    }
}

/// Submit packets in order without blocking the next request on the previous
/// response. The bounded window also limits sequence reordering at the peer.
async fn packet_upload_worker(
    mut reader: tokio::io::DuplexStream,
    mut writer: PostWriter,
    failure: Failure,
    bytes_flushed: std::sync::Arc<portable_atomic::AtomicU64>,
    flush_notify: std::sync::Arc<tokio::sync::Notify>,
) {
    let max_each = writer.cfg.meta.sc_max_each_post.rand().max(1) as usize;
    // Limit both pending requests and their aggregate payload size. A
    // configured POST exceeding the byte budget still fits in one slot.
    let window = (4 * 1024 * 1024 / max_each).clamp(1, 8);
    let mut acks = PacketAcks {
        responses: Vec::with_capacity(window),
        ordered: std::collections::VecDeque::with_capacity(window),
        first_seq: 0,
        buffer: None,
        reuse_h2_body: writer.h2_client.is_some()
            && writer.cfg.meta.uplink_data == UplinkPlacement::Body,
        max_packet: max_each,
        bytes_flushed: &bytes_flushed,
        flush_notify: &flush_notify,
    };
    let result = pipeline_packets(&mut reader, &mut writer, &mut acks, window).await;
    if let Err(e) = result {
        crate::logging::debug(format_args!("xhttp packet upload failed: {e}"));
        failure.set(e);
    }
    flush_notify.notify_waiters();
}

async fn pipeline_packets(
    reader: &mut tokio::io::DuplexStream,
    writer: &mut PostWriter,
    acks: &mut PacketAcks<'_>,
    window: usize,
) -> io::Result<()> {
    let mut last_post = None;
    loop {
        while acks.ordered.len() >= window {
            acks.advance().await?;
        }
        let mut buf = acks
            .buffer
            .take()
            .unwrap_or_else(|| BytesMut::zeroed(acks.max_packet));
        let mut n = acks.while_waiting(reader.read(&mut buf)).await?;
        if n == 0 {
            break;
        }

        let min_interval =
            std::time::Duration::from_millis(writer.cfg.meta.sc_min_interval_ms.rand());
        if let Some(last) = last_post
            && min_interval > std::time::Duration::ZERO
        {
            let deadline = last + min_interval;
            // The configured interval already delays the next POST. Use that
            // time to collect caller bytes, rather than freezing a tiny packet
            // while the duplex pipe fills behind it. Keep the same size bound,
            // interval and sequence ordering; the first packet is immediate.
            while n < buf.len() && tokio::time::Instant::now() < deadline {
                let got = acks
                    .while_waiting(async {
                        tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline) => Ok(0),
                        next = reader.read(&mut buf[n..]) => next,
                        }
                    })
                    .await?;
                if got == 0 {
                    break;
                }
                n += got;
            }
            acks.while_waiting(async {
                tokio::time::sleep_until(deadline).await;
                Ok(())
            })
            .await?;
        }
        last_post = Some(tokio::time::Instant::now());

        if acks.reuse_h2_body {
            let owner = buf.freeze();
            let response = acks
                .while_waiting(writer.start_packet(&owner[..n], Some(owner.slice(..n))))
                .await?;
            acks.push(n, Some(owner), response);
        } else {
            let response = acks
                .while_waiting(writer.start_packet(&buf[..n], None))
                .await?;
            acks.buffer = Some(buf);
            acks.push(n, None, response);
        }
    }
    while !acks.ordered.is_empty() {
        acks.advance().await?;
    }
    Ok(())
}

impl XhttpConfig {
    /// Construct one xhttp request: placement engine (session/seq) first,
    /// then X-Padding (reference `newRequest` → `applyMeta` → `applyXPadding`).
    fn build_request(
        &self,
        scheme: &str,
        authority: &str,
        method: &str,
        session: Option<&str>,
        seq: Option<&str>,
        has_body: bool,
    ) -> io::Result<http::Request<()>> {
        // Xray normalizes the base path from both configured placements,
        // even for requests that carry no seq/session. Append path metadata
        // below; preserve an exact resource when both placements are external.
        let base_path = &self.path;
        let mut path = base_path.clone();
        let mut query = self.query.clone();
        let mut wire_headers = Vec::new();
        let mut cookies = Vec::new();

        let m = &self.meta;
        let pad = self.gen_padding();
        if !m.x_obfs {
            wire_headers.push((
                "referer",
                format!("{scheme}://{authority}{base_path}?x_padding={pad}"),
            ));
        } else {
            match m.x_placement {
                XPlacement::Header => wire_headers.push((m.x_header.as_str(), pad)),
                XPlacement::Query => set_query_value(&mut query, &m.x_key, &pad),
                XPlacement::Cookie => cookies.push(format!("{}={pad}", m.x_key)),
                XPlacement::QueryInHeader => wire_headers.push((
                    m.x_header.as_str(),
                    format!("{scheme}://{authority}{base_path}?{}={pad}", m.x_key),
                )),
            }
        }

        // stream-one targets the bare path (no session id segment).
        for (placement, key, value) in [
            (m.session_placement, m.session_key.as_str(), session),
            (m.seq_placement, m.seq_key.as_str(), seq),
        ] {
            let Some(value) = value.filter(|v| !v.is_empty()) else {
                continue;
            };
            match placement {
                Placement::Path => {
                    if !path.ends_with('/') {
                        path.push('/');
                    }
                    escape_url_component(&mut path, value.as_bytes(), true);
                }
                Placement::Query => set_query_value(&mut query, key, value),
                Placement::Header => wire_headers.push((key, value.to_string())),
                Placement::Cookie => cookies.push(format!("{key}={value}")),
            }
        }

        let mut uri = format!("{scheme}://{authority}{path}");
        if !query.is_empty() {
            uri.push('?');
            uri.push_str(&query);
        }

        let mut builder = http::Request::builder().method(method).uri(uri);
        // Xray's `GetRequestHeader`: with no `User-Agent` configured the
        // request is a Chrome `fetch` (`TryDefaultHeadersWith(header,
        // "fetch")`), one of the profile names picks another browser, and any
        // other `User-Agent` is the user's own and leaves the request as it is.
        let configured_ua = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
            .map(|(_, value)| value.as_str());
        let browser = super::browser::defaults(configured_ua, super::browser::Variant::Fetch);
        for (name, value) in &self.headers {
            if HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str()) {
                continue;
            }
            if browser.replaces(name)
                || (browser.drop_configured_ua && name.eq_ignore_ascii_case("user-agent"))
            {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        for (name, value) in &browser.force {
            builder = builder.header(*name, value.as_str());
        }
        for (name, value) in &browser.fill {
            if !self
                .headers
                .iter()
                .any(|(set, _)| set.eq_ignore_ascii_case(name))
            {
                builder = builder.header(*name, value.as_str());
            }
        }
        let mut request = builder
            .body(())
            .map_err(|e| io::Error::other(format!("xhttp: build request: {e}")))?;
        // A streamed body (stream-one, stream-up) announces itself as gRPC by
        // default (Xray `FillStreamRequest`), and reverse proxies key response
        // streaming on that. A packet-up upload carries no content type at all:
        // Xray's `FillPacketRequest` sets none and Go's client adds none.
        let packet = seq.is_some() || self.mode == Mode::PacketUp;
        if has_body && !self.no_grpc_header && !packet {
            wire_headers.push(("content-type", "application/grpc".to_owned()));
        }
        let headers = request.headers_mut();
        for (name, value) in wire_headers {
            let name = http::HeaderName::try_from(name)
                .map_err(|e| io::Error::other(format!("xhttp: header name: {e}")))?;
            let value = http::HeaderValue::try_from(value)
                .map_err(|e| io::Error::other(format!("xhttp: header value: {e}")))?;
            headers.insert(name, value);
        }
        if !cookies.is_empty() {
            append_cookies(headers, &cookies.join("; "))?;
        }
        Ok(request)
    }

    fn gen_padding(&self) -> String {
        let target = self.padding.rand() as usize;
        if self.meta.x_obfs && self.meta.x_method == PadMethod::Tokenish {
            tokenish(target)
        } else {
            "X".repeat(target)
        }
    }
}

fn append_cookies(headers: &mut http::HeaderMap, cookies: &str) -> io::Result<()> {
    let mut value = Vec::new();
    if let Some(old) = headers.get(http::header::COOKIE) {
        value.extend_from_slice(old.as_bytes());
        if !value.is_empty() {
            value.extend_from_slice(b"; ");
        }
    }
    value.extend_from_slice(cookies.as_bytes());
    let value = http::HeaderValue::from_bytes(&value)
        .map_err(|e| io::Error::other(format!("xhttp: cookie: {e}")))?;
    headers.insert(http::header::COOKIE, value);
    Ok(())
}

/// Go's URL query `Set` replaces all values for the key and emits a sorted query.
fn set_query_value(query: &mut String, key: &str, value: &str) {
    let mut values = std::collections::BTreeMap::<Vec<u8>, Vec<Vec<u8>>>::new();
    for part in query
        .split('&')
        .filter(|part| !part.is_empty() && !part.contains(';'))
    {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        if let (Some(name), Some(value)) =
            (decode_query_component(name), decode_query_component(value))
        {
            values.entry(name).or_default().push(value);
        }
    }
    values.insert(key.as_bytes().to_vec(), vec![value.as_bytes().to_vec()]);
    query.clear();
    for (name, values) in values {
        for value in values {
            if !query.is_empty() {
                query.push('&');
            }
            escape_url_component(query, &name, false);
            query.push('=');
            escape_url_component(query, &value, false);
        }
    }
}

fn decode_query_component(input: &str) -> Option<Vec<u8>> {
    let mut bytes = input.bytes();
    let mut result = Vec::with_capacity(input.len());
    while let Some(b) = bytes.next() {
        result.push(match b {
            b'%' => {
                let hi = char::from(bytes.next()?).to_digit(16)? as u8;
                let lo = char::from(bytes.next()?).to_digit(16)? as u8;
                hi << 4 | lo
            }
            b'+' => b' ',
            _ => b,
        });
    }
    Some(result)
}

fn escape_url_component(out: &mut String, input: &[u8], path: bool) {
    const HEX: &[u8] = b"0123456789ABCDEF";
    for &b in input {
        if b.is_ascii_alphanumeric() || b"-_.~".contains(&b) || (path && b"$&+,/:;=@".contains(&b))
        {
            out.push(char::from(b));
        } else if !path && b == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(char::from(HEX[(b >> 4) as usize]));
            out.push(char::from(HEX[(b & 0xf) as usize]));
        }
    }
}

/// Random dashed-UUID session id (default), or `session_table` /
/// `session_length` drawn characters (reference `newSessionID`).
fn new_session_id(meta: &Meta) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    if meta.session_table.is_empty() || meta.session_len.0 == 0 {
        let mut b = [0u8; 16];
        let _ = crate::util::random_bytes(&mut b);
        b[6] = (b[6] & 0x0f) | 0x40;
        b[8] = (b[8] & 0x3f) | 0x80;
        let mut h = String::with_capacity(36);
        for (i, v) in b.iter().enumerate() {
            if matches!(i, 4 | 6 | 8 | 10) {
                h.push('-');
            }
            h.push(HEX[(v >> 4) as usize] as char);
            h.push(HEX[(v & 0x0f) as usize] as char);
        }
        return h;
    }
    let table: Vec<char> = core_config::xhttp_session_table(&meta.session_table)
        .chars()
        .collect();
    let len = meta.session_len.rand() as usize;
    let mut out = String::with_capacity(len);
    let mut buf = [0u8; 8];
    for _ in 0..len {
        let _ = crate::util::random_bytes(&mut buf);
        out.push(table[u64::from_le_bytes(buf) as usize % table.len()]);
    }
    out
}

pub(crate) const HUF_BITS: [u8; 257] = [
    13, 23, 28, 28, 28, 28, 28, 28, 28, 24, 30, 28, 28, 30, 28, 28, 28, 28, 28, 28, 28, 28, 30, 28,
    28, 28, 28, 28, 28, 28, 28, 28, 6, 10, 10, 12, 13, 6, 8, 11, 10, 10, 8, 11, 8, 6, 6, 6, 5, 5,
    5, 6, 6, 6, 6, 6, 6, 6, 7, 8, 15, 6, 12, 10, 13, 6, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
    7, 7, 7, 7, 7, 7, 7, 7, 8, 7, 8, 13, 19, 13, 14, 6, 15, 5, 6, 5, 6, 5, 6, 6, 6, 5, 7, 7, 6, 6,
    6, 5, 6, 7, 6, 5, 5, 6, 7, 7, 7, 7, 7, 15, 11, 14, 13, 28, 20, 22, 20, 20, 22, 22, 22, 23, 22,
    23, 23, 23, 23, 23, 24, 23, 24, 24, 22, 23, 24, 23, 23, 23, 23, 21, 22, 23, 22, 23, 23, 24, 22,
    21, 20, 22, 22, 23, 23, 21, 23, 22, 22, 24, 21, 22, 23, 23, 21, 21, 22, 21, 23, 22, 23, 23, 20,
    22, 22, 22, 23, 22, 22, 23, 26, 26, 20, 19, 22, 23, 22, 25, 26, 26, 26, 27, 27, 26, 24, 25, 19,
    21, 26, 27, 27, 26, 27, 24, 21, 21, 26, 26, 28, 27, 27, 27, 20, 24, 20, 21, 22, 21, 21, 23, 22,
    22, 25, 25, 24, 24, 26, 23, 26, 27, 26, 26, 27, 27, 27, 27, 27, 28, 27, 27, 27, 27, 27, 26, 30,
];

/// HPACK-Huffman-encoded byte length of `s` (RFC 7541 Appendix B).
fn huffman_len(s: &str) -> usize {
    let bits: usize = s.bytes().map(|b| HUF_BITS[b as usize] as usize).sum();
    bits.div_ceil(8)
}

/// base62 token whose HPACK-Huffman-encoded length lands within ±2 of
/// `target` (reference `GenerateTokenishPaddingBase62`): random base62 of
/// roughly the right raw length, then filler `X`/`Z` (8-bit Huffman codes,
/// stable length) tune the encoded size in, bounded by 150 iterations.
fn tokenish(target: usize) -> String {
    const BASE62: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let rng_byte = || -> u8 {
        let mut b = [0u8; 1];
        let _ = crate::util::random_bytes(&mut b);
        b[0]
    };
    // base62 chars are ~0.8 huffman bytes of entropy each on average.
    let len = target.div_ceil(4) * 5;
    let mut out: String = (0..len)
        .map(|_| BASE62[rng_byte() as usize % 62] as char)
        .collect();
    for _ in 0..150 {
        let enc = huffman_len(&out);
        if enc.abs_diff(target) <= 2 {
            return out;
        }
        if enc < target.saturating_sub(2) {
            out.push(if rng_byte() % 2 == 0 { 'X' } else { 'Z' });
        } else if enc > target + 2 && !out.is_empty() {
            out.pop();
        } else {
            // encoded within ±2 of a neighbor slot — keep rotating the body
            let idx = rng_byte() as usize % out.len();
            out.replace_range(
                idx..idx + 1,
                &(BASE62[rng_byte() as usize % 62] as char).to_string(),
            );
        }
    }
    out
}

fn base64_url(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let n = ((chunk[0] as u32) << 16)
            | ((*chunk.get(1).unwrap_or(&0) as u32) << 8)
            | (*chunk.get(2).unwrap_or(&0) as u32);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[n as usize & 63] as char);
        }
    }
    out
}

#[cfg(test)]
#[path = "xhttp_upload_buffer_tests.rs"]
mod upload_buffer_tests;

#[cfg(test)]
#[path = "xhttp_path_tests.rs"]
mod path_tests;

#[cfg(test)]
mod tests {
    use super::super::h2io;

    #[tokio::test]
    async fn xhttp_default_xray_settings_preserve_order_and_explicit_windows() {
        async fn observed(
            xhttp: bool,
            override_present: bool,
            connection: Option<u32>,
            stream: Option<u32>,
        ) -> (Vec<(u16, u32)>, u32) {
            let (client, mut peer) = tokio::io::duplex(4096);
            let mut builder = h2io::client_builder();
            if let Some(window) = connection {
                builder.initial_connection_window_size(window);
            }
            if let Some(window) = stream {
                builder.initial_window_size(window);
            }
            if xhttp {
                apply_xhttp_h2_settings(&mut builder, override_present);
            }
            let handshake =
                tokio::spawn(async move { builder.handshake::<_, Bytes>(client).await });
            let mut preface = [0; 24];
            peer.read_exact(&mut preface).await.unwrap();
            assert_eq!(&preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
            let mut head = [0; 9];
            peer.read_exact(&mut head).await.unwrap();
            assert_eq!(&head[3..], &[4, 0, 0, 0, 0, 0]);
            let length = u32::from_be_bytes([0, head[0], head[1], head[2]]) as usize;
            let mut body = vec![0; length];
            peer.read_exact(&mut body).await.unwrap();
            assert!(body.len().is_multiple_of(6));
            let settings = body
                .as_chunks::<6>()
                .0
                .iter()
                .map(|entry| {
                    (
                        u16::from_be_bytes(entry[..2].try_into().unwrap()),
                        u32::from_be_bytes(entry[2..].try_into().unwrap()),
                    )
                })
                .collect();
            peer.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, &[0, 0, 4, 8, 0, 0, 0, 0, 0]);
            let mut increment = [0; 4];
            peer.read_exact(&mut increment).await.unwrap();
            let (_client, _connection) = handshake.await.unwrap().unwrap();
            (settings, u32::from_be_bytes(increment))
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            for (xhttp, present, conn, stream, frame, delta) in [
                (false, false, None, None, 16384, (1 << 30) - 65535),
                (true, false, None, None, 1 << 20, 1 << 30),
                (true, true, Some(196608), None, 1 << 20, 196608 - 65535),
                // A present but invalid env value retains the base fallback.
                (true, true, None, None, 1 << 20, (1 << 30) - 65535),
                (true, false, None, Some(131072), 1 << 20, 1 << 30),
                (
                    false,
                    true,
                    Some(262144),
                    Some(98304),
                    16384,
                    262144 - 65535,
                ),
            ] {
                let (settings, increment) = observed(xhttp, present, conn, stream).await;
                assert_eq!(
                    settings,
                    vec![
                        (2, 0),
                        (4, stream.unwrap_or(4 << 20)),
                        (5, frame),
                        (6, 10 << 20)
                    ]
                );
                assert_eq!(increment, delta);
            }
        })
        .await
        .expect("bounded raw XHTTP default settings and ordinary-H2 scope check");
    }

    #[tokio::test]
    async fn packet_worker_batches_during_the_existing_post_interval() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (dial_tx, mut dial_rx) = mpsc::unbounded_channel();
        let dialer: std::sync::Arc<Dialer> = std::sync::Arc::new(move || {
            let tx = dial_tx.clone();
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(65536);
                tx.send(server).unwrap();
                Ok(Box::new(client) as AnyStream)
            })
        });
        let config = cfg(
            json!({"mode":"packet-up", "sc_min_posts_interval_ms":"100", "sc_max_each_post_bytes":"65536"}),
        );
        let writer = PostWriter {
            cfg: config,
            scheme: "http".into(),
            authority: "test".into(),
            session_id: "batch-test".into(),
            seq: 0,
            dialer,
            h2_client: None,
            h3_client: None,
            h1_client: None,
            first_connection: None,
        };
        let (mut input, reader) = tokio::io::duplex(1024);
        let flushed = std::sync::Arc::new(portable_atomic::AtomicU64::new(0));
        let count = flushed.clone();
        let worker = tokio::spawn(packet_upload_worker(
            reader,
            writer,
            Failure::default(),
            flushed,
            std::sync::Arc::new(tokio::sync::Notify::new()),
        ));
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut io = dial_rx.recv().await.unwrap();
            let head = read_request_head(&mut io).await.to_ascii_lowercase();
            assert!(head.contains("content-length: 1\r\n"));
            assert_eq!(io.read_u8().await.unwrap(), 0x5a);
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            ready_tx.send(()).unwrap();
            let head = read_request_head(&mut io).await.to_ascii_lowercase();
            assert!(head.contains("content-length: 49152\r\n"));
            let mut body = vec![0; 48 * 1024];
            io.read_exact(&mut body).await.unwrap();
            assert!(body.iter().all(|byte| *byte == 0x5a));
            io.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), async move {
            input.write_all(&[0x5a]).await.unwrap();
            ready_rx.await.unwrap();
            input.write_all(&vec![0x5a; 48 * 1024]).await.unwrap();
            input.shutdown().await.unwrap();
            worker.await.unwrap();
            server.await.unwrap();
        })
        .await
        .unwrap();
        assert_eq!(
            count.load(std::sync::atomic::Ordering::Acquire),
            48 * 1024 + 1
        );
    }
    #[tokio::test]
    async fn packet_flush_rechecks_completion_and_failure_after_wait_registration() {
        use tokio::io::AsyncWriteExt;
        for fail in [false, true] {
            let config = cfg(serde_json::json!({"mode":"packet-up"}));
            let mut split = SplitConn::new(&config);
            let (io, _reader) = tokio::io::duplex(1);
            let flushed = std::sync::Arc::new(portable_atomic::AtomicU64::new(0));
            let completion = flushed.clone();
            let failure = Failure::default();
            let error = failure.clone();
            split.up = Up::Packets(Box::new(PacketsUp {
                io,
                failure,
                bytes_written: std::sync::Arc::new(portable_atomic::AtomicU64::new(1)),
                bytes_flushed: flushed,
                flush_notify: std::sync::Arc::new(tokio::sync::Notify::new()),
                // Complete between the first check and waiter registration;
                // no later notification will arrive.
                flush_wait: Some(Box::pin(async move {
                    if fail {
                        error.set(io::Error::other("upload failed"));
                    } else {
                        completion.store(1, std::sync::atomic::Ordering::Release);
                    }
                    std::future::pending::<()>().await;
                })),
                task: tokio::spawn(async {}),
            }));
            let mut conn = XhttpConn {
                split: Box::new(split),
            };
            let result = tokio::time::timeout(std::time::Duration::from_secs(1), conn.flush())
                .await
                .expect("flush must not wait for a notification already lost");
            assert_eq!(result.is_err(), fail);
        }
    }
    const TEST_PERIOD: std::time::Duration = std::time::Duration::from_millis(200);
    const TEST_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_millis(600);

    /// A pooled connection on a keep-alive, as the dial path sets it up,
    /// with short test timings.
    async fn pooled_with_keep_alive(
        client_io: tokio::io::DuplexStream,
    ) -> (
        std::sync::Arc<h2io::H2Pool>,
        h2::client::SendRequest<Bytes>,
        JoinHandle<()>,
    ) {
        pooled_with_timings(client_io, Some((TEST_PERIOD, TEST_PING_TIMEOUT)), None).await
    }

    /// The same, with the keep-alive and the idle limit given explicitly.
    async fn pooled_with_timings(
        client_io: tokio::io::DuplexStream,
        keep_alive: Option<(std::time::Duration, std::time::Duration)>,
        idle: Option<std::time::Duration>,
    ) -> (
        std::sync::Arc<h2io::H2Pool>,
        h2::client::SendRequest<Bytes>,
        JoinHandle<()>,
    ) {
        let (client, connection, clock) =
            h2io::h2_handshake(Box::new(client_io), &h2io::client_builder(), "xhttp")
                .await
                .unwrap();
        let pool = std::sync::Arc::new(h2io::H2Pool::new());
        let counter = pool.finish_dial(Some(client.clone()), 1).await.unwrap();
        drop(h2io::CounterGuard::new(counter.clone()));
        let driver = tokio::spawn(h2io::drive_h2_connection(
            connection,
            clock,
            keep_alive.map(|(period, timeout)| h2io::H2KeepAlive::always(period, timeout)),
            std::sync::Arc::downgrade(&pool),
            counter,
            idle,
            "xhttp",
        ));
        (pool, client, driver)
    }

    #[tokio::test]
    async fn h2_keep_alive_evicts_a_silent_connection() {
        // the peer holds its end and never reads or writes
        let (client_io, _silent) = tokio::io::duplex(64 * 1024);
        let started = std::time::Instant::now();
        let (pool, client, driver) = pooled_with_keep_alive(client_io).await;
        tokio::time::timeout(std::time::Duration::from_secs(3), driver)
            .await
            .expect("silent connection kept past period + PING timeout")
            .unwrap();
        let took = started.elapsed();
        assert!(
            took >= TEST_PERIOD + TEST_PING_TIMEOUT,
            "evicted before the PING timeout: {took:?}"
        );
        assert!(
            matches!(pool.acquire(1, 0).await, h2io::H2Acquire::NeedDial(_)),
            "dead connection still pooled"
        );
        assert!(
            client.ready().await.is_err(),
            "dead connection still usable"
        );
    }

    #[tokio::test]
    async fn h2_keep_alive_keeps_a_connection_that_answers() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            while connection.accept().await.is_some() {}
        });
        let (pool, _client, driver) = pooled_with_keep_alive(client_io).await;
        // many periods and PING timeouts of idling
        tokio::time::sleep(5 * (TEST_PERIOD + TEST_PING_TIMEOUT)).await;
        assert!(!driver.is_finished(), "healthy idle connection dropped");
        assert!(
            matches!(pool.acquire(1, 0).await, h2io::H2Acquire::Ready(..)),
            "healthy idle connection left the pool"
        );
        server.abort();
    }

    #[tokio::test]
    async fn h2_connection_that_ends_leaves_the_pool() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let (pool, _client, driver) = pooled_with_keep_alive(client_io).await;
        drop(server_io);
        tokio::time::timeout(TEST_PERIOD, driver)
            .await
            .expect("closed connection not noticed")
            .unwrap();
        assert!(matches!(
            pool.acquire(1, 0).await,
            h2io::H2Acquire::NeedDial(_)
        ));
    }

    /// The idle limit the tests below run with, instead of the 300 s default.
    const TEST_H2_IDLE: std::time::Duration = std::time::Duration::from_millis(300);

    #[tokio::test]
    async fn an_idle_pooled_connection_closes_after_the_limit() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            while connection.accept().await.is_some() {}
        });
        let started = std::time::Instant::now();
        // the keep-alive answers, so only the idle limit can end this one
        let (pool, client, driver) = pooled_with_timings(
            client_io,
            Some((TEST_PERIOD, TEST_PING_TIMEOUT)),
            Some(TEST_H2_IDLE),
        )
        .await;
        tokio::time::timeout(std::time::Duration::from_secs(3), driver)
            .await
            .expect("idle connection kept past the limit")
            .unwrap();
        assert!(
            started.elapsed() >= TEST_H2_IDLE,
            "closed before the idle limit: {:?}",
            started.elapsed()
        );
        assert!(
            matches!(pool.acquire(1, 0).await, h2io::H2Acquire::NeedDial(_)),
            "closed connection still pooled"
        );
        assert!(client.ready().await.is_err(), "closed connection usable");
        server.abort();
    }

    #[tokio::test]
    async fn the_idle_limit_spares_a_connection_carrying_a_stream() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            while connection.accept().await.is_some() {}
        });
        let (client, connection, clock) =
            h2io::h2_handshake(Box::new(client_io), &h2io::client_builder(), "xhttp")
                .await
                .unwrap();
        let pool = std::sync::Arc::new(h2io::H2Pool::new());
        let counter = pool.finish_dial(Some(client), 1).await.unwrap();
        // a live stream holds the counter above zero for the whole test
        let held = h2io::CounterGuard::new(counter.clone());
        let driver = tokio::spawn(h2io::drive_h2_connection(
            connection,
            clock,
            Some(h2io::H2KeepAlive::always(TEST_PERIOD, TEST_PING_TIMEOUT)),
            std::sync::Arc::downgrade(&pool),
            counter,
            Some(TEST_H2_IDLE),
            "xhttp",
        ));
        tokio::time::sleep(4 * TEST_H2_IDLE).await;
        assert!(!driver.is_finished(), "connection with a stream was closed");
        drop(held);
        tokio::time::timeout(std::time::Duration::from_secs(3), driver)
            .await
            .expect("connection kept after its last stream left")
            .unwrap();
        server.abort();
    }

    #[tokio::test]
    async fn h2_xmux_rotates_with_an_existing_tunnel_held_open() {
        for xmux in [
            json!({"max_connections": 1, "c_max_reuse_times": 1}),
            json!({"max_connections": 1, "h_max_request_times": 1}),
            json!({"max_connections": 1, "h_max_reusable_secs": 1}),
        ] {
            let config = cfg(json!({"mode": "stream-one", "xmux": xmux}));
            let (client_io, server_io) = tokio::io::duplex(16 * 1024);
            let server = tokio::spawn(async move {
                let mut connection = h2::server::handshake(server_io).await.unwrap();
                while connection.accept().await.is_some() {}
            });
            let (client, connection, clock) =
                h2io::h2_handshake(Box::new(client_io), &super::xhttp_h2_builder(), "xhttp")
                    .await
                    .unwrap();
            let counter = config.register_h2(client, connection, clock, 1, 1).await;
            let tunnel = h2io::CounterGuard::new(counter.clone());
            if xmux.get("h_max_reusable_secs").is_some() {
                tokio::time::sleep(std::time::Duration::from_millis(1050)).await;
            }
            let acquire = config.h2_pool.acquire_requests(1, 0, 1).await;
            assert!(matches!(acquire, h2io::H2Acquire::NeedDial(_)), "{xmux}");
            assert_eq!(config.h2_pool.pooled(), 0);
            assert!(!server.is_finished(), "rotation killed an active tunnel");
            drop(tunnel);
            tokio::time::timeout(std::time::Duration::from_secs(2), server)
                .await
                .expect("retired connection did not close")
                .unwrap();
        }
    }

    #[tokio::test]
    async fn h2_packet_rotation_keeps_the_original_download_connection() {
        use tokio::io::AsyncWriteExt;

        let config = cfg(json!({
            "mode": "packet-up", "path": "/test",
            "xmux": {"max_connections": 1, "h_max_request_times": 2},
        }));
        let (client_io, server_io) = tokio::io::duplex(32 * 1024);
        let (next_io, next_server_io) = tokio::io::duplex(32 * 1024);
        let next = std::sync::Mutex::new(Some(next_io));
        let dialer: std::sync::Arc<Dialer> = std::sync::Arc::new(move || {
            let io = next.lock().unwrap().take();
            Box::pin(async move {
                io.map(|io| Box::new(io) as AnyStream)
                    .ok_or_else(|| io::Error::other("unexpected third H2 connection"))
            })
        });
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let serve = |socket, endpoint, tx: tokio::sync::mpsc::UnboundedSender<_>| {
            tokio::spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                let mut downloads = Vec::new();
                while let Some(Ok((request, mut respond))) = connection.accept().await {
                    tx.send((endpoint, request.method().clone())).unwrap();
                    if request.method() == http::Method::GET {
                        downloads.push(
                            respond
                                .send_response(http::Response::new(()), false)
                                .unwrap(),
                        );
                        continue;
                    }
                    tokio::spawn(async move {
                        let mut body = request.into_body();
                        while let Some(Ok(chunk)) = body.data().await {
                            body.flow_control().release_capacity(chunk.len()).unwrap();
                        }
                        let _ = respond.send_response(http::Response::new(()), true);
                    });
                }
            })
        };
        let first = serve(server_io, 1, tx.clone());
        let second = serve(next_server_io, 2, tx);
        let mut tunnel =
            super::connect(Box::new(client_io), true, true, "srv", 443, &config, dialer)
                .await
                .unwrap();
        for chunk in [b"abc", b"def"] {
            tunnel.write_all(chunk).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(2), tunnel.flush())
                .await
                .unwrap()
                .unwrap();
        }
        for expected in [
            (1, http::Method::GET),
            (1, http::Method::POST),
            (2, http::Method::POST),
        ] {
            assert_eq!(
                tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
                    .await
                    .unwrap(),
                Some(expected)
            );
        }
        assert!(
            !first.is_finished(),
            "upload rotation closed the original connection"
        );
        drop(tunnel);
        first.abort();
        second.abort();
    }

    #[tokio::test]
    async fn h2_xmux_prefers_the_connection_with_fewer_active_tunnels() {
        let config = cfg(json!({"mode": "stream-one", "xmux": {"max_connections": 2}}));
        let register = || async {
            let (client_io, server_io) = tokio::io::duplex(4096);
            let peer = tokio::spawn(async move {
                let mut server = h2::server::handshake(server_io).await.unwrap();
                while server.accept().await.is_some() {}
            });
            let (client, connection, clock) =
                h2io::h2_handshake(Box::new(client_io), &super::xhttp_h2_builder(), "xhttp")
                    .await
                    .unwrap();
            (
                config.register_h2(client, connection, clock, 2, 1).await,
                peer,
            )
        };
        let (busy, busy_peer) = register().await;
        let (idle, idle_peer) = register().await;
        let held = h2io::CounterGuard::new(busy);
        drop(h2io::CounterGuard::new(idle.clone()));

        for _ in 0..16 {
            let h2io::H2Acquire::Ready(_, chosen) = config.h2_pool.acquire_requests(2, 0, 1).await
            else {
                panic!("reuse a pooled H2 connection");
            };
            assert!(std::sync::Arc::ptr_eq(&chosen, &idle));
            drop(h2io::CounterGuard::new(chosen));
        }

        drop(held);
        busy_peer.abort();
        idle_peer.abort();
    }

    #[tokio::test]
    async fn h2_xmux_capacity_waits_and_drop_wakes_next_stream() {
        let (client_io, server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            let mut connection = h2::server::handshake(server_io).await.unwrap();
            while connection.accept().await.is_some() {}
        });
        let (client, connection) = h2::client::handshake(client_io).await.unwrap();
        let driver = tokio::spawn(connection);
        let pool = std::sync::Arc::new(h2io::H2Pool::new());
        let count = pool.finish_dial(Some(client), 1).await.unwrap();
        let guard = h2io::CounterGuard::new(count.clone());
        let waiting_pool = pool.clone();
        let waiting = tokio::spawn(async move { waiting_pool.acquire(1, 1).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!waiting.is_finished(), "xmux limit was ignored");
        drop(guard);
        let next = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        let h2io::H2Acquire::Ready(_, count) = next else {
            panic!("reuse existing H2 connection")
        };
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(h2io::CounterGuard::new(count.clone()));
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);
        // Cancelling a waiter must not consume capacity.
        let guard = h2io::CounterGuard::new({
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            count.clone()
        });
        let waiter_pool = pool.clone();
        let cancelled = tokio::spawn(async move { waiter_pool.acquire(1, 1).await });
        tokio::task::yield_now().await;
        cancelled.abort();
        let _ = cancelled.await;
        drop(guard);
        let h2io::H2Acquire::Ready(_, count) = pool.acquire(1, 1).await else {
            panic!("capacity leaked")
        };
        drop(h2io::CounterGuard::new(count));
        let h2io::H2Acquire::Ready(_, count) = pool.acquire(usize::MAX, 1).await else {
            panic!("idle connection must be reused before dialing")
        };
        let held = h2io::CounterGuard::new(count);
        let next = pool.acquire(usize::MAX, 1).await;
        assert!(
            matches!(next, h2io::H2Acquire::NeedDial(_)),
            "maxConcurrency must open a new connection when full"
        );
        drop(next);
        drop(held);
        driver.abort();
        server.abort();
    }

    #[tokio::test]
    async fn cancelled_h2_dial_releases_slot_and_wakes_waiter() {
        let pool = std::sync::Arc::new(h2io::H2Pool::new());
        let first = pool.acquire(1, 0).await;
        let waiting_pool = pool.clone();
        let waiting = tokio::spawn(async move { waiting_pool.acquire(1, 0).await });
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        drop(first);
        let next = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(next, h2io::H2Acquire::NeedDial(_)));
        drop(next);
        assert_eq!(pool.active_dials(), 0);
    }

    #[tokio::test]
    async fn aborted_h2_connection_dial_releases_reservation() {
        let pool = std::sync::Arc::new(h2io::H2Pool::new());
        let worker_pool = pool.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let worker = tokio::spawn(async move {
            let reservation = worker_pool.acquire(1, 0).await;
            ready_tx.send(()).unwrap();
            std::future::pending::<()>().await;
            drop(reservation);
        });
        ready_rx.await.unwrap();
        worker.abort();
        assert!(worker.await.unwrap_err().is_cancelled());
        let next = tokio::time::timeout(std::time::Duration::from_secs(1), pool.acquire(1, 0))
            .await
            .unwrap();
        drop(next);
        assert_eq!(pool.active_dials(), 0);
    }
    use super::*;
    use serde_json::json;

    fn cfg(entries: Value) -> XhttpConfig {
        let t = entries.as_object().expect("object").clone();
        XhttpConfig::parse(&t).expect("parse")
    }

    #[test]
    fn meta_defaults() {
        let c = cfg(json!({}));
        assert_eq!(c.mode, Mode::Auto);
        assert_eq!(c.path, "/");
        assert_eq!(c.padding, Range(100, 1000));
        assert_eq!(c.meta.session_placement, Placement::Path);
        assert_eq!(c.meta.session_key, "x_session"); // header default not used for path
        assert_eq!(c.meta.uplink_method, "POST");
        assert_eq!(c.meta.uplink_data, UplinkPlacement::Body);
        assert_eq!(c.meta.x_method, PadMethod::RepeatX);
        assert!(!c.meta.x_obfs);
    }

    /// `auto` per Xray (splithttp/dialer.go, `mode == "auto"`): packet-up,
    /// stream-one under REALITY. Plain TLS or none is not REALITY, and an
    /// explicit mode is kept either way.
    #[test]
    fn auto_mode_resolves_like_xray() {
        for raw in [json!({}), json!({"mode": "auto"}), json!({"mode": ""})] {
            let c = cfg(raw);
            assert_eq!(c.resolved_mode(false), Mode::PacketUp);
            assert_eq!(c.resolved_mode(true), Mode::StreamOne);
        }
        for (raw, mode) in [
            ("packet-up", Mode::PacketUp),
            ("stream-up", Mode::StreamUp),
            ("stream-one", Mode::StreamOne),
        ] {
            let c = cfg(json!({ "mode": raw }));
            assert_eq!(c.resolved_mode(false), mode, "{raw} without REALITY");
            assert_eq!(c.resolved_mode(true), mode, "{raw} with REALITY");
        }
        let split = cfg(json!({
            "download_settings": {
                "server": "download.example",
                "server_port": 443,
                "transport": {"type": "xhttp"}
            }
        }));
        assert_eq!(split.resolved_mode(false), Mode::PacketUp);
        assert_eq!(split.resolved_mode(true), Mode::StreamUp);
    }

    #[tokio::test]
    async fn split_http1_uses_independent_settings_and_one_session() {
        use tokio::io::{AsyncBufReadExt, BufReader};
        use tokio::net::{TcpListener, TcpStream};

        async fn request(socket: TcpStream) -> (String, BufReader<TcpStream>) {
            let mut io = BufReader::new(socket);
            let mut head = String::new();
            loop {
                let last = head.len();
                assert_ne!(io.read_line(&mut head).await.unwrap(), 0);
                if &head[last..] == "\r\n" {
                    break;
                }
            }
            (head, io)
        }

        let uplink = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let downlink = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_port = uplink.local_addr().unwrap().port();
        let down_port = downlink.local_addr().unwrap().port();
        let config = json!({"transport": {
            "type": "xhttp", "path": "/up", "host": "up.example",
            "download_settings": {
                "server": "127.0.0.1", "server_port": down_port,
                "transport": {"type": "xhttp", "path": "/down", "host": "down.example"}
            }
        }});
        let transport =
            super::super::Transport::parse(config.as_object().unwrap(), "test").unwrap();
        let client = async {
            let mut stream = transport
                .connect_or_dial(None, "127.0.0.1", up_port, &DialOptions::default())
                .await
                .unwrap();
            stream.write_all(b"from client").await.unwrap();
            stream.flush().await.unwrap();
            let mut reply = [0; 9];
            stream.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"from peer");
        };
        let peer = async {
            let (down, _) = downlink.accept().await.unwrap();
            let (down_head, mut down) = request(down).await;
            let download_path = down_head.split_whitespace().nth(1).unwrap();
            let session = download_path
                .split('?')
                .next()
                .unwrap()
                .strip_prefix("/down/")
                .unwrap();
            assert!(down_head.starts_with("GET /down/"));
            assert!(
                down_head
                    .to_ascii_lowercase()
                    .contains("\r\nhost: down.example\r\n")
            );

            let (up, _) = uplink.accept().await.unwrap();
            let (up_head, mut up) = request(up).await;
            assert!(up_head.starts_with(&format!("POST /up/{session}/0")));
            assert!(
                up_head
                    .to_ascii_lowercase()
                    .contains("\r\nhost: up.example\r\n")
            );
            let mut data = [0; 11];
            up.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"from client");
            up.get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            down.get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nfrom peer")
                .await
                .unwrap();
        };

        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            tokio::join!(client, peer);
        })
        .await
        .unwrap();
    }

    #[test]
    fn meta_header_key_defaults_are_asymmetric() {
        let c = cfg(json!({"session_placement": "header", "seq_placement": "cookie"}));
        assert_eq!(c.meta.session_key, "X-Session");
        assert_eq!(c.meta.seq_key, "x_seq");
    }

    #[test]
    fn request_path_session_and_seq() {
        let c = cfg(json!({"path": "/xhttp"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID1"), None, false)
            .unwrap();
        assert_eq!(req.uri().path(), "/xhttp/SID1");
        let req = c
            .build_request("https", "srv:443", "POST", Some("SID1"), Some("7"), true)
            .unwrap();
        assert_eq!(req.uri().path(), "/xhttp/SID1/7");
    }

    #[test]
    fn request_header_and_query_placements() {
        let c = cfg(json!({"path": "/up/", "session_placement": "header"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        // trailing slash preserved (load-bearing for reverse proxies)
        assert_eq!(req.uri().path(), "/up/");
        assert_eq!(req.headers().get("X-Session").unwrap(), "SID");

        let c = cfg(json!({"seq_placement": "query"}));
        let req = c
            .build_request("https", "srv:443", "POST", Some("SID"), Some("3"), true)
            .unwrap();
        assert!(req.uri().query().unwrap().contains("x_seq=3"));
    }

    #[test]
    fn request_cookie_placement() {
        let c = cfg(json!({"session_placement": "cookie"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        assert_eq!(req.headers().get("cookie").unwrap(), "x_session=SID");
    }

    #[test]
    fn padding_legacy_referer() {
        let c = cfg(json!({"x_padding_bytes": 50, "x_padding_method": "tokenish", "path": "/x"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        let referer = req.headers().get("referer").unwrap();
        // Xray pads the request URL before the session goes in: the bare path
        assert!(
            referer
                .to_str()
                .unwrap()
                .starts_with("https://srv:443/x/?x_padding=")
        );
        let pad = referer.to_str().unwrap().rsplit('=').next().unwrap();
        assert_eq!(pad.len(), 50);
        // `X`s, as Xray's `GeneratePadding` writes them: HPACK codes `X` in
        // eight bits, so the HEADERS frame is as long as Xray's
        assert!(pad.bytes().all(|b| b == b'X'));
    }

    #[test]
    fn requests_preserve_path_query_and_replace_generated_fields() {
        let c = cfg(json!({
            "mode": "stream-one", "path": "/stream resource?token=a%2Fb&flag",
            "headers": {"referer": "old", "content-type": "text/plain"},
            "x_padding_bytes": 4
        }));
        let request = c
            .build_request("https", "srv", "POST", None, None, true)
            .unwrap();
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/stream%20resource/?token=a%2Fb&flag"
        );
        assert_eq!(
            request.headers()["referer"],
            "https://srv/stream%20resource/?x_padding=XXXX"
        );
        assert_eq!(request.headers().get_all("referer").iter().count(), 1);
        assert_eq!(request.headers()["content-type"], "application/grpc");
        assert_eq!(request.headers().get_all("content-type").iter().count(), 1);

        let c = cfg(json!({
            "mode": "packet-up", "path": "/packet?z=1&x_seq=old&z=2&flag",
            "session_placement": "path", "seq_placement": "query",
            "x_padding_obfs_mode": true, "x_padding_placement": "query",
            "x_padding_key": "x pad", "x_padding_bytes": 4
        }));
        let request = c
            .build_request("https", "srv", "POST", Some("id"), Some("3"), true)
            .unwrap();
        assert_eq!(
            request.uri().path_and_query().unwrap().as_str(),
            "/packet/id?flag=&x+pad=XXXX&x_seq=3&z=1&z=2"
        );
    }

    #[test]
    fn packet_size_and_schedule_normalization_match_xray() {
        let c = cfg(json!({
            "mode": "packet-up", "x_padding_bytes": 0,
            "sc_max_each_post_bytes": "0-0", "sc_min_posts_interval_ms": 0,
            "uplink_data_placement": "header", "uplink_chunk_size": "32-128"
        }));
        assert_eq!(c.padding, Range(100, 1000));
        assert_eq!(c.meta.sc_max_each_post, Range(1_000_000, 1_000_000));
        assert_eq!(c.meta.sc_min_interval_ms, Range(30, 30));
        assert_eq!(c.meta.uplink_chunk, Range(64, 128));
        let c = cfg(json!({"mode": "packet-up", "sc_min_posts_interval_ms": "-1-30"}));
        assert_eq!(c.meta.sc_min_interval_ms, Range(0, 0));
    }

    /// Xray appends the session and seq to its normalized path, which ends
    /// with a slash: with the session in a header, the download GET goes to
    /// `/xh/` and an upload to `/xh/<seq>`, which is what its server routes.
    #[test]
    fn paths_follow_xrays_append_to_path() {
        let path = |c: &XhttpConfig, session: Option<&str>, seq: Option<&str>| {
            c.build_request("https", "srv:443", "POST", session, seq, false)
                .unwrap()
                .uri()
                .path()
                .to_string()
        };
        let plain = cfg(json!({"path": "/xh"}));
        assert_eq!(path(&plain, Some("SID"), None), "/xh/SID");
        assert_eq!(path(&plain, Some("SID"), Some("7")), "/xh/SID/7");
        assert_eq!(path(&plain, None, None), "/xh/");
        let header = cfg(json!({"path": "/xh", "session_placement": "header"}));
        assert_eq!(path(&header, Some("SID"), None), "/xh/");
        assert_eq!(path(&header, Some("SID"), Some("7")), "/xh/7");
        let slash = cfg(json!({"path": "/xh/"}));
        assert_eq!(path(&slash, Some("SID"), Some("7")), "/xh/SID/7");
    }

    /// With no User-Agent configured, the request carries Xray's Chrome
    /// `fetch` headers; a configured one leaves the request alone.
    #[test]
    fn requests_carry_xrays_browser_headers() {
        let c = cfg(json!({}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        let ua = req.headers().get("user-agent").unwrap().to_str().unwrap();
        assert!(
            ua.starts_with("Mozilla/5.0 (Windows NT 10.0; Win64; x64)"),
            "{ua}"
        );
        for name in [
            "sec-ch-ua",
            "sec-ch-ua-mobile",
            "sec-ch-ua-platform",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "sec-fetch-site",
            "priority",
            "accept",
        ] {
            assert!(req.headers().contains_key(name), "{name}");
        }
        let own = cfg(json!({"headers": {"User-Agent": "mine"}}));
        let req = own
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        assert_eq!(req.headers().get("user-agent").unwrap(), "mine");
        assert!(!req.headers().contains_key("sec-ch-ua"));

        // a profile name is not a user agent: it picks one, as
        // `TryDefaultHeadersWith` does
        let firefox = cfg(json!({"headers": {"User-Agent": "firefox"}}));
        let req = firefox
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        let ua = req.headers().get("user-agent").unwrap().to_str().unwrap();
        assert!(ua.contains("Gecko/20100101 Firefox/"), "{ua}");
        assert!(
            !req.headers().contains_key("sec-ch-ua"),
            "firefox sends none"
        );
        assert_eq!(req.headers().get("priority").unwrap(), "u=4");
        assert_eq!(
            req.headers().get("accept-language").unwrap(),
            "en-US,en;q=0.5"
        );

        // a configured header the fill set also carries stays as configured
        let keeps = cfg(json!({"headers": {"Accept": "text/plain"}}));
        let req = keeps
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        assert_eq!(req.headers().get("accept").unwrap(), "text/plain");
        assert_eq!(req.headers().get("cache-control").unwrap(), "no-cache");
    }

    /// A packet-up upload carries no content type, as Xray's
    /// `FillPacketRequest` sends it; a streamed body is announced as gRPC.
    #[test]
    fn a_packet_up_upload_has_no_content_type_and_a_stream_is_grpc() {
        for mode in ["packet-up", "auto"] {
            let packet = cfg(json!({"mode": mode}));
            let req = packet
                .build_request("https", "srv:443", "POST", Some("SID"), Some("0"), true)
                .unwrap();
            assert!(req.headers().get("content-type").is_none());
        }
        let stream = cfg(json!({"mode": "stream-one"}));
        let req = stream
            .build_request("https", "srv:443", "POST", None, None, true)
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/grpc"
        );
    }

    #[test]
    fn authority_for_prefers_host_then_sni_then_server() {
        let bare = cfg(json!({}));
        assert_eq!(
            bare.authority_for("cdn.example.com", "1.2.3.4", 443),
            "cdn.example.com"
        );
        assert_eq!(bare.authority_for("", "1.2.3.4", 443), "1.2.3.4");
        assert_eq!(bare.authority_for("", "2001:db8::1", 443), "[2001:db8::1]");

        let explicit = cfg(json!({"host": "override.example.com"}));
        assert_eq!(
            explicit.authority_for("cdn.example.com", "1.2.3.4", 443),
            "override.example.com"
        );
    }

    #[test]
    fn h1_only_respects_reality_and_alpn() {
        let auto = cfg(json!({"mode": "auto"}));
        assert!(auto.h1_only(None));

        let tls_default = crate::tls_client::TlsOptions::from_outbound(
            json!({"tls": {"enabled": true, "server_name": "example.com"}})
                .as_object()
                .unwrap(),
            "example.com",
            "test",
        )
        .unwrap()
        .unwrap();
        assert!(!auto.h1_only(Some(&tls_default)));

        let tls_h1 = crate::tls_client::TlsOptions::from_outbound(
            json!({"tls": {"enabled": true, "server_name": "example.com", "alpn": ["http/1.1"]}})
                .as_object()
                .unwrap(),
            "example.com",
            "test",
        )
        .unwrap()
        .unwrap();
        assert!(auto.h1_only(Some(&tls_h1)));

        let tls_reality = crate::tls_client::TlsOptions::from_outbound(
            json!({
                "tls": {
                    "enabled": true,
                    "server_name": "example.com",
                    "utls": {"enabled": true, "fingerprint": "chrome"},
                    "reality": {
                        "enabled": true,
                        "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
                        "short_id": "0102030405060708"
                    }
                }
            })
            .as_object()
            .unwrap(),
            "example.com",
            "test",
        )
        .unwrap()
        .unwrap();
        assert!(!auto.h1_only(Some(&tls_reality)));
    }

    #[test]
    fn padding_obfs_header_and_tokenish() {
        let c = cfg(json!({
            "x_padding_obfs_mode": true,
            "x_padding_placement": "header",
            "x_padding_method": "tokenish",
            "x_padding_bytes": "100-100"
        }));
        let req = c
            .build_request("https", "srv:443", "GET", Some("S"), None, false)
            .unwrap();
        let pad = req.headers().get("X-Padding").unwrap().to_str().unwrap();
        // tokenish tunes the Huffman length into the reference's ±2 window.
        assert!((98..=102).contains(&huffman_len(pad)));
        assert!(!pad.bytes().all(|b| b == b'X'));
        assert!(pad.bytes().all(|b| b.is_ascii_alphanumeric()));
    }

    #[test]
    fn grpc_header_toggle() {
        let c = cfg(json!({}));
        let req = c
            .build_request("https", "srv:443", "POST", None, None, true)
            .unwrap();
        assert_eq!(
            req.headers().get("content-type").unwrap(),
            "application/grpc"
        );
        let c = cfg(json!({"no_grpc_header": true}));
        let req = c
            .build_request("https", "srv:443", "POST", None, None, true)
            .unwrap();
        assert!(req.headers().get("content-type").is_none());
    }

    #[test]
    fn get_falls_back_to_post_outside_packet_up() {
        let c = cfg(json!({"mode": "stream-one", "uplink_http_method": "get"}));
        assert_eq!(c.meta.uplink_method, "POST");
        let c = cfg(json!({"mode": "packet-up", "uplink_http_method": "get"}));
        assert_eq!(c.meta.uplink_method, "GET");
    }

    #[test]
    fn uplink_header_rejected_outside_packet_up() {
        let err = XhttpConfig::parse(
            json!({"mode": "stream-up", "uplink_data_placement": "header"})
                .as_object()
                .unwrap(),
        );
        assert!(err.is_err());
    }

    #[test]
    fn base64_url_alphabet() {
        assert_eq!(base64_url(&[0xfb, 0xff]), "-_8");
        assert_eq!(base64_url(&[]), "");
    }

    #[test]
    fn session_id_uuid_shape() {
        let id = new_session_id(&cfg(json!({})).meta);
        assert_eq!(id.len(), 36);
        assert_eq!(id.matches('-').count(), 4);
    }

    /// Read one HTTP/1.1 request head off a raw stream.
    async fn read_request_head(io: &mut tokio::io::DuplexStream) -> String {
        use tokio::io::AsyncReadExt;
        let mut raw = Vec::new();
        let mut byte = [0u8; 1];
        while !raw.ends_with(b"\r\n\r\n") {
            assert_eq!(
                io.read(&mut byte).await.expect("read head"),
                1,
                "eof in head"
            );
            raw.push(byte[0]);
        }
        String::from_utf8(raw).expect("utf8 head")
    }

    /// Wire test over in-process raw HTTP/1.1 peers: the client must send a
    /// `Connection: close` download GET on the connection it was handed, and the
    /// seq-numbered upload POST on a second connection from the dialer, each with
    /// padding. The download body must flow back through the conn.

    #[tokio::test]
    async fn download_head_waiting_for_first_post_does_not_deadlock() {
        let (client_io, mut download) = tokio::io::duplex(65536);
        let (post_tx, mut post_rx) = mpsc::unbounded_channel();
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
            let post_tx = post_tx.clone();
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(65536);
                post_tx.send(server).unwrap();
                Ok(Box::new(client) as AnyStream)
            })
        });
        let server = tokio::spawn(async move {
            let head = read_request_head(&mut download).await;
            assert!(head.starts_with("GET "));
            // Delay all download response bytes until upload is received.
            let mut upload = post_rx.recv().await.unwrap();
            let head = read_request_head(&mut upload).await;
            assert!(head.starts_with("POST "));
            let mut payload = [0; 4];
            upload.read_exact(&mut payload).await.unwrap();
            assert_eq!(&payload, b"ping");
            upload
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            download
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\npong")
                .await
                .unwrap();
        });
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let config = cfg(json!({"path":"/xhttp","mode":"packet-up"}));
            let mut connection = super::connect(
                Box::new(client_io),
                false,
                false,
                "srv",
                80,
                &config,
                dialer,
            )
            .await
            .unwrap();
            connection.write_all(b"ping").await.unwrap();
            connection.flush().await.unwrap();
            let mut reply = [0; 4];
            connection.read_exact(&mut reply).await.unwrap();
            assert_eq!(&reply, b"pong");
            server.await.unwrap();
        })
        .await
        .expect("GET/upload deadlock");
    }

    #[tokio::test]
    async fn rejected_download_header_reaches_the_reader() {
        let (client, mut server) = tokio::io::duplex(65536);
        let task = tokio::spawn(async move {
            read_request_head(&mut server).await;
            server
                .write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
        });
        let dialer: std::sync::Arc<super::Dialer> =
            std::sync::Arc::new(|| Box::pin(async { Err(io::Error::other("unused dial")) }));
        let config = cfg(json!({"path":"/xhttp","mode":"packet-up"}));
        let mut connection =
            super::connect(Box::new(client), false, false, "srv", 80, &config, dialer)
                .await
                .unwrap();
        let mut byte = [0];
        let error = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            connection.read(&mut byte),
        )
        .await
        .unwrap()
        .unwrap_err();
        assert!(error.to_string().contains("403"));
        task.await.unwrap();
    }

    #[tokio::test]
    async fn packet_up_cookie_payload_names_each_chunk() {
        let chunks = format!("x_data_0={}; x_data_1=AAAA", "A".repeat(64));
        for (headers, expected) in [
            (json!({}), chunks.clone()),
            (
                json!({"cookie": "proxy=value"}),
                format!("proxy=value; {chunks}"),
            ),
        ] {
            let (client, mut server) = tokio::io::duplex(1024);
            let mut writer = PostWriter {
                cfg: cfg(json!({
                    "mode": "packet-up", "uplink_data_placement": "cookie",
                    "uplink_chunk_size": 3, "headers": headers
                })),
                scheme: "http".into(),
                authority: "srv".into(),
                session_id: "test-session".into(),
                seq: 0,
                dialer: std::sync::Arc::new(|| {
                    Box::pin(async { Err(io::Error::other("first connection was supplied")) })
                }),
                h2_client: None,
                h3_client: None,
                h1_client: None,
                first_connection: Some(Box::new(client)),
            };
            let peer = async {
                let head = read_request_head(&mut server).await;
                assert_eq!(
                    head.lines().find_map(|line| line.strip_prefix("cookie: ")),
                    Some(expected.as_str())
                );
                server
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                    .await
                    .unwrap();
            };
            let (result, ()) = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                tokio::join!(writer.send_packet(&[0; 51]), peer)
            })
            .await
            .unwrap();
            result.unwrap();
        }
    }

    #[tokio::test]
    async fn dropping_http1_stream_one_cancels_a_pending_response() {
        let (client, mut peer) = tokio::io::duplex(65536);
        let dialer = std::sync::Arc::new(|| {
            Box::pin(async { Err(io::Error::other("unused dial")) })
                as Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send>>
        });
        let config = cfg(json!({"mode": "stream-one"}));
        let connection = super::connect(Box::new(client), false, false, "srv", 80, &config, dialer)
            .await
            .unwrap();
        read_request_head(&mut peer).await;
        drop(connection);
        let mut byte = [0];
        assert_eq!(
            tokio::time::timeout(std::time::Duration::from_millis(500), peer.read(&mut byte))
                .await
                .expect("upload response reader must drop with the tunnel")
                .unwrap(),
            0,
        );
    }

    #[tokio::test]
    async fn http1_stream_one_rejection_reaches_both_halves() {
        let (client, mut peer) = tokio::io::duplex(65536);
        let dialer = std::sync::Arc::new(|| {
            Box::pin(async { Err(io::Error::other("unused dial")) })
                as Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send>>
        });
        let config = cfg(json!({"mode": "stream-one"}));
        let mut connection =
            super::connect(Box::new(client), false, false, "srv", 80, &config, dialer)
                .await
                .unwrap();
        read_request_head(&mut peer).await;
        peer.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
            .await
            .unwrap();
        let mut byte = [0];
        let read = connection.read(&mut byte).await.unwrap_err();
        let write = connection.write(b"ping").await.unwrap_err();
        assert!(read.to_string().contains("403"));
        assert!(write.to_string().contains("403"));
    }

    #[tokio::test]
    async fn packet_up_keeps_rejected_post_visible_to_later_flush() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (download, _get_peer) = tokio::io::duplex(65536);
            let (post_tx, mut post_rx) = mpsc::unbounded_channel();
            let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
                let post_tx = post_tx.clone();
                Box::pin(async move {
                    let (client, peer) = tokio::io::duplex(65536);
                    post_tx.send(peer).unwrap();
                    Ok(Box::new(client) as AnyStream)
                })
            });
            let config = cfg(json!({"mode": "packet-up"}));
            let mut connection =
                super::connect(Box::new(download), false, false, "srv", 80, &config, dialer)
                    .await
                    .unwrap();
            connection.write_all(b"ping").await.unwrap();
            let mut post = post_rx.recv().await.unwrap();
            read_request_head(&mut post).await;
            let mut data = [0; 4];
            post.read_exact(&mut data).await.unwrap();
            assert_eq!(&data, b"ping");
            post.write_all(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            for _ in 0..2 {
                let error =
                    tokio::time::timeout(std::time::Duration::from_millis(500), connection.flush())
                        .await
                        .expect("terminal POST error must not leave flush waiting")
                        .unwrap_err();
                assert!(error.to_string().contains("403"));
            }
        })
        .await
        .expect("POST setup must complete");
    }

    #[tokio::test]
    async fn failed_upload_is_not_replayed_and_next_attempt_dials_fresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
            let calls = calls.clone();
            Box::pin(async move {
                let n = calls.fetch_add(1, Ordering::SeqCst);
                let (client, mut server) = tokio::io::duplex(65536);
                tokio::spawn(async move {
                    read_request_head(&mut server).await;
                    let mut body = [0; 4];
                    server.read_exact(&mut body).await.unwrap();
                    if n == 0 {
                        assert_eq!(&body, b"lost");
                        return;
                    }
                    assert_eq!(&body, b"next");
                    server
                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                        .await
                        .unwrap();
                    let mut byte = [0];
                    let _ = server.read(&mut byte).await;
                });
                Ok(Box::new(client) as AnyStream)
            })
        });
        let mut writer = PostWriter {
            cfg: cfg(json!({"path":"/xhttp"})),
            scheme: "http".into(),
            authority: "srv".into(),
            session_id: "test-session".into(),
            h2_client: None,
            h3_client: None,
            h1_client: None,
            first_connection: None,
            seq: 0,
            dialer,
        };
        assert!(writer.send_packet(b"lost").await.is_err());
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "ambiguous POST must not replay"
        );
        writer.send_packet(b"next").await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn wire_packet_up_starts_next_request_before_older_response() {
        use std::time::Duration;

        let ok = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
        let forbidden = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        for reject in [false, true] {
            tokio::time::timeout(Duration::from_secs(2), async {
                let (download, mut get) = tokio::io::duplex(4096);
                let (post_tx, mut post_rx) = mpsc::unbounded_channel();
                let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
                    let post_tx = post_tx.clone();
                    Box::pin(async move {
                        let (local, peer) = tokio::io::duplex(4096);
                        post_tx.send(peer).unwrap();
                        Ok(Box::new(local) as AnyStream)
                    })
                });
                let cfg = cfg(json!({"mode":"packet-up", "sc_max_each_post_bytes":4}));
                let mut client =
                    super::connect(Box::new(download), false, false, "srv", 443, &cfg, dialer)
                        .await
                        .unwrap();
                let _ = read_request_head(&mut get).await;
                client.write_all(b"pingpong").await.unwrap();

                let mut first = post_rx.recv().await.unwrap();
                let mut second = post_rx.recv().await.unwrap();
                let mut payload = [0; 4];
                assert!(read_request_head(&mut first).await.contains("/0 HTTP/1.1"));
                first.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"ping");
                assert!(read_request_head(&mut second).await.contains("/1 HTTP/1.1"));
                second.read_exact(&mut payload).await.unwrap();
                assert_eq!(&payload, b"pong");

                second
                    .write_all(if reject { forbidden.as_slice() } else { ok })
                    .await
                    .unwrap();
                let mut flush = Box::pin(client.flush());
                if reject {
                    let error = flush.await.unwrap_err();
                    assert!(error.to_string().contains("403"));
                    assert!(
                        post_rx.try_recv().is_err(),
                        "ambiguous POST must not replay"
                    );
                } else {
                    assert!(
                        tokio::time::timeout(Duration::from_millis(50), &mut flush)
                            .await
                            .is_err(),
                        "later acknowledgement cannot flush the earlier packet"
                    );
                    first.write_all(ok).await.unwrap();
                    flush.await.unwrap();
                }
            })
            .await
            .expect("pipeline test timed out");
        }
    }

    #[tokio::test]
    async fn wire_packet_up_roundtrip() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let timeout = std::time::Duration::from_secs(10);

        let (client_io, mut get_io) = tokio::io::duplex(1 << 16);
        let (post_tx, mut post_rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
            let post_tx = post_tx.clone();
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(1 << 16);
                post_tx.send(server).expect("server side");
                Ok(Box::new(client) as AnyStream)
            })
        });
        let c = cfg(json!({"path": "/xhttp", "x_padding_bytes": "20-40"}));
        let stream: AnyStream = Box::new(client_io);

        let server = tokio::spawn(async move {
            // --- download GET: its own connection, closed after the response ---
            let head = read_request_head(&mut get_io).await;
            let line = head.lines().next().unwrap().to_string();
            assert!(line.starts_with("GET /xhttp/"), "got {line:?}");
            assert!(line.ends_with(" HTTP/1.1"), "got {line:?}");
            let path = line.split(' ').nth(1).unwrap();
            assert_eq!(path.matches('/').count(), 2, "got {path:?}");
            let lower = head.to_ascii_lowercase();
            assert!(lower.contains("\r\nconnection: close\r\n"), "got {head:?}");
            assert!(lower.contains("\r\nhost: srv\r\n"), "got {head:?}");
            assert!(lower.contains("x_padding="), "padding missing: {head:?}");
            get_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n")
                .await
                .unwrap();

            // --- upload POST seq=0: a second connection from the dialer ---
            let mut post_io = post_rx.recv().await.expect("dialled connection");
            let head = read_request_head(&mut post_io).await;
            let line = head.lines().next().unwrap().to_string();
            assert!(line.starts_with("POST /xhttp/"), "got {line:?}");
            assert!(line.contains("/0 HTTP/1.1"), "got {line:?}");
            let lower = head.to_ascii_lowercase();
            assert!(lower.contains("\r\ncontent-length: 4\r\n"), "got {head:?}");
            assert!(
                !lower.contains("connection: close"),
                "upload must keep alive"
            );
            assert!(
                !lower.contains("x-data-"),
                "the payload rides the body, a header copy arrives twice: {head:?}"
            );
            let mut body = [0u8; 4];
            post_io.read_exact(&mut body).await.unwrap();
            assert_eq!(&body, b"ping");
            post_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            // keep both ends open until the client has read everything
            tokio::time::sleep(std::time::Duration::from_millis(300)).await;
            drop(get_io);
            drop(post_io);
        });

        let mut conn = tokio::time::timeout(
            timeout,
            super::connect(stream, false, false, "srv", 443, &c, dialer),
        )
        .await
        .expect("connect timed out")
        .expect("connect");
        tokio::time::timeout(timeout, async {
            conn.write_all(b"ping").await.expect("write");
            conn.flush().await.expect("flush");
            let mut buf = vec![0u8; 5];
            conn.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"hello");
        })
        .await
        .expect("roundtrip timed out");
        tokio::time::timeout(timeout, server)
            .await
            .expect("server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn wire_packet_up_keep_alive_reuse() {
        wire_packet_up_h1_uploads(None).await;
    }

    #[tokio::test]
    async fn wire_packet_up_h1_rotates_after_get_and_first_post() {
        wire_packet_up_h1_uploads(Some(json!({
            "max_connections": 1,
            "h_max_request_times": 2
        })))
        .await;
    }

    async fn wire_packet_up_h1_uploads(xmux: Option<Value>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let timeout = std::time::Duration::from_secs(10);

        let (client_io, mut get_io) = tokio::io::duplex(1 << 16);
        let (post_tx, mut post_rx) = mpsc::unbounded_channel::<tokio::io::DuplexStream>();
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
            let post_tx = post_tx.clone();
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(1 << 16);
                post_tx.send(server).expect("server side");
                Ok(Box::new(client) as AnyStream)
            })
        });
        let rotate = xmux.is_some();
        let c = cfg(json!({"path": "/xhttp", "x_padding_bytes": "20-40", "xmux": xmux}));
        let stream: AnyStream = Box::new(client_io);

        let server = tokio::spawn(async move {
            // GET
            let _ = read_request_head(&mut get_io).await;
            get_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
                .await
                .unwrap();

            // POST 0
            let mut post_io = post_rx.recv().await.expect("dialled connection 0");
            let head0 = read_request_head(&mut post_io).await;
            assert!(head0.contains("/0 HTTP/1.1"));
            let mut body0 = [0u8; 4];
            post_io.read_exact(&mut body0).await.unwrap();
            assert_eq!(&body0, b"ping");
            post_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            eprintln!("SERVER: POST 0 complete");

            // The GET and first POST spend the request budget when rotation
            // is enabled. The GET stays open while the second POST dials.
            let mut post_io = if rotate {
                post_rx.recv().await.expect("rotated upload connection")
            } else {
                post_io
            };
            let head1 = read_request_head(&mut post_io).await;
            eprintln!(
                "SERVER: POST 1 read: {}",
                head1.lines().next().unwrap_or("")
            );
            assert!(head1.contains("/1 HTTP/1.1"), "got {head1:?}");
            let mut body1 = [0u8; 4];
            post_io.read_exact(&mut body1).await.unwrap();
            assert_eq!(&body1, b"pong");
            post_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            eprintln!("SERVER: POST 1 complete");

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            drop(get_io);
            drop(post_io);
        });

        let mut conn = tokio::time::timeout(
            timeout,
            super::connect(stream, false, false, "srv", 443, &c, dialer),
        )
        .await
        .expect("connect timed out")
        .expect("connect");

        tokio::time::timeout(timeout, async {
            conn.write_all(b"ping").await.expect("write 0");
            conn.flush().await.expect("flush 0");
            eprintln!("CLIENT: write 0 done");
            conn.write_all(b"pong").await.expect("write 1");
            conn.flush().await.expect("flush 1");
            eprintln!("CLIENT: write 1 done");
        })
        .await
        .expect("writes timed out");

        tokio::time::timeout(timeout, server)
            .await
            .expect("server timed out")
            .unwrap();
    }

    #[tokio::test]
    async fn wire_h2_packet_up_roundtrip() {
        wire_h2_split_roundtrip("packet-up").await;
    }

    #[tokio::test]
    async fn wire_h2_stream_up_roundtrip() {
        wire_h2_split_roundtrip("stream-up").await;
    }

    #[tokio::test]
    async fn wire_h2_split_with_one_peer_stream_keeps_the_download_open() {
        for mode in ["stream-up", "packet-up"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let client = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (download_socket, _) = listener.accept().await.unwrap();
            let (download, upload) = tokio::sync::oneshot::channel();
            let download_task = tokio::spawn(async move {
                let mut conn = h2::server::Builder::new()
                    .max_concurrent_streams(1)
                    .handshake::<_, Bytes>(download_socket)
                    .await
                    .unwrap();
                let (request, mut respond) = conn.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), http::Method::GET);
                let path = request.uri().path().to_owned();
                let mut sender = respond
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                let deliver = tokio::spawn(async move {
                    let (upload_path, payload) = upload.await.unwrap();
                    let expected = if mode == "packet-up" {
                        format!("{path}/0")
                    } else {
                        path
                    };
                    assert_eq!(upload_path, expected);
                    assert_eq!(payload, b"upload");
                    sender
                        .send_data(Bytes::from_static(b"download"), true)
                        .unwrap();
                });
                // Keep polling the GET connection so the response can be
                // delivered, but accept no further streams on it.
                tokio::select! {
                    _ = conn.accept() => panic!("unexpected GET connection event"),
                    res = deliver => res.unwrap(),
                }
                while conn.accept().await.is_some() {}
            });
            let dialer: std::sync::Arc<Dialer> = std::sync::Arc::new(move || {
                Box::pin(async move {
                    Ok(Box::new(tokio::net::TcpStream::connect(addr).await?) as AnyStream)
                })
            });
            let upload_task = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut conn = h2::server::Builder::new()
                    .max_concurrent_streams(1)
                    .handshake::<_, Bytes>(socket)
                    .await
                    .unwrap();
                let (mut request, mut respond) = conn.accept().await.unwrap().unwrap();
                assert_eq!(request.method(), http::Method::POST);
                let read = tokio::spawn(async move {
                    let mut payload = Vec::new();
                    while let Some(chunk) = request.body_mut().data().await {
                        let chunk = chunk.unwrap();
                        request
                            .body_mut()
                            .flow_control()
                            .release_capacity(chunk.len())
                            .unwrap();
                        payload.extend_from_slice(&chunk);
                    }
                    respond
                        .send_response(http::Response::new(()), true)
                        .unwrap();
                    download
                        .send((request.uri().path().to_owned(), payload))
                        .unwrap();
                });
                tokio::select! {
                    _ = conn.accept() => panic!("unexpected upload connection event"),
                    res = read => res.unwrap(),
                }
                while conn.accept().await.is_some() {}
            });

            let c = cfg(json!({"mode": mode, "path": "/xhttp", "xmux": {"max_connections": 1}}));
            let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
                let mut conn = super::connect(Box::new(client), true, true, "srv", 443, &c, dialer)
                    .await
                    .unwrap();
                conn.write_all(b"upload").await.unwrap();
                conn.shutdown().await.unwrap();
                let mut reply = [0u8; 8];
                conn.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"download");
                assert_eq!(c.h2_pool.pooled(), 1);
            })
            .await;
            download_task.abort();
            upload_task.abort();
            result.unwrap_or_else(|_| panic!("{mode} deadlocked on the sole H2 stream"));
        }
    }

    async fn wire_h2_split_roundtrip(mode: &str) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let timeout = std::time::Duration::from_secs(10);

        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let c = cfg(json!({"mode": mode, "path": "/xhttp", "x_padding_bytes": "20-40"}));
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<(String, Vec<u8>)>();

        let server = tokio::spawn(async move {
            let mut h2_srv = crate::outbound::transport::h2io::server_builder()
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server h2 handshake");

            while let Some(Ok((mut req, mut respond))) = h2_srv.accept().await {
                let seen_tx = seen_tx.clone();
                tokio::spawn(async move {
                    let path = req.uri().path().to_string();
                    if req.method() == http::Method::GET {
                        let mut send = respond
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                false,
                            )
                            .expect("send GET response");
                        send.send_data(Bytes::from_static(b"hello-h2"), false)
                            .expect("send GET data");
                        // keep stream open briefly so client reads it
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        let _ = send.send_data(Bytes::new(), true);
                    } else {
                        let mut data = Vec::new();
                        while let Some(Ok(chunk)) = req.body_mut().data().await {
                            let _ = req.body_mut().flow_control().release_capacity(chunk.len());
                            data.extend_from_slice(&chunk);
                        }
                        let _ = seen_tx.send((path, data));
                        respond
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                true,
                            )
                            .expect("send POST response");
                    }
                });
            }
        });

        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(|| {
            Box::pin(async { Err(io::Error::other("h1 dialer must not be called in h2 mode")) })
        });
        // Passing `has_reality = true` marks the in-process stream as h2 without a TLS wrapper.
        let mut conn = tokio::time::timeout(
            timeout,
            super::connect(Box::new(client_io), true, true, "srv", 443, &c, dialer),
        )
        .await
        .expect("connect timed out")
        .expect("connect");

        tokio::time::timeout(timeout, async {
            conn.write_all(b"ping").await.expect("write 0");
            conn.flush().await.expect("flush 0");
            conn.write_all(b"pong").await.expect("write 1");
            conn.flush().await.expect("flush 1");
            conn.shutdown().await.expect("shutdown upload");
            let mut buf = vec![0u8; 8];
            conn.read_exact(&mut buf).await.expect("read");
            assert_eq!(&buf, b"hello-h2");
        })
        .await
        .expect("roundtrip timed out");

        let (p0, b0) = seen_rx.recv().await.expect("POST 0");
        if mode == "packet-up" {
            assert!(p0.starts_with("/xhttp/") && p0.ends_with("/0"), "got {p0}");
            assert_eq!(b0, b"ping");
            let (p1, b1) = seen_rx.recv().await.expect("POST 1");
            assert!(p1.starts_with("/xhttp/") && p1.ends_with("/1"), "got {p1}");
            assert_eq!(b1, b"pong");
        } else {
            assert!(p0.starts_with("/xhttp/"), "got {p0}");
            assert_eq!(b0, b"pingpong");
        }
        drop(conn);
        server.abort();
    }

    /// `auto` under REALITY is one bidirectional POST to the bare path: no
    /// session id, no GET, a gRPC body, and the reply comes down its response.
    #[tokio::test]
    async fn wire_auto_over_reality_is_stream_one() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let timeout = std::time::Duration::from_secs(10);
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let c = cfg(json!({"mode": "auto", "path": "/xhttp"}));
        let (seen_tx, mut seen_rx) = mpsc::unbounded_channel::<(String, String, String)>();
        let server = tokio::spawn(async move {
            let mut h2_srv = crate::outbound::transport::h2io::server_builder()
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server h2 handshake");
            while let Some(Ok((mut req, mut respond))) = h2_srv.accept().await {
                let content_type = req
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("")
                    .to_string();
                let _ = seen_tx.send((
                    req.method().to_string(),
                    req.uri().path().to_string(),
                    content_type,
                ));
                tokio::spawn(async move {
                    let mut send = respond
                        .send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                            false,
                        )
                        .expect("send response");
                    // echo the body, then end with the request
                    while let Some(Ok(chunk)) = req.body_mut().data().await {
                        let _ = req.body_mut().flow_control().release_capacity(chunk.len());
                        let _ = send.send_data(chunk, false);
                    }
                    let _ = send.send_data(Bytes::from_static(b"|end"), true);
                });
            }
        });
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(|| {
            Box::pin(async { Err(io::Error::other("stream-one dials nothing more")) })
        });
        // `has_reality = true`: the session runs as it would under REALITY
        let mut conn = tokio::time::timeout(
            timeout,
            super::connect(Box::new(client_io), true, true, "srv", 443, &c, dialer),
        )
        .await
        .expect("connect timed out")
        .expect("connect");
        tokio::time::timeout(timeout, async {
            conn.write_all(b"ping").await.expect("write");
            conn.flush().await.expect("flush");
            conn.shutdown().await.expect("half-close");
            let mut got = Vec::new();
            conn.read_to_end(&mut got).await.expect("read");
            assert_eq!(got, b"ping|end");
        })
        .await
        .expect("roundtrip timed out");
        let (method, path, content_type) = seen_rx.recv().await.expect("one request");
        assert_eq!(
            (method.as_str(), path.as_str()),
            // the bare path, with the slash Xray adds for path placement
            // (splithttp/config.go GetNormalizedPath)
            ("POST", "/xhttp/"),
            "auto under REALITY must be stream-one"
        );
        assert_eq!(content_type, "application/grpc");
        assert!(
            seen_rx.try_recv().is_err(),
            "stream-one is a single request"
        );
        drop(conn);
        server.abort();
    }

    /// The half-close idle limit the tests below run with.
    const TEST_IDLE: std::time::Duration = std::time::Duration::from_millis(300);

    /// A plain HTTP/1.1 split peer for the half-close tests: the download
    /// connection is handed back raw, every dialled upload connection is
    /// served in the background (200 to each POST, bodies collected).
    struct FakeSplit {
        get_io: tokio::io::DuplexStream,
        bodies: mpsc::UnboundedReceiver<Vec<u8>>,
    }

    async fn packet_up_over_fake_h1() -> (AnyStream, FakeSplit) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, mut get_io) = tokio::io::duplex(1 << 16);
        let (body_tx, bodies) = mpsc::unbounded_channel::<Vec<u8>>();
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(move || {
            let body_tx = body_tx.clone();
            Box::pin(async move {
                let (client, mut server) = tokio::io::duplex(1 << 16);
                tokio::spawn(async move {
                    loop {
                        let mut raw = Vec::new();
                        let mut byte = [0u8; 1];
                        while !raw.ends_with(b"\r\n\r\n") {
                            match server.read(&mut byte).await {
                                Ok(1) => raw.push(byte[0]),
                                _ => return,
                            }
                        }
                        let head = String::from_utf8_lossy(&raw).to_ascii_lowercase();
                        let len = head
                            .lines()
                            .find_map(|l| l.strip_prefix("content-length:"))
                            .and_then(|v| v.trim().parse::<usize>().ok())
                            .unwrap_or(0);
                        let mut body = vec![0u8; len];
                        if server.read_exact(&mut body).await.is_err() {
                            return;
                        }
                        let _ = body_tx.send(body);
                        if server
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await
                            .is_err()
                        {
                            return;
                        }
                    }
                });
                Ok(Box::new(client) as AnyStream)
            })
        });
        let mut c = cfg(json!({"mode": "packet-up", "path": "/xhttp"}));
        c.half_close_idle = TEST_IDLE;
        let conn = tokio::spawn(async move {
            super::connect(Box::new(client_io), false, false, "srv", 443, &c, dialer).await
        });
        let _ = read_request_head(&mut get_io).await;
        get_io
            .write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
            .await
            .unwrap();
        let conn = conn.await.unwrap().expect("connect");
        (conn, FakeSplit { get_io, bodies })
    }

    async fn send_chunk(io: &mut tokio::io::DuplexStream, data: &[u8]) {
        use tokio::io::AsyncWriteExt;
        let mut framed = format!("{:x}\r\n", data.len()).into_bytes();
        framed.extend_from_slice(data);
        framed.extend_from_slice(b"\r\n");
        io.write_all(&framed).await.unwrap();
    }

    /// Half-close is not the end of the download: a response that starts
    /// after the shutdown and takes longer than the idle limit in total, but
    /// never pauses that long, is read to its end.
    #[tokio::test]
    async fn packet_up_half_close_still_reads_the_whole_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut conn, mut peer) = packet_up_over_fake_h1().await;
        conn.write_all(b"request").await.unwrap();
        conn.shutdown().await.expect("half-close");
        assert_eq!(peer.bodies.recv().await.unwrap(), b"request");

        let gap = TEST_IDLE / 3;
        let server = tokio::spawn(async move {
            for i in 0..5u8 {
                tokio::time::sleep(gap).await;
                send_chunk(&mut peer.get_io, &[b'0' + i]).await;
            }
            peer.get_io.write_all(b"0\r\n\r\n").await.unwrap();
            peer.get_io
        });
        let mut got = Vec::new();
        tokio::time::timeout(TEST_IDLE * 10, conn.read_to_end(&mut got))
            .await
            .expect("the response never ended")
            .expect("read");
        assert_eq!(got, b"01234");
        drop(server.await.unwrap());
    }

    /// Half-closed and then nothing from the server for the idle limit: the
    /// session ends, the read sees EOF and the download connection is
    /// closed. Without the limit this waits for the server forever.
    #[tokio::test]
    async fn packet_up_half_close_with_a_silent_download_ends_the_session() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut conn, mut peer) = packet_up_over_fake_h1().await;
        conn.write_all(b"request").await.unwrap();
        conn.shutdown().await.expect("half-close");
        assert_eq!(peer.bodies.recv().await.unwrap(), b"request");

        let started = tokio::time::Instant::now();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), conn.read(&mut buf))
            .await
            .expect("a half-closed, silent session must end")
            .expect("read");
        assert_eq!(n, 0, "EOF");
        assert!(started.elapsed() >= TEST_IDLE);
        // the download GET is cancelled: its connection is closed
        let mut rest = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            peer.get_io.read_to_end(&mut rest),
        )
        .await
        .expect("the download connection stays open")
        .expect("read GET connection");
    }

    /// The relay reads and writes from different tasks: the read is already
    /// pending when the writer half-closes. The limit must still end a silent
    /// session, so arming it has to wake the pending read.
    #[tokio::test]
    async fn split_half_close_with_a_pending_read_ends_a_silent_session() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut conn, mut peer) = packet_up_over_fake_h1().await;
        conn.write_all(b"request").await.unwrap();
        conn.flush().await.unwrap();
        assert_eq!(peer.bodies.recv().await.unwrap(), b"request");
        let (mut reader, mut writer) = tokio::io::split(conn);
        let read = tokio::spawn(async move {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await.map(|_| got)
        });
        // let the read reach Pending before the shutdown arms the limit
        tokio::time::sleep(TEST_IDLE / 3).await;
        let started = tokio::time::Instant::now();
        writer.shutdown().await.expect("half-close");
        let got = tokio::time::timeout(TEST_IDLE * 5, read)
            .await
            .expect("the pending read was not woken by the half-close")
            .unwrap()
            .expect("read");
        assert!(got.is_empty());
        assert!(started.elapsed() >= TEST_IDLE);
        drop(peer);
    }

    /// Same split, but the response arrives after the half-close: it is
    /// still read to its end.
    #[tokio::test]
    async fn split_half_close_with_a_pending_read_still_gets_the_response() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut conn, mut peer) = packet_up_over_fake_h1().await;
        conn.write_all(b"request").await.unwrap();
        conn.flush().await.unwrap();
        assert_eq!(peer.bodies.recv().await.unwrap(), b"request");
        let (mut reader, mut writer) = tokio::io::split(conn);
        let read = tokio::spawn(async move {
            let mut got = Vec::new();
            reader.read_to_end(&mut got).await.map(|_| got)
        });
        tokio::time::sleep(TEST_IDLE / 3).await;
        writer.shutdown().await.expect("half-close");
        let gap = TEST_IDLE / 3;
        for i in 0..5u8 {
            tokio::time::sleep(gap).await;
            send_chunk(&mut peer.get_io, &[b'0' + i]).await;
        }
        peer.get_io.write_all(b"0\r\n\r\n").await.unwrap();
        let got = tokio::time::timeout(TEST_IDLE * 10, read)
            .await
            .expect("the response never ended")
            .unwrap()
            .expect("read");
        assert_eq!(got, b"01234");
    }

    /// Without a half-close there is no idle limit: a quiet tunnel is not a
    /// finished one.
    #[tokio::test]
    async fn packet_up_without_half_close_has_no_idle_limit() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut conn, mut peer) = packet_up_over_fake_h1().await;
        conn.write_all(b"request").await.unwrap();
        conn.flush().await.unwrap();
        assert_eq!(peer.bodies.recv().await.unwrap(), b"request");
        let mut buf = [0u8; 16];
        assert!(
            tokio::time::timeout(TEST_IDLE * 6, conn.read(&mut buf))
                .await
                .is_err(),
            "an idle session that was not half-closed must stay up"
        );
        send_chunk(&mut peer.get_io, b"late").await;
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"late");
    }

    /// Dropping the connection object cancels the download GET.
    #[tokio::test]
    async fn dropping_a_packet_up_conn_closes_the_download() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut conn, mut peer) = packet_up_over_fake_h1().await;
        conn.write_all(b"request").await.unwrap();
        conn.flush().await.unwrap();
        assert_eq!(peer.bodies.recv().await.unwrap(), b"request");
        drop(conn);
        let mut rest = Vec::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            peer.get_io.read_to_end(&mut rest),
        )
        .await
        .expect("the download connection outlives the session")
        .expect("read GET connection");
    }

    /// Over HTTP/2 the cancelled download is a reset of the GET stream.
    #[tokio::test]
    async fn h2_packet_up_half_close_with_a_silent_download_resets_the_get() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        let mut c = cfg(json!({"mode": "packet-up", "path": "/xhttp"}));
        c.half_close_idle = TEST_IDLE;
        let (reset_tx, mut reset_rx) = mpsc::unbounded_channel::<()>();
        let server = tokio::spawn(async move {
            let mut h2_srv = crate::outbound::transport::h2io::server_builder()
                .handshake::<_, Bytes>(server_io)
                .await
                .expect("server h2 handshake");
            while let Some(Ok((mut req, mut respond))) = h2_srv.accept().await {
                let reset_tx = reset_tx.clone();
                tokio::spawn(async move {
                    if req.method() == http::Method::GET {
                        let mut send = respond
                            .send_response(
                                http::Response::builder().status(200).body(()).unwrap(),
                                false,
                            )
                            .unwrap();
                        // silent: only a reset from the client ends this
                        let _ = std::future::poll_fn(|cx| send.poll_reset(cx)).await;
                        let _ = reset_tx.send(());
                    } else {
                        while let Some(Ok(chunk)) = req.body_mut().data().await {
                            let _ = req.body_mut().flow_control().release_capacity(chunk.len());
                        }
                        let _ = respond.send_response(
                            http::Response::builder().status(200).body(()).unwrap(),
                            true,
                        );
                    }
                });
            }
        });
        let dialer: std::sync::Arc<super::Dialer> = std::sync::Arc::new(|| {
            Box::pin(async { Err(io::Error::other("no h1 dial in h2 mode")) })
        });
        let mut conn = super::connect(Box::new(client_io), true, true, "srv", 443, &c, dialer)
            .await
            .expect("connect");
        conn.write_all(b"request").await.unwrap();
        conn.shutdown().await.expect("half-close");
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), conn.read(&mut buf))
            .await
            .expect("a half-closed, silent session must end")
            .expect("read");
        assert_eq!(n, 0);
        tokio::time::timeout(std::time::Duration::from_secs(5), reset_rx.recv())
            .await
            .expect("the GET stream was never reset")
            .expect("reset");
        drop(conn);
        server.abort();
    }

    /// A conn whose download chunks are fed by the test.
    async fn direct_h2_download(
        status: Option<u16>,
        payload: Bytes,
    ) -> (
        XhttpConn,
        JoinHandle<()>,
        JoinHandle<()>,
        mpsc::UnboundedReceiver<h2::Reason>,
        h2::client::SendRequest<Bytes>,
    ) {
        direct_h2_download_profile(status, payload, true).await
    }

    async fn direct_h2_download_profile(
        status: Option<u16>,
        payload: Bytes,
        xray_settings: bool,
    ) -> (
        XhttpConn,
        JoinHandle<()>,
        JoinHandle<()>,
        mpsc::UnboundedReceiver<h2::Reason>,
        h2::client::SendRequest<Bytes>,
    ) {
        let (client_io, server_io) = tokio::io::duplex(65536);
        let (reset_tx, reset_rx) = mpsc::unbounded_channel();
        let (accepted_tx, accepted_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let mut accepted_tx = Some(accepted_tx);
            let mut conn = h2io::server_builder()
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            while let Some(Ok((_request, mut response))) = conn.accept().await {
                if let Some(accepted) = accepted_tx.take() {
                    let _ = accepted.send(());
                }
                let payload = payload.clone();
                let reset_tx = reset_tx.clone();
                tokio::spawn(async move {
                    if let Some(status) = status {
                        let mut send = response
                            .send_response(
                                http::Response::builder().status(status).body(()).unwrap(),
                                payload.is_empty(),
                            )
                            .unwrap();
                        if !payload.is_empty() {
                            send.send_data(payload, true).unwrap();
                        }
                    } else {
                        let reason = std::future::poll_fn(|cx| response.poll_reset(cx))
                            .await
                            .unwrap();
                        reset_tx.send(reason).unwrap();
                    }
                });
            }
        });
        let mut builder = h2io::client_builder();
        if xray_settings {
            apply_xhttp_h2_settings(&mut builder, false);
        }
        let (mut request, connection) = builder.handshake::<_, Bytes>(client_io).await.unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let (response, _upload) = request
            .send_request(
                http::Request::builder()
                    .method("GET")
                    .uri("http://localhost/bench/session")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let mut split = SplitConn::new(&cfg(json!({"mode":"packet-up"})));
        split.set_h2_download_stream(response, false);
        assert!(
            split.dl_task.is_none(),
            "H2 GET must not spawn a forwarding task"
        );
        // Keep the shared client alive like the production H2 pool. Otherwise
        // canceling its sole stream may legitimately close the whole connection.
        // Also ensure HEADERS reached the peer: canceling a never-opened request
        // need not emit RST_STREAM on an idle stream.
        accepted_rx.await.expect("GET accepted before cancellation");
        (
            XhttpConn {
                split: Box::new(split),
            },
            server,
            driver,
            reset_rx,
            request,
        )
    }

    #[tokio::test]
    async fn direct_h2_large_remote_end_finishes_credit_for_both_frame_profiles() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            for selected in [false, true] {
                let (mut conn, server, driver, _, _client) = direct_h2_download_profile(
                    Some(200),
                    Bytes::from(vec![b'x'; 2 * 1024 * 1024 + 3]),
                    selected,
                )
                .await;
                let mut prefix = [0; 3];
                conn.read_exact(&mut prefix).await.unwrap();
                assert_eq!(prefix, [b'x'; 3]);
                let mut buf = [0; 8192];
                for _ in 0..(2 * 1024 * 1024 / buf.len()) {
                    conn.read_exact(&mut buf).await.unwrap();
                    assert!(buf.iter().all(|&byte| byte == b'x'));
                }
                assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
                assert!(conn.split.direct_h2.as_ref().unwrap().body.is_none());
                drop(conn);
                driver.abort();
                server.abort();
            }
        })
        .await
        .expect("large END_STREAM must drain retained credit and expose EOF");
    }

    #[tokio::test]
    async fn direct_h2_download_retains_partial_chunk_before_eof() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (mut conn, server, driver, _, _client) =
                direct_h2_download(Some(200), Bytes::from_static(b"abcdef")).await;
            let mut head = [0; 4];
            conn.read_exact(&mut head).await.unwrap();
            assert_eq!(&head, b"abcd");
            let mut tail = Vec::new();
            conn.read_to_end(&mut tail).await.unwrap();
            assert_eq!(&tail, b"ef");
            assert_eq!(conn.read(&mut head).await.unwrap(), 0);
            drop(conn);
            driver.abort();
            server.abort();
        })
        .await
        .expect("bounded direct H2 download");
    }

    #[tokio::test]
    async fn direct_h2_credit_tracks_partial_reads_and_pause() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (mut conn, server, driver, _, _client) =
                direct_h2_download(Some(200), Bytes::from(vec![b'x'; 16384])).await;
            let mut head = [0; 3];
            conn.read_exact(&mut head).await.unwrap();
            assert_eq!(head, [b'x'; 3]);
            assert_eq!(conn.split.pending.len(), 16381);
            assert_eq!(
                conn.split
                    .direct_h2
                    .as_mut()
                    .unwrap()
                    .body
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .used_capacity(),
                16381,
                "unread suffix must retain its receive credit"
            );
            for _ in 0..3 {
                tokio::task::yield_now().await;
            }
            assert_eq!(
                conn.split
                    .direct_h2
                    .as_mut()
                    .unwrap()
                    .body
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .used_capacity(),
                16381,
                "connection-driver progress must not refund a paused reader's suffix"
            );
            let mut large = vec![0; 32768];
            assert_eq!(
                conn.read(&mut large).await.unwrap(),
                8192,
                "large relay buffers must retain reference body-read quanta"
            );
            assert!(large[..8192].iter().all(|&byte| byte == b'x'));
            assert_eq!(
                conn.split
                    .direct_h2
                    .as_mut()
                    .unwrap()
                    .body
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .used_capacity(),
                8189
            );
            assert_eq!(conn.read(&mut large).await.unwrap(), 8189);
            assert_eq!(conn.read(&mut large).await.unwrap(), 0);
            drop(conn);
            driver.abort();
            server.abort();
        })
        .await
        .expect("bounded partial-read consumed-credit test");
    }

    #[tokio::test]
    async fn direct_h2_buffered_credit_after_driver_eof_does_not_wait_for_dead_driver() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (mut conn, server, driver, _, _client) =
                direct_h2_download(Some(200), Bytes::from(vec![b'x'; 16384])).await;
            let mut buf = [0; 8192];
            conn.read_exact(&mut buf).await.unwrap();
            assert!(buf.iter().all(|&byte| byte == b'x'));
            assert_eq!(conn.split.pending.len(), 8192);
            server.abort();
            assert!(server.await.unwrap_err().is_cancelled());
            tokio::time::timeout(std::time::Duration::from_secs(1), driver)
                .await
                .expect("transport EOF must terminate the driver")
                .unwrap();
            // This successful buffered read happens strictly AFTER recv_eof
            // drained its queues and the connection driver exited.
            conn.read_exact(&mut buf).await.unwrap();
            assert!(buf.iter().all(|&byte| byte == b'x'));
            assert_eq!(
                conn.split
                    .direct_h2
                    .as_mut()
                    .unwrap()
                    .body
                    .as_mut()
                    .unwrap()
                    .flow_control()
                    .used_capacity(),
                0,
                "buffered consumption must return local receive debt exactly once"
            );
            let result = tokio::time::timeout(
                std::time::Duration::from_millis(200),
                conn.read(&mut [0; 1]),
            )
            .await;
            assert!(
                matches!(result, Ok(Ok(0)) | Ok(Err(_))),
                "late buffered credit must never wait for an exited driver: {result:?}"
            );
            assert!(conn.split.direct_h2.as_ref().unwrap().body.is_none());
        })
        .await
        .expect("bounded buffered-after-driver-EOF control");
    }

    #[tokio::test]
    async fn direct_h2_graceful_goaway_keeps_existing_stream_credit_live() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let (client_io, server_io) = tokio::io::duplex(1 << 20);
            let (started_tx, started_rx) = tokio::sync::oneshot::channel();
            let server = tokio::spawn(async move {
                let mut peer = h2io::server_builder()
                    .handshake::<_, Bytes>(server_io)
                    .await
                    .unwrap();
                let (_, mut response) = peer.accept().await.unwrap().unwrap();
                let mut send = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                send.send_data(Bytes::from(vec![b'x'; 8 * 1024 * 1024]), true)
                    .unwrap();
                peer.graceful_shutdown();
                started_tx.send(()).unwrap();
                while let Some(request) = peer.accept().await {
                    assert!(request.is_ok());
                }
            });
            let (mut client, connection) = h2io::client_builder()
                .handshake::<_, Bytes>(client_io)
                .await
                .unwrap();
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (response, _upload) = client
                .send_request(
                    http::Request::builder()
                        .method("GET")
                        .uri("http://localhost/bench/session")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let mut split = SplitConn::new(&cfg(json!({"mode":"packet-up"})));
            split.set_h2_download_stream(response, false);
            let mut conn = XhttpConn {
                split: Box::new(split),
            };
            started_rx.await.unwrap();
            let mut buf = [0; 8192];
            let mut received = 0;
            let mut goaway_observed_before_window_exhaustion = false;
            while received < 8 * 1024 * 1024 {
                conn.read_exact(&mut buf).await.unwrap();
                assert!(buf.iter().all(|&b| b == b'x'));
                received += buf.len();
                tokio::task::yield_now().await;
                let mut cx = Context::from_waker(std::task::Waker::noop());
                if matches!(client.poll_ready(&mut cx), Poll::Ready(Err(_)))
                    && received < 4 * 1024 * 1024
                {
                    goaway_observed_before_window_exhaustion = true;
                }
            }
            assert!(
                goaway_observed_before_window_exhaustion,
                "control must observe GOAWAY before needing existing-stream credit"
            );
            assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
            drop(conn);
            driver.abort();
            server.abort();
        })
        .await
        .expect("GOAWAY must preserve flow control for an eligible existing stream");
    }

    #[tokio::test]
    async fn direct_h2_eof_fence_does_not_hang_after_peer_eof() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (mut conn, server, driver, _, _client) =
                direct_h2_download(Some(200), Bytes::from(vec![b'x'; 16384])).await;
            conn.read_exact(&mut vec![0; 16384]).await.unwrap();
            server.abort();
            let result = conn.read(&mut [0; 1]).await;
            assert!(
                matches!(result, Ok(0) | Err(_)),
                "no extra payload after EOF"
            );
            drop(conn);
            driver.abort();
        })
        .await
        .expect("peer EOF must wake/finish a credit-fenced reader");
    }

    #[tokio::test]
    async fn direct_h2_eof_fence_does_not_hang_after_flush_error() {
        use std::sync::{
            Arc,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        };
        use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite};
        struct FailWrites {
            inner: tokio::io::DuplexStream,
            fail: Arc<AtomicBool>,
            failures: Arc<AtomicUsize>,
        }
        impl AsyncRead for FailWrites {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                out: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, out)
            }
        }
        impl AsyncWrite for FailWrites {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                bytes: &[u8],
            ) -> Poll<io::Result<usize>> {
                if self.fail.load(Ordering::SeqCst) {
                    self.failures.fetch_add(1, Ordering::SeqCst);
                    return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
                }
                Pin::new(&mut self.inner).poll_write(cx, bytes)
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(65536);
            let server = tokio::spawn(async move {
                let mut connection = h2io::server_builder()
                    .handshake::<_, Bytes>(server_io)
                    .await
                    .unwrap();
                while let Some(Ok((_, mut response))) = connection.accept().await {
                    response
                        .send_response(http::Response::new(()), false)
                        .unwrap()
                        .send_data(Bytes::from(vec![b'x'; 16384]), true)
                        .unwrap();
                }
            });
            let fail = Arc::new(AtomicBool::new(false));
            let failures = Arc::new(AtomicUsize::new(0));
            let (mut client, connection) = h2io::client_builder()
                .handshake::<_, Bytes>(FailWrites {
                    inner: client_io,
                    fail: fail.clone(),
                    failures: failures.clone(),
                })
                .await
                .unwrap();
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (response, _) = client
                .send_request(
                    http::Request::builder()
                        .uri("http://localhost/eof")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let mut split = SplitConn::new(&cfg(json!({"mode":"packet-up"})));
            split.set_h2_download_stream(response, false);
            let mut conn = XhttpConn {
                split: Box::new(split),
            };
            conn.read_exact(&mut vec![0; 16384]).await.unwrap();
            fail.store(true, Ordering::SeqCst);
            let result = conn.read(&mut [0; 1]).await;
            assert!(matches!(result, Ok(0) | Err(_)));
            assert!(
                failures.load(Ordering::SeqCst) > 0,
                "a real credit write must fail"
            );
            drop(conn);
            drop(client);
            driver.abort();
            server.abort();
        })
        .await
        .expect("failed credit flush must not strand a body at EOF");
    }

    #[tokio::test]
    async fn direct_h2_exact_pairs_drain_without_more_peer_data() {
        use std::sync::{Arc, Mutex};
        use tokio::io::{AsyncRead, AsyncWrite};
        struct Recorded {
            inner: tokio::io::DuplexStream,
            wire: Arc<Mutex<Vec<u8>>>,
        }
        impl AsyncRead for Recorded {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                out: &mut ReadBuf<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_read(cx, out)
            }
        }
        impl AsyncWrite for Recorded {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
                data: &[u8],
            ) -> Poll<io::Result<usize>> {
                let n = ready!(Pin::new(&mut self.inner).poll_write(cx, data))?;
                self.wire.lock().unwrap().extend_from_slice(&data[..n]);
                Poll::Ready(Ok(n))
            }
            fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut Context<'_>,
            ) -> Poll<io::Result<()>> {
                Pin::new(&mut self.inner).poll_shutdown(cx)
            }
        }
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (client_io, server_io) = tokio::io::duplex(65536);
            let server = tokio::spawn(async move {
                let mut conn = h2io::server_builder()
                    .handshake::<_, Bytes>(server_io)
                    .await
                    .unwrap();
                let mut held = Vec::new();
                while let Some(Ok((_, mut response))) = conn.accept().await {
                    let mut send = response
                        .send_response(http::Response::new(()), false)
                        .unwrap();
                    send.send_data(Bytes::from(vec![b'x'; 16384]), false)
                        .unwrap();
                    held.push(send);
                }
            });
            let wire = Arc::new(Mutex::new(Vec::new()));
            let (mut client, connection) = h2io::client_builder()
                .handshake::<_, Bytes>(Recorded {
                    inner: client_io,
                    wire: wire.clone(),
                })
                .await
                .unwrap();
            let driver = tokio::spawn(async move {
                let _ = connection.await;
            });
            let (response, _) = client
                .send_request(
                    http::Request::builder()
                        .uri("http://localhost/credit")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let mut body = response.await.unwrap().into_body();
            assert_eq!(body.data().await.unwrap().unwrap().len(), 16384);
            // Current-thread executor: no await/driver poll between these two
            // actual read credits, and the peer sends no further H2 DATA.
            wire.lock().unwrap().clear();
            let mut cx = Context::from_waker(std::task::Waker::noop());
            for _ in 0..2 {
                assert!(matches!(
                    body.flow_control()
                        .poll_release_capacity_exact(&mut cx, 8192),
                    Poll::Ready(Ok(()))
                ));
            }
            while wire.lock().unwrap().len() < 52 {
                tokio::task::yield_now().await;
            }
            let bytes = wire.lock().unwrap().clone();
            assert_eq!(bytes.len(), 52);
            let frames = bytes
                .as_chunks::<13>()
                .0
                .iter()
                .map(|frame| {
                    assert_eq!(&frame[..5], &[0, 0, 4, 8, 0]);
                    (
                        u32::from_be_bytes(frame[5..9].try_into().unwrap()),
                        u32::from_be_bytes(frame[9..13].try_into().unwrap()),
                    )
                })
                .collect::<Vec<_>>();
            assert_eq!(frames, vec![(0, 8192), (1, 8192), (0, 8192), (1, 8192)]);
            drop(body);
            drop(client);
            driver.abort();
            server.abort();
        })
        .await
        .expect("all exact pairs must drain without another input wake");
    }

    struct FullH2CreditQueue {
        client: h2::client::SendRequest<Bytes>,
        connection: h2::client::Connection<tokio::io::DuplexStream, Bytes>,
        body: h2::RecvStream,
        resets: mpsc::UnboundedReceiver<h2::Reason>,
        server: JoinHandle<()>,
    }

    /// Stop polling the live connection after receiving the body, so callers
    /// can fill the credit queue and exercise a pending read before resuming.
    async fn full_h2_credit_queue() -> FullH2CreditQueue {
        const BULK: usize = 65 * 8192;
        let (client_io, server_io) = tokio::io::duplex(65536);
        let (reset_tx, resets) = mpsc::unbounded_channel();
        let server = tokio::spawn(async move {
            let mut connection = h2io::server_builder()
                .handshake::<_, Bytes>(server_io)
                .await
                .unwrap();
            while let Some(Ok((request, mut response))) = connection.accept().await {
                let bulk = request.uri().path() == "/bulk";
                let mut send = response
                    .send_response(http::Response::new(()), false)
                    .unwrap();
                send.send_data(
                    if bulk {
                        Bytes::from(vec![b'x'; BULK])
                    } else {
                        Bytes::from_static(b"ok")
                    },
                    !bulk,
                )
                .unwrap();
                if bulk {
                    let reset_tx = reset_tx.clone();
                    tokio::spawn(async move {
                        let reason = std::future::poll_fn(|cx| send.poll_reset(cx))
                            .await
                            .unwrap();
                        reset_tx.send(reason).unwrap();
                    });
                }
            }
        });
        let (mut client, mut connection) = h2io::client_builder()
            .handshake::<_, Bytes>(client_io)
            .await
            .unwrap();
        let (response, _) = client
            .send_request(
                http::Request::builder()
                    .uri("http://localhost/bulk")
                    .body(())
                    .unwrap(),
                true,
            )
            .unwrap();
        let mut body = tokio::select! {
            body = async {
                let mut body = response.await.unwrap().into_body();
                let mut received = 0;
                while received < BULK {
                    let bytes = body.data().await.unwrap().unwrap();
                    assert!(bytes.iter().all(|&byte| byte == b'x'));
                    received += bytes.len();
                }
                assert_eq!(received, BULK);
                body
            } => body,
            result = &mut connection => panic!("credit test connection exited: {result:?}"),
        };
        let mut cx = Context::from_waker(std::task::Waker::noop());
        for _ in 0..64 {
            assert!(matches!(
                body.flow_control()
                    .poll_release_capacity_exact(&mut cx, 8192),
                Poll::Ready(Ok(()))
            ));
        }
        assert!(
            body.flow_control()
                .poll_release_capacity_exact(&mut cx, 8192)
                .is_pending()
        );
        assert_eq!(body.flow_control().used_capacity(), 8192);
        FullH2CreditQueue {
            client,
            connection,
            body,
            resets,
            server,
        }
    }

    #[tokio::test]
    async fn direct_h2_bounded_credit_keeps_neighbor_and_cancel_working() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let FullH2CreditQueue {
                mut client,
                connection,
                mut body,
                mut resets,
                server,
            } = full_h2_credit_queue().await;
            let (neighbor, _) = client
                .send_request(
                    http::Request::builder()
                        .uri("http://localhost/neighbor")
                        .body(())
                        .unwrap(),
                    true,
                )
                .unwrap();
            let driver = tokio::spawn(connection);
            let response = neighbor.await.unwrap();
            let mut split = SplitConn::new(&cfg(json!({"mode":"packet-up"})));
            // A neighboring direct reader uses the same connection while the
            // bulk reader still owns one unreturned consumed quantum.
            split.direct_h2 = Some(DirectH2Download {
                response: None,
                body: Some(response.into_body()),
                credit_due: 0,
                request_gzip: false,
                gzip: None,
            });
            let mut neighbor = XhttpConn {
                split: Box::new(split),
            };
            let mut bytes = Vec::new();
            neighbor.read_to_end(&mut bytes).await.unwrap();
            assert_eq!(bytes, b"ok");
            assert_eq!(body.flow_control().used_capacity(), 8192);
            drop(body);
            assert_eq!(resets.recv().await.unwrap(), h2::Reason::CANCEL);
            drop(neighbor);
            drop(client);
            driver.abort();
            server.abort();
        })
        .await
        .expect("bounded credit must not starve neighbor or cancellation");
    }

    #[tokio::test]
    async fn h2_packet_up_idle_timeout_drains_pending_data_before_eof() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            let FullH2CreditQueue {
                client,
                connection,
                body,
                mut resets,
                server,
            } = full_h2_credit_queue().await;
            let mut split = SplitConn::new(&cfg(json!({"mode":"packet-up"})));
            // The final 8 KiB chunk has been partly read, but there is no
            // space to release the credit for the already consumed bytes.
            split.pending = Bytes::from_static(b"xxxx");
            split.direct_h2 = Some(DirectH2Download {
                response: None,
                body: Some(body),
                credit_due: 8192 - split.pending.len(),
                request_gzip: false,
                gzip: None,
            });
            split.half_closed = Some(HalfClosed::new(std::time::Duration::ZERO));
            let mut conn = XhttpConn {
                split: Box::new(split),
            };
            let mut tail = Vec::new();
            conn.read_to_end(&mut tail).await.unwrap();
            assert_eq!(tail, b"xxxx");
            assert_eq!(conn.read(&mut [0]).await.unwrap(), 0);

            let driver = tokio::spawn(connection);
            assert_eq!(resets.recv().await.unwrap(), h2::Reason::CANCEL);
            drop(client);
            driver.abort();
            server.abort();
        })
        .await
        .expect("half-close timeout must preserve received bytes before EOF");
    }

    #[tokio::test]
    async fn direct_h2_download_reports_rejected_status_once_then_eof() {
        use tokio::io::AsyncReadExt;
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (mut conn, server, driver, _, _client) =
                direct_h2_download(Some(403), Bytes::new()).await;
            let mut buf = [0; 8];
            let error = conn.read(&mut buf).await.unwrap_err();
            assert!(error.to_string().contains("h2 download status: 403"));
            assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
            drop(conn);
            driver.abort();
            server.abort();
        })
        .await
        .expect("bounded direct H2 rejection");
    }

    #[tokio::test]
    async fn direct_h2_finish_resets_get_even_before_response_headers() {
        tokio::time::timeout(std::time::Duration::from_secs(3), async {
            let (mut conn, server, driver, mut resets, _client) =
                direct_h2_download(None, Bytes::new()).await;
            conn.split.finish();
            assert_eq!(resets.recv().await.unwrap(), h2::Reason::CANCEL);
            drop(conn);
            driver.abort();
            server.abort();
        })
        .await
        .expect("dropping an unpolled response must cancel GET");
    }

    /// A conn whose download chunks are fed by the test.
    fn conn_with_download() -> (XhttpConn, mpsc::Sender<io::Result<Bytes>>) {
        let mut split = SplitConn::new(&cfg(json!({"mode": "packet-up", "path": "/xhttp"})));
        let (tx, rx) = mpsc::channel(4);
        split.dl = rx;
        (
            XhttpConn {
                split: Box::new(split),
            },
            tx,
        )
    }

    #[tokio::test]
    async fn download_read_takes_every_queued_chunk() {
        use tokio::io::AsyncReadExt;
        let (mut conn, tx) = conn_with_download();
        for chunk in [&b"abc"[..], b"defg", b"hi"] {
            tx.send(Ok(Bytes::from_static(chunk))).await.unwrap();
        }
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcdefghi");
        tx.send(Ok(Bytes::from_static(b"tail"))).await.unwrap();
        drop(tx);
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"tail");
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn download_read_into_a_small_buffer_keeps_every_byte() {
        use tokio::io::AsyncReadExt;
        let (mut conn, tx) = conn_with_download();
        for chunk in [&b"abc"[..], b"defg", b"hi"] {
            tx.send(Ok(Bytes::from_static(chunk))).await.unwrap();
        }
        drop(tx);
        let mut buf = [0u8; 2];
        let mut reads = Vec::new();
        loop {
            let n = conn.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            reads.push(buf[..n].to_vec());
        }
        assert_eq!(reads.concat(), b"abcdefghi");
        assert!(reads.iter().all(|r| r.len() == 2 || r == b"i"));
    }

    #[tokio::test]
    async fn download_eof_after_queued_chunks_comes_after_the_data() {
        use tokio::io::AsyncReadExt;
        let (mut conn, tx) = conn_with_download();
        tx.send(Ok(Bytes::from_static(b"one"))).await.unwrap();
        tx.send(Ok(Bytes::from_static(b"two"))).await.unwrap();
        drop(tx);
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"onetwo");
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
    }

    #[tokio::test]
    async fn download_error_after_data_is_reported_by_the_next_read() {
        use tokio::io::AsyncReadExt;
        let (mut conn, tx) = conn_with_download();
        tx.send(Ok(Bytes::from_static(b"data"))).await.unwrap();
        tx.send(Err(io::Error::other("broken download")))
            .await
            .unwrap();
        drop(tx);
        let mut buf = [0u8; 64];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"data");
        let e = conn.read(&mut buf).await.unwrap_err();
        assert_eq!(e.to_string(), "broken download");
        assert_eq!(conn.read(&mut buf).await.unwrap(), 0);
    }

    /// Data left in a chunk by a full buffer is served before a queued error.
    #[tokio::test]
    async fn download_error_waits_for_the_rest_of_a_chunk() {
        use tokio::io::AsyncReadExt;
        let (mut conn, tx) = conn_with_download();
        tx.send(Ok(Bytes::from_static(b"abcdef"))).await.unwrap();
        tx.send(Err(io::Error::other("broken download")))
            .await
            .unwrap();
        let mut buf = [0u8; 4];
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"abcd");
        let n = conn.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ef");
        let e = conn.read(&mut buf).await.unwrap_err();
        assert_eq!(e.to_string(), "broken download");
    }
}
