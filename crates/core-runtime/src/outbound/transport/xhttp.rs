//! XHTTP (Xray "splithttp") client transport — HTTP/1.1 and HTTP/2.
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

use super::h1io;
use crate::inbound::AnyStream;

/// Opens one more connection to the same server, with the same TCP options, the
/// same TLS and the same ALPN as the first.
pub(crate) type Dialer =
    dyn Fn() -> Pin<Box<dyn Future<Output = io::Result<AnyStream>> + Send>> + Send + Sync;

/// How long a packet-up session may go without download traffic once the
/// local side has half-closed it. Packet-up cannot tell the server that the
/// upload ended, so an upstream that waits for EOF never answers and never
/// closes; without a limit the session, its download request and the local
/// socket live until the server gives up. Every download chunk restarts the
/// limit, so a response that keeps moving is read to its end. Xray ends the
/// same case with its `downlinkOnly` policy timer (5 s by default); this is
/// twice that. `TACHYON_XHTTP_HALF_CLOSE_IDLE_MS` overrides it.
const HALF_CLOSE_IDLE: std::time::Duration = std::time::Duration::from_secs(10);

fn half_close_idle() -> std::time::Duration {
    static IDLE: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *IDLE.get_or_init(|| {
        if let Ok(val) = std::env::var("TACHYON_XHTTP_HALF_CLOSE_IDLE_MS")
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
        let parts: Vec<&str> = s.split('-').collect();
        let (lo, hi) = match parts.as_slice() {
            [a] => (*a, *a),
            [a, b] => (*a, *b),
            _ => anyhow::bail!("invalid range {s:?}"),
        };
        let lo: u64 = lo
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid range {s:?}"))?;
        let hi: u64 = hi
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("invalid range {s:?}"))?;
        Ok(Range(lo.min(hi), lo.max(hi)))
    }

    fn rand(&self) -> u64 {
        if self.0 == self.1 {
            return self.0;
        }
        let mut b = [0u8; 8];
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut b);
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
            Range::parse(&s("sc_max_each_post_bytes"), Range(1_000_000, 1_000_000))?;
        let uplink_chunk = match s("uplink_chunk_size") {
            v if !v.is_empty() && v != "0" && v != "0-0" => Range::parse(&v, Range(3000, 4000))?,
            _ => match uplink_data {
                UplinkPlacement::Cookie => Range(2048, 3072),
                UplinkPlacement::Header => Range(3000, 4000),
                UplinkPlacement::Body => sc_max_each_post,
            },
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
            sc_min_interval_ms: Range::parse(&s("sc_min_posts_interval_ms"), Range(30, 30))?,
        })
    }
}

pub(crate) struct H2Counter {
    active: std::sync::atomic::AtomicUsize,
    notify: std::sync::Arc<tokio::sync::Notify>,
}

impl std::ops::Deref for H2Counter {
    type Target = std::sync::atomic::AtomicUsize;
    fn deref(&self) -> &Self::Target {
        &self.active
    }
}

struct PooledClient {
    client: h2::client::SendRequest<Bytes>,
    active_streams: std::sync::Arc<H2Counter>,
}

struct H2PoolState {
    clients: Vec<PooledClient>,
    active_dials: usize,
}

pub(crate) struct H2Pool {
    state: std::sync::Mutex<H2PoolState>,
    notify: std::sync::Arc<tokio::sync::Notify>,
}

pub(crate) enum H2Acquire {
    Ready(h2::client::SendRequest<Bytes>, std::sync::Arc<H2Counter>),
    NeedDial(H2DialGuard),
}

pub(crate) struct H2DialGuard(std::sync::Arc<H2Pool>);

impl Drop for H2DialGuard {
    fn drop(&mut self) {
        let mut state = self.0.state.lock().expect("h2 pool");
        state.active_dials -= 1;
        drop(state);
        self.0.notify.notify_waiters();
    }
}

pub(crate) struct TrackedStream {
    inner: AnyStream,
    counter: std::sync::Arc<H2Counter>,
}

impl Drop for TrackedStream {
    fn drop(&mut self) {
        self.counter
            .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
        self.counter.notify.notify_waiters();
    }
}

impl tokio::io::AsyncRead for TrackedStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TrackedStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct CounterGuard(Option<std::sync::Arc<H2Counter>>);

impl CounterGuard {
    fn new(c: std::sync::Arc<H2Counter>) -> Self {
        Self(Some(c))
    }

    fn into_inner(mut self) -> std::sync::Arc<H2Counter> {
        self.0.take().expect("counter present")
    }
}

impl Drop for CounterGuard {
    fn drop(&mut self) {
        if let Some(c) = self.0.take() {
            c.fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
            c.notify.notify_waiters();
        }
    }
}

impl H2Pool {
    pub(crate) fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(H2PoolState {
                clients: Vec::new(),
                active_dials: 0,
            }),
            notify: std::sync::Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub(crate) async fn acquire(
        self: &std::sync::Arc<Self>,
        max_conns: usize,
        max_concurrency: usize,
    ) -> H2Acquire {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            let candidate = {
                let mut guard = self.state.lock().expect("h2 pool");

                let has_capacity = max_concurrency > 0
                    && guard.clients.iter().any(|client| {
                        client
                            .active_streams
                            .load(std::sync::atomic::Ordering::Relaxed)
                            < max_concurrency
                    });
                if !has_capacity && guard.clients.len() + guard.active_dials < max_conns {
                    guard.active_dials += 1;
                    return H2Acquire::NeedDial(H2DialGuard(self.clone()));
                }

                if guard.clients.is_empty() {
                    None
                } else {
                    let best = guard
                        .clients
                        .iter()
                        .enumerate()
                        .filter(|(_, c)| {
                            max_concurrency == 0
                                || c.active_streams.load(std::sync::atomic::Ordering::Relaxed)
                                    < max_concurrency
                        })
                        .min_by_key(|(_, c)| {
                            c.active_streams.load(std::sync::atomic::Ordering::Relaxed)
                        })
                        .map(|(_, best)| best);
                    if let Some(best) = best {
                        let client = best.client.clone();
                        let active = best.active_streams.clone();
                        active.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        Some((client, active))
                    } else {
                        None
                    }
                }
            };

            let Some((candidate, active_streams)) = candidate else {
                notified.await;
                continue;
            };

            let stream_guard = CounterGuard::new(active_streams.clone());
            let client = candidate;
            match client.ready().await {
                Ok(client) => {
                    return H2Acquire::Ready(client, stream_guard.into_inner());
                }
                Err(_) => {
                    drop(stream_guard);
                    self.evict(&active_streams).await;
                }
            }
        }
    }

    pub(crate) async fn evict(&self, active_streams: &std::sync::Arc<H2Counter>) {
        let mut guard = self.state.lock().expect("h2 pool");
        guard
            .clients
            .retain(|c| !std::sync::Arc::ptr_eq(&c.active_streams, active_streams));
        drop(guard);
        self.notify.notify_waiters();
    }

    pub(crate) async fn finish_dial(
        &self,
        client: Option<h2::client::SendRequest<Bytes>>,
        max_conns: usize,
    ) -> Option<std::sync::Arc<H2Counter>> {
        let mut guard = self.state.lock().expect("h2 pool");
        let mut counter = None;
        if let Some(c) = client {
            let cnt = std::sync::Arc::new(H2Counter {
                active: std::sync::atomic::AtomicUsize::new(1),
                notify: self.notify.clone(),
            });
            if guard.clients.len() >= max_conns {
                guard.clients.remove(0);
            }
            guard.clients.push(PooledClient {
                client: c,
                active_streams: cnt.clone(),
            });
            counter = Some(cnt);
        }
        drop(guard);
        self.notify.notify_waiters();
        counter
    }
}

/// How long a pooled HTTP/2 connection waits for a PING answer. Xray takes
/// the `http2.Transport` default, 15 s.
const H2_PING_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// When anything was last read from a pooled HTTP/2 connection.
struct ReadClock {
    base: tokio::time::Instant,
    /// milliseconds since `base`
    last: std::sync::atomic::AtomicU64,
}

impl ReadClock {
    fn new() -> Self {
        Self {
            base: tokio::time::Instant::now(),
            last: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn touch(&self) {
        let ms = self.base.elapsed().as_millis() as u64;
        self.last.store(ms, std::sync::atomic::Ordering::Relaxed);
    }

    fn last(&self) -> u64 {
        self.last.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn idle(&self) -> std::time::Duration {
        self.base
            .elapsed()
            .saturating_sub(std::time::Duration::from_millis(self.last()))
    }
}

/// The socket under a pooled HTTP/2 connection, stamping every read.
struct ReadActivity<S> {
    inner: S,
    clock: std::sync::Arc<ReadClock>,
}

impl<S: AsyncRead + Unpin> AsyncRead for ReadActivity<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let res = Pin::new(&mut self.inner).poll_read(cx, buf);
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            self.clock.touch();
        }
        res
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for ReadActivity<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

type H2Connection = h2::client::Connection<ReadActivity<AnyStream>, Bytes>;

type H2Fresh = (
    h2::client::SendRequest<Bytes>,
    H2Connection,
    std::sync::Arc<ReadClock>,
);

/// HTTP/2 handshake on a fresh connection whose reads are tracked for the
/// keep-alive.
async fn h2_handshake(stream: AnyStream) -> io::Result<H2Fresh> {
    let clock = std::sync::Arc::new(ReadClock::new());
    let io = ReadActivity {
        inner: stream,
        clock: clock.clone(),
    };
    let (send_request, connection) = super::h2io::client_builder()
        .handshake(io)
        .await
        .map_err(|e| io::Error::other(format!("xhttp: h2 handshake: {e}")))?;
    Ok((send_request, connection, clock))
}

/// Returns once the connection fails its liveness check, as Xray's
/// `ReadIdleTimeout` does: after `period` with nothing read, send a PING and
/// give it `ping_timeout` ([`H2_PING_TIMEOUT`]). A connection that keeps delivering frames is
/// never pinged, and one that delivers anything while a PING is out is given
/// another timeout, so only a peer that is silent for the whole timeout fails.
async fn h2_keep_alive(
    ping_pong: &mut h2::PingPong,
    clock: &ReadClock,
    period: std::time::Duration,
    ping_timeout: std::time::Duration,
) -> &'static str {
    loop {
        let idle = clock.idle();
        if idle < period {
            tokio::time::sleep(period - idle).await;
            continue;
        }
        let mut seen = clock.last();
        let ping = ping_pong.ping(h2::Ping::opaque());
        tokio::pin!(ping);
        loop {
            match tokio::time::timeout(ping_timeout, ping.as_mut()).await {
                Ok(Ok(_)) => break,
                Ok(Err(_)) => return "ping failed",
                Err(_) if clock.last() != seen => seen = clock.last(),
                Err(_) => return "no PING answer",
            }
        }
    }
}

/// Drives one pooled HTTP/2 connection. When it ends or stops answering
/// PINGs it leaves the pool; dropping it fails the streams still on it.
async fn drive_h2_connection(
    mut connection: H2Connection,
    clock: std::sync::Arc<ReadClock>,
    keep_alive: Option<(std::time::Duration, std::time::Duration)>,
    pool: std::sync::Weak<H2Pool>,
    counter: std::sync::Arc<H2Counter>,
) {
    let ping_pong = keep_alive.and_then(|times| Some((connection.ping_pong()?, times)));
    match ping_pong {
        Some((mut ping_pong, (period, ping_timeout))) => {
            tokio::select! {
                res = &mut connection => {
                    if let Err(e) = res {
                        crate::logging::debug(format_args!("xhttp h2 connection: {e}"));
                    }
                }
                why = h2_keep_alive(&mut ping_pong, &clock, period, ping_timeout) => {
                    crate::logging::debug(format_args!("xhttp h2 connection: {why}, closing"));
                }
            }
        }
        None => {
            if let Err(e) = connection.await {
                crate::logging::debug(format_args!("xhttp h2 connection: {e}"));
            }
        }
    }
    if let Some(pool) = pool.upgrade() {
        pool.evict(&counter).await;
    }
}

#[derive(Clone)]
pub(crate) struct XhttpConfig {
    host: Option<String>,
    path: String,
    mode: Mode,
    headers: Vec<(String, String)>,
    padding: Range,
    no_grpc_header: bool,
    meta: Meta,
    /// keep-alive connections shared by the upload POSTs of every dial of this
    /// transport
    pool: std::sync::Arc<super::xmux::Pool>,
    h2_pool: std::sync::Arc<H2Pool>,
    /// see [`HALF_CLOSE_IDLE`]
    half_close_idle: std::time::Duration,
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
        let mut path = t
            .get("path")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string();
        if !path.starts_with('/') {
            path.insert(0, '/');
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
        Ok(Self {
            host,
            path,
            mode,
            headers,
            padding: Range::parse(
                t.get("x_padding_bytes")
                    .and_then(Value::as_str)
                    .unwrap_or(""),
                Range(100, 1000),
            )?,
            no_grpc_header: t.get("no_grpc_header").and_then(Value::as_bool) == Some(true),
            meta: Meta::resolve(t, mode)?,
            pool: super::xmux::Pool::new(super::xmux::XmuxConfig::parse(
                t.get("xmux"),
                "v2ray-xhttp.xmux",
            )?),
            h2_pool: std::sync::Arc::new(H2Pool::new()),
            half_close_idle: half_close_idle(),
        })
    }
}

pub(crate) enum H2Connect {
    Stream(AnyStream),
    Fallback(AnyStream),
    Skip,
}

impl XhttpConfig {
    fn authority_for(&self, sni: &str, server: &str, port: u16) -> String {
        if let Some(host) = &self.host {
            return host.clone();
        }
        if !sni.is_empty() && sni != server {
            return sni.to_string();
        }
        if server.contains(':') && !server.starts_with('[') {
            format!("[{server}]:{port}")
        } else {
            format!("{server}:{port}")
        }
    }

    async fn open_h2_session(
        &self,
        mut send_req: h2::client::SendRequest<Bytes>,
        counter: std::sync::Arc<H2Counter>,
        scheme: &str,
        authority: &str,
        mode: Mode,
    ) -> io::Result<AnyStream> {
        let guard = CounterGuard::new(counter);
        if mode == Mode::StreamOne {
            let request = self.build_request(
                scheme,
                authority,
                &self.meta.uplink_method,
                None,
                None,
                true,
            )?;
            let (response, send) = send_req
                .send_request(request, false)
                .map_err(|e| io::Error::other(format!("xhttp: send_request: {e}")))?;
            let stream: AnyStream = Box::new(super::h2io::H2Io {
                h2: super::h2io::H2Stream::shared(response, send),
            });
            return Ok(Box::new(TrackedStream {
                inner: stream,
                counter: guard.into_inner(),
            }));
        }

        let mut this = SplitConn::new(self);
        let get_req = self.build_request(
            scheme,
            authority,
            "GET",
            Some(&this.session_id),
            None,
            false,
        )?;
        let (get_resp, _get_send) = send_req
            .send_request(get_req, true)
            .map_err(|e| io::Error::other(format!("xhttp: h2 GET send_request: {e}")))?;
        this.spawn_h2_download_stream(get_resp);

        match mode {
            Mode::StreamUp => {
                let up_req = self.build_request(
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
                let (up_resp, up_send) = up_client
                    .send_request(up_req, false)
                    .map_err(|e| io::Error::other(format!("xhttp: h2 upload send_request: {e}")))?;
                let failure = Failure::default();
                this.up = Up::H2Stream(Box::new(H2StreamUp {
                    io: super::h2io::H2Io {
                        h2: super::h2io::H2Stream::upload_only(up_send),
                    },
                    failure: failure.clone(),
                }));
                this.spawn_h2_upload_ack(up_resp, failure);
            }
            _ => {
                let (client_write, worker_read) = tokio::io::duplex(128 * 1024);
                let failure = Failure::default();
                let writer = PostWriter {
                    cfg: self.clone(),
                    scheme: scheme.to_string(),
                    authority: authority.to_string(),
                    session_id: this.session_id.clone(),
                    seq: 0,
                    dialer: std::sync::Arc::new(|| {
                        Box::pin(async {
                            Err(io::Error::other(
                                "xhttp: h2 packet-up does not use h1 dialer",
                            ))
                        })
                    }),
                    h2_client: Some(send_req),
                };
                let bytes_written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let bytes_flushed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
                let flush_notify = std::sync::Arc::new(tokio::sync::Notify::new());
                let task = tokio::spawn(packet_upload_worker(
                    worker_read,
                    writer,
                    failure.clone(),
                    std::sync::Arc::clone(&bytes_flushed),
                    std::sync::Arc::clone(&flush_notify),
                ));
                this.up = Up::Packets(Box::new(PacketsUp {
                    io: client_write,
                    failure,
                    bytes_written,
                    bytes_flushed,
                    flush_notify,
                    flush_wait: None,
                    task,
                }));
            }
        }

        Ok(Box::new(TrackedStream {
            inner: Box::new(XhttpConn {
                split: Box::new(this),
            }),
            counter: guard.into_inner(),
        }))
    }

    pub(crate) async fn connect_h2_stream(
        &self,
        tls: Option<&crate::tls_client::TlsOptions>,
        server: &str,
        port: u16,
        dial: &crate::outbound::dial::DialOptions,
    ) -> io::Result<H2Connect> {
        let Some(tls) = tls else {
            return Ok(H2Connect::Skip);
        };
        if self.h1_only(Some(tls)) {
            return Ok(H2Connect::Skip);
        }
        let has_reality = tls.reality().is_some();
        let mode = self.resolved_mode(has_reality);
        let authority = self.authority_for(tls.server_name(), server, port);
        let scheme = "https";
        let max_conns = self.pool.max_connections();

        {
            let acq = self
                .h2_pool
                .acquire(max_conns, self.pool.max_concurrency())
                .await;
            match acq {
                H2Acquire::Ready(send_req, counter) => {
                    let result = self
                        .open_h2_session(send_req, counter.clone(), scheme, &authority, mode)
                        .await;
                    if result.is_err() {
                        self.h2_pool.evict(&counter).await;
                    }
                    result.map(H2Connect::Stream)
                }
                H2Acquire::NeedDial(dial_guard) => {
                    let dialed: io::Result<Result<H2Fresh, AnyStream>> = async {
                        let tcp = crate::outbound::dial::connect_tcp(server, port, dial).await?;
                        let alpn: &[&[u8]] = &[b"h2", b"http/1.1"];
                        let stream = tls.wrap_with_defaults(tcp, alpn).await?;
                        let negotiated = crate::inbound::stream_alpn(&stream);
                        // Xray REALITY sets NextProtos = nil on the server (so EncryptedExtensions
                        // carries no ALPN, logged as alpn=[]) while serving HTTP/2 (SetUnencryptedHTTP2)
                        // on the inner listener. Standard TLS servers without h2 ALPN fall back to
                        // the HTTP/1.1 xhttp::connect path on the already-established stream.
                        let is_h2 = negotiated == Some(b"h2")
                            || (has_reality && negotiated != Some(b"http/1.1"));
                        if !is_h2 {
                            return Ok(Err(stream));
                        }
                        Ok(Ok(h2_handshake(stream).await?))
                    }
                    .await;

                    match dialed {
                        Ok(Ok((send_request, connection, clock))) => {
                            let counter = self
                                .register_h2(send_request.clone(), connection, clock, max_conns)
                                .await;
                            drop(dial_guard);
                            let guard = CounterGuard::new(counter.clone());
                            let send_req = match send_request.ready().await {
                                Ok(req) => req,
                                Err(e) => {
                                    drop(guard);
                                    self.h2_pool.evict(&counter).await;
                                    return Err(io::Error::other(format!("xhttp: h2 ready: {e}")));
                                }
                            };
                            let stream = self
                                .open_h2_session(
                                    send_req,
                                    guard.into_inner(),
                                    scheme,
                                    &authority,
                                    mode,
                                )
                                .await?;
                            Ok(H2Connect::Stream(stream))
                        }
                        Ok(Err(fallback_stream)) => {
                            drop(dial_guard);
                            Ok(H2Connect::Fallback(fallback_stream))
                        }
                        Err(e) => {
                            drop(dial_guard);
                            Err(e)
                        }
                    }
                }
            }
        }
    }

    /// Put a fresh HTTP/2 connection into the pool and start driving it,
    /// with the xmux keep-alive.
    async fn register_h2(
        &self,
        send_request: h2::client::SendRequest<Bytes>,
        connection: H2Connection,
        clock: std::sync::Arc<ReadClock>,
        max_conns: usize,
    ) -> std::sync::Arc<H2Counter> {
        let counter = self
            .h2_pool
            .finish_dial(Some(send_request), max_conns)
            .await
            .expect("counter present");
        tokio::spawn(drive_h2_connection(
            connection,
            clock,
            self.pool
                .h2_keep_alive()
                .map(|period| (period, H2_PING_TIMEOUT)),
            std::sync::Arc::downgrade(&self.h2_pool),
            counter.clone(),
        ));
        counter
    }

    /// The mode a session runs in. `auto` follows Xray (splithttp/dialer.go,
    /// `mode == "auto"`): packet-up, or stream-one under REALITY. Xray picks
    /// stream-up for REALITY with `downloadSettings`, which this client has not.
    fn resolved_mode(&self, has_reality: bool) -> Mode {
        match self.mode {
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
        tls.alpn().len() == 1 && tls.alpn()[0].as_slice() == b"http/1.1"
    }
}

/// One xhttp tunnel: a download source and an upload sink. Over HTTP/1.1 those
/// are two connections, not two streams on one.
pub(crate) struct XhttpConn {
    split: Box<SplitConn>,
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
    let negotiated = crate::inbound::stream_alpn(&stream);
    let is_h2 = negotiated == Some(b"h2") || (has_reality && negotiated != Some(b"http/1.1"));
    let authority = cfg.authority_for("", server, port);
    let scheme = if secure { "https" } else { "http" };
    let mode = cfg.resolved_mode(has_reality);
    crate::logging::debug(format_args!(
        "xhttp: connect {server}:{port} secure={secure} is_h2={is_h2} mode={mode:?}"
    ));

    // Over HTTP/2, stream-one, stream-up, and packet-up all multiplex streams
    // over the pooled HTTP/2 connection.
    if is_h2 {
        let (send_request, connection, clock) = h2_handshake(stream).await?;
        let max_conns = cfg.pool.max_connections();
        let counter = cfg
            .register_h2(send_request.clone(), connection, clock, max_conns)
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
            .open_h2_session(send_req, guard.into_inner(), scheme, &authority, mode)
            .await;
    }

    let mut this = SplitConn::new(cfg);

    // stream-one is one bidirectional request on one connection: the body goes
    // up and the response comes back down it, so there is no separate download.
    if mode == Mode::StreamOne {
        let request = cfg.build_request(
            scheme,
            &authority,
            &cfg.meta.uplink_method,
            None,
            None,
            true,
        )?;
        let (io, resp) = h1io::Stream::start(stream, &request, &authority, true).await?;
        let failure = Failure::default();
        this.up = Up::Stream(Box::new(StreamUp {
            io,
            failure: failure.clone(),
        }));
        this.spawn_upload_download(resp, failure);
        return Ok(Box::new(XhttpConn {
            split: Box::new(this),
        }));
    }

    // The download GET is a long request, so it takes a connection of its own
    // with `Connection: close` — the reference says outright that a download GET
    // never shares one. The connection the caller dialled is exactly that, so
    // nothing extra is opened for it.
    let mut io = stream;
    let request = cfg.build_request(
        scheme,
        &authority,
        "GET",
        Some(&this.session_id),
        None,
        false,
    )?;
    let mut head_bytes = Vec::with_capacity(256);
    h1io::write_head(
        &mut head_bytes,
        &request,
        &authority,
        h1io::Framing::None,
        true,
    );
    io.write_all(&head_bytes).await?;
    io.flush().await?;
    this.spawn_download_stream(io);

    match mode {
        Mode::StreamUp => {
            let request = cfg.build_request(
                scheme,
                &authority,
                &cfg.meta.uplink_method,
                Some(&this.session_id),
                None,
                true,
            )?;
            let io = (dialer)().await?;
            let (io, resp) = h1io::Stream::start(io, &request, &authority, false).await?;
            let failure = Failure::default();
            this.up = Up::Stream(Box::new(StreamUp {
                io,
                failure: failure.clone(),
            }));
            // the upload's own response carries nothing back: it only says
            // whether the server took the request
            this.spawn_upload_ack(resp, failure);
        }
        // packet-up (and auto→packet-up)
        _ => {
            let (client_write, worker_read) = tokio::io::duplex(128 * 1024);
            let failure = Failure::default();
            let writer = PostWriter {
                cfg: cfg.clone(),
                scheme: scheme.to_string(),
                authority: authority.clone(),
                session_id: this.session_id.clone(),
                seq: 0,
                dialer,
                h2_client: None,
            };
            let bytes_written = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let bytes_flushed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let flush_notify = std::sync::Arc::new(tokio::sync::Notify::new());
            let task = tokio::spawn(packet_upload_worker(
                worker_read,
                writer,
                failure.clone(),
                std::sync::Arc::clone(&bytes_flushed),
                std::sync::Arc::clone(&flush_notify),
            ));
            this.up = Up::Packets(Box::new(PacketsUp {
                io: client_write,
                failure,
                bytes_written,
                bytes_flushed,
                flush_notify,
                flush_wait: None,
                task,
            }));
        }
    }
    Ok(Box::new(XhttpConn {
        split: Box::new(this),
    }))
}

/// What an upload request's response said, once the task behind it has seen it.
///
/// The error lives behind a lock rather than in the write path because it
/// arrives on somebody else's task: a refused upload POST shows up as the next
/// `poll_write` failing, not as the write that was already in flight.
#[derive(Clone, Default)]
struct Failure(std::sync::Arc<std::sync::Mutex<Option<io::Error>>>);

impl Failure {
    fn set(&self, e: io::Error) {
        if let Ok(mut slot) = self.0.lock() {
            *slot = Some(e);
        }
    }

    fn take(&self) -> Option<io::Error> {
        self.0.lock().ok().and_then(|mut slot| slot.take())
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

struct PostWriter {
    cfg: XhttpConfig,
    scheme: String,
    authority: String,
    session_id: String,
    seq: u64,
    dialer: std::sync::Arc<Dialer>,
    h2_client: Option<h2::client::SendRequest<Bytes>>,
}

impl PostWriter {
    /// A keep-alive connection for one upload POST, out of the pool when there
    /// is a free one and dialled when there is not.
    async fn connection(&self) -> io::Result<(super::xmux::Lease, AnyStream)> {
        if let Some(client) = self.cfg.pool.acquire().await {
            let mut lease = super::xmux::Lease::new(client);
            if let Some(io) = lease.take() {
                return Ok((lease, io));
            }
        }
        let (client, io) = self.fresh_connection().await?;
        Ok((client, io))
    }

    /// Always dial a fresh HTTP/1.1 connection and register it in the pool.
    async fn fresh_connection(&self) -> io::Result<(super::xmux::Lease, AnyStream)> {
        let io = (self.dialer)().await?;
        let client = self.cfg.pool.insert(io).await;
        // `insert` parks the connection in the pool, and the pool is the only
        // owner, so it comes back out through the same door
        let mut lease = super::xmux::Lease::new(client);
        let io = lease
            .take()
            .ok_or_else(|| io::Error::other("xhttp: pooled connection unavailable"))?;
        Ok((lease, io))
    }

    /// Send one upload chunk over HTTP/2.
    async fn send_packet_h2(
        &self,
        client: h2::client::SendRequest<Bytes>,
        req: http::Request<()>,
        payload: Bytes,
    ) -> io::Result<()> {
        let mut client = client
            .ready()
            .await
            .map_err(|e| io::Error::other(format!("xhttp: h2 post ready: {e}")))?;
        let end_of_stream = payload.is_empty();
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
            let bytes = chunk.map_err(|e| io::Error::other(format!("xhttp: h2 post body: {e}")))?;
            let _ = body.flow_control().release_capacity(bytes.len());
        }
        Ok(())
    }

    /// Send one upload chunk as a single sequenced POST (reference
    /// `packetConn.sendPacket`).
    async fn send_packet(&mut self, chunk: &[u8]) -> io::Result<()> {
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
            UplinkPlacement::Body => Some(Bytes::copy_from_slice(chunk)),
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
            let chunk_size = self.cfg.meta.uplink_chunk.rand().max(1) as usize;
            let bytes = b64.as_bytes();
            let mut at = 0;
            while at < bytes.len() {
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
            let hvalue = http::HeaderValue::try_from(*piece)
                .map_err(|e| io::Error::other(format!("xhttp: header value: {e}")))?;
            if let UplinkPlacement::Cookie = self.cfg.meta.uplink_data {
                if let Some(h) = req.headers_mut().get_mut("cookie") {
                    let mut v = h.as_bytes().to_vec();
                    v.extend_from_slice(format!("; {}={}", name, piece).as_bytes());
                    *h = v
                        .try_into()
                        .map_err(|e| io::Error::other(format!("xhttp: cookie: {e}")))?;
                    continue;
                }
                req.headers_mut().insert("cookie", hvalue);
            } else {
                req.headers_mut().insert(hname, hvalue);
            }
        }
        let payload = payload.unwrap_or_default();

        if let Some(h2_client) = &self.h2_client {
            return self.send_packet_h2(h2_client.clone(), req, payload).await;
        }

        let (lease, io) = self.connection().await?;
        lease.client.take_request();
        // Never replay a POST after an ambiguous response failure: the peer
        // may already have accepted this sequence and its payload.
        let (head, mut body) = Self::post(io, &req, &self.authority, &payload).await?;
        h1io::expect_ok(&head, "upload")?;
        body.drain().await?;
        if let Some(io) = body.into_inner() {
            lease.client.give(io);
        }
        // Drop returns usage, and retires a connection with no complete body.
        Ok(())
    }

    /// One `Content-Length` POST plus its response head, over one connection.
    /// The connection comes back inside the body, and only out of it once the
    /// body has been drained.
    async fn post(
        io: AnyStream,
        request: &http::Request<()>,
        authority: &str,
        payload: &[u8],
    ) -> io::Result<(h1io::Head, h1io::Body)> {
        let mut io = io;
        let (head, pending) = h1io::send(&mut io, request, authority, payload, false)
            .await
            .map_err(|e| io::Error::other(format!("xhttp: send packet: {e}")))?;
        let body = h1io::Body::new(io, &head, pending);
        Ok((head, body))
    }
}

struct SplitConn {
    /// The rest of the last download chunk.
    pending: Bytes,
    /// A download error met by a read that already returned data; the next
    /// read reports it.
    dl_error: Option<io::Error>,
    dl: mpsc::Receiver<io::Result<Bytes>>,
    dl_task: tokio::task::JoinHandle<()>,
    ack_task: Option<tokio::task::JoinHandle<()>>,
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
    bytes_written: std::sync::Arc<std::sync::atomic::AtomicU64>,
    bytes_flushed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    flush_notify: std::sync::Arc<tokio::sync::Notify>,
    flush_wait: Option<Pin<Box<dyn std::future::Future<Output = ()> + Send>>>,
    task: tokio::task::JoinHandle<()>,
}

enum Up {
    Stream(Box<StreamUp>),
    H2Stream(Box<H2StreamUp>),
    Packets(Box<PacketsUp>),
    None,
}

impl SplitConn {
    fn new(cfg: &XhttpConfig) -> Self {
        let session_id = new_session_id(&cfg.meta);
        let (_, dl) = mpsc::channel(4);
        Self {
            pending: Bytes::new(),
            dl_error: None,
            dl,
            dl_task: tokio::spawn(async {}),
            ack_task: None,
            up: Up::None,
            session_id,
            half_closed: None,
            half_close_limit: cfg.half_close_idle,
            read_waker: None,
        }
    }

    /// End the whole session: cancel the download request (an HTTP/1.1
    /// download connection is closed, an HTTP/2 stream is reset) and stop
    /// the upload. Reads see EOF from here on.
    fn finish(&mut self) {
        self.dl_task.abort();
        if let Some(ack) = self.ack_task.take() {
            ack.abort();
        }
        if let Up::Packets(state) = &mut self.up {
            state.task.abort();
        }
        self.dl.close();
        self.half_closed = None;
    }

    /// Read GET headers concurrently with upload; a server may await the
    /// first VLESS payload before answering the download request.
    fn spawn_download_stream(&mut self, mut io: AnyStream) {
        let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(4);
        self.dl = rx;
        self.dl_task = tokio::spawn(async move {
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
            pump(h1io::Body::new(io, &head, pending), tx).await;
        });
    }

    /// Feed the download channel from an HTTP/2 GET stream without blocking initial dial.
    fn spawn_h2_download_stream(&mut self, response: h2::client::ResponseFuture) {
        let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(4);
        self.dl = rx;
        self.dl_task = tokio::spawn(async move {
            let resp = match response.await {
                Ok(r) => r,
                Err(e) => {
                    let _ = tx
                        .send(Err(io::Error::other(format!(
                            "xhttp: h2 download response: {e}"
                        ))))
                        .await;
                    return;
                }
            };
            if resp.status().as_u16() != 200 {
                let _ = tx
                    .send(Err(io::Error::other(format!(
                        "xhttp: h2 download status: {}",
                        resp.status()
                    ))))
                    .await;
                return;
            }
            let mut body = resp.into_body();
            while let Some(chunk) = body.data().await {
                match chunk {
                    Ok(bytes) => {
                        let len = bytes.len();
                        let _ = body.flow_control().release_capacity(len);
                        if !bytes.is_empty() && tx.send(Ok(bytes)).await.is_err() {
                            return;
                        }
                    }
                    Err(e) => {
                        let _ = tx
                            .send(Err(io::Error::other(format!(
                                "xhttp: h2 download body: {e}"
                            ))))
                            .await;
                        return;
                    }
                }
            }
        });
    }

    /// The upload request's response when it *is* the download stream, which is
    /// what stream-one does: one request, body up and body down.
    fn spawn_upload_download(
        &mut self,
        task: JoinHandle<io::Result<h1io::Body>>,
        failure: Failure,
    ) {
        let (tx, rx) = mpsc::channel::<io::Result<Bytes>>(4);
        self.dl = rx;
        self.dl_task = tokio::spawn(async move {
            match task.await {
                Ok(Ok(body)) => pump(body, tx).await,
                Ok(Err(e)) => {
                    failure.set(e);
                    let _ = tx.send(Err(failure.take().expect("just set"))).await;
                }
                Err(e) => {
                    let e = io::Error::other(format!("xhttp: upload: {e}"));
                    failure.set(io::Error::other(e.to_string()));
                    let _ = tx.send(Err(e)).await;
                }
            }
        });
    }

    /// The upload request's response when nothing comes back through it, which
    /// is stream-up: the download has a connection of its own, so this response
    /// only says whether the server took the request. Drain it and keep a
    /// failure for the next write.
    fn spawn_upload_ack(&mut self, task: JoinHandle<io::Result<h1io::Body>>, failure: Failure) {
        if let Some(old) = self.ack_task.take() {
            old.abort();
        }
        self.ack_task = Some(tokio::spawn(async move {
            let mut body = match task.await {
                Ok(Ok(body)) => body,
                Ok(Err(e)) => {
                    failure.set(e);
                    return;
                }
                Err(e) => {
                    failure.set(io::Error::other(format!("xhttp: upload: {e}")));
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
async fn pump(mut body: h1io::Body, tx: mpsc::Sender<io::Result<Bytes>>) {
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
        if let Some(e) = split.dl_error.take() {
            return Poll::Ready(Err(e));
        }
        // Fill the buffer from the chunks already queued; whatever ends the
        // download after some data waits for the next read.
        let mut filled = false;
        loop {
            if !split.pending.is_empty() {
                let n = out.remaining().min(split.pending.len());
                out.put_slice(&split.pending[..n]);
                bytes::Buf::advance(&mut split.pending, n);
                filled = true;
                if out.remaining() == 0 {
                    return Poll::Ready(Ok(()));
                }
            }
            match split.dl.poll_recv(cx) {
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
                    return Poll::Ready(Ok(()));
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
                if let Some(e) = state.failure.take() {
                    return Poll::Ready(Err(e));
                }
                Pin::new(&mut state.io).poll_write(cx, buf)
            }
            Up::H2Stream(state) => {
                if let Some(e) = state.failure.take() {
                    return Poll::Ready(Err(e));
                }
                Pin::new(&mut state.io).poll_write(cx, buf)
            }
            Up::Packets(state) => {
                if let Some(e) = state.failure.take() {
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
            Up::Stream(state) => Pin::new(&mut state.io).poll_flush(cx),
            Up::H2Stream(state) => Pin::new(&mut state.io).poll_flush(cx),
            Up::Packets(state) => {
                if let Some(e) = state.failure.take() {
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
                    if let Some(e) = state.failure.take() {
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
                ready!(Pin::new(&mut state.io).poll_shutdown(cx))?;
            }
            Up::H2Stream(state) => {
                ready!(Pin::new(&mut state.io).poll_shutdown(cx))?;
            }
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
        self.dl_task.abort();
        if let Some(ack) = self.ack_task.take() {
            ack.abort();
        }
        if let Up::Packets(state) = &mut self.up {
            state.task.abort();
        }
    }
}

/// Background worker reading from the write pipe and uploading sequential POST packets.
async fn packet_upload_worker(
    mut reader: tokio::io::DuplexStream,
    mut writer: PostWriter,
    failure: Failure,
    bytes_flushed: std::sync::Arc<std::sync::atomic::AtomicU64>,
    flush_notify: std::sync::Arc<tokio::sync::Notify>,
) {
    let max_each = writer.cfg.meta.sc_max_each_post.rand().max(1) as usize;
    let min_interval = std::time::Duration::from_millis(writer.cfg.meta.sc_min_interval_ms.rand());
    let mut buf = vec![0u8; max_each];
    let mut last_post: Option<std::time::Instant> = None;

    loop {
        let mut n = match reader.read(&mut buf).await {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) => {
                failure.set(e);
                break;
            }
        };

        if let Some(last) = last_post
            && min_interval > std::time::Duration::ZERO
        {
            let deadline = tokio::time::Instant::from_std(last + min_interval);
            // The configured interval already delays the next POST. Use that
            // time to collect caller bytes, rather than freezing a tiny packet
            // while the duplex pipe fills behind it. Keep the same size bound,
            // interval and sequence ordering; the first packet is immediate.
            while n < buf.len() && tokio::time::Instant::now() < deadline {
                tokio::select! {
                    biased;
                    _ = tokio::time::sleep_until(deadline) => break,
                    next = reader.read(&mut buf[n..]) => match next {
                        Ok(0) => break,
                        Ok(got) => n += got,
                        Err(e) => {
                            failure.set(e);
                            flush_notify.notify_waiters();
                            return;
                        }
                    }
                }
            }
            tokio::time::sleep_until(deadline).await;
        }
        last_post = Some(std::time::Instant::now());

        if let Err(e) = writer.send_packet(&buf[..n]).await {
            crate::logging::debug(format_args!("xhttp packet upload failed: {e}"));
            failure.set(e);
            break;
        }

        bytes_flushed.fetch_add(n as u64, std::sync::atomic::Ordering::Release);
        flush_notify.notify_waiters();
    }
    flush_notify.notify_waiters();
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
        let mut path = self.path.clone();
        let mut query: Vec<(String, String)> = Vec::new();
        let mut extra_headers: Vec<(String, String)> = Vec::new();

        let m = &self.meta;
        // stream-one targets the bare path (no session id segment).
        if let Some(sid) = session {
            match m.session_placement {
                Placement::Path => {
                    if !path.ends_with('/') {
                        path.push('/');
                    }
                    path.push_str(sid);
                }
                Placement::Query => query.push((m.session_key.clone(), sid.to_string())),
                Placement::Header => extra_headers.push((m.session_key.clone(), sid.to_string())),
                Placement::Cookie => {
                    extra_headers.push(("cookie".to_string(), format!("{}={}", m.session_key, sid)))
                }
            }
        } else if !path.ends_with('/') {
            // stream-one: the reference client and Xray server expect the path to end
            // with a trailing slash when matching the route.
            path.push('/');
        }
        if let Some(seq) = seq {
            match m.seq_placement {
                Placement::Path => {
                    if !path.ends_with('/') {
                        path.push('/');
                    }
                    path.push_str(seq);
                }
                Placement::Query => query.push((m.seq_key.clone(), seq.to_string())),
                Placement::Header => extra_headers.push((m.seq_key.clone(), seq.to_string())),
                Placement::Cookie => {
                    extra_headers.push(("cookie".to_string(), format!("{}={}", m.seq_key, seq)))
                }
            }
        }

        // X-Padding.
        let pad = self.gen_padding();
        if m.x_obfs {
            match m.x_placement {
                XPlacement::Header => extra_headers.push((m.x_header.clone(), pad.clone())),
                XPlacement::Query => query.push((m.x_key.clone(), pad.clone())),
                XPlacement::Cookie => {
                    extra_headers.push(("cookie".to_string(), format!("{}={}", m.x_key, pad)))
                }
                XPlacement::QueryInHeader => extra_headers.push((
                    m.x_header.clone(),
                    format!("{scheme}://{authority}{path}?{}={pad}", m.x_key),
                )),
            }
        } else if !pad.is_empty() {
            // Legacy Xray: padding as ?x_padding= inside a Referer header. The
            // filler is a literal '0' rather than the configured method's
            // characters, because the server validates the *length* and the byte
            // is free -- and the reference is explicit that this exact default is
            // the one that has been live-verified against Xray. A zero length
            // sends no header at all, which is also what the reference does.
            extra_headers.push((
                "referer".to_string(),
                format!(
                    "{scheme}://{authority}{path}?x_padding={}",
                    "0".repeat(pad.len())
                ),
            ));
        }

        let mut uri = format!("{scheme}://{authority}{path}");
        if !query.is_empty() {
            uri.push('?');
            let parts: Vec<String> = query.iter().map(|(k, v)| format!("{k}={v}")).collect();
            uri.push_str(&parts.join("&"));
        }

        let mut builder = http::Request::builder().method(method).uri(uri);
        for (name, value) in &self.headers {
            if HOP_BY_HOP.contains(&name.to_ascii_lowercase().as_str()) {
                continue;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        for (name, value) in extra_headers {
            builder = builder.header(name.as_str(), value);
        }
        // A streamed body (stream-one, stream-up) announces itself as gRPC by
        // default — reference `applyGRPCHeader` — and reverse proxies key
        // response streaming on that. A packet-up upload is not a stream: the
        // reference sends a plain `application/octet-stream` there, which is what
        // its HTTP client puts on a body it is given, so that is what goes on the
        // wire. Announcing gRPC on a per-packet upload is a claim nobody made.
        if has_body && !self.no_grpc_header {
            let content_type = if seq.is_some() || self.mode == Mode::PacketUp {
                "application/octet-stream"
            } else {
                "application/grpc"
            };
            builder = builder.header("content-type", content_type);
        }
        builder
            .body(())
            .map_err(|e| io::Error::other(format!("xhttp: build request: {e}")))
    }

    fn gen_padding(&self) -> String {
        let target = self.padding.rand() as usize;
        match self.meta.x_method {
            PadMethod::RepeatX => "X".repeat(target),
            PadMethod::Tokenish => tokenish(target),
        }
    }
}

/// Random dashed-UUID session id (default), or `session_table` /
/// `session_length` drawn characters (reference `newSessionID`).
fn new_session_id(meta: &Meta) -> String {
    const HEX: &[u8] = b"0123456789abcdef";
    if meta.session_table.is_empty() || meta.session_len.0 == 0 {
        let mut b = [0u8; 16];
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut b);
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
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut buf);
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
        let _ = crate::outbound::shadowsocks::crypto::random_bytes(&mut b);
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
mod tests {
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
        };
        let (mut input, reader) = tokio::io::duplex(1024);
        let flushed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
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
            let flushed = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
            let completion = flushed.clone();
            let failure = Failure::default();
            let error = failure.clone();
            split.up = Up::Packets(Box::new(PacketsUp {
                io,
                failure,
                bytes_written: std::sync::Arc::new(std::sync::atomic::AtomicU64::new(1)),
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
        std::sync::Arc<super::H2Pool>,
        h2::client::SendRequest<Bytes>,
        JoinHandle<()>,
    ) {
        let (client, connection, clock) = super::h2_handshake(Box::new(client_io)).await.unwrap();
        let pool = std::sync::Arc::new(super::H2Pool::new());
        let counter = pool.finish_dial(Some(client.clone()), 1).await.unwrap();
        drop(super::CounterGuard::new(counter.clone()));
        let driver = tokio::spawn(super::drive_h2_connection(
            connection,
            clock,
            Some((TEST_PERIOD, TEST_PING_TIMEOUT)),
            std::sync::Arc::downgrade(&pool),
            counter,
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
            matches!(pool.acquire(1, 0).await, super::H2Acquire::NeedDial(_)),
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
            matches!(pool.acquire(1, 0).await, super::H2Acquire::Ready(..)),
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
            super::H2Acquire::NeedDial(_)
        ));
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
        let pool = std::sync::Arc::new(super::H2Pool::new());
        let count = pool.finish_dial(Some(client), 1).await.unwrap();
        let guard = super::CounterGuard::new(count.clone());
        let waiting_pool = pool.clone();
        let waiting = tokio::spawn(async move { waiting_pool.acquire(1, 1).await });
        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        assert!(!waiting.is_finished(), "xmux limit was ignored");
        drop(guard);
        let next = tokio::time::timeout(std::time::Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        let super::H2Acquire::Ready(_, count) = next else {
            panic!("reuse existing H2 connection")
        };
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 1);
        drop(super::CounterGuard::new(count.clone()));
        assert_eq!(count.load(std::sync::atomic::Ordering::Relaxed), 0);
        // Cancelling a waiter must not consume capacity.
        let guard = super::CounterGuard::new({
            count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            count.clone()
        });
        let waiter_pool = pool.clone();
        let cancelled = tokio::spawn(async move { waiter_pool.acquire(1, 1).await });
        tokio::task::yield_now().await;
        cancelled.abort();
        let _ = cancelled.await;
        drop(guard);
        let super::H2Acquire::Ready(_, count) = pool.acquire(1, 1).await else {
            panic!("capacity leaked")
        };
        drop(super::CounterGuard::new(count));
        let super::H2Acquire::Ready(_, count) = pool.acquire(usize::MAX, 1).await else {
            panic!("idle connection must be reused before dialing")
        };
        let held = super::CounterGuard::new(count);
        let next = pool.acquire(usize::MAX, 1).await;
        assert!(
            matches!(next, super::H2Acquire::NeedDial(_)),
            "maxConcurrency must open a new connection when full"
        );
        drop(next);
        drop(held);
        driver.abort();
        server.abort();
    }

    #[tokio::test]
    async fn cancelled_h2_dial_releases_slot_and_wakes_waiter() {
        let pool = std::sync::Arc::new(super::H2Pool::new());
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
        assert!(matches!(next, super::H2Acquire::NeedDial(_)));
        drop(next);
        assert_eq!(pool.state.lock().unwrap().active_dials, 0);
    }

    #[tokio::test]
    async fn aborted_h2_connection_dial_releases_reservation() {
        let pool = std::sync::Arc::new(super::H2Pool::new());
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
        assert_eq!(pool.state.lock().unwrap().active_dials, 0);
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
        let c = cfg(json!({"x_padding_bytes": "50-50", "path": "/x"}));
        let req = c
            .build_request("https", "srv:443", "GET", Some("SID"), None, false)
            .unwrap();
        let referer = req.headers().get("referer").unwrap();
        assert!(
            referer
                .to_str()
                .unwrap()
                .starts_with("https://srv:443/x/SID?x_padding=")
        );
        let pad = referer.to_str().unwrap().rsplit('=').next().unwrap();
        assert_eq!(pad.len(), 50);
        // the legacy default fills with '0', not the obfs method's characters: the
        // server validates the length, and '0' is the byte the reference's
        // live-verified default uses
        assert!(pad.bytes().all(|b| b == b'0'));
    }

    /// A packet-up upload is a packet, not a stream: the reference sends
    /// `application/octet-stream` there and reserves the gRPC content type for
    /// the streamed modes, and a production node refused ours until it did.
    #[test]
    fn a_packet_up_upload_is_octet_stream_and_a_stream_is_grpc() {
        for mode in ["packet-up", "auto"] {
            let packet = cfg(json!({"mode": mode}));
            let req = packet
                .build_request("https", "srv:443", "POST", Some("SID"), Some("0"), true)
                .unwrap();
            assert_eq!(
                req.headers().get("content-type").unwrap(),
                "application/octet-stream"
            );
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
        assert_eq!(bare.authority_for("", "1.2.3.4", 443), "1.2.3.4:443");

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
            assert!(lower.contains("\r\nhost: srv:443\r\n"), "got {head:?}");
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

            // POST 1: MUST arrive on the SAME post_io, not a new dial!
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
