//! XHTTP connection reuse ("XMUX").
//!
//! Ported from `transport/v2rayxhttp/xmux.go`, which mirrors Xray's
//! `XmuxConfig`. Nothing here changes what goes on the wire â€” the server
//! identifies a session by its session id, not by the connection carrying it â€”
//! so pooling is purely a client-side policy. What it buys is behaving like an
//! Xray client (subscription configs routinely carry an xmux section) and not
//! paying a fresh TCP+TLS handshake for every stream.
//!
//! Each pooled connection carries the counters that decide when it retires: live
//! streams, handouts left, HTTP requests left and an expiry. Retiring is
//! deferred: a connection with live streams stays up until the last one leaves.

use std::sync::Arc;
use std::sync::atomic::{AtomicI32, AtomicUsize, Ordering};
use std::time::Duration;

use tokio::sync::Mutex;

use crate::inbound::AnyStream;

/// Xray `net.ChromeH2KeepAlivePeriod`.
const H2_KEEP_ALIVE_DEFAULT: Duration = Duration::from_secs(45);

/// `max_concurrency` bounds the streams one connection may carry,
/// `max_connections` the pool size; both zero mean unlimited. A zero
/// `c_max_reuse_times` / `h_max_request_times` / `h_max_reusable_secs` is
/// unlimited too, which is what an xmux section with only one field set leaves
/// for the rest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct IntRange(pub u64, pub u64);

impl IntRange {
    const fn zero() -> Self {
        Self(0, 0)
    }

    /// `"4"`, `"1-3"`, a number or a two-element array, like the reference.
    fn parse(value: &serde_json::Value, at: &str) -> anyhow::Result<Self> {
        let pair = match value {
            serde_json::Value::Null => return Ok(Self::zero()),
            serde_json::Value::String(text) => {
                let parts: Vec<&str> = text.split('-').collect();
                match parts.as_slice() {
                    [a] => (a.trim().to_string(), a.trim().to_string()),
                    [a, b] => (a.trim().to_string(), b.trim().to_string()),
                    _ => anyhow::bail!("{at}: invalid range {text:?}"),
                }
            }
            serde_json::Value::Number(number) => (number.to_string(), number.to_string()),
            serde_json::Value::Array(list) if list.len() == 2 => {
                (number_text(&list[0]), number_text(&list[1]))
            }
            _ => anyhow::bail!("{at}: must be a number, a range or a two-element array"),
        };
        let lo: u64 = pair
            .0
            .parse()
            .map_err(|_| anyhow::anyhow!("{at}: invalid range {:?}", pair.0))?;
        let hi: u64 = pair
            .1
            .parse()
            .map_err(|_| anyhow::anyhow!("{at}: invalid range {:?}", pair.1))?;
        if lo > i32::MAX as u64 || hi > i32::MAX as u64 {
            anyhow::bail!("{at}: value exceeds i32::MAX");
        }
        Ok(Self(lo.min(hi), lo.max(hi)))
    }

    /// The range is rolled once, not per request.
    fn roll(&self) -> u64 {
        if self.0 == self.1 || self.1 == 0 {
            return self.0;
        }
        let mut bytes = [0u8; 8];
        let _ = getrandom::fill(&mut bytes);
        self.0 + u64::from_le_bytes(bytes) % (self.1 - self.0 + 1)
    }
}

fn number_text(value: &serde_json::Value) -> String {
    value.as_u64().map(|v| v.to_string()).unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct XmuxConfig {
    pub max_concurrency: IntRange,
    pub max_connections: IntRange,
    pub c_max_reuse_times: IntRange,
    pub h_max_request_times: IntRange,
    pub h_max_reusable_secs: IntRange,
    /// `h_keep_alive_period`, seconds: the HTTP/2 keep-alive ping, as in
    /// Xray (0 is 45 s, negative is off). HTTP/1.1 has no ping.
    pub keep_alive_period: i64,
}

impl Default for XmuxConfig {
    fn default() -> Self {
        Self {
            max_concurrency: IntRange::zero(),
            max_connections: IntRange(3, 3),
            c_max_reuse_times: IntRange::zero(),
            h_max_request_times: IntRange(600, 900),
            h_max_reusable_secs: IntRange(1800, 3000),
            keep_alive_period: 0,
        }
    }
}

impl XmuxConfig {
    /// Xray's all-or-nothing rule: an absent *or entirely empty* section takes
    /// the defaults, and a section with any field set is taken as written, so
    /// unset ranges stay zero (unlimited). lx.6 moved the default from
    /// `max_concurrency 1` to `max_connections 3`.
    pub(crate) fn parse(value: Option<&serde_json::Value>, at: &str) -> anyhow::Result<Self> {
        let Some(map) = value.and_then(serde_json::Value::as_object) else {
            return Ok(Self::default());
        };
        if map.is_empty() {
            return Ok(Self::default());
        }
        let max_concurrency = IntRange::parse(
            map.get("max_concurrency")
                .unwrap_or(&serde_json::Value::Null),
            &format!("{at}.max_concurrency"),
        )?;
        let max_connections = IntRange::parse(
            map.get("max_connections")
                .unwrap_or(&serde_json::Value::Null),
            &format!("{at}.max_connections"),
        )?;
        if max_concurrency.1 > 0 && max_connections.1 > 0 {
            anyhow::bail!(
                "{at}: xmux.max_connections cannot be specified together with xmux.max_concurrency"
            );
        }
        let config = Self {
            max_concurrency,
            max_connections,
            c_max_reuse_times: IntRange::parse(
                map.get("c_max_reuse_times")
                    .unwrap_or(&serde_json::Value::Null),
                &format!("{at}.c_max_reuse_times"),
            )?,
            h_max_request_times: IntRange::parse(
                map.get("h_max_request_times")
                    .unwrap_or(&serde_json::Value::Null),
                &format!("{at}.h_max_request_times"),
            )?,
            h_max_reusable_secs: IntRange::parse(
                map.get("h_max_reusable_secs")
                    .unwrap_or(&serde_json::Value::Null),
                &format!("{at}.h_max_reusable_secs"),
            )?,
            keep_alive_period: map
                .get("h_keep_alive_period")
                .and_then(serde_json::Value::as_i64)
                .unwrap_or(0),
        };
        if config.max_connections == IntRange::zero()
            && config.max_concurrency == IntRange::zero()
            && config.c_max_reuse_times == IntRange::zero()
            && config.h_max_request_times == IntRange::zero()
            && config.h_max_reusable_secs == IntRange::zero()
            && config.keep_alive_period == 0
        {
            return Ok(Self::default());
        }
        Ok(config)
    }

    pub(crate) fn lifetime(&self) -> Lifetime {
        let limit = |range: IntRange| match range.roll() as i32 {
            0 => i32::MAX,
            value => value,
        };
        let secs = self.h_max_reusable_secs.roll();
        Lifetime {
            uses: AtomicI32::new(limit(self.c_max_reuse_times)),
            requests: AtomicI32::new(limit(self.h_max_request_times)),
            deadline: (secs > 0).then(|| tokio::time::Instant::now() + Duration::from_secs(secs)),
        }
    }
}

/// Lifetime of a logical XMUX client. Connection retirement excludes new
/// tunnels while existing streams can finish on the same connection.
pub(crate) struct Lifetime {
    uses: AtomicI32,
    requests: AtomicI32,
    deadline: Option<tokio::time::Instant>,
}

impl Lifetime {
    fn deadline_passed(&self) -> bool {
        self.deadline
            .is_some_and(|at| tokio::time::Instant::now() >= at)
    }

    pub(crate) fn can_reuse(&self) -> bool {
        self.uses.load(Ordering::Relaxed) > 0
            && self.requests.load(Ordering::Relaxed) > 0
            && !self.deadline_passed()
    }

    pub(crate) fn take_use(&self) {
        self.uses.fetch_sub(1, Ordering::Relaxed);
    }

    pub(crate) fn take_requests(&self, count: i32) {
        self.requests.fetch_sub(count, Ordering::Relaxed);
    }

    /// An active packet-up tunnel may keep its current client after the
    /// handout budget has run out. Rotate the upload when its HTTP request
    /// budget or age is exhausted, without moving the download stream.
    pub(crate) fn try_take_packet(&self) -> bool {
        let mut left = self.requests.load(Ordering::Relaxed);
        while left > 0 && !self.deadline_passed() {
            match self.requests.compare_exchange_weak(
                left,
                left - 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(current) => left = current,
            }
        }
        false
    }
}

/// Like Xray's HTTP/1.1 dialer, each XMUX client owns a pool of raw POST
/// sockets while the GET and streaming POST run on dedicated sockets.
struct H1Client {
    sockets: std::sync::Mutex<Vec<AnyStream>>,
    running: AtomicUsize,
    lifetime: Lifetime,
}

impl H1Client {
    fn new(config: &XmuxConfig) -> Self {
        Self {
            sockets: std::sync::Mutex::new(Vec::new()),
            running: AtomicUsize::new(0),
            lifetime: config.lifetime(),
        }
    }
}

struct H1Usage {
    client: Arc<H1Client>,
}

impl Drop for H1Usage {
    fn drop(&mut self) {
        if self.client.running.fetch_sub(1, Ordering::Relaxed) == 1
            && !self.client.lifetime.can_reuse()
        {
            // No tunnel can borrow these POST sockets again. The pool may
            // see no more dials for the lifetime of the router process.
            let mut sockets = self.client.sockets.lock().expect("xhttp H1 sockets");
            *sockets = Vec::new();
        }
    }
}

/// A logical tunnel can use its client for both upload and download. Cloning
/// its lease shares that one reservation, so two requests still count as one
/// tunnel toward maxConcurrency.
#[derive(Clone)]
pub(crate) struct H1Session(Arc<H1Usage>);

impl H1Session {
    fn new(client: Arc<H1Client>) -> Self {
        client.running.fetch_add(1, Ordering::Relaxed);
        client.lifetime.take_use();
        Self(Arc::new(H1Usage { client }))
    }

    fn client(&self) -> &H1Client {
        &self.0.client
    }

    pub(crate) fn take_request(&self) {
        self.client().lifetime.take_requests(1);
    }

    pub(crate) fn try_take_packet(&self) -> bool {
        self.client().lifetime.try_take_packet()
    }

    pub(crate) fn take_socket(&self) -> Option<AnyStream> {
        self.client()
            .sockets
            .lock()
            .expect("xhttp H1 sockets")
            .pop()
    }

    pub(crate) fn return_socket(&self, io: AnyStream) {
        self.client()
            .sockets
            .lock()
            .expect("xhttp H1 sockets")
            .push(io);
    }
}

/// The pool itself.
pub(crate) struct Pool {
    config: XmuxConfig,
    /// rolled once at construction, like the reference
    concurrency: u64,
    connections: u64,
    clients: Mutex<Vec<Arc<H1Client>>>,
}

impl Pool {
    pub(crate) fn new(config: XmuxConfig) -> Arc<Self> {
        let concurrency = config.max_concurrency.roll();
        let connections = config.max_connections.roll();
        Arc::new(Self {
            config,
            concurrency,
            connections,
            clients: Mutex::new(Vec::new()),
        })
    }

    pub(crate) fn max_concurrency(&self) -> usize {
        self.concurrency as usize
    }

    /// How long a pooled HTTP/2 connection may read nothing before it is
    /// pinged, or `None` for no pings. Xray's `hKeepAlivePeriod` rules: 0
    /// takes Chrome's 45 s, a negative value turns the ping off.
    pub(crate) fn h2_keep_alive(&self) -> Option<Duration> {
        match self.config.keep_alive_period {
            0 => Some(H2_KEEP_ALIVE_DEFAULT),
            secs if secs < 0 => None,
            secs => Some(Duration::from_secs(secs as u64)),
        }
    }

    pub(crate) fn h3_keep_alive(&self) -> Option<Duration> {
        match self.config.keep_alive_period {
            0 => Some(Duration::from_secs(10)),
            secs if secs < 0 => None,
            secs => Some(Duration::from_secs(secs as u64)),
        }
    }

    pub(crate) fn lifetime(&self) -> Lifetime {
        self.config.lifetime()
    }

    pub(crate) fn max_connections(&self) -> usize {
        if self.connections > 0 {
            self.connections as usize
        } else if self.concurrency > 0 {
            // maxConcurrency selects a new connection once every existing
            // one is busy; it is mutually exclusive with maxConnections.
            usize::MAX
        } else {
            1
        }
    }

    pub(crate) async fn h1_session(&self) -> H1Session {
        let mut clients = self.clients.lock().await;
        clients.retain(|client| client.lifetime.can_reuse());
        if self.connections == 0 || clients.len() >= self.connections as usize {
            let candidates: Vec<_> = clients
                .iter()
                .filter(|client| {
                    self.concurrency == 0
                        || client.running.load(Ordering::Relaxed) < self.concurrency as usize
                })
                .collect();
            if !candidates.is_empty() {
                return H1Session::new(candidates[pick(candidates.len())].clone());
            }
        }
        let client = Arc::new(H1Client::new(&self.config));
        clients.push(client.clone());
        H1Session::new(client)
    }
}

pub(crate) fn pick(len: usize) -> usize {
    if len <= 1 {
        return 0;
    }
    let mut bytes = [0u8; 8];
    let _ = getrandom::fill(&mut bytes);
    (u64::from_le_bytes(bytes) % len as u64) as usize
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn h1_tunnels_share_logical_clients_but_not_borrowed_sockets() {
        let pool = Pool::new(XmuxConfig {
            max_connections: IntRange(1, 1),
            ..XmuxConfig::default()
        });
        let first = pool.h1_session().await;
        let (io, _peer) = tokio::io::duplex(1024);
        first.return_socket(Box::new(io));
        let borrowed = first
            .take_socket()
            .expect("first upload borrows the socket");
        let second = pool.h1_session().await;
        assert!(std::ptr::eq(first.client(), second.client()));
        assert!(second.take_socket().is_none(), "the socket is in use");
        first.return_socket(borrowed);
        assert!(second.take_socket().is_some(), "the socket is reusable");
    }

    #[tokio::test]
    async fn fresh_http1_handout_counts_once_against_reuse_times() {
        let pool = Pool::new(XmuxConfig {
            max_connections: IntRange(1, 1),
            c_max_reuse_times: IntRange(2, 2),
            ..XmuxConfig::default()
        });
        let first = pool.h1_session().await;
        let reused = pool.h1_session().await;
        assert!(std::ptr::eq(first.client(), reused.client()));
        assert!(
            first.try_take_packet(),
            "an existing tunnel can still upload"
        );
        let next = pool.h1_session().await;
        assert!(!std::ptr::eq(first.client(), next.client()));
    }

    #[test]
    fn h2_keep_alive_follows_xray() {
        let period = |v: serde_json::Value| {
            Pool::new(XmuxConfig::parse(Some(&v), "xmux").unwrap()).h2_keep_alive()
        };
        assert_eq!(
            Pool::new(XmuxConfig::default()).h2_keep_alive(),
            Some(Duration::from_secs(45))
        );
        let at = serde_json::json!({"h_keep_alive_period": 0, "max_connections": 2});
        assert_eq!(period(at), Some(Duration::from_secs(45)));
        let at = serde_json::json!({"h_keep_alive_period": 20});
        assert_eq!(period(at), Some(Duration::from_secs(20)));
        assert_eq!(period(serde_json::json!({"h_keep_alive_period": -1})), None);
    }

    #[tokio::test]
    async fn h1_session_clone_does_not_double_count_and_cancel_releases_usage() {
        let pool = Pool::new(XmuxConfig {
            max_concurrency: IntRange(1, 1),
            max_connections: IntRange::zero(),
            ..XmuxConfig::default()
        });
        let session = pool.h1_session().await;
        let client = session.0.client.clone();
        let held = session.clone();
        assert_eq!(client.running.load(Ordering::Relaxed), 1);
        let (io, _peer) = tokio::io::duplex(1024);
        session.return_socket(Box::new(io));
        drop(session);
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let request = tokio::spawn(async move {
            let _io = held.take_socket().unwrap();
            ready_tx.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        ready_rx.await.unwrap();
        let second = pool.h1_session().await;
        assert!(!std::ptr::eq(client.as_ref(), second.client()));
        request.abort();
        let _ = request.await;
        let reused = pool.h1_session().await;
        assert!(std::ptr::eq(client.as_ref(), reused.client()));
        assert!(
            reused.take_socket().is_none(),
            "cancellation drops the socket"
        );
    }

    use super::*;

    fn range(value: serde_json::Value) -> IntRange {
        IntRange::parse(&value, "t").expect("range")
    }

    #[test]
    fn ranges_accept_every_spelling() {
        assert_eq!(range(serde_json::json!(4)), IntRange(4, 4));
        assert_eq!(range(serde_json::json!("1-3")), IntRange(1, 3));
        assert_eq!(
            range(serde_json::json!("3-1")),
            IntRange(1, 3),
            "order is normalised"
        );
        assert_eq!(range(serde_json::json!([600, 900])), IntRange(600, 900));
        assert_eq!(range(serde_json::Value::Null), IntRange::zero());
        assert!(IntRange::parse(&serde_json::json!("a-b"), "t").is_err());
    }

    #[test]
    fn an_absent_or_empty_section_takes_the_lx6_defaults() {
        let default = XmuxConfig::parse(None, "xmux").expect("parse");
        assert_eq!(
            default.max_connections,
            IntRange(3, 3),
            "lx.6 changed this from 1"
        );
        assert_eq!(default.max_concurrency, IntRange::zero());
        assert_eq!(default.h_max_request_times, IntRange(600, 900));
        assert_eq!(default.h_max_reusable_secs, IntRange(1800, 3000));
        let empty = XmuxConfig::parse(Some(&serde_json::json!({})), "xmux").expect("parse");
        assert_eq!(empty, default, "an empty object is the same as no section");
    }

    #[test]
    fn a_partly_filled_section_is_taken_as_written() {
        let config = XmuxConfig::parse(
            Some(&serde_json::json!({"c_max_reuse_times": "4-8"})),
            "xmux",
        )
        .expect("parse");
        assert_eq!(config.c_max_reuse_times, IntRange(4, 8));
        assert_eq!(
            config.max_connections,
            IntRange::zero(),
            "unset means unlimited"
        );
        assert_eq!(config.h_max_request_times, IntRange::zero());
    }

    #[test]
    fn max_connections_and_max_concurrency_are_exclusive() {
        let err = XmuxConfig::parse(
            Some(&serde_json::json!({
                "max_connections": 3,
                "max_concurrency": 4,
            })),
            "xmux",
        )
        .expect_err("exclusive")
        .to_string();
        assert!(err.contains("cannot be specified together"), "got {err}");
    }

    #[test]
    fn a_range_rolls_inside_its_bounds() {
        let single = IntRange(7, 7);
        assert_eq!(single.roll(), 7);
        for _ in 0..16 {
            let value = IntRange(5, 9).roll();
            assert!((5..=9).contains(&value), "rolled {value} out of range");
        }
    }

    #[tokio::test]
    async fn last_tunnel_drops_retired_sockets_without_another_dial() {
        let pool = Pool::new(XmuxConfig {
            c_max_reuse_times: IntRange(1, 1),
            ..XmuxConfig::default()
        });
        let tunnel = pool.h1_session().await;
        let client = tunnel.0.client.clone();
        let (socket, _peer) = tokio::io::duplex(1024);
        tunnel.return_socket(Box::new(socket));
        let active = tunnel.clone();
        drop(tunnel);
        assert_eq!(client.sockets.lock().unwrap().len(), 1);
        drop(active);
        assert_eq!(client.sockets.lock().unwrap().capacity(), 0);
    }

    #[tokio::test]
    async fn h1_pool_retires_a_client_after_its_http_requests() {
        let config = XmuxConfig::parse(
            Some(&serde_json::json!({
                "max_connections": 1,
                "h_max_request_times": 2
            })),
            "xmux",
        )
        .unwrap();
        let pool = Pool::new(config);

        let first = pool.h1_session().await;
        first.take_request(); // initial download GET
        assert!(first.try_take_packet());
        assert!(!first.try_take_packet(), "the next upload rotates");
        let next = pool.h1_session().await;
        assert!(!std::ptr::eq(first.client(), next.client()));
        assert!(next.try_take_packet());
    }
}
