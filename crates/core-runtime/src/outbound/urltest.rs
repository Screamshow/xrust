//! urltest outbound: probes member outbounds with an HTTP request through
//! each and routes through the lowest-latency one, re-probing on an interval.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use core_config::probe_url::ProbeUrl;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::watch;

use crate::inbound::{AnyStream, Conn, Target};
use crate::logging;
use crate::route::Router;
use crate::tls_client;

pub struct Urltest {
    shared: Arc<Shared>,
}

const WAKE_PROBE_BUDGET: Duration = Duration::from_secs(3);

#[derive(Clone, Copy, Default)]
struct WakeProbe {
    requested: u64,
    completed: u64,
}

impl WakeProbe {
    fn pending(&self) -> bool {
        self.requested != self.completed
    }
}

struct Shared {
    tag: String,
    interrupt: bool,
    members: Vec<String>,
    resolved: OnceLock<Vec<usize>>,
    current: AtomicUsize,
    last_active: Mutex<Instant>,
    wake_probe: watch::Sender<WakeProbe>,
    idle_timeout: Duration,
    probe: ProbeUrl,
    interval: Duration,
    tolerance_ms: u64,
}

impl Urltest {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let members = obj
            .get("outbounds")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing tags"))?
            .iter()
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("{at}: outbounds entries must be strings"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if members.is_empty() {
            anyhow::bail!("{at}: missing tags");
        }
        let probe = ProbeUrl::parse(
            obj.get("url")
                .and_then(Value::as_str)
                .unwrap_or("https://www.gstatic.com/generate_204"),
        )
        .ok_or_else(|| anyhow::anyhow!("{at}: invalid HTTP probe URL"))?;
        let interval = parse_duration(
            obj.get("interval"),
            Duration::from_secs(180),
            format!("{at}: interval").as_str(),
        )?;
        let idle_default = Duration::from_secs(30 * 60);
        let idle_timeout = parse_duration(obj.get("idle_timeout"), idle_default, "idle_timeout")?;
        let tolerance_ms = obj.get("tolerance").and_then(Value::as_u64).unwrap_or(50);
        Ok(Self {
            shared: Arc::new(Shared {
                tag: obj
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string(),
                interrupt: obj
                    .get("interrupt_exist_connections")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
                members,
                resolved: OnceLock::new(),
                current: AtomicUsize::new(0),
                last_active: Mutex::new(Instant::now()),
                wake_probe: watch::Sender::new(WakeProbe::default()),
                idle_timeout: if idle_timeout.is_zero() {
                    idle_default
                } else {
                    idle_timeout
                },
                probe,
                interval: if interval.is_zero() {
                    Duration::from_secs(180)
                } else {
                    interval
                },
                tolerance_ms,
            }),
        })
    }

    /// Resolve member tags against the built outbound table (at startup).
    pub fn resolve(&self, tags: &std::collections::HashMap<String, usize>) -> anyhow::Result<()> {
        let mut resolved = Vec::with_capacity(self.shared.members.len());
        for tag in &self.shared.members {
            let index = tags.get(tag).copied().ok_or_else(|| {
                anyhow::anyhow!("urltest member references unknown outbound {tag:?}")
            })?;
            resolved.push(index);
        }
        let _ = self.shared.resolved.set(resolved);
        Ok(())
    }

    async fn selected_member(&self) -> io::Result<usize> {
        let members = self
            .shared
            .resolved
            .get()
            .ok_or_else(|| io::Error::other("urltest members not resolved"))?;
        let requested = {
            let mut last_active = self
                .shared
                .last_active
                .lock()
                .expect("urltest activity lock");
            if last_active.elapsed() >= self.shared.idle_timeout {
                self.shared.wake_probe.send_if_modified(|wake| {
                    if wake.pending() {
                        return false;
                    }
                    wake.requested += 1;
                    true
                });
            }
            *last_active = Instant::now();
            let wake = *self.shared.wake_probe.borrow();
            (members.len() > 1 && wake.pending()).then_some(wake.requested)
        };
        if let Some(requested) = requested {
            // A UDP socket can be created even when its peer is gone, so both
            // transports wait for the same wake probe before dialing.
            let mut wake = self.shared.wake_probe.subscribe();
            let _ = tokio::time::timeout(
                WAKE_PROBE_BUDGET + Duration::from_secs(1),
                wake.wait_for(|wake| wake.completed >= requested),
            )
            .await;
        }
        members
            .get(self.shared.current.load(Ordering::Relaxed))
            .copied()
            .ok_or_else(|| io::Error::other("urltest selection out of range"))
    }

    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        router
            .connect_index(self.selected_member().await?, target)
            .await
    }

    pub async fn connect_udp(
        &self,
        router: &Router,
        target: &Target,
    ) -> io::Result<tokio::net::UdpSocket> {
        router
            .connect_udp_index(self.selected_member().await?, target)
            .await
    }

    /// Member tags and the current selection (clash group view).
    pub fn all(&self) -> &[String] {
        &self.shared.members
    }

    pub fn now(&self) -> &str {
        self.shared
            .members
            .get(self.shared.current.load(Ordering::Relaxed))
            .map(String::as_str)
            .unwrap_or_default()
    }

    /// Switch to member by tag across reloads or runtime commands.
    pub fn select(&self, member: &str) -> bool {
        if let Some(pos) = self.shared.members.iter().position(|m| m == member) {
            self.shared.current.store(pos, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    pub(crate) fn apply_probe_results(
        &self,
        router: &Router,
        results: &std::collections::HashMap<usize, Option<u16>>,
    ) {
        let Some(members) = self.shared.resolved.get() else {
            return;
        };
        let values: Vec<_> = members
            .iter()
            .map(|member| results.get(member).copied().flatten().map(u64::from))
            .collect();
        apply_results(&self.shared, router, values);
    }

    pub(crate) fn spawn(&self, router: Arc<Router>) -> tokio::task::JoinHandle<()> {
        let shared = Arc::clone(&self.shared);
        let mut wake = shared.wake_probe.subscribe();
        tokio::spawn(async move {
            loop {
                let state = *wake.borrow();
                if state.pending() {
                    probe_all(&shared, &router, shared.members.len() > 1).await;
                    shared
                        .wake_probe
                        .send_modify(|wake| wake.completed = state.requested);
                } else {
                    tokio::select! {
                        _ = probe_all(&shared, &router, false) => {}
                        _ = wake.wait_for(WakeProbe::pending) => continue,
                    }
                }
                tokio::select! {
                    _ = tokio::time::sleep(shared.interval) => {}
                    _ = wake.wait_for(WakeProbe::pending) => continue,
                }
                let idle = shared
                    .last_active
                    .lock()
                    .expect("urltest activity lock")
                    .elapsed()
                    >= shared.idle_timeout;
                if idle {
                    let _ = wake.wait_for(WakeProbe::pending).await;
                }
            }
        })
    }
}

async fn probe_all(shared: &Arc<Shared>, router: &Arc<Router>, waking: bool) {
    let Some(members) = shared.resolved.get() else {
        return;
    };
    // Reference probes every member concurrently and records each result as
    // it lands, so the clash history fills while the round is still running.
    // The pool is capped at 8: a 42-member subscription round all at once
    // saturates a router CPU and blows the per-probe budget, and the
    // statuses the UI shows would never fill — the same nodes answer in
    // ~1s when tested one at a time.
    let sem = Arc::new(tokio::sync::Semaphore::new(8));
    let mut set = tokio::task::JoinSet::new();
    for (pos, member) in members.iter().enumerate() {
        let shared = Arc::clone(shared);
        let router = Arc::clone(router);
        let sem = Arc::clone(&sem);
        let member = *member;
        set.spawn(async move {
            let permit = sem.acquire().await.expect("probe pool never closes");
            let ms = probe_member(&shared, &router, member).await;
            drop(permit);
            // Do not expose an earlier success as current availability
            // after a failed round (including all retries).
            if let Some(ms) = ms {
                router.record_delay(member, ms as u32);
            } else {
                router.clear_delay(member);
            }
            (pos, ms)
        });
    }
    let mut results = vec![None; members.len()];
    let current = shared.current.load(Ordering::Relaxed);
    let collect = async {
        let mut current_finished = false;
        while let Some(joined) = set.join_next().await {
            if let Ok((pos, ms)) = joined {
                results[pos] = ms;
                current_finished |= pos == current;
                if waking && current_finished && results.iter().any(Option::is_some) {
                    break;
                }
            }
        }
    };
    if waking {
        // Keep the first flow bounded if the previous member or another
        // probe does not answer. Any completed healthy member can be used.
        let _ = tokio::time::timeout(WAKE_PROBE_BUDGET, collect).await;
    } else {
        collect.await;
    }
    apply_results(shared, router, results);
}

fn apply_results(shared: &Shared, router: &Router, results: Vec<Option<u64>>) {
    let Some((best_pos, best_ms)) = results
        .iter()
        .enumerate()
        .filter_map(|(pos, ms)| ms.map(|ms| (pos, ms)))
        .min_by_key(|(_, ms)| *ms)
    else {
        return;
    };
    let current = shared.current.load(Ordering::Relaxed);
    let switch = match results.get(current).copied().flatten() {
        Some(current_ms) => {
            best_pos != current && current_ms.saturating_sub(best_ms) > shared.tolerance_ms
        }
        None => best_pos != current,
    };
    if switch {
        crate::clash_state::switch_group(router, &shared.tag, shared.interrupt, || {
            shared.current.swap(best_pos, Ordering::Relaxed) != best_pos
        });
    }
}

/// Logs every completed read/write of a probe connection with its size and
/// the gap since the previous one: a stalled TLS handshake shows up as one
/// huge `r` gap, a paced one as a run of small `r` entries.
///
/// With `watchdog`, an I/O gap past [`STALL`] aborts the attempt instead of
/// riding out the TCP retransmission timer — a fresh connection rolls the
/// dice again and usually answers in one clean RTT. The deadline lives in a
/// `Sleep` polled alongside the I/O: a parked read gets no poll, so a
/// check-on-poll guard would never fire exactly when it is needed.
struct Tap {
    inner: AnyStream,
    member: usize,
    last: Instant,
    watchdog: bool,
    stall: Pin<Box<tokio::time::Sleep>>,
}

const STALL: Duration = Duration::from_millis(1200);

impl Tap {
    fn new(inner: AnyStream, member: usize, watchdog: bool) -> Self {
        Self {
            inner,
            member,
            last: Instant::now(),
            watchdog,
            stall: Box::pin(tokio::time::sleep(STALL)),
        }
    }

    fn mark(&mut self, dir: &str, n: usize) {
        let now = Instant::now();
        let gap = now.duration_since(self.last).as_millis();
        self.last = now;
        if self.watchdog {
            self.stall
                .as_mut()
                .reset(tokio::time::Instant::now() + STALL);
        }
        logging::debug(format_args!(
            "urltest tap[{}]: {dir}{n} +{gap}ms",
            self.member
        ));
    }
}

impl AsyncRead for Tap {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let res = Pin::new(&mut this.inner).poll_read(cx, buf);
        if matches!(&res, Poll::Ready(Ok(()))) {
            let n = buf.filled().len() - before;
            if n > 0 {
                this.mark("r", n);
            }
            return res;
        }
        if this.watchdog && res.is_pending() && this.stall.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe read stalled",
            )));
        }
        res
    }
}

impl AsyncWrite for Tap {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let res = Pin::new(&mut this.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &res {
            if *n > 0 {
                this.mark("w", *n);
            }
            return res;
        }
        if this.watchdog && res.is_pending() && this.stall.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "probe write stalled",
            )));
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn probe_member(shared: &Shared, router: &Router, member: usize) -> Option<u64> {
    // Reference has recorded a 6390 ms probe, so its budget is at least
    // ~6.4 s; nodes that answer solo in 5-6 s must still fill the clash
    // history, or the UI shows them as dead while the reference shows them
    // alive. A stalled attempt is cut at STALL and retried on a fresh
    // connection inside the same budget — loss costs one clean re-roll
    // instead of riding the full retransmission timer. The budget is 14 s
    // so a heavy member gets its second attempt: a first attempt can burn
    // 6+ s (dial plus the stall cut), and the 7 s retry guard then needs
    // ~7 s left to still allow the re-roll.
    //
    // Keep retries inside this probe budget. Outbound setup has its own
    // deadline and pooled dial reservations are released on cancellation.
    let deadline = Instant::now() + Duration::from_secs(14);
    for attempt in 1..=3u8 {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining < Duration::from_millis(400)
            || (attempt > 1 && remaining < Duration::from_secs(7))
        {
            break;
        }
        match tokio::time::timeout(remaining, probe_once(shared, router, member, attempt)).await {
            Ok(ProbeAttempt::Done(ms)) => return Some(ms),
            Ok(ProbeAttempt::Retry) => {}
            Ok(ProbeAttempt::Fail) | Err(_) => break,
        }
    }
    None
}

/// One probe attempt: `Retry` only for losses a fresh connection can dodge,
/// `Fail` for answers that will not change on a re-roll.
enum ProbeAttempt {
    Done(u64),
    Retry,
    Fail,
}

async fn probe_once(shared: &Shared, router: &Router, member: usize, attempt: u8) -> ProbeAttempt {
    let start = Instant::now();
    let target = Target::Domain(shared.probe.host.clone(), shared.probe.port);
    let probe = async {
        let Ok(Conn::Plain(stream)) = router.connect_index(member, &target).await else {
            logging::debug(format_args!(
                "urltest probe[{member}]/a{attempt}: dial failed after {}ms",
                start.elapsed().as_millis()
            ));
            return ProbeAttempt::Fail;
        };
        let dial_ms = start.elapsed();
        let watchdog = attempt < 3;
        let tapped: AnyStream = Box::new(Tap::new(stream, member, watchdog));
        let mut stream: AnyStream = if shared.probe.tls {
            match tls_client::wrap_probe(tapped, &shared.probe.host, &router.inner().probe_tls)
                .await
            {
                Ok(s) => s,
                Err(e) => {
                    logging::debug(format_args!(
                        "urltest probe[{member}]/a{attempt}: tls failed after {}ms: {e}",
                        dial_ms.as_millis()
                    ));
                    return if e.kind() == io::ErrorKind::TimedOut {
                        ProbeAttempt::Retry
                    } else {
                        ProbeAttempt::Fail
                    };
                }
            }
        } else {
            tapped
        };
        let tls_at = start.elapsed();
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            shared.probe.path, shared.probe.authority
        );
        if stream.write_all(request.as_bytes()).await.is_err() {
            return ProbeAttempt::Retry;
        }
        // One read per chunk, not one per byte: the head crosses a boxed
        // stream plus a TLS record layer, and a byte-at-a-time loop pays
        // that round trip ~200 times for every probe in the round.
        let mut head = Vec::with_capacity(256);
        let mut buf = [0u8; 1024];
        loop {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return ProbeAttempt::Retry,
                Ok(n) => head.extend_from_slice(&buf[..n]),
            }
            if let Some(end) = head.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let end = end + 4;
                if end > 16 * 1024 {
                    return ProbeAttempt::Fail;
                }
                // A read may include the start of the body. The response head
                // is complete even when CRLF CRLF is not at the end of it.
                head.truncate(end);
                break;
            }
            if head.len() >= 16 * 1024 {
                return ProbeAttempt::Fail;
            }
        }
        let head_at = start.elapsed();
        logging::debug(format_args!(
            "urltest probe[{member}]/a{attempt}: dial {}ms tls {}ms req {}ms total {}ms",
            dial_ms.as_millis(),
            tls_at.saturating_sub(dial_ms).as_millis(),
            head_at.saturating_sub(tls_at).as_millis(),
            head_at.as_millis()
        ));
        let head = String::from_utf8_lossy(&head);
        let Some(status) = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
        else {
            return ProbeAttempt::Fail;
        };
        if !status.starts_with('2') {
            return ProbeAttempt::Fail;
        }
        // Use the same post-handshake request metric as the manual Clash
        // test. Dial/TLS failures and the full attempt budget still apply.
        // No extra request or keep-alive support is required.
        ProbeAttempt::Done(head_at.saturating_sub(tls_at).as_millis() as u64)
    };
    probe.await
}

/// badoption.Duration: Go `time.ParseDuration` strings (`1m30s`, `1.5h`,
/// `250us`, plus the `d` badoption adds), integers in nanoseconds (Go
/// time.Duration JSON semantics). A bare number string still reads as
/// seconds; `check` refuses it before `run` gets here anyway.
pub(crate) fn parse_duration(
    value: Option<&Value>,
    default: Duration,
    at: &str,
) -> anyhow::Result<Duration> {
    let Some(value) = value else {
        return Ok(default);
    };
    match value {
        Value::Number(n) => {
            let nanos = n
                .as_u64()
                .ok_or_else(|| anyhow::anyhow!("{at}: invalid duration"))?;
            Ok(Duration::from_nanos(nanos))
        }
        Value::String(raw) => {
            let raw = raw.trim();
            if raw.is_empty() {
                return Ok(default);
            }
            if let Ok(seconds) = raw.parse::<f64>() {
                return Duration::try_from_secs_f64(seconds)
                    .map_err(|_| anyhow::anyhow!("{at}: invalid duration {raw:?}"));
            }
            go_duration(raw).map_err(|err| anyhow::anyhow!("{at}: {err}"))
        }
        other => anyhow::bail!("{at}: invalid duration value {other}"),
    }
}

/// `time.ParseDuration`: one or more `<number><unit>` segments. A negative
/// duration is a timeout that never waits, so it comes out as zero.
fn go_duration(raw: &str) -> Result<Duration, String> {
    let (negative, mut rest) = match raw.as_bytes().first() {
        Some(b'-') => (true, &raw[1..]),
        Some(b'+') => (false, &raw[1..]),
        _ => (false, raw),
    };
    if rest.is_empty() {
        return Err(format!("invalid duration {raw:?}"));
    }
    let mut nanos = 0f64;
    while !rest.is_empty() {
        let digits = rest
            .find(|c: char| !c.is_ascii_digit() && c != '.')
            .unwrap_or(rest.len());
        let number: f64 = rest[..digits]
            .parse()
            .map_err(|_| format!("invalid duration {raw:?}"))?;
        rest = &rest[digits..];
        let unit_len = rest
            .find(|c: char| c.is_ascii_digit() || c == '.')
            .unwrap_or(rest.len());
        let scale = match &rest[..unit_len] {
            "ns" => 1.0,
            "us" | "\u{b5}s" | "\u{3bc}s" => 1e3,
            "ms" => 1e6,
            "s" => 1e9,
            "m" => 60e9,
            "h" => 3600e9,
            "d" => 86400e9,
            "" => return Err(format!("missing unit in duration {raw:?}")),
            other => return Err(format!("unknown duration unit {other:?} in {raw:?}")),
        };
        rest = &rest[unit_len..];
        nanos += (number * scale).round();
    }
    if negative {
        return Ok(Duration::ZERO);
    }
    if !nanos.is_finite() || nanos >= u64::MAX as f64 {
        return Err(format!("invalid duration {raw:?}"));
    }
    Ok(Duration::from_nanos(nanos as u64))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn automatic_switch_respects_interruption_policy() {
        use crate::{
            clash_state::{ConnHandle, ConnMeta},
            route::ConnContext,
        };
        use serde_json::json;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut buf = [0; 1024];
                let _ = stream.read(&mut buf).await;
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        for interrupt in [false, true] {
            let root = json!({"outbounds":[
                {"type":"block", "tag":"dead"}, {"type":"direct", "tag":"live"},
                {"type":"urltest", "tag":"group", "outbounds":["dead","live"], "url":url, "interrupt_exist_connections":interrupt}
            ]});
            let router = Router::new(&root).unwrap();
            let idx = router.index_of("group").unwrap();
            let inner = router.inner();
            let (_, _, crate::route::Outbound::Urltest(group)) =
                inner.outbound_table().find(|(i, _, _)| *i == idx).unwrap()
            else {
                panic!("urltest")
            };
            let ctx = ConnContext::new(
                "test",
                "127.0.0.1:1234".parse().unwrap(),
                Target::Domain("example.com".into(), 443),
                "tcp",
            );
            let tracker = ConnHandle::open_with_context(
                ConnMeta {
                    network: "tcp",
                    inbound: "test".into(),
                    source: "local".into(),
                    host: "example.com".into(),
                    destination: "example.com:443".into(),
                    chains: vec!["group".into(), "dead".into()],
                    rule: String::new(),
                    rule_payload: String::new(),
                },
                &ctx,
                &router,
            );
            probe_all(&group.shared, &router, false).await;
            assert_eq!(group.now(), "live");
            assert_eq!(tracker.is_closed(), interrupt);
        }
        server.abort();
    }

    use super::*;
    use serde_json::json;

    #[tokio::test]
    async fn idle_group_suspends_then_wakes_on_tcp_and_udp() {
        use tokio::net::TcpListener;
        let server = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = server.local_addr().unwrap();
        let config = json!({"outbounds":[
            {"type":"direct", "tag":"live"},
            {"type":"urltest", "tag":"group", "outbounds":["live"],
             "url":format!("http://{addr}?health=1"), "interval":"30ms", "idle_timeout":"90ms"}
        ]});
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = server.accept().await {
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(stream.read_u8().await.unwrap());
                }
                let request = String::from_utf8(request).unwrap();
                assert!(
                    request.starts_with(&format!("GET /?health=1 HTTP/1.1\r\nHost: {addr}\r\n"))
                );
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
                tx.send(()).unwrap();
            }
        });
        let router = Router::new(&config).unwrap();
        let group = router.index_of("group").unwrap();
        let target = Target::Ip(
            TcpListener::bind("127.0.0.1:0")
                .await
                .unwrap()
                .local_addr()
                .unwrap(),
        );
        for network in ["tcp", "udp"] {
            tokio::time::timeout(Duration::from_secs(2), rx.recv())
                .await
                .unwrap()
                .unwrap();
            tokio::time::sleep(Duration::from_millis(220)).await;
            while rx.try_recv().is_ok() {}
            assert!(
                tokio::time::timeout(Duration::from_millis(100), rx.recv())
                    .await
                    .is_err()
            );
            match network {
                "tcp" => {
                    let _ = router.connect_index(group, &target).await;
                }
                _ => {
                    let _ = router.connect_udp_index(group, &target).await;
                }
            }
        }
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .unwrap()
            .unwrap();
        task.abort();
    }

    #[tokio::test]
    async fn idle_group_dials_live_member_on_first_tcp_and_udp_flow() {
        let health = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", health.local_addr().unwrap());
        let health_worker = tokio::spawn(async move {
            while let Ok((mut stream, _)) = health.accept().await {
                let mut request = [0; 1024];
                stream.read(&mut request).await.unwrap();
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                    .await
                    .unwrap();
            }
        });
        let router = Router::new(&json!({"outbounds":[
            {"type":"block", "tag":"unavailable"},
            {"type":"direct", "tag":"live"},
            {"type":"urltest", "tag":"group", "outbounds":["unavailable","live"],
             "url":url, "interval":"1h", "idle_timeout":"90ms"}
        ]}))
        .unwrap();
        let index = router.index_of("group").unwrap();
        let inner = router.inner();
        let (_, _, crate::route::Outbound::Urltest(group)) = inner
            .outbound_table()
            .find(|(i, _, _)| *i == index)
            .unwrap()
        else {
            panic!("urltest");
        };
        tokio::time::timeout(Duration::from_secs(2), async {
            while group.now() != "live" {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        // Model a cached choice that is now unavailable, while the next
        // periodic check is far enough away to avoid masking the wake path.
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(group.select("unavailable"));
        let tcp = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let tcp_target = Target::Ip(tcp.local_addr().unwrap());
        let udp_target = Target::Ip(udp.local_addr().unwrap());
        let (tcp_result, udp_result) = tokio::time::timeout(Duration::from_secs(2), async {
            tokio::join!(
                router.connect_index(index, &tcp_target),
                router.connect_udp_index(index, &udp_target)
            )
        })
        .await
        .unwrap();
        assert!(matches!(tcp_result.unwrap(), Conn::Plain(_)));
        assert_eq!(group.now(), "live");
        udp_result.unwrap().send(b"first").await.unwrap();
        let mut data = [0; 16];
        let (length, _) = tokio::time::timeout(Duration::from_secs(2), udp.recv_from(&mut data))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&data[..length], b"first");
        health_worker.abort();
    }

    #[test]
    fn check_and_runtime_agree_on_probe_urls() {
        for (url, valid) in [
            ("http://[::1]/health", true),
            ("http://[::1]oops", false),
            ("http://host:65536", false),
        ] {
            let outbound = json!({"type":"urltest","tag":"group","outbounds":["direct"],"url":url});
            let root = json!({"outbounds":[{"type":"direct","tag":"direct"},outbound]});
            assert_eq!(
                core_config::check_str(&root.to_string()).is_ok(),
                valid,
                "{url}"
            );
            assert_eq!(
                Urltest::build(outbound.as_object().unwrap(), "test").is_ok(),
                valid,
                "{url}"
            );
        }
    }

    #[test]
    fn probe_url_parsing() {
        let p = ProbeUrl::parse("https://www.gstatic.com/generate_204").expect("parse");
        assert!(p.tls);
        assert_eq!(p.host, "www.gstatic.com");
        assert_eq!(p.port, 443);
        assert_eq!(p.path, "/generate_204");

        let p = ProbeUrl::parse("http://127.0.0.1:8123/").expect("parse");
        assert!(!p.tls);
        assert_eq!(p.port, 8123);
        assert_eq!(p.path, "/");

        assert!(ProbeUrl::parse("ftp://x/").is_none());
        assert!(ProbeUrl::parse("nonsense").is_none());
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(
            parse_duration(Some(&json!("3m")), Duration::ZERO, "t").expect("ok"),
            Duration::from_secs(180)
        );
        assert_eq!(
            parse_duration(Some(&json!("500ms")), Duration::ZERO, "t").expect("ok"),
            Duration::from_millis(500)
        );
        assert_eq!(
            parse_duration(Some(&json!("2h")), Duration::ZERO, "t").expect("ok"),
            Duration::from_secs(7200)
        );
        assert_eq!(
            parse_duration(Some(&json!("3d")), Duration::ZERO, "t").expect("ok"),
            Duration::from_secs(3 * 86400)
        );
        assert_eq!(
            parse_duration(Some(&json!(30)), Duration::ZERO, "t").expect("ok"),
            Duration::from_nanos(30)
        );
        assert_eq!(
            parse_duration(None, Duration::from_secs(7), "t").expect("ok"),
            Duration::from_secs(7)
        );
        assert!(parse_duration(Some(&json!("3w")), Duration::ZERO, "t").is_err());
    }
    /// `check` takes every Go duration, so `run` has to read them too.
    #[test]
    fn compound_go_durations() {
        let read = |raw: &str| parse_duration(Some(&json!(raw)), Duration::ZERO, "t");
        assert_eq!(read("1m30s").unwrap(), Duration::from_secs(90));
        assert_eq!(read("1h0m0s").unwrap(), Duration::from_secs(3600));
        assert_eq!(read("1.5s").unwrap(), Duration::from_millis(1500));
        assert_eq!(read("2s500ms").unwrap(), Duration::from_millis(2500));
        assert_eq!(read("250us").unwrap(), Duration::from_micros(250));
        assert_eq!(read("250\u{b5}s").unwrap(), Duration::from_micros(250));
        assert_eq!(read("40ns").unwrap(), Duration::from_nanos(40));
        assert_eq!(read("+1d2h").unwrap(), Duration::from_secs(93_600));
        assert_eq!(read("-5s").unwrap(), Duration::ZERO);
        assert_eq!(read("10").unwrap(), Duration::from_secs(10));
        for bad in ["1m30", "s", "-", "1..2s", "1x", "1e3s"] {
            assert!(read(bad).is_err(), "{bad}");
        }
    }
    #[test]
    fn invalid_duration_never_panics() {
        for raw in [
            "NaN",
            "inf",
            "-inf",
            "999999999999999999999999h",
            "1m30",
            "1e3s",
        ] {
            assert!(parse_duration(Some(&json!(raw)), Duration::ZERO, "t").is_err());
        }
    }
}

/// A byte size written the way the reference writes it: a number, or a number
/// with a unit suffix. `buffer_size` is the only user, and it is spelled "1MB"
/// in configs people copy from the docs, so the suffixes have to work.
pub(crate) fn parse_size(value: Option<&Value>, at: &str) -> anyhow::Result<usize> {
    let Some(value) = value else {
        return Ok(0);
    };
    match value {
        Value::Number(n) => n
            .as_u64()
            .map(|v| v as usize)
            .ok_or_else(|| anyhow::anyhow!("{at}: invalid size")),
        Value::String(raw) => {
            let raw = raw.trim();
            if raw.is_empty() {
                return Ok(0);
            }
            let split = raw
                .find(|c: char| !c.is_ascii_digit() && c != '.')
                .unwrap_or(raw.len());
            let (digits, unit) = raw.split_at(split);
            let value: f64 = digits
                .parse()
                .map_err(|_| anyhow::anyhow!("{at}: invalid size {raw:?}"))?;
            // Binary, not decimal: these are buffer sizes, and "1MB" meaning
            // 1000 bytes would put a cap four orders of magnitude below what the
            // config says.
            let scale: f64 = match unit.trim().to_ascii_lowercase().as_str() {
                "" | "b" => 1.0,
                "k" | "kb" => 1024.0,
                "m" | "mb" => 1024.0 * 1024.0,
                "g" | "gb" => 1024.0 * 1024.0 * 1024.0,
                other => anyhow::bail!("{at}: unknown size unit {other:?}"),
            };
            let bytes = value * scale;
            if bytes < 0.0 || !bytes.is_finite() {
                anyhow::bail!("{at}: size {raw:?} is out of range");
            }
            Ok(bytes as usize)
        }
        other => anyhow::bail!("{at}: invalid size value {other}"),
    }
}

#[cfg(test)]
mod size_tests {
    use super::parse_size;
    use serde_json::Value;

    fn parse(raw: &str) -> usize {
        parse_size(Some(&Value::String(raw.to_string())), "buffer_size").expect("parses")
    }

    #[test]
    fn plain_numbers_are_bytes() {
        assert_eq!(parse("0"), 0);
        assert_eq!(parse("512"), 512);
    }

    #[test]
    fn suffixes_are_binary() {
        assert_eq!(parse("1KB"), 1024);
        assert_eq!(parse("1MB"), 1024 * 1024);
        assert_eq!(parse("1mb"), 1024 * 1024);
        assert_eq!(parse("2 GB"), 2 * 1024 * 1024 * 1024);
    }

    #[test]
    fn an_empty_value_is_zero() {
        assert_eq!(parse(""), 0);
    }

    #[test]
    fn garbage_is_an_error_not_a_silent_zero() {
        // A size that quietly becomes 0 would turn buffer_size into "never
        // flush on size", which looks like it works and never does.
        assert!(parse_size(Some(&Value::String("lots".into())), "buffer_size").is_err());
        assert!(parse_size(Some(&Value::String("1XB".into())), "buffer_size").is_err());
    }
}
