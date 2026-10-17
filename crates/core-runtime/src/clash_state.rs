//! Live connection registry and traffic counters behind the Clash API views
//! (`GET /connections`, `GET /traffic`, `DELETE /connections`).
//!
//! Every relayed TCP connection gets an entry with the routing metadata the
//! reference exposes: inbound, source, destination, rule, chain and the byte
//! counters. Entries also carry a close signal, so the controller can drop a
//! connection the way Clash does.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use portable_atomic::AtomicU64;

use tokio::sync::Notify;

/// Routing metadata for one relayed connection.
#[derive(Clone, Debug)]
pub struct ConnMeta {
    pub network: &'static str,
    pub inbound: String,
    pub source: String,
    pub host: String,
    pub destination: String,
    pub chains: Vec<String>,
    pub rule: String,
    pub rule_payload: String,
}

struct Shared {
    id: u64,
    meta: ConnMeta,
    routing: Option<crate::route::ConnContext>,
    scope: Option<Arc<()>>,
    start: Instant,
    upload: AtomicU64,
    download: AtomicU64,
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

/// Cloneable close signal: the relay loop waits on it, the controller sets it.
#[derive(Clone)]
pub struct CloseSignal {
    closed: Arc<AtomicBool>,
    notify: Arc<Notify>,
}

impl CloseSignal {
    /// Resolves once the connection was closed through the API.
    pub async fn wait(&self) {
        loop {
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.closed.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }
}

fn trigger(closed: &AtomicBool, notify: &Notify) {
    closed.store(true, Ordering::Release);
    notify.notify_waiters();
}

fn registry() -> &'static Mutex<HashMap<u64, Arc<Shared>>> {
    static REGISTRY: OnceLock<Mutex<HashMap<u64, Arc<Shared>>>> = OnceLock::new();
    REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static UPLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);
static DOWNLOAD_TOTAL: AtomicU64 = AtomicU64::new(0);

/// Handle held by the relay loop; dropping it removes the entry.
pub struct ConnHandle {
    shared: Arc<Shared>,
}

impl ConnHandle {
    pub fn open(meta: ConnMeta) -> Self {
        Self::open_inner(meta, None, None)
    }

    pub fn open_with_context(
        meta: ConnMeta,
        ctx: &crate::route::ConnContext,
        router: &crate::route::Router,
    ) -> Self {
        let mut routing = ctx.clone();
        // Routing evidence is sufficient; never retain buffered user traffic.
        routing.sniff_prefix = Vec::new();
        Self::open_inner(meta, Some(routing), Some(router.connection_scope()))
    }

    fn open_inner(
        meta: ConnMeta,
        routing: Option<crate::route::ConnContext>,
        scope: Option<Arc<()>>,
    ) -> Self {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let shared = Arc::new(Shared {
            id,
            meta,
            routing,
            scope,
            start: Instant::now(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            closed: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
        });
        if let Ok(mut guard) = registry().lock() {
            guard.insert(id, Arc::clone(&shared));
        }
        Self { shared }
    }

    pub fn id(&self) -> u64 {
        self.shared.id
    }

    /// Close signal for `select!` in the relay loop.
    pub fn close_signal(&self) -> CloseSignal {
        CloseSignal {
            closed: Arc::clone(&self.shared.closed),
            notify: Arc::clone(&self.shared.notify),
        }
    }

    pub fn is_closed(&self) -> bool {
        self.shared.closed.load(Ordering::Acquire)
    }

    pub fn add_upload(&self, bytes: u64) {
        self.shared.upload.fetch_add(bytes, Ordering::Relaxed);
        UPLOAD_TOTAL.fetch_add(bytes, Ordering::Relaxed);
    }

    pub fn add_download(&self, bytes: u64) {
        self.shared.download.fetch_add(bytes, Ordering::Relaxed);
        DOWNLOAD_TOTAL.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl Drop for ConnHandle {
    fn drop(&mut self) {
        if let Ok(mut guard) = registry().lock() {
            guard.remove(&self.shared.id);
        }
    }
}

/// One row of `GET /connections`.
pub struct ConnView {
    pub id: String,
    pub upload: u64,
    pub download: u64,
    pub start: Instant,
    pub meta: ConnMeta,
}

/// Process-wide byte counters without collecting connection metadata.
pub fn traffic_totals() -> (u64, u64) {
    (
        UPLOAD_TOTAL.load(Ordering::Relaxed),
        DOWNLOAD_TOTAL.load(Ordering::Relaxed),
    )
}

/// Live entries plus the process-wide totals.
pub fn snapshot() -> (Vec<ConnView>, u64, u64) {
    let entries: Vec<Arc<Shared>> = registry()
        .lock()
        .map(|guard| guard.values().cloned().collect())
        .unwrap_or_default();
    let views = entries
        .into_iter()
        .map(|entry| ConnView {
            id: entry.id.to_string(),
            upload: entry.upload.load(Ordering::Relaxed),
            download: entry.download.load(Ordering::Relaxed),
            start: entry.start,
            meta: entry.meta.clone(),
        })
        .collect();
    (
        views,
        UPLOAD_TOTAL.load(Ordering::Relaxed),
        DOWNLOAD_TOTAL.load(Ordering::Relaxed),
    )
}

/// `DELETE /connections/{id}`; `false` when the id is unknown.
pub fn close(id: u64) -> bool {
    let entry = registry()
        .lock()
        .ok()
        .and_then(|guard| guard.get(&id).cloned());
    match entry {
        Some(entry) => {
            trigger(&entry.closed, &entry.notify);
            true
        }
        None => false,
    }
}

/// Serialize a group transition with connection registration. Entries created
/// after the transition can never be selected for closure by that transition.
pub(crate) fn switch_group(
    router: &crate::route::Router,
    group: &str,
    interrupt: bool,
    switch: impl FnOnce() -> bool,
) {
    if !interrupt {
        switch();
        return;
    }
    let scope = router.connection_scope();
    let entries = registry().lock().expect("connections");
    if switch() {
        for entry in entries.values().filter(|entry| {
            entry.scope.as_ref().is_some_and(|s| Arc::ptr_eq(s, &scope))
                && entry.meta.chains.iter().any(|tag| tag == group)
        }) {
            trigger(&entry.closed, &entry.notify);
        }
    }
}

/// `DELETE /connections`.
pub fn close_all() -> usize {
    let entries: Vec<Arc<Shared>> = registry()
        .lock()
        .map(|guard| guard.values().cloned().collect())
        .unwrap_or_default();
    for entry in &entries {
        trigger(&entry.closed, &entry.notify);
    }
    entries.len()
}

/// Re-evaluate tracked sessions using one coherent routing snapshot. No dial
/// occurs; ordinary DNS/route actions run on copies of the captured context.
pub async fn close_invalid_routes(router: &crate::route::Router) -> serde_json::Value {
    use crate::route::Decision;
    let entries: Vec<_> = registry()
        .lock()
        .map(|guard| guard.values().cloned().collect())
        .unwrap_or_default();
    let snapshot = router.inner();
    let mut tasks = tokio::task::JoinSet::new();
    let mut invalid = Vec::new();
    let mut skipped = 0usize;
    for entry in entries {
        if !entry
            .scope
            .as_ref()
            .is_some_and(|scope| Arc::ptr_eq(scope, &router.connection_scope()))
        {
            continue;
        }
        let Some(mut ctx) = entry.routing.clone() else {
            continue;
        };
        let original_destination = ctx.destination.to_string();
        if let Some(original) = ctx.route_original_destination.take() {
            ctx.destination = original;
        }
        let had_destination_rule = !entry.meta.rule_payload.is_empty();
        ctx.matched_rule = None;
        let current = Arc::clone(&snapshot);
        tasks.spawn(async move {
            let decision = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                current.route_walk::<tokio::net::TcpStream>(None, &mut ctx),
            )
            .await;
            let changed = match decision {
                Ok(Ok(Decision::Outbound(index))) => {
                    let tag = current
                        .outbound_table()
                        .find(|(i, _, _)| *i == index)
                        .map(|(_, tag, _)| tag);
                    let still_destination_rule = ctx
                        .matched_rule
                        .as_ref()
                        .is_some_and(|(_, payload)| !payload.is_empty());
                    Some(
                        tag != entry.meta.chains.first().map(String::as_str)
                            || ctx.destination.to_string() != original_destination
                            || (had_destination_rule && !still_destination_rule),
                    )
                }
                Ok(Ok(Decision::HijackDns)) => Some(true),
                Ok(Err(_))
                    if ctx
                        .matched_rule
                        .as_ref()
                        .is_some_and(|(rule, _)| rule.contains("=> reject")) =>
                {
                    Some(true)
                }
                _ => None,
            };
            (entry.id, changed)
        });
        if tasks.len() >= 16 {
            match tasks.join_next().await {
                Some(Ok((id, Some(true)))) => invalid.push(id),
                Some(Ok((_, Some(false)))) => {}
                _ => skipped += 1,
            }
        }
    }
    while let Some(result) = tasks.join_next().await {
        match result {
            Ok((id, Some(true))) => invalid.push(id),
            Ok((_, Some(false))) => {}
            _ => skipped += 1,
        }
    }
    // Another reload must not make this evaluation close current sessions.
    if !Arc::ptr_eq(&snapshot, &router.inner()) {
        return serde_json::json!({"closed":0,"skipped":skipped,"superseded":true});
    }
    let closed = invalid.into_iter().filter(|id| close(*id)).count();
    serde_json::json!({"closed":closed,"skipped":skipped,"superseded":false})
}

/// Count UDP payload bytes so `/traffic` sees datagram traffic too.
pub fn add_udp(upload: u64, download: u64) {
    UPLOAD_TOTAL.fetch_add(upload, Ordering::Relaxed);
    DOWNLOAD_TOTAL.fetch_add(download, Ordering::Relaxed);
}

#[cfg(test)]
mod tests {
    #[test]
    fn registration_after_switch_is_not_closed_by_that_switch() {
        use crate::{
            inbound::Target,
            route::{ConnContext, Router},
        };
        let router =
            Router::new(&serde_json::json!({"outbounds":[{"type":"direct","tag":"node"}]}))
                .unwrap();
        let ctx = ConnContext::new(
            "test",
            "127.0.0.1:1234".parse().unwrap(),
            Target::Domain("example.com".into(), 443),
            "tcp",
        );
        let mut meta = unique_meta("registration-race.example:443");
        meta.chains = vec!["group".into()];
        let old = ConnHandle::open_with_context(meta.clone(), &ctx, &router);
        let (go, ready) = std::sync::mpsc::channel();
        let (attempt, attempting) = std::sync::mpsc::channel();
        std::thread::scope(|scope| {
            let router_ref = &router;
            let worker = scope.spawn(move || {
                ready.recv().unwrap();
                attempt.send(()).unwrap();
                ConnHandle::open_with_context(meta, &ctx, router_ref)
            });
            switch_group(&router, "group", true, || {
                go.send(()).unwrap();
                attempting.recv().unwrap();
                true
            });
            let fresh = worker.join().unwrap();
            assert!(old.is_closed());
            assert!(!fresh.is_closed());
        });
    }

    use super::*;

    fn meta() -> ConnMeta {
        unique_meta("example.com:443")
    }

    /// The registry is process-global: serialize the tests inside this binary.
    fn guard() -> &'static tokio::sync::Mutex<()> {
        static LOCK: std::sync::OnceLock<tokio::sync::Mutex<()>> = std::sync::OnceLock::new();
        LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
    }

    /// Distinct destination per call so parallel tests can find their entry.
    fn unique_meta(destination: &str) -> ConnMeta {
        ConnMeta {
            network: "tcp",
            inbound: "mixed-in".into(),
            source: "192.168.1.10:5000".into(),
            host: "example.com".into(),
            destination: destination.into(),
            chains: vec!["proxy".into()],
            rule: "DomainSuffix".into(),
            rule_payload: "example.com".into(),
        }
    }

    #[tokio::test]
    async fn registry_tracks_counters_and_close() {
        let _serial = guard().lock().await;
        let handle = ConnHandle::open(meta());
        let signal = handle.close_signal();
        handle.add_upload(10);
        handle.add_download(20);
        let (views, up_total, down_total) = snapshot();
        let view = views
            .iter()
            .find(|v| v.meta.destination == "example.com:443")
            .expect("entry listed");
        assert_eq!((view.upload, view.download), (10, 20));
        assert_eq!(view.meta.rule, "DomainSuffix");
        assert!(up_total >= 10 && down_total >= 20);

        let id: u64 = view.id.parse().expect("id");
        assert_eq!(id, handle.id());
        assert!(close(id), "close reports the connection was found");
        tokio::select! {
            _ = signal.wait() => {}
            _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                panic!("close signal not delivered")
            }
        }
        assert!(!close(id + 10_000), "unknown ids report false");
    }

    #[tokio::test]
    async fn close_all_wakes_every_relay() {
        let _serial = guard().lock().await;
        let first = ConnHandle::open(meta());
        let second = ConnHandle::open(meta());
        let first_signal = first.close_signal();
        let second_signal = second.close_signal();
        assert!(close_all() >= 2, "both relays are registered");
        for signal in [first_signal, second_signal] {
            tokio::select! {
                _ = signal.wait() => {}
                _ = tokio::time::sleep(std::time::Duration::from_millis(500)) => {
                    panic!("close_all missed a relay")
                }
            }
        }
    }

    #[tokio::test]
    async fn dropping_the_handle_removes_the_entry() {
        let _serial = guard().lock().await;
        let destination = "dropped.example.com:443";
        assert!(
            !snapshot()
                .0
                .iter()
                .any(|view| view.meta.destination == destination)
        );
        {
            let _handle = ConnHandle::open(unique_meta(destination));
            assert_eq!(
                snapshot()
                    .0
                    .iter()
                    .filter(|view| view.meta.destination == destination)
                    .count(),
                1
            );
        }
        assert!(
            !snapshot()
                .0
                .iter()
                .any(|view| view.meta.destination == destination),
            "dropping the handle removes the entry"
        );
    }
}
