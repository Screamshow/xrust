pub(crate) mod bufpool;
pub mod cache_file;
#[cfg(feature = "clash-api")]
pub mod clash_api;
pub mod clash_mode;
pub mod clash_state;
pub mod dns;
pub mod http_client;
pub mod inbound;
pub mod logging;
#[cfg(target_os = "linux")]
pub mod netns;
pub mod ntp;
pub mod outbound;
#[cfg(unix)]
pub mod protect;
pub mod route;
pub mod tls_client;
pub mod tls_utls;
pub mod util;
pub mod ws;
#[cfg(feature = "clash-api")]
mod zip;

pub use core_crypto::env_var;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Context;
use serde_json::Value;
use tokio::task::JoinHandle;

use crate::route::Router;

/// A started box instance: running inbound listeners plus their tasks.
pub struct BoxInstance {
    router: Arc<Router>,
    reload_boundary: Value,
    tasks: Vec<JoinHandle<()>>,
    inbounds: Vec<(String, SocketAddr)>,
    dns: Option<Arc<dns::DnsService>>,
    clash_api: Option<SocketAddr>,
    cache_file: Option<Arc<std::sync::Mutex<cache_file::CacheFile>>>,
}

/// Dialer options `check` accepts and the runtime does not read. The reference
/// applies each of them to the outbound's own sockets; saying so once per
/// entry beats leaving a mistyped `netns` looking like it worked.
///
/// Everything else in `DIALER_OUT_FIELDS` is honoured by
/// `outbound::dial::DialOptions`, which is the single place a socket is built.
const UNHONORED_DIALER_FIELDS: &[&str] = &[
    "fallback_network_type",
    "network_strategy",
    "network_type",
    // a Linux socket option and a Linux-only dial, applied by `outbound/dial.rs`
    // there and nowhere else
    #[cfg(not(target_os = "linux"))]
    "netns",
    #[cfg(not(target_os = "linux"))]
    "tcp_multi_path",
    // `protect_path` is a unix socket protocol, and a no-op off unix
    #[cfg(not(unix))]
    "protect_path",
];

/// One warning per entry per field, so a shared option is not repeated.
fn warn_unhonored_options(root: &Value) {
    for (section, index, field) in unhonored_options(root) {
        logging::warn(format_args!(
            "{section}[{index}].{field}: accepted by check, not applied at runtime (ignored)"
        ));
    }
}

/// Which entries carry an option we accept but do not apply.
fn unhonored_options(root: &Value) -> Vec<(&'static str, usize, &'static str)> {
    let mut out = Vec::new();
    for section in ["outbounds", "endpoints", "inbounds"] {
        let empty = Vec::new();
        for (i, entry) in root
            .get(section)
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let Some(object) = entry.as_object() else {
                continue;
            };
            for field in UNHONORED_DIALER_FIELDS {
                if object.contains_key(*field) && !object[*field].is_null() {
                    out.push((section, i, *field));
                }
            }
        }
    }
    out
}

impl BoxInstance {
    /// Local addresses of all started inbounds.
    pub fn inbound_addrs(&self) -> &[(String, SocketAddr)] {
        &self.inbounds
    }

    /// The configured dns service (`None` without a `dns` section).
    pub fn dns(&self) -> Option<Arc<dns::DnsService>> {
        self.dns.clone()
    }

    /// The `experimental.cache_file` store (`None` when not configured).
    pub fn cache_file(&self) -> Option<cache_file::SharedCacheFile> {
        self.cache_file.clone()
    }

    /// Bound clash-api external controller (`None` when not configured).
    pub fn clash_api_addr(&self) -> Option<SocketAddr> {
        self.clash_api
    }

    /// Running router instance.
    pub fn router(&self) -> Arc<Router> {
        Arc::clone(&self.router)
    }

    /// Perform in-place hot reload without stopping inbounds or dropping connections.
    pub async fn reload_in_place(&mut self, new_root: &Value) -> anyhow::Result<()> {
        anyhow::ensure!(
            can_reload_in_place(&self.reload_boundary, new_root),
            "configuration changes listeners or other restart-only settings"
        );
        warn_unhonored_options(new_root);

        // 1. Build and validate new router inner BEFORE mutating anything running
        let prepared = Router::prepare(new_root)?;
        let new_inner = prepared.inner();

        // 2. Build and validate new DNS service BEFORE mutating anything running
        let new_dns = dns::DnsService::build_with_rule_sets(new_root, Some(new_inner.rule_sets()))
            .context("dns section")?;

        // Prepare downloads and endpoints before changing the live router.
        let ready = async {
            prepared
                .rule_sets()
                .start_remote(&prepared, self.cache_file.clone())
                .await?;
            prepared.start_endpoints().await?;
            anyhow::Ok(())
        }
        .await;
        if let Err(error) = ready {
            stop_tasks(prepared.take_probe_tasks()).await;
            return Err(error);
        }
        // Remote updater tasks remain tracked on the prepared inner.

        // 3. Migrate active DNS cache, server addrs, reverse mappings, and fakeip pools
        if let (Some(new_svc), Some(old_svc)) = (&new_dns, &self.dns) {
            new_svc.migrate_from(old_svc);
        }

        // 4. Atomically apply the new router inner (delay history, selectors, and urltest preserved)
        self.router.apply_prepared_inner(new_inner).await?;

        // 5. Connect DNS service to the shared router and publish globally
        if let Some(service) = &new_dns {
            service.attach_cache(self.cache_file.clone());
            service.set_router(Arc::clone(&self.router));
        }
        dns::set_service(new_dns.clone());
        self.dns = new_dns;

        // 7. Hot-apply log settings
        let log = new_root.get("log");
        let level = log.and_then(|l| l.get("level")).and_then(Value::as_str);
        let disabled = log
            .and_then(|l| l.get("disabled"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        if let Some(lvl) = level {
            logging::set_level(lvl);
        }
        logging::set_enabled(!disabled);
        self.router.record_applied_config(new_root);

        Ok(())
    }

    /// Abort all listeners and connection tasks.
    pub fn shutdown(self) {
        for task in self.tasks.into_iter().chain(self.router.take_probe_tasks()) {
            task.abort();
        }
        flush_cache(&self.cache_file);
    }

    /// Wait until aborted listener tasks have released their sockets.
    pub async fn shutdown_wait(self) {
        let mut tasks = self.tasks;
        tasks.extend(self.router.take_probe_tasks());
        stop_tasks(tasks).await;
        flush_cache(&self.cache_file);
    }
}

fn flush_cache(cache: &Option<cache_file::SharedCacheFile>) {
    if let Some(cache) = cache
        && let Err(error) = cache.lock().expect("cache").flush()
    {
        logging::warn(format_args!("cache file: shutdown flush failed ({error})"));
    }
}

async fn stop_tasks(tasks: Vec<JoinHandle<()>>) {
    for task in &tasks {
        task.abort();
    }
    for task in tasks {
        let _ = task.await;
    }
}

/// Build and start the data plane from a parsed configuration document.
pub async fn start(root: &Value) -> anyhow::Result<BoxInstance> {
    let mut tasks = Vec::new();
    let result = start_inner(root, &mut tasks).await;
    if result.is_err() {
        stop_tasks(tasks).await;
    }
    result
}

async fn start_inner(root: &Value, tasks: &mut Vec<JoinHandle<()>>) -> anyhow::Result<BoxInstance> {
    core_tls::install_default_provider();
    warn_unhonored_options(root);
    let log = root.get("log");
    let level = log.and_then(|l| l.get("level")).and_then(Value::as_str);
    let output = log.and_then(|l| l.get("output")).and_then(Value::as_str);
    let timestamp = log
        .and_then(|l| l.get("timestamp"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let disabled = log
        .and_then(|l| l.get("disabled"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    if !logging::init(output, level, timestamp)
        && let Some(raw) = level
    {
        anyhow::bail!("unknown log level: {raw}");
    }
    if disabled {
        logging::set_disabled();
    }

    // network_namespaces: every namespace has to be enterable before the first
    // dial asks for one, which is where the reference starts them too
    #[cfg(target_os = "linux")]
    if let Some(namespaces) = root.get("network_namespaces") {
        for line in netns::setup(&netns_from_config(namespaces)?)? {
            logging::info(format_args!("{line}"));
        }
    }

    // experimental.cache_file: the bbolt store for rule-sets, fakeip and DNS
    let cache_file: Option<cache_file::SharedCacheFile> = cache_file::CacheFile::open(
        cache_file::CacheFileOptions::from_config(root.get("experimental"))?,
    )?
    .map(|store| Arc::new(std::sync::Mutex::new(store)));
    // the clash mode is persisted like the reference persists bucketMode
    clash_mode::attach_store(cache_file.clone());
    let router = Router::new(root)?;
    router.attach_selection_cache(cache_file.clone());
    // remote rule sets fetch before the instance is up: a failed first fetch
    // aborts the start, exactly like `RemoteRuleSet.StartContext`
    let remote_result = router
        .rule_sets()
        .start_remote(&router, cache_file.clone())
        .await;
    tasks.extend(router.take_probe_tasks());
    remote_result?;
    router.start_endpoints().await?;
    let dns_service = dns::DnsService::build_with_rule_sets(root, Some(&router.rule_sets()))
        .context("dns section")?;
    if let Some(service) = &dns_service {
        service.attach_cache(cache_file.clone());
        // `dns.server.detour` dials through the outbounds
        service.set_router(Arc::clone(&router));
    }
    dns::set_service(dns_service.clone());

    tasks.extend(router.take_probe_tasks());
    #[allow(unused_mut)]
    let mut clash_api = None;
    #[cfg(feature = "clash-api")]
    if let Some(clash) = clash_api::ClashApi::build(root).context("experimental.clash_api")? {
        let (addr, handle) = clash.bind_and_spawn(Arc::clone(&router)).await?;
        logging::info(format_args!("clash-api: restful api listening at {addr}"));
        tasks.push(handle);
        clash_api = Some(addr);
    }
    if let Some(ntp) = ntp::NtpService::build(root)? {
        tasks.push(ntp.spawn());
    }
    let mut inbounds = Vec::new();
    let empty = Vec::new();
    let list = root
        .get("inbounds")
        .and_then(Value::as_array)
        .unwrap_or(&empty);
    for (i, obj) in list.iter().enumerate() {
        let ty = obj
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("inbounds[{i}]: missing type"))?;
        let tag = obj
            .get("tag")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match ty {
            "mixed" | "socks" | "http" => {
                let flavor = match ty {
                    "http" => inbound::mixed::Flavor::Http,
                    _ => inbound::mixed::Flavor::Mixed,
                };
                let inbound = inbound::mixed::Mixed::bind_as(obj, Arc::clone(&router), flavor)
                    .await
                    .with_context(|| format!("inbounds[{i}]: {ty}"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "direct" => {
                let inbound = inbound::direct::Direct::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: direct"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "redirect" => {
                let inbound = inbound::redirect::Redirect::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: redirect"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "tproxy" => {
                let inbound = inbound::tproxy::Tproxy::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tproxy"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "vless" => {
                let inbound = inbound::proxy::Vless::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: vless"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "tun" => {
                let inbound = inbound::tun::Tun::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: tun"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            "hysteria2" => {
                let inbound = inbound::hysteria2::Hysteria2::bind(obj, Arc::clone(&router))
                    .await
                    .with_context(|| format!("inbounds[{i}]: hysteria2"))?;
                let addr = inbound.local_addr()?;
                inbounds.push((tag.clone(), addr));
                tasks.push(tokio::spawn(inbound.serve()));
            }
            other => anyhow::bail!("inbounds[{i}]: inbound type {other:?} not implemented yet"),
        }
    }

    if let Some(cache) = &cache_file {
        let cache = Arc::clone(cache);
        tasks.push(tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                cache.lock().expect("cache").flush_if_due();
            }
        }));
    }
    router.record_applied_config(root);
    Ok(BoxInstance {
        router,
        reload_boundary: reload_boundary(root),
        tasks: std::mem::take(tasks),
        inbounds,
        dns: dns_service,
        clash_api,
        cache_file,
    })
}

/// Load a configuration file, run the box, and block until SIGINT/SIGTERM.
pub async fn run(config_path: &std::path::Path) -> anyhow::Result<()> {
    run_with_loader(|| {
        std::fs::read_to_string(config_path)
            .with_context(|| format!("read config {}", config_path.display()))
    })
    .await
}

/// Run the box from raw JSON configuration string, and block until SIGINT/SIGTERM.
pub async fn run_str(raw: &str) -> anyhow::Result<()> {
    run_with_loader(|| Ok(raw.to_string())).await
}

fn checked_config(raw: &str) -> anyhow::Result<Value> {
    core_config::check_str(raw).map_err(anyhow::Error::msg)?;
    serde_json::from_str(raw).context("decode config")
}

async fn reload_instance(
    instance: BoxInstance,
    previous: &Value,
    next: &Value,
) -> anyhow::Result<(BoxInstance, bool)> {
    instance.shutdown_wait().await;
    match start(next).await {
        Ok(instance) => Ok((instance, true)),
        Err(error) => {
            logging::warn(format_args!(
                "reload failed, restoring previous configuration: {error:#}"
            ));
            let restored = start(previous)
                .await
                .context("restore previous configuration after reload failure")?;
            Ok((restored, false))
        }
    }
}

// Keep only immutable runtime settings, not a second copy of subscriptions.
fn reload_boundary(root: &Value) -> Value {
    let mut boundary = serde_json::Map::new();
    for key in ["inbounds", "ntp", "network_namespaces"] {
        if let Some(value) = root.get(key) {
            boundary.insert(key.to_string(), value.clone());
        }
    }
    if let Some(experimental) = root.get("experimental") {
        let mut immutable = serde_json::Map::new();
        for key in ["clash_api", "cache_file"] {
            if let Some(value) = experimental.get(key) {
                immutable.insert(key.into(), value.clone());
            }
        }
        boundary.insert("experimental".into(), Value::Object(immutable));
    }
    Value::Object(boundary)
}

/// Canonical parsed-config identity shared by the CLI planner and live API.
pub fn configuration_fingerprint(root: &Value) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "{:x}",
        Sha256::digest(serde_json::to_vec(root).expect("config JSON"))
    )
}

pub fn can_reload_in_place(old_root: &Value, new_root: &Value) -> bool {
    if old_root.get("inbounds") != new_root.get("inbounds") {
        return false;
    }
    let old_clash = old_root
        .get("experimental")
        .and_then(|e| e.get("clash_api"));
    let new_clash = new_root
        .get("experimental")
        .and_then(|e| e.get("clash_api"));
    if old_clash != new_clash {
        return false;
    }
    let cache = |root: &Value| {
        root.get("experimental")
            .and_then(|e| e.get("cache_file"))
            .cloned()
    };
    if cache(old_root) != cache(new_root) {
        return false;
    }
    #[cfg(target_os = "linux")]
    if old_root.get("network_namespaces") != new_root.get("network_namespaces") {
        return false;
    }
    if old_root.get("ntp") != new_root.get("ntp") {
        return false;
    }
    true
}

/// Reload the original CLI configuration sources on SIGHUP.
pub async fn run_with_loader(
    mut load: impl FnMut() -> anyhow::Result<String>,
) -> anyhow::Result<()> {
    // Register HUP before startup, including potentially slow remote downloads.
    #[cfg(unix)]
    let (mut term, mut hup) = {
        use tokio::signal::unix::{SignalKind, signal};
        (
            signal(SignalKind::terminate())?,
            signal(SignalKind::hangup())?,
        )
    };
    let mut root = checked_config(&load()?)?;
    let mut instance = start(&root).await?;
    loop {
        #[cfg(unix)]
        let reload = tokio::select! {
            _ = tokio::signal::ctrl_c() => false,
            _ = term.recv() => false,
            _ = hup.recv() => true,
        };
        #[cfg(not(unix))]
        let reload = {
            tokio::signal::ctrl_c().await?;
            false
        };
        if !reload {
            logging::info(format_args!("shutting down"));
            instance.shutdown_wait().await;
            return Ok(());
        }
        let next = match load().and_then(|raw| checked_config(&raw)) {
            Ok(next) => next,
            Err(error) => {
                logging::warn(format_args!(
                    "reload configuration rejected; keeping current runtime: {error:#}"
                ));
                continue;
            }
        };
        if can_reload_in_place(&root, &next) {
            match instance.reload_in_place(&next).await {
                Ok(()) => root = next,
                Err(error) => logging::warn(format_args!("hot reload failed: {error:#}")),
            }
            continue;
        }
        let (reloaded, accepted) = reload_instance(instance, &root, &next).await?;
        instance = reloaded;
        if accepted {
            root = next;
            logging::info(format_args!("configuration reloaded after SIGHUP"));
        }
    }
}

/// The `network_namespaces` section as the manager wants it.
#[cfg(target_os = "linux")]
fn netns_from_config(value: &Value) -> anyhow::Result<Vec<netns::Namespace>> {
    let list = value
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("network_namespaces: must be a list"))?;
    list.iter()
        .map(|entry| {
            let kind = match entry.get("type").and_then(Value::as_str).unwrap_or("") {
                "" | "default" => netns::Kind::Default,
                "unshare" => netns::Kind::Unshare,
                other => anyhow::bail!("network namespace: unknown type: {other}"),
            };
            Ok(netns::Namespace {
                kind,
                tag: entry
                    .get("tag")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                path: entry
                    .get("path")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string(),
                pid_file: entry
                    .get("pid_file")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .map(str::to_string),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    async fn socks_ready(port: u16) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .unwrap();
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut response = [0; 2];
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            stream.read_exact(&mut response),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(response, [5, 0]);
    }

    #[tokio::test]
    async fn reload_rebinds_same_port_and_recovers_partial_start_failure() {
        let probe = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);
        let old = json!({"inbounds":[{"type":"mixed","tag":"old","listen":"127.0.0.1","listen_port":port}],
            "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}});
        let instance = start(&old).await.unwrap();
        socks_ready(port).await;
        let mut next = old.clone();
        next["inbounds"][0]["tag"] = json!("new");
        let (instance, accepted) = reload_instance(instance, &old, &next).await.unwrap();
        assert!(accepted);
        assert_eq!(instance.inbound_addrs()[0].0, "new");
        socks_ready(port).await;
        let busy = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut broken = next.clone();
        broken["inbounds"]
            .as_array_mut()
            .unwrap()
            .push(json!({"type":"mixed","tag":"busy",
            "listen":"127.0.0.1","listen_port":busy.local_addr().unwrap().port()}));
        let (instance, accepted) = reload_instance(instance, &next, &broken).await.unwrap();
        assert!(!accepted);
        assert_eq!(instance.inbound_addrs().len(), 1);
        assert_eq!(instance.inbound_addrs()[0].0, "new");
        socks_ready(port).await;
        instance.shutdown_wait().await;
        assert!(
            tokio::net::TcpListener::bind(("127.0.0.1", port))
                .await
                .is_ok()
        );
    }

    #[test]
    fn reload_validation_rejects_bad_configuration() {
        assert!(checked_config("{broken").is_err());
        assert!(checked_config(r#"{"inbounds":[{"type":"unknown"}]}"#).is_err());
    }

    #[test]
    fn options_we_accept_but_do_not_apply_are_named() {
        let config = json!({
            "outbounds": [
                {"type": "direct", "tag": "d", "netns": "n", "network_strategy": "prefer_ipv4",
                 "routing_mark": 99, "bind_interface": "eth0"},
                {"type": "block", "tag": "b", "reuse_addr": true, "network_strategy": null}
            ],
            "inbounds": [
                {"type": "mixed", "tag": "in", "tcp_multi_path": true}
            ]
        });
        // `domain_strategy` and `fallback_delay` are applied everywhere;
        // `netns` and `tcp_multi_path` only on Linux, and the interface group
        // is not applied at all, which is what the reference does off Android
        let expected: Vec<(&str, usize, &str)> = if cfg!(target_os = "linux") {
            vec![("outbounds", 0, "network_strategy")]
        } else {
            vec![
                ("outbounds", 0, "network_strategy"),
                ("outbounds", 0, "netns"),
                ("inbounds", 0, "tcp_multi_path"),
            ]
        };
        assert_eq!(
            unhonored_options(&config),
            expected,
            "the honored options stay quiet and a null is not an option"
        );
    }
}
