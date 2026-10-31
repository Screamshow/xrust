//! Routing engine: rule walk with actions (route / route-options / reject /
//! hijack-dns / sniff / resolve), connection context, and outbound dispatch.

pub mod mmap_set;
pub mod neighbor;
pub mod process;
pub mod rule;
pub mod rule_set;
pub mod rule_set_index;
pub mod rule_set_remote;
pub mod sniff;
mod sniff_bittorrent;
mod sniff_quic;

use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub use crate::inbound::Target;
pub use rule::{
    Action, RejectFlood, RejectMethod, ResolveAction, RouteOptions, Rule, apply_route_options,
};

use crate::dns::{self, QueryMeta};
use crate::inbound::Conn;
use crate::logging;
use crate::outbound::block::Block;
use crate::outbound::chain::Chain;
use crate::outbound::direct::Direct;
use crate::outbound::hysteria2::Hysteria2;
use crate::outbound::masque::Masque;
use crate::outbound::proxy::{HttpOut, Selector};
use crate::outbound::secure::{Trojan, Vless};
use crate::outbound::tailscale::Tailscale;
use crate::outbound::urltest::Urltest;
use crate::outbound::wireguard::WireGuard;

/// Result of a completed rule walk for one connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Outbound(usize),
    HijackDns,
}

/// Sniff outcome recorded on the context for duplicate-skip logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffError {
    NeedMore,
    Failed(String),
}

/// Per-connection metadata visible to rule matchers and actions.
#[derive(Debug, Clone)]
pub struct ConnContext {
    pub inbound: Option<String>,
    pub source: SocketAddr,
    pub destination: Target,
    pub origin_destination: Option<Target>,
    pub network: &'static str,
    pub protocol: Option<String>,
    pub domain: Option<String>,
    /// Original DNS name recovered from FakeIP; sniff/resolve may replace the other names.
    pub fakeip_domain: Option<String>,
    pub auth_user: Option<String>,
    pub client: Option<String>,
    pub destination_addresses: Vec<IpAddr>,
    pub fakeip: bool,
    pub sniff_prefix: Vec<u8>,
    pub sniff_error: Option<SniffError>,
    pub sniffer_names: Vec<String>,
    pub sniff_timeout: Option<Duration>,
    pub ip_version: Option<u8>,
    pub route_original_destination: Option<Target>,
    /// Clash connection view: the rule that produced the decision.
    pub matched_rule: Option<(String, String)>,
    /// `route.find_neighbor`: the client's hardware address, when the
    /// neighbour tables know it.
    pub source_mac: Option<neighbor::MacAddr>,
    /// `route.find_neighbor`: the client's DHCP hostname.
    pub source_hostname: Option<String>,
    /// `route.find_process`: the process that opened the connection.
    pub process: Option<process::ProcessInfo>,
    pub udp_timeout: Option<Duration>,
    pub udp_disable_domain_unmapping: Option<bool>,
    pub tls_fragment: Option<bool>,
    pub tls_record_fragment: Option<bool>,
}

use std::net::IpAddr;

impl Default for ConnContext {
    fn default() -> Self {
        Self {
            inbound: None,
            source: SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0),
            destination: Target::Ip(SocketAddr::new(
                IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                0,
            )),
            origin_destination: None,
            network: "tcp",
            protocol: None,
            domain: None,
            fakeip_domain: None,
            auth_user: None,
            client: None,
            destination_addresses: Vec::new(),
            fakeip: false,
            sniff_prefix: Vec::new(),
            sniff_error: None,
            sniffer_names: Vec::new(),
            sniff_timeout: None,
            ip_version: None,
            route_original_destination: None,
            matched_rule: None,
            source_mac: None,
            source_hostname: None,
            process: None,
            udp_timeout: None,
            udp_disable_domain_unmapping: None,
            tls_fragment: None,
            tls_record_fragment: None,
        }
    }
}

impl ConnContext {
    pub fn new(
        inbound: &str,
        source: SocketAddr,
        destination: Target,
        network: &'static str,
    ) -> Self {
        Self {
            inbound: Some(inbound.to_string()),
            source,
            destination,
            network,
            ..Default::default()
        }
    }
}

// A TCP socket deadline alone does not bound TLS/transport negotiation or
// pooled capacity waits. This budget ends when a usable tunnel is returned;
// it never limits established TCP/UDP session lifetime.
const OUTBOUND_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(15);

/// Retain an explicit TCP dial budget and allow transport setup on top of it.
/// Groups inherit their longest member budget; sequential chains/detours add
/// their budgets. Resolve from config so every protocol shares this policy.
fn outbound_setup_budgets(root: &Value) -> anyhow::Result<Vec<std::time::Duration>> {
    use std::time::Duration;
    let configs: Vec<&Value> = ["outbounds", "endpoints"]
        .iter()
        .flat_map(|key| {
            root.get(key)
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .collect();
    let tags: HashMap<&str, usize> = configs
        .iter()
        .enumerate()
        .filter_map(|(i, c)| c.get("tag").and_then(Value::as_str).map(|tag| (tag, i)))
        .collect();
    let mut own = Vec::new();
    for config in &configs {
        let mut options = serde_json::Map::new();
        if let Some(value) = config.get("connect_timeout") {
            options.insert("connect_timeout".into(), value.clone());
        }
        let explicit = crate::outbound::dial::DialOptions::parse(&options)?.connect_timeout;
        own.push(OUTBOUND_SETUP_TIMEOUT.saturating_add(explicit.unwrap_or(Duration::ZERO)));
    }
    fn visit(
        i: usize,
        configs: &[&Value],
        tags: &HashMap<&str, usize>,
        own: &[Duration],
        path: &mut Vec<usize>,
        memo: &mut [Option<Duration>],
    ) -> Duration {
        if let Some(budget) = memo[i] {
            return budget;
        }
        if path.contains(&i) {
            return OUTBOUND_SETUP_TIMEOUT;
        }
        path.push(i);
        let c = configs[i];
        let kind = c.get("type").and_then(Value::as_str).unwrap_or("");
        let mut budget = own[i];
        if matches!(kind, "selector" | "urltest" | "chain") {
            let children = c
                .get("outbounds")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|v| v.as_str().and_then(|tag| tags.get(tag).copied()));
            let mut group = Duration::ZERO;
            for child in children {
                let next = visit(child, configs, tags, own, path, memo);
                group = if kind == "chain" {
                    group.saturating_add(next)
                } else {
                    group.max(next)
                };
            }
            budget = budget.max(group);
        }
        if let Some(&detour) = c
            .get("detour")
            .and_then(Value::as_str)
            .and_then(|tag| tags.get(tag))
        {
            budget = budget.saturating_add(visit(detour, configs, tags, own, path, memo));
        }
        path.pop();
        memo[i] = Some(budget);
        budget
    }
    let mut memo = vec![None; configs.len()];
    Ok((0..configs.len())
        .map(|i| visit(i, &configs, &tags, &own, &mut Vec::new(), &mut memo))
        .collect())
}

pub enum Outbound {
    Direct(Direct),
    Block(Block),
    Http(HttpOut),
    Vless(Vless),
    Trojan(Trojan),
    Hysteria2(Hysteria2),
    Masque(Masque),
    WireGuard(Arc<WireGuard>),
    Urltest(Urltest),
    Selector(Selector),
    Chain(Chain),
    Tailscale(Tailscale),
}

impl Outbound {
    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        match self {
            Outbound::Direct(direct) => direct
                .connect(target)
                .await
                .map(|s| Conn::Plain(Box::new(s))),
            Outbound::Block(block) => block
                .connect(target)
                .await
                .map(|s| Conn::Plain(Box::new(s))),
            Outbound::Http(http) => http.connect(target).await.map(Conn::Plain),
            Outbound::Vless(vless) => vless.connect(target).await.map(Conn::Plain),
            Outbound::Trojan(trojan) => trojan.connect(target).await.map(Conn::Plain),
            Outbound::Hysteria2(hy2) => hy2.connect(target).await.map(Conn::Plain),
            Outbound::Masque(masque) => masque.connect(target).await.map(Conn::Plain),
            Outbound::WireGuard(wg) => wg.connect(target).await.map(Conn::Plain),
            Outbound::Urltest(urltest) => urltest.connect(router, target).await,
            Outbound::Selector(selector) => selector.connect(router, target).await,
            Outbound::Chain(chain) => chain.connect(router, target).await,
            Outbound::Tailscale(ts) => ts.connect(target).await.map(Conn::Plain),
        }
    }

    /// UDP dial; only outbounds that can carry datagrams implement it.
    pub async fn connect_udp(
        &self,
        router: &Router,
        target: &Target,
    ) -> io::Result<tokio::net::UdpSocket> {
        match self {
            Outbound::Direct(direct) => direct.connect_udp(target).await,
            Outbound::Hysteria2(hy2) => hy2.connect_udp(target).await,
            Outbound::Masque(masque) => masque.connect_udp(target).await,
            Outbound::Vless(vless) => vless.connect_udp(target).await,
            Outbound::Trojan(trojan) => trojan.connect_udp(target).await,
            Outbound::WireGuard(wg) => wg.connect_udp(target).await,
            Outbound::Block(_) => Err(io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "blocked by outbound",
            )),
            Outbound::Selector(selector) => selector.connect_udp(router, target).await,
            Outbound::Urltest(urltest) => urltest.connect_udp(router, target).await,
            Outbound::Chain(chain) => chain.connect_udp(router, target).await,
            Outbound::Tailscale(ts) => ts.connect_udp(target).await,
            _ => Err(io::Error::other("udp not supported by this outbound")),
        }
    }

    pub fn apply_dial_defaults(
        &mut self,
        default_mark: Option<u32>,
        default_interface: Option<&str>,
    ) {
        let apply = |dial: &mut crate::outbound::dial::DialOptions| {
            if dial.routing_mark.is_none() {
                dial.routing_mark = default_mark;
            }
            if dial.bind_interface.is_none() {
                dial.bind_interface = default_interface.map(str::to_string);
            }
        };

        match self {
            Outbound::Direct(d) => apply(&mut d.dial),
            Outbound::Vless(v) => apply(&mut v.dial),
            Outbound::Trojan(t) => apply(&mut t.dial),
            Outbound::Http(h) => apply(&mut h.dial),
            _ => {}
        }
    }

    fn build(obj: &Value, at: &str) -> anyhow::Result<Outbound> {
        let ty = obj
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing type"))?;
        let obj = obj
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        match ty {
            "direct" => Ok(Outbound::Direct(Direct::build(obj, at)?)),
            "block" => Ok(Outbound::Block(Block)),
            "http" => Ok(Outbound::Http(HttpOut::build(obj, at)?)),
            "vless" => Ok(Outbound::Vless(Vless::build(obj, at)?)),
            "trojan" => Ok(Outbound::Trojan(Trojan::build(obj, at)?)),
            "hysteria2" => Ok(Outbound::Hysteria2(Hysteria2::build(obj, at)?)),
            "masque" => Ok(Outbound::Masque(Masque::build(obj, at)?)),
            "urltest" => Ok(Outbound::Urltest(Urltest::build(obj, at)?)),
            "selector" => Ok(Outbound::Selector(Selector::build(obj, at)?)),
            "chain" => Ok(Outbound::Chain(Chain::build(obj, at)?)),
            other => Err(anyhow::anyhow!(
                "{at}: outbound type {other:?} not implemented yet"
            )),
        }
    }
}

/// Whether TSRS can hold `rules` as they are. When it cannot, the set is
/// loaded into memory instead, and the log says why.
pub(crate) fn mmap_keeps(rules: &[Value], tags: &[String]) -> bool {
    match mmap_set::tsrs_unsupported(rules) {
        None => true,
        Some(reason) => {
            logging::warn(format_args!(
                "rule-set {}: mmap cannot keep {reason}, using memory rules",
                tags.join(",")
            ));
            false
        }
    }
}

/// `route` section fields accepted by check but not yet honored at runtime.
/// `route.rule_set`: the inline, local and remote variants. Inline and local
/// sets load here; a remote set needs the downloader and is reported instead of
/// being silently ignored.
pub(crate) fn build_rule_sets(
    route: &serde_json::Map<String, Value>,
    clients: &crate::http_client::Registry,
) -> anyhow::Result<rule_set::RuleSetRegistry> {
    build_rule_sets_reusing(route, clients, None)
}

/// Build `route.rule_set`, sharing inline and local sets that `previous`
/// already built from the same entry and the same file.
pub(crate) fn build_rule_sets_reusing(
    route: &serde_json::Map<String, Value>,
    clients: &crate::http_client::Registry,
    previous: Option<&rule_set::RuleSetRegistry>,
) -> anyhow::Result<rule_set::RuleSetRegistry> {
    let mut registry = rule_set::RuleSetRegistry::new();
    let mut remotes = rule_set_remote::RemoteRegistry::new();
    let Some(list) = route.get("rule_set").filter(|value| !value.is_null()) else {
        return Ok(registry);
    };
    let entries = list
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("route.rule_set: must be an array"))?;
    for (i, entry) in entries.iter().enumerate() {
        let at = format!("route.rule_set[{i}]");
        let entry = entry
            .as_object()
            .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
        let ty = entry
            .get("type")
            .and_then(Value::as_str)
            .unwrap_or("inline");
        let tags = rule_set_tags(entry, &at)?;
        let use_mmap = entry.get("mmap").and_then(Value::as_bool).unwrap_or(false);
        let mode_str = entry.get("mode").and_then(Value::as_str).unwrap_or("auto");
        let mode = match mode_str {
            "memory" => mmap_set::MmapMode::Memory,
            "mmap" => mmap_set::MmapMode::Mmap,
            _ => mmap_set::MmapMode::Auto,
        };
        let origin = match ty {
            "inline" => rule_set::RuleSetOrigin::new(entry, None),
            "local" => {
                let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
                rule_set::RuleSetOrigin::new(entry, Some(&resolve_rule_set_path(path, &tags)))
            }
            _ => None,
        };
        if let (Some(origin), Some(previous)) = (&origin, previous)
            && let Some(set) = previous.reusable(origin)
        {
            logging::info(format_args!("kept unchanged rule-set {}", tags.join(",")));
            registry.insert_built(set, Some(origin.clone()));
            continue;
        }

        match ty {
            "inline" => {
                let rules = entry
                    .get("rules")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if use_mmap && mmap_keeps(&rules, &tags) {
                    let mut compiler = mmap_set::RuleSetCompiler::new();
                    let tsrs_bytes = compiler.compile(&rules)?;
                    let cache_file = entry.get("cache_file").and_then(Value::as_str);
                    let target_path = if let Some(cf) = cache_file {
                        std::path::PathBuf::from(cf)
                    } else {
                        rule_set_remote::default_tsrs_cache_path(&tags[0])
                    };
                    if let Some(parent) = target_path.parent() {
                        let _ = std::fs::create_dir_all(parent);
                    }
                    rule_set_remote::write_tsrs_if_changed(&target_path, &tsrs_bytes)?;
                    let mmap_set = std::sync::Arc::new(mmap_set::MmapRuleSet::open_with_mode(
                        &target_path,
                        mode,
                    )?);
                    logging::info(format_args!(
                        "compiled and mmapped inline rule-set {}",
                        tags.join(",")
                    ));
                    registry.insert_built(
                        std::sync::Arc::new(rule_set::RuleSet::new_with_mmap(tags, mmap_set)),
                        origin.clone(),
                    );
                } else {
                    let set = rule_set::RuleSet::new(tags, rules)
                        .map_err(|err| anyhow::anyhow!("{at}: {err}"))?;
                    logging::info(format_args!("loaded rule-set {}", set.tags().join(",")));
                    registry.insert_built(std::sync::Arc::new(set), origin.clone());
                }
            }
            "local" => {
                let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
                let resolved_path = resolve_rule_set_path(path, &tags);
                let data = std::fs::read(&resolved_path)
                    .map_err(|err| anyhow::anyhow!("{at}: read {path}: {err}"))?;
                if data.starts_with(b"TSRS") {
                    let mmap_set = std::sync::Arc::new(mmap_set::MmapRuleSet::open_with_mode(
                        &resolved_path,
                        mode,
                    )?);
                    logging::info(format_args!(
                        "loaded rule-set {} via mmap from {}",
                        tags.join(","),
                        resolved_path
                    ));
                    registry.insert_built(
                        std::sync::Arc::new(rule_set::RuleSet::new_with_mmap(tags, mmap_set)),
                        origin.clone(),
                    );
                } else {
                    let rules = parse_rule_set_payload(&data, entry, &at)?;
                    // the file is not needed once decoded
                    drop(data);
                    if use_mmap && mmap_keeps(&rules, &tags) {
                        let mut compiler = mmap_set::RuleSetCompiler::new();
                        let tsrs_bytes = compiler.compile(&rules)?;
                        let cache_file = entry.get("cache_file").and_then(Value::as_str);
                        let target_path = if let Some(cf) = cache_file {
                            std::path::PathBuf::from(cf)
                        } else {
                            rule_set_remote::default_tsrs_cache_path(&tags[0])
                        };
                        if let Some(parent) = target_path.parent() {
                            let _ = std::fs::create_dir_all(parent);
                        }
                        rule_set_remote::write_tsrs_if_changed(&target_path, &tsrs_bytes)?;
                        let mmap_set = std::sync::Arc::new(mmap_set::MmapRuleSet::open_with_mode(
                            &target_path,
                            mode,
                        )?);
                        logging::info(format_args!(
                            "compiled and mmapped rule-set {} ({} rules)",
                            tags.join(","),
                            rules.len()
                        ));
                        registry.insert_built(
                            std::sync::Arc::new(rule_set::RuleSet::new_with_mmap(tags, mmap_set)),
                            origin.clone(),
                        );
                    } else {
                        let set = rule_set::RuleSet::new(tags, rules)
                            .map_err(|err| anyhow::anyhow!("{at}: {err}"))?;
                        logging::info(format_args!("loaded rule-set {}", set.tags().join(",")));
                        registry.insert_built(std::sync::Arc::new(set), origin.clone());
                    }
                }
            }
            "remote" => {
                let url = entry
                    .get("url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .replace("{tag}", &tags[0]);
                if url.is_empty() {
                    anyhow::bail!("{at}: missing url");
                }
                let client_spec = entry.get("http_client").filter(|v| !v.is_null());
                let detour = entry
                    .get("download_detour")
                    .and_then(Value::as_str)
                    .filter(|tag| !tag.is_empty());
                let client = if client_spec.is_some() {
                    if detour.is_some() {
                        anyhow::bail!(
                            "{at}: http_client is conflict with deprecated download_detour field"
                        );
                    }
                    let spec = clients.resolve(client_spec, &at)?;
                    crate::http_client::HttpClient::from_config(spec.as_ref(), &at)?
                } else if let Some(detour) = detour {
                    logging::warn(format_args!(
                        "{at}: download_detour is deprecated, use http_client"
                    ));
                    let mut wrapper = serde_json::Map::new();
                    wrapper.insert("detour".into(), Value::String(detour.into()));
                    crate::http_client::HttpClient::from_config(Some(&Value::Object(wrapper)), &at)?
                } else {
                    let spec = clients.default_client(route)?;
                    crate::http_client::HttpClient::from_config(spec.as_ref(), &at)?
                };
                let update_interval = crate::outbound::urltest::parse_duration(
                    entry.get("update_interval"),
                    std::time::Duration::ZERO,
                    &at,
                )?;
                let cache_interval = crate::outbound::urltest::parse_duration(
                    entry.get("cache_interval"),
                    std::time::Duration::ZERO,
                    &at,
                )?;
                let delta_update = entry
                    .get("delta_update")
                    .and_then(Value::as_bool)
                    .unwrap_or(true);
                let cache_file = entry
                    .get("cache_file")
                    .and_then(Value::as_str)
                    .map(str::to_string);
                let initial_path = entry
                    .get("initial_path")
                    .and_then(Value::as_str)
                    .filter(|path| !path.is_empty())
                    .and_then(|path| std::path::absolute(resolve_rule_set_path(path, &tags)).ok())
                    .map(|path| path.to_string_lossy().replace('\\', "/"));
                // an empty set has nothing to compile
                let set = std::sync::Arc::new(rule_set::RuleSet::new(tags.clone(), Vec::new())?);
                remotes.push(rule_set_remote::RemoteRuleSet {
                    tags: tags.clone(),
                    spec: rule_set_remote::RemoteSpec {
                        url,
                        initial_path,
                        update_interval,
                        client,
                        format: entry
                            .get("format")
                            .and_then(Value::as_str)
                            .map(str::to_string),
                        mmap: use_mmap,
                        delta_update,
                        cache_interval,
                        cache_file,
                        mode,
                    },
                    set: set.clone(),
                    etag: None,
                    last_updated: None,
                });
                registry.insert(set);
            }
            other => anyhow::bail!("{at}: unknown rule-set type: {other}"),
        }
    }
    registry.attach_remotes(remotes);
    Ok(registry)
}

/// `option.RuleSet.tag`: a listable of non-empty strings.
fn rule_set_tags(entry: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Vec<String>> {
    let mut tags = Vec::new();
    match entry.get("tag") {
        Some(Value::String(text)) => tags.push(text.clone()),
        Some(Value::Array(items)) => {
            for item in items {
                if let Some(text) = item.as_str() {
                    tags.push(text.to_string());
                }
            }
        }
        _ => {}
    }
    if tags.is_empty() || tags.iter().any(|tag| tag.is_empty()) {
        anyhow::bail!("{at}: missing tag");
    }
    Ok(tags)
}

/// A multi-tag set interpolates `{tag}` per tag; the first tag loads by default.
fn resolve_rule_set_path(path: &str, tags: &[String]) -> String {
    if !path.contains("{tag}") {
        return path.to_string();
    }
    path.replace("{tag}", &tags[0])
}

/// The payload of a local rule set: the binary container or the source JSON.
fn parse_rule_set_payload(
    data: &[u8],
    entry: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<Vec<Value>> {
    let format = entry.get("format").and_then(Value::as_str).unwrap_or("");
    if format == "tsrs" || data.starts_with(b"TSRS") {
        return Ok(Vec::new());
    }
    let binary = format == "binary"
        || (format.is_empty() && data.starts_with(b"SRS"))
        || (format.is_empty()
            && entry
                .get("path")
                .and_then(Value::as_str)
                .is_some_and(|path| path.ends_with(".srs")));
    if binary {
        return core_config::srs::read(data).map_err(|err| anyhow::anyhow!("{at}: {err}"));
    }
    let text = std::str::from_utf8(data).map_err(|_| anyhow::anyhow!("{at}: not utf-8"))?;
    let value: Value =
        serde_json::from_str(text).map_err(|err| anyhow::anyhow!("{at}: parse source: {err}"))?;
    Ok(rule_set::source_rules(value))
}

const ROUTE_UNIMPL_FIELDS: &[&str] = &[
    "geoip",
    "geosite",
    "override_android_vpn",
    "default_network_strategy",
    "default_network_type",
    "default_fallback_network_type",
    "default_fallback_delay",
];

/// Parsed `route` section dialing defaults (reference `NetworkOptions`).
#[derive(Debug, Clone, Default)]
pub struct RouteDefaults {
    pub auto_detect_interface: bool,
    pub default_interface: Option<String>,
    pub default_mark: Option<u32>,
    /// `route.default_domain_resolver` server tag (string form or `.server`).
    pub default_domain_resolver: Option<String>,
    /// `route.find_neighbor`: learn the client's MAC and DHCP hostname.
    pub find_neighbor: bool,
}

impl RouteDefaults {
    fn parse(route: Option<&Value>) -> anyhow::Result<Self> {
        let Some(map) = route.and_then(Value::as_object) else {
            return Ok(Self::default());
        };
        let mut out = Self {
            auto_detect_interface: map
                .get("auto_detect_interface")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            default_interface: map
                .get("default_interface")
                .and_then(Value::as_str)
                .map(str::to_string),
            default_mark: map
                .get("default_mark")
                .and_then(Value::as_u64)
                .map(|v| v as u32),
            default_domain_resolver: None,
            find_neighbor: map
                .get("find_neighbor")
                .and_then(Value::as_bool)
                .unwrap_or(false),
        };
        match map.get("default_domain_resolver") {
            None | Some(Value::Null) => {}
            Some(Value::String(tag)) => out.default_domain_resolver = Some(tag.clone()),
            Some(obj @ Value::Object(_)) => {
                out.default_domain_resolver = obj
                    .get("server")
                    .and_then(Value::as_str)
                    .map(str::to_string);
            }
            Some(_) => anyhow::bail!(
                "route.default_domain_resolver: json: cannot unmarshal into option._DomainResolveOptions"
            ),
        }
        Ok(out)
    }

    /// Interface to bind outbound dials to: explicit `default_interface`
    /// wins, otherwise the auto-detected default route NIC when
    /// `auto_detect_interface` is set (reference `DefaultDialer`).
    pub fn bind_interface(&self) -> Option<String> {
        if let Some(name) = &self.default_interface {
            return Some(name.clone());
        }
        if self.auto_detect_interface {
            return detect_default_interface();
        }
        None
    }
}

/// Detect the default-route NIC (Linux `/proc/net/route`); other platforms
/// have no portable equivalent and return `None`.
fn detect_default_interface() -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        let table = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in table.lines().skip(1) {
            let mut cols = line.split_whitespace();
            let iface = cols.next()?;
            let dest = cols.next()?;
            // Destination 00000000 = default route.
            if dest == "00000000" {
                return Some(iface.to_string());
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

pub struct RouterInner {
    pub(crate) probe_tls: tokio_rustls::TlsConnector,
    pub(crate) outbounds: Vec<Outbound>,
    pub(crate) tags: HashMap<String, usize>,
    pub(crate) default: usize,
    pub(crate) rules: Vec<Rule>,
    pub(crate) defaults: RouteDefaults,
    pub(crate) rule_sets: Option<Arc<rule_set::RuleSetRegistry>>,
    /// `route.find_process`, or any rule that names a process: the `/proc`
    /// walk per connection is only worth it when something will read it.
    pub(crate) find_process: bool,
    pub(crate) probe_tasks: std::sync::Mutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Clash `DelayHistory` slots, one per outbound: reference keeps a
    /// single record per proxy, replaced by every successful probe.
    pub(crate) delay_history: Vec<std::sync::Mutex<Option<(String, u32)>>>,
    setup_timeouts: Vec<std::time::Duration>,
    /// Lease files for the neighbour resolver, when anything reads it.
    neighbor_lease_files: Option<Vec<String>>,
    // Exact endpoint identity, kept private: these values contain keys.
    wireguard_configs: HashMap<String, (Value, Arc<WireGuard>)>,
}

pub struct Router {
    connection_scope: Arc<()>,
    inner: std::sync::RwLock<Arc<RouterInner>>,
    applied_config: std::sync::Mutex<Value>,
    selection_cache: std::sync::RwLock<Option<crate::cache_file::SharedCacheFile>>,
}

/// A `local` DNS server with `neighbor_domain` answers from the same tables.
fn neighbor_domain_configured(root: &Value) -> bool {
    root.get("dns")
        .and_then(|dns| dns.get("servers"))
        .and_then(Value::as_array)
        .is_some_and(|servers| {
            servers.iter().any(|server| {
                server.get("type").and_then(Value::as_str) == Some("local")
                    && server
                        .get("neighbor_domain")
                        .is_some_and(|value| !value.is_null())
            })
        })
}

impl RouterInner {
    /// The registry both routers share, remote sets included.
    pub fn rule_sets(&self) -> &rule_set::RuleSetRegistry {
        self.rule_sets
            .as_ref()
            .expect("route registry built in Router::new")
    }

    /// Route dialing defaults (`route.auto_detect_interface`, …).
    pub fn defaults(&self) -> &RouteDefaults {
        &self.defaults
    }

    /// Abort the urltest probe loops (called on instance shutdown).
    pub fn take_probe_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        std::mem::take(&mut *self.probe_tasks.lock().expect("probe tasks"))
    }

    pub(crate) fn track_background_task(&self, task: tokio::task::JoinHandle<()>) {
        self.probe_tasks
            .lock()
            .expect("background tasks")
            .push(task);
    }

    /// Clash `DelayHistory`: record a successful probe against `index`.
    pub fn record_delay(&self, index: usize, delay: u32) {
        let index = self.delay_provenance_index(index);
        let Some(slot) = self.delay_history.get(index) else {
            return;
        };
        #[cfg(feature = "clash-api")]
        let ts = crate::clash_api::history_timestamp();
        #[cfg(not(feature = "clash-api"))]
        let ts = String::new();
        *slot.lock().expect("delay history") = Some((ts, delay));
    }

    /// A failed probe invalidates the previous successful measurement.
    pub fn clear_delay(&self, index: usize) {
        let index = self.delay_provenance_index(index);
        if let Some(slot) = self.delay_history.get(index) {
            *slot.lock().expect("delay history") = None;
        }
    }

    /// The stored record behind `index`, groups resolving to their member.
    pub fn delay_history(&self, index: usize) -> Option<(String, u32)> {
        self.delay_history
            .get(self.delay_provenance_index(index))?
            .lock()
            .expect("delay history")
            .clone()
    }

    /// Walk `now` down through selector/urltest chains to the member that
    /// holds the record.
    fn delay_provenance_index(&self, index: usize) -> usize {
        let mut index = index;
        for _ in 0..self.outbounds.len() {
            let now_tag = match self.outbounds.get(index) {
                Some(Outbound::Selector(selector)) => selector.now(),
                Some(Outbound::Urltest(urltest)) => urltest.now(),
                _ => break,
            };
            match self.tags.get(now_tag) {
                Some(&next) if next != index => index = next,
                _ => break,
            }
        }
        index
    }

    pub(crate) fn build(root: &Value) -> anyhow::Result<Self> {
        Self::build_reusing(root, None)
    }

    /// Build without touching process-wide state; `publish` installs that
    /// once this inner is the one that serves traffic.
    pub(crate) fn build_reusing(
        root: &Value,
        previous: Option<&RouterInner>,
    ) -> anyhow::Result<Self> {
        let defaults = RouteDefaults::parse(root.get("route"))?;
        let bind_iface = defaults.bind_interface();
        let empty = Vec::new();
        let outbounds_list = root
            .get("outbounds")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        let mut outbounds = Vec::with_capacity(outbounds_list.len());
        let mut tags = HashMap::new();
        let mut wireguard_configs = HashMap::new();
        for (i, obj) in outbounds_list.iter().enumerate() {
            let tag = obj
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !tag.is_empty() {
                if tags.contains_key(&tag) {
                    anyhow::bail!("duplicate outbound tag: {tag}");
                }
                tags.insert(tag, i);
            }
            let mut outbound = Outbound::build(obj, &format!("outbounds[{i}]"))?;
            outbound.apply_dial_defaults(defaults.default_mark, bind_iface.as_deref());
            outbounds.push(outbound);
        }
        let endpoints_list = root
            .get("endpoints")
            .and_then(Value::as_array)
            .unwrap_or(&empty);
        for (i, obj) in endpoints_list.iter().enumerate() {
            let at = format!("endpoints[{i}]");
            let ty = obj.get("type").and_then(Value::as_str).unwrap_or_default();
            let map = obj
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("{at}: must be an object"))?;
            let outbound = match ty {
                "wireguard" => {
                    let tag = map.get("tag").and_then(Value::as_str).unwrap_or_default();
                    let identity = if tag.is_empty() {
                        at.clone()
                    } else {
                        format!("tag:{tag}")
                    };
                    let reused = previous.and_then(|old| {
                        old.wireguard_configs
                            .get(&identity)
                            .filter(|(config, _)| config == obj)
                            .map(|(_, wg)| Arc::clone(wg))
                    });
                    let wg = match reused {
                        Some(wg) => wg,
                        None => Arc::new(WireGuard::build(map, &at)?),
                    };
                    wireguard_configs.insert(identity, (obj.clone(), Arc::clone(&wg)));
                    Outbound::WireGuard(wg)
                }
                "openconnect" => anyhow::bail!(
                    "{at}: openconnect client is not implemented yet (config check parity only)"
                ),
                "tailscale" => Outbound::Tailscale(Tailscale::build(map, &at)?),
                _ => anyhow::bail!("{at}: unknown endpoint type: {ty}"),
            };
            let tag = map
                .get("tag")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_string();
            if !tag.is_empty() {
                if tags.contains_key(&tag) {
                    anyhow::bail!("duplicate outbound tag: {tag}");
                }
                tags.insert(tag, outbounds.len());
            }
            outbounds.push(outbound);
        }
        for outbound in &mut outbounds {
            match outbound {
                Outbound::Selector(selector) => selector.resolve(&tags)?,
                Outbound::Urltest(urltest) => urltest.resolve(&tags)?,
                Outbound::Chain(chain) => chain.resolve(&tags)?,
                _ => {}
            }
        }

        let mut rules = Vec::new();
        let mut registry = rule_set::RuleSetRegistry::new();
        if let Some(route) = root.get("route")
            && let Some(map) = route.as_object()
        {
            for key in ROUTE_UNIMPL_FIELDS {
                if map.get(*key).is_some_and(|v| !v.is_null()) {
                    logging::warn(format_args!("route.{key} is not implemented yet (ignored)"));
                }
            }
            registry = build_rule_sets_reusing(
                map,
                &crate::http_client::Registry::from_config(root)?,
                previous.and_then(|old| old.rule_sets.as_deref()),
            )?;
            if let Some(list) = map.get("rules").and_then(Value::as_array) {
                for (i, obj) in list.iter().enumerate() {
                    rules.push(Rule::build_with_rule_sets(
                        obj,
                        &format!("route.rules[{i}]"),
                        true,
                        &registry,
                    )?);
                }
            }
        }

        let default = match root
            .get("route")
            .and_then(|r| r.get("final"))
            .and_then(Value::as_str)
        {
            Some(final_tag) => {
                let idx = *tags.get(final_tag).ok_or_else(|| {
                    anyhow::anyhow!("route.final: unknown outbound {final_tag:?}")
                })?;
                logging::info(format_args!("routing final: {final_tag}"));
                idx
            }
            None => 0,
        };

        let lease_files: Vec<String> = root
            .get("route")
            .and_then(|route| route.get("dhcp_lease_files"))
            .map(|value| match value {
                Value::String(path) => vec![path.clone()],
                Value::Array(list) => list
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect(),
                _ => Vec::new(),
            })
            .unwrap_or_default();
        let find_process = root
            .get("route")
            .and_then(|route| route.get("find_process"))
            .and_then(Value::as_bool)
            == Some(true)
            || rules.iter().any(Rule::needs_process);
        let neighbor_lease_files = (defaults.find_neighbor
            || rules.iter().any(Rule::needs_neighbor)
            || neighbor_domain_configured(root))
        .then_some(lease_files);
        let delay_history = (0..outbounds.len())
            .map(|_| std::sync::Mutex::new(None))
            .collect();
        let mut setup_timeouts = outbound_setup_budgets(root)?;
        setup_timeouts.resize(outbounds.len(), OUTBOUND_SETUP_TIMEOUT);
        Ok(RouterInner {
            probe_tls: crate::tls_client::probe_connector(root)?,
            outbounds,
            tags,
            default,
            rules,
            defaults,
            rule_sets: Some(Arc::new(registry)),
            find_process,
            probe_tasks: std::sync::Mutex::new(Vec::new()),
            delay_history,
            setup_timeouts,
            neighbor_lease_files,
            wireguard_configs,
        })
    }

    /// Install the process-wide settings this inner was built with.
    fn publish(&self) {
        crate::dns::set_default_domain_resolver(self.defaults.default_domain_resolver.clone());
        if let Some(lease_files) = &self.neighbor_lease_files {
            neighbor::ensure(lease_files);
        }
    }

    /// Start listening endpoints (e.g. WireGuard server listeners).
    pub async fn start_endpoints(&self) -> io::Result<()> {
        for outbound in &self.outbounds {
            if let Outbound::WireGuard(wg) = outbound {
                wg.start_listen().await?;
            }
        }
        Ok(())
    }

    /// Index of the outbound `route.final` points at (the direct default).
    pub fn default_index(&self) -> usize {
        self.default
    }

    pub fn index_of(&self, tag: &str) -> Option<usize> {
        self.tags.get(tag).copied()
    }

    /// (index, tag, outbound) for every built outbound — clash API views.
    pub fn outbound_table(&self) -> impl Iterator<Item = (usize, &str, &Outbound)> {
        self.outbounds.iter().enumerate().map(|(i, outbound)| {
            let tag = self
                .tags
                .iter()
                .find(|(_, idx)| **idx == i)
                .map(|(t, _)| t.as_str())
                .unwrap_or("");
            (i, tag, outbound)
        })
    }

    /// Clash view: per rule, the Clash condition items and the
    /// outbound they select.
    pub fn clash_rules(&self) -> Vec<(String, String, String)> {
        self.rules.iter().map(|rule| rule.clash_view()).collect()
    }

    pub fn default_tag(&self) -> &str {
        self.outbound_table()
            .find(|(i, ..)| *i == self.default)
            .map(|(_, tag, _)| tag)
            .unwrap_or("")
    }

    /// Switch a `selector` group to one of its members (clash `PUT /proxies`).
    pub fn select_member(&self, group_tag: &str, member: &str) -> Result<bool, SelectError> {
        let index = self.index_of(group_tag).ok_or(SelectError::NotFound)?;
        let Some(outbound) = self.outbounds.get(index) else {
            return Err(SelectError::NotFound);
        };
        match outbound {
            Outbound::Selector(selector) => {
                if selector.select(member) {
                    Ok(true)
                } else {
                    Err(SelectError::NotMember)
                }
            }
            _ => Err(SelectError::NotSelector),
        }
    }

    pub async fn route_walk<S>(
        &self,
        client: Option<&mut S>,
        ctx: &mut ConnContext,
    ) -> io::Result<Decision>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.route_walk_packet(client, ctx, None).await
    }

    async fn route_walk_packet<S>(
        &self,
        mut client: Option<&mut S>,
        ctx: &mut ConnContext,
        packet: Option<&[&[u8]]>,
    ) -> io::Result<Decision>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        prepare(ctx, self.find_process)?;
        for (i, rule) in self.rules.iter().enumerate() {
            if !rule.matches(ctx) {
                continue;
            }
            let action = rule.action();
            ctx.matched_rule = Some(rule.clash_match(ctx));
            logging::debug(format_args!(
                "route: match[{i}] {} => {}",
                ctx.destination,
                action.type_name()
            ));

            if let Some(opts) = action.route_options() {
                apply_route_options(ctx, opts);
            }

            match action {
                Action::Sniff { sniffer, timeout } => {
                    if let Some(c) = client.as_deref_mut() {
                        sniff::action_sniff(c, ctx, sniffer, *timeout).await;
                    } else if let Some(packet) = packet {
                        sniff::action_sniff_packet(packet, ctx, sniffer, *timeout);
                    }
                }
                Action::Resolve(res) => {
                    if let Err(err) = action_resolve(ctx, res).await {
                        logging::debug(format_args!(
                            "route: resolve failed for {}: {err}",
                            ctx.destination
                        ));
                    }
                }
                _ => {}
            }

            match action {
                Action::Route { outbound, .. } => {
                    return Ok(Decision::Outbound(self.outbound_index(outbound)?));
                }
                Action::Bypass { outbound, .. } if !outbound.is_empty() => {
                    return Ok(Decision::Outbound(self.outbound_index(outbound)?));
                }
                Action::Reject {
                    method,
                    no_drop,
                    flood,
                } => {
                    return Err(reject_error(*method, *no_drop, flood));
                }
                Action::HijackDns => return Ok(Decision::HijackDns),
                _ => {}
            }
        }
        ctx.matched_rule = Some(("final".into(), self.default_tag().into()));
        Ok(Decision::Outbound(self.default))
    }

    fn outbound_index(&self, tag: &str) -> io::Result<usize> {
        self.index_of(tag)
            .ok_or_else(|| io::Error::other(format!("outbound not found: {tag}")))
    }
}

impl Router {
    /// A router for a hot reload: built beside the running `previous` and
    /// sharing its unchanged inline and local rule sets.
    pub(crate) fn prepare(root: &Value, previous: &Router) -> anyhow::Result<Arc<Self>> {
        let previous = previous.inner();
        let inner = RouterInner::build_reusing(root, Some(&previous))?;
        Ok(Arc::new(Self {
            inner: std::sync::RwLock::new(Arc::new(inner)),
            connection_scope: Arc::new(()),
            applied_config: std::sync::Mutex::new(serde_json::json!({"generation": 0})),
            selection_cache: std::sync::RwLock::new(None),
        }))
    }

    pub fn new(root: &Value) -> anyhow::Result<Arc<Router>> {
        let inner = RouterInner::build(root)?;
        inner.publish();
        let router = Arc::new(Router {
            inner: std::sync::RwLock::new(Arc::new(inner)),
            connection_scope: Arc::new(()),
            applied_config: std::sync::Mutex::new(serde_json::json!({"generation": 0})),
            selection_cache: std::sync::RwLock::new(None),
        });
        let inner_ref = router.inner();
        for outbound in &inner_ref.outbounds {
            if let Outbound::Urltest(urltest) = outbound {
                let handle = urltest.spawn(Arc::clone(&router));
                inner_ref
                    .probe_tasks
                    .lock()
                    .expect("probe tasks")
                    .push(handle);
            }
        }
        Ok(router)
    }

    pub fn inner(&self) -> Arc<RouterInner> {
        self.inner.read().expect("router inner lock").clone()
    }

    /// Restore only selections that still belong to the same named group.
    /// Keep the handle on the Router so in-place reloads retain persistence.
    pub fn attach_selection_cache(&self, cache: Option<crate::cache_file::SharedCacheFile>) {
        if let Some(store) = &cache {
            let store = store.lock().expect("selection cache");
            let inner = self.inner();
            for (tag, index) in &inner.tags {
                if let Outbound::Selector(group) = &inner.outbounds[*index]
                    && let Some(selected) =
                        store.get(crate::cache_file::BUCKET_SELECTED, tag.as_bytes())
                    && let Ok(selected) = std::str::from_utf8(&selected)
                {
                    group.select(selected);
                }
            }
        }
        *self
            .selection_cache
            .write()
            .expect("selection cache handle") = cache;
        self.prune_selection_cache();
    }

    fn prune_selection_cache(&self) {
        let cache = self.selection_cache.read().expect("selection cache handle");
        let Some(store) = cache.as_ref() else {
            return;
        };
        let mut store = store.lock().expect("selection cache");
        let inner = self.inner();
        // At most one record per active selector. No history of removed groups
        // or members survives startup or a successfully applied hot reload.
        store.retain_selected(|tag, member| {
            let (Ok(tag), Ok(member)) = (std::str::from_utf8(tag), std::str::from_utf8(member)) else {
                return false;
            };
            inner.tags.get(tag).is_some_and(|index| {
                matches!(&inner.outbounds[*index], Outbound::Selector(group) if group.all().iter().any(|item| item == member))
            })
        });
        if let Err(error) = store.flush() {
            crate::logging::warn(format_args!("prune selector selections: {error}"));
        }
    }

    fn persist_selection(&self, tag: &str) {
        let cache = self.selection_cache.read().expect("selection cache handle");
        if let Some(store) = cache.as_ref() {
            let mut store = store.lock().expect("selection cache");
            let inner = self.inner();
            let Some(Outbound::Selector(group)) =
                inner.tags.get(tag).map(|index| &inner.outbounds[*index])
            else {
                return;
            };
            // Concurrent API requests may have switched again before this
            // writer acquired the store. Persist the current member under
            // that lock rather than overwriting a newer choice with our input.
            let member = group.now();
            if store
                .get(crate::cache_file::BUCKET_SELECTED, tag.as_bytes())
                .as_deref()
                == Some(member.as_bytes())
            {
                return;
            }
            store.put(
                crate::cache_file::BUCKET_SELECTED,
                tag.as_bytes(),
                member.as_bytes().to_vec(),
            );
            if let Err(error) = store.flush() {
                crate::logging::warn(format_args!("save selector selection: {error}"));
            }
        }
    }

    pub fn rule_sets(&self) -> Arc<rule_set::RuleSetRegistry> {
        self.inner()
            .rule_sets
            .as_ref()
            .expect("route registry built in Router::new")
            .clone()
    }

    /// Published only after startup or a complete in-place apply succeeds.
    pub fn applied_config(&self) -> Value {
        self.applied_config.lock().expect("applied config").clone()
    }

    pub(crate) fn connection_scope(&self) -> Arc<()> {
        Arc::clone(&self.connection_scope)
    }

    pub(crate) fn record_applied_config(&self, root: &Value) {
        let hash = crate::configuration_fingerprint(root);
        let mut state = self.applied_config.lock().expect("applied config");
        let generation = state["generation"].as_u64().unwrap_or(0) + 1;
        let attempt = state["reload_attempt"].as_u64().unwrap_or(0) + 1;
        *state = serde_json::json!({
            "pid": std::process::id(), "generation": generation,
            "config_sha256": hash, "ready": true,
            "hot_reload": true, "connection_revalidation": true, "schema": 1,
            "reload_attempt": attempt
        });
    }

    /// A reload that left the running configuration in place. The generation
    /// and hash stay; `rejected_sha256` names the refused configuration when
    /// it was valid JSON, so a waiting manager can stop waiting for it.
    pub(crate) fn record_rejected_reload(&self, rejected: Option<&Value>) {
        let mut state = self.applied_config.lock().expect("applied config");
        let attempt = state["reload_attempt"].as_u64().unwrap_or(0) + 1;
        state["reload_attempt"] = attempt.into();
        state["rejected_sha256"] = rejected
            .map(crate::configuration_fingerprint)
            .map_or(Value::Null, Value::String);
    }

    pub fn defaults(&self) -> RouteDefaults {
        self.inner().defaults.clone()
    }

    pub fn take_probe_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        self.inner().take_probe_tasks()
    }

    pub(crate) fn track_background_task(&self, task: tokio::task::JoinHandle<()>) {
        self.inner().track_background_task(task);
    }

    pub fn record_delay(&self, index: usize, delay: u32) {
        self.inner().record_delay(index, delay);
    }

    pub fn clear_delay(&self, index: usize) {
        self.inner().clear_delay(index);
    }

    pub fn delay_history(&self, index: usize) -> Option<(String, u32)> {
        self.inner().delay_history(index)
    }

    pub fn default_index(&self) -> usize {
        self.inner().default_index()
    }

    pub fn index_of(&self, tag: &str) -> Option<usize> {
        self.inner().index_of(tag)
    }

    pub fn default_tag(&self) -> String {
        self.inner().default_tag().to_string()
    }

    pub fn clash_rules(&self) -> Vec<(String, String, String)> {
        self.inner().clash_rules()
    }

    pub fn select_member(&self, group_tag: &str, member: &str) -> Result<bool, SelectError> {
        let inner = self.inner();
        let index = inner.index_of(group_tag).ok_or(SelectError::NotFound)?;
        let Outbound::Selector(group) = &inner.outbounds[index] else {
            return Err(SelectError::NotSelector);
        };
        if !group.all().iter().any(|tag| tag == member) {
            return Err(SelectError::NotMember);
        }
        crate::clash_state::switch_group(
            self,
            group_tag,
            group.interrupt_exist_connections(),
            || {
                let changed = group.now() != member;
                group.select(member);
                self.persist_selection(group_tag);
                changed
            },
        );
        Ok(true)
    }

    pub fn start_endpoints<'a>(
        &'a self,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + Send + 'a>> {
        let inner = self.inner();
        Box::pin(async move { inner.start_endpoints().await })
    }

    pub fn connect<'a>(
        &'a self,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        self.connect_index(self.default_index(), target)
    }

    pub fn connect_index<'a>(
        &'a self,
        index: usize,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<Conn>> + Send + 'a>> {
        let inner = self.inner();
        Box::pin(async move {
            let Some(outbound) = inner.outbounds.get(index) else {
                return Err(io::Error::other("outbound index out of range"));
            };
            tokio::time::timeout(inner.setup_timeouts[index], outbound.connect(self, target))
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "outbound setup timeout"))?
        })
    }

    pub fn connect_udp_index<'a>(
        &'a self,
        index: usize,
        target: &'a Target,
    ) -> Pin<Box<dyn Future<Output = io::Result<tokio::net::UdpSocket>> + Send + 'a>> {
        let inner = self.inner();
        Box::pin(async move {
            let Some(outbound) = inner.outbounds.get(index) else {
                return Err(io::Error::other("outbound index out of range"));
            };
            tokio::time::timeout(
                inner.setup_timeouts[index],
                outbound.connect_udp(self, target),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "outbound setup timeout"))?
        })
    }

    pub async fn route<S>(&self, client: &mut S, ctx: &mut ConnContext) -> io::Result<Decision>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        self.inner().route_walk(Some(client), ctx).await
    }

    pub async fn route_raw(&self, ctx: &mut ConnContext) -> io::Result<Decision> {
        self.inner()
            .route_walk::<tokio::net::TcpStream>(None, ctx)
            .await
    }

    /// Route a datagram without consuming or modifying its payload.
    pub async fn route_packet(&self, ctx: &mut ConnContext, packet: &[u8]) -> io::Result<Decision> {
        self.route_datagrams(ctx, &[packet]).await
    }

    pub async fn route_datagrams(
        &self,
        ctx: &mut ConnContext,
        packet: &[&[u8]],
    ) -> io::Result<Decision> {
        self.inner()
            .route_walk_packet::<tokio::net::TcpStream>(None, ctx, Some(packet))
            .await
    }

    pub fn build_inner(root: &Value) -> anyhow::Result<RouterInner> {
        RouterInner::build(root)
    }

    pub async fn apply_inner(self: &Arc<Self>, new_inner: RouterInner) -> anyhow::Result<()> {
        self.apply_prepared_inner(Arc::new(new_inner)).await
    }

    pub(crate) async fn apply_prepared_inner(
        self: &Arc<Self>,
        new_inner: Arc<RouterInner>,
    ) -> anyhow::Result<()> {
        let old_inner = self.inner();

        // 1. Preserve delay history by tag across reloads
        for (tag, &old_idx) in &old_inner.tags {
            if let Some(hist) = old_inner.delay_history(old_idx)
                && let Some(&new_idx) = new_inner.tags.get(tag)
                && let Some(slot) = new_inner.delay_history.get(new_idx)
            {
                *slot.lock().expect("delay history") = Some(hist);
            }
        }

        // 2. Preserve selector and urltest selections and latencies
        for (tag, &old_idx) in &old_inner.tags {
            if let Some(Outbound::Selector(old_sel)) = old_inner.outbounds.get(old_idx)
                && let Some(&new_idx) = new_inner.tags.get(tag)
                && let Some(Outbound::Selector(new_sel)) = new_inner.outbounds.get(new_idx)
            {
                let _ = new_sel.select(old_sel.now());
            } else if let Some(Outbound::Urltest(old_url)) = old_inner.outbounds.get(old_idx)
                && let Some(&new_idx) = new_inner.tags.get(tag)
                && let Some(Outbound::Urltest(new_url)) = new_inner.outbounds.get(new_idx)
            {
                let _ = new_url.select(old_url.now());
                new_url.copy_latencies_from(old_url);
            }
        }

        // 3. Stop old urltest probe tasks
        let old_tasks = old_inner.take_probe_tasks();
        for task in old_tasks {
            task.abort();
        }

        // 4. Atomically install new inner router
        new_inner.publish();
        *self.inner.write().expect("router inner lock") = Arc::clone(&new_inner);
        self.prune_selection_cache();

        // 5. Spawn new urltest probe tasks using self (Arc<Router>)
        for outbound in &new_inner.outbounds {
            if let Outbound::Urltest(urltest) = outbound {
                let handle = urltest.spawn(Arc::clone(self));
                new_inner
                    .probe_tasks
                    .lock()
                    .expect("probe tasks")
                    .push(handle);
            }
        }

        Ok(())
    }

    pub async fn reload(self: &Arc<Self>, root: &Value) -> anyhow::Result<()> {
        let new_inner = RouterInner::build_reusing(root, Some(&self.inner()))?;
        self.apply_inner(new_inner).await
    }
}

/// `PUT /proxies/{name}` failure classes (reference clash API messages).
#[derive(Debug, PartialEq, Eq)]
pub enum SelectError {
    NotFound,
    NotSelector,
    NotMember,
}

/// FakeIP reverse mapping + ip_version before the rule walk.
fn prepare(ctx: &mut ConnContext, want_process: bool) -> io::Result<()> {
    if let Target::Ip(addr) = ctx.destination
        && let Some(dns) = dns::current()
    {
        if let Some(domain) = dns.fakeip_domain(addr.ip()) {
            ctx.fakeip_domain = Some(domain.clone());
            ctx.origin_destination = Some(ctx.destination.clone());
            ctx.destination = Target::Domain(domain, addr.port());
            ctx.fakeip = true;
            logging::debug(format_args!(
                "route: found fakeip domain: {}",
                ctx.destination
            ));
        } else if dns.is_fakeip(addr.ip()) {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "missing fakeip record",
            ));
        } else if ctx.domain.is_none()
            && let Some(domain) = dns.reverse_domain(addr.ip())
        {
            // Reverse DNS affects domain matching, not the dial destination.
            ctx.domain = Some(domain.clone());
            logging::debug(format_args!("route: found reverse mapped domain: {domain}"));
        }
    }
    // `route.find_neighbor`: the client's own identity, for the
    // `source_mac_address` / `source_hostname` rule items
    if let Some(resolver) = neighbor::current() {
        ctx.source_mac = resolver.lookup_mac(ctx.source.ip());
        ctx.source_hostname = resolver.lookup_hostname(ctx.source.ip());
    }
    // `route.find_process`: the process behind the socket, for the
    // `process_name` / `process_path` / `user` rule items
    let destination = match ctx.origin_destination.as_ref().unwrap_or(&ctx.destination) {
        Target::Ip(addr) => Some(*addr),
        Target::Domain(..) => None,
    };
    if want_process && let Some(info) = process::find_owner(ctx.network, ctx.source, destination) {
        // per-connection, so debug: at the default level this costs nothing —
        // and the user suffix is built inside the format, not before it
        match &info.user_name {
            Some(name) => logging::debug(format_args!(
                "found process path: {}, user: {}",
                info.path, name
            )),
            None => logging::debug(format_args!("found process path: {}", info.path)),
        }
        ctx.process = Some(info);
    }
    ctx.ip_version = match ctx.destination {
        Target::Ip(a) => Some(if a.is_ipv6() { 6 } else { 4 }),
        Target::Domain(..) => None,
    };
    Ok(())
}

fn reject_error(method: RejectMethod, no_drop: bool, flood: &rule::RejectFlood) -> io::Error {
    match method {
        RejectMethod::Drop => io::Error::new(io::ErrorKind::ConnectionReset, "dropped by rule"),
        RejectMethod::Reply => {
            io::Error::other("reject method `reply` is not supported for TCP connections")
        }
        RejectMethod::Default => {
            if !no_drop && flood.trigger() {
                logging::debug(format_args!("dropped due to flooding"));
                return io::Error::new(io::ErrorKind::ConnectionReset, "dropped by rule");
            }
            io::Error::new(io::ErrorKind::ConnectionRefused, "rejected by rule")
        }
    }
}

async fn action_resolve(ctx: &mut ConnContext, action: &ResolveAction) -> io::Result<()> {
    let host = match &ctx.destination {
        Target::Domain(host, _) => host.clone(),
        Target::Ip(_) => match &ctx.domain {
            Some(d) => d.clone(),
            None => return Ok(()),
        },
    };
    let Some(dns) = dns::current() else {
        return Err(io::Error::other("resolve action requires dns section"));
    };
    let resolve_fut = async {
        match &action.server {
            Some(tag) => dns.resolve_via_with(tag, &host, action.strategy).await,
            None => dns.resolve_with(&host, action.strategy).await,
        }
    };
    let addrs = if let Some(timeout) = action.timeout {
        tokio::time::timeout(timeout, resolve_fut)
            .await
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("resolve timeout for {host}"),
                )
            })?
    } else {
        resolve_fut.await
    }?;
    logging::debug(format_args!(
        "route: resolved [{}] for {host}",
        addrs
            .iter()
            .map(|a| a.to_string())
            .collect::<Vec<_>>()
            .join(" ")
    ));
    if ctx.ip_version.is_none() && !addrs.is_empty() {
        ctx.ip_version = Some(if addrs[0].is_ipv6() { 6 } else { 4 });
    }
    if let Some(&ip) = addrs.first() {
        if ctx.domain.is_none()
            && let Target::Domain(ref h, _) = ctx.destination
        {
            ctx.domain = Some(h.clone());
        }
        let port = ctx.destination.port();
        ctx.destination = Target::Ip(SocketAddr::new(ip, port));
    }
    ctx.destination_addresses = addrs;
    Ok(())
}

const DNS_HIJACK_TIMEOUT: Duration = Duration::from_secs(10);

/// Serve length-prefixed TCP DNS queries through the dns service
/// (`action: hijack-dns`); `prefix` is sniffed bytes already read.
pub async fn hijack_dns<S>(client: &mut S, ctx: &ConnContext) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let dns =
        dns::current().ok_or_else(|| io::Error::other("hijack-dns: dns service not configured"))?;
    let mut buf = ctx.sniff_prefix.clone();
    let mut chunk = vec![0u8; 4096];
    loop {
        while buf.len() < 2 {
            match tokio::time::timeout(DNS_HIJACK_TIMEOUT, client.read(&mut chunk)).await {
                Ok(Ok(0)) => return Ok(()),
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "hijack-dns: read timeout",
                    ));
                }
            }
        }
        let len = usize::from(u16::from_be_bytes([buf[0], buf[1]]));
        if len < 12 {
            return Err(io::Error::other("hijack-dns: bad query length"));
        }
        while buf.len() < 2 + len {
            match tokio::time::timeout(DNS_HIJACK_TIMEOUT, client.read(&mut chunk)).await {
                Ok(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "hijack-dns: truncated query",
                    ));
                }
                Ok(Ok(n)) => buf.extend_from_slice(&chunk[..n]),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "hijack-dns: read timeout",
                    ));
                }
            }
        }
        let query = buf[2..2 + len].to_vec();
        buf.drain(..2 + len);

        let meta = QueryMeta {
            inbound: ctx.inbound.clone(),
            source: Some(ctx.source.ip()),
            network: Some("tcp".to_string()),
        };
        let resp = dns.exchange(&meta, &query, true).await?;
        let mut framed = Vec::with_capacity(2 + resp.len());
        framed.extend_from_slice(&(resp.len() as u16).to_be_bytes());
        framed.extend_from_slice(&resp);
        client.write_all(&framed).await?;
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn setup_budgets_preserve_long_dials_in_groups_and_detours() {
        use std::time::Duration;
        let budgets = super::outbound_setup_budgets(&serde_json::json!({"outbounds":[
            {"type":"direct","tag":"plain"},
            {"type":"vless","tag":"slow","connect_timeout":"30s"},
            {"type":"selector","tag":"group","outbounds":["plain","slow"]},
            {"type":"urltest","tag":"auto","outbounds":["group"]},
            {"type":"vless","tag":"via","connect_timeout":"2s","detour":"slow"},
            {"type":"chain","tag":"chain","outbounds":["plain","slow"]}
        ]}))
        .unwrap();
        assert_eq!(budgets, [15, 45, 45, 45, 62, 60].map(Duration::from_secs));
    }

    use super::*;
    use serde_json::json;

    #[test]
    fn route_defaults_parse_string_and_object_resolver() {
        let d = RouteDefaults::parse(Some(&json!({
            "auto_detect_interface": true,
            "default_interface": "eth9",
            "default_mark": 42,
            "default_domain_resolver": "u"
        })))
        .unwrap();
        assert!(d.auto_detect_interface);
        assert_eq!(d.default_interface.as_deref(), Some("eth9"));
        assert_eq!(d.default_mark, Some(42));
        assert_eq!(d.default_domain_resolver.as_deref(), Some("u"));
        assert_eq!(d.bind_interface().as_deref(), Some("eth9"));

        let d = RouteDefaults::parse(Some(&json!({
            "default_domain_resolver": {"server": "u", "strategy": "prefer_ipv4"}
        })))
        .unwrap();
        assert_eq!(d.default_domain_resolver.as_deref(), Some("u"));
        assert_eq!(d.bind_interface(), None);

        let d = RouteDefaults::parse(Some(&json!({"default_domain_resolver": null}))).unwrap();
        assert_eq!(d.default_domain_resolver, None);

        RouteDefaults::parse(Some(&json!({"default_domain_resolver": ["x"]})))
            .expect_err("array form must fail");
        RouteDefaults::parse(Some(&json!({"auto_detect_interface": "yes"}))).ok();
    }

    /// The whole path, not just the lookup: a live socket, `prepare`, and a
    /// rule that names this very process. Linux-only because the searcher is.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_rule_can_route_by_the_process_that_opened_the_socket() {
        // the rule names whatever this test binary is called
        let own = std::fs::read_link("/proc/self/exe").expect("own exe");
        let name = own
            .file_name()
            .expect("file name")
            .to_string_lossy()
            .into_owned();
        let router = Router::new(&json!({
            "outbounds": [{"type": "direct", "tag": "d"}],
            "route": {
                "find_process": true,
                "rules": [{"process_name": name, "outbound": "d"}],
                "final": "d"
            }
        }))
        .expect("router");

        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("connect");
        let (server, _) = listener.accept().expect("accept");

        let mut ctx = ConnContext::new(
            "in",
            client.local_addr().expect("source"),
            Target::Ip(server.local_addr().expect("server")),
            "tcp",
        );
        prepare(&mut ctx, true).expect("ordinary destination");
        let owner = ctx.process.as_ref().expect("prepare found the owner");
        assert_eq!(owner.path, own.to_string_lossy(), "this very test binary");
        assert!(
            router.inner().rules[0].matches(&ctx),
            "and the rule matches it"
        );
        drop((client, server));
    }

    #[test]
    fn router_applies_route_defaults_to_direct() {
        let router = Router::new(&json!({
            "outbounds": [
                {"type": "direct", "tag": "marked"},
                {"type": "direct", "tag": "plain"}
            ],
            "route": {
                "final": "plain",
                "default_interface": "lo",
                "default_mark": 7,
                "default_domain_resolver": "u"
            }
        }))
        .unwrap();
        assert_eq!(router.defaults().default_mark, Some(7));
        assert_eq!(router.defaults().bind_interface().as_deref(), Some("lo"));
        assert_eq!(
            router.defaults().default_domain_resolver.as_deref(),
            Some("u"),
            "route defaults install the ddr tag"
        );

        // Explicit outbound fields win over route defaults. `routing_mark` is
        // Linux-only, and off Linux the reference refuses it, so the mark can
        // only be checked there; the interface option is portable.
        let router = Router::new(&json!({
            "outbounds": [{"type": "direct", "tag": "d", "bind_interface": "eth0"}],
            "route": {"final": "d", "default_interface": "lo", "default_mark": 7}
        }))
        .unwrap();
        match router.inner().outbounds.first() {
            Some(Outbound::Direct(d)) => {
                assert_eq!(d.dial.bind_interface.as_deref(), Some("eth0"));
            }
            _ => panic!("expected direct outbound"),
        }

        #[cfg(target_os = "linux")]
        {
            let router = Router::new(&json!({
                "outbounds": [{"type": "direct", "tag": "d", "routing_mark": 99}],
                "route": {"final": "d", "default_mark": 7}
            }))
            .unwrap();
            match router.inner().outbounds.first() {
                Some(Outbound::Direct(d)) => assert_eq!(d.dial.routing_mark, Some(99)),
                _ => panic!("expected direct outbound"),
            }
        }

        // Proxy sockets inherit defaults too; explicit values still win.
        #[cfg(target_os = "linux")]
        for explicit in [None, Some(99)] {
            let mut outbound = json!({
                "type": "vless", "tag": "v", "server": "127.0.0.1", "server_port": 443,
                "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811"
            });
            if let Some(mark) = explicit {
                outbound["routing_mark"] = json!(mark);
                outbound["bind_interface"] = json!("eth0");
            }
            let router = Router::new(&json!({
                "outbounds": [outbound],
                "route": {"final": "v", "default_mark": 7, "default_interface": "lo"}
            }))
            .unwrap();
            match router.inner().outbounds.first() {
                Some(Outbound::Vless(v)) => {
                    assert_eq!(v.dial.routing_mark, Some(explicit.unwrap_or(7)));
                    assert_eq!(
                        v.dial.bind_interface.as_deref(),
                        Some(if explicit.is_some() { "eth0" } else { "lo" })
                    );
                }
                _ => panic!("expected vless outbound"),
            }
        }

        // No route section defaults to empty ddr tag.
        let router = Router::new(&json!({"outbounds": [{"type": "direct", "tag": "d"}]})).unwrap();
        assert_eq!(router.defaults().default_domain_resolver, None);
    }

    #[test]
    fn clash_delay_history_records_and_groups_derive() {
        let router = Router::new(&json!({
            "outbounds": [
                {"type": "direct", "tag": "d1"},
                {"type": "direct", "tag": "dead"},
                {"type": "selector", "tag": "sel", "outbounds": ["d1", "dead"]}
            ],
            "route": {"final": "d1"}
        }))
        .unwrap();
        let d1 = router.inner().tags["d1"];
        let sel = router.inner().tags["sel"];

        assert!(router.delay_history(d1).is_none(), "no probe, no record");
        router.record_delay(d1, 654);
        let (time, delay) = router.delay_history(d1).expect("recorded");
        assert_eq!(delay, 654);
        assert!(time.contains('T') && time.ends_with('Z'), "RFC3339: {time}");
        let (group_time, group_delay) = router.delay_history(sel).expect("derived");
        assert_eq!(group_delay, 654, "selector follows its current member");
        assert_eq!(group_time, time, "same record, one timestamp");

        router
            .select_member("sel", "dead")
            .expect("selector switches");
        assert!(
            router.delay_history(sel).is_none(),
            "the new member has no record of its own"
        );

        router.record_delay(d1, 700);
        let (_, delay) = router.delay_history(d1).expect("recorded");
        assert_eq!(delay, 700, "one slot, replaced per probe");
        router.select_member("sel", "d1").unwrap();
        router.clear_delay(sel);
        assert!(router.delay_history(d1).is_none());
        assert!(router.delay_history(sel).is_none());
        router.record_delay(d1, 701);
        assert_eq!(router.delay_history(sel).unwrap().1, 701, "recovery");
    }

    #[tokio::test]
    async fn router_hot_reload_migrates_delay_and_selectors() {
        let root1 = json!({
            "outbounds": [
                {"type": "direct", "tag": "d1"},
                {"type": "direct", "tag": "d2"},
                {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2"]}
            ],
            "route": {"final": "d1"}
        });
        let router = Router::new(&root1).unwrap();
        let d2 = router.index_of("d2").unwrap();
        router.record_delay(d2, 123);
        router.select_member("sel", "d2").unwrap();

        // New config with reordered outbounds or added outbound:
        let root2 = json!({
            "outbounds": [
                {"type": "direct", "tag": "d3"},
                {"type": "direct", "tag": "d2"},
                {"type": "direct", "tag": "d1"},
                {"type": "selector", "tag": "sel", "outbounds": ["d1", "d2", "d3"]}
            ],
            "route": {"final": "d2"}
        });
        router.reload(&root2).await.unwrap();

        // Verify delay history migrated for d2:
        let new_d2 = router.index_of("d2").unwrap();
        assert_eq!(router.delay_history(new_d2).unwrap().1, 123);

        // Verify selector choice preserved:
        let sel_idx = router.index_of("sel").unwrap();
        assert_eq!(router.delay_history(sel_idx).unwrap().1, 123);
    }

    #[test]
    fn reject_error_flood_and_no_drop() {
        let flood = rule::RejectFlood::default();
        for _ in 0..50 {
            let e = reject_error(RejectMethod::Default, false, &flood);
            assert_eq!(e.kind(), io::ErrorKind::ConnectionRefused, "pre-flood");
        }
        let e = reject_error(RejectMethod::Default, false, &flood);
        assert_eq!(
            e.kind(),
            io::ErrorKind::ConnectionReset,
            "51st hit escalates to drop"
        );

        let flood = rule::RejectFlood::default();
        for _ in 0..60 {
            let e = reject_error(RejectMethod::Default, true, &flood);
            assert_eq!(
                e.kind(),
                io::ErrorKind::ConnectionRefused,
                "no_drop never floods"
            );
        }

        let flood = rule::RejectFlood::default();
        let e = reject_error(RejectMethod::Drop, false, &flood);
        assert_eq!(e.kind(), io::ErrorKind::ConnectionReset);
        assert!(!flood.trigger(), "drop method must not touch the counter");
    }

    #[tokio::test]
    async fn action_resolve_failure_is_non_fatal_and_continues_routing() {
        let config = json!({
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "direct", "tag": "fallback"}
            ],
            "route": {
                "rules": [
                    {
                        "domain_suffix": ["youtube.com"],
                        "action": "resolve",
                        "server": "non-existent-dns-server"
                    },
                    {
                        "domain_suffix": ["youtube.com"],
                        "action": "route",
                        "outbound": "fallback"
                    }
                ],
                "final": "direct"
            }
        });
        let router = Router::new(&config).unwrap();
        let mut ctx = ConnContext::new(
            "tun",
            "192.168.1.100:12345".parse().unwrap(),
            Target::Domain("www.youtube.com".into(), 443),
            "tcp",
        );
        let decision = router
            .route_raw(&mut ctx)
            .await
            .expect("route should succeed despite resolve failure");
        let Decision::Outbound(idx) = decision else {
            panic!("expected outbound decision");
        };
        assert_eq!(idx, router.index_of("fallback").unwrap());
    }

    async fn test_guard() -> tokio::sync::MutexGuard<'static, ()> {
        static LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
        LOCK.lock().await
    }

    #[tokio::test]
    async fn action_resolve_rewrites_destination_to_ip_and_preserves_domain() {
        let _g = test_guard().await;
        let dns_config = json!({
            "dns": {
                "servers": [
                    {
                        "type": "hosts",
                        "tag": "local-dns",
                        "predefined": {
                            "www.youtube.com": "142.250.186.206"
                        }
                    }
                ],
                "final": "local-dns"
            }
        });
        let dns = crate::dns::DnsService::build(&dns_config).unwrap().unwrap();
        crate::dns::set_service(Some(dns));

        let config = json!({
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "direct", "tag": "yt-out"}
            ],
            "route": {
                "rules": [
                    {
                        "domain_suffix": ["youtube.com"],
                        "action": "resolve",
                        "server": "local-dns"
                    },
                    {
                        "domain_suffix": ["youtube.com"],
                        "action": "route",
                        "outbound": "yt-out"
                    }
                ],
                "final": "direct"
            }
        });
        let router = Router::new(&config).unwrap();
        let mut ctx = ConnContext::new(
            "tun",
            "192.168.1.100:12345".parse().unwrap(),
            Target::Domain("www.youtube.com".into(), 443),
            "tcp",
        );
        let decision = router
            .route_raw(&mut ctx)
            .await
            .expect("route should succeed");
        let Decision::Outbound(idx) = decision else {
            panic!("expected outbound decision");
        };
        assert_eq!(idx, router.index_of("yt-out").unwrap());
        // Verify ctx.domain is preserved for subsequent rules
        assert_eq!(ctx.domain.as_deref(), Some("www.youtube.com"));
        // Verify ctx.destination is rewritten to resolved IP:
        assert_eq!(
            ctx.destination,
            Target::Ip("142.250.186.206:443".parse().unwrap())
        );

        crate::dns::set_service(None);
    }
}
