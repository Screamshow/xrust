//! Remote rule sets: `RemoteRuleSet` in the reference. The set is created
//! empty and filled during start, so the first fetch failures surface the same
//! way the reference reports them (`initial rule-set: <tag>`).

use std::io;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use serde_json::Value;

use super::super::cache_file::{BUCKET_RULE_SET, SharedCacheFile, saved_binary};
use super::super::http_client::HttpClient;
use super::super::logging;
use super::rule_set::RuleSet;
use crate::route::Router;

/// `sha256` over the (tag-expanded) URL, as the reference keys the cache.
fn url_hash(url: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(url.as_bytes());
    hasher.finalize().into()
}

fn sha256_digest(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

/// Bind the image to its expanded download URL without storing subscription URLs.
fn provenance_path(cache: &std::path::Path) -> std::path::PathBuf {
    let mut path = cache.as_os_str().to_owned();
    path.push(".origin");
    path.into()
}

fn cached_digest(cache: &std::path::Path, url: &str) -> Option<[u8; 32]> {
    use std::io::Read;
    let mut file = std::fs::File::open(provenance_path(cache)).ok()?;
    let mut record = [0u8; 64];
    if file.metadata().ok()?.len() != record.len() as u64 {
        return None;
    }
    file.read_exact(&mut record).ok()?;
    (record[..32] == url_hash(url)).then(|| record[32..].try_into().expect("fixed SHA-256"))
}

/// Default path for caching mmap-able .tsrs binary images.
/// On Linux/OpenWrt this points to `/tmp/xrust-rulesets/` (tmpfs in RAM),
/// which prevents wearing down SPI flash storage.
pub fn default_tsrs_cache_path(tag: &str) -> std::path::PathBuf {
    #[cfg(unix)]
    {
        std::path::PathBuf::from(format!("/tmp/xrust-rulesets/{tag}.tsrs"))
    }
    #[cfg(not(unix))]
    {
        std::env::temp_dir().join(format!("xrust-rulesets/{tag}.tsrs"))
    }
}

/// Reference default: 24h when `update_interval` is absent.
const DEFAULT_UPDATE_INTERVAL: Duration = Duration::from_secs(24 * 60 * 60);

/// Retry ladder for a set that was still empty at start: 5, 10, 20 and then
/// every 30 seconds, the schedule podkop-engine's OpenWrt build settled on.
/// Once one fetch lands, the periodic updater takes over.
const RECOVERY_LADDER: [Duration; 4] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(20),
    Duration::from_secs(30),
];

/// Opt-in: keep the engine running with an empty rule-set instead of aborting
/// the start, and fetch it in the background. `XRUST_RULESET_SOFT_START=1`.
///
/// Off by default, because the reference aborts with `initial rule-set:
/// <tag>` and an empty set means the rules pointing at it match nothing. A
/// router booting before its WAN is up is the case this is for: failing to
/// start there costs DNS as well as the proxy.
pub fn soft_start_enabled() -> bool {
    matches!(
        crate::env_var("RULESET_SOFT_START").as_deref(),
        Some("1") | Some("true")
    )
}

#[derive(Debug, Clone)]
pub struct RemoteSpec {
    pub url: String,
    /// `initial_path`: a local copy to start from before the first fetch.
    pub initial_path: Option<String>,
    /// `update_interval` (0 = the 24h default).
    pub update_interval: Duration,
    pub client: HttpClient,
    /// `format`, when the config pinned one.
    pub format: Option<String>,
    /// Zero-copy mmap binary rule-set toggle.
    pub mmap: bool,
    /// Incremental binary delta updates toggle.
    pub delta_update: bool,
    /// Cache update interval (e.g. "1h"). Overrides update_interval when set.
    pub cache_interval: Duration,
    /// Custom path to cache .tsrs binary file (default: /tmp/xrust-rulesets/<tag>.tsrs).
    pub cache_file: Option<String>,
    /// Mmap mode: "auto" | "mmap" | "memory".
    pub mode: crate::route::mmap_set::MmapMode,
}

/// The live state of one remote set: the shared set plus the fetch bookkeeping.
/// The lock is async because a fetch holds it across I/O.
#[derive(Debug)]
pub struct RemoteRuleSet {
    pub tags: Vec<String>,
    pub spec: RemoteSpec,
    pub set: Arc<RuleSet>,
    pub etag: Option<String>,
    pub last_updated: Option<std::time::SystemTime>,
}

impl RemoteRuleSet {
    fn refresh_schedule(&self, now: std::time::SystemTime) -> (Duration, Duration) {
        let interval = [self.spec.cache_interval, self.spec.update_interval]
            .into_iter()
            .find(|duration| !duration.is_zero())
            .unwrap_or(DEFAULT_UPDATE_INTERVAL);
        let age = self
            .last_updated
            .and_then(|time| now.duration_since(time).ok());
        (interval.saturating_sub(age.unwrap_or_default()), interval)
    }

    pub fn tag(&self) -> &str {
        &self.tags[0]
    }

    pub fn tsrs_cache_path(&self) -> std::path::PathBuf {
        if let Some(path) = &self.spec.cache_file {
            std::path::PathBuf::from(path)
        } else {
            default_tsrs_cache_path(self.tag())
        }
    }

    fn accepts_tsrs(&self) -> bool {
        self.spec.mmap
            || self.spec.mode.should_use_mmap()
            || self.spec.format.as_deref() == Some("tsrs")
    }

    fn publish_mmap(
        &self,
        path: &std::path::Path,
        bytes: &[u8],
        downloaded: bool,
    ) -> io::Result<crate::route::mmap_set::MmapRuleSet> {
        write_tsrs_if_changed(path, bytes)?;
        let set = crate::route::mmap_set::MmapRuleSet::open_with_mode(path, self.spec.mode)?;
        if set.raw_bytes() != bytes {
            return Err(io::Error::other("mmap cache changed during publication"));
        }
        if downloaded {
            let mut record = [0u8; 64];
            record[..32].copy_from_slice(&url_hash(&self.spec.url));
            record[32..].copy_from_slice(&sha256_digest(bytes));
            write_tsrs_if_changed(&provenance_path(path), &record)?;
        }
        Ok(set)
    }

    /// `None` when TSRS cannot keep these rules: the caller loads them into
    /// memory and, once that has succeeded, calls `remove_stale_tsrs`.
    fn compile_and_cache_mmap(
        &self,
        rules: &[Value],
        cache_path: &std::path::Path,
        downloaded: bool,
    ) -> io::Result<Option<crate::route::mmap_set::MmapRuleSet>> {
        if !crate::route::mmap_keeps(rules, &self.tags) {
            return Ok(None);
        }
        let mut compiler = crate::route::mmap_set::RuleSetCompiler::new();
        let bytes = compiler
            .compile(rules)
            .map_err(|e| io::Error::other(format!("compile tsrs: {e}")))?;
        self.publish_mmap(cache_path, &bytes, downloaded).map(Some)
    }

    /// After the set has moved from mmap to memory rules, drop its `.tsrs` so
    /// a restart does not restore the old rules. Only call this once the new
    /// rules are in place: a failed update must keep the working file.
    fn remove_stale_tsrs(&self, cache_path: &std::path::Path) {
        let _ = std::fs::remove_file(provenance_path(cache_path));
        if !cache_path.exists() {
            return;
        }
        match std::fs::remove_file(cache_path) {
            Ok(()) => logging::info(format_args!(
                "removed mmap cache {} of rule-set {}",
                cache_path.display(),
                self.tag()
            )),
            Err(error) => logging::warn(format_args!(
                "remove mmap cache {} of rule-set {}: {error}",
                cache_path.display(),
                self.tag()
            )),
        }
    }

    /// `RemoteRuleSet.StartContext`: cache file, then initial path, then the
    /// first fetch. A cache entry saved from a different URL is refetched.
    pub async fn start(
        &mut self,
        router: &Router,
        cache: Option<&SharedCacheFile>,
    ) -> io::Result<()> {
        let mut loaded = false;
        let tsrs_path = self.tsrs_cache_path();
        let use_mmap = self.spec.mmap || self.spec.mode.should_use_mmap();

        if use_mmap && let Some(digest) = cached_digest(&tsrs_path, &self.spec.url) {
            match crate::route::mmap_set::MmapRuleSet::open_with_mode(&tsrs_path, self.spec.mode) {
                Ok(mmap_set) if sha256_digest(mmap_set.raw_bytes()) == digest => {
                    self.set.replace_mmap(Arc::new(mmap_set));
                    self.last_updated = std::fs::metadata(&tsrs_path)
                        .and_then(|m| m.modified())
                        .ok();
                    loaded = true;
                    logging::info(format_args!(
                        "restored rule-set {} via mmap from {}",
                        self.tag(),
                        tsrs_path.display()
                    ));
                }
                Ok(_) => logging::warn(format_args!(
                    "mmap cache digest mismatch for {}",
                    self.tag()
                )),
                Err(error) => {
                    logging::warn(format_args!(
                        "open cached mmap rule-set {}: {error}, will refetch",
                        tsrs_path.display()
                    ));
                }
            }
        }

        #[allow(clippy::collapsible_if)]
        if !loaded {
            if let Some(cache) = cache {
                match self.restore_from_cache(cache) {
                    Ok(true) => loaded = true,
                    Ok(false) => {}
                    Err(error) => {
                        logging::warn(format_args!(
                            "restore cached rule-set, will refetch: {error}"
                        ));
                    }
                }
            }
        }
        #[allow(clippy::collapsible_if)]
        if !loaded {
            if let Some(path) = &self.spec.initial_path {
                match std::fs::read(path) {
                    Ok(data) => {
                        if data.starts_with(b"TSRS") {
                            match crate::route::mmap_set::MmapRuleSet::open_with_mode(
                                path,
                                self.spec.mode,
                            ) {
                                Ok(mmap_set) => {
                                    self.set.replace_mmap(Arc::new(mmap_set));
                                    loaded = true;
                                    logging::info(format_args!(
                                        "loaded rule-set {} via mmap from {}",
                                        self.tag(),
                                        path
                                    ));
                                }
                                Err(error) => logging::warn(format_args!(
                                    "load initial mmap rule-set from {path}: {error}"
                                )),
                            }
                        } else {
                            let parsed = parse_payload(&data, self.spec.format.as_deref());
                            // the file is not needed once decoded
                            drop(data);
                            match parsed {
                                Ok(rules) => {
                                    let mut leaves_mmap = false;
                                    #[allow(clippy::collapsible_if)]
                                    if use_mmap {
                                        match self.compile_and_cache_mmap(&rules, &tsrs_path, false)
                                        {
                                            Ok(Some(mmap_set)) => {
                                                self.set.replace_mmap(Arc::new(mmap_set));
                                                loaded = true;
                                                logging::info(format_args!(
                                                    "loaded rule-set {} (compiled to mmap) from {}",
                                                    self.tag(),
                                                    path
                                                ));
                                            }
                                            Ok(None) => leaves_mmap = true,
                                            Err(_) => {}
                                        }
                                    }
                                    if !loaded {
                                        match self.set.replace_rules(rules) {
                                            Ok(()) => {
                                                if leaves_mmap {
                                                    self.remove_stale_tsrs(&tsrs_path);
                                                }
                                                loaded = true;
                                                logging::info(format_args!(
                                                    "loaded rule-set {} from {}",
                                                    self.tag(),
                                                    path
                                                ));
                                            }
                                            Err(error) => logging::warn(format_args!(
                                                "load initial rule-set from {path}: {error}"
                                            )),
                                        }
                                    }
                                }
                                Err(error) => logging::warn(format_args!(
                                    "load initial rule-set from {path}: {error}"
                                )),
                            }
                        }
                        if loaded {
                            self.last_updated =
                                std::fs::metadata(path).and_then(|m| m.modified()).ok();
                        }
                    }
                    Err(error) => {
                        logging::warn(format_args!("load initial rule-set from {path}: {error}"))
                    }
                }
            }
        }
        if !loaded {
            self.fetch(router, true, cache).await.map_err(|error| {
                io::Error::other(format!("initial rule-set: {}: {error}", self.tag()))
            })?;
        }
        Ok(())
    }

    /// Load a cached copy; `Ok(false)` when there is nothing usable.
    fn restore_from_cache(&mut self, cache: &SharedCacheFile) -> io::Result<bool> {
        let raw = {
            let guard = cache.lock().expect("cache file");
            guard.get(BUCKET_RULE_SET, self.tag().as_bytes())
        };
        let Some(raw) = raw else {
            return Ok(false);
        };
        let mut saved = saved_binary::unmarshal(&raw)
            .ok_or_else(|| io::Error::other("malformed cached rule-set"))?;
        // `saved` owns a copy of the content; neither is kept past decoding
        drop(raw);
        if saved.url_hash != url_hash(&self.spec.url) {
            logging::info(format_args!(
                "cached rule-set was downloaded from another URL, will refetch"
            ));
            return Ok(false);
        }
        let content = std::mem::take(&mut saved.content);
        if content.starts_with(b"TSRS") {
            if !self.accepts_tsrs() {
                return Ok(false);
            }
            let set = self.publish_mmap(&self.tsrs_cache_path(), &content, true)?;
            self.set.replace_mmap(Arc::new(set));
        } else {
            let rules = parse_payload(&content, self.spec.format.as_deref())?;
            drop(content);
            self.set.replace_rules(rules).map_err(io::Error::other)?;
        }
        self.etag = if saved.last_etag.is_empty() {
            None
        } else {
            Some(saved.last_etag)
        };
        self.last_updated =
            Some(std::time::UNIX_EPOCH + std::time::Duration::from_secs(saved.last_updated));
        logging::info(format_args!("restored rule-set {} from cache", self.tag()));
        Ok(true)
    }

    fn save_to_cache(&self, cache: &SharedCacheFile, content: &[u8]) {
        let saved = saved_binary::SavedBinaryRef {
            last_updated: self
                .last_updated
                .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or_else(saved_binary::now_unix),
            content,
            last_etag: self.etag.as_deref().unwrap_or_default(),
            url_hash: url_hash(&self.spec.url),
        };
        let record = saved_binary::marshal_ref(&saved);
        let mut guard = cache.lock().expect("cache file");
        guard.put(BUCKET_RULE_SET, self.tag().as_bytes(), record);
        if let Err(error) = guard.flush() {
            logging::error(format_args!("save rule-set cache: {error}"));
        }
    }

    async fn fetch_delta(&mut self, router: &Router, path: &std::path::Path) -> io::Result<bool> {
        let Some(digest) = cached_digest(path, &self.spec.url) else {
            return Ok(false);
        };
        let base = std::fs::read(path)?;
        if !base.starts_with(b"TSRS") || sha256_digest(&base) != digest {
            return Ok(false);
        }
        let mut headers = vec![("X-Base-SHA256".to_string(), hex_encode(&digest))];
        if let Some(etag) = &self.etag {
            headers.push(("If-None-Match".to_string(), etag.clone()));
        }
        let response = self
            .spec
            .client
            .get(router, &format!("{}.delta", self.spec.url), &headers)
            .await?;
        if response.status != 200 || !response.body.starts_with(b"TDLT") {
            return Ok(false);
        }
        let bytes = crate::route::mmap_set::apply_delta(&base, &response.body)
            .map_err(|error| io::Error::other(format!("apply delta: {error}")))?;
        let set = self.publish_mmap(path, &bytes, true)?;
        self.set.replace_mmap(Arc::new(set));
        if let Some(etag) = response.header("etag") {
            self.etag = Some(etag.to_string());
        }
        self.last_updated = Some(std::time::SystemTime::now());
        logging::info(format_args!(
            "updated rule-set {} via delta patch ({} bytes)",
            self.tag(),
            response.body.len()
        ));
        Ok(true)
    }

    /// `RemoteRuleSet.fetch`: conditional GET, 304 keeps the current rules.
    /// Supports incremental binary delta updates (`.delta`) and zero-copy mmap.
    pub async fn fetch(
        &mut self,
        router: &Router,
        is_start: bool,
        cache: Option<&SharedCacheFile>,
    ) -> io::Result<()> {
        let tsrs_path = self.tsrs_cache_path();
        let use_mmap = self.spec.mmap || self.spec.mode.should_use_mmap();

        if use_mmap && self.spec.delta_update {
            match self.fetch_delta(router, &tsrs_path).await {
                Ok(true) => return Ok(()),
                Ok(false) => {}
                Err(error) => logging::debug(format_args!(
                    "delta update for {}: {error}, falling back to full fetch",
                    self.tag()
                )),
            }
        }

        let mut headers = Vec::new();
        if let Some(etag) = &self.etag {
            headers.push(("If-None-Match".to_string(), etag.clone()));
        }
        let response = self
            .spec
            .client
            .get(router, &self.spec.url, &headers)
            .await?;
        match response.status {
            200 => {}
            304 => {
                self.last_updated = Some(std::time::SystemTime::now());
                if let Some(cache) = cache {
                    self.touch_cache(cache);
                }
                logging::info(format_args!("update rule-set {}: not modified", self.tag()));
                return Ok(());
            }
            status => {
                return Err(io::Error::other(format!("unexpected status: {status}")));
            }
        }
        let _ = is_start;

        // A TSRS body is taken as-is only by a set that opted into it (`mmap`
        // or `format: tsrs`). The reference has no such format, so for a
        // `binary`/`source` set (all of Forkop's) the server cannot hand the
        // engine a pre-built table in place of the declared one.
        if !self.accepts_tsrs() && response.body.starts_with(b"TSRS") {
            return Err(io::Error::other(
                "TSRS rule-set body refused: the set enables neither mmap nor format tsrs",
            ));
        }
        if response.body.starts_with(b"TSRS") {
            let mmap_set = self.publish_mmap(&tsrs_path, &response.body, true)?;
            self.set.replace_mmap(Arc::new(mmap_set));
            logging::info(format_args!(
                "updated rule-set {} via TSRS binary",
                self.tag()
            ));
        } else {
            let rules = parse_payload(&response.body, self.spec.format.as_deref())?;
            if use_mmap {
                match self.compile_and_cache_mmap(&rules, &tsrs_path, true) {
                    Ok(Some(mmap_set)) => {
                        self.set.replace_mmap(Arc::new(mmap_set));
                        logging::info(format_args!(
                            "compiled and mmapped rule-set {} ({} rules)",
                            self.tag(),
                            rules.len()
                        ));
                    }
                    Ok(None) => {
                        // compile the memory rules first: a failed update keeps
                        // the current rules and the working TSRS file
                        self.set.replace_rules(rules).map_err(io::Error::other)?;
                        self.remove_stale_tsrs(&tsrs_path);
                    }
                    Err(e) => {
                        logging::warn(format_args!(
                            "failed to compile mmap: {e}, falling back to memory rules"
                        ));
                        self.set.replace_rules(rules).map_err(io::Error::other)?;
                    }
                }
            } else {
                // a set that does not compile keeps the current rules
                self.set.replace_rules(rules).map_err(io::Error::other)?;
            }
        }

        if let Some(etag) = response.header("etag") {
            self.etag = Some(etag.to_string());
        }
        self.last_updated = Some(std::time::SystemTime::now());
        if let Some(cache) = cache {
            self.save_to_cache(cache, &response.body);
        }
        logging::info(format_args!("updated rule-set {}", self.tag()));
        Ok(())
    }

    /// 304 keeps the content; only the timestamp moves (reference behaviour).
    fn touch_cache(&self, cache: &SharedCacheFile) {
        let raw = {
            let guard = cache.lock().expect("cache file");
            guard.get(BUCKET_RULE_SET, self.tag().as_bytes())
        };
        let Some(mut saved) = raw.as_deref().and_then(saved_binary::unmarshal) else {
            return;
        };
        if saved.url_hash != url_hash(&self.spec.url) {
            return;
        }
        saved.last_updated = self
            .last_updated
            .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or_else(saved_binary::now_unix);
        let mut guard = cache.lock().expect("cache file");
        guard.put(
            BUCKET_RULE_SET,
            self.tag().as_bytes(),
            saved_binary::marshal(&saved),
        );
    }
}

/// Split out so the updater task can own the state without cloning the set.
#[derive(Debug, Default)]
pub struct RemoteRegistry {
    sets: Vec<Arc<Mutex<RemoteRuleSet>>>,
}

impl RemoteRegistry {
    pub fn new() -> Self {
        Self { sets: Vec::new() }
    }

    pub fn push(&mut self, set: RemoteRuleSet) {
        self.sets.push(Arc::new(Mutex::new(set)));
    }

    pub fn is_empty(&self) -> bool {
        self.sets.is_empty()
    }

    /// Fetch every remote set once; a failure aborts the start unless
    /// `XRUST_RULESET_SOFT_START` asks for the set to be filled later.
    pub async fn start_all(
        &self,
        router: &Arc<Router>,
        cache: Option<&SharedCacheFile>,
    ) -> anyhow::Result<()> {
        self.start_all_with(router, cache, soft_start_enabled())
            .await
    }

    async fn start_all_with(
        &self,
        router: &Arc<Router>,
        cache: Option<&SharedCacheFile>,
        soft: bool,
    ) -> anyhow::Result<()> {
        for set in &self.sets {
            if let Err(error) = set.lock().await.start(router, cache).await {
                if !soft {
                    return Err(error.into());
                }
                logging::warn(format_args!(
                    "{error}: starting with an empty rule-set, retrying in the background"
                ));
                router.track_background_task(spawn_recovery(
                    Arc::clone(set),
                    Arc::clone(router),
                    cache.cloned(),
                ));
            }
        }
        Ok(())
    }

    /// Periodic refresh; the task ends with the process.
    pub fn spawn_updaters(&self, router: Arc<Router>, cache: Option<SharedCacheFile>) {
        for set in &self.sets {
            let state = Arc::clone(set);
            let router = Arc::clone(&router);
            let cache = cache.clone();
            let owner = Arc::clone(&router);
            let task = tokio::spawn(async move {
                let (delay, interval) = state
                    .lock()
                    .await
                    .refresh_schedule(std::time::SystemTime::now());
                let mut ticker =
                    tokio::time::interval_at(tokio::time::Instant::now() + delay, interval);
                ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
                loop {
                    ticker.tick().await;
                    let mut guard = state.lock().await;
                    if let Err(error) = guard.fetch(&router, false, cache.as_ref()).await {
                        logging::error(format_args!("fetch rule-set {}: {error}", guard.tag()));
                    }
                }
            });
            owner.track_background_task(task);
        }
    }
}

/// Keep fetching a set that was empty at start: the recovery ladder until one
/// attempt lands, after which the periodic updater owns it again.
fn spawn_recovery(
    set: Arc<Mutex<RemoteRuleSet>>,
    router: Arc<Router>,
    cache: Option<SharedCacheFile>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        for delay in RECOVERY_LADDER {
            tokio::time::sleep(delay).await;
            let mut guard = set.lock().await;
            match guard.fetch(&router, false, cache.as_ref()).await {
                Ok(()) => {
                    logging::info(format_args!(
                        "recovered rule-set {} after an empty start",
                        guard.tag()
                    ));
                    return;
                }
                Err(error) => {
                    logging::warn(format_args!("fetch rule-set {}: {error}", guard.tag()));
                }
            }
        }
        logging::warn(format_args!(
            "rule-set {} is still empty, the periodic updater will keep trying",
            set.lock().await.tag()
        ));
    })
}

/// `ruleSet.Read` for a downloaded payload: the pinned `format` wins, then the
/// SRS magic, then the URL/path extension (`ruleSetDefaultFormat`).
pub fn parse_payload(data: &[u8], format: Option<&str>) -> io::Result<Vec<Value>> {
    match format {
        Some("source") => parse_source(data),
        Some("binary") => parse_binary(data),
        Some("tsrs") => Ok(Vec::new()),
        Some(other) => Err(io::Error::other(format!(
            "unknown rule-set format: {other}"
        ))),
        None => {
            if data.starts_with(b"TSRS") {
                Ok(Vec::new())
            } else if data.starts_with(b"SRS") {
                parse_binary(data)
            } else {
                parse_source(data)
            }
        }
    }
}

fn parse_source(data: &[u8]) -> io::Result<Vec<Value>> {
    let value: Value = serde_json::from_slice(data)
        .map_err(|error| io::Error::other(format!("decode rule-set source: {error}")))?;
    Ok(crate::route::rule_set::source_rules(value))
}

fn parse_binary(data: &[u8]) -> io::Result<Vec<Value>> {
    core_config::srs::read(data)
        .map_err(|error| io::Error::other(format!("read rule-set: {error}")))
}

/// Compare with fixed scratch space; do not duplicate a large mmap ruleset.
pub(crate) fn file_matches(path: &std::path::Path, bytes: &[u8]) -> bool {
    use std::io::Read;
    let Ok(mut file) = std::fs::File::open(path) else {
        return false;
    };
    if !file
        .metadata()
        .is_ok_and(|meta| meta.len() == bytes.len() as u64)
    {
        return false;
    }
    let mut scratch = [0u8; 8192];
    for chunk in bytes.chunks(scratch.len()) {
        if file.read_exact(&mut scratch[..chunk.len()]).is_err() || &scratch[..chunk.len()] != chunk
        {
            return false;
        }
    }
    true
}

/// Atomic replacement also protects an existing mmap during reload preparation.
pub(crate) fn write_tsrs_if_changed(path: &std::path::Path, bytes: &[u8]) -> io::Result<()> {
    if file_matches(path, bytes) {
        return Ok(());
    }
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)?;
    }
    use portable_atomic::AtomicU64;
    use std::io::Write;
    use std::sync::atomic::Ordering;
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let tmp = path.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp)?;
        file.write_all(bytes)?;
        drop(file);
        std::fs::rename(&tmp, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_refresh_uses_remaining_cache_lifetime() {
        let mut set = remote("schedule", "http://localhost/rules");
        let now = std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(200);
        set.spec.update_interval = Duration::from_secs(120);
        set.spec.cache_interval = Duration::from_secs(60);
        for (age, remaining) in [(0, 60), (20, 40), (60, 0), (150, 0)] {
            set.last_updated = Some(now - Duration::from_secs(age));
            assert_eq!(
                set.refresh_schedule(now),
                (Duration::from_secs(remaining), Duration::from_secs(60))
            );
        }
        set.last_updated = None;
        set.spec.cache_interval = Duration::ZERO;
        assert_eq!(set.refresh_schedule(now).0, Duration::from_secs(120));
    }

    #[cfg(unix)]
    #[test]
    fn default_cache_lives_under_the_xrust_directory() {
        assert_eq!(
            default_tsrs_cache_path("main"),
            std::path::PathBuf::from("/tmp/xrust-rulesets/main.tsrs")
        );
    }

    #[test]
    fn unchanged_tsrs_keeps_file_and_changed_tsrs_preserves_old_mapping() {
        let path =
            std::env::temp_dir().join(format!("rust-x-tsrs-noop-{}.bin", std::process::id()));
        let first = vec![0x11; 20_000];
        write_tsrs_if_changed(&path, &first).unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();
        let map = crate::route::mmap_set::mmap_io::MmapBuffer::open(&path).unwrap();
        write_tsrs_if_changed(&path, &first).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before
        );
        let second = vec![0x22; 20_000];
        write_tsrs_if_changed(&path, &second).unwrap();
        assert_eq!(&map[..], &first);
        assert!(file_matches(&path, &second));
        assert!(!file_matches(&path, &first));
        drop(map);
        std::fs::remove_file(path).unwrap();
    }
    use serde_json::json;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    const CRLF: &str = "\r\n";

    async fn router() -> Arc<Router> {
        Router::new(&json!({
            "log": {"level": "error"},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .expect("router")
    }

    fn srs_with(domain: &str) -> Vec<u8> {
        core_config::srs::compile(&json!({"rules": [{"domain_suffix": [domain]}]}), 2)
            .expect("compile")
    }

    fn remote(tag: &str, url: &str) -> RemoteRuleSet {
        let tags = vec![tag.to_string()];
        let set = Arc::new(RuleSet::new(tags.clone(), Vec::new()).expect("empty set"));
        RemoteRuleSet {
            tags,
            spec: RemoteSpec {
                url: url.to_string(),
                initial_path: None,
                update_interval: Duration::ZERO,
                client: HttpClient::default(),
                format: None,
                mmap: false,
                delta_update: true,
                cache_interval: Duration::ZERO,
                cache_file: None,
                mode: crate::route::mmap_set::MmapMode::Auto,
            },
            set,
            etag: None,
            last_updated: None,
        }
    }

    async fn serve(response: Vec<u8>) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });
        (format!("http://{addr}/ruleset.srs"), handle)
    }

    fn body_response(payload: &[u8]) -> Vec<u8> {
        let mut response = format!(
            "HTTP/1.1 200 OK{CRLF}Content-Length: {}{CRLF}{CRLF}",
            payload.len()
        )
        .into_bytes();
        response.extend_from_slice(payload);
        response
    }

    #[test]
    fn payload_format_detection() {
        let srs = srs_with("example.com");
        let rules = parse_payload(&srs, None).expect("srs");
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0]["domain_suffix"][0], "example.com");
        let source = json!({"rules": [{"domain": ["a.test"]}]}).to_string();
        let rules = parse_payload(source.as_bytes(), None).expect("source");
        assert_eq!(rules[0]["domain"][0], "a.test");
        // a pinned format wins over the payload sniffing
        let error = parse_payload(&srs, Some("source")).unwrap_err();
        assert!(error.to_string().contains("rule-set source"));
        let error = parse_payload(source.as_bytes(), Some("other")).unwrap_err();
        assert_eq!(error.to_string(), "unknown rule-set format: other");
    }

    #[tokio::test]
    async fn start_fetches_and_fills_the_set() {
        let router = router().await;
        let payload = srs_with("fetched.example");
        let (url, server) = serve(body_response(&payload)).await;
        let mut set = remote("rs", &url);
        set.start(&router, None).await.expect("start");
        server.abort();
        assert_eq!(set.set.rule_count(), 1);
        assert!(set.last_updated.is_some());
    }

    #[tokio::test]
    async fn not_modified_keeps_the_rules() {
        let router = router().await;
        let payload = srs_with("cached.example");
        let (url, server) = serve(body_response(&payload)).await;
        let mut set = remote("rs", &url);
        set.start(&router, None).await.expect("start");
        server.abort();
        // the second response is 304: the set keeps what it had
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let etag_url = format!("http://{addr}/ruleset.srs");
        set.spec.url = etag_url.clone();
        set.etag = Some("W/\"".to_string());
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut head = [0u8; 1024];
            let read = stream.read(&mut head).await.unwrap_or(0);
            let request = String::from_utf8_lossy(&head[..read]).to_string();
            assert!(request.contains("If-None-Match"), "{request}");
            let _ = stream
                .write_all(format!("HTTP/1.1 304 Not Modified{CRLF}{CRLF}").as_bytes())
                .await;
        });
        set.fetch(&router, false, None).await.expect("fetch");
        server.await.ok();
        assert_eq!(set.set.rule_count(), 1);
    }

    #[tokio::test]
    async fn unexpected_status_is_an_error() {
        let router = router().await;
        let (url, server) =
            serve(format!("HTTP/1.1 500 Internal Server Error{CRLF}{CRLF}").into_bytes()).await;
        let mut set = remote("rs", &url);
        let error = set.start(&router, None).await.unwrap_err();
        assert!(
            error.to_string().contains("unexpected status: 500"),
            "{error}"
        );
        assert!(error.to_string().contains("initial rule-set: rs"));
        server.abort();
    }

    mod https_fixture {
        include!("../../tests/support/https_fixture.rs");
    }

    /// A router that trusts the test CA through the top-level `certificate`
    /// option, as a user with a private rule-set server would configure it.
    async fn router_trusting_test_ca() -> Arc<Router> {
        Router::new(&json!({
            "log": {"level": "error"},
            "certificate": {"certificate_path": [https_fixture::CA_PATH]},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .expect("router")
    }

    #[tokio::test]
    async fn https_fetch_with_a_trusted_ca_and_the_right_name_fills_the_set() {
        let router = router_trusting_test_ca().await;
        let payload = srs_with("trusted.example");
        let server =
            https_fixture::serve_https(https_fixture::VALID, https_fixture::ok_response(&payload))
                .await;
        let mut set = remote("rs", &server.url("/ruleset.srs"));
        set.start(&router, None).await.expect("trusted https fetch");
        assert_eq!(set.set.rule_count(), 1);
        assert_eq!(server.served(), 1);
        // the same through a named detour outbound
        let mut set = remote("rs", &server.url("/ruleset.srs"));
        set.spec.client.detour = Some("direct".to_string());
        set.start(&router, None)
            .await
            .expect("trusted fetch via detour");
        assert_eq!(set.set.rule_count(), 1);
    }

    #[tokio::test]
    async fn https_fetch_refuses_an_unverified_server() {
        let payload = srs_with("never.example");
        let trusting = router_trusting_test_ca().await;
        let default_roots = router().await;
        for (label, cert, router, expected) in [
            // valid chain, but its CA is not configured: only Mozilla roots
            (
                "unknown CA",
                https_fixture::VALID,
                &default_roots,
                "UnknownIssuer",
            ),
            (
                "bad signature",
                https_fixture::UNTRUSTED,
                &trusting,
                "BadSignature",
            ),
            (
                "wrong name",
                https_fixture::WRONG_NAME,
                &trusting,
                "not valid for name",
            ),
            (
                "expired",
                https_fixture::EXPIRED,
                &trusting,
                "certificate expired",
            ),
        ] {
            let server =
                https_fixture::serve_https(cert, https_fixture::ok_response(&payload)).await;
            let mut set = remote("rs", &server.url("/ruleset.srs"));
            let error = set.start(router, None).await.unwrap_err().to_string();
            assert!(error.contains(expected), "{label}: {error}");
            assert_eq!(set.set.rule_count(), 0, "{label}");
            assert_eq!(server.served(), 0, "{label}: the request was sent");
        }
    }

    #[tokio::test]
    async fn failed_https_update_keeps_the_previous_set() {
        let router = router_trusting_test_ca().await;
        let first = https_fixture::serve_https(
            https_fixture::VALID,
            https_fixture::ok_response(&srs_with("first.example")),
        )
        .await;
        let mut set = remote("rs", &first.url("/ruleset.srs"));
        set.start(&router, None).await.expect("first fetch");
        assert_eq!(set.set.rule_count(), 1);
        let updated = set.last_updated;
        // the next update meets a certificate that does not verify
        let second = https_fixture::serve_https(
            https_fixture::EXPIRED,
            https_fixture::ok_response(&srs_with("a.example b.example")),
        )
        .await;
        set.spec.url = second.url("/ruleset.srs");
        let error = set.fetch(&router, false, None).await.unwrap_err();
        assert!(error.to_string().contains("certificate expired"), "{error}");
        assert_eq!(set.set.rule_count(), 1, "the old rules stay in place");
        assert_eq!(set.last_updated, updated);
        assert_eq!(second.served(), 0);
    }

    #[tokio::test]
    async fn soft_start_survives_and_recovers_the_set() {
        let router = router().await;
        let payload = srs_with("recovered.example");
        // 500 for the start attempts, the real set for the recovery fetch
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let hits = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served = Arc::clone(&hits);
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let response = if served.fetch_add(1, std::sync::atomic::Ordering::SeqCst) < 2 {
                    format!("HTTP/1.1 500 Internal Server Error{CRLF}{CRLF}").into_bytes()
                } else {
                    body_response(&payload)
                };
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });
        let mut registry = RemoteRegistry::new();
        registry.push(remote("rs", &format!("http://{addr}/ruleset.srs")));

        // the reference aborts the start
        let error = registry.start_all(&router, None).await.unwrap_err();
        assert!(
            error.to_string().contains("initial rule-set: rs"),
            "{error}"
        );

        // soft start: the engine stays up, the set is empty for now
        registry
            .start_all_with(&router, None, true)
            .await
            .expect("soft start");
        assert_eq!(registry.sets[0].lock().await.set.rule_count(), 0);

        // and the background ladder fills it without help
        for _ in 0..100 {
            if registry.sets[0].lock().await.set.rule_count() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let set = registry.sets[0].lock().await;
        assert_eq!(set.set.rule_count(), 1, "recovered in the background");
        assert!(
            set.set.index().has_suffix("recovered.example"),
            "the recovered set compiled its suffix"
        );
        drop(set);
        server.abort();
    }

    #[tokio::test]
    async fn initial_path_is_used_before_the_first_fetch() {
        let router = router().await;
        let payload = srs_with("local.example");
        let path = std::env::temp_dir().join("xrust-remote-rule-set-test.srs");
        std::fs::write(&path, &payload).expect("write");
        let path = path.to_string_lossy().to_string();
        // a URL that would fail: the initial path must be enough
        let mut set = remote("rs", "http://127.0.0.1:1/ruleset.srs");
        set.spec.initial_path = Some(path);
        set.start(&router, None).await.expect("start");
        assert_eq!(set.set.rule_count(), 1);
        assert!(
            set.set.index().has_suffix("local.example"),
            "the initial path compiled its suffix"
        );
        let _ = std::fs::remove_file(std::env::temp_dir().join("xrust-remote-rule-set-test.srs"));
    }

    #[tokio::test]
    async fn remote_mmap_compile_and_match() {
        let router = router().await;
        let payload = srs_with("mmap-fast.org");
        let (url, server) = serve(body_response(&payload)).await;
        let cache_file = std::env::temp_dir().join(format!("test-rs-{}.tsrs", std::process::id()));
        let mut set = remote("mmap_rs", &url);
        set.spec.mmap = true;
        set.spec.cache_file = Some(cache_file.to_string_lossy().to_string());
        set.start(&router, None).await.expect("start");
        server.abort();

        // Check file exists on disk/tmpfs
        assert!(cache_file.exists(), "cache_file must be written");
        let data = std::fs::read(&cache_file).expect("read cached tsrs");
        assert!(data.starts_with(b"TSRS"));

        // Match context
        let ctx = crate::route::ConnContext::new(
            "in",
            "10.0.0.2:1234".parse().unwrap(),
            crate::route::Target::Domain("sub.mmap-fast.org".to_string(), 443),
            "tcp",
        );
        assert!(
            set.set.matches(&ctx),
            "mmap rule set must match sub.mmap-fast.org"
        );

        let _ = std::fs::remove_file(provenance_path(&cache_file));
        let _ = std::fs::remove_file(&cache_file);
    }

    /// CQ-04: a `binary`/`source` set (all of Forkop's) does not take a
    /// pre-built TSRS image from the server in place of what it declared.
    #[tokio::test]
    async fn tsrs_body_is_refused_unless_the_set_opted_in() {
        let router = router().await;
        let image = crate::route::mmap_set::RuleSetCompiler::new()
            .compile(&[json!({"domain_suffix": ["image.example"]})])
            .expect("tsrs");
        let (url, server) = serve(body_response(&image)).await;
        let cache_file =
            std::env::temp_dir().join(format!("rust-x-tsrs-refused-{}.tsrs", std::process::id()));
        let _ = std::fs::remove_file(provenance_path(&cache_file));
        let _ = std::fs::remove_file(&cache_file);
        for format in [Some("binary"), Some("source"), None] {
            let mut set = remote("rs", &url);
            set.spec.format = format.map(str::to_string);
            set.spec.cache_file = Some(cache_file.to_string_lossy().to_string());
            let error = set.fetch(&router, false, None).await.unwrap_err();
            assert!(error.to_string().contains("TSRS"), "{format:?}: {error}");
            assert!(set.set.mmap().is_none(), "{format:?}");
            assert!(!cache_file.exists(), "{format:?}: the image was written");
        }
        // a set that opted into mmap still takes it
        let mut set = remote("rs", &url);
        set.spec.mmap = true;
        set.spec.cache_file = Some(cache_file.to_string_lossy().to_string());
        set.fetch(&router, false, None)
            .await
            .expect("an mmap set takes TSRS");
        assert!(set.set.mmap().is_some());
        server.abort();
        let _ = std::fs::remove_file(provenance_path(&cache_file));
        let _ = std::fs::remove_file(&cache_file);
    }

    #[tokio::test]
    async fn mismatched_or_unmarked_mmap_requires_full_download() {
        let router = router().await;
        let old = crate::route::mmap_set::RuleSetCompiler::new()
            .compile(&[json!({"domain": ["old.test"]})])
            .unwrap();
        let new = crate::route::mmap_set::RuleSetCompiler::new()
            .compile(&[json!({"domain": ["new.test"]})])
            .unwrap();
        for reason in ["url", "legacy", "digest"] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}/rules", listener.local_addr().unwrap());
            let path = std::env::temp_dir().join(format!(
                "xrust-cache-origin-{}-{reason}.tsrs",
                std::process::id()
            ));
            let mut remote = remote("same-tag", &url);
            remote.spec.cache_file = Some(path.to_string_lossy().into_owned());
            remote.spec.mmap = true;
            if reason == "url" {
                remote.spec.url = format!("{url}/previous");
            }
            remote.publish_mmap(&path, &old, true).unwrap();
            remote.spec.url = url;
            if reason == "legacy" {
                std::fs::remove_file(provenance_path(&path)).unwrap();
            } else if reason == "digest" {
                // Interrupted or interleaved publication of the image and origin.
                write_tsrs_if_changed(&path, &new).unwrap();
            }
            let response = body_response(&srs_with("fresh.test"));
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") {
                    request.push(socket.read_u8().await.unwrap());
                }
                assert!(request.starts_with(b"GET /rules HTTP/1.1\r\n"));
                socket.write_all(&response).await.unwrap();
            });
            remote.start(&router, None).await.unwrap();
            tokio::time::timeout(Duration::from_secs(3), server)
                .await
                .expect("the current URL must receive a full GET")
                .unwrap();
            let ctx = crate::route::ConnContext::new(
                "in",
                "10.0.0.2:1234".parse().unwrap(),
                crate::route::Target::Domain("fresh.test".into(), 443),
                "tcp",
            );
            assert!(remote.set.matches(&ctx));
            drop(remote);
            std::fs::remove_file(&path).unwrap();
            std::fs::remove_file(provenance_path(&path)).unwrap();
        }
    }

    #[test]
    fn restores_legacy_tsrs_only_from_the_matching_persistent_cache() {
        use crate::cache_file::{CacheFile, CacheFileOptions};

        let root = std::env::temp_dir().join(format!(
            "xrust-legacy-tsrs-migration-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("rules.tsrs");
        let cache = Arc::new(std::sync::Mutex::new(
            CacheFile::open(CacheFileOptions {
                enabled: true,
                path: root.join("cache.db").to_string_lossy().into_owned(),
                ..Default::default()
            })
            .unwrap()
            .unwrap(),
        ));
        let mut remote = remote("migrate", "http://rules.test/data.tsrs");
        remote.spec.format = Some("tsrs".into());
        remote.spec.cache_file = Some(path.to_string_lossy().into_owned());
        let rules = crate::route::mmap_set::RuleSetCompiler::new()
            .compile(&[json!({"domain": ["kept.test"]})])
            .unwrap();
        write_tsrs_if_changed(&path, &rules).unwrap();
        remote.save_to_cache(&cache, &rules);
        remote.spec.url = "http://other.test/data.tsrs".into();
        assert!(!remote.restore_from_cache(&cache).unwrap());
        assert!(!provenance_path(&path).exists());
        remote.spec.url = "http://rules.test/data.tsrs".into();
        assert!(remote.restore_from_cache(&cache).unwrap());
        assert!(remote.set.mmap().is_some());
        assert_eq!(
            cached_digest(&path, &remote.spec.url),
            Some(sha256_digest(&rules))
        );
        drop(remote);
        drop(cache);
        std::fs::remove_dir_all(root).unwrap();
    }

    #[tokio::test]
    async fn remote_delta_update_flow() {
        let router = router().await;
        let base_rules = json!([{"domain_suffix": ["base-site.com"]}]);
        let mut compiler = crate::route::mmap_set::RuleSetCompiler::new();
        let base_tsrs = compiler.compile(base_rules.as_array().unwrap()).unwrap();
        let base_sha = sha256_digest(&base_tsrs);

        let cache_file =
            std::env::temp_dir().join(format!("test-delta-{}.tsrs", std::process::id()));

        // Build target tsrs with additional domain
        let mut target_compiler = crate::route::mmap_set::RuleSetCompiler::new();
        let target_rules = json!([{"domain_suffix": ["base-site.com", "delta-added.com"]}]);
        let target_tsrs = target_compiler
            .compile(target_rules.as_array().unwrap())
            .unwrap();
        let target_sha = sha256_digest(&target_tsrs);

        let delta_bytes = crate::route::mmap_set::DeltaBuilder::new(base_sha, target_sha)
            .add_suffix("delta-added.com")
            .build();

        // Serve delta when requested
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let delta_clone = delta_bytes.clone();
        let server = tokio::spawn(async move {
            while let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let response = body_response(&delta_clone);
                let _ = stream.write_all(&response).await;
                let _ = stream.flush().await;
            }
        });

        let mut set = remote("delta_rs", &format!("http://{addr}/ruleset.srs"));
        set.spec.mmap = true;
        set.spec.delta_update = true;
        set.spec.cache_file = Some(cache_file.to_string_lossy().to_string());
        set.publish_mmap(&cache_file, &base_tsrs, true).unwrap();
        set.start(&router, None).await.expect("start");

        // Verify base matches before delta
        let ctx = crate::route::ConnContext::new(
            "in",
            "10.0.0.2:1234".parse().unwrap(),
            crate::route::Target::Domain("delta-added.com".to_string(), 443),
            "tcp",
        );
        assert!(
            !set.set.matches(&ctx),
            "delta-added should not match before delta"
        );

        // Now trigger fetch, which requests .delta and applies it
        set.fetch(&router, false, None).await.expect("fetch delta");
        assert!(
            set.set.matches(&ctx),
            "delta-added must match after delta applied"
        );

        server.abort();
        let _ = std::fs::remove_file(provenance_path(&cache_file));
        let _ = std::fs::remove_file(&cache_file);
    }
}
