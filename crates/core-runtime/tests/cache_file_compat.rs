//! cache.db written before the writer stopped cloning the tree
//! (`tests/data/cache-file-v0026.db`) must load, restore fakeip and remote
//! rule sets, and be rewritten byte for byte.
//!
//! The fixture is made by `write_fixture` (ignored) on the old writer:
//! `CACHE_FIXTURE_OUT=<path> cargo test --test cache_file_compat -- --ignored`.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use core_runtime::cache_file::{
    BUCKET_CHAIN_DISABLED, BUCKET_DNS_CACHE, BUCKET_EXPAND, BUCKET_MODE, BUCKET_RDRC,
    BUCKET_RULE_SET, BUCKET_SELECTED, CacheFile, CacheFileOptions, saved_binary,
};
use core_runtime::dns::transport::{FakeIpStore, IpPrefix};

const CACHE_ID: &str = "fixture-id";
const FAKEIP_DOMAINS: usize = 300;

fn fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/data/cache-file-v0026.db")
}

fn options(path: &Path) -> CacheFileOptions {
    CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        cache_id: CACHE_ID.into(),
        store_fakeip: true,
        // only explicit flushes write
        flush_interval: Duration::from_secs(3600),
        ..Default::default()
    }
}

fn pool() -> FakeIpStore {
    FakeIpStore::new(
        Some(IpPrefix::parse("198.18.0.0/15").unwrap()),
        Some(IpPrefix::parse("fc00::/18").unwrap()),
    )
}

fn temp_copy(tag: &str) -> PathBuf {
    let dir =
        std::env::temp_dir().join(format!("rust-x-cache-compat-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cache.db");
    std::fs::copy(fixture(), &path).unwrap();
    path
}

fn domain(i: usize, v6: bool) -> String {
    format!("site-{i:03}.v{}.example", if v6 { 6 } else { 4 })
}

fn rule_set_body(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn saved(seed: u8, len: usize) -> saved_binary::SavedBinary {
    saved_binary::SavedBinary {
        last_updated: 1_700_000_000 + u64::from(seed),
        content: rule_set_body(seed, len),
        last_etag: format!("\"etag-{seed}\""),
        url_hash: [seed; 32],
    }
}

/// Every bucket the store models plus one it does not.
fn fill(path: &Path) {
    let _ = std::fs::remove_file(path);
    let cache = Arc::new(Mutex::new(CacheFile::open(options(path)).unwrap().unwrap()));
    let fakeip = pool();
    fakeip.attach_cache(Some(cache.clone()));
    for i in 0..FAKEIP_DOMAINS {
        fakeip.create(&domain(i, false), false).unwrap();
        fakeip.create(&domain(i, true), true).unwrap();
    }
    let mut store = cache.lock().unwrap();
    // overflow pages for one body, an inline one for the other
    let big = saved_binary::marshal(&saved(1, 9000));
    store.put(BUCKET_RULE_SET, b"remote-big", big);
    store.put(
        BUCKET_RULE_SET,
        b"remote-small",
        saved_binary::marshal(&saved(2, 40)),
    );
    store.put(BUCKET_SELECTED, b"proxy", b"node-a".to_vec());
    store.put(BUCKET_SELECTED, b"video", b"node-b".to_vec());
    store.put(BUCKET_EXPAND, b"proxy", vec![1]);
    store.put(BUCKET_MODE, b"mode", b"rule".to_vec());
    store.put(BUCKET_CHAIN_DISABLED, b"chain-a", vec![1]);
    for i in 0..20u8 {
        store.put(
            BUCKET_RDRC,
            format!("rdrc-{i}.example").as_bytes(),
            vec![i; 12],
        );
        store.put(
            BUCKET_DNS_CACHE,
            format!("q-{i}.example").as_bytes(),
            vec![i; 30],
        );
    }
    store.put("foreign", &[0xfe, 0x00], vec![7]);
    store.flush().unwrap();
}

fn assert_content(path: &Path) {
    let cache = Arc::new(Mutex::new(CacheFile::open(options(path)).unwrap().unwrap()));
    let fakeip = pool();
    fakeip.attach_cache(Some(cache.clone()));
    let mut ips = Vec::new();
    for i in 0..FAKEIP_DOMAINS {
        for v6 in [false, true] {
            let name = domain(i, v6);
            let ip = fakeip.create(&name, v6).unwrap();
            assert_eq!(fakeip.lookup_domain(ip).as_deref(), Some(name.as_str()));
            ips.push(ip);
        }
    }
    assert_eq!(
        ips[0],
        "198.18.0.2".parse::<IpAddr>().unwrap(),
        "restored mapping keeps its address"
    );
    let store = cache.lock().unwrap();
    for (key, seed, len) in [(&b"remote-big"[..], 1u8, 9000), (b"remote-small", 2, 40)] {
        let raw = store.get(BUCKET_RULE_SET, key).expect("rule set body");
        let body = saved_binary::unmarshal(&raw).expect("saved binary");
        let want = saved(seed, len);
        assert_eq!(body.content, want.content);
        assert_eq!(body.last_updated, want.last_updated);
        assert_eq!(body.last_etag, want.last_etag);
        assert_eq!(body.url_hash, want.url_hash);
    }
    assert_eq!(
        store.get(BUCKET_SELECTED, b"proxy"),
        Some(b"node-a".to_vec())
    );
    assert_eq!(
        store.get(BUCKET_SELECTED, b"video"),
        Some(b"node-b".to_vec())
    );
    assert_eq!(store.get(BUCKET_EXPAND, b"proxy"), Some(vec![1]));
    assert_eq!(store.get(BUCKET_MODE, b"mode"), Some(b"rule".to_vec()));
    assert_eq!(store.get(BUCKET_CHAIN_DISABLED, b"chain-a"), Some(vec![1]));
    assert_eq!(store.keys(BUCKET_RDRC).len(), 20);
    assert_eq!(
        store.get(BUCKET_DNS_CACHE, b"q-19.example"),
        Some(vec![19; 30])
    );
    assert_eq!(store.get("foreign", &[0xfe, 0x00]), Some(vec![7]));
    assert_eq!(
        store.raw_keys("fakeip_address").len(),
        2 * FAKEIP_DOMAINS + 1,
        "addresses plus metadata"
    );
}

/// Dirty the store without changing its content.
fn touch(store: &mut CacheFile) {
    store.put(BUCKET_SELECTED, b"zz-touch", vec![1]);
    store.delete(BUCKET_SELECTED, b"zz-touch");
}

#[test]
#[ignore = "regenerates the fixture; set CACHE_FIXTURE_OUT"]
fn write_fixture() {
    let out = std::env::var("CACHE_FIXTURE_OUT").expect("CACHE_FIXTURE_OUT");
    fill(Path::new(&out));
}

#[test]
fn old_file_restores_every_bucket() {
    let path = temp_copy("restore");
    assert_content(&path);
    // reading alone writes nothing
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(fixture()).unwrap()
    );
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn writes_match_the_old_writer_byte_for_byte() {
    let expected = std::fs::read(fixture()).unwrap();
    // the same content written from scratch
    let path = temp_copy("fresh");
    fill(&path);
    assert_eq!(std::fs::read(&path).unwrap(), expected, "fresh write");
    // the old file opened and flushed unchanged
    std::fs::copy(fixture(), &path).unwrap();
    let mut store = CacheFile::open(options(&path)).unwrap().unwrap();
    touch(&mut store);
    store.flush().unwrap();
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), expected, "rewrite");
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[test]
fn edited_old_file_survives_reopen() {
    let path = temp_copy("edit");
    let mut store = CacheFile::open(options(&path)).unwrap().unwrap();
    store.put(BUCKET_SELECTED, b"proxy", b"node-c".to_vec());
    store.put(BUCKET_RULE_SET, b"remote-new", rule_set_body(9, 50_000));
    store.delete(BUCKET_DNS_CACHE, b"q-0.example");
    store.flush().unwrap();
    drop(store);
    let store = CacheFile::open(options(&path)).unwrap().unwrap();
    assert_eq!(
        store.get(BUCKET_SELECTED, b"proxy"),
        Some(b"node-c".to_vec())
    );
    assert_eq!(
        store.get(BUCKET_RULE_SET, b"remote-new"),
        Some(rule_set_body(9, 50_000))
    );
    assert_eq!(store.get(BUCKET_DNS_CACHE, b"q-0.example"), None);
    assert_eq!(
        store.get(BUCKET_DNS_CACHE, b"q-1.example"),
        Some(vec![1; 30])
    );
    assert_eq!(store.get("foreign", &[0xfe, 0x00]), Some(vec![7]));
    assert_eq!(
        store.raw_keys("fakeip_address").len(),
        2 * FAKEIP_DOMAINS + 1
    );
    drop(store);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}

#[cfg(unix)]
#[test]
fn failed_flush_keeps_memory_and_the_previous_file() {
    use std::os::unix::fs::PermissionsExt;
    let path = temp_copy("readonly");
    let dir = path.parent().unwrap().to_path_buf();
    let mut store = CacheFile::open(options(&path)).unwrap().unwrap();
    store.put(BUCKET_SELECTED, b"proxy", b"node-z".to_vec());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o555)).unwrap();
    if std::fs::write(dir.join("probe"), b"x").is_ok() {
        // root ignores directory permissions
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
        eprintln!("directory stays writable; skipping");
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    assert!(store.flush().is_err());
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(
        store.get(BUCKET_SELECTED, b"proxy"),
        Some(b"node-z".to_vec())
    );
    assert_eq!(
        std::fs::read(&path).unwrap(),
        std::fs::read(fixture()).unwrap()
    );
    assert!(!dir.join("cache.db.tmp").exists());
    // still dirty: the next flush writes it out
    store.flush().unwrap();
    drop(store);
    let store = CacheFile::open(options(&path)).unwrap().unwrap();
    assert_eq!(
        store.get(BUCKET_SELECTED, b"proxy"),
        Some(b"node-z".to_vec())
    );
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

async fn serve_rule_set_once() -> (String, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/rules.json", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut buf = vec![0u8; 4096];
        let mut used = 0;
        while !buf[..used].windows(4).any(|w| w == b"\r\n\r\n") {
            let count = stream.read(&mut buf[used..]).await.unwrap();
            assert!(count > 0, "request ended early");
            used += count;
        }
        let body = r#"{"version":1,"rules":[{"domain_suffix":["remote.example"]}]}"#;
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    });
    (url, server)
}

async fn resolves_to_fakeip(instance: &core_runtime::BoxInstance) -> bool {
    let dns = instance.dns().unwrap();
    let query = core_runtime::dns::codec::build_query(
        7,
        "remote.example",
        hickory_proto::rr::RecordType::A,
    )
    .unwrap();
    let raw = dns
        .exchange(&core_runtime::dns::QueryMeta::default(), &query, true)
        .await
        .unwrap();
    core_runtime::dns::codec::answer_ips(&raw)
        .unwrap()
        .first()
        .is_some_and(|ip| ip.to_string().starts_with("198.18."))
}

#[tokio::test]
async fn remote_rule_set_and_fakeip_restore_after_restart() {
    let path = temp_copy("runtime");
    let (url, server) = serve_rule_set_once().await;
    let root = serde_json::json!({"outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"final":"direct","rule_set":[{"type":"remote","tag":"remote","format":"source",
            "url":url}]},
        "dns":{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"},
            {"type":"hosts","tag":"real","path":[],"predefined":{"remote.example":["203.0.113.7"]}}],
            "rules":[{"rule_set":"remote","action":"route","server":"fake"}],"final":"real"},
        "experimental":{"cache_file":{"enabled":true,"store_fakeip":true,"cache_id":CACHE_ID,
            "path":path}}});
    let instance = core_runtime::start(&root).await.unwrap();
    server.await.unwrap();
    assert!(resolves_to_fakeip(&instance).await);
    let fakeip = instance.dns().unwrap().fakeip_stores().pop().unwrap();
    let restored = "198.18.0.2".parse::<IpAddr>().unwrap();
    assert_eq!(
        fakeip.lookup_domain(restored).as_deref(),
        Some(domain(0, false).as_str()),
        "fakeip from the old file"
    );
    instance.shutdown_wait().await;

    // the download server is gone: only the cache can supply the set
    let instance = core_runtime::start(&root).await.unwrap();
    assert!(resolves_to_fakeip(&instance).await, "rule set from cache");
    let fakeip = instance.dns().unwrap().fakeip_stores().pop().unwrap();
    assert_eq!(
        fakeip.lookup_domain(restored).as_deref(),
        Some(domain(0, false).as_str())
    );
    instance.shutdown_wait().await;
    let store = CacheFile::open(options(&path)).unwrap().unwrap();
    assert!(store.get(BUCKET_RULE_SET, b"remote").is_some());
    assert!(store.get(BUCKET_RULE_SET, b"remote-big").is_some());
    drop(store);
    std::fs::remove_dir_all(path.parent().unwrap()).unwrap();
}
