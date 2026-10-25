use core_runtime::cache_file::{CacheFile, CacheFileOptions};
use core_runtime::dns::transport::{FakeIpStore, IpPrefix};
use core_runtime::inbound::Target;
use core_runtime::route::ConnContext;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::{Arc, Mutex};

fn pool() -> FakeIpStore {
    FakeIpStore::new(
        Some(IpPrefix::parse("198.18.0.0/15").unwrap()),
        Some(IpPrefix::parse("fc00::/18").unwrap()),
    )
}

#[test]
fn fakeip_survives_reopen_and_preserves_binary_keys_and_cursors() {
    let path = std::env::temp_dir().join(format!("rust-x-fakeip-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let options = CacheFileOptions {
        enabled: true,
        store_fakeip: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    let first = pool();
    first.attach_cache(Some(cache.clone()));
    let v4 = first.create("first.example", false).unwrap();
    let v6 = first.create("first.example", true).unwrap();
    // Distinct invalid UTF-8 binary keys used to collapse to the same lossy string.
    cache.lock().unwrap().put("foreign", &[0xfe], vec![1]);
    cache.lock().unwrap().put("foreign", &[0xff], vec![2]);
    cache.lock().unwrap().flush().unwrap();
    drop((first, cache));
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    let reopened = pool();
    reopened.attach_cache(Some(cache.clone()));
    for (ip, v6) in [(v4, false), (v6, true)] {
        assert_eq!(reopened.lookup_domain(ip).as_deref(), Some("first.example"));
        assert_eq!(reopened.create("first.example", v6).unwrap(), ip);
        assert_ne!(reopened.create("second.example", v6).unwrap(), ip);
    }
    assert_eq!(cache.lock().unwrap().get("foreign", &[0xfe]), Some(vec![1]));
    assert_eq!(cache.lock().unwrap().get("foreign", &[0xff]), Some(vec![2]));
    // A Go-formatted cache has packed address keys and raw address values.
    let go_ip = Ipv4Addr::new(198, 18, 1, 200);
    cache
        .lock()
        .unwrap()
        .put("fakeip_address", &go_ip.octets(), b"go.example".to_vec());
    cache
        .lock()
        .unwrap()
        .put("fakeip_domain4", b"go.example", go_ip.octets().to_vec());
    cache
        .lock()
        .unwrap()
        .delete("fakeip_address", b"fakeip_metadata");
    cache.lock().unwrap().flush().unwrap();
    drop((reopened, cache));
    let cache = Arc::new(Mutex::new(CacheFile::open(options).unwrap().unwrap()));
    let imported = pool();
    imported.attach_cache(Some(cache.clone()));
    assert_eq!(
        imported.lookup_domain(go_ip.into()).as_deref(),
        Some("go.example")
    );
    assert_eq!(
        imported.create("go.example", false).unwrap(),
        IpAddr::V4(go_ip)
    );
    // A fresh import resumes beyond the highest Go address.
    let next = imported.create("after-import.example", false).unwrap();
    assert_eq!(next, IpAddr::V4(Ipv4Addr::new(198, 18, 1, 201)));
    let disabled = pool();
    cache.lock().unwrap().flush().unwrap();
    let disabled_cache = Arc::new(Mutex::new(
        CacheFile::open(CacheFileOptions {
            enabled: true,
            path: path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap()
        .unwrap(),
    ));
    disabled.attach_cache(Some(disabled_cache));
    assert_eq!(disabled.lookup_domain(go_ip.into()), None);
    std::fs::remove_file(path).unwrap();
}

#[tokio::test]
async fn runtime_rejects_unknown_fakeip_and_flushes_on_shutdown() {
    let path =
        std::env::temp_dir().join(format!("rust-x-fakeip-runtime-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let root = json!({"outbounds":[{"type":"direct","tag":"direct"}],
        "route":{"final":"direct"},
        "dns":{"servers":[{"type":"fakeip","tag":"fake","inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"},
            {"type":"hosts","tag":"hosts","path":[],"predefined":{}}],"final":"hosts"},
        "experimental":{"cache_file":{"enabled":true,"store_fakeip":true,"flush_interval":"1s","path":path}}});
    let instance = core_runtime::start(&root).await.unwrap();
    let dns = core_runtime::dns::current().unwrap();
    let store = dns.fakeip_stores().pop().unwrap();
    let allocated = store.create("saved.example", false).unwrap();
    tokio::time::sleep(std::time::Duration::from_millis(1200)).await;
    let on_disk = CacheFile::open(CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    })
    .unwrap()
    .unwrap();
    let IpAddr::V4(address) = allocated else {
        panic!("IPv4 allocation")
    };
    assert_eq!(
        on_disk.get("fakeip_address", &address.octets()).as_deref(),
        Some(b"saved.example".as_slice())
    );
    for network in ["tcp", "udp"] {
        for ip in ["198.18.1.50", "fc00::123"] {
            let mut ctx = ConnContext::new(
                "test",
                "127.0.0.1:12345".parse().unwrap(),
                Target::Ip(
                    format!(
                        "{}:443",
                        if ip.contains(':') {
                            format!("[{ip}]")
                        } else {
                            ip.into()
                        }
                    )
                    .parse()
                    .unwrap(),
                ),
                network,
            );
            let error = instance.router().route_raw(&mut ctx).await.unwrap_err();
            assert_eq!(error.kind(), std::io::ErrorKind::NotFound);
            assert_eq!(error.to_string(), "missing fakeip record");
        }
    }
    instance.shutdown_wait().await;
    let instance = core_runtime::start(&root).await.unwrap();
    assert_eq!(
        core_runtime::dns::current()
            .unwrap()
            .fakeip_domain(allocated)
            .as_deref(),
        Some("saved.example")
    );
    instance.shutdown_wait().await;
    std::fs::remove_file(path).unwrap();
}

#[test]
fn go_metadata_cursor_and_wrap_preserve_paired_records() {
    let path =
        std::env::temp_dir().join(format!("rust-x-fakeip-go-meta-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let options = CacheFileOptions {
        enabled: true,
        store_fakeip: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    // Go adapter.FakeIPMetadata: uint16 BE lengths followed by netip
    // prefix/address binary encodings. IPv6 is an invalid/absent prefix.
    let metadata = vec![
        0, 5, 198, 18, 0, 0, 15, 0, 1, 255, 0, 4, 198, 18, 0, 200, 0, 0,
    ];
    cache
        .lock()
        .unwrap()
        .put("fakeip_address", b"fakeip_metadata", metadata);
    let imported = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/15").unwrap()), None);
    imported.attach_cache(Some(cache.clone()));
    assert_eq!(
        imported.create("next.example", false).unwrap(),
        "198.18.0.201".parse::<IpAddr>().unwrap()
    );
    let small = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/30").unwrap()), None);
    small.attach_cache(Some(cache.clone()));
    let old = small.create("old.example", false).unwrap();
    let new = small.create("new.example", false).unwrap();
    assert_eq!(old, new);
    assert_eq!(small.lookup_address("old.example", false), None);
    assert_eq!(small.lookup_domain(new).as_deref(), Some("new.example"));
    cache.lock().unwrap().flush().unwrap();
    drop((small, imported, cache));
    let cache = Arc::new(Mutex::new(CacheFile::open(options).unwrap().unwrap()));
    let reopened = FakeIpStore::new(Some(IpPrefix::parse("198.18.0.0/30").unwrap()), None);
    reopened.attach_cache(Some(cache));
    assert_eq!(reopened.lookup_domain(new).as_deref(), Some("new.example"));
    assert_eq!(reopened.lookup_address("old.example", false), None);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn lru_eviction_removes_both_reverse_maps_without_persistent_cache() {
    let store = pool();
    let first4 = store.create("first.example", false).unwrap();
    let first6 = store.create("first.example", true).unwrap();
    for index in 0..16384 {
        let domain = format!("eviction-{index}.example");
        store.create(&domain, false).unwrap();
        store.create(&domain, true).unwrap();
    }
    assert_eq!(store.lookup_address("first.example", false), None);
    assert_eq!(store.lookup_address("first.example", true), None);
    assert_eq!(store.lookup_domain(first4), None);
    assert_eq!(store.lookup_domain(first6), None);
    let last = "eviction-16383.example";
    let address = store.lookup_address(last, false).unwrap();
    assert_eq!(store.lookup_domain(address).as_deref(), Some(last));
}

#[test]
fn startup_repairs_missing_reverse_and_removes_corrupt_orphan_records() {
    let path = std::env::temp_dir().join(format!("rust-x-repair-{}.db", std::process::id()));
    let options = CacheFileOptions {
        enabled: true,
        store_fakeip: true,
        path: path.to_string_lossy().into_owned(),
        ..Default::default()
    };
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    {
        let mut file = cache.lock().unwrap();
        file.put("fakeip_domain4", b"restored.example", vec![198, 18, 0, 12]);
        file.put(
            "fakeip_domain4",
            b"wrong-family.example",
            "fc00::a"
                .parse::<std::net::Ipv6Addr>()
                .unwrap()
                .octets()
                .to_vec(),
        );
        file.put(
            "fakeip_address",
            &[198, 18, 0, 13],
            b"orphan.example".to_vec(),
        );
        file.put(
            "fakeip_address",
            b"invalid-key",
            b"garbage.example".to_vec(),
        );
        file.flush().unwrap();
    }
    let store = pool();
    store.attach_cache(Some(cache.clone()));
    assert_eq!(
        store
            .lookup_domain("198.18.0.12".parse().unwrap())
            .as_deref(),
        Some("restored.example")
    );
    assert!(
        store
            .lookup_address("wrong-family.example", false)
            .is_none()
    );
    {
        let mut file = cache.lock().unwrap();
        assert!(file.get("fakeip_address", &[198, 18, 0, 13]).is_none());
        assert!(file.get("fakeip_address", b"invalid-key").is_none());
        file.flush().unwrap();
    }
    drop((store, cache));
    let cache = Arc::new(Mutex::new(CacheFile::open(options).unwrap().unwrap()));
    let reopened = pool();
    reopened.attach_cache(Some(cache));
    assert_eq!(
        reopened
            .lookup_domain("198.18.0.12".parse().unwrap())
            .as_deref(),
        Some("restored.example")
    );
    drop(reopened);
    std::fs::remove_file(path).unwrap();
}

#[test]
fn persistent_lru_eviction_deletes_both_records_and_preserves_other_family() {
    let path = std::env::temp_dir().join(format!("rust-x-evict-disk-{}.db", std::process::id()));
    let cache = Arc::new(Mutex::new(
        CacheFile::open(CacheFileOptions {
            enabled: true,
            store_fakeip: true,
            path: path.to_string_lossy().into_owned(),
            flush_interval: std::time::Duration::from_secs(3600),
            ..Default::default()
        })
        .unwrap()
        .unwrap(),
    ));
    let store = pool();
    store.attach_cache(Some(cache.clone()));
    let old4 = store.create("first.example", false).unwrap();
    let old6 = store.create("first.example", true).unwrap();
    for n in 0..16384 {
        store.create(&format!("new-{n}.example"), false).unwrap();
    }
    let file = cache.lock().unwrap();
    assert!(file.get("fakeip_domain4", b"first.example").is_none());
    let IpAddr::V4(addr) = old4 else { panic!() };
    assert!(file.get("fakeip_address", &addr.octets()).is_none());
    assert_eq!(store.lookup_domain(old6).as_deref(), Some("first.example"));
    drop(file);
    cache.lock().unwrap().flush().unwrap();
    drop((store, cache));
    std::fs::remove_file(path).unwrap();
}

fn reload_cache(name: &str) -> (std::path::PathBuf, CacheFileOptions) {
    let path = std::env::temp_dir().join(format!("rust-x-{name}-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let options = CacheFileOptions {
        enabled: true,
        store_fakeip: true,
        path: path.to_string_lossy().into_owned(),
        // only the explicit flush below writes the file
        flush_interval: std::time::Duration::from_secs(3600),
        ..Default::default()
    };
    (path, options)
}

fn assert_pair(cache: &Mutex<CacheFile>, domain: &str, ip: IpAddr) {
    let (bucket, address) = match ip {
        IpAddr::V4(ip) => ("fakeip_domain4", ip.octets().to_vec()),
        IpAddr::V6(ip) => ("fakeip_domain6", ip.octets().to_vec()),
    };
    let file = cache.lock().unwrap();
    assert_eq!(
        file.get(bucket, domain.as_bytes()),
        Some(address.clone()),
        "forward record of {domain}"
    );
    assert_eq!(
        file.get("fakeip_address", &address),
        Some(domain.as_bytes().to_vec()),
        "reverse record of {ip}"
    );
}

// A hot reload migrates the pool from memory and then attaches the same cache.
// Names already in memory must keep their records on disk, so a restart after
// the reload still finds them.
#[test]
fn hot_reload_keeps_fakeip_records_on_disk() {
    let (path, options) = reload_cache("fakeip-reload");
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    let old = pool();
    old.attach_cache(Some(cache.clone()));
    let names = ["a.example", "b.example", "c.example"];
    let mut assigned = Vec::new();
    for name in names {
        assigned.push((name, old.create(name, false).unwrap()));
        assigned.push((name, old.create(name, true).unwrap()));
    }

    // the order of `BoxInstance::reload_in_place`
    let reloaded = pool();
    reloaded.migrate_from(&old);
    reloaded.attach_cache(Some(cache.clone()));
    for &(name, ip) in &assigned {
        assert_eq!(reloaded.create(name, ip.is_ipv6()).unwrap(), ip);
        assert_pair(&cache, name, ip);
    }
    cache.lock().unwrap().flush().unwrap();
    drop((old, reloaded, cache));

    let cache = Arc::new(Mutex::new(CacheFile::open(options).unwrap().unwrap()));
    for &(name, ip) in &assigned {
        assert_pair(&cache, name, ip);
    }
    let restarted = pool();
    restarted.attach_cache(Some(cache.clone()));
    for &(name, ip) in &assigned {
        assert_eq!(restarted.lookup_domain(ip).as_deref(), Some(name));
        assert_eq!(restarted.lookup_address(name, ip.is_ipv6()), Some(ip));
    }
    // the cursors carry on after the last address of each family
    assert_eq!(
        restarted.create("d.example", false).unwrap(),
        "198.18.0.5".parse::<IpAddr>().unwrap()
    );
    assert_eq!(
        restarted.create("d.example", true).unwrap(),
        "fc00::5".parse::<IpAddr>().unwrap()
    );
    drop((restarted, cache));
    std::fs::remove_file(path).unwrap();
}

// When the disk holds a different address for a name the migrated memory
// already knows, the disk pair wins and the old address is released.
#[test]
fn hot_reload_prefers_the_disk_address_of_a_known_name() {
    let (path, options) = reload_cache("fakeip-reload-replace");
    let cache = Arc::new(Mutex::new(
        CacheFile::open(options.clone()).unwrap().unwrap(),
    ));
    let memory_only = pool();
    let stale = memory_only.create("moved.example", false).unwrap();
    let disk: IpAddr = "198.18.0.9".parse().unwrap();
    {
        let mut file = cache.lock().unwrap();
        file.put("fakeip_domain4", b"moved.example", vec![198, 18, 0, 9]);
        file.put(
            "fakeip_address",
            &[198, 18, 0, 9],
            b"moved.example".to_vec(),
        );
    }
    let reloaded = pool();
    reloaded.migrate_from(&memory_only);
    reloaded.attach_cache(Some(cache.clone()));
    assert_eq!(reloaded.lookup_address("moved.example", false), Some(disk));
    assert_eq!(
        reloaded.lookup_domain(disk).as_deref(),
        Some("moved.example")
    );
    assert_eq!(reloaded.lookup_domain(stale), None);
    assert_pair(&cache, "moved.example", disk);
    cache.lock().unwrap().flush().unwrap();
    drop((memory_only, reloaded, cache));
    let cache = Arc::new(Mutex::new(CacheFile::open(options).unwrap().unwrap()));
    assert_pair(&cache, "moved.example", disk);
    drop(cache);
    std::fs::remove_file(path).unwrap();
}
