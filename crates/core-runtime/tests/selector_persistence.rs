use core_runtime::route::Outbound;
use serde_json::{Value, json};

fn selected(instance: &core_runtime::BoxInstance, tag: &str) -> String {
    let inner = instance.router().inner();
    let (_, _, outbound) = inner
        .outbound_table()
        .find(|(_, name, _)| *name == tag)
        .unwrap();
    let Outbound::Selector(group) = outbound else {
        panic!("not a selector");
    };
    group.now().to_owned()
}

#[tokio::test]
async fn manual_choices_survive_restart_and_reload_with_safe_fallbacks() {
    let path = std::env::temp_dir().join(format!("xrust-selectors-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut config = json!({
        "outbounds": [
            {"type":"direct", "tag":"a"},
            {"type":"direct", "tag":"b"},
            {"type":"selector", "tag":"youtube", "outbounds":["a","b"], "default":"a"},
            {"type":"selector", "tag":"discord", "outbounds":["a","b"], "default":"a"}
        ],
        "route":{"final":"youtube"},
        "experimental":{"cache_file":{"enabled":true,"path":path}}
    });
    // Simulate an old cache containing a long history of renamed groups,
    // removed members, malformed keys and unrelated buckets.
    let options =
        core_runtime::cache_file::CacheFileOptions::from_config(config.get("experimental"))
            .unwrap();
    let mut seeded = core_runtime::cache_file::CacheFile::open(options.clone())
        .unwrap()
        .unwrap();
    for index in 0..2000 {
        seeded.put(
            core_runtime::cache_file::BUCKET_SELECTED,
            format!("retired-{index}").as_bytes(),
            b"b".to_vec(),
        );
    }
    seeded.put(
        core_runtime::cache_file::BUCKET_SELECTED,
        b"youtube",
        b"removed-member".to_vec(),
    );
    seeded.put(
        core_runtime::cache_file::BUCKET_SELECTED,
        &[0xff],
        b"b".to_vec(),
    );
    seeded.put(
        core_runtime::cache_file::BUCKET_MODE,
        b"test-marker",
        b"keep".to_vec(),
    );
    seeded.flush().unwrap();
    drop(seeded);
    let mut instance = core_runtime::start(&config).await.unwrap();
    let pruned = core_runtime::cache_file::CacheFile::open(options.clone())
        .unwrap()
        .unwrap();
    assert!(
        pruned
            .raw_keys(core_runtime::cache_file::BUCKET_SELECTED)
            .is_empty()
    );
    assert_eq!(
        pruned.get(core_runtime::cache_file::BUCKET_MODE, b"test-marker"),
        Some(b"keep".to_vec())
    );
    drop(pruned);
    instance.router().select_member("youtube", "b").unwrap();
    instance.router().select_member("discord", "b").unwrap();
    assert!(
        instance
            .router()
            .select_member("youtube", "missing")
            .is_err()
    );
    // Read from disk before shutdown: an accepted API selection is durable.
    let store = core_runtime::cache_file::CacheFile::open(
        core_runtime::cache_file::CacheFileOptions::from_config(config.get("experimental"))
            .unwrap(),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        store.get(core_runtime::cache_file::BUCKET_SELECTED, b"youtube"),
        Some(b"b".to_vec())
    );
    drop(store);
    instance.shutdown_wait().await;
    instance = core_runtime::start(&config).await.unwrap();
    assert_eq!(selected(&instance, "youtube"), "b");
    assert_eq!(selected(&instance, "discord"), "b");
    // Array reordering must not reinterpret the cached member as an index.
    config["outbounds"][2]["outbounds"] = json!(["b", "a"]);
    instance.reload_in_place(&config).await.unwrap();
    instance.router().select_member("youtube", "a").unwrap();
    instance.shutdown_wait().await;
    instance = core_runtime::start(&config).await.unwrap();
    assert_eq!(selected(&instance, "youtube"), "a");
    assert_eq!(selected(&instance, "discord"), "b");
    instance.shutdown_wait().await;
    // Repeated hot reloads with changing group names must not accumulate keys.
    instance = core_runtime::start(&config).await.unwrap();
    for index in 0..40 {
        let tag = format!("discord-{index}");
        config["outbounds"][3]["tag"] = json!(tag);
        instance.reload_in_place(&config).await.unwrap();
        instance.router().select_member(&tag, "b").unwrap();
        let disk = core_runtime::cache_file::CacheFile::open(options.clone())
            .unwrap()
            .unwrap();
        let mut keys = disk.keys(core_runtime::cache_file::BUCKET_SELECTED);
        keys.sort();
        assert_eq!(keys, vec![tag, "youtube".to_owned()]);
    }
    config["outbounds"][3]["tag"] = json!("discord");
    instance.reload_in_place(&config).await.unwrap();
    instance.router().select_member("discord", "b").unwrap();
    instance.shutdown_wait().await;
    // A removed member falls back to the configured default.
    config["outbounds"][3]["outbounds"] = json!(["a"]);
    instance = core_runtime::start(&config).await.unwrap();
    assert_eq!(selected(&instance, "discord"), "a");
    instance.shutdown_wait().await;
    // With caching disabled, a new process uses defaults.
    config["experimental"]["cache_file"]["enabled"] = Value::Bool(false);
    instance = core_runtime::start(&config).await.unwrap();
    instance.router().select_member("youtube", "b").unwrap();
    instance.shutdown_wait().await;
    instance = core_runtime::start(&config).await.unwrap();
    assert_eq!(selected(&instance, "youtube"), "a");
    instance.shutdown_wait().await;
    std::fs::remove_file(path).unwrap();
}
