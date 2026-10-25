//! A clash mode saved in cache.db comes back at start. Its own test binary:
//! the mode is process-global and must start as `rule` here.

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;

use core_runtime::cache_file::{BUCKET_MODE, CacheFile, CacheFileOptions};
use core_runtime::clash_mode;

#[test]
fn a_saved_mode_is_restored_without_relocking_the_store() {
    let path = std::env::temp_dir().join(format!("xrust-clash-mode-{}.db", std::process::id()));
    let options = CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        flush_interval: Duration::from_secs(3600),
        ..CacheFileOptions::default()
    };
    let mut store = CacheFile::open(options).unwrap().unwrap();
    store.put(BUCKET_MODE, b"mode", clash_mode::GLOBAL.as_bytes().to_vec());
    let store = Arc::new(Mutex::new(store));
    assert_eq!(clash_mode::get(), clash_mode::RULE);

    let (done, finished) = mpsc::channel();
    let handle = Arc::clone(&store);
    std::thread::spawn(move || {
        clash_mode::attach_store(Some(handle));
        let _ = done.send(());
    });
    finished
        .recv_timeout(Duration::from_secs(10))
        .expect("attach_store hung or panicked on a saved non-default mode");

    assert_eq!(clash_mode::get(), clash_mode::GLOBAL);
    assert_eq!(
        store.lock().unwrap().get(BUCKET_MODE, b"mode"),
        Some(b"global".to_vec())
    );
    let _ = std::fs::remove_file(&path);
}
