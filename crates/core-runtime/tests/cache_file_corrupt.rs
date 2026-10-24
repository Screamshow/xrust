//! A damaged cache.db must not stop the store from opening, and opening it
//! must not touch the file.

use std::path::{Path, PathBuf};
use std::time::Duration;

use core_runtime::cache_file::{BUCKET_FAKEIP, BUCKET_SELECTED, CacheFile, CacheFileOptions};

const PS: usize = 4096;

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// `pages` zeroed pages with both meta pages pointing at root page 2.
fn image(pages: usize) -> Vec<u8> {
    let mut f = vec![0u8; PS * pages];
    for id in 0..2u64 {
        let o = id as usize * PS;
        f[o..o + 8].copy_from_slice(&id.to_le_bytes());
        f[o + 8..o + 10].copy_from_slice(&4u16.to_le_bytes());
        let m = o + 16;
        f[m..m + 4].copy_from_slice(&0xED0C_DAEDu32.to_le_bytes());
        f[m + 4..m + 8].copy_from_slice(&2u32.to_le_bytes());
        f[m + 8..m + 12].copy_from_slice(&(PS as u32).to_le_bytes());
        f[m + 16..m + 24].copy_from_slice(&2u64.to_le_bytes());
        f[m + 32..m + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        f[m + 40..m + 48].copy_from_slice(&(pages as u64).to_le_bytes());
        f[m + 48..m + 56].copy_from_slice(&id.to_le_bytes());
        let sum = fnv1a64(&f[m..m + 56]);
        f[m + 56..m + 64].copy_from_slice(&sum.to_le_bytes());
    }
    f
}

/// A branch page whose only child is itself.
fn self_branch(f: &mut [u8], id: u64) {
    let base = id as usize * PS;
    f[base..base + 8].copy_from_slice(&id.to_le_bytes());
    f[base + 8..base + 10].copy_from_slice(&1u16.to_le_bytes());
    f[base + 10..base + 12].copy_from_slice(&1u16.to_le_bytes());
    let e = base + 16;
    f[e..e + 4].copy_from_slice(&16u32.to_le_bytes());
    f[e + 4..e + 8].copy_from_slice(&1u32.to_le_bytes());
    f[e + 8..e + 16].copy_from_slice(&id.to_le_bytes());
    f[e + 16] = b'x';
}

/// A leaf page of `(flags, key, value)` elements.
fn leaf(f: &mut [u8], id: u64, elems: &[(u32, &[u8], &[u8])]) {
    let base = id as usize * PS;
    f[base..base + 8].copy_from_slice(&id.to_le_bytes());
    f[base + 8..base + 10].copy_from_slice(&2u16.to_le_bytes());
    f[base + 10..base + 12].copy_from_slice(&(elems.len() as u16).to_le_bytes());
    let mut data = base + 16 + 16 * elems.len();
    for (i, (flags, key, value)) in elems.iter().enumerate() {
        let e = base + 16 + 16 * i;
        f[e..e + 4].copy_from_slice(&flags.to_le_bytes());
        f[e + 4..e + 8].copy_from_slice(&((data - e) as u32).to_le_bytes());
        f[e + 8..e + 12].copy_from_slice(&(key.len() as u32).to_le_bytes());
        f[e + 12..e + 16].copy_from_slice(&(value.len() as u32).to_le_bytes());
        f[data..data + key.len()].copy_from_slice(key);
        data += key.len();
        f[data..data + value.len()].copy_from_slice(value);
        data += value.len();
    }
}

fn bucket(root: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&root.to_le_bytes());
    v
}

fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("cache-corrupt-{tag}-{}.db", std::process::id()))
}

fn options(path: &Path, cache_id: &str) -> CacheFileOptions {
    CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        cache_id: cache_id.into(),
        store_fakeip: true,
        flush_interval: Duration::from_secs(3600),
        ..Default::default()
    }
}

#[test]
fn page_cycle_at_the_root_starts_empty_and_keeps_the_file() {
    let mut f = image(3);
    self_branch(&mut f, 2);
    for cache_id in ["", "some-id"] {
        let path = temp_path(if cache_id.is_empty() {
            "root"
        } else {
            "root-id"
        });
        std::fs::write(&path, &f).unwrap();
        let store = CacheFile::open(options(&path, cache_id))
            .expect("a damaged file must not fail the open")
            .expect("store");
        assert!(store.raw_keys(BUCKET_SELECTED).is_empty());
        assert_eq!(std::fs::read(&path).unwrap(), f, "open must not rewrite");
        drop(store);
        assert_eq!(std::fs::read(&path).unwrap(), f, "drop must not rewrite");
        std::fs::remove_file(&path).unwrap();
    }
}

#[test]
fn damaged_bucket_is_skipped_and_the_rest_loads() {
    let mut f = image(5);
    leaf(
        &mut f,
        2,
        &[
            (1, BUCKET_FAKEIP.as_bytes(), &bucket(3)),
            (1, BUCKET_SELECTED.as_bytes(), &bucket(4)),
        ],
    );
    self_branch(&mut f, 3);
    leaf(&mut f, 4, &[(0, b"group", b"node")]);
    let path = temp_path("bucket");
    std::fs::write(&path, &f).unwrap();
    let store = CacheFile::open(options(&path, ""))
        .expect("open")
        .expect("store");
    assert_eq!(store.get(BUCKET_SELECTED, b"group"), Some(b"node".to_vec()));
    assert!(store.raw_keys(BUCKET_FAKEIP).is_empty());
    drop(store);
    assert_eq!(std::fs::read(&path).unwrap(), f, "the file stays as it was");
    std::fs::remove_file(&path).unwrap();
}
