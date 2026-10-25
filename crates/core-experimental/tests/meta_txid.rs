//! bbolt writes each commit to one of two meta pages in turn; the reader must
//! use the valid one with the higher txid, as the reference `db.meta()` does.

use std::path::PathBuf;

use core_experimental::bbolt::Db;

const PS: usize = 4096;

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn meta(f: &mut [u8], id: u64, root: u64, txid: u64) {
    let o = id as usize * PS;
    f[o..o + 8].copy_from_slice(&id.to_le_bytes());
    f[o + 8..o + 10].copy_from_slice(&4u16.to_le_bytes());
    let m = o + 16;
    f[m..m + 4].copy_from_slice(&0xED0C_DAEDu32.to_le_bytes());
    f[m + 4..m + 8].copy_from_slice(&2u32.to_le_bytes());
    f[m + 8..m + 12].copy_from_slice(&(PS as u32).to_le_bytes());
    f[m + 16..m + 24].copy_from_slice(&root.to_le_bytes());
    f[m + 32..m + 40].copy_from_slice(&u64::MAX.to_le_bytes());
    f[m + 40..m + 48].copy_from_slice(&6u64.to_le_bytes());
    f[m + 48..m + 56].copy_from_slice(&txid.to_le_bytes());
    let sum = fnv1a64(&f[m..m + 56]);
    f[m + 56..m + 64].copy_from_slice(&sum.to_le_bytes());
}

/// A one-element leaf page; `flags` 1 makes `value` a bucket header.
fn leaf(f: &mut [u8], id: u64, flags: u32, key: &[u8], value: &[u8]) {
    let b = id as usize * PS;
    f[b..b + 8].copy_from_slice(&id.to_le_bytes());
    f[b + 8..b + 10].copy_from_slice(&2u16.to_le_bytes());
    f[b + 10..b + 12].copy_from_slice(&1u16.to_le_bytes());
    let e = b + 16;
    f[e..e + 4].copy_from_slice(&flags.to_le_bytes());
    f[e + 4..e + 8].copy_from_slice(&16u32.to_le_bytes());
    f[e + 8..e + 12].copy_from_slice(&(key.len() as u32).to_le_bytes());
    f[e + 12..e + 16].copy_from_slice(&(value.len() as u32).to_le_bytes());
    let d = e + 16;
    f[d..d + key.len()].copy_from_slice(key);
    f[d + key.len()..d + key.len() + value.len()].copy_from_slice(value);
}

/// Two committed trees: root 2 holds `b/k = old`, root 3 holds `b/k = new`.
/// `meta0` and `meta1` are each a `(root, txid)` pair.
fn read(tag: &str, meta0: (u64, u64), meta1: (u64, u64), tear1: bool) -> Vec<u8> {
    let mut f = vec![0u8; PS * 6];
    for (root, child, value) in [(2u64, 4u64, b"old"), (3, 5, b"new")] {
        let mut bucket = [0u8; 16];
        bucket[..8].copy_from_slice(&child.to_le_bytes());
        leaf(&mut f, root, 1, b"b", &bucket);
        leaf(&mut f, child, 0, b"k", value);
    }
    meta(&mut f, 0, meta0.0, meta0.1);
    meta(&mut f, 1, meta1.0, meta1.1);
    if tear1 {
        f[PS + 16 + 60] ^= 0xff;
    }
    let name = format!("bbolt-meta-{tag}-{}.db", std::process::id());
    let path: PathBuf = std::env::temp_dir().join(name);
    std::fs::write(&path, &f).unwrap();
    let value = Db::open(&path).unwrap().get(&["b"], b"k").unwrap().unwrap();
    std::fs::remove_file(path).unwrap();
    value
}

#[test]
fn the_newer_meta_page_wins() {
    // meta 1 newer: what a Go file looks like after an odd-numbered commit
    assert_eq!(read("meta1", (2, 2), (3, 3), false), b"new");
    // meta 0 newer
    assert_eq!(read("meta0", (3, 5), (2, 4), false), b"new");
    // a torn newer meta falls back to the older valid one
    assert_eq!(read("torn", (2, 2), (3, 3), true), b"old");
}
