//! A damaged cache.db must give an error, not a stack overflow, a hang or a
//! huge allocation. Each file is built page by page.

use std::io;
use std::path::PathBuf;
use std::sync::mpsc;
use std::time::Duration;

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

/// A file of `pages` zeroed pages with both meta pages set.
fn image(ps: usize, pages: usize, root: u64, high_water: u64) -> Vec<u8> {
    let mut f = vec![0u8; ps * pages];
    for id in 0..2u64 {
        let o = id as usize * ps;
        f[o..o + 8].copy_from_slice(&id.to_le_bytes());
        f[o + 8..o + 10].copy_from_slice(&4u16.to_le_bytes());
        let m = o + 16;
        f[m..m + 4].copy_from_slice(&0xED0C_DAEDu32.to_le_bytes());
        f[m + 4..m + 8].copy_from_slice(&2u32.to_le_bytes());
        f[m + 8..m + 12].copy_from_slice(&(ps as u32).to_le_bytes());
        f[m + 16..m + 24].copy_from_slice(&root.to_le_bytes());
        f[m + 32..m + 40].copy_from_slice(&u64::MAX.to_le_bytes());
        f[m + 40..m + 48].copy_from_slice(&high_water.to_le_bytes());
        f[m + 48..m + 56].copy_from_slice(&id.to_le_bytes());
        let sum = fnv1a64(&f[m..m + 56]);
        f[m + 56..m + 64].copy_from_slice(&sum.to_le_bytes());
    }
    f
}

fn header(f: &mut [u8], ps: usize, id: u64, flags: u16, count: usize, overflow: u32) -> usize {
    let base = id as usize * ps;
    f[base..base + 8].copy_from_slice(&id.to_le_bytes());
    f[base + 8..base + 10].copy_from_slice(&flags.to_le_bytes());
    f[base + 10..base + 12].copy_from_slice(&(count as u16).to_le_bytes());
    f[base + 12..base + 16].copy_from_slice(&overflow.to_le_bytes());
    base
}

/// A branch page whose children are `children`, keyed by their index.
fn branch(f: &mut [u8], ps: usize, id: u64, children: &[u64]) {
    let base = header(f, ps, id, 0x01, children.len(), 0);
    let keys = base + 16 + 16 * children.len();
    for (i, child) in children.iter().enumerate() {
        let e = base + 16 + 16 * i;
        let data = keys + i;
        f[e..e + 4].copy_from_slice(&((data - e) as u32).to_le_bytes());
        f[e + 4..e + 8].copy_from_slice(&1u32.to_le_bytes());
        f[e + 8..e + 16].copy_from_slice(&child.to_le_bytes());
        f[data] = i as u8;
    }
}

/// A leaf page of `(flags, key, value)` elements.
fn leaf(f: &mut [u8], ps: usize, id: u64, elems: &[(u32, &[u8], &[u8])]) {
    let base = header(f, ps, id, 0x02, elems.len(), 0);
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

/// The value of a bucket element whose root is page `root`.
fn bucket(root: u64) -> [u8; 16] {
    let mut v = [0u8; 16];
    v[0..8].copy_from_slice(&root.to_le_bytes());
    v
}

fn save(tag: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("bbolt-corrupt-{tag}-{}.db", std::process::id()));
    std::fs::write(&path, bytes).unwrap();
    path
}

fn open(tag: &str, bytes: &[u8]) -> Db {
    let path = save(tag, bytes);
    let db = Db::open(&path).expect("meta pages are valid");
    std::fs::remove_file(path).unwrap();
    db
}

fn assert_invalid<T: std::fmt::Debug>(result: io::Result<T>, needle: &str) {
    let error = result.expect_err("a damaged tree must be an error");
    assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    assert!(error.to_string().contains(needle), "{error}");
}

/// Every reader entry point over the root tree fails cleanly.
fn assert_root_rejected(db: &Db, needle: &str) {
    assert_invalid(db.bucket_names(), needle);
    assert_invalid(db.has_bucket(&["b"]), needle);
    assert_invalid(db.get(&["b"], b"k"), needle);
    assert_invalid(db.bucket_page_raw(&["b"]), needle);
}

/// Run `f` on a thread, failing instead of hanging if it does not finish.
fn bounded<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = mpsc::channel();
    std::thread::Builder::new()
        .stack_size(512 * 1024)
        .spawn(move || {
            let _ = tx.send(f());
        })
        .unwrap();
    rx.recv_timeout(Duration::from_secs(20))
        .expect("the reader did not finish in 20 s")
}

#[test]
fn self_referencing_branch_is_an_error() {
    let mut f = image(PS, 3, 2, 3);
    branch(&mut f, PS, 2, &[2]);
    let db = open("self", &f);
    bounded(move || assert_root_rejected(&db, "reached twice"));
}

#[test]
fn page_cycle_inside_a_bucket_is_an_error() {
    let mut f = image(PS, 5, 2, 5);
    leaf(&mut f, PS, 2, &[(1, b"b", &bucket(3))]);
    branch(&mut f, PS, 3, &[4]);
    branch(&mut f, PS, 4, &[3]);
    let db = open("cycle", &f);
    bounded(move || {
        assert_eq!(db.bucket_names().unwrap(), vec!["b".to_string()]);
        assert!(db.has_bucket(&["b"]).unwrap());
        assert_invalid(db.get(&["b"], b"k"), "reached twice");
        assert_invalid(db.bucket_page_raw(&["b"]), "reached twice");
        assert_invalid(db.has_bucket(&["b", "c"]), "reached twice");
    });
}

#[test]
fn child_page_ids_outside_the_tree_are_errors() {
    // pages 3 and 4 are well formed leaves, but past the high water mark
    let high_water = 3;
    let cases = [
        (u64::MAX / PS as u64, "high water mark"),
        (u64::MAX, "high water mark"),
        (0, "meta page"),
        (1, "meta page"),
        (high_water, "high water mark"),
        (high_water + 1, "high water mark"),
        (99, "high water mark"),
    ];
    for (child, needle) in cases {
        let mut f = image(PS, 5, 2, high_water);
        branch(&mut f, PS, 2, &[child]);
        leaf(&mut f, PS, 3, &[(1, b"b", &bucket(4))]);
        leaf(&mut f, PS, 4, &[(0, b"k", b"v")]);
        let db = open("bounds", &f);
        assert_root_rejected(&db, needle);
    }
    // the same pages as a bucket root
    let mut f = image(PS, 5, 2, high_water);
    leaf(&mut f, PS, 2, &[(1, b"b", &bucket(4))]);
    leaf(&mut f, PS, 4, &[(0, b"k", b"v")]);
    let db = open("bounds-bucket", &f);
    assert_invalid(db.get(&["b"], b"k"), "high water mark");
    assert_invalid(db.has_bucket(&["b"]), "high water mark");
}

#[test]
fn overflow_past_the_high_water_mark_is_an_error() {
    let mut f = image(PS, 4, 2, 3);
    leaf(&mut f, PS, 2, &[(0, b"k", b"v")]);
    f[2 * PS + 12..2 * PS + 16].copy_from_slice(&1u32.to_le_bytes());
    let db = open("overflow-hw", &f);
    assert_invalid(db.bucket_names(), "overflow above high water mark");
    // a huge overflow count is refused before it is read
    f[2 * PS + 12..2 * PS + 16].copy_from_slice(&u32::MAX.to_le_bytes());
    let db = open("overflow-max", &f);
    assert_invalid(db.bucket_names(), "overflow above high water mark");
}

#[test]
fn root_on_a_meta_page_is_refused_at_open() {
    let f = image(PS, 3, 1, 3);
    let path = save("meta-root", &f);
    let error = Db::open(&path).err().expect("root 1 is a meta page");
    std::fs::remove_file(path).unwrap();
    assert_eq!(error.kind(), io::ErrorKind::InvalidData);
}

/// Each branch points twice at the next one: 2^40 paths over 41 pages.
#[test]
fn shared_subtrees_fail_fast() {
    let levels = 40u64;
    let mut f = image(PS, levels as usize + 3, 2, levels + 3);
    for id in 2..2 + levels {
        branch(&mut f, PS, id, &[id + 1, id + 1]);
    }
    leaf(&mut f, PS, 2 + levels, &[]);
    let db = open("dag", &f);
    bounded(move || assert_root_rejected(&db, "reached twice"));
}

#[test]
fn a_page_inside_another_pages_overflow_is_an_error() {
    let mut f = image(PS, 5, 2, 5);
    branch(&mut f, PS, 2, &[3, 4]);
    leaf(&mut f, PS, 3, &[(0, b"a", b"1")]);
    f[3 * PS + 12..3 * PS + 16].copy_from_slice(&1u32.to_le_bytes());
    leaf(&mut f, PS, 4, &[(0, b"b", b"2")]);
    let db = open("overflow-overlap", &f);
    assert_invalid(db.bucket_names(), "page 4 reached twice");
}

/// A chain of single-child branches, `levels` deep, over 256-byte pages.
fn chain(levels: u64) -> Vec<u8> {
    let ps = 256;
    let mut f = image(ps, levels as usize + 3, 2, levels + 3);
    for id in 2..2 + levels {
        branch(&mut f, ps, id, &[id + 1]);
    }
    leaf(&mut f, ps, 2 + levels, &[(1, b"b", &bucket(0))]);
    f
}

#[test]
fn deep_page_chains_are_bounded() {
    // distinct pages, so only the depth bound stops this one
    let db = open("depth-20000", &chain(20_000));
    bounded(move || assert_root_rejected(&db, "too deep"));
    // 64 branch levels is the limit; real cache files are 1-3 deep
    let db = open("depth-64", &chain(64));
    assert_eq!(db.bucket_names().unwrap(), vec!["b".to_string()]);
    let db = open("depth-65", &chain(65));
    assert_root_rejected(&db, "too deep");
}

#[test]
fn overlapping_elements_are_an_error() {
    // 200 elements all pointing at one 800-byte value
    let mut f = image(PS, 3, 2, 3);
    let base = header(&mut f, PS, 2, 0x02, 200, 0);
    let data = base + 16 + 16 * 200;
    for i in 0..200 {
        let e = base + 16 + 16 * i;
        f[e + 4..e + 8].copy_from_slice(&((data - e) as u32).to_le_bytes());
        f[e + 8..e + 12].copy_from_slice(&1u32.to_le_bytes());
        f[e + 12..e + 16].copy_from_slice(&800u32.to_le_bytes());
    }
    let db = open("overlap", &f);
    assert_invalid(db.bucket_names(), "overlap");
}

#[test]
fn element_count_past_the_page_is_an_error() {
    let mut f = image(PS, 3, 2, 3);
    header(&mut f, PS, 2, 0x02, u16::MAX as usize, 0);
    let db = open("count", &f);
    assert_invalid(db.bucket_names(), "element table");
}
