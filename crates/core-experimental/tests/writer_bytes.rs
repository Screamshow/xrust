//! The writer's output is pinned to what it produced before it switched to a
//! borrowed tree: same pages, same order, same bytes.

use core_experimental::bbolt::{Db, EntrySpec, NodeSpec};

fn fnv1a64(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in data {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_add(seed)).collect()
}

/// Unsorted input, nested and empty buckets, a sequence, overflow values,
/// binary keys and a bucket wide enough for a branch of branches.
fn tree() -> NodeSpec {
    let wide = NodeSpec {
        entries: (0..120u32)
            .rev()
            .map(|i| {
                EntrySpec::Kv(
                    format!("{i:04}-{}", "k".repeat(200)),
                    pattern(1800, i as u8),
                )
            })
            .collect(),
    };
    let nested = NodeSpec {
        entries: vec![
            EntrySpec::Kv("z".into(), b"last".to_vec()),
            EntrySpec::Bucket {
                name: "inner".into(),
                seq: 7,
                node: NodeSpec {
                    entries: vec![EntrySpec::Kv("deep".into(), pattern(9000, 3))],
                },
            },
            EntrySpec::RawKv(vec![0xff, 0x00], vec![1]),
            EntrySpec::Kv("a".into(), Vec::new()),
        ],
    };
    NodeSpec {
        entries: vec![
            EntrySpec::Bucket {
                name: "wide".into(),
                seq: 0,
                node: wide,
            },
            EntrySpec::Bucket {
                name: "empty".into(),
                seq: 0,
                node: NodeSpec {
                    entries: Vec::new(),
                },
            },
            EntrySpec::Bucket {
                name: "nested".into(),
                seq: 42,
                node: nested,
            },
            EntrySpec::Bucket {
                name: "fakeip_address".into(),
                seq: 0,
                node: NodeSpec {
                    entries: (0..700u32)
                        .map(|i| {
                            EntrySpec::RawKv(
                                (0xC612_0000u32 + i).to_be_bytes().to_vec(),
                                format!("host-{i}.example").into_bytes(),
                            )
                        })
                        .collect(),
                },
            },
        ],
    }
}

#[test]
fn output_matches_the_old_writer() {
    let path = std::env::temp_dir().join(format!("rust-x-bbolt-bytes-{}.db", std::process::id()));
    core_experimental::bbolt::write(&path, &tree()).unwrap();
    let bytes = std::fs::read(&path).unwrap();
    let db = Db::open(&path).unwrap();
    assert_eq!(
        db.get(&["nested", "inner"], b"deep").unwrap(),
        Some(pattern(9000, 3))
    );
    assert_eq!(db.get(&["nested"], &[0xff, 0x00]).unwrap(), Some(vec![1]));
    let key = format!("{:04}-{}", 5, "k".repeat(200));
    assert_eq!(
        db.get(&["wide"], key.as_bytes()).unwrap(),
        Some(pattern(1800, 5))
    );
    assert_eq!(db.bucket_page_raw(&["empty"]).unwrap(), Some(Vec::new()));
    assert_eq!(
        db.bucket_page_raw(&["fakeip_address"])
            .unwrap()
            .unwrap()
            .len(),
        700
    );
    std::fs::remove_file(&path).unwrap();
    assert_eq!(bytes.len(), EXPECTED_LEN);
    assert_eq!(fnv1a64(&bytes), EXPECTED_FNV);
}

// Measured on the writer before the change.
const EXPECTED_LEN: usize = 331_776;
const EXPECTED_FNV: u64 = 0x7cfb_29c9_93f4_681d;
