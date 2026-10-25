//! CQ-04: a TSRS image is mapped straight from the cache directory (or an
//! opted-in download). Its offsets and counts come from the file, so a
//! corrupt or hostile image must be refused before any typed slice is formed.

use core_runtime::route::mmap_set::format::HEADER_SIZE;
use core_runtime::route::mmap_set::{MmapRuleSet, RuleSetCompiler};

// byte positions of the header fields (`format::Header`, 72 bytes)
const DOMAINS_OFFSET: usize = 16;
const DOMAINS_COUNT: usize = 20;
const V6_OFFSET: usize = 48;
const V6_COUNT: usize = 52;
const STRING_OFFSET: usize = 64;
const STRING_LEN: usize = 68;

fn put_u32(bytes: &mut [u8], at: usize, value: u32) {
    bytes[at..at + 4].copy_from_slice(&value.to_ne_bytes());
}

#[test]
fn hostile_tsrs_tables_are_refused() {
    assert_eq!(HEADER_SIZE, 72);
    let mut compiler = RuleSetCompiler::new();
    compiler.add_domain("a.example");
    let base = compiler.finish();
    assert!(MmapRuleSet::from_bytes(&base).is_some());
    let len = base.len() as u32;
    let mut cases: Vec<(&str, Vec<(usize, u32)>)> = vec![
        ("table past the end", vec![(DOMAINS_OFFSET, len)]),
        ("count past the end", vec![(DOMAINS_COUNT, u32::MAX)]),
        (
            "strings past the end",
            vec![(STRING_OFFSET, len - 1), (STRING_LEN, 2)],
        ),
        (
            "strings wrap",
            vec![(STRING_OFFSET, u32::MAX), (STRING_LEN, u32::MAX)],
        ),
        // in bounds, but `&[DomainEntry]` needs 4-byte alignment
        (
            "misaligned domain table",
            vec![(DOMAINS_OFFSET, HEADER_SIZE as u32 + 1)],
        ),
    ];
    if std::mem::align_of::<u128>() == 16 {
        // in bounds, 8 mod 16: what the old compiler wrote for IPv6
        cases.push((
            "misaligned v6 table",
            vec![(V6_OFFSET, HEADER_SIZE as u32), (V6_COUNT, 1)],
        ));
    }
    for (name, patch) in cases {
        let mut bytes = base.clone();
        for (at, value) in patch {
            put_u32(&mut bytes, at, value);
        }
        assert!(MmapRuleSet::from_bytes(&bytes).is_none(), "{name}");
        // the same image found in the cache directory
        let path = std::env::temp_dir().join(format!(
            "rust-x-hostile-{}-{}.tsrs",
            std::process::id(),
            name.replace(' ', "-")
        ));
        std::fs::write(&path, &bytes).expect("write image");
        assert!(MmapRuleSet::open(&path).is_err(), "{name} (file)");
        let _ = std::fs::remove_file(&path);
    }
}
