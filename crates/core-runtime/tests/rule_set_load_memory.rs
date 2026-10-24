//! Compiling a rule set must not copy the decoded strings.
//!
//! `RuleSet::new` takes the decoded rules by value and moves their strings
//! into the index. If it cloned them instead, the decoded tree and the index
//! would hold every entry twice while the set is built, which is the load
//! peak this guards.
//!
//! One test per binary: the allocator counters are process-wide.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

use core_runtime::route::rule_set::RuleSet;
use serde_json::{Value, json};

struct Counting;

static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(size: usize) {
    let live = LIVE.fetch_add(size, Ordering::Relaxed) + size;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            grow(layout.size());
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let out = unsafe { System.realloc(ptr, layout, new_size) };
        if !out.is_null() {
            // counted as a new block next to the old one, then the old freed
            grow(new_size);
            LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        }
        out
    }
}

#[global_allocator]
static ALLOC: Counting = Counting;

const N: usize = 20_000;
const LEN: usize = 200;

fn entry(kind: char, n: usize) -> Value {
    let head = format!("{kind}{n}.");
    let mut name = "x".repeat(LEN - head.len() - 4);
    name.insert_str(0, &head);
    name.push_str(".com");
    // exact capacity, like the SRS decoder's strings
    Value::String(name.as_str().to_string())
}

#[test]
fn compile_moves_decoded_strings_into_the_index() {
    let domains: Vec<Value> = (0..N).map(|n| entry('d', n)).collect();
    let suffixes: Vec<Value> = (0..N).map(|n| entry('s', n)).collect();
    let rules = vec![
        json!({ "domain": domains }),
        json!({ "domain_suffix": suffixes }),
        json!({ "invert": true, "domain": [entry('i', 0)] }),
    ];
    let strings = 2 * N * LEN;

    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let set = RuleSet::new(vec!["geo".into()], rules).expect("rule set");
    let extra = PEAK.load(Ordering::Relaxed) - before;

    assert!(set.index().has_domain(entry('d', 7).as_str().unwrap()));
    assert_eq!(set.rule_count(), 3);
    // the hash tables and the moved boxes stay well under one copy of the
    // strings; a clone per entry alone would be `strings`
    assert!(
        extra < strings / 2,
        "compile peaked {extra} bytes over the decoded rules ({strings} bytes of strings)"
    );
}
