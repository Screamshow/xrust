//! Isolate template ownership costs; this is not whole-core RSS attribution.
use core_tls::{fingerprints, hello::Template};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::{
    Arc,
    atomic::{AtomicIsize, Ordering},
};

struct CountAlloc;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOC: CountAlloc = CountAlloc;

enum Tables {
    Owned(Vec<Template>),
    Shared(Vec<Arc<Template>>),
}
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args
        .get(1)
        .expect("usage: shared_template_memory owned|shared [count] [fingerprint]");
    let count: usize = args.get(2).map(|s| s.parse().unwrap()).unwrap_or(112);
    assert!((1..=10000).contains(&count));
    let name = args.get(3).map(String::as_str).unwrap_or("chrome");
    let before = LIVE.load(Ordering::Relaxed);
    let tables = match mode.as_str() {
        "owned" => Tables::Owned(
            (0..count)
                .map(|_| fingerprints::by_name(name).unwrap())
                .collect(),
        ),
        "shared" => Tables::Shared(
            (0..count)
                .map(|_| fingerprints::shared_by_name(name).unwrap())
                .collect(),
        ),
        _ => panic!("mode must be owned or shared"),
    };
    let held = LIVE.load(Ordering::Relaxed) - before;
    let length = match &tables {
        Tables::Owned(v) => v.len(),
        Tables::Shared(v) => v.len(),
    };
    assert_eq!(length, count);
    println!("mode={mode} name={name} count={count} live_delta={held}");
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        for line in status.lines().filter(|s| {
            ["VmRSS:", "RssAnon:", "VmHWM:"]
                .iter()
                .any(|key| s.starts_with(key))
        }) {
            println!("{line}");
        }
    }
    std::hint::black_box(&tables);
    drop(tables);
    println!(
        "after_drop_live_delta={}",
        LIVE.load(Ordering::Relaxed) - before
    );
}
