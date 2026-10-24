//! A flush must not copy the stored keys and values before writing them: the
//! only large allocation is the file image itself. One test per binary, so
//! the counting allocator sees nothing else.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use core_runtime::cache_file::{BUCKET_RULE_SET, CacheFile, CacheFileOptions};

struct CountAlloc;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);

fn grow(by: usize) {
    let live = LIVE.fetch_add(by, Ordering::Relaxed) + by;
    PEAK.fetch_max(live, Ordering::Relaxed);
}

unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let p = unsafe { System.alloc(layout) };
        if !p.is_null() {
            grow(layout.size());
        }
        p
    }
    unsafe fn dealloc(&self, p: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(p, layout) };
    }
    unsafe fn realloc(&self, p: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let q = unsafe { System.realloc(p, layout, new_size) };
        if !q.is_null() {
            if new_size > layout.size() {
                grow(new_size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - new_size, Ordering::Relaxed);
            }
        }
        q
    }
}
#[global_allocator]
static ALLOC: CountAlloc = CountAlloc;

#[test]
fn flush_allocates_about_one_file_image() {
    let dir = std::env::temp_dir().join(format!("rust-x-flush-alloc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("cache.db");
    let mut store = CacheFile::open(CacheFileOptions {
        enabled: true,
        path: path.to_string_lossy().into_owned(),
        flush_interval: Duration::from_secs(3600),
        ..Default::default()
    })
    .unwrap()
    .unwrap();
    let body: Vec<u8> = (0..4 << 20).map(|i: u32| (i % 251) as u8).collect();
    store.put(BUCKET_RULE_SET, b"remote", body);
    for i in 0..20_000u32 {
        let ip = (0xC612_0000u32 + i).to_be_bytes();
        store.put(
            "fakeip_address",
            &ip,
            format!("host-{i:05}.example.com").into_bytes(),
        );
    }

    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    store.flush().unwrap();
    let extra = PEAK.load(Ordering::Relaxed) - before;
    let file = std::fs::metadata(&path).unwrap().len() as usize;
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();

    // The image Vec grows by doubling, so up to twice the file; copies of the
    // stored data would add at least one more file's worth per copy.
    assert!(
        extra < 2 * file + file / 2,
        "flush allocated {extra} bytes for a {file}-byte file"
    );
}
