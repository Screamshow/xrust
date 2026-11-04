//! A flush borrows stored bytes and streams its image. Index allocations may
//! scale with entry count, but a large value must not require an image copy.
//! One test per binary isolates the counting allocator.

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
fn flush_streams_large_values_without_allocating_a_file_image() {
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

    println!("mixed_flush_extra={extra} database_bytes={file}");
    assert!(
        extra < file,
        "flush allocated {extra} bytes for a {file}-byte file"
    );

    use core_experimental::bbolt::{self, EntryRef, NodeRef};
    let value = vec![0x5a; 8 * 1024 * 1024];
    let tree = || NodeRef {
        entries: vec![EntryRef::Bucket {
            name: b"rule_set",
            seq: 0,
            node: NodeRef {
                entries: vec![EntryRef::Kv(b"large", &value)],
            },
        }],
    };
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let image = bbolt::encode_ref(tree()).unwrap();
    let image_peak = PEAK.load(Ordering::Relaxed) - before;

    // Recreate the owned temporary directory after the mixed-cache check.
    std::fs::create_dir_all(&dir).unwrap();
    let output = std::fs::File::create(&path).unwrap();
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    bbolt::write_to(std::io::BufWriter::with_capacity(32 * 1024, output), tree()).unwrap();
    let stream_peak = PEAK.load(Ordering::Relaxed) - before;
    assert!(image_peak >= value.len());
    assert!(
        stream_peak < 128 * 1024,
        "payload-sized allocation: {stream_peak}"
    );
    assert_eq!(std::fs::read(&path).unwrap(), image);
    println!(
        "large_value_bytes={} image_peak={image_peak} stream_peak={stream_peak}",
        value.len()
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
