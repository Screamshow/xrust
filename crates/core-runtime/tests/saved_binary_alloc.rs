//! Saving a remote list must not retain an intermediate payload-sized copy.
use core_runtime::cache_file::saved_binary::{
    SavedBinary, SavedBinaryRef, marshal, marshal_ref, unmarshal,
};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering};

struct CountAlloc;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
unsafe impl GlobalAlloc for CountAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            let live = LIVE.fetch_add(layout.size(), Ordering::Relaxed) + layout.size();
            PEAK.fetch_max(live, Ordering::Relaxed);
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size(), Ordering::Relaxed);
        unsafe { System.dealloc(ptr, layout) };
    }
}
#[global_allocator]
static ALLOC: CountAlloc = CountAlloc;

fn measure(encode: impl FnOnce() -> Vec<u8>) -> (Vec<u8>, usize) {
    let before = LIVE.load(Ordering::Relaxed);
    PEAK.store(before, Ordering::Relaxed);
    let record = encode();
    (record, PEAK.load(Ordering::Relaxed) - before)
}

#[test]
fn borrowed_record_preserves_bytes_and_avoids_a_payload_copy() {
    let content = vec![0x5a; 4 * 1024 * 1024];
    let etag = "e".repeat(256);
    let (old, old_peak) = measure(|| {
        marshal(&SavedBinary {
            last_updated: 1_700_000_000,
            content: content.clone(),
            last_etag: etag.clone(),
            url_hash: [7; 32],
        })
    });
    let (new, new_peak) = measure(|| {
        marshal_ref(&SavedBinaryRef {
            last_updated: 1_700_000_000,
            content: &content,
            last_etag: &etag,
            url_hash: [7; 32],
        })
    });
    assert_eq!(old, new, "existing cache record bytes must be preserved");
    assert!(
        new_peak <= content.len() + etag.len() + 128,
        "expected only the encoded record allocation: {new_peak}"
    );
    assert_eq!(old_peak - new_peak, content.len() + etag.len());
    let decoded = unmarshal(&new).unwrap();
    assert_eq!(decoded.content, content);
    assert_eq!(decoded.last_etag, etag);
    println!(
        "payload_bytes={} owned_peak={old_peak} borrowed_peak={new_peak} saved_bytes={}",
        content.len(),
        old_peak - new_peak
    );
}
