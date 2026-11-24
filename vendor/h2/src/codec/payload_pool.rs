//! Small, reusable DATA allocations keep received frames from pinning the
//! HTTP/2 decoder's buffer. The idea comes from Tachyon Core v0.6.3
//! (`fb03c40`, `vendor/h2/src/codec/recycle.rs`). This version bounds the
//! cache by size class and leaves large frames on the shared read buffer.

use bytes::{Bytes, BytesMut};
use std::sync::Mutex;

const CAPACITIES: [usize; 7] = [
    512,
    4096,
    16 * 1024,
    32 * 1024,
    64 * 1024,
    128 * 1024,
    256 * 1024,
];
// The decoder can enqueue several DATA frames before another worker returns
// any of their payloads. Bound the total dormant storage across all workers.
const MAX_SPARES: [usize; CAPACITIES.len()] = [4, 8, 64, 8, 4, 2, 1];
static SPARES: Mutex<[Vec<Vec<u8>>; CAPACITIES.len()]> =
    Mutex::new([const { Vec::new() }; CAPACITIES.len()]);

pub(super) fn detach(payload: BytesMut) -> Bytes {
    if payload.is_empty() {
        return Bytes::new();
    }
    let Some(class) = CAPACITIES.iter().position(|&capacity| payload.len() <= capacity) else {
        return payload.freeze();
    };

    let storage =
        SPARES.lock().unwrap_or_else(|error| error.into_inner())[class].pop();
    let mut storage = storage.unwrap_or_else(|| Vec::with_capacity(CAPACITIES[class]));
    storage.extend_from_slice(&payload);
    drop(payload);
    Bytes::from_owner(Payload { class, storage })
}

struct Payload {
    class: usize,
    storage: Vec<u8>,
}

impl AsRef<[u8]> for Payload {
    fn as_ref(&self) -> &[u8] {
        &self.storage
    }
}

impl Drop for Payload {
    fn drop(&mut self) {
        let mut spares = SPARES.lock().unwrap_or_else(|error| error.into_inner());
        let spares = &mut spares[self.class];
        if spares.len() < MAX_SPARES[self.class] {
            self.storage.clear();
            spares.push(std::mem::take(&mut self.storage));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_is_detached_and_storage_is_reused_after_the_last_reference() {
        let input = BytesMut::from(&[42; 8192][..]);
        let input_ptr = input.as_ptr();
        let payload = detach(input);
        let payload_ptr = payload.as_ptr();
        assert_ne!(payload_ptr, input_ptr);

        let remaining = payload.slice(1..);
        drop(payload);
        assert!(remaining.iter().all(|&byte| byte == 42));
        drop(remaining);

        let next = detach(BytesMut::from(&[13; 8192][..]));
        assert_eq!(next.as_ptr(), payload_ptr);
        assert!(next.iter().all(|&byte| byte == 13));
    }

    #[test]
    fn large_payload_keeps_its_original_storage() {
        let input = BytesMut::from(&vec![42; CAPACITIES[6] + 1][..]);
        let input_ptr = input.as_ptr();
        let payload = detach(input);
        assert_eq!(payload.as_ptr(), input_ptr);
    }
}
