//! Buffers of connections that are waiting for their socket.
//!
//! A stream hands a buffer back when a read goes Pending with nothing left in
//! it and takes one again when it next needs it: a busy connection gets the
//! same memory back without a new allocation, and an idle one holds none.

use std::sync::Mutex;

/// Buffers each pool keeps; the rest are freed.
const POOL_KEEP: usize = 8;

pub(crate) struct Pool(Mutex<Vec<Vec<u8>>>);

impl Pool {
    pub(crate) const fn new() -> Self {
        Self(Mutex::new(Vec::new()))
    }

    /// An empty buffer, with capacity if one was pooled.
    pub(crate) fn take(&self) -> Vec<u8> {
        self.0
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
            .unwrap_or_default()
    }

    pub(crate) fn give(&self, mut buf: Vec<u8>) {
        if buf.capacity() == 0 {
            return;
        }
        buf.clear();
        let mut pool = self.0.lock().unwrap_or_else(|e| e.into_inner());
        if pool.len() < POOL_KEEP {
            pool.push(buf);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keeps_at_most_pool_keep_buffers_and_hands_them_back_empty() {
        let pool = Pool::new();
        for _ in 0..POOL_KEEP + 3 {
            pool.give(vec![7u8; 100]);
        }
        pool.give(Vec::new());
        let mut kept = 0;
        loop {
            let buf = pool.take();
            if buf.capacity() == 0 {
                break;
            }
            assert!(buf.is_empty());
            kept += 1;
        }
        assert_eq!(kept, POOL_KEEP);
    }
}
