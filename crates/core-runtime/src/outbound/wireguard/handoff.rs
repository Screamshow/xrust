use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

const RECEIVE_BURST: usize = 8 * 1024;
const RECEIVE_WINDOW: Duration = Duration::from_millis(25);
// A bulk reply can pause for a TCP window update or a retransmission.
// Keep its receive bias through short gaps, while ignoring tiny replies.
const QUIET: Duration = Duration::from_millis(300);

pub(super) fn adaptive_enabled(is_awg: bool, override_mode: Option<&str>) -> bool {
    is_awg && override_mode != Some("one")
}

pub(super) struct ReceiveActivity {
    signal: Arc<AtomicBool>,
    window_start: Option<Instant>,
    bytes: usize,
    last_active: Option<Instant>,
}

impl ReceiveActivity {
    pub(super) fn new(signal: Arc<AtomicBool>) -> Self {
        Self {
            signal,
            window_start: None,
            bytes: 0,
            last_active: None,
        }
    }

    pub(super) fn observe(&mut self, now: Instant, received: usize, queued: usize, stalled: bool) {
        if self
            .window_start
            .is_none_or(|start| now.duration_since(start) >= RECEIVE_WINDOW)
        {
            self.window_start = Some(now);
            self.bytes = 0;
        }
        self.bytes = self.bytes.saturating_add(received);
        let was_active = self.signal.load(Ordering::Relaxed);
        if stalled || queued >= RECEIVE_BURST || self.bytes >= RECEIVE_BURST {
            self.last_active = Some(now);
            self.bytes = 0;
            self.window_start = Some(now);
        }
        let active = self
            .last_active
            .is_some_and(|last| now.duration_since(last) < QUIET);
        if active != was_active {
            self.signal.store(active, Ordering::Release);
        }
    }
}

pub(super) struct InFlight {
    feedback: Arc<AtomicBool>,
    waits: VecDeque<oneshot::Receiver<()>>,
}

impl InFlight {
    pub(super) fn new(feedback: Arc<AtomicBool>) -> Self {
        Self {
            feedback,
            waits: VecDeque::with_capacity(2),
        }
    }

    pub(super) fn limit(&self) -> usize {
        if self.feedback.load(Ordering::Acquire) {
            1
        } else {
            2
        }
    }

    pub(super) fn has_room(&self) -> bool {
        self.waits.len() < self.limit()
    }

    pub(super) async fn wait_for_room(&mut self) -> Result<(), oneshot::error::RecvError> {
        while !self.has_room() {
            self.waits.pop_front().expect("full queue").await?;
        }
        Ok(())
    }

    pub(super) fn push(&mut self, accepted: oneshot::Receiver<()>) {
        // A concurrent downgrade can leave at most these two pending until
        // the next admission check. No submitted block can be recalled.
        debug_assert!(self.waits.len() < 2);
        self.waits.push_back(accepted);
    }

    pub(super) async fn drain(&mut self) -> Result<(), oneshot::error::RecvError> {
        while let Some(wait) = self.waits.pop_front() {
            wait.await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_is_the_awg_default_with_a_one_block_override() {
        assert!(adaptive_enabled(true, None));
        assert!(!adaptive_enabled(true, Some("one")));
        assert!(!adaptive_enabled(false, None));
        assert!(!adaptive_enabled(false, Some("adaptive")));
    }

    #[test]
    fn feedback_ignores_small_replies_switches_and_recovers() {
        let now = Instant::now();
        let signal = Arc::new(AtomicBool::new(false));
        let mut rx = ReceiveActivity::new(signal.clone());
        let tx = InFlight::new(signal);
        rx.observe(now, 64, 0, false);
        rx.observe(now + Duration::from_millis(30), 64, 0, false);
        assert_eq!(tx.limit(), 2);
        rx.observe(now + Duration::from_millis(31), 4096, 0, false);
        rx.observe(now + Duration::from_millis(32), 4096, 0, false);
        assert_eq!(tx.limit(), 1);
        rx.observe(now + Duration::from_millis(150), 0, 8192, true);
        assert_eq!(tx.limit(), 1);
        rx.observe(now + Duration::from_millis(151), 0, 0, false);
        assert_eq!(tx.limit(), 1);
        rx.observe(now + Duration::from_millis(273), 64, 0, false);
        assert_eq!(tx.limit(), 1);
        // A small reply after silence must not revive the old receive burst.
        rx.observe(now + Duration::from_millis(451), 64, 0, false);
        assert_eq!(tx.limit(), 2);
    }

    #[tokio::test]
    async fn downgrade_waits_for_both_outstanding_blocks() {
        let flag = Arc::new(AtomicBool::new(false));
        let mut tx = InFlight::new(flag.clone());
        let (first, first_done) = oneshot::channel();
        let (second, second_done) = oneshot::channel();
        tx.push(first_done);
        tx.push(second_done);
        flag.store(true, Ordering::Release);
        first.send(()).unwrap();
        let wait = tx.wait_for_room();
        tokio::pin!(wait);
        assert!(
            tokio::time::timeout(Duration::from_millis(5), &mut wait)
                .await
                .is_err()
        );
        second.send(()).unwrap();
        wait.await.unwrap();
    }

    #[tokio::test]
    async fn close_drain_detects_dropped_ack() {
        let mut tx = InFlight::new(Arc::new(AtomicBool::new(false)));
        let (first, first_done) = oneshot::channel();
        let (second, second_done) = oneshot::channel();
        tx.push(first_done);
        tx.push(second_done);
        first.send(()).unwrap();
        drop(second);
        assert!(tx.drain().await.is_err());
    }
}
