use super::*;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering};
use std::sync::{Arc, Mutex};
use std::task::Wake;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
struct Wire {
    blocked: AtomicBool,
    writes: Mutex<Vec<Vec<u8>>>,
    flushes: AtomicUsize,
}

struct Io(Arc<Wire>);

impl AsyncRead for Io {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for Io {
    fn poll_write(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.0.blocked.load(AtomicOrdering::SeqCst) {
            return Poll::Pending;
        }
        self.0.writes.lock().unwrap().push(bytes.to_vec());
        Poll::Ready(Ok(bytes.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.0.flushes.fetch_add(1, AtomicOrdering::SeqCst);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[derive(Default)]
struct Wakes(AtomicUsize);

impl Wake for Wakes {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, AtomicOrdering::SeqCst);
    }
}

fn config() -> Config {
    Config {
        initial_max_send_streams: 100,
        local_max_buffer_size: 65535,
        local_next_stream_id: 1.into(),
        local_push_enabled: false,
        extended_connect_protocol_enabled: false,
        local_reset_duration: Duration::ZERO,
        local_reset_max: 10,
        remote_reset_max: 10,
        remote_init_window_sz: DEFAULT_INITIAL_WINDOW_SIZE,
        remote_max_initiated: None,
        local_max_error_reset_streams: None,
        data_frame_budget: DEFAULT_DATA_FRAME_BUDGET,
        recv_min_refresh: Some(4096),
        pseudo_order: crate::frame::PseudoOrder::default(),
    }
}

fn received(bytes: u32) -> (Recv, Store, Counts) {
    let config = config();
    let mut recv = Recv::new(peer::Dyn::Client, &config);
    recv.flow.inc_window(bytes).unwrap();
    recv.flow.assign_capacity(bytes).unwrap();
    recv.consume_connection_window(bytes).unwrap();
    let mut store = Store::new();
    let mut stream = store.insert(1.into(), Stream::new(1.into(), 65535, bytes + 65535));
    stream.recv_flow.set_min_refresh(Some(4096));
    stream.recv_flow.send_data(bytes).unwrap();
    stream.in_flight_recv_data = bytes;
    drop(stream);
    (recv, store, Counts::new(peer::Dyn::Client, &config))
}

fn returned(
    recv: &mut Recv,
    store: &mut Store,
    cx: &Context<'_>,
    bytes: u32,
) -> Poll<Result<(), UserError>> {
    let mut stream = store.find_mut(&1.into()).unwrap();
    recv.poll_release_capacity_exact(cx, bytes, &mut stream, &mut None)
}

fn frames(wire: &Wire) -> Vec<(u32, u32)> {
    let bytes: Vec<u8> = wire
        .writes
        .lock()
        .unwrap()
        .iter()
        .flatten()
        .copied()
        .collect();
    assert_eq!(bytes.len() % 13, 0);
    bytes
        .chunks_exact(13)
        .map(|frame| {
            assert_eq!(&frame[..5], &[0, 0, 4, 8, 0]);
            (
                u32::from_be_bytes(frame[5..9].try_into().unwrap()),
                u32::from_be_bytes(frame[9..13].try_into().unwrap()),
            )
        })
        .collect()
}

fn remote_end_and_unlink(store: &mut Store, counts: &mut Counts) -> store::Key {
    let mut stream = store.find_mut(&1.into()).unwrap();
    stream.ref_inc(); // body still owns its opaque stream reference
    stream.state.send_open(true).unwrap();
    let mut headers = frame::Headers::new(1.into(), Default::default(), http::HeaderMap::new());
    headers.set_end_stream();
    stream.state.recv_open(&headers).unwrap();
    assert!(stream.state.is_closed());
    let key = stream.key();
    counts.transition_after(stream, false);
    assert!(
        store.find_mut(&1.into()).is_none(),
        "closed stream leaves active ID map"
    );
    assert!(
        store.try_resolve(key).is_some(),
        "body/queue still owns slab state"
    );
    key
}

#[test]
fn exact_credit_remote_end_unlinks_id_but_retains_all_read_pairs() {
    let (mut recv, mut store, mut counts) = received(16384);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let mut cx = Context::from_waker(&waker);
    for _ in 0..2 {
        assert!(matches!(
            returned(&mut recv, &mut store, &cx, 8192),
            Poll::Ready(Ok(()))
        ));
    }
    let key = remote_end_and_unlink(&mut store, &mut counts);
    assert_eq!(store.try_resolve(key).unwrap().pending_exact_credits, 2);
    assert!(recv
        .poll_exact_credit_flushed(&cx, &mut store.try_resolve(key).unwrap(), &mut None)
        .is_pending());
    let wire = Arc::new(Wire::default());
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(wire.clone()));
    for _ in 0..2 {
        while recv
            .buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap()
            == BufferStatus::Complete
        {}
        assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
        recv.finish_exact_credit_flush(&mut store, &mut counts);
    }
    assert_eq!(
        frames(&wire),
        vec![(0, 8192), (1, 8192), (0, 8192), (1, 8192)]
    );
    assert_eq!(
        wakes.0.load(AtomicOrdering::SeqCst),
        1,
        "EOF fence woken on last actual flush"
    );
    let mut stream = store.try_resolve(key).unwrap();
    assert_eq!(stream.pending_exact_credits, 0);
    assert!(recv
        .poll_exact_credit_flushed(&cx, &mut stream, &mut None)
        .is_ready());
    stream.ref_dec();
    counts.transition_after(stream, false);
    assert!(
        store.try_resolve(key).is_none(),
        "last body ref releases closed state"
    );
}

#[test]
fn exact_credit_cancel_and_failed_flush_release_retention_without_aba() {
    let (mut recv, mut store, mut counts) = received(16384);
    let mut cx = Context::from_waker(Waker::noop());
    for _ in 0..2 {
        assert!(matches!(
            returned(&mut recv, &mut store, &cx, 8192),
            Poll::Ready(Ok(()))
        ));
    }
    let key = remote_end_and_unlink(&mut store, &mut counts);
    let mut stream = store.try_resolve(key).unwrap();
    stream.is_recv = false; // local body cancellation
    stream.ref_dec();
    counts.transition_after(stream, false);
    assert!(
        store.try_resolve(key).is_some(),
        "queued controls retain state without Arc cycle"
    );
    let wire = Arc::new(Wire::default());
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(wire.clone()));
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(
        frames(&wire),
        vec![(0, 8192)],
        "no stream update after local cancellation"
    );
    assert_eq!(store.try_resolve(key).unwrap().pending_exact_credits, 1);
    // Connection failure abandons remaining controls exactly once.
    recv.clear_queues(false, &mut store, &mut counts);
    recv.clear_queues(false, &mut store, &mut counts);
    assert!(store.try_resolve(key).is_none());
    assert_eq!(recv.in_flight_data, 0);
    let replacement = store
        .insert(3.into(), Stream::new(3.into(), 65535, 65535))
        .key();
    assert!(
        store.try_resolve(key).is_none(),
        "recycled slot must not resolve old stream ID"
    );
    assert_eq!(
        store
            .try_resolve(replacement)
            .unwrap()
            .pending_exact_credits,
        0
    );
}

#[test]
fn exact_credit_retains_two_reads_before_driver_and_flushes_pairs() {
    let (mut recv, mut store, mut counts) = received(16384);
    let cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        returned(&mut recv, &mut store, &cx, 8192),
        Poll::Ready(Ok(()))
    ));
    assert!(matches!(
        returned(&mut recv, &mut store, &cx, 8192),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(recv.exact_credits.len(), 2);
    assert!(recv
        .exact_credits
        .iter()
        .all(|x| x.connection == 8192 && x.stream == 8192));
    assert_eq!(recv.in_flight_data, 0);

    let wire = Arc::new(Wire::default());
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(wire.clone()));
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    assert!(
        !codec.has_send_capacity(),
        "pair boundary must survive a later poll"
    );
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Complete,
        "normal send/input progress turn between pairs"
    );
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(
        frames(&wire),
        vec![(0, 8192), (1, 8192), (0, 8192), (1, 8192)]
    );
    assert_eq!(wire.flushes.load(AtomicOrdering::SeqCst), 2);
    assert_eq!(
        wire.writes
            .lock()
            .unwrap()
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        vec![26, 26]
    );
}

#[test]
fn exact_credit_terminal_cleanup_then_late_release_has_no_retained_tokens() {
    let total = (MAX_EXACT_CREDITS as u32 + 1) * 8192;
    let (mut recv, mut store, mut counts) = received(total);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let cx = Context::from_waker(&waker);
    for _ in 0..MAX_EXACT_CREDITS {
        assert!(matches!(
            returned(&mut recv, &mut store, &cx, 8192),
            Poll::Ready(Ok(()))
        ));
    }
    assert!(returned(&mut recv, &mut store, &cx, 8192).is_pending());
    let key = remote_end_and_unlink(&mut store, &mut counts);
    recv.clear_queues(false, &mut store, &mut counts);
    assert!(
        wakes.0.load(AtomicOrdering::SeqCst) > 0,
        "terminal cleanup must wake the queue-full consumer"
    );
    let mut stream = store.try_resolve(key).unwrap();
    assert_eq!(stream.pending_exact_credits, 0);
    assert!(!stream.exact_credit_waiting);
    assert_eq!(stream.in_flight_recv_data, 8192);
    recv.release_capacity_after_eof(8192, &mut stream).unwrap();
    assert_eq!(stream.in_flight_recv_data, 0);
    assert_eq!(recv.in_flight_data, 0);
    assert_eq!(stream.pending_exact_credits, 0);
    assert!(recv.exact_credits.is_empty());
    assert!(recv.pending_window_updates.is_empty());
    let before = (recv.flow.available(), stream.recv_flow.available());
    assert!(recv.release_capacity_after_eof(1, &mut stream).is_err());
    assert_eq!(
        before,
        (recv.flow.available(), stream.recv_flow.available())
    );
    counts.transition(stream, |_, stream| stream.ref_dec());
    assert!(
        store.try_resolve(key).is_none(),
        "late release must not leak the closed Slab entry"
    );
}

#[test]
fn exact_credit_queue_bound_is_atomic_and_wakes_blocked_consumer() {
    let total = (MAX_EXACT_CREDITS as u32 + 1) * 8192;
    let (mut recv, mut store, mut counts) = received(total);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let cx = Context::from_waker(&waker);
    for _ in 0..MAX_EXACT_CREDITS {
        assert!(matches!(
            returned(&mut recv, &mut store, &cx, 8192),
            Poll::Ready(Ok(()))
        ));
    }
    assert_eq!(recv.exact_credits.len(), MAX_EXACT_CREDITS);
    assert_eq!(recv.exact_credits.capacity(), MAX_EXACT_CREDITS);
    assert!(
        recv.exact_credits.capacity() * std::mem::size_of::<ExactCredit>() <= 1024,
        "bounded connection-wide snapshot storage must stay at most 1 KiB"
    );
    let before = (
        recv.in_flight_data,
        recv.flow.window_size(),
        recv.flow.available(),
    );
    assert!(returned(&mut recv, &mut store, &cx, 8192).is_pending());
    assert_eq!(
        before,
        (
            recv.in_flight_data,
            recv.flow.window_size(),
            recv.flow.available()
        )
    );
    assert_eq!(store.find_mut(&1.into()).unwrap().in_flight_recv_data, 8192);
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(Arc::new(Wire::default())));
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    let mut io_cx = Context::from_waker(Waker::noop());
    assert!(matches!(codec.flush(&mut io_cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Complete
    );
    assert_eq!(wakes.0.load(AtomicOrdering::SeqCst), 1);
    assert!(matches!(
        returned(&mut recv, &mut store, &cx, 8192),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(recv.in_flight_data, 0);
    assert_eq!(recv.exact_credits.len(), MAX_EXACT_CREDITS);
}

#[test]
fn exact_credit_close_does_not_double_refund_or_update_dropped_stream() {
    let (mut recv, mut store, mut counts) = received(16384);
    let cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        returned(&mut recv, &mut store, &cx, 8192),
        Poll::Ready(Ok(()))
    ));
    let mut stream = store.find_mut(&1.into()).unwrap();
    stream.is_recv = false;
    recv.release_closed_capacity(&mut stream, &mut None, &mut counts);
    assert_eq!(stream.in_flight_recv_data, 0);
    assert_eq!(recv.in_flight_data, 0);
    drop(stream);
    let wire = Arc::new(Wire::default());
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(wire.clone()));
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Complete
    );
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(frames(&wire), vec![(0, 8192), (0, 8192)]);
}

#[test]
fn exact_credit_eof_fence_waits_for_flush_and_connection_cleanup_wakes_it() {
    let (mut recv, mut store, mut counts) = received(16384);
    let wakes = Arc::new(Wakes::default());
    let waker = Waker::from(wakes.clone());
    let cx = Context::from_waker(&waker);
    assert!(matches!(
        returned(&mut recv, &mut store, &cx, 8192),
        Poll::Ready(Ok(()))
    ));
    assert!(recv
        .poll_exact_credit_flushed(&cx, &mut store.find_mut(&1.into()).unwrap(), &mut None)
        .is_pending());
    let wire = Arc::new(Wire::default());
    wire.blocked.store(true, AtomicOrdering::SeqCst);
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(wire.clone()));
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    assert!(recv.exact_credits.is_empty());
    let mut io_cx = Context::from_waker(Waker::noop());
    assert!(codec.flush(&mut io_cx).is_pending());
    assert!(
        recv.poll_exact_credit_flushed(&cx, &mut store.find_mut(&1.into()).unwrap(), &mut None)
            .is_pending(),
        "dequeued does not mean flushed"
    );
    wire.blocked.store(false, AtomicOrdering::SeqCst);
    assert!(matches!(codec.flush(&mut io_cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);

    assert!(recv
        .poll_exact_credit_flushed(&cx, &mut store.find_mut(&1.into()).unwrap(), &mut None)
        .is_ready());
    assert_eq!(wakes.0.load(AtomicOrdering::SeqCst), 1);
    assert!(matches!(
        returned(&mut recv, &mut store, &cx, 8192),
        Poll::Ready(Ok(()))
    ));
    assert!(recv
        .poll_exact_credit_flushed(&cx, &mut store.find_mut(&1.into()).unwrap(), &mut None)
        .is_pending());
    recv.clear_queues(false, &mut store, &mut counts);
    assert!(recv
        .poll_exact_credit_flushed(&cx, &mut store.find_mut(&1.into()).unwrap(), &mut None)
        .is_ready());
    assert_eq!(wakes.0.load(AtomicOrdering::SeqCst), 2);
}

#[test]
fn exact_credit_pair_flush_does_not_join_an_older_control() {
    let (mut recv, mut store, mut counts) = received(8192);
    let cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        returned(&mut recv, &mut store, &cx, 8192),
        Poll::Ready(Ok(()))
    ));
    let wire = Arc::new(Wire::default());
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(wire.clone()));
    codec
        .buffer(frame::WindowUpdate::new(StreamId::zero(), 1234).into())
        .unwrap();
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::CodecFull
    );
    assert_eq!(recv.exact_credits.len(), 1);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(frames(&wire), vec![(0, 1234), (0, 8192), (1, 8192)]);
    assert_eq!(
        wire.writes
            .lock()
            .unwrap()
            .iter()
            .map(Vec::len)
            .collect::<Vec<_>>(),
        vec![13, 26]
    );
}

#[test]
fn exact_credit_slow_writer_keeps_flush_boundary_and_neighbor_turn() {
    let (mut recv, mut store, mut counts) = received(16384);
    let cx = Context::from_waker(Waker::noop());
    for _ in 0..2 {
        assert!(matches!(
            returned(&mut recv, &mut store, &cx, 8192),
            Poll::Ready(Ok(()))
        ));
    }
    let wire = Arc::new(Wire::default());
    wire.blocked.store(true, AtomicOrdering::SeqCst);
    let mut codec = Codec::<_, Prioritized<Bytes>>::new(Io(wire.clone()));
    let mut cx = Context::from_waker(Waker::noop());
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Flush
    );
    assert!(codec.flush(&mut cx).is_pending());
    assert!(!codec.has_send_capacity());
    assert_eq!(recv.exact_credits.len(), 1);
    wire.blocked.store(false, AtomicOrdering::SeqCst);
    assert!(matches!(codec.flush(&mut cx), Poll::Ready(Ok(()))));
    recv.finish_exact_credit_flush(&mut store, &mut counts);
    assert_eq!(
        recv.buffer_pending(&mut store, &mut counts, &mut codec)
            .unwrap(),
        BufferStatus::Complete
    );
    assert!(
        codec.has_send_capacity(),
        "neighbor DATA may be buffered on this turn"
    );
    assert_eq!(frames(&wire), vec![(0, 8192), (1, 8192)]);
}
