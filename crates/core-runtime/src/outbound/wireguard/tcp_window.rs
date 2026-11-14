//! Bounded TCP ring storage. Receive storage may grow, but is never reclaimed
//! while a connection can still receive its previously advertised credit.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use smoltcp::socket::tcp::{Socket, SocketBuffer, State};

pub(super) const SMALL_RECV: usize = 128 * 1024;
pub(super) const SMALL_SEND: usize = 64 * 1024;
pub(super) const LARGE: usize = 2 * 1024 * 1024;
#[cfg(test)]
const RECV_EXTRA: usize = LARGE - SMALL_RECV;
#[cfg(target_pointer_width = "32")]
const TOTAL_EXTRA: usize = 8 * 1024 * 1024;
#[cfg(not(target_pointer_width = "32"))]
const TOTAL_EXTRA: usize = 32 * 1024 * 1024;
const IDLE: Duration = Duration::from_secs(10);
const RETRY: Duration = Duration::from_millis(250);
const GROW_AT: usize = SMALL_SEND / 2;

// Independent halves prevent control connections from consuming either
// allowance merely by connecting. RX leases last until the socket closes.
static RECEIVE: Budget = Budget::new(TOTAL_EXTRA / 2);
static TRANSMIT: Budget = Budget::new(TOTAL_EXTRA / 2);

struct Budget {
    used: AtomicUsize,
    limit: usize,
}

impl Budget {
    const fn new(limit: usize) -> Self {
        Self {
            used: AtomicUsize::new(0),
            limit,
        }
    }

    fn acquire(&self, bytes: usize) -> Option<Reservation<'_>> {
        let mut used = self.used.load(Ordering::Relaxed);
        loop {
            let next = used.checked_add(bytes)?;
            if next > self.limit {
                return None;
            }
            match self
                .used
                .compare_exchange_weak(used, next, Ordering::Relaxed, Ordering::Relaxed)
            {
                Ok(_) => {
                    return Some(Reservation {
                        budget: self,
                        bytes,
                    });
                }
                Err(actual) => used = actual,
            }
        }
    }
}

pub(super) struct Reservation<'a> {
    budget: &'a Budget,
    bytes: usize,
}

impl Reservation<'_> {
    fn release(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.bytes);
        self.bytes -= bytes;
        self.budget.used.fetch_sub(bytes, Ordering::Relaxed);
    }
}

impl Drop for Reservation<'_> {
    fn drop(&mut self) {
        self.budget.used.fetch_sub(self.bytes, Ordering::Relaxed);
    }
}

fn buffer(capacity: usize) -> Option<SocketBuffer<'static>> {
    let mut storage = Vec::new();
    storage.try_reserve_exact(capacity).ok()?;
    storage.resize(capacity, 0);
    Some(SocketBuffer::new(storage))
}

// Preserve the zeroed-allocation semantics of the former vec![0; recv_size]
// RX rings, with an explicit failure path. Large untouched pages need not be
// written merely to make their already-zero contents visible to the socket.
fn receive_buffer(capacity: usize) -> Option<SocketBuffer<'static>> {
    let layout = std::alloc::Layout::array::<u8>(capacity).ok()?;
    if capacity == 0 {
        return Some(SocketBuffer::new(Vec::new()));
    }
    // SAFETY: the nonzero layout describes exactly capacity u8 elements.
    // This uses the same global allocator that will later deallocate the Vec.
    let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
    if ptr.is_null() {
        return None;
    }
    // SAFETY: all capacity bytes were initialized by alloc_zeroed; alignment
    // and capacity exactly match the allocation, whose ownership moves once.
    let storage = unsafe { Vec::from_raw_parts(ptr, capacity, capacity) };
    Some(SocketBuffer::new(storage))
}

#[derive(Default)]
pub(super) struct ReceiveWindow<'a> {
    reservation: Option<Reservation<'a>>,
    received: usize,
    retry_at: Option<Instant>,
}

impl ReceiveWindow<'static> {
    pub(super) fn maintain(&mut self, socket: &mut Socket<'_>, now: Instant, received: usize) {
        self.maintain_with(socket, now, received, &RECEIVE);
    }
}

impl<'a> ReceiveWindow<'a> {
    pub(super) fn deadline(&self) -> Option<Instant> {
        self.retry_at
    }

    fn maintain_with(
        &mut self,
        socket: &mut Socket<'_>,
        now: Instant,
        received: usize,
        budget: &'a Budget,
    ) {
        self.received = self.received.saturating_add(received);
        if self.reservation.is_some() {
            return;
        }
        if self.retry_at.is_some_and(|at| now < at) {
            return;
        }
        self.retry_at = None;
        let capacity = LARGE.min(socket.receive_window_capacity());
        if !matches!(
            socket.state(),
            State::Established | State::FinWait1 | State::FinWait2
        ) || capacity <= socket.recv_capacity()
            || self.received.saturating_add(socket.recv_queue()) < GROW_AT
        {
            return;
        }
        // Charge all replacement storage while both rings exist. Never shrink
        // RX: an empty ring does not revoke credit already advertised to a peer.
        let Some(mut reservation) = budget.acquire(capacity) else {
            self.retry_at = Some(now + RETRY);
            return;
        };
        let Some(replacement) = receive_buffer(capacity) else {
            self.retry_at = Some(now + RETRY);
            return;
        };
        let old_capacity = socket.recv_capacity();
        match socket.replace_receive_buffer(replacement) {
            Ok(old) => {
                drop(old);
                reservation.release(old_capacity);
                self.reservation = Some(reservation);
            }
            Err(_) => self.retry_at = Some(now + RETRY),
        }
    }
}

#[derive(Default)]
pub(super) struct SendWindow<'a> {
    reservation: Option<Reservation<'a>>,
    empty_since: Option<Instant>,
    retry_at: Option<Instant>,
}

impl SendWindow<'static> {
    pub(super) fn maintain(&mut self, socket: &mut Socket<'_>, now: Instant, pending: usize) {
        self.maintain_with(socket, now, pending, &TRANSMIT);
    }
}

impl<'a> SendWindow<'a> {
    pub(super) fn deadline(&self) -> Option<Instant> {
        if self.reservation.is_some() {
            self.empty_since.map(|since| {
                let idle = since + IDLE;
                self.retry_at.map_or(idle, |retry| retry.max(idle))
            })
        } else {
            self.retry_at
        }
    }

    fn maintain_with(
        &mut self,
        socket: &mut Socket<'_>,
        now: Instant,
        pending: usize,
        budget: &'a Budget,
    ) {
        let queued = socket.send_queue(); // Includes sent but unacknowledged data.
        let active = queued > 0 || pending > 0;
        if active {
            self.empty_since = None;
        } else if self.reservation.is_some() {
            self.empty_since.get_or_insert(now);
        }

        if self.retry_at.is_some_and(|at| now < at) {
            return;
        }
        self.retry_at = None;
        if self.reservation.is_some() {
            if active
                || !self
                    .empty_since
                    .is_some_and(|since| now.duration_since(since) >= IDLE)
            {
                return;
            }
            // The old large allocation still exists while making its small
            // replacement. Charge that workspace to the same bounded allowance.
            let Some(workspace) = budget.acquire(SMALL_SEND) else {
                self.retry_at = Some(now + RETRY);
                return;
            };
            let Some(small) = buffer(SMALL_SEND) else {
                self.retry_at = Some(now + RETRY);
                return;
            };
            match socket.replace_send_buffer(small) {
                Ok(old) => {
                    drop(old);
                    self.reservation.take();
                    self.empty_since = None;
                }
                Err(_) => {
                    self.retry_at = Some(now + RETRY);
                }
            }
            drop(workspace);
        } else if matches!(socket.state(), State::Established | State::CloseWait)
            && queued.saturating_add(pending) >= GROW_AT
        {
            // Reserve the entire replacement, not just the net growth, until
            // the old base allocation has actually been freed.
            let Some(mut reservation) = budget.acquire(LARGE) else {
                self.retry_at = Some(now + RETRY);
                return;
            };
            let Some(large) = buffer(LARGE) else {
                self.retry_at = Some(now + RETRY);
                return;
            };
            match socket.replace_send_buffer(large) {
                Ok(old) => {
                    drop(old);
                    reservation.release(SMALL_SEND);
                    self.reservation = Some(reservation);
                }
                Err(_) => {
                    self.retry_at = Some(now + RETRY);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn split_allowances_preserve_large_ring_counts_and_workspace() {
        for (total, expected) in [(8 * 1024 * 1024, 2), (32 * 1024 * 1024, 8)] {
            let receive = Budget::new(total / 2);
            let transmit = Budget::new(total / 2);
            let mut rx = Vec::new();
            while let Some(r) = receive.acquire(RECV_EXTRA) {
                rx.push(r);
            }
            assert_eq!(rx.len(), expected);
            let mut tx = Vec::new();
            for _ in 0..expected {
                let mut r = transmit.acquire(LARGE).unwrap();
                r.release(SMALL_SEND);
                tx.push(r);
            }
            assert!(transmit.acquire(LARGE).is_none());
            let work: Vec<_> = (0..expected)
                .map(|_| transmit.acquire(SMALL_SEND).unwrap())
                .collect();
            assert!(
                receive.used.load(Ordering::Relaxed) + transmit.used.load(Ordering::Relaxed)
                    <= total
            );
            drop((rx, tx, work));
            assert_eq!(receive.used.load(Ordering::Relaxed), 0);
            assert_eq!(transmit.used.load(Ordering::Relaxed), 0);
            assert!(transmit.acquire(usize::MAX).is_none());
        }
    }

    #[test]
    fn reservations_are_shared_bounded_and_returned_concurrently() {
        let budget = Budget::new(TOTAL_EXTRA / 2);
        std::thread::scope(|scope| {
            for _ in 0..32 {
                let budget = &budget;
                scope.spawn(move || {
                    for _ in 0..500 {
                        let r = budget.acquire(LARGE);
                        assert!(budget.used.load(Ordering::Relaxed) <= budget.limit);
                        std::thread::yield_now();
                        drop(r);
                    }
                });
            }
        });
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn failed_buffer_replacement_returns_budget_and_retains_data() {
        let budget = Budget::new(LARGE);
        let mut socket = Socket::new(
            SocketBuffer::new(vec![0; SMALL_RECV]),
            SocketBuffer::new(vec![0; SMALL_SEND]),
        );
        // Direct replacement cannot silently discard an occupied replacement.
        let mut replacement = SocketBuffer::new(vec![0; LARGE]);
        assert_eq!(replacement.enqueue_slice(b"occupied"), 8);
        let lease = budget.acquire(LARGE).unwrap();
        assert!(socket.replace_send_buffer(replacement).is_err());
        drop(lease);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        assert_eq!(socket.send_capacity(), SMALL_SEND);
    }

    /// Real TCP handshake and ACK processing, entirely within one in-memory
    /// interface. The peer socket lets tests decide when queued data is ACKed.
    struct Connected {
        interface: smoltcp::iface::Interface,
        device: smoltcp::phy::Loopback,
        sockets: smoltcp::iface::SocketSet<'static>,
        client: smoltcp::iface::SocketHandle,
        peer: smoltcp::iface::SocketHandle,
        clock_ms: i64,
    }

    impl Connected {
        fn new() -> Self {
            use smoltcp::iface::{Config, Interface, SocketSet};
            use smoltcp::phy::{Loopback, Medium};
            use smoltcp::time::Instant as SmolInstant;
            use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr};

            let mut device = Loopback::new(Medium::Ip);
            let mut interface = Interface::new(
                Config::new(HardwareAddress::Ip),
                &mut device,
                SmolInstant::from_millis(0),
            );
            interface.update_ip_addrs(|addresses| {
                addresses
                    .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                    .unwrap();
            });
            let mut sockets = SocketSet::new(Vec::new());
            let mut server = Socket::new(
                SocketBuffer::new(vec![0; SMALL_RECV]),
                SocketBuffer::new(vec![0; SMALL_SEND]),
            );
            server.set_ack_delay(None);
            server.listen(80).unwrap();
            let peer = sockets.add(server);
            let mut sender = Socket::new(
                SocketBuffer::new(vec![0; SMALL_RECV]),
                SocketBuffer::new(vec![0; SMALL_SEND]),
            );
            sender.set_receive_capacity_limit(LARGE).unwrap();
            sender.set_ack_delay(None);
            sender.set_nagle_enabled(false);
            sender
                .connect(
                    interface.context(),
                    (IpAddress::v4(127, 0, 0, 1), 80),
                    50000,
                )
                .unwrap();
            let client = sockets.add(sender);
            let mut fixture = Self {
                interface,
                device,
                sockets,
                client,
                peer,
                clock_ms: 0,
            };
            fixture.drive();
            assert_eq!(fixture.sender().state(), State::Established);
            fixture
        }

        fn sender(&mut self) -> &mut Socket<'static> {
            self.sockets.get_mut::<Socket<'static>>(self.client)
        }

        fn drive(&mut self) {
            for _ in 0..16 {
                self.clock_ms += 1;
                self.interface.poll(
                    smoltcp::time::Instant::from_millis(self.clock_ms),
                    &mut self.device,
                    &mut self.sockets,
                );
            }
        }

        fn transmit_without_peer_ack(&mut self) {
            self.clock_ms += 1;
            self.interface.poll_egress(
                smoltcp::time::Instant::from_millis(self.clock_ms),
                &mut self.device,
                &mut self.sockets,
            );
        }

        fn take_peer_data(&mut self, expected: &[u8]) {
            self.drive();
            let mut received = vec![0; expected.len()];
            let n = self
                .sockets
                .get_mut::<Socket<'static>>(self.peer)
                .recv_slice(&mut received)
                .unwrap();
            assert_eq!(n, expected.len());
            assert_eq!(received, expected);
            self.drive();
            assert_eq!(self.sender().send_queue(), 0);
        }
    }

    #[test]
    fn send_window_grows_for_bulk_but_not_control_data() {
        let budget = Budget::new(LARGE);
        let mut connection = Connected::new();
        let mut window = SendWindow::default();
        let now = Instant::now();
        assert_eq!(connection.sender().send_slice(b"control"), Ok(7));
        window.maintain_with(connection.sender(), now, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), SMALL_SEND);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        assert_eq!(window.deadline(), None);
        connection.take_peer_data(b"control");

        let bulk = vec![0x5a; GROW_AT];
        assert_eq!(connection.sender().send_slice(&bulk), Ok(GROW_AT));
        window.maintain_with(connection.sender(), now + RETRY, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), LARGE);
        assert_eq!(connection.sender().recv_capacity(), SMALL_RECV);
        assert_eq!(budget.used.load(Ordering::Relaxed), LARGE - SMALL_SEND);
        connection.take_peer_data(&bulk);
    }

    #[test]
    fn receive_window_requires_bulk_and_keeps_advertised_capacity_until_close() {
        let budget = Budget::new(LARGE);
        let mut connection = Connected::new();
        let mut window = ReceiveWindow::default();
        let now = Instant::now();
        window.maintain_with(connection.sender(), now, GROW_AT - 1, &budget);
        assert_eq!(connection.sender().recv_capacity(), SMALL_RECV);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        window.maintain_with(connection.sender(), now, 1, &budget);
        assert_eq!(connection.sender().recv_capacity(), LARGE);
        assert_eq!(budget.used.load(Ordering::Relaxed), LARGE - SMALL_RECV);
        window.maintain_with(connection.sender(), now + IDLE * 4, 0, &budget);
        assert_eq!(connection.sender().recv_capacity(), LARGE);
        assert_eq!(window.deadline(), None);
        assert_eq!(budget.used.load(Ordering::Relaxed), LARGE - SMALL_RECV);
        drop(connection);
        drop(window);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn receive_window_retries_after_budget_return_without_more_data() {
        let budget = Budget::new(LARGE);
        let held = budget.acquire(LARGE).unwrap();
        let mut connection = Connected::new();
        let mut window = ReceiveWindow::default();
        let now = Instant::now();
        window.maintain_with(connection.sender(), now, GROW_AT, &budget);
        assert_eq!(window.deadline(), Some(now + RETRY));
        assert_eq!(connection.sender().recv_capacity(), SMALL_RECV);
        drop(held);
        window.maintain_with(connection.sender(), now + RETRY, 0, &budget);
        assert_eq!(connection.sender().recv_capacity(), LARGE);
        assert_eq!(window.deadline(), None);
        assert_eq!(budget.used.load(Ordering::Relaxed), LARGE - SMALL_RECV);
    }

    #[test]
    fn receive_window_grows_for_response_after_local_write_half_close() {
        let budget = Budget::new(LARGE);
        let mut connection = Connected::new();
        connection.sender().close();
        connection.drive();
        assert_eq!(connection.sender().state(), State::FinWait2);
        let response = vec![0x5c; GROW_AT];
        assert_eq!(
            connection
                .sockets
                .get_mut::<Socket<'static>>(connection.peer)
                .send_slice(&response),
            Ok(GROW_AT)
        );
        connection.drive();
        let mut window = ReceiveWindow::default();
        window.maintain_with(connection.sender(), Instant::now(), 0, &budget);
        assert_eq!(connection.sender().recv_capacity(), LARGE);
        assert_eq!(connection.sender().state(), State::FinWait2);
        let mut received = vec![0; GROW_AT];
        assert_eq!(connection.sender().recv_slice(&mut received), Ok(GROW_AT));
        assert_eq!(received, response);
    }

    #[test]
    fn send_window_preserves_unacked_and_reclaims_only_after_empty_idle() {
        let budget = Budget::new(LARGE);
        let mut connection = Connected::new();
        let mut window = SendWindow::default();
        let now = Instant::now();
        let bulk = vec![0xa7; GROW_AT];
        assert_eq!(connection.sender().send_slice(&bulk), Ok(GROW_AT));
        window.maintain_with(connection.sender(), now, 0, &budget);
        connection.transmit_without_peer_ack();
        assert_eq!(connection.sender().send_queue(), GROW_AT);
        window.maintain_with(connection.sender(), now + IDLE * 2, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), LARGE);
        assert_eq!(window.deadline(), None);

        connection.take_peer_data(&bulk);
        let empty = now + IDLE * 3;
        window.maintain_with(connection.sender(), empty, 0, &budget);
        assert_eq!(window.deadline(), Some(empty + IDLE));
        window.maintain_with(
            connection.sender(),
            empty + IDLE - Duration::from_millis(1),
            0,
            &budget,
        );
        assert_eq!(connection.sender().send_capacity(), LARGE);
        window.maintain_with(connection.sender(), empty + IDLE, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), SMALL_SEND);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        assert_eq!(window.deadline(), None);
        assert_eq!(connection.sender().send_slice(b"after idle"), Ok(10));
        connection.take_peer_data(b"after idle");
    }

    #[test]
    fn send_window_retries_existing_fallback_after_budget_is_returned() {
        let budget = Budget::new(LARGE);
        let holder = budget.acquire(LARGE).unwrap();
        let mut connection = Connected::new();
        let mut window = SendWindow::default();
        let now = Instant::now();
        let bulk = vec![0x73; GROW_AT];
        assert_eq!(connection.sender().send_slice(&bulk), Ok(GROW_AT));
        window.maintain_with(connection.sender(), now, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), SMALL_SEND);
        assert_eq!(connection.sender().send_queue(), GROW_AT);
        assert_eq!(window.deadline(), Some(now + RETRY));
        drop(holder);
        window.maintain_with(
            connection.sender(),
            now + RETRY - Duration::from_millis(1),
            0,
            &budget,
        );
        assert_eq!(connection.sender().send_capacity(), SMALL_SEND);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        window.maintain_with(connection.sender(), now + RETRY, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), LARGE);
        assert_eq!(connection.sender().send_queue(), GROW_AT);
        assert_eq!(window.deadline(), None);
        connection.take_peer_data(&bulk);
        drop(connection);
        drop(window);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn send_window_pending_caller_data_prevents_idle_reclaim() {
        let budget = Budget::new(LARGE);
        let mut connection = Connected::new();
        let mut window = SendWindow::default();
        let now = Instant::now();
        window.maintain_with(connection.sender(), now, GROW_AT, &budget);
        assert_eq!(connection.sender().send_capacity(), LARGE);
        window.maintain_with(connection.sender(), now + IDLE, 0, &budget);
        assert_eq!(window.deadline(), Some(now + IDLE * 2));
        window.maintain_with(connection.sender(), now + IDLE * 2, 1, &budget);
        assert_eq!(connection.sender().send_capacity(), LARGE);
        assert_eq!(window.deadline(), None);
        window.maintain_with(connection.sender(), now + IDLE * 3, 0, &budget);
        window.maintain_with(connection.sender(), now + IDLE * 4, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), SMALL_SEND);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn send_window_retries_shrink_without_unaccounted_workspace() {
        let budget = Budget::new(LARGE);
        let mut connection = Connected::new();
        let mut window = SendWindow::default();
        let now = Instant::now();
        window.maintain_with(connection.sender(), now, GROW_AT, &budget);
        window.maintain_with(connection.sender(), now, 0, &budget);
        let workspace_holder = budget.acquire(SMALL_SEND).unwrap();
        assert_eq!(budget.used.load(Ordering::Relaxed), budget.limit);
        window.maintain_with(connection.sender(), now + IDLE, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), LARGE);
        assert_eq!(window.deadline(), Some(now + IDLE + RETRY));
        drop(workspace_holder);
        window.maintain_with(
            connection.sender(),
            now + IDLE + RETRY - Duration::from_millis(1),
            0,
            &budget,
        );
        assert_eq!(connection.sender().send_capacity(), LARGE);
        window.maintain_with(connection.sender(), now + IDLE + RETRY, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), SMALL_SEND);
        assert_eq!(window.deadline(), None);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn send_window_allows_half_closed_reply_but_never_grows_closed_socket() {
        let budget = Budget::new(LARGE);
        let mut closed = Socket::new(
            SocketBuffer::new(vec![0; SMALL_RECV]),
            SocketBuffer::new(vec![0; SMALL_SEND]),
        );
        let mut unused = SendWindow::default();
        let now = Instant::now();
        unused.maintain_with(&mut closed, now, GROW_AT, &budget);
        assert_eq!(closed.send_capacity(), SMALL_SEND);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
        assert_eq!(unused.deadline(), None);

        let mut connection = Connected::new();
        connection
            .sockets
            .get_mut::<Socket<'static>>(connection.peer)
            .close();
        connection.drive();
        assert_eq!(connection.sender().state(), State::CloseWait);
        let bulk = vec![0x39; GROW_AT];
        assert_eq!(connection.sender().send_slice(&bulk), Ok(GROW_AT));
        let mut window = SendWindow::default();
        window.maintain_with(connection.sender(), now, 0, &budget);
        assert_eq!(connection.sender().send_capacity(), LARGE);
        connection.take_peer_data(&bulk);
        drop(connection);
        drop(window);
        assert_eq!(budget.used.load(Ordering::Relaxed), 0);
    }
    // Insert inside tcp_window::tests after adopting receive_buffer().
    // These are storage/ownership smoke checks, not RSS or allocator benchmarks.

    #[test]
    fn receive_buffer_zero_and_boundary_sizes_are_initialized() {
        for capacity in [0, 1, 3, 127, 4095, 4096, 4097, SMALL_RECV, LARGE] {
            let mut ring = receive_buffer(capacity).expect("small bounded allocation");
            assert_eq!(ring.capacity(), capacity);
            assert!(ring.is_empty());
            assert_eq!(ring.window(), capacity);
            {
                // A new ring exposes its complete storage contiguously. Request
                // the entire capacity so a partially initialized tail is checked.
                let bytes = ring.enqueue_many(capacity);
                assert_eq!(bytes.len(), capacity);
                assert!(bytes.iter().all(|&byte| byte == 0));
                bytes.fill(0xa5);
            }
            assert_eq!(ring.len(), capacity);
            let bytes = ring.dequeue_many(capacity);
            assert_eq!(bytes.len(), capacity);
            assert!(bytes.iter().all(|&byte| byte == 0xa5));
            assert!(ring.is_empty());
        }
    }

    #[test]
    fn receive_buffer_repeated_write_and_drop_keeps_owned_storage_valid() {
        // Drop rings with queued bytes, then request fresh zeroed storage. This
        // exercises ordinary Vec ownership and permits allocator reuse without
        // requiring any particular allocation address or retention behaviour.
        for round in 0..24u8 {
            let capacity = [3, 4097, SMALL_RECV][usize::from(round) % 3];
            let mut ring = receive_buffer(capacity).expect("small bounded allocation");
            let pattern = 0xa5 ^ round;
            {
                let bytes = ring.enqueue_many(capacity);
                assert_eq!(bytes.len(), capacity);
                assert!(bytes.iter().all(|&byte| byte == 0));
                bytes.fill(pattern);
            }
            assert_eq!(ring.len(), capacity);
            assert!(
                ring.get_allocated(0, capacity)
                    .iter()
                    .all(|&byte| byte == pattern)
            );
            drop(ring);
        }
    }

    #[test]
    fn receive_buffer_rejects_unrepresentable_layout_sizes() {
        // Layout rejects these before any allocation attempt. Do not attempt a
        // huge but representable allocation to manufacture a real OOM condition.
        assert!(receive_buffer(usize::MAX).is_none());
        assert!(receive_buffer(isize::MAX as usize + 1).is_none());
    }
}
