//! Shared UDP packet path for direct / tproxy inbounds: a small NAT-like
//! session table keyed by (source, destination) that either hijacks DNS
//! (one exchange per datagram) or forwards through a connected outbound UDP
//! socket with an idle-timeout reverse reader (reference `udpnat.Service`).

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};
use std::time::{Duration, Instant};

use portable_atomic::AtomicU64;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UdpSocket;

use crate::dns::QueryMeta;
use crate::inbound::{AnyWrite, Target};
use crate::logging;
use crate::route::{ConnContext, Decision, Router};

/// Idle timeout for an outbound UDP flow (sing-box `C.UDPTimeout` family;
/// route-options `udp_timeout` is applied per-flow when present).
pub(crate) const DEFAULT_UDP_TIMEOUT: Duration = Duration::from_secs(120);
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

type FlowKey = (SocketAddr, SocketAddr);

/// Packets held back while the outbound socket is not writable. The old
/// code spent one `to_vec()` plus one `tokio::spawn` per packet here, which
/// turns a temporary full send buffer into a task-and-memory avalanche.
/// Now one writer task drains a bounded backlog and the newest packet is
/// dropped at the cap -- a UDP proxy loses datagrams under pressure anyway,
/// the difference is only whether it also loses its budget.
const UDP_BACKLOG_MAX: usize = 64;

/// How many datagrams a flow may hold while a QUIC ClientHello comes
/// together. A post-quantum hello takes two; past this it is not coming.
const MAX_SNIFF_DATAGRAMS: usize = 8;

/// Datagrams a flow may queue while its first datagram opens the outbound.
/// The opener sends them in arrival order once the flow is up; the ones past
/// the cap are dropped. A QUIC or DNS client sends a handful before it waits
/// for an answer, and a full 64 KiB datagram per slot keeps the worst case at
/// 1 MiB per opening flow (about 24 KiB at a 1500-byte MTU).
const MAX_OPENING_DATAGRAMS: usize = 16;

/// `hijack-dns` exchanges one hub runs at once; a query past it is dropped
/// and the client's resolver retries. Each holds a task and, toward a UDP
/// server, a socket and a 64 KiB buffer for up to the server timeout. Above
/// dnsmasq's default `dns-forward-max` (150), so a forwarder is not cut.
const MAX_DNS_HIJACKS: usize = 256;

/// What [`UdpHub::open_flow`] made of a flow's datagrams so far.
enum Opened {
    Flow(Arc<Flow>),
    /// the sniff wants another datagram; route anyway after this long
    Wait(Duration),
}

struct Flow {
    tracker: Option<Arc<crate::clash_state::ConnHandle>>,
    kind: FlowKind,
    last_ms: AtomicU64,
    timeout: Duration,
    /// datagrams `try_send` refused; drained in order by the writer task
    backlog: Mutex<VecDeque<Vec<u8>>>,
    /// exactly one writer task is (or will be) draining `backlog`
    writing: AtomicBool,
}

enum FlowKind {
    /// `action: hijack-dns` â€” stateless per-query exchange.
    Dns,
    /// Connected outbound socket + reverse pump to the client.
    Outbound { sock: Arc<UdpSocket> },
}

impl Flow {
    fn record_upload(&self, bytes: usize) {
        if let Some(tracker) = &self.tracker {
            tracker.add_upload(bytes as u64);
        }
    }

    fn touch(&self) {
        self.last_ms.store(now_ms(), Ordering::Relaxed);
    }

    fn idle(&self) -> Duration {
        let last = self.last_ms.load(Ordering::Relaxed);
        Duration::from_millis(now_ms().saturating_sub(last))
    }

    /// Hold a datagram the socket would not take and make sure one writer
    /// task will send it. The swap only wins when no writer is running, so
    /// there is never a second one; the writer's own re-check covers the
    /// race where it exits between this push and that swap.
    fn hold_back(self: &Arc<Self>, payload: &[u8]) {
        {
            let mut backlog = self.backlog.lock().expect("backlog");
            if backlog.len() < UDP_BACKLOG_MAX {
                backlog.push_back(payload.to_vec());
            }
        }
        if !self.writing.swap(true, Ordering::AcqRel) {
            let flow = Arc::clone(self);
            tokio::spawn(async move {
                flow.drain_backlog().await;
            });
        }
    }

    /// Send the backlog in order; release the flag once empty, re-checking
    /// once so a push that raced the release cannot be stranded with no
    /// writer looking at it.
    async fn drain_backlog(self: Arc<Self>) {
        let mut writing = WritingGuard(Some(&self));
        loop {
            loop {
                let next = self.backlog.lock().expect("backlog").pop_front();
                let Some(pkt) = next else {
                    break;
                };
                if let FlowKind::Outbound { sock } = &self.kind {
                    let result = tokio::select! {
                        result = tokio::time::timeout(self.timeout, sock.send(&pkt)) => result,
                        _ = async {
                            if let Some(tracker) = &self.tracker { tracker.close_signal().wait().await; }
                            else { std::future::pending::<()>().await; }
                        } => return,
                    };
                    match result {
                        Ok(Ok(n)) => self.record_upload(n),
                        _ => {
                            self.backlog.lock().expect("backlog").clear();
                            if let Some(tracker) = &self.tracker {
                                crate::clash_state::close(tracker.id());
                            }
                            return;
                        }
                    }
                }
            }
            writing.0 = None;
            self.writing.store(false, Ordering::Release);
            if self.backlog.lock().expect("backlog").is_empty() {
                return;
            }
            if self.writing.swap(true, Ordering::AcqRel) {
                return;
            }
            writing.0 = Some(&self);
        }
    }
}

struct WritingGuard<'a>(Option<&'a Flow>);
impl Drop for WritingGuard<'_> {
    fn drop(&mut self) {
        if let Some(flow) = self.0 {
            flow.writing.store(false, Ordering::Release);
        }
    }
}

pub(crate) struct StopHub(pub(crate) Arc<UdpHub>);
impl Drop for StopHub {
    fn drop(&mut self) {
        self.0.stop();
    }
}

static START_EPOCH: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();

pub(crate) fn now_ms() -> u64 {
    let epoch = START_EPOCH.get_or_init(Instant::now);
    epoch.elapsed().as_millis().min(u128::from(u64::MAX)) as u64
}

/// How a reply datagram is framed before it goes back.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum DatagramFrame {
    /// the bare payload: direct and tproxy inbounds answer a socket
    Raw,
    /// a SOCKS5 UDP relay header in front of it (mixed inbound)
    Socks,
    /// `[len:u16][payload]`, which is what `vmess.Service`'s `serverPacketConn`
    /// reads and writes for the UDP command
    LengthPrefixed,
    /// `[atyp][addr][port][payload]` (Shadowsocks AEAD UDP payload)
    Shadowsocks,
    /// `[len:u16][address][port][payload]` (PacketAddr mode in sing-box / v2fly)
    PacketAddr,
    /// Xray Mux.Cool Keep/Data reply, addressed by its session ID.
    Xudp(u16),
}

impl DatagramFrame {
    /// Frame `payload` for `dest` into `out` (cleared first).
    ///
    /// `Raw` needs no framing at all, so the send loops skip this entirely
    /// and hand `send` the recv-buffer slice â€” a `to_vec()` per datagram
    /// for a header of zero bytes.
    pub(crate) fn apply_into(self, dest: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
        out.clear();
        match self {
            DatagramFrame::Raw => out.extend_from_slice(payload),
            DatagramFrame::Socks => socks_udp_datagram(dest, payload, out),
            DatagramFrame::LengthPrefixed => {
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
            DatagramFrame::Shadowsocks => ss_udp_datagram(dest, payload, out),
            DatagramFrame::PacketAddr => {
                let mut body =
                    Vec::with_capacity(crate::outbound::packet::MAX_ADDR_PORT + payload.len());
                let target = Target::Ip(dest);
                let _ = crate::outbound::packet::put_addr_port(&mut body, &target);
                body.extend_from_slice(payload);
                out.extend_from_slice(&(body.len() as u16).to_be_bytes());
                out.extend_from_slice(&body);
            }
            DatagramFrame::Xudp(id) => {
                let meta_len = if dest.is_ipv4() { 12u16 } else { 24u16 };
                out.extend_from_slice(&meta_len.to_be_bytes());
                out.extend_from_slice(&id.to_be_bytes());
                out.extend_from_slice(&[2, 1, 2]); // Keep, Data, UDP
                out.extend_from_slice(&dest.port().to_be_bytes());
                match dest.ip() {
                    IpAddr::V4(ip) => {
                        out.push(1);
                        out.extend_from_slice(&ip.octets());
                    }
                    IpAddr::V6(ip) => {
                        out.push(3);
                        out.extend_from_slice(&ip.octets());
                    }
                }
                out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
                out.extend_from_slice(payload);
            }
        }
    }
}

fn ss_udp_datagram(dest: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.reserve(7 + payload.len());
    match dest.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&dest.port().to_be_bytes());
    out.extend_from_slice(payload);
}

#[allow(dead_code)]
#[derive(Clone, Debug)]
pub(crate) struct TunReply {
    pub src: SocketAddr,
    pub dest: SocketAddr,
    pub payload: Vec<u8>,
}

/// Where a reply datagram goes: back out of a socket the client is reading
/// from, down a stream it is reading a length-prefixed sequence off, or back to
/// the TUN interface.
#[derive(Clone)]
pub(crate) enum Reply {
    /// Weak on purpose: a session task that outlives its inbound must not be
    /// what holds the listening socket open, or the next `bind` after a
    /// reload gets `EADDRINUSE` (issue #5). The inbound owns the only strong
    /// handle, so aborting `serve` closes the port.
    Socket(Weak<UdpSocket>),
    Stream(Arc<tokio::sync::Mutex<AnyWrite>>),
    #[allow(dead_code)]
    Tun {
        sender: tokio::sync::mpsc::Sender<TunReply>,
    },
    Shadowsocks {
        socket: Weak<UdpSocket>,
        method: crate::outbound::shadowsocks::crypto::Method,
        master_key: Arc<Vec<u8>>,
    },
}

/// A weak reply handle that is still backed by a socket.
fn live(socket: &Weak<UdpSocket>) -> io::Result<Arc<UdpSocket>> {
    socket
        .upgrade()
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotConnected, "udp socket is gone"))
}

impl Reply {
    async fn send(
        &self,
        framed: &[u8],
        source: SocketAddr,
        remote: SocketAddr,
    ) -> std::io::Result<()> {
        match self {
            Reply::Socket(socket) => live(socket)?.send_to(framed, source).await.map(|_| ()),
            Reply::Stream(writer) => {
                let mut writer = writer.lock().await;
                writer.write_all(framed).await
            }
            Reply::Tun { sender } => sender
                .send(TunReply {
                    src: remote,
                    dest: source,
                    payload: framed.to_vec(),
                })
                .await
                .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "tun reply channel closed")),
            Reply::Shadowsocks {
                socket,
                method,
                master_key,
            } => {
                let socket = live(socket)?;
                use crate::outbound::shadowsocks::crypto::{Cipher, derive_subkey, random_bytes};
                let mut salt = vec![0u8; method.salt_len()];
                random_bytes(&mut salt)?;
                let subkey = derive_subkey(*method, master_key, &salt);
                let cipher = Cipher::new(*method, &subkey.0[..subkey.1]);
                let mut body = framed.to_vec();
                cipher
                    .seal(0, &mut body)
                    .map_err(|e| io::Error::other(format!("ss udp seal: {e}")))?;
                let mut packet = salt;
                packet.extend_from_slice(&body);
                socket.send_to(&packet, source).await.map(|_| ())
            }
        }
    }
}

struct PendingFlow {
    id: u64,
    queue: VecDeque<Vec<u8>>,
}

impl PendingFlow {
    /// Keep the first datagrams, drop the rest: once the flow is up the
    /// client's retransmits get through on the fast path anyway.
    fn push(&mut self, payload: &[u8]) {
        if self.queue.len() < MAX_OPENING_DATAGRAMS {
            self.queue.push_back(payload.to_vec());
        }
    }
}

/// The single task allowed to open one flow. It routes and opens on the
/// first datagram, then sends what queued up meanwhile. On error or drop the
/// queue is discarded and the entry released, so the next datagram of the
/// tuple starts a fresh open.
pub(crate) struct FlowOpener {
    hub: Arc<UdpHub>,
    key: FlowKey,
    id: u64,
    first: Option<Vec<u8>>,
}

impl FlowOpener {
    pub async fn run(mut self, reply: Reply, tag: &str) -> io::Result<()> {
        let (source, dest) = self.key;
        let target = Target::Ip(dest);
        let mut next = self.first.take();
        loop {
            let payload = match next.take() {
                Some(payload) => payload,
                None => match self.hub.next_pending(self.key, self.id) {
                    Some(payload) => payload,
                    None => return Ok(()),
                },
            };
            let Some(flow) = self
                .hub
                .flow_for(reply.clone(), source, dest, &payload, tag, &target)
                .await?
            else {
                continue;
            };
            if let FlowKind::Dns = flow.kind {
                // one exchange per query, as before: a slow answer must not
                // hold the next query of the same tuple
                let Ok(slot) = Arc::clone(&self.hub.dns_slots).try_acquire_owned() else {
                    logging::debug(format_args!("udp hijack-dns {tag} {source}: busy, dropped"));
                    continue;
                };
                let hub = Arc::clone(&self.hub);
                let reply = reply.clone();
                let tag = tag.to_string();
                tokio::spawn(async move {
                    let _slot = slot;
                    if let Err(err) = hub.hijack_one(reply, source, dest, &payload, &tag).await {
                        logging::debug(format_args!("udp hijack-dns {tag} {source}: {err}"));
                    }
                });
                continue;
            }
            self.hub
                .deliver(&flow, reply.clone(), source, dest, &payload, tag)
                .await?;
        }
    }
}

impl Drop for FlowOpener {
    fn drop(&mut self) {
        self.hub.release_pending(self.key, self.id);
    }
}

pub(crate) struct UdpHub {
    router: Arc<Router>,
    flows: RwLock<HashMap<FlowKey, Arc<Flow>>>,
    /// First packets for one tuple share an initialization gate, so a burst
    /// cannot create multiple proxy sessions whose idle tasks race each other.
    opening: Mutex<HashMap<FlowKey, Weak<tokio::sync::Mutex<()>>>>,
    /// Datagrams of flows not routed yet because a packet sniff asked for
    /// more, in arrival order. Touched only under the flow's opening gate.
    held: Mutex<HashMap<FlowKey, Vec<Vec<u8>>>>,
    /// Flows a [`FlowOpener`] is opening, with the datagrams that came in
    /// meanwhile. One opener owns each entry, tagged by its id.
    pending: Mutex<HashMap<FlowKey, PendingFlow>>,
    /// `pending.len()`, readable without the lock on the fast path
    pending_count: AtomicUsize,
    /// [`MAX_DNS_HIJACKS`] permits, one per running `hijack-dns` exchange
    dns_slots: Arc<tokio::sync::Semaphore>,
    next_opener: AtomicU64,
    reverse_tasks: Mutex<Vec<tokio::task::AbortHandle>>,
    timeout: Duration,
    /// how replies are framed before they go back
    frame: DatagramFrame,
}

impl UdpHub {
    pub fn new(router: Arc<Router>, timeout: Duration, frame: DatagramFrame) -> Arc<Self> {
        let hub = Arc::new(Self {
            router,
            flows: RwLock::new(HashMap::new()),
            opening: Mutex::new(HashMap::new()),
            held: Mutex::new(HashMap::new()),
            pending: Mutex::new(HashMap::new()),
            pending_count: AtomicUsize::new(0),
            dns_slots: Arc::new(tokio::sync::Semaphore::new(MAX_DNS_HIJACKS)),
            next_opener: AtomicU64::new(0),
            reverse_tasks: Mutex::new(Vec::new()),
            timeout: if timeout.is_zero() {
                DEFAULT_UDP_TIMEOUT
            } else {
                timeout
            },
            frame,
        });
        let sweeper = Arc::downgrade(&hub);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_INTERVAL).await;
                let Some(sweeper) = sweeper.upgrade() else {
                    return; // the connection this hub belongs to is gone
                };
                sweeper.sweep().await;
            }
        });
        hub
    }

    /// Release per-flow reply sockets when a transparent listener is stopped.
    pub fn stop(&self) {
        for task in self.reverse_tasks.lock().expect("reverse tasks").drain(..) {
            task.abort();
        }
        self.flows.write().expect("flows").clear();
        self.held.lock().expect("held").clear();
        let mut pending = self.pending.lock().expect("pending");
        pending.clear();
        self.pending_count.store(0, Ordering::Release);
    }

    async fn sweep(&self) {
        let mut flows = self.flows.write().expect("flows");
        flows.retain(|_, flow| flow.idle() < flow.timeout);
    }

    /// Fast path for the receive loops: an already-open outbound flow is fed
    /// straight from the reader â€” `try_send` with no copy and no per-packet
    /// task. Returns `false` when the flow is unknown (or is a DNS hijack,
    /// which needs the async exchange), and the caller should fall back to
    /// spawning the full [`UdpHub::handle`].
    pub fn try_existing(&self, source: SocketAddr, dest: SocketAddr, payload: &[u8]) -> bool {
        let flow = self
            .flows
            .read()
            .expect("flows")
            .get(&(source, dest))
            .cloned();
        let Some(flow) = flow else {
            return false;
        };
        if flow
            .tracker
            .as_ref()
            .is_some_and(|tracker| tracker.is_closed())
        {
            self.flows.write().expect("flows").remove(&(source, dest));
            return false;
        }
        let FlowKind::Outbound { sock } = &flow.kind else {
            return false;
        };
        // while a writer is draining the backlog, new packets go behind it:
        // a lucky try_send must not overtake the queued datagrams
        if flow.writing.load(Ordering::Acquire) {
            flow.hold_back(payload);
            flow.touch();
            return true;
        }
        match sock.try_send(payload) {
            Ok(n) => {
                flow.record_upload(n);
                flow.touch();
                true
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                flow.hold_back(payload);
                flow.touch();
                true
            }
            Err(err) => {
                logging::debug(format_args!("udp fast path send: {err}"));
                flow.touch();
                true
            }
        }
    }

    /// Entry point for receive loops that must not wait on an open. Sends
    /// the datagram on an open flow, queues it behind a flow that is still
    /// opening (bounded, see [`MAX_OPENING_DATAGRAMS`]), or returns the one
    /// [`FlowOpener`] for this tuple, which the caller runs in its own task.
    pub fn offer(
        self: &Arc<Self>,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
    ) -> Option<FlowOpener> {
        let key = (source, dest);
        // a flow still draining its queue keeps later datagrams behind it
        if self.pending_count.load(Ordering::Acquire) != 0 && self.queue_pending(key, payload) {
            return None;
        }
        if self.try_existing(source, dest, payload) {
            return None;
        }
        let mut pending = self.pending.lock().expect("pending");
        if let Some(entry) = pending.get_mut(&key) {
            entry.push(payload);
            return None;
        }
        let id = self.next_opener.fetch_add(1, Ordering::Relaxed);
        pending.insert(
            key,
            PendingFlow {
                id,
                queue: VecDeque::new(),
            },
        );
        self.pending_count.store(pending.len(), Ordering::Release);
        Some(FlowOpener {
            hub: Arc::clone(self),
            key,
            id,
            first: Some(payload.to_vec()),
        })
    }

    /// Queue behind an opening flow; `false` when the flow is not opening.
    fn queue_pending(&self, key: FlowKey, payload: &[u8]) -> bool {
        match self.pending.lock().expect("pending").get_mut(&key) {
            Some(entry) => {
                entry.push(payload);
                true
            }
            None => false,
        }
    }

    /// The next queued datagram of opener `id`, or release its entry when
    /// the queue is empty. Both happen under one lock, so a datagram either
    /// lands in the queue before the release or finds the flow open after it.
    fn next_pending(&self, key: FlowKey, id: u64) -> Option<Vec<u8>> {
        let mut pending = self.pending.lock().expect("pending");
        let entry = pending.get_mut(&key).filter(|entry| entry.id == id)?;
        if let Some(payload) = entry.queue.pop_front() {
            return Some(payload);
        }
        pending.remove(&key);
        self.pending_count.store(pending.len(), Ordering::Release);
        None
    }

    fn release_pending(&self, key: FlowKey, id: u64) {
        let mut pending = self.pending.lock().expect("pending");
        if pending.get(&key).is_some_and(|entry| entry.id == id) {
            pending.remove(&key);
            self.pending_count.store(pending.len(), Ordering::Release);
        }
    }

    #[cfg(test)]
    fn opening_flows(&self) -> usize {
        self.pending.lock().expect("pending").len()
    }

    /// Handle one datagram received from `source` toward `dest`, and answer it
    /// through `reply`.
    pub async fn handle(
        self: &Arc<Self>,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
    ) -> std::io::Result<()> {
        self.handle_routed(reply, source, dest, payload, tag, &Target::Ip(dest))
            .await
    }

    /// Preserve a named proxy destination in routing even though the flow key
    /// and the datagram reply use its resolved socket address.
    #[allow(clippy::too_many_arguments)]
    pub async fn handle_routed(
        self: &Arc<Self>,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
        target: &Target,
    ) -> std::io::Result<()> {
        let Some(flow) = self
            .flow_for(reply.clone(), source, dest, payload, tag, target)
            .await?
        else {
            return Ok(());
        };
        self.deliver(&flow, reply, source, dest, payload, tag).await
    }

    /// The live flow `payload` goes to, opening it if needed; datagrams a
    /// packet sniff held back are delivered before it returns. `None` means
    /// the sniff held `payload` too.
    async fn flow_for(
        self: &Arc<Self>,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
        target: &Target,
    ) -> std::io::Result<Option<Arc<Flow>>> {
        let key = (source, dest);
        if let Some(flow) = self.live_flow(key) {
            flow.touch();
            return Ok(Some(flow));
        }
        let _gate = self.gate(key).lock_owned().await;
        if let Some(existing) = self.live_flow(key) {
            existing.touch();
            return Ok(Some(existing));
        }
        let mut held = self
            .held
            .lock()
            .expect("held")
            .remove(&key)
            .unwrap_or_default();
        let first = held.is_empty();
        held.push(payload.to_vec());
        let force = held.len() >= MAX_SNIFF_DATAGRAMS;
        match self
            .open_flow(reply.clone(), source, dest, tag, target, &held, force)
            .await?
        {
            Opened::Wait(timeout) => {
                self.held.lock().expect("held").insert(key, held);
                if first {
                    self.route_held_after(key, timeout, reply, tag, target);
                }
                Ok(None)
            }
            Opened::Flow(flow) => {
                // the held ones go first; this datagram goes after them
                held.pop();
                for earlier in &held {
                    self.deliver(&flow, reply.clone(), source, dest, earlier, tag)
                        .await?;
                }
                Ok(Some(flow))
            }
        }
    }

    fn live_flow(&self, key: FlowKey) -> Option<Arc<Flow>> {
        self.flows
            .read()
            .expect("flows")
            .get(&key)
            .filter(|flow| {
                !flow
                    .tracker
                    .as_ref()
                    .is_some_and(|tracker| tracker.is_closed())
            })
            .cloned()
    }

    /// The opening gate of one tuple: first datagrams share it, so a burst
    /// cannot create multiple proxy sessions whose idle tasks race each other.
    fn gate(&self, key: FlowKey) -> Arc<tokio::sync::Mutex<()>> {
        let mut opening = self.opening.lock().expect("opening");
        opening.retain(|_, gate| gate.strong_count() != 0);
        match opening.get(&key).and_then(Weak::upgrade) {
            Some(gate) => gate,
            None => {
                let gate = Arc::new(tokio::sync::Mutex::new(()));
                opening.insert(key, Arc::downgrade(&gate));
                gate
            }
        }
    }

    async fn deliver(
        &self,
        flow: &Flow,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
    ) -> std::io::Result<()> {
        match &flow.kind {
            FlowKind::Dns => self.hijack_one(reply, source, dest, payload, tag).await,
            FlowKind::Outbound { sock } => {
                let n = sock.send(payload).await?;
                flow.record_upload(n);
                Ok(())
            }
        }
    }

    /// The rest of a split ClientHello may never come: once the sniff
    /// timeout runs out, route the flow on what it has and send what it held.
    fn route_held_after(
        self: &Arc<Self>,
        key: FlowKey,
        timeout: Duration,
        reply: Reply,
        tag: &str,
        target: &Target,
    ) {
        let hub = Arc::downgrade(self);
        let tag = tag.to_string();
        let target = target.clone();
        tokio::spawn(async move {
            tokio::time::sleep(timeout).await;
            let Some(hub) = hub.upgrade() else {
                return;
            };
            let (source, dest) = key;
            let _gate = hub.gate(key).lock_owned().await;
            // a later datagram may have completed the sniff meanwhile
            let Some(held) = hub.held.lock().expect("held").remove(&key) else {
                return;
            };
            let flow = match hub
                .open_flow(reply.clone(), source, dest, &tag, &target, &held, true)
                .await
            {
                Ok(Opened::Flow(flow)) => flow,
                Ok(Opened::Wait(_)) => return,
                Err(err) => {
                    logging::debug(format_args!("udp {tag} {source}: {err}"));
                    return;
                }
            };
            for datagram in &held {
                if let Err(err) = hub
                    .deliver(&flow, reply.clone(), source, dest, datagram, &tag)
                    .await
                {
                    logging::debug(format_args!("udp {tag} {source}: {err}"));
                    return;
                }
            }
        });
    }

    /// Route a new flow by its datagrams so far and open it. `force` routes
    /// even when the sniff would rather see another datagram.
    #[allow(clippy::too_many_arguments)]
    async fn open_flow(
        self: &Arc<Self>,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        tag: &str,
        target: &Target,
        datagrams: &[Vec<u8>],
        force: bool,
    ) -> std::io::Result<Opened> {
        let key = (source, dest);
        let mut ctx = ConnContext::new(tag, source, target.clone(), "udp");
        let views: Vec<&[u8]> = datagrams.iter().map(Vec::as_slice).collect();
        let decision = self.router.route_datagrams(&mut ctx, &views).await?;
        if !force && ctx.sniff_error == Some(crate::route::SniffError::NeedMore) {
            return Ok(Opened::Wait(
                ctx.sniff_timeout
                    .unwrap_or(crate::route::rule::DEFAULT_SNIFF_TIMEOUT),
            ));
        }
        logging::debug(format_args!(
            "udp {tag} {source} -> {} => {:?}",
            ctx.destination, decision
        ));
        let flow = match decision {
            Decision::HijackDns => Flow {
                tracker: None,
                kind: FlowKind::Dns,
                last_ms: AtomicU64::new(now_ms()),
                timeout: self.timeout,
                backlog: Mutex::new(VecDeque::new()),
                writing: AtomicBool::new(false),
            },
            Decision::Outbound(idx) => {
                let tracker = Arc::new(crate::clash_state::ConnHandle::open_with_context(
                    super::clash_meta(&ctx, &self.router, idx),
                    &ctx,
                    &self.router,
                ));
                let target = if ctx.udp_disable_domain_unmapping == Some(false)
                    && let Some(orig) = &ctx.origin_destination
                {
                    orig
                } else {
                    &ctx.destination
                };
                let timeout = ctx.udp_timeout.unwrap_or(self.timeout);
                // Outbound bridges read the per-flow idle policy before spawning
                // their pumps, including route-options overrides.
                let signal = tracker.close_signal();
                let sock = tokio::select! {
                    biased;
                    _ = signal.wait() => return Err(super::closed_by_api()),
                    result = crate::outbound::packet::UDP_BRIDGE_TIMEOUT
                        .scope(timeout, self.router.connect_udp_index(idx, target)) => result?,
                };
                let sock = Arc::new(sock);
                let task = spawn_reverse(
                    Arc::clone(&sock),
                    reply,
                    self.frame,
                    source,
                    tag,
                    timeout,
                    Arc::clone(self),
                    key,
                    Some(Arc::clone(&tracker)),
                );
                let mut tasks = self.reverse_tasks.lock().expect("reverse tasks");
                tasks.retain(|task| !task.is_finished());
                tasks.push(task);
                Flow {
                    tracker: Some(tracker),
                    kind: FlowKind::Outbound { sock },
                    last_ms: AtomicU64::new(now_ms()),
                    timeout,
                    backlog: Mutex::new(VecDeque::new()),
                    writing: AtomicBool::new(false),
                }
            }
        };
        let flow = Arc::new(flow);
        self.flows
            .write()
            .expect("flows")
            .insert(key, Arc::clone(&flow));
        Ok(Opened::Flow(flow))
    }

    async fn hijack_one(
        &self,
        reply: Reply,
        source: SocketAddr,
        dest: SocketAddr,
        payload: &[u8],
        tag: &str,
    ) -> std::io::Result<()> {
        let dns = crate::dns::current()
            .ok_or_else(|| std::io::Error::other("hijack-dns: dns service not configured"))?;
        let meta = QueryMeta {
            inbound: Some(tag.to_string()),
            source: Some(source.ip()),
            network: Some("udp".to_string()),
        };
        let resp = dns.exchange(&meta, payload, true).await?;
        logging::debug(format_args!(
            "udp hijack-dns {tag} {source} -> {dest}: {}B reply",
            resp.len()
        ));
        if self.frame == DatagramFrame::Raw {
            reply.send(&resp, source, dest).await?;
        } else {
            let mut framed = Vec::new();
            self.frame.apply_into(dest, &resp, &mut framed);
            reply.send(&framed, source, dest).await?;
        }
        Ok(())
    }

    fn touch_flow(&self, key: FlowKey, socket: &Arc<UdpSocket>) -> bool {
        let flows = self.flows.read().expect("flows");
        let Some(flow) = flows.get(&key) else {
            return false;
        };
        if let FlowKind::Outbound { sock } = &flow.kind
            && Arc::ptr_eq(sock, socket)
        {
            flow.touch();
            return true;
        }
        false
    }

    fn flow_is_active(&self, key: FlowKey, socket: &Arc<UdpSocket>) -> bool {
        self.flows
            .read()
            .expect("flows")
            .get(&key)
            .is_some_and(|flow| {
                matches!(&flow.kind, FlowKind::Outbound {sock} if Arc::ptr_eq(sock, socket))
                    && flow.idle() < flow.timeout
            })
    }

    pub fn has_active_flow(&self, source: SocketAddr, dest: SocketAddr) -> bool {
        self.flows
            .read()
            .expect("flows")
            .get(&(source, dest))
            .is_some_and(|flow| flow.idle() < flow.timeout)
    }

    async fn remove_flow(&self, key: FlowKey, socket: &Arc<UdpSocket>) {
        let mut flows = self.flows.write().expect("flows");
        if flows.get(&key).is_some_and(
            |flow| matches!(&flow.kind, FlowKind::Outbound {sock} if Arc::ptr_eq(sock, socket)),
        ) {
            flows.remove(&key);
        }
    }
}

/// The UDP command of a proxy-protocol server inbound: `[len:u16][payload]` in
/// both directions over the connection the client already opened, with every
/// datagram going to the destination its request head named.
///
/// `vmess.Service`'s `serverPacketConn` byte for byte -- a length, the payload,
/// and no address in either direction, because the head carried it. The
/// reference's vless and trojan inbounds wrap this the same way, and their
/// inbounds listen on TCP only: there is no second socket to bind.
pub(crate) async fn relay_stream_datagrams<S>(
    mut reader: S,
    writer: Arc<tokio::sync::Mutex<AnyWrite>>,
    source: SocketAddr,
    dest: SocketAddr,
    tag: &str,
    router: &Arc<Router>,
) -> std::io::Result<()>
where
    S: AsyncRead + Unpin,
{
    let hub = UdpHub::new(
        Arc::clone(router),
        Duration::ZERO,
        DatagramFrame::LengthPrefixed,
    );
    let _stop_hub = StopHub(Arc::clone(&hub));
    let reply = Reply::Stream(writer);
    let mut len = [0u8; 2];
    loop {
        if let Err(err) = reader.read_exact(&mut len).await {
            // a client that closes between datagrams has simply finished; only
            // a half-read length is a protocol error
            return match err.kind() {
                std::io::ErrorKind::UnexpectedEof if len == [0, 0] => Ok(()),
                _ => Err(err),
            };
        }
        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
        reader.read_exact(&mut payload).await?;
        hub.handle(reply.clone(), source, dest, &payload, tag)
            .await?;
    }
}

/// The destination a UDP command's head has to name: an address, because the
/// datagrams that follow carry none.
pub(crate) fn udp_destination(destination: &Target) -> std::io::Result<SocketAddr> {
    match destination {
        Target::Ip(addr) => Ok(*addr),
        Target::Domain(host, port) => {
            if let Ok(ip) = host.parse::<IpAddr>() {
                Ok(SocketAddr::new(ip, *port))
            } else {
                Err(std::io::Error::other(format!(
                    "the udp command names the destination in its head, and {host:?} is not an address"
                )))
            }
        }
    }
}

/// SOCKS5 UDP datagram header `[RSV][RSV][FRAG][ATYP][ADDR][PORT]` + payload,
/// appended to `out` (cleared by the caller through `apply_into`).
fn socks_udp_datagram(dest: SocketAddr, payload: &[u8], out: &mut Vec<u8>) {
    out.reserve(10 + payload.len());
    out.extend_from_slice(&[0, 0, 0]);
    match dest.ip() {
        IpAddr::V4(ip) => {
            out.push(0x01);
            out.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            out.push(0x04);
            out.extend_from_slice(&ip.octets());
        }
    }
    out.extend_from_slice(&dest.port().to_be_bytes());
    out.extend_from_slice(payload);
}

#[allow(clippy::too_many_arguments)]
fn spawn_reverse(
    outbound: Arc<UdpSocket>,
    reply: Reply,
    frame: DatagramFrame,
    source: SocketAddr,
    tag: &str,
    idle: Duration,
    hub: Arc<UdpHub>,
    key: FlowKey,
    tracker: Option<Arc<crate::clash_state::ConnHandle>>,
) -> tokio::task::AbortHandle {
    let tag = tag.to_string();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        // framing buffer for non-Raw frames, kept across datagrams so the
        // capacity survives; Raw replies borrow `buf` directly and never
        // touch it
        let mut out = Vec::new();
        loop {
            let recv = tokio::select! {
                result = tokio::time::timeout(idle, outbound.recv(&mut buf)) => result,
                _ = async {
                    if let Some(tracker) = &tracker { tracker.close_signal().wait().await; }
                    else { std::future::pending::<()>().await; }
                } => {
                    hub.remove_flow(key, &outbound).await;
                    return;
                }
            };
            match recv {
                Ok(Ok(n)) => {
                    // Both directions count as activity. A receive-only media
                    // flow must keep its established proxy/NAT session.
                    if !hub.touch_flow(key, &outbound) {
                        return;
                    }
                    if let Some(tracker) = &tracker {
                        tracker.add_download(n as u64);
                    }
                    let framed: &[u8] = if frame == DatagramFrame::Raw {
                        &buf[..n]
                    } else {
                        frame.apply_into(key.1, &buf[..n], &mut out);
                        &out
                    };
                    if let Err(err) = reply.send(framed, source, key.1).await {
                        logging::debug(format_args!("udp reverse {tag} {source}: {err}"));
                        hub.remove_flow(key, &outbound).await;
                        return;
                    }
                }
                Ok(Err(err)) => {
                    logging::debug(format_args!("udp reverse {tag} {source}: {err}"));
                    hub.remove_flow(key, &outbound).await;
                    return;
                }
                Err(_) => {
                    // Sending without replies is also a live UDP session.
                    if hub.flow_is_active(key, &outbound) {
                        continue;
                    }
                    // Idle timeout â€” drop the flow (reference udpnat purge).
                    hub.remove_flow(key, &outbound).await;
                    return;
                }
            }
        }
    })
    .abort_handle()
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn selector_switch_closes_udp_flow_and_next_packet_reopens_it() {
        let router = Router::new(&serde_json::json!({"outbounds":[
            {"type":"direct","tag":"a"}, {"type":"direct","tag":"b"},
            {"type":"selector","tag":"group","outbounds":["a","b"],"interrupt_exist_connections":true}
        ],"route":{"final":"group"}})).unwrap();
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let source = reply.local_addr().unwrap();
        let dest = server.local_addr().unwrap();
        let hub = UdpHub::new(router.clone(), Duration::from_secs(60), DatagramFrame::Raw);
        hub.handle(
            Reply::Socket(Arc::downgrade(&reply)),
            source,
            dest,
            b"old",
            "test",
        )
        .await
        .unwrap();
        let old = hub
            .flows
            .read()
            .unwrap()
            .get(&(source, dest))
            .unwrap()
            .tracker
            .as_ref()
            .unwrap()
            .id();
        router.select_member("group", "b").unwrap();
        hub.handle(
            Reply::Socket(Arc::downgrade(&reply)),
            source,
            dest,
            b"new",
            "test",
        )
        .await
        .unwrap();
        let flows = hub.flows.read().unwrap();
        let fresh = flows
            .get(&(source, dest))
            .unwrap()
            .tracker
            .as_ref()
            .unwrap();
        assert_ne!(old, fresh.id());
        assert!(!fresh.is_closed());
        drop(flows);
        hub.stop();
    }

    #[tokio::test]
    async fn stream_eof_releases_the_dedicated_udp_hub() {
        use tokio::io::AsyncWriteExt;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dest = server.local_addr().unwrap();
        let (mut caller, reader) = tokio::io::duplex(1024);
        let writer = Arc::new(tokio::sync::Mutex::new(
            Box::new(tokio::io::sink()) as AnyWrite
        ));
        let router = direct_test_router();
        let relay = tokio::spawn(async move {
            relay_stream_datagrams(
                reader,
                writer,
                "127.0.0.1:12345".parse().unwrap(),
                dest,
                "test",
                &router,
            )
            .await
        });
        caller.write_all(b"\x00\x04ping").await.unwrap();
        let mut bytes = [0; 16];
        let (_, peer) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        drop(caller);
        let _ = tokio::time::timeout(Duration::from_secs(2), relay)
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if UdpSocket::bind(peer).await.is_ok() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("UDP socket leaked after stream EOF");
    }

    use super::*;

    #[tokio::test]
    async fn udp_tracker_counts_first_fast_queued_and_reverse_payloads() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let source = reply.local_addr().unwrap();
        let dest = server.local_addr().unwrap();
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_secs(60),
            DatagramFrame::Raw,
        );
        hub.handle(
            Reply::Socket(Arc::downgrade(&reply)),
            source,
            dest,
            b"first",
            "test",
        )
        .await
        .unwrap();
        let mut buffer = [0u8; 128];
        let (_, peer) = tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert!(hub.try_existing(source, dest, b"fast"));
        tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        let flow = hub
            .flows
            .read()
            .unwrap()
            .get(&(source, dest))
            .unwrap()
            .clone();
        flow.hold_back(b"queued");
        tokio::time::timeout(Duration::from_secs(2), server.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        server.send_to(b"reply", peer).await.unwrap();
        let count = tokio::time::timeout(Duration::from_secs(2), reply.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..count], b"reply");
        let id = flow.tracker.as_ref().unwrap().id();
        let (views, _, _) = crate::clash_state::snapshot();
        let view = views.iter().find(|view| view.id == id.to_string()).unwrap();
        assert_eq!(view.upload, 5 + 4 + 6);
        assert_eq!(view.download, 5);
        hub.stop();
    }

    fn direct_test_router() -> Arc<Router> {
        Router::new(&serde_json::json!({
            "outbounds": [{"type": "direct", "tag": "out"}],
            "route": {"final": "out"}
        }))
        .expect("direct router")
    }

    #[tokio::test]
    async fn removed_udp_rule_closes_flow_and_next_datagram_is_rerouted() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let source = reply.local_addr().unwrap();
        let dest = server.local_addr().unwrap();
        let root = serde_json::json!({"outbounds":[{"type":"direct","tag":"chosen"},{"type":"direct","tag":"fallback"}],"route":{"final":"fallback","rules":[{"ip_cidr":["127.0.0.1/32"],"outbound":"chosen"}]}});
        let mut instance = crate::start(&root).await.unwrap();
        let router = instance.router();
        let hub = UdpHub::new(
            Arc::clone(&router),
            Duration::from_secs(60),
            DatagramFrame::Raw,
        );
        hub.handle(
            Reply::Socket(Arc::downgrade(&reply)),
            source,
            dest,
            b"old",
            "test",
        )
        .await
        .unwrap();
        let original = hub
            .flows
            .read()
            .unwrap()
            .get(&(source, dest))
            .unwrap()
            .tracker
            .as_ref()
            .unwrap()
            .id();
        let mut next = root.clone();
        next["route"]["rules"] = serde_json::json!([]);
        instance.reload_in_place(&next).await.unwrap();
        let result = crate::clash_state::close_invalid_routes(&router).await;
        assert!(result["closed"].as_u64().unwrap() > 0);
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(!hub.flows.read().unwrap().contains_key(&(source, dest)));
        hub.handle(
            Reply::Socket(Arc::downgrade(&reply)),
            source,
            dest,
            b"new",
            "test",
        )
        .await
        .unwrap();
        let tracker = hub
            .flows
            .read()
            .unwrap()
            .get(&(source, dest))
            .unwrap()
            .tracker
            .as_ref()
            .unwrap()
            .id();
        assert_ne!(original, tracker);
        hub.stop();
        instance.shutdown_wait().await;
    }
    #[tokio::test]
    async fn reverse_traffic_keeps_a_receive_only_udp_flow_alive() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("server");
        let client = UdpSocket::bind("127.0.0.1:0").await.expect("client");
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let source = client.local_addr().expect("source");
        let dest = server.local_addr().expect("dest");
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_millis(100),
            DatagramFrame::Raw,
        );
        hub.handle(
            Reply::Socket(Arc::downgrade(&reply)),
            source,
            dest,
            b"start",
            "test",
        )
        .await
        .expect("open flow");
        let mut buf = [0; 64];
        let (_, upstream) = server.recv_from(&mut buf).await.expect("first packet");
        // The client does not transmit again, while the server remains active.
        for sequence in 0..12u8 {
            server
                .send_to(&[sequence], upstream)
                .await
                .expect("server reply");
            let n = tokio::time::timeout(Duration::from_secs(1), client.recv(&mut buf))
                .await
                .expect("reply deadline")
                .expect("reply");
            assert_eq!(&buf[..n], &[sequence]);
            hub.sweep().await;
            assert!(
                hub.flows
                    .read()
                    .expect("flows")
                    .contains_key(&(source, dest)),
                "active receive-only flow was swept at packet {sequence}"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        hub.stop();
    }

    #[tokio::test]
    async fn an_old_reverse_task_cannot_remove_a_replacement_udp_flow() {
        let old = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("old"));
        let replacement = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("replacement"));
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_secs(1),
            DatagramFrame::Raw,
        );
        let key = (
            "127.0.0.1:30000".parse().expect("source"),
            "127.0.0.1:30001".parse().expect("dest"),
        );
        hub.flows.write().expect("flows").insert(
            key,
            Arc::new(Flow {
                tracker: None,
                kind: FlowKind::Outbound { sock: replacement },
                last_ms: AtomicU64::new(now_ms()),
                timeout: Duration::from_secs(1),
                backlog: Mutex::new(VecDeque::new()),
                writing: AtomicBool::new(false),
            }),
        );
        let task = spawn_reverse(
            old,
            Reply::Socket(Arc::downgrade(&reply)),
            DatagramFrame::Raw,
            key.0,
            "test",
            Duration::from_millis(20),
            Arc::clone(&hub),
            key,
            None,
        );
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert!(task.is_finished(), "old reverse task must finish");
        assert!(
            hub.flows.read().expect("flows").contains_key(&key),
            "old timeout removed a newer flow with the same tuple"
        );
        hub.stop();
    }

    #[tokio::test]
    async fn sending_without_replies_keeps_the_same_udp_session() {
        let server = UdpSocket::bind("127.0.0.1:0").await.expect("server");
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let source = reply.local_addr().expect("source");
        let dest = server.local_addr().expect("dest");
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_millis(100),
            DatagramFrame::Raw,
        );
        let mut first_peer = None;
        let mut buf = [0; 64];
        for sequence in 0..12u8 {
            hub.handle(
                Reply::Socket(Arc::downgrade(&reply)),
                source,
                dest,
                &[sequence],
                "test",
            )
            .await
            .expect("send");
            let (_, peer) =
                tokio::time::timeout(Duration::from_secs(1), server.recv_from(&mut buf))
                    .await
                    .expect("receive deadline")
                    .expect("receive");
            assert_eq!(
                peer,
                *first_peer.get_or_insert(peer),
                "active sender's NAT session changed"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        hub.stop();
    }

    #[tokio::test]
    async fn concurrent_first_datagrams_open_one_proxy_udp_session() {
        use std::sync::atomic::AtomicUsize;
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy");
        let proxy = listener.local_addr().expect("proxy addr");
        let accepted = Arc::new(AtomicUsize::new(0));
        let count = Arc::clone(&accepted);
        let server = tokio::spawn(async move {
            let mut streams = Vec::new();
            loop {
                let (mut stream, _) = listener.accept().await.expect("accept");
                count.fetch_add(1, Ordering::Relaxed);
                let mut header = [0; 19];
                stream
                    .read_exact(&mut header)
                    .await
                    .expect("VLESS Mux header");
                assert_eq!(header[18], crate::outbound::packet::CMD_MUX);
                stream.write_all(&[0, 0]).await.expect("VLESS response");
                streams.push(stream);
            }
        });
        let router = Router::new(&serde_json::json!({
            "outbounds": [{"type":"vless", "tag":"out", "server":"127.0.0.1",
                "server_port":proxy.port(), "uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}],
            "route":{"final":"out"}
        }))
        .expect("router");
        let hub = UdpHub::new(router, Duration::from_secs(1), DatagramFrame::Raw);
        let reply = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"));
        let barrier = Arc::new(tokio::sync::Barrier::new(17));
        let mut requests = tokio::task::JoinSet::new();
        for sequence in 0..16u8 {
            let hub = Arc::clone(&hub);
            let reply = Arc::clone(&reply);
            let barrier = Arc::clone(&barrier);
            requests.spawn(async move {
                barrier.wait().await;
                hub.handle(
                    Reply::Socket(Arc::downgrade(&reply)),
                    "127.0.0.1:30000".parse().expect("source"),
                    "192.0.2.1:50000".parse().expect("dest"),
                    &[sequence],
                    "test",
                )
                .await
            });
        }
        barrier.wait().await;
        while let Some(request) = requests.join_next().await {
            request.expect("task").expect("send");
        }
        // connect_udp returns before the proxy's accept loop has drained its
        // listen backlog. Observe the sockets after that loop gets scheduled.
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert_eq!(
            accepted.load(Ordering::Relaxed),
            1,
            "first-packet burst opened duplicate proxy UDP sessions"
        );
        hub.stop();
        server.abort();
    }

    /// The datagrams of a UDP command carry no address, so the head has to name
    /// one. A name cannot be sent to, and a session that accepted one would
    /// answer nothing for as long as the client waited -- so it is refused with
    /// the name in the message instead.
    #[test]
    fn a_udp_command_destination_has_to_be_an_address() {
        assert_eq!(
            udp_destination(&Target::Ip("10.0.0.1:53".parse().expect("addr"))).expect("ip"),
            "10.0.0.1:53".parse::<SocketAddr>().expect("addr")
        );
        assert_eq!(
            udp_destination(&Target::Ip("[::1]:5353".parse().expect("addr"))).expect("v6"),
            "[::1]:5353".parse::<SocketAddr>().expect("addr")
        );
        let err = udp_destination(&Target::Domain("dns.example.com".into(), 53))
            .expect_err("a name was accepted");
        assert!(err.to_string().contains("dns.example.com"), "{err}");
    }

    /// The framing is the reference's `serverPacketConn`: a length and the
    /// payload, with the address nowhere in it.
    #[test]
    fn length_prefixed_frames_carry_no_address() {
        let dest = "10.0.0.1:53".parse::<SocketAddr>().expect("addr");
        let mut out = Vec::new();
        DatagramFrame::LengthPrefixed.apply_into(dest, b"hello", &mut out);
        assert_eq!(out, b"\x00\x05hello".to_vec());
        DatagramFrame::Raw.apply_into(dest, b"hello", &mut out);
        assert_eq!(out, b"hello".to_vec());
        DatagramFrame::Socks.apply_into(dest, b"hello", &mut out);
        assert_eq!(&out[..3], &[0, 0, 0]);
        assert_eq!(&out[3..], b"\x01\x0a\x00\x00\x01\x00\x35hello");
    }

    /// A datagram the length describes has to arrive whole and nothing else:
    /// the relay reads exactly that many bytes, so a frame that is one byte
    /// short would eat the next frame's length.
    #[test]
    fn a_length_prefix_covers_its_whole_payload() {
        let dest = "10.0.0.1:53".parse::<SocketAddr>().expect("addr");
        for len in [1usize, 2, 255, 1400, 65_535] {
            let payload = vec![(len % 251) as u8; len];
            let mut framed = Vec::new();
            DatagramFrame::LengthPrefixed.apply_into(dest, &payload, &mut framed);
            assert_eq!(framed.len(), len + 2, "{len}");
            assert_eq!(
                u16::from_be_bytes([framed[0], framed[1]]) as usize,
                len,
                "{len}"
            );
            assert_eq!(&framed[2..], &payload[..], "{len}");
        }
    }

    #[test]
    fn packetaddr_frame_roundtrip() {
        let dest = "1.2.3.4:53".parse::<SocketAddr>().expect("addr");
        let payload = b"dns-packet";
        let mut framed = Vec::new();
        DatagramFrame::PacketAddr.apply_into(dest, payload, &mut framed);
        assert!(framed.len() > 2);
        let len = u16::from_be_bytes([framed[0], framed[1]]) as usize;
        assert_eq!(len, framed.len() - 2);
        let (got_target, got_payload) =
            crate::outbound::packet::take_addr_port(&framed[2..]).expect("take addr port");
        assert_eq!(got_target, Target::Ip(dest));
        assert_eq!(got_payload, payload);
    }

    /// VLESS-over-WebSocket server that holds every upgrade until the test
    /// answers it: `true` opens the flow, `false` closes the connection,
    /// which fails the open.
    struct HeldProxy {
        port: u16,
        requests: tokio::sync::mpsc::UnboundedReceiver<tokio::sync::oneshot::Sender<bool>>,
        datagrams: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    }

    impl HeldProxy {
        async fn start() -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("proxy");
            let port = listener.local_addr().expect("proxy addr").port();
            let (request_tx, requests) = tokio::sync::mpsc::unbounded_channel();
            let (datagram_tx, datagrams) = tokio::sync::mpsc::unbounded_channel();
            tokio::spawn(async move {
                while let Ok((stream, _)) = listener.accept().await {
                    tokio::spawn(serve_held(stream, request_tx.clone(), datagram_tx.clone()));
                }
            });
            Self {
                port,
                requests,
                datagrams,
            }
        }

        fn router(&self) -> Arc<Router> {
            Router::new(&serde_json::json!({
                "outbounds": [{"type": "vless", "tag": "out", "server": "127.0.0.1",
                    "server_port": self.port, "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
                    "packet_encoding": "", "transport": {"type": "ws", "path": "/"}}],
                "route": {"final": "out"}
            }))
            .expect("proxy router")
        }

        async fn next_request(&mut self) -> tokio::sync::oneshot::Sender<bool> {
            tokio::time::timeout(Duration::from_secs(5), self.requests.recv())
                .await
                .expect("dial deadline")
                .expect("proxy server")
        }

        /// No further dial shows up within a short window.
        async fn assert_no_request(&mut self) {
            let next = tokio::time::timeout(Duration::from_millis(200), self.requests.recv()).await;
            assert!(next.is_err(), "an unexpected extra dial reached the proxy");
        }

        /// Payloads that reached the server within `window`.
        async fn received(&mut self, window: Duration) -> Vec<Vec<u8>> {
            let mut out = Vec::new();
            let deadline = tokio::time::Instant::now() + window;
            while let Ok(Some(payload)) =
                tokio::time::timeout_at(deadline, self.datagrams.recv()).await
            {
                out.push(payload);
            }
            out
        }
    }

    /// One VLESS-over-WebSocket connection: hold the upgrade until the test
    /// decides, then forward the `[len][payload]` datagrams it carries.
    async fn serve_held(
        mut stream: tokio::net::TcpStream,
        requests: tokio::sync::mpsc::UnboundedSender<tokio::sync::oneshot::Sender<bool>>,
        datagrams: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    ) -> Option<()> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).await.ok()?;
            head.push(byte[0]);
        }
        let head = String::from_utf8(head).ok()?;
        let key = head.lines().find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.trim()
                .eq_ignore_ascii_case("sec-websocket-key")
                .then(|| value.trim().to_string())
        })?;
        let (answer, decided) = tokio::sync::oneshot::channel();
        requests.send(answer).ok()?;
        if decided.await != Ok(true) {
            return None; // closing before the upgrade fails the open
        }
        crate::ws::accept(&mut stream, &key).await.ok()?;
        let mut data = Vec::new();
        // VLESS head for an IPv4 target: version, uuid, addons, command, port,
        // address type, address
        let mut head_left = 26;
        loop {
            let mut frame = [0u8; 2];
            stream.read_exact(&mut frame).await.ok()?;
            let len = match frame[1] & 0x7f {
                126 => {
                    let mut len = [0u8; 2];
                    stream.read_exact(&mut len).await.ok()?;
                    u64::from(u16::from_be_bytes(len))
                }
                127 => {
                    let mut len = [0u8; 8];
                    stream.read_exact(&mut len).await.ok()?;
                    u64::from_be_bytes(len)
                }
                len => u64::from(len),
            };
            let mut mask = [0u8; 4];
            if frame[1] & 0x80 != 0 {
                stream.read_exact(&mut mask).await.ok()?;
            }
            let mut payload = vec![0u8; usize::try_from(len).ok()?];
            stream.read_exact(&mut payload).await.ok()?;
            for (i, byte) in payload.iter_mut().enumerate() {
                *byte ^= mask[i % 4];
            }
            match frame[0] & 0x0f {
                0..=2 => data.extend_from_slice(&payload),
                8 => return None,
                _ => continue,
            }
            let skip = head_left.min(data.len());
            data.drain(..skip);
            head_left -= skip;
            while data.len() >= 2 {
                let n = usize::from(u16::from_be_bytes([data[0], data[1]]));
                if data.len() < 2 + n {
                    break;
                }
                datagrams.send(data[2..2 + n].to_vec()).ok()?;
                data.drain(..2 + n);
            }
        }
    }

    fn opener_flow(port: u16) -> (SocketAddr, SocketAddr) {
        (
            SocketAddr::from(([127, 0, 0, 1], port)),
            "192.0.2.1:9".parse().expect("dest"),
        )
    }

    async fn reply_socket() -> Arc<UdpSocket> {
        Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("reply"))
    }

    #[tokio::test]
    async fn datagrams_of_an_opening_flow_queue_behind_its_one_opener() {
        let mut proxy = HeldProxy::start().await;
        let hub = UdpHub::new(proxy.router(), Duration::from_secs(60), DatagramFrame::Raw);
        let reply = reply_socket().await;
        let (source, dest) = opener_flow(31000);
        let mut openers = Vec::new();
        for sequence in 0..200u8 {
            openers.extend(hub.offer(source, dest, &[sequence]));
        }
        assert_eq!(openers.len(), 1, "one opener for the whole burst");
        assert_eq!(hub.opening_flows(), 1);
        let opener = openers.pop().expect("opener");
        let run = tokio::spawn(async move {
            opener
                .run(Reply::Socket(Arc::downgrade(&reply)), "test")
                .await
        });
        let open = proxy.next_request().await;
        assert!(hub.offer(source, dest, &[200]).is_none());
        open.send(true).expect("accept");
        run.await.expect("opener task").expect("opened");
        let expected: Vec<Vec<u8>> = (0..=MAX_OPENING_DATAGRAMS as u8).map(|s| vec![s]).collect();
        assert_eq!(proxy.received(Duration::from_millis(300)).await, expected);
        assert_eq!(hub.opening_flows(), 0, "the entry is released once drained");
        assert_eq!(hub.pending_count.load(Ordering::Acquire), 0);
        assert!(
            hub.offer(source, dest, b"late").is_none(),
            "open flow, fast path"
        );
        assert_eq!(
            proxy.received(Duration::from_millis(300)).await,
            vec![b"late".to_vec()]
        );
        proxy.assert_no_request().await;
        hub.stop();
    }

    #[tokio::test]
    async fn a_slow_opening_flow_does_not_hold_back_another_flow() {
        let mut proxy = HeldProxy::start().await;
        let hub = UdpHub::new(proxy.router(), Duration::from_secs(60), DatagramFrame::Raw);
        let reply = reply_socket().await;
        let (slow_source, dest) = opener_flow(31001);
        let (fast_source, _) = opener_flow(31002);
        let slow = hub.offer(slow_source, dest, b"slow").expect("slow opener");
        let slow_reply = Reply::Socket(Arc::downgrade(&reply));
        let slow_run = tokio::spawn(async move { slow.run(slow_reply, "test").await });
        let slow_open = proxy.next_request().await;

        let fast = hub.offer(fast_source, dest, b"fast").expect("fast opener");
        let fast_reply = Reply::Socket(Arc::downgrade(&reply));
        let fast_run = tokio::spawn(async move { fast.run(fast_reply, "test").await });
        proxy.next_request().await.send(true).expect("accept fast");
        fast_run.await.expect("fast task").expect("fast opened");
        assert_eq!(
            proxy.received(Duration::from_millis(300)).await,
            vec![b"fast".to_vec()]
        );
        assert_eq!(
            hub.opening_flows(),
            1,
            "only the slow flow is still opening"
        );

        slow_open.send(false).expect("reject slow");
        assert!(slow_run.await.expect("slow task").is_err());
        assert_eq!(hub.opening_flows(), 0);
        hub.stop();
    }

    #[tokio::test]
    async fn a_failed_open_drops_its_queue_and_the_next_datagram_retries() {
        let mut proxy = HeldProxy::start().await;
        let hub = UdpHub::new(proxy.router(), Duration::from_secs(60), DatagramFrame::Raw);
        let reply = reply_socket().await;
        let (source, dest) = opener_flow(31003);
        let opener = hub.offer(source, dest, b"first").expect("opener");
        for _ in 0..50 {
            assert!(hub.offer(source, dest, b"queued").is_none());
        }
        let first_reply = Reply::Socket(Arc::downgrade(&reply));
        let run = tokio::spawn(async move { opener.run(first_reply, "test").await });
        proxy.next_request().await.send(false).expect("reject");
        assert!(run.await.expect("opener task").is_err());
        assert_eq!(hub.opening_flows(), 0, "a failed open leaves no entry");
        assert_eq!(hub.pending_count.load(Ordering::Acquire), 0);
        proxy.assert_no_request().await;
        assert!(proxy.received(Duration::from_millis(100)).await.is_empty());

        let retry = hub.offer(source, dest, b"retry").expect("fresh opener");
        let retry_reply = Reply::Socket(Arc::downgrade(&reply));
        let run = tokio::spawn(async move { retry.run(retry_reply, "test").await });
        proxy.next_request().await.send(true).expect("accept");
        run.await.expect("retry task").expect("opened");
        assert_eq!(
            proxy.received(Duration::from_millis(300)).await,
            vec![b"retry".to_vec()]
        );
        assert_eq!(hub.opening_flows(), 0);
        hub.stop();
    }

    #[tokio::test]
    async fn a_dropped_opener_releases_its_flow() {
        let hub = UdpHub::new(
            direct_test_router(),
            Duration::from_secs(60),
            DatagramFrame::Raw,
        );
        let (source, dest) = opener_flow(31004);
        let opener = hub.offer(source, dest, b"one").expect("opener");
        assert!(hub.offer(source, dest, b"two").is_none());
        drop(opener);
        assert_eq!(hub.opening_flows(), 0);
        assert!(hub.offer(source, dest, b"three").is_some());
        assert_eq!(hub.opening_flows(), 0, "and so does the second one");
        hub.stop();
    }
}
