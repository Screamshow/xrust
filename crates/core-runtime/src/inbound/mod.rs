use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use crate::clash_state;
use crate::logging;
use crate::route::{ConnContext, Decision, Router, hijack_dns};

pub mod direct;
pub mod hysteria2;
pub mod mixed;
pub mod mux;
pub mod proxy;
pub mod redirect;
pub mod tls;
pub mod tproxy;
pub(crate) mod transport;
pub mod tun;
pub(crate) mod udp;

#[cfg(target_os = "linux")]
mod relay;

/// A TCP listener on `addr`, with `SO_REUSEADDR`.
///
/// The reference's Go runtime sets it on every listener, and without it a
/// rebind right after a reload loses to a TIME_WAIT socket the previous
/// instance left behind — one half of issue #5's `Address in use`. Off
/// Windows, where `SO_REUSEADDR` means "let two sockets own the port".
pub(crate) fn bind_tcp(addr: SocketAddr) -> io::Result<tokio::net::TcpListener> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.listen(128)?;
    socket.set_nonblocking(true)?;
    let listener: std::net::TcpListener = socket.into();
    tokio::net::TcpListener::from_std(listener)
}

/// A UDP socket on `addr`, with the same `SO_REUSEADDR` treatment.
pub(crate) fn bind_udp(addr: SocketAddr) -> io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    #[cfg(unix)]
    socket.set_reuse_address(true)?;
    socket.bind(&addr.into())?;
    socket.set_nonblocking(true)?;
    let std_socket: std::net::UdpSocket = socket.into();
    tokio::net::UdpSocket::from_std(std_socket)
}

/// Keep-alive on an accepted client socket, with the reference listener's
/// values (`common/listener/listener_tcp.go`: `C.TCPKeepAliveInitial` 5 min,
/// `C.TCPKeepAliveInterval` 75 s, the kernel's 9 probes). Without it a LAN
/// client that vanishes (Wi-Fi drop, phone asleep) leaves a relay waiting on
/// a socket that never errors while the upstream stays up; with it the kernel
/// fails that socket about 5 min + 9 x 75 s ~ 16 min after the last word
/// from the peer. The interval is long on purpose: probes wake phone radios.
const ACCEPTED_KEEP_ALIVE_IDLE: std::time::Duration = std::time::Duration::from_secs(300);
#[cfg_attr(
    not(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "windows"
    )),
    allow(dead_code)
)]
const ACCEPTED_KEEP_ALIVE_INTERVAL: std::time::Duration = std::time::Duration::from_secs(75);

pub(crate) fn keep_alive_accepted(stream: &TcpStream) {
    let params = socket2::TcpKeepalive::new().with_time(ACCEPTED_KEEP_ALIVE_IDLE);
    #[cfg(any(
        target_os = "linux",
        target_os = "android",
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "windows"
    ))]
    let params = params.with_interval(ACCEPTED_KEEP_ALIVE_INTERVAL);
    if let Err(err) = socket2::SockRef::from(stream).set_tcp_keepalive(&params) {
        // the connection still works, it just is not probed
        logging::debug(format_args!("accepted socket keep-alive: {err}"));
    }
}

/// An error from a serving loop: log it loudly and pause, never end the loop.
///
/// Every inbound used to `return` on the first `accept` failure, which drops
/// the socket — the process stays `running` while the port goes dark, which
/// is how issue #5 reported it. `tproxy` and `direct` were worse: their TCP
/// and UDP halves are `select!`ed, so one transient error took both down.
/// We own this socket, so nothing that fails on it is permanent; `EMFILE` and
/// friends clear up, and a socket that really is gone is worth shouting about
/// once a second rather than dying silently.
pub(crate) async fn serve_stalled(scope: &str, err: &io::Error) {
    logging::error(format_args!("{scope}: {err}; keeping the listener up"));
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
}

/// Object-safe stream for dial results (TCP, TLS, future transports).
///
/// `Any` is here so the relay can recognise a bare `TcpStream` behind the box
/// and hand both ends to the kernel (`splice`) instead of copying.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any {
    fn as_any(&self) -> &dyn std::any::Any;
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any;
}
impl<T: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any> ProxyStream for T {
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn std::any::Any {
        self
    }
}
pub type AnyStream = Box<dyn ProxyStream>;
pub type AnyWrite = Box<dyn AsyncWrite + Send + Unpin>;

/// Vision's peer can stop outer TLS encryption independently of our writes.
/// Switch only the read side, preserving bytes already buffered by TLS.
pub(crate) fn enable_vision_direct_read(stream: &mut AnyStream) -> bool {
    let stream = (**stream).as_any_mut();
    if let Some(alpn) = stream.downcast_mut::<AlpnStream>() {
        return enable_vision_direct_read(&mut alpn.inner);
    }
    if let Some(vless) = stream.downcast_mut::<crate::outbound::secure::VlessStream>() {
        return vless.enable_vision_direct_read();
    }
    if let Some(tls) = stream.downcast_mut::<crate::tls_utls::FingerprintStream<TcpStream>>() {
        tls.enable_direct_read();
        return true;
    }
    false
}

/// Vision decides between outer TLS records whether the next bytes are still
/// TLS, so a read must stop after each record. Called before the first read.
///
/// Batching left on under Vision is not a slow path but a broken one: the
/// bytes behind the record that carried the Direct command are the inner
/// session's, and opening them as one more outer record fails its tag and ends
/// the download. So this walks the same layers as its neighbours rather than
/// relying on where it happens to be called from.
pub(crate) fn disable_tls_read_batching(stream: &mut AnyStream) {
    let stream = (**stream).as_any_mut();
    if let Some(alpn) = stream.downcast_mut::<AlpnStream>() {
        return disable_tls_read_batching(&mut alpn.inner);
    }
    if let Some(vless) = stream.downcast_mut::<crate::outbound::secure::VlessStream>() {
        return vless.disable_tls_read_batching();
    }
    if let Some(tls) = stream.downcast_mut::<crate::tls_utls::FingerprintStream<TcpStream>>() {
        tls.disable_read_batching();
    }
}

/// Only the TCP fingerprint TLS wrapper exposes a compatible raw transport.
pub(crate) fn supports_vision_direct(stream: &mut AnyStream) -> bool {
    let stream = (**stream).as_any_mut();
    if let Some(alpn) = stream.downcast_mut::<AlpnStream>() {
        return supports_vision_direct(&mut alpn.inner);
    }
    if let Some(vless) = stream.downcast_mut::<crate::outbound::secure::VlessStream>() {
        return vless.supports_vision_direct();
    }
    stream.is::<crate::tls_utls::FingerprintStream<TcpStream>>()
}

/// Enter raw writes only after the last encrypted Vision frame was drained.
pub(crate) fn enable_vision_direct_write(stream: &mut AnyStream) -> bool {
    let stream = (**stream).as_any_mut();
    if let Some(alpn) = stream.downcast_mut::<AlpnStream>() {
        return enable_vision_direct_write(&mut alpn.inner);
    }
    if let Some(vless) = stream.downcast_mut::<crate::outbound::secure::VlessStream>() {
        return vless.enable_vision_direct_write();
    }
    if let Some(tls) = stream.downcast_mut::<crate::tls_utls::FingerprintStream<TcpStream>>() {
        return tls.enable_direct_write();
    }
    false
}

/// A stream carrying its negotiated ALPN protocol from the TLS handshake.
pub struct AlpnStream {
    inner: AnyStream,
    alpn: Option<Vec<u8>>,
}

impl AlpnStream {
    pub fn new(inner: AnyStream, alpn: Option<Vec<u8>>) -> Self {
        Self { inner, alpn }
    }

    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }
}

impl AsyncRead for AlpnStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for AlpnStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// Retrieve the negotiated ALPN protocol, if this stream carried a TLS handshake.
pub fn stream_alpn(stream: &AnyStream) -> Option<&[u8]> {
    let any = (**stream).as_any();
    if let Some(a) = any.downcast_ref::<AlpnStream>() {
        return a.alpn();
    }
    if let Some(t) = any.downcast_ref::<crate::inbound::tls::TlsStream<tokio::net::TcpStream>>() {
        return t.alpn.as_deref();
    }
    None
}

/// An established upstream connection.
pub enum Conn {
    Plain(AnyStream),
}

// A `Conn` is a finished upstream stream; the runtime fetches (rule-sets,
// provider updates) read and write one directly.
impl Conn {
    /// The upstream stream.
    pub fn into_plain(self) -> io::Result<AnyStream> {
        match self {
            Conn::Plain(stream) => Ok(stream),
        }
    }
}

/// SOCKS reply state on the client side of a mixed inbound connection.
enum LazyReply {
    /// HTTP CONNECT path: no SOCKS reply is due.
    None,
    /// SOCKS success reply waiting to be flushed on first payload I/O.
    Pending(Vec<u8>),
    /// Success reply flushed.
    Sent,
    /// Terminal: success flushed, or failure written, or never applicable.
    Done,
}

/// Client stream that flushes the SOCKS success reply as soon as the upstream
/// connection is up (reference `ConnHandshakeSuccess`, called by the router the
/// moment the dial returns), and defensively on the first read/write as well
/// (reference `LazyConn`) for a path that establishes the upstream silently.
pub struct ClientConn {
    inner: AnyStream,
    reply: LazyReply,
    /// the socket's address, kept here because a boxed stream has none to ask:
    /// `direct` needs it to work out its destination, and only ever holds a
    /// real socket there
    local: Option<SocketAddr>,
}

impl ClientConn {
    /// SOCKS path: success `reply` bytes flush on first payload I/O.
    pub fn socks(inner: TcpStream, reply: Vec<u8>) -> Self {
        let local = inner.local_addr().ok();
        Self {
            inner: Box::new(inner),
            reply: LazyReply::Pending(reply),
            local,
        }
    }

    /// HTTP CONNECT path: the 200 response is written by the caller.
    pub fn http(inner: TcpStream) -> Self {
        let local = inner.local_addr().ok();
        Self {
            inner: Box::new(inner),
            reply: LazyReply::None,
            local,
        }
    }

    /// A stream that carries a protocol frame of its own -- what the server
    /// inbounds hand over once they have unwrapped the request.
    pub fn framed(inner: AnyStream, local: SocketAddr) -> Self {
        Self {
            inner,
            reply: LazyReply::None,
            local: Some(local),
        }
    }

    /// The upstream is up: flush the success reply now (reference
    /// `ConnHandshakeSuccess`, called by the router right after the dial).
    ///
    /// The lazy first-payload flush stays as a second chance, for a path that
    /// establishes the upstream without saying so -- but a client that waits for
    /// this reply cannot be the one to trigger it.
    pub async fn established(&mut self) -> io::Result<()> {
        match std::mem::replace(&mut self.reply, LazyReply::Done) {
            LazyReply::Pending(bytes) => match self.inner.write_all(&bytes).await {
                Ok(()) => {
                    self.reply = LazyReply::Sent;
                    Ok(())
                }
                Err(e) => {
                    self.reply = LazyReply::Done;
                    Err(e)
                }
            },
            other => {
                self.reply = other;
                Ok(())
            }
        }
    }

    /// Write a SOCKS failure reply if the success reply is still pending
    /// (reference `HandshakeFailure`).
    pub async fn fail(&mut self, err: &io::Error) -> io::Result<()> {
        if matches!(self.reply, LazyReply::Pending(_)) {
            let code = reply_code_for_error(err);
            self.reply = LazyReply::Done;
            self.inner.write_all(&socks_failure_reply(code)).await?;
        }
        Ok(())
    }

    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.local
            .ok_or_else(|| io::Error::other("this stream has no socket address"))
    }

    /// The bare client socket, when nothing sits between us and it and no SOCKS
    /// reply is still owed: only then may the kernel move its bytes directly.
    #[cfg(target_os = "linux")]
    fn raw_tcp(&self) -> Option<&TcpStream> {
        if matches!(self.reply, LazyReply::Pending(_)) {
            return None;
        }
        (&*self.inner as &dyn std::any::Any).downcast_ref::<TcpStream>()
    }

    fn poll_flush_reply(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let mut bytes = match std::mem::replace(&mut self.reply, LazyReply::Done) {
                LazyReply::Pending(bytes) => bytes,
                other => {
                    self.reply = other;
                    return Poll::Ready(Ok(()));
                }
            };
            match Pin::new(&mut self.inner).poll_write(cx, &bytes) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::other("socks reply write stalled")));
                }
                Poll::Ready(Ok(n)) => {
                    bytes.drain(..n);
                    if bytes.is_empty() {
                        self.reply = LazyReply::Sent;
                        return Poll::Ready(Ok(()));
                    }
                    self.reply = LazyReply::Pending(bytes);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => {
                    self.reply = LazyReply::Pending(bytes);
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncRead for ClientConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match this.poll_flush_reply(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_read(cx, buf),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for ClientConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match this.poll_flush_reply(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.inner).poll_write(cx, buf),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// SOCKS5 success reply bound to the proxy-side local address
/// (reference `LazyConn` success reply).
pub fn socks_success_reply(local: SocketAddr) -> Vec<u8> {
    let mut out = vec![0x05, 0x00, 0x00];
    match local {
        SocketAddr::V4(a) => {
            out.push(0x01);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(0x04);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out
}

pub fn socks_failure_reply(code: u8) -> Vec<u8> {
    vec![0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
}

/// Reference `ReplyCodeForError`: map OS errnos only (raw_os_error), so
/// synthetic errors like block/reject stay0x01 (general failure).
fn reply_code_for_error(err: &io::Error) -> u8 {
    match err.raw_os_error() {
        // ENETUNREACH / WSAENETUNREACH
        Some(101) | Some(10051) => 0x03,
        // EHOSTUNREACH / WSAEHOSTUNREACH
        Some(113) | Some(10065) => 0x04,
        // ECONNREFUSED / WSAECONNREFUSED
        Some(111) | Some(10061) => 0x05,
        // EPERM / WSAEACCES
        Some(1) | Some(10013) => 0x02,
        _ => 0x01,
    }
}

fn clash_host(ctx: &ConnContext) -> String {
    match &ctx.destination {
        Target::Ip(addr) => ctx.domain.clone().unwrap_or_else(|| addr.ip().to_string()),
        Target::Domain(host, _) => host.clone(),
    }
}

#[cfg(test)]
mod monitoring_tests {
    use super::*;

    #[test]
    fn monitor_uses_sniffed_domain_without_changing_dial_target() {
        let mut ctx = ConnContext {
            destination: Target::Ip("198.18.0.40:443".parse().unwrap()),
            domain: Some("example.com".into()),
            ..Default::default()
        };
        assert_eq!(clash_host(&ctx), "example.com");
        assert_eq!(ctx.destination.to_string(), "198.18.0.40:443");
        ctx.domain = None;
        assert_eq!(clash_host(&ctx), "198.18.0.40");
        ctx.destination = Target::Domain("mapped.example".into(), 443);
        ctx.domain = Some("sniffed.example".into());
        assert_eq!(clash_host(&ctx), "mapped.example");
    }
}

/// Clash connection-view metadata for a routed connection: inbound, source,
/// destination, matched rule and the outbound chain.
pub fn clash_meta(
    ctx: &ConnContext,
    router: &Router,
    outbound_index: usize,
) -> clash_state::ConnMeta {
    let host = clash_host(ctx);
    let mut chains = Vec::new();
    let mut index = Some(outbound_index);
    // expand selector groups into their selected member (one level, like the
    // reference chain display for group proxies)
    for _ in 0..8 {
        let Some(current) = index else { break };
        let inner = router.inner();
        let Some((_, tag, outbound)) = inner.outbound_table().find(|(i, _, _)| *i == current)
        else {
            break;
        };
        chains.push(tag.to_string());
        index = match outbound {
            crate::route::Outbound::Selector(selector) => router.index_of(selector.now()),
            crate::route::Outbound::Urltest(urltest) => router.index_of(urltest.now()),
            _ => None,
        };
    }
    let (rule, rule_payload) = ctx
        .matched_rule
        .clone()
        .unwrap_or_else(|| ("".to_string(), String::new()));
    clash_state::ConnMeta {
        network: ctx.network,
        inbound: ctx.inbound.clone().unwrap_or_default(),
        source: ctx.source.to_string(),
        host,
        destination: ctx.destination.to_string(),
        chains,
        rule,
        rule_payload,
    }
}

/// The bare TCP socket behind a relay client, if there is one: a socket that
/// was accepted as is (`redirect`, `tproxy`), or a `ClientConn` with nothing
/// between it and the socket and no SOCKS reply still owed.
#[cfg(target_os = "linux")]
fn client_raw_tcp(client: &dyn std::any::Any) -> Option<&TcpStream> {
    if let Some(tcp) = client.downcast_ref::<TcpStream>() {
        return Some(tcp);
    }
    client.downcast_ref::<ClientConn>()?.raw_tcp()
}

/// A Vision stream on a raw-capable TLS-over-TCP upstream: the only upstream
/// whose download may leave userspace later on.
#[cfg(target_os = "linux")]
fn vision_splice_candidate(stream: &mut AnyStream) -> bool {
    (**stream)
        .as_any_mut()
        .downcast_mut::<crate::outbound::vision::VisionStream>()
        .is_some_and(|vision| vision.supports_direct())
}

/// The socket under a Vision upstream whose reads are Direct with nothing left
/// in any layer above it: from here on it carries the payload as is.
#[cfg(target_os = "linux")]
fn vision_direct_socket(stream: &dyn std::any::Any) -> Option<&TcpStream> {
    if let Some(vision) = stream.downcast_ref::<crate::outbound::vision::VisionStream>() {
        return vision_direct_socket((**vision.direct_read_inner()?).as_any());
    }
    if let Some(vless) = stream.downcast_ref::<crate::outbound::secure::VlessStream>() {
        return vision_direct_socket((**vless.read_inner()?).as_any());
    }
    if let Some(alpn) = stream.downcast_ref::<AlpnStream>() {
        return vision_direct_socket((*alpn.inner).as_any());
    }
    stream
        .downcast_ref::<crate::tls_utls::FingerprintStream<TcpStream>>()?
        .direct_read_transport()
}

/// Relay the client stream into an established upstream connection, replaying
/// any sniff-read `prefix` upstream first. With a `tracker` the connection is
/// registered in the Clash connection view: byte counters feed `/connections`
/// and `/traffic`, and `DELETE /connections/{id}` can drop it.
///
/// Socket to socket on Linux goes through `splice(2)` (see `relay`); every other
/// shape of stream takes the userspace loops below.
pub async fn pump_conn_tracked<S>(
    client: S,
    conn: Conn,
    prefix: &[u8],
    tracker: Option<&clash_state::ConnHandle>,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any,
{
    let half = HalfOpen::default();
    let relay = end_half_open(
        pump_conn_tracked_inner(client, conn, prefix, tracker, &half),
        &half,
        half_close_idle(),
    );
    if let Some(tracker) = tracker {
        let signal = tracker.close_signal();
        tokio::select! {
            biased;
            _ = signal.wait() => Err(closed_by_api()),
            result = relay => result,
        }
    } else {
        relay.await
    }
}

async fn pump_conn_tracked_inner<S>(
    mut client: S,
    conn: Conn,
    prefix: &[u8],
    tracker: Option<&clash_state::ConnHandle>,
    half: &HalfOpen,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + std::any::Any,
{
    match conn {
        Conn::Plain(mut upstream) => {
            // A tracker is not a precondition here: the kernel path is what
            // the plain relay exists for, and in a bench (or a build with the
            // connection view off) it used to be skipped entirely because
            // nothing to count meant no splice at all.
            #[cfg(target_os = "linux")]
            let mut prefix = prefix;
            #[cfg(target_os = "linux")]
            if let Some(client_tcp) = client_raw_tcp(&client) {
                // a plain vless client over a bare socket: its request head
                // waits for the first payload, which the kernel relay cannot
                // pair with it, so that one write happens here
                if let Some(vless) = (*upstream)
                    .as_any_mut()
                    .downcast_mut::<crate::outbound::secure::VlessStream>()
                    .filter(|vless| vless.raw_capable())
                {
                    let sent = if prefix.is_empty() {
                        vless.send_head_from(client_tcp).await?
                    } else {
                        vless.write_all(prefix).await?;
                        vless.flush().await?;
                        std::mem::take(&mut prefix).len()
                    };
                    if let Some(tracker) = tracker {
                        tracker.add_upload(sent as u64);
                    }
                }
                let up = &*upstream as &dyn std::any::Any;
                if let Some(upstream_tcp) = up.downcast_ref::<TcpStream>() {
                    return relay::relay(client_tcp, upstream_tcp, prefix, tracker, false, half)
                        .await;
                }
                // a plain vless client: the kernel moves the bytes once the
                // relay has eaten the two-byte answer head
                if let Some(upstream_tcp) = up
                    .downcast_ref::<crate::outbound::secure::VlessStream>()
                    .and_then(|v| v.raw_pending())
                {
                    return relay::relay(client_tcp, upstream_tcp, prefix, tracker, true, half)
                        .await;
                }
            }
            // Vision on TLS over TCP: userspace until its download is Direct
            // and drained, then the kernel for that direction
            #[cfg(target_os = "linux")]
            if client_raw_tcp(&client).is_some() && vision_splice_candidate(&mut upstream) {
                if !prefix.is_empty() {
                    upstream.write_all(prefix).await?;
                    if let Some(tracker) = tracker {
                        tracker.add_upload(prefix.len() as u64);
                    }
                }
                return relay::relay_vision(&mut client, &mut upstream, tracker, half)
                    .await
                    .map(|_| ());
            }

            if !prefix.is_empty() {
                upstream.write_all(prefix).await?;
                if let Some(tracker) = tracker {
                    tracker.add_upload(prefix.len() as u64);
                }
            }
            match tracker {
                Some(tracker) => {
                    relay_tracked(&mut client, &mut upstream, tracker, half).await?;
                }
                None => {
                    copy_bidirectional_pooled(&mut client, &mut upstream, half).await?;
                }
            }
            Ok(())
        }
    }
}

/// Controller asked to drop the connection (`DELETE /connections/{id}`).
fn closed_by_api() -> io::Error {
    io::Error::other("connection closed by clash api")
}

/// Each direction of a userspace relay moves up to this much per read
/// (2 * 65535 ~ 128 KiB), so a steady transfer costs one write per eight TLS
/// records, halving syscalls on routers.
///
/// Buffers are recycled through `BUF_POOL`. The pool retains at most
/// `POOL_CAP * relay_buf()` (2 MiB); directions with pending data own additional
/// buffers. A drained userspace direction returns its buffer while awaiting data.
fn relay_buf() -> usize {
    static SIZE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *SIZE.get_or_init(|| {
        if let Some(val) = crate::env_var("RELAY_BUF")
            && let Ok(n) = val.parse::<usize>()
            && n > 0
        {
            return n;
        }
        2 * 65535
    })
}

/// Relay buffers waiting for the next read or connection. Drained userspace
/// directions return them while waiting for data; other owners return them on
/// close. At 128 KiB each can incur an mmap/munmap pair on glibc. Pool retention
/// is capped at 16 x 128 KiB = 2 MiB, independently of active buffered data.
static BUF_POOL: std::sync::Mutex<Vec<Vec<u8>>> = std::sync::Mutex::new(Vec::new());
const POOL_CAP: usize = 16;

fn take_buf() -> Vec<u8> {
    let mut pool = BUF_POOL.lock().unwrap_or_else(|e| e.into_inner());
    match pool.pop() {
        Some(mut buf) => {
            buf.resize(relay_buf(), 0);
            buf
        }
        None => vec![0u8; relay_buf()],
    }
}

fn give_buf(buf: Vec<u8>) {
    if buf.capacity() < relay_buf() / 2 || buf.capacity() > relay_buf() * 2 {
        return;
    }
    // Retain initialized length: reusing a drained buffer does not need another
    // zero-fill. Only the bytes actually filled by AsyncRead are forwarded.
    let mut pool = BUF_POOL.lock().unwrap_or_else(|e| e.into_inner());
    if pool.len() < POOL_CAP {
        pool.push(buf);
    }
}

/// The client side of a relay, counting what crosses it for the connection
/// view: bytes read from it are upload, bytes written to it are download.
struct Counted<'a, S> {
    inner: &'a mut S,
    tracker: Option<&'a clash_state::ConnHandle>,
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<'_, S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let before = buf.filled().len();
        let poll = std::pin::Pin::new(&mut *self.inner).poll_read(cx, buf);
        if let (std::task::Poll::Ready(Ok(())), Some(tracker)) = (&poll, self.tracker) {
            tracker.add_upload((buf.filled().len() - before) as u64);
        }
        poll
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<'_, S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        data: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let poll = std::pin::Pin::new(&mut *self.inner).poll_write(cx, data);
        if let (std::task::Poll::Ready(Ok(n)), Some(tracker)) = (&poll, self.tracker) {
            tracker.add_download(*n as u64);
        }
        poll
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut *self.inner).poll_shutdown(cx)
    }
}

struct PooledBuffer {
    buf: Option<Vec<u8>>,
    read_done: bool,
    need_flush: bool,
    pos: usize,
    cap: usize,
    amt: u64,
}

impl PooledBuffer {
    fn new(buf: Vec<u8>) -> Self {
        Self {
            buf: Some(buf),
            read_done: false,
            need_flush: false,
            pos: 0,
            cap: 0,
            amt: 0,
        }
    }

    #[inline]
    fn buffer(&mut self) -> &mut [u8] {
        self.buf.get_or_insert_with(take_buf)
    }

    fn release_buffer(&mut self) {
        if let Some(buf) = self.buf.take() {
            give_buf(buf);
        }
    }

    fn poll_fill_buf<R>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + ?Sized,
    {
        let cap = self.cap;
        let mut read_buf = ReadBuf::new(self.buffer());
        read_buf.set_filled(cap);

        let res = reader.as_mut().poll_read(cx, &mut read_buf);
        if let Poll::Ready(Ok(())) = res {
            let filled_len = read_buf.filled().len();
            self.read_done = self.cap == filled_len;
            self.cap = filled_len;
        }
        res
    }

    fn poll_write_buf<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<usize>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        let (pos, cap) = (self.pos, self.cap);
        let buf_len = self.buffer().len();
        match writer.as_mut().poll_write(cx, &self.buffer()[pos..cap]) {
            Poll::Pending => {
                if !self.read_done && cap < buf_len {
                    ready!(self.poll_fill_buf(cx, reader.as_mut()))?;
                }
                Poll::Pending
            }
            res => res,
        }
    }

    pub fn poll_copy<R, W>(
        &mut self,
        cx: &mut Context<'_>,
        mut reader: Pin<&mut R>,
        mut writer: Pin<&mut W>,
    ) -> Poll<io::Result<u64>>
    where
        R: AsyncRead + ?Sized,
        W: AsyncWrite + ?Sized,
    {
        loop {
            let buf_len = self.buffer().len();
            if self.cap < buf_len && !self.read_done {
                match self.poll_fill_buf(cx, reader.as_mut()) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                    Poll::Pending => {
                        if self.pos == self.cap {
                            // No unread bytes remain. A keep-alive or half-closed
                            // connection must not pin a relay-sized allocation
                            // merely because its next read (or flush) is pending.
                            self.release_buffer();
                            if self.need_flush {
                                ready!(writer.as_mut().poll_flush(cx))?;
                                self.need_flush = false;
                            }
                            return Poll::Pending;
                        }
                    }
                }
            }

            while self.pos < self.cap {
                let i = ready!(self.poll_write_buf(cx, reader.as_mut(), writer.as_mut()))?;
                if i == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write zero byte into writer",
                    )));
                } else {
                    self.pos += i;
                    self.amt += i as u64;
                    self.need_flush = true;
                }
            }

            self.pos = 0;
            self.cap = 0;

            if self.read_done {
                self.release_buffer();
                ready!(writer.as_mut().poll_flush(cx))?;
                return Poll::Ready(Ok(self.amt));
            }
        }
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        self.release_buffer();
    }
}

#[cfg(test)]
mod relay_buffer_tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn drained_buffer_is_released_and_reused_without_losing_data() {
        let payload = vec![0x5a; relay_buf() * 2 + 17];
        let (mut source, mut reader) = tokio::io::duplex(payload.len());
        let (mut writer, mut destination) = tokio::io::duplex(payload.len());
        let mut buffer = PooledBuffer::new(take_buf());
        let mut cx = Context::from_waker(std::task::Waker::noop());

        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert!(buffer.buf.is_none(), "idle direction retains its buffer");
        for _ in 0..2 {
            source.write_all(&payload).await.unwrap();
            assert!(
                buffer
                    .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                    .is_pending()
            );
            assert!(buffer.buf.is_none(), "drained direction retains its buffer");
            let mut received = vec![0; payload.len()];
            destination.read_exact(&mut received).await.unwrap();
            assert_eq!(received, payload);
        }
        source.shutdown().await.unwrap();
        assert!(
            matches!(buffer.poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer)), Poll::Ready(Ok(n)) if n == (payload.len() * 2) as u64)
        );
    }

    #[tokio::test]
    async fn backpressure_keeps_unwritten_bytes_until_the_writer_resumes() {
        let payload: Vec<u8> = (0..96).collect();
        let (mut source, mut reader) = tokio::io::duplex(96);
        let (mut writer, mut destination) = tokio::io::duplex(64);
        let mut buffer = PooledBuffer::new(take_buf());
        source.write_all(&payload).await.unwrap();
        let mut cx = Context::from_waker(std::task::Waker::noop());
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert!(buffer.buf.is_some());
        assert_eq!(buffer.cap - buffer.pos, 32);
        let mut received = vec![0; 96];
        destination.read_exact(&mut received[..64]).await.unwrap();
        assert!(
            buffer
                .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                .is_pending()
        );
        assert!(buffer.buf.is_none());
        destination.read_exact(&mut received[64..]).await.unwrap();
        assert_eq!(received, payload);
    }

    struct PendingFlush;

    impl AsyncWrite for PendingFlush {
        fn poll_write(
            self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(bytes.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Pending
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn pending_flush_does_not_pin_a_drained_buffer() {
        for eof in [false, true] {
            let (mut source, mut reader) = tokio::io::duplex(16);
            source.write_all(b"request").await.unwrap();
            if eof {
                source.shutdown().await.unwrap();
            }
            let mut buffer = PooledBuffer::new(take_buf());
            let mut writer = PendingFlush;
            let mut cx = Context::from_waker(std::task::Waker::noop());
            assert!(
                buffer
                    .poll_copy(&mut cx, Pin::new(&mut reader), Pin::new(&mut writer))
                    .is_pending()
            );
            assert!(buffer.need_flush);
            assert!(buffer.buf.is_none());
            assert_eq!(buffer.amt, 7);
        }
    }
}

/// Set by the first direction of a relay that finishes; see [`end_half_open`].
#[derive(Default)]
pub(crate) struct HalfOpen(std::sync::atomic::AtomicBool);

impl HalfOpen {
    pub(crate) fn finish(&self) {
        self.0.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    fn finished(&self) -> bool {
        self.0.load(std::sync::atomic::Ordering::Relaxed)
    }
}

/// How long a relay with one direction over may go without activity on the
/// other before it ends. Neither side can do anything about a peer that keeps
/// its half open and silent: the session, its sockets and buffers would live
/// until that peer gives up. Xray ends the same case with its `uplinkOnly` and
/// `downlinkOnly` timers, 1 s by default (`features/policy/policy.go`), and so does this: a
/// VLESS or trojan upstream is not told the upload ended, as with Xray, so
/// this limit is what ends such a session and closes its connection, when
/// Xray's client would. A download that keeps moving is never cut.
/// `XRUST_HALF_CLOSE_IDLE_MS` overrides it.
const HALF_CLOSE_IDLE: std::time::Duration = std::time::Duration::from_secs(1);

fn half_close_idle() -> std::time::Duration {
    static IDLE: std::sync::OnceLock<std::time::Duration> = std::sync::OnceLock::new();
    *IDLE.get_or_init(|| {
        if let Some(val) = crate::env_var("HALF_CLOSE_IDLE_MS")
            && let Ok(ms) = val.parse::<u64>()
            && ms > 0
        {
            return std::time::Duration::from_millis(ms);
        }
        HALF_CLOSE_IDLE
    })
}

/// Run `relay` until it ends, or, once `half` says a direction is over, until
/// the relay has not been woken for [`HALF_CLOSE_IDLE`]. Every wake restarts
/// the limit: the relay is only ever woken by its sockets, so a direction
/// that keeps moving is never cut. Until a direction is over there is no
/// timer at all. The end is quiet (`Ok`), like the end of the relay.
async fn end_half_open<F>(relay: F, half: &HalfOpen, idle: std::time::Duration) -> io::Result<()>
where
    F: std::future::Future<Output = io::Result<()>>,
{
    let mut relay = std::pin::pin!(relay);
    let mut timer: Option<Pin<Box<tokio::time::Sleep>>> = None;
    std::future::poll_fn(|cx| {
        if let Poll::Ready(result) = relay.as_mut().poll(cx) {
            return Poll::Ready(result);
        }
        if !half.finished() {
            return Poll::Pending;
        }
        let now = tokio::time::Instant::now();
        match &mut timer {
            Some(t) if t.deadline() <= now => return Poll::Ready(Ok(())),
            Some(t) => t.as_mut().reset(now + idle),
            None => timer = Some(Box::pin(tokio::time::sleep_until(now + idle))),
        }
        if let Some(t) = &mut timer {
            let _ = t.as_mut().poll(cx);
        }
        Poll::Pending
    })
    .await
}

#[cfg(test)]
mod half_open_tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;
    use tokio::io::duplex;
    use tokio::time::{Instant, timeout};

    const IDLE: Duration = Duration::from_millis(150);

    /// A relay of `app` <-> `server` through two duplex pairs, ended by the
    /// half-open limit; returns when it ends.
    fn relay(
        relay_client: tokio::io::DuplexStream,
        relay_up: tokio::io::DuplexStream,
    ) -> tokio::task::JoinHandle<io::Result<()>> {
        tokio::spawn(async move {
            let (mut a, mut b) = (relay_client, relay_up);
            let half = HalfOpen::default();
            end_half_open(
                async {
                    copy_bidirectional_pooled(&mut a, &mut b, &half)
                        .await
                        .map(|_| ())
                },
                &half,
                IDLE,
            )
            .await
        })
    }

    #[tokio::test]
    async fn a_silent_half_open_relay_ends() {
        let (mut app, relay_client) = duplex(4096);
        let (relay_up, mut server) = duplex(4096);
        let task = relay(relay_client, relay_up);
        app.write_all(b"request").await.unwrap();
        app.shutdown().await.unwrap();
        let mut got = [0u8; 7];
        server.read_exact(&mut got).await.unwrap();
        let started = Instant::now();
        let ended = timeout(IDLE * 10, task).await.expect("relay must end");
        ended.unwrap().unwrap();
        assert!(started.elapsed() >= IDLE, "ended before the limit");
        // the client side sees the end of the stream
        let mut rest = Vec::new();
        app.read_to_end(&mut rest).await.unwrap();
        assert!(rest.is_empty());
    }

    #[tokio::test]
    async fn an_answer_that_keeps_moving_after_half_close_arrives_whole() {
        let (mut app, relay_client) = duplex(4096);
        let (relay_up, mut server) = duplex(4096);
        let task = relay(relay_client, relay_up);
        app.shutdown().await.unwrap();
        let reader = tokio::spawn(async move {
            let mut got = Vec::new();
            app.read_to_end(&mut got).await.unwrap();
            got
        });
        // eight pieces, each well inside the limit, the whole well past it
        for i in 0..8u8 {
            tokio::time::sleep(IDLE / 3).await;
            server.write_all(&[i; 100]).await.unwrap();
        }
        server.shutdown().await.unwrap();
        drop(server);
        task.await.unwrap().unwrap();
        let got = reader.await.unwrap();
        let want: Vec<u8> = (0..8u8).flat_map(|i| [i; 100]).collect();
        assert_eq!(got, want);
    }

    #[tokio::test]
    async fn a_silent_relay_with_both_halves_open_is_not_cut() {
        let (mut app, relay_client) = duplex(4096);
        let (relay_up, mut server) = duplex(4096);
        let task = relay(relay_client, relay_up);
        tokio::time::sleep(IDLE * 3).await;
        assert!(!task.is_finished(), "no direction ended, no limit applies");
        app.write_all(b"ping").await.unwrap();
        let mut got = [0u8; 4];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
        drop(app);
        drop(server);
        task.await.unwrap().unwrap();
    }
}

enum TransferState {
    Running(PooledBuffer),
    ShuttingDown(u64),
    Done(u64),
}

fn transfer_one_direction<A, B>(
    cx: &mut Context<'_>,
    state: &mut TransferState,
    r: &mut A,
    w: &mut B,
) -> Poll<io::Result<u64>>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut r = Pin::new(r);
    let mut w = Pin::new(w);

    loop {
        match state {
            TransferState::Running(buf) => {
                let count = ready!(buf.poll_copy(cx, r.as_mut(), w.as_mut()))?;
                *state = TransferState::ShuttingDown(count);
            }
            TransferState::ShuttingDown(count) => {
                ready!(w.as_mut().poll_shutdown(cx))?;
                *state = TransferState::Done(*count);
            }
            TransferState::Done(count) => return Poll::Ready(Ok(*count)),
        }
    }
}

async fn copy_bidirectional_pooled<A, B>(
    a: &mut A,
    b: &mut B,
    half: &HalfOpen,
) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin + ?Sized,
    B: AsyncRead + AsyncWrite + Unpin + ?Sized,
{
    let mut a_to_b = TransferState::Running(PooledBuffer::new(take_buf()));
    let mut b_to_a = TransferState::Running(PooledBuffer::new(take_buf()));
    std::future::poll_fn(|cx| {
        let res_a = transfer_one_direction(cx, &mut a_to_b, a, b)?;
        let res_b = transfer_one_direction(cx, &mut b_to_a, b, a)?;
        if res_a.is_ready() || res_b.is_ready() {
            half.finish();
        }
        let amt_a = ready!(res_a);
        let amt_b = ready!(res_b);
        Poll::Ready(Ok((amt_a, amt_b)))
    })
    .await
}

/// Counted bidirectional relay that aborts when the API closes the entry.
///
/// Both directions are driven by one poll-based copy, so a write that cannot
/// finish yet never holds up the other direction.
async fn relay_tracked<S, U>(
    client: &mut S,
    upstream: &mut U,
    tracker: &clash_state::ConnHandle,
    half: &HalfOpen,
) -> io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let signal = tracker.close_signal();
    let mut counted = Counted {
        inner: client,
        tracker: Some(tracker),
    };
    tokio::select! {
        biased;
        result = copy_bidirectional_pooled(
            &mut counted,
            upstream,
            half,
        ) => result.map(|_| ()),
        _ = signal.wait() => Err(closed_by_api()),
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target {
    Ip(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn port(&self) -> u16 {
        match self {
            Target::Ip(addr) => addr.port(),
            Target::Domain(_, port) => *port,
        }
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Target::Ip(addr) => write!(f, "{addr}"),
            Target::Domain(host, port) => write!(f, "{host}:{port}"),
        }
    }
}

pub fn require_u16(
    obj: &serde_json::Map<String, Value>,
    key: &str,
    at: &str,
) -> anyhow::Result<u16> {
    obj.get(key)
        .and_then(Value::as_u64)
        .and_then(|v| u16::try_from(v).ok())
        .ok_or_else(|| anyhow::anyhow!("{at}: missing or invalid {key}"))
}

/// Common `listen` / `listen_port` parsing for inbound listeners.
pub(crate) fn parse_listen(
    obj: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<(std::net::IpAddr, u16)> {
    let port = require_u16(obj, "listen_port", at)?;
    let host = obj
        .get("listen")
        .and_then(Value::as_str)
        .unwrap_or("127.0.0.1");
    let ip: std::net::IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("{at}: invalid listen address {host:?}"))?;
    Ok((ip, port))
}

/// True when `network` includes `tcp` (absent = tcp+udp default → true).
pub(crate) fn network_includes_tcp(obj: &serde_json::Map<String, Value>) -> bool {
    match obj.get("network").and_then(Value::as_str) {
        None | Some("") => true,
        Some(n) => n
            .split(',')
            .map(str::trim)
            .any(|part| part.eq_ignore_ascii_case("tcp")),
    }
}

pub(crate) fn network_includes_udp(obj: &serde_json::Map<String, Value>) -> bool {
    match obj.get("network").and_then(Value::as_str) {
        None | Some("") => true,
        Some(n) => n
            .split(',')
            .map(str::trim)
            .any(|part| part.eq_ignore_ascii_case("udp")),
    }
}

/// Register before dialing so a group transition can also cancel old setup.
pub(crate) async fn connect_tracked(
    router: &Router,
    index: usize,
    ctx: &ConnContext,
) -> io::Result<(Conn, clash_state::ConnHandle)> {
    let tracker =
        clash_state::ConnHandle::open_with_context(clash_meta(ctx, router, index), ctx, router);
    let signal = tracker.close_signal();
    let conn = tokio::select! {
        biased;
        _ = signal.wait() => return Err(closed_by_api()),
        result = router.connect_index(index, &ctx.destination) => result?,
    };
    Ok((conn, tracker))
}

/// Route one accepted transparent connection (direct / redirect / tproxy):
/// no SOCKS reply, destination already resolved by the inbound.
pub(crate) async fn drive_transparent(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    destination: Target,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    keep_alive_accepted(&stream);
    drive_framed(ClientConn::http(stream), peer, destination, tag, router).await
}

/// The same routing decision for a stream that already carries its own frame.
pub(crate) async fn drive_framed(
    mut client: ClientConn,
    peer: SocketAddr,
    destination: Target,
    tag: &str,
    router: &Arc<Router>,
) -> io::Result<()> {
    let mut ctx = ConnContext::new(tag, peer, destination, "tcp");
    let decision = match router.route(&mut client, &mut ctx).await {
        Ok(decision) => decision,
        Err(err) => return Err(err),
    };
    match decision {
        Decision::HijackDns => {
            logging::info(format_args!(
                "inbound {tag} {peer} HIJACK-DNS {}",
                ctx.destination
            ));
            hijack_dns(&mut client, &ctx).await
        }
        Decision::Outbound(idx) => {
            let dest = ctx.destination.clone();
            let (conn, tracker) = connect_tracked(router, idx, &ctx).await?;
            logging::info(format_args!("inbound {tag} {peer} CONNECT {dest}"));

            pump_conn_tracked(client, conn, &ctx.sniff_prefix, Some(&tracker)).await
        }
    }
}

/// Copy both directions until one side closes.
pub async fn pump<A, B>(mut a: A, mut b: B) -> io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    tokio::io::copy_bidirectional(&mut a, &mut b).await
}

/// Dial the proxy target through the router's default outbound.
pub async fn dial(router: &Arc<Router>, target: &Target) -> io::Result<Conn> {
    router.connect(target).await
}
