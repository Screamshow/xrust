use std::io;
use std::sync::Arc;

use serde_json::Value;
use tokio::io::AsyncWriteExt;

use crate::inbound::{AnyStream, Target};
use crate::outbound::mux;
use crate::outbound::packet::{CMD_MUX, CMD_TCP, PacketEncoding, spawn_packet_bridge};
use crate::outbound::proxy::server_endpoint;
use crate::outbound::transport::Transport;
use crate::tls_client::TlsOptions;

mod head;
use head::PendingHead;

/// vless address block: port first, then ATYP (1=v4, 2=domain, 3=v6) + addr.
fn encode_vless_target(target: &Target) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&target.port().to_be_bytes());
    match target {
        Target::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x03);
                out.extend_from_slice(&v6.octets());
            }
        },
        Target::Domain(host, _) => {
            out.push(0x02);
            let raw = host.as_bytes();
            if raw.len() > 255 {
                return Err(io::Error::other("domain too long"));
            }
            out.push(raw.len() as u8);
            out.extend_from_slice(raw);
        }
    }
    Ok(out)
}

/// vless wants a canonical UUID and nothing else. The server side falls back
/// to a UUIDv5 of the raw string (`inbound::proxy::parse_user_uuid`), as the
/// reference does for users; a client must not dial with a UUID nobody
/// configured, so the two stay apart.
fn parse_uuid(raw: &str) -> io::Result<[u8; 16]> {
    let hex: String = raw.chars().filter(|c| *c != '-').collect();
    if hex.len() != 16 * 2 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(io::Error::other("invalid uuid"));
    }
    let mut uuid = [0u8; 16];
    for (i, byte) in uuid.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| io::Error::other("invalid uuid"))?;
    }
    Ok(uuid)
}

/// The only flow the reference accepts (`vless.NewClient`).
const FLOW: &str = "xtls-rprx-vision";

/// vless outbound (TCP command, with the `xtls-rprx-vision` flow).
#[derive(Clone)]
pub struct Vless {
    server: String,
    port: u16,
    uuid: [u8; 16],
    transport: Transport,
    tls: Option<TlsOptions>,
    /// `flow: xtls-rprx-vision` — the payload is framed, see `vision`.
    vision: bool,
    /// how datagrams are framed on the stream, see `packet`
    packet_encoding: PacketEncoding,
    /// Mux.Cool session pool; `None` when multiplexing is off
    mux: Option<Arc<mux::Client>>,
    pub dial: crate::outbound::dial::DialOptions,
}

impl Vless {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let uuid_raw = obj
            .get("uuid")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing uuid"))?;
        let uuid = parse_uuid(uuid_raw).map_err(|e| anyhow::anyhow!("{at}: {e}"))?;
        let flow = obj.get("flow").and_then(Value::as_str).unwrap_or("");
        let vision = match flow {
            "" => false,
            "xtls-rprx-vision" => true,
            other => anyhow::bail!("{at}: vless flow {other:?} is not supported"),
        };
        let transport = Transport::parse(obj, at)?;
        let tls = TlsOptions::from_outbound(obj, &server, at)?;
        let multiplex = match obj.get("multiplex") {
            Some(value) if !value.is_null() => {
                mux::MuxOptions::parse(value, &format!("{at}.multiplex"))?
            }
            _ => mux::MuxOptions::default(),
        };
        let packet_encoding =
            PacketEncoding::parse(obj.get("packet_encoding").and_then(Value::as_str), at)?;
        Ok(Self {
            server,
            port,
            uuid,
            transport,
            tls,
            vision,
            packet_encoding,
            mux: if multiplex.min_streams > 0
                || multiplex.max_connections > 0
                || multiplex.max_streams > 0
            {
                Some(mux::Client::new(multiplex)?)
            } else {
                None
            },
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        if let Some(mux) = &self.mux {
            if !mux.has_dialer().await {
                // a session is opened against the magic destination through the
                // same request machinery a normal connection uses
                let copy = self.clone();
                mux.set_dialer(Arc::new(move || {
                    let copy = copy.clone();
                    let target = mux::mux_target();
                    Box::pin(async move { copy.connect_direct(&target).await })
                }))
                .await;
            }
            let stream = mux.open(target).await?;
            return Ok(Box::new(stream));
        }
        self.connect_direct(target).await
    }

    async fn connect_direct(&self, target: &Target) -> io::Result<AnyStream> {
        self.dial(CMD_TCP, target).await
    }

    /// A datagram relay: the request head names the destination (or the
    /// packetaddr magic name) and the framing takes over from there.
    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let (local, peer) = crate::outbound::quic::udp_loopback_pair().await?;
        let mode = self.packet_encoding;
        let stream = self
            .dial(mode.command(), &mode.request_target(target))
            .await?;
        spawn_packet_bridge(stream, peer, mode, target.clone());
        Ok(local)
    }

    async fn dial(&self, command: u8, target: &Target) -> io::Result<AnyStream> {
        let header = request_head(&self.uuid, command, target, self.vision)?;
        // a ws transport with early data sends its upgrade request with the
        // first write below, so the head and first payload ride in it
        let mut stream = self
            .transport
            .connect_or_dial(self.tls.as_ref(), &self.server, self.port, &self.dial)
            .await?;
        if self.vision {
            crate::inbound::disable_tls_read_batching(&mut stream);
        }
        // The head waits for the first payload and both go in one write, as
        // Xray's client sends them (`proxy/vless/outbound`: the head goes into
        // a `BufferedWriter`, the first payload read within 500 ms is written
        // behind it, `SetBuffered(false)` flushes both). Over TLS one write is
        // one record, so the head alone would be a first application-data
        // record of a few dozen bytes, a shape no browser sends; on ws, gRPC
        // and the rest it would be a frame or a message of its own, and on
        // XHTTP packet-up a POST of its own. (A glued POST was once read back
        // twice by Xray 26.9; the cause was our client sending each POST's
        // payload in the body *and* in an `x-data` header, fixed since, not the
        // gluing: Xray's own client glues, and ours glued passes against Xray
        // 26.10.21 in packet-up, stream-up and stream-one, see
        // tests/vless_first_record.rs.)
        //
        // With Vision the first write above is the UUID and the first frame,
        // so they ride with the head too. A destination that talks first gets
        // the head alone when the wait is over, and the UUID with the first
        // frame after it: that is what the Xray binary sends. Its source
        // writes a padded empty Vision frame behind the head on that timeout,
        // but the inbounds hand the outbound a reader whose timeout reports
        // no data rather than `ErrReadTimeout`, so the branch never runs. A
        // client that leaves before its first byte gets nothing sent at all,
        // also as with Xray.
        let request = PendingHead::new(header, VLESS_FIRST_PAYLOAD_WAIT, VLESS_FIRST_WRITE);
        let framed: AnyStream = Box::new(VlessStream {
            inner: stream,
            request,
            header_pending: true,
            need: 2,
            buf: Vec::new(),
        });
        if self.vision {
            // Vision frames the payload that follows the request header
            Ok(Box::new(crate::outbound::vision::VisionStream::new(
                framed, self.uuid,
            )))
        } else {
            Ok(framed)
        }
    }
}

/// How long the request head waits for the first payload: Xray's client reads
/// once with this timeout (`ReadMultiBufferTimeout(500ms)`) before it flushes.
const VLESS_FIRST_PAYLOAD_WAIT: std::time::Duration = std::time::Duration::from_millis(500);

/// The most the head's write carries, head included: Xray's `BufferedWriter`
/// flushes its one `buf.Size` buffer when it fills, so a larger first payload
/// leaves in an 8 KiB write and then the rest.
const VLESS_FIRST_WRITE: usize = 8192;

/// `[version][uuid][addonsLen][addons][command][addr][port]`, reference
/// `WriteRequest`. The flow travels in the addons as protobuf field 1, and a
/// server with `flow` on the user refuses a request without it.
fn request_head(
    uuid: &[u8; 16],
    command: u8,
    target: &Target,
    vision: bool,
) -> io::Result<Vec<u8>> {
    let mut addons = Vec::new();
    if vision {
        addons.push(0x0a); // field 1, wire type 2
        addons.push(FLOW.len() as u8); // 17 bytes, so a one-byte uvarint
        addons.extend_from_slice(FLOW.as_bytes());
    }
    let mut header = Vec::with_capacity(24 + addons.len());
    header.push(0x00);
    header.extend_from_slice(uuid);
    header.push(addons.len() as u8);
    header.extend_from_slice(&addons);
    header.push(command);
    // Xray's Mux request ends at the command; XUDP names the destination.
    if command != CMD_MUX {
        header.extend_from_slice(&encode_vless_target(target)?);
    }
    Ok(header)
}

/// vless response ([version][addonsLen][addons]) is sent lazily by servers on
/// the first upstream write, so it is consumed transparently on first read.
pub struct VlessStream {
    inner: AnyStream,
    /// the request head, until the first payload (or the deadline) takes it
    request: PendingHead,
    header_pending: bool,
    need: usize,
    buf: Vec<u8>,
}

impl VlessStream {
    pub(crate) fn enable_vision_direct_write(&mut self) -> bool {
        crate::inbound::enable_vision_direct_write(&mut self.inner)
    }

    pub(crate) fn supports_vision_direct(&mut self) -> bool {
        crate::inbound::supports_vision_direct(&mut self.inner)
    }

    pub(crate) fn enable_vision_direct_read(&mut self) -> bool {
        crate::inbound::enable_vision_direct_read(&mut self.inner)
    }
    /// The bare socket underneath, while the response head has not been touched:
    /// the relay can then eat the head itself and hand the rest to the kernel.
    #[cfg(target_os = "linux")]
    pub(crate) fn raw_pending(&self) -> Option<&tokio::net::TcpStream> {
        if !self.request.is_sent() || !self.header_pending || !self.buf.is_empty() {
            return None;
        }
        (&*self.inner as &dyn std::any::Any).downcast_ref::<tokio::net::TcpStream>()
    }

    /// Whether `raw_pending` will hand out the socket once the request head is
    /// out: the transport is a bare socket and nothing was read yet.
    #[cfg(target_os = "linux")]
    pub(crate) fn raw_capable(&self) -> bool {
        self.header_pending
            && self.buf.is_empty()
            && self.inner.as_any().is::<tokio::net::TcpStream>()
    }

    /// Send the request head the way a write would, taking the first payload
    /// straight off the client socket: the kernel relay that follows cannot
    /// pair them. Returns how many client bytes went with the head.
    #[cfg(target_os = "linux")]
    pub(crate) async fn send_head_from(
        &mut self,
        client: &tokio::net::TcpStream,
    ) -> io::Result<usize> {
        let Some(until) = self.request.waiting_until() else {
            return Ok(0);
        };
        let mut first = vec![0u8; VLESS_FIRST_WRITE];
        let got = loop {
            match tokio::time::timeout_at(until, client.readable()).await {
                Err(_) => break 0,
                Ok(ready) => ready?,
            }
            match client.try_read(&mut first) {
                Ok(0) => {
                    // the client left before its first byte
                    self.request.abandon();
                    return Ok(0);
                }
                Ok(n) => break n,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) => return Err(error),
            }
        };
        if got == 0 {
            // the wait is over: the head goes alone. (A client that is done
            // already leaves the head unsent, see `PendingHead::abandon`.)
            self.request.start_alone();
        } else {
            self.write_all(&first[..got]).await?;
        }
        self.flush().await?;
        Ok(got)
    }

    /// The stream underneath, once the response head is consumed.
    #[cfg(target_os = "linux")]
    pub(crate) fn read_inner(&self) -> Option<&AnyStream> {
        (!self.header_pending && self.buf.is_empty()).then_some(&self.inner)
    }
}

impl tokio::io::AsyncRead for VlessStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = &mut *self;
        std::task::ready!(this.request.poll_before_read(&mut this.inner, cx))?;
        if this.header_pending {
            let mut probe = [0u8; 1];
            while this.buf.len() < this.need {
                let mut read_buf = tokio::io::ReadBuf::new(&mut probe);
                match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut read_buf) {
                    std::task::Poll::Ready(Ok(())) => {
                        if read_buf.filled().is_empty() {
                            return std::task::Poll::Ready(Err(io::Error::other(
                                "vless: connection closed before response",
                            )));
                        }
                        this.buf.push(probe[0]);
                        if this.buf.len() == 2 {
                            if this.buf[0] != 0x00 {
                                return std::task::Poll::Ready(Err(io::Error::other(
                                    "bad vless response version",
                                )));
                            }
                            this.need += usize::from(this.buf[1]);
                        }
                    }
                    std::task::Poll::Ready(Err(err)) => return std::task::Poll::Ready(Err(err)),
                    std::task::Poll::Pending => return std::task::Poll::Pending,
                }
            }
            this.header_pending = false;
            this.buf.clear();
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl tokio::io::AsyncWrite for VlessStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        // the first payload joins the request head; after that, a passthrough
        let this = self.get_mut();
        this.request.poll_write(&mut this.inner, cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        this.request.poll_flush(&mut this.inner, cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // The end of the upload is not passed on: Xray's client never tells
        // the server (its request copy just returns, `outbound.go`
        // `postRequest`), so neither close_notify nor a FIN goes out here, and
        // the download stays open. The session ends when the relay gives up
        // on the quiet half (`end_half_open`) and drops the stream, which
        // then closes the connection with close_notify, as Xray's `Close`.
        let this = self.get_mut();
        std::task::ready!(this.request.poll_before_shutdown(&mut this.inner, cx))?;
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }
}

/// trojan outbound: TLS is mandatory; password is SHA224-hex authenticated.
#[derive(Clone)]
pub struct Trojan {
    server: String,
    port: u16,
    password_hash: String,
    transport: Transport,
    tls: Option<TlsOptions>,
    pub dial: crate::outbound::dial::DialOptions,
}

/// `trojan.CommandTCP`
const TROJAN_CMD_TCP: u8 = 0x01;
/// `trojan.CommandUDP`
pub(crate) const TROJAN_CMD_UDP: u8 = 0x03;

impl Trojan {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let password = obj
            .get("password")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing password"))?;
        use sha2::Digest;
        let digest = sha2::Sha224::digest(password.as_bytes());
        let password_hash = digest
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect::<String>();
        // Mux sessions are not wired for trojan; carrying on without them would
        // put every connection on its own tunnel behind the user's back.
        if obj
            .get("multiplex")
            .and_then(|m| m.get("enabled"))
            .and_then(Value::as_bool)
            == Some(true)
        {
            anyhow::bail!("{at}: multiplex is not supported on the trojan outbound");
        }
        let transport = Transport::parse(obj, at)?;
        let tls = TlsOptions::from_outbound(obj, &server, at)?;
        if tls.is_none() {
            anyhow::bail!("{at}: trojan requires TLS");
        }
        Ok(Self {
            server,
            port,
            password_hash,
            transport,
            tls,
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        Ok(Box::new(self.dial(TROJAN_CMD_TCP, target).await?))
    }

    /// trojan has one datagram form: the request head names the target and
    /// every packet carries its own address, length and CRLF on the same
    /// stream (`trojan.WritePacket`).
    pub async fn connect_udp(&self, target: &Target) -> io::Result<tokio::net::UdpSocket> {
        let (local, peer) = crate::outbound::quic::udp_loopback_pair().await?;
        let stream = self.dial(TROJAN_CMD_UDP, target).await?;
        spawn_packet_bridge(
            Box::new(stream),
            peer,
            PacketEncoding::Trojan,
            target.clone(),
        );
        Ok(local)
    }

    async fn dial(&self, command: u8, target: &Target) -> io::Result<TrojanStream> {
        let Some(tls) = &self.tls else {
            return Err(io::Error::other("trojan requires TLS"));
        };
        let header = trojan_request_head(&self.password_hash, command, target)?;
        let stream = self
            .transport
            .connect_or_dial(Some(tls), &self.server, self.port, &self.dial)
            .await?;
        Ok(TrojanStream::new(stream, header))
    }
}

/// `[hex(sha224(password))][CRLF][command][address][port][CRLF]`. The
/// destination block is `M.SocksaddrSerializer`, whose family bytes are the
/// SOCKS ones: 1 = IPv4, 4 = IPv6, 3 = domain.
pub(crate) fn trojan_request_head(
    password_hash: &str,
    command: u8,
    target: &Target,
) -> io::Result<Vec<u8>> {
    let mut header = Vec::with_capacity(64 + crate::outbound::packet::MAX_ADDR_PORT + 256);
    header.extend_from_slice(password_hash.as_bytes());
    header.extend_from_slice(b"\r\n");
    header.push(command);
    header.extend_from_slice(&crate::outbound::proxy::encode_target_with(target, 0x03)?);
    header.extend_from_slice(b"\r\n");
    Ok(header)
}

/// How long the request head waits for the first payload to travel with it.
/// Xray's client copies once with this timeout before it flushes the head
/// (`buf.CopyOnceTimeout(link.Reader, bodyWriter, 100ms)`), so a client that
/// talks first sends head and payload in one write, and a server-first
/// destination gets the head on its own once the wait is over.
pub(crate) const TROJAN_FIRST_PAYLOAD_WAIT: std::time::Duration =
    std::time::Duration::from_millis(100);

/// The most payload that joins the head in its write: one TLS record's worth
/// for both together, which is the cut sing-box's single `Write` gets from
/// its TLS layer too.
const TROJAN_FIRST_WRITE: usize = core_tls::record::MAX_FRAGMENT;

/// A trojan connection whose request head waits for the first payload, like
/// both references: sing-box's `ClientConn.Write` prepends the head to the first
/// write, and Xray buffers the head with the first payload and flushes them
/// together. Either way the head is never a record of its own while the client
/// talks first -- a 56-byte hex key, CRLF and an address alone in the first
/// application-data record would be a shape no browser produces.
pub(crate) struct TrojanStream {
    inner: AnyStream,
    head: PendingHead,
}

impl TrojanStream {
    pub(crate) fn new(inner: AnyStream, head: Vec<u8>) -> Self {
        Self::with_wait(inner, head, TROJAN_FIRST_PAYLOAD_WAIT)
    }

    pub(crate) fn with_wait(inner: AnyStream, head: Vec<u8>, wait: std::time::Duration) -> Self {
        Self {
            inner,
            head: PendingHead::new(head, wait, TROJAN_FIRST_WRITE),
        }
    }
}

impl tokio::io::AsyncRead for TrojanStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        out: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        std::task::ready!(this.head.poll_before_read(&mut this.inner, cx))?;
        std::pin::Pin::new(&mut this.inner).poll_read(cx, out)
    }
}

impl tokio::io::AsyncWrite for TrojanStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let this = self.get_mut();
        this.head.poll_write(&mut this.inner, cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        this.head.poll_flush(&mut this.inner, cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        // The end of the upload is not passed on: Xray's client never tells
        // the server (its request copy just returns, `outbound.go`
        // `postRequest`), so neither close_notify nor a FIN goes out here, and
        // the download stays open. The session ends when the relay gives up
        // on the quiet half (`end_half_open`) and drops the stream, which
        // then closes the connection with close_notify, as Xray's `Close`.
        let this = self.get_mut();
        std::task::ready!(this.head.poll_before_shutdown(&mut this.inner, cx))?;
        std::pin::Pin::new(&mut this.inner).poll_flush(cx)
    }
}

#[cfg(test)]
mod tests;
