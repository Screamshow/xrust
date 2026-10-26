use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::{AnyStream, Conn, Target};
use crate::route::Router;

pub(crate) fn server_host(
    obj: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<String> {
    obj.get("server")
        .and_then(Value::as_str)
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("{at}: missing server"))
}

pub(crate) fn server_endpoint(
    obj: &serde_json::Map<String, Value>,
    at: &str,
) -> anyhow::Result<(String, u16)> {
    let server = server_host(obj, at)?;
    let port = obj
        .get("server_port")
        .and_then(Value::as_u64)
        .and_then(|p| u16::try_from(p).ok())
        .ok_or_else(|| anyhow::anyhow!("{at}: missing server_port"))?;
    Ok((server, port))
}

fn credentials(obj: &serde_json::Map<String, Value>) -> Option<(String, String)> {
    let username = obj.get("username").and_then(Value::as_str)?;
    let password = obj.get("password").and_then(Value::as_str)?;
    Some((username.to_string(), password.to_string()))
}

/// SOCKS-shaped address block: ATYP, address, then the port. IPv4 is 1 and
/// IPv6 is 4; the domain number is the caller's (trojan's
/// `M.SocksaddrSerializer` uses the SOCKS 3).
pub(crate) fn encode_target_with(target: &Target, domain_atyp: u8) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    match target {
        Target::Ip(addr) => match addr.ip() {
            std::net::IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        },
        Target::Domain(host, _) => {
            out.push(domain_atyp);
            let raw = host.as_bytes();
            if raw.len() > 255 {
                return Err(io::Error::other("domain too long"));
            }
            out.push(raw.len() as u8);
            out.extend_from_slice(raw);
        }
    }
    out.extend_from_slice(&target.port().to_be_bytes());
    Ok(out)
}

/// http outbound: CONNECT tunnel, optionally wrapped in TLS.
pub struct HttpOut {
    server: String,
    port: u16,
    credentials: Option<(String, String)>,
    tls: Option<Arc<crate::tls_client::TlsOptions>>,
    pub dial: crate::outbound::dial::DialOptions,
}

impl HttpOut {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let (server, port) = server_endpoint(obj, at)?;
        let tls = crate::tls_client::TlsOptions::from_outbound(obj, &server, at)?;
        Ok(Self {
            server,
            port,
            credentials: credentials(obj),
            tls: tls.map(Arc::new),
            dial: crate::outbound::dial::DialOptions::parse(obj)?,
        })
    }

    pub async fn connect(&self, target: &Target) -> io::Result<AnyStream> {
        let tcp =
            crate::outbound::dial::connect_tcp(self.server.as_str(), self.port, &self.dial).await?;
        let mut stream: AnyStream = match &self.tls {
            Some(tls) => Box::new(tls.connect_stream(tcp, &[]).await?),
            None => Box::new(tcp),
        };
        let authority = match target {
            Target::Ip(addr) => addr.to_string(),
            Target::Domain(host, port) => format!("{host}:{port}"),
        };
        let mut request = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n");
        if let Some((username, password)) = &self.credentials {
            use std::fmt::Write as _;
            let raw = format!("{username}:{password}");
            let encoded = base64_std(raw.as_bytes());
            let _ = write!(request, "Proxy-Authorization: Basic {encoded}\r\n");
        }
        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;
        let mut response = Vec::with_capacity(128);
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await?;
            response.push(byte[0]);
            if response.ends_with(b"\r\n\r\n") {
                break;
            }
            if response.len() > 16 * 1024 {
                return Err(io::Error::other("http proxy response too large"));
            }
        }
        let head = String::from_utf8_lossy(&response);
        let status = head
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .unwrap_or_default();
        if !status.starts_with('2') {
            return Err(io::Error::other(format!("http proxy refused: {status}")));
        }
        Ok(stream)
    }
}

pub(crate) fn base64_std(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let n = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

/// selector: first member by default (runtime switching arrives with clash_api).
pub struct Selector {
    interrupt: bool,
    raw_members: Vec<String>,
    default: Option<String>,
    resolved: Vec<usize>,
    current: AtomicUsize,
}

impl Selector {
    pub fn build(obj: &serde_json::Map<String, Value>, at: &str) -> anyhow::Result<Self> {
        let raw_members = obj
            .get("outbounds")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow::anyhow!("{at}: missing tags"))?
            .iter()
            .map(|m| {
                m.as_str()
                    .map(str::to_string)
                    .ok_or_else(|| anyhow::anyhow!("{at}: selector members must be strings"))
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if raw_members.is_empty() {
            anyhow::bail!("{at}: missing tags");
        }
        let default = obj
            .get("default")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok(Self {
            interrupt: obj
                .get("interrupt_exist_connections")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false),
            raw_members,
            default,
            resolved: Vec::new(),
            current: AtomicUsize::new(0),
        })
    }

    /// Resolve member tags against the built outbound table (once, at startup).
    pub fn resolve(
        &mut self,
        tags: &std::collections::HashMap<String, usize>,
    ) -> anyhow::Result<()> {
        let mut resolved = Vec::with_capacity(self.raw_members.len());
        for tag in &self.raw_members {
            let index = tags.get(tag).copied().ok_or_else(|| {
                anyhow::anyhow!("selector member references unknown outbound {tag:?}")
            })?;
            resolved.push(index);
        }
        let current = match &self.default {
            Some(tag) => self
                .raw_members
                .iter()
                .position(|m| m == tag)
                .ok_or_else(|| anyhow::anyhow!("selector default {tag:?} is not a member"))?,
            None => 0,
        };
        self.resolved = resolved;
        self.current.store(current, Ordering::Relaxed);
        Ok(())
    }

    pub async fn connect(&self, router: &Router, target: &Target) -> io::Result<Conn> {
        let index = self.current.load(Ordering::Relaxed);
        let Some(member) = self.resolved.get(index) else {
            return Err(io::Error::other("selector has no members"));
        };
        router.connect_index(*member, target).await
    }

    pub fn interrupt_exist_connections(&self) -> bool {
        self.interrupt
    }

    /// Switch to `member` by tag (clash `PUT /proxies/{name}`).
    pub fn select(&self, member: &str) -> bool {
        if let Some(pos) = self.raw_members.iter().position(|m| m == member) {
            self.current.store(pos, Ordering::Relaxed);
            true
        } else {
            false
        }
    }

    /// Member tags and the current selection (clash group view).
    pub fn all(&self) -> &[String] {
        &self.raw_members
    }

    pub fn now(&self) -> &str {
        self.raw_members
            .get(self.current.load(Ordering::Relaxed))
            .map(String::as_str)
            .unwrap_or_default()
    }

    pub async fn connect_udp(
        &self,
        router: &Router,
        target: &Target,
    ) -> io::Result<tokio::net::UdpSocket> {
        let index = self.current.load(Ordering::Relaxed);
        let Some(member) = self.resolved.get(index) else {
            return Err(io::Error::other("selector has no members"));
        };
        router.connect_udp_index(*member, target).await
    }
}
