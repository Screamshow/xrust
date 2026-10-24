//! Minimal HTTP/1.1 client for the runtime's own fetches: remote rule-sets,
//! provider updates and the clash-api UI download. It dials through the router
//! so a `detour` (or the deprecated `download_detour`) reaches the same
//! outbounds as user traffic.
//!
//! Scope: HTTP/1.1 with `content-length`/chunked bodies and redirect
//! following. HTTP/2 is not negotiated — the reference also falls back to
//! HTTP/1.1 for these fetches unless an `h2` ALPN is forced.

use std::io;
use std::time::Duration;

use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::inbound::AnyStream;
use crate::route::Target;
use crate::tls_client::TlsOptions;

/// Reference `defaultHTTPTimeout` + `rule-set` fetch budget.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const IO_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_REDIRECTS: usize = 10;
const MAX_BODY: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone)]
pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Url {
    pub secure: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

impl Url {
    pub fn parse(raw: &str) -> io::Result<Self> {
        let (scheme, rest) = raw
            .split_once("://")
            .ok_or_else(|| io::Error::other(format!("invalid URL {raw:?}")))?;
        let secure = match scheme.to_ascii_lowercase().as_str() {
            "http" => false,
            "https" => true,
            other => {
                return Err(io::Error::other(format!(
                    "unsupported URL scheme {other:?}"
                )));
            }
        };
        let (authority, path) = match rest.find(['/', '?', '#']) {
            Some(at) => (&rest[..at], &rest[at..]),
            None => (rest, ""),
        };
        // strip userinfo and the fragment; the path is kept verbatim
        let authority = match authority.rsplit_once('@') {
            Some((_, host)) => host,
            None => authority,
        };
        let (host, port) = match authority.rsplit_once(':') {
            Some((host, port)) if !host.is_empty() && port.chars().all(|c| c.is_ascii_digit()) => (
                host.to_string(),
                port.parse()
                    .map_err(|_| io::Error::other(format!("invalid port in URL {raw:?}")))?,
            ),
            _ => (authority.to_string(), if secure { 443 } else { 80 }),
        };
        if host.is_empty() {
            return Err(io::Error::other(format!("invalid URL {raw:?}")));
        }
        let path = match path.find('#') {
            Some(at) => &path[..at],
            None => path,
        };
        let path = if path.is_empty() { "/" } else { path };
        Ok(Self {
            secure,
            host: host.trim_matches(['[', ']']).to_string(),
            port,
            path: path.to_string(),
        })
    }

    /// `host[:port]` for the `Host` header (the default port stays implicit).
    pub fn authority(&self) -> String {
        let default = if self.secure { 443 } else { 80 };
        if self.port == default {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Resolve a `Location` header against this URL.
    pub fn join(&self, location: &str) -> io::Result<Url> {
        if location.contains("://") {
            return Url::parse(location);
        }
        let base = if self.secure { "https" } else { "http" };
        if let Some(rest) = location.strip_prefix("//") {
            return Url::parse(&format!("{base}://{rest}"));
        }
        if location.starts_with('/') {
            return Url::parse(&format!("{base}://{}{location}", self.authority()));
        }
        let directory = match self.path.rfind('/') {
            Some(at) => &self.path[..=at],
            None => "/",
        };
        Url::parse(&format!(
            "{base}://{}{directory}{location}",
            self.authority()
        ))
    }
}

/// `option.HTTPClientOptions`, reduced to the fields the fetches honour.
#[derive(Debug, Clone, Default)]
pub struct HttpClient {
    /// Outbound tag the request is dialed through (`None` = router default).
    pub detour: Option<String>,
    pub tls: Option<std::sync::Arc<TlsOptions>>,
    pub headers: Vec<(String, String)>,
}

impl HttpClient {
    pub fn from_config(obj: Option<&Value>, at: &str) -> anyhow::Result<Self> {
        let Some(obj) = obj.and_then(Value::as_object) else {
            return Ok(Self::default());
        };
        let detour = obj
            .get("detour")
            .and_then(Value::as_str)
            .filter(|tag| !tag.is_empty())
            .map(str::to_string);
        let tls = match obj.get("tls").and_then(Value::as_object) {
            Some(tls) => {
                // reuse the outbound TLS parser: only `tls` matters here
                let mut wrapper = serde_json::Map::new();
                wrapper.insert("tls".into(), Value::Object(tls.clone()));
                let server = obj
                    .get("server_name")
                    .and_then(Value::as_str)
                    .unwrap_or("localhost");
                TlsOptions::from_outbound(&wrapper, server, at)?.map(std::sync::Arc::new)
            }
            None => None,
        };
        let headers = obj
            .get("headers")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .filter_map(|entry| {
                        let pair = entry.as_object()?;
                        let key = pair.get("key")?.as_str()?.to_string();
                        let value = pair.get("value")?.as_str()?.to_string();
                        Some((key, value))
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(Self {
            detour,
            tls,
            headers,
        })
    }

    /// `GET url` with redirects followed; the response body is bounded.
    pub async fn get(
        &self,
        router: &crate::route::Router,
        url: &str,
        extra_headers: &[(String, String)],
    ) -> io::Result<Response> {
        let mut current = Url::parse(url)?;
        for _ in 0..=MAX_REDIRECTS {
            let response = self.request(router, &current, extra_headers).await?;
            match response.status {
                301 | 302 | 303 | 307 | 308 => {
                    let Some(location) = response.header("location") else {
                        return Ok(response);
                    };
                    current = current.join(location)?;
                }
                _ => return Ok(response),
            }
        }
        Err(io::Error::other(format!(
            "too many redirects fetching {url:?}"
        )))
    }

    async fn request(
        &self,
        router: &crate::route::Router,
        url: &Url,
        extra_headers: &[(String, String)],
    ) -> io::Result<Response> {
        let host = url.host.clone();
        let target = Target::Domain(host, url.port);
        let conn = tokio::time::timeout(CONNECT_TIMEOUT, self.dial(router, &target))
            .await
            .map_err(|_| io::Error::other(format!("connect to {} timed out", url.authority())))??;

        let stream: AnyStream = if url.secure {
            match &self.tls {
                // an explicit `tls` block on the client is used as written
                Some(tls) => Box::new(tls.connect_stream(conn, &[b"http/1.1"]).await?),
                // Otherwise the server is verified (chain, name, validity)
                // against the embedded Mozilla roots plus the top-level
                // `certificate` option, like the URLTest probes. The detour
                // outbound only carries the bytes: its own TLS settings,
                // `insecure` included, do not apply to this server.
                None => {
                    let trust = router.inner().probe_tls.clone();
                    crate::tls_client::wrap_probe(conn, &url.host, &trust).await?
                }
            }
        } else {
            conn
        };

        let mut head = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: sing-box {}\r\nAccept: */*\r\n",
            url.path,
            url.authority(),
            env!("CARGO_PKG_VERSION")
        );
        for (key, value) in self.headers.iter().chain(extra_headers) {
            head.push_str(&format!("{key}: {value}\r\n"));
        }
        head.push_str("Connection: close\r\n\r\n");

        let mut stream = stream;
        tokio::time::timeout(IO_TIMEOUT, async {
            stream.write_all(head.as_bytes()).await?;
            stream.flush().await?;
            read_response(&mut stream).await
        })
        .await
        .map_err(|_| io::Error::other(format!("fetching {} timed out", url.path)))?
    }

    async fn dial(&self, router: &crate::route::Router, target: &Target) -> io::Result<AnyStream> {
        let conn = match &self.detour {
            Some(tag) => match router.index_of(tag) {
                Some(index) => router.connect_index(index, target).await,
                None => {
                    return Err(io::Error::other(format!(
                        "http client detour {tag:?} not found"
                    )));
                }
            },
            None => router.connect(target).await,
        }?;
        conn.into_plain()
    }
}

async fn read_response(stream: &mut AnyStream) -> io::Result<Response> {
    read_response_limited(stream, MAX_BODY).await
}

/// Read one response; the body, however it is framed, is bounded by `limit`.
async fn read_response_limited(stream: &mut AnyStream, limit: usize) -> io::Result<Response> {
    let mut buffer = Vec::with_capacity(8 * 1024);
    let mut chunk = [0u8; 8 * 1024];
    // head
    let head_end = loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::other("connection closed before response head"));
        }
        buffer.extend_from_slice(&chunk[..read]);
        if let Some(at) = find_head_end(&buffer) {
            break at;
        }
        if buffer.len() > 64 * 1024 {
            return Err(io::Error::other("response head too large"));
        }
    };
    let head = String::from_utf8_lossy(&buffer[..head_end]).to_string();
    // the head ends with the CRLFCRLF separator itself
    let rest = buffer[head_end + 4..].to_vec();
    let mut lines = head.split("\r\n");
    let status_line = lines.next().unwrap_or_default();
    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|code| code.parse().ok())
        .ok_or_else(|| io::Error::other(format!("bad status line {status_line:?}")))?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers.push((key.trim().to_ascii_lowercase(), value.trim().to_string()));
        }
    }
    let find = |name: &str| {
        headers
            .iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    let chunked = find("transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));

    // 204 and 304 never carry a body (RFC 9110 §15.3.5, §15.4.5); a 304 may
    // still state the length of the representation it refers to.
    let body = if status == 204 || status == 304 {
        Vec::new()
    } else if chunked {
        decode_chunked_limited(rest, stream, limit).await?
    } else if let Some(length) = content_length(&headers)? {
        // The declared size is checked before any more of the body is read,
        // so a peer cannot make us buffer past the limit, or wait for a body
        // that would be refused anyway.
        if length > limit {
            return Err(io::Error::other("response body too large"));
        }
        let mut body = rest;
        while body.len() < length {
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                return Err(io::Error::other(format!(
                    "truncated body: {} of {length} bytes",
                    body.len()
                )));
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body.truncate(length);
        body
    } else {
        let mut body = rest;
        loop {
            if body.len() > limit {
                return Err(io::Error::other("response body too large"));
            }
            let read = stream.read(&mut chunk).await?;
            if read == 0 {
                break;
            }
            body.extend_from_slice(&chunk[..read]);
        }
        body
    };
    if body.len() > limit {
        return Err(io::Error::other("response body too large"));
    }
    Ok(Response {
        status,
        headers,
        body,
    })
}

/// Longest chunk-size line accepted, extensions included.
const MAX_CHUNK_LINE: usize = 4 * 1024;

/// `Content-Length` (RFC 9112 §6.3): decimal digits only. Repeated values,
/// in one header as a list or in several headers, must all be the same.
/// `None` when the header is absent; an error when it is malformed or too
/// large for `usize`.
fn content_length(headers: &[(String, String)]) -> io::Result<Option<usize>> {
    let mut length = None;
    for (key, value) in headers {
        if key != "content-length" {
            continue;
        }
        for part in value.split(',') {
            let part = part.trim();
            let parsed = (!part.is_empty())
                .then_some(part)
                .filter(|p| p.bytes().all(|b| b.is_ascii_digit()))
                .and_then(|p| p.parse::<usize>().ok());
            match (parsed, length) {
                (Some(n), None) => length = Some(n),
                (Some(n), Some(seen)) if n == seen => {}
                _ => return Err(io::Error::other(format!("bad content-length {value:?}"))),
            }
        }
    }
    Ok(length)
}

/// `transfer-encoding: chunked`: size line, data, CRLF, until a zero chunk.
/// The chunk sizes come from the peer, so every size is parsed strictly and
/// checked against what is left of `limit` before any of its data is read.
/// Release builds have no overflow checks and abort on panic: an unchecked
/// `start + size` here once let one response stop the whole process.
async fn decode_chunked_limited(
    initial: Vec<u8>,
    stream: &mut AnyStream,
    limit: usize,
) -> io::Result<Vec<u8>> {
    let too_large = || io::Error::other("response body too large");
    let mut buffer = initial;
    let mut body = Vec::new();
    let mut scratch = [0u8; 8 * 1024];
    loop {
        let (size, start) = loop {
            let Some(at) = find_crlf(&buffer) else {
                // A line of MAX_CHUNK_LINE bytes may already have its CR
                // buffered while the LF is still in flight; only a buffer
                // longer than that can no longer hold a line within the limit.
                if buffer.len() > MAX_CHUNK_LINE + 1 {
                    return Err(io::Error::other("chunk size line too long"));
                }
                let read = stream.read(&mut scratch).await?;
                if read == 0 {
                    return Err(io::Error::other("truncated chunked body"));
                }
                buffer.extend_from_slice(&scratch[..read]);
                continue;
            };
            if at > MAX_CHUNK_LINE {
                return Err(io::Error::other("chunk size line too long"));
            }
            let size = parse_chunk_size(&buffer[..at]).ok_or_else(|| {
                io::Error::other(format!(
                    "bad chunk size {:?}",
                    String::from_utf8_lossy(&buffer[..at])
                ))
            })?;
            break (size, at + 2);
        };
        if size == 0 {
            return Ok(body);
        }
        // the limit counts what is already in `body`
        if size > limit.saturating_sub(body.len()) {
            return Err(too_large());
        }
        let data_end = start.checked_add(size).ok_or_else(too_large)?;
        let needed = data_end.checked_add(2).ok_or_else(too_large)?;
        while buffer.len() < needed {
            let read = stream.read(&mut scratch).await?;
            if read == 0 {
                return Err(io::Error::other("truncated chunked body"));
            }
            buffer.extend_from_slice(&scratch[..read]);
        }
        if &buffer[data_end..needed] != b"\r\n" {
            return Err(io::Error::other("chunk data not followed by CRLF"));
        }
        body.extend_from_slice(&buffer[start..data_end]);
        buffer.drain(..needed);
    }
}

/// `chunk-size [ chunk-ext ]` (RFC 9112 §7.1): one or more hex digits, then
/// optional whitespace and extensions after `;`. A sign, a `0x` prefix or a
/// value that does not fit in `usize` is refused.
fn parse_chunk_size(line: &[u8]) -> Option<usize> {
    let end = line.iter().position(|&b| b == b';').unwrap_or(line.len());
    let digits = line[..end].trim_ascii();
    if digits.is_empty() {
        return None;
    }
    let mut size: usize = 0;
    for &b in digits {
        let digit = (b as char).to_digit(16)? as usize;
        size = size.checked_mul(16)?.checked_add(digit)?;
    }
    Some(size)
}

fn find_crlf(buffer: &[u8]) -> Option<usize> {
    buffer.windows(2).position(|window| window == b"\r\n")
}

fn find_head_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    const CRLF: &str = "\r\n";

    fn url(raw: &str) -> Url {
        Url::parse(raw).expect("url")
    }

    #[test]
    fn a_named_client_is_resolved_by_its_tag() {
        let root = serde_json::json!({
            "http_clients": [
                {"tag": "clash", "detour": "proxy", "headers": {"user-agent": "meta"}},
                {"tag": "plain"}
            ]
        });
        let registry = Registry::from_config(&root).expect("registry");
        let route = serde_json::Map::new();

        // an object is the client itself, a string names a registry entry
        assert_eq!(
            registry
                .resolve(Some(&serde_json::json!({"detour": "direct"})), "rs")
                .expect("object"),
            Some(serde_json::json!({"detour": "direct"}))
        );
        assert_eq!(
            registry
                .resolve(Some(&serde_json::json!("clash")), "rs")
                .expect("tag")
                .expect("entry")["detour"],
            serde_json::json!("proxy")
        );
        assert!(
            registry
                .resolve(Some(&serde_json::json!("nope")), "rs")
                .expect_err("unknown tag")
                .to_string()
                .contains("http client not found: nope")
        );

        // `route.default_http_client` is the one named for every other fetch
        assert!(
            registry
                .default_client(&route)
                .expect("no default")
                .is_none()
        );
        let with_default = serde_json::Map::from_iter([(
            "default_http_client".into(),
            serde_json::json!("plain"),
        )]);
        assert!(
            registry
                .default_client(&with_default)
                .expect("default")
                .expect("entry")["tag"]
                == "plain"
        );
    }

    #[test]
    fn url_parsing() {
        let parsed = url("https://example.com/a/b?c=d");
        assert!(parsed.secure);
        assert_eq!(parsed.host, "example.com");
        assert_eq!(parsed.port, 443);
        assert_eq!(parsed.path, "/a/b?c=d");
        assert_eq!(parsed.authority(), "example.com");
        assert_eq!(url("http://1.2.3.4:8080").port, 8080);
        assert_eq!(url("http://1.2.3.4:8080").authority(), "1.2.3.4:8080");
        assert_eq!(url("https://[::1]:8443/x").host, "::1");
        assert_eq!(url("https://host").path, "/");
        assert!(Url::parse("ftp://host/x").is_err());
        assert!(Url::parse("host/x").is_err());
    }

    #[test]
    fn url_join() {
        let base = url("https://a.test/x/y?q=1");
        assert_eq!(base.join("/abs").unwrap().path, "/abs");
        assert_eq!(base.join("rel").unwrap().path, "/x/rel");
        assert_eq!(base.join("//b.test/z").unwrap().host, "b.test");
        assert_eq!(base.join("https://c.test/w").unwrap().host, "c.test");
    }

    #[test]
    fn client_config_parsing() {
        let value = serde_json::json!({
            "detour": "proxy",
            "headers": [{"key": "X-Test", "value": "1"}]
        });
        let client = HttpClient::from_config(Some(&value), "test").expect("client");
        assert_eq!(client.detour.as_deref(), Some("proxy"));
        assert_eq!(
            client.headers,
            vec![("X-Test".to_string(), "1".to_string())]
        );
        let insecure = serde_json::json!({"tls": {"enabled": true, "insecure": true}});
        let client = HttpClient::from_config(Some(&insecure), "test").expect("client");
        assert!(client.tls.is_some());
        let empty = HttpClient::from_config(None, "test").expect("client");
        assert!(empty.detour.is_none() && empty.tls.is_none());
    }

    #[test]
    fn chunked_body_decoding() {
        // 5 "hello", 6 " world", then the terminating zero chunk
        let data: Vec<u8> = ["5", "hello", "6", " world", "0", ""]
            .join(CRLF)
            .into_bytes();
        let mut buffer = data.clone();
        let mut body = Vec::new();
        for _ in 0..4 {
            let Some(at) = find_crlf(&buffer) else {
                panic!("no CRLF in {:?}", String::from_utf8_lossy(&buffer));
            };
            let line = String::from_utf8_lossy(&buffer[..at]).to_string();
            let size = usize::from_str_radix(line.trim(), 16).expect("size");
            if size == 0 {
                break;
            }
            let start = at + 2;
            let needed = start + size + 2;
            body.extend_from_slice(&buffer[start..start + size]);
            buffer.drain(..needed);
        }
        assert_eq!(body, b"hello world");
    }

    /// A stream that delivers `pieces` one write at a time, then either ends
    /// or, with `hold_open`, stays open so a decoder that waits for more data
    /// would hang instead of failing.
    fn piecewise(pieces: Vec<Vec<u8>>, hold_open: bool) -> AnyStream {
        let (client, mut server) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            for piece in pieces {
                if server.write_all(&piece).await.is_err() {
                    return;
                }
                let _ = server.flush().await;
                tokio::task::yield_now().await;
            }
            if hold_open {
                std::future::pending::<()>().await;
            }
        });
        Box::new(client)
    }

    async fn decode(pieces: &[&[u8]], limit: usize) -> io::Result<Vec<u8>> {
        decode_open(pieces, limit, false).await
    }

    async fn decode_open(pieces: &[&[u8]], limit: usize, hold_open: bool) -> io::Result<Vec<u8>> {
        let mut stream = piecewise(pieces.iter().map(|p| p.to_vec()).collect(), hold_open);
        tokio::time::timeout(
            Duration::from_secs(5),
            decode_chunked_limited(Vec::new(), &mut stream, limit),
        )
        .await
        .expect("the decoder must answer, not wait for more data")
    }

    fn error_text(result: io::Result<Vec<u8>>) -> String {
        result
            .expect_err("malformed body must be an error")
            .to_string()
    }

    #[tokio::test]
    async fn chunked_valid_bodies_decode() {
        // several chunks, an extension, uppercase hex, a trailer after the zero chunk
        let body =
            b"5\r\nhello\r\n6;name=value\r\n world\r\nA\r\n0123456789\r\n0\r\nX-T: 1\r\n\r\n";
        assert_eq!(
            decode(&[body], MAX_BODY).await.unwrap(),
            b"hello world0123456789"
        );
        // the same bytes arriving one at a time
        let bytes: Vec<&[u8]> = body.chunks(1).collect();
        assert_eq!(
            decode(&bytes, MAX_BODY).await.unwrap(),
            b"hello world0123456789"
        );
        // a body that is only the zero chunk
        assert_eq!(decode(&[b"0\r\n\r\n"], MAX_BODY).await.unwrap(), b"");
        // exactly at the limit is allowed
        assert_eq!(
            decode(&[b"5\r\nhello\r\n0\r\n\r\n"], 5).await.unwrap(),
            b"hello"
        );
        // data already read with the head is used first
        let mut stream = piecewise(vec![b"lo\r\n0\r\n\r\n".to_vec()], false);
        let decoded = decode_chunked_limited(b"5\r\nhel".to_vec(), &mut stream, MAX_BODY)
            .await
            .unwrap();
        assert_eq!(decoded, b"hello");
    }

    #[tokio::test]
    async fn chunked_huge_sizes_are_errors_not_panics() {
        // usize::MAX: `start + size + 2` used to overflow and panic
        let max = format!("{:x}\r\nabc", usize::MAX);
        let text = error_text(decode(&[max.as_bytes()], MAX_BODY).await);
        assert!(text.contains("too large"), "{text}");
        // one hex digit more than fits in usize
        let wider = format!("1{}\r\n", "0".repeat(usize::BITS as usize / 4));
        let text = error_text(decode(&[wider.as_bytes()], MAX_BODY).await);
        assert!(text.contains("bad chunk size"), "{text}");
        // over the limit: refused before any data is read or buffered,
        // even though the peer keeps the connection open
        let text = error_text(decode_open(&[b"5\r\n"], 4, true).await);
        assert!(text.contains("too large"), "{text}");
    }

    #[tokio::test]
    async fn chunked_total_over_the_limit_is_refused() {
        // each chunk fits, the sum does not; the second one is refused
        // before its data is read
        let text = error_text(decode_open(&[b"5\r\nhello\r\n6\r\n"], 10, true).await);
        assert!(text.contains("too large"), "{text}");
        let text =
            error_text(decode(&[b"5\r\nhello\r\n5\r\nworld\r\n1\r\n!\r\n0\r\n\r\n"], 10).await);
        assert!(text.contains("too large"), "{text}");
    }

    #[tokio::test]
    async fn chunked_truncated_bodies_are_errors() {
        for pieces in [
            &[&b""[..]][..],
            &[b"5"],
            &[b"5\r\nhel"],
            &[b"5\r\nhello"],
            &[b"5\r\nhello\r\n"],
        ] {
            let text = error_text(decode(pieces, MAX_BODY).await);
            assert!(text.contains("truncated"), "{pieces:?}: {text}");
        }
    }

    #[tokio::test]
    async fn chunked_malformed_sizes_are_errors() {
        for line in [&b"zz"[..], b"", b"+5", b"-1", b"0x5", b"5 5", b";ext"] {
            let mut body = line.to_vec();
            body.extend_from_slice(b"\r\nhello\r\n0\r\n\r\n");
            let text = error_text(decode(&[&body], MAX_BODY).await);
            assert!(text.contains("bad chunk size"), "{line:?}: {text}");
        }
        // data not followed by CRLF
        let text = error_text(decode(&[b"5\r\nhelloXY0\r\n\r\n"], MAX_BODY).await);
        assert!(text.contains("chunk data"), "{text}");
        // a size line that never ends
        let endless = vec![b'1'; 8 * 1024];
        let text = error_text(decode_open(&[&endless], MAX_BODY, true).await);
        assert!(text.contains("size line too long"), "{text}");
    }

    /// A size line of `len` bytes: "5;x=" padded with an extension value.
    fn size_line(len: usize) -> Vec<u8> {
        let mut line = b"5;x=".to_vec();
        line.resize(len, b'a');
        line
    }

    /// Decode `line` + CRLF + "hello" + the zero chunk. With `split`, the CR
    /// is already buffered (as if read with the response head) and the LF
    /// only arrives from the stream, so the line's end is seen in two reads.
    async fn decode_line(len: usize, split: bool) -> io::Result<Vec<u8>> {
        let mut initial = size_line(len);
        let rest: &[u8] = b"hello\r\n0\r\n\r\n";
        let mut pieces = Vec::new();
        if split {
            initial.push(b'\r');
            pieces.push(b"\n".to_vec());
        } else {
            initial.extend_from_slice(b"\r\n");
        }
        pieces.push(rest.to_vec());
        let mut stream = piecewise(pieces, true);
        tokio::time::timeout(
            Duration::from_secs(5),
            decode_chunked_limited(initial, &mut stream, MAX_BODY),
        )
        .await
        .expect("the decoder must answer, not wait for more data")
    }

    #[tokio::test]
    async fn chunk_size_line_limit_is_the_same_whole_or_split() {
        assert_eq!(MAX_CHUNK_LINE, 4096);
        for split in [false, true] {
            for len in [MAX_CHUNK_LINE - 1, MAX_CHUNK_LINE] {
                let decoded = decode_line(len, split)
                    .await
                    .unwrap_or_else(|e| panic!("len {len}, split {split}: {e}"));
                assert_eq!(decoded, b"hello", "len {len}, split {split}");
            }
            let text = error_text(decode_line(MAX_CHUNK_LINE + 1, split).await);
            assert!(text.contains("size line too long"), "split {split}: {text}");
        }
    }

    /// Read one response from `pieces` with a body limit of `limit`.
    async fn respond(pieces: &[&[u8]], limit: usize, hold_open: bool) -> io::Result<Response> {
        let mut stream = piecewise(pieces.iter().map(|p| p.to_vec()).collect(), hold_open);
        tokio::time::timeout(
            Duration::from_secs(5),
            read_response_limited(&mut stream, limit),
        )
        .await
        .expect("the reader must answer, not wait for more data")
    }

    fn with_length(value: &str, body: &str) -> Vec<u8> {
        format!("HTTP/1.1 200 OK\r\nContent-Length: {value}\r\n\r\n{body}").into_bytes()
    }

    fn response_error(result: io::Result<Response>) -> String {
        result.expect_err("must be an error").to_string()
    }

    // Content-Length tests come in three groups:
    // - valid responses: read the same before and after the SEC-07 fix;
    // - SEC-07: a declared length over MAX_BODY is refused from the header;
    // - deliberate changes that came with it: the limit boundary,
    //   malformed and repeated values, truncated bodies, 204/304.

    // --- valid responses -------------------------------------------------

    #[tokio::test]
    async fn content_length_valid_bodies_are_read() {
        // zero length: no body to wait for, even with the connection open
        let response = respond(&[&with_length("0", "")], MAX_BODY, true)
            .await
            .unwrap();
        assert_eq!(response.body, b"");
        // the whole body arrives with the head
        let response = respond(&[&with_length("5", "hello")], MAX_BODY, true)
            .await
            .unwrap();
        assert_eq!(response.body, b"hello");
        // part of the body arrives with the head, the rest in later reads
        let head = with_length("11", "hel");
        let response = respond(&[&head, b"lo", b" ", b"world"], MAX_BODY, true)
            .await
            .unwrap();
        assert_eq!(response.body, b"hello world");
        // the head itself split across reads, then the body byte by byte
        let mut pieces: Vec<&[u8]> = vec![b"HTTP/1.1 200 OK\r\nConte", b"nt-Length: 5\r\n\r\n"];
        pieces.extend(b"hello".chunks(1));
        let response = respond(&pieces, MAX_BODY, true).await.unwrap();
        assert_eq!(response.body, b"hello");
        // bytes past the declared length are not part of the body
        let response = respond(&[&with_length("5", "helloEXTRA")], MAX_BODY, false)
            .await
            .unwrap();
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn content_length_at_the_limit_is_read() {
        let response = respond(&[&with_length("5", "hello")], 5, true)
            .await
            .unwrap();
        assert_eq!(response.body, b"hello");
    }

    // --- SEC-07 ----------------------------------------------------------

    #[tokio::test]
    async fn sec07_declared_length_over_max_body_is_refused_before_reading() {
        // The declared size alone is enough: the server keeps the connection
        // open and sends no body. Before the fix the client waited for the
        // body (and buffered whatever came) up to the declared length.
        let declared = (MAX_BODY + 1).to_string();
        let text = response_error(respond(&[&with_length(&declared, "")], MAX_BODY, true).await);
        assert!(text.contains("too large"), "{text}");
        let text = response_error(
            respond(
                &[&with_length(&u64::MAX.to_string(), "abc")],
                MAX_BODY,
                true,
            )
            .await,
        );
        assert!(text.contains("too large"), "{text}");
    }

    // --- deliberate changes that came with the fix -----------------------

    #[tokio::test]
    async fn content_length_one_over_the_limit_is_refused() {
        let text = response_error(respond(&[&with_length("6", "")], 5, true).await);
        assert!(text.contains("too large"), "{text}");
    }

    #[tokio::test]
    async fn content_length_identical_list_is_one_length() {
        // RFC 9112 §6.3: a list of identical values is one length. Before,
        // such a header did not parse and was ignored.
        let response = respond(&[&with_length("5, 5", "hello")], MAX_BODY, true)
            .await
            .unwrap();
        assert_eq!(response.body, b"hello");
    }

    #[tokio::test]
    async fn content_length_malformed_values_are_errors() {
        let overflow = format!("{}0", usize::MAX);
        for value in [
            "abc",
            "-1",
            "+5",
            "5 5",
            "0x5",
            "",
            "5, 6",
            "5,",
            overflow.as_str(),
        ] {
            let text =
                response_error(respond(&[&with_length(value, "hello")], MAX_BODY, true).await);
            assert!(text.contains("bad content-length"), "{value:?}: {text}");
        }
        // two headers that disagree
        let head = b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello";
        let text = response_error(respond(&[head], MAX_BODY, true).await);
        assert!(text.contains("bad content-length"), "{text}");
    }

    #[tokio::test]
    async fn content_length_truncated_body_is_an_error() {
        let text = response_error(respond(&[&with_length("10", "hell")], MAX_BODY, false).await);
        assert!(text.contains("truncated"), "{text}");
        let text = response_error(respond(&[&with_length("5", "")], MAX_BODY, false).await);
        assert!(text.contains("truncated"), "{text}");
    }

    #[tokio::test]
    async fn bodiless_statuses_ignore_content_length() {
        // a 304 may carry the length of the representation it refers to
        // (RFC 9110 §8.6); there is no body to read or wait for
        for status in ["304 Not Modified", "204 No Content"] {
            let head = format!("HTTP/1.1 {status}\r\nContent-Length: 1000\r\n\r\n");
            let response = respond(&[head.as_bytes()], MAX_BODY, true).await.unwrap();
            assert!(response.body.is_empty(), "{status}");
        }
    }

    #[tokio::test]
    async fn sec07_get_refuses_a_content_length_over_the_limit() {
        // SEC-07 end to end: before the fix the client read until the peer
        // closed and returned the short body as a success
        let router = test_router().await;
        let declared = (MAX_BODY + 1).to_string();
        let (url, server) = serve_once(
            [
                "HTTP/1.1 200 OK",
                &format!("Content-Length: {declared}"),
                "",
                "abc",
            ]
            .join(CRLF),
        )
        .await;
        let error = HttpClient::default()
            .get(&router, &url, &[])
            .await
            .expect_err("declared body over the limit");
        server.await.ok();
        assert!(error.to_string().contains("too large"), "{error}");
    }

    #[tokio::test]
    async fn get_refuses_an_overflowing_chunk_size() {
        let router = test_router().await;
        let (url, server) = serve_once(
            [
                "HTTP/1.1 200 OK",
                "Transfer-Encoding: chunked",
                "",
                &format!("{:x}", usize::MAX),
                "abc",
            ]
            .join(CRLF),
        )
        .await;
        let error = HttpClient::default()
            .get(&router, &url, &[])
            .await
            .expect_err("overflowing chunk size");
        server.await.ok();
        assert!(error.to_string().contains("too large"), "{error}");
    }

    async fn serve_once(response: String) -> (String, tokio::task::JoinHandle<()>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            if let Ok((mut stream, _)) = listener.accept().await {
                let mut head = [0u8; 1024];
                let _ = stream.read(&mut head).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.flush().await;
            }
        });
        (format!("http://{addr}/ruleset.srs"), handle)
    }

    async fn test_router() -> Arc<crate::route::Router> {
        crate::route::Router::new(&serde_json::json!({
            "log": {"level": "error"},
            "outbounds": [{"type": "direct", "tag": "direct"}]
        }))
        .expect("router")
    }

    #[tokio::test]
    async fn get_reads_status_headers_and_body() {
        let router = test_router().await;
        let (url, server) = serve_once(
            [
                "HTTP/1.1 200 OK",
                "Content-Length: 5",
                "Etag: \"abc\"",
                "",
                "hello",
            ]
            .join(CRLF),
        )
        .await;
        let response = HttpClient::default()
            .get(&router, &url, &[])
            .await
            .expect("get");
        server.await.ok();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"hello");
        assert_eq!(response.header("etag"), Some("\"abc\""));
    }

    #[tokio::test]
    async fn chunked_bodies_are_decoded() {
        let router = test_router().await;
        let (url, server) = serve_once(
            [
                "HTTP/1.1 200 OK",
                "Transfer-Encoding: chunked",
                "",
                "5",
                "hello",
                "6",
                " world",
                "0",
                "",
                "",
            ]
            .join(CRLF),
        )
        .await;
        let response = HttpClient::default()
            .get(&router, &url, &[])
            .await
            .expect("get");
        server.await.ok();
        assert_eq!(response.body, b"hello world");
    }

    #[tokio::test]
    async fn redirects_are_followed() {
        let router = test_router().await;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let target = format!("http://{addr}/final.srs");
        let server = tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.expect("accept");
            let mut head = [0u8; 1024];
            let _ = first.read(&mut head).await;
            let _ = first
                .write_all(
                    format!("HTTP/1.1 302 Found{CRLF}Location: {target}{CRLF}Content-Length: 0{CRLF}{CRLF}")
                        .as_bytes(),
                )
                .await;
            let (mut second, _) = listener.accept().await.expect("accept");
            let _ = second.read(&mut head).await;
            let _ = second
                .write_all(
                    format!("HTTP/1.1 200 OK{CRLF}Content-Length: 2{CRLF}{CRLF}ok").as_bytes(),
                )
                .await;
        });
        let response = HttpClient::default()
            .get(&router, &format!("http://{addr}/start.srs"), &[])
            .await
            .expect("get");
        server.await.ok();
        assert_eq!(response.status, 200);
        assert_eq!(response.body, b"ok");
    }
}

/// The top-level `http_clients` registry: the named clients a string
/// `http_client` -- or `route.default_http_client` -- points at. A value
/// that is an object is the client itself; a string is a tag into this
/// map, exactly as `option.HTTPClient.UnmarshalJSON` resolves it.
#[derive(Debug, Default, Clone)]
pub struct Registry {
    clients: std::collections::HashMap<String, Value>,
}

impl Registry {
    pub fn from_config(root: &Value) -> anyhow::Result<Self> {
        let mut clients = std::collections::HashMap::new();
        let empty = Vec::new();
        for (i, entry) in root
            .get("http_clients")
            .and_then(Value::as_array)
            .unwrap_or(&empty)
            .iter()
            .enumerate()
        {
            let at = format!("http_clients[{i}]");
            let object = entry
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("{at}: must be a JSON object"))?;
            let tag = object
                .get("tag")
                .and_then(Value::as_str)
                .filter(|tag| !tag.is_empty())
                .ok_or_else(|| anyhow::anyhow!("missing http client tag"))?;
            if clients.insert(tag.to_string(), entry.clone()).is_some() {
                anyhow::bail!("duplicate http client tag: {tag}");
            }
        }
        Ok(Self { clients })
    }

    /// The object a `http_client` value stands for.
    pub fn resolve(&self, value: Option<&Value>, at: &str) -> anyhow::Result<Option<Value>> {
        let Some(value) = value.filter(|value| !value.is_null()) else {
            return Ok(None);
        };
        match value {
            Value::String(tag) => self
                .clients
                .get(tag)
                .cloned()
                .map(Some)
                .ok_or_else(|| anyhow::anyhow!("{at}: http client not found: {tag}")),
            other => Ok(Some(other.clone())),
        }
    }

    /// `route.default_http_client`, named once for every download that
    /// carries no client of its own.
    pub fn default_client(
        &self,
        route: &serde_json::Map<String, Value>,
    ) -> anyhow::Result<Option<Value>> {
        let tag = route
            .get("default_http_client")
            .and_then(Value::as_str)
            .filter(|tag| !tag.is_empty());
        match tag {
            None => Ok(None),
            Some(tag) => self
                .clients
                .get(tag)
                .cloned()
                .map(Some)
                .ok_or_else(|| anyhow::anyhow!("route.default_http_client: not found: {tag}")),
        }
    }
}
