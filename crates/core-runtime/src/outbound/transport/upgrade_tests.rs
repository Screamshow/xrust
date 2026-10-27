//! The shape of the websocket and HTTPUpgrade requests: with no `User-Agent`
//! configured both carry the browser `ws` headers Xray puts on them, and the
//! HTTPUpgrade request carries the websocket key and version its dialer adds.

use sha1::{Digest, Sha1};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::*;

/// Reads a request head off `server`, answers 101 for the key it carries and
/// hands the head back.
async fn upgrade_head(mut server: tokio::io::DuplexStream, accept: bool) -> String {
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        match server.read(&mut byte).await {
            Ok(0) | Err(_) => break,
            Ok(_) => head.push(byte[0]),
        }
    }
    let head = String::from_utf8_lossy(&head).to_string();
    let mut response = String::from("HTTP/1.1 101 Switching Protocols\r\n");
    if accept {
        let key = head
            .lines()
            .find_map(|line| line.strip_prefix("Sec-WebSocket-Key: "))
            .unwrap_or_default()
            .to_string();
        let mut hash = Sha1::new();
        hash.update(key.as_bytes());
        hash.update(WS_GUID);
        response.push_str("Upgrade: websocket\r\nConnection: Upgrade\r\n");
        response.push_str(&format!(
            "Sec-WebSocket-Accept: {}\r\n",
            base64_std(&hash.finalize())
        ));
    }
    response.push_str("\r\n");
    let _ = server.write_all(response.as_bytes()).await;
    head
}

/// The names a request head carries, in the order they appear.
fn names(head: &str) -> Vec<String> {
    head.lines()
        .skip(1)
        .filter(|line| !line.is_empty())
        .filter_map(|line| line.split_once(':'))
        .map(|(name, _)| name.to_string())
        .collect()
}

fn value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.lines().skip(1).find_map(|line| {
        let (key, value) = line.split_once(": ")?;
        key.eq_ignore_ascii_case(name).then_some(value)
    })
}

async fn ws_head(headers: &[(String, String)]) -> String {
    let (client, server) = tokio::io::duplex(8192);
    let head = tokio::spawn(upgrade_head(server, true));
    let no_early = EarlyData {
        max: 0,
        header_name: "",
    };
    let handshake = ws_handshake(
        Box::new(client),
        "/ws",
        "example.com",
        headers,
        &[],
        no_early,
    );
    let (upgraded, head) = tokio::join!(handshake, head);
    upgraded.expect("ws upgrade");
    head.expect("head")
}

async fn httpupgrade_head(headers: &[(String, String)]) -> String {
    let (client, server) = tokio::io::duplex(8192);
    let head = tokio::spawn(upgrade_head(server, false));
    let handshake = httpupgrade_handshake(Box::new(client), "/hu", "example.com", headers);
    let (upgraded, head) = tokio::join!(handshake, head);
    upgraded.expect("httpupgrade");
    head.expect("head")
}

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[tokio::test]
async fn a_ws_upgrade_carries_the_browser_headers() {
    let head = ws_head(&[]).await;
    assert!(
        head.starts_with("GET /ws HTTP/1.1\r\nHost: example.com\r\n"),
        "{head}"
    );
    for name in [
        "Sec-CH-UA",
        "Sec-CH-UA-Mobile",
        "Sec-CH-UA-Platform",
        "DNT",
        "User-Agent",
        "Accept-Language",
        "Sec-Fetch-Mode",
        "Sec-Fetch-Dest",
        "Sec-Fetch-Site",
        "Cache-Control",
        "Pragma",
        "Accept",
    ] {
        assert!(value(&head, name).is_some(), "{name} missing from {head}");
    }
    assert_eq!(value(&head, "Sec-Fetch-Mode"), Some("websocket"));
    assert_eq!(value(&head, "Sec-Fetch-Dest"), Some("empty"));
    assert_eq!(value(&head, "Sec-Fetch-Site"), Some("same-origin"));
    assert!(
        value(&head, "User-Agent")
            .expect("user agent")
            .contains("Chrome/"),
        "{head}"
    );
    // a websocket upgrade has no `Priority`, unlike an XHTTP request
    assert!(value(&head, "Priority").is_none(), "{head}");
    // the mandatory headers keep their place at the front
    let names = names(&head);
    assert_eq!(
        &names[..5],
        [
            "Host",
            "Upgrade",
            "Connection",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version"
        ]
    );
}

/// A `User-Agent` of the user's own leaves the request as it was before:
/// nothing browser-like is added, as in the reference.
#[tokio::test]
async fn an_own_user_agent_keeps_the_upgrade_bare() {
    let head = ws_head(&headers(&[("User-Agent", "mine/1.0")])).await;
    assert_eq!(value(&head, "User-Agent"), Some("mine/1.0"));
    assert!(value(&head, "Sec-CH-UA").is_none(), "{head}");
    assert!(value(&head, "Sec-Fetch-Mode").is_none(), "{head}");
}

/// `User-Agent: firefox` names a profile: the Firefox headers replace it.
#[tokio::test]
async fn a_named_profile_replaces_the_user_agent() {
    let head = ws_head(&headers(&[("User-Agent", "firefox")])).await;
    let ua = value(&head, "User-Agent").expect("user agent");
    assert!(ua.contains("Gecko/20100101 Firefox/"), "{ua}");
    assert_eq!(value(&head, "Accept-Language"), Some("en-US,en;q=0.5"));
    assert!(value(&head, "Sec-CH-UA").is_none(), "{head}");
}

/// A configured header the fill set also carries stays the configured one.
#[tokio::test]
async fn a_configured_header_wins_over_the_fill() {
    let head = ws_head(&headers(&[("Accept", "text/plain")])).await;
    assert_eq!(value(&head, "Accept"), Some("text/plain"));
    assert_eq!(value(&head, "Cache-Control"), Some("no-cache"));
}

#[tokio::test]
async fn an_httpupgrade_request_is_shaped_like_the_reference() {
    let head = httpupgrade_head(&[]).await;
    let names = names(&head);
    assert_eq!(&names[..2], ["Host", "User-Agent"], "{head}");
    // `net/http` writes the rest in name order
    let rest: Vec<&str> = names[2..].iter().map(String::as_str).collect();
    let mut sorted = rest.clone();
    sorted.sort_unstable();
    assert_eq!(rest, sorted, "{head}");
    assert_eq!(
        rest,
        [
            "Accept",
            "Accept-Language",
            "Cache-Control",
            "Connection",
            "DNT",
            "Pragma",
            "Sec-CH-UA",
            "Sec-CH-UA-Mobile",
            "Sec-CH-UA-Platform",
            "Sec-Fetch-Dest",
            "Sec-Fetch-Mode",
            "Sec-Fetch-Site",
            "Sec-WebSocket-Key",
            "Sec-WebSocket-Version",
            "Upgrade",
        ]
    );
    assert_eq!(value(&head, "Connection"), Some("Upgrade"));
    assert_eq!(value(&head, "Upgrade"), Some("websocket"));
    assert_eq!(value(&head, "Sec-WebSocket-Version"), Some("13"));
    // 16 random bytes, standard base64 with its padding
    let key = value(&head, "Sec-WebSocket-Key").expect("key");
    assert_eq!(key.len(), 24, "{key}");
    assert!(key.ends_with("=="), "{key}");
}

/// Two upgrades draw their own keys.
#[tokio::test]
async fn every_httpupgrade_request_has_its_own_key() {
    let first = httpupgrade_head(&[]).await;
    let second = httpupgrade_head(&[]).await;
    assert_ne!(
        value(&first, "Sec-WebSocket-Key"),
        value(&second, "Sec-WebSocket-Key")
    );
}

/// A configured key and version are left as they are, as the reference's
/// `if len(req.Header.Values(..)) == 0` does.
#[tokio::test]
async fn a_configured_key_is_kept() {
    let head = httpupgrade_head(&headers(&[
        ("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="),
        ("Sec-WebSocket-Version", "8"),
    ]))
    .await;
    assert_eq!(
        value(&head, "Sec-WebSocket-Key"),
        Some("dGhlIHNhbXBsZSBub25jZQ==")
    );
    assert_eq!(value(&head, "Sec-WebSocket-Version"), Some("8"));
}
