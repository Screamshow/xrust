//! HTTP destination for both automatic and manual latency probes.
pub struct ProbeUrl {
    pub tls: bool,
    pub host: String,
    pub port: u16,
    pub authority: String,
    pub path: String,
}

impl ProbeUrl {
    pub fn parse(url: &str) -> Option<Self> {
        let (scheme, rest) = url.split_once("://")?;
        let tls = if scheme.eq_ignore_ascii_case("https") {
            true
        } else if scheme.eq_ignore_ascii_case("http") {
            false
        } else {
            return None;
        };
        let rest = rest.split('#').next()?;
        if rest.bytes().any(|b| b.is_ascii_control() || b == b' ') {
            return None;
        }
        let (authority, path) = rest.split_at(rest.find(['/', '?']).unwrap_or(rest.len()));
        let (host, port) = if let Some(literal) = authority.strip_prefix('[') {
            let (host, suffix) = literal.split_once(']')?;
            host.parse::<std::net::Ipv6Addr>().ok()?;
            (
                host,
                if suffix.is_empty() {
                    None
                } else {
                    Some(suffix.strip_prefix(':')?)
                },
            )
        } else {
            let (host, port) = authority
                .split_once(':')
                .map_or((authority, None), |(host, port)| (host, Some(port)));
            if host.is_empty() || host.contains(['[', ']', '@', '\\']) {
                return None;
            }
            (host, port)
        };
        let port = match port {
            Some(p) if !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()) => p.parse().ok()?,
            Some(_) => return None,
            None if tls => 443,
            None => 80,
        };
        Some(Self {
            tls,
            host: host.to_owned(),
            port,
            authority: authority.to_owned(),
            path: if path.starts_with('/') {
                path.to_owned()
            } else {
                format!("/{path}")
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ProbeUrl;

    #[test]
    fn probe_authority_and_target() {
        for (url, host, port, authority, path) in [
            ("https://[::1]?a=1#frag", "::1", 443, "[::1]", "/?a=1"),
            ("http://[::1]:81/ok", "::1", 81, "[::1]:81", "/ok"),
            ("http://site:8000", "site", 8000, "site:8000", "/"),
            ("https://site?q=1", "site", 443, "site", "/?q=1"),
        ] {
            let p = ProbeUrl::parse(url).unwrap();
            assert_eq!(
                (
                    p.host.as_str(),
                    p.port,
                    p.authority.as_str(),
                    p.path.as_str()
                ),
                (host, port, authority, path)
            );
        }
        for url in [
            "ftp://site/",
            "http:///x",
            "http://[::1]junk/",
            "http://::1/",
            "http://site:bad/",
            "http://site:65536/",
        ] {
            assert!(ProbeUrl::parse(url).is_none(), "{url}");
        }
    }
}
