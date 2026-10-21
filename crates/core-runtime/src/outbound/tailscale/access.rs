//! Fail-closed evaluation of network grants for the LuCI TCP bridge.
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Rule {
    #[serde(rename = "SrcIPs", default)]
    pub sources: Vec<String>,
    #[serde(rename = "DstPorts", default)]
    pub destinations: Vec<Destination>,
    #[serde(rename = "IPProto", default)]
    pub protocols: Vec<u16>,
    #[serde(rename = "SrcBits", default)]
    pub source_bits: Vec<u8>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Destination {
    #[serde(rename = "IP")]
    pub ip: String,
    #[serde(rename = "Ports")]
    pub ports: Ports,
    #[serde(rename = "Bits", default)]
    pub bits: Option<u8>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Ports {
    #[serde(rename = "First")]
    pub first: u16,
    #[serde(rename = "Last")]
    pub last: u16,
}

fn matches(pattern: &str, ip: IpAddr, bits: Option<u8>) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some((start, end)) = pattern.split_once('-') {
        return match (start.parse::<IpAddr>(), end.parse::<IpAddr>(), ip) {
            (Ok(IpAddr::V4(a)), Ok(IpAddr::V4(b)), IpAddr::V4(ip)) => a <= ip && ip <= b,
            (Ok(IpAddr::V6(a)), Ok(IpAddr::V6(b)), IpAddr::V6(ip)) => a <= ip && ip <= b,
            _ => false,
        };
    }
    let (address, prefix) = if let Some((address, prefix)) = pattern.split_once('/') {
        let Ok(prefix) = prefix.parse::<u8>() else {
            return false;
        };
        (address, Some(prefix))
    } else {
        (pattern, bits)
    };
    let Ok(address) = address.parse::<IpAddr>() else {
        return false;
    };
    match (address, ip) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            let n = prefix.unwrap_or(32);
            n <= 32 && (n == 0 || u32::from(a) >> (32 - n) == u32::from(b) >> (32 - n))
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            let n = prefix.unwrap_or(128);
            n <= 128 && (n == 0 || u128::from(a) >> (128 - n) == u128::from(b) >> (128 - n))
        }
        _ => false,
    }
}

pub fn allows(rules: &[Rule], source: IpAddr, destination: IpAddr, port: u16) -> bool {
    allows_protocol(rules, source, destination, port, 6)
}

/// Tailscale PeerAPI's Internet-access probe, not permission to an arbitrary
/// public DNS server. See ipn/ipnlocal/peerapi.go replyToDNSQueries.
pub fn allows_exit_dns(rules: &[Rule], source: IpAddr) -> bool {
    let probe = if source.is_ipv4() {
        "0.0.0.0"
    } else {
        "2000::"
    };
    allows_protocol(rules, source, probe.parse().unwrap(), 53, 6)
}
pub fn allows_protocol(
    rules: &[Rule],
    source: IpAddr,
    destination: IpAddr,
    port: u16,
    protocol: u16,
) -> bool {
    rules.iter().any(|r| {
        (if r.protocols.is_empty() {
            matches!(protocol, 1 | 6 | 17 | 58)
        } else {
            r.protocols.contains(&protocol)
        }) && r
            .sources
            .iter()
            .enumerate()
            .any(|(i, p)| matches(p, source, r.source_bits.get(i).copied()))
            && r.destinations.iter().any(|d| {
                matches(&d.ip, destination, d.bits) && d.ports.first <= port && port <= d.ports.last
            })
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn exit_dns_requires_internet_grant_in_the_peers_address_family() {
        let src = "100.64.1.2".parse().unwrap();
        let limited: Vec<Rule> = serde_json::from_value(serde_json::json!([{"SrcIPs":["*"],"DstPorts":[{"IP":"1.1.1.1","Ports":{"First":53,"Last":53}}]}])).unwrap();
        assert!(!allows_exit_dns(&limited, src));
        let internet: Vec<Rule> = serde_json::from_value(serde_json::json!([{"SrcIPs":["*"],"DstPorts":[{"IP":"0.0.0.0/0","Ports":{"First":0,"Last":65535}},{"IP":"2000::/3","Ports":{"First":0,"Last":65535}}]}])).unwrap();
        assert!(allows_exit_dns(&internet, src));
        assert!(allows_exit_dns(
            &internet,
            "fd7a:115c:a1e0::2".parse().unwrap()
        ));
        assert!(!allows_exit_dns(&[], src));
    }
    #[test]
    fn restrictive_web_grant() {
        let rules: Vec<Rule> = serde_json::from_value(serde_json::json!([{"SrcIPs":["100.64.0.0/10"],"IPProto":[6],"DstPorts":[{"IP":"*","Ports":{"First":443,"Last":443}}]}])).unwrap();
        let src = "100.64.1.1".parse().unwrap();
        let dst = "100.64.1.2".parse().unwrap();
        assert!(allows(&rules, src, dst, 443));
        assert!(!allows(&rules, src, dst, 22));
        assert!(!allows(&[], src, dst, 443));
        assert!(!allows(&rules, "192.168.1.1".parse().unwrap(), dst, 443));
    }
    #[test]
    fn invalid_and_capability_patterns_fail_closed() {
        let ip = "100.64.1.1".parse().unwrap();
        assert!(!matches("100.64.1.1/bad", ip, None));
        assert!(!matches("cap:example", ip, None));
        assert!(!matches("100.64.0.0/33", ip, None));
        assert!(matches("100.64.1.0-100.64.1.255", ip, None));
    }
}
