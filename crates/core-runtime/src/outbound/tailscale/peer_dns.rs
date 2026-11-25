//! Bounded DNS-only PeerAPI, carried by the authenticated userspace mesh.
//! No TCP listener is opened on LAN/WAN; queries use the router's local DNS.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hickory_proto::op::{Message, MessageType, OpCode};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    io,
    net::IpAddr,
    sync::{Arc, RwLock},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::mpsc,
};

pub const PORT: u16 = 41643;
const MAX_QUERY: usize = 4096;
const MAX_HEADER: usize = 8192;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    #[serde(rename = "Proxied", default)]
    proxied: bool,
    #[serde(rename = "Domains", default)]
    domains: Option<Vec<String>>,
    #[serde(rename = "ExtraRecords", default)]
    extra_records: Option<Vec<ExtraRecord>>,
    #[serde(rename = "ExitNodeFilteredSet", default)]
    exit_node_filtered_set: Option<Vec<String>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ExtraRecord {
    name: String,
    #[serde(rename = "Type", default)]
    record_type: String,
    value: String,
}

#[derive(Default)]
pub(crate) struct DnsState {
    hosts: HashMap<String, Vec<IpAddr>>,
    search_domains: Vec<String>,
    filtered_names: Vec<String>,
}

impl DnsState {
    pub(crate) fn from_netmap<'a>(
        config: Option<&DnsConfig>,
        local: Option<&super::control::NodeObj>,
        peers: impl IntoIterator<Item = &'a super::control::PeerObj>,
    ) -> Self {
        let mut state = Self {
            filtered_names: config
                .and_then(|cfg| cfg.exit_node_filtered_set.as_deref())
                .unwrap_or_default()
                .iter()
                .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
                .filter(|name| !name.is_empty())
                .collect(),
            ..Default::default()
        };
        let Some(local) = local else {
            return state;
        };
        let want_aaaa = local.cap_map.contains_key("magicdns-aaaa")
            || local.capabilities.iter().any(|cap| cap == "magicdns-aaaa");
        let is_v6_only = {
            let addresses = addresses_from_prefixes(&local.addresses);
            !addresses.is_empty() && addresses.iter().all(IpAddr::is_ipv6)
        };
        let domain = config
            .filter(|cfg| cfg.proxied)
            .and(local.name.as_deref())
            .map(canonical_name)
            .and_then(|name| name.split_once('.').map(|(_, domain)| domain.to_owned()));
        state.search_domains.extend(domain.clone());
        if let Some(cfg) = config {
            state.search_domains.extend(
                cfg.domains
                    .iter()
                    .flatten()
                    .map(|name| canonical_name(name))
                    .filter(|name| !name.is_empty()),
            );
        }
        let mut add_host = |name: Option<&str>, prefixes: &[String]| {
            let Some(name) = name.map(canonical_name).filter(|name| !name.is_empty()) else {
                return;
            };
            let mut addresses = addresses_from_prefixes(prefixes);
            if addresses.is_empty() {
                return;
            }
            if is_v6_only {
                addresses.retain(IpAddr::is_ipv6);
            } else if !want_aaaa && addresses.iter().any(IpAddr::is_ipv4) {
                addresses.retain(IpAddr::is_ipv4);
            } else {
                addresses.sort_by_key(IpAddr::is_ipv6);
            }
            if let Some((first, _)) = name
                .split_once('.')
                .filter(|(_, suffix)| domain.as_deref() == Some(*suffix))
            {
                state.hosts.insert(first.to_owned(), addresses.clone());
            }
            state.hosts.insert(name, addresses);
        };
        for peer in peers {
            add_host(peer.name.as_deref(), &peer.addresses);
        }
        add_host(local.name.as_deref(), &local.addresses);
        if let Some(cfg) = config {
            let mut extra = HashMap::<String, Vec<IpAddr>>::new();
            for record in cfg.extra_records.iter().flatten() {
                if matches!(record.record_type.as_str(), "" | "A" | "AAAA")
                    && let Ok(address) = record.value.parse::<IpAddr>()
                {
                    let name = canonical_name(&record.name);
                    if !name.is_empty() && hickory_proto::rr::Name::from_ascii(&name).is_ok() {
                        extra.entry(name).or_default().push(address);
                    }
                }
            }
            state.hosts.extend(extra);
        }
        state
    }

    /// None means the name is outside the embedded MagicDNS host table.
    pub(crate) fn lookup(&self, name: &str) -> Option<&[IpAddr]> {
        self.lookup_with_search(name, false)
    }

    pub(crate) fn lookup_with_search(&self, name: &str, search: bool) -> Option<&[IpAddr]> {
        let name = canonical_name(name);
        if search && !name.contains('.') {
            for domain in &self.search_domains {
                if let Some(ips) = self.hosts.get(&format!("{name}.{domain}")) {
                    return Some(ips);
                }
            }
        }
        self.hosts.get(&name).map(Vec::as_slice)
    }

    pub(crate) fn exchange(
        &self,
        query: &Message,
        name: &str,
        search: bool,
        ttl: u32,
    ) -> io::Result<Vec<u8>> {
        match self.lookup_with_search(name, search) {
            Some(ips) => crate::dns::codec::synth_addresses(query, ips, ttl),
            None => crate::dns::codec::name_error(query),
        }
    }

    fn permits_exit_lookup(&self, name: &str) -> bool {
        let name = canonical_name(name);
        !self.filtered_names.iter().any(|entry| {
            if entry.starts_with('.') {
                name.len() > entry.len() && name.ends_with(entry)
            } else {
                name == *entry
            }
        })
    }
}

fn canonical_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn addresses_from_prefixes(prefixes: &[String]) -> Vec<IpAddr> {
    prefixes
        .iter()
        .filter_map(|prefix| prefix.parse::<smoltcp::wire::IpCidr>().ok())
        .map(|prefix| prefix.address().into())
        .collect()
}

struct Request {
    wire: Vec<u8>,
    message: Message,
}

fn parse_request(bytes: &[u8]) -> io::Result<Option<Request>> {
    let bad = || io::Error::new(io::ErrorKind::InvalidData, "invalid DNS request");
    let Some(end) = bytes.windows(4).position(|b| b == b"\r\n\r\n") else {
        return if bytes.len() > MAX_HEADER {
            Err(bad())
        } else {
            Ok(None)
        };
    };
    if end > MAX_HEADER {
        return Err(bad());
    }
    let header = std::str::from_utf8(&bytes[..end]).map_err(|_| bad())?;
    let mut lines = header.split("\r\n");
    let request: Vec<_> = lines
        .next()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    if request.len() != 3 || !matches!(request[2], "HTTP/1.0" | "HTTP/1.1") {
        return Err(bad());
    }
    let mut length = None;
    let mut dns_type = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or_else(bad)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(bad());
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(bad());
            }
            length = Some(value.trim().parse::<usize>().map_err(|_| bad())?);
        }
        if name.eq_ignore_ascii_case("content-type") {
            dns_type = value.trim().eq_ignore_ascii_case("application/dns-message");
        }
    }
    let query = match request[0] {
        "GET" => {
            let encoded = request[1].strip_prefix("/dns-query?dns=").ok_or_else(bad)?;
            if encoded.len() > MAX_QUERY * 2 {
                return Err(bad());
            }
            URL_SAFE_NO_PAD
                .decode(encoded.trim_end_matches('='))
                .map_err(|_| bad())?
        }
        "POST" if request[1] == "/dns-query" && dns_type => {
            let length = length.filter(|n| *n <= MAX_QUERY).ok_or_else(bad)?;
            if bytes.len() < end + 4 + length {
                return Ok(None);
            }
            bytes[end + 4..end + 4 + length].to_vec()
        }
        _ => return Err(bad()),
    };
    if query.len() < 12 || query.len() > MAX_QUERY {
        return Err(bad());
    }
    let message = Message::from_vec(&query).map_err(|_| bad())?;
    if message.message_type != MessageType::Query
        || message.op_code != OpCode::Query
        || message.queries.len() != 1
    {
        return Err(bad());
    }
    Ok(Some(Request {
        wire: query,
        message,
    }))
}

async fn resolve(query: &[u8], resolver: std::net::SocketAddr) -> io::Result<Vec<u8>> {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(resolver).await?;
    socket.send(query).await?;
    let mut reply = vec![0; 65535];
    let n = socket.recv(&mut reply).await?;
    reply.truncate(n);
    if reply.len() < 12 || reply[..2] != query[..2] || reply[2] & 0x80 == 0 {
        return Err(io::Error::other("invalid local DNS response"));
    }
    if reply[2] & 2 != 0 {
        let mut tcp = tokio::net::TcpStream::connect(resolver).await?;
        tcp.write_u16(query.len() as u16).await?;
        tcp.write_all(query).await?;
        let n = tcp.read_u16().await? as usize;
        reply.resize(n, 0);
        tcp.read_exact(&mut reply).await?;
        if reply.len() < 12 || reply[..2] != query[..2] || reply[2] & 0x80 == 0 {
            return Err(io::Error::other("invalid local DNS response"));
        }
    }
    Ok(reply)
}

pub(crate) async fn serve(
    mut input: mpsc::Receiver<Vec<u8>>,
    output: mpsc::Sender<Vec<u8>>,
    dns: Arc<RwLock<DnsState>>,
) {
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        let mut bytes = vec![];
        while let Some(chunk) = input.recv().await {
            if bytes.len() + chunk.len() > MAX_HEADER + 4 + MAX_QUERY {
                return Err(io::Error::other("request too large"));
            }
            bytes.extend_from_slice(&chunk);
            if let Some(request) = parse_request(&bytes)? {
                let name = request.message.queries[0].name().to_ascii();
                if !dns.read().unwrap().permits_exit_lookup(&name) {
                    return crate::dns::codec::refused_response(&request.message);
                }
                return resolve(&request.wire, "127.0.0.1:53".parse().unwrap()).await;
            }
        }
        Err(io::Error::other("incomplete request"))
    })
    .await;
    let (status, body) = match result {
        Ok(Ok(body)) => ("200 OK", body),
        Ok(Err(_)) => ("400 Bad Request", vec![]),
        Err(_) => ("504 Gateway Timeout", vec![]),
    };
    let mut response = format!("HTTP/1.1 {status}\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
    response.extend(body);
    let _ = output.send(response).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query() -> Vec<u8> {
        vec![
            0x12, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            3, b'c', b'o', b'm', 0, 0, 1, 0, 1,
        ]
    }

    #[test]
    fn magic_dns_follows_the_self_aaaa_capability_and_address_families() {
        let config: DnsConfig =
            serde_json::from_value(serde_json::json!({"Proxied": true})).unwrap();
        let local = |addresses: &[&str], aaaa: bool| -> super::super::control::NodeObj {
            let caps = if aaaa {
                serde_json::json!({"magicdns-aaaa": []})
            } else {
                serde_json::Value::Null
            };
            serde_json::from_value(serde_json::json!({
                "ID": 1, "Key": "nodekey:local", "Name": "local.test.ts.net.",
                "Addresses": addresses, "CapMap": caps,
            }))
            .unwrap()
        };
        let peer: super::super::control::PeerObj = serde_json::from_value(serde_json::json!({
            "ID": 2, "Key": "nodekey:peer", "Name": "peer.test.ts.net.",
            "Addresses": ["100.64.0.2/32", "fd7a:115c:a1e0::2/128"],
        }))
        .unwrap();
        let other: super::super::control::PeerObj = serde_json::from_value(serde_json::json!({
            "ID": 3, "Key": "nodekey:other", "Name": "other.alien.ts.net.",
            "Addresses": ["fd7a:115c:a1e0::3/128"],
        }))
        .unwrap();
        let ipv4: IpAddr = "100.64.0.2".parse().unwrap();
        let ipv6: IpAddr = "fd7a:115c:a1e0::2".parse().unwrap();
        let for_node = |local| DnsState::from_netmap(Some(&config), Some(&local), [&peer, &other]);
        let dual = ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"];
        let dns = for_node(local(&dual, false));
        assert_eq!(dns.lookup("PEER.Test.TS.NET."), Some([ipv4].as_slice()));
        assert_eq!(dns.lookup("peer"), Some([ipv4].as_slice()));
        assert!(dns.lookup("other").is_none());
        assert_eq!(
            dns.lookup("other.alien.ts.net").unwrap()[0].to_string(),
            "fd7a:115c:a1e0::3"
        );
        assert_eq!(
            for_node(local(&dual, true)).lookup("peer"),
            Some([ipv4, ipv6].as_slice())
        );
        assert_eq!(
            for_node(local(&dual[1..], false)).lookup("peer"),
            Some([ipv6].as_slice())
        );

        let local = local(&dual, false);
        let unproxied = DnsState::from_netmap(None, Some(&local), [&peer]);
        assert_eq!(
            unproxied.lookup("peer.test.ts.net"),
            Some([ipv4].as_slice())
        );
        assert!(unproxied.lookup("peer").is_none());

        let raw = crate::dns::codec::build_query(
            12,
            "peer.test.ts.net",
            hickory_proto::rr::RecordType::AAAA,
        )
        .unwrap();
        let (query, info) = crate::dns::codec::parse_query(&raw).unwrap();
        let no_aaaa = dns.exchange(&query, &info.name, false, 30).unwrap();
        assert!(crate::dns::codec::answer_ips(&no_aaaa).unwrap().is_empty());
        let aaaa = for_node(local_with_aaaa(&local))
            .exchange(&query, &info.name, false, 30)
            .unwrap();
        assert_eq!(crate::dns::codec::answer_ips(&aaaa).unwrap(), vec![ipv6]);
    }

    fn local_with_aaaa(local: &super::super::control::NodeObj) -> super::super::control::NodeObj {
        let mut local = local.clone();
        local.capabilities.push("magicdns-aaaa".into());
        local
    }

    #[test]
    fn magic_dns_wire_serves_extra_address_records_and_search_domains() {
        let config: DnsConfig = serde_json::from_value(serde_json::json!({
            "Domains": ["search.example"],
            "ExtraRecords": [
                {"Name":"test.search.example.","Type":"AAAA","Value":"192.0.2.3"},
                {"Name":"test.search.example.","Type":"A","Value":"2001:db8::3"},
                {"Name":"ignored.search.example.","Type":"TXT","Value":"192.0.2.4"}
            ],
        }))
        .unwrap();
        let local: super::super::control::NodeObj =
            serde_json::from_value(serde_json::json!({"ID":1,"Key":"nodekey:test"})).unwrap();
        let dns = DnsState::from_netmap(Some(&config), Some(&local), []);
        let raw =
            crate::dns::codec::build_query(20, "test", hickory_proto::rr::RecordType::A).unwrap();
        let (query, info) = crate::dns::codec::parse_query(&raw).unwrap();
        let reply = dns.exchange(&query, &info.name, false, 30).unwrap();
        let response = Message::from_vec(&reply).unwrap();
        assert_eq!(
            response.metadata.response_code,
            hickory_proto::op::ResponseCode::NXDomain
        );
        let reply = dns.exchange(&query, &info.name, true, 30).unwrap();
        assert_eq!(
            crate::dns::codec::answer_ips(&reply).unwrap(),
            ["192.0.2.3".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(dns.lookup_with_search("test", true).unwrap().len(), 2);
        assert!(dns.lookup_with_search("ignored", true).is_none());
    }

    #[tokio::test]
    async fn refused_names_receive_a_dns_response_without_local_resolution() {
        let config: DnsConfig = serde_json::from_value(serde_json::json!({
            "ExitNodeFilteredSet": ["example.com", ".private.example", ""],
        }))
        .unwrap();
        let dns = DnsState::from_netmap(Some(&config), None, []);
        assert!(!dns.permits_exit_lookup("ExAmPlE.Com."));
        assert!(!dns.permits_exit_lookup("child.PRIVATE.Example."));
        assert!(dns.permits_exit_lookup("some.example.com"));
        assert!(dns.permits_exit_lookup("private.example"));
        assert!(dns.permits_exit_lookup("notprivate.example"));

        let (tx, rx) = mpsc::channel(1);
        let (reply, mut responses) = mpsc::channel(1);
        let request = format!(
            "GET /dns-query?dns={} HTTP/1.1\r\nHost: peer\r\n\r\n",
            URL_SAFE_NO_PAD.encode(query())
        );
        tx.send(request.into_bytes()).await.unwrap();
        let server = tokio::spawn(serve(rx, reply, Arc::new(RwLock::new(dns))));
        let response = tokio::time::timeout(Duration::from_secs(1), responses.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
        let body = response
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .unwrap()
            + 4;
        let message = Message::from_vec(&response[body..]).unwrap();
        assert_eq!(message.metadata.id, 0x1234);
        assert_eq!(
            message.metadata.response_code,
            hickory_proto::op::ResponseCode::Refused
        );
        assert!(message.answers.is_empty());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn local_dns_udp_and_truncated_tcp_fallback() {
        for truncated in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let udp = tokio::net::UdpSocket::bind(addr).await.unwrap();
            let q = query();
            let expected = q.clone();
            let server = tokio::spawn(async move {
                let mut packet = vec![0; 4096];
                let (n, peer) = udp.recv_from(&mut packet).await.unwrap();
                assert_eq!(&packet[..n], &expected);
                packet.truncate(n);
                packet[2] |= 0x80;
                if truncated {
                    packet[2] |= 2;
                }
                udp.send_to(&packet, peer).await.unwrap();
                if truncated {
                    let (mut stream, _) = listener.accept().await.unwrap();
                    let n = stream.read_u16().await.unwrap() as usize;
                    let mut request = vec![0; n];
                    stream.read_exact(&mut request).await.unwrap();
                    assert_eq!(request, expected);
                    packet[2] &= !2;
                    stream.write_u16(packet.len() as u16).await.unwrap();
                    stream.write_all(&packet).await.unwrap();
                }
            });
            let response = tokio::time::timeout(Duration::from_secs(2), resolve(&q, addr))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&response[..2], &q[..2]);
            assert_eq!(response[2] & 0x82, 0x80);
            server.await.unwrap();
        }
    }
    #[test]
    fn dns_only_http_get_post_and_partial_requests() {
        let q = query();
        let get = format!(
            "GET /dns-query?dns={} HTTP/1.1\r\nHost: peer\r\n\r\n",
            URL_SAFE_NO_PAD.encode(&q)
        );
        assert_eq!(parse_request(get.as_bytes()).unwrap().unwrap().wire, q);
        let mut post = format!("POST /dns-query HTTP/1.1\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n", q.len()).into_bytes();
        assert!(parse_request(&post).unwrap().is_none());
        post.extend(&q);
        assert_eq!(parse_request(&post).unwrap().unwrap().wire, q);
        for bad in [
            "GET / HTTP/1.1\r\n\r\n",
            "POST /dns-query HTTP/1.1\r\nContent-Length: 99999\r\n\r\n",
            "GET /dns-query?dns=AAAA HTTP/1.1\r\n\r\n",
        ] {
            assert!(parse_request(bad.as_bytes()).is_err());
        }
        assert!(parse_request(&vec![b'a'; MAX_HEADER + 1]).is_err());
    }
}
