//! DNS wire message helpers on top of `hickory-proto`: query parsing/building,
//! refused/synthetic responses, TTL rewriting and answer extraction.

use std::io;
use std::net::IpAddr;
use std::str::FromStr;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{RData, Record, RecordType};

pub const DEFAULT_TTL: u32 = 600;

/// Identity of the first question in a query message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryInfo {
    pub id: u16,
    /// Lowercased name without the trailing dot.
    pub name: String,
    pub qtype: RecordType,
}

pub fn parse_query(raw: &[u8]) -> io::Result<(Message, QueryInfo)> {
    let msg =
        Message::from_vec(raw).map_err(|e| io::Error::other(format!("dns: decode query: {e}")))?;
    if msg.metadata.message_type != MessageType::Query {
        return Err(io::Error::other("dns: expected a query message"));
    }
    let q = msg
        .queries
        .first()
        .ok_or_else(|| io::Error::other("dns: query has no question"))?;
    let info = QueryInfo {
        id: msg.metadata.id,
        name: normalize_name(&q.name().to_string()),
        qtype: q.query_type(),
    };
    Ok((msg, info))
}

/// One `option.DNSRecordOptions` entry. The reference unmarshals the JSON
/// into a `dns.RR`; the rdata union used by `predefined` answers is `A`,
/// `AAAA`, `CNAME`, `TXT` and `MX`, plus the base64 wire form a marshalled
/// config carries.
pub fn decode_record(record: &serde_json::Value, at: &str) -> io::Result<Record> {
    if let Some(raw) = record.as_str() {
        let wire = super::rules::base64_decode(raw)
            .map_err(|error| io::Error::other(format!("{at}: {error}")))?;
        return record_from_wire(&wire, at);
    }
    let object = record
        .as_object()
        .ok_or_else(|| io::Error::other(format!("{at}: must be an object or base64 string")))?;
    let ttl = object
        .get("ttl")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(600) as u32;
    let name = match object.get("name").and_then(serde_json::Value::as_str) {
        Some(name) => hickory_proto::rr::Name::from_str(&format!("{name}."))
            .map_err(|e| io::Error::other(format!("{at}: bad name: {e}")))?,
        None => hickory_proto::rr::Name::root(),
    };
    let rdata = match object.get("value") {
        Some(serde_json::Value::String(text)) => match IpAddr::from_str(text) {
            Ok(IpAddr::V4(addr)) => RData::A(A(addr)),
            Ok(IpAddr::V6(addr)) => RData::AAAA(AAAA(addr)),
            Err(_) => RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![text.to_string()])),
        },
        Some(value @ serde_json::Value::Object(_)) => record_rdata(value, at)?,
        _ => {
            return Err(io::Error::other(format!(
                "{at}: value must be a string or a typed record object"
            )));
        }
    };
    Ok(Record::from_rdata(name, ttl, rdata))
}

fn record_rdata(value: &serde_json::Value, at: &str) -> io::Result<RData> {
    let rtype = value
        .get("type")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| io::Error::other(format!("{at}: value is missing type")))?;
    match rtype {
        "A" | "AAAA" => {
            let ip = value
                .get("ip")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing ip")))?;
            match IpAddr::from_str(ip)
                .map_err(|e| io::Error::other(format!("{at}: bad ip {ip:?}: {e}")))?
            {
                IpAddr::V4(addr) => Ok(RData::A(A(addr))),
                IpAddr::V6(addr) => Ok(RData::AAAA(AAAA(addr))),
            }
        }
        "CNAME" => {
            let target = value
                .get("domain")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing domain")))?;
            Ok(RData::CNAME(hickory_proto::rr::rdata::CNAME(
                hickory_proto::rr::Name::from_str(&format!("{target}."))
                    .map_err(|e| io::Error::other(format!("{at}: bad domain: {e}")))?,
            )))
        }
        "TXT" => {
            let text = value
                .get("text")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing text")))?;
            Ok(RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![
                text.to_string(),
            ])))
        }
        "MX" => {
            let preference = value
                .get("preference")
                .and_then(|value| value.as_u64().and_then(|v| u16::try_from(v).ok()))
                .ok_or_else(|| io::Error::other(format!("{at}: missing preference")))?;
            let exchange = value
                .get("domain")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| io::Error::other(format!("{at}: missing domain")))?;
            Ok(RData::MX(hickory_proto::rr::rdata::MX::new(
                preference,
                hickory_proto::rr::Name::from_str(&format!("{exchange}."))
                    .map_err(|e| io::Error::other(format!("{at}: bad domain: {e}")))?,
            )))
        }
        other => Err(io::Error::other(format!(
            "{at}: unsupported record type {other:?}"
        ))),
    }
}

/// Minimal wire-format reader for the base64 form: name, type, class, ttl and
/// rdata, which is all a `Record` needs.
fn record_from_wire(wire: &[u8], at: &str) -> io::Result<Record> {
    let mut offset = 0usize;
    let name = read_wire_name(wire, &mut offset, at)?;
    let rtype = read_u16(wire, &mut offset, at)?;
    let _class = read_u16(wire, &mut offset, at)?;
    let ttl = read_u32(wire, &mut offset, at)?;
    let rdlength = read_u16(wire, &mut offset, at)? as usize;
    let rdata = wire
        .get(offset..offset + rdlength)
        .ok_or_else(|| io::Error::other(format!("{at}: truncated rdata")))?;
    let rdata = match RecordType::from(rtype) {
        RecordType::A => {
            let bytes: [u8; 4] = rdata
                .try_into()
                .map_err(|_| io::Error::other(format!("{at}: bad A rdata")))?;
            RData::A(A(std::net::Ipv4Addr::from(bytes)))
        }
        RecordType::AAAA => {
            let bytes: [u8; 16] = rdata
                .try_into()
                .map_err(|_| io::Error::other(format!("{at}: bad AAAA rdata")))?;
            RData::AAAA(AAAA(std::net::Ipv6Addr::from(bytes)))
        }
        RecordType::TXT => {
            let mut text = String::new();
            let mut rest = rdata;
            while let Some((&len, tail)) = rest.split_first() {
                let len = len as usize;
                let chunk = tail
                    .get(..len)
                    .ok_or_else(|| io::Error::other(format!("{at}: bad TXT rdata")))?;
                text.push_str(&String::from_utf8_lossy(chunk));
                rest = &tail[len..];
            }
            RData::TXT(hickory_proto::rr::rdata::TXT::new(vec![text]))
        }
        RecordType::CNAME => {
            let mut inner = 0usize;
            RData::CNAME(hickory_proto::rr::rdata::CNAME(read_wire_name(
                rdata, &mut inner, at,
            )?))
        }
        other => {
            return Err(io::Error::other(format!(
                "{at}: unsupported record type {other:?}"
            )));
        }
    };
    Ok(Record::from_rdata(name, ttl, rdata))
}

fn read_wire_name(
    wire: &[u8],
    offset: &mut usize,
    at: &str,
) -> io::Result<hickory_proto::rr::Name> {
    let mut labels: Vec<String> = Vec::new();
    loop {
        let len = *wire
            .get(*offset)
            .ok_or_else(|| io::Error::other(format!("{at}: truncated name")))?
            as usize;
        *offset += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return Err(io::Error::other(format!("{at}: bad label length")));
        }
        let end = *offset + len;
        let label = wire
            .get(*offset..end)
            .ok_or_else(|| io::Error::other(format!("{at}: truncated label")))?;
        labels.push(String::from_utf8_lossy(label).to_string());
        *offset = end;
    }
    hickory_proto::rr::Name::from_labels(labels)
        .map_err(|e| io::Error::other(format!("{at}: bad name: {e}")))
}

fn read_u16(wire: &[u8], offset: &mut usize, at: &str) -> io::Result<u16> {
    let bytes = wire
        .get(*offset..*offset + 2)
        .ok_or_else(|| io::Error::other(format!("{at}: truncated record")))?;
    *offset += 2;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_u32(wire: &[u8], offset: &mut usize, at: &str) -> io::Result<u32> {
    let bytes = wire
        .get(*offset..*offset + 4)
        .ok_or_else(|| io::Error::other(format!("{at}: truncated record")))?;
    *offset += 4;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub fn parse_message(raw: &[u8]) -> io::Result<Message> {
    Message::from_vec(raw).map_err(|e| io::Error::other(format!("dns: decode message: {e}")))
}

pub fn normalize_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

pub fn build_query(id: u16, name: &str, qtype: RecordType) -> io::Result<Vec<u8>> {
    let name = hickory_proto::rr::Name::from_str(&format!("{name}."))
        .map_err(|e| io::Error::other(format!("dns: bad name {name:?}: {e}")))?;
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    msg.add_query(hickory_proto::op::Query::query(name, qtype));
    msg.to_vec()
        .map_err(|e| io::Error::other(format!("dns: encode query: {e}")))
}

fn response_skeleton(query: &Message, rcode: ResponseCode) -> Message {
    let mut resp = Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
    resp.metadata.response_code = rcode;
    resp.metadata.recursion_desired = query.metadata.recursion_desired;
    resp.metadata.recursion_available = true;
    resp.queries = query.queries.clone();
    resp
}

fn encode(msg: &Message) -> io::Result<Vec<u8>> {
    msg.to_vec()
        .map_err(|e| io::Error::other(format!("dns: encode response: {e}")))
}

/// REFUSED reply echoing the question (reject action, default method).
pub fn refused_response(query: &Message) -> io::Result<Vec<u8>> {
    encode(&response_skeleton(query, ResponseCode::Refused))
}

/// NOERROR with an empty answer section (fakeip family not configured).
pub fn empty_success(query: &Message) -> io::Result<Vec<u8>> {
    encode(&response_skeleton(query, ResponseCode::NoError))
}

/// Synthesize an A/AAAA answer for fakeip.
pub fn synth_address(query: &Message, addr: IpAddr, ttl: u32) -> io::Result<Vec<u8>> {
    let Some(q) = query.queries.first() else {
        return Err(io::Error::other("dns: query has no question"));
    };
    let mut resp = response_skeleton(query, ResponseCode::NoError);
    let rdata = match addr {
        IpAddr::V4(ip) => RData::A(A(ip)),
        IpAddr::V6(ip) => RData::AAAA(AAAA(ip)),
    };
    resp.answers
        .push(Record::from_rdata(q.name().clone(), ttl, rdata));
    encode(&resp)
}

/// Synthesize an A/AAAA answer carrying every address of `addrs`, which is
/// what the `hosts` and `local` server types answer with.
pub fn synth_addresses(query: &Message, addrs: &[IpAddr], ttl: u32) -> io::Result<Vec<u8>> {
    let Some(q) = query.queries.first() else {
        return Err(io::Error::other("dns: query has no question"));
    };
    // dns.FixedResponse only answers with the family the question asked for
    let v4 = matches!(q.query_type(), RecordType::A);
    let v6 = matches!(q.query_type(), RecordType::AAAA);
    if !v4 && !v6 {
        return encode(&response_skeleton(query, ResponseCode::NoError));
    }
    let mut resp = response_skeleton(query, ResponseCode::NoError);
    for addr in addrs {
        let rdata = match *addr {
            IpAddr::V4(ip) if v4 => RData::A(A(ip)),
            IpAddr::V6(ip) if v6 => RData::AAAA(AAAA(ip)),
            _ => continue,
        };
        resp.answers
            .push(Record::from_rdata(q.name().clone(), ttl, rdata));
    }
    encode(&resp)
}

/// NXDOMAIN, which is what the `hosts` transport answers for a name it does
/// not know.
pub fn name_error(query: &Message) -> io::Result<Vec<u8>> {
    encode(&response_skeleton(query, ResponseCode::NXDomain))
}

/// `action: predefined` — a synthesized answer from the configured records.
pub fn predefined_response(
    query: &Message,
    predefined: &super::rules::PredefinedResponse,
) -> io::Result<Vec<u8>> {
    let rcode = predefined
        .rcode
        .map(|value| ResponseCode::from(value & 0x0f, 0))
        .unwrap_or(ResponseCode::NoError);
    let mut resp = response_skeleton(query, rcode);
    let mut append = |records: &[Record], section: u8| {
        for record in records {
            match section {
                0 => resp.answers.push(record.clone()),
                1 => resp.authorities.push(record.clone()),
                _ => resp.additionals.push(record.clone()),
            }
        }
    };
    append(&predefined.answer, 0);
    append(&predefined.ns, 1);
    append(&predefined.extra, 2);
    encode(&resp)
}

/// Set every answer TTL (rewrite_ttl rule action); returns re-encoded bytes.
pub fn rewrite_ttl(raw: &[u8], ttl: u32) -> io::Result<Vec<u8>> {
    let mut msg = parse_message(raw)?;
    for record in &mut msg.answers {
        record.ttl = ttl;
    }
    encode(&msg)
}

/// Set the caller ID and cap record lifetimes in a single encode. A cached
/// negative response communicates its remaining lifetime in the authority SOA.
pub fn cached_answer(raw: &[u8], remaining: u32, id: u16) -> io::Result<Vec<u8>> {
    let mut msg = parse_message(raw)?;
    msg.metadata.id = id;
    for record in msg
        .answers
        .iter_mut()
        .chain(&mut msg.authorities)
        .chain(&mut msg.additionals)
    {
        record.ttl = record.ttl.min(remaining);
    }
    encode(&msg)
}

/// All A/AAAA addresses in the answer section.
pub fn answer_ips(raw: &[u8]) -> io::Result<Vec<IpAddr>> {
    let msg = parse_message(raw)?;
    let mut out = Vec::new();
    for record in &msg.answers {
        match &record.data {
            RData::A(a) => out.push(IpAddr::V4(a.0)),
            RData::AAAA(a) => out.push(IpAddr::V6(a.0)),
            _ => {}
        }
    }
    Ok(out)
}

/// Response header metadata used for caching decisions.
#[derive(Debug, Clone, Copy)]
pub struct ResponseMeta {
    pub rcode: ResponseCode,
    /// Negative responses require an authority SOA (RFC 2308).
    pub cache_ttl: Option<u32>,
}

pub fn response_meta(raw: &[u8]) -> io::Result<ResponseMeta> {
    let msg = parse_message(raw)?;
    // We cache the complete wire response. Expire it when any included RR
    // expires, so a short-lived glue record cannot be renewed on cache hits.
    let packet_ttl = msg
        .answers
        .iter()
        .chain(&msg.authorities)
        .chain(&msg.additionals)
        .map(|record| record.ttl)
        .min();
    let soa_ttl = msg
        .authorities
        .iter()
        .filter_map(|record| match &record.data {
            RData::SOA(soa) => Some(record.ttl.min(soa.minimum)),
            _ => None,
        })
        .min();
    // A CNAME chain may terminate in NXDOMAIN or NODATA. Retain the minimum
    // lifetime of the chain and its negative terminal answer.
    let has_requested_type = msg.queries.first().is_some_and(|query| {
        msg.answers.iter().any(|record| {
            query.query_type() == RecordType::ANY || record.data.record_type() == query.query_type()
        })
    });
    let cache_ttl = if msg.metadata.response_code == ResponseCode::NXDomain || !has_requested_type {
        soa_ttl.map(|ttl| ttl.min(packet_ttl.unwrap_or(ttl)))
    } else {
        packet_ttl
    };
    Ok(ResponseMeta {
        rcode: msg.metadata.response_code,
        cache_ttl,
    })
}

/// Rewrite the response ID to match the client query (cache hits).
///
/// The id is the first 16 bits of the wire format (hickory writes
/// `metadata.id` first), so this is a two-byte patch: parsing and
/// re-encoding the message here used to cost a full round through the
/// record vectors per hit.
pub fn set_id(raw: &[u8], id: u16) -> io::Result<Vec<u8>> {
    if raw.len() < 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns: short response",
        ));
    }
    let mut out = raw.to_vec();
    out[..2].copy_from_slice(&id.to_be_bytes());
    Ok(out)
}

/// Replace ECS while retaining the client's other EDNS options and flags.
pub fn set_client_subnet(query: &[u8], addr: IpAddr, bits: u8) -> io::Result<Vec<u8>> {
    use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
    let mut msg = parse_message(query)?;
    let options = msg
        .edns
        .get_or_insert_with(hickory_proto::op::Edns::new)
        .options_mut();
    options.remove(EdnsCode::Subnet);
    options.insert(EdnsOption::Subnet(ClientSubnet::new(addr, bits, 0)));
    encode(&msg)
}

/// Truncate only on the last UDP hop. The cache and TCP clients retain the
/// complete upstream response.
pub fn udp_answer(query: &[u8], response: Vec<u8>) -> io::Result<Vec<u8>> {
    if response.len() <= 512 {
        return Ok(response);
    }
    let limit = usize::from(parse_message(query)?.max_payload()).min(65507);
    if response.len() <= limit {
        return Ok(response);
    }
    let mut truncated = parse_message(&response)?.truncate();
    // Do not echo large options (e.g. padding) in a truncated answer.
    if let Some(edns) = &mut truncated.edns {
        edns.options_mut().options.clear();
    }
    let raw = encode(&truncated)?;
    if raw.len() <= limit {
        return Ok(raw);
    }
    truncated.queries.clear();
    encode(&truncated)
}

pub fn parse_record_type(raw: &str) -> Option<RecordType> {
    RecordType::from_str(raw).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_roundtrip() {
        let raw = build_query(0x1234, "Example.COM", RecordType::A).unwrap();
        let (msg, info) = parse_query(&raw).unwrap();
        assert_eq!(info.id, 0x1234);
        assert_eq!(info.name, "example.com");
        assert_eq!(info.qtype, RecordType::A);
        assert!(msg.metadata.recursion_desired);
    }

    #[test]
    fn synth_and_extract() {
        let raw = build_query(7, "fake.test", RecordType::A).unwrap();
        let (query, _) = parse_query(&raw).unwrap();
        let resp = synth_address(&query, "198.18.0.1".parse().unwrap(), 600).unwrap();
        let meta = response_meta(&resp).unwrap();
        assert_eq!(meta.rcode, ResponseCode::NoError);
        assert_eq!(meta.cache_ttl, Some(600));
        assert_eq!(
            answer_ips(&resp).unwrap(),
            vec!["198.18.0.1".parse::<IpAddr>().unwrap()]
        );
        let resp = set_id(&resp, 99).unwrap();
        assert_eq!(parse_message(&resp).unwrap().metadata.id, 99);
    }

    #[test]
    fn refused_echoes_question() {
        let raw = build_query(42, "blocked.test", RecordType::HTTPS).unwrap();
        let (query, info) = parse_query(&raw).unwrap();
        let resp = refused_response(&query).unwrap();
        let msg = parse_message(&resp).unwrap();
        assert_eq!(msg.metadata.id, 42);
        assert_eq!(msg.metadata.response_code, ResponseCode::Refused);
        let (_, back) = parse_query(
            // parse_query requires QR=0; inspect directly instead
            &raw,
        )
        .unwrap();
        assert_eq!(back, info);
    }

    #[test]
    fn negative_responses_expire_with_the_soa_and_age_its_ttl() {
        use hickory_proto::rr::{Name, rdata::SOA};
        let query = parse_message(&build_query(7, "missing.test", RecordType::A).unwrap()).unwrap();
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            let mut msg = parse_message(&name_error(&query).unwrap()).unwrap();
            msg.metadata.response_code = code;
            assert_eq!(
                response_meta(&encode(&msg).unwrap()).unwrap().cache_ttl,
                None
            );
            let soa = SOA::new(Name::root(), Name::root(), 1, 60, 60, 60, 5);
            msg.authorities
                .push(Record::from_rdata(Name::root(), 60, RData::SOA(soa)));
            let raw = encode(&msg).unwrap();
            assert_eq!(response_meta(&raw).unwrap().cache_ttl, Some(5));
            let hit = parse_message(&cached_answer(&raw, 2, 99).unwrap()).unwrap();
            assert_eq!(hit.metadata.id, 99);
            assert_eq!(hit.authorities[0].ttl, 2);
            msg.authorities[0].ttl = 0;
            assert_eq!(
                response_meta(&encode(&msg).unwrap()).unwrap().cache_ttl,
                Some(0)
            );
        }
    }

    #[test]
    fn udp_reply_obeys_the_query_limit_and_preserves_the_full_answer() {
        let plain = build_query(42, "large.test", RecordType::A).unwrap();
        let mut request = parse_message(&plain).unwrap();
        let ips = (1..65)
            .map(|last| IpAddr::from([192, 0, 2, last]))
            .collect::<Vec<_>>();
        let raw = synth_addresses(&request, &ips, 60).unwrap();
        assert!(raw.len() > 768 && raw.len() < 4096);
        let short = udp_answer(&plain, raw.clone()).unwrap();
        let reply = parse_message(&short).unwrap();
        assert!(short.len() <= 512 && reply.metadata.truncation);
        assert_eq!(reply.queries, request.queries);
        assert_eq!(reply.metadata.id, 42);
        request
            .edns
            .get_or_insert_with(hickory_proto::op::Edns::new)
            .set_max_payload(768);
        assert!(
            parse_message(&udp_answer(&encode(&request).unwrap(), raw.clone()).unwrap())
                .unwrap()
                .metadata
                .truncation
        );
        request.edns.as_mut().unwrap().set_max_payload(4096);
        assert_eq!(
            udp_answer(&encode(&request).unwrap(), raw.clone()).unwrap(),
            raw
        );
    }

    #[test]
    fn positive_cache_lifetime_accounts_for_glue_and_authority_records() {
        let query = parse_message(&build_query(7, "glue.test", RecordType::A).unwrap()).unwrap();
        let raw = synth_address(&query, "192.0.2.1".parse().unwrap(), 300).unwrap();
        let mut msg = parse_message(&raw).unwrap();
        let mut short = msg.answers[0].clone();
        short.ttl = 5;
        msg.additionals.push(short.clone());
        assert_eq!(
            response_meta(&encode(&msg).unwrap()).unwrap().cache_ttl,
            Some(5)
        );
        msg.additionals.clear();
        msg.authorities.push(short);
        assert_eq!(
            response_meta(&encode(&msg).unwrap()).unwrap().cache_ttl,
            Some(5)
        );
    }

    #[test]
    fn client_subnet_replaces_only_ecs_and_encodes_prefix_bytes() {
        use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
        let plain = build_query(7, "ecs.test", RecordType::A).unwrap();
        let mut msg =
            parse_message(&set_client_subnet(&plain, "192.0.2.0".parse().unwrap(), 24).unwrap())
                .unwrap();
        let edns = msg.edns.as_mut().unwrap();
        edns.set_dnssec_ok(true).set_max_payload(1232);
        edns.options_mut()
            .insert(EdnsOption::Unknown(65000, vec![17]));
        let ip = "2001:db8:1234::".parse().unwrap();
        let wire = set_client_subnet(&encode(&msg).unwrap(), ip, 48).unwrap();
        assert_eq!(&wire[10..12], &[0, 1]);
        let edns = parse_message(&wire).unwrap().edns.unwrap();
        assert!(edns.flags().dnssec_ok);
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(
            edns.options().get_all(EdnsCode::Subnet),
            vec![&EdnsOption::Subnet(ClientSubnet::new(ip, 48, 0))]
        );
        assert_eq!(
            edns.option(EdnsCode::Unknown(65000)),
            Some(&EdnsOption::Unknown(65000, vec![17]))
        );
        assert!(wire.windows(4).any(|field| field == [0, 8, 0, 10]));
    }

    #[test]
    fn ttl_rewrite() {
        let raw = build_query(1, "t.test", RecordType::A).unwrap();
        let (query, _) = parse_query(&raw).unwrap();
        let resp = synth_address(&query, "10.0.0.1".parse().unwrap(), 600).unwrap();
        let rewritten = rewrite_ttl(&resp, 60).unwrap();
        assert_eq!(response_meta(&rewritten).unwrap().cache_ttl, Some(60));
    }

    #[test]
    fn set_id_matches_reencode_path() {
        let raw = build_query(7, "four.test", RecordType::A).unwrap();
        let (query, _) = parse_query(&raw).unwrap();
        let addrs = [
            "10.0.0.1".parse().unwrap(),
            "10.0.0.2".parse().unwrap(),
            "10.0.0.3".parse().unwrap(),
            "10.0.0.4".parse().unwrap(),
        ];
        let resp = synth_addresses(&query, &addrs, 600).unwrap();
        let out = set_id(&resp, 0xBEEF).unwrap();
        // the patch leaves everything but the id untouched, byte for byte
        assert_eq!(&out[2..], &resp[2..]);
        assert_eq!(&out[..2], &0xBEEFu16.to_be_bytes());
        // and the same id the old parse → set → encode path produced
        let mut msg = parse_message(&resp).unwrap();
        msg.metadata.id = 0xBEEF;
        assert_eq!(out, encode(&msg).unwrap());
        assert!(set_id(&[0u8], 1).is_err());
    }
}
