//! SRS — the sing-box binary rule-set container (`common/srs`).
//!
//! Layout: the `SRS` magic, a version byte, a zlib stream (best compression
//! upstream) holding a varint rule count and the encoded rules. Rules are
//! either a `default` headless rule (a tagged item list terminated by
//! `final` + `invert`) or a `logical` rule (`mode` + nested rules). The
//! zlib *bytes* differ between deflate implementations, so this module
//! guarantees wire compatibility of the payload, not of the container:
//! a file written here is read by the reference and the other way round.

use std::io::{Read, Write};

use serde_json::{Map, Value};

pub const MAGIC: [u8; 3] = [0x53, 0x52, 0x53];
pub const VERSION_CURRENT: u8 = 5;

const ITEM_QUERY_TYPE: u8 = 0;
const ITEM_NETWORK: u8 = 1;
const ITEM_DOMAIN: u8 = 2;
const ITEM_DOMAIN_KEYWORD: u8 = 3;
const ITEM_DOMAIN_REGEX: u8 = 4;
const ITEM_SOURCE_IP_CIDR: u8 = 5;
const ITEM_IP_CIDR: u8 = 6;
const ITEM_SOURCE_PORT: u8 = 7;
const ITEM_SOURCE_PORT_RANGE: u8 = 8;
const ITEM_PORT: u8 = 9;
const ITEM_PORT_RANGE: u8 = 10;
const ITEM_PROCESS_NAME: u8 = 11;
const ITEM_PROCESS_PATH: u8 = 12;
const ITEM_PACKAGE_NAME: u8 = 13;
const ITEM_WIFI_SSID: u8 = 14;
const ITEM_WIFI_BSSID: u8 = 15;
const ITEM_ADGUARD_DOMAIN: u8 = 16;
const ITEM_PROCESS_PATH_REGEX: u8 = 17;
const ITEM_NETWORK_TYPE: u8 = 18;
const ITEM_NETWORK_IS_EXPENSIVE: u8 = 19;
const ITEM_NETWORK_IS_CONSTRAINED: u8 = 20;
const ITEM_NETWORK_INTERFACE_ADDRESS: u8 = 21;
const ITEM_DEFAULT_INTERFACE_ADDRESS: u8 = 22;
const ITEM_PACKAGE_NAME_REGEX: u8 = 23;
const ITEM_FINAL: u8 = 0xFF;

const MAX_LOGICAL_DEPTH: usize = 100;
/// `prefixLabel` / `rootLabel` of sing's domain matcher.
const PREFIX_LABEL: u8 = b'\r';
const ROOT_LABEL: u8 = b'\n';

/// Upper bound of the inflated payload. Real lists inflate about 1.7x
/// (300k domain suffixes: 4.0 MB file, 6.9 MB payload), so 64 MiB holds
/// roughly 2.9M domains and matches the rule-set download cap.
pub const MAX_PAYLOAD_SIZE: usize = 64 << 20;
/// Upper bound of the decoded rules, estimated as string bytes plus
/// [`VALUE_COST`] per produced value: about 3M domains of typical length
/// (300k suffixes cost 26 MB), so a real list at [`MAX_PAYLOAD_SIZE`] fits.
/// Without it a payload of empty strings or a chain-shaped trie expands
/// 50x or quadratically.
pub const MAX_DECODED_SIZE: usize = 256 << 20;
/// Rough heap cost of one decoded value (`Value` + `String` headers).
const VALUE_COST: usize = 64;
/// Smallest encoded sizes, used to reject counts the data cannot hold.
const MIN_RULE_SIZE: usize = 3;
const MIN_PREFIX_SIZE: usize = 6;
const MIN_RANGE_SIZE: usize = 10;
const MIN_INTERFACE_ENTRY_SIZE: usize = 2;
/// Initial capacity cap for vectors sized from the file.
const MAX_PREALLOC: usize = 4096;
/// Longest domain matcher key, which is also the depth of the trie walk.
/// DNS names are at most 253 bytes; the bound keeps the walk's stack and
/// key buffer small even when a crafted trie is one long chain with few
/// leaves, which the decoded-size budget alone does not see.
const MAX_DOMAIN_KEY_LEN: usize = 4096;

/// Decoder limits; tests shrink them to probe the boundaries.
#[derive(Clone, Copy)]
struct Limits {
    payload: usize,
    decoded: usize,
}

const DEFAULT_LIMITS: Limits = Limits {
    payload: MAX_PAYLOAD_SIZE,
    decoded: MAX_DECODED_SIZE,
};

// ------------------------------------------------------------------ reading

/// Parse an SRS container into its rules (`Vec<Value>` of headless rules).
pub fn read(data: &[u8]) -> Result<Vec<Value>, String> {
    read_limited(data, DEFAULT_LIMITS)
}

fn read_limited(data: &[u8], limits: Limits) -> Result<Vec<Value>, String> {
    if data.len() < 4 || data[..3] != MAGIC {
        return Err("invalid sing-box rule-set file".to_string());
    }
    let version = data[3];
    if version > VERSION_CURRENT {
        return Err(format!("unsupported version: {version}"));
    }
    let payload = inflate(&data[4..], limits.payload)?;
    let mut reader = Reader::new(&payload, limits.decoded);
    let count = reader.count(MIN_RULE_SIZE)?;
    let mut rules = Vec::with_capacity(count.min(MAX_PREALLOC));
    for index in 0..count {
        reader.budget.charge(0)?;
        rules.push(
            read_rule(&mut reader, version, 0)
                .map_err(|err| format!("read rule[{index}]: {err}"))?,
        );
    }
    Ok(rules)
}

/// Inflate the zlib stream, failing once it exceeds `limit` bytes. The
/// first pass only counts, so an oversized stream allocates nothing; the
/// second fills a buffer of the exact size.
fn inflate(compressed: &[u8], limit: usize) -> Result<Vec<u8>, String> {
    let error = |err: std::io::Error| format!("decompress rule-set: {err}");
    let mut decoder = flate2::read::ZlibDecoder::new(compressed);
    let mut chunk = [0u8; 16 * 1024];
    let mut size = 0usize;
    loop {
        let read = decoder.read(&mut chunk).map_err(error)?;
        if read == 0 {
            break;
        }
        size += read;
        if size > limit {
            return Err(format!(
                "decompress rule-set: payload exceeds {limit} bytes"
            ));
        }
    }
    let mut payload = Vec::with_capacity(size);
    flate2::read::ZlibDecoder::new(compressed)
        .take(size as u64)
        .read_to_end(&mut payload)
        .map_err(error)?;
    Ok(payload)
}

/// Read an SRS container and report the version it was written with.
pub fn read_with_version(data: &[u8]) -> Result<(u8, Vec<Value>), String> {
    if data.len() < 4 || data[..3] != MAGIC {
        return Err("invalid sing-box rule-set file".to_string());
    }
    Ok((data[3], read(data)?))
}

fn read_rule(reader: &mut Reader<'_>, version: u8, depth: usize) -> Result<Value, String> {
    if depth > MAX_LOGICAL_DEPTH {
        return Err("logical rule nested too deep".to_string());
    }
    let rule_type = reader.u8()?;
    let mut rule = Map::new();
    match rule_type {
        0 => {
            read_default_rule(reader, version, &mut rule)?;
        }
        1 => {
            rule.insert("type".into(), Value::String("logical".into()));
            let mode = reader.u8()?;
            rule.insert(
                "mode".into(),
                Value::String(match mode {
                    0 => "and".to_string(),
                    1 => "or".to_string(),
                    other => return Err(format!("unknown logical mode: {other}")),
                }),
            );
            let count = reader.count(MIN_RULE_SIZE)?;
            let mut rules = Vec::with_capacity(count.min(MAX_PREALLOC));
            for index in 0..count {
                reader.budget.charge(0)?;
                rules.push(read_rule(reader, version, depth + 1)?);
                let _ = index;
            }
            rule.insert("rules".into(), Value::Array(rules));
            if reader.u8()? != 0 {
                rule.insert("invert".into(), Value::Bool(true));
            }
        }
        other => return Err(format!("unknown rule type: {other}")),
    }
    Ok(Value::Object(rule))
}

fn read_default_rule(
    reader: &mut Reader<'_>,
    version: u8,
    rule: &mut Map<String, Value>,
) -> Result<(), String> {
    let mut last_item = 0u8;
    loop {
        let item = reader.u8()?;
        match item {
            ITEM_QUERY_TYPE => {
                let values = reader.u16_vec()?;
                let names: Vec<Value> = values
                    .into_iter()
                    .map(|value| Value::String(query_type_name(value).to_string()))
                    .collect();
                rule.insert("query_type".into(), Value::Array(names));
            }
            ITEM_NETWORK => {
                rule.insert("network".into(), Value::Array(reader.str_values()?));
            }
            ITEM_DOMAIN => {
                let (domains, suffixes) = read_domain_matcher(reader, version == 1)?;
                if !domains.is_empty() {
                    rule.insert("domain".into(), Value::Array(domains));
                }
                if !suffixes.is_empty() {
                    rule.insert("domain_suffix".into(), Value::Array(suffixes));
                }
            }
            ITEM_DOMAIN_KEYWORD => {
                rule.insert("domain_keyword".into(), Value::Array(reader.str_values()?));
            }
            ITEM_DOMAIN_REGEX => {
                rule.insert("domain_regex".into(), Value::Array(reader.str_values()?));
            }
            ITEM_SOURCE_IP_CIDR => {
                rule.insert("source_ip_cidr".into(), read_ip_set(reader)?);
            }
            ITEM_IP_CIDR => {
                rule.insert("ip_cidr".into(), read_ip_set(reader)?);
            }
            ITEM_SOURCE_PORT => {
                rule.insert("source_port".into(), port_values(reader.u16_vec()?));
            }
            ITEM_SOURCE_PORT_RANGE => {
                rule.insert(
                    "source_port_range".into(),
                    Value::Array(reader.str_values()?),
                );
            }
            ITEM_PORT => {
                rule.insert("port".into(), port_values(reader.u16_vec()?));
            }
            ITEM_PORT_RANGE => {
                rule.insert("port_range".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PROCESS_NAME => {
                rule.insert("process_name".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PROCESS_PATH => {
                rule.insert("process_path".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PROCESS_PATH_REGEX => {
                rule.insert(
                    "process_path_regex".into(),
                    Value::Array(reader.str_values()?),
                );
            }
            ITEM_PACKAGE_NAME => {
                rule.insert("package_name".into(), Value::Array(reader.str_values()?));
            }
            ITEM_PACKAGE_NAME_REGEX => {
                rule.insert(
                    "package_name_regex".into(),
                    Value::Array(reader.str_values()?),
                );
            }
            ITEM_WIFI_SSID => {
                rule.insert("wifi_ssid".into(), Value::Array(reader.str_values()?));
            }
            ITEM_WIFI_BSSID => {
                rule.insert("wifi_bssid".into(), Value::Array(reader.str_values()?));
            }
            ITEM_ADGUARD_DOMAIN => {
                let list = read_adguard_matcher(reader)?;
                if !list.is_empty() {
                    rule.insert("domain_keyword".into(), Value::Array(list));
                }
            }
            ITEM_NETWORK_TYPE => {
                let values = reader.u8_vec()?;
                let names: Vec<Value> = values
                    .into_iter()
                    .map(|value| Value::String(network_type_name(value).to_string()))
                    .collect();
                rule.insert("network_type".into(), Value::Array(names));
            }
            ITEM_NETWORK_IS_EXPENSIVE => {
                rule.insert("network_is_expensive".into(), Value::Bool(true));
            }
            ITEM_NETWORK_IS_CONSTRAINED => {
                rule.insert("network_is_constrained".into(), Value::Bool(true));
            }
            ITEM_NETWORK_INTERFACE_ADDRESS => {
                let count = reader.count(MIN_INTERFACE_ENTRY_SIZE)?;
                let mut map = Map::new();
                for _ in 0..count {
                    let key = reader.u8()?;
                    let prefixes = reader.prefix_vec()?;
                    map.insert(network_type_name(key).to_string(), Value::Array(prefixes));
                }
                rule.insert("network_interface_address".into(), Value::Object(map));
            }
            ITEM_DEFAULT_INTERFACE_ADDRESS => {
                let prefixes = reader.prefix_vec()?;
                rule.insert("default_interface_address".into(), Value::Array(prefixes));
            }
            ITEM_FINAL => {
                let invert = reader.u8()? != 0;
                if invert {
                    rule.insert("invert".into(), Value::Bool(true));
                }
                return Ok(());
            }
            other => {
                return Err(format!(
                    "unknown rule item type: {other}, last type: {last_item}"
                ));
            }
        }
        last_item = item;
    }
}

fn query_type_name(value: u16) -> &'static str {
    match value {
        1 => "A",
        2 => "AAAA",
        28 => "HTTPS",
        65 => "HTTPS",
        _ => "A",
    }
}

fn network_type_name(value: u8) -> &'static str {
    match value {
        0 => "wifi",
        1 => "cellular",
        2 => "ethernet",
        3 => "other",
        _ => "",
    }
}

// ------------------------------------------------------------------ writing

/// `downgradeRuleSetVersion`: the reference compiler lowers the container
/// version to the oldest one that still carries every rule item.
pub fn downgrade_version(value: &Value, version: u8) -> u8 {
    let rules: Vec<Value> = value
        .get("rules")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let has = |field: &str| {
        rules.iter().any(|rule| {
            rule.get(field)
                .is_some_and(|value| !listable(Some(value)).unwrap_or_default().is_empty())
                || rule.get(field) == Some(&Value::Bool(true))
        })
    };
    let mut version = version;
    if version == 5 && !has("package_name_regex") {
        version = 4;
    }
    if version == 4 && !has("network_interface_address") && !has("default_interface_address") {
        version = 3;
    }
    if version == 3
        && !has("network_type")
        && !has("network_is_expensive")
        && !has("network_is_constrained")
    {
        version = 2;
    }
    version
}

/// Compile a source rule-set (`{version, rules}` or `{rules}`) into an SRS
/// container.
pub fn compile(value: &Value, version: u8) -> Result<Vec<u8>, String> {
    if version == 0 || version > VERSION_CURRENT {
        return Err(format!("unknown rule-set version: {version}"));
    }
    let rules = match value.get("rules") {
        Some(Value::Array(rules)) => rules.clone(),
        Some(other) => return Err(format!("rules must be an array, got {}", kind(other))),
        None => Vec::new(),
    };
    let mut writer = Writer::default();
    writer.uvarint(rules.len() as u64);
    for rule in &rules {
        write_rule(&mut writer, rule, version)?;
    }
    let mut payload = Vec::new();
    flate2::write::ZlibEncoder::new(&mut payload, flate2::Compression::best())
        .write_all(&writer.out)
        .map_err(|err| format!("compress rule-set: {err}"))?;
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&MAGIC);
    out.push(version);
    out.extend_from_slice(&payload);
    Ok(out)
}

fn write_rule(writer: &mut Writer, rule: &Value, version: u8) -> Result<(), String> {
    let rule = rule
        .as_object()
        .ok_or_else(|| "rule must be an object".to_string())?;
    let rule_type = rule
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("default");
    match rule_type {
        "default" => {
            writer.u8(0);
            write_default_rule(writer, rule, version)
        }
        "logical" => {
            writer.u8(1);
            let mode = match rule
                .get("mode")
                .and_then(Value::as_str)
                .ok_or_else(|| "logical rule is missing mode".to_string())?
            {
                "and" => 0u8,
                "or" => 1u8,
                other => return Err(format!("unknown logical mode: {other}")),
            };
            writer.u8(mode);
            let rules = rule
                .get("rules")
                .and_then(Value::as_array)
                .ok_or_else(|| "logical rule is missing rules".to_string())?;
            writer.uvarint(rules.len() as u64);
            for sub in rules {
                write_rule(writer, sub, version)?;
            }
            writer.u8(u8::from(rule.get("invert") == Some(&Value::Bool(true))));
            Ok(())
        }
        other => Err(format!("unknown rule type: {other}")),
    }
}

fn write_default_rule(
    writer: &mut Writer,
    rule: &Map<String, Value>,
    version: u8,
) -> Result<(), String> {
    if let Some(values) = rule.get("query_type") {
        let mut encoded = Vec::new();
        for value in strings(values)? {
            encoded.push(query_type_code(&value)?);
        }
        writer.item_u16_vec(ITEM_QUERY_TYPE, &encoded);
    }
    if let Some(values) = rule.get("network") {
        writer.item_str_vec(ITEM_NETWORK, &strings(values)?);
    }
    let domains = listable(rule.get("domain"))?;
    let suffixes = listable(rule.get("domain_suffix"))?;
    if !domains.is_empty() || !suffixes.is_empty() {
        writer.u8(ITEM_DOMAIN);
        write_domain_matcher(writer, &domains, &suffixes, version == 1)?;
    }
    if let Some(values) = rule.get("domain_keyword") {
        writer.item_str_vec(ITEM_DOMAIN_KEYWORD, &strings(values)?);
    }
    if let Some(values) = rule.get("domain_regex") {
        writer.item_str_vec(ITEM_DOMAIN_REGEX, &strings(values)?);
    }
    if let Some(values) = rule.get("source_ip_cidr") {
        writer.item_ip_set(ITEM_SOURCE_IP_CIDR, &strings(values)?);
    }
    if let Some(values) = rule.get("ip_cidr") {
        writer.item_ip_set(ITEM_IP_CIDR, &strings(values)?);
    }
    if let Some(values) = rule.get("source_port") {
        writer.item_u16_vec(ITEM_SOURCE_PORT, &ports(values)?);
    }
    if let Some(values) = rule.get("source_port_range") {
        writer.item_str_vec(ITEM_SOURCE_PORT_RANGE, &strings(values)?);
    }
    if let Some(values) = rule.get("port") {
        writer.item_u16_vec(ITEM_PORT, &ports(values)?);
    }
    if let Some(values) = rule.get("port_range") {
        writer.item_str_vec(ITEM_PORT_RANGE, &strings(values)?);
    }
    if let Some(values) = rule.get("process_name") {
        writer.item_str_vec(ITEM_PROCESS_NAME, &strings(values)?);
    }
    if let Some(values) = rule.get("process_path") {
        writer.item_str_vec(ITEM_PROCESS_PATH, &strings(values)?);
    }
    if let Some(values) = rule.get("process_path_regex") {
        writer.item_str_vec(ITEM_PROCESS_PATH_REGEX, &strings(values)?);
    }
    if let Some(values) = rule.get("package_name") {
        writer.item_str_vec(ITEM_PACKAGE_NAME, &strings(values)?);
    }
    if let Some(values) = rule.get("package_name_regex")
        && !listable(Some(values))?.is_empty()
    {
        if version < 5 {
            return Err(
                "`package_name_regex` rule item is only supported in version 5 or later".into(),
            );
        }
        writer.item_str_vec(ITEM_PACKAGE_NAME_REGEX, &strings(values)?);
    }
    if let Some(values) = rule.get("network_type") {
        let list = listable(Some(values))?;
        if !list.is_empty() {
            if version < 3 {
                return Err(
                    "`network_type` rule item is only supported in version 3 or later".into(),
                );
            }
            let mut encoded = Vec::new();
            for value in &list {
                encoded.push(network_type_code(value)?);
            }
            writer.item_u8_vec(ITEM_NETWORK_TYPE, &encoded);
        }
    }
    if rule.get("network_is_expensive") == Some(&Value::Bool(true)) {
        if version < 3 {
            return Err(
                "`network_is_expensive` rule item is only supported in version 3 or later".into(),
            );
        }
        writer.u8(ITEM_NETWORK_IS_EXPENSIVE);
    }
    if rule.get("network_is_constrained") == Some(&Value::Bool(true)) {
        if version < 3 {
            return Err(
                "`network_is_constrained` rule item is only supported in version 3 or later".into(),
            );
        }
        writer.u8(ITEM_NETWORK_IS_CONSTRAINED);
    }
    if let Some(Value::Object(map)) = rule.get("network_interface_address")
        && !map.is_empty()
    {
        if version < 4 {
            return Err(
                "`network_interface_address` rule item is only supported in version 4 or later"
                    .into(),
            );
        }
        writer.u8(ITEM_NETWORK_INTERFACE_ADDRESS);
        writer.uvarint(map.len() as u64);
        for (key, value) in map {
            let code = network_type_code(key)?;
            writer.u8(code);
            let prefixes = listable(Some(value))?;
            writer.uvarint(prefixes.len() as u64);
            for prefix in &prefixes {
                write_prefix(writer, prefix)?;
            }
        }
    }
    if let Some(values) = rule.get("default_interface_address") {
        let prefixes = listable(Some(values))?;
        if !prefixes.is_empty() {
            if version < 4 {
                return Err(
                    "`default_interface_address` rule item is only supported in version 4 or later"
                        .into(),
                );
            }
            writer.u8(ITEM_DEFAULT_INTERFACE_ADDRESS);
            writer.uvarint(prefixes.len() as u64);
            for prefix in &prefixes {
                write_prefix(writer, prefix)?;
            }
        }
    }
    if let Some(values) = rule.get("wifi_ssid") {
        writer.item_str_vec(ITEM_WIFI_SSID, &strings(values)?);
    }
    if let Some(values) = rule.get("wifi_bssid") {
        writer.item_str_vec(ITEM_WIFI_BSSID, &strings(values)?);
    }
    writer.u8(ITEM_FINAL);
    writer.u8(u8::from(rule.get("invert") == Some(&Value::Bool(true))));
    Ok(())
}

// ------------------------------------------------------------- domain trie

/// `domain.NewMatcher(...).Write`: the succinct set of reversed domain keys.
fn write_domain_matcher(
    writer: &mut Writer,
    domains: &[String],
    suffixes: &[String],
    legacy: bool,
) -> Result<(), String> {
    let mut list: Vec<String> = Vec::new();
    let mut seen: Vec<String> = Vec::new();
    for suffix in suffixes {
        if seen.iter().any(|entry| entry == suffix) {
            continue;
        }
        seen.push(suffix.clone());
        if suffix.starts_with('.') {
            list.push(reverse_domain(&format!("{}{suffix}", PREFIX_LABEL as char)));
        } else if legacy {
            list.push(reverse_domain(suffix));
            let dotted = format!(".{suffix}");
            if !seen.contains(&dotted) {
                seen.push(dotted.clone());
                list.push(reverse_domain(&format!("{}{dotted}", PREFIX_LABEL as char)));
            }
        } else {
            list.push(reverse_domain(&format!("{}{suffix}", ROOT_LABEL as char)));
        }
    }
    for domain in domains {
        if seen.iter().any(|entry| entry == domain) {
            continue;
        }
        seen.push(domain.clone());
        list.push(reverse_domain(domain));
    }
    list.sort();
    let set = SuccinctSet::build(&list);
    writer.u8(0);
    writer.u64_slice(&set.leaves);
    writer.u64_slice(&set.label_bitmap);
    writer.bytes(&set.labels);
    Ok(())
}

/// `domain.Matcher.Dump()`: un-reverse every key and split it by its label.
fn read_domain_matcher(
    reader: &mut Reader<'_>,
    _legacy: bool,
) -> Result<(Vec<Value>, Vec<Value>), String> {
    let _version = reader.u8()?;
    let leaves = reader.u64_slice()?;
    let label_bitmap = reader.u64_slice()?;
    let labels = reader.bytes()?;
    let ranks = index_ranks(&label_bitmap);
    let set = SuccinctSet {
        leaves,
        label_bitmap,
        labels,
        ranks,
    };
    let mut domains: Vec<String> = Vec::new();
    let mut prefixes: Vec<String> = Vec::new();
    // each key is classified as the walk yields it; the keys are not collected first
    set.keys(&mut reader.budget, |key| {
        let key = reverse_domain(key);
        let Some(label) = key.as_bytes().first().copied() else {
            return;
        };
        match label {
            PREFIX_LABEL => {
                let raw = key[1..].to_string();
                // a prefix that also exists as an exact domain is a suffix only
                if let Some(root) = raw.strip_prefix('.') {
                    let root = root.to_string();
                    if domains.contains(&root) {
                        domains.retain(|domain| *domain != root);
                        prefixes.push(root);
                        return;
                    }
                }
                prefixes.push(raw);
            }
            ROOT_LABEL => prefixes.push(key[1..].to_string()),
            _ => domains.push(key),
        }
    })?;
    drop(set);
    // the lists are converted below; spare capacity would sit next to that copy
    domains.shrink_to_fit();
    prefixes.shrink_to_fit();
    domains.sort();
    prefixes.sort();
    Ok((
        domains.into_iter().map(Value::String).collect(),
        prefixes.into_iter().map(Value::String).collect(),
    ))
}

/// The AdGuard matcher is a plain string list upstream.
fn read_adguard_matcher(reader: &mut Reader<'_>) -> Result<Vec<Value>, String> {
    reader.str_values()
}

/// sing's `succinctSet`, bit for bit (`common/domain/set.go`).
struct SuccinctSet {
    leaves: Vec<u64>,
    label_bitmap: Vec<u64>,
    labels: Vec<u8>,
    /// `ranks[w]` — ones before word `w`; `ranks[words]` is the total count.
    /// The reference keeps the same table (`indexRank64`) so that rank/select
    /// stay O(1)/O(log words): a plain scan per edge is quadratic and the
    /// hagezi-class sets take minutes on a router.
    ranks: Vec<u64>,
}

impl SuccinctSet {
    fn build(keys: &[String]) -> Self {
        struct Element {
            start: usize,
            end: usize,
            column: usize,
        }
        let mut leaves: Vec<u64> = Vec::new();
        let mut label_bitmap: Vec<u64> = Vec::new();
        let mut labels: Vec<u8> = Vec::new();
        let mut label_index = 0usize;
        let mut queue = vec![Element {
            start: 0,
            end: keys.len(),
            column: 0,
        }];
        let mut index = 0usize;
        while index < queue.len() {
            let element = &queue[index];
            let mut start = element.start;
            let end = element.end;
            let column = element.column;
            if column == keys[element.start].len() {
                set_bit(&mut leaves, index, 1);
                start += 1;
            }
            let mut cursor = start;
            while cursor < end {
                let from = cursor;
                let first = keys[from].as_bytes()[column];
                while cursor < end && keys[cursor].as_bytes()[column] == first {
                    cursor += 1;
                }
                queue.push(Element {
                    start: from,
                    end: cursor,
                    column: column + 1,
                });
                labels.push(first);
                set_bit(&mut label_bitmap, label_index, 0);
                label_index += 1;
            }
            set_bit(&mut label_bitmap, label_index, 1);
            label_index += 1;
            index += 1;
        }
        let ranks = index_ranks(&label_bitmap);
        Self {
            leaves,
            label_bitmap,
            labels,
            ranks,
        }
    }

    /// `succinctSet.keys()`: walk the set back into its keys. The walk keeps
    /// its own stack: a crafted trie can be one chain as deep as the payload.
    /// Each key goes to `emit` in walk order.
    fn keys(&self, budget: &mut Budget, mut emit: impl FnMut(&str)) -> Result<(), String> {
        struct Frame {
            node_id: usize,
            cursor: usize,
        }
        let inconsistent = || "invalid domain matcher: inconsistent succinct set".to_string();
        let mut current: Vec<u8> = Vec::new();
        self.emit_leaf(0, &current, &mut emit, budget)?;
        let mut stack = vec![Frame {
            node_id: 0,
            cursor: 0,
        }];
        while let Some(frame) = stack.last() {
            let (node_id, cursor) = (frame.node_id, frame.cursor);
            if get_bit(&self.label_bitmap, cursor) == 0 {
                // the reference indexes these unchecked: a valid set always
                // has the label, the bitmap word and the child's block
                let label = self
                    .labels
                    .get(cursor.saturating_sub(node_id))
                    .copied()
                    .ok_or_else(inconsistent)?;
                let next_node = self.count_zeros(cursor + 1).ok_or_else(inconsistent)?;
                let index = self
                    .select_ith_one(next_node.saturating_sub(1))
                    .ok_or_else(inconsistent)?;
                if current.len() >= MAX_DOMAIN_KEY_LEN {
                    return Err(format!(
                        "invalid domain matcher: key longer than {MAX_DOMAIN_KEY_LEN} bytes"
                    ));
                }
                current.push(label);
                self.emit_leaf(next_node, &current, &mut emit, budget)?;
                stack.push(Frame {
                    node_id: next_node,
                    cursor: index + 1,
                });
                continue;
            }
            // this node is done: back to the parent's next edge
            stack.pop();
            if let Some(parent) = stack.last_mut() {
                current.pop();
                parent.cursor += 1;
            }
        }
        Ok(())
    }

    fn emit_leaf(
        &self,
        node_id: usize,
        current: &[u8],
        emit: &mut impl FnMut(&str),
        budget: &mut Budget,
    ) -> Result<(), String> {
        if get_bit(&self.leaves, node_id) != 0 {
            let key = String::from_utf8_lossy(current);
            budget.charge(key.len())?;
            emit(&key);
        }
        Ok(())
    }

    /// Zeros before `index`, from the rank table; `None` past the bitmap.
    fn count_zeros(&self, index: usize) -> Option<usize> {
        let word = index >> 6;
        let bit = index & 63;
        let partial = if bit == 0 {
            0
        } else {
            let mask = u64::MAX >> (64 - bit);
            (self.label_bitmap.get(word)? & mask).count_ones() as u64
        };
        let ones = self.ranks.get(word)? + partial;
        index.checked_sub(usize::try_from(ones).ok()?)
    }

    /// The position of the `index`-th set bit: the rank table turns the
    /// word walk into a binary search.
    fn select_ith_one(&self, index: usize) -> Option<usize> {
        let word = self
            .ranks
            .partition_point(|rank| *rank <= index as u64)
            .checked_sub(1)?;
        let mut rest = index.checked_sub(usize::try_from(self.ranks[word]).ok()?)?;
        let mut bits = *self.label_bitmap.get(word)?;
        while bits != 0 {
            if rest == 0 {
                return Some((word << 6) + bits.trailing_zeros() as usize);
            }
            bits &= bits - 1;
            rest -= 1;
        }
        None
    }
}

fn set_bit(bits: &mut Vec<u64>, index: usize, value: u64) {
    let word = index >> 6;
    while word >= bits.len() {
        bits.push(0);
    }
    bits[word] |= value << (index & 63);
}

fn get_bit(bits: &[u64], index: usize) -> u64 {
    let word = index >> 6;
    if word >= bits.len() {
        return 0;
    }
    (bits[word] >> (index & 63)) & 1
}

fn index_ranks(bitmap: &[u64]) -> Vec<u64> {
    let mut ranks = Vec::with_capacity(bitmap.len() + 1);
    let mut total = 0u64;
    for word in bitmap {
        ranks.push(total);
        total += word.count_ones() as u64;
    }
    ranks.push(total);
    ranks
}

// ------------------------------------------------------------- ip encoding

fn write_prefix(writer: &mut Writer, prefix: &str) -> Result<(), String> {
    let (addr, bits) = split_prefix(prefix)?;
    write_addr(writer, &addr);
    writer.u8(bits);
    Ok(())
}

fn write_addr(writer: &mut Writer, addr: &std::net::IpAddr) {
    let bytes = match addr {
        std::net::IpAddr::V4(addr) => addr.octets().to_vec(),
        std::net::IpAddr::V6(addr) => addr.octets().to_vec(),
    };
    writer.uvarint(bytes.len() as u64);
    writer.out.extend_from_slice(&bytes);
}

fn read_ip_set(reader: &mut Reader<'_>) -> Result<Value, String> {
    let version = reader.u8()?;
    if version != 1 {
        return Err("invalid IP set version".to_string());
    }
    let count = reader.u64()?;
    let count = reader.check_count(count, MIN_RANGE_SIZE)?;
    let mut ranges = Vec::with_capacity(count.min(MAX_PREALLOC));
    for _ in 0..count {
        let from = read_addr(reader)?;
        let to = read_addr(reader)?;
        ranges.push((from, to));
    }
    // the reference stores merged ranges; rebuild the covered prefixes
    let mut prefixes: Vec<String> = Vec::new();
    for (from, to) in ranges {
        for prefix in range_to_prefixes(&from, &to) {
            reader.budget.charge(prefix.len())?;
            prefixes.push(prefix);
        }
    }
    Ok(Value::Array(
        prefixes.into_iter().map(Value::String).collect(),
    ))
}

fn read_addr(reader: &mut Reader<'_>) -> Result<std::net::IpAddr, String> {
    let len = reader.uvarint()?;
    if len != 4 && len != 16 {
        return Err("invalid IP set address".to_string());
    }
    let bytes = reader.take(len as usize)?;
    match bytes.len() {
        4 => {
            let mut raw = [0u8; 4];
            raw.copy_from_slice(bytes);
            Ok(std::net::IpAddr::from(raw))
        }
        _ => {
            let mut raw = [0u8; 16];
            raw.copy_from_slice(bytes);
            Ok(std::net::IpAddr::from(raw))
        }
    }
}

fn range_to_prefixes(from: &std::net::IpAddr, to: &std::net::IpAddr) -> Vec<String> {
    // An inclusive range is reported as the aligned CIDR blocks that cover it.
    match (from, to) {
        (std::net::IpAddr::V4(from), std::net::IpAddr::V4(to)) => {
            blocks(u128::from(u32::from(*from)), u128::from(u32::from(*to)), 32)
                .into_iter()
                .map(|(start, bits)| format!("{}/{}", std::net::Ipv4Addr::from(start as u32), bits))
                .collect()
        }
        (std::net::IpAddr::V6(from), std::net::IpAddr::V6(to)) => {
            blocks(u128::from(*from), u128::from(*to), 128)
                .into_iter()
                .map(|(start, bits)| format!("{}/{}", std::net::Ipv6Addr::from(start), bits))
                .collect()
        }
        _ => Vec::new(),
    }
}

/// The aligned power-of-two blocks covering `start..=end`.
fn blocks(mut start: u128, end: u128, width: u32) -> Vec<(u128, u32)> {
    let mut out = Vec::new();
    while start <= end {
        // the largest block that is aligned at `start`
        let max_size = if start == 0 {
            1u128 << width
        } else {
            1u128 << start.trailing_zeros().min(width)
        };
        let room = (end - start) + 1;
        let mut size = max_size;
        while size > room {
            size >>= 1;
        }
        let bits = width - size.trailing_zeros();
        out.push((start, bits.min(width)));
        match start.checked_add(size) {
            Some(next) => start = next,
            None => break,
        }
    }
    out
}

fn split_prefix(prefix: &str) -> Result<(std::net::IpAddr, u8), String> {
    let (addr, bits) = prefix
        .split_once('/')
        .ok_or_else(|| format!("invalid prefix: {prefix}"))?;
    let addr: std::net::IpAddr = addr
        .parse()
        .map_err(|_| format!("invalid prefix address: {addr}"))?;
    let bits: u8 = bits
        .parse()
        .map_err(|_| format!("invalid prefix bits: {bits}"))?;
    Ok((addr, bits))
}

fn read_prefix(reader: &mut Reader<'_>) -> Result<String, String> {
    let addr = read_addr(reader)?;
    let bits = reader.u8()?;
    let prefix = format!("{addr}/{bits}");
    reader.budget.charge(prefix.len())?;
    Ok(prefix)
}

// ------------------------------------------------------------------ helpers

fn kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

fn listable(value: Option<&Value>) -> Result<Vec<String>, String> {
    match value {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::String(text)) => Ok(vec![text.clone()]),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| match item {
                Value::String(text) => Ok(text.clone()),
                other => Err(format!("expected a string, got {}", kind(other))),
            })
            .collect(),
        Some(other) => Err(format!("expected a string, got {}", kind(other))),
    }
}

fn strings(value: &Value) -> Result<Vec<String>, String> {
    listable(Some(value))
}

fn ports(value: &Value) -> Result<Vec<u16>, String> {
    let mut out = Vec::new();
    match value {
        Value::Number(number) => out.push(
            number
                .as_u64()
                .filter(|value| *value <= u64::from(u16::MAX))
                .ok_or_else(|| "port out of range".to_string())? as u16,
        ),
        Value::Array(items) => {
            for item in items {
                let number = item
                    .as_u64()
                    .ok_or_else(|| "port must be a number".to_string())?;
                if number > u64::from(u16::MAX) {
                    return Err("port out of range".to_string());
                }
                out.push(number as u16);
            }
        }
        other => return Err(format!("port must be a number, got {}", kind(other))),
    }
    Ok(out)
}

fn port_values(values: Vec<u16>) -> Value {
    Value::Array(values.into_iter().map(Value::from).collect())
}

fn query_type_code(name: &str) -> Result<u16, String> {
    match name {
        "A" | "1" => Ok(1),
        "AAAA" | "28" => Ok(28),
        "HTTPS" | "65" => Ok(65),
        other => Err(format!("unsupported query_type: {other}")),
    }
}

fn network_type_code(name: &str) -> Result<u8, String> {
    match name {
        "wifi" | "0" => Ok(0),
        "cellular" | "1" => Ok(1),
        "ethernet" | "2" => Ok(2),
        "other" | "3" => Ok(3),
        other => Err(format!("unsupported network_type: {other}")),
    }
}

fn reverse_domain(domain: &str) -> String {
    // exact capacity: these strings are kept as decoded rule values
    let mut reversed = String::with_capacity(domain.len());
    reversed.extend(domain.chars().rev());
    reversed
}

// ------------------------------------------------------------------ codecs

#[derive(Default)]
struct Writer {
    out: Vec<u8>,
}

impl Writer {
    fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    fn uvarint(&mut self, mut value: u64) {
        while value >= 0x80 {
            self.out.push((value as u8) | 0x80);
            value >>= 7;
        }
        self.out.push(value as u8);
    }

    fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_be_bytes());
    }

    fn bytes(&mut self, value: &[u8]) {
        self.uvarint(value.len() as u64);
        self.out.extend_from_slice(value);
    }

    fn u64_slice(&mut self, values: &[u64]) {
        self.uvarint(values.len() as u64);
        for value in values {
            self.u64(*value);
        }
    }

    fn str_vec(&mut self, values: &[String]) {
        self.uvarint(values.len() as u64);
        for value in values {
            self.bytes(value.as_bytes());
        }
    }

    fn u8_vec(&mut self, values: &[u8]) {
        self.uvarint(values.len() as u64);
        self.out.extend_from_slice(values);
    }

    fn u16_vec(&mut self, values: &[u16]) {
        self.uvarint(values.len() as u64);
        for value in values {
            self.out.extend_from_slice(&value.to_be_bytes());
        }
    }

    fn item_str_vec(&mut self, item: u8, values: &[String]) {
        if values.is_empty() {
            return;
        }
        self.u8(item);
        self.str_vec(values);
    }

    fn item_u8_vec(&mut self, item: u8, values: &[u8]) {
        if values.is_empty() {
            return;
        }
        self.u8(item);
        self.u8_vec(values);
    }

    fn item_u16_vec(&mut self, item: u8, values: &[u16]) {
        if values.is_empty() {
            return;
        }
        self.u8(item);
        self.u16_vec(values);
    }

    fn item_ip_set(&mut self, item: u8, prefixes: &[String]) {
        if prefixes.is_empty() {
            return;
        }
        self.u8(item);
        let ranges = merge_prefixes(prefixes);
        self.u8(1);
        self.u64(ranges.len() as u64);
        for (from, to) in ranges {
            write_addr(self, &from);
            write_addr(self, &to);
        }
    }
}

/// Cover the given prefixes with the minimal set of aligned ranges, the shape
/// `netipx.IPSet` stores.
fn merge_prefixes(prefixes: &[String]) -> Vec<(std::net::IpAddr, std::net::IpAddr)> {
    let mut v4: Vec<(u32, u8)> = Vec::new();
    let mut v6: Vec<(u128, u8)> = Vec::new();
    for prefix in prefixes {
        let Ok((addr, bits)) = split_prefix(prefix) else {
            continue;
        };
        match addr {
            std::net::IpAddr::V4(addr) => {
                let value = u32::from(addr);
                let start = value & (!0u32 << (32 - bits.min(32)));
                v4.push((start, bits.min(32)));
            }
            std::net::IpAddr::V6(addr) => {
                let value = u128::from(addr);
                let start = if bits >= 128 {
                    value
                } else {
                    value & (!0u128 << (128 - bits))
                };
                v6.push((start, bits));
            }
        }
    }
    let mut out = Vec::new();
    v4.sort_unstable();
    let mut index = 0usize;
    while index < v4.len() {
        let (start, bits) = v4[index];
        let size = 1u32 << (32 - bits);
        let end = start.saturating_add(size.saturating_sub(1));
        let mut next = index + 1;
        while next < v4.len() && v4[next].0 <= end.saturating_add(1) {
            let (other, other_bits) = v4[next];
            let other_end = other.saturating_add((1u32 << (32 - other_bits)).saturating_sub(1));
            let end = end.max(other_end);
            let _ = end;
            next += 1;
        }
        out.push((
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(start)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::from(end)),
        ));
        index = next;
    }
    v6.sort_unstable();
    let mut index = 0usize;
    while index < v6.len() {
        let (start, bits) = v6[index];
        let size = 1u128 << (128 - bits.min(128));
        let mut end = start.saturating_add(size.saturating_sub(1));
        let mut next = index + 1;
        while next < v6.len() && v6[next].0 <= end.saturating_add(1) {
            let (other, other_bits) = v6[next];
            let other_end = other.saturating_add((1u128 << (128 - other_bits)).saturating_sub(1));
            end = end.max(other_end);
            next += 1;
        }
        out.push((
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(start)),
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(end)),
        ));
        index = next;
    }
    out
}

/// What is left of the decoded-size allowance of one file.
struct Budget(usize);

impl Budget {
    /// Account for one decoded value carrying `len` bytes of data.
    fn charge(&mut self, len: usize) -> Result<(), String> {
        let cost = len.saturating_add(VALUE_COST);
        self.0 = self
            .0
            .checked_sub(cost)
            .ok_or_else(|| "rule-set decodes to too many values".to_string())?;
        Ok(())
    }
}

struct Reader<'a> {
    data: &'a [u8],
    offset: usize,
    budget: Budget,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8], budget: usize) -> Self {
        Self {
            data,
            offset: 0,
            budget: Budget(budget),
        }
    }

    fn remaining(&self) -> usize {
        self.data.len() - self.offset
    }

    /// An element count: every element takes at least `min_size` bytes, so a
    /// count the rest of the payload cannot hold is rejected up front.
    fn count(&mut self, min_size: usize) -> Result<usize, String> {
        let count = self.uvarint()?;
        self.check_count(count, min_size)
    }

    fn check_count(&self, count: u64, min_size: usize) -> Result<usize, String> {
        let room = self.remaining() / min_size;
        match usize::try_from(count) {
            Ok(count) if count <= room => Ok(count),
            _ => Err(format!(
                "rule-set element count {count} exceeds the remaining {} bytes",
                self.remaining()
            )),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| "rule-set read overflow".to_string())?;
        let slice = self
            .data
            .get(self.offset..end)
            .ok_or_else(|| "unexpected end of rule-set".to_string())?;
        self.offset = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u64(&mut self) -> Result<u64, String> {
        let bytes = self.take(8)?;
        let mut raw = [0u8; 8];
        raw.copy_from_slice(bytes);
        Ok(u64::from_be_bytes(raw))
    }

    fn uvarint(&mut self) -> Result<u64, String> {
        let mut value = 0u64;
        let mut shift = 0u32;
        loop {
            let byte = self.u8()?;
            value |= u64::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift > 63 {
                return Err("rule-set varint overflow".to_string());
            }
        }
    }

    fn bytes(&mut self) -> Result<Vec<u8>, String> {
        let len = self.count(1)?;
        Ok(self.take(len)?.to_vec())
    }

    fn str(&mut self) -> Result<String, String> {
        let len = self.count(1)?;
        let bytes = self.take(len)?;
        self.budget.charge(len)?;
        String::from_utf8(bytes.to_vec()).map_err(|_| "invalid utf-8 in rule-set".to_string())
    }

    fn str_values(&mut self) -> Result<Vec<Value>, String> {
        Ok(self.str_vec()?.into_iter().map(Value::String).collect())
    }

    fn str_vec(&mut self) -> Result<Vec<String>, String> {
        let count = self.count(1)?;
        let mut out = Vec::with_capacity(count.min(MAX_PREALLOC));
        for _ in 0..count {
            out.push(self.str()?);
        }
        Ok(out)
    }

    fn u8_vec(&mut self) -> Result<Vec<u8>, String> {
        let count = self.count(1)?;
        for _ in 0..count {
            self.budget.charge(0)?;
        }
        Ok(self.take(count)?.to_vec())
    }

    fn u16_vec(&mut self) -> Result<Vec<u16>, String> {
        let count = self.count(2)?;
        let mut out = Vec::with_capacity(count.min(MAX_PREALLOC));
        for _ in 0..count {
            self.budget.charge(0)?;
            let bytes = self.take(2)?;
            out.push(u16::from_be_bytes([bytes[0], bytes[1]]));
        }
        Ok(out)
    }

    fn u64_slice(&mut self) -> Result<Vec<u64>, String> {
        let count = self.count(8)?;
        let mut out = Vec::with_capacity(count.min(MAX_PREALLOC));
        for _ in 0..count {
            out.push(self.u64()?);
        }
        Ok(out)
    }

    fn prefix_vec(&mut self) -> Result<Vec<Value>, String> {
        let count = self.count(MIN_PREFIX_SIZE)?;
        let mut out = Vec::with_capacity(count.min(MAX_PREALLOC));
        for _ in 0..count {
            out.push(Value::String(read_prefix(self)?));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn round_trip(source: Value, version: u8) -> Value {
        let compiled = compile(&source, version).expect("compile");
        let rules = read(&compiled).expect("read");
        json!({ "version": version, "rules": rules })
    }

    #[test]
    fn container_shape() {
        let compiled = compile(&json!({"rules": [{"domain": ["a.com"]}]}), 2).expect("compile");
        assert_eq!(&compiled[..3], b"SRS");
        assert_eq!(compiled[3], 2);
        assert!(read(&compiled).is_ok());
        assert!(read(b"XXX\x02").is_err());
        assert!(read(b"SRS\x09").is_err(), "version gate");
    }

    #[test]
    fn domain_matcher_round_trip() {
        let source = json!({
            "rules": [
                {"domain": ["example.com"], "domain_suffix": ["a.com", "b.org"]},
                {"domain_suffix": [".ads.net"]},
            ]
        });
        let out = round_trip(source.clone(), 3);
        assert_eq!(out["rules"][0]["domain"], json!(["example.com"]));
        assert_eq!(out["rules"][0]["domain_suffix"], json!(["a.com", "b.org"]));
        assert_eq!(out["rules"][1]["domain_suffix"], json!([".ads.net"]));
    }

    #[test]
    fn ip_and_port_items() {
        let source = json!({
            "rules": [
                {"ip_cidr": ["10.0.0.0/8", "192.168.0.0/16"], "port": [80, 443]},
                {
                    "source_ip_cidr": ["2001:db8::/32"],
                    "source_port": [1000],
                    "port_range": ["8000-9000"]
                },
            ]
        });
        let out = round_trip(source.clone(), 3);
        assert_eq!(
            out["rules"][0]["ip_cidr"],
            json!(["10.0.0.0/8", "192.168.0.0/16"])
        );
        assert_eq!(out["rules"][0]["port"], json!([80, 443]));
        assert_eq!(out["rules"][1]["source_ip_cidr"], json!(["2001:db8::/32"]));
        assert_eq!(out["rules"][1]["source_port"], json!([1000]));
        assert_eq!(out["rules"][1]["port_range"], json!(["8000-9000"]));
    }

    #[test]
    fn network_flags_and_interface_addresses() {
        let source = json!({
            "rules": [{
                "network_type": ["wifi"],
                "network_is_expensive": true,
                "network_is_constrained": true,
            }]
        });
        let out = round_trip(source, 3);
        assert_eq!(out["rules"][0]["network_type"], json!(["wifi"]));
        assert_eq!(out["rules"][0]["network_is_expensive"], json!(true));
        assert_eq!(out["rules"][0]["network_is_constrained"], json!(true));

        let source = json!({
            "rules": [{
                "network_interface_address": {"wifi": ["192.168.1.0/24"]},
                "default_interface_address": ["10.0.0.0/8"],
            }]
        });
        let out = round_trip(source, 4);
        assert_eq!(
            out["rules"][0]["network_interface_address"],
            json!({"wifi": ["192.168.1.0/24"]})
        );
        assert_eq!(
            out["rules"][0]["default_interface_address"],
            json!(["10.0.0.0/8"])
        );
    }

    #[test]
    fn logical_rules_carry_their_own_invert() {
        let source = json!({
            "rules": [{
                "type": "logical",
                "mode": "or",
                "rules": [{"domain_suffix": ["a.com"]}, {"port": [443]}],
                "invert": true,
            }]
        });
        let out = round_trip(source, 3);
        assert_eq!(out["rules"][0]["type"], json!("logical"));
        assert_eq!(out["rules"][0]["mode"], json!("or"));
        assert_eq!(out["rules"][0]["invert"], json!(true));
        assert_eq!(out["rules"][0]["rules"][1]["port"], json!([443]));
    }

    #[test]
    fn version_gates_and_downgrade() {
        let source = json!({"rules": [{"package_name_regex": [r"^com\."]}]});
        assert!(
            compile(&source, 4).is_err(),
            "package_name_regex needs version 5"
        );
        let source = json!({"rules": [{"network_type": ["wifi"]}]});
        assert!(compile(&source, 2).is_err(), "network_type needs version 3");
        let source = json!({"rules": [{"default_interface_address": ["10.0.0.0/8"]}]});
        assert!(
            compile(&source, 3).is_err(),
            "default_interface_address needs version 4"
        );
        // the compiler lowers the container version to what the rules need
        let source = json!({"rules": [{"domain": ["a.com"]}]});
        assert_eq!(downgrade_version(&source, 5), 2);
        let source = json!({"rules": [{"network_type": ["wifi"]}]});
        assert_eq!(downgrade_version(&source, 5), 3);
        let source = json!({"rules": [{"default_interface_address": ["10.0.0.0/8"]}]});
        assert_eq!(downgrade_version(&source, 5), 4);
        let source = json!({"rules": [{"package_name_regex": [r"^com\."]}]});
        assert_eq!(downgrade_version(&source, 5), 5);
    }

    #[test]
    fn query_type_and_wifi_items() {
        let source = json!({
            "rules": [{
                "query_type": ["HTTPS"],
                "wifi_ssid": ["home"],
                "wifi_bssid": ["aa:bb:cc:dd:ee:ff"],
            }]
        });
        let out = round_trip(source, 3);
        assert_eq!(out["rules"][0]["query_type"], json!(["HTTPS"]));
        assert_eq!(out["rules"][0]["wifi_ssid"], json!(["home"]));
        assert_eq!(out["rules"][0]["wifi_bssid"], json!(["aa:bb:cc:dd:ee:ff"]));
    }

    #[test]
    fn legacy_v1_suffixes_use_the_legacy_matcher() {
        // version 1 keeps a suffix as both the domain and its ".domain" form
        let compiled =
            compile(&json!({"rules": [{"domain_suffix": ["legacy.com"]}]}), 1).expect("compile");
        let out = read(&compiled).expect("read");
        let suffix = out[0]
            .get("domain_suffix")
            .and_then(|v| v.as_array())
            .cloned();
        assert!(suffix.is_some_and(|list| list.contains(&json!("legacy.com"))));
    }

    // ------------------------------------------------- untrusted input

    fn uvarint(out: &mut Vec<u8>, value: u64) {
        let mut writer = Writer::default();
        writer.uvarint(value);
        out.extend_from_slice(&writer.out);
    }

    /// Wrap a raw payload into an SRS container.
    fn container(payload: &[u8], version: u8) -> Vec<u8> {
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::fast());
        encoder.write_all(payload).expect("compress");
        let mut out = MAGIC.to_vec();
        out.push(version);
        out.extend(encoder.finish().expect("compress"));
        out
    }

    fn payload_of(compiled: &[u8]) -> Vec<u8> {
        let mut payload = Vec::new();
        flate2::read::ZlibDecoder::new(&compiled[4..])
            .read_to_end(&mut payload)
            .expect("inflate");
        payload
    }

    /// One default rule holding `item` followed by `body`.
    fn one_item(item: u8, body: &[u8]) -> Vec<u8> {
        let mut payload = vec![1, 0, item];
        payload.extend_from_slice(body);
        payload.extend_from_slice(&[ITEM_FINAL, 0]);
        payload
    }

    fn read_err(payload: &[u8]) -> String {
        read(&container(payload, 4)).expect_err("corrupted payload must fail")
    }

    #[test]
    fn huge_counts_are_rejected_without_allocating() {
        // rule count: 2^60 overflowed the capacity, 2e8 asked for 6.4 GB
        for count in [1u64 << 60, 200_000_000, u64::MAX] {
            let mut payload = Vec::new();
            uvarint(&mut payload, count);
            assert!(read_err(&payload).contains("element count"), "{count}");
        }
        // logical rule count
        let mut payload = vec![1, 1, 0];
        uvarint(&mut payload, 1 << 59);
        assert!(read_err(&payload).contains("element count"));
        // IP set range count is a fixed u64
        let mut body = vec![1];
        body.extend_from_slice(&(1u64 << 58).to_be_bytes());
        assert!(read_err(&one_item(ITEM_IP_CIDR, &body)).contains("element count"));
        // every counted list inside a rule
        for item in [
            ITEM_QUERY_TYPE,
            ITEM_NETWORK,
            ITEM_DOMAIN_KEYWORD,
            ITEM_PORT,
            ITEM_NETWORK_TYPE,
            ITEM_NETWORK_INTERFACE_ADDRESS,
            ITEM_DEFAULT_INTERFACE_ADDRESS,
            ITEM_ADGUARD_DOMAIN,
        ] {
            let mut body = Vec::new();
            uvarint(&mut body, 1 << 62);
            assert!(
                read_err(&one_item(item, &body)).contains("element count"),
                "item {item}"
            );
        }
        // trie arrays: leaves, bitmap, labels
        for position in 0..3 {
            let mut body = vec![1];
            for index in 0..3 {
                uvarint(&mut body, if index == position { 1 << 61 } else { 0 });
            }
            assert!(read_err(&one_item(ITEM_DOMAIN, &body)).contains("element count"));
        }
    }

    #[test]
    fn element_count_boundary() {
        // three one-byte strings fit in three bytes, four do not
        let mut reader = Reader::new(&[3, 0, 0, 0], MAX_DECODED_SIZE);
        assert_eq!(reader.str_vec().expect("fits").len(), 3);
        let mut reader = Reader::new(&[4, 0, 0, 0], MAX_DECODED_SIZE);
        assert!(reader.str_vec().is_err());
        // u64 words are 8 bytes each
        let mut data = vec![1];
        data.extend_from_slice(&[0; 8]);
        assert_eq!(
            Reader::new(&data, MAX_DECODED_SIZE).u64_slice(),
            Ok(vec![0])
        );
        data[0] = 2;
        assert!(Reader::new(&data, MAX_DECODED_SIZE).u64_slice().is_err());
    }

    #[test]
    fn inconsistent_domain_trie_is_an_error() {
        // empty bitmap with one label: indexed past the bitmap
        let body = [1, 0, 0, 1, b'a'];
        assert!(read_err(&one_item(ITEM_DOMAIN, &body)).contains("inconsistent"));
        // a bitmap without the child's terminating one: select past the end
        let mut body = vec![1, 0, 1];
        body.extend_from_slice(&0u64.to_be_bytes());
        body.extend_from_slice(&[1, b'a']);
        assert!(read_err(&one_item(ITEM_DOMAIN, &body)).contains("inconsistent"));
        // an edge without its label
        let mut body = vec![1, 0, 1];
        body.extend_from_slice(&0b10u64.to_be_bytes());
        body.push(0);
        assert!(read_err(&one_item(ITEM_DOMAIN, &body)).contains("inconsistent"));
    }

    #[test]
    fn deep_trie_does_not_overflow_the_stack() {
        // one key is one chain of nodes; the walk used to recurse per node
        // and then kept a stack frame per node
        let long = "a".repeat(200_000);
        let compiled = compile(&json!({"rules": [{"domain": [long]}]}), 2).unwrap();
        let error = read(&compiled).unwrap_err();
        assert!(error.contains("key longer than"), "{error}");
    }

    #[test]
    fn domain_key_length_boundary() {
        for (len, ok) in [(MAX_DOMAIN_KEY_LEN, true), (MAX_DOMAIN_KEY_LEN + 1, false)] {
            let key = "a".repeat(len);
            let compiled = compile(&json!({"rules": [{"domain": [key.clone()]}]}), 2).unwrap();
            match read(&compiled) {
                Ok(rules) => {
                    assert!(ok, "{len}");
                    assert_eq!(rules[0]["domain"], json!([key]));
                }
                Err(error) => {
                    assert!(!ok, "{len}: {error}");
                    assert!(error.contains("key longer than"), "{error}");
                }
            }
        }
    }

    #[test]
    fn deep_trie_with_rare_leaves_is_rejected() {
        // a 2M-node chain with a single leaf at the end: within the payload
        // and decoded-size limits, but the walk would hold a frame and a key
        // byte per node; it must stop at the key length bound instead
        let deep = "b".repeat(2_000_000);
        let compiled = compile(&json!({"rules": [{"domain": [deep, "a.example"]}]}), 2).unwrap();
        assert!(compiled.len() < MAX_PAYLOAD_SIZE);
        let error = read(&compiled).unwrap_err();
        assert!(error.contains("key longer than"), "{error}");
    }

    #[test]
    fn decoded_size_is_bounded() {
        // "a", "aa", ...: the keys grow quadratically with the payload
        let keys: Vec<String> = (1..=2000).map(|len| "a".repeat(len)).collect();
        let compiled = compile(&json!({"rules": [{"domain": keys}]}), 2).unwrap();
        assert!(compiled.len() < 4096);
        assert_eq!(
            read(&compiled).expect("within the default limit")[0]["domain"]
                .as_array()
                .map(Vec::len),
            Some(2000)
        );
        let limits = Limits {
            payload: MAX_PAYLOAD_SIZE,
            decoded: 1 << 20,
        };
        let error = read_limited(&compiled, limits).unwrap_err();
        assert!(error.contains("too many values"), "{error}");

        // empty strings: one payload byte per value
        let mut body = Vec::new();
        uvarint(&mut body, 8_000_000);
        body.resize(body.len() + 8_000_000, 0);
        let error = read_err(&one_item(ITEM_DOMAIN_KEYWORD, &body));
        assert!(error.contains("too many values"), "{error}");
    }

    #[test]
    fn decoded_size_boundary() {
        // one rule plus ten three-byte strings
        let mut body = vec![10];
        for _ in 0..10 {
            body.extend_from_slice(&[3, b'a', b'b', b'c']);
        }
        let data = container(&one_item(ITEM_DOMAIN_KEYWORD, &body), 2);
        let cost = VALUE_COST + 10 * (3 + VALUE_COST);
        let limits = |decoded| Limits {
            payload: MAX_PAYLOAD_SIZE,
            decoded,
        };
        let rules = read_limited(&data, limits(cost)).expect("exactly at the limit");
        assert_eq!(
            rules[0]["domain_keyword"].as_array().map(Vec::len),
            Some(10)
        );
        assert!(read_limited(&data, limits(cost - 1)).is_err());
    }

    #[test]
    fn payload_size_boundary() {
        // a zero rule count followed by padding the reader ignores
        let limits = Limits {
            payload: 4096,
            decoded: MAX_DECODED_SIZE,
        };
        let at_limit = container(&[0; 4096], 2);
        assert_eq!(read_limited(&at_limit, limits), Ok(Vec::new()));
        let over = container(&[0; 4097], 2);
        let error = read_limited(&over, limits).unwrap_err();
        assert!(error.contains("exceeds 4096 bytes"), "{error}");
    }

    #[test]
    fn zip_bomb_is_rejected() {
        // ~65 KB that inflate past the default limit
        let mut encoder = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
        let chunk = vec![0u8; 1 << 20];
        for _ in 0..MAX_PAYLOAD_SIZE / chunk.len() {
            encoder.write_all(&chunk).unwrap();
        }
        encoder.write_all(&[0]).unwrap();
        let mut bomb = MAGIC.to_vec();
        bomb.push(3);
        bomb.extend(encoder.finish().unwrap());
        assert!(bomb.len() < 256 << 10);
        let error = read(&bomb).unwrap_err();
        assert!(error.contains("payload exceeds"), "{error}");
    }

    #[test]
    fn reference_container_decodes() {
        // a small list compiled by the reference (stored deflate block)
        const LOCAL: &[u8] = &[
            0x53, 0x52, 0x53, 0x02, 0x78, 0xda, 0x01, 0x58, 0x00, 0xa7, 0xff, 0x02, 0x00, 0x02,
            0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x20, 0x00, 0x00, 0x00, 0x02, 0xad, 0x55, 0x55,
            0x55, 0x55, 0x54, 0xaa, 0xaa, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x20,
            0x65, 0x6c, 0x70, 0x6d, 0x61, 0x78, 0x65, 0x2e, 0x74, 0xd0, 0x73, 0xb9, 0x69, 0xd0,
            0x6c, 0xbe, 0x2d, 0xd0, 0x6c, 0xb3, 0x61, 0xd1, 0x63, 0x83, 0x6f, 0xd1, 0x6c, 0x80,
            0x0a, 0xd0, 0xb4, 0x0a, 0xff, 0x00, 0x00, 0x06, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x01, 0x04, 0xcb, 0x00, 0x71, 0x00, 0x04, 0xcb, 0x00, 0x71, 0xff, 0xff,
            0x00, 0xd7, 0x0b, 0x19, 0x5d,
        ];
        assert_eq!(
            read(LOCAL).expect("read"),
            vec![
                json!({"domain_suffix": ["local-list.example", "другой.example"]}),
                json!({"ip_cidr": ["203.0.113.0/24"]}),
            ]
        );
    }

    #[test]
    fn larger_list_round_trip() {
        let domains: Vec<String> = (0..3000).map(|i| format!("host{i}.example.com")).collect();
        let suffixes: Vec<String> = (0..3000).map(|i| format!("site{i}.example.net")).collect();
        let source = json!({
            "rules": [
                {"domain": domains, "domain_suffix": suffixes},
                {"ip_cidr": ["10.0.0.0/8", "2001:db8::/32"], "port": [53, 443]},
                {"type": "logical", "mode": "and", "rules": [
                    {"domain_keyword": ["ads"]}, {"network": ["udp"]}
                ]},
            ]
        });
        let out = round_trip(source.clone(), 2);
        let mut expected_domains = domains.clone();
        expected_domains.sort();
        let mut expected_suffixes = suffixes.clone();
        expected_suffixes.sort();
        assert_eq!(out["rules"][0]["domain"], json!(expected_domains));
        assert_eq!(out["rules"][0]["domain_suffix"], json!(expected_suffixes));
        assert_eq!(out["rules"][1], source["rules"][1]);
        assert_eq!(out["rules"][2], source["rules"][2]);
    }

    #[test]
    fn mutated_inputs_never_panic() {
        let seeds: Vec<Vec<u8>> = [
            json!({"rules": [{
                "domain": ["a.com", "b.org", "cc.net"],
                "domain_suffix": ["x.com", ".y.com"],
                "domain_keyword": ["k"],
                "ip_cidr": ["1.2.3.0/24", "::1/128"],
                "port": [80, 443],
                "query_type": ["A"],
            }]}),
            json!({"rules": [{"type": "logical", "mode": "or", "rules": [
                {"domain": ["q.com"]}, {"port_range": ["1:5"]}
            ]}]}),
            json!({"rules": [{
                "network_type": ["wifi"],
                "network_interface_address": {"wifi": ["192.168.1.0/24"]},
                "default_interface_address": ["10.0.0.0/8"],
            }]}),
        ]
        .iter()
        .map(|source| payload_of(&compile(source, 4).unwrap()))
        .collect();
        let mut state: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..4000 {
            let mut payload = seeds[(next() % seeds.len() as u64) as usize].clone();
            for _ in 0..1 + next() % 4 {
                let position = (next() as usize) % payload.len();
                match next() % 4 {
                    0 => payload[position] = next() as u8,
                    1 => payload[position] ^= 1 << (next() % 8),
                    2 => payload.truncate(position.max(1)),
                    _ => payload.insert(position, next() as u8),
                }
            }
            let mut data = container(&payload, 4);
            if next() % 8 == 0 {
                // damage the zlib stream itself
                let position = 4 + (next() as usize) % (data.len() - 4);
                data[position] ^= next() as u8 | 1;
            }
            let _ = read(&data);
        }
    }
}
