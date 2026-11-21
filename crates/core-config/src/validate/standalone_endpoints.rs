//! Schema checks offered by the standalone CLI for endpoints it cannot run.

use super::*;

const OVPN_CLIENT: &str = "OpenVPNClientEndpointOptions";
const OVPN_SERVER: &str = "OpenVPNServerEndpointOptions";
const OC_EP: &str = "OpenConnectEndpointOptions";

/// reference `option.OpenVPNServerEndpointOptions`: ListenOptions (incl. the
/// embedded InboundOptions decode fields) + `OpenVPNEndpointOptions` +
/// server fields. No dialer fields on the server side.
const KNOWN_OVPN_SERVER_FIELDS: &[&str] = &[
    "type",
    "tag",
    "listen",
    "listen_port",
    "bind_interface",
    "routing_mark",
    "reuse_addr",
    "netns",
    "disable_tcp_keep_alive",
    "tcp_keep_alive",
    "tcp_keep_alive_interval",
    "tcp_fast_open",
    "tcp_multi_path",
    "udp_fragment",
    "udp_timeout",
    "detour",
    "proxy_protocol",
    "proxy_protocol_accept_no_header",
    "sniff",
    "sniff_override_destination",
    "sniff_timeout",
    "domain_strategy",
    "udp_disable_domain_unmapping",
    "system",
    "name",
    "mtu",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "mode",
    "network",
    "remote",
    "remote_port",
    "max_clients",
    "address",
    "peer_address",
    "peer_address_ipv6",
    "topology",
    "duplicate_cn",
    "users",
    "static_key",
    "static_key_path",
    "key_direction",
    "tls",
    "cipher",
    "data_ciphers",
    "data_ciphers_fallback",
    "auth",
    "mss_fix",
    "mss_fix_disabled",
    "mss_fix_mode",
    "replay_window",
    "replay_window_time",
    "push",
    "ping_interval",
    "ping_restart",
    "renegotiate_interval",
    "renegotiate_disabled",
    "renegotiate_bytes",
    "renegotiate_packets",
    "handshake_window",
];

/// reference `option.TailscaleEndpointOptions` + wrapper.
const KNOWN_OPENCONNECT_FIELDS: &[&str] = &[
    "type",
    "tag",
    "system",
    "name",
    "udp_timeout",
    "udp_mapping",
    "udp_filtering",
    "udp_nat_max",
    "server",
    "flavor",
    "username",
    "password",
    "auth_group",
    "cookie",
    "token",
    "reported_os",
    "user_agent",
    "version",
    "local_hostname",
    "mobile",
    "csd",
    "hip",
    "tncc",
    "fortinet_host_check",
    "no_udp",
    "dtls_local_port",
    "compression_disabled",
    "compression_mode",
    "ipv6_disabled",
    "http_keepalive_disabled",
    "xml_post_disabled",
    "external_auth_disabled",
    "password_authentication_disabled",
    "tcp_keep_alive_enabled",
    "pfs",
    "mtu",
    "base_mtu",
    "dpd_interval",
    "reconnect_timeout",
    "trojan_interval",
    "queue_length",
    "allow_insecure_crypto",
    "tls",
    "form_entries",
];

const KNOWN_OVPN_TLS_IN_FIELDS: &[&str] = &[
    "certificate",
    "certificate_path",
    "key",
    "key_path",
    "client_certificate",
    "client_certificate_path",
    "verify_client_certificate",
    "client_name",
    "client_name_type",
    "peer_fingerprint",
    "crl_path",
    "remote_certificate_ku",
    "remote_certificate_eku",
    "remote_certificate_tls",
    "certificate_profile",
    "ns_certificate_type",
    "version_min",
    "version_max",
    "cipher",
    "groups",
    "control_wrap",
];

const KNOWN_OVPN_CWRAP_FIELDS: &[&str] = &["type", "key", "key_path", "direction"];
const KNOWN_OVPN_CWRAP_IN_FIELDS: &[&str] =
    &["type", "key", "key_path", "direction", "force_cookie"];
const KNOWN_OVPN_USER_FIELDS: &[&str] = &["username", "password"];
const KNOWN_OVPN_PUSH_FIELDS: &[&str] = &[
    "routes",
    "dns",
    "dns_servers",
    "search_domains",
    "dhcp_options",
    "redirect_gateway",
    "redirect_gateway_flags",
    "block_outside_dns",
    "ping_interval",
    "ping_restart",
];
const KNOWN_OVPN_PUSH_DNS_SERVER_FIELDS: &[&str] = &[
    "priority",
    "addresses",
    "resolve_domains",
    "dnssec",
    "transport",
    "sni",
];
const KNOWN_OC_TOKEN_FIELDS: &[&str] = &[
    "mode",
    "secret",
    "secret_path",
    "pin",
    "password",
    "device_id",
    "counter",
];
const KNOWN_OC_TLS_FIELDS: &[&str] = &[
    "insecure",
    "server_name",
    "peer_fingerprint",
    "system_trust_disabled",
    "certificate_authority",
    "certificate_authority_path",
    "client_certificate",
    "client_certificate_path",
    "client_key",
    "client_key_path",
    "client_key_password",
    "mca_certificate",
    "mca_certificate_path",
    "mca_key",
    "mca_key_path",
    "mca_key_password",
];
const KNOWN_OC_MOBILE_FIELDS: &[&str] = &["platform_version", "device_type", "device_unique_id"];
const KNOWN_OC_WRAPPER_FIELDS: &[&str] = &["wrapper_path"];
const KNOWN_OC_TNCC_FIELDS: &[&str] = &[
    "wrapper_path",
    "device_id",
    "user_agent",
    "machine_identification_enabled",
    "certificates",
];
const KNOWN_OC_TNCC_CERT_FIELDS: &[&str] = &["certificate", "certificate_path"];
const KNOWN_OC_FORTINET_FIELDS: &[&str] = &["hostcheck", "check_virtual_desktop"];
const KNOWN_OC_FORM_ENTRY_FIELDS: &[&str] =
    &["form_id", "submission_key", "name", "value", "promote"];

const OVPN_SERVER_PROTOCOLS: &[&str] = &["", "udp", "tcp"];
const OVPN_MODES: &[&str] = &["", "tls", "static_key"];
const OVPN_TOPOLOGIES: &[&str] = &["", "net30", "p2p", "subnet"];
const OVPN_KEY_DIRECTIONS: &[&str] = &["", "server", "client"];
const OC_FLAVORS: &[&str] = &["", "anyconnect", "gp", "fortinet", "f5", "pulse", "nc"];
const OVPN_REMOTE_CERT_TLS: &[&str] = &["", "server", "client", "none"];
fn openvpn_server_tls_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].tls");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_SERVER,
                "tls",
                "option.OpenVPNInboundTLSOptions",
            ));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_TLS_IN_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in [
        "certificate_path",
        "key_path",
        "client_certificate_path",
        "verify_client_certificate",
        "client_name",
        "client_name_type",
        "crl_path",
        "remote_certificate_eku",
        "remote_certificate_tls",
        "certificate_profile",
        "ns_certificate_type",
        "version_min",
        "version_max",
        "cipher",
        "groups",
    ] {
        if let Some(v) = m.get(f) {
            ep_str(v, &format!("{at}.{f}"), OVPN_SERVER, &format!("tls.{f}"))?;
        }
    }
    for f in [
        "certificate",
        "key",
        "client_certificate",
        "peer_fingerprint",
        "remote_certificate_ku",
    ] {
        if let Some(v) = m.get(f) {
            check_listable_string(v, &format!("{at}.{f}"))?;
        }
    }
    if let Some(v) = m.get("control_wrap") {
        openvpn_control_wrap_decode(i, v, true)?;
    }
    Ok(())
}

fn openvpn_control_wrap_decode(i: usize, value: &Value, inbound: bool) -> Result<(), String> {
    let at = format!("endpoints[{i}].tls.control_wrap");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                if inbound { OVPN_SERVER } else { OVPN_CLIENT },
                "tls.control_wrap",
                if inbound {
                    "option.OpenVPNInboundControlWrapOptions"
                } else {
                    "option.OpenVPNControlWrapOptions"
                },
            ));
        }
    };
    let known: &[&str] = if inbound {
        KNOWN_OVPN_CWRAP_IN_FIELDS
    } else {
        KNOWN_OVPN_CWRAP_FIELDS
    };
    for key in m.keys() {
        let k = key.as_str();
        if !known.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in ["type", "direction"] {
        if let Some(v) = m.get(f) {
            ep_str(
                v,
                &format!("{at}.{f}"),
                if inbound { OVPN_SERVER } else { OVPN_CLIENT },
                &format!("tls.control_wrap.{f}"),
            )?;
        }
    }
    for f in ["key", "key_path"] {
        if let Some(v) = m.get(f) {
            check_listable_string(v, &format!("{at}.{f}"))?;
        }
    }
    if inbound && let Some(v) = m.get("force_cookie") {
        ep_bool(
            v,
            &format!("{at}.force_cookie"),
            OVPN_SERVER,
            "tls.control_wrap.force_cookie",
        )?;
    }
    Ok(())
}

pub(super) fn openvpn_server_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_SERVER_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    let listen = format!("{OVPN_SERVER}.ListenOptions");
    if let Some(v) = obj.get("listen") {
        ep_str(v, &format!("{at}.listen"), &listen, "listen")?;
    }
    if let Some(v) = obj.get("listen_port") {
        ep_unsigned(
            v,
            &format!("{at}.listen_port"),
            &listen,
            "listen_port",
            u16::MAX as u64,
        )?;
    }
    for f in ["bind_interface", "netns"] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), &listen, f)?;
        }
    }
    if let Some(v) = obj.get("routing_mark") {
        check_routing_mark(v, &format!("{at}.routing_mark"))?;
    }
    for f in [
        "reuse_addr",
        "disable_tcp_keep_alive",
        "tcp_fast_open",
        "tcp_multi_path",
        "udp_fragment",
        "proxy_protocol",
        "proxy_protocol_accept_no_header",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), &listen, f)?;
        }
    }
    for f in ["tcp_keep_alive", "tcp_keep_alive_interval", "udp_timeout"] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), &listen, f)?;
        }
    }
    if let Some(v) = obj.get("detour") {
        match v {
            Value::String(_) | Value::Null => {}
            Value::Object(map) if map.is_empty() => {}
            other => {
                return Err(go_field_err(
                    &format!("{at}.detour"),
                    other,
                    &listen,
                    "detour",
                    "string",
                ));
            }
        }
    }
    let inb = format!("{OVPN_SERVER}.ListenOptions.InboundOptions");
    if let Some(v) = obj.get("sniff") {
        ep_bool(v, &format!("{at}.sniff"), &inb, "sniff")?;
    }
    if let Some(v) = obj.get("sniff_override_destination") {
        ep_bool(
            v,
            &format!("{at}.sniff_override_destination"),
            &inb,
            "sniff_override_destination",
        )?;
    }
    if let Some(v) = obj.get("sniff_timeout") {
        check_duration_field(v, &format!("{at}.sniff_timeout"), &inb, "sniff_timeout")?;
    }
    if let Some(v) = obj.get("udp_disable_domain_unmapping") {
        ep_bool(
            v,
            &format!("{at}.udp_disable_domain_unmapping"),
            &inb,
            "udp_disable_domain_unmapping",
        )?;
    }
    if let Some(v) = obj.get("domain_strategy") {
        match v {
            Value::String(s) if DOMAIN_STRATEGIES.contains(&s.as_str()) => {}
            Value::String(s) => {
                return Err(format!(
                    "{at}.domain_strategy: unknown domain strategy: {s}"
                ));
            }
            x if is_zero_json(x) => {}
            other => {
                return Err(go_field_err(
                    &format!("{at}.domain_strategy"),
                    other,
                    &inb,
                    "domain_strategy",
                    "string",
                ));
            }
        }
    }
    let epc = format!("{OVPN_SERVER}.OpenVPNEndpointOptions");
    if let Some(v) = obj.get("system") {
        ep_bool(v, &format!("{at}.system"), &epc, "system")?;
    }
    if let Some(v) = obj.get("name") {
        ep_str(v, &format!("{at}.name"), &epc, "name")?;
    }
    if let Some(v) = obj.get("mtu") {
        ep_unsigned(v, &format!("{at}.mtu"), &epc, "mtu", u32::MAX as u64)?;
    }
    if let Some(v) = obj.get("udp_mapping") {
        check_udp_nat(v, &format!("{at}.udp_mapping"), &epc, "udp_mapping")?;
    }
    if let Some(v) = obj.get("udp_filtering") {
        check_udp_nat(v, &format!("{at}.udp_filtering"), &epc, "udp_filtering")?;
    }
    if let Some(v) = obj.get("udp_nat_max") {
        ep_unsigned(
            v,
            &format!("{at}.udp_nat_max"),
            &epc,
            "udp_nat_max",
            u32::MAX as u64,
        )?;
    }
    for f in [
        "mode",
        "network",
        "remote",
        "topology",
        "key_direction",
        "cipher",
        "auth",
        "mss_fix_mode",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    for f in ["duplicate_cn", "mss_fix_disabled"] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    if let Some(v) = obj.get("remote_port") {
        ep_unsigned(
            v,
            &format!("{at}.remote_port"),
            OVPN_SERVER,
            "remote_port",
            u16::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("max_clients") {
        ep_int(v, &format!("{at}.max_clients"), OVPN_SERVER, "max_clients")?;
    }
    for f in ["mss_fix", "replay_window"] {
        if let Some(v) = obj.get(f) {
            ep_unsigned(v, &format!("{at}.{f}"), OVPN_SERVER, f, u32::MAX as u64)?;
        }
    }
    for f in ["renegotiate_bytes", "renegotiate_packets"] {
        if let Some(v) = obj.get(f) {
            check_u64_field(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    for f in [
        "replay_window_time",
        "ping_interval",
        "ping_restart",
        "renegotiate_interval",
        "handshake_window",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    if let Some(v) = obj.get("address") {
        check_prefix_list(v, &format!("{at}.address"))?;
    }
    for f in ["peer_address", "peer_address_ipv6"] {
        if let Some(v) = obj.get(f) {
            check_addr_field(v, &format!("{at}.{f}"), OVPN_SERVER, f)?;
        }
    }
    if let Some(v) = obj.get("data_ciphers") {
        check_listable_string(v, &format!("{at}.data_ciphers"))?;
    }
    if let Some(v) = obj.get("data_ciphers_fallback") {
        ep_str(
            v,
            &format!("{at}.data_ciphers_fallback"),
            OVPN_SERVER,
            "data_ciphers_fallback",
        )?;
    }
    if let Some(v) = obj.get("static_key") {
        check_listable_string(v, &format!("{at}.static_key"))?;
    }
    if let Some(v) = obj.get("static_key_path") {
        ep_str(
            v,
            &format!("{at}.static_key_path"),
            OVPN_SERVER,
            "static_key_path",
        )?;
    }
    if let Some(v) = obj.get("users") {
        openvpn_users_decode(i, v)?;
    }
    if let Some(v) = obj.get("push") {
        openvpn_push_decode(i, v)?;
    }
    if let Some(v) = obj.get("tls") {
        openvpn_server_tls_decode(i, v)?;
    }
    Ok(())
}

fn openvpn_users_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].users");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_SERVER,
                "users",
                "[]auth.User",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type auth.User",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OVPN_USER_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        for f in KNOWN_OVPN_USER_FIELDS {
            if let Some(v) = m.get(*f) {
                ep_str(v, &format!("{path}.{f}"), "User", f)?;
            }
        }
    }
    Ok(())
}

fn openvpn_push_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].push");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OVPN_SERVER,
                "push",
                "option.OpenVPNPushOptions",
            ));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !KNOWN_OVPN_PUSH_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    if let Some(v) = m.get("routes") {
        check_prefix_list(v, &format!("{at}.routes"))?;
    }
    if let Some(v) = m.get("dns") {
        check_listable_addr(v, &format!("{at}.dns"))?;
    }
    if let Some(v) = m.get("search_domains") {
        check_listable_string(v, &format!("{at}.search_domains"))?;
    }
    if let Some(v) = m.get("dhcp_options") {
        check_listable_string(v, &format!("{at}.dhcp_options"))?;
    }
    if let Some(v) = m.get("redirect_gateway_flags") {
        check_listable_string(v, &format!("{at}.redirect_gateway_flags"))?;
    }
    for f in ["redirect_gateway", "block_outside_dns"] {
        if let Some(v) = m.get(f) {
            ep_bool(v, &format!("{at}.{f}"), "OpenVPNPushOptions", f)?;
        }
    }
    for f in ["ping_interval", "ping_restart"] {
        if let Some(v) = m.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), "OpenVPNPushOptions", f)?;
        }
    }
    if let Some(v) = m.get("dns_servers") {
        openvpn_push_dns_servers_decode(i, v)?;
    }
    Ok(())
}

fn openvpn_push_dns_servers_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].push.dns_servers");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                "OpenVPNPushOptions",
                "dns_servers",
                "[]option.OpenVPNPushDNSServerOptions",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type option.OpenVPNPushDNSServerOptions",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OVPN_PUSH_DNS_SERVER_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        if let Some(v) = m.get("priority") {
            ep_int(
                v,
                &format!("{path}.priority"),
                "OpenVPNPushDNSServerOptions",
                "priority",
            )?;
        }
        for f in ["addresses", "resolve_domains"] {
            if let Some(v) = m.get(f) {
                check_listable_string(v, &format!("{path}.{f}"))?;
            }
        }
        for f in ["dnssec", "transport", "sni"] {
            if let Some(v) = m.get(f) {
                ep_str(v, &format!("{path}.{f}"), "OpenVPNPushDNSServerOptions", f)?;
            }
        }
    }
    Ok(())
}

pub(super) fn openconnect_decode(i: usize, obj: &Map<String, Value>) -> Result<(), String> {
    let at = format!("endpoints[{i}]");
    for key in obj.keys() {
        let k = key.as_str();
        if !KNOWN_OPENCONNECT_FIELDS.contains(&k) && !DIALER_OUT_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    if let Some(v) = obj.get("system") {
        ep_bool(v, &format!("{at}.system"), OC_EP, "system")?;
    }
    if let Some(v) = obj.get("name") {
        ep_str(v, &format!("{at}.name"), OC_EP, "name")?;
    }
    if let Some(v) = obj.get("mtu") {
        ep_unsigned(v, &format!("{at}.mtu"), OC_EP, "mtu", u32::MAX as u64)?;
    }
    if let Some(v) = obj.get("base_mtu") {
        ep_unsigned(
            v,
            &format!("{at}.base_mtu"),
            OC_EP,
            "base_mtu",
            u32::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("dtls_local_port") {
        ep_unsigned(
            v,
            &format!("{at}.dtls_local_port"),
            OC_EP,
            "dtls_local_port",
            u16::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("queue_length") {
        ep_unsigned(
            v,
            &format!("{at}.queue_length"),
            OC_EP,
            "queue_length",
            u32::MAX as u64,
        )?;
    }
    if let Some(v) = obj.get("udp_mapping") {
        check_udp_nat(v, &format!("{at}.udp_mapping"), OC_EP, "udp_mapping")?;
    }
    if let Some(v) = obj.get("udp_filtering") {
        check_udp_nat(v, &format!("{at}.udp_filtering"), OC_EP, "udp_filtering")?;
    }
    if let Some(v) = obj.get("udp_nat_max") {
        ep_unsigned(
            v,
            &format!("{at}.udp_nat_max"),
            OC_EP,
            "udp_nat_max",
            u32::MAX as u64,
        )?;
    }
    for f in [
        "server",
        "flavor",
        "username",
        "password",
        "auth_group",
        "cookie",
        "reported_os",
        "user_agent",
        "version",
        "local_hostname",
        "compression_mode",
    ] {
        if let Some(v) = obj.get(f) {
            ep_str(v, &format!("{at}.{f}"), OC_EP, f)?;
        }
    }
    for f in [
        "no_udp",
        "compression_disabled",
        "ipv6_disabled",
        "http_keepalive_disabled",
        "xml_post_disabled",
        "external_auth_disabled",
        "password_authentication_disabled",
        "tcp_keep_alive_enabled",
        "pfs",
        "allow_insecure_crypto",
    ] {
        if let Some(v) = obj.get(f) {
            ep_bool(v, &format!("{at}.{f}"), OC_EP, f)?;
        }
    }
    for f in [
        "udp_timeout",
        "dpd_interval",
        "reconnect_timeout",
        "trojan_interval",
    ] {
        if let Some(v) = obj.get(f) {
            check_duration_field(v, &format!("{at}.{f}"), OC_EP, f)?;
        }
    }
    if let Some(v) = obj.get("token") {
        openconnect_object_decode(
            i,
            v,
            "token",
            OC_EP,
            "option.OpenConnectTokenOptions",
            KNOWN_OC_TOKEN_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("mobile") {
        openconnect_object_decode(
            i,
            v,
            "mobile",
            OC_EP,
            "option.OpenConnectMobileOptions",
            KNOWN_OC_MOBILE_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("csd") {
        openconnect_object_decode(
            i,
            v,
            "csd",
            OC_EP,
            "option.OpenConnectCSDOptions",
            KNOWN_OC_WRAPPER_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("hip") {
        openconnect_object_decode(
            i,
            v,
            "hip",
            OC_EP,
            "option.OpenConnectHIPOptions",
            KNOWN_OC_WRAPPER_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("fortinet_host_check") {
        openconnect_object_decode(
            i,
            v,
            "fortinet_host_check",
            OC_EP,
            "option.OpenConnectFortinetHostCheckOptions",
            KNOWN_OC_FORTINET_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("tncc") {
        openconnect_tncc_decode(i, v)?;
    }
    if let Some(v) = obj.get("tls") {
        openconnect_object_decode(
            i,
            v,
            "tls",
            OC_EP,
            "option.OpenConnectTLSOptions",
            KNOWN_OC_TLS_FIELDS,
        )?;
    }
    if let Some(v) = obj.get("form_entries") {
        openconnect_form_entries_decode(i, v)?;
    }
    endpoint_dial_decode(
        &at,
        obj,
        &format!("{OC_EP}.DialerOptions"),
        &format!("{OC_EP}.DialerOptions.AbstractDialerOptions"),
    )
}

fn openconnect_object_decode(
    i: usize,
    value: &Value,
    field: &str,
    outer: &str,
    go_ty: &str,
    known: &[&str],
) -> Result<(), String> {
    let at = format!("endpoints[{i}].{field}");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(&at, other, outer, field, go_ty));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !known.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for k in known {
        if let Some(v) = m.get(*k) {
            match v {
                Value::Bool(_) | Value::Null => {}
                Value::Number(_) if *k == "counter" => {}
                Value::String(_) => {}
                x if is_zero_json(x) => {}
                other => {
                    let ty = if *k == "counter" { "uint64" } else { "string" };
                    return Err(go_field_err(
                        &format!("{at}.{k}"),
                        other,
                        outer,
                        &format!("{field}.{k}"),
                        ty,
                    ));
                }
            }
        }
    }
    Ok(())
}

fn openconnect_tncc_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].tncc");
    let m = match value {
        Value::Object(m) => m,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OC_EP,
                "tncc",
                "option.OpenConnectTNCCOptions",
            ));
        }
    };
    for key in m.keys() {
        let k = key.as_str();
        if !KNOWN_OC_TNCC_FIELDS.contains(&k) {
            return Err(format!("{at}.{k}: json: unknown field \"{k}\""));
        }
    }
    for f in ["wrapper_path", "device_id", "user_agent"] {
        if let Some(v) = m.get(f) {
            ep_str(v, &format!("{at}.{f}"), OC_EP, &format!("tncc.{f}"))?;
        }
    }
    if let Some(v) = m.get("machine_identification_enabled") {
        ep_bool(
            v,
            &format!("{at}.machine_identification_enabled"),
            OC_EP,
            "tncc.machine_identification_enabled",
        )?;
    }
    if let Some(v) = m.get("certificates") {
        let items = match v {
            Value::Array(items) => items,
            Value::Null => return Ok(()),
            other => {
                return Err(go_field_err(
                    &format!("{at}.certificates"),
                    other,
                    OC_EP,
                    "tncc.certificates",
                    "[]option.OpenConnectTNCCCertificateOptions",
                ));
            }
        };
        for (n, item) in items.iter().enumerate() {
            let path = format!("{at}.certificates[{n}]");
            let cm = match item {
                Value::Object(cm) => cm,
                other => {
                    return Err(format!(
                        "{path}: json: cannot unmarshal {} into Go value of type option.OpenConnectTNCCCertificateOptions",
                        json_kind(other)
                    ));
                }
            };
            for key in cm.keys() {
                let k = key.as_str();
                if !KNOWN_OC_TNCC_CERT_FIELDS.contains(&k) {
                    return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
                }
            }
            if let Some(cv) = cm.get("certificate") {
                check_listable_string(cv, &format!("{path}.certificate"))?;
            }
            if let Some(cv) = cm.get("certificate_path") {
                ep_str(
                    cv,
                    &format!("{path}.certificate_path"),
                    "OpenConnectTNCCCertificateOptions",
                    "certificate_path",
                )?;
            }
        }
    }
    Ok(())
}

fn openconnect_form_entries_decode(i: usize, value: &Value) -> Result<(), String> {
    let at = format!("endpoints[{i}].form_entries");
    let items = match value {
        Value::Array(items) => items,
        Value::Null => return Ok(()),
        other => {
            return Err(go_field_err(
                &at,
                other,
                OC_EP,
                "form_entries",
                "[]option.OpenConnectFormEntryOptions",
            ));
        }
    };
    for (n, item) in items.iter().enumerate() {
        let path = format!("{at}[{n}]");
        let m = match item {
            Value::Object(m) => m,
            other => {
                return Err(format!(
                    "{path}: json: cannot unmarshal {} into Go value of type option.OpenConnectFormEntryOptions",
                    json_kind(other)
                ));
            }
        };
        for key in m.keys() {
            let k = key.as_str();
            if !KNOWN_OC_FORM_ENTRY_FIELDS.contains(&k) {
                return Err(format!("{path}.{k}: json: unknown field \"{k}\""));
            }
        }
        for &f in KNOWN_OC_FORM_ENTRY_FIELDS {
            if let Some(v) = m.get(f) {
                match f {
                    "promote" => {
                        ep_bool(v, &format!("{path}.{f}"), "OpenConnectFormEntryOptions", f)?
                    }
                    _ => ep_str(v, &format!("{path}.{f}"), "OpenConnectFormEntryOptions", f)?,
                }
            }
        }
    }
    Ok(())
}

/// `uint64` struct field: non-negative numbers OK.
fn check_u64_field(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        v if is_zero_json(v) => Ok(()),
        Value::Number(n) if n.as_u64().is_some() => Ok(()),
        Value::Number(_) => Err(format!(
            "{at}: json: cannot unmarshal number {} into Go struct field {go_struct}.{field} of type uint64",
            go_number_literal(value)
        )),
        other => Err(go_field_err(at, other, go_struct, field, "uint64")),
    }
}

/// `*badoption.Addr` struct field: null / string / empty object OK.
fn check_addr_field(value: &Value, at: &str, go_struct: &str, field: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            if s.parse::<std::net::IpAddr>().is_ok() {
                Ok(())
            } else {
                Err(format!("{at}: ParseAddr({s:?}): unable to parse IP"))
            }
        }
        Value::Object(m) if m.is_empty() => Ok(()),
        other => Err(go_field_err(at, other, go_struct, field, "netip.Addr")),
    }
}

/// `badoption.Listable[netip.Addr]` decode: single address or array; the
/// reference union error keeps both attempts (`... | ParseAddr(...): ...`).
fn check_listable_addr(value: &Value, at: &str) -> Result<(), String> {
    match value {
        Value::Null => Ok(()),
        Value::String(s) => {
            if s.parse::<std::net::IpAddr>().is_ok() {
                Ok(())
            } else {
                Err(format!(
                    "{at}: (netip.ParseAddr({s:?}): unable to parse IP | json: cannot unmarshal string into Go value of type **netip.Addr)"
                ))
            }
        }
        Value::Array(items) => {
            for item in items {
                match item {
                    Value::Null => {}
                    Value::String(s) if s.parse::<std::net::IpAddr>().is_ok() => {}
                    Value::String(s) => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type **netip.Addr | ParseAddr({s:?}): unable to parse IP)"
                        ));
                    }
                    other => {
                        return Err(format!(
                            "{at}: (json: cannot unmarshal array into Go value of type **netip.Addr | json: cannot unmarshal {} into Go value of type netip.Addr)",
                            json_kind(other)
                        ));
                    }
                }
            }
            Ok(())
        }
        other => {
            let kind = json_kind(other);
            Err(format!(
                "{at}: (json: cannot unmarshal {kind} into Go value of type string | json: cannot unmarshal {kind} into Go value of type **netip.Addr)"
            ))
        }
    }
}

// ---------------------------------------------------------------------------
const OVPN_CLIENT_CERT_POLICY: &[&str] = &["", "require", "optional", "none"];
const OC_COMPRESSION_MODES: &[&str] = &["stateless", "all"];
const OC_TOKEN_MODES: &[&str] = &["totp", "hotp", "stoken", "oidc"];
const OC_PROTOCOL_BAD: &[char] = &['\x00', '\r', '\n'];

fn ep_bool_val(obj: &Map<String, Value>, key: &str) -> bool {
    obj.get(key).and_then(Value::as_bool).unwrap_or(false)
}

fn ep_u64_val(obj: &Map<String, Value>, key: &str) -> u64 {
    obj.get(key).and_then(Value::as_u64).unwrap_or(0)
}

/// duration field → nanoseconds (decode already rejected bad text).
fn ep_ns(obj: &Map<String, Value>, key: &str) -> i128 {
    obj.get(key)
        .and_then(Value::as_str)
        .and_then(go_duration_ns)
        .unwrap_or(0)
}

/// nested object present (post-prune: non-null only; `tls: {}` prunes to nil).
fn ovpn_nested_present(obj: &Map<String, Value>, key: &str) -> bool {
    matches!(obj.get(key), Some(v) if !v.is_null() && !prunes_value(v))
}

/// `badoption.Listable` length: string (even `""`) → 1, array → len, else 0.
fn ovpn_listable_len(value: Option<&Value>) -> usize {
    match value {
        Some(Value::String(_)) => 1,
        Some(Value::Array(items)) => items.len(),
        _ => 0,
    }
}

fn ovpn_listable_values(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::String(s)) => vec![s.clone()],
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| v.as_str().unwrap_or("").to_string())
            .collect(),
        _ => Vec::new(),
    }
}

/// reference `materialSource`: inline list joined with `\n`.
fn ovpn_material_content(value: Option<&Value>) -> String {
    tls_listable_join(value)
}

fn ovpn_material_is_set(content: &str, path: &str) -> bool {
    !content.is_empty() || !path.is_empty()
}

/// `material.Validate`: conflict only.
fn ovpn_material_source(name: &str, value: Option<&Value>, path: &str) -> Result<String, String> {
    let content = ovpn_material_content(value);
    if !path.is_empty() && !content.is_empty() {
        return Err(format!("material path and content are both set: {name}"));
    }
    Ok(content)
}

fn ovpn_required_material_source(
    name: &str,
    value: Option<&Value>,
    path: &str,
) -> Result<String, String> {
    let content = ovpn_material_source(name, value, path)?;
    if !ovpn_material_is_set(&content, path) {
        return Err(format!("missing `{name}` or `{name}_path`"));
    }
    Ok(content)
}

/// `keyDirectionValue` (protocol/openvpn/endpoint.go).
fn ovpn_key_direction_value(direction: &str) -> Result<i32, String> {
    if !OVPN_KEY_DIRECTIONS.contains(&direction) {
        return Err(format!(
            "unsupported key direction: {direction} (expected \"server\" or \"client\")"
        ));
    }
    Ok(match direction {
        "" => -1,
        "server" => 0,
        _ => 1,
    })
}

/// control-wrap activity: `Type/Key/KeyPath/Direction` (+ `ForceCookie` server-side).
fn ovpn_control_wrap_active(wrap: &Map<String, Value>, force_cookie_counts: bool) -> bool {
    let wrap_type = wrap.get("type").and_then(Value::as_str).unwrap_or("");
    let key_path = wrap.get("key_path").and_then(Value::as_str).unwrap_or("");
    let direction = wrap.get("direction").and_then(Value::as_str).unwrap_or("");
    !wrap_type.is_empty()
        || ovpn_listable_len(wrap.get("key")) > 0
        || !key_path.is_empty()
        || !direction.is_empty()
        || (force_cookie_counts && ep_bool_val(wrap, "force_cookie"))
}

// ---------------------------------------------------------------------------
// openvpn client library phase helpers: compression, allow-compression,
// remotes (resolveClientRemotes) — sing-openvpn compression_options.go,
// allow_compression.go, client_supervisor.go.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// openvpn-client initialize — sbx-src protocol/openvpn/client.go
// buildClientOptions (157) → buildClientTunnelOptions (407) →
// buildStaticKeyClientOptions (316) / tls branch (181) → NewClient library
// phase (sing-openvpn client.go NewClient → validateImplementedClientOptions).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// openvpn-server initialize — sbx-src protocol/openvpn/server.go
// NewServerEndpoint → buildServerOptions (264) at check time; the ovpn.NewServer
// library (validateImplementedServerOptions / validateServerTunnelOptions /
// validateServerResourceOptions / applyServerPush DNSSEC etc.) runs at Start()
// and is unreachable during `check`.
// ---------------------------------------------------------------------------

pub(super) fn openvpn_server_initialize(
    _i: usize,
    _tag: &str,
    obj: &Map<String, Value>,
) -> Result<(), String> {
    let mode = endpoint_str(obj, "mode");
    let mode = if mode.is_empty() { "tls" } else { mode };
    if !OVPN_MODES.contains(&mode) {
        return Err(format!(
            "unsupported mode: {mode} (expected \"tls\" or \"static_key\")"
        ));
    }
    let mut addresses: Vec<String> = Vec::new();
    if let Some(Value::Array(items)) = obj.get("address") {
        for item in items {
            match item.as_str() {
                Some(s) => addresses.push(s.to_string()),
                None => return Err("server address[0] is invalid".to_string()),
            }
        }
    }
    if addresses.is_empty() {
        return Err("missing server address".to_string());
    }
    // validateServerAddresses: sequential duplicate/validity scan.
    let mut has4 = false;
    let mut has6 = false;
    for (addr_index, address) in addresses.iter().enumerate() {
        let host = address.split('/').next().unwrap_or("");
        match parse_ip_addr(host) {
            Some(true) => {
                if has4 {
                    return Err("multiple IPv4 server address pools are not supported".to_string());
                }
                has4 = true;
            }
            Some(false) => {
                if has6 {
                    return Err("multiple IPv6 server address pools are not supported".to_string());
                }
                has6 = true;
            }
            None => return Err(format!("server address[{addr_index}] is invalid")),
        }
    }
    let topology = endpoint_str(obj, "topology");
    if !OVPN_TOPOLOGIES.contains(&topology) {
        return Err(format!(
            "invalid topology {topology}, allowed values: subnet, p2p, net30"
        ));
    }
    let network = endpoint_str(obj, "network");
    if !OVPN_SERVER_PROTOCOLS.contains(&network) {
        return Err(format!("unsupported network: {network}"));
    }
    let protocol = if network.is_empty() { "udp" } else { network };

    if mode == "static_key" {
        return openvpn_server_static_options(obj, protocol, &addresses, has4, has6);
    }

    if !ovpn_nested_present(obj, "tls") {
        return Err("missing `tls` options".to_string());
    }
    if ovpn_listable_len(obj.get("static_key")) > 0
        || !endpoint_str(obj, "static_key_path").is_empty()
        || !endpoint_str(obj, "key_direction").is_empty()
        || !endpoint_str(obj, "cipher").is_empty()
        || !endpoint_str(obj, "remote").is_empty()
        || obj.get("remote_port").and_then(Value::as_u64).unwrap_or(0) != 0
        || obj
            .get("peer_address")
            .is_some_and(|v| !prunes_value(v) && !v.is_null())
        || obj
            .get("peer_address_ipv6")
            .is_some_and(|v| !prunes_value(v) && !v.is_null())
    {
        return Err("static-key server options require `mode: static_key`".to_string());
    }
    openvpn_server_tls_options(obj)?;
    openvpn_server_push_options(obj)
}

/// buildStaticKeyServerOptions (server.go:346).
fn openvpn_server_static_options(
    obj: &Map<String, Value>,
    protocol: &str,
    addresses: &[String],
    has4: bool,
    has6: bool,
) -> Result<(), String> {
    if ovpn_nested_present(obj, "tls") {
        return Err("`tls` options are not supported in `static_key` mode".to_string());
    }
    if ovpn_listable_len(obj.get("users")) > 0 || ep_bool_val(obj, "duplicate_cn") {
        return Err("user authentication is not supported in `static_key` mode".to_string());
    }
    if ovpn_nested_present(obj, "push") {
        return Err("push options are not supported in `static_key` mode".to_string());
    }
    if ep_ns(obj, "renegotiate_interval") != 0
        || ep_bool_val(obj, "renegotiate_disabled")
        || ep_u64_val(obj, "renegotiate_bytes") != 0
        || ep_u64_val(obj, "renegotiate_packets") != 0
        || ep_ns(obj, "handshake_window") != 0
    {
        return Err(
            "TLS timing and renegotiation options are not supported in `static_key` mode"
                .to_string(),
        );
    }
    if ovpn_listable_len(obj.get("data_ciphers")) > 0
        || !endpoint_str(obj, "data_ciphers_fallback").is_empty()
    {
        return Err(
            "`data_ciphers` and `data_ciphers_fallback` are not supported in `static_key` mode; use `cipher`"
                .to_string(),
        );
    }
    ovpn_required_material_source(
        "static_key",
        obj.get("static_key"),
        endpoint_str(obj, "static_key_path"),
    )?;
    ovpn_key_direction_value(endpoint_str(obj, "key_direction"))?;
    let peer4 = endpoint_str(obj, "peer_address");
    if !peer4.is_empty() && parse_ip_addr(peer4) != Some(true) {
        return Err("`peer_address` must be an IPv4 address".to_string());
    }
    let peer6 = endpoint_str(obj, "peer_address_ipv6");
    if !peer6.is_empty() && parse_ip_addr(peer6) != Some(false) {
        return Err("`peer_address_ipv6` must be an IPv6 address".to_string());
    }
    let _ = addresses;
    if has4 && peer4.is_empty() {
        return Err("missing `peer_address` for the IPv4 static-key tunnel".to_string());
    }
    if has6 && peer6.is_empty() {
        return Err("missing `peer_address_ipv6` for the IPv6 static-key tunnel".to_string());
    }
    if !peer4.is_empty() && !has4 {
        return Err(
            "`peer_address` requires an IPv4 tunnel `address` in `static_key` mode".to_string(),
        );
    }
    if !peer6.is_empty() && !has6 {
        return Err(
            "`peer_address_ipv6` requires an IPv6 tunnel `address` in `static_key` mode"
                .to_string(),
        );
    }
    let remote = endpoint_str(obj, "remote");
    let remote_port = obj.get("remote_port").and_then(Value::as_u64).unwrap_or(0);
    if protocol == "udp" {
        if remote.is_empty() || remote_port == 0 {
            return Err(
                "`remote` and `remote_port` are required for a UDP static-key server".to_string(),
            );
        }
    } else if !remote.is_empty() || remote_port != 0 {
        return Err(
            "`remote` and `remote_port` are only used by a UDP static-key server".to_string(),
        );
    }
    Ok(())
}

/// tls branch (server.go:297) — buildServerTLSOptions (442).
fn openvpn_server_tls_options(obj: &Map<String, Value>) -> Result<(), String> {
    let tls = match obj.get("tls") {
        Some(Value::Object(m)) => m,
        _ => return Err("missing `tls` options".to_string()),
    };
    let tls_str_of = |map: &Map<String, Value>, key: &str| -> String {
        map.get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string()
    };
    let vcc = tls_str_of(tls, "verify_client_certificate");
    if !OVPN_CLIENT_CERT_POLICY.contains(&vcc.as_str()) {
        return Err(format!(
            "invalid client certificate policy {vcc}, allowed values: require, optional, none"
        ));
    }
    ovpn_required_material_source(
        "tls.certificate",
        tls.get("certificate"),
        &tls_str_of(tls, "certificate_path"),
    )?;
    ovpn_required_material_source("tls.key", tls.get("key"), &tls_str_of(tls, "key_path"))?;
    ovpn_material_source(
        "tls.client_certificate",
        tls.get("client_certificate"),
        &tls_str_of(tls, "client_certificate_path"),
    )?;
    let remote_certificate_tls = tls_str_of(tls, "remote_certificate_tls");
    if !OVPN_REMOTE_CERT_TLS.contains(&remote_certificate_tls.as_str()) {
        return Err(format!(
            "invalid `tls.remote_certificate_tls`: {remote_certificate_tls}"
        ));
    }
    let remote_certificate_eku = tls_str_of(tls, "remote_certificate_eku");
    if !remote_certificate_eku.is_empty() && !remote_certificate_tls.is_empty() {
        return Err(
            "`tls.remote_certificate_eku` is conflict with `tls.remote_certificate_tls`"
                .to_string(),
        );
    }
    // control wrap: activity includes force_cookie on the server.
    if let Some(Value::Object(wrap)) = tls.get("control_wrap")
        && ovpn_control_wrap_active(wrap, true)
    {
        let wrap_key = ovpn_required_material_source(
            "tls.control_wrap.key",
            wrap.get("key"),
            &tls_str_of(wrap, "key_path"),
        )?;
        let _ = wrap_key;
        let wrap_type = tls_str_of(wrap, "type");
        let direction = tls_str_of(wrap, "direction");
        let force_cookie = ep_bool_val(wrap, "force_cookie");
        match wrap_type.as_str() {
            "tls_auth" => {
                if force_cookie {
                    return Err(
                        "`tls.control_wrap.force_cookie` is only supported by `tls_crypt_v2`"
                            .to_string(),
                    );
                }
                ovpn_key_direction_value(&direction)?;
            }
            "tls_crypt" => {
                if !direction.is_empty() {
                    return Err(
                        "`tls.control_wrap.direction` is only supported by `tls_auth`".to_string(),
                    );
                }
                if force_cookie {
                    return Err(
                        "`tls.control_wrap.force_cookie` is only supported by `tls_crypt_v2`"
                            .to_string(),
                    );
                }
            }
            "tls_crypt_v2" => {
                if !direction.is_empty() {
                    return Err(
                        "`tls.control_wrap.direction` is only supported by `tls_auth`".to_string(),
                    );
                }
            }
            "" => return Err("missing control wrap type".to_string()),
            other => return Err(format!("unknown control wrap type: {other}")),
        }
    }
    Ok(())
}

/// applyServerPushOptions (server.go:536) — endpoint-stage errors only.
fn openvpn_server_push_options(obj: &Map<String, Value>) -> Result<(), String> {
    let Some(Value::Object(push)) = obj.get("push") else {
        return Ok(());
    };
    if let Some(Value::Array(dns_servers)) = push.get("dns_servers") {
        for (server_index, server) in dns_servers.iter().enumerate() {
            let Value::Object(server) = server else {
                continue;
            };
            if let Some(Value::Array(items)) = server.get("addresses") {
                for (address_index, item) in items.iter().enumerate() {
                    let value = item.as_str().unwrap_or("");
                    if !ovpn_push_dns_addr_ok(value) {
                        return Err(format!(
                            "invalid push.dns_servers[{server_index}].addresses[{address_index}]: {value}"
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// netip.ParseAddr / ParseAddrPort with a non-zero port requirement.
fn ovpn_push_dns_addr_ok(value: &str) -> bool {
    if value.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let Some((host, port)) = rest.split_once("]:") else {
            return false;
        };
        if host.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        return matches!(port.parse::<u16>(), Ok(p) if p != 0);
    }
    let Some((host, port)) = value.rsplit_once(':') else {
        return false;
    };
    if host.contains(':') || host.parse::<std::net::Ipv4Addr>().is_err() {
        return false;
    }
    matches!(port.parse::<u16>(), Ok(p) if p != 0)
}

// ---------------------------------------------------------------------------
// tailscale initialize — sbx-src/protocol/tailscale/endpoint.go NewEndpoint.
// ---------------------------------------------------------------------------

// openconnect initialize — sbx-src/protocol/openconnect/client.go NewEndpoint
// (keepalive → url.Parse → materials) + sing-openconnect NewClient
// (defaults → token → validateClientOptions → parseServerURL → buildClientTLS →
// flavor).
// ---------------------------------------------------------------------------

pub(super) fn openconnect_initialize(
    _i: usize,
    _tag: &str,
    obj: &Map<String, Value>,
) -> Result<(), String> {
    let keep_alive_enabled = ep_bool_val(obj, "tcp_keep_alive_enabled")
        || ep_ns(obj, "tcp_keep_alive") != 0
        || ep_ns(obj, "tcp_keep_alive_interval") != 0;
    if keep_alive_enabled && ep_bool_val(obj, "disable_tcp_keep_alive") {
        return Err("tcp_keep_alive_enabled conflicts with disable_tcp_keep_alive".to_string());
    }
    // CheckSecurityFeature for csd/hip/tncc wrapper paths is a runtime check.
    let server = endpoint_str(obj, "server");
    oc_check_url_parse(server)?;
    // buildClientOptions material sources (validate-only).
    let tls = match obj.get("tls") {
        Some(Value::Object(m)) => m,
        _ => &Map::new(),
    };
    oc_material_source(
        "tls.certificate_authority",
        tls.get("certificate_authority"),
        &oc_str(tls, "certificate_authority_path"),
    )?;
    oc_material_source(
        "tls.client_certificate",
        tls.get("client_certificate"),
        &oc_str(tls, "client_certificate_path"),
    )?;
    oc_material_source(
        "tls.client_key",
        tls.get("client_key"),
        &oc_str(tls, "client_key_path"),
    )?;
    oc_material_source(
        "tls.mca_certificate",
        tls.get("mca_certificate"),
        &oc_str(tls, "mca_certificate_path"),
    )?;
    oc_material_source(
        "tls.mca_key",
        tls.get("mca_key"),
        &oc_str(tls, "mca_key_path"),
    )?;
    if let Some(Value::Object(tncc)) = obj.get("tncc")
        && let Some(Value::Array(certs)) = tncc.get("certificates")
    {
        for (cert_index, cert) in certs.iter().enumerate() {
            let Value::Object(cert) = cert else { continue };
            oc_material_source(
                &format!("tncc.certificates[{cert_index}].certificate"),
                cert.get("certificate"),
                &oc_str(cert, "certificate_path"),
            )?;
        }
    }

    // openconnect.NewClient
    if server.is_empty() {
        return Err("missing openconnect server".to_string());
    }
    let token = match obj.get("token") {
        Some(Value::Object(m)) => Some(m),
        _ => None,
    };
    let token_secret = token.map(|m| oc_str(m, "secret")).unwrap_or_default();
    let token_secret_path = token.map(|m| oc_str(m, "secret_path")).unwrap_or_default();
    if !token_secret_path.is_empty() {
        if !token_secret.is_empty() {
            return Err("token secret and secret path cannot both be configured".to_string());
        }
        go_read_file(&token_secret_path).map_err(|e| {
            format!("load token secret: read openconnect material: open {token_secret_path}: {e}")
        })?;
    }
    oc_validate_client_options(obj)?;

    // parseServerURL(options.Server)
    oc_check_server_url(server)?;

    // buildClientTLS(options.TLSConfig)
    oc_build_client_tls(tls)?;

    // newFlavorFrontend(options.Flavor) — flavor defaults to "anyconnect".
    let flavor = endpoint_str(obj, "flavor");
    if !OC_FLAVORS.contains(&flavor) {
        return Err(format!("unsupported openconnect flavor: {flavor}"));
    }
    Ok(())
}

fn oc_str(map: &Map<String, Value>, key: &str) -> String {
    map.get(key)
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string()
}

/// reference `materialSource` (sing-openconnect material.go).
fn oc_material_source(name: &str, value: Option<&Value>, path: &str) -> Result<String, String> {
    let content = tls_listable_join(value);
    if !path.is_empty() && !content.is_empty() {
        return Err(format!("material path and content are both set: {name}"));
    }
    Ok(content)
}

/// reference `validateClientOptions` (sing-openconnect client.go:202).
fn oc_validate_client_options(obj: &Map<String, Value>) -> Result<(), String> {
    // char scan: fixed order (Go map iteration is randomized; DTLS cipher
    // fields do not exist in the endpoint options).
    for (name, key) in [
        ("local hostname", "local_hostname"),
        ("user agent", "user_agent"),
        ("version", "version"),
    ] {
        let value = oc_str(obj, key);
        if value.chars().any(|c| OC_PROTOCOL_BAD.contains(&c)) {
            return Err(format!("{name} contains an invalid protocol character"));
        }
    }
    if let Some(Value::Object(mobile)) = obj.get("mobile") {
        for (name, key) in [
            ("mobile platform version", "platform_version"),
            ("mobile device type", "device_type"),
            ("mobile device unique ID", "device_unique_id"),
        ] {
            let value = oc_str(mobile, key);
            if value.is_empty() {
                return Err(format!("{name} cannot be empty"));
            }
            if value.chars().any(|c| OC_PROTOCOL_BAD.contains(&c)) {
                return Err(format!("{name} contains an invalid protocol character"));
            }
        }
    }
    if ep_ns(obj, "reconnect_timeout") < 0 {
        return Err("reconnect timeout cannot be negative".to_string());
    }
    if ep_ns(obj, "trojan_interval") < 0 {
        return Err("trojan interval cannot be negative".to_string());
    }
    let dpd = ep_ns(obj, "dpd_interval");
    if !(0..=4_611_686_018_427_387_903).contains(&dpd) {
        return Err("DPD interval is outside the supported range".to_string());
    }
    let mtu = ep_u64_val(obj, "mtu");
    let base_mtu = ep_u64_val(obj, "base_mtu");
    if mtu > 65535 || base_mtu > 65535 {
        return Err("MTU exceeds wire limit".to_string());
    }
    // queue_length: u32 can never exceed usize::MAX/2 on supported targets.
    let raw_mode = oc_str(obj, "compression_mode");
    let mode = if raw_mode.is_empty() {
        "stateless"
    } else {
        raw_mode.as_str()
    };
    if !OC_COMPRESSION_MODES.contains(&mode) {
        return Err(format!("unsupported compression mode: {mode}"));
    }
    if ep_bool_val(obj, "compression_disabled") && mode != "stateless" {
        return Err(format!(
            "compression_disabled conflicts with compression mode {mode}"
        ));
    }
    if let Some(Value::Array(entries)) = obj.get("form_entries") {
        for entry in entries {
            let Value::Object(entry) = entry else {
                continue;
            };
            let submission_key = oc_str(entry, "submission_key");
            let form_id = oc_str(entry, "form_id");
            let name = oc_str(entry, "name");
            if submission_key.is_empty() && (form_id.is_empty() || name.is_empty()) {
                return Err(
                    "form entry requires a submission key or a form ID and field name".to_string(),
                );
            }
            if ep_bool_val(entry, "promote") && !oc_str(entry, "value").is_empty() {
                return Err("promoted form entry cannot also provide a value".to_string());
            }
        }
    }
    if let Some(Value::Object(token)) = obj.get("token") {
        let secret = oc_str(token, "secret");
        let secret_path = oc_str(token, "secret_path");
        if secret.is_empty() && secret_path.is_empty() {
            return Err("software token requires a secret".to_string());
        }
        let mode = oc_str(token, "mode");
        if !OC_TOKEN_MODES.contains(&mode.as_str()) {
            return Err(format!(
                "unsupported openconnect software token mode: {mode}"
            ));
        }
    }
    Ok(())
}

/// reference `parseServerURL` (sing-openconnect http_client.go:18).
fn oc_check_server_url(server: &str) -> Result<(), String> {
    let url = if server.contains("://") {
        server.to_string()
    } else {
        format!("https://{server}")
    };
    let rest = match url.find("://") {
        Some(idx) => &url[idx + 3..],
        None => url.as_str(),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(idx) => (Some(&authority[..idx]), &authority[idx + 1..]),
        None => (None, authority),
    };
    let (host, port) = if let Some(stripped) = hostport.strip_prefix('[') {
        match stripped.split_once("]:") {
            Some((host, port)) => (host, Some(port)),
            None => (stripped, None),
        }
    } else {
        match hostport.rsplit_once(':') {
            Some((host, port)) if !host.contains(':') => (host, Some(port)),
            _ => (hostport, None),
        }
    };
    let scheme = url.split("://").next().unwrap_or("").to_ascii_lowercase();
    if scheme != "https" || host.is_empty() {
        return Err("server must be an HTTPS host".to_string());
    }
    if userinfo.is_some() {
        return Err("server must not contain URL user information".to_string());
    }
    let scheme_end = url.find("://").map(|i| i + 3).unwrap_or(0);
    let after_authority = &url[scheme_end + authority.len()..];
    if after_authority.contains('?') || after_authority.contains('#') {
        return Err("server must not contain a query or fragment".to_string());
    }
    let _ = port;
    Ok(())
}

/// reference endpoint-side `url.Parse` (client.go:133) — best-effort: control
/// characters and a non-numeric port are the reachable failures.
fn oc_check_url_parse(server: &str) -> Result<(), String> {
    let url = if server.contains("://") {
        server.to_string()
    } else {
        format!("https://{server}")
    };
    if url.chars().any(|c| c < '\x20' || c == '\x7f') {
        return Err(format!(
            "parse server: parse {url:?}: net/url: invalid control character in URL"
        ));
    }
    let rest = match url.find("://") {
        Some(idx) => &url[idx + 3..],
        None => url.as_str(),
    };
    let authority_end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_end];
    let hostport = match authority.rfind('@') {
        Some(idx) => &authority[idx + 1..],
        None => authority,
    };
    if !hostport.starts_with('[') {
        if let Some((_, port)) = hostport.rsplit_once(':')
            && !port.is_empty()
            && !port.bytes().all(|b| b.is_ascii_digit())
        {
            return Err(format!(
                "parse server: parse {url:?}: invalid port \":{port}\" after host"
            ));
        }
    } else if let Some(rest) = hostport.strip_prefix('[')
        && let Some((_, port)) = rest.split_once("]:")
        && !port.is_empty()
        && !port.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(format!(
            "parse server: parse {url:?}: invalid port \":{port}\" after host"
        ));
    }
    Ok(())
}

/// reference `buildClientTLS` (sing-openconnect tls_config.go:43).
fn oc_build_client_tls(tls: &Map<String, Value>) -> Result<(), String> {
    let ca = tls_listable_join(tls.get("certificate_authority"));
    let ca_path = oc_str(tls, "certificate_authority_path");
    if !ca.is_empty() || !ca_path.is_empty() {
        let content = if !ca_path.is_empty() {
            go_read_file(&ca_path).map_err(|e| {
                format!(
                    "load TLS certificate authority: read openconnect material: open {ca_path}: {e}"
                )
            })?
        } else {
            ca.clone()
        };
        if !oc_pem_has_certificate(&content) {
            return Err("invalid openconnect TLS material: certificate authority".to_string());
        }
    }
    oc_load_optional_certificate(
        tls,
        "client_certificate",
        "client_certificate_path",
        "client_key",
        "client_key_path",
        "client_key_password",
        "client",
    )?;
    oc_load_optional_certificate(
        tls,
        "mca_certificate",
        "mca_certificate_path",
        "mca_key",
        "mca_key_path",
        "mca_key_password",
        "MCA",
    )?;
    // certificate expiry warnings / MinVersion / cipher / PFS are driven by
    // fields the endpoint never sets (defaults cannot fail).
    let fingerprints = ovpn_listable_values(tls.get("peer_fingerprint"));
    for value in &fingerprints {
        oc_parse_peer_fingerprint(value)?;
    }
    Ok(())
}

/// reference `loadOptionalCertificate` (tls_config.go:669).
fn oc_load_optional_certificate(
    tls: &Map<String, Value>,
    cert_key: &str,
    cert_path_key: &str,
    key_key: &str,
    key_path_key: &str,
    password_key: &str,
    name: &str,
) -> Result<(), String> {
    let cert_content = tls_listable_join(tls.get(cert_key));
    let cert_path = oc_str(tls, cert_path_key);
    let key_content = tls_listable_join(tls.get(key_key));
    let key_path = oc_str(tls, key_path_key);
    let cert_set = !cert_content.is_empty() || !cert_path.is_empty();
    let key_set = !key_content.is_empty() || !key_path.is_empty();
    if cert_set != key_set {
        return Err(format!(
            "invalid openconnect TLS material: {name} certificate and key must both be set"
        ));
    }
    if !cert_set {
        return Ok(());
    }
    let cert_pem = if !cert_path.is_empty() {
        go_read_file(&cert_path).map_err(|e| {
            format!("load {name} certificate: read openconnect material: open {cert_path}: {e}")
        })?
    } else {
        cert_content
    };
    let key_pem = if !key_path.is_empty() {
        go_read_file(&key_path).map_err(|e| {
            format!("load {name} key: read openconnect material: open {key_path}: {e}")
        })?
    } else {
        key_content
    };
    let password = oc_str(tls, password_key);
    oc_decrypt_key_pem(&key_pem, &password).map_err(|e| format!("decrypt {name} key: {e}"))?;
    if !oc_pem_has_certificate(&cert_pem) {
        return Err(format!(
            "parse {name} certificate and key: x509: failed to find any PEM data in certificate input"
        ));
    }
    if !oc_pem_has_private_key(&key_pem) {
        return Err(format!(
            "parse {name} certificate and key: x509: failed to find any PEM data in key input"
        ));
    }
    // certificate/key DER match cannot be verified without crypto parsing —
    // documented GAP; probing uses non-PEM material that fails above.
    Ok(())
}

/// reference `decryptPrivateKeyPEM` (tls_config.go:695) — password checks only.
fn oc_decrypt_key_pem(content: &str, password: &str) -> Result<(), String> {
    for block in oc_pem_blocks(content) {
        if block.0 == "ENCRYPTED PRIVATE KEY" && password.is_empty() {
            return Err("encrypted PKCS#8 private key requires a password".to_string());
        }
        if block.2 && password.is_empty() {
            return Err("encrypted private key requires a password".to_string());
        }
    }
    Ok(())
}

/// minimal PEM scanner: (type, base64 body, legacy_encrypted_header).
fn oc_pem_blocks(content: &str) -> Vec<(String, String, bool)> {
    let mut blocks = Vec::new();
    let lines: Vec<&str> = content.lines().collect();
    let mut idx = 0;
    while idx < lines.len() {
        let line = lines[idx].trim_end_matches('\r');
        if let Some(ty) = line
            .strip_prefix("-----BEGIN ")
            .and_then(|s| s.strip_suffix("-----"))
        {
            if ty.is_empty() || ty.contains(' ') || ty.contains(':') {
                idx += 1;
                continue;
            }
            let mut body_lines: Vec<&str> = Vec::new();
            let mut legacy_encrypted = false;
            let mut in_headers = true;
            let mut j = idx + 1;
            let mut closed = false;
            while j < lines.len() {
                let cur = lines[j].trim_end_matches('\r');
                if cur.starts_with("-----END ") {
                    closed = true;
                    break;
                }
                if in_headers {
                    if cur.trim().is_empty() {
                        in_headers = false;
                    } else if cur.starts_with("Proc-Type:") && cur.contains("ENCRYPTED") {
                        legacy_encrypted = true;
                    } else if cur.contains(':') && !cur.starts_with("-----") {
                        // PEM header line.
                    } else {
                        in_headers = false;
                        body_lines.push(cur);
                    }
                } else {
                    body_lines.push(cur);
                }
                j += 1;
            }
            if closed {
                blocks.push((ty.to_string(), body_lines.concat(), legacy_encrypted));
                idx = j + 1;
                continue;
            }
        }
        idx += 1;
    }
    blocks
}

fn oc_pem_has_certificate(content: &str) -> bool {
    matches!(
        oc_pem_blocks(content).first(),
        Some((ty, body, _)) if ty == "CERTIFICATE" && oc_base64_ok(body)
    )
}

fn oc_pem_has_private_key(content: &str) -> bool {
    matches!(
        oc_pem_blocks(content).first(),
        Some((ty, body, _))
            if matches!(ty.as_str(), "PRIVATE KEY" | "RSA PRIVATE KEY" | "EC PRIVATE KEY")
                && oc_base64_ok(body)
    )
}

/// conservative base64 validity (std alphabet, padding only at the end).
fn oc_base64_ok(body: &str) -> bool {
    let body: String = body.chars().filter(|c| !c.is_whitespace()).collect();
    if body.is_empty() {
        return false;
    }
    let bytes = body.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return false;
    }
    let mut padding = 0;
    for (idx, b) in bytes.iter().enumerate() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' => {
                if padding > 0 {
                    return false;
                }
            }
            b'=' => {
                padding += 1;
                if idx < bytes.len() - 2 {
                    return false;
                }
            }
            _ => return false,
        }
    }
    padding <= 2
}

/// reference `parsePeerFingerprint` (tls_config.go:233).
fn oc_parse_peer_fingerprint(value: &str) -> Result<(), String> {
    let mut encoded: &str = value;
    let mut maximum_length = 40usize;
    let mut case_sensitive = false;
    if let Some(rest) = value.strip_prefix("sha1:") {
        encoded = rest;
    } else if let Some(rest) = value.strip_prefix("sha256:") {
        encoded = rest;
        maximum_length = 64;
    } else if let Some(rest) = value.strip_prefix("pin-sha256:") {
        encoded = rest;
        maximum_length = 44;
        case_sensitive = true;
    } else if value.contains(':') {
        return Err(format!(
            "unsupported server certificate fingerprint: {value}"
        ));
    }
    if encoded.len() < 4 || encoded.len() > maximum_length {
        return Err(format!("invalid server certificate fingerprint: {value}"));
    }
    if case_sensitive {
        for (idx, ch) in encoded.char_indices() {
            let ok = ch.is_ascii_alphanumeric() || ch == '+' || ch == '/';
            if !ok && (ch != '=' || idx < encoded.len().saturating_sub(2)) {
                return Err(format!("invalid server certificate fingerprint: {value}"));
            }
        }
        if encoded.len() == maximum_length {
            let decoded = oc_base64_strict_decode(encoded);
            if decoded.as_deref().map(|d| d.len()) != Some(32) {
                return Err(format!("invalid server certificate fingerprint: {value}"));
            }
        }
    } else {
        if !encoded.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!("invalid server certificate fingerprint: {value}"));
        }
    }
    Ok(())
}

/// strict base64 std decode (non-zero trailing bits rejected), 32-byte check.
fn oc_base64_strict_decode(input: &str) -> Option<Vec<u8>> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = input.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut buf = 0u32;
    let mut bits = 0u32;
    for (idx, b) in bytes.iter().enumerate() {
        if *b == b'=' {
            if idx < bytes.len() - 2 {
                return None;
            }
            if !bits.is_multiple_of(8) && (buf & ((1 << bits) - 1)) != 0 {
                return None;
            }
            continue;
        }
        let val = ALPHABET.iter().position(|a| a == b)? as u32;
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    if out.len() != 32 {
        return None;
    }
    Some(out)
}
