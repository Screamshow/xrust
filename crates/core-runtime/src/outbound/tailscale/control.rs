//! Tailscale control plane client (HTTPS 443 coordination).
//!
//! Handles registration, machine/node key persistence, Noise_IK establishment,
//! and MapResponse peer/DERP streaming.

use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use x25519_dalek::{PublicKey, StaticSecret};

use crate::outbound::tailscale::derp::DerpMapUpdate;

pub(crate) const IPN_VERSION: &str = concat!("1.104.7-rustx", env!("CARGO_PKG_VERSION"));

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Hostinfo {
    #[serde(rename = "IPNVersion", default)]
    pub ipn_version: String,
    #[serde(rename = "OSVersion", default)]
    pub os_version: String,
    #[serde(rename = "Distro", default)]
    pub distro: String,
    #[serde(rename = "DistroVersion", default)]
    pub distro_version: String,
    #[serde(rename = "OS", default = "default_os")]
    pub os: String,
    #[serde(rename = "Hostname", default)]
    pub hostname: String,
    #[serde(rename = "StateEncrypted", default)]
    pub state_encrypted: bool,
    #[serde(rename = "RoutableIPs", default)]
    pub routable_ips: Vec<String>,
    #[serde(rename = "Services", default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<Service>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Service {
    #[serde(rename = "Proto")]
    pub proto: String,
    #[serde(rename = "Port")]
    pub port: u16,
}

impl Hostinfo {
    /// The numeric prefix identifies the reference Tailscale release. The
    /// control capability version is negotiated separately.
    pub fn new(hostname: &str, routes: &[String]) -> Self {
        Self::from_release(
            hostname,
            routes,
            &fs::read_to_string("/etc/os-release").unwrap_or_default(),
            &fs::read_to_string("/etc/openwrt_release").unwrap_or_default(),
            &fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default(),
        )
    }

    fn from_release(
        hostname: &str,
        routes: &[String],
        os: &str,
        openwrt: &str,
        kernel: &str,
    ) -> Self {
        fn field(text: &str, key: &str) -> String {
            text.lines()
                .find_map(|line| {
                    let (name, value) = line.split_once('=')?;
                    (name.trim() == key).then(|| value.trim().trim_matches(['\'', '"']).to_owned())
                })
                .unwrap_or_default()
        }
        let mut distro = field(os, "ID");
        let mut distro_version = field(os, "VERSION_ID");
        if !openwrt.is_empty() {
            distro = "openwrt".into();
            let version = field(openwrt, "DISTRIB_RELEASE");
            if !version.is_empty() {
                distro_version = version;
            }
        }
        // Keep the OS family stable for existing node identities. The hosted
        // control plane withheld addresses when Linux was changed to OpenWrt.
        // Its machine list ignores Distro, so include the release in the
        // displayed version as well as the proper distribution fields.
        let os_version = if distro == "openwrt" {
            format!("OpenWrt {distro_version}")
        } else {
            kernel.trim().into()
        };
        Self {
            ipn_version: IPN_VERSION.into(),
            os: std::env::consts::OS.into(),
            os_version,
            distro,
            distro_version,
            hostname: hostname.into(),
            state_encrypted: false,
            routable_ips: routes.to_vec(),
            services: if routes.iter().any(|r| r == "0.0.0.0/0") {
                vec![
                    Service {
                        proto: "peerapi4".into(),
                        port: super::peer_dns::PORT,
                    },
                    Service {
                        proto: "peerapi6".into(),
                        port: super::peer_dns::PORT,
                    },
                    Service {
                        proto: "peerapi-dns-proxy".into(),
                        port: 1,
                    },
                ]
            } else {
                vec![]
            },
        }
    }
}

fn default_os() -> String {
    "linux".to_string()
}

#[cfg(test)]
mod hostinfo_tests {
    use super::*;

    #[test]
    fn only_implicit_allowed_ips_inherit_node_addresses() {
        let map: MapResponse = serde_json::from_value(serde_json::json!({
            "Node": {"ID": 1, "Key": "nodekey:test", "Addresses": ["100.64.0.1/32"]},
            "Peers": [{"ID": 2, "Key": "nodekey:peer", "Addresses": ["100.64.0.2/32"], "AllowedIPs": null}]
        }))
        .unwrap();
        let node = map.node.unwrap();
        assert_eq!(node.allowed_ips(), ["100.64.0.1/32"]);
        assert_eq!(map.peers.unwrap()[0].allowed_ips(), ["100.64.0.2/32"]);

        let mut wire = serde_json::to_value(node).unwrap();
        for (allowed, expected) in [
            (serde_json::Value::Null, vec!["100.64.0.1/32"]),
            (serde_json::json!([]), vec![]),
            (
                serde_json::json!(["192.168.1.0/24", "0.0.0.0/0"]),
                vec!["192.168.1.0/24", "0.0.0.0/0"],
            ),
        ] {
            wire["AllowedIPs"] = allowed;
            let node: NodeObj = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(node.allowed_ips(), expected);
        }
    }

    #[test]
    fn only_a_bare_keepalive_is_skipped() {
        let parse = |raw: &str| serde_json::from_str::<super::MapResponse>(raw).unwrap();
        assert!(parse(r#"{"KeepAlive":true}"#).is_keep_alive_only());
        assert!(!parse(r#"{"KeepAlive":true,"PeersRemoved":[7]}"#).is_keep_alive_only());
        assert!(!parse(r#"{"KeepAlive":true,"PacketFilter":[]}"#).is_keep_alive_only());
        assert!(!parse(r#"{"PeersChanged":[]}"#).is_keep_alive_only());
        assert!(!parse(r#"{"KeepAlive":true,"DNSConfig":{}}"#).is_keep_alive_only());
    }

    #[test]
    fn stable_tailnet_id_is_read_from_the_self_node() {
        let map: MapResponse = serde_json::from_value(serde_json::json!({
            "Node": {"ID": 1, "Key": "nodekey:test", "StableTailnetID": "tn-test"},
            "Peers": [{"ID": 2, "Key": "nodekey:peer", "StableTailnetID": "ignored"}]
        }))
        .unwrap();
        let node = map.node.unwrap();
        assert_eq!(node.stable_tailnet_id(), Some("tn-test"));
        let mut wire = serde_json::to_value(node).unwrap();
        for value in [Value::Null, serde_json::json!("")] {
            wire["StableTailnetID"] = value;
            let node: NodeObj = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(node.stable_tailnet_id(), None);
        }
    }

    #[test]
    fn openwrt_hostinfo_preserves_os_family_and_reports_release() {
        let info = Hostinfo::from_release(
            "router",
            &["192.168.1.0/24".into()],
            "ID=openwrt\nVERSION_ID=25.12.5\n",
            "DISTRIB_RELEASE='25.12.5'\n",
            "6.12.94\n",
        );
        let value = serde_json::to_value(info).unwrap();
        assert_eq!(value["Distro"], "openwrt");
        assert_eq!(value["DistroVersion"], "25.12.5");
        assert_eq!(value["OS"], std::env::consts::OS);
        assert_eq!(value["OSVersion"], "OpenWrt 25.12.5");
        assert_eq!(value["IPNVersion"], IPN_VERSION);
        assert_eq!(value["RoutableIPs"][0], "192.168.1.0/24");
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuthObj {
    #[serde(rename = "AuthKey")]
    pub auth_key: String,
}

impl std::fmt::Debug for AuthObj {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthObj")
            .field("auth_key", &"[redacted]")
            .finish()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "Auth", skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthObj>,
    #[serde(rename = "Hostinfo")]
    pub hostinfo: Hostinfo,
    #[serde(rename = "Ephemeral")]
    pub ephemeral: bool,
    #[serde(rename = "Followup", default, skip_serializing_if = "Option::is_none")]
    pub followup: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeObj {
    #[serde(rename = "HomeDERP", default)]
    pub home_derp: Option<u16>,
    #[serde(rename = "ID")]
    pub id: u64,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    #[serde(rename = "Capabilities", default, deserialize_with = "null_default")]
    pub capabilities: Vec<String>,
    #[serde(rename = "CapMap", default, deserialize_with = "null_default")]
    pub cap_map: HashMap<String, Value>,
    #[serde(
        rename = "StableTailnetID",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    stable_tailnet_id: Option<String>,
    #[serde(rename = "Addresses", default, deserialize_with = "null_default")]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    allowed_ips: Option<Vec<String>>,
    #[serde(rename = "Endpoints", default, deserialize_with = "null_default")]
    pub endpoints: Vec<String>,
    #[serde(rename = "DERP", default)]
    pub derp: Option<Value>,
}

impl NodeObj {
    pub fn allowed_ips(&self) -> &[String] {
        self.allowed_ips.as_deref().unwrap_or(&self.addresses)
    }

    pub(crate) fn stable_tailnet_id(&self) -> Option<&str> {
        self.stable_tailnet_id
            .as_deref()
            .filter(|id| !id.is_empty())
    }
}

fn null_default<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Ok(Option::<T>::deserialize(deserializer)?.unwrap_or_default())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterResponse {
    #[serde(rename = "Node", default)]
    pub node: Option<NodeObj>,
    #[serde(rename = "MachineAuthorized", default)]
    pub machine_authorized: Option<bool>,
    #[serde(rename = "AuthURL", default)]
    pub auth_url: Option<String>,
    #[serde(rename = "Error", default)]
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MapRequest {
    #[serde(rename = "Version")]
    pub version: u32,
    #[serde(rename = "Compress")]
    pub compress: String,
    #[serde(rename = "KeepAlive")]
    pub keep_alive: bool,
    #[serde(rename = "NodeKey")]
    pub node_key: String,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Vec<String>,
    #[serde(rename = "Stream")]
    pub stream: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PeerObj {
    #[serde(rename = "DiscoKey", default)]
    pub disco_key: Option<String>,
    #[serde(rename = "HomeDERP", default)]
    pub home_derp: Option<u16>,
    #[serde(rename = "ID")]
    pub id: u64,
    #[serde(rename = "Key")]
    pub key: String,
    #[serde(rename = "Name", default)]
    pub name: Option<String>,
    #[serde(rename = "Addresses", default, deserialize_with = "null_default")]
    pub addresses: Vec<String>,
    #[serde(rename = "AllowedIPs", default)]
    pub allowed_ips: Option<Vec<String>>,
    #[serde(rename = "Endpoints", default)]
    pub endpoints: Option<Vec<String>>,
    #[serde(rename = "DERP", default)]
    pub derp: Option<Value>,
    #[serde(rename = "Online", default)]
    pub online: Option<bool>,
    #[serde(rename = "IsWireGuardOnly", default)]
    pub is_wireguard_only: bool,
}

impl PeerObj {
    pub fn allowed_ips(&self) -> &[String] {
        self.allowed_ips.as_deref().unwrap_or(&self.addresses)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PeerChange {
    #[serde(rename = "NodeID")]
    node_id: u64,
    #[serde(rename = "DERPRegion")]
    derp_region: Option<u16>,
    endpoints: Option<Vec<String>>,
    key: Option<String>,
    disco_key: Option<String>,
    online: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MapResponse {
    #[serde(rename = "PeersChanged", default)]
    pub peers_changed: Option<Vec<PeerObj>>,
    #[serde(rename = "PeersChangedPatch", default)]
    pub peers_changed_patch: Option<Vec<PeerChange>>,
    #[serde(rename = "PeersRemoved", default)]
    pub peers_removed: Option<Vec<u64>>,
    #[serde(rename = "OnlineChange", default)]
    pub online_change: Option<HashMap<u64, bool>>,
    #[serde(rename = "PacketFilter", default)]
    pub packet_filter: Option<Vec<super::access::Rule>>,
    #[serde(rename = "PacketFilters", default)]
    pub packet_filters: Option<std::collections::HashMap<String, Option<Vec<super::access::Rule>>>>,
    #[serde(rename = "Node", default)]
    pub node: Option<NodeObj>,
    #[serde(rename = "Peers", default)]
    pub peers: Option<Vec<PeerObj>>,
    #[serde(rename = "DERPMap", default)]
    pub derp_map: Option<DerpMapUpdate>,
    #[serde(rename = "DNSConfig", default)]
    pub dns_config: Option<super::peer_dns::DnsConfig>,
    #[serde(rename = "KeepAlive", default)]
    pub keep_alive: Option<bool>,
}

impl MapResponse {
    /// A stream keepalive that carries no change at all.
    pub fn is_keep_alive_only(&self) -> bool {
        self.keep_alive == Some(true)
            && self.peers_changed.is_none()
            && self.peers_changed_patch.is_none()
            && self.peers_removed.is_none()
            && self.online_change.is_none()
            && self.packet_filter.is_none()
            && self.packet_filters.is_none()
            && self.node.is_none()
            && self.peers.is_none()
            && self.derp_map.is_none()
            && self.dns_config.is_none()
    }

    pub(crate) fn update_peers(&mut self, peers: &mut HashMap<u64, PeerObj>, first: bool) {
        // Full maps omit Peers when there are no nodes. Deltas on an
        // established stream may also omit it, while retaining the table.
        if first {
            peers.clear();
        }
        if let Some(full) = self.peers.take().filter(|full| !full.is_empty()) {
            peers.clear();
            peers.extend(full.into_iter().map(|peer| (peer.id, peer)));
            return;
        }
        for id in self.peers_removed.take().into_iter().flatten() {
            peers.remove(&id);
        }
        for peer in self.peers_changed.take().into_iter().flatten() {
            peers.insert(peer.id, peer);
        }
        for (id, online) in self.online_change.take().into_iter().flatten() {
            if let Some(peer) = peers.get_mut(&id) {
                peer.online = Some(online);
            }
        }
        for change in self.peers_changed_patch.take().into_iter().flatten() {
            let Some(peer) = peers.get_mut(&change.node_id) else {
                continue;
            };
            if let Some(region) = change.derp_region.filter(|region| *region != 0) {
                peer.home_derp = Some(region);
            }
            if let Some(endpoints) = change.endpoints {
                peer.endpoints = Some(endpoints);
            }
            if let Some(key) = change.key {
                peer.key = key;
            }
            if let Some(disco_key) = change.disco_key {
                peer.disco_key = Some(disco_key);
            }
            if let Some(online) = change.online {
                peer.online = Some(online);
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
struct PersistedState {
    #[serde(rename = "Version")]
    version: u32,
    #[serde(rename = "MachineKey")]
    machine_key: String,
    #[serde(rename = "NodeKey")]
    node_key: String,
}

pub fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{:02x}", b);
    }
    s
}

#[allow(clippy::result_unit_err)]
pub fn from_hex(s: &str, out: &mut [u8]) -> Result<(), ()> {
    if !s.is_ascii() || s.len() != out.len() * 2 {
        return Err(());
    }
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|_| ())?;
    }
    Ok(())
}

/// Loads or creates persistent/ephemeral machine key and node key.
pub fn load_or_create_keys(
    state_dir: Option<&Path>,
    ephemeral: bool,
) -> io::Result<(StaticSecret, StaticSecret)> {
    if !ephemeral && let Some(dir) = state_dir {
        let state_file = dir.join("tailscale.state");
        match fs::read_to_string(&state_file) {
            Ok(content) => {
                let invalid = || {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tailscale: invalid or legacy key state; explicit identity reset required",
                    )
                };
                let state: PersistedState =
                    serde_json::from_str(&content).map_err(|_| invalid())?;
                if state.version != 1 {
                    return Err(invalid());
                }
                let decode = |key: &str| {
                    let mut bytes = [0u8; 32];
                    from_hex(key, &mut bytes).map_err(|_| invalid())?;
                    Ok::<_, io::Error>(StaticSecret::from(bytes))
                };
                return Ok((decode(&state.machine_key)?, decode(&state.node_key)?));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }

        let m_sec = generate_secret();
        let n_sec = generate_secret();
        let state = PersistedState {
            version: 1,
            machine_key: to_hex(&m_sec.to_bytes()),
            node_key: to_hex(&n_sec.to_bytes()),
        };
        let json = serde_json::to_vec(&state).map_err(io::Error::other)?;
        fs::create_dir_all(dir)?;
        // A fixed create_new staging file serializes first-time initialization.
        // Never overwrite an existing identity or accept a partially written file.
        let staging = dir.join("tailscale.state.new");
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&staging)?;
        // Another initializer may have published its state after our first read.
        if state_file.exists() {
            drop(file);
            fs::remove_file(&staging)?;
            return load_or_create_keys(state_dir, ephemeral);
        }
        let result = (|| {
            file.write_all(&json)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&staging, &state_file)?;
            #[cfg(unix)]
            fs::File::open(dir)?.sync_all()?;
            Ok::<_, io::Error>(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&staging);
        }
        result?;
        return Ok((m_sec, n_sec));
    }

    Ok((generate_secret(), generate_secret()))
}

fn generate_secret() -> StaticSecret {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("getrandom secret");
    StaticSecret::from(bytes)
}

pub fn parse_key_hex(s: &str) -> Option<[u8; 32]> {
    let clean = s
        .trim()
        .strip_prefix("mkey:")
        .or_else(|| s.trim().strip_prefix("nodekey:"))
        .unwrap_or(s.trim());
    if clean.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    from_hex(clean, &mut out).ok()?;
    Some(out)
}

/// Converts a public key into the Tailscale `"nodekey:<hex>"` format.
pub fn node_key_str(pk: &PublicKey) -> String {
    format!("nodekey:{}", to_hex(pk.as_bytes()))
}

/// Converts a public key into the Tailscale `"mkey:<hex>"` format.
pub fn machine_key_str(pk: &PublicKey) -> String {
    format!("mkey:{}", to_hex(pk.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct StateDir(std::path::PathBuf);

    impl StateDir {
        fn new() -> Self {
            let mut nonce = [0u8; 16];
            getrandom::fill(&mut nonce).unwrap();
            Self(std::env::temp_dir().join(format!("rust-x-ts-{}", to_hex(&nonce))))
        }
    }

    impl Drop for StateDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn identity_survives_restart() {
        let dir = StateDir::new();
        let first = load_or_create_keys(Some(&dir.0), false).unwrap();
        let second = load_or_create_keys(Some(&dir.0), false).unwrap();
        assert_eq!(first.0.to_bytes(), second.0.to_bytes());
        assert_eq!(first.1.to_bytes(), second.1.to_bytes());
        assert_eq!(PublicKey::from(&first.1), PublicKey::from(&second.1));
        assert!(!dir.0.join("tailscale.state.new").exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(dir.0.join("tailscale.state"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn invalid_state_is_preserved_and_rejected() {
        let dir = StateDir::new();
        fs::create_dir_all(&dir.0).unwrap();
        let path = dir.0.join("tailscale.state");
        for content in [
            "broken",
            r#"{"MachineKey":"00","NodeKey":"00"}"#,
            r#"{"Version":1,"MachineKey":"00","NodeKey":"00"}"#,
        ] {
            fs::write(&path, content).unwrap();
            assert!(matches!(load_or_create_keys(Some(&dir.0), false),
                Err(err) if err.kind() == io::ErrorKind::InvalidData));
            assert_eq!(fs::read_to_string(&path).unwrap(), content);
        }
    }

    #[test]
    fn ephemeral_identity_does_not_touch_persistent_state() {
        let dir = StateDir::new();
        let first = load_or_create_keys(Some(&dir.0), true).unwrap();
        let second = load_or_create_keys(Some(&dir.0), true).unwrap();
        assert_ne!(first.0.to_bytes(), second.0.to_bytes());
        assert!(!dir.0.exists());
        let persistent = load_or_create_keys(Some(&dir.0), false).unwrap();
        load_or_create_keys(Some(&dir.0), true).unwrap();
        let restored = load_or_create_keys(Some(&dir.0), false).unwrap();
        assert_eq!(persistent.0.to_bytes(), restored.0.to_bytes());
    }

    #[test]
    fn persistence_failure_is_reported() {
        let dir = StateDir::new();
        fs::create_dir_all(&dir.0).unwrap();
        fs::write(dir.0.join("tailscale.state.new"), "occupied").unwrap();
        assert!(load_or_create_keys(Some(&dir.0), false).is_err());
        assert!(!dir.0.join("tailscale.state").exists());
    }

    #[test]
    fn non_ascii_key_is_rejected_without_panic() {
        assert!(parse_key_hex(&"é".repeat(32)).is_none());
    }

    #[test]
    fn test_register_and_map_response_parsing() {
        let register_json = r#"{
            "Node": {
                "ID": 1001,
                "Key": "nodekey:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                "Addresses": ["100.64.0.1/32", "fd7a:115c:a1e0::1/128"],
                "AllowedIPs": ["100.64.0.1/32"],
                "Endpoints": ["1.2.3.4:41641"]
            },
            "MachineAuthorized": true
        }"#;

        let reg_resp: RegisterResponse = serde_json::from_str(register_json).unwrap();
        assert_eq!(reg_resp.machine_authorized, Some(true));
        let node = reg_resp.node.unwrap();
        assert_eq!(node.id, 1001);
        assert_eq!(node.addresses.len(), 2);
        assert_eq!(node.addresses[0], "100.64.0.1/32");

        let map_json = r#"{
            "Peers": [
                {
                    "ID": 2002,
                    "Key": "nodekey:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
                    "Name": "peer-server",
                    "Addresses": ["100.64.0.2/32"],
                    "AllowedIPs": ["100.64.0.2/32", "192.168.10.0/24"],
                    "Endpoints": ["5.6.7.8:41641"],
                    "DERP": 1,
                    "Online": true
                }
            ],
            "DERPMap": {
                "Regions": {
                    "1": {
                        "RegionID": 1,
                        "RegionCode": "nyc",
                        "Nodes": [
                            {
                                "Name": "1a",
                                "RegionID": 1,
                                "HostName": "derp1a.tailscale.com",
                                "Port": 443
                            }
                        ]
                    }
                }
            }
        }"#;

        let map_resp: MapResponse = serde_json::from_str(map_json).unwrap();
        let peers = map_resp.peers.unwrap();
        assert_eq!(peers.len(), 1);
        assert_eq!(peers[0].name.as_deref(), Some("peer-server"));
        assert_eq!(peers[0].allowed_ips.as_ref().unwrap().len(), 2);

        let derp_map = super::super::derp::DerpMap::from(map_resp.derp_map.unwrap());
        assert!(derp_map.regions.contains_key("1"));
        let region = &derp_map.regions["1"];
        assert_eq!(region.region_code, "nyc");
        assert_eq!(region.nodes[0].host_name, "derp1a.tailscale.com");
    }

    #[test]
    fn test_key_hex_conversion() {
        let pk_bytes = [42u8; 32];
        let pk = PublicKey::from(pk_bytes);
        let formatted = node_key_str(&pk);
        assert!(formatted.starts_with("nodekey:"));
        let parsed = parse_key_hex(&formatted).unwrap();
        assert_eq!(parsed, pk_bytes);
    }

    #[test]
    fn peer_patches_apply_in_wire_order_and_new_streams_clear_old_peers() {
        let parse = |raw: &str| serde_json::from_str::<MapResponse>(raw).unwrap();
        let mut peers = HashMap::new();
        parse(
            r#"{"Peers":[{"ID":1,"Key":"old","Endpoints":["192.0.2.1:1"]},
                           {"ID":2,"Key":"removed"}],"PeersRemoved":[1]}"#,
        )
        .update_peers(&mut peers, true);
        let mut patch = parse(
            r#"{"KeepAlive":true,"PeersRemoved":[2],
            "PeersChanged":[{"ID":1,"Key":"replacement","Endpoints":["192.0.2.1:1"]}],
            "OnlineChange":{"1":true},
            "PeersChangedPatch":[{"NodeID":1,"DERPRegion":8,"DiscoKey":"disco",
                                  "Key":"rotated","Endpoints":[],"Online":false},
                                 {"NodeID":3,"Key":"unknown"}]}"#,
        );
        assert!(!patch.is_keep_alive_only());
        patch.update_peers(&mut peers, false);
        assert_eq!(peers.len(), 1);
        let peer = &peers[&1];
        assert_eq!(peer.key, "rotated");
        assert_eq!(peer.disco_key.as_deref(), Some("disco"));
        assert_eq!(peer.home_derp, Some(8));
        assert_eq!(peer.endpoints, Some(vec![]));
        assert_eq!(peer.online, Some(false));
        parse(r#"{"Node":{"ID":4,"Key":"self"}}"#).update_peers(&mut peers, true);
        assert!(peers.is_empty());
    }
}
