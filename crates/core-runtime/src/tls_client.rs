//! Outbound TLS client: rustls with the pure-Rust crypto provider.
//!
//! uTLS fingerprints and REALITY land in F2 (ADR-0004); uTLS degrades with a
//! warning, REALITY is rejected because silent fallback would be misleading.

use std::io;
use std::sync::Arc;

use core_tls::rustls;
use rustls_pemfile::certs;
use rustls_pemfile::private_key;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_rustls::client::TlsStream;

use crate::inbound::AnyStream;

const TLS_CONFIG_CACHE_CAPACITY: usize = 32;
type TlsConfigKey = (bool, bool, bool, Vec<Vec<u8>>, Vec<String>, u64);
type TlsConfigCache = lru::LruCache<TlsConfigKey, Arc<rustls::ClientConfig>>;

fn new_tls_config_cache() -> std::sync::Mutex<TlsConfigCache> {
    std::sync::Mutex::new(TlsConfigCache::new(
        std::num::NonZeroUsize::new(TLS_CONFIG_CACHE_CAPACITY).unwrap(),
    ))
}

const DANGEROUS_SCHEMES: &[rustls::SignatureScheme] = &[
    rustls::SignatureScheme::ED25519,
    rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
    rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
    rustls::SignatureScheme::ECDSA_NISTP521_SHA512,
    rustls::SignatureScheme::RSA_PKCS1_SHA256,
    rustls::SignatureScheme::RSA_PKCS1_SHA384,
    rustls::SignatureScheme::RSA_PKCS1_SHA512,
    rustls::SignatureScheme::RSA_PSS_SHA256,
    rustls::SignatureScheme::RSA_PSS_SHA384,
    rustls::SignatureScheme::RSA_PSS_SHA512,
];

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        DANGEROUS_SCHEMES.to_vec()
    }
}

/// A uTLS fingerprint, resolved from the name the config used.
#[derive(Clone, Debug)]
pub struct Fingerprint {
    pub name: String,
    pub template: core_tls::hello::Template,
}

/// Read a pin field: one base64 SHA-256, or a list of them, as the reference
/// accepts. The value is the same either way - the field says what is hashed,
/// not how many entries are allowed.
fn decode_pin_list(
    tls: &serde_json::Map<String, Value>,
    field: &str,
    at: &str,
) -> anyhow::Result<Vec<[u8; 32]>> {
    let Some(value) = tls.get(field) else {
        return Ok(Vec::new());
    };
    if value.is_null() {
        return Ok(Vec::new());
    }

    let mut raw = Vec::new();
    match value {
        Value::Array(items) => {
            for item in items {
                let s = item
                    .as_str()
                    .ok_or_else(|| anyhow::anyhow!("{at}: tls.{field} entries must be strings"))?;
                raw.push(s.to_string());
            }
        }
        Value::String(s) => raw.push(s.clone()),
        other => {
            return Err(anyhow::anyhow!(
                "{at}: tls.{field} must be a string or a list of strings, got {other}"
            ));
        }
    }

    let mut out = Vec::with_capacity(raw.len());
    for entry in raw {
        let entry = entry.trim();
        if entry.is_empty() {
            continue;
        }
        let bytes = base64_decode(entry).ok_or_else(|| {
            anyhow::anyhow!("{at}: tls.{field} entry {entry:?} is not valid base64")
        })?;
        let len = bytes.len();
        let digest: [u8; 32] = bytes.try_into().map_err(|_| {
            anyhow::anyhow!("{at}: tls.{field} entry {entry:?} is {len} bytes, a SHA-256 pin is 32")
        })?;
        out.push(digest);
    }
    Ok(out)
}

/// Standard base64, with or without padding. The reference writes padded values;
/// a hand-edited config often loses the padding, and rejecting that would make
/// the pin unusable rather than merely untidy.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    let mut acc: u32 = 0;
    let mut bits = 0u32;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    for c in input.bytes() {
        if c == b'=' || c == b'\n' || c == b'\r' {
            continue;
        }
        let v = TABLE.iter().position(|t| *t == c)? as u32;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    if out.is_empty() { None } else { Some(out) }
}

/// REALITY: the server's public key and the short id that opens the session id
/// seal. A server that fails the REALITY check is refused, see
/// [`TlsOptions::establish`].
#[derive(Clone, Debug)]
pub struct Reality {
    pub public_key: [u8; 32],
    pub short_id: Vec<u8>,
    pub fingerprint: Option<Fingerprint>,
}

#[derive(Clone, Debug)]
pub struct TlsOptions {
    server_name: String,
    insecure: bool,
    disable_sni: bool,
    alpn: Vec<Vec<u8>>,
    min_tls13: bool,
    max_tls12: bool,
    ca_certs: Vec<rustls::pki_types::CertificateDer<'static>>,
    /// `certificate_sha256`: SHA-256 over the whole DER end-entity certificate.
    /// Upstream added this in 1.15; the reference calls the value a "pcs" and it
    /// is what proxy links carry.
    certificate_sha256: Vec<[u8; 32]>,
    /// `certificate_public_key_sha256`: SHA-256 over the SPKI, the public key
    /// alone. A different value from the above, so it is a second field rather
    /// than an older spelling of the first - but the only pin field that exists
    /// before 1.15, and the only one lx accepts.
    certificate_public_key_sha256: Vec<[u8; 32]>,
    /// Our own ClientHello instead of rustls': a captured browser fingerprint
    /// and the handshake written for it.
    fingerprint: Option<Fingerprint>,
    reality: Option<Reality>,
    /// Which stack does the handshake and the record layer. Our own reads
    /// records in place out of a fixed buffer; rustls shifts plaintext between
    /// two of its own buffers, and that came to a third of the client CPU on a
    /// busy websocket. `None` means "decide", see [`TlsOptions::own_stack`].
    stack: Option<bool>,
    fragment: bool,
    cipher_suites: Vec<String>,
}

impl TlsOptions {
    /// SNI / certificate name (config `server_name`, defaulting to the server).
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// Configured ALPN protocol list (empty when unset).
    pub fn alpn(&self) -> &[Vec<u8>] {
        &self.alpn
    }

    /// Parse outbound `tls` options; `None` when TLS is absent or disabled.
    pub fn from_outbound(
        obj: &serde_json::Map<String, Value>,
        server: &str,
        at: &str,
    ) -> anyhow::Result<Option<Self>> {
        let Some(tls) = obj.get("tls").and_then(Value::as_object) else {
            return Ok(None);
        };
        if tls.get("enabled").and_then(Value::as_bool) != Some(true) {
            return Ok(None);
        }

        let server_name = tls
            .get("server_name")
            .and_then(Value::as_str)
            .unwrap_or(server)
            .to_string();
        let insecure = tls
            .get("insecure")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let disable_sni = tls
            .get("disable_sni")
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let alpn = tls
            .get("alpn")
            .and_then(Value::as_array)
            .map(|list| {
                list.iter()
                    .map(|v| v.as_str().map(str::as_bytes).map(<[u8]>::to_vec))
                    .collect::<Option<Vec<_>>>()
                    .ok_or_else(|| anyhow::anyhow!("{at}: tls.alpn entries must be strings"))
            })
            .transpose()?
            .unwrap_or_default();

        let min_tls13 = match tls.get("min_version").and_then(Value::as_str) {
            None | Some("") => false,
            Some("1.2") => false,
            Some("1.3") => true,
            Some(other) => anyhow::bail!("{at}: tls.min_version {other:?} not supported"),
        };
        let max_tls12 = match tls.get("max_version").and_then(Value::as_str) {
            None | Some("") => false,
            Some("1.2") => true,
            Some("1.3") => false,
            Some(other) => anyhow::bail!("{at}: tls.max_version {other:?} not supported"),
        };

        let mut ca_certs = Vec::new();
        if let Some(pem) = tls.get("certificate").and_then(Value::as_str) {
            load_pem_certs(pem.as_bytes(), &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate: {e}"))?;
        }
        if let Some(path) = tls.get("certificate_path").and_then(Value::as_str) {
            let raw = std::fs::read(path)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path {path:?}: {e}"))?;
            load_pem_certs(&raw, &mut ca_certs)
                .map_err(|e| anyhow::anyhow!("{at}: tls.certificate_path {path:?}: {e}"))?;
        }

        let certificate_sha256 = decode_pin_list(tls, "certificate_sha256", at)?;
        let certificate_public_key_sha256 =
            decode_pin_list(tls, "certificate_public_key_sha256", at)?;

        let fingerprint = match tls.get("utls").and_then(Value::as_object) {
            Some(u) if u.get("enabled").and_then(Value::as_bool) == Some(true) => {
                let name = u
                    .get("fingerprint")
                    .and_then(Value::as_str)
                    .unwrap_or("chrome")
                    .to_string();
                let template = core_tls::fingerprints::by_name(&name).ok_or_else(|| {
                    anyhow::anyhow!("{at}: tls.utls.fingerprint: {name:?} is not a known browser")
                })?;
                Some(Fingerprint { name, template })
            }
            _ => None,
        };
        let reality = match tls.get("reality").and_then(Value::as_object) {
            Some(r) if r.get("enabled").and_then(Value::as_bool) == Some(true) => {
                let public_key =
                    parse_reality_key(r.get("public_key").and_then(Value::as_str).ok_or_else(
                        || anyhow::anyhow!("{at}: tls.reality.public_key is required"),
                    )?)
                    .map_err(|e| anyhow::anyhow!("{at}: tls.reality.public_key: {e}"))?;
                let short_id =
                    parse_short_id(r.get("short_id").and_then(Value::as_str).unwrap_or(""))
                        .map_err(|e| anyhow::anyhow!("{at}: tls.reality.short_id: {e}"))?;
                let fingerprint = match r.get("fingerprint").and_then(Value::as_str) {
                    Some(name) => {
                        let template = core_tls::fingerprints::by_name(name).ok_or_else(|| {
                            anyhow::anyhow!(
                                "{at}: tls.reality.fingerprint: {name:?} is not a known browser"
                            )
                        })?;
                        Some(Fingerprint {
                            name: name.to_string(),
                            template,
                        })
                    }
                    None => None,
                };
                Some(Reality {
                    public_key,
                    short_id,
                    fingerprint,
                })
            }
            _ => None,
        };

        let has_pins = !certificate_sha256.is_empty() || !certificate_public_key_sha256.is_empty();
        if reality.is_some() && (insecure || has_pins) {
            let ignored = match (insecure, has_pins) {
                (true, true) => "tls.insecure and the certificate pins are",
                (true, false) => "tls.insecure is",
                _ => "the certificate pins are",
            };
            crate::logging::warn(format_args!(
                "{at}: {ignored} ignored with REALITY: the server is authenticated \
                 by tls.reality.public_key only"
            ));
        } else if insecure && has_pins {
            crate::logging::info(format_args!(
                "{at}: tls.insecure with a certificate pin: the pin replaces the CA \
                 and name check"
            ));
        }

        let stack = match tls.get("stack").and_then(Value::as_str) {
            Some("core") | Some("own") => Some(true),
            Some("rustls") => Some(false),
            Some(other) => {
                return Err(anyhow::anyhow!(
                    "{at}: tls.stack: {other:?} is not one of core, own, rustls"
                ));
            }
            None => None,
        };

        let fragment = tls
            .get("fragment")
            .and_then(Value::as_bool)
            .unwrap_or(false)
            || tls
                .get("record_fragment")
                .and_then(Value::as_bool)
                .unwrap_or(false);

        let cipher_suites = tls
            .get("cipher_suites")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(Value::as_str)
                    .map(ToString::to_string)
                    .collect()
            })
            .unwrap_or_default();

        Ok(Some(Self {
            fingerprint,
            reality,
            stack,
            server_name,
            insecure,
            disable_sni,
            alpn,
            min_tls13,
            max_tls12,
            ca_certs,
            certificate_sha256,
            certificate_public_key_sha256,
            fragment,
            cipher_suites,
        }))
    }

    pub async fn connect(&self, stream: TcpStream) -> io::Result<TlsStream<TcpStream>> {
        self.connect_with_defaults(stream, &[]).await
    }

    /// TLS over any stream — the runtime fetches (rule-sets, providers) may
    /// be dialed through a proxy outbound, so the socket is not a `TcpStream`.
    pub async fn connect_stream<S>(
        &self,
        stream: S,
        default_alpn: &[&[u8]],
    ) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.handshake(stream, default_alpn).await
    }

    /// Like [`connect`], but offers `default_alpn` when the config set none —
    /// transports such as grpc/http need `h2` and sing-box injects it there.
    pub async fn connect_with_defaults(
        &self,
        stream: TcpStream,
        default_alpn: &[&[u8]],
    ) -> io::Result<TlsStream<TcpStream>> {
        self.handshake(stream, default_alpn).await
    }

    async fn handshake<S>(&self, stream: S, default_alpn: &[&[u8]]) -> io::Result<TlsStream<S>>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send,
    {
        self.refuse_reality("rustls")?;
        let versions: &[&'static rustls::SupportedProtocolVersion] = if self.min_tls13 {
            &[&rustls::version::TLS13]
        } else if self.max_tls12 {
            &[&rustls::version::TLS12]
        } else {
            rustls::ALL_VERSIONS
        };
        let alpn: Vec<Vec<u8>> = if !self.alpn.is_empty() {
            self.alpn.clone()
        } else {
            default_alpn.iter().map(|a| a.to_vec()).collect()
        };

        let connector = TlsConnector::from(self.client_config(versions, &alpn)?);
        let name = if self.disable_sni {
            rustls::pki_types::ServerName::IpAddress(rustls::pki_types::IpAddr::V4(
                std::net::Ipv4Addr::UNSPECIFIED.into(),
            ))
        } else {
            rustls::pki_types::ServerName::try_from(self.server_name.clone()).map_err(|_| {
                io::Error::other(format!("invalid server_name {:?}", self.server_name))
            })?
        };
        connector.connect(name, stream).await
    }

    fn has_pins(&self) -> bool {
        !self.certificate_sha256.is_empty() || !self.certificate_public_key_sha256.is_empty()
    }

    /// The certificate verifier for the rustls paths, or `None` for the plain
    /// root store.
    ///
    /// A pin always holds. With `insecure` it replaces the chain and name
    /// check (pin instead of CA, as the reference does), without it the chain
    /// is checked too. Only with no pin does `insecure` accept anything.
    fn rustls_verifier(
        &self,
    ) -> io::Result<Option<Arc<dyn rustls::client::danger::ServerCertVerifier>>> {
        if self.has_pins() {
            let verifier = if self.insecure {
                core_tls::verify::PinVerifier::instead_of_chain(
                    self.certificate_sha256.clone(),
                    self.certificate_public_key_sha256.clone(),
                )?
            } else {
                let inner = core_tls::verify::WebpkiVerifier::new(Arc::new(self.root_store()?))?
                    .into_inner();
                core_tls::verify::PinVerifier::new(
                    inner,
                    self.certificate_sha256.clone(),
                    self.certificate_public_key_sha256.clone(),
                )
            };
            return Ok(Some(Arc::new(verifier)));
        }
        if self.insecure {
            return Ok(Some(Arc::new(AcceptAny)));
        }
        Ok(None)
    }

    /// The rustls paths cannot do REALITY. Plain TLS in its place would send
    /// the traffic to whoever answers, so they refuse instead.
    fn refuse_reality(&self, path: &str) -> io::Result<()> {
        if self.reality.is_some() {
            return Err(io::Error::other(format!(
                "REALITY {}: not available over {path}; refusing plain TLS",
                self.server_name
            )));
        }
        Ok(())
    }

    fn root_store(&self) -> io::Result<rustls::RootCertStore> {
        // No `ca` in the config means "no pin", not "trust nothing": an empty
        // store here failed every DoH query and every plain-rustls handshake
        // with `invalid peer certificate: UnknownIssuer`, so no domain ever
        // resolved. `establish` already fell back to the Mozilla roots.
        if self.ca_certs.is_empty() {
            return Ok(core_tls::verify::WebpkiVerifier::mozilla_store());
        }
        let mut roots = rustls::RootCertStore::empty();
        for cert in &self.ca_certs {
            roots
                .add(cert.clone())
                .map_err(|e| io::Error::other(format!("bad CA certificate: {e}")))?;
        }
        Ok(roots)
    }

    /// The `ClientConfig` for these options, shared across connects. Building
    /// one re-parses every CA certificate, which does not belong on the
    /// connect path — the cache key is everything that changes the result.
    fn client_config(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[Vec<u8>],
    ) -> io::Result<Arc<rustls::ClientConfig>> {
        static CACHE: std::sync::OnceLock<std::sync::Mutex<TlsConfigCache>> =
            std::sync::OnceLock::new();
        self.client_config_cached(versions, alpn, CACHE.get_or_init(new_tls_config_cache))
    }

    fn client_config_cached(
        &self,
        versions: &[&'static rustls::SupportedProtocolVersion],
        alpn: &[Vec<u8>],
        cache: &std::sync::Mutex<TlsConfigCache>,
    ) -> io::Result<Arc<rustls::ClientConfig>> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher as _};

        let mut ca = DefaultHasher::new();
        for cert in &self.ca_certs {
            cert.as_ref().hash(&mut ca);
        }
        self.certificate_sha256.hash(&mut ca);
        self.certificate_public_key_sha256.hash(&mut ca);
        let key = (
            self.min_tls13,
            self.max_tls12,
            self.insecure,
            alpn.to_vec(),
            self.cipher_suites.clone(),
            ca.finish(),
        );
        if let Some(config) = cache.lock().expect("tls config cache").get(&key) {
            return Ok(Arc::clone(config));
        }

        let provider = if !self.cipher_suites.is_empty() {
            let suites: Vec<_> = self
                .cipher_suites
                .iter()
                .filter_map(|s| core_crypto::resolve_cipher_suite(s))
                .collect();
            if !suites.is_empty() {
                Arc::new(core_crypto::provider_with_suites(suites))
            } else {
                Arc::new(core_crypto::provider())
            }
        } else {
            Arc::new(core_crypto::provider())
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .map_err(|e| io::Error::other(format!("tls: protocol versions: {e}")))?;
        let mut config = match self.rustls_verifier()? {
            Some(verifier) => builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
            None => builder
                .with_root_certificates(self.root_store()?)
                .with_no_client_auth(),
        };
        config.alpn_protocols = alpn.to_vec();
        let config = Arc::new(config);
        // A concurrent miss may have installed this key while we built it.
        // Reuse that entry; eviction only drops the cache's reference, so
        // configurations still held by active connections remain valid.
        let mut cache = cache.lock().expect("tls config cache");
        if let Some(existing) = cache.get(&key) {
            return Ok(Arc::clone(existing));
        }
        cache.put(key, Arc::clone(&config));
        Ok(config)
    }

    /// QUIC client config for quinn (hysteria2, DoQ/DoH3): TLS 1.3 only, no
    /// session resumption, ALPN from `tls.alpn` or `default_alpn`.
    pub fn quic_config(
        &self,
        default_alpn: &[&[u8]],
    ) -> io::Result<core_tls::quic::QuicClientConfig> {
        self.refuse_reality("QUIC")?;
        let provider = if !self.cipher_suites.is_empty() {
            let suites: Vec<_> = self
                .cipher_suites
                .iter()
                .filter_map(|s| core_crypto::resolve_cipher_suite(s))
                .collect();
            if !suites.is_empty() {
                Arc::new(core_crypto::quic_provider_with_suites(suites))
            } else {
                core_tls::quic::configured_provider()
            }
        } else {
            core_tls::quic::configured_provider()
        };

        let builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| io::Error::other(format!("QUIC TLS provider: {e}")))?;
        let mut config = match self.rustls_verifier()? {
            Some(verifier) => builder
                .dangerous()
                .with_custom_certificate_verifier(verifier)
                .with_no_client_auth(),
            None => builder
                .with_root_certificates(self.root_store()?)
                .with_no_client_auth(),
        };
        if !self.alpn.is_empty() {
            config.alpn_protocols = self.alpn.clone();
        } else {
            config.alpn_protocols = default_alpn.iter().map(|a| a.to_vec()).collect();
        }
        // quic-go based clients (hysteria2, sing-box, Xray) set no session
        // cache: every hello is a full handshake with both key shares. A
        // rustls ticket would add pre_shared_key/early_data, and its key
        // exchange hint would shrink key_share to the group used last time.
        config.resumption = rustls::client::Resumption::disabled();
        core_tls::quic::QuicClientConfig::try_from_rustls(Arc::new(config))
            .map_err(|e| io::Error::other(format!("QUIC initial suite: {e}")))
    }

    /// The fingerprint this handshake would present, and the REALITY parameters
    /// that go with it, if the config asked for our own ClientHello.
    pub fn fingerprint(&self) -> Option<&Fingerprint> {
        self.fingerprint
            .as_ref()
            .or_else(|| self.reality.as_ref().and_then(|r| r.fingerprint.as_ref()))
    }

    pub fn reality(&self) -> Option<&Reality> {
        self.reality.as_ref()
    }

    /// Whose TLS does the handshake and the record layer.
    ///
    /// A fingerprint or REALITY settles it: neither can be presented through
    /// rustls. Past that the config decides (`tls.stack`), and by default ours
    /// does, because it decrypts in place out of one fixed buffer where rustls
    /// moves plaintext between two of its own -- on a busy websocket that was a
    /// third of the client CPU. The one thing ours cannot do is TLS 1.2 on the
    /// client, so a config pinned to 1.2 stays on rustls.
    fn own_stack(&self) -> bool {
        if self.fragment || self.reality.is_some() {
            return true;
        }
        if self.fingerprint().is_some() {
            return true;
        }
        if let Some(stack) = self.stack {
            return stack;
        }
        !self.max_tls12
    }

    /// The verifier for our own stack without REALITY: the same policy as
    /// [`TlsOptions::rustls_verifier`].
    fn own_stack_verifier(&self) -> io::Result<Box<dyn core_tls::verify::CertVerifier>> {
        if self.has_pins() && self.insecure {
            return Ok(Box::new(core_tls::verify::PinVerifier::instead_of_chain(
                self.certificate_sha256.clone(),
                self.certificate_public_key_sha256.clone(),
            )?));
        }
        if self.insecure {
            return Ok(Box::new(core_tls::verify::AcceptsAnything));
        }
        let roots = if self.ca_certs.is_empty() {
            core_tls::verify::WebpkiVerifier::mozilla_roots()
        } else {
            let mut store = rustls::RootCertStore::empty();
            for cert in &self.ca_certs {
                store
                    .add(cert.clone())
                    .map_err(|e| io::Error::other(format!("trust store: {e}")))?;
            }
            core_tls::verify::WebpkiVerifier::new(Arc::new(store))
        };
        let base = roots.map_err(|e| io::Error::other(format!("trust store: {e}")))?;
        // A pin narrows what is trusted, so it wraps the chain check rather
        // than replacing it: a pinned certificate that does not chain to a
        // known root is still refused.
        if !self.has_pins() {
            return Ok(Box::new(base));
        }
        Ok(Box::new(core_tls::verify::PinVerifier::new(
            base.into_inner(),
            self.certificate_sha256.clone(),
            self.certificate_public_key_sha256.clone(),
        )))
    }

    /// Establish the connection, with our own TLS when a fingerprint is
    /// configured and the library's otherwise.
    ///
    /// Both are returned as the same boxed stream, so nothing downstream has to
    /// know which one it got: that is the only reason the signature is this
    /// rather than two functions at every call site.
    /// What the hello offers: `tls.alpn`, else what the transport asks for,
    /// else `h2, http/1.1`.
    ///
    /// Xray's `GetTLSConfig` leaves no connection without ALPN: with nothing
    /// in the config it offers `h2, http/1.1`, whether or not a fingerprint
    /// is named. Our own stack writes a browser template either way, and a
    /// browser hello with no ALPN extension at all is one no browser sends,
    /// so the default covers every connection it writes rather than the
    /// REALITY and fingerprint ones alone.
    fn offered_alpn<'a>(&'a self, default_alpn: &[&'a [u8]]) -> Vec<&'a [u8]> {
        let offered: Vec<&[u8]> = if self.alpn.is_empty() {
            default_alpn.to_vec()
        } else {
            self.alpn.iter().map(|p| p.as_slice()).collect()
        };
        if offered.is_empty() {
            return vec![b"h2", b"http/1.1"];
        }
        offered
    }

    pub async fn establish<S>(&self, stream: S, default_alpn: &[&[u8]]) -> io::Result<AnyStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        self.establish_with_record_cap(stream, default_alpn, core_tls::record::MAX_FRAGMENT)
            .await
    }

    /// The same, told the steady-state record size of the transport that will
    /// run on this connection: a transport whose reference client writes in
    /// `buf.Size` pieces asks for 8192, so the records on the wire are the
    /// lengths that client's writes produce. It is a parameter rather than a
    /// field so a dial does not have to clone the options (certificates and
    /// the fingerprint template included) to set it.
    pub async fn establish_with_record_cap<S>(
        &self,
        stream: S,
        default_alpn: &[&[u8]],
        record_cap: usize,
    ) -> io::Result<AnyStream>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let alpn = self.offered_alpn(default_alpn);
        if !self.own_stack() {
            return Ok(Box::new(ClosingTls {
                inner: self.connect_stream(stream, default_alpn).await?,
                shut: false,
            }));
        }
        // With no fingerprint named, present chrome: ours always writes its own
        // hello, so there is a template to pick either way.
        let (name, template) = match self.fingerprint() {
            Some(f) => (f.name.clone(), f.template.clone()),
            None => ("chrome".to_string(), core_tls::fingerprints::chrome()),
        };
        let reality = self.reality.as_ref();
        let seal = reality.map(|r| core_tls::client::RealitySeal {
            public_key: &r.public_key,
            short_id: &r.short_id,
        });
        // A REALITY server is trusted by its borrowed certificate under the auth
        // key and by nothing else: `insecure`, pins and the chain play no part.
        // Kept as a concrete type so the verdict can be checked after the
        // handshake.
        let (verifier, reality_verifier): (Box<dyn core_tls::verify::CertVerifier>, _) =
            if reality.is_some() {
                let v = core_tls::verify::RealityVerifier::default();
                (Box::new(v.clone()), Some(v))
            } else {
                (self.own_stack_verifier()?, None)
            };
        let cipher_suites: Vec<u16> = self
            .cipher_suites
            .iter()
            .filter_map(|s| core_crypto::resolve_cipher_suite_id(s))
            .collect();
        let config = core_tls::client::Config {
            template: &template,
            server_name: if self.disable_sni {
                ""
            } else {
                &self.server_name
            },
            alpn: &alpn,
            verifier: &*verifier,
            reality: seal,
            fragment: self.fragment,
            cipher_suites,
        };
        let mut handshake = core_tls::client::Handshake::new(config)?;
        let mut stream = stream;
        let result = handshake
            .run(&mut stream)
            .await
            .map_err(|e| io::Error::other(format!("{name} handshake: {e}")));
        if let Some(v) = reality_verifier.as_ref() {
            if !v.is_verified() {
                // A server that does not recognise us answers as the site it
                // fronts; so does a redirect or a MITM. Nothing of ours goes to it.
                crate::logging::warn(format_args!(
                    "REALITY {}: authentication failed ({}); connection refused, \
                     check public_key, short_id and the clock",
                    self.server_name,
                    v.verdict()
                ));
                return Err(io::Error::other(match result {
                    Err(e) => format!("REALITY {}: {e}", self.server_name),
                    Ok(()) => format!(
                        "REALITY {}: authentication failed: {}",
                        self.server_name,
                        v.verdict()
                    ),
                }));
            }
            crate::logging::debug(format_args!(
                "REALITY {}: {}",
                self.server_name,
                v.verdict()
            ));
        }
        result?;
        let connection = core_tls::client::Connection::new(&mut handshake)?;
        let alpn = handshake.alpn.clone();
        crate::logging::debug(format_args!(
            "tls: established {} sni={} alpn=[{}]",
            name,
            self.server_name,
            alpn.iter()
                .map(|a| String::from_utf8_lossy(a).into_owned())
                .collect::<Vec<_>>()
                .join(",")
        ));
        let tls_stream = Box::new(crate::tls_utls::FingerprintStream::with_record_cap(
            stream, connection, record_cap,
        ));
        Ok(Box::new(crate::inbound::AlpnStream::new(tls_stream, alpn)))
    }

    pub async fn wrap(&self, stream: TcpStream) -> io::Result<AnyStream> {
        self.establish(stream, &[]).await
    }

    pub async fn wrap_with_defaults(
        &self,
        stream: TcpStream,
        default_alpn: &[&[u8]],
    ) -> io::Result<AnyStream> {
        self.establish(stream, default_alpn).await
    }

    /// Like [`Self::wrap_with_defaults`], with the records of the transport
    /// that will run on the connection.
    pub(crate) async fn wrap_with_record_cap(
        &self,
        stream: TcpStream,
        default_alpn: &[&[u8]],
        record_cap: usize,
    ) -> io::Result<AnyStream> {
        self.establish_with_record_cap(stream, default_alpn, record_cap)
            .await
    }

    /// Replace whatever `tls.alpn` said: a transport that knows which protocol
    /// it will speak on this connection narrows the offer itself.
    pub(crate) fn set_alpn(&mut self, alpn: &[&[u8]]) {
        self.alpn = alpn.iter().map(|a| a.to_vec()).collect();
    }
}

/// A REALITY public key: 32 bytes of X25519, base64url without padding.
pub(crate) fn parse_reality_key(value: &str) -> Result<[u8; 32], String> {
    use base64::Engine;
    let raw = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|e| e.to_string())?;
    raw.try_into()
        .map_err(|_| format!("{value:?} is not 32 bytes"))
}

/// A REALITY short id: an even number of hex digits, at most 16.
pub(crate) fn parse_short_id(value: &str) -> Result<Vec<u8>, String> {
    if value.is_empty() {
        return Ok(Vec::new());
    }
    if value.len() > 16 || !value.len().is_multiple_of(2) {
        return Err(format!("{value:?} must be 1..8 bytes of hex"));
    }
    (0..value.len() / 2)
        .map(|i| {
            u8::from_str_radix(&value[i * 2..i * 2 + 2], 16)
                .map_err(|_| format!("{value:?} is not hex"))
        })
        .collect()
}

/// Trust for the runtime's own HTTPS: URLTest probes and the downloads of
/// remote rule-sets and external_ui without an explicit `tls` block. It is
/// independent of the proxy node's TLS/REALITY options. Embedded Mozilla
/// roots also work on OpenWrt without a system CA package. Additional roots
/// use the existing top-level certificate configuration.
pub(crate) fn probe_connector(root: &Value) -> anyhow::Result<TlsConnector> {
    let mut roots = core_tls::verify::WebpkiVerifier::mozilla_store();
    if let Some(options) = root.get("certificate") {
        for field in ["certificate", "certificate_path"] {
            let Some(value) = options.get(field).filter(|v| !v.is_null()) else {
                continue;
            };
            let entries: Vec<&str> = match value {
                Value::String(s) => vec![s],
                Value::Array(items) => items
                    .iter()
                    .map(|v| {
                        v.as_str()
                            .ok_or_else(|| anyhow::anyhow!("certificate.{field}: expected strings"))
                    })
                    .collect::<anyhow::Result<_>>()?,
                _ => anyhow::bail!("certificate.{field}: expected a string or string array"),
            };
            if entries.is_empty() {
                continue;
            }
            // Inline entries may be individual PEM lines or complete PEM blocks.
            let pems = if field == "certificate" {
                vec![entries.join("\n").into_bytes()]
            } else {
                entries
                    .iter()
                    .map(std::fs::read)
                    .collect::<Result<Vec<_>, _>>()?
            };
            for pem in pems {
                let mut parsed = Vec::new();
                load_pem_certs(&pem, &mut parsed)?;
                anyhow::ensure!(
                    !parsed.is_empty(),
                    "certificate.{field}: no PEM certificates"
                );
                for cert in parsed {
                    roots.add(cert)?;
                }
            }
        }
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(core_crypto::provider()))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// Authenticate an HTTPS server (URLTest site or download), including its name
/// and handshake signatures.
pub(crate) async fn wrap_probe(
    stream: AnyStream,
    server_name: &str,
    connector: &TlsConnector,
) -> io::Result<AnyStream> {
    let name = rustls::pki_types::ServerName::try_from(server_name.to_string())
        .map_err(|_| io::Error::other(format!("invalid probe server_name {server_name:?}")))?;
    Ok(Box::new(connector.connect(name, stream).await?))
}

fn load_pem_certs(
    mut pem: &[u8],
    out: &mut Vec<rustls::pki_types::CertificateDer<'static>>,
) -> io::Result<()> {
    for cert in certs(&mut pem) {
        out.push(cert.map_err(|e| io::Error::other(format!("bad PEM: {e}")))?);
    }
    Ok(())
}

/// Load a PEM private key (unused yet; inbound TLS server lands in F5).
#[allow(dead_code)]
fn load_pem_key(mut pem: &[u8]) -> io::Result<()> {
    private_key(&mut pem)?;
    Ok(())
}

/// A rustls client stream that says close_notify when it is dropped without a
/// shutdown, as Go's `tls.Conn.Close` does; a shutdown already sends it
/// (tokio-rustls). There is no waiting in a drop, so this is one attempt:
/// whatever the socket takes now.
struct ClosingTls<S: AsyncWrite + Unpin> {
    inner: TlsStream<S>,
    shut: bool,
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for ClosingTls<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for ClosingTls<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        self.shut = true;
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// `io::Write` over an async writer, for one attempt with nobody to wake.
struct NowWriter<'a, S>(&'a mut S);

impl<S: AsyncWrite + Unpin> io::Write for NowWriter<'_, S> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
        match std::pin::Pin::new(&mut *self.0).poll_write(&mut cx, buf) {
            std::task::Poll::Ready(result) => result,
            std::task::Poll::Pending => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<S: AsyncWrite + Unpin> Drop for ClosingTls<S> {
    fn drop(&mut self) {
        if self.shut {
            return;
        }
        let (io, connection) = self.inner.get_mut();
        connection.send_close_notify();
        while connection.wants_write() {
            match connection.write_tls(&mut NowWriter(io)) {
                Ok(n) if n > 0 => {}
                _ => break,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn options(value: Value) -> anyhow::Result<Option<TlsOptions>> {
        let obj = value.as_object().expect("an object").clone();
        TlsOptions::from_outbound(&obj, "example.com", "443")
    }

    /// No connection goes out without ALPN, as in Xray: `tls.alpn` wins,
    /// then what the transport asks for, then `h2, http/1.1`.
    #[test]
    fn a_hello_always_offers_alpn() {
        let plain = options(json!({"tls": {"enabled": true}})).unwrap().unwrap();
        assert_eq!(
            plain.offered_alpn(&[]),
            vec![b"h2".as_slice(), b"http/1.1".as_slice()],
            "a raw TLS outbound with no fingerprint used to offer none"
        );
        // what the transport asks for is left alone
        assert_eq!(
            plain.offered_alpn(&[b"http/1.1"]),
            vec![b"http/1.1".as_slice()]
        );
        let configured = options(json!({"tls": {"enabled": true, "alpn": ["h3"]}}))
            .unwrap()
            .unwrap();
        assert_eq!(configured.offered_alpn(&[b"h2"]), vec![b"h3".as_slice()]);
    }

    #[test]
    fn tls_cache_separates_certificate_and_public_key_pin_policies() {
        let mut tls = options(json!({"tls": {"enabled": true}})).unwrap().unwrap();
        let cache = new_tls_config_cache();
        let versions = &[&rustls::version::TLS13];
        let plain = tls.client_config_cached(versions, &[], &cache).unwrap();
        tls.certificate_sha256 = vec![[1; 32]];
        let pinned = tls.client_config_cached(versions, &[], &cache).unwrap();
        assert!(!Arc::ptr_eq(&plain, &pinned));
        tls.certificate_sha256 = vec![[2; 32]];
        let changed = tls.client_config_cached(versions, &[], &cache).unwrap();
        assert!(!Arc::ptr_eq(&pinned, &changed));
        tls.certificate_public_key_sha256 = vec![[3; 32]];
        let public = tls.client_config_cached(versions, &[], &cache).unwrap();
        assert!(!Arc::ptr_eq(&changed, &public));
        assert!(Arc::ptr_eq(
            &public,
            &tls.client_config_cached(versions, &[], &cache).unwrap()
        ));
    }

    fn golden_cert(pem: &[u8]) -> rustls::pki_types::CertificateDer<'static> {
        rustls_pemfile::certs(&mut &pem[..])
            .next()
            .unwrap()
            .unwrap()
    }

    fn golden_key() -> rustls::pki_types::PrivateKeyDer<'static> {
        rustls_pemfile::private_key(
            &mut include_bytes!("../../../tests/golden/certs/localhost.key").as_slice(),
        )
        .unwrap()
        .unwrap()
    }

    /// A P-256 key that belongs to none of the golden certificates: a server
    /// presenting one of them with this key has a copy of the certificate and
    /// not its key.
    const OTHER_KEY: &[u8] = b"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg8qHRyWI0YekLHzX+
AM3z8J7bxUIpWjg/MrnUqb7wchKhRANCAAREXEc3xfZCP97wCTFKHg/dwvuwFf4d
tKRtIBbVNqzAuojxmi55s2+rAP2MkmRaA4dJ5cDEEsVBbwnQkkEKHOPK
-----END PRIVATE KEY-----
";

    /// Serves a certificate with whatever key it is given, matching or not.
    #[derive(Debug)]
    struct AnyPair(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for AnyPair {
        fn resolve(
            &self,
            _hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    fn server_config(
        cert: rustls::pki_types::CertificateDer<'static>,
        key_holder: bool,
        provider: Arc<rustls::crypto::CryptoProvider>,
    ) -> rustls::ServerConfig {
        let key = if key_holder {
            golden_key()
        } else {
            rustls_pemfile::private_key(&mut &OTHER_KEY[..])
                .unwrap()
                .unwrap()
        };
        let key = core_crypto::sign::any_supported_type(&key).unwrap();
        rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(AnyPair(Arc::new(
                rustls::sign::CertifiedKey::new(vec![cert], key),
            ))))
    }

    /// Which server certificate a row of the pin table presents.
    #[derive(Clone, Copy, Debug)]
    enum Served {
        /// chains to the configured CA, right name, right key
        Valid,
        /// self-signed, so it chains to nothing configured
        SelfSigned,
        /// chains to the CA, but for another name
        WrongName,
        /// the valid certificate, signed for with a key that is not its own
        Stolen,
    }

    /// The pin policy on both TCP stacks. A pin always holds; `insecure` only
    /// decides whether the chain and name are checked as well. With no pin,
    /// `insecure` still accepts anything.
    #[tokio::test]
    async fn ordinary_tls_requires_matching_pins_in_addition_to_the_ca() {
        use sha2::Digest;
        use tokio::net::TcpListener;
        let valid = golden_cert(include_bytes!(
            "../../../tests/golden/certs/urltest-valid.crt"
        ));
        let self_signed = golden_cert(include_bytes!("../../../tests/golden/certs/localhost.crt"));
        let wrong_name = golden_cert(include_bytes!(
            "../../../tests/golden/certs/urltest-wrong-name.crt"
        ));
        let ca = golden_cert(include_bytes!("../../../tests/golden/certs/urltest-ca.crt"));
        let pin = |c: &rustls::pki_types::CertificateDer<'_>| -> [u8; 32] {
            sha2::Sha256::digest(c.as_ref()).into()
        };
        let cert_pin = pin(&valid);
        let key_pin = core_tls::verify::spki_sha256(valid.as_ref()).unwrap();
        let self_signed_pin = pin(&self_signed);
        let wrong_name_pin = pin(&wrong_name);
        let zero = [0u8; 32];
        use Served::*;
        // served, certificate pins, public key pins, insecure, accepted
        type Row = (Served, Vec<[u8; 32]>, Vec<[u8; 32]>, bool, bool);
        let table: Vec<Row> = vec![
            (Valid, vec![], vec![], false, true),
            (Valid, vec![cert_pin], vec![key_pin], false, true),
            (Valid, vec![zero], vec![], false, false),
            (Valid, vec![], vec![zero], false, false),
            (Valid, vec![cert_pin], vec![zero], false, false),
            // insecure no longer switches the pins off
            (Valid, vec![zero], vec![zero], true, false),
            (Valid, vec![zero], vec![], true, false),
            (Valid, vec![], vec![zero], true, false),
            (Valid, vec![cert_pin], vec![zero], true, false),
            (Valid, vec![cert_pin], vec![key_pin], true, true),
            (Valid, vec![cert_pin], vec![], true, true),
            (Valid, vec![], vec![key_pin], true, true),
            // no pin: insecure accepts anything, as before
            (Valid, vec![], vec![], true, true),
            (SelfSigned, vec![], vec![], true, true),
            (WrongName, vec![], vec![], true, true),
            (Stolen, vec![], vec![], true, true),
            // pin instead of CA: a self-signed or misnamed certificate is taken
            // on its pin with insecure, and still needs the chain without it
            (SelfSigned, vec![], vec![], false, false),
            (SelfSigned, vec![self_signed_pin], vec![], false, false),
            (SelfSigned, vec![self_signed_pin], vec![], true, true),
            (SelfSigned, vec![zero], vec![], true, false),
            (WrongName, vec![wrong_name_pin], vec![], false, false),
            (WrongName, vec![wrong_name_pin], vec![], true, true),
            // a copy of the pinned certificate without its key is refused
            (Stolen, vec![cert_pin], vec![key_pin], true, false),
            (Stolen, vec![cert_pin], vec![], true, false),
            (Stolen, vec![cert_pin], vec![key_pin], false, false),
            (Stolen, vec![], vec![], false, false),
        ];
        for own_stack in [true, false] {
            for (served, cert_pins, key_pins, insecure, expected) in &table {
                let (cert, key_holder) = match served {
                    Valid => (valid.clone(), true),
                    SelfSigned => (self_signed.clone(), true),
                    WrongName => (wrong_name.clone(), true),
                    Stolen => (valid.clone(), false),
                };
                let cfg = server_config(cert, key_holder, Arc::new(core_crypto::provider()));
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let task = tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let _ = acceptor.accept(socket).await;
                });
                let mut tls = options(json!({"tls":{"enabled":true,"server_name":"localhost"}}))
                    .unwrap()
                    .unwrap();
                tls.ca_certs = vec![ca.clone()];
                tls.certificate_sha256 = cert_pins.clone();
                tls.certificate_public_key_sha256 = key_pins.clone();
                tls.insecure = *insecure;
                tls.stack = Some(own_stack);
                assert_eq!(tls.own_stack(), own_stack);
                let socket = TcpStream::connect(addr).await.unwrap();
                let result =
                    tokio::time::timeout(std::time::Duration::from_secs(5), tls.wrap(socket))
                        .await
                        .unwrap();
                assert_eq!(
                    result.is_ok(),
                    *expected,
                    "TLS pin policy: own_stack={own_stack} served={served:?} \
                     cert_pins={} key_pins={} insecure={insecure}: {:?}",
                    cert_pins.len(),
                    key_pins.len(),
                    result.err()
                );
                task.abort();
            }
        }
    }

    #[test]
    fn tls_config_cache_evicts_old_entries_without_invalidating_live_configs() {
        let tls = options(json!({"tls": {"enabled": true}})).unwrap().unwrap();
        let cache = new_tls_config_cache();
        let versions = &[&rustls::version::TLS13];
        let first_alpn = vec![b"first".to_vec()];
        let first = tls
            .client_config_cached(versions, &first_alpn, &cache)
            .unwrap();
        let repeated = tls
            .client_config_cached(versions, &first_alpn, &cache)
            .unwrap();
        assert!(Arc::ptr_eq(&first, &repeated));
        drop(repeated);
        for index in 0..TLS_CONFIG_CACHE_CAPACITY {
            let alpn = vec![format!("entry-{index}").into_bytes()];
            tls.client_config_cached(versions, &alpn, &cache).unwrap();
        }
        assert_eq!(cache.lock().unwrap().len(), TLS_CONFIG_CACHE_CAPACITY);
        assert_eq!(Arc::strong_count(&first), 1);
        assert_eq!(first.alpn_protocols, first_alpn);
        let rebuilt = tls
            .client_config_cached(versions, &first_alpn, &cache)
            .unwrap();
        assert!(!Arc::ptr_eq(&first, &rebuilt));
        assert_eq!(rebuilt.alpn_protocols, first.alpn_protocols);
        assert_eq!(cache.lock().unwrap().len(), TLS_CONFIG_CACHE_CAPACITY);
    }

    #[tokio::test]
    async fn quic_requires_matching_certificate_and_public_key_pins() {
        use sha2::Digest;
        let cert = rustls_pemfile::certs(
            &mut include_bytes!("../../../tests/golden/certs/urltest-valid.crt").as_slice(),
        )
        .next()
        .unwrap()
        .unwrap();
        let ca = rustls_pemfile::certs(
            &mut include_bytes!("../../../tests/golden/certs/urltest-ca.crt").as_slice(),
        )
        .next()
        .unwrap()
        .unwrap();
        let cert_pin: [u8; 32] = sha2::Sha256::digest(cert.as_ref()).into();
        let key_pin = core_tls::verify::spki_sha256(cert.as_ref()).unwrap();
        let endpoint_config =
            || quinn::EndpointConfig::new(Arc::new(core_tls::quic::HmacSha256Key::new(&[9; 32])));
        let serve = |key_holder: bool, classical_only: bool| {
            let mut provider = (*core_tls::quic::configured_provider()).clone();
            if classical_only {
                provider
                    .kx_groups
                    .retain(|g| g.name() == rustls::NamedGroup::X25519);
            }
            let mut cfg = server_config(cert.clone(), key_holder, Arc::new(provider));
            cfg.alpn_protocols = vec![b"h3".to_vec()];
            let server_config = quinn::ServerConfig::new(
                Arc::new(core_tls::quic::QuicServerConfig::try_from(cfg).unwrap()),
                Arc::new(core_tls::quic::HandshakeTokenKeyRustCrypto::new([7; 64])),
            );
            let server = quinn::Endpoint::new(
                endpoint_config(),
                Some(server_config),
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                quinn::default_runtime().unwrap(),
            )
            .unwrap();
            let addr = server.local_addr().unwrap();
            let task = tokio::spawn(async move {
                while let Some(incoming) = server.accept().await {
                    tokio::spawn(async move {
                        if let Ok(connection) = incoming.await {
                            connection.closed().await;
                        }
                    });
                }
            });
            (addr, task)
        };
        let (genuine, genuine_task) = serve(true, false);
        let (classical, classical_task) = serve(true, true);
        // the pinned certificate, signed for with a key that is not its own
        let (stolen, stolen_task) = serve(false, false);
        for chrome in [false, true] {
            for (addr, cert_pins, key_pins, insecure, expected) in [
                (genuine, vec![cert_pin], vec![key_pin], false, true),
                // Both offered shares must retain the matching private key.
                (classical, vec![cert_pin], vec![key_pin], false, true),
                (classical, vec![[0; 32]], vec![], false, false),
                (genuine, vec![[0; 32]], vec![], false, false),
                (genuine, vec![], vec![[0; 32]], false, false),
                // insecure does not switch the pins off
                (genuine, vec![cert_pin], vec![key_pin], true, true),
                (genuine, vec![cert_pin], vec![], true, true),
                (genuine, vec![[0; 32]], vec![], true, false),
                (genuine, vec![], vec![[0; 32]], true, false),
                (genuine, vec![[0; 32]], vec![[0; 32]], true, false),
                // and without a pin it still accepts anything
                (genuine, vec![], vec![], true, true),
                (stolen, vec![], vec![], true, true),
                // a pin is only as good as the handshake signature behind it
                (stolen, vec![cert_pin], vec![key_pin], true, false),
                (stolen, vec![cert_pin], vec![key_pin], false, false),
            ] {
                let mut tls = options(json!({"tls":{"enabled":true,"server_name":"localhost"}}))
                    .unwrap()
                    .unwrap();
                tls.ca_certs = vec![ca.clone()];
                tls.certificate_sha256 = cert_pins;
                tls.certificate_public_key_sha256 = key_pins;
                tls.insecure = insecure;
                let mut client = quinn::Endpoint::new(
                    endpoint_config(),
                    None,
                    std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                    quinn::default_runtime().unwrap(),
                )
                .unwrap();
                let crypto = tls.quic_config(&[b"h3"]).unwrap();
                let crypto = if chrome {
                    crypto.with_hy2_chrome().unwrap()
                } else {
                    crypto
                };
                let mut config = quinn::ClientConfig::new(Arc::new(crypto));
                if chrome {
                    let mut transport = quinn::TransportConfig::default();
                    transport.chrome_initial(true);
                    config.transport_config(Arc::new(transport));
                }
                client.set_default_client_config(config);
                let result = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.connect(addr, "localhost").unwrap(),
                )
                .await
                .unwrap();
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "QUIC pin policy: insecure={insecure} {:?}",
                    result.err()
                );
                client.close(0u32.into(), b"test complete");
            }
        }
        genuine_task.abort();
        classical_task.abort();
        stolen_task.abort();
    }

    /// Browser profiles on our own stack still verify the chain and the name.
    #[tokio::test]
    async fn fingerprinted_tls_verifies_the_certificate() {
        use tokio::net::TcpListener;
        let valid = golden_cert(include_bytes!(
            "../../../tests/golden/certs/urltest-valid.crt"
        ));
        let wrong_name = golden_cert(include_bytes!(
            "../../../tests/golden/certs/urltest-wrong-name.crt"
        ));
        let ca = golden_cert(include_bytes!("../../../tests/golden/certs/urltest-ca.crt"));
        for fingerprint in ["chrome", "firefox", "safari", "edge"] {
            for (cert, expected) in [(&valid, true), (&valid, true), (&wrong_name, false)] {
                let cfg = server_config(cert.clone(), true, Arc::new(core_crypto::provider()));
                let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let task = tokio::spawn(async move {
                    let (socket, _) = listener.accept().await.unwrap();
                    let _ = acceptor.accept(socket).await;
                });
                let mut tls = options(json!({"tls": {
                    "enabled": true,
                    "server_name": "localhost",
                    "utls": {"enabled": true, "fingerprint": fingerprint}
                }}))
                .unwrap()
                .unwrap();
                tls.ca_certs = vec![ca.clone()];
                assert!(tls.own_stack(), "{fingerprint}");
                let socket = TcpStream::connect(addr).await.unwrap();
                let result =
                    tokio::time::timeout(std::time::Duration::from_secs(5), tls.wrap(socket))
                        .await
                        .unwrap();
                assert_eq!(
                    result.is_ok(),
                    expected,
                    "{fingerprint}: {:?}",
                    result.err()
                );
                task.abort();
            }
        }
    }

    /// The whole point of the change: a fingerprint in the config is a table we
    /// resolve now, and the hello it produces is ours.
    #[test]
    fn a_fingerprint_resolves_to_a_table() {
        let tls = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "firefox"}}
        }))
        .expect("valid")
        .expect("tls present");
        let fingerprint = tls.fingerprint().expect("a fingerprint");
        assert_eq!(fingerprint.name, "firefox");
        assert!(
            fingerprint
                .template
                .extensions
                .iter()
                .any(|e| matches!(e, core_tls::hello::Ext::KeyShare(_)))
        );
        assert!(tls.reality().is_none());
    }

    #[test]
    fn random_fingerprints_survive_runtime_construction() {
        for name in ["random", "randomized"] {
            let tls = options(json!({
                "server": "example.com",
                "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": name}}
            }))
            .expect("a validator-accepted fingerprint must also start")
            .expect("TLS present");
            assert_eq!(tls.fingerprint().unwrap().name, name);
            assert!(tls.own_stack());
        }
    }

    /// An empty fingerprint is chrome, the way the reference reads it, and a
    /// name it does not know is refused rather than quietly downgraded: the
    /// whole point of asking for a browser is getting that browser.
    #[test]
    fn the_fingerprint_name_is_not_guessed_at() {
        let chrome = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "utls": {"enabled": true}}
        }))
        .expect("valid")
        .expect("tls present");
        assert_eq!(chrome.fingerprint().expect("a fingerprint").name, "chrome");

        let err = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "netscape"}}
        }))
        .expect_err("an unknown browser is an error");
        assert!(err.to_string().contains("netscape"), "{err}");
    }

    /// REALITY's public key is 32 bytes of X25519 and its short id is up to
    /// eight bytes of hex; both are parsed the way the reference writes them.
    #[test]
    fn the_reality_parameters_are_parsed_like_the_reference_writes_them() {
        let key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8";
        let tls = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "reality": {
                "enabled": true, "public_key": key, "short_id": "1234abcd"
            }}
        }))
        .expect("valid")
        .expect("tls present");
        let reality = tls.reality().expect("reality");
        assert_eq!(reality.short_id, vec![0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(reality.public_key.len(), 32);

        // no short id is legal: the server may have none configured
        let none = options(json!({
            "server": "example.com",
            "tls": {"enabled": true, "reality": {"enabled": true, "public_key": key}}
        }))
        .expect("valid")
        .expect("tls present");
        assert!(none.reality().expect("reality").short_id.is_empty());

        for bad in ["123", "1234567890abcdef01", "zz"] {
            let value = json!({
                "server": "example.com",
                "tls": {"enabled": true, "reality": {
                    "enabled": true, "public_key": key, "short_id": bad
                }}
            });
            assert!(options(value).is_err(), "short_id {bad:?} was accepted");
        }
    }

    #[test]
    fn a_reality_key_that_is_not_32_bytes_is_refused() {
        for bad in ["", "AAAA", "not base64 at all!"] {
            let value = json!({
                "server": "example.com",
                "tls": {"enabled": true, "reality": {"enabled": true, "public_key": bad}}
            });
            assert!(options(value).is_err(), "public_key {bad:?} was accepted");
        }
    }

    /// The rustls path says close_notify when its stream is dropped without
    /// a shutdown, as Go's `tls.Conn.Close` does, and on a shutdown, keeping
    /// the download open.
    #[tokio::test]
    async fn the_rustls_path_says_close_notify_on_drop_and_shutdown() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        core_tls::install_default_provider();
        let dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/golden/certs");
        let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.crt")).unwrap(),
        ))
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(
            std::fs::File::open(dir.join("localhost.key")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(certs, key)
                .unwrap(),
        );
        for shutdown in [false, true] {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::clone(&config));
            let server = tokio::spawn(async move {
                let (socket, _) = listener.accept().await.unwrap();
                let mut tls = acceptor.accept(socket).await.unwrap();
                tls.write_all(b"go").await.unwrap();
                let mut got = Vec::new();
                let end = tls.read_to_end(&mut got).await.map_err(|e| e.kind());
                // the download goes on after the client's close_notify
                let _ = tls.write_all(b"late").await;
                let _ = tls.shutdown().await;
                end.map(|_| got)
            });
            let tls = options(json!({"tls": {"enabled": true, "server_name": "localhost",
                "insecure": true}}))
            .unwrap()
            .unwrap();
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut stream = tls.establish(tcp, &[]).await.unwrap();
            let mut go = [0u8; 2];
            stream.read_exact(&mut go).await.unwrap();
            stream.write_all(b"bye").await.unwrap();
            if shutdown {
                stream.shutdown().await.unwrap();
                let mut late = Vec::new();
                stream.read_to_end(&mut late).await.unwrap();
                assert_eq!(late, b"late");
            }
            drop(stream);
            assert_eq!(
                server.await.unwrap(),
                Ok(b"bye".to_vec()),
                "shutdown {shutdown}"
            );
        }
    }
}
