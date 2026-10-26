use std::io;

use crate::keyshare;

fn err(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ext {
    Static(u16, Vec<u8>),
    Sni,
    /// The protocol list the caller configured, in the fingerprint's own order.
    Alpn,
    KeyShare(Vec<u8>),
    /// GREASE `encrypted_client_hello` (0xfe0d), drawn fresh per hello.
    EchGrease(EchGrease),
}

/// What a profile fixes about its GREASE ECH; config_id, enc and the payload
/// are drawn per hello, as uTLS's `GREASEEncryptedClientHelloExtension` does
/// (utls aa6edf4b11af, u_ech.go:65-143).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchGrease {
    /// HPKE (kdf, aead) pairs, one picked per hello (u_ech.go:95-109).
    pub cipher_suites: &'static [(u16, u16)],
    /// Plaintext lengths, one picked per hello; the payload is 16 bytes longer,
    /// the AEAD tag (u_ech.go:130-160, u_hpke.go:28-35).
    pub payload_lens: &'static [u16],
}

const HKDF_SHA256: u16 = 0x0001;
const AES_128_GCM: u16 = 0x0001;
const CHACHA20_POLY1305: u16 = 0x0003;

impl EchGrease {
    /// BoringSSL's defaults, used by uTLS Chrome (u_ech.go:296-306,
    /// u_parrots.go:963).
    pub const CHROME: EchGrease = EchGrease {
        cipher_suites: &[(HKDF_SHA256, AES_128_GCM)],
        payload_lens: &[128, 160, 192, 224],
    };
    /// uTLS Firefox 148 (u_parrots.go:1577-1589).
    pub const FIREFOX: EchGrease = EchGrease {
        cipher_suites: &[(HKDF_SHA256, AES_128_GCM), (HKDF_SHA256, CHACHA20_POLY1305)],
        payload_lens: &[223],
    };

    /// The extension body (RFC 9849 §5, outer variant): type 0, cipher suite,
    /// config_id, enc, payload (u_ech.go:177-200).
    fn body(&self) -> io::Result<Vec<u8>> {
        let mut draw = [0u8; 32 + 1];
        getrandom::fill(&mut draw).map_err(|e| err(&format!("no entropy: {e}")))?;
        let (kdf, aead) = self.cipher_suites[pick(self.cipher_suites.len())?];
        // config_id is a random byte (u_ech.go:73-80)
        let config_id = draw[32];
        // enc is the public half of a fresh X25519 key, a real curve point:
        // HPKE SetupSender with DHKEM(X25519) (u_ech.go:111-128,
        // internal/hpke/hpke.go:88-108)
        let secret: [u8; 32] = draw[..32].try_into().expect("32 bytes");
        let enc = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(secret));
        let mut payload =
            vec![0u8; self.payload_lens[pick(self.payload_lens.len())?] as usize + 16];
        getrandom::fill(&mut payload).map_err(|e| err(&format!("no entropy: {e}")))?;

        let mut b = Vec::with_capacity(10 + 32 + payload.len());
        b.push(0x00);
        b.extend_from_slice(&kdf.to_be_bytes());
        b.extend_from_slice(&aead.to_be_bytes());
        b.push(config_id);
        b.extend_from_slice(&32u16.to_be_bytes());
        b.extend_from_slice(enc.as_bytes());
        b.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        b.extend_from_slice(&payload);
        Ok(b)
    }
}

/// A uniform index below `n` (n > 0).
fn pick(n: usize) -> io::Result<usize> {
    let n = n as u32;
    let limit = u32::MAX - u32::MAX % n;
    loop {
        let mut b = [0u8; 4];
        getrandom::fill(&mut b).map_err(|e| err(&format!("no entropy: {e}")))?;
        let v = u32::from_be_bytes(b);
        if v < limit {
            return Ok((v % n) as usize);
        }
    }
}

#[derive(Debug, Clone)]
pub struct Template {
    pub record_version: [u8; 2],
    pub client_version: [u8; 2],
    pub cipher_suites: Vec<u8>,
    pub compression: Vec<u8>,
    pub extensions: Vec<Ext>,
}

#[derive(Debug)]
pub struct ParsedHello {
    pub template: Template,
    pub random: [u8; 32],
    pub session_id: Vec<u8>,
    pub sni: String,
    pub x25519_public: Option<[u8; 32]>,
}

fn u16_at(b: &[u8], off: usize) -> io::Result<u16> {
    b.get(off..off + 2)
        .map(|s| u16::from_be_bytes([s[0], s[1]]))
        .ok_or_else(|| err("u16 oob"))
}

fn take<'a>(b: &'a [u8], off: &mut usize, n: usize) -> io::Result<&'a [u8]> {
    let s = b.get(*off..*off + n).ok_or_else(|| err("take oob"))?;
    *off += n;
    Ok(s)
}

pub fn parse_record(data: &[u8]) -> io::Result<ParsedHello> {
    if data.len() < 5 || data[0] != 0x16 {
        return Err(err("not a handshake record"));
    }
    let rec_ver = [data[1], data[2]];
    let rec_len = u16_at(data, 3)? as usize;
    if data.len() < 5 + rec_len {
        return Err(err("short record"));
    }
    let hs = &data[5..5 + rec_len];
    // `16 03 01 00 00` is a whole record with nothing in it; indexing it was
    // a panic, and release builds abort on panic
    if hs.first() != Some(&0x01) {
        return Err(err("not a ClientHello"));
    }
    let mut off = 4;
    let client_version: [u8; 2] = take(hs, &mut off, 2)?.try_into().unwrap();
    let random: [u8; 32] = take(hs, &mut off, 32)?.try_into().unwrap();
    let sid_len = take(hs, &mut off, 1)?[0] as usize;
    let session_id = take(hs, &mut off, sid_len)?.to_vec();
    let cs_len = u16_at(hs, off)? as usize;
    off += 2;
    let cipher_suites = take(hs, &mut off, cs_len)?.to_vec();
    let comp_len = take(hs, &mut off, 1)?[0] as usize;
    let compression = take(hs, &mut off, comp_len)?.to_vec();
    let ext_total = u16_at(hs, off)? as usize;
    off += 2;
    let ext_end = off + ext_total;
    if hs.len() < ext_end {
        return Err(err("short extensions"));
    }
    let mut extensions = Vec::new();
    let mut sni = String::new();
    let mut x25519_public = None;
    while off < ext_end {
        let id = u16_at(hs, off)?;
        off += 2;
        let len = u16_at(hs, off)? as usize;
        off += 2;
        let body = take(hs, &mut off, len)?.to_vec();
        match id {
            0x0000 => {
                sni = parse_sni(&body)?;
                extensions.push(Ext::Sni);
            }
            0x0033 => {
                x25519_public = extract_x25519(&body)?;
                extensions.push(Ext::KeyShare(body));
            }
            _ => extensions.push(Ext::Static(id, body)),
        }
    }
    Ok(ParsedHello {
        template: Template {
            record_version: rec_ver,
            client_version,
            cipher_suites,
            compression,
            extensions,
        },
        random,
        session_id,
        sni,
        x25519_public,
    })
}

fn parse_sni(body: &[u8]) -> io::Result<String> {
    if body.len() < 5 {
        return Err(err("short sni"));
    }
    let list_len = u16_at(body, 0)? as usize;
    if body.len() < 2 + list_len {
        return Err(err("short sni list"));
    }
    if body[2] != 0 {
        return Err(err("sni type not host"));
    }
    let name_len = u16_at(body, 3)? as usize;
    let name = body
        .get(5..5 + name_len)
        .ok_or_else(|| err("short sni name"))?;
    String::from_utf8(name.to_vec()).map_err(|_| err("sni not utf8"))
}

fn extract_x25519(body: &[u8]) -> io::Result<Option<[u8; 32]>> {
    for (group, key) in keyshare::entries(body)? {
        if group == keyshare::X25519 && key.len() == 32 {
            return Ok(Some(key.try_into().expect("32 bytes")));
        }
    }
    for (group, key) in keyshare::entries(body)? {
        if (group == keyshare::X25519MLKEM768 || group == 0x45ac || group == 0x6399)
            && key.len() == 1184 + 32
        {
            return Ok(Some(key[1184..].try_into().expect("32 bytes")));
        }
    }
    Ok(None)
}

/// One ClientHello record from a template. Per hello, like uTLS: the GREASE
/// values (`Grease`), the GREASE ECH body and -- through the caller -- random,
/// session id and key shares.
pub fn build(
    template: &Template,
    random: &[u8; 32],
    session_id: &[u8],
    sni: &str,
    alpn: &[&[u8]],
    shares: Option<&keyshare::Shares>,
) -> io::Result<Vec<u8>> {
    let mut hs = Vec::new();
    hs.extend_from_slice(&template.client_version);
    hs.extend_from_slice(random);
    if session_id.len() > 32 {
        return Err(err("session_id too long"));
    }
    hs.push(session_id.len() as u8);
    hs.extend_from_slice(session_id);
    let grease = Grease::draw()?;
    let ciphers = grease.cipher_suites(&template.cipher_suites);
    hs.extend_from_slice(&(ciphers.len() as u16).to_be_bytes());
    hs.extend_from_slice(&ciphers);
    hs.push(template.compression.len() as u8);
    hs.extend_from_slice(&template.compression);

    let mut exts = Vec::new();
    let mut grease_exts = 0;
    for e in &template.extensions {
        let (id, body): (u16, Vec<u8>) = match e {
            // the first GREASE extension takes ext1, the second ext2
            Ext::Static(id, body) if keyshare::is_grease(*id) => {
                grease_exts += 1;
                (grease.extension(grease_exts)?, body.clone())
            }
            Ext::Static(id @ 0x000a, body) => (*id, grease.u16_list(body, 2, grease.group)),
            Ext::Static(id @ 0x002b, body) => (*id, grease.u16_list(body, 1, grease.version)),
            Ext::Static(id, body) => (*id, body.clone()),
            // an empty name is `disable_sni`: the extension is left out rather
            // than sent with a zero-length host, which is not the same thing
            Ext::Sni if sni.is_empty() => continue,
            Ext::Sni => (0x0000, build_sni(sni)?),
            Ext::Alpn if alpn.is_empty() => continue,
            Ext::Alpn => (0x0010, build_alpn(alpn)?),
            Ext::KeyShare(raw) => {
                // the GREASE share carries the supported_groups GREASE value:
                // servers check that the two agree
                let raw = grease.key_share(raw)?;
                (
                    0x0033,
                    match shares {
                        Some(s) => s.body(&raw)?,
                        None => raw,
                    },
                )
            }
            Ext::EchGrease(ech) => (0xfe0d, ech.body()?),
        };
        exts.extend_from_slice(&id.to_be_bytes());
        exts.extend_from_slice(&(body.len() as u16).to_be_bytes());
        exts.extend_from_slice(&body);
    }
    hs.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    hs.extend_from_slice(&exts);

    let mut handshake = Vec::with_capacity(4 + hs.len());
    handshake.push(0x01);
    handshake.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
    handshake.extend_from_slice(&hs);

    let mut record = Vec::with_capacity(5 + handshake.len());
    record.push(0x16);
    record.extend_from_slice(&template.record_version);
    record.extend_from_slice(&(handshake.len() as u16).to_be_bytes());
    record.extend_from_slice(&handshake);
    Ok(record)
}

/// The GREASE values of one hello, drawn the way uTLS draws its
/// `greaseSeed` per handshake (utls aa6edf4b11af, u_parrots.go:3049-3061 and
/// GetBoringGREASEValue in u_tls_extensions.go:983): one value each for the
/// cipher list, the groups (supported_groups and key_share alike), the two
/// GREASE extensions and supported_versions. They are independent of one
/// another -- the cipher value may equal the group value -- except that the
/// two extension ids differ, since a repeated id is a duplicate extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Grease {
    cipher: u16,
    group: u16,
    ext1: u16,
    ext2: u16,
    version: u16,
}

impl Grease {
    fn draw() -> io::Result<Self> {
        let mut seed = [0u8; 5];
        getrandom::fill(&mut seed).map_err(|e| err(&format!("no entropy: {e}")))?;
        Ok(Self::from_seed(seed))
    }

    /// 0xωaωa from the high nibble of each seed byte.
    fn from_seed(seed: [u8; 5]) -> Self {
        let value = |byte: u8| {
            let v = (byte & 0xf0) as u16 | 0x0a;
            v << 8 | v
        };
        let ext1 = value(seed[2]);
        let mut ext2 = value(seed[3]);
        if ext2 == ext1 {
            ext2 ^= 0x1010;
        }
        Grease {
            cipher: value(seed[0]),
            group: value(seed[1]),
            ext1,
            ext2,
            version: value(seed[4]),
        }
    }

    /// The `n`th (1-based) GREASE extension's id; uTLS supports two.
    fn extension(&self, n: usize) -> io::Result<u16> {
        match n {
            1 => Ok(self.ext1),
            2 => Ok(self.ext2),
            _ => Err(err("at most two GREASE extensions are supported")),
        }
    }

    fn cipher_suites(&self, suites: &[u8]) -> Vec<u8> {
        self.u16_list(suites, 0, self.cipher)
    }

    /// `body` with every GREASE u16 after `skip` length bytes set to `value`.
    fn u16_list(&self, body: &[u8], skip: usize, value: u16) -> Vec<u8> {
        let mut out = body.to_vec();
        if let Some(list) = out.get_mut(skip..) {
            for pair in list.as_chunks_mut::<2>().0 {
                if keyshare::is_grease(u16::from_be_bytes(*pair)) {
                    *pair = value.to_be_bytes();
                }
            }
        }
        out
    }

    /// A captured `key_share` body with its GREASE entries' group set to the
    /// group value; their data is kept.
    fn key_share(&self, body: &[u8]) -> io::Result<Vec<u8>> {
        let mut out = body.to_vec();
        let mut off = 2;
        for (group, key) in keyshare::entries(body)? {
            if keyshare::is_grease(group) {
                out[off..off + 2].copy_from_slice(&self.group.to_be_bytes());
            }
            off += 4 + key.len();
        }
        Ok(out)
    }
}

fn build_sni(name: &str) -> io::Result<Vec<u8>> {
    let n = name.as_bytes();
    if n.len() > u16::MAX as usize {
        return Err(err("sni too long"));
    }
    let mut b = Vec::with_capacity(5 + n.len());
    b.extend_from_slice(&((n.len() + 3) as u16).to_be_bytes());
    b.push(0x00);
    b.extend_from_slice(&(n.len() as u16).to_be_bytes());
    b.extend_from_slice(n);
    Ok(b)
}

/// The ALPN extension body: a 16-bit list length and then the protocols, in
/// the order the caller configured. The extension's own length is the framing
/// the builder writes around this.
fn build_alpn(alpn: &[&[u8]]) -> io::Result<Vec<u8>> {
    let total: usize = alpn.iter().map(|p| p.len() + 1).sum();
    if total > u16::MAX as usize {
        return Err(err("alpn list too long"));
    }
    let mut b = Vec::with_capacity(2 + total);
    b.extend_from_slice(&(total as u16).to_be_bytes());
    for protocol in alpn {
        if protocol.len() > u8::MAX as usize || protocol.is_empty() {
            return Err(err("alpn protocol must be 1..=255 bytes"));
        }
        b.push(protocol.len() as u8);
        b.extend_from_slice(protocol);
    }
    Ok(b)
}

pub fn key_share_group(body: &[u8]) -> io::Result<Vec<u16>> {
    Ok(keyshare::entries(body)?
        .into_iter()
        .map(|(group, _)| group)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// uTLS's mapping from seed to GREASE value, over every seed byte: the
    /// high nibble picks ω in 0xωaωa, and a second extension id equal to the
    /// first is moved by 0x1010 (u_parrots.go:3059-3061).
    #[test]
    fn grease_seed_maps_like_utls() {
        for byte in 0..=255u8 {
            let hi = (byte >> 4) as u16;
            let want = (hi << 12) | 0x0a00 | (hi << 4) | 0x0a;
            let g = Grease::from_seed([byte, byte, byte, 0x00, byte]);
            assert_eq!(g.cipher, want);
            assert_eq!(g.group, want);
            assert_eq!(g.version, want);
            assert_eq!(g.ext1, want);
            let same = Grease::from_seed([0, 0, byte, byte, 0]);
            assert_eq!(same.ext2, want ^ 0x1010);
            assert!(keyshare::is_grease(same.ext2));
        }
        assert!(Grease::from_seed([0; 5]).extension(3).is_err());
    }

    /// The sniffers hand this parser whatever a client sent. It may refuse,
    /// it may not panic: release builds abort on panic.
    #[test]
    fn no_input_makes_the_parser_panic() {
        assert!(parse_record(&[0x16, 0x03, 0x01, 0x00, 0x00]).is_err());
        let mut sni = vec![0x00, 0x00];
        let body = build_sni("example.com").unwrap();
        sni.extend_from_slice(&(body.len() as u16).to_be_bytes());
        sni.extend_from_slice(&body);
        let mut hs = vec![0x03, 0x03];
        hs.extend_from_slice(&[7; 32]);
        hs.extend_from_slice(&[0, 0, 2, 0x13, 0x01, 1, 0]);
        hs.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        hs.extend_from_slice(&sni);
        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&((hs.len() + 4) as u16).to_be_bytes());
        record.push(0x01);
        record.extend_from_slice(&(hs.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&hs);
        assert_eq!(parse_record(&record).unwrap().sni, "example.com");
        for len in 0..record.len() {
            let _ = parse_record(&record[..len]);
        }
        for at in 0..record.len() {
            for value in [0x00, 0x01, 0x7f, 0x80, 0xff] {
                let mut bent = record.clone();
                bent[at] = value;
                let _ = parse_record(&bent);
            }
        }
    }
}
