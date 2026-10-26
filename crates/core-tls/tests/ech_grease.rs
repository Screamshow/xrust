//! GREASE ECH (RFC 9849 §6.2) is drawn fresh for every hello.
//!
//! The expected parameters are uTLS's (aa6edf4b11af, the revision Xray
//! v26.10.21 pins), written out here rather than read from our tables:
//! Chrome uses `BoringGREASEECH` (u_ech.go:296-306, u_parrots.go:963): HKDF-SHA256
//! with AES-128-GCM and a payload of 128/160/192/224 + 16 bytes. Firefox 148
//! (u_parrots.go:1577-1589) picks AES-128-GCM or ChaCha20-Poly1305 and sends a
//! 223 + 16 byte payload. config_id is a random byte (u_ech.go:73-80) and enc a
//! fresh X25519 public key (u_ech.go:111-128, internal/hpke/hpke.go:88-108).
//! Safari, Edge, iOS, QQ, 360 and Android send no ECH extension there.

use std::collections::BTreeSet;

use core_tls::fingerprints;
use core_tls::hello::{Ext, Template, build, parse_record};
use core_tls::keyshare::{self, Shares};

const ECH: u16 = 0xfe0d;
const SEQUENTIAL: usize = 64;
const THREADS: usize = 8;
const PER_THREAD: usize = 16;

const CHROME_SUITES: &[(u16, u16)] = &[(0x0001, 0x0001)];
const CHROME_PAYLOADS: &[usize] = &[144, 176, 208, 240];
const FIREFOX_SUITES: &[(u16, u16)] = &[(0x0001, 0x0001), (0x0001, 0x0003)];
const FIREFOX_PAYLOADS: &[usize] = &[239];

#[derive(Debug, Clone, PartialEq, Eq)]
struct Outer {
    kdf: u16,
    aead: u16,
    config_id: u8,
    enc: Vec<u8>,
    payload: Vec<u8>,
}

/// ECHClientHello, outer variant: type, cipher suite, config_id, enc and
/// payload, each with its length, and nothing after them.
fn parse_outer(body: &[u8]) -> Result<Outer, String> {
    let u16_at = |off: usize| -> Result<u16, String> {
        body.get(off..off + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
            .ok_or_else(|| format!("short ECH body at {off}"))
    };
    if body.first() != Some(&0x00) {
        return Err(format!("not an outer ECH: {:02x?}", body.first()));
    }
    let kdf = u16_at(1)?;
    let aead = u16_at(3)?;
    let config_id = *body.get(5).ok_or("no config_id")?;
    let enc_len = u16_at(6)? as usize;
    let enc = body.get(8..8 + enc_len).ok_or("short enc")?.to_vec();
    let payload_len = u16_at(8 + enc_len)? as usize;
    let start = 10 + enc_len;
    let payload = body
        .get(start..start + payload_len)
        .ok_or("short payload")?
        .to_vec();
    if start + payload_len != body.len() {
        return Err(format!(
            "{} bytes after the payload",
            body.len() - start - payload_len
        ));
    }
    Ok(Outer {
        kdf,
        aead,
        config_id,
        enc,
        payload,
    })
}

/// The extensions of a hello as (id, body), with every length field checked
/// against what it frames.
fn extensions(record: &[u8]) -> Vec<(u16, Vec<u8>)> {
    assert_eq!(record[0], 0x16);
    assert_eq!(
        u16::from_be_bytes([record[3], record[4]]) as usize,
        record.len() - 5,
        "record length"
    );
    assert_eq!(record[5], 0x01);
    let hs_len = u32::from_be_bytes([0, record[6], record[7], record[8]]) as usize;
    assert_eq!(hs_len, record.len() - 9, "handshake length");
    let hs = &record[9..];
    let mut off = 2 + 32;
    off += 1 + hs[off] as usize;
    off += 2 + u16::from_be_bytes([hs[off], hs[off + 1]]) as usize;
    off += 1 + hs[off] as usize;
    let total = u16::from_be_bytes([hs[off], hs[off + 1]]) as usize;
    off += 2;
    assert_eq!(off + total, hs.len(), "extensions length");
    let mut out = Vec::new();
    while off < hs.len() {
        let id = u16::from_be_bytes([hs[off], hs[off + 1]]);
        let len = u16::from_be_bytes([hs[off + 2], hs[off + 3]]) as usize;
        out.push((id, hs[off + 4..off + 4 + len].to_vec()));
        off += 4 + len;
    }
    assert_eq!(off, hs.len(), "extensions end where they say");
    parse_record(record).expect("our own parser takes it");
    out
}

/// x25519 public keys are little-endian integers below 2^255 - 19.
fn canonical_x25519(key: &[u8]) -> bool {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    for i in (0..32).rev() {
        if key[i] != p[i] {
            return key[i] < p[i];
        }
    }
    false
}

fn shares_for(template: &Template) -> Option<Shares> {
    template.extensions.iter().find_map(|e| match e {
        Ext::KeyShare(body) => Some(Shares::for_body(body).expect("our keys")),
        _ => None,
    })
}

fn hello(template: &Template, shares: Option<&Shares>) -> Vec<u8> {
    build(
        template,
        &[0x11; 32],
        &[0x22; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
        shares,
    )
    .expect("build")
}

/// GREASE set aside: an id becomes 0x0a0a, and so does every GREASE value in
/// supported_groups and supported_versions (all drawn per hello).
fn ungrease(id: u16, body: &[u8]) -> (u16, Vec<u8>) {
    let mut body = body.to_vec();
    let skip = match id {
        0x000a => 2,
        0x002b => 1,
        _ => body.len(),
    };
    let start = skip.min(body.len());
    for pair in body[start..].as_chunks_mut::<2>().0 {
        if keyshare::is_grease(u16::from_be_bytes(*pair)) {
            *pair = [0x0a, 0x0a];
        }
    }
    let id = if keyshare::is_grease(id) { 0x0a0a } else { id };
    (id, body)
}

/// Everything but GREASE values, the ECH body and -- for a template that
/// shuffles -- the extension order equals the template. SNI, ALPN, key share
/// and ECH are compared by id only.
fn check_against_template(name: &str, template: &Template, exts: &[(u16, Vec<u8>)]) {
    let want: Vec<(u16, Option<Vec<u8>>)> = template
        .extensions
        .iter()
        .map(|e| match e {
            Ext::Static(ECH, _) | Ext::EchGrease(_) => (ECH, None),
            Ext::Static(id, body) => {
                let (id, body) = ungrease(*id, body);
                (id, Some(body))
            }
            Ext::Sni => (0x0000, None),
            Ext::Alpn => (0x0010, None),
            Ext::KeyShare(_) => (0x0033, None),
        })
        .collect();
    let mut got: Vec<(u16, Option<Vec<u8>>)> = exts
        .iter()
        .map(|(id, body)| match *id {
            ECH | 0x0000 | 0x0010 | 0x0033 => (*id, None),
            id => {
                let (id, body) = ungrease(id, body);
                (id, Some(body))
            }
        })
        .collect();
    let mut want = want;
    assert_eq!(want.len(), got.len(), "{name}: extension count");
    if template.shuffle_extensions {
        for (i, (a, b)) in want.iter().zip(&got).enumerate() {
            if a.0 == 0x0a0a || b.0 == 0x0a0a {
                assert_eq!(a, b, "{name}: GREASE extension #{i} moved");
            }
        }
        want.sort();
        got.sort();
    }
    assert_eq!(want, got, "{name}: extensions");
}

fn collect(name: &str, template: &Template) -> Vec<Outer> {
    let shares = shares_for(template);
    let one = |shares: Option<&Shares>| -> (Outer, usize) {
        let record = hello(template, shares);
        let exts = extensions(&record);
        check_against_template(name, template, &exts);
        let ech: Vec<_> = exts.iter().filter(|(id, _)| *id == ECH).collect();
        assert_eq!(ech.len(), 1, "{name}: one ECH extension");
        let outer = parse_outer(&ech[0].1).unwrap_or_else(|e| panic!("{name}: {e}"));
        // the hello without its ECH body has one length, whatever was drawn
        (outer, record.len() - ech[0].1.len())
    };
    let mut outers = Vec::new();
    let mut rest = BTreeSet::new();
    for _ in 0..SEQUENTIAL {
        let (outer, len) = one(shares.as_ref());
        outers.push(outer);
        rest.insert(len);
    }
    let parallel: Vec<(Outer, usize)> = std::thread::scope(|scope| {
        let workers: Vec<_> = (0..THREADS)
            .map(|_| {
                scope.spawn(|| {
                    let shares = shares_for(template);
                    (0..PER_THREAD)
                        .map(|_| one(shares.as_ref()))
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("a worker"))
            .collect()
    });
    for (outer, len) in parallel {
        outers.push(outer);
        rest.insert(len);
    }
    assert_eq!(
        rest.len(),
        1,
        "{name}: the rest of the hello moved: {rest:?}"
    );
    outers
}

fn check_profile(name: &str, template: &Template, suites: &[(u16, u16)], payloads: &[usize]) {
    let outers = collect(name, template);
    let n = outers.len();
    assert_eq!(n, SEQUENTIAL + THREADS * PER_THREAD);
    let mut encs = BTreeSet::new();
    let mut payload_bodies = BTreeSet::new();
    let mut ids = BTreeSet::new();
    let mut lens = BTreeSet::new();
    let mut used_suites = BTreeSet::new();
    let peer = x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng);
    for o in &outers {
        assert!(
            suites.contains(&(o.kdf, o.aead)),
            "{name}: suite {:04x}/{:04x}",
            o.kdf,
            o.aead
        );
        assert!(
            payloads.contains(&o.payload.len()),
            "{name}: payload length {}",
            o.payload.len()
        );
        assert_eq!(o.enc.len(), 32, "{name}: enc is an X25519 key");
        assert!(o.enc.iter().any(|b| *b != 0), "{name}: all-zero enc");
        assert!(canonical_x25519(&o.enc), "{name}: enc is not canonical");
        let key: [u8; 32] = o.enc.clone().try_into().unwrap();
        assert!(
            peer.diffie_hellman(&key.into()).was_contributory(),
            "{name}: enc is a low-order point"
        );
        encs.insert(o.enc.clone());
        payload_bodies.insert(o.payload.clone());
        ids.insert(o.config_id);
        lens.insert(o.payload.len());
        used_suites.insert((o.kdf, o.aead));
    }
    eprintln!(
        "{name}: {n} hellos, {} enc, {} payloads, {} config_id, lengths {lens:?}, suites {used_suites:04x?}",
        encs.len(),
        payload_bodies.len(),
        ids.len()
    );
    assert_eq!(encs.len(), n, "{name}: enc repeats across hellos");
    assert_eq!(payload_bodies.len(), n, "{name}: payload repeats");
    // 192 draws of a byte give about 135 distinct values
    assert!(
        ids.len() >= 64,
        "{name}: only {} config_id values",
        ids.len()
    );
    // a missing value here has odds below 1e-15
    assert_eq!(
        lens,
        payloads.iter().copied().collect(),
        "{name}: payload lengths drawn"
    );
    assert_eq!(
        used_suites,
        suites.iter().copied().collect(),
        "{name}: cipher suites drawn"
    );
}

#[test]
fn firefox_draws_fresh_ech_grease_per_hello() {
    let template = fingerprints::by_name("firefox").unwrap();
    check_profile("firefox", &template, FIREFOX_SUITES, FIREFOX_PAYLOADS);
}

#[test]
fn chrome_draws_fresh_ech_grease_per_hello() {
    for name in [
        "chrome",
        "",
        "chrome_psk",
        "chrome_psk_shuffle",
        "chrome_padding_psk_shuffle",
        "chrome_pq",
        "chrome_pq_psk",
    ] {
        let template = fingerprints::by_name(name).unwrap();
        let label = if name.is_empty() { "(empty)" } else { name };
        check_profile(label, &template, CHROME_SUITES, CHROME_PAYLOADS);
    }
}

/// The captured chrome variants `by_name` does not hand out still carry ECH.
#[test]
fn chrome_variant_tables_draw_fresh_ech_grease() {
    type Table = fn() -> Template;
    let tables: [(&str, Table); 6] = [
        ("chrome_psk", fingerprints::chrome_psk),
        ("chrome_psk_shuffle", fingerprints::chrome_psk_shuffle),
        (
            "chrome_padding_psk_shuffle",
            fingerprints::chrome_padding_psk_shuffle,
        ),
        ("chrome_pq", fingerprints::chrome_pq),
        ("chrome_pq_psk", fingerprints::chrome_pq_psk),
        ("chrome", fingerprints::chrome),
    ];
    for (name, table) in tables {
        check_profile(name, &table(), CHROME_SUITES, CHROME_PAYLOADS);
    }
}

/// `random` is one browser per process and `randomized` a reshuffled chrome:
/// whichever carries ECH draws it fresh too.
#[test]
fn random_policies_draw_fresh_ech_grease() {
    for name in ["random", "randomized"] {
        let template = fingerprints::by_name(name).unwrap();
        let record = hello(&template, shares_for(&template).as_ref());
        if !extensions(&record).iter().any(|(id, _)| *id == ECH) {
            continue;
        }
        let firefox = fingerprints::firefox();
        let (suites, payloads) = if template.cipher_suites == firefox.cipher_suites {
            (FIREFOX_SUITES, FIREFOX_PAYLOADS)
        } else {
            (CHROME_SUITES, CHROME_PAYLOADS)
        };
        check_profile(name, &template, suites, payloads);
    }
}

/// Where the reference sends no ECH, neither do we.
#[test]
fn profiles_without_ech_in_the_reference_send_none() {
    for name in ["safari", "edge", "ios", "qq", "360", "android"] {
        let template = fingerprints::by_name(name).unwrap();
        let record = hello(&template, shares_for(&template).as_ref());
        assert!(
            !extensions(&record).iter().any(|(id, _)| *id == ECH),
            "{name} sends ECH"
        );
    }
}
