//! Every vendored fingerprint rebuilds its own capture byte-for-byte, apart
//! from GREASE values and the GREASE ECH body, which is checked by structure,
//! and, for the Chrome tables that shuffle per hello, the extension order.
//!
//! The captures are what the reference sent as a uTLS client
//! (tests/spikes/clienthello/captures, taken on sing-box-lx 1.14.2-lx.3). A
//! template that rebuilds its capture is the whole claim of ADR-0004: the
//! fingerprint is data we vendored, not a guess.

use std::path::PathBuf;

use core_tls::fingerprints;
use core_tls::hello::{EchGrease, build, parse_record};

fn capture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join(if matches!(name, "chrome" | "firefox" | "safari") {
            "../../tests/spikes/clienthello/captures-sing-box-x"
        } else {
            "../../tests/spikes/clienthello/captures"
        })
        .join(format!("{name}.bin"))
}

fn alpn_of(hello: &core_tls::hello::ParsedHello) -> Vec<Vec<u8>> {
    hello
        .template
        .extensions
        .iter()
        .find_map(|ext| match ext {
            core_tls::hello::Ext::Static(0x0010, body) => Some(body.clone()),
            _ => None,
        })
        .map(|body| {
            // skip the 2-byte list length, then read the length-prefixed names
            let mut out = Vec::new();
            let mut off = 2;
            while off < body.len() {
                let len = body[off] as usize;
                off += 1;
                out.push(body[off..off + len].to_vec());
                off += len;
            }
            out
        })
        .unwrap_or_default()
}

/// The names the reference maps to a table of their own, and which therefore
/// have a capture to be diffed against. The six `chrome_*` aliases share the
/// chrome table in the reference, and `HelloChrome_Auto` picks a Chrome version
/// per handshake (three handshakes from one process give three different
/// hellos: tests/spikes/clienthello/chrome_stability.sh), so an alias capture
/// is some *other* version and cannot be diffed against our table.
const CANONICAL: &[&str] = &["chrome", "firefox", "edge", "safari", "ios"];

#[test]
fn every_table_rebuilds_its_capture() {
    for name in CANONICAL {
        let Some(template) = fingerprints::by_name(name) else {
            panic!("{name} has no table");
        };
        let path = capture(name);
        let data = std::fs::read(&path).expect("capture");
        let hello = parse_record(&data).expect("parse");

        let alpn = alpn_of(&hello);
        let alpn: Vec<&[u8]> = alpn.iter().map(|p| p.as_slice()).collect();
        let rebuilt = build(
            &template,
            &hello.random,
            &hello.session_id,
            &hello.sni,
            &alpn,
            None,
        )
        .expect("build");
        let ech = template.extensions.iter().find_map(|e| match e {
            core_tls::hello::Ext::EchGrease(ech) => Some(*ech),
            _ => None,
        });
        assert!(
            same_except_grease(&rebuilt, &data, ech, template.shuffle_extensions),
            "{name}: the rebuilt hello differs from the capture outside GREASE"
        );
    }
}

#[test]
fn modern_profiles_keep_hybrid_groups_shares_and_configured_alpn() {
    use core_tls::hello::Ext;
    use core_tls::keyshare::{MLKEM768_EK_LEN, Shares, X25519, X25519MLKEM768};
    for name in ["chrome", "firefox", "safari"] {
        let template = fingerprints::by_name(name).expect("modern profile");
        let again = fingerprints::by_name(name).expect("stable profile");
        assert_eq!(template.extensions, again.extensions);
        assert_eq!(template.cipher_suites, again.cipher_suites);
        let groups = template
            .extensions
            .iter()
            .find_map(|e| match e {
                Ext::Static(10, body) => Some(
                    body[2..]
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|p| u16::from_be_bytes([p[0], p[1]]))
                        .collect::<Vec<_>>(),
                ),
                _ => None,
            })
            .expect("supported groups");
        let key_body = template
            .extensions
            .iter()
            .find_map(|e| match e {
                Ext::KeyShare(body) => Some(body),
                _ => None,
            })
            .expect("key shares");
        let shares = Shares::for_body(key_body).expect("fresh keys");
        assert!(groups.contains(&X25519MLKEM768));
        assert!(shares.public(X25519MLKEM768).is_some());
        if name == "firefox" {
            assert_eq!(
                shares.public(X25519).unwrap(),
                &shares.public(X25519MLKEM768).unwrap()[MLKEM768_EK_LEN..]
            );
        }
        let hello = build(
            &template,
            &[7; 32],
            &[0; 32],
            "example.com",
            &[b"h2"],
            Some(&shares),
        )
        .expect("build modern hello");
        assert_eq!(
            alpn_of(&parse_record(&hello).unwrap()),
            vec![b"h2".to_vec()]
        );
    }
}

#[test]
fn the_names_the_reference_accepts_all_resolve() {
    for name in fingerprints::NAMES {
        assert!(fingerprints::by_name(name).is_some(), "{name} has no table");
    }
    assert!(
        fingerprints::by_name("nope").is_none(),
        "an unknown name resolves to nothing"
    );
    assert!(
        fingerprints::by_name("").is_some(),
        "an empty fingerprint is chrome, as in the reference"
    );
}

#[test]
fn random_policies_are_process_stable_and_random_is_firefox() {
    for name in ["random", "randomized"] {
        let first = fingerprints::by_name(name).unwrap();
        for _ in 0..16 {
            let next = fingerprints::by_name(name).unwrap();
            assert_eq!(first.cipher_suites, next.cipher_suites);
            assert_eq!(first.extensions, next.extensions);
        }
    }
    // The owner's decision: `random` is firefox, not a draw per process.
    let random = fingerprints::by_name("random").unwrap();
    let firefox = fingerprints::firefox();
    assert_eq!(random.cipher_suites, firefox.cipher_suites);
    assert_eq!(random.extensions, firefox.extensions);
}

/// The modern chrome hello must still offer the hybrid share current Xray
/// servers demand (SPEC 083/089), and its session id must be 32 bytes of
/// compat space for REALITY to seal into.
#[test]
fn chrome_carries_a_hybrid_key_share_and_a_32_byte_session_id() {
    let template = fingerprints::by_name("chrome").expect("chrome");
    let data = std::fs::read(capture("chrome")).expect("capture");
    let hello = parse_record(&data).expect("parse");
    assert_eq!(hello.session_id.len(), 32);
    let groups = template
        .extensions
        .iter()
        .find_map(|ext| match ext {
            core_tls::hello::Ext::KeyShare(body) => core_tls::hello::key_share_group(body).ok(),
            _ => None,
        })
        .expect("chrome offers a key share");
    assert!(
        groups.contains(&0x11ec),
        "X25519MLKEM768 present, got {groups:04x?}"
    );
    assert!(groups.contains(&0x001d), "plain X25519 present too");
}

/// GREASE: a reserved value a client picks at random per handshake, so even the
/// reference never repeats its own hello. Everything else must match exactly.
fn is_grease(value: u16) -> bool {
    let low = (value & 0x0f) as u8;
    low == 0x0a && (value >> 8) as u8 == (value & 0xff) as u8
}

/// Mask the GREASE values inside one extension body, so two hellos that differ
/// only in them compare equal.
fn mask_body(id: u16, body: &[u8]) -> Vec<u8> {
    let mut out = body.to_vec();
    // a list of u16 values: supported_groups, key_share group ids, and
    // supported_versions after its one-byte length
    let skip = if id == 0x002b { 1 } else { 0 };
    let u16_list = matches!(id, 0x000a | 0x0023 | 0x0033 | 0x001d | 0x002b);
    if u16_list {
        let start = skip.min(out.len());
        for pair in out[start..].chunks_mut(2) {
            if pair.len() == 2 {
                let value = u16::from_be_bytes([pair[0], pair[1]]);
                if is_grease(value) {
                    pair.copy_from_slice(&0x0a0au16.to_be_bytes());
                }
            }
        }
    }
    out
}

/// The two hellos agree once GREASE is set aside. GREASE ECH is drawn per
/// hello, so both sides only have to be a well-formed outer ECH the profile's
/// parameters allow.
fn same_except_grease(
    rebuilt: &[u8],
    capture: &[u8],
    ech: Option<EchGrease>,
    shuffled: bool,
) -> bool {
    let (Ok(mut left), Ok(mut right)) = (parse_record(rebuilt), parse_record(capture)) else {
        return false;
    };
    if shuffled {
        // the order is drawn per hello: compare the extensions as a set, with
        // the GREASE ones, which never move, compared in place
        for hello in [&mut left, &mut right] {
            let key = |e: &core_tls::hello::Ext| match e {
                core_tls::hello::Ext::Static(id, _) if is_grease(*id) => None,
                core_tls::hello::Ext::Static(id, _) => Some(*id),
                core_tls::hello::Ext::Sni => Some(0x0000),
                core_tls::hello::Ext::Alpn => Some(0x0010),
                core_tls::hello::Ext::KeyShare(_) => Some(0x0033),
                core_tls::hello::Ext::EchGrease(_) => Some(0xfe0d),
            };
            let exts = &mut hello.template.extensions;
            let movable: Vec<usize> = (0..exts.len())
                .filter(|&i| key(&exts[i]).is_some())
                .collect();
            let mut sorted: Vec<_> = movable.iter().map(|&i| exts[i].clone()).collect();
            sorted.sort_by_key(|e| key(e));
            for (slot, ext) in movable.into_iter().zip(sorted) {
                exts[slot] = ext;
            }
        }
    }
    let mask = |data: &[u8]| -> Vec<u16> {
        data.chunks(2)
            .filter(|c| c.len() == 2)
            .map(|c| {
                let value = u16::from_be_bytes([c[0], c[1]]);
                if is_grease(value) { 0x0a0a } else { value }
            })
            .collect()
    };
    if left.template.record_version != right.template.record_version
        || left.template.client_version != right.template.client_version
        || left.random != right.random
        // the session id is the compatibility field: its length is the claim
        // (REALITY seals its auth key into it), its content is per-handshake
        || left.session_id.len() != right.session_id.len()
        || left.sni != right.sni
        || left.template.compression != right.template.compression
        || mask(&left.template.cipher_suites) != mask(&right.template.cipher_suites)
        || left.template.extensions.len() != right.template.extensions.len()
    {
        return false;
    }
    let mut diffs = Vec::new();
    for (i, (a, b)) in left
        .template
        .extensions
        .iter()
        .zip(right.template.extensions.iter())
        .enumerate()
    {
        if !same_extension(a, b, ech) {
            diffs.push(format!("#{i} rebuilt={a:?} capture={b:?}"));
        }
    }
    if !diffs.is_empty() {
        eprintln!("DIFF {diffs:?}");
        return false;
    }
    true
}

fn same_extension(
    a: &core_tls::hello::Ext,
    b: &core_tls::hello::Ext,
    ech: Option<EchGrease>,
) -> bool {
    use core_tls::hello::Ext;
    match (a, b) {
        (Ext::Static(0xfe0d, body_a), Ext::Static(0xfe0d, body_b)) => {
            ech.is_some_and(|ech| allowed_ech(body_a, ech) && allowed_ech(body_b, ech))
        }
        (Ext::Static(id_a, body_a), Ext::Static(id_b, body_b)) => {
            (is_grease(*id_a) && is_grease(*id_b))
                || (id_a == id_b && mask_body(*id_a, body_a) == mask_body(*id_b, body_b))
        }
        (Ext::Sni, Ext::Sni) | (Ext::Alpn, Ext::Alpn) => true,
        (Ext::KeyShare(a), Ext::KeyShare(b)) => mask_body(0x0033, a) == mask_body(0x0033, b),
        _ => false,
    }
}

/// An outer ECHClientHello whose suite and payload length the profile allows,
/// with a 32-byte enc and nothing after the payload.
fn allowed_ech(body: &[u8], ech: EchGrease) -> bool {
    let u16_at = |off: usize| {
        body.get(off..off + 2)
            .map(|b| u16::from_be_bytes([b[0], b[1]]))
    };
    let (Some(kdf), Some(aead), Some(enc_len)) = (u16_at(1), u16_at(3), u16_at(6)) else {
        return false;
    };
    let Some(payload_len) = u16_at(8 + enc_len as usize) else {
        return false;
    };
    body[0] == 0
        && ech.cipher_suites.contains(&(kdf, aead))
        && enc_len == 32
        && ech.payload_lens.iter().any(|n| n + 16 == payload_len)
        && body.len() == 10 + enc_len as usize + payload_len as usize
}
