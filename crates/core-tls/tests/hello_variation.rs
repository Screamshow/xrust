//! What changes from one ClientHello to the next, and what has to agree inside
//! one. The references (uTLS presets, as Sing-Box X and Xray send them) draw
//! per handshake: five GREASE values (cipher, group, two extension ids,
//! version), the GREASE ECH body and, for Chrome, the extension order.
//! Everything else is constant, so it must be constant here too.

use std::collections::HashSet;

use core_tls::fingerprints;
use core_tls::hello::{Ext, build, parse_record};
use core_tls::keyshare::{Shares, entries, is_grease};

const ROUNDS: usize = 400;

/// What one hello carries in its GREASE slots.
#[derive(Debug, Default)]
struct Slots {
    cipher: Vec<u16>,
    groups: Vec<u16>,
    key_share: Vec<u16>,
    versions: Vec<u16>,
    extensions: Vec<u16>,
    order: Vec<u16>,
}

fn u16s(body: &[u8]) -> Vec<u16> {
    body.as_chunks::<2>()
        .0
        .iter()
        .map(|p| u16::from_be_bytes(*p))
        .collect()
}

fn hello(name: &str, with_shares: bool) -> Slots {
    let template = fingerprints::by_name(name).expect("profile");
    let shares = with_shares.then(|| {
        let ks = template
            .extensions
            .iter()
            .find_map(|e| match e {
                Ext::KeyShare(body) => Some(body.clone()),
                _ => None,
            })
            .expect("key share");
        Shares::for_body(&ks).expect("shares")
    });
    let record = build(
        &template,
        &[7; 32],
        &[9; 32],
        "www.example.com",
        &[b"h2", b"http/1.1"],
        shares.as_ref(),
    )
    .expect("build");
    let parsed = parse_record(&record).expect("parse");
    let mut slots = Slots {
        cipher: u16s(&parsed.template.cipher_suites)
            .into_iter()
            .filter(|v| is_grease(*v))
            .collect(),
        ..Slots::default()
    };
    for ext in &parsed.template.extensions {
        let (id, body) = match ext {
            Ext::Static(id, body) => (*id, body.as_slice()),
            Ext::Sni => (0x0000, &[][..]),
            Ext::KeyShare(body) => (0x0033, body.as_slice()),
            _ => unreachable!("parse_record yields Static, Sni and KeyShare"),
        };
        slots.order.push(if is_grease(id) { 0x0a0a } else { id });
        if is_grease(id) {
            slots.extensions.push(id);
        }
        let grease = |list: Vec<u16>| list.into_iter().filter(|v| is_grease(*v)).collect();
        match id {
            0x000a => slots.groups = grease(u16s(&body[2..])),
            0x002b => slots.versions = grease(u16s(&body[1..])),
            0x0033 => {
                slots.key_share = entries(body)
                    .expect("key share")
                    .into_iter()
                    .map(|(g, _)| g)
                    .filter(|g| is_grease(*g))
                    .collect()
            }
            _ => {}
        }
    }
    slots
}

/// Each slot is GREASE-shaped, the key share's GREASE equals the groups', the
/// two extension ids differ, and every slot is drawn on its own: over many
/// hellos each takes most of the 16 values, and the cipher value sometimes
/// equals the group value (uTLS draws them independently).
fn grease_is_drawn_per_hello(name: &str) {
    let mut seen: [HashSet<u16>; 5] = Default::default();
    let mut cipher_eq_group = 0;
    for round in 0..ROUNDS {
        let s = hello(name, round % 8 == 0);
        assert_eq!(s.cipher.len(), 1, "{name}: one GREASE cipher");
        assert_eq!(s.groups.len(), 1, "{name}: one GREASE group");
        assert_eq!(
            s.key_share, s.groups,
            "{name}: key_share GREASE = groups GREASE"
        );
        assert_eq!(s.versions.len(), 1, "{name}: one GREASE version");
        assert_eq!(s.extensions.len(), 2, "{name}: two GREASE extensions");
        assert_ne!(
            s.extensions[0], s.extensions[1],
            "{name}: distinct GREASE ids"
        );
        for value in s.cipher.iter().chain(&s.groups).chain(&s.versions) {
            assert!(is_grease(*value));
        }
        cipher_eq_group += usize::from(s.cipher == s.groups);
        for (set, value) in seen.iter_mut().zip([
            s.cipher[0],
            s.groups[0],
            s.extensions[0],
            s.extensions[1],
            s.versions[0],
        ]) {
            set.insert(value);
        }
    }
    for (slot, set) in ["cipher", "group", "ext1", "ext2", "version"]
        .iter()
        .zip(&seen)
    {
        assert!(
            set.len() >= 12,
            "{name}: {slot} took only {} values",
            set.len()
        );
    }
    assert!(
        cipher_eq_group > 0,
        "{name}: cipher and group GREASE never collided"
    );
}

#[test]
fn safari_grease_is_drawn_per_hello() {
    grease_is_drawn_per_hello("safari");
}

#[test]
fn chrome_grease_is_drawn_per_hello() {
    grease_is_drawn_per_hello("chrome");
}

#[test]
fn firefox_has_no_grease_and_a_fixed_order() {
    let first = hello("firefox", true);
    for _ in 0..64 {
        let s = hello("firefox", false);
        assert!(s.cipher.is_empty() && s.groups.is_empty() && s.extensions.is_empty());
        assert!(s.key_share.is_empty() && s.versions.is_empty());
        assert_eq!(s.order, first.order);
    }
}

#[test]
fn safari_keeps_its_order_and_grease_positions() {
    let first = hello("safari", true);
    assert_eq!(first.order.first(), Some(&0x0a0a));
    assert_eq!(first.order.last(), Some(&0x0a0a));
    for _ in 0..64 {
        assert_eq!(hello("safari", false).order, first.order);
    }
}

/// Chrome shuffles every extension but GREASE per hello, like uTLS's
/// `ShuffleChromeTLSExtensions`: the order varies, the set does not, and the
/// two GREASE extensions stay first and last.
#[test]
fn chrome_shuffles_its_extensions_per_hello() {
    let mut orders = HashSet::new();
    let mut first_slot = HashSet::new();
    let reference: HashSet<u16> = hello("chrome", true).order.into_iter().collect();
    for _ in 0..ROUNDS {
        let s = hello("chrome", false);
        assert_eq!(s.order.first(), Some(&0x0a0a));
        assert_eq!(s.order.last(), Some(&0x0a0a));
        assert_eq!(s.order.iter().copied().collect::<HashSet<_>>(), reference);
        first_slot.insert(s.order[1]);
        orders.insert(s.order);
    }
    assert!(orders.len() > ROUNDS * 9 / 10, "{} orders", orders.len());
    // every movable extension reaches the first movable slot
    assert_eq!(first_slot.len(), reference.len() - 1);
}

/// The process-stable `randomized` profile keeps the order it drew.
#[test]
fn randomized_keeps_its_drawn_order() {
    let first = hello("randomized", true);
    for _ in 0..32 {
        assert_eq!(hello("randomized", false).order, first.order);
    }
}
