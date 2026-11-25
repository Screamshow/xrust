//! Disco key advertisements from Tailscale v1.104.7 net/packet/tsmp.go.

use smoltcp::wire::Ipv4Packet;
use std::net::IpAddr;

const TSMP: u8 = 99;
const DISCO_ADVERTISEMENT: u8 = b'a';
const DISCO_LEN: usize = 33;

pub(super) fn disco_advertisement(
    local: &[IpAddr],
    remote: &[IpAddr],
    key: [u8; 32],
) -> Option<Vec<u8>> {
    let dest = *remote.first()?;
    let source = *local.iter().find(|addr| addr.is_ipv4() == dest.is_ipv4())?;
    let mut packet = Vec::with_capacity(if dest.is_ipv4() { 53 } else { 73 });
    match (source, dest) {
        (IpAddr::V4(source), IpAddr::V4(dest)) => {
            packet.extend([0x45, 0, 0, 53, 0, 0, 0, 0, 64, TSMP, 0, 0]);
            packet.extend(source.octets());
            packet.extend(dest.octets());
            Ipv4Packet::new_unchecked(packet.as_mut_slice()).fill_checksum();
        }
        (IpAddr::V6(source), IpAddr::V6(dest)) => {
            packet.extend([0x60, 0, 0, 0, 0, DISCO_LEN as u8, TSMP, 64]);
            packet.extend(source.octets());
            packet.extend(dest.octets());
        }
        _ => return None,
    }
    packet.push(DISCO_ADVERTISEMENT);
    packet.extend(key);
    Some(packet)
}

/// Called after the IP length has been checked and WireGuard padding removed.
/// Return an empty TSMP payload for IPv4 fragments.
pub(super) fn payload(packet: &[u8]) -> Option<&[u8]> {
    match packet[0] >> 4 {
        4 if packet[9] == TSMP => {
            let header = Ipv4Packet::new_unchecked(packet);
            if header.more_frags() || header.frag_offset() != 0 {
                return Some(&[]);
            }
            Some(&packet[usize::from(header.header_len())..])
        }
        6 if packet[6] == TSMP => Some(&packet[40..]),
        _ => None,
    }
}

pub(super) fn is_disco_advertisement(payload: &[u8]) -> bool {
    payload.first() == Some(&DISCO_ADVERTISEMENT)
}

pub(super) fn disco_key(payload: &[u8]) -> Option<[u8; 32]> {
    if !is_disco_advertisement(payload) {
        return None;
    }
    payload.get(1..DISCO_LEN)?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn advertisement_matches_the_pinned_upstream_ipv4_and_ipv6_vectors() {
        for (source, dest, header) in [
            (
                "1.2.3.4",
                "4.3.2.1",
                vec![
                    0x45, 0, 0, 0x35, 0, 0, 0, 0, 0x40, 0x63, 0x70, 0x5d, 1, 2, 3, 4, 4, 3, 2, 1,
                ],
            ),
            (
                "2001:db8::1",
                "2001:db8::2",
                vec![
                    0x60, 0, 0, 0, 0, 0x21, 0x63, 0x40, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0,
                    0, 0, 0, 0, 1, 0x20, 1, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2,
                ],
            ),
        ] {
            let key = [b'a'; 32];
            let bytes =
                disco_advertisement(&[source.parse().unwrap()], &[dest.parse().unwrap()], key)
                    .unwrap();
            assert_eq!(bytes, [header.as_slice(), &[b'a'; 33]].concat());
            assert_eq!(disco_key(payload(&bytes).unwrap()), Some(key));
        }
    }
}
