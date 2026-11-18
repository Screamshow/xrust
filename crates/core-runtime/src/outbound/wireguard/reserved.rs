//! Reserved bytes are a bind-layer extension: MAC/Noise always use the
//! canonical zero bytes. Match sing-box's ClientBind without an endpoint map,
//! so peers/tunnels sharing a server address keep their own routing bytes.
use std::borrow::Cow;

pub(super) fn outbound(bytes: &[u8], reserved: [u8; 3]) -> Cow<'_, [u8]> {
    if reserved == [0; 3] || bytes.len() < 4 || bytes[1..4] == reserved {
        return Cow::Borrowed(bytes);
    }
    let mut wire = bytes.to_vec();
    wire[1..4].copy_from_slice(&reserved);
    Cow::Owned(wire)
}

pub(super) fn inbound(bytes: &[u8]) -> Cow<'_, [u8]> {
    if bytes.len() < 4 || bytes[1..4] == [0; 3] {
        return Cow::Borrowed(bytes);
    }
    let mut canonical = bytes.to_vec();
    canonical[1..4].fill(0);
    Cow::Owned(canonical)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserved_only_changes_the_bind_header() {
        for len in [0, 1, 3, 4, 16, 32, 64, 92, 148, 1500] {
            let mut packet: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            if len >= 4 {
                packet[..4].copy_from_slice(&[1, 0, 0, 0]);
            }
            let wire = outbound(&packet, [19, 81, 203]);
            assert_eq!(wire.len(), len);
            assert_eq!(inbound(&wire), packet);
            assert!(matches!(outbound(&packet, [0; 3]), Cow::Borrowed(_)));
        }
    }
}
