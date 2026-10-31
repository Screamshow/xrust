//! The `quic_transport_parameters` extension a quic-go client sends.
//!
//! QUIC Initial packets are protected with keys derived from the destination
//! connection id, which travels in the clear, so anyone on the path can read
//! the ClientHello and this extension. quinn writes its own parameter set, in
//! an order it shuffles per connection, and adds two parameters no quic-go
//! client sends; every client we imitate -- hysteria, sing-box, Xray's QUIC
//! transports -- is quic-go, whose set and order are fixed
//! (`wire.TransportParameters.Marshal`, client perspective).
//!
//! The values stay the ones quinn negotiated with itself, except where
//! quic-go's differ and advertising quic-go's is safe: a limit we advertise
//! below what we can actually take is always safe, since it only bounds what
//! the peer may send us.

/// The parameters a quic-go client writes, in the order it writes them. A
/// greased parameter goes ahead of all of them.
///
/// Ids outside this list are dropped: quinn's `grease_quic_bit` (0x2ab2) and
/// `min_ack_delay` (0xff04de1b) have no place in a quic-go client's hello,
/// and the server-only ids cannot appear in a client's.
const ORDER: &[u64] = &[
    STREAM_DATA_BIDI_LOCAL,
    STREAM_DATA_BIDI_REMOTE,
    STREAM_DATA_UNI,
    MAX_DATA,
    STREAMS_BIDI,
    STREAMS_UNI,
    MAX_IDLE_TIMEOUT,
    MAX_UDP_PAYLOAD_SIZE,
    MAX_ACK_DELAY,
    ACK_DELAY_EXPONENT,
    DISABLE_ACTIVE_MIGRATION,
    ACTIVE_CONNECTION_ID_LIMIT,
    INITIAL_SOURCE_CONNECTION_ID,
    MAX_DATAGRAM_FRAME_SIZE,
];

const MAX_IDLE_TIMEOUT: u64 = 0x01;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const MAX_DATA: u64 = 0x04;
const STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const STREAM_DATA_UNI: u64 = 0x07;
const STREAMS_BIDI: u64 = 0x08;
const STREAMS_UNI: u64 = 0x09;
const ACK_DELAY_EXPONENT: u64 = 0x0a;
const MAX_ACK_DELAY: u64 = 0x0b;
const DISABLE_ACTIVE_MIGRATION: u64 = 0x0c;
const ACTIVE_CONNECTION_ID_LIMIT: u64 = 0x0e;
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;
const MAX_DATAGRAM_FRAME_SIZE: u64 = 0x20;

/// Parameters a quic-go client writes whatever their value, so an absent one
/// is written as a zero rather than left out.
const ALWAYS: &[u64] = &[
    STREAM_DATA_BIDI_LOCAL,
    STREAM_DATA_BIDI_REMOTE,
    STREAM_DATA_UNI,
    MAX_DATA,
    STREAMS_BIDI,
    STREAMS_UNI,
    MAX_IDLE_TIMEOUT,
    INITIAL_SOURCE_CONNECTION_ID,
];

/// `protocol.MaxActiveConnectionIDs`: what a quic-go client advertises, where
/// quinn advertises its own queue length. Fewer connection ids than we can
/// hold is a limit on the peer, never on us.
const QUIC_GO_ACTIVE_CONNECTION_ID_LIMIT: u64 = 4;
/// `protocol.DefaultActiveConnectionIDLimit`: the value both sides leave out.
const DEFAULT_ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;
/// `ackhandler.MaxAckDelay + protocol.TimerGranularity`, in milliseconds: a
/// quic-go client always sends this, because it is not the protocol default.
/// We delay an ack by less than this, which the parameter permits.
const QUIC_GO_MAX_ACK_DELAY_MS: u64 = 26;
/// `protocol.DefaultAckDelayExponent`: the value quic-go leaves out.
const DEFAULT_ACK_DELAY_EXPONENT: u64 = 3;
/// `wire.MaxDatagramSize`: the largest DATAGRAM frame a quic-go client
/// accepts, where quinn advertises its whole datagram buffer.
const QUIC_GO_MAX_DATAGRAM_FRAME_SIZE: u64 = 16383;

/// Whether an id is one of the reserved ones used for greasing: `31 * n + 27`
/// (RFC 9000 §18.1).
fn is_grease(id: u64) -> bool {
    id % 31 == 27
}

/// Rewrite a client's transport parameters the way a quic-go client sends
/// them. `quinn` is the blob quinn-proto wrote for this connection.
pub(crate) fn in_quic_go_order(quinn: &[u8]) -> Vec<u8> {
    let parsed = parse(quinn);
    let value_of = |want: u64| {
        parsed
            .iter()
            .find(|(id, _)| *id == want)
            .map(|(_, value)| *value)
    };
    let mut out = Vec::with_capacity(quinn.len() + 24);

    // The greased parameter goes first. quinn draws one of the same shape as
    // quic-go's -- a reserved id and up to 15 random bytes -- so it is reused
    // rather than drawn again here.
    if let Some((id, value)) = parsed.iter().find(|(id, _)| is_grease(*id)) {
        write_param(&mut out, *id, value);
    }

    for &id in ORDER {
        match id {
            ACTIVE_CONNECTION_ID_LIMIT => {
                // Left out at the protocol default, as quic-go leaves it out,
                // and otherwise advertised as quic-go's own limit.
                let keep = value_of(id)
                    .and_then(varint)
                    .is_some_and(|limit| limit != DEFAULT_ACTIVE_CONNECTION_ID_LIMIT);
                if keep {
                    write_varint_param(&mut out, id, QUIC_GO_ACTIVE_CONNECTION_ID_LIMIT);
                }
            }
            MAX_ACK_DELAY => write_varint_param(&mut out, id, QUIC_GO_MAX_ACK_DELAY_MS),
            ACK_DELAY_EXPONENT => {
                // Only when it is not the default, which is the only value
                // this stack uses, so normally it is absent.
                if let Some(exponent) = value_of(id).and_then(varint)
                    && exponent != DEFAULT_ACK_DELAY_EXPONENT
                {
                    write_varint_param(&mut out, id, exponent);
                }
            }
            MAX_DATAGRAM_FRAME_SIZE => {
                if value_of(id).is_some() {
                    write_varint_param(&mut out, id, QUIC_GO_MAX_DATAGRAM_FRAME_SIZE);
                }
            }
            _ => match value_of(id) {
                Some(value) => write_param(&mut out, id, value),
                // An empty value is the whole parameter for
                // `disable_active_migration`, so only the ones quic-go always
                // writes are filled in when quinn left them out.
                None if ALWAYS.contains(&id) => write_varint_param(&mut out, id, 0),
                None => {}
            },
        }
    }
    out
}

/// Xray 26.10.21 ChromeParrot profile. Limits come from the actual transport
/// configuration, never from a decorative replacement of flow-control values.
pub(crate) fn in_chrome_order(quinn: &[u8], seed: &[u8; 64]) -> Vec<u8> {
    let parsed = parse(quinn);
    let mut fields: Vec<(u64, Vec<u8>)> = parsed
        .iter()
        .filter(|(id, _)| {
            is_grease(*id)
                || matches!(
                    *id,
                    MAX_IDLE_TIMEOUT
                        | MAX_UDP_PAYLOAD_SIZE
                        | MAX_DATA
                        | STREAM_DATA_BIDI_LOCAL
                        | STREAM_DATA_BIDI_REMOTE
                        | STREAM_DATA_UNI
                        | STREAMS_BIDI
                        | STREAMS_UNI
                        | INITIAL_SOURCE_CONNECTION_ID
                )
        })
        .map(|(id, value)| (*id, value.to_vec()))
        .collect();
    if parsed.iter().any(|(id, _)| *id == MAX_DATAGRAM_FRAME_SIZE) {
        let mut value = Vec::new();
        // The peer's packet is bounded by our real max_udp_payload_size (1472),
        // so this Chrome frame limit cannot exceed our packet/buffer capacity.
        write_varint(&mut value, 65_536);
        fields.push((MAX_DATAGRAM_FRAME_SIZE, value));
    }
    fields.push((0x3128, b"ORIG".to_vec()));
    let grease_version = u32::from_be_bytes(seed[60..64].try_into().expect("four bytes"))
        & 0xf0f0_f0f0
        | 0x0a0a_0a0a;
    let mut versions = 1u32.to_be_bytes().to_vec();
    let available = if seed[59] & 1 == 0 {
        [grease_version, 1]
    } else {
        [1, grease_version]
    };
    for version in available {
        versions.extend_from_slice(&version.to_be_bytes());
    }
    fields.push((0x11, versions));
    for i in (1..fields.len()).rev() {
        let at = (fields.len() - 1 - i) * 4;
        let draw = u32::from_le_bytes(seed[at..at + 4].try_into().expect("four bytes"));
        fields.swap(i, draw as usize % (i + 1));
    }
    let mut out = Vec::new();
    for (id, value) in fields {
        write_param(&mut out, id, &value);
    }
    out
}

/// Split a parameter blob into `(id, value)` pairs. A malformed tail is
/// dropped: the blob comes from quinn's own writer, so this cannot happen,
/// and a panic here would take a connection down.
fn parse(mut bytes: &[u8]) -> Vec<(u64, &[u8])> {
    let mut out = Vec::new();
    while !bytes.is_empty() {
        let Some((id, rest)) = read_varint(bytes) else {
            break;
        };
        let Some((len, rest)) = read_varint(rest) else {
            break;
        };
        let len = len as usize;
        if rest.len() < len {
            break;
        }
        out.push((id, &rest[..len]));
        bytes = &rest[len..];
    }
    out
}

/// A parameter value that is a single varint, for the ones we rewrite.
fn varint(value: &[u8]) -> Option<u64> {
    read_varint(value).map(|(v, _)| v)
}

fn read_varint(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let first = *bytes.first()?;
    let len = 1usize << (first >> 6);
    if bytes.len() < len {
        return None;
    }
    let mut value = u64::from(first & 0x3f);
    for byte in &bytes[1..len] {
        value = (value << 8) | u64::from(*byte);
    }
    Some((value, &bytes[len..]))
}

fn write_varint(out: &mut Vec<u8>, value: u64) {
    debug_assert!(value < (1 << 62));
    if value < (1 << 6) {
        out.push(value as u8);
    } else if value < (1 << 14) {
        out.extend_from_slice(&(value as u16 | 0x4000).to_be_bytes());
    } else if value < (1 << 30) {
        out.extend_from_slice(&(value as u32 | 0x8000_0000).to_be_bytes());
    } else {
        out.extend_from_slice(&(value | 0xc000_0000_0000_0000).to_be_bytes());
    }
}

fn write_param(out: &mut Vec<u8>, id: u64, value: &[u8]) {
    write_varint(out, id);
    write_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn write_varint_param(out: &mut Vec<u8>, id: u64, value: u64) {
    let mut encoded = Vec::with_capacity(8);
    write_varint(&mut encoded, value);
    write_param(out, id, &encoded);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_parameters_preserve_real_limits_and_shuffle() {
        let input = quinn_blob();
        let a = in_chrome_order(&input, &[0x12; 64]);
        let b = in_chrome_order(&input, &[0x34; 64]);
        assert_ne!(a, b);
        assert_eq!(value(&a, MAX_DATA), Some(20 * 1024 * 1024));
        assert_eq!(value(&a, STREAM_DATA_BIDI_LOCAL), Some(8 * 1024 * 1024));
        assert_eq!(value(&a, MAX_DATAGRAM_FRAME_SIZE), Some(65_536));
        assert!(
            parse(&a)
                .iter()
                .any(|(id, v)| *id == 0x3128 && *v == b"ORIG")
        );
        assert_eq!(
            parse(&a)
                .iter()
                .find(|(id, _)| *id == 0x11)
                .unwrap()
                .1
                .len(),
            12
        );
        assert!(
            parse(&a)
                .iter()
                .all(|(id, _)| !matches!(*id, 0x2ab2 | 0xff04de1b | MAX_ACK_DELAY))
        );
    }

    #[test]
    fn chrome_version_grease_can_precede_or_follow_v1() {
        for position in [0, 1] {
            let mut seed = [0x12; 64];
            seed[59] = position;
            let encoded = in_chrome_order(&quinn_blob(), &seed);
            let parsed = parse(&encoded);
            let versions = parsed.iter().find(|(id, _)| *id == 0x11).unwrap().1;
            assert_eq!(&versions[..4], &1u32.to_be_bytes());
            let available: Vec<_> = versions[4..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|v| u32::from_be_bytes(*v))
                .collect();
            assert_eq!(available[1 - position as usize], 1);
            assert_eq!(available[position as usize] & 0x0f0f_0f0f, 0x0a0a_0a0a);
        }
    }

    /// A blob in quinn's shape: shuffled order, a greased parameter in the
    /// middle of it, `grease_quic_bit` and `min_ack_delay` present, an
    /// `active_connection_id_limit` of its own queue length.
    fn quinn_blob() -> Vec<u8> {
        let mut out = Vec::new();
        write_varint_param(&mut out, MAX_IDLE_TIMEOUT, 30_000);
        write_varint_param(&mut out, 0x2ab2, 0); // grease_quic_bit
        write_varint_param(&mut out, STREAM_DATA_UNI, 8 * 1024 * 1024);
        write_param(&mut out, 27 + 31 * 5, &[1, 2, 3]); // quinn's grease
        write_varint_param(&mut out, MAX_DATA, 20 * 1024 * 1024);
        write_varint_param(&mut out, ACTIVE_CONNECTION_ID_LIMIT, 5);
        write_param(&mut out, INITIAL_SOURCE_CONNECTION_ID, &[]);
        write_varint_param(&mut out, STREAM_DATA_BIDI_LOCAL, 8 * 1024 * 1024);
        write_varint_param(&mut out, 0xff04_de1b, 1000); // min_ack_delay
        write_varint_param(&mut out, STREAMS_BIDI, 100);
        write_varint_param(&mut out, MAX_UDP_PAYLOAD_SIZE, 1452);
        write_varint_param(&mut out, STREAM_DATA_BIDI_REMOTE, 8 * 1024 * 1024);
        write_varint_param(&mut out, STREAMS_UNI, 100);
        write_varint_param(&mut out, ACK_DELAY_EXPONENT, 3);
        write_varint_param(&mut out, MAX_DATAGRAM_FRAME_SIZE, 65535);
        out
    }

    fn ids(blob: &[u8]) -> Vec<u64> {
        parse(blob).into_iter().map(|(id, _)| id).collect()
    }

    fn value(blob: &[u8], want: u64) -> Option<u64> {
        parse(blob)
            .into_iter()
            .find(|(id, _)| *id == want)
            .and_then(|(_, value)| varint(value))
    }

    #[test]
    fn the_order_is_the_reference_clients() {
        let out = in_quic_go_order(&quinn_blob());
        let ids = ids(&out);
        assert!(
            is_grease(ids[0]),
            "a greased parameter comes first: {ids:?}"
        );
        assert_eq!(
            &ids[1..],
            [
                STREAM_DATA_BIDI_LOCAL,
                STREAM_DATA_BIDI_REMOTE,
                STREAM_DATA_UNI,
                MAX_DATA,
                STREAMS_BIDI,
                STREAMS_UNI,
                MAX_IDLE_TIMEOUT,
                MAX_UDP_PAYLOAD_SIZE,
                MAX_ACK_DELAY,
                ACTIVE_CONNECTION_ID_LIMIT,
                INITIAL_SOURCE_CONNECTION_ID,
                MAX_DATAGRAM_FRAME_SIZE,
            ]
        );
    }

    #[test]
    fn the_parameters_no_reference_client_sends_are_dropped() {
        let out = in_quic_go_order(&quinn_blob());
        let ids = ids(&out);
        assert!(!ids.contains(&0x2ab2), "grease_quic_bit stayed");
        assert!(!ids.contains(&0xff04_de1b), "min_ack_delay stayed");
        // the default exponent is left out, as the reference leaves it out
        assert!(!ids.contains(&ACK_DELAY_EXPONENT), "{ids:?}");
    }

    #[test]
    fn the_rewritten_values_are_the_reference_clients() {
        let out = in_quic_go_order(&quinn_blob());
        assert_eq!(
            value(&out, ACTIVE_CONNECTION_ID_LIMIT),
            Some(QUIC_GO_ACTIVE_CONNECTION_ID_LIMIT)
        );
        assert_eq!(value(&out, MAX_ACK_DELAY), Some(QUIC_GO_MAX_ACK_DELAY_MS));
        assert_eq!(
            value(&out, MAX_DATAGRAM_FRAME_SIZE),
            Some(QUIC_GO_MAX_DATAGRAM_FRAME_SIZE)
        );
        // everything else is carried over untouched
        assert_eq!(value(&out, MAX_IDLE_TIMEOUT), Some(30_000));
        assert_eq!(value(&out, MAX_DATA), Some(20 * 1024 * 1024));
        assert_eq!(value(&out, STREAM_DATA_BIDI_LOCAL), Some(8 * 1024 * 1024));
        assert_eq!(value(&out, STREAMS_BIDI), Some(100));
        assert_eq!(value(&out, MAX_UDP_PAYLOAD_SIZE), Some(1452));
    }

    /// The connection id is the one parameter whose value is not a varint,
    /// and an empty one still has to be written.
    #[test]
    fn an_empty_source_connection_id_is_still_written() {
        let out = in_quic_go_order(&quinn_blob());
        let found = parse(&out)
            .into_iter()
            .find(|(id, _)| *id == INITIAL_SOURCE_CONNECTION_ID)
            .expect("the source connection id is always written");
        assert!(found.1.is_empty());

        let mut with_cid = Vec::new();
        write_param(&mut with_cid, INITIAL_SOURCE_CONNECTION_ID, &[7, 7, 7, 7]);
        let out = in_quic_go_order(&with_cid);
        let found = parse(&out)
            .into_iter()
            .find(|(id, _)| *id == INITIAL_SOURCE_CONNECTION_ID)
            .expect("kept");
        assert_eq!(found.1, [7, 7, 7, 7]);
    }

    /// A blob without the parameters quic-go always writes still gets them,
    /// as zeros, so the shape does not change with the configuration.
    #[test]
    fn the_always_written_parameters_are_filled_in() {
        let out = in_quic_go_order(&[]);
        assert_eq!(
            ids(&out),
            [
                STREAM_DATA_BIDI_LOCAL,
                STREAM_DATA_BIDI_REMOTE,
                STREAM_DATA_UNI,
                MAX_DATA,
                STREAMS_BIDI,
                STREAMS_UNI,
                MAX_IDLE_TIMEOUT,
                MAX_ACK_DELAY,
                INITIAL_SOURCE_CONNECTION_ID,
            ],
            "no grease to carry over, and only the mandatory ones are filled"
        );
        assert_eq!(value(&out, MAX_DATA), Some(0));
    }

    /// An `active_connection_id_limit` of the protocol default is left out,
    /// the way quic-go leaves it out.
    #[test]
    fn a_default_connection_id_limit_is_left_out() {
        let mut blob = Vec::new();
        write_varint_param(
            &mut blob,
            ACTIVE_CONNECTION_ID_LIMIT,
            DEFAULT_ACTIVE_CONNECTION_ID_LIMIT,
        );
        let out = in_quic_go_order(&blob);
        assert!(!ids(&out).contains(&ACTIVE_CONNECTION_ID_LIMIT));
    }

    #[test]
    fn varints_round_trip() {
        for value in [
            0u64,
            1,
            63,
            64,
            16383,
            16384,
            1 << 29,
            1 << 30,
            (1 << 62) - 1,
        ] {
            let mut out = Vec::new();
            write_varint(&mut out, value);
            assert_eq!(read_varint(&out), Some((value, &[][..])), "{value}");
        }
    }

    #[test]
    fn a_truncated_blob_is_dropped_not_panicked() {
        let mut blob = Vec::new();
        write_varint_param(&mut blob, MAX_DATA, 1234);
        blob.extend_from_slice(&[0x40]); // a two-byte varint id, one byte left
        let parsed = parse(&blob);
        assert_eq!(parsed.len(), 1);
        assert_eq!(value(&in_quic_go_order(&blob), MAX_DATA), Some(1234));
    }
}
