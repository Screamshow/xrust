//! Small helpers shared across the runtime.

use std::io;

use base64::Engine as _;

/// Standard base64 with padding, as the reference decodes it: a length that is
/// not a multiple of four and anything outside the alphabet are errors.
pub(crate) fn decode_base64_std(input: &str) -> io::Result<Vec<u8>> {
    base64::engine::general_purpose::STANDARD
        .decode(input)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// Fill `buf` from the system random source.
pub fn random_bytes(buf: &mut [u8]) -> io::Result<()> {
    getrandom::fill(buf).map_err(|e| io::Error::other(format!("rng: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrip() {
        let decoded = decode_base64_std("MTIzNDU2Nzg5MGFiY2RlZg==").expect("decode");
        assert_eq!(decoded, b"1234567890abcdef");
        assert!(decode_base64_std("AAAAA").is_err());
        assert!(decode_base64_std("!!??").is_err());
    }
}
