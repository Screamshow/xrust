#[cfg(feature = "alloc")]
use alloc::boxed::Box;

#[cfg(feature = "tls12")]
use super::{DecryptBufferAdapter, EncryptBufferAdapter};
use crate::fastchacha::ChaChaPoly;

use chacha20poly1305::KeySizeUser;
#[cfg(feature = "tls12")]
use chacha20poly1305::{AeadInPlace, KeyInit};
use rustls::crypto::cipher::{
    self, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::{ConnectionTrafficSecrets, ContentType, ProtocolVersion};

#[cfg(feature = "tls12")]
use rustls::crypto::cipher::{KeyBlockShape, NONCE_LEN, Tls12AeadAlgorithm};

pub struct Chacha20Poly1305;

impl Tls13AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Cipher(ChaChaPoly::new(key.as_ref()), iv))
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Cipher(ChaChaPoly::new(key.as_ref()), iv))
    }

    fn key_len(&self) -> usize {
        chacha20poly1305::ChaCha20Poly1305::key_size()
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
    }
}

#[cfg(feature = "tls12")]
impl Tls12AeadAlgorithm for Chacha20Poly1305 {
    fn encrypter(&self, key: AeadKey, iv: &[u8], _: &[u8]) -> Box<dyn MessageEncrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            Iv::copy(iv),
        ))
    }

    fn decrypter(&self, key: AeadKey, iv: &[u8]) -> Box<dyn MessageDecrypter> {
        Box::new(Tls12Cipher(
            chacha20poly1305::ChaCha20Poly1305::new_from_slice(key.as_ref())
                .expect("key should be valid"),
            Iv::copy(iv),
        ))
    }

    fn key_block_shape(&self) -> KeyBlockShape {
        KeyBlockShape {
            enc_key_len: 32,
            fixed_iv_len: 12,
            explicit_nonce_len: 0,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: &[u8],
        _explicit: &[u8],
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        // This should always be true because KeyBlockShape and the Iv nonce len are in
        // agreement.
        debug_assert_eq!(NONCE_LEN, iv.len());
        Ok(ConnectionTrafficSecrets::Chacha20Poly1305 {
            key,
            iv: Iv::new(iv[..].try_into().expect("conversion should succeed")),
        })
    }
}

struct Tls13Cipher(ChaChaPoly, Iv);

impl MessageEncrypter for Tls13Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);
        payload.extend_from_slice(&m.typ.to_array());

        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(total_len);

        // sealed where it lies, the tag appended after it
        let tag = self.0.seal(&nonce, &aad, payload.as_mut());
        payload.extend_from_slice(&tag);
        Ok(OutboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + CHACHAPOLY1305_OVERHEAD
    }
}

impl MessageDecrypter for Tls13Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut m.payload;
        let len = payload.len();
        if len < CHACHAPOLY1305_OVERHEAD {
            return Err(rustls::Error::DecryptError);
        }
        let nonce = cipher::Nonce::new(&self.1, seq).0;
        let aad = cipher::make_tls13_aad(len);
        let tag_at = len - CHACHAPOLY1305_OVERHEAD;
        let tag: [u8; 16] = payload[tag_at..]
            .try_into()
            .map_err(|_| rustls::Error::DecryptError)?;
        if !self.0.open(&nonce, &aad, &mut payload[..tag_at], &tag) {
            return Err(rustls::Error::DecryptError);
        }
        payload.truncate(tag_at);

        m.into_tls13_unpadded_message()
    }
}

#[cfg(feature = "tls12")]
struct Tls12Cipher(chacha20poly1305::ChaCha20Poly1305, Iv);

#[cfg(feature = "tls12")]
impl MessageEncrypter for Tls12Cipher {
    fn encrypt(
        &mut self,
        m: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = self.encrypted_payload_len(m.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);

        payload.extend_from_chunks(&m.payload);

        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).0.into();
        let aad = cipher::make_tls12_aad(seq, m.typ, m.version, m.payload.len());

        self.0
            .encrypt_in_place(&nonce, &aad, &mut EncryptBufferAdapter(&mut payload))
            .map_err(|_| rustls::Error::EncryptError)
            .map(|_| OutboundOpaqueMessage::new(m.typ, m.version, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + CHACHAPOLY1305_OVERHEAD
    }
}

#[cfg(feature = "tls12")]
impl MessageDecrypter for Tls12Cipher {
    fn decrypt<'a>(
        &mut self,
        mut m: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, rustls::Error> {
        let payload = &m.payload;
        let nonce: chacha20poly1305::Nonce = cipher::Nonce::new(&self.1, seq).0.into();
        let aad = cipher::make_tls12_aad(
            seq,
            m.typ,
            m.version,
            payload.len() - CHACHAPOLY1305_OVERHEAD,
        );

        let payload = &mut m.payload;
        self.0
            .decrypt_in_place(&nonce, &aad, &mut DecryptBufferAdapter(payload))
            .map_err(|_| rustls::Error::DecryptError)?;

        Ok(m.into_plain_message())
    }
}

const CHACHAPOLY1305_OVERHEAD: usize = 16;

#[cfg(test)]
#[allow(clippy::cast_possible_truncation)]
mod tests {
    use super::*;
    use alloc::vec::Vec;
    use chacha20poly1305::{AeadInPlace, KeyInit};
    use rustls::crypto::cipher::OutboundChunks;

    fn pattern(n: usize, seed: u8) -> Vec<u8> {
        (0..n)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    const KEY: [u8; 32] = [0x42; 32];
    const IV: [u8; 12] = [
        0x0a, 0xc1, 0x49, 0x3c, 0xa1, 0x90, 0x58, 0x53, 0xb0, 0xbb, 0xa0, 0x3e,
    ];

    /// Bytes on the wire match RustCrypto's AEAD over the same inner plaintext,
    /// nonce and AAD, either side of the 256-byte fast-path threshold.
    #[test]
    fn tls13_records_match_rustcrypto() {
        let alg = Chacha20Poly1305;
        let mut enc = Tls13AeadAlgorithm::encrypter(&alg, AeadKey::from(KEY), Iv::new(IV));
        let mut dec = Tls13AeadAlgorithm::decrypter(&alg, AeadKey::from(KEY), Iv::new(IV));
        let soft = chacha20poly1305::ChaCha20Poly1305::new((&KEY).into());
        for (i, len) in [0usize, 1, 254, 255, 256, 257, 511, 512, 1400, 16384]
            .into_iter()
            .enumerate()
        {
            let seq = 1000 + i as u64;
            let plain = pattern(len, i as u8);
            let m = OutboundPlainMessage {
                typ: ContentType::ApplicationData,
                version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::Single(&plain),
            };
            let record = enc.encrypt(m, seq).expect("encrypt").encode();

            let mut want = plain.clone();
            want.push(ContentType::ApplicationData.into());
            let aad = cipher::make_tls13_aad(want.len() + 16);
            let nonce = cipher::Nonce::new(&Iv::new(IV), seq).0;
            let tag = soft
                .encrypt_in_place_detached((&nonce).into(), &aad, &mut want)
                .expect("reference seal");
            want.extend_from_slice(&tag);
            assert_eq!(record[..5], aad, "header, len {len}");
            assert_eq!(record[5..], want[..], "body, len {len}");

            let mut body = want.clone();
            let m = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut body,
            );
            let out = dec.decrypt(m, seq).expect("decrypt");
            assert_eq!(out.typ, ContentType::ApplicationData);
            assert_eq!(out.payload, &plain[..], "plaintext, len {len}");
        }
    }

    /// A flipped tag or body byte, the wrong sequence number or a record too
    /// short for a tag is a decrypt error.
    #[test]
    fn tls13_bad_records_are_refused() {
        let alg = Chacha20Poly1305;
        let mut enc = Tls13AeadAlgorithm::encrypter(&alg, AeadKey::from(KEY), Iv::new(IV));
        let mut dec = Tls13AeadAlgorithm::decrypter(&alg, AeadKey::from(KEY), Iv::new(IV));
        for len in [0usize, 255, 256, 1400] {
            let plain = pattern(len, 7);
            let m = OutboundPlainMessage {
                typ: ContentType::Handshake,
                version: ProtocolVersion::TLSv1_2,
                payload: OutboundChunks::Single(&plain),
            };
            let record = enc.encrypt(m, 3).expect("encrypt").encode();
            let body = &record[5..];
            let mut cases = Vec::new();
            let mut tag = body.to_vec();
            *tag.last_mut().expect("tag") ^= 0x01;
            cases.push((tag, 3));
            let mut data = body.to_vec();
            data[len / 2] ^= 0x80;
            cases.push((data, 3));
            cases.push((body.to_vec(), 4));
            cases.push((body[..15].to_vec(), 3));
            for (mut bad, seq) in cases {
                let m = InboundOpaqueMessage::new(
                    ContentType::ApplicationData,
                    ProtocolVersion::TLSv1_2,
                    &mut bad,
                );
                assert!(
                    matches!(dec.decrypt(m, seq), Err(rustls::Error::DecryptError)),
                    "len {len} seq {seq}"
                );
            }
            let mut good = body.to_vec();
            let m = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut good,
            );
            let out = dec.decrypt(m, 3).expect("decrypt");
            assert_eq!(out.typ, ContentType::Handshake);
            assert_eq!(out.payload, &plain[..]);
        }
    }
}
