//! VLESS `encryption` layer (`mlkem768x25519plus`, SPEC 032) — the client
//! post-quantum handshake that sits inside VLESS, beneath the transport and
//! independent of TLS. Ported from sing-box-lx `protocol/vless/encryption/`
//! (itself ported from starifly/sing-box, GPL-3.0): `common.go` (frame codec
//! + AEAD), `client.go` (handshake), `lx_support.go`, `xor.go`.
//!
//! Wire summary (client side):
//! - Client Hello: `iv(16) ‖ relays ‖ [len‖pfsPublicKey]nfsAEAD ‖
//!   [len‖padding]nfsAEAD`, relay per key: ephemeral x25519 public key (32)
//!   or ML-KEM-768 ciphertext (1088) plus 32-byte hash-chain links.
//! - Server Hello: `[pfsPublicKey(1184+32)]nfsAEAD@MaxNonce ‖ [ticket(32)] ‖
//!   [len‖padding]`, then `[len]nfsAEAD` client padding echo.
//! - `unitedKey = pfsKey ‖ nfsKey` (pfs = mlkem768 ‖ x25519 shared secrets).
//!   Record AEAD = blake3.DeriveKey(ctx); ctx = our pfsPublicKey (uplink),
//!   peer pfsPublicKey (downlink), the 16-byte server random (0-RTT) or the
//!   sealed ticket (0-RTT downlink). Counters start at zero and increment
//!   before each use (RFC-style record AEAD).
//! - Appearance `random` (xorMode 2) XORs only the 5-byte record headers
//!   after the handshake, with AES-CTR keyed by blake3("VLESS", unitedKey).
//!
//! Record re-keying at the max nonce (reference `MaxNonce` swap) is omitted:
//! it triggers after 2⁹⁶ records on one connection.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use aes::cipher::{KeyIvInit, StreamCipher};
use bytes::BytesMut;
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::inbound::AnyStream;

use aes::cipher::KeyInit as AeadKeyInit;
use core_crypto::fastgcm::Gcm;
use ml_kem::kem::EncapsulationKey;
use ml_kem::kem::{Decapsulate, Encapsulate};
use ml_kem::{Encoded, EncodedSizeUser, KemCore, MlKem768, MlKem768Params};
use rand_core::RngCore;

/// OS RNG adapter over the engine's fill helper (rand_core 0.6).
#[derive(Debug)]
pub(crate) struct OsRngCore;
impl RngCore for OsRngCore {
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        rand_fill(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}
impl rand_core::CryptoRng for OsRngCore {}

type ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;
type Aes128Ctr = ctr::Ctr128BE<aes::Aes256>;

const MAX_NONCE: [u8; 12] = [0xff; 12];
const RELAY_HASH_LEN: usize = 32;
const MLKEM_EK_LEN: usize = 1184;
const MLKEM_CT_LEN: usize = 1088;
const X25519_PUB_LEN: usize = 32;
const RECORD_HEADER: usize = 5;

fn rand_fill(buf: &mut [u8]) {
    crate::outbound::wireguard::awg::fill_random(buf);
}

fn rand_int(n: usize) -> usize {
    if n <= 1 {
        return 0;
    }
    let mut b = [0u8; 8];
    rand_fill(&mut b);
    (u64::from_le_bytes(b) % n as u64) as usize
}

fn rand_between(from: i64, to: i64) -> i64 {
    if from >= to {
        return from;
    }
    from + (rand_int((to - from) as usize) as i64)
}

// --- blake3 helpers (reference uses lukechampine.com/blake3) ----------------

fn derive_key_aead(ctx: &[u8], key: &[u8]) -> [u8; 32] {
    // The reference passes the ctx as a Go string — raw bytes preserved.
    // Use the library's byte-context API; arbitrary wire bytes are not UTF-8.
    blake3::derive_key_bytes(ctx, key)
}

fn blake3_sum256(data: &[u8]) -> [u8; 32] {
    let mut h = blake3::Hasher::new();
    h.update(data);
    h.finalize().into()
}

/// AES-CTR stream keyed by blake3("VLESS", key) — `NewCTR` in the reference.
fn new_ctr(key: &[u8], iv: &[u8]) -> Aes128Ctr {
    // context "VLESS" is valid UTF-8 — plain derive_key is fine here.
    let k: [u8; 32] = blake3::derive_key("VLESS", key);
    Aes128Ctr::new(
        aes::cipher::generic_array::GenericArray::from_slice(&k),
        iv.into(),
    )
}

// --- record AEAD ------------------------------------------------------------

enum RecordAead {
    Aes(Gcm),
    Cha(Box<ChaCha20Poly1305>),
}

impl RecordAead {
    fn new(ctx: &[u8], key: &[u8], use_aes: bool) -> Self {
        let k = derive_key_aead(ctx, key);
        if use_aes {
            RecordAead::Aes(Gcm::new(&k))
        } else {
            RecordAead::Cha(Box::new(ChaCha20Poly1305::new_from_slice(&k).expect("key")))
        }
    }

    fn seal(&self, nonce: &[u8; 12], plaintext: &[u8], aad: &[u8]) -> Vec<u8> {
        match self {
            RecordAead::Aes(a) => {
                let mut buf = plaintext.to_vec();
                let tag = a.seal(nonce, aad, &mut buf);
                buf.extend_from_slice(&tag);
                buf
            }
            RecordAead::Cha(c) => {
                use chacha20poly1305::aead::{Aead, Payload};
                c.encrypt(
                    nonce.into(),
                    Payload {
                        msg: plaintext,
                        aad,
                    },
                )
                .expect("seal")
            }
        }
    }

    /// Seal `buf` in place, returning the tag — the record write path
    /// stages header + payload in one buffer and seals the payload half.
    fn seal_region(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> [u8; 16] {
        match self {
            RecordAead::Aes(a) => a.seal(nonce, aad, buf),
            RecordAead::Cha(c) => {
                use chacha20poly1305::aead::AeadInPlace;
                let t = c
                    .encrypt_in_place_detached(nonce.into(), aad, buf)
                    .expect("seal");
                let mut out = [0u8; 16];
                out.copy_from_slice(&t);
                out
            }
        }
    }

    /// Open `sealed` (`ciphertext || tag`) in place, truncating to the
    /// plaintext. One buffer through the hot path instead of seal→copy.
    fn open_region(&self, nonce: &[u8; 12], aad: &[u8], sealed: &mut Vec<u8>) -> Result<(), ()> {
        if sealed.len() < 16 {
            return Err(());
        }
        let split = sealed.len() - 16;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&sealed[split..]);
        let ok = match self {
            RecordAead::Aes(a) => {
                let (ct, _) = sealed.split_at_mut(split);
                a.open(nonce, aad, ct, &tag)
            }
            RecordAead::Cha(c) => {
                use chacha20poly1305::aead::AeadInPlace;
                let (ct, _) = sealed.split_at_mut(split);
                c.decrypt_in_place_detached(
                    nonce.into(),
                    aad,
                    ct,
                    chacha20poly1305::Tag::from_slice(&tag),
                )
                .is_ok()
            }
        };
        if !ok {
            return Err(());
        }
        sealed.truncate(split);
        Ok(())
    }

    fn open(&self, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, ()> {
        match self {
            RecordAead::Aes(a) => {
                if ciphertext.len() < 16 {
                    return Err(());
                }
                let split = ciphertext.len() - 16;
                let mut tag = [0u8; 16];
                tag.copy_from_slice(&ciphertext[split..]);
                let mut buf = ciphertext[..split].to_vec();
                a.open(nonce, aad, &mut buf, &tag).then_some(buf).ok_or(())
            }
            RecordAead::Cha(c) => {
                use chacha20poly1305::aead::{Aead, Payload};
                c.decrypt(
                    nonce.into(),
                    Payload {
                        msg: ciphertext,
                        aad,
                    },
                )
                .map_err(|_| ())
            }
        }
    }
}

fn increase_nonce(nonce: &mut [u8; 12]) {
    for i in (0..12).rev() {
        nonce[i] = nonce[i].wrapping_add(1);
        if nonce[i] != 0 {
            break;
        }
    }
}

fn encode_header(out: &mut [u8; RECORD_HEADER], len: usize) {
    out[0] = 23;
    out[1] = 3;
    out[2] = 3;
    out[3] = (len >> 8) as u8;
    out[4] = len as u8;
}

fn decode_header(h: &[u8; RECORD_HEADER]) -> Result<usize, ()> {
    let l = (h[3] as usize) << 8 | h[4] as usize;
    if h[0] != 23 || h[1] != 3 || h[2] != 3 {
        return Err(());
    }
    (17..=16640).contains(&l).then_some(l).ok_or(())
}

fn encode_length(l: usize) -> [u8; 2] {
    [(l >> 8) as u8, l as u8]
}

fn decode_length(b: &[u8]) -> usize {
    (b[0] as usize) << 8 | b[1] as usize
}

// ---------------------------------------------------------------------------
// Client instance.
// ---------------------------------------------------------------------------

enum NfsPublicKey {
    X25519(x25519_dalek::PublicKey),
    Mlkem(Box<EncapsulationKey<MlKem768Params>>),
}

pub struct ClientInstance {
    nfs_p_keys: Vec<NfsPublicKey>,
    nfs_p_keys_bytes: Vec<Vec<u8>>,
    hash32s: Vec<[u8; 32]>,
    relays_length: usize,
    xor_mode: u32,
    seconds: u32,
    padding_lens: Vec<[i64; 3]>,
    padding_gaps: Vec<[i64; 3]>,
    ticket: Arc<Mutex<Option<TicketState>>>,
}

#[derive(Debug, Clone)]
struct TicketState {
    pfs_key: Vec<u8>,
    ticket: [u8; 16],
    expire: std::time::Instant,
}

impl ClientInstance {
    pub fn new(spec: &core_config::vless_enc::ClientEncryptionSpec) -> anyhow::Result<Self> {
        if spec.keys.is_empty() {
            anyhow::bail!("empty nfsPKeysBytes");
        }
        let mut nfs_p_keys = Vec::with_capacity(spec.keys.len());
        let mut hash32s = Vec::with_capacity(spec.keys.len());
        let mut relays_length = 0usize;
        for k in &spec.keys {
            if k.len() == X25519_PUB_LEN {
                let arr: [u8; 32] = k.as_slice().try_into().expect("len checked");
                nfs_p_keys.push(NfsPublicKey::X25519(x25519_dalek::PublicKey::from(arr)));
                relays_length += 32 + 32;
            } else {
                let raw: [u8; MLKEM_EK_LEN] = k
                    .as_slice()
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("invalid ML-KEM-768 encapsulation key"))?;
                let ek: Encoded<EncapsulationKey<MlKem768Params>> = raw.into();
                let ek = <EncapsulationKey<MlKem768Params> as EncodedSizeUser>::from_bytes(&ek);
                nfs_p_keys.push(NfsPublicKey::Mlkem(Box::new(ek)));
                relays_length += MLKEM_CT_LEN + 32;
            }
            hash32s.push(blake3_sum256(k));
        }
        relays_length -= RELAY_HASH_LEN;
        let (padding_lens, padding_gaps) = split_padding(&spec.padding)?;
        Ok(Self {
            nfs_p_keys,
            nfs_p_keys_bytes: spec.keys.clone(),
            hash32s,
            relays_length,
            xor_mode: spec.xor_mode,
            seconds: spec.seconds,
            padding_lens,
            padding_gaps,
            ticket: Arc::new(Mutex::new(None)),
        })
    }

    pub fn from_config(
        obj: &serde_json::Map<String, Value>,
        at: &str,
    ) -> anyhow::Result<Option<Self>> {
        let Some(enc) = obj.get("encryption").and_then(Value::as_str) else {
            return Ok(None);
        };
        if enc.is_empty() || enc == "none" {
            return Ok(None);
        }
        let spec = core_config::vless_enc::parse_client_encryption(enc)
            .map_err(|e| anyhow::anyhow!("{at}: parse encryption: {e}"))?;
        Ok(Some(Self::new(&spec).map_err(|e| {
            anyhow::anyhow!("{at}: initialize encryption: {e}")
        })?))
    }

    /// Perform the handshake over a dialed stream; returns the encrypted conn
    /// that carries the inner VLESS flow.
    pub async fn handshake(&self, mut conn: AnyStream) -> io::Result<AnyStream> {
        // Use AES-256-GCM; Xray detects the client's cipher from the first
        // authenticated handshake record. Gcm retains its software fallback.
        let use_aes = true;

        let iv_and_relays_len = 16 + self.relays_length;
        let pfs_key_exchange_len = 18 + MLKEM_EK_LEN + 32 + 16;
        let (padding_len, padding_lens, padding_gaps) =
            create_padding(&self.padding_lens, &self.padding_gaps);

        let mut client_hello = vec![0u8; iv_and_relays_len + pfs_key_exchange_len + padding_len];
        let mut iv = [0u8; 16];
        rand_fill(&mut iv);
        client_hello[..16].copy_from_slice(&iv);

        // Relays.
        let mut nfs_key = [0u8; 32];
        {
            let mut relays = &mut client_hello[16..iv_and_relays_len];
            let mut last_ctr: Option<Aes128Ctr> = None;
            let count = self.nfs_p_keys.len();
            for (j, key) in self.nfs_p_keys.iter().enumerate() {
                let index = match key {
                    NfsPublicKey::X25519(server_pub) => {
                        let mut sk_bytes = [0u8; 32];
                        rand_fill(&mut sk_bytes);
                        let sk = x25519_dalek::StaticSecret::from(sk_bytes);
                        let pk = x25519_dalek::PublicKey::from(&sk);
                        relays[..32].copy_from_slice(pk.as_bytes());
                        nfs_key = sk.diffie_hellman(server_pub).to_bytes();
                        if nfs_key == [0; 32] {
                            return Err(io::Error::other("vless-enc: invalid server X25519 key"));
                        }
                        32
                    }
                    NfsPublicKey::Mlkem(ek) => {
                        let (ciphertext, shared) = ek
                            .encapsulate(&mut OsRngCore)
                            .map_err(|()| io::Error::other("mlkem encapsulate failed"))?;
                        nfs_key.copy_from_slice(&shared.0);
                        relays[..MLKEM_CT_LEN].copy_from_slice(&ciphertext.0);
                        MLKEM_CT_LEN
                    }
                };
                if self.xor_mode > 0 {
                    let mut ctr = new_ctr(&self.nfs_p_keys_bytes[j], &iv);
                    ctr.apply_keystream(&mut relays[..index]);
                }
                if let Some(ctr) = &mut last_ctr {
                    ctr.apply_keystream(&mut relays[..RELAY_HASH_LEN]);
                }
                if j == count - 1 {
                    break;
                }
                let mut ctr = new_ctr(&nfs_key, &iv);
                let mut hash = self.hash32s[j + 1];
                ctr.apply_keystream(&mut hash);
                relays[index..index + RELAY_HASH_LEN].copy_from_slice(&hash);
                last_ctr = Some(ctr);
                relays = &mut relays[index + RELAY_HASH_LEN..];
            }
        }

        // nfsAEAD with an incrementing counter (client seals: length, pfs
        // public key, padding length, padding echo — later the padding echo
        // again in the Read() path).
        let mut nfs_nonce = [0u8; 12];
        let nfs_aead = RecordAead::new(&iv, &nfs_key, use_aes);
        increase_nonce(&mut nfs_nonce);

        // 0-RTT attempt with a live ticket.
        if self.seconds > 0 {
            let cached = self.ticket.lock().unwrap().clone();
            if let Some(t) = cached
                && std::time::Instant::now() < t.expire
            {
                let united = [t.pfs_key.as_slice(), nfs_key.as_slice()].concat();
                let sealed_len = nfs_aead.seal(&nfs_nonce, &encode_length(32), &[]);
                client_hello[iv_and_relays_len..iv_and_relays_len + 18]
                    .copy_from_slice(&sealed_len);
                increase_nonce(&mut nfs_nonce);
                let sealed_ticket = nfs_aead.seal(&nfs_nonce, &t.ticket, &[]);
                let ticket_end = iv_and_relays_len + 18 + sealed_ticket.len();
                client_hello[iv_and_relays_len + 18..ticket_end].copy_from_slice(&sealed_ticket);
                let pre_write_len = ticket_end;
                let aead_ctx = client_hello[iv_and_relays_len + 18..ticket_end].to_vec();
                let aead = RecordAead::new(&aead_ctx, &united, use_aes);
                let xor_out = (self.xor_mode == 2).then(|| new_ctr(&united, &iv));
                return Ok(Box::new(EncryptedConn {
                    inner: conn,
                    united_key: united,
                    aead: Some((aead_ctx, Some(aead))),
                    peer_aead: None,
                    peer_padding: None,
                    pre_write: Some(client_hello[..pre_write_len].to_vec()),
                    raw: BytesMut::new(),
                    stage: Vec::new(),
                    rec: None,
                    out_buf: Vec::new(),
                    out_pos: 0,
                    out_flush: false,
                    out_claimed: 0,
                    out_nonce: [0u8; 12],
                    in_nonce: [0u8; 12],
                    is_0rtt: true,
                    ticket_cache: Some(self.ticket.clone()),
                    xor_out_ctr: xor_out,
                    xor_in_ctr: None,
                    out_skip: 0,
                    in_skip: 0,
                    direct: VisionDirect::default(),
                }));
            }
        }

        // Full handshake: pfs key exchange region.
        let mut pfs_public_key_plain = [0u8; MLKEM_EK_LEN + 32];
        let (dk, x_sk) = {
            let pfs =
                &mut client_hello[iv_and_relays_len..iv_and_relays_len + pfs_key_exchange_len];
            let sealed_len = nfs_aead.seal(&nfs_nonce, &encode_length(MLKEM_EK_LEN + 32 + 16), &[]);
            increase_nonce(&mut nfs_nonce);
            pfs[..18].copy_from_slice(&sealed_len);
            let (dk, ek) = MlKem768::generate(&mut OsRngCore);
            let mut x_sk_bytes = [0u8; 32];
            rand_fill(&mut x_sk_bytes);
            let x_sk = x25519_dalek::StaticSecret::from(x_sk_bytes);
            let x_pk = x25519_dalek::PublicKey::from(&x_sk);
            pfs_public_key_plain[..MLKEM_EK_LEN].copy_from_slice(ek.as_bytes().as_slice());
            pfs_public_key_plain[MLKEM_EK_LEN..].copy_from_slice(x_pk.as_bytes());
            let sealed_pk = nfs_aead.seal(&nfs_nonce, &pfs_public_key_plain, &[]);
            increase_nonce(&mut nfs_nonce);
            pfs[18..].copy_from_slice(&sealed_pk);
            (dk, x_sk)
        };

        // Padding region.
        let pad_start = iv_and_relays_len + pfs_key_exchange_len;
        let padding = &mut client_hello[pad_start..];
        let sealed_len = nfs_aead.seal(&nfs_nonce, &encode_length(padding_len - 18), &[]);
        increase_nonce(&mut nfs_nonce);
        padding[..18].copy_from_slice(&sealed_len);
        let sealed_pad = nfs_aead.seal(&nfs_nonce, &padding[18..padding_len - 16], &[]);
        increase_nonce(&mut nfs_nonce);
        padding[18..].copy_from_slice(&sealed_pad);

        // Send the hello fragmented with gaps (reference behavior).
        let mut lens: Vec<usize> = padding_lens.iter().map(|b| b[0].max(0) as usize).collect();
        lens[0] += iv_and_relays_len + pfs_key_exchange_len;
        let mut sent = 0usize;
        for (i, l) in lens.into_iter().enumerate() {
            if l > 0 && sent + l <= client_hello.len() {
                conn.write_all(&client_hello[sent..sent + l]).await?;
                sent += l;
            }
            if let Some(gap) = padding_gaps.get(i)
                && gap[0] > 0
            {
                tokio::time::sleep(std::time::Duration::from_millis(gap[0] as u64)).await;
            }
        }
        if sent < client_hello.len() {
            conn.write_all(&client_hello[sent..]).await?;
        }
        conn.flush().await?;

        // Server Hello: pfs public key under the max nonce.
        let mut encrypted_pfs_public_key = vec![0u8; MLKEM_CT_LEN + 32 + 16];
        conn.read_exact(&mut encrypted_pfs_public_key).await?;
        let pfs_server = nfs_aead
            .open(&MAX_NONCE, &encrypted_pfs_public_key, &[])
            .map_err(|_| io::Error::other("vless-enc: server hello decrypt failed"))?;

        let ct_bytes: [u8; MLKEM_CT_LEN] = pfs_server[..MLKEM_CT_LEN]
            .try_into()
            .map_err(|_| io::Error::other("vless-enc: bad mlkem ct"))?;
        let shared = dk
            .decapsulate(&ct_bytes.into())
            .map_err(|()| io::Error::other("vless-enc: decapsulate failed"))?;
        let mut x_peer = [0u8; 32];
        x_peer.copy_from_slice(&pfs_server[MLKEM_CT_LEN..MLKEM_CT_LEN + 32]);
        let x_peer = x25519_dalek::PublicKey::from(x_peer);
        let x_shared = x_sk.diffie_hellman(&x_peer).to_bytes();
        if x_shared == [0; 32] {
            return Err(io::Error::other("vless-enc: invalid ephemeral X25519 key"));
        }

        let mut pfs_key = Vec::with_capacity(64 + nfs_key.len());
        pfs_key.extend_from_slice(&shared.0);
        pfs_key.extend_from_slice(&x_shared);
        let united_key = [pfs_key.as_slice(), nfs_key.as_slice()].concat();
        let our_ctx = pfs_public_key_plain.to_vec();
        // Go's Open() rewrote the slice in place: the ctx is the PLAIN server
        // pfs public key, not the sealed bytes.
        let peer_ctx = pfs_server[..MLKEM_CT_LEN + 32].to_vec();

        // Encrypted ticket. The downlink record counter is shared with the
        // padding-length record that follows (ticket = [1], padding = [2]).
        let mut encrypted_ticket = [0u8; 32];
        conn.read_exact(&mut encrypted_ticket).await?;
        let ticket_record = encrypted_ticket;
        let mut in_nonce = [0u8; 12];
        increase_nonce(&mut in_nonce);
        let ticket = RecordAead::new(&peer_ctx, &united_key, use_aes)
            .open(&in_nonce, &ticket_record, &[])
            .map_err(|_| io::Error::other("vless-enc: ticket decrypt failed"))?;
        let seconds = decode_length(&ticket);

        if self.seconds > 0 && seconds > 0 {
            let mut t = [0u8; 16];
            t.copy_from_slice(&ticket[..16]);
            *self.ticket.lock().unwrap() = Some(TicketState {
                pfs_key,
                ticket: t,
                expire: std::time::Instant::now() + std::time::Duration::from_secs(seconds as u64),
            });
        }

        // Peer padding length.
        let mut encrypted_length = [0u8; 18];
        conn.read_exact(&mut encrypted_length).await?;
        increase_nonce(&mut in_nonce);
        let length_record = RecordAead::new(&peer_ctx, &united_key, use_aes)
            .open(&in_nonce, &encrypted_length, &[])
            .map_err(|_| io::Error::other("vless-enc: padding length decrypt failed"))?;
        let peer_padding_len = decode_length(&length_record);

        let (xor_out_ctr, xor_in_ctr, in_skip) = if self.xor_mode == 2 {
            (
                Some(new_ctr(&united_key, &iv)),
                Some(new_ctr(&united_key, &ticket[..16])),
                0,
            )
        } else {
            (None, None, 0)
        };

        let our_aead_ready = RecordAead::new(&our_ctx, &united_key, use_aes);
        let peer_aead_ready = RecordAead::new(&peer_ctx, &united_key, use_aes);
        Ok(Box::new(EncryptedConn {
            inner: conn,
            united_key,
            aead: Some((our_ctx, Some(our_aead_ready))),
            peer_aead: Some(peer_aead_ready),
            peer_padding: Some(peer_padding_len),
            pre_write: None,
            raw: BytesMut::new(),
            stage: Vec::new(),
            rec: None,
            out_buf: Vec::new(),
            out_pos: 0,
            out_flush: false,
            out_claimed: 0,
            out_nonce: [0u8; 12],
            in_nonce,
            is_0rtt: false,
            ticket_cache: None,
            xor_out_ctr,
            xor_in_ctr,
            out_skip: 0,
            in_skip,
            direct: VisionDirect::default(),
        }))
    }
}

type PaddingBlocks = Vec<[i64; 3]>;

fn split_padding(padding: &str) -> anyhow::Result<(PaddingBlocks, PaddingBlocks)> {
    let blocks = core_config::vless_enc::parse_padding(padding).map_err(|e| anyhow::anyhow!(e))?;
    let mut lens = Vec::new();
    let mut gaps = Vec::new();
    for (i, b) in blocks.into_iter().enumerate() {
        if i % 2 == 0 {
            lens.push(b);
        } else {
            gaps.push(b);
        }
    }
    Ok((lens, gaps))
}

fn create_padding(
    padding_lens: &[[i64; 3]],
    padding_gaps: &[[i64; 3]],
) -> (usize, PaddingBlocks, PaddingBlocks) {
    let (padding_lens, padding_gaps) = if padding_lens.is_empty() {
        (vec![[100, 111, 1111], [50, 0, 3333]], vec![[75, 0, 111]])
    } else {
        (padding_lens.to_vec(), padding_gaps.to_vec())
    };
    let mut length = 0usize;
    let mut lens = Vec::new();
    for y in &padding_lens {
        let l = if y[0] >= rand_between(0, 100) {
            rand_between(y[1], y[2])
        } else {
            0
        };
        length += l as usize;
        lens.push([l, 0, 0]);
    }
    let mut gaps = Vec::new();
    for y in &padding_gaps {
        let g = if y[0] >= rand_between(0, 100) {
            rand_between(y[1], y[2])
        } else {
            0
        };
        gaps.push([g, 0, 0]);
    }
    (length, lens, gaps)
}

// ---------------------------------------------------------------------------
// The encrypted record conn.
// ---------------------------------------------------------------------------

pub struct EncryptedConn {
    inner: AnyStream,
    united_key: Vec<u8>,
    /// `(ctx, aead)` — our uplink AEAD; the 0-RTT path builds it from the
    /// sealed ticket record.
    aead: Option<(Vec<u8>, Option<RecordAead>)>,
    /// downlink AEAD, derived once per connection — rebuilding it per
    /// record cost a blake3 derive on every read
    peer_aead: Option<RecordAead>,
    peer_padding: Option<usize>,
    pre_write: Option<Vec<u8>>,
    raw: BytesMut,
    /// wire bytes staged toward the current read target. It lives in the
    /// conn, not in `poll_read`'s frame: a local buffer would be dropped
    /// when the poll returns Pending and the partially read bytes are gone.
    stage: Vec<u8>,
    /// header of the record whose body is still arriving — parsed once so
    /// a resumed read does not de-xor it with an already-advanced keystream
    rec: Option<([u8; RECORD_HEADER], usize)>,
    /// record bytes the kernel has not taken yet, and whether an
    /// interrupted flush is what the conn still owes the caller
    out_buf: Vec<u8>,
    out_pos: usize,
    out_flush: bool,
    /// Plaintext represented by the staged record, even if the caller grows
    /// its buffer while our write/flush is Pending (the pooled relay does).
    out_claimed: usize,
    out_nonce: [u8; 12],
    in_nonce: [u8; 12],
    is_0rtt: bool,
    ticket_cache: Option<Arc<Mutex<Option<TicketState>>>>,
    xor_out_ctr: Option<Aes128Ctr>,
    xor_in_ctr: Option<Aes128Ctr>,
    out_skip: usize,
    in_skip: usize,
    direct: VisionDirect,
}

const RECORD_MAX: usize = 8192;

#[derive(Default)]
struct VisionDirect {
    read: bool,
    write: bool,
    read_header: Vec<u8>,
    write_header: Vec<u8>,
    read_skip: usize,
    write_skip: usize,
}

impl EncryptedConn {
    // Xray unwraps CommonConn once: Direct skips the encryption AEAD, but
    // retains the outer transport and the random appearance's header XOR.
    pub(crate) fn enable_vision_direct_read(&mut self) -> bool {
        if self.rec.is_some() || !self.stage.is_empty() || self.peer_padding.is_some() {
            return false;
        }
        self.direct.read = true;
        true
    }

    pub(crate) fn enable_vision_direct_write(&mut self) -> bool {
        if self.out_pos < self.out_buf.len() || self.out_flush || self.out_claimed != 0 {
            return false;
        }
        self.direct.write = true;
        true
    }

    /// Append one encrypted record for `chunk` (capped at `RECORD_MAX`)
    /// directly onto `out`, which may already hold the pre_write bytes.
    fn poll_build_record_into(&mut self, buf: &[u8], out: &mut Vec<u8>) -> io::Result<()> {
        let chunk_len = buf.len().min(RECORD_MAX);
        let chunk = &buf[..chunk_len];
        let Some((_ctx, aead_opt)) = self.aead.as_mut() else {
            return Err(io::Error::other("vless-enc: no aead"));
        };
        let Some(aead) = aead_opt.as_ref() else {
            return Err(io::Error::other("vless-enc: 0rtt aead not ready"));
        };
        let l = chunk_len + 16;
        let mut header = [0u8; RECORD_HEADER];
        encode_header(&mut header, l);
        increase_nonce(&mut self.out_nonce);
        let start = out.len();
        out.extend_from_slice(&header);
        out.extend_from_slice(chunk);
        let tag = aead.seal_region(&self.out_nonce, &header, &mut out[start + RECORD_HEADER..]);
        out.extend_from_slice(&tag);
        if let Some(ctr) = &mut self.xor_out_ctr {
            xor_stream(ctr, &mut self.out_skip, &mut out[start..]);
        }
        Ok(())
    }
}

/// XOR the 5-byte record headers (skipping handshake bytes and record
/// bodies), mirroring `XorConn` for one record per call.
fn xor_stream(ctr: &mut Aes128Ctr, skip: &mut usize, buf: &mut [u8]) {
    if *skip >= buf.len() {
        *skip -= buf.len();
        return;
    }
    let start = *skip;
    *skip = 0;
    let end = (start + RECORD_HEADER).min(buf.len());
    ctr.apply_keystream(&mut buf[start..end]);
}

/// XorConn's header-only transform, including split headers and multiple TLS
/// records in one I/O call. Decode the plaintext length before masking writes.
fn xor_direct(
    ctr: &mut Aes128Ctr,
    skip: &mut usize,
    header: &mut Vec<u8>,
    mut buf: &mut [u8],
    reading: bool,
) {
    while !buf.is_empty() {
        let n = (*skip).min(buf.len());
        *skip -= n;
        buf = &mut buf[n..];
        if buf.is_empty() {
            break;
        }
        let n = (RECORD_HEADER - header.len()).min(buf.len());
        if reading {
            ctr.apply_keystream(&mut buf[..n]);
        }
        header.extend_from_slice(&buf[..n]);
        if !reading {
            ctr.apply_keystream(&mut buf[..n]);
        }
        buf = &mut buf[n..];
        if header.len() == RECORD_HEADER {
            *skip = usize::from(u16::from_be_bytes([header[3], header[4]]));
            header.clear();
        }
    }
}

impl AsyncWrite for EncryptedConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = &mut *self;
        if this.direct.write {
            if this.xor_out_ctr.is_none() {
                return Pin::new(&mut this.inner).poll_write(cx, buf);
            }
            if this.out_pos >= this.out_buf.len() {
                this.out_buf.clear();
                this.out_buf
                    .extend_from_slice(&buf[..buf.len().min(RECORD_MAX)]);
                xor_direct(
                    this.xor_out_ctr.as_mut().expect("checked"),
                    &mut this.direct.write_skip,
                    &mut this.direct.write_header,
                    &mut this.out_buf,
                    false,
                );
                this.out_pos = 0;
                this.out_claimed = this.out_buf.len();
            }
            while this.out_pos < this.out_buf.len() {
                let n = ready!(
                    Pin::new(&mut this.inner).poll_write(cx, &this.out_buf[this.out_pos..])
                )?;
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::WriteZero.into()));
                }
                this.out_pos += n;
            }
            this.out_buf.clear();
            this.out_pos = 0;
            return Poll::Ready(Ok(std::mem::take(&mut this.out_claimed)));
        }
        // an interrupted flush is answered before anything new is built —
        // rebuilding here would put a duplicate record on the wire
        if this.out_flush {
            ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
            this.out_flush = false;
            return Poll::Ready(Ok(std::mem::take(&mut this.out_claimed)));
        }
        if this.out_pos >= this.out_buf.len() {
            // nothing staged: pre_write (0-RTT client hello) leads, then the
            // record is built straight into the same buffer — no intermediate
            // Vec, no second copy of the payload
            if this.aead.as_ref().and_then(|a| a.1.as_ref()).is_none() {
                return Poll::Ready(Err(io::Error::other("vless-enc: 0rtt aead not ready")));
            }
            let pre_write = this.pre_write.take();
            let mut staged = std::mem::take(&mut this.out_buf);
            staged.clear();
            if let Some(pre) = &pre_write {
                staged.extend_from_slice(pre);
            }
            if let Err(err) = this.poll_build_record_into(buf, &mut staged) {
                this.pre_write = pre_write;
                this.out_buf = staged;
                return Poll::Ready(Err(err));
            }
            this.out_buf = staged;
            this.out_pos = 0;
            this.out_claimed = buf.len().min(RECORD_MAX);
        }
        while this.out_pos < this.out_buf.len() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.out_buf[this.out_pos..]) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
                Poll::Ready(Ok(0)) => return Poll::Ready(Err(io::ErrorKind::WriteZero.into())),
                Poll::Ready(Ok(n)) => this.out_pos += n,
            }
        }
        this.out_buf.clear();
        this.out_pos = 0;
        this.out_flush = true;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        this.out_flush = false;
        Poll::Ready(Ok(std::mem::take(&mut this.out_claimed)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(_cx)
    }
}

impl AsyncRead for EncryptedConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        out: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if this.direct.read {
            if !this.raw.is_empty() {
                let n = out.remaining().min(this.raw.len());
                out.put_slice(&this.raw.split_to(n));
                return Poll::Ready(Ok(()));
            }
            let before = out.filled().len();
            ready!(Pin::new(&mut this.inner).poll_read(cx, out))?;
            if let Some(ctr) = &mut this.xor_in_ctr {
                xor_direct(
                    ctr,
                    &mut this.direct.read_skip,
                    &mut this.direct.read_header,
                    &mut out.filled_mut()[before..],
                    true,
                );
            }
            return Poll::Ready(Ok(()));
        }
        // 0-RTT: the first read carries the 16-byte server random, which
        // seeds the downlink AEAD (and the XOR stream for `random`).
        if this.is_0rtt && this.peer_aead.is_none() {
            ready!(fill_stage(this, cx, 16))?;
            let mut server_random = [0u8; 16];
            server_random.copy_from_slice(&this.stage[..16]);
            this.stage.clear();
            this.peer_aead = Some(RecordAead::new(&server_random, &this.united_key, true));
            if this.xor_out_ctr.is_some() && this.xor_in_ctr.is_none() {
                this.xor_in_ctr = Some(new_ctr(&this.united_key, &server_random));
            }
            this.is_0rtt = false;
        }
        // 1-RTT: a padded `[len]AEAD` record precedes the data.
        if let Some(peer_padding_len) = this.peer_padding {
            ready!(fill_stage(this, cx, peer_padding_len))?;
            if let Some(aead) = this.peer_aead.as_ref() {
                increase_nonce(&mut this.in_nonce);
                aead.open_region(&this.in_nonce, &[], &mut this.stage)
                    .map_err(|_| io::Error::other("vless-enc: padding decrypt failed"))?;
            }
            this.stage.clear();
            this.peer_padding = None;
        }
        if this.raw.is_empty() {
            if this.rec.is_none() {
                ready!(fill_stage(this, cx, RECORD_HEADER))?;
                let mut header = [0u8; RECORD_HEADER];
                header.copy_from_slice(&this.stage[..RECORD_HEADER]);
                if let Some(ctr) = &mut this.xor_in_ctr {
                    xor_stream(ctr, &mut this.in_skip, &mut header);
                }
                let l = decode_header(&header).map_err(|_| {
                    // Xray responds to an expired ticket with noise. Drop only
                    // the matching cached session; a concurrent new handshake
                    // may already have replaced it. The next dial starts fresh.
                    if let Some(cache) = this.ticket_cache.take() {
                        let mut cached = cache.lock().unwrap();
                        if cached
                            .as_ref()
                            .is_some_and(|t| this.united_key.starts_with(&t.pfs_key))
                        {
                            *cached = None;
                        }
                    }
                    io::Error::other("vless-enc: invalid record header; new handshake needed")
                })?;
                this.ticket_cache = None;
                this.rec = Some((header, l));
                // the header now lives in `rec`; the stage is free to hold
                // the body, which may arrive over several polls
                this.stage.clear();
            }
            let (header, l) = this.rec.expect("record header parsed above");
            ready!(fill_stage(this, cx, l))?;
            let Some(aead) = this.peer_aead.as_ref() else {
                return Poll::Ready(Err(io::Error::other("vless-enc: peer aead missing")));
            };
            increase_nonce(&mut this.in_nonce);
            aead.open_region(&this.in_nonce, &header, &mut this.stage)
                .map_err(|_| io::Error::other("vless-enc: record decrypt failed"))?;
            this.raw.extend_from_slice(&this.stage);
            this.stage.clear();
            this.rec = None;
        }
        let n = out.remaining().min(this.raw.len());
        out.put_slice(&this.raw.split_to(n));
        Poll::Ready(Ok(()))
    }
}

use std::task::ready;

/// Stage `target` bytes from `inner` into the conn's persistent `stage`
/// buffer, resuming where an earlier Pending call stopped. Staging in a
/// per-call local would lose the bytes read before the poll returned.
fn fill_stage(
    this: &mut EncryptedConn,
    cx: &mut Context<'_>,
    target: usize,
) -> Poll<io::Result<()>> {
    let EncryptedConn { inner, stage, .. } = this;
    while stage.len() < target {
        let have = stage.len();
        stage.resize(target, 0);
        let mut chunk = ReadBuf::new(&mut stage[have..]);
        match Pin::new(&mut *inner).poll_read(cx, &mut chunk) {
            Poll::Pending => {
                stage.truncate(have);
                return Poll::Pending;
            }
            Poll::Ready(Err(err)) => {
                stage.truncate(have);
                return Poll::Ready(Err(err));
            }
            Poll::Ready(Ok(())) => {
                let n = chunk.filled().len();
                stage.truncate(have + n);
                if n == 0 {
                    return Poll::Ready(Err(io::ErrorKind::UnexpectedEof.into()));
                }
            }
        }
    }
    Poll::Ready(Ok(()))
}
// ---------------------------------------------------------------------------
// Outbound wiring.
// ---------------------------------------------------------------------------

/// The configured VLESS encryption layer; `None` leaves VLESS untouched.
pub struct VlessEncryption {
    instance: ClientInstance,
}

impl VlessEncryption {
    pub fn from_config(
        obj: &serde_json::Map<String, Value>,
        at: &str,
    ) -> anyhow::Result<Option<Self>> {
        Ok(ClientInstance::from_config(obj, at)?.map(|instance| Self { instance }))
    }

    /// Handshake over the connected stream (above the transport/TLS, below
    /// the inner VLESS flow).
    pub async fn wrap(&self, stream: AnyStream) -> io::Result<AnyStream> {
        self.instance.handshake(stream).await
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn vision_direct_random_masks_only_headers_across_fragmented_io() {
        let key = [0x42; 96];
        let iv = [0x17; 16];
        let mut plain = Vec::new();
        for n in [17, 4096, 12000] {
            let mut h = [0; RECORD_HEADER];
            encode_header(&mut h, n);
            plain.extend_from_slice(&h);
            plain.extend(std::iter::repeat_n(0x55, n));
        }
        let mut oracle = plain.clone();
        let mut ctr = new_ctr(&key, &iv);
        let mut at = 0;
        while at < oracle.len() {
            let n = usize::from(u16::from_be_bytes([oracle[at + 3], oracle[at + 4]]));
            ctr.apply_keystream(&mut oracle[at..at + RECORD_HEADER]);
            at += RECORD_HEADER + n;
        }
        for chunk in [1, 2, 4, 5, 7, 4096, 65536] {
            let mut masked = plain.clone();
            let mut ctr = new_ctr(&key, &iv);
            let (mut skip, mut header) = (0, Vec::new());
            for part in masked.chunks_mut(chunk) {
                xor_direct(&mut ctr, &mut skip, &mut header, part, false);
            }
            assert_eq!(masked, oracle);
            let mut ctr = new_ctr(&key, &iv);
            let (mut skip, mut header) = (0, Vec::new());
            for part in masked.chunks_mut(chunk) {
                xor_direct(&mut ctr, &mut skip, &mut header, part, true);
            }
            assert_eq!(masked, plain);
        }
    }

    #[test]
    fn aes_records_use_the_full_derived_key() {
        use aes_gcm::aead::AeadInPlace;
        use aes_gcm::{Aes256Gcm, KeyInit};
        let context = b"independent AES-256 record check";
        let key = [0x42; 96];
        let derived = super::derive_key_aead(context, &key);
        let oracle = Aes256Gcm::new_from_slice(&derived).unwrap();
        let nonce = [0x17; 12];
        let aad = [23, 3, 3, 0, 20];
        let mut expected = b"ping".to_vec();
        oracle
            .encrypt_in_place((&nonce).into(), &aad, &mut expected)
            .unwrap();
        assert_eq!(
            super::RecordAead::new(context, &key, true).seal(&nonce, b"ping", &aad),
            expected
        );
    }

    #[test]
    fn binary_derive_context_matches_reference_vector() {
        let context = [0xff, 0, 0xc3, 0x28, 0x80, 0xf0, 0x9f, 0x92];
        let result = super::derive_key_aead(&context, &[0x42; 32]);
        let hex: String = result.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(
            hex,
            "4451382280b53cfedf471e21ab6d875d19d59c0af168c12930b2929a6258a917"
        );
        for context in ["", "VLESS", "unicode контекст"] {
            assert_eq!(
                super::derive_key_aead(context.as_bytes(), &[0x42; 32]),
                blake3::derive_key(context, &[0x42; 32])
            );
        }
    }

    use super::*;

    /// Minimal in-process responder mirroring Xray-core
    /// `proxy/vless/encryption/server.go` (native appearance, no 0-RTT):
    /// full handshake + one record echo each way.
    struct TestServer {
        x_sk: x25519_dalek::StaticSecret,
    }

    fn x_pk_bytes(sk: &x25519_dalek::StaticSecret) -> [u8; 32] {
        *x25519_dalek::PublicKey::from(sk).as_bytes()
    }

    async fn echo_roundtrip(client_io: AnyStream, server_io: AnyStream) {
        // Client config: a single x25519 key (the server's public).
        let server = TestServer {
            x_sk: x25519_dalek::StaticSecret::from([0x11u8; 32]),
        };
        let server_pub = x_pk_bytes(&server.x_sk);
        let key_b64 = {
            const A: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            let mut acc = 0u32;
            let mut bits = 0;
            for &b in server_pub.iter() {
                acc = (acc << 8) | b as u32;
                bits += 8;
                while bits >= 6 {
                    bits -= 6;
                    out.push(A[(acc >> bits) as usize & 63] as char);
                }
            }
            // Raw encoding tail: 32 bytes = 256 bits = 42*6 + 4 → one final
            // 4-bit group, zero-padded to a 6-bit symbol.
            if bits > 0 {
                out.push(A[((acc << (6 - bits)) & 63) as usize] as char);
            }
            out
        };
        let spec = core_config::vless_enc::parse_client_encryption(&format!(
            "mlkem768x25519plus.native.1rtt.{key_b64}"
        ))
        .expect("parse");
        let instance = ClientInstance::new(&spec).expect("init");

        let client = tokio::spawn(async move { instance.handshake(client_io).await });

        // --- server handshake (sync, native, no 0rtt) ---
        let mut conn = server_io;
        let mut iv_and_relays = vec![0u8; 16 + 32]; // single x25519 key: relay only
        conn.read_exact(&mut iv_and_relays).await.unwrap();
        let iv: [u8; 16] = iv_and_relays[..16].try_into().unwrap();
        let relays = iv_and_relays[16..].to_vec();

        // peer x25519 public = relays[..32] (native: not XORed)
        let peer_pub: [u8; 32] = relays[..32].try_into().unwrap();
        let peer_pk = x25519_dalek::PublicKey::from(peer_pub);
        let nfs_key = server.x_sk.diffie_hellman(&peer_pk).to_bytes();

        let mut nfs_nonce = [0u8; 12];
        let nfs_aead = RecordAead::new(&iv, &nfs_key, true);
        increase_nonce(&mut nfs_nonce);

        // encryptedLength (sealed EncodeLength(1216))
        let mut encrypted_length = [0u8; 18];
        conn.read_exact(&mut encrypted_length).await.unwrap();
        let dec = nfs_aead
            .open(&nfs_nonce, &encrypted_length, &[])
            .expect("len decrypt");
        increase_nonce(&mut nfs_nonce);
        assert_eq!(decode_length(&dec), MLKEM_EK_LEN + 32 + 16);

        // encryptedPfsPublicKey
        let mut encrypted_pfs = vec![0u8; MLKEM_EK_LEN + 32 + 16];
        conn.read_exact(&mut encrypted_pfs).await.unwrap();
        let pfs_public_key = nfs_aead
            .open(&nfs_nonce, &encrypted_pfs, &[])
            .expect("pfs decrypt");
        let pfs_public_key_client_plain = pfs_public_key.clone();
        increase_nonce(&mut nfs_nonce);

        // Encapsulate toward the client's pfs public key.
        let client_ek: [u8; MLKEM_EK_LEN] = pfs_public_key[..MLKEM_EK_LEN].try_into().unwrap();
        let client_ek =
            <EncapsulationKey<MlKem768Params> as EncodedSizeUser>::from_bytes(&client_ek.into());
        let (ciphertext, mlkem_shared) =
            Encapsulate::encapsulate(&client_ek, &mut OsRngCore).expect("encapsulate");
        let mut x_s_bytes = [0u8; 32];
        rand_fill(&mut x_s_bytes);
        let x_s = x25519_dalek::StaticSecret::from(x_s_bytes);
        let x_s_pub = x25519_dalek::PublicKey::from(&x_s);
        let x_p_pub: [u8; 32] = pfs_public_key[MLKEM_EK_LEN..].try_into().unwrap();
        let x_shared = x_s
            .diffie_hellman(&x25519_dalek::PublicKey::from(x_p_pub))
            .to_bytes();
        let mut pfs_key = Vec::new();
        pfs_key.extend_from_slice(&mlkem_shared.0);
        pfs_key.extend_from_slice(&x_shared);
        let united_key = [pfs_key.as_slice(), nfs_key.as_slice()].concat();

        let mut pfs_public_key_server = Vec::new();
        pfs_public_key_server.extend_from_slice(&ciphertext.0);
        pfs_public_key_server.extend_from_slice(x_s_pub.as_bytes());

        // Server Hello: [pfsPublicKey]@MaxNonce, [ticket], [len|padding]
        let our_ctx = pfs_public_key_server.clone();
        // Go opened the client pfs key in place — the ctx is the PLAIN key.
        let peer_ctx = pfs_public_key_client_plain.clone();
        let our_aead = RecordAead::new(&our_ctx, &united_key, true);
        let peer_aead = RecordAead::new(&peer_ctx, &united_key, true);

        let sealed_pfs = nfs_aead.seal(&MAX_NONCE, &pfs_public_key_server, &[]);
        conn.write_all(&sealed_pfs).await.unwrap();
        let mut our_nonce = [0u8; 12];
        let ticket_record = {
            increase_nonce(&mut our_nonce);
            let mut ticket_plain = [0u8; 16];
            rand_fill(&mut ticket_plain);
            our_aead.seal(&our_nonce, &ticket_plain, &[])
        };
        let mut out = Vec::new();
        out.extend_from_slice(&ticket_record);
        {
            increase_nonce(&mut our_nonce);
            let sealed_len = our_aead.seal(&our_nonce, &encode_length(16), &[]);
            increase_nonce(&mut our_nonce);
            let sealed_pad = our_aead.seal(&our_nonce, &[], &[]);
            out.extend_from_slice(&sealed_len);
            out.extend_from_slice(&sealed_pad);
        }
        conn.write_all(&out).await.unwrap();

        // Client's padding echo: [18]nfsAEAD.
        let mut encrypted_length = [0u8; 18];
        conn.read_exact(&mut encrypted_length).await.unwrap();
        let dec = nfs_aead
            .open(&nfs_nonce, &encrypted_length, &[])
            .expect("client padding len decrypt");
        increase_nonce(&mut nfs_nonce);
        let pad_len = decode_length(&dec);
        let mut pad = vec![0u8; pad_len];
        conn.read_exact(&mut pad).await.unwrap();
        nfs_aead
            .open(&nfs_nonce, &pad, &[])
            .expect("client padding decrypt");
        increase_nonce(&mut nfs_nonce);

        // --- record echo ---
        let mut client_conn = client.await.unwrap().expect("client handshake");
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        client_conn.write_all(b"ping-record").await.unwrap();
        let mut rec = [0u8; RECORD_HEADER];
        conn.read_exact(&mut rec).await.unwrap();
        let l = decode_header(&rec).expect("header");
        let mut data = vec![0u8; l];
        conn.read_exact(&mut data).await.unwrap();
        let opened = peer_aead
            .open(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], &data, &rec)
            .expect("record decrypt");
        assert_eq!(&opened, b"ping-record");

        // server echoes back under the peer ctx
        {
            increase_nonce(&mut our_nonce);
            // pong: 4-byte payload + 16-byte tag → record length 20
            let frame = [23u8, 3, 3, 0, 20];
            let sealed = our_aead.seal(&our_nonce, b"pong", &frame);
            conn.write_all(&frame).await.unwrap();
            conn.write_all(&sealed).await.unwrap();
        }
        let mut back = vec![0u8; 4];
        client_conn.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"pong");
    }

    #[tokio::test]
    async fn handshake_full_and_record_echo() {
        let (client_io, server_io) = tokio::io::duplex(1 << 16);
        echo_roundtrip(Box::new(client_io), Box::new(server_io)).await;
    }

    /// Hands out a few bytes per call and alternates with a Pending, so
    /// every exact-read and every record write has to resume mid-stream.
    struct Chunked<S> {
        inner: S,
        per: usize,
        r_ok: bool,
        w_ok: bool,
        f_ok: bool,
    }

    impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for Chunked<S> {
        fn poll_read(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            let this = &mut *self;
            if !this.r_ok {
                this.r_ok = true;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            this.r_ok = false;
            let mut tmp = vec![0u8; buf.remaining().min(this.per)];
            let mut rb = tokio::io::ReadBuf::new(&mut tmp);
            match std::pin::Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => {
                    buf.put_slice(rb.filled());
                    std::task::Poll::Ready(Ok(()))
                }
                other => other,
            }
        }
    }

    impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for Chunked<S> {
        fn poll_write(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<io::Result<usize>> {
            let this = &mut *self;
            if !this.w_ok {
                this.w_ok = true;
                cx.waker().wake_by_ref();
                return std::task::Poll::Pending;
            }
            this.w_ok = false;
            let n = buf.len().min(this.per);
            std::pin::Pin::new(&mut this.inner).poll_write(cx, &buf[..n])
        }
        fn poll_flush(
            mut self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            if !self.f_ok {
                self.f_ok = true;
                cx.waker().wake_by_ref();
                return Poll::Pending;
            }
            std::pin::Pin::new(&mut self.inner).poll_flush(cx)
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<io::Result<()>> {
            std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
        }
    }

    #[tokio::test]
    async fn records_survive_fragmented_io() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let client_io = Box::new(Chunked {
            inner: a,
            per: 7,
            r_ok: true,
            w_ok: true,
            f_ok: true,
        });
        let server_io = Box::new(Chunked {
            inner: b,
            per: 5,
            r_ok: true,
            w_ok: true,
            f_ok: true,
        });
        echo_roundtrip(client_io, server_io).await;
    }

    #[tokio::test]
    async fn pending_record_claims_only_the_original_plaintext() {
        for pending_flush in [false, true] {
            let (a, mut b) = tokio::io::duplex(4096);
            let inner = Box::new(Chunked {
                inner: a,
                per: 4096,
                r_ok: true,
                w_ok: pending_flush,
                f_ok: !pending_flush,
            });
            let mut conn = EncryptedConn {
                inner,
                united_key: vec![0x42; 96],
                aead: Some((
                    b"test".to_vec(),
                    Some(RecordAead::new(b"test", &[0x42; 96], true)),
                )),
                peer_aead: None,
                peer_padding: None,
                pre_write: None,
                raw: BytesMut::new(),
                stage: Vec::new(),
                rec: None,
                out_buf: Vec::new(),
                out_pos: 0,
                out_flush: false,
                out_claimed: 0,
                out_nonce: [0; 12],
                in_nonce: [0; 12],
                is_0rtt: false,
                ticket_cache: None,
                xor_out_ctr: None,
                xor_in_ctr: None,
                out_skip: 0,
                in_skip: 0,
                direct: VisionDirect::default(),
            };
            let first =
                std::future::poll_fn(|cx| Poll::Ready(Pin::new(&mut conn).poll_write(cx, b"abc")))
                    .await;
            assert!(first.is_pending());
            // The relay can append new client bytes during Pending. They
            // must remain unclaimed until a subsequent encrypted record.
            let n = std::future::poll_fn(|cx| Pin::new(&mut conn).poll_write(cx, b"abcdef"))
                .await
                .unwrap();
            assert_eq!(n, 3);
            conn.write_all(b"def").await.unwrap();
            let aead = RecordAead::new(b"test", &[0x42; 96], true);
            for (nonce, expected) in [(1, b"abc"), (2, b"def")] {
                let mut header = [0; 5];
                b.read_exact(&mut header).await.unwrap();
                let mut record = vec![0; decode_header(&header).unwrap()];
                b.read_exact(&mut record).await.unwrap();
                let mut counter = [0; 12];
                counter[11] = nonce;
                assert_eq!(aead.open(&counter, &record, &header).unwrap(), expected);
            }
        }
    }
}
