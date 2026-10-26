//! AES-GCM and ChaCha20-Poly1305 speed on 16 KiB records, the TLS record
//! size: `cargo run --release -p core-crypto --example gcm_speed`.
//! `ONLY_GCM=1` skips the generic RustCrypto paths.

use std::time::Instant;

use core_crypto::fastgcm::Gcm;
use rustls::CipherSuite;

fn main() {
    let size = 16 * 1024 + 1;
    let total: usize = 2 << 30;
    let key = [7u8; 16];
    let nonce = [1u8; 12];
    let aad = [0x17, 3, 3, 0x40, 0x11];
    let gcm = Gcm::new(&key);
    let kind = match &gcm {
        #[cfg(target_arch = "x86_64")]
        Gcm::Ni(_) => "ni",
        #[cfg(target_arch = "aarch64")]
        Gcm::V8(_) => "v8",
        #[cfg(target_os = "linux")]
        Gcm::Alg(_) => "afalg",
        Gcm::Soft128(_) | Gcm::Soft256(_) => "soft",
        #[allow(unreachable_patterns)]
        _ => "other",
    };
    let mut buf = vec![0u8; size];
    let t = Instant::now();
    let mut n = 0;
    while n < total {
        let tag = gcm.seal(&nonce, &aad, &mut buf);
        std::hint::black_box(tag);
        n += size;
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "fastgcm[{kind}] seal 16K: {:.2} GiB/s",
        n as f64 / s / (1u64 << 30) as f64
    );
    let tag = gcm.seal(&nonce, &aad, &mut buf);
    let sealed = buf.clone();
    let t = Instant::now();
    let mut n = 0;
    while n < total {
        buf.copy_from_slice(&sealed);
        assert!(gcm.open(&nonce, &aad, &mut buf, &tag));
        n += size;
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "fastgcm[{kind}] copy+open 16K: {:.2} GiB/s",
        n as f64 / s / (1u64 << 30) as f64
    );
    let t = Instant::now();
    let mut n = 0;
    while n < total {
        buf.copy_from_slice(&sealed);
        std::hint::black_box(&mut buf);
        n += size;
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "copy only 16K: {:.2} GiB/s",
        n as f64 / s / (1u64 << 30) as f64
    );
    let key256 = [7u8; 32];
    let g256 = Gcm::new(&key256);
    let t = Instant::now();
    let mut n = 0;
    while n < total {
        std::hint::black_box(g256.seal(&nonce, &aad, &mut buf));
        n += size;
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "fastgcm aes256 seal 16K: {:.2} GiB/s",
        n as f64 / s / (1u64 << 30) as f64
    );
    if std::env::var("ONLY_GCM").is_ok() {
        return;
    }
    for (name, suite, klen) in [
        ("aes128", CipherSuite::TLS13_AES_128_GCM_SHA256, 16),
        ("chacha", CipherSuite::TLS13_CHACHA20_POLY1305_SHA256, 32),
    ] {
        let key = vec![7u8; klen];
        let t = Instant::now();
        let mut n = 0;
        while n < total / 4 {
            let out = core_crypto::tls13_seal(suite, &key, &nonce, &aad, &buf).unwrap();
            std::hint::black_box(out);
            n += size;
        }
        let s = t.elapsed().as_secs_f64();
        println!(
            "tls13_seal {name} 16K: {:.2} GiB/s",
            n as f64 / s / (1u64 << 30) as f64
        );
    }
    let chacha = core_crypto::fastchacha::ChaChaPoly::new(&[7u8; 32]);
    let t = Instant::now();
    let mut n = 0;
    while n < total {
        std::hint::black_box(chacha.seal(&nonce, &aad, &mut buf));
        n += size;
    }
    let s = t.elapsed().as_secs_f64();
    println!(
        "fastchacha seal 16K: {:.2} GiB/s",
        n as f64 / s / (1u64 << 30) as f64
    );
}
