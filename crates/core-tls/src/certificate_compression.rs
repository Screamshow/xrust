//! Bounded RFC 8879 decoding for the algorithms the browser profiles offer.
use std::io::{self, Read};

use crate::hello::{Ext, Template};

fn bad(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Largest uncompressed certificate message accepted, and the largest zstd
/// window the decoder may reserve for it.
const MAX_CERTIFICATE_SIZE: usize = 1024 * 1024;

pub(crate) fn decode(body: &[u8], template: &Template) -> io::Result<Vec<u8>> {
    if body.len() < 8 {
        return Err(bad("short CompressedCertificate"));
    }
    let algorithm = u16::from_be_bytes([body[0], body[1]]);
    let length = |bytes: &[u8]| {
        (usize::from(bytes[0]) << 16) | (usize::from(bytes[1]) << 8) | usize::from(bytes[2])
    };
    let expected = length(&body[2..5]);
    if expected == 0 || expected > MAX_CERTIFICATE_SIZE || length(&body[5..8]) != body.len() - 8 {
        return Err(bad("invalid CompressedCertificate lengths"));
    }
    let offered = template.extensions.iter().any(|extension| {
        matches!(extension, Ext::Static(27, algorithms)
            if algorithms.get(1..).is_some_and(|list|
                list.as_chunks::<2>().0.iter().any(|pair| *pair == algorithm.to_be_bytes())))
    });
    if !offered {
        return Err(bad(
            "server used an unadvertised certificate compression algorithm",
        ));
    }
    let compressed = &body[8..];
    let reader: Box<dyn Read + '_> = match algorithm {
        1 => Box::new(flate2::read::ZlibDecoder::new(compressed)),
        2 => Box::new(brotli::Decompressor::new(compressed, 4096)),
        // A certificate never needs a window larger than the largest one we
        // accept, and the window also caps the decoder's history buffer.
        3 => Box::new(
            ruzstd::decoding::StreamingDecoder::new_with_max_window_size(
                compressed,
                MAX_CERTIFICATE_SIZE as u64,
            )
            .map_err(|_| bad("invalid zstd certificate frame"))?,
        ),
        _ => return Err(bad("unsupported certificate compression algorithm")),
    };
    let mut decoded = Vec::with_capacity(expected);
    reader.take(expected as u64 + 1).read_to_end(&mut decoded)?;
    if decoded.len() != expected {
        return Err(bad("certificate decompressed length mismatch"));
    }
    Ok(decoded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Counts the heap bytes the current thread holds, so a test can measure
    /// what the decoders allocate internally, not only what they return.
    mod meter {
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::Cell;

        thread_local! {
            static LIVE: Cell<usize> = const { Cell::new(0) };
            static PEAK: Cell<usize> = const { Cell::new(0) };
        }

        fn grow(bytes: usize) {
            let _ = LIVE.try_with(|live| {
                let now = live.get() + bytes;
                live.set(now);
                let _ = PEAK.try_with(|peak| peak.set(peak.get().max(now)));
            });
        }

        fn shrink(bytes: usize) {
            let _ = LIVE.try_with(|live| live.set(live.get().saturating_sub(bytes)));
        }

        struct Meter;

        // SAFETY: every call is forwarded to the system allocator unchanged.
        unsafe impl GlobalAlloc for Meter {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                let ptr = unsafe { System.alloc(layout) };
                if !ptr.is_null() {
                    grow(layout.size());
                }
                ptr
            }
            unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
                let ptr = unsafe { System.alloc_zeroed(layout) };
                if !ptr.is_null() {
                    grow(layout.size());
                }
                ptr
            }
            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                unsafe { System.dealloc(ptr, layout) };
                shrink(layout.size());
            }
            unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
                let new = unsafe { System.realloc(ptr, layout, size) };
                if !new.is_null() {
                    shrink(layout.size());
                    grow(size);
                }
                new
            }
        }

        #[global_allocator]
        static METER: Meter = Meter;

        /// Peak bytes allocated on this thread while `run` executes.
        pub fn peak<T>(run: impl FnOnce() -> T) -> (T, usize) {
            let base = LIVE.with(Cell::get);
            PEAK.with(|peak| peak.set(base));
            let result = run();
            (result, PEAK.with(Cell::get) - base)
        }
    }

    fn message(algorithm: u16, expected: usize, compressed: &[u8]) -> Vec<u8> {
        let mut body = algorithm.to_be_bytes().to_vec();
        body.extend_from_slice(&u32::try_from(expected).unwrap().to_be_bytes()[1..]);
        body.extend_from_slice(&u32::try_from(compressed.len()).unwrap().to_be_bytes()[1..]);
        body.extend_from_slice(compressed);
        body
    }

    const MIB: usize = 1024 * 1024;

    // A frame may not declare a window larger than any certificate we accept.
    #[test]
    fn zstd_window_larger_than_any_certificate_is_refused() {
        let template = crate::fingerprints::firefox();
        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd]; // magic
        frame.push(0x00); // no content size, not single segment, no checksum
        frame.push(16 << 3); // window descriptor: 2^(10+16) = 64 MiB
        let header: u32 = 1 | (1 << 1) | (64 << 3); // last RLE block of 64 bytes
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.push(7);
        let body = message(3, 64, &frame);
        let (result, peak) = meter::peak(|| decode(&body, &template));
        eprintln!("zstd, 64 MiB window header: peak {peak} bytes");
        assert!(result.is_err(), "a 64 MiB window must be refused");
        assert!(
            peak < MIB,
            "zstd reserved {peak} bytes for a 64-byte certificate"
        );
    }

    // BLD-01 (RUSTSEC-2026-0344): one compressed block of 31 sequences, each
    // one literal plus a 131074-byte match at offset 1, expands to about
    // 4 MiB although a block may hold at most 128 KiB. ruzstd 0.8 built the
    // whole block in memory before the outer length limit could stop it.
    #[test]
    fn zstd_block_beyond_the_block_maximum_is_refused_inside_the_decoder() {
        const SEQUENCES: usize = 31;
        let mut block = vec![(SEQUENCES as u8) << 3 | 0b01, b'A']; // RLE literals
        block.push(SEQUENCES as u8);
        block.push(0x54); // literal length, offset and match length codes: RLE
        block.extend_from_slice(&[1, 2, 52]); // 1 literal; offset 1; 65539 + 16 bits
        // Backward bitstream: per sequence 2 offset bits (0) and 16 match
        // length bits (all 1); RLE states take no bits. A 1 marks the end.
        let mut bits = Vec::new();
        for _ in 0..SEQUENCES {
            bits.extend_from_slice(&[0, 0]);
            bits.extend_from_slice(&[1; 16]);
        }
        let total = bits.len();
        let mut stream = vec![0u8; (total + 1).div_ceil(8)];
        for (read, bit) in bits.into_iter().enumerate() {
            let position = total - 1 - read;
            stream[position / 8] |= bit << (position % 8);
        }
        stream[total / 8] |= 1 << (total % 8);
        block.extend_from_slice(&stream);

        let mut frame = vec![0x28, 0xb5, 0x2f, 0xfd, 0x00, 10 << 3]; // 1 MiB window
        let header = 1 | (2 << 1) | (u32::try_from(block.len()).unwrap() << 3);
        frame.extend_from_slice(&header.to_le_bytes()[..3]);
        frame.extend_from_slice(&block);
        let body = message(3, 64, &frame);
        let (result, peak) = meter::peak(|| decode(&body, &template_firefox()));
        eprintln!("zstd, over-long block: peak {peak} bytes");
        assert!(result.is_err());
        assert!(
            peak < MIB,
            "zstd built {peak} bytes for a 64-byte certificate"
        );
    }

    fn template_firefox() -> Template {
        crate::fingerprints::firefox()
    }

    #[test]
    fn zstd_certificate_decodes_within_its_own_size() {
        let template = crate::fingerprints::firefox();
        let certificate: Vec<u8> = (0..64 * 1024u32).map(|i| (i * 7 % 251) as u8).collect();
        let compressed = ruzstd::encoding::compress_to_vec(
            &certificate[..],
            ruzstd::encoding::CompressionLevel::Fastest,
        );
        let body = message(3, certificate.len(), &compressed);
        let (result, peak) = meter::peak(|| decode(&body, &template));
        eprintln!("zstd, 64 KiB certificate: peak {peak} bytes");
        assert_eq!(result.unwrap(), certificate);
        assert!(
            peak < 2 * MIB,
            "zstd used {peak} bytes for a 64 KiB certificate"
        );
    }

    // brotli (offered by every browser profile) sizes its ring buffer from the
    // stream header, at most 2^24 bytes without large-window mode, and shrinks
    // it only for a last meta-block. A stream that never ends its first
    // meta-block holds the whole window: bounded by the format, not by us.
    #[test]
    fn brotli_allocation_is_bounded_by_the_largest_standard_window() {
        let template = crate::fingerprints::chrome();
        let mut stream = Vec::new();
        {
            let mut writer = brotli::CompressorWriter::new(&mut stream, 4096, 5, 24);
            writer.write_all(&[7; 64]).unwrap();
            writer.flush().unwrap();
            // dropped without `close`: no last meta-block
            std::mem::forget(writer);
        }
        let body = message(2, 64, &stream);
        let (_, peak) = meter::peak(|| decode(&body, &template));
        eprintln!("brotli, 2^24 window, open meta-block: peak {peak} bytes");
        assert!(peak <= 16 * MIB + MIB, "brotli held {peak} bytes");
    }

    #[test]
    fn refuses_bad_lengths_unoffered_algorithms_and_excess_output() {
        let template = crate::fingerprints::firefox();
        let mut encoder =
            flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&[7; 64]).unwrap();
        let compressed = encoder.finish().unwrap();
        let mut body = vec![0, 1, 0, 0, 64];
        let length = u32::try_from(compressed.len()).unwrap().to_be_bytes();
        body.extend_from_slice(&length[1..]);
        body.extend_from_slice(&compressed);
        assert_eq!(decode(&body, &template).unwrap(), vec![7; 64]);
        body[4] = 63;
        assert!(decode(&body, &template).is_err());
        body[4] = 65;
        assert!(decode(&body, &template).is_err());
        body[4] = 64;
        body[1] = 99;
        assert!(decode(&body, &template).is_err());
        assert!(decode(&[0; 7], &template).is_err());
        body[2] = 0xff;
        assert!(decode(&body, &template).is_err());
    }
}
