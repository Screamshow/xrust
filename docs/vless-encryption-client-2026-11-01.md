# VLESS Encryption client integration, 2026-11-01

Requested scope: support the existing encrypted VLESS subscription node while
preserving XHTTP packet-up, TLS verification, SNI, fingerprint and transport
settings. No release or production installation is part of this change.

Source: Rust X dev at `37e8b70a466efea32ce4b687b58079e4aa6d938a`, with the
local changes described here. Forkop X dev baseline:
`4ef5b35932d5270c6345d7cfc1f4ce0e9441a460`.

## Implementation

The existing `outbound/vless_enc.rs` module was not wired into `secure::Vless`.
The outbound now constructs one shared encryption instance and wraps the dialed
transport before sending the VLESS header. Clones share the session ticket.
Absent/empty/`none` encryption retains the existing path, including PendingHead.
No XHTTP/TLS implementation or settings were changed.

Comparison with the local independent Xray sources identified and corrected:

- AES-256-GCM uses the complete derived 32-byte key, rather than AES-128.
- The PFS block length includes its authentication tag.
- Resumed sessions advance the handshake nonce before sealing the ticket,
  initialize their record cipher, and cache the decrypted ticket.
- Random appearance uses the decrypted ticket as the full-handshake downlink
  CTR context and does not skip bytes already consumed outside the record layer.
- Native/xorpub resumed downlinks do not incorrectly acquire header XOR.
- A rejected cached ticket is invalidated without erasing a newer concurrent
  session; the next connection performs a full handshake. Failed application
  requests are not silently replayed.
- Preserve the exact plaintext count across Pending writes/flushes even when
  the pooled relay appends bytes. Without this fix, real HTTPS produced TLS
  bad-record-MAC alerts despite bulk echo success. A regression test covers
  both Pending-write and Pending-flush with a growing caller buffer.
- Reject zero X25519 shared secrets, validate padding during configuration check,
  match Xray's maximum record length, and flush the full handshake before reading.

Configuration validation now parses the supported specification rather than
rejecting every non-`none` value. CLI compatibility output advertises
`outbound.vless.encryption`. Forkop passes this explicit capability into its
generator; older binaries retain their prior rejection behavior. Existing Go
core behavior is preserved. Server-side VLESS Encryption was not added.

## Verification

- Five focused encryption module tests, including fragmented I/O and an
  independent RustCrypto AES-256 record oracle: passed.
- Core-config rust-x profile: 197 unit tests and 17 integration tests passed.
- Existing secure outbound tests: 19 passed sequentially. The initial parallel
  run failed two exact elapsed-time assertions (50/100 ms); no timer or transport
  implementation was changed to silence them.
- Forkop generator: old/new capability, subscription, manual links, JSON nodes,
  empty incompatible section preservation and Go-core controls: passed.
- Feature parsing and existing Trojan/XHTTP capability tests: passed.
- Clippy for core-runtime/core-cli under rust-x with warnings denied: passed.

The reusable independent peer harness is
`scripts/test_vless_encryption_xray.py`. It uses loopback-only listeners,
generated test keys and a fresh localhost certificate with certificate/name
verification enabled. It tests native/xorpub/random, 1rtt/0rtt and TLS over
TCP/XHTTP packet-up/stream-up/stream-one: 24 cases, each with three byte-checked
256 KiB + 37 byte echo transfers plus an independently verified inner TLS echo. Negative SNI/key/UUID and server-restart ticket
recovery controls are included. The verified peer is Xray 26.9.8, commit 37ceb8b;
this is not a statement about every later Xray version.

Local evidence directories are outside the source tree under
`tmp/vless-encryption-controls` and `tmp/vless-encryption-final`; the final
harness writes binary hashes and peer version to `metadata.json`.

This does not establish encrypted UDP/Vision interoperability, every key-chain
or ML-KEM static-key configuration, universal outer traffic indistinguishability,
or throughput/CPU/RSS improvements. SRS and routing behavior are unchanged.

## ARM and real subscription node

Release-profile builds for x86_64-unknown-linux-musl and
aarch64-unknown-linux-musl passed with the existing target crypto flags.
The final x86 candidate SHA-256 is
`3800d4c317ff59cd0df0deb6ba90e2a749090a5fcbc38ef662a2942a4c6553c9`.
The ARM candidate SHA-256 is
`7a9d0d76b55e76e49f3c76a8708c7f27e3740b1b0f36bf0a40763280213016a0`.

The user-supplied real node passed HTTP 200, HTTPS 200 (577 bytes) and HTTPS 204
through both independent Xray and the final x86 candidate. The earlier candidate
failed HTTPS; this exposed the growing-buffer/Pending bug described above, which
was fixed before declaring success. The local harness now tests inner TLS in
every one of its 24 cases, in addition to the 72 bulk echo transfers.

On the operator MT6000, the ARM candidate ran as an isolated temporary process,
listening only on loopback port 29187. Its config selected the actual node from
the router's private subscription cache without exporting that cache. The
existing packet-up, TLS, SNI and Chrome fingerprint were retained; certificate
verification was not disabled. HTTPS returned 200 / 204 / 200, with both 200
responses carrying 577 bytes. Repeated requests exercised the configured 0rtt
session reuse. The temporary binary's hash was checked after transfer.

The temporary process/config/binary and probe directory were removed. Production
core/config/UCI hashes and existing core PIDs 6521 and 5659 matched before and
after. Installed packages remained Forkop/LuCI 2.6.5 and rust-x 0.0.33-r1; no
service restart, firewall change or package installation was performed. This
source change is local on dev; main, public releases and the installed dashboard
have not been updated.
