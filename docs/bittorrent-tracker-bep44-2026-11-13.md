# HTTP tracker validation and BEP 44 sniffing

Implemented on existing dev after 0.0.40, following the focused comparison with
Jolymmiles/Xray-core def50474c27bc3ace24a6295761222a97cc07869. Protocol behavior
was inspected; external Go code was not copied. No version or dependency change.

## Behavior

- Extended HTTP tracker detection requires info_hash and peer_id to decode to
  20 bytes, with valid percent escapes, and port to be an ASCII unsigned integer
  in 0..65535. Port zero remains accepted for clients without an incoming listener.
  Arbitrary tracker paths remain accepted. Duplicate recognized fields, including
  valueless duplicates, do not establish classification. Invalid tracker fields
  cannot be rescued by appending a BEP 17 piece parameter.
- Existing BEP 17 HTTP seed detection retains the binary hash and unsigned piece
  checks. UA-only HTTP remains HTTP; payload replay and Host extraction are intact.
- Extended DHT detection additionally recognizes BEP 44 get and put. Get requires
  a 20-byte target and validates optional seq. Put requires the existing 20-byte
  node ID, a nonempty token and a structurally valid bencoded value of at most
  1000 encoded bytes. Mutable fields require k=32 bytes, sig=64 bytes, seq in
  0..INT64_MAX, optional cas in the same range and optional salt of at most
  64 bytes. Presence of any mutable field requires the complete mutable shape.
- BEP 44 uses Mainline DHT for arbitrary data; recognizing it does not establish
  torrent file transfer. Signature lengths are checked, not cryptographic validity.
- Existing DHT size/depth/item bounds, duplicate-key checks, full-datagram checks
  and error-only rejection remain. No peer cache or new heap buffer is introduced.
  uTP rules and ordinary (non-extended) classification are unchanged.

Examples: /search?info_hash=document&peer_id=browser&port=banana no longer earns
a BitTorrent DIRECT exception or BitTorrent rejection. Correct BEP 44 queries
now select the configured BitTorrent route only with bittorrent-extended enabled.

## Verification

Checks run in existing Ubuntu WSL, offline and locked, with installed Rust 1.99.1.
The first attempt with the default Rust 1.89 stopped before compilation because
the existing smoltcp 0.14 dependency requires Rust 1.91 or newer.

Commands (CARGO_TARGET_DIR points to the existing operator artifacts/cpu-target):

```
cargo +1.99.1 test -p core-runtime --no-default-features --features rust-x --offline --locked --lib route::sniff_bittorrent
cargo +1.99.1 test -p core-runtime --no-default-features --features rust-x --offline --locked --test bittorrent_direct --test udp_sniff --test udp_dns_sniff --test udp_quic_sniff
cargo +1.99.1 clippy -p core-runtime --lib --test bittorrent_direct --no-default-features --features rust-x --offline --locked -- -D warnings
cargo +1.99.1 fmt --all -- --check
git diff --check
```

Classifier unit tests cover valid/invalid tracker IDs and ports, duplicate fields,
immutable/mutable BEP 44 shapes, bounds, truncated messages and trailing bytes.
Router tests cover IPv4/IPv6 DIRECT selection, disabled-sniff controls, malformed
HTTP staying on the normal route and split TCP prefix replay. Existing UDP
DNS/QUIC/STUN and ambiguous-uTP controls are included.

Results: 11 classifier unit tests and 21 integration tests passed, none skipped
in the selected suites. Clippy completed with warnings denied; formatting and
git diff --check passed. Other library tests were filtered out deliberately.

No live swarm, router/VM, ARM execution, performance benchmark, hosted CI,
publication or installation is part of this increment.
