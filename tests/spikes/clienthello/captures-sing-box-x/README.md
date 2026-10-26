# Sing-Box X 1.0.3 ClientHello captures

Captured on loopback with `tools/capture_x_fingerprints.py` from our x86_64
Sing-Box X 1.0.3 binary, extracted from the hash-verified mirror IPK and unpacked
with UPX. `provenance.json` records the package, binary and capture hashes.
These fixtures contain generated public handshake data and a dummy VLESS UUID.

Firefox 148 and Safari 26.3 presets and the coherent randomized/REALITY behavior
originate in Sing-Box X's `patches/tls-fingerprints` series by FiyeroT from
podkop-engine v1.14.2-r12 (GPL-3.0-or-later), crediting Xray-core and
refraction-networking/utls aa6edf4. Rust X uses measured tables rather than Go code.

Chrome aliases resolve to the updated Chrome table, used for Forkop XHTTP.
Firefox and Safari are the other profiles used by this deployment.
Random profiles are outside this update; no new runtime support is added for them.
Firefox's classical X25519 share reuses the hybrid X25519 key; Chrome and Safari
use independent keys. REALITY's existing client version remains 26.3.27.

Legacy Edge/iOS/Android/360/QQ tables remain unchanged and do not gain modern
hybrid REALITY compatibility through these changes. The captured ECH GREASE
bodies are not replayed: the tables keep only the profile's HPKE suites and
payload lengths, and config_id, enc and payload are drawn per hello. Real ECH and
TLS session resumption are not implemented.

Like uTLS (and Sing-Box X 1.0.3/1.0.4 and Xray 26.10.21 on the wire), every
hello draws five GREASE values -- cipher, group (supported_groups and the
key_share entry alike), the two extension ids (never equal) and version --
independently of one another. The Chrome table shuffles its extensions per
hello with uTLS's `ShuffleChromeTLSExtensions` procedure, GREASE fixed, and
lists them in uTLS's HelloChrome_133 order because that procedure's outcome
depends on the starting order. Firefox and Safari keep a fixed order.

Regenerate tables with `python3 tools/fingerprint_tables.py`, then `cargo fmt`.
