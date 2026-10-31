# Xrust QUIC Chrome preset

Based on rustls 0.23.46 (crates.io checksum
48e13bd8c0e9365c43cfa5c9e8f9ad49d3c8444926c9aac819e0e4dc503c8fdf).
Original authorship and licenses are retained.

The optional `ClientConfig::quic_chrome_ech_grease` selects a QUIC-only
ClientHello preset before its bytes enter the TLS transcript. It adds fresh
GREASE ECH, H3 ALPS and the supported certificate-compression offer, orders
the signature schemes, removes TLS-1.2-only offers, and shuffles extensions.
Ordinary TLS and configs without this option keep rustls' original path.
Certificate/pin/Finished verification is not bypassed. The core-tls backend
supplies Brotli decompression and fresh GREASE per connection.

The QUIC preset retains independently generated classical and hybrid exchanges,
matching the Xray reference's two public shares. Either server selection completes
with its own retained private key. Other rustls configurations keep the original
shared-component optimization.
