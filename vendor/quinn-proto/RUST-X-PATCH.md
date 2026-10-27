# Xrust patches: Initial padding and explicit pacing

Vendored quinn-proto 0.11.18 from the crates.io source already used by Xrust.
Original authorship and licenses are preserved. Two changes are added, both
inert unless something asks for them: a config flag that is off by default,
and two controller hooks whose defaults keep the published behaviour.

## Change 1: padding every client Initial to the send size

`TransportConfig::pad_initial_to_mtu(bool)` (`src/config/transport.rs`) and
`Connection::initial_padding` (`src/connection/mod.rs`). With the flag on, a
datagram this side sends as a client carrying an Initial packet is padded to
the current send size instead of `MIN_INITIAL_SIZE`, RFC 9000's 1200-byte
minimum. The server side keeps the minimum either way, and so does a datagram
with no room for the larger padding.

Why: a quic-go client pads every Initial it sends to the size it is sending.
A client hello with a post-quantum key share spans two Initial datagrams, so
the reference leaves two datagrams of the same length on the wire where this
library left a full one and a minimum-sized one — a length pair visible on
every connection, since an Initial packet is protected with keys derived from
the connection id in its own header. Xrust is a client, and the sizes it sends
are part of what it imitates.

## Change 2: an explicit pacing rate and a per-packet loss signal

`Controller::pacing_rate_bytes` and `Controller::on_packet_lost`
(`src/congestion.rs`), `Pacer::delay_at_rate` (`src/connection/pacing.rs`) and
the two call sites in `src/connection/mod.rs`. Both trait methods have
defaults -- `None` and a no-op -- so a controller that ignores them behaves
exactly as before, and `delay_at_rate` falls back to `delay` when the rate is
`None`.

Why: a bandwidth controller paces at a rate it is told, not at cwnd/RTT, and
it counts losses per packet rather than per ACK batch. That is what hysteria's
Brutal needs (`crates/core-runtime/src/outbound/quic/brutal.rs`), and
hysteria2 is the protocol where the client is given the link rate and is
expected to send at it. These two hunks and the pacer's tests come from
tachyon-core, GPL-3.0-only, with its authorship preserved.

Grep for `xrust:` to find every line that differs from the published crate.

## Keeping it

When the version moves, re-vendor from the crates.io source and reapply both
changes: the config field, its setter and the `initial_padding` helper with its
two call sites, then the two trait methods, `delay_at_rate` with its tests and
the two call sites in the connection. The library's own test suite must pass; it is not a
workspace member (its dev-dependencies are not ours), so run it from a copy
outside the tree:

    cp -a vendor/quinn-proto <somewhere outside the workspace>
    cd <that copy> && cargo test --features rustls-ring

309 tests and 3 doc-tests passed with these patches on 0.11.18.

A vendored crate no longer follows `cargo update`, so a security advisory
against quinn-proto now has to be ported here by hand: check it when
`cargo audit` reports one, and keep the version in `Cargo.toml` honest so the
advisory databases still match it.
