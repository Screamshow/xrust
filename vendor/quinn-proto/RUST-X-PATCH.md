# Padding every client Initial to the send size

Vendored quinn-proto 0.11.18 from the crates.io source already used by Xrust.
Original authorship and licenses are preserved. One behaviour is added, behind
a config flag that is off by default, so the library behaves exactly as it did
for anything that does not ask for it.

## The change

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

Grep for `xrust:` to find every line that differs from the published crate.

## Keeping it

When the version moves, re-vendor from the crates.io source and reapply the
three hunks: the config field, its setter and the `initial_padding` helper with
its two call sites. The library's own test suite must pass; it is not a
workspace member (its dev-dependencies are not ours), so run it from a copy
outside the tree:

    cp -a vendor/quinn-proto <somewhere outside the workspace>
    cd <that copy> && cargo test --features rustls-ring

303 tests and 3 doc-tests passed with this patch on 0.11.18.

A vendored crate no longer follows `cargo update`, so a security advisory
against quinn-proto now has to be ported here by hand: check it when
`cargo audit` reports one, and keep the version in `Cargo.toml` honest so the
advisory databases still match it.
