# Xrust protocol profile

Supported release platforms: OpenWrt x86_64 and aarch64_cortex-a53 only.
CI tests run on Linux; both release targets use static musl binaries.
Other platform code inherited from upstream is not a supported build target.

Firefox/Safari and Chrome for XHTTP now use our Sing-Box X 1.0.3 captures.
See [the uTLS refresh report](RUST-X-UTLS-2026-10-10.md).

Xrust does not ship Naive, VMess, Trojan, Shadowsocks, TUIC, AnyTLS,
Snell, ShadowTLS, FPTN, outbound SOCKS and OpenVPN. Config `check` rejects
these types. SOCKS4/4a client requests are rejected; SOCKS5 and HTTP mixed
inbounds remain available for Forkop DirectProxy.

VLESS/Vision, TLS/uTLS/REALITY, WebSocket, HTTPUpgrade, HTTP/2, gRPC, XHTTP,
Hysteria2, WireGuard/AmneziaWG, MASQUE, Tailscale, DNS, SRS, TProxy, Redirect,
TUN, direct, selectors/urltest and Clash API remain enabled.

Release build: `cargo build --locked -p core-cli --no-default-features --features rust-x --release --target x86_64-unknown-linux-musl`.
There is a single protocol profile: the default features build the same core
as the release command. `rust-x` stays as an alias of `full`, so packaging
scripts that pass `--no-default-features --features rust-x` keep working.
Profile tests: `cargo test -p core-config --test rust_x_profile`.

The removed protocols used to sit behind an optional `legacy-protocols` Cargo
feature; that feature and the modules only it compiled were deleted, and can
be recovered from git history if needed. Keep fork-specific fixes in focused
commits and port upstream changes without replacing our DNS, routing,
monitoring or OpenWrt behavior; upstream protocols outside this profile are
not imported.

Shared helpers under VMess/Shadowsocks/FPTN remain in the source because
retained protocols use them. Release LTO removes unreachable implementations.
OpenWrt APK/IPK packaging and installation checks are described in
[OpenWrt packages](OPENWRT-PACKAGES.md).

Forkop subscription testing and the native TLS read-side Vision Direct fix are
documented in [FORKOP-VM25-2026-10-10.md](FORKOP-VM25-2026-10-10.md).

## Verification, 2026-10-10

Both profiles built from upstream commit
`7084dedd161016f74a6068f4ebddefcc9cd5974b` plus these profile changes,
using Rust 1.99.0, locked dependencies and the same x86_64 musl release flags.

| Profile | Binary bytes | MiB |
| --- | ---: | ---: |
| Full, with legacy-protocols | 12,752,656 | 12.16 |
| Xrust default | 11,017,744 | 10.51 |

Reduction: 1,734,912 bytes (1.65 MiB), 13.6%. Binaries are not UPX-packed.
The installed UPX-packed Sing-Box X 1.0.3 binary on VM25 measured 9,972,284
bytes: this Xrust candidate is still 1,045,460 bytes (1.00 MiB, 10.5%) larger.
These are binary file lengths, not total package/dependency or RAM usage.

Xrust SHA-256:
`1acccb6d113c0fad4b09b2f693ceb94813d516f5f034e8de5f98337a9bf76166`.
Full comparison SHA-256:
`079c9946266e594ab2c749fefe6e7eb4fe97d805003f4e90ca2bfd49cb7735f8`.

Two config profile tests passed. Loopback runtime smoke passed HTTP through
SOCKS5 and HTTP mixed inbound, rejected SOCKS4, and rejected removed protocol
types at check time. Full-profile compilation passed as well.
Real VLESS/REALITY/XHTTP/Hysteria2 traffic and OpenWrt deployment were not
tested for this candidate. No OpenWrt VM or mirror changes were made.
