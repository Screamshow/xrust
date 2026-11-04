# Optional BitTorrent classification, stage 1

Changes are local on existing Xrust `dev`, based on `7702796`. No release,
router installation, Forkop setting or Sing-Box implementation is changed.

## Configuration contract

The new explicit sniff name is `bittorrent-extended`. Recognized connections
still receive the existing protocol name `bittorrent`. The sing-box-compatible
version output advertises `sniff.bittorrent-extended` for future Forkop capability
detection. Forkop must require this feature AND the Xrust core identity before
enabling the setting. Required disabled label: `Доступно только для Xrust`.

For future integration, replace the normal sniff action's default list with
`bittorrent-extended,tls,http,dns,quic,stun,dtls,ssh,rdp,ntp` while enabled,
then insert `protocol: bittorrent -> direct-out` before user proxy/VPN sections.
Do not add a second sniff after an ordinary sniff has already classified HTTP.
HTTP classification is extended even if `http` appears first in the same list.
Without the explicit name, the existing default behavior is preserved.

## Detection

- Existing cleartext TCP handshake and UDP tracker connect signatures.
- Extended uTP recognizes SYN v1, zero timestamp difference, complete bounded
  extension chains (selective ACK and extension bits), and no trailing payload.
  Legacy default uTP classification is preserved. The stricter optional mode
  intentionally does not infer BitTorrent from a standalone uTP DATA packet.
- DHT validates complete bencoding, transaction and message type, 20-byte node ID,
  known query name and required target/info_hash fields. Responses require ID.
  Error-only messages do not establish a BitTorrent classification.
- HTTP tracker GET requires nonempty info_hash, peer_id and port parameters.
  Known torrent User-Agent names must match a token boundary. Generic downloader
  aria2, magnet text, arbitrary /announce paths and an isolated info_hash do not
  suffice. Existing Host/domain extraction and payload replay remain intact.

DHT inspection has fixed stack storage, maximum 4096 bytes, 256 parsed items,
8 nesting levels and 32 dictionary fields. These bounds limit inspection only;
they do not truncate or drop forwarded data. Larger or unusual DHT messages can
remain unclassified. HTTP reuses the existing header parsing/timeout behavior;
no separate payload buffer or peer cache is added. No new timer is introduced.

## Verification scope

Executed locally in Ubuntu WSL: 4 classifier unit tests, 3 Router integration
tests and 9 existing UDP sniff tests passed (16 total). `cargo clippy -p
core-runtime --lib --no-default-features --features rust-x -- -D warnings`
passed; formatting and `git diff --check` passed. No platform CI was run.

Focused tests cover complete/truncated DHT, common queries, malformed messages,
duplicate top-level keys, deep/large structures, uTP extension bounds, HTTP near
misses, split TCP reads, byte preservation, IPv4/IPv6 route decisions and optional
enablement. Existing UDP sniff controls cover DNS/QUIC/STUN/WireGuard behavior.
Routing tests exercise the Router with in-memory TCP streams/datagrams; they do
not yet establish real torrent-client interoperability or end-to-end forwarding.

Pending after this increment: Forkop checkbox/backend/signature integration,
generated UI/localization checks, VM lifecycle/direct traffic tests and ARM
CPU/RSS A/B measurement. No claim of MSE/PE, HTTPS payload detection, complete
torrent-application coverage or measured ARM resource cost is made.

UwuRay was inspected for protocol behavior, not copied into this GPL-3.0-only
project. Its firewall DROP layer is not part of this implementation.
