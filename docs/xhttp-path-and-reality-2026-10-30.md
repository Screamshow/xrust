# XHTTP exact paths and full stream-one REALITY verification

Date: 2026-10-30. Development only; no release, package installation or changes
to the operator router's running core/configuration.

## Path correction

For a configured resource such as `/media.ts`, append a separator only when
either session or seq placement is `path`. If both are header/query/cookie,
preserve `/media.ts` exactly; preserve an explicit `/media.ts/` as well.
Use the same normalized base for legacy Referer padding and query-in-header
padding. Standard path-placement requests retain their existing targets.

This follows the placement-dependent normalization in
[Xray 26.7.28](https://github.com/XTLS/Xray-core/blob/v26.7.28/transport/internet/splithttp/config.go#L18),
also checked in 26.10.21. TLS/H2 settings, mode resolution, batching, pacing,
metadata keys, payload placement and streaming implementations are unchanged.
This narrowly corrects the trailing separator, not arbitrary URL rewriting.

Three focused test functions cover the non-path combinations, mixed placements,
explicit trailing slashes, legacy/obfuscated padding, streaming modes and
empty/relative/root resources. Before the correction two failed with an extra
slash; afterward all 54 XHTTP tests passed. Formatting, whitespace checks and
core-runtime lib/tests Clippy with `-D warnings` passed.

### ARM runtime checks

An authenticated temporary ARM client talked to an isolated TLS/H2 peer on
the operator computer. The peer checked exact resource paths and Referer URLs,
normalizing only the random session UUID; mismatches received 404. All 16
session/seq combinations from path/header/query/cookie were tested:

| Client | Accepted | Expected resource rejection |
|---|---:|---:|
| Previous Xrust client-fixes build | 7 | 9 |
| Path-corrected Xrust | 16 | 0 |
| Independent Xray 26.7.28 client | 16 | 0 |

The nine baseline rejections are expected negative controls, not successful
traffic tests. The controlled peer does not emulate a real CDN.

Separately, against the actual independent Xray server, corrected ARM Xrust
passed byte-exact 512 KiB echo for header/query/cookie placement in packet-up,
stream-up and stream-one over TLS/H2 (nine cases). Three explicit TLS/H1.1
packet-up cases also passed; negotiated H1.1 was verified in client logs.
No certificate-verification bypass was enabled.

Corrected ARM build SHA-256:
`accceb021f3d7aebbab2831f9c286f286af4d436fdbd8da0597c90305c1be609`.
Prior client-fixes ARM build:
`500e26667f8a33e31561659d5e9593da22d6b7fe701d725425cf1af08d2de113`.

## Full stream-one + REALITY, before the path-only correction

The prior client-fixes build above (source committed as `9e8d3a6`) was tested
on GL-MT6000 ARM against independent Xray 26.7.28, commit `5ca6f4b`. The peer
and a local TLS 1.3 decoy ran on the computer, keeping peer/load work off ARM.
The server accepted only stream-one; its normal REALITY authentication/version
checks were retained. No insecure client flag was used.

Four Xrust cases passed: explicit stream-one with Chrome, Firefox and Safari,
plus Chrome `auto`. Each passed 64-byte echo, 4 MiB upload with server SHA-256,
4 MiB download with client SHA-256, and simultaneous 4 MiB each direction on
one logical connection. Independent ARM Xray passed the same four operations
as a fixture control. Auto therefore interoperated with the stream-one-only
server, not merely a permissive packet-up listener.

Wrong short ID, wrong public key and wrong VLESS UUID were all rejected without
reaching the application sink. The negative clients were confirmed to have
started normally; these are authentication controls, not invalid-config exits.

The path-only correction leaves the tested default `/bench/` target unchanged.
These results establish the described TCP interoperability with this peer,
not UDP, latest post-quantum settings, arbitrary subscriptions/CDNs, identical
wire timing or universal camouflage. Stream-one performance code was not changed.

## Isolation and evidence

Tests used authenticated LAN listeners and a peer restricted to a local sink.
Windows Xray listened on loopback behind a byte-transparent Python TCP relay;
the relay did not terminate TLS/REALITY. Synthetic keys/credentials stayed in
temporary operator files. No firewall/package/service changes were required.
Test processes and router temporary directories were removed. Installed
package lists, working process PIDs and binary/UCI/runtime/firewall hashes
matched before/after both test phases.

Operator workspace evidence: `tmp/stream-one-reality-20261030/` (eight REALITY
cases, peer/client logs and router state) and `tmp/xhttp-path-20261030/`
(48 path controls, 12 traffic controls, build/check logs, source and router
state). These are scoped local interoperability tests, not full CI or release
validation.
