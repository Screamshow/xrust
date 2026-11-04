# REALITY browser key shares: operator-key regression (2026-11-04)

## Failure and isolation

On the operator GL-MT6000 (192.168.90.1), installed Rust X 0.0.34-r1
rejected an operator-supplied VLESS TCP/REALITY/Vision connection with
`the certificate carries no Ed25519 key`. UUID, SNI, public key, short ID,
flow and Firefox fingerprint matched the share link; the router clock matched UTC.
No credentials or full share link are retained in this report.

Independent Xray 26.7.28 passed an HTTPS request to example.com (HTTP 200),
both on Windows and in an isolated ARM process on the same router.
The installed Rust X failed with Firefox and Chrome using the default
REALITY options. With Firefox and explicit `support_x25519mlkem768: true`,
the same installed Rust X authenticated the REALITY certificate and passed
HTTP 200. Safari with the default hybrid-removal option also failed against this peer.
The remote server version and configuration are unknown. These observations
establish sensitivity to the offered hybrid group, not a universal server policy.

## Fix

In the existing dev checkout, absent `support_x25519mlkem768` now preserves
the selected browser's key shares instead of removing X25519MLKEM768.
Explicit false continues to request the compact classical profile; explicit true
preserves hybrid support only where the selected browser profile has it.
Certificate authentication, SNI, short ID, keys, ordinary TLS and browser
profiles are not weakened or replaced. No automatic retry/fingerprint change.
The default ClientHello can be larger, as in its original browser template.

The first-flight regression test covers Chrome, Firefox and Safari, each with
REALITY default/false/true and ordinary TLS. It checks emitted hybrid shares
and the retained compact-size bound for explicit false.

## Verification

- The first-flight test passed all 12 combinations. The 13 TLS client unit tests
  passed, including certificate verification and certificate/public-key pin checks.
- Locked/offline ARM musl release build passed. Candidate SHA-256:
  `596d7ee9f420f0b327fe1982db0e510b94006b2aa2967098d0efc75027ed8f73`.
- On the operator router, the candidate with the original REALITY parameters and
  no hybrid preference passed three HTTPS GET requests per Firefox/Chrome/Safari:
  9/9 HTTP 200 responses, 577 application bytes each, REALITY certificate accepted.
- Explicit false with Firefox reproduced the authentication failure 3/3 times.
- Installed executable/config hashes, package versions and service PIDs matched
  before/after. The isolated candidate and temporary configurations were removed.
  No package installation, service restart, firewall or persistent config changes.
- Evidence: operator workspace `tmp/reality-key-fix-20261104/` (build script,
  candidate, probe script/results, sanitized before/after invariants). Source was
  the existing dev checkout at ea0a01d plus this patch, with its existing 0.0.33
  version metadata; this is an unreleased diagnostic candidate, not a 0.0.34 package.

This checks one remote peer's TCP REALITY/Vision HTTPS traffic, not UDP,
universal server compatibility or full timing/DPI equivalence. The larger default
ClientHello restores the chosen profile but may span multiple TCP segments.

## Existing subscription comparison before release

All 61 concrete server outbounds in the operator's active configuration were
tested through isolated localhost SOCKS inbounds, first with installed 0.0.34,
then with the candidate. Both cores used identical per-node parameters.
HTTPS GET to example.com passed on all 58 previously working entries in both
cores (HTTP 200, 577 bytes). Two entries (indices 54 and 55) failed in both.
The newly supplied key (index 60) failed in baseline and passed in candidate.
This includes TCP, XHTTP, gRPC and WebSocket entries, with existing TLS/REALITY
and Firefox/Safari/Chrome settings. No credentials or full configs were archived.
The temporary core/configs were removed; the managed service was not restarted.
Evidence: `tmp/reality-key-fix-20261104/subscription-results.txt` and probe script.
This is a short HTTPS reachability comparison, not a throughput/UDP or long-lived
connection test. Existing established connections do not change unless the
operator later installs/restarts the core; new default REALITY handshakes do.
