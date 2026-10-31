# Vision Direct: fragmented inner TLS records — 2026-10-31

Local implementation on existing Xrust dev, base bf78cc7363b24cf023ee250c0e9e8a8f497e441a. No release, push, main integration or working router installation performed.

## Confirmed cause and fix

The old Vision writer called frame_take before next_command and checked whether only that frame contained a complete TLS application record. A normal 16 KiB inner TLS record is split into smaller Vision frames, so none can pass the old completeness check. Subsequent chunks begin in a record body, and the upload may remain padded/outer-encrypted instead of entering Direct. A deterministic regression test failed on the old implementation (Continue instead of Direct).

WriteRecords now retains a five-byte header plus remaining byte count across writes and frame boundaries. It handles handshake, CCS and application records, including fragmented headers; invalid types/versions/lengths permanently disable this detection. It stops a frame at the first complete application record boundary, preserving the beginning of the next record. Direct still requires an eligible inner TLS 1.3 ServerHello or the already accepted peer Direct state, plus raw-capable outer TLS. The last padded frame must finish through the TLS writer before raw writes begin. No application body is buffered by this detector. Existing frame size and padding bounds remain.

This is a correction to when Vision stops outer encryption, not permission to weaken REALITY authentication or ordinary TLS verification. It changes transition timing for previously mishandled segmentation. Full DPI/timing equivalence has not been established.

## Focused verification

- Old-source regression test fails on a 16 KiB inner record split by frame_take.
- 22 outbound Vision tests pass: record/header fragmentation, CCS, malformed lengths, bounded framing, partial writes, transient padding and buffered tails.
- 6 relay tests pass through actual outer TLS, including large inner application record with 3-byte, 8192-byte and whole-flight fragmentation, byte-exact full duplex, counter totals, half-close, extra data after Direct, API close and TLS 1.2 fallback.
- 6 REALITY authentication tests pass, including wrong key/short ID and all browser profiles.
- Strict core-runtime Clippy with rust-x and git diff --check pass.
- ARM candidate built using unchanged release profile and .cargo/config.toml ARM acceleration flags.

## ARM comparison

Same MT6000, client worker=1 pinned to CPU 0, direct WSL peer Xray 26.10.21, actual inner TLS with certificate verification, REALITY PQ explicitly true on all three clients. Generator/peer remain outside router on separate CPU affinities. Actual Ethernet link is 1 Gbit/s. Old source bf78cc7 exact ARM artifact from previous comparison versus local candidate versus verified official Tachyon v0.2.7. Three repeats, rotated order. Each run warms up, then 64 MiB each direction at 100 Mbit/s and 128 MiB each direction without cap, with concurrent echo and full payload/completion ACK validation. 36 measured transfers passed, no echo failures, no client socket drops. Raw evidence: Forkop tmp/vision-direct-20261031.

Medians at saturation; CPU is process CPU seconds per GiB, RSS is sampled process peak (excludes kernel queues and whole-router memory):

| Client | Upload Mbit/s | Download Mbit/s | Upload CPU s/GiB | Download CPU s/GiB | Peak RSS MiB up/down |
|---|---:|---:|---:|---:|---:|
| Xrust baseline | 393.1 | 898.3 | 15.4 | 2.2 | 5.78 / 5.78 |
| Xrust candidate | 858.1 | 872.5 | 2.8 | 2.0 | 5.61 / 5.61 |
| Tachyon 0.2.7 | 852.5 | 860.1 | 2.8 | 4.6 | 6.98 / 6.99 |

Upload candidate/baseline: 2.18x speed, about 82% less process CPU per GiB at saturation. This is not an 82% whole-router CPU or power reduction. Upload ranges: baseline 367.4–424.4, candidate 821.5–879.8, Tachyon 834.5–919.6 Mbit/s.

Download ranges overlap strongly: baseline 648.8–918.3, candidate 824.3–893.2, Tachyon 565.6–925.3 Mbit/s. No repeatable download speed improvement is established; the previous comparison's lower baseline download median was not reproduced in this series. Do not advertise a download multiplier.

At actual 100 Mbit/s, median CPU s/GiB up/down: baseline 6.2/5.9, candidate 5.9/5.9, Tachyon 7.2/7.2. Fixed-rate CPU has considerable session variation; saturation result must not be generalized to low load. Peer max average CPU 57.6% (one core=100%, four allocated); generator max 68.9% of its core. Rates near 900 Mbit/s are also bounded by gigabit LAN; three local repetitions do not establish WAN gains or latency SLA.

## Restoration and artifacts

Router package list, working binary/config hashes and working process identity match baseline. Working private configuration stayed only on router; collected evidence excludes it. Test processes and exact temporary router directory removed. WSL peer removed; narrow TCP firewall rule removed; original absent .wslconfig and NAT restored; five container identities verified. See restoration JSON files in the fixture directory for actual results.

Candidate source: crates/core-runtime/src/outbound/vision.rs and crates/core-runtime/src/inbound/relay/vision_tests.rs. Diff/binary hashes, configuration and scripts: manifest.json; raw transfers: results.json; medians/ranges: summary.json; logs: repro.log, check.log, build.log, run.log. Candidate remains local for review; no all-platform CI or release claim.
