# WG/AWG RX and independent-client follow-up — 2026-11-14

Completed local development and MT6000 verification; this is not a release
announcement. Working checkout: `tmp/xrust-independent-review`, existing `dev`,
base `cb67b21ae6043777f89a0d3c3d2a1aefe1f8c372`. The preceding adaptive TX
changes were already local and are preserved. Initial tracked diff and the
untracked TCP-window implementation are backed up in `tmp/awg-next-20261114`.

## Candidate

Receive storage begins at 128 KiB for every TCP connection. Before SYN the socket
configures a potential 2 MiB receive-storage limit to negotiate window scaling;
only actually backed credit is advertised. Receive activity can obtain a larger
ring from the existing independent RX allowance. The replacement temporarily
charges both allocations; the previous storage is freed before returning its
allowance. Failure leaves the old buffer intact. Capacity is not reduced until
the socket closes because an idle empty queue does not revoke advertised credit.

The vendored smoltcp API preserves queued bytes and out-of-order assembler spans,
including wrapped storage, along with ACK/sequence state, negotiated scaling,
previously advertised credit and TCP timers. Growth schedules a window update.
The runtime retries a denied growth after 250 ms through its existing wakeup.
TX policy, AWG wire encoder, authentication/replay, random padding/header masking,
crypto, MTU, allocator and target crypto flags are unchanged by this RX candidate.
Growth also works in FIN-WAIT1/2: closing the local write half does not stop a
remote response. A guard bounds the receive acceptance edge by actual backing
storage during the SYN-to-final-ACK transition, when the saved unscaled SYN field
must not become permission for unallocated memory under the prospective scale.
The configurable scale is capped at RFC 7323's maximum of 14.

The allowance bounds additional TCP ring storage, not total process RSS, live
relay queues, kernel memory or total router memory. A connection that has grown
RX retains its reserve through later idleness. This is a deliberate TCP-contract
constraint, not an adaptive RX reclamation claim.
Eight already-grown but unclosed receive connections on 64-bit targets (two on
32-bit) can still occupy the RX allowance and leave later bulk on 128 KiB; the
policy removes allocation by idle connects, not all lifetime fairness limits.

## Cold TX and memory investigation

A separate diagnostic build changes only fallible TX-buffer allocation from
reserve-and-zero-fill to the global allocator's zeroed-allocation API. It retains
the existing allocation-failure path. This diagnostic is kept separate from the
RX candidate until measurements justify adopting it. Raw paired results and minor
fault/RSS samples are in `tmp/awg-next-20261114/calloc-cold`.

This completed 42 batches, seven alternating repeats of three cases per variant.
The allocation-only build is **not adopted**. No-capture cold upload medians were
157.67 -> 157.72 Mbit/s (ranges 145.81–157.88 and 145.67–157.85); peak RSS was
10796 -> 10944 KiB. Held-eight/four-flow medians were 302.92 -> 303.05 Mbit/s and
18696 -> 18648 KiB. Idle/regrowth peak RSS fell 29380 -> 23568 KiB, while its
finite upload median fell 157.55 -> 146.12 Mbit/s. This is not a general speed or
memory win. Minor faults, peak RSS and allocator-retained pages are separate
observations; these results do not establish a leak.

The separate bounded inner-TCP diagnostic is not used for throughput claims.
An initial capture lost metadata and is retained with that limitation. The
improved run completed 21/21 batches; the initial file without kernel timestamps
is excluded from timing analysis, leaving 20 kernel-timestamped zero-drop traces.
Across all 20, each of the first four sender bursts ended exactly at the Linux
peer's advertised receive-credit edge. Slow completion also occurred with the
original eager 2 MiB TX baseline. The trace localizes these early waits to peer
receive credit; it does not prove why the Linux peer expands it earlier or later,
or that client timing has no influence. The earlier three-repeat 7.5% cold median
cost must not be treated as a demonstrated persistent allocator regression.

A causal control sets only the owned Linux listener's receive buffer: requested
2 MiB with SO_RCVBUFFORCE, actual SO_RCVBUF 4 MiB; accepted sockets inherit the
locked setting. Seven paired zero-drop traced repeats gave eager/adaptive medians
211.079/211.029 Mbit/s. A separate **no-capture** seven-pair confirmation gave
211.092/211.154 Mbit/s, ranges 210.839–211.291 and 211.075–211.394. The earlier
145/157 Mbit/s completion bands disappeared under this control. Thus peer-credit
growth materially affects the cold metric; this does not eliminate every startup
cost or prove a WAN result. The control compares original eager TX with the
previous adaptive TX, not automatically every later RX change. Its CPU difference
is one 0.01-second accounting tick per 16 MiB and is not a demonstrated 25% CPU
regression.

The inner TUN capture can contain coalesced TCP buffers. Its byte/sequence credit
analysis does not count physical outer packets, infer wire ACK ratios or prove
AWG camouflage. Those are separate from the bounded outer metadata controls.

## References and measurement limits

Latest published tachyon-core was checked through the GitHub release API:
[`v0.5.2`](https://github.com/Dushnilin/tachyon-core/releases/tag/v0.5.2),
published 2026-11-13 08:05:37 UTC. Published architecture-specific musl artifacts
are used as a product comparison; this does not isolate compiler/profile effects
from source changes. Official amneziawg-go v3.1.20260828, source
`b5928efb6ca19f0153958460c3d141f04abc5c2e`, is the independent client and peer;
the exact x86/ARM binary hashes are in each manifest.

Go-client measurements include its direct SOCKS relay and Go process together.
Linux TCP/queue memory is outside their process RSS, whereas the native client
holds its TCP rings in process memory. Process CPU/RSS therefore do not establish
total-system CPU/RAM or power savings. Finite transfers include TCP ramp-up and
completion ACK; they are not steady-state capacity measurements. Short concurrent
echo samples do not establish reliable p99. LAN/netem tests do not establish WAN,
DPI or full timing/camouflage equivalence.

## Local four-client comparison

`local-primary` completed all **120 batches**: ten cases, four clients, three
rotated repeats. It used symmetric owned-veth netem at about 70 ms RTT, the same
nonzero AWG profile and independent Go peer, one client CPU, 16 MiB aggregate
saturated transfers and 4 MiB fixed-5-Mbit/s controls. No packet capture ran in
this primary series. Payload, completion ACK, concurrent echo, encrypted volume,
fresh Go-client handshake and both client/peer socket-drop checks passed.

Medians in Mbit/s; this is x86 local evidence, not MT6000 evidence:

| Case, 70 ms | Prior adaptive TX | RX candidate | Tachyon 0.5.2 | Official Go + direct relay |
| --- | ---: | ---: | ---: | ---: |
| held0, one upload | 157.62 | 157.72 | 118.45 | 142.89 |
| held0, one download | 118.23 | 118.31 | 126.12 | 117.03 |
| held0, four uploads | 304.19 | 304.34 | 170.48 | 204.90 |
| held0, four downloads | 206.63 | 206.95 | 188.28 | 176.34 |
| held8, one upload | 157.50 | 145.98 | 50.05 | 133.45 |
| held8, one download | 12.21 | 125.64 | 48.74 | 141.11 |
| held8, four uploads | 304.60 | 268.28 | 135.35 | 202.03 |
| held8, four downloads | 44.22 | 206.44 | 135.34 | 173.54 |

The held8 download improvement is approximately 10.3x / 4.7x versus the previous
TX-only candidate. Its observed median peak process RSS is 9504 -> 11000 KiB for
one flow and 10764 -> 17608 KiB for four; Go+relay is 20268 / 24752 KiB. This is
faster active delivery with additional native RX storage, not a claim of reduced
RSS in every scenario. At fixed 5 Mbit/s download, candidate RSS is 9004 -> 10116
KiB and CPU/GiB is 12.8 for both; no equal-rate CPU saving is shown there.
Cold held0 upload RSS falls 10900 -> 9156 KiB; control sockets no longer allocate
large RX merely by connecting.

**Retained adverse result:** held8 upload medians fall about 7.3% / 11.9% in this
series. The earlier fixed-peer control compared eager TX with prior adaptive TX;
it does not automatically explain away this RX-candidate result. A separate
prior/RX fixed-peer control and ARM verification are required. Raw repeats,
ranges, CPU, echo and memory phases are retained in `local-primary` and its
`reference-summary.json`; saturation CPU/GiB at different rates is not an
equal-rate efficiency comparison.

A separate **prior versus initial-RX** control now also completed 18/18 batches
with the owned peer receive buffer fixed, without capture: held0 one upload
211.328 -> 211.181 Mbit/s; held8 one upload 211.193 -> 211.039; held8 four uploads
626.969 -> 624.061. All medians of three repeats, CPU/GiB 3.2 for both. The large
held8 TX penalty did not reproduce under fixed peer credit. This supports the
receive-window sensitivity of the default-peer whole-transfer comparison while
retaining its adverse medians; it is not a proof of universal TX equivalence.

The initial-RX candidate also completed 12 plain-WG batches and 12 randomized
loss-control batches. Plain-WG is a compatibility control, not an AWG reference
substitution. Loss was 0.05% independently on each owned outer veth half,
approximately 0.1% combined path loss; three stochastic repeats are not general
WAN evidence. All payload/ACK/echo/tunnel checks passed with zero measured socket
drops. Four fixed-rate outer captures against native and Go clients had zero
capture drops and multiple random transport prefixes/H4 in both clients; H1/H2
were observed for native. The Go client is configured before capture starts, so
this capture does not claim its handshake distribution or junk sequence.
This establishes presence of the checked synthetic obfuscation structure, not
equal timing, complete distributions, universal AWG 3.x options or DPI parity.

## Verification and restoration

The final candidate additionally uses fallible global-allocator zeroed allocation
for **RX only**, preserving `Vec` allocation/deallocation layout and initialized
bytes. TX remains unchanged. Three rotated memory-control repeats (nine batches
including Go) measured initial-RX/final-RX median peak RSS 42924/28416 KiB,
approximately 34% lower. Finite upload medians were 157.38/157.49 Mbit/s. These
are a separate series from the 120-batch initial-RX comparison above. After socket
closure the first pair recovered to approximately 9.9 MiB at one second; raw
RSS/anonymous/PSS/FD and +1/+12-second observations are retained. RX leases still
last until close, and allocator retention remains distinct from live rings.

The final helper passed independent ownership/layout/MSRV review and three focused
initialization, boundary and drop tests. The whole runtime initially failed the
unchanged large-loopback-UDP packet-bridge test in mirrored WSL, also in isolation.
After restoring NAT, the entire final runtime passed **830 tests, five ignored**,
without modifying that test or packet path. Strict Clippy also passed. Thus the
mirrored test failure is retained as an environment limitation, not silently
discarded or reported as a successful test.

Before the zeroed-allocation refinement, RX source passed 827 runtime library tests (five ignored), strict runtime
all-target Clippy, 438 vendored smoltcp library tests, and no-alloc+async checking.
The new runtime half-close case passed. One initial whole-runtime run failed the
unmodified Tailscale idle-STUN test; the complete retry passed without changing
that code. Release x86_64-musl and aarch64-musl builds passed. These focused checks
are not full platform CI.

Final performance and restoration results are recorded below. No release, remote
push or installed-package replacement is part of this work.

Final exact-binary follow-up completed 24 download batches, four fixed-rate AWG
outer-metadata batches and two plain-WG controls, all with successful completion
and cleanup. Final x86 SHA-256 is
`0d994cb1ffdca7aeda1e420ef03d952f55611d77705ef50d522bd72893b0594b`;
final ARM64 SHA-256 is
`18612631b70a29de4f7b2713a22ca14d4e3e07c4ba7a10dfe2482a2011e9f0fa`.
Both match the corresponding measured zeroed-RX binary byte for byte after
test-only additions. Source invariants were rechecked against the preceding
candidate; release profiles, crypto/allocator configuration and unchanged
AWG/crypto/TLS files match.

## MT6000 verification

The first staging attempt failed because Windows scp could not read the root-owned
WSL UNC temporary archive. No traffic measurements were made. Its cleanup record
confirms unchanged packages/production invariants and removal of owned resources.
The fixture now transfers the owned archive over SSH stdin with an exact allowed
remote target; this is an orchestration fix, not a core change.

The retried ARM smoke completed all eight 1 MiB checks across four clients and two
directions/held cases. It is script validation, not primary speed evidence. The
full ARM comparison completed **120/120 batches**, three rotated repeats of ten
cases and four clients, with all payload/ACK/echo/tunnel-volume and zero socket-drop
checks passing. Production baseline: rust-x 0.0.40-r1,
working PIDs 17309/18018, working binary SHA-256
`c6eab9addf14705ce8dd6cc702e87598f4756ba09f4145dd1c5d797cc9a508be`.

The native clients ran on logical CPU 0 with one worker. Go and its direct SOCKS
relay shared that same CPU; their process CPU and RSS are summed. Peer Go ran on
WSL CPUs 2–5 and generator on CPU 6. WSL was directly reachable in mirrored mode;
no application UDP forwarder participated. The owned peer TUN egress received
0/70 ms netem: an asymmetric addition of about one delay per TCP round trip,
not the symmetric outer-veth local fixture and not a general WAN model. MTU 1380
and the synthetic nonzero AWG J/S/H profile were unchanged. Existing production
router traffic remained running; these are controlled one-client-CPU process
measurements, not unrestricted multicore, total-router memory/CPU or power tests.

ARM whole-transfer rate medians (observed min–max), Mbit/s:

| Case | Prior adaptive TX | Final Xrust | Tachyon 0.5.2 | Official Go + relay |
| --- | ---: | ---: | ---: | ---: |
| 70 ms, held0 upload | 147.72 (146.10–150.49) | 144.79 (143.91–146.44) | 104.50 (14.05–109.79) | 122.50 (121.80–124.45) |
| 70 ms, held0 download | 118.21 (115.53–118.79) | 115.12 (112.37–116.23) | 115.22 (112.42–116.28) | 109.85 (105.62–117.88) |
| 70 ms, held8 upload | 140.86 (138.32–145.22) | 143.39 (141.32–148.07) | 49.04 (48.27–49.13) | 124.13 (122.46–124.83) |
| 70 ms, held8 download | 12.74 (12.52–12.94) | 117.49 (115.26–118.39) | 47.50 (46.68–47.69) | 110.97 (108.12–114.50) |
| LAN, held0 upload | 212.07 (207.73–222.14) | 218.39 (208.26–219.87) | 275.76 (257.81–277.35) | 253.64 (251.03–254.77) |
| LAN, held0 download | 270.96 (266.86–271.06) | 278.03 (258.98–279.28) | 350.68 (289.43–365.76) | 242.37 (235.19–251.93) |

The requested held8 RX improvement reproduces on MT6000: **9.22x versus prior,
2.47x versus latest Tachyon, 5.9% above Go** in this particular series. Its CPU/GiB
is 39.04 -> 24.96 versus prior at different saturation rates; equal-rate controls
below are the appropriate efficiency comparison. Advertised-window evidence also
supports the localization: sampled sender `rwnd_limited` maxima were 96.3–97.3%
for prior and 32.6–41.7% for final in the three held8 downloads. The final sockets
negotiate scale 6; Go/kernel TCP uses scale 7 here. These are interoperable TCP
contracts, not identical internal TCP fingerprints or outer-timing parity.

Observed process resource medians; RSS is sampled current load RSS, KiB:

| Case | CPU s/GiB prior / final / Tachyon / Go+relay | Load RSS prior / final / Tachyon / Go+relay |
| --- | ---: | ---: |
| 70 ms held8 download | 39.04 / 24.96 / 25.60 / 33.92 | 6328 / 9288 / 9456 / 30796 |
| 70 ms held8 upload | 32.00 / 32.00 / 40.32 / 32.64 | 8528 / 8464 / 9468 / 26724 |
| 70 ms fixed5 download | 46.08 / 48.64 / 56.32 / 97.28 | 6188 / 8100 / 8992 / 10820 |
| 70 ms fixed5 upload | 53.76 / 53.76 / 66.56 / 102.40 | 7992 / 7988 / 9040 / 10604 |
| LAN fixed50 download | 32.64 / 33.92 / 33.92 / 62.08 | 7680 / 7688 / 10092 / 11968 |
| LAN fixed50 upload | 39.68 / 42.24 / 39.68 / 56.32 | 7684 / 7748 / 8360 / 10740 |

The faster held8 download requires about 2.9 MiB more native resident memory than
prior. Final process RSS is lower than Go+relay in these cases, but Linux TCP and
queues reside outside Go process RSS; **no total-router RAM advantage is claimed**.
In the three final held8 downloads, 2-second post-close RSS had median 5696 KiB,
compared with prior 5660 KiB. This is recovery of these finite sessions, not an
arbitrary-duration leak proof.

**Remaining tradeoffs:** cold 70-ms upload/download medians are about 2.0%/2.6%
below prior; LAN results overlap or vary; Tachyon remains materially faster in LAN
saturation and uses less process CPU there. Fixed50 CPU medians are 6.5% higher
for final upload and 3.9% higher for final download versus prior, with short-run
counter precision and three-repeat limits. Thus this is not an across-the-board
speed/CPU win. Sampled LAN saturated-download echo median rises from 10.61 to
24.28 ms; these short samples do not establish p99. The slow 14.05-Mbit/s Tachyon
cold-upload repeat remains in its range; its cause is not localized or dismissed.

The first postprocessor failed on two RSS-less samples emitted while Tachyon
processes were terminating, 2.84/2.89 seconds **after** their measured intervals.
Raw records are retained and marked separately; every batch has complete load
memory samples, with no boundary-only fallback. Corrected postprocessing verifies
all 120 rows and cleanup; it does not alter traffic measurements or drop a repeat.

All router package, production binary/config/firewall hashes, working PIDs and
service state match the baseline. The test directory, Go TUN, destination rule,
route table, peer interface and runtime files were removed. WSL NAT and absent
original `.wslconfig` were restored, the narrow Hyper-V rule removed and the same
five container IDs verified. Raw ARM rows, named TCP traces, sampled memory,
summaries and restoration are in `tmp/awg-next-20261114/arm/primary-final`.

Final source is still local on existing `dev`, HEAD
`cb67b21ae6043777f89a0d3c3d2a1aefe1f8c372`; at the end of verification no commit, push, release or package
installation was performed. `final-source-audit.json` confirms 65 unchanged
crypto/TLS/AWG/storage/config files and equal release profiles. A source archive
and tracked patch are retained alongside the initial backups. The exact measured
binary/source checks are in `final-checks.json` and `final-local-complete.json`.

The long execution pause interrupted the first plain-WG control after one batch.
It is excluded and marked `interrupted.json`. Normal WSL shutdown hung during an
expired pre-start helper's restoration; restarting WslService and a subsequent
normal shutdown/boot recovered it. No HCS VM was forcibly terminated: the guarded
VM-reset attempt refused an outdated VM identity. NAT, the same five container
IDs and absence of owned namespaces/processes were verified before fresh controls.
The operator router had not been mutated at that point.
