# Transport performance investigation, 2026-10-23

Scope: Xrust's HTTP/2, XHTTP, gRPC, H2MUX, VLESS TLS/REALITY/Vision,
WebSocket and WireGuard/AmneziaWG. This continues `transport-review-2026-10-23.md`.
No router/server deployment, release, version change or core switch is included.

## Confirmed problems and implementation

1. **Padded H2MUX interoperability.** The client announced protocol version 0
   while sending version 1 padding metadata. It also wrapped individual streams
   instead of the session carrying the H2 preface. Independent sing-box rejected
   it even though the earlier self-to-self PadStream tests passed. Use version 1
   and wrap the session, preserve version 0 for unpadded connections. The inbound
   now reads the versioned handshake explicitly and supports both versions.
   Added independent client and server checks for both padding settings.
   Protocol references: [sing-mux protocol](https://github.com/SagerNet/sing-mux/blob/main/protocol.go),
   [session setup](https://github.com/SagerNet/sing-mux/blob/main/client.go).
2. **H2 send-credit stall.** poll_capacity reports changes; it is not a readiness
   query for already assigned capacity. Spend available capacity before polling
   for more. A focused test consumes the capacity notification first, then writes
   without another WINDOW_UPDATE.
3. **XHTTP flush notification race.** The upload worker could finish/fail between
   checking counters and registering the waiter. Recheck completion and failure
   after polling the waiter. A deterministic regression models completion in
   exactly that gap, with no later notification.
4. **XHTTP packet-up batching.** The worker used to stop reading while waiting
   for the configured minimum POST interval (default 30 ms). It now collects
   caller bytes during that existing wait, up to the configured POST-size limit.
   The first POST remains immediate. The interval, sequence order, size limit,
   explicit modes and no-ambiguous-POST-replay policy are preserved. A 1 KiB pipe
   test verifies a 48 KiB burst is combined into the next POST without loss.
5. **WireGuard/AWG receive allocation churn.** smoltcp RX tokens dropped their
   decrypted packet allocation after consumption. RX and TX now return/reuse
   buffers through the same 64-entry pool. RefCell is confined to the synchronous
   single-owner virtual device; RX/TX tokens can coexist without unsafe aliases.
   A test checks pointer reuse by a response TX token and the pool bound.
6. **WireGuard/AWG upload queue overflow.** The caller pump kept reading after
   the virtual TCP send buffer filled, up to the 1 MiB overflow guard, which then
   removed the connection. Each chunk now waits for acknowledgment that its bytes
   entered the smoltcp send buffer. This applies backpressure before overflow.
   EOF no longer clears queued bytes. The interop test now transfers and verifies
   2 MiB concurrently in both directions.
7. **WireGuard/AWG scheduling latency.** Limit UDP/command drain batches to 64,
   deliver TCP data immediately after polling smoltcp, and disable Nagle on the
   virtual TCP sockets. The queue limit prevents a continuous producer from
   starving TCP polling and the opposite traffic direction.

TLS cryptography, REALITY authentication, Vision Direct transition rules and
WebSocket framing/masking are unchanged. Their relevant paths are measured as
controls; no unmeasured crypto or WebSocket speedup is claimed.

## Reproducible setup

The active checkout includes unrelated unfinished server REALITY/Xray changes
and does not compile as a whole. Verification uses the existing clean main
archive (`691f00a`) in the parent workspace's `tmp/transport-review-source`, with
the previous transport fixes plus only this investigation's changes. Original
uncommitted server work is preserved. No tests on that combined unfinished tree
are claimed.

Local WSL2 Linux 6.18.33.2, Ryzen 9 9950X3D, x86_64-unknown-linux-musl release
profile, generic x86 baseline and mimalloc. One client worker pinned to CPU 0,
reference servers to CPUs 2/4/6/8, load/receivers to CPUs 10-31. SMT siblings of
the client and server physical cores are excluded from the load. Before/after binaries
use the same target, profile and allocator. Baseline includes the fixes from the
preceding review; candidate adds the changes above. These are loopback x86
measurements, not ARM router or WAN benchmarks.

Independent peers: sing-box 1.14.2-lx.11 and Xray 26.9.8. The older standard
sing-box 1.14.1-extended-2.7.2 fixture has no AWG fields; it cannot validate AWG.
The existing broad bench had placeholder WG keys and download-only/p50 metrics.
New `scripts/bench/bench_transport_ab.py` reuses its protocol fixtures but uses
real synthetic WG keys, proper endpoint configs, receiver-confirmed upload
counts, p50/p99, CPU/GiB, RSS, 32 held sessions and recovery samples. Order
alternates between repeats. Binary SHA-256 and affinity are in every result JSON.

Xray's default freedom outbound blocks private destinations. That initially
made both our client and the independent Xray client hang. The isolated test
server now permits only the local receiver's IP and test ports via finalRules;
no external server or host firewall was modified. That initial failure was a
fixture problem, not evidence of another XHTTP defect.

Plain synthetic payloads do not exercise Vision Direct. Separate `--inner-tls`
runs use actual TLS 1.3 payloads with the generated fixture CA. Those runs measure
download/latency only; they avoid concurrent Python SSL read/write in the upload
generator. They do not prove every real-subscription/REALITY/PQ combination.

The raw data and validation logs are kept in the parent workspace under
`artifacts/transport-perf-20261023/` and `tmp/transport-perf-*.log`.

## Measurements

Use only `paired-final.json`, `controls.json` and `inner-tls.json` for the final
results. Earlier smoke/diagnostic files are exploratory. The first paired run
was discarded after finding that worker-join timeouts had entered the transfer
denominator. The final harness samples bytes/CPU/time before stopping workers.

The primary series uses three A/B repetitions per protocol, two seconds per
direction/stream-count phase, 150 checked 64-byte echo samples after warmup.
Values below are medians across repetitions, not sums across protocols.

| XHTTP packet-up metric | Baseline | Candidate |
|---|---:|---:|
| Upload, 1 stream | 0.033 Gbps | 0.256 Gbps |
| Upload, 8 streams | 0.264 Gbps | 2.048 Gbps |
| Download, 1 stream | 1.626 Gbps | 1.619 Gbps |
| Download, 8 streams | 3.135 Gbps | 3.202 Gbps |
| Echo p50 | 30.882 ms | 30.862 ms |
| Echo p99 | 32.089 ms | 32.060 ms |
| Upload CPU, 8 streams | 2.438 s/GiB | 1.489 s/GiB |
| Peak client RSS | 95.285 MiB | 96.617 MiB |

XHTTP upload improves about 7.8x in this setup, with about 39% less client CPU
per GiB. It does not remove the latency floor from the configured 30 ms POST
interval. Peak RSS is about 1.3 MiB higher in this load; this is a throughput
improvement, not a whole-process memory reduction claim.

H2/gRPC/unpadded H2MUX do not show a consistent bulk-throughput gain. Keep the
send-credit fix for correctness, and the padded-session fix for interoperability.
For example gRPC upload at 8 streams is 4.383 -> 4.399 Gbps, download at 8 streams
8.598 -> 8.648 Gbps. Those differences are too small to attribute to optimization.

| WG/AWG metric | WG baseline | WG candidate | AWG baseline | AWG candidate |
|---|---:|---:|---:|---:|
| Completed repetitions | 3/3 | 3/3 | 2/3 | 3/3 |
| Echo p50 | 11.729 ms | 0.446 ms | 11.731 ms | 0.454 ms |
| Echo p99 | 12.007 ms | 0.576 ms | 11.998 ms | 0.540 ms |
| Download, 1 stream | 1.527 Gbps | 1.520 Gbps | 1.512 Gbps | 1.525 Gbps |
| Download, 8 streams | 1.561 Gbps | 1.556 Gbps | 1.562 Gbps | 1.597 Gbps |
| Upload, 1 stream | stalled, <0.001 Gbps | 1.365 Gbps | stalled, ~0.001 Gbps | 1.363 Gbps |
| Upload, 8 streams | 0.038 Gbps | 1.227 Gbps | 0.038 Gbps | 1.226 Gbps |
| Peak client RSS | 17.324 MiB | 10.270 MiB | 17.646 MiB | 10.488 MiB |

AWG baseline repetition 0 failed a transfer; it was retained as a failure, not
silently discarded. Its numerical medians use the two completed runs. Every
candidate run in the primary/control/inner-TLS series completed. The point is
recovering a broken upload path and reducing scheduling delay, not claiming a
speed multiplier against a healthy WireGuard baseline. Download speed is
essentially unchanged. AWG here uses the synthetic junk/padding/header preset
from the script; this does not establish every AWG 3.x obfuscation mode.

TLS/REALITY/WebSocket controls passed. Their single-repetition throughput
differences are not evidence of improved cryptography or masking. Actual inner
TLS 1.3 payloads also passed for both TLS+Vision and REALITY+Vision. Inner-TLS
multi-stream throughput is constrained by this Python SSL workload and is not
used to rank the cores or claim a new Direct optimization.

## Validation

- Outbound unit suite: 550 passed, 6 existing ignored, 264 filtered.
- Independent `transports_interop`, `mux`, `wireguard_interop`: passed. The
  transport suite now checks both H2MUX roles with/without padding; WireGuard
  verifies the complete 2 MiB payload rather than only a short echo.
- core-runtime Clippy with lib/tests and `-D warnings`: passed.
- Workspace no-default-features `rust-x` check: passed, with the existing 14
  reduced-profile dead-code warnings.
- Changed Rust sources were formatted; Git whitespace checks passed.

All Rust checks above refer to the isolated main snapshot plus this patch set,
not the unrelated unfinished server changes in the active checkout. Final logs:
`transport-perf-verified-{unit,interop,clippy,profile}.log` in the parent `tmp/`.
