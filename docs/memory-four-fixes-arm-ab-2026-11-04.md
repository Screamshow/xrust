# Combined ARM comparison of four memory changes

Baseline source: `95e76e8`; candidate source: `3c38de0`. Both built as
core-cli release, aarch64-unknown-linux-musl, locked/offline dependencies,
no-default-features + rust-x, normal System allocator and preserved .cargo
crypto flags. Separate candidate target directory was used after a shared
Cargo target directory produced a stale cross-checkout dependency error.
No source fix was needed for that build-cache conflict.

Binary SHA-256:
- baseline: `6b81a9a636ba618d52195f737067befdc6272fb6c2712b02755d9c8c2c0ad896`
- candidate: `a98320b51f1cd94fd68c1ff9e5a10b97dd4a19c8735abab381c4aee429b3926f`

## Fixture and limits

Actual MT6000 client, one XRUST_WORKERS worker, taskset logical CPU 3. Synthetic
config, no private subscriptions: 112 Chrome TLS VLESS outbounds; 75 remote
SRS v2 lists, 1200 synthetic domain suffixes per list. Each complete list
generation is about 1.47 MB compressed; cache.db is 1552384 bytes. All 112
outbounds are constructed but traffic uses node0. This does not simulate 112
simultaneously active proxy endpoints.

Baseline/candidate order: B/C/C/B/B/C. Each traffic trial has cold startup,
idle, 80 held TCP sessions, byte-checked echo, closed-session recovery, 64 MiB
download/upload at saturation, 32 MiB download/upload paced at 50 Mbit/s,
recovery and restart from the resulting cache. Separate fresh processes
exercise two full 75-list replacements (A -> B -> A) every four seconds.

PC generator, sink/list server and independent Xray 26.7.28 TLS peer. Xray
executable SHA-256:
`1d9674327972a21afd4c906a7a72bb0856935aa9e0227c87f34f03d11a88bddf`.
Test certificate is the repository localhost fixture; CA verification remains
enabled. Xray's default private-target block caused fixture timeouts until
the test config explicitly allowed only TCP 127.0.0.1:29483. Those failed
preflight attempts are excluded from the final series.

Windows Firewall blocks inbound Node/Xray LAN connections. Attempted creation
of a narrow temporary rule failed with access denied; no rule was created.
Existing OpenWrt25 was reachable after checking VMware, but its host-only/NAT
networks have no direct ARM LAN route. No VM network/package/service changes
were made. The initial SSH timeout was not evidence that the VM was off;
vmrun list showed it running, and start was idempotent.

Final memory fixture uses SSH reverse forwarding to loopback-only ports 29484
and 29485 on the router for lists and the peer. Thus ARM memory measurements
are valid for this controlled topology, but saturation throughput, CPU and echo
latency are fixture-limited. They are functional controls, not authoritative
direct-LAN performance comparisons or WAN improvement claims. Extra SSH server
work is outside core process CPU/RSS and not whole-router resource accounting.

## Sampling

Router /proc status/stat sampled every ~200 ms; CPU converted at 100 ticks/s.
RSS/RssAnon are process measurements; kernel queues, page cache and other
router processes are excluded. HWM is cumulative within each test process;
sampled peaks can miss short spikes. Startup timing includes SSH/supervisor
setup and a 700 ms settle, so it is a comparison metric, not pure core startup.
Payload transfers validate SHA-256 and upload completion responses. Held
sessions verify prefix forwarding and subsequent echo. FDs recorded before and
after closing sessions. Three repeats and a LAN/tunnel fixture do not establish
universal memory gains, leaks absent over long periods, p99 latency or full
protocol compatibility. Gains from separate microbenchmarks are not added.

## Final results

All six traffic trials and six refresh trials completed, with three repetitions
per variant in the stated interleaved order. 24 hash-verified bulk transfers
completed, totaling 1207959552 bytes (1152 MiB). 480 held sessions verified
prefix delivery and subsequent echo. Twelve complete list-generation changes
covered 900 changed list downloads. All six warm restarts used the cache with
zero network list requests; each cold traffic start fetched all 75 lists.

Medians, KiB; RSS values are the final settled sample of the named phase:

| State | Baseline RSS | Candidate RSS | Difference |
| --- | ---: | ---: | ---: |
| Cold-start idle | 16152 | 15948 | -204 (-1.3%) |
| 80 held sessions | 18188 | 17536 | -652 (-3.6%) |
| After closing the 80 sessions | 16772 | 16512 | -260 |
| After all transfers/recovery | 17028 | 16764 | -264 |
| Warm-start idle | 16104 | 15948 | -156 |
| After second full list update | 17740 | 17332 | -408 |

With 80 held sessions, median RssAnon was 12456 -> 11736 KiB (-720).
Median cumulative HWM after the two refresh generations was 19348 -> 18080 KiB
(-1268, about 1.24 MiB or 6.6%). This is a whole test-core process comparison,
not a sum of prior allocation probes. A realistic smaller SRS cache and many
unchanged pre-existing structures limit the overall percentage improvement.

All trials had 170 FDs with 80 held sessions, then 10 after closure and after
final recovery. This proves closure/recovery for the checked short series;
it does not prove absence of a long-running leak. One baseline final refresh
RSS sample reached 18660 KiB versus 17728/17740 in its other runs; all raw
observations are retained rather than removed.

Cold readiness: median 2.228 -> 2.230 seconds; warm readiness 1.724 -> 1.726
seconds. These include fixture overhead, and establish no startup-speed gain.

## Traffic controls, not direct performance acceptance

All fixed-rate transfers sustained about 49.6 Mbit/s download and 49.8 Mbit/s
upload. Median core CPU seconds per 32 MiB were download 0.30 -> 0.30, upload
0.34 -> 0.33. In the tunnel-limited saturated controls, median download was
320.7 -> 324.8 Mbit/s, upload 419.0 -> 407.5 Mbit/s. Candidate upload ranged
378.6--429.5 Mbit/s; baseline 413.7--420.7. These overlapping/noisy results do
not establish a speed gain or a core regression. Echo p95 was mixed: fixed
download median 6.25 -> 11.87 ms, fixed upload 33.49 -> 33.86 ms. It is not
valid to claim improved latency from this series.

Refresh CPU also differed by phase: first generation 0.80 -> 0.88 s, second
1.54 -> 1.12 s. Scheduling and overlap of 75 timer-driven downloads mean these
are not isolated writer CPU benchmarks; no aggregate CPU gain is claimed.

Direct peer/generator CPU acceptance remains unverified because the Windows
LAN firewall rules could not be changed with the current process privileges.
The successful series is adequate for the reported controlled process-memory
comparison and traffic correctness, not a substitute for that direct fixture.

## Restoration

Owned supervisor/core/monitor processes terminated normally; SSH tunnels and
PC peer/list/sink processes were stopped. Router test logs were copied to the
local evidence directory, then the exact owned /tmp/memory-ab-20261104 tree
was removed. No test listener remained on the router. Package-list hash,
Forkop UCI hash, service running state and both working sing-box PID/executable
hashes exactly matched the pre-test capture. No working service restart, core
replacement or router firewall change was made. No Windows firewall rule was
created. Existing WSL and OpenWrt25 instances were left available; unrelated
processes were not stopped.

Raw local evidence (untracked, outside the core repository): Forkop
`tmp/memory-ab-20261104/` contains fixture generation, binaries/build script,
supervisor, benchmark driver, sample JSONL, events, request logs and summary.
The summary excludes all events before the final peers-ready record.
