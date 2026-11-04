# Release sniffed TCP prefixes before the relay ends

Base: dev `95e76e8`. No package/version/default change.

## Change

Production SOCKS4, SOCKS5, HTTP CONNECT and generic TCP handlers now move
`ConnContext.sniff_prefix` into `pump_conn_tracked_owned` after route selection
and outbound setup. The userspace, Vision and Linux splice paths drop its
allocation after sending its bytes upstream. Clearing an `&[u8]` previously
only cleared a reference and left the owning Vec alive for the session.

The borrowed `pump_conn_tracked` API remains for callers that do not transfer
ownership; it copies into the owned implementation. Production handlers use
the owned API and do not add this copy. Plain VLESS still sends its request
head with the prefix, sends the prefix once and counts it once.

## Verification

- Linux: relay_splice 9, relay_tracking 4, connection_recovery 6 and the new
  sniff_prefix_lifetime test passed (20 tests). The last test observes actual
  deallocation while userspace and TCP splice sessions remain usable, verifies
  subsequent bytes and a response after upload EOF.
- The existing manual relay_memory benchmark was ignored by its normal test
  invocation; it is not counted as passed.
- Linux: 9 relay buffer/Vision tests and 15 hot-reload tests passed. Of 14
  reported inbound tests, 11 executed; redirect, TProxy and TUN returned early
  without CAP_NET_ADMIN/device support and are not counted as passed coverage.
- Total executed: 55 tests. One manual benchmark ignored, three privileged
  inbound scenarios skipped. `cargo clippy --locked --offline -p core-runtime
  --all-targets -- -D warnings` passed. Formatting and `git diff --check` passed.

## Isolated ARM allocation experiment

MT6000 aarch64, release profile, preserved target crypto flags, System allocator,
one current-thread Tokio runtime. Executable SHA-256:
`bcb8c2c3b1d1c8948c698bb04e31d9893c3a4bca5bd52702a7fc45e6f189ccfa`.

`examples/sniff_prefix_memory.rs` creates 80 duplex relays. The borrowed control
reproduces the former caller-owned prefix lifetime; the owned mode consumes it.
This compares two paths in the same probe binary, not complete old/new installed
cores. Each mode checks prefix contents, subsequent bytes and clean completion.
Three runs per mode and prefix size, ordered borrowed/owned/owned/borrowed/
borrowed/owned; all 12 runs completed all 80 connections.

| Prefix bytes per session | Borrowed live allocation delta | Owned delta | Difference |
| --- | ---: | ---: | ---: |
| 2048 | 860060 B | 696220 B | 163840 B (160 KiB) |
| 8192 | 1351580 B | 696220 B | 655360 B (640 KiB) |

Median process RSS was 1512 -> 1320 KiB and 2076 -> 1320 KiB respectively.
Live-allocation differences match exactly 80 times the prefix size. RSS also
includes allocator/page effects; this does not establish a whole-core percentage,
whole-router memory saving, WAN latency or throughput improvement. The probe
uses userspace relays; Linux splice lifetime is covered separately by the test.

Raw local evidence (not committed): Forkop `tmp/sniff-memory-arm-results.txt` and
`tmp/sniff-memory-router-{before,after}.txt`.

## Router restoration

Only `/tmp/sniff-memory-20261104/probe` was staged; no listeners, service/config/
firewall/package changes. The executable and directory were removed. Installed
package-list hash, Forkop UCI hash, service running state and both working
sing-box PID/executable hashes matched before/after. No working core was replaced.
