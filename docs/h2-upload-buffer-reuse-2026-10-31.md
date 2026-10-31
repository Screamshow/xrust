# H2 upload buffer reuse — 2026-10-31

Stream-one and gRPC reuse bounded upload storage rather than allocating a fresh
payload buffer for each write. Reuse is enabled by default;
`XRUST_H2_UPLOAD_POOL=0` restores the previous allocation path for diagnostics.
The existing legacy environment-prefix compatibility is retained.

`Bytes::from_owner` owns each buffer until its final H2 reference or slice is
dropped. Two process-wide pools retain at most eight idle buffers each: 8 KiB
and 48 KiB classes, up to 448 KiB of idle payload capacity. This does not cap
buffers owned by active streams. The borrowed payload still must be copied.
No unsafe code is added.

gRPC/Protobuf wire bytes, XHTTP write chunks, H2 SETTINGS/windows, TLS/REALITY
configuration, authentication and certificate verification are preserved.
Allocation changes may affect timing/coalescing; full DPI indistinguishability
is not established. Shared H2Io users also use this allocation path.

## ARM evidence

MT6000, one client worker on CPU 0, direct Ethernet to WSL Xray 26.10.21,
REALITY Chrome with PQ enabled, three rotated repeats. Baseline and pooled arms
used the same binary, changing only the pool environment flag. All 96 measured
transfers (four variants, two protocols, two directions, fixed 100 Mbit/s and
saturation) passed payload, final ACK and concurrent echo checks.

| Upload saturation median | Previous allocation | Reuse | Tachyon 0.2.7 |
|---|---:|---:|---:|
| stream-one Mbit/s | 437.2 | 567.7 | 629.5 |
| stream-one CPU s/GiB | 10.4 | 9.0 | 7.1 |
| stream-one peak RSS MiB | 6.70 | 6.71 | 8.29 |
| gRPC Mbit/s | 411.5 | 632.1 | 579.5 |
| gRPC CPU s/GiB | 12.0 | 7.2 | 7.9 |
| gRPC peak RSS MiB | 6.12 | 6.36 | 8.17 |

These results support a sustained-upload improvement, not universal parity.
Stream-one still trails Tachyon. gRPC throughput ranges overlap. At fixed
100 Mbit/s stream-one CPU/GiB rises from 18.72 to 20.80, while gRPC falls from
16.80 to 15.68, with overlapping ranges. gRPC download median falls from 652.6
to 612.3 Mbit/s, also with overlapping ranges and essentially unchanged CPU/GiB.
The working router had other connections; their contribution to variation is
not isolated. Longer randomized multi-connection ARM performance remains untested.

The separate core-runtime opt-level=3 experiment was rejected: executable size
grew 20.2% without a comparable consistent upload benefit. Cargo release profiles
and ARM crypto flags remain unchanged.

## Verification and scope

With pooling enabled by default and explicitly disabled, 11 gRPC, 9 H2 and
48 XHTTP tests pass in each run; one existing manual H2 test remains ignored.
Strict core-runtime rust-x Clippy, formatting and diff checks pass.
Focused tests cover gRPC encoding, H2 backpressure/half-close, XHTTP traffic,
buffer lifetime across cloned slices and concurrent pool reuse. Concurrent pool
ownership checks are not a multi-connection performance benchmark. The previous
ARM experiment also passed focused tests with reuse enabled and disabled.

Raw measurements and source/binary hashes are in the Forkop workspace at
`tmp/h2-stream-grpc-20261031`. The full benchmark report is
`docs/stream-one-grpc-buffer-study-2026-10-31.md` in that workspace. Its initial
decision describes the opt-in study; the subsequent user request authorized
default enablement in dev. This source change does not publish a release or
install a package on the working router.
