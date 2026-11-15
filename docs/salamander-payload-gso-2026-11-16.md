# Salamander payload GSO

The direct Linux/IPv4/fixed-port Salamander HY2 socket now accepts GSO segments.
Every resulting wire datagram retains its own fresh8-byte salt and unchanged
BLAKE2b(password||salt)+XOR format, including the final short segment. The receive
path, queues, QUIC windows, congestion controller and network timers are unchanged.
Plain HY2, Gecko, port hopping and other QUIC callers retain their previous policy.

Only that direct Salamander endpoint enables a new default-false Quinn transport
option: payload-only GSO. STREAM/DATAGRAM Data transmits can batch; control-only
Data transmits end after their first datagram. Initial/Handshake behavior and the
existing20-datagram transmit budget/effective10-segment cap are retained. No
instrumentation, receive-cap experiment or runtime diagnostic selector is shipped.

Verification passed full ARM workspace release, all-target check and Clippy,
HY2 eleven tests, two Salamander tests (real Linux GSO, independent formula,
boundaries/fallback/invalid descriptors), and three actual Quinn-proto peer tests
for STREAM/DATAGRAM/control behavior. Eighteen ARM wire controls against independent
Xray were independently re-decoded with zero observer loss: fixed parameters,
ALPNh3, public Initial authentication, salt and datagram/GRO bounds passed.
Random extension/TP orders remain in raw evidence. The old third-Initial PN2 vs
Xray PN1/padding difference remains; short-header framing/timing equivalence is
not claimed. Application UDP forwarding was not measured by these TCP workloads.

Final clean production versus dev e0cdb926, MT6000 all four CPUs/workers,24 warm
windows with three rotated repeats: saturated upload median243.78→338.18Mbps,
CPU40.88→28.20s/GiB, RSS15824→15892KiB. Upload speed improves in every pair
(+38.19..+47.44%); CPU/GiB falls about31%. This is a saturated upload result,
not a31% saving at fixed100Mbps or in total-router CPU/watts.

Latency tradeoff: upload echo-p95 medians3.60→5.16ms and max medians9.63→17.50ms,
with overlapping p95 ranges. Download speed pairs are mixed
(+25.76/−22.41/+17.85%); download CPU/GiB rises1.17–2.17% and p95 rises
0.109–2.427ms. No established download or latency fix is claimed. Two plain-HY2
sanity transfers also pass; they are not a repeated plain-HY2 performance series.

Separate same-ELF policy controls support the batching mechanism. WORK9 rejects
steady control GSO as the cause of download losses: actual control-multi deltas
were zero in all three legacy download interiors. Kernel/SAL-RX diagnostics and
the rejected receive-cap8 experiment remain research artifacts; cap8 did not
preserve RSS or consistently eliminate loss. Raw manifests/captures/CPU/RSS/echo
and red controls are in `tmp/xrust-finish-20261115/hy2` in the research workspace.
