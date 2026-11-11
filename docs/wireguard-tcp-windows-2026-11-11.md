# Bounded WG/AWG TCP windows

## Behavior

Native WireGuard TCP connections previously used 128 KiB receive and 64 KiB send rings. Their capacity limits throughput over a high-RTT path even when CPU has headroom. The new large rings are 2 MiB in each direction, shared by ordinary WG and AmneziaWG.

Additional ring capacity is reserved atomically across every WG endpoint in the process:

| Target | Additional capacity budget | Large connections |
|---|---:|---:|
| 64-bit ARM/x86 | 32 MiB | 8 |
| 32-bit MIPS | 8 MiB | 2 |

Each large connection reserves 3.8125 MiB above the small 192 KiB pair. When the allowance is full, new connections retain the old small rings. Those existing fallback connections are not resized later. Closing a connection, failing its setup or destroying its stack returns the reservation. Base buffers, application queues, crypto buffers, kernel queues and allocator retention are outside this allowance: it is not a total RSS limit or an OOM guarantee for every router.

The smaller MIPS allowance avoids applying the MT6000's memory policy unchanged to the supported RAM-limited 24Kc target. No user configuration, protocol parser, SRS, crypto or AWG obfuscation parameter changes are required. The TCP window and timing/batching of the encrypted traffic can change; universal camouflage equivalence is not claimed.

## Causal throughput evidence

The local ARM fixture uses MT6000 with one client worker/CPU, an official amneziawg-go v3.1.20260828 WSL peer, disposable keys, MTU 1380 and nonzero J/S/H parameters. Owned-interface netem adds one 70/140 ms delay to a TCP round trip. There is no external traffic server or application UDP forwarder.

With the receive ring held at 2 MiB, changing only TX from 512 KiB to 2 MiB in equally instrumented diagnostic builds gave these medians of three 16 MiB uploads:

| Added RTT | TX 512 KiB | TX 2 MiB |
|---|---:|---:|
| 70 ms | 53.40 Mbit/s | 145.51 Mbit/s |
| 140 ms | 27.03 Mbit/s | 76.74 Mbit/s |

The unchanged build and instrumented 512 KiB control matched closely. In the smaller-TX control the ring was full in about 75% of observed stack iterations and upstream data waited for space. In the 2 MiB variant the proportion was about 27%. These are observations, not CPU-time percentages. Internal TCP captures found no repeated segment-start sequence values in that series. The smaller ring's capacity/RTT ceiling agrees with the measured bottleneck.

The diagnostic larger-TX peak process RSS increased by about 1.5 MiB. Echo median at 70 ms increased from 71.81 to 74.45 ms; at 140 ms it changed from 141.83 to 142.47 ms. These short synthetic-path samples do not establish WAN tail latency, total router memory/power, steady-state speed or universal parity with the Linux TCP stack. CPU/GiB includes concurrent echo and setup; it is not an isolated crypto profile.

## Release preparation verification

- 49 focused WireGuard tests include budget exhaustion/reuse, small-ring selection and concurrent acquire/drop. The large-connection count is target dependent (8/2).
- Local workspace tests: 1570 passed, 14 explicitly ignored; workspace Clippy and the rust-x profile Clippy pass. Four Python script tests pass.
- Privileged SO_MARK socket test, FakeIP exit gate and 14 inbound tests pass. Six rust-x profile tests pass.
- The existing exit-gate test's google.com query was found to traverse an earlier `evaluate` rule in the full fixture, contrary to its no-upstream comment. The test now uses the fixture's explicit FakeIP domain before `evaluate`. The corrected test passes in a network namespace with only loopback. No DNS runtime behavior was changed.
- ARM64, x86_64 and MIPS release builds pass their current size budgets with the existing target crypto flags. Existing MIPS 24Kc QEMU runtime checks pass HTTP/SOCKS to a local TLS proxy, DNS hijack, Clash counters and software TLS.
- The final MIPS binary additionally passes actual native AWG TCP-ring policy checks under QEMU: two large plus two fallback connections, release/reuse while fallback remains alive, and return of the allowance after 32 refused TCP connections. This is functional emulation evidence, not physical-MIPS speed/RAM evidence.
- The physical MT6000 fixture checks eight large plus eight fallback connections, release/reuse, 32 refused connections and repeated 16-way uploads/downloads for both WG and AWG, at saturation and at approximately 48 Mbit/s aggregate application rate. Payload bytes, final ACK and concurrent echo are verified; working Forkop is kept separate.

The exact final ARM binary passed 192 AWG and 192 WG measured transfers (384 total). Process FD counts were 11 before and after each mode. Sampled peak RSS was 25,744/24,192 KiB (AWG/WG), recovering to 7,972/7,928 KiB after closing connections. Saturation produced 68/430 client UDP socket drops, all recovered by TCP; rate-limited phases had zero measured client socket drops. These are finite recovery controls, not a memory soak or a zero-loss claim. Router package/config/binary/PID/service invariants matched and owned resources were removed. Original WSL NAT, absent .wslconfig and five container IDs were restored.

Operator raw evidence and scripts are retained outside the repository under Forkop's `tmp/awg-release-ready-20261111`, `tmp/awg-final-arm-20261111`, `tmp/awg-final-mips-20261111` and `tmp/awg-cause-20261111`. Test keys and runtime profiles are not release artifacts.

## Remaining limits

The previous direct reference comparison contained one native download at 70 ms falling to about 11.64 Mbit/s. Ten subsequent captured downloads of the unchanged candidate gave 120.60–128.26 Mbit/s with correct data and no observed sender TCP retransmissions. Its cause remains unlocalized; a release must not claim it fixed or claim universal reference parity.

Saturation can drop datagrams on the native client's UDP socket; the parallel TCP controls recover them. Drops are recorded separately from rate-limited controls rather than silently excluded. Larger windows also increased saturated LAN echo latency in the earlier series. Low-memory physical MIPS routers and long-running production memory behavior have not been benchmarked. Package installation/rollback, signed artifacts and publication remain part of the separate release workflow.
