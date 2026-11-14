# Bounded reusable transmit rings for WG/AWG

This records the initial TX-only development step. The current combined policy
also grows RX on demand; see `wireguard-adaptive-rx-2026-11-14.md` and the final
`awg-rx-reference-followup-2026-11-14.md` verification report. Statements about
immutable RX below describe the preceding TX-only candidate.

Native WG/AWG previously assigned a lifetime 2 MiB RX + 2 MiB TX pair to the first eight TCP connections (two on 32-bit targets). Idle control connections could retain the entire extra-capacity allowance, leaving later transfers on fixed 128 KiB RX / 64 KiB TX rings. A fallback connection could not grow after another connection released its allocation.

This candidate separates RX and TX allowances within the existing total extra capacity: 16 + 16 MiB on 64-bit targets and 4 + 4 MiB on 32-bit targets. The immutable receive allowance preserves the former eight/two large RX rings and their negotiated window scaling. All connections start with a 64 KiB transmit ring. An established or half-closed connection with at least 32 KiB queued plus caller-pending data can acquire a 2 MiB transmit ring. Sent but unacknowledged bytes remain in the logical queue and are preserved during replacement.

A large TX ring returns to 64 KiB only after its send queue and caller-pending queue have stayed empty for ten seconds. Existing fallback connections retry growth when capacity becomes available, throttled to 250 ms. Idle and retry deadlines participate in the stack task's wakeup calculation; an otherwise quiet endpoint can return its allowance without unrelated traffic.

The budget charges the whole replacement allocation until the old storage is freed, including the temporary 64 KiB allocation needed to shrink. Failed reservations or fallible allocations preserve the existing ring. The budget bounds extra ring capacity, including replacement workspace, rather than total process RSS: base rings, relay queues, crypto buffers, allocator retention and kernel queues remain separate.

The vendored smoltcp 0.14.0 extension is additive: `Socket::replace_send_buffer` takes caller-owned empty storage, preserves all unacknowledged/unsent bytes in logical order, returns the old ring, and does not change RX storage, reassembly, sequence/ACK state, retransmission timers or negotiated options. Original authorship and the 0BSD license are retained. Borrowed storage and `no_std`/no-alloc builds remain supported by the API. The runtime uses fallible heap allocations.

AWG parameters, CPS chains, magic headers, random prefixes, padding/header masking, AEAD, authentication/replay, MTU and TLS/target crypto flags are unchanged. More data in flight can change encrypted packet timing and burst lengths. Unchanged protocol encoding is not a claim of timing/DPI indistinguishability.

This is an upload-memory policy change. Idle connections still retain their receive credit; receive-side storage is not shrunk or dynamically reassigned. It does not fix every download limit, eliminate UDP drops, or establish ARM/WAN throughput gains from local x86 evidence.

Verification and measured limits are recorded in the Forkop operator report `docs/awg-adaptive-tx-local-verification-2026-11-14.md`; reusable fixture and raw evidence live in the operator workspace under `tmp/awg-adaptive-local-20261114`. No release publication or router installation is part of this candidate.
