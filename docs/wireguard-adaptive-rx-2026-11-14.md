# WG/AWG receive storage growth

Local development candidate, 2026-11-14. This extends the adaptive TX policy
described in `wireguard-adaptive-tx-2026-11-14.md` with independently bounded
receive storage growth. It is not a release, an installed package update or a
performance claim. Measurements and their limitations belong in the operator
verification report.

## Policy and accounting

Each TCP connection starts with a 128 KiB RX ring and a 64 KiB TX ring. Before
connecting, the runtime configures a prospective RX maximum of 2 MiB, allowing
the SYN to negotiate scaling for later growth while advertising only storage
already supplied to the socket. Small control connections do not acquire large
RX reservations merely by connecting.

The runtime considers RX growth once bytes removed from its receive ring plus
the currently queued contiguous bytes reach 32 KiB. This is cumulative activity,
not a recent-rate estimate or proof that the caller application consumed those
bytes. Growth is allowed in Established, FinWait1 and FinWait2: closing the local
write half must not prevent a large response from using a larger receive window.
The target is at most 2 MiB and at most the window representable by the negotiated
scale. A peer without scaling therefore does not trigger a useless large
allocation. Budget or allocation failures retain the current storage and retry
after 250 ms; that deadline participates in the existing stack task's wakeups.

RX and TX have separate, process-wide extra-capacity budgets shared across
endpoints. On 64-bit targets they receive 16 MiB each, 32 MiB combined; on 32-bit
targets they receive 4 MiB each, 8 MiB combined. During growth, the reservation
charges the entire replacement while both allocations exist. The old allocation
is freed before returning its base-capacity credit. Failed attempts return their
temporary reservation without discarding received bytes.

An RX reservation lasts until its socket is removed. RX never shrinks on an idle
timer: an empty ring can still owe the peer all previously advertised receive
credit. The existing TX idle-reclamation rule is separate. These budgets bound
extra TCP ring capacity and replacement workspace, not live connection count,
base rings, relay queues, allocator retention, process RSS or total router RAM.
Idle connections that previously grew RX can retain that storage until close.

## TCP contract

The additive vendored smoltcp APIs are `set_receive_capacity_limit`,
`receive_window_capacity` and `replace_receive_buffer`. The configured maximum
survives reset/connect/listen. Scaling is fixed by the handshake, capped at the
RFC 7323 maximum shift of 14, and falls back to zero when the peer lacks window
scaling support. Increasing storage never renegotiates the scale.

Replacement accepts only empty storage at least as large as the existing ring
and within the configured maximum. It preserves the logical queued bytes,
wrapped out-of-order ranges, assembler, sequence/ACK state, FIN state and timers.
Failure is atomic. The last advertised ACK/window edge stays unchanged until an
outgoing packet publishes the newly backed credit; a small increase also requests
a window update, and a failed device emit preserves that request.

A receive guard also bounds segment acceptance by actual storage. This matters
before the final handshake ACK: the saved SYN window field is unscaled and must
not become permission to write beyond a small ring when interpreted with the
larger prospective scale. The guard does not reduce valid outstanding credit
from a grow-only ring.

AWG encoding, dressing/CPS, random prefixes, masking, authentication/replay,
cryptography and MTU are outside this change. Different receive credit can alter
traffic bursts and timing; preserving these mechanisms does not establish full
timing or DPI indistinguishability from the original implementation.

## Focused verification

RX replacements use the global allocator's zeroed-allocation API with a checked
layout and explicit null/failure handling, then transfer sole ownership to a
matching `Vec<u8>`. This retains the former receive-ring zeroed allocation
semantics without eagerly writing every untouched page. TX allocation is
unchanged. The three additional helper tests cover zero and boundary sizes,
initialized storage, ordinary write/drop ownership and rejected invalid layouts.
This does not guarantee allocator page release or recovery from OS OOM kills.

The final local checks passed: runtime library 830 tests with 5 ignored;
vendored smoltcp library 438 tests; no-alloc plus async compilation; formatting;
strict runtime all-target Clippy; release x86_64-musl and aarch64-musl builds.
These are focused checks, not full platform CI or ARM performance validation.

Three runtime RX tests cover the activity threshold, lifetime reservation,
retry after budget return and a real TCP response after local write half-close.
Nine vendored RX tests cover pre-SYN configuration/reset, scale limits and
no-scaling negotiation, backed credit publication, the pre-final-ACK guard,
wrapped queued and multiple out-of-order ranges with TCP gap filling, atomic
rejection, old-credit acceptance, failed emit, borrowed storage and FIN state.
