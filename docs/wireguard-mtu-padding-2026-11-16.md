# MTU-aware WireGuard transport padding

Ordinary WireGuard and AWG transport padding now follows the official
`calculatePaddingSize` algorithm: alignment is bounded by the last MTU-sized
unit. At inner MTU1380 a full-size packet therefore produces a1412-byte WG
UDP payload, or1428 bytes with AWG S4=16, instead of1424/1440. Oversized inputs
retain every input byte and follow the reference modulo-MTU rule. Explicit
AWG content-padding and random-trailer window policies retain their precedence.
Noise encryption, handshake/cookie/replay logic, counters, rekey/keepalive timers,
receive windows, GSO grouping and the Tailscale seal path are unchanged.

The independent references were Linux kernel WireGuard and pristine official
AmneziaWG-Go source b5928efb6ca19f0153958460c3d141f04abc5c2e. The latter ELF was
built from a verified unchanged source archive (SHA256
ea80cf3de12e9349c24887cfa95b7849c52798e68cd83781b82c98bdb6de1cb3).
Seventy official WireGuard-Go and210 AWG known-key authenticated vectors,
40 focused Rust tests, core-runtime all-targets check, Clippy and ARM release
build passed. Thirty actual official-peer paced UDP controls cover three repeats,
MTU1280/1380/1400, oversized inputs and protected AWG headers. They verify
content/ACK, public framing, boundary lengths and counters; arbitrary captured
application ciphertext was not claimed to be decrypted.

Six separate bidirectional bulk captures and three short ARM WG captures passed
ordinary datagram/nonce/boundary checks with zero observer drops. Their stronger
aggregate gates requesting actual source-egress GSO descriptors were incomplete:
no such descriptors were observed for WG. WSL ingress GRO descriptors in AWG
are not proof that the source called UDP_SEGMENT. Failed aggregate results remain
failed; real socket GSO tests and observed GRO reconstruction have separate scopes.

On MT6000 all four CPUs/workers,48 warm/gated CPU windows compared the isolated
patch with dev e0cdb926 (100Mbps and saturation, both directions, three rotated
repeats). This is a format correction, not a demonstrated speed improvement.
WG saturated download medians were365.0→353.1Mbps, with paired changes
−1.52/−6.29/−1.03%; CPU/GiB24.98→25.02s. AWG saturated upload CPU/GiB
37.02→37.76s. Other changes were mixed. Paired peak RSS differences stayed
within−204..+156KiB and client/Go socket drop deltas were zero. No full network
timer, all optional AWG-profile, IPv6 or camouflage-equivalence claim is made.

The separate research workspace contains source/ELF manifests, red fixture
attempts, raw captures and per-window CPU/RSS/echo data under
`tmp/xrust-finish-20261115/wg`. Its fixture uses a native Linux NAT rule to expose
the kernel peer through WSL mirrored networking; no application UDP relay is in
the measured path. No package or working Forkop service was replaced.
