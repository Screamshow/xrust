# Forkop local changes to smoltcp 0.14.0

This directory vendors the crates.io `smoltcp` 0.14.0 package. Upstream
authorship, the package metadata and `LICENSE-0BSD.txt` are preserved.
The package was copied from the existing local Cargo registry cache;
Cargo cache markers `.cargo-ok` and `.cargo_vcs_info.json` were omitted.

Production changes are confined to `src/socket/tcp.rs`. The additive TCP API
`Socket::replace_send_buffer` replaces caller-provided transmit storage
while preserving the complete logical queue, including sent but unacknowledged
bytes. It rejects nonempty or insufficient replacement storage without changes,
returns the previous buffer on success, and allocates no memory internally.
It preserves receive storage, reassembly, TCP sequence/ACK state, timers and
negotiated options. The caller must account for both old and replacement storage
while replacing a buffer and poll the interface afterwards.

The receive-side APIs are `set_receive_capacity_limit`,
`receive_window_capacity` and `replace_receive_buffer`. A prospective receive
maximum is configured before opening the connection and survives reset. The
handshake negotiates scaling for that maximum, capped at RFC 7323's shift 14,
while advertising only actually backed credit. Peers without scaling retain
the unscaled limit. Receive replacement is grow-only, preserves queued and
wrapped out-of-order bytes and reassembly state, and schedules a window update.
Previously advertised credit is retained until the update is successfully sent.
A segment-acceptance guard also bounds the receive edge by actual storage during
the SYN-to-final-ACK transition; the unscaled SYN field cannot grant unbacked
memory when a larger prospective scale is used.

The added tests cover queue wrap, failure atomicity, outstanding bytes and
retransmission, receive reassembly, borrowed storage, empty queues and closing
sockets. RX controls include scale negotiation/reset and no-scaling fallback,
old-credit acceptance, queued/OOO gap filling, atomic rejection, failed emit,
backed window publication and the pre-final-ACK storage bound. Idle empty receive
queues are not permission to shrink storage or revoke outstanding credit.

This extension does not choose a memory budget, an idle timeout, or a buffer
growth policy. Those decisions belong to the embedding runtime. It does not
change a transport's cipher, packet format, camouflage parameters or UDP path.

Runtime policy: `docs/wireguard-adaptive-tx-2026-11-14.md` and
`docs/wireguard-adaptive-rx-2026-11-14.md` in the repository. Performance or
compatibility claims require validation of
the embedding runtime; a successful storage test alone is not a throughput
measurement.
