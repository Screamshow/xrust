# Native Tailscale UDP receive buffer fix

Bursts of exit-node traffic could overflow the native Tailscale UDP socket's system-default receive queue. On the GL-MT6000 test router its effective size was 212992 bytes. Four concurrent 4 MiB HTTPS uploads reproduced local socket drops. A-B-A and B-A-B comparisons gave 264/225/421 drops in the default-buffer phases and zero drops in all three 2 MiB phases. All 24 uploads completed with HTTP 200. These are local socket counters shared by native peers, not a measurement of WAN packet loss.

DirectMesh now configures its bound UDP receive socket before use, targeting an effective 2 MiB queue. Linux's requested size accounts for kernel doubling. The ordinary operation respects system limits; if capped, Linux SO_RCVBUFFORCE is attempted for that socket only. The resulting size is read back. Restricted privileges do not prevent startup; failure to reach or verify the target produces a warning. Queues already at least as large as the target are retained. Send buffers and global sysctls are unchanged.

## Verification

- Focused x86 musl native Tailscale suite: 68 passed, zero failed, one CAP_NET_ADMIN assertion explicitly ignored.
- Complete ARM64 Rust X release-profile build passed with existing target crypto settings.
- Exact production buffer function executed in a separate ARM harness on the GL-MT6000: privileged 212992 -> 2097152 bytes; uid/gid 65534 fallback 212992 -> 425984 bytes. Both verified UDP datagrams, send-buffer preservation and idempotency. This was an exact-function harness, not the full ARM unit-test executable.
- Correct compiled artifact xrust 0.0.35 plus this change installed for the separate native Tailscale service on the operator router. Main release 0.0.34 proxy was preserved. Both binaries accepted the current configuration. The live native socket reported receive=2097152, send=212992 bytes; exit-node connectivity and PeerAPI DNS passed.
- Phone Telegram media transfer completed during six live samples on November 5, 15:28:37–15:29:03 Moscow. UDP drops remained zero; TUN errors/drops and tun_write_errors remained zero; cumulative tun_send_errors remained at four without growth.

Exact rollback was staged privately on the operator router. No release, tag, package version, global rmem sysctl, UCI or persistent routing changes were made. Temporary probes were removed. The operator native service currently uses a separate candidate executable; a future normal component update may replace that arrangement.

## Limits

The live test confirms that transfer, not all Telegram or iOS behavior. Latency tails, kernel queue memory under sustained load, additional architectures and long-term stability remain unverified. More buffering can affect latency; 2 MiB is a bounded per-socket choice supported by the measured burst test, not a general WAN performance claim.
