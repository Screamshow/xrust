# Focused AWG compatibility corrections, 2026-11-14

Local changes on existing Xrust dev, base `731adcb6faef3cbb4040aa4acde5a2b6e06a9182`. Comparison reference: official AmneziaWG kernel module `v3.1.20260906`, commit `4569c4c67f3a57414969260cafbbd04694fbaae0`, selected by Slava-Shchipunov/awg-openwrt `03b62269e2edc168504f057cffaafda11b25ed92`.

These fix concrete issues found in the code comparison; they are not a new protocol implementation or a claim of complete AWG 3.1 parity.

## Corrections

- Header protection takes the first 12 bytes of the prefix, including when S4 exceeds 12. Valid protected profiles with S4=16/64 no longer panic on transport sealing. Cipher, key derivation, authentication and replay processing are unchanged.
- Optional content padding and random-trailer calculations account for both the 16-byte transport header and 16-byte authentication tag. Outgoing UDP-window growth uses the unpadded datagram size before choosing padding, as in the kernel. Incoming window growth occurs after authentication instead of being influenced by unauthenticated packets. Existing padding without either extension retains its multiple-of-16 behavior.
- CPS `<c>` emits a big-endian 32-bit counter. A random initial value is selected for each initiation sequence, shared by all counter tags in a packet and advanced between nonempty I1-I5 packets. Existing tags are retained; invalid counter arguments and unknown tags remain explicit errors.
- Incoming cookie replies are consumed even with DisableCookies, matching the kernel's distinction between receiving replies and issuing challenges. No new server-side cookie challenge/DoS subsystem is introduced.
- Configured RekeyTimeout applies to initial and cookie-triggered retries. MaxHandshakeAttempts is selected once per handshake cycle rather than reselected on each retry; an explicit AWG attempt limit is not truncated by the legacy 90-second cap. Configured session timing bounds are considered by the scheduler instead of always using default deadlines.
- AWG KeepaliveTimeout now schedules reactive keepalives after authenticated, allowed inner data. Additional receives do not continually postpone the first deadline; a further timer can be scheduled after it fires. Outgoing authenticated transport cancels a pending reactive keepalive. PersistentKeepalive remains separate. This new reactive behavior is scoped to AWG; plain WG retains its previous behavior.
- Linux AWG initiation/response uses the kernel's 0x88 DS byte, and random junk uses a randomized byte. Control sends temporarily override the socket class and restore it before returning. The single owning stack task has no await between override/send/restore; bulk data/GSO does not pay these extra socket calls. Non-Linux sends retain their existing traffic-class behavior.

## Compatibility and scope

Endpoint schema, key formats, H/S/J parameters, existing CPS syntax, Noise/AEAD, replay checks, MTU, SO_MARK and TCP RX/TX buffer policy remain intact. Corrected optional 3.1 behavior intentionally changes outputs that differed from the reference. The existing native outer data path and independent Tailscale stack are not replaced.

This is focused compatibility work. The code comparison identified additional differences in full timer/recovery design and kernel-vs-smoltcp behavior; these corrections do not establish identical complete timer state machines, inner TCP fingerprints, outer packet distributions or DPI indistinguishability. Nor does accepting a profile prove support for every possible AWG 3.1 option combination. In particular, under-load cookie-challenge serving was not implemented here.

## Validation

On an isolated Linux source snapshot exported from the exact dev HEAD with the local changes overlaid:

- Runtime rust-x library: **838 passed, 0 failed, 5 ignored** (830 existing plus eight new regressions).
- Strict runtime all-target Clippy: passed.
- Formatting and diff whitespace checks: passed.
- Release ARM64-musl build: passed, using the existing release/crypto configuration. Local output `tmp/awg-code-compare-20261114/fixed-arm64`, SHA-256 `10fb626c0913dd8fe109cd0584e6641ab07f69582ae493376ce4abe582aca933`.

After strengthening the authentication regression with a correctly classified transport header and a deliberately invalid AEAD tag, all five runtime-path compatibility regressions passed again. That final change was test-only; release production code was unchanged.

New tests cover prefix lengths 12/13/16/64 against the independent ChaCha20 implementation already used by the suite, padding arithmetic including tag/legacy controls, CPS counter byte order and repeated counter tags, protected transport sealing/decryption at S4=12/16/64, valid encrypted cookie processing with DisableCookies and a custom retry interval, reactive keepalive scheduling/sending/cancellation, plain-WG encrypted payload compatibility, and IPv4/IPv6 control sends with socket-class restoration.

Transport round trips exercise actual Stack/Noise methods, but both endpoints are in-process code; they are not an independent kernel/Go interoperability run. Kernel behavior was compared by pinned source. No live WARP test, router installation, speed comparison, full platform CI or DPI measurement was performed. Evidence/build logs reside in the operator workspace under `tmp/awg-code-compare-20261114`.

No release, tag, main integration, push or package installation was performed for this task.
