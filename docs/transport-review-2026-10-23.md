# Transport review and focused fixes, 2026-10-23

Reviewed Xrust main `691f00a`, including the outbound H2, XHTTP, gRPC,
H2MUX, WebSocket, Vision and WireGuard/AmneziaWG paths. No release or router
installation is included. Existing work on server REALITY and Xray compatibility
is preserved.

This records the initial review. Subsequent interoperability fixes, performance
work and final verification are recorded in
[the follow-up report](transport-performance-2026-10-23.md).

## Findings and changes

- **gRPC custom paths:** the outbound always escaped the entire service name
  and appended `/Tun`. Xray service names starting with `/` instead specify a
  custom service/method path. Implemented that form, preserving segment escaping,
  ordinary `api/test -> /api%2Ftest/Tun`, and the single-slash edge cases. The
  inbound already recognized custom paths. Specification/reference:
  https://github.com/XTLS/Xray-core/blob/main/transport/internet/grpc/config.go
- **H2 upload allocation bounds:** H2Io copied the entire caller buffer into
  owned storage, including while the peer had no send capacity. Bound each write
  to 48 KiB. gRPC also splits large writes, reserving 16 bytes for framing so the
  complete allocation stays below that bound. This affects HTTP/2, H2MUX and
  XHTTP paths that use H2Io, plus gRPC separately. It does not change receive
  windows, congestion control, packet-up batching or TLS verification. A 1 MiB
  caller buffer no longer requires a single 1 MiB staging copy. This is an
  allocation bound, not a measured reduction in whole-process RSS or a speed claim.
- **H2MUX padding correctness:** PadStream discarded unwritten frame bytes on
  short writes/Pending and lost partially read frame headers on Pending. Lengths
  above u16 also wrapped. Added persistent write/read state, bounded frame
  payloads, WriteZero detection, truncated-frame errors and drain on flush/close.
  Removed the extra heap allocation/copy for every padded payload read; padding
  discard uses a fixed stack buffer. Empty writes no longer consume padding slots.
- **WireGuard/AmneziaWG:** authenticated empty keepalive packets popped a pooled
  decrypt buffer and dropped it. Return that buffer to the existing bounded pool.
  This avoids pool depletion/allocation churn, not an unbounded memory leak.
- **VLESS, TLS, REALITY and Vision:** retained their cryptography, TLS checks and
  Direct transition rules. Their connections benefit from the applicable shared
  transport fixes; no blanket claim of faster crypto or new REALITY compatibility.
- **WebSocket:** already caps upload payloads at 65,535 bytes, reuses its frame
  buffer and preserves partial-write state. No speculative rewrite was made.

## Supplied Trojan link

Credentials and the full link are deliberately absent from this report/tests.
Using the supplied node, certificate verification and ALPN h2 succeeded. The old
escaped-service-plus-Tun path returned HTTP 404; the custom path returned HTTP 200
with application/grpc. An independent Node HTTP/2 probe then completed a Trojan
TCP HTTP request, receiving HTTP/1.1 200 from example.com. The patched Rust runtime
also passed the same real request through its mixed inbound and Trojan outbound,
with certificate verification enabled.

The visible percent-encoded display name alone does **not** reproduce the UI
whitespace error. The old validator rejected literal whitespace even after `#`,
where it is display metadata. Forkop's Trojan validator now permits spaces there,
but still rejects whitespace in connection parameters and control characters
anywhere. Added anonymized tests for encoded/literal labels, slashed service names,
password whitespace and control characters. A Markdown hyperlink is not a valid
authority value; a copied link must contain the plain host there. Explicit custom
authority differing from the server/SNI is still not implemented by our parser.

## Initial verification

The active checkout initially failed to compile in pre-existing unfinished
server REALITY changes (ServerReality fields/types). Rust verification therefore
uses an isolated archive of main plus exactly these four edited outbound files,
under the parent workspace's `tmp/transport-review-source`. A reused dependency
cache initially carried the other checkout's TLS API; forcing local dependency
rebuild resolved that. No unrelated source fixes were added.

- Outbound runtime unit tests: 546 passed, 6 existing ignored, 264 filtered.
  Includes H2/gRPC 1 MiB transfers over a 1 KiB duplex channel with bounded writes,
  padded H2MUX over 3/127-byte channels with payloads above 65,535 bytes and the
  transition through all sixteen padded frames, plus truncated-header rejection.
- Independent sing-box `1.14.1-extended-2.7.2`: transports_interop, mux and
  wireguard_interop passed. Transport matrix includes VLESS WS/gRPC/H2 over TLS
  and Trojan WS over TLS. Loopback fixtures use their existing test certificates
  and insecure fixture setting; the separate live probe verifies its certificate.
- Rust X core-config profile: 3 passed.
- Workspace check with no default features and `rust-x`: passed with existing
  dead-code warnings in the reduced profile.
- core-runtime clippy, lib and tests, with `-D warnings`: passed.
- Frontend validators: 372 passed. After the final control-character regex
  adjustment, the 34 Trojan cases were rerun successfully. ESLint on the changed
  validator, TypeScript and LuCI build passed. Generated main.js was updated.
- The real ucode backend parser preserved `/20763/test` from an anonymized
  percent-encoded serviceName and produced the expected Trojan/TLS/gRPC outbound.

Logs in the parent workspace: `tmp/transport-review-{isolated-tests,interop,
profile,clippy,live-grpc}.log`. No WAN throughput/CPU/p99 comparison or router
memory-pressure benchmark was performed. AmneziaWG's unit codecs are covered by
the outbound suite; this run does not establish independent live AWG interoperability.
