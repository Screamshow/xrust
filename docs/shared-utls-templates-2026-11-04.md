# Share immutable uTLS templates between outbounds

Base: dev `1b1624a`, after the independently verified sniff-prefix change.
No version, package, core-default or verification-policy changes.

## Implementation

`core_tls::fingerprints::shared_by_name` lazily fills six fixed OnceLock slots
with Arc<Template>. Chrome aliases share one slot; random retains the existing
Firefox policy; randomized retains the existing once-per-process profile.
Unknown names are rejected without inserting a cache entry. The existing
owned `by_name` API remains unchanged.

Runtime Fingerprint stores the shared Arc, including fingerprints parsed inside
REALITY settings. Cloning TLS/outbound options no longer deep-copies the table.
Ordinary fingerprinted handshakes borrow the immutable table through an Arc.
REALITY without hybrid-group opt-in uses Arc::make_mut before applying the
existing compacting operation: its copy is private to that handshake. This
still has a temporary template copy for that REALITY path; this change does
not eliminate every per-handshake allocation. Cached tables remain resident
for process lifetime, with a fixed upper bound of six profiles.

## Verification

- Complete core-tls test invocation completed successfully, including template
  reconstruction, verified browser handshakes, GREASE/shuffling, random policies,
  server handshakes and QUIC. The conditional external example.com smoke test is
  not used as evidence for controlled interoperability.
- 13 runtime tls_client tests passed, including shared ownership/isolation,
  certificate and SPKI pins, CA checks and cache separation.
- 4 own-stack stream tests, 15 hot-reload tests and the URLTest authentication
  test passed.
- 6 REALITY authentication tests passed, including wrong-key/short-ID rejection
  and all browser profiles. The PQ wire probe passed all four preference cases:
  default/false REALITY without hybrid groups, explicit true with hybrid groups,
  ordinary Chrome TLS retaining hybrid groups.
- VLESS/TLS echo passed with actual `SING_BOX_REF` set to the existing
  Sing-Box X 1.14.2-x-1.0.3 Linux/amd64 reference. The earlier invocation without
  that variable returned early and is not counted as interoperability evidence.
- Clippy for core-tls/core-runtime, all targets with warnings denied, passed
  after relocating the new test module to the end of its file. Formatting and
  git diff whitespace checks passed.
- Full core-cli ARM release build passed with locked/offline dependencies,
  rust-x profile and unchanged target crypto flags. The standalone executable
  ran `version` on MT6000 and reported xrust 0.0.33. SHA-256:
  `1c18e039420fd683d8ee3a3f9ee150d8f96cadcb899259fcd1a011e95a9da85c`.

No claim of full platform CI, broad protocol compatibility, timing/DPI
equivalence or a measured throughput gain is made.

## ARM memory experiment

`core-tls/examples/shared_template_memory.rs`, MT6000 aarch64, release profile,
System allocator. The two modes in the same executable compare 112 independently
owned templates from the unchanged by_name API with 112 shared references.
Each mode runs in a fresh process. Three repetitions per mode/profile, ordered
owned/shared/shared/owned/owned/shared. The shared case includes first table
initialization, not just a warmed cache.

| Profile | Owned live allocation | Shared live allocation | Saving |
| --- | ---: | ---: | ---: |
| Chrome | 241024 B | 3064 B | 237960 B (232.4 KiB) |
| Firefox | 236768 B | 3026 B | 233742 B (228.3 KiB) |
| Safari | 228816 B | 2955 B | 225861 B (220.6 KiB) |

All three repeated live-allocation values matched for each fixed profile/mode.
Median RSS: Chrome 612 -> 328 KiB, Firefox 596 -> 332 KiB, Safari 596 -> 332 KiB.
Randomized was also exercised in six runs; fresh processes generated different
profiles, so no precise paired saving is attributed to that series.

The probe measures template storage, not a whole config/core/router. RSS also
includes allocator and page effects. The savings cannot be added directly to
another experiment's RSS difference. After dropping shared references, the
process-wide table remains intentionally cached; the printed after-drop count
also includes stdout initialization.

Probe SHA-256:
`07198da78a68764c948a2b7f1db86ad8488cda442e21d8392fea757c632c32ee`.
Raw local evidence, not committed: Forkop `tmp/utls-shared-arm-results.txt`,
`tmp/utls-shared-arm-core-smoke.txt` and `tmp/utls-shared-router-*.txt`.

## Restoration

Only owned probe/core files were staged in dedicated /tmp directories on the
router. They were removed afterward. No listeners, package installation,
firewall/configuration edits, working-core replacement or service restarts.
Final package-list hash, Forkop UCI hash, service running state, and both
working sing-box PID/executable hashes matched the initial snapshot.
