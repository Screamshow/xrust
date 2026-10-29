# Client corrections and ARM verification, 2026-10-30

Three focused changes on dev, without a release or installation:

- URLTest finds the first HTTP header terminator even when the read also
  contains body bytes. This prevents false background failures/retries for
  successful responses on a persistent connection, preserving the head limit.
- UDP sniffing leaves the ambiguous 148-byte `01 00 00 00` shape unclassified
  instead of identifying a WireGuard initiation as uTP/BitTorrent. An actual
  uTP DATA packet with this length and zero connection ID is also deliberately
  left unclassified; other positive uTP controls still match.
- H2 XHTTP packet-up Body uploads share the filled worker buffer with H2 and
  reclaim it only when uniquely owned. If H2 still holds a reference, the
  session switches back to copying. H1, header/cookie payloads and streaming
  modes preserve their existing sending paths. Initial buffer size, allocator,
  POST limits/pacing, TLS and H2 settings are unchanged.

Verification: 51 XHTTP unit tests, 19 URLTest/UDP integration tests, formatting,
diff whitespace checks and core-runtime lib/tests Clippy with `-D warnings`.
ARM GL-MT6000 independent Xray 26.7.28 tests verified the two functional fixes
and packet-up traffic; stream-up/stream-one TLS controls also passed.

In five paired ARM single-flow upload phases, median CPU per GiB decreased
14.506 to 12.471 seconds (about 14%); median rate was 253 to 254 Mbit/s.
Separate upload-only tests showed about 0.8-1.0 MiB lower peak RSS; general
idle or whole-process RAM savings are not established. Do not extrapolate
these results to all workloads, total router CPU or stream-one.

Checked structures matched in 36 ARM ClientHello captures and controlled H2
request comparisons (headers/order, SETTINGS, initial window, POST and DATA
sizes, payload). This does not prove identical timing or complete camouflage.
REALITY captures in this cycle stopped at ClientHello, not full interoperability.

Original all-on-router upload8 write deadlines of two seconds were not a
confirmed client hang. A later split PC-generator/peer + ARM-client fixture
passed paced and saturated upload8 plus concurrent echo for baseline,
candidate and independent Xray. All bytes arrived. Under saturation the two
Xrust variants had maximum delivery gaps of 83/127 ms and echo of 70/62 ms.
The all-on-ARM control overloaded fixture resources, including a test Xray
OOM; a subsequent memory-guarded baseline test was stopped at its budget.
The exact old threaded timeout chain remains unlocalized. Do not change the
core merely to silence this overloaded fixture.

Operator-router package/runtime/config invariants matched after cleanup.
Synthetic loopback/LAN tests are not a universal WAN/CDN compatibility claim.
