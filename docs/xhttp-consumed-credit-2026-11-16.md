# XHTTP body ownership and Xray flow-control profile

Split-mode HTTP/2 GET bodies are read directly by their consumer instead of a
separate task/channel. Credit follows actual consumption in at most8KiB units.
The bounded64-pair queue preserves connection/stream WINDOW_UPDATE order and
flush boundaries; stable stream keys retain final credit after remote END_STREAM.
Terminal driver exit completes local buffered accounting without queuing updates
that can no longer be sent. Live GOAWAY streams keep normal flow control.

XHTTP-only defaults now advertise MAX_FRAME_SIZE1MiB and an opening connection
credit increment1GiB, matching the checked independent Xray profile. Explicit
H2 window overrides remain authoritative. Ordinary H2/gRPC settings, POST1MB/30ms,
padding, XMUX, authentication and network timer constants are unchanged.

Verification:70 XHTTP and nine deterministic h2 accounting/queue/teardown tests,
Clippy and original-flags ARM release passed. Independent ARM Xray wire33 covers
18 ordinary transfers, pause/resume/cancel/post-cancel and nine actual largeDATA
cases. All content/ACK controls and29 loss-free captures pass. Consumed-credit
sequences match reference; selected defaults also match ordered SETTINGS,
opening credit and DATA histograms. Both1MiB frames are actually exercised in
each2MiB largeDATA case. Header order, close GOAWAY and POST segmentation
deviations remain documented; full timing/DPI equivalence is not claimed.

MT6000 native4,72 warm/gated windows, three rotated repeats, against dev e0cdb926:
fixed100Mbps download CPU/GiB repeat-paired medians fall20.41% for packet-up TLS,
20.27% for packet-up REALITY and14.08% for stream-up REALITY. Sampled RSS falls
about68–104KiB and remains about1.75–1.9MiB below frozen Tachyon0.5.3. Residual
fixed-rate CPU versus Tachyon is still about24–30% higher. Saturated packet-up
TLS download CPU falls16.72%, with paired median speed change+0.24%.

Tradeoffs: stream-up saturated download is slower in all three pairs
(−6.70/−5.55/−1.31%), with median paired echo-p95 increase7.07ms. Saturated
stream-up upload CPU rises2.18–8.68% (paired median6.32%), while speed changes
are mixed. These are process/LAN measurements, not total-router memory or watts.

A separate production RSS9 actually delivers8MiB in1MiB DATA frames, comparing
the final ELF with the16KiB factor and independent Xray. Whole-process lifetime
HWM medians8992/11360/37808KiB respectively; production HWM is lower in each
pair against the16KiB factor.100ms sampled transient RSS has overlapping/noisy
ranges and is not uniformly lower. This is not a Tachyon large-frame comparison.

The prior prototypes' missing final stream updates and post-driver-exit EOF
stall were reproduced before repair. Raw red controls, source/ELF manifests,
wire captures, CPU/RSS/echo ranges and the final integration split are retained
in the research workspace `tmp/xrust-finish-20261115`. The previous local opt-in
gRPC work is preserved separately and is not included in this change.
