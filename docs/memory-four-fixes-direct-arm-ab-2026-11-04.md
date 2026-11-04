# Direct-LAN follow-up for the four memory changes

Baseline `95e76e8`, candidate `3c38de0`; same production ARM binaries and
synthetic config as memory-four-fixes-arm-ab-2026-11-04.md. The user disabled
Private/Public Windows firewall profiles before this series. The agent did not
change that setting or create any firewall rules. Direct connectivity was
verified by an ARM HTTP fetch and route lookup to 192.168.90.201 over br-lan.

The entire payload path is now PC generator -> ARM SOCKS/VLESS/TLS client ->
PC Xray peer -> PC loopback sink. SSH is used only for control and /proc
sampling, with no data forwarding. The peer is the existing Windows Xray
26.7.28 binary, not a Linux/WSL peer; this is documented explicitly rather
than claiming the historical WSL fixture was reproduced exactly. The PC sink
control exceeds 3 Gbit/s. Xray permits only the owned loopback TCP sink port
through its default private-target policy. Test certificate verification stays
enabled. No private subscription/configuration is copied.

One ARM worker, logical CPU 3, normal System allocator, unchanged release/crypto
flags. 112 Chrome TLS outbounds, traffic through node0; 75 remote SRS lists,
90000 domain suffixes total, ~1.47 MB compressed; 80 held connections. Same
B/C/C/B/B/C order, cold/warm cache, list replacements, held-session/recovery
and fixed/saturated traffic phases as the tunnel series. Process status is
sampled every ~200 ms. Startup timing includes control/settle overhead.

PC Node/Xray CPU/RSS sampling identifies only the processes owned by this
fixture. Process CPU seconds are distinct from CPU percent, core RSS from
kernel/socket memory, and process RAM from total router RAM/power. Short LAN
echo observations are not WAN/p99 guarantees. Three repeats bound conclusions
to this fixture; CPU/GiB comparisons use equal verified payload sizes.

## Results

Three repetitions per version; every trial completed. Main series: 24
hash-verified bulk transfers totaling 1152 MiB, 480 verified held sessions,
12 complete 75-list replacements (900 changed downloads) and six warm
restarts with zero network list requests. Additional long series: 12 verified
512 MiB transfers, totaling 6 GiB. Combined: 36 bulk transfers / 7.125 GiB.

Medians, KiB:

| State | Baseline | Candidate | Difference |
| --- | ---: | ---: | ---: |
| Cold idle RSS | 16164 | 15980 | -184 |
| 80 held sessions RSS | 18196 | 17568 | -628 (-3.5%) |
| 80 held sessions RssAnon | 12464 | 11768 | -696 |
| Post-close recovery RSS | 16760 | 16540 | -220 |
| Final traffic recovery RSS | 17000 | 16780 | -220 |
| Warm idle RSS | 16100 | 15988 | -112 |
| After second list replacement RSS | 17832 | 17348 | -484 |
| HWM after two replacements | 19448 | 17984 | -1464 (-7.5%) |

FDs consistently returned from 170 (80 held sessions) to 10 after closing
them and at final recovery. No process crash, checksum mismatch or stalled
transfer occurred. This short experiment does not establish long-term leak
absence. Cold/warm readiness medians were 2.222/1.713 s baseline and
2.225/1.719 s candidate; control/settle overhead is included, so no startup
speed improvement is claimed.

## Direct traffic and CPU

For longer, more stable observations, each fresh process performed one 512 MiB
download and upload, again ordered B/C/C/B/B/C. Values below are medians of
three trials; CPU/GiB is core process CPU seconds, not total router CPU.

| Direction | Baseline Mbit/s | Candidate Mbit/s | Baseline CPU s/GiB | Candidate CPU s/GiB |
| --- | ---: | ---: | ---: | ---: |
| Download, 512 MiB | 556.1 | 568.7 | 5.12 | 4.96 |
| Upload, 512 MiB | 566.5 | 599.5 | 5.34 | 5.32 |

Download speed ranges were 536.2--566.5 vs 519.6--611.3 Mbit/s; upload
559.7--602.4 vs 554.7--602.5. Download CPU seconds per transfer were
2.78/2.49/2.56 vs 2.80/2.48/2.35, upload 2.81/2.60/2.67 vs
2.80/2.63/2.66. The ranges overlap. This does not establish a throughput/CPU
gain or a consistent performance regression. The short 64 MiB controls had
mixed medians (download 591.3 -> 559.9, upload 555.0 -> 565.9 Mbit/s), another
reason not to promote a percentage speed claim from this small sample.

Fixed-rate transfers sustained ~49.8--49.9 Mbit/s in both versions. CPU per
32 MiB download was 0.28 -> 0.30 s, upload 0.29 -> 0.29 s; coarse tick sampling
and short durations limit interpretation. Median per-trial echo p95 at fixed
rate was download 2.97 -> 1.78 ms, upload 1.99 -> 2.05 ms. Long saturated
download echo p95 was 5.76 -> 5.31 ms, upload 8.36 -> 9.94 ms. Mixed direction
results do not establish improved tail latency or a reliable WAN/p99 bound.

PC long-series 500 ms samples peaked near 54% of one CPU for Node and 39% for
Xray; peak RSS ~88/31 MiB. These process samples show headroom during the
observed portion, not every microburst. The LAN series is independent of SSH
forwarding, but does not prove the maximum possible core throughput or
performance on other transports/peers. No new full protocol/platform CI claim.

Refresh CPU medians: first replacement 0.85 -> 0.76 s, second 1.34 -> 1.15 s.
Seventy-five timer-driven updates overlap, so these phase measurements are
not an isolated writer CPU benchmark and are not used for a general CPU claim.

## Restoration

Both series ended normally. Owned ARM core/supervisor/monitor processes and
PC Xray/Node servers stopped; router test logs were retrieved, then the exact
owned /tmp/memory-ab-direct-20261104 tree was removed. No router test listener
remained. Package-list hash, Forkop UCI hash, running service state, and both
working sing-box PID/executable hashes matched the pre-test snapshot exactly.
No working-core replacement, service restart, router firewall/configuration
edit or package installation. Windows Firewall remains in the user-selected
state; the agent did not toggle profiles. Test ports are no longer needed.

Local untracked evidence: Forkop tmp/memory-ab-direct-20261104, including
configs, binary hashes, events/sample logs, summaries and benchmark scripts.
Earlier tunnel results are retained separately at tmp/memory-ab-20261104.
