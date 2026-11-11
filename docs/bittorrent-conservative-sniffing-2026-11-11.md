# Conservative BitTorrent classification

Implemented on existing dev after 0.0.38. Protocol behavior was compared with
Jolymmiles/Xray-core 297fef3a284910ef307df67978a748a6f71be275; the Go code was
not copied. No version, release or installed router was changed.

- Both ordinary and extended UDP sniffing require an opening uTP SYN. Standalone
  DATA/STATE/FIN/RESET no longer establish BitTorrent in ordinary mode. A flow
  first observed mid-session can therefore remain unclassified.
- The shared SYN validator requires complete, supported extension chains and no
  trailing payload. It prefers a complete TURN ChannelData frame when framing
  overlaps. This is a conservative heuristic: a genuine SYN with the same TURN
  length coincidence also remains unclassified. Arbitrary sequence numbers,
  zero connection IDs and supported SYN extensions remain accepted.
- DHT announce_peer additionally requires a nonempty string token, integer port
  in 0..65535 and a nonzero port unless a nonnegative, nonzero implied_port is
  supplied. The port field is still required with implied_port. Existing DHT
  size/depth/item limits, full-datagram validation and error-only rejection stay.
- HTTP User-Agent alone no longer labels a connection BitTorrent. Ancillary
  update requests and unmarked HTTP seeds retain normal HTTP routing. Tracker
  query and BEP 17 seed signals remain; this does not detect encrypted payloads.

BEP 44 recognition and stricter SYN sequence/connection-ID requirements are
outside this change. Existing flows are not reclassified and no peer-IP cache
is introduced. This change favors fewer false routing/blocking decisions over
recognition of ambiguous traffic.

Verification uses core-runtime with no default features and rust-x: classifier
unit tests, bittorrent_direct, udp_sniff, udp_dns_sniff, udp_quic_sniff, formatting,
Clippy lib/tests with warnings denied, and git diff --check. Router tests cover
IPv4/IPv6 route decisions, split TCP replay, positive SYN/tracker/seed controls,
TURN, missing extension payloads and UA-only HTTP. No real swarm, ARM performance
or live router verification is claimed.

Results: 8 classifier unit tests and 20 integration tests passed. Cargo fmt and
Clippy passed. git diff --check passed from Windows PowerShell (WSL Git cannot
resolve this worktree's Windows gitdir path). The old operator Cargo cache lacked
ml-dsa; checks used the existing /home/evidence/.cargo cache, offline and locked.

## Real client follow-up

Independent libtorrent 2.0.12.0 transferred an owned 4 MiB file over SOCKS5
through the candidate on isolated WSL localhost ports. Extended recognition
selected direct and completed with SHA-256
2b07811057df887086f06a67edc6ebf911de8b6741156e7a2eb1416a4b8b1b2e.
With only HTTP/TLS sniffing and a blocking final route, the same client received
zero payload bytes. DHT/LSD, discovery and encryption were disabled deliberately;
this covers a real cleartext TCP peer handshake, not a public swarm or uTP.
Candidate debug ELF SHA-256:
5d544ed7642ef2f548c37e2c4ad20445a64b8960cfabcecf0759e654107d188e.
Fixture: operator tmp/bt-live-check.py; result: tmp/bt-live-results.json. Owned
core processes were terminated in finally blocks. Existing services were untouched.
OpenWrt 25 VM SSH host-key verification failed; no VM mutations were attempted.

The real client check also passed with only uTP enabled (TCP disabled) through
SOCKS5 UDP on the x86_64 musl release candidate. The 4 MiB payload hash matched;
the disabled-sniff control received zero bytes. Release ELF SHA-256:
c9dfcc3886b967fe5583d0f78a0ec65c0c3fa5560ad88ca2bffcae5fa7fd01ad.
Result: tmp/bt-live-results-utp.json. This supplements the earlier TCP check;
it does not establish arbitrary client or public swarm compatibility.

The same release ELF passed the TCP-only repetition with the same payload hash
and zero-byte negative control (tmp/bt-live-results-release.json).
Locked/offline rust-x workspace release builds passed using the existing
cross-target toolchain and unmodified target flags: x86_64 musl 9,187,136 bytes;
aarch64 musl 7,379,608 bytes. Both fit the CI size budgets. ARM was compiled,
not executed. MIPS and complete hosted CI remain unverified for this local diff.
No publication, main integration or device installation was performed.

## OpenWrt 25 VM follow-up

SSH was recovered using the existing tmp/vm25-saveapply-known_hosts file with
StrictHostKeyChecking=yes. The ED25519 key matched the previously saved key;
the default Windows known_hosts simply had no entry for this VM.

An isolated, distinct-basename copy of the verified x86_64 release ELF ran on
OpenWrt 25.12.5 VMware x86/64 in /tmp/xrust-bt-check-20261111. No installed
package, UCI, firewall or service was changed. The real libtorrent TCP case
passed through its SOCKS listener, using a bounded SSH reverse tunnel back to
the owned WSL seeder: 4 MiB, matching payload SHA-256, disabled-sniff control
zero bytes. Evidence: operator tmp/bt-live-results-vm.json and bt-live-check.py.
This is a binary/runtime check, not package installation or VM uTP coverage.
Cleanup passed: the owned process and listener/reverse-forward ports were gone,
and the temporary VM directory was removed. Forkop remained running with the
same working PID 17849. Package-list hash, installed binary, UCI and generated
runtime configuration hashes all matched the captured baseline.
