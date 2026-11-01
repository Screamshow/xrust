# BitTorrent HTTP recognition follow-up

Scope: Xrust dev after 0.0.32, following the differential comparison with UwuRay
69eb7273ba627246509eecc3ce406fbb94434ba9. No version bump, release, installation
or Forkop frontend/backend change is part of this follow-up.

## Behavior

- The optional extended HTTP classifier requires a three-part request line with
  single spaces, a nonempty target without ASCII whitespace/control bytes and
  HTTP/1.0 or HTTP/1.1 before it can create a BitTorrent routing exception.
  The ordinary HTTP classifier with extended recognition disabled is unchanged.
- BEP 17 HTTP seeds can match GET requests with a percent-decoded 20-byte
  info_hash and an unsigned decimal piece number fitting u32. Malformed escapes,
  wrong hash length, duplicate hash/piece fields and invalid piece numbers do
  not supply this signal. Existing tracker and UA signals remain independent.
- The UA prefix list grows from 6 to 33 names, including BiglyBT, BitComet,
  LibreTorrent, TorrServer, Flud and WebTorrent. Names still require end of
  value, slash or space; arbitrary occurrences inside a browser UA do not match.
- Existing tracker conditions, DHT limits, uTP validation and UDP classification
  are unchanged. LSD, MSE/PE and HTTPS content recognition are not added.

The seed check uses borrowed slices, counters and stack-held options; it does
not decode into a new buffer or add per-peer state. This is a code property,
not a measured CPU/RSS or throughput result. A recognized torrent client's HTTP
UA can still classify its ancillary HTTP requests, not only content downloads.

## Verification

Passed: formatting check, 12 focused library tests, 4 BitTorrent routing tests,
9 UDP sniffing integration tests and Clippy for core-runtime lib/tests under
the rust-x profile with warnings denied. The final 642-case Router comparison
also passed its TCP byte-preservation assertions.

Compared with the released baseline, exactly 29 corpus classifications changed:
27 additional UA strings and the BEP 17 seed now match; the invalid HTTP-version
request no longer matches. All UDP cases retain their results. The candidate
matches 33 of the 82 generated UA strings; this deliberately does not claim
coverage of every UwuRay name or UA formatting variation. None of the control,
random, opaque, ambiguous or malformed groups receives a BitTorrent label in
the candidate. The diff is retained as candidate-delta-20261101.json.

Focused Rust tests cover classifier positives and near misses, routing through
the actual Router, split TCP input with preserved bytes, IPv4/IPv6 contexts,
disabled extension behavior, DHT and other UDP protocol controls. These are
local Linux tests, not a live router throughput or Internet swarm measurement.

The repeat corpus and before/after results are retained outside the source tree
under tmp/bt-comparison-20261031 in the operator workspace; the comparison report
for the released baseline is unchanged. Candidate output is separately named
xrust-candidate-20261101.json. The corpus has 642 synthetic cases, including 500
random UDP cases and 82 generated UA strings, and is not a representative
distribution for estimating real-world recognition percentages.

Protocol reference: https://www.bittorrent.org/beps/bep_0017.html
