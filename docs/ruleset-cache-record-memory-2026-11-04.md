# Avoid the intermediate remote rule-set payload copy

Base: dev `8cba1c9`. Scoped follow-up to sniff-prefix lifetime and shared uTLS
templates; no version/package/default change.

## Change

RemoteRuleSet::save_to_cache previously cloned the downloaded content and ETag
into SavedBinary, then serialized them into a second owned buffer. It now
passes a SavedBinaryRef to marshal_ref, borrowing the response while building
the owned persistent record. Encoding completes before acquiring the cache
mutex. The record itself still owns its data when inserted into the cache.

The owned SavedBinary/marshal API remains available and delegates to the same
encoder. Capacity includes ETag length and maximum varint/metadata overhead,
avoiding growth of a payload-sized output buffer with longer ETags.

Record bytes/version, timestamp, ETag and URL identity are preserved. CacheFile
flush, atomic replacement, file/directory sync, dirty state and retry behavior
are unchanged. This does not implement streaming of the complete database
image, stale-record pruning or zero-copy loading/touching of cached records.

## Allocation verification

saved_binary_alloc uses System with a counting allocator and a 4 MiB payload,
256-byte ETag and identical timestamp/URL hash. The owned control clones the
payload/ETag before encoding; the borrowed mode encodes directly. Both modes
use the same encoder, isolating the eliminated intermediate copy rather than
comparing complete old/new core binaries. Original input memory is excluded
from the additional allocation counts.

Linux WSL debug results:

| Mode | Peak additional live allocations |
| --- | ---: |
| Owned intermediate | 8389181 B |
| Borrowed input | 4194621 B |
| Difference | 4194560 B (4 MiB plus the ETag) |

The test also requires byte-identical output, successful decode and only one
record-sized allocation for borrowed encoding. This measures live Rust
allocations during record construction, not process RSS/VmHWM, entire cache
flush peak or whole-router RAM. Benefits depend on the list size and overlap
with other allocations; no throughput/CPU percentage is claimed.

## Verification and restoration

- WSL: 40 executed tests passed: cache_file 10, cache_file_compat 5,
  cache_file_corrupt 2, cache_file_flush_alloc 1, saved_binary_alloc 1,
  route::rule_set_remote 15 and cache_file unit tests 6. The fixture generator
  was ignored as intended and is not counted as a passed check.
- Coverage includes old-cache byte compatibility, list/FakeIP restoration,
  failed flush preservation, sync failure/retry, HTTPS/certificate rejection,
  HTTP 304 and list-update recovery.
- Clippy for core-runtime all targets with warnings denied passed. Formatting
  and git diff whitespace checks passed.
- ARM release test executable ran three times on MT6000 with System allocator;
  all assertions passed and allocation figures exactly matched the WSL table.
  SHA-256: `c1990ea7cb1a9e2698c70759b474292bf9354546d97c1e779973c81a9935532a`.
- Only the owned `/tmp/cache-record-20261104/test` executable/directory was
  created on the router and then removed. Packages, service running state,
  Forkop UCI hash, and both working sing-box PID/executable hashes matched
  before/after. No service/configuration/firewall/package changes were made.

Raw local evidence, not committed: Forkop `tmp/cache-record-arm-results.txt`
and `tmp/cache-record-router-{before,after}.txt`. No full platform CI or
package/lifecycle verification is claimed for this scoped source change.
