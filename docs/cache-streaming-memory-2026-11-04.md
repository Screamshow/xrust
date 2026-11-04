# Stream cache.db without a full in-memory image

Base: dev `1fb4496`, after the separate remote-record copy removal.
No version/package/default change.

## Implementation and durability

The bbolt Writer now targets Write + Seek. It writes element headers, then
borrowed keys/values, then bounded zero padding. Even a value spanning many
overflow pages is written directly, without assembling an overflow-page image.
Data pages are allocated/emitted consecutively, so there is no seek/forced
buffer flush per data page. The two metadata pages are patched at the end.

CacheFile::flush uses a 32 KiB BufWriter over the temporary file, flushes the
writer, syncs the file, renames it over the database, then syncs the parent
directory. Errors before rename remove the temporary file and leave the old
database intact. Dirty state clears only after all steps succeed; a directory
sync error still reports replacement and leaves the store dirty for retry.

The owned encode_ref API remains available through Cursor<Vec<u8>>. It is not
used by production CacheFile::flush. Metadata/indices still require memory
proportional to entry count; this is not constant-memory storage of all data.

## Controlled memory results

System counting allocator; existing cache_file_flush_alloc test extended with
mixed-cache and oversized-value controls. The mixed cache contains a 4 MiB
rule-set value and 20000 FakeIP-style records. The oversized-value comparison
uses two paths in the same writer build: encode_ref versus file streaming.
It is not a measurement of complete old/new installed cores.

| Case | Additional peak live allocations |
| --- | ---: |
| Mixed cache flush, file size 5070848 B | WSL 1953049 B; ARM 1953048 B |
| 8 MiB value, complete image in memory | 16797834 B |
| Same 8 MiB value, streamed to file | 36928 B |

The image and streamed files are byte-identical. ARM release test ran three
times on MT6000, with identical allocation results. Large-value streaming has
a test budget below 128 KiB; mixed-cache flush must allocate less than one
complete database image. WSL used a debug test build, ARM used release; the
agreement in allocation counts does not make their timing comparable.

These are Rust live allocations above the pre-existing input/store. They are
not process RSS/VmHWM, kernel page cache, whole-router RAM, power or throughput.
No percentage reduction of total core memory is claimed.

## Verification

- Frozen writer-bytes fixture passed, covering unsorted entries, nested/empty
  buckets, binary keys, sequences, overflow values and branch-of-branch pages.
- Historical cache byte compatibility and list/FakeIP restoration passed.
- Corrupt database tests and metadata selection passed.
- Fault injection passed for a partial output write, metadata seek and final
  writer flush. Runtime partial-write failure removes the temp file and keeps
  the old database; pre-rename errors, directory-sync failure and retry tests passed.
- Remote-list fetch/update/HTTPS/recovery tests passed.
- Go 1.27.0 with go.sum-pinned bbolt 1.5.0 independently read the generated
  database; the runtime also loaded a Go-created cache database. Go dependencies
  were fetched from the official proxy because they were absent from its cache.
- 57 distinct Linux tests executed successfully; the fixture generator remained
  ignored. Go-dependent legs were rerun with an actual Go toolchain after the
  initial invocation without Go on PATH.
- Clippy for core-experimental/core-runtime all targets with warnings denied
  passed. Formatting and git diff whitespace checks passed.

ARM test executable SHA-256:
`4131f50410d848cd30c9366ab4b68af8c825c2b5ec66ef2a14c67729e87f8ab5`.
Raw local evidence, not committed: Forkop `tmp/cache-stream-arm-results.txt`
and `tmp/cache-stream-router-{before,after}.txt`.

## Router restoration

Only the owned /tmp/cache-stream-20261104 executable/directory was staged and
then removed. Test databases used owned temporary paths and were cleaned up.
Packages, Forkop running state/UCI hash and both working sing-box PID/executable
hashes matched before/after. No working-core replacement, package install,
firewall/configuration edit or service restart. No full platform/package CI
claim is made.
