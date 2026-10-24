# domain_regex and mmap rule sets

## Regex syntax

sing-box compiles `domain_regex` with Go `regexp` (RE2 syntax, Perl flags).
Xrust uses the Rust `regex` crate. The two are close but not identical.

Translated by Xrust (rule sets, route rules, DNS rules, `check`):

- `\Q...\E`: everything up to the first `\E`, or to the end of the pattern,
  is literal text, backslashes included. `\Q` inside a character class and
  a stray `\E` are errors in both.

Known differences that are not translated (checked against sing-box 1.14.3
`rule-set match`):

| Pattern | sing-box | Xrust |
|---|---|---|
| `a{1001}` (repeat count over 1000) | error | accepted |
| `a**` (nested repetition) | error | accepted |
| `(?x) a` (verbose flag) | error | accepted |

Rejected by both: `\C`, `\Z`, `\k<n>`, `(unclosed`. Accepted by both:
`(?<n>a)`, `\pN`, `[[:word:]]`, `(?U)a+`, `\z`.

This list comes from spot checks. It is not a full compatibility claim:
other patterns may still behave differently. A pattern that only Xrust
accepts makes a config that sing-box rejects; keep shared configs to the
common syntax.

## mmap (TSRS) rule sets

A TSRS image holds one OR over `domain`, `domain_suffix`, `domain_keyword`,
destination `ip_cidr` and destination `port`/`port_range` for the whole set.
It has no place for `domain_regex`, `invert`, logical rules, `network`,
source address or source port, and no way to require two groups at once
(a rule with both a destination and a port becomes "either").

When `mmap: true` (or remote `mode: "mmap"`) is set on a set whose rules
need any of those, Xrust loads it into memory instead and logs
`rule-set <tag>: mmap cannot keep <reason>, using memory rules`. This
applies to inline and local sets, remote downloads, the remote
`initial_path` and hot reload. For a remote set the old `.tsrs` cache file
of that set is removed, so a restart restores it from `cache.db` into memory.
A set that fits still goes to TSRS. Memory use for a set that falls back is
that of a normal (non-mmap) set.

Limitation: an already built `.tsrs` file has no record of what was dropped
when it was made, so it is used as it is:

- a local rule set whose file is `.tsrs`;
- a remote download whose body is TSRS;
- the remote `initial_path` when it is a `.tsrs` file;
- at remote start, a `.tsrs` cache written by an earlier version for a set
  with such rules. It is used until the next full download, which
  reloads the set into memory and removes the file (a TSRS delta update
  patches the old file instead). Deleting the cache file avoids the wait.
