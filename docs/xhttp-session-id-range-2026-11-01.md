# XHTTP session ID range validation — 2026-11-01

Investigated Forkop X PR #15 at 3ece8cd17ba75a262ac90df2646e4f887375a85e.
Rust X source: existing dev checkout, base 665ac15cdc112988d39385a3f59628f6f10370d5.
The PR supplied the reproducible Base62 / 4-8 case; its filtering commits were not merged.

## Cause and change

Xray v26.10.21 infra/conf/transport_method.go roomSize sums table_size^n for every n in the inclusive configured range. Sing-Box X does the same in sessionIDRoom. Rust X incorrectly considered table_size^minimum only.

https://github.com/XTLS/Xray-core/blob/v26.10.21/infra/conf/transport_method.go#L393-L409
https://github.com/XTLS/Xray-core/blob/v26.10.21/infra/conf/transport_method.go#L491-L500

Changed only core-config validation to sum the full range, with saturating arithmetic and an early stop at 2^31. Single-character tables use the range width directly. Existing positivity, syntax and reversed-range checks remain. Session ID generation and transport code are unchanged.

Added 16 table/range cases in both canonical and sing-box alias field forms (32 validation outcomes), covering Base62, hex, decimal and custom alphabets; fixed lengths, valid variable ranges, insufficient space, zero, reversed and malformed ranges.

## Verification

- New regression test failed on unmodified code with the reported 14,776,336 error, then passed with the fix.
- core-config library: 197 passed.
- xhttp_compat: 2 passed.
- rust_x_profile: 6 passed.
- core-config Clippy, all targets, rust-x profile: passed with warnings denied.
- x86_64-unknown-linux-musl release build of core-cli, rust-x profile: passed.
- git diff --check: passed.

OpenWrt 25 VMware at 192.168.1.1: Forkop 2.6.4, installed Rust X 0.0.32.
Synthetic cached subscription with one ordinary valid VLESS outbound and one XHTTP Base62 / 4-8 outbound generated successfully with the installed Forkop generator. Installed Rust X rejected the resulting config; candidate accepted the identical generated config.

| Base62 length | Installed Rust X | Candidate | Sing-Box X reference |
|---|---|---|---|
| 4-8 | reject | accept | accept |
| 4 | reject | reject | reject |
| 5 | reject | reject | reject |
| 4-5 | reject | reject | reject |
| 6 | accept | accept | accept |
| 6-8 | accept | accept | accept |

Reference: sing-box 1.14.2-x-1.0.2.
Candidate SHA256: 310ae53d8321aa05822d9b1df14524cccb158614e88737193e45efc25f8382ad.
Reference SHA256: 0f4870e60ff0aefda3c988a1883396bf9b71ff0ba9b88370fc4804fd5bddb63b.

VM before/final state summaries matched SHA256 347d91f66a3f63cc14521fe99858fb82dcc837547d4b1fb3098bee5a647802f0: package versions, service enabled/running status, working core PID set, installed core and UCI/runtime config hashes. No packages, working configuration or services were changed. Only synthetic fixtures and separate binaries were placed in the owned temporary directory.

## Scope and conclusion

This verifies configuration acceptance, not remote XHTTP payload interoperability or full platform CI. No release, push, main integration or installation was performed.

The specific Base62 / 4-8 case is a Rust X validator compatibility defect, not an intrinsically invalid provider node. PR #15's unconditional filter is unnecessary for this case after the core fix and would remove a node accepted by Sing-Box X. General safe handling of genuinely invalid subscription nodes remains a separate Forkop improvement.
