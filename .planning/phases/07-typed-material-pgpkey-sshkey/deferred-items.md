# Phase 07 — Deferred Items

Items discovered out-of-scope for plans in this phase. Track for future cleanup
plans / a dedicated `chore:` commit.

## From Plan 08 (SSH ship gate)

### RUSTSEC-2026-0009 — `time` crate Denial of Service via Stack Exhaustion

- **Crate:** `time 0.3.41`
- **Pulled by:** `x509-parser 0.16.0` (transitive) and `chrono` (transitive)
- **First seen during Plan 08 verification:** `cargo audit` reports this
  alongside the documented RUSTSEC-2023-0071 (rsa Marvin attack, accepted
  via Plan 04 in `deny.toml`).
- **Date of advisory:** 2026-02-05 — POSTDATES Phase 6 (`x509-parser` integration)
  and Phase 7 Plan 01 (`pgp 0.19.0` integration). Was not present at those
  ship times; surfaced after the advisory database was updated.
- **Cipherpost exposure:** `time` is used internally by chrono for date
  parsing + by x509-parser for cert validity timestamps. Cipherpost does NOT
  parse attacker-controlled `time` values — chrono's local-time call uses
  the system clock, x509-parser parses validity windows under the strict
  RFC 5280 profile (which has fixed-width date forms). Stack-exhaustion
  exposure is LOW.
- **Recommended action:** Wait for `time` upstream patch, then `cargo update -p time`
  in a follow-up `chore: bump time + cargo audit clean` plan. Add a
  `deny.toml [advisories] ignore` entry IF the audit is gating CI before
  the upstream patch lands.
- **Out of scope for Plan 08** — pre-existing vulnerability not introduced by
  this plan; tracked per executor scope-boundary rule.

### `cargo-deny` advisory-db parse error: unsupported CVSS version 4.0

- **Tool:** `cargo deny check`
- **Symptom:** `failed to load advisory database: ... unsupported CVSS version: 4.0`
  parsing `astral-tokio-tar/RUSTSEC-2026-0066.md`.
- **Root cause:** newer RUSTSEC advisories carry CVSS 4.0 strings; older
  `cargo-deny` versions only support CVSS 3.x. NOT a cipherpost code issue.
- **Recommended action:** `cargo install --force cargo-deny` to pick up the
  latest version, OR pin a newer `cargo-deny` in CI's setup step.
- **Out of scope for Plan 08** — toolchain issue, not introduced by this plan.

### Pre-existing fmt drift in unrelated files

Per Plan 05 + Plan 06 + Plan 07 SUMMARYs: `src/payload/{ingest,mod}.rs` +
`src/preview.rs` carry pre-existing `cargo fmt --check` diffs unrelated to
Plan 08's edits. `cargo fmt --check` on the new Plan 08 test files is clean.
Recommended: dedicated `chore: cargo fmt repo-wide` plan after Phase 7 closes.

### Pre-existing clippy `uninlined_format_args` warnings

Per Plan 06 SUMMARY: `build.rs:17` + 19 `src/preview.rs` warnings predate
Plan 06. Plan 08's new test files add zero clippy warnings of any class
(test files use the established `assert!(a, "msg: {:?}", v)` pattern that
clippy accepts). Recommended: same `chore: cargo fmt + clippy` plan as above.
