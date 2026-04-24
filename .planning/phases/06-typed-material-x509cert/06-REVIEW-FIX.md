---
phase: 06-typed-material-x509cert
fixed_at: 2026-04-24
review_path: .planning/phases/06-typed-material-x509cert/06-REVIEW.md
iteration: 1
findings_in_scope: 1
fixed: 1
skipped: 0
status: all_fixed
---

# Phase 6: Code Review Fix Report

**Fixed at:** 2026-04-24
**Source review:** `.planning/phases/06-typed-material-x509cert/06-REVIEW.md`
**Iteration:** 1

**Summary:**
- Findings in scope: 1 (WR-01 only — Info items IN-01..IN-08 deferred per `fix_scope: critical_warning`)
- Fixed: 1
- Skipped: 0

## Fixed Issues

### WR-01: PEM path silently accepts trailing data after `-----END CERTIFICATE-----`

**Files modified:** `src/payload/ingest.rs`, `tests/material_x509_ingest.rs`
**Commit:** `a12d6ec`
**Applied fix:**

Added a trailing-bytes rejection gate on the PEM path of `ingest::x509_cert`.
The `pem_rem` slice returned by `x509_parser::pem::parse_x509_pem` (bytes
after the first `-----END CERTIFICATE-----`) is now inspected; any
non-whitespace byte returns `Error::InvalidMaterial { variant: "x509_cert",
reason: "trailing bytes after certificate" }` — identical shape to the
existing DER-path rejection.

Reason-string reuse is deliberate: it keeps the oracle-hygiene surface flat
(same user-facing Display across both paths, same entry in
`EXPECTED_REASONS` in `tests/x509_error_oracle.rs`, no new `reason` label to
add). This honors the load-bearing constraint from `CLAUDE.md` that
`Error::InvalidMaterial { reason }` must be a curated short literal.

Trailing ASCII whitespace (LF, CRLF, spaces, tabs) is tolerated — matches
OpenSSL's convention of appending a final `\n` after the END marker and
avoids breaking realistic PEM files.

Added three regression tests in `tests/material_x509_ingest.rs`:

1. `x509_cert_pem_with_trailing_second_cert_rejected` — the canonical WR-01
   case: two concatenated PEM-armored certs must be rejected rather than
   silently dropping the second.
2. `x509_cert_pem_with_trailing_junk_rejected` — arbitrary non-whitespace
   bytes after the END marker are rejected.
3. `x509_cert_pem_with_trailing_whitespace_accepted` — boundary case: extra
   `\n\n   \r\n\t` after the END marker still parses, so OpenSSL-produced
   PEM files continue to work.

**Dual-pipeline note (addressed during fix).**
The reviewer flagged `src/preview.rs:56-65` as a "duplicated invariant"
parser entry point that also performs a trailing-bytes check. I confirmed
no change is needed there: `render_x509_preview` is only reached in
`run_receive` on bytes that have already been through `ingest::x509_cert`
(sender side) and round-tripped through JCS (receiver side) — i.e. it
operates on canonical DER that has already passed the stricter gate.
The preview-level check remains as a belt-and-braces defence inside the
module that owns the parser import (D-P6-09), matching the oracle-hygiene
contract. No caller can reach preview with a multi-PEM input, so the
concatenated-cert smuggling path is not reachable via preview.

## Verification

- `cargo test --features mock` — all tests pass (12 tests in
  `material_x509_ingest.rs` including the 3 new WR-01 regression tests;
  `x509_error_oracle.rs` still green without list changes since the
  reason string is an existing literal).
- `cargo fmt --check` — clean.
- `cargo clippy --all-targets -- -D warnings` — clean.

## Follow-ups (Info, out of scope for this iteration)

Not fixed this pass (scope was `critical_warning`):

- **IN-01** add an integration test for the PEM wrong-label reject arm.
- **IN-02** `render_x509_preview` re-parses the cert (defensive, accepted).
- **IN-03** `expect()` in base64→UTF-8 path in `pem_armor_certificate`.
- **IN-04** `write!`/`writeln!`-to-String `.expect()` noise in `preview.rs`.
- **IN-05** `render_serial_hex` leading-zero stripping produces odd-length
  hex; diverges from `openssl x509 -serial` convention.
- **IN-06** `expired_or_valid_tag` fail-open on clock failure semantics.
- **IN-07** no explicit Clap test pinning `MaterialVariant::GenericSecret`
  default.
- **IN-08** stale module docstring in
  `phase2_material_variants_unimplemented.rs`.

These can be addressed in a follow-up polish pass or rolled into the next
milestone's first cleanup phase.

---

_Fixed: 2026-04-24_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
