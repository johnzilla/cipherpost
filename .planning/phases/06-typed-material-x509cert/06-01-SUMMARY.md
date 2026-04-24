---
phase: 06-typed-material-x509cert
plan: 01
subsystem: payload
tags: [rust, x509, payload, parser, typed-material, x509-parser, serde, error-oracle]

# Dependency graph
requires:
  - phase: 02-send-receive-and-explicit-acceptance
    provides: "Material::GenericSecret variant pattern, base64_std serde helper, enforce_plaintext_cap, Envelope + JCS round-trip contract"
  - phase: 01-foundation
    provides: "Error enum with thiserror + #[source] chain hygiene; exit_code dispatcher; JCS serialization via serde_canonical_json"
provides:
  - "Material::X509Cert { bytes: Vec<u8> } struct variant (was unit)"
  - "Material::as_x509_cert_bytes() accessor with variant-mismatch error"
  - "Material::plaintext_size() exhaustive method (all 4 variants)"
  - "payload::ingest submodule with x509_cert(raw) + generic_secret(bytes)"
  - "Error::InvalidMaterial { variant, reason } variant (exit 1, generic Display)"
  - "x509-parser 0.16 dependency with verify OFF (ring/aws-lc absent)"
  - "Extended Debug redaction for X509Cert([REDACTED N bytes])"
affects: [06-02, 06-03, 06-04, 07-pgp-ssh, 08-pin-burn]

# Tech tracking
tech-stack:
  added:
    - "x509-parser 0.16.0 (MIT/Apache-2.0; Rusticata family; default-features = false; verify feature OFF)"
    - "Transitive deps pulled by x509-parser 0.16: asn1-rs 0.6.2, der-parser 9.0.0, oid-registry 0.7.1, rusticata-macros 4.1.0, time 0.3.41, nom 7.1.3"
  patterns:
    - "payload/ directory module layout (src/payload/mod.rs + src/payload/ingest.rs) — first multi-file module in src/"
    - "Ingest-layer normalization: raw bytes → typed Material via pure Result<Material, Error>-returning functions; Phase 7 extends with ingest::pgp_key() + ingest::ssh_key()"
    - "Variant-mismatch errors use Error::InvalidMaterial with `variant_tag()` helper for snake_case wire tag lookup"
    - "Uniform Debug redaction across all byte-carrying Material variants (pitfall #7)"

key-files:
  created:
    - "src/payload/ingest.rs — PEM/DER sniff, strict-DER validation, trailing-bytes check, generic-reason Error::InvalidMaterial"
  modified:
    - "src/payload/mod.rs (renamed from src/payload.rs) — X509Cert struct variant, accessor, plaintext_size, extended Debug, variant_tag helper, pub mod ingest declaration"
    - "src/error.rs — new Error::InvalidMaterial { variant, reason } variant + exit_code arm"
    - "src/flow.rs — material_type_string match arm updated to `Material::X509Cert { .. }` pattern"
    - "tests/phase2_material_variants_unimplemented.rs — X509Cert case rewritten to construct struct variant; non-generic-tag serde test drops X509Cert (tested elsewhere)"
    - "Cargo.toml — added x509-parser 0.16"
    - "Cargo.lock — pinned time 0.3.41 (MSRV-driven downgrade from 0.3.47)"

key-decisions:
  - "AD-2 resolved: new src/payload/ingest.rs file, not inline `pub mod ingest { ... }` — Phase 7 will add pgp_key() + ssh_key() peer functions and file-level grouping reads cleaner"
  - "Transitive time 0.3.47 downgraded to 0.3.41 via Cargo.lock to keep rustc 1.85.1 MSRV green (0.3.47 requires 1.88.0)"
  - "Error::InvalidMaterial does not use #[source] or #[from] — the reason: String is the sanitation gate; wrapping x509_parser::X509Error would bait a Display-chain leak"
  - "variant_tag() helper is a private free-function, not an impl-method — matches the existing `material_type_string` convention in flow.rs"

patterns-established:
  - "payload/ directory module with per-variant ingest functions (Phase 7 will add ingest::pgp_key + ingest::ssh_key next to x509_cert)"
  - "Error::InvalidMaterial reason strings are short, curated literals — never wrap parser-internal error types; oracle hygiene enforced by convention"
  - "Material byte accessors return Result<&[u8], Error>; mismatch error uses Error::InvalidMaterial with `variant: \"<snake>\"` + reason: `\"accessor called on wrong variant\"`"

requirements-completed: []  # Plan 01 lays foundation for X509-01..03, 06, 08; checkbox completion waits on Plans 02-04 wiring (acceptance banner, CLI flag, round-trip). Phase VERIFICATION.md will mark requirements at phase close per traceability-table convention.

# Metrics
duration: 17min
completed: 2026-04-24
---

# Phase 6 Plan 01: Typed Material X509Cert Foundation Summary

**`Material::X509Cert` promoted from unit to struct variant with canonical-DER bytes; `payload::ingest` submodule added with PEM/DER sniff + strict-DER validation + trailing-bytes check; `Error::InvalidMaterial` variant shipped with generic Display and exit 1; `x509-parser 0.16` pulled with `verify` feature OFF (ring/aws-lc absent from dep tree).**

## Performance

- **Duration:** ~17 min
- **Started:** 2026-04-24T18:22:Z (approx — phase execution start)
- **Completed:** 2026-04-24T18:39:26Z
- **Tasks:** 3 / 3
- **Files modified:** 4 (`src/error.rs`, `src/flow.rs`, `src/payload/mod.rs` — renamed from `src/payload.rs`, `tests/phase2_material_variants_unimplemented.rs`, `Cargo.toml`, `Cargo.lock`)
- **Files created:** 1 (`src/payload/ingest.rs`)
- **Tests:** 107 passing under `cargo test --features mock` (+9 vs. 98 at end of Phase 5)

## Accomplishments

- `Material::X509Cert` converted from unit variant to `{ bytes: Vec<u8> }` struct variant; wire shape flips from `{"type":"x509_cert"}` to `{"type":"x509_cert","bytes":"<base64-std>"}` using the existing `base64_std` serde helper with no configuration change.
- `as_x509_cert_bytes()` accessor parallel to existing `as_generic_secret_bytes()`; variant mismatch returns `Error::InvalidMaterial { variant: "<snake>", reason: "accessor called on wrong variant" }` (D-P6-15) — preserves the original accessor's signature (no migration).
- `Material::plaintext_size()` method returns the raw-byte length for each variant exhaustively (GenericSecret: `bytes.len()`; X509Cert: `bytes.len()`; PgpKey/SshKey: 0 placeholders for Phase 7). Feeds `enforce_plaintext_cap` pre-encrypt (D-P6-16 / X509-06).
- Manual Debug redaction uniform across all byte-carrying variants: `X509Cert([REDACTED N bytes])` mirrors `GenericSecret([REDACTED N bytes])` — no per-variant carve-outs; Phase 7 SSH/PGP secret keys reuse this shell.
- `src/payload/ingest.rs` module with `x509_cert(raw)` implementing: ASCII-whitespace-skip sniff, PEM vs DER branch, non-CERTIFICATE label rejection, strict-DER validation via `x509_parser::parse_x509_certificate`, explicit trailing-bytes check (D-P6-07). `generic_secret(bytes)` trivial symmetry wrapper.
- `Error::InvalidMaterial { variant: String, reason: String }` — generic Display literal `"invalid material: variant={variant}, reason={reason}"`; NO `#[source]` or `#[from]` (would bait `X509Error::InvalidCertificate` leak via `err.source()`). Explicit `exit_code()` arm maps to exit 1 (X509-08; distinct from exit 3 sig failures).
- `x509-parser = { version = "0.16", default-features = false }` pulled with `verify` feature OFF; `cargo tree | grep -E "ring|aws-lc"` returns no matches (belt-and-suspenders even though 0.16 has `default = []`).

## Task Commits

1. **Task 1: x509-parser 0.16 dependency + clean dep tree** — `2acee87` (chore)
2. **Task 2: Error::InvalidMaterial variant (exit 1, generic Display)** — `e5102ae` (feat)
3. **Task 3: Typed Material::X509Cert + payload::ingest submodule** — `d27034a` (feat)

**Plan metadata commit:** pending (this SUMMARY.md + STATE.md + ROADMAP.md)

## Dep Tree Observations

Captured per the plan's output spec:

- `cargo tree -p x509-parser` first line: `x509-parser v0.16.0` (expected 0.16.x; not 0.17, not 0.18 — available 0.18.1 rejected per plan because 0.17 breaks to nom 8.0).
- `cargo tree | grep -E "ring|aws-lc"` — empty output (grep exit 1 = PASS; no matches).
- Transitives added: `asn1-rs 0.6.2`, `der-parser 9.0.0`, `oid-registry 0.7.1`, `rusticata-macros 4.1.0`, `time 0.3.41`, `synstructure 0.13.2`, `num-bigint 0.4.6`, `num-integer 0.1.46`, `num-conv 0.1.0`, `num-traits 0.2.19`, `nom 7.1.3`, `data-encoding 2.11.0`, `deranged 0.4.0`, `time-core 0.1.4`, `time-macros 0.2.22`, `powerfmt 0.2.0`.

## Error::InvalidMaterial Reason Strings (for Plan 04 enumeration test)

Per the plan's output spec — list of every `reason` string literal constructed in this plan:

| Call site | `variant` | `reason` |
|-----------|-----------|----------|
| `src/payload/ingest.rs` x509_cert PEM-body path | `"x509_cert"` | `"PEM body decode failed"` |
| `src/payload/ingest.rs` x509_cert PEM-label path | `"x509_cert"` | `"PEM label is not CERTIFICATE"` |
| `src/payload/ingest.rs` x509_cert DER-parse path | `"x509_cert"` | `"malformed DER"` |
| `src/payload/ingest.rs` x509_cert trailing-bytes path | `"x509_cert"` | `"trailing bytes after certificate"` |
| `src/payload/mod.rs` as_x509_cert_bytes mismatch | `"generic_secret" / "pgp_key" / "ssh_key"` (dynamic via variant_tag) | `"accessor called on wrong variant"` |

Plan 04's enumeration test should construct each of these explicitly and assert (a) the Display string contains neither `X509Error`, `x509_parser::`, `nom::`, nor `parse error at offset`, and (b) the `exit_code` returns 1.

## Decisions Made

- **AD-2 resolved as "new file":** `src/payload.rs` → `src/payload/mod.rs` directory module with `src/payload/ingest.rs` sibling. The pattern-map flagged inline `pub mod ingest { ... }` as the lower-friction option; the plan explicitly specified a new file to keep Phase 7's `pgp_key()` and `ssh_key()` additions from fattening a single file. Went with the plan's directive (new file). `git mv` preserves history.
- **`variant_tag` is a private free-function, not an impl-method.** Mirrors `material_type_string` at `src/flow.rs:710` — same convention (free fn, snake_case wire tag lookup, exhaustive match over all 4 Material variants). Avoids duplication concern: `material_type_string` returns `&'static str` for acceptance-banner rendering; `variant_tag` returns the same strings but lives in `payload/mod.rs` where it's consumed. Phase 7 can trivially consolidate if desired.
- **Ingest module tests are lightweight.** Full integration suite (happy DER, happy PEM LF + CRLF, wrong-label rejection, BER rejection, trailing-bytes rejection, end-to-end round trip) lives in Plan 04 per 06-01-PLAN comment. Plan 01's unit tests cover only trivial paths — a green `cargo test --lib` on the ingest module without requiring a fixture file.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] MSRV-driven `time` downgrade**
- **Found during:** Task 1 (cargo build after adding x509-parser)
- **Issue:** x509-parser 0.16's transitive `time 0.3.47` requires rustc 1.88.0; cipherpost's MSRV is `rust-version = "1.85"` per Cargo.toml. Fresh `cargo build` failed with `time@0.3.47 requires rustc 1.88.0`.
- **Fix:** Ran `cargo update time --precise 0.3.41` to pick the latest 1.85-compatible version. Transitively downgraded `time-core 0.1.4`, `time-macros 0.2.22`, `deranged 0.4.0`, `num-conv 0.1.0`. No changes to `Cargo.toml` dep spec — all pinning is in `Cargo.lock`.
- **Files modified:** `Cargo.lock`
- **Verification:** `cargo build` green; `cargo test --features mock` 107 tests pass; `cargo fmt --check` + `cargo clippy --all-targets -- -D warnings` clean.
- **Committed in:** `2acee87` (Task 1 commit, alongside the x509-parser addition)

**2. [formatter] cargo fmt applied to `Material::X509Cert { bytes: vec![0; 123] }.plaintext_size()` in a test assertion**
- **Found during:** Task 3 (final `cargo fmt --check`)
- **Issue:** The inline struct-literal-then-method-call on one line exceeded the rustfmt width and was broken across 4 lines. Not a logic change — pure formatting.
- **Fix:** `cargo fmt` applied; re-verified tests still pass.
- **Files modified:** `src/payload/mod.rs` (lines 294-298)
- **Committed in:** `d27034a` (Task 3 commit)

---

**Total deviations:** 2 auto-fixed (1 blocking MSRV fix, 1 formatter adjustment)
**Impact on plan:** Both are cosmetic/toolchain-level — the MSRV pin is a lockfile-only change that preserves the exact Cargo.toml dep spec the plan specified; the fmt adjustment is a mechanical rustfmt response. No scope creep; no architectural decisions altered.

## Issues Encountered

- None beyond the MSRV pin above. The `git mv src/payload.rs src/payload/mod.rs` executed cleanly; Rust's module resolution picked up the directory module with no rustc complaint.

## Threat Flags

None introduced by this plan beyond what's already in the phase threat model (T-06-01..06). The new `src/payload/ingest.rs` entry point is the only new trust boundary and is explicitly covered by T-06-01 (parser hardening), T-06-02 (error-oracle hygiene), T-06-03 (DER canonicity), T-06-04 (memory DoS — accepted with Plan 03 cap-check integration), T-06-05 (Debug leak), T-06-06 (supply-chain).

## User Setup Required

None — library-layer changes only. No new env vars, no new CLI flags, no external services. CLI wiring comes in Plans 02-03.

## Next Phase Readiness

- **Plan 02 (clap `--material` flag) ready:** The typed-Material surface is in place; Plan 02 only needs to add `MaterialVariant` ValueEnum + `--material` flag + `Send { material: MaterialVariant, … }` field + `main.rs` dispatch arm.
- **Plan 03 (`run_send` variant dispatch) ready:** `payload::ingest::x509_cert(raw)` + `Material::plaintext_size()` already exist; Plan 03 threads `--material` into `run_send`, calls ingest, then `enforce_plaintext_cap(material.plaintext_size())` per the CONTEXT §specifics cap-check order.
- **Plan 04 (acceptance banner preview + JCS fixture + round-trip test) ready:** `src/preview.rs` (new module) + fixture cert bytes + `tests/material_x509_ingest.rs` + `tests/x509_roundtrip.rs` all depend on the typed-Material library surface now in place.
- **No blockers.**

## Self-Check: PASSED

- `src/payload/ingest.rs` — FOUND
- `src/payload/mod.rs` — FOUND (renamed from `src/payload.rs`, verified via `git log --oneline --follow`)
- `src/payload.rs` — correctly absent (git rename)
- Commit `2acee87` — FOUND (`chore(06-01): add x509-parser 0.16 dependency (verify feature OFF)`)
- Commit `e5102ae` — FOUND (`feat(06-01): add Error::InvalidMaterial variant (exit 1, generic Display)`)
- Commit `d27034a` — FOUND (`feat(06-01): typed Material::X509Cert + payload::ingest submodule`)
- `cargo build` — exit 0
- `cargo test --features mock` — 107 passing, 0 failed, 5 ignored (pre-existing `regenerate_*_fixture` etc.)
- `cargo fmt --check` — exit 0
- `cargo clippy --all-targets -- -D warnings` — exit 0
- `cargo tree -p x509-parser | head -1` — `x509-parser v0.16.0`
- `cargo tree | grep -E "ring|aws-lc"` — exit 1 (no matches; PASS)

---
*Phase: 06-typed-material-x509cert*
*Completed: 2026-04-24*
