---
phase: 06-typed-material-x509cert
plan: 02
subsystem: preview
tags: [rust, x509, preview, acceptance-banner, rendering, x509-parser, oid-registry]

# Dependency graph
requires:
  - phase: 06
    plan: 01
    provides: "Material::X509Cert { bytes } struct variant; Error::InvalidMaterial variant; x509-parser 0.16 dependency with time 0.3.41 MSRV pin; payload/ingest submodule"
  - phase: 02-send-receive-and-explicit-acceptance
    provides: "format_unix_as_iso_utc helper in flow.rs; Error::InvalidMaterial precedent"
provides:
  - "preview::render_x509_preview(bytes) -> Result<String, Error> — pure function rendering the X.509 acceptance-banner subblock"
  - "pub mod preview declared in src/lib.rs (alphabetical between payload + receipt)"
  - "format_unix_as_iso_utc promoted from private fn to pub(crate) fn for reuse"
  - "OID-to-human key-algorithm mapping (Ed25519, Ed448, RSA-N, RSA-PSS, ECDSA P-256/P-384/P-521/secp256k1) with dotted-OID fallback"
  - "Sanitized error-oracle contract: only `malformed DER` and `trailing bytes after certificate` reasons emitted — no x509-parser internals leak"
affects: [06-03, 06-04, 07-pgp-ssh]

# Tech tracking
tech-stack:
  added: []  # no new Cargo dependencies; x509-parser was already pulled by Plan 01
  patterns:
    - "src/preview.rs as a typed-material rendering module; Phase 7 adds render_pgp_preview + render_ssh_preview as siblings"
    - "OID-based key-algorithm dispatch (not PublicKey-enum-based) — Ed25519/Ed448 surface through PublicKey::Unknown and must be routed via spki.algorithm.algorithm"
    - "Pure-function rendering returning Result<String, Error> — no side effects, caller (TtyPrompter in Plan 03) owns emission"
    - "Char-count-based DN truncation (not byte-slice) — UTF-8-safe per x509-parser Display impl which may emit CJK codepoints"

key-files:
  created:
    - "src/preview.rs — 249 lines; render_x509_preview + 4 private helpers (truncate_display, render_serial_hex, expired_or_valid_tag, render_key_algorithm); 8 unit tests"
  modified:
    - "src/lib.rs — added `pub mod preview;` alphabetically between payload + receipt (1-line change)"
    - "src/flow.rs — `fn format_unix_as_iso_utc` → `pub(crate) fn format_unix_as_iso_utc` + doc-comment note on single-source-of-truth invariant"

key-decisions:
  - "DN rendering uses x509-parser's Display impl (OpenSSL-forward order: C=US, O=..., CN=...) per RESEARCH CORRECTION 1. No RFC 4514 backward-order reversal — the built-in Display matches `openssl x509 -noout -subject` output, which is what engineers' mental model expects."
  - "Key-algorithm detection routes through spki.algorithm.algorithm (the OID), NOT through spki.parsed() → PublicKey enum. Ed25519/Ed448 come through PublicKey::Unknown (RESEARCH CORRECTION 2); only RSA / ECDSA dispatches call spki.parsed() to extract key_size / curve-param OID."
  - "secp256k1 uses dotted-OID string comparison (`curve_oid.to_id_string() == \"1.3.132.0.10\"`) — no exported constant in oid-registry 0.7. Rest of the curve set (P-256/384/521) uses exported constants."
  - "expired_or_valid_tag fails open on SystemTime clock error (returns `[VALID]`). User still sees the NotAfter timestamp and can evaluate — the tag is UX decoration, not a block."
  - "render_x509_preview returns a String with NO leading and NO trailing `\\n` per D-P6-17. Caller owns outer banner layout; TtyPrompter (Plan 03) will emit via an `eprintln!` or `eprint!` with the caller's own newline control."
  - "Golden-string test against the hand-crafted fixture cert is deferred to Plan 04 (fixture lands there). Plan 02 ships the unit-testable internals only: error oracle, truncation helpers, serial hex, and [EXPIRED]/[VALID] tag logic."

patterns-established:
  - "src/preview.rs as the single module that imports x509-parser for rendering paths; ingest.rs is the other (and only other) x509-parser consumer"
  - "Multi-line String building via writeln! macro into a pre-allocated String, with the final line using write! (no trailing newline) — matches the D-P6-17 caller-owned-layout contract"
  - "OID-by-OID dispatch with early-return for each algorithm family; spki.parsed() called only inside the RSA branch (the only branch that needs key_size); curve OID extraction via Option<Any>.as_ref()?.as_oid()?.compare"
  - "Error::InvalidMaterial reuse: same two reason strings (\"malformed DER\", \"trailing bytes after certificate\") as Plan 01's ingest.rs — deduplicated oracle surface across ingest + preview"

requirements-completed: []  # X509-04's machinery ships here but the requirement is checkbox-gated on Plan 03 wiring the subblock into TtyPrompter::render_and_confirm; marked complete by phase VERIFICATION.md at phase close.

# Metrics
duration: 7min
completed: 2026-04-24
---

# Phase 6 Plan 02: X.509 Preview Renderer Summary

**`preview::render_x509_preview(bytes) -> Result<String, Error>` shipped as a pure rendering function in a new `src/preview.rs` module; x509-parser imports stay out of payload/ and flow.rs; `format_unix_as_iso_utc` bumped to `pub(crate)` for reuse without duplicating the civil-from-days arithmetic.**

## Performance

- **Duration:** ~7 min
- **Started:** 2026-04-24T18:47:10Z
- **Completed:** 2026-04-24T18:54:27Z
- **Tasks:** 1 / 1
- **Files created:** 1 (`src/preview.rs`)
- **Files modified:** 2 (`src/lib.rs`, `src/flow.rs`)
- **Tests:** 115 passing under `cargo test --features mock` (+8 vs. 107 at end of Plan 01; all 8 new tests in `preview::tests`)

## Accomplishments

- `preview::render_x509_preview(bytes: &[u8]) -> Result<String, Error>` implements the full D-P6-09 subblock: separator line (`--- X.509 ` + 57 dashes = 61 chars, matching the `===` banner border), Subject, Issuer, Serial, NotBefore, NotAfter (with `[VALID]` / `[EXPIRED]` tag), Key algorithm (human-readable with dotted-OID fallback), and full 64-hex SHA-256 fingerprint over the canonical DER.
- `src/lib.rs` declares `pub mod preview;` alphabetically between `payload` and `receipt` — Phase 7 will add `render_pgp_preview` and `render_ssh_preview` inside the same module.
- `src/flow.rs::format_unix_as_iso_utc` visibility bumped from private `fn` to `pub(crate) fn` — single source of truth for "YYYY-MM-DD HH:MM UTC" formatting across acceptance-banner emission (flow.rs) and typed-material previews (preview.rs). No duplication; no double-" UTC" suffix bug (UAT-2 2026-04-21 pin held).
- OID-to-human key-algorithm mapping covers the top ~10 per CONTEXT.md discretion row: **Ed25519** (OID 1.3.101.112), **Ed448** (1.3.101.113), **RSA-N** (1.2.840.113549.1.1.1, N from `spki.parsed()` → `PublicKey::RSA.key_size()`), **RSA-PSS** (1.2.840.113549.1.1.10), **ECDSA P-256** (EC public key OID + prime256v1 parameter), **ECDSA P-384** (secp384r1), **ECDSA P-521** (secp521r1), **ECDSA secp256k1** (dotted-string match 1.3.132.0.10 — no exported constant in oid-registry 0.7). Unknown algorithm OIDs fall through to `<dotted.oid>` rendering; unknown curve OIDs fall through to `ECDSA <dotted.oid>`.
- Error-oracle hygiene: two sanitized reason strings (`"malformed DER"` and `"trailing bytes after certificate"`) — identical to Plan 01's `payload::ingest::x509_cert` constructions, so the oracle surface across the two callers is deduplicated at exactly 2 strings for parse-failure paths. Source-level grep for `X509Error|nom::|parse error at offset` in `src/preview.rs` returns zero matches.
- 8 unit tests in `preview::tests` cover: parse-fail oracle hygiene (`render_x509_preview_rejects_garbage_generically`), truncation helpers (short + long), serial hex (short + long), `[EXPIRED]` / `[VALID]` tag past/future paths, and the `SEPARATOR_DASH_COUNT = 57` invariant. Full-cert golden-string rendering lands in Plan 04 with the fixture.

## Task Commits

1. **Task 1: src/preview.rs with render_x509_preview; export from lib.rs; promote format_unix_as_iso_utc visibility** — `94b09af` (feat)

**Plan metadata commit:** pending (this SUMMARY.md + STATE.md + ROADMAP.md + REQUIREMENTS.md)

## x509-parser 0.16 API Accessor Paths Used (for Plan 04's golden-string test)

Per the plan's output spec — record the exact accessor paths against `x509_parser::certificate::X509Certificate<'_>`:

| Field | Access path | Return type |
|-------|-------------|-------------|
| Subject DN | `cert.subject().to_string()` | `String` (OpenSSL-forward order per Display impl) |
| Issuer DN | `cert.issuer().to_string()` | `String` (same) |
| Serial (raw bytes) | `cert.tbs_certificate.raw_serial()` | `&'a [u8]` |
| NotBefore (unix) | `cert.validity().not_before.timestamp()` | `i64` |
| NotAfter (unix) | `cert.validity().not_after.timestamp()` | `i64` |
| SPKI | `&cert.tbs_certificate.subject_pki` | `&SubjectPublicKeyInfo<'a>` |
| Algorithm OID | `&spki.algorithm.algorithm` | `&Oid<'a>` |
| Algorithm parameters | `spki.algorithm.parameters.as_ref()` | `Option<&Any<'a>>` |
| OID from Any | `any.as_oid()` | `Result<Oid<'a>, _>` (NOTE: owned Oid — compared via `PartialEq` symmetric) |
| Parsed public key | `spki.parsed()` | `Result<PublicKey<'a>, X509Error>` (called only in RSA branch for key_size) |
| RSA key size | `rsa.key_size()` | `usize` (bits) |
| Curve-OID dotted string | `oid.to_id_string()` | `String` (used for secp256k1 fallback match) |

No accessor renames were needed relative to the plan's code — every method the plan named exists on 0.16.0. The one subtlety is that `Any::as_oid()` returns an **owned** `Oid` (not a reference); comparisons against `OID_EC_P256: Oid<'static>` work because `Oid` derives `PartialEq` and Rust's auto-ref coercion resolves `Oid == Oid<'static>` symmetrically.

## OID Constants Used (from `x509_parser::oid_registry`)

All verified present in oid-registry 0.7.1 (re-exported by x509-parser 0.16):

| Constant | Dotted OID | Purpose |
|----------|-----------|---------|
| `OID_SIG_ED25519` | 1.3.101.112 | Ed25519 key (via OID match, not PublicKey enum) |
| `OID_SIG_ED448` | 1.3.101.113 | Ed448 key (same pattern) |
| `OID_PKCS1_RSAENCRYPTION` | 1.2.840.113549.1.1.1 | RSA key; gate to `spki.parsed()` for key_size |
| `OID_PKCS1_RSASSAPSS` | 1.2.840.113549.1.1.10 | RSA-PSS (direct return) |
| `OID_KEY_TYPE_EC_PUBLIC_KEY` | 1.2.840.10045.2.1 | EC public key; gate to `parameters.as_oid()` for curve |
| `OID_EC_P256` | 1.2.840.10045.3.1.7 | P-256 named curve |
| `OID_NIST_EC_P384` | 1.3.132.0.34 | P-384 named curve |
| `OID_NIST_EC_P521` | 1.3.132.0.35 | P-521 named curve |

**Fallback used:** `"1.3.132.0.10"` string match for secp256k1 (no exported constant in oid-registry 0.7; documented at RESEARCH Focus 4 line 428).

## Helper Functions Beyond the Public API

Per the plan's output spec:

| Function | Visibility | Purpose |
|----------|-----------|---------|
| `truncate_display(s: &str, limit: usize) -> String` | private | Unicode-scalar-value-based truncation with `…` suffix; used for Subject + Issuer DNs |
| `render_serial_hex(raw: &[u8]) -> String` | private | Lowercase hex + `0x` prefix; strip leading zeros; truncate at 16 hex chars with `… (truncated)` |
| `expired_or_valid_tag(not_after_unix: i64) -> &'static str` | private | `[EXPIRED]` vs `[VALID]`; fails open on clock error |
| `render_key_algorithm(cert: &X509Certificate) -> String` | private | OID-first dispatch with dotted-OID fallbacks |

## Decisions Made

- **DN rendering = OpenSSL-forward order via Display impl** (RESEARCH CORRECTION 1). `x509-parser 0.16` does NOT expose `to_rfc4514()`; the built-in Display emits `C=US, O=..., CN=...` which matches `openssl x509 -noout -subject` and security engineers' mental model. CONTEXT.md's reference to "RFC 4514" was shorthand for the same openssl-parity intent. No hand-rolled RDN reversal code — added complexity without user-visible benefit.
- **OID-first key-algorithm dispatch** (RESEARCH CORRECTION 2). Ed25519/Ed448 surface through `PublicKey::Unknown` in x509-parser 0.16 — a PublicKey-enum-based match would miss them entirely. Solution: match on `spki.algorithm.algorithm` (the OID) first; call `spki.parsed()` only inside the RSA branch where `key_size()` is needed. Every Ed/RSA-PSS case returns before any `parsed()` call.
- **Secp256k1 dotted-OID string fallback** (no exported constant). oid-registry 0.7 does not define a constant for secp256k1 (1.3.132.0.10); `curve_oid.to_id_string() == "1.3.132.0.10"` is the documented fallback path. Rest of the top-8 curve set uses exported constants.
- **Fail-open on clock error for `[VALID]` tag.** `SystemTime::now().duration_since(UNIX_EPOCH)` can theoretically return Err if the system clock is set before the epoch. We return `[VALID]` in that case — the user still sees the NotAfter ISO timestamp and can evaluate independently. `[EXPIRED]` is a UX nudge, not a block (X509-04 explicitly: "display but not block").
- **No leading / trailing newline** (D-P6-17). Return string starts with `--- X.509 ` separator and ends with `SHA-256:     <hex>` (no `\n` after). Plan 03's TtyPrompter wiring will emit via `eprintln!("{}", preview_str)` which adds exactly one newline before the TTL line — the banner composes cleanly without double-newline blank lines.
- **Golden-string test deferred to Plan 04.** Plan 02 ships unit-testable internals (error oracle, truncation, serial hex, tag logic, separator width constant); golden-string rendering against a known DER fixture needs the fixture itself, which lands in Plan 04 alongside `tests/fixtures/x509_cert_fixture.der` and the JCS envelope fixture.

## Deviations from Plan

None of substance. The plan's code in `<action>` Step B was implemented verbatim with four micro-adjustments that were within the plan's "fix any compilation errors" guidance:

1. **`if alg_oid == &OID_SIG_ED25519` → `if *alg_oid == OID_SIG_ED25519`.** The plan's form (`&Oid == &Oid<'static>`) compiles fine, but I used the dereferenced form (`Oid == Oid<'static>`) to match how x509-parser itself uses these constants (verified at `x509_parser::verify.rs:40` and `x509_parser::x509.rs:236`). Both forms are equivalent under Rust's `PartialEq` auto-ref; the dereferenced form matches the codebase convention of the upstream crate.
2. **`if let Ok(curve_oid) = params.as_oid()` — `curve_oid` is an owned `Oid` (not `&Oid`).** The plan's comment noted "`as_oid()` returns `Result<&Oid, ...>`"; actually it returns `Result<Oid>` (owned, per `asn1-rs 0.6.2::any.rs:264`'s `impl_any_as!` macro expansion). Comparisons against `OID_EC_P256: Oid<'static>` still work because `Oid: PartialEq` and auto-ref handles the comparison.
3. **`if curve_oid == OID_EC_P256` (not `== &OID_EC_P256`).** Same reasoning as (1) — symmetric `PartialEq` auto-ref; matched upstream convention.
4. **Dereferenced comparisons throughout `render_key_algorithm`** — `*alg_oid == OID_SIG_ED25519` etc. Same reason.

None of these changes materials the behavior; all are compile-time equivalent under Rust's `PartialEq` rules. No auto-fixes (Rule 1-3) were needed — the library compiled and all tests passed on the first build attempt. No architectural questions surfaced (no Rule 4).

## Issues Encountered

None. Cargo build green on first compile; `cargo test --lib preview::tests` 8/8 on first run; full `cargo test --features mock` 115/115 passing; `cargo fmt --check` exit 0; `cargo clippy --all-targets -- -D warnings` exit 0. Pinned `flow::tests::format_unix_as_iso_utc_epoch` test still green after the visibility bump (the test lives in `#[cfg(test)] mod tests` inside `flow.rs` and sees `pub(crate)` items in-scope).

## Threat Flags

None introduced. The plan's `<threat_model>` already scopes T-06-07..10 (re-parse DoS, oracle leak, emission-order side channel, fingerprint determinism) and all four are mitigated as designed:
- **T-06-07** — `x509_parser::parse_x509_certificate` is the parse path; every error returns `Error::InvalidMaterial` — no panics. `panic = "abort"` in `[profile.release]` catches any theoretical library panic as a process-terminating event.
- **T-06-08** — two sanitized reason strings only (`"malformed DER"`, `"trailing bytes after certificate"`); identical to Plan 01's ingest path; source grep for `X509Error|nom::|parse error at offset` returns zero.
- **T-06-09** — pure function returns `String`; no `eprintln!` / `println!` / file writes inside `src/preview.rs`. Emission is the caller's job (Plan 03 wiring).
- **T-06-10** — `Sha256::digest(bytes)` over the same canonical DER stored in `Material::X509Cert.bytes` — matches `openssl x509 -noout -fingerprint -sha256 -in cert.der -inform DER` output on the stored bytes.

## User Setup Required

None — library-layer changes only. No new env vars, no new CLI flags (Plan 03 adds `--material x509-cert` and `--armor`), no external services.

## Next Phase Readiness

- **Plan 03 (CLI surface + `run_send`/`run_receive` wiring) ready.** The `preview::render_x509_preview(bytes)` function is in place; Plan 03 can thread `Material::X509Cert { bytes }` → `preview::render_x509_preview(bytes)?` → `Option<String>` into the `Prompter::render_and_confirm` signature per AD-1 in 06-PATTERNS.md. The pure-function contract lets Plan 03 pick either AD-1 Option A (pre-render in caller) or Option B (render inside impl) without a code change here.
- **Plan 04 (JCS fixture + integration tests) ready.** Once the fixture DER exists, a golden-string test `tests/x509_banner_render.rs` can import `cipherpost::preview::render_x509_preview` and assert line-by-line against the known cert (Subject `CN=cipherpost-fixture, O=cipherpost, C=XX`, Serial `0x01`, NotBefore 2026-01-01, NotAfter 2028-01-01, Ed25519 key). `[VALID]` tag will fire because current test-time is 2026-04-24 (inside the validity window).
- **No blockers.**

## Self-Check: PASSED

- `src/preview.rs` — FOUND (via `ls src/preview.rs`)
- `src/lib.rs` contains `pub mod preview;` — FOUND (grep match count 1)
- `src/flow.rs` contains `pub(crate) fn format_unix_as_iso_utc` — FOUND (grep match count 1)
- Commit `94b09af` — FOUND (`git log --oneline | grep 94b09af`)
- `cargo build` — exit 0
- `cargo test --lib preview::tests` — 8/8 passing
- `cargo test --lib` — 34/34 passing
- `cargo test --features mock` — 115/115 passing (counts summed from `test result: ok. N passed` lines)
- `cargo fmt --check` — exit 0
- `cargo clippy --all-targets -- -D warnings` — exit 0
- `cargo test --lib flow::tests::format_unix_as_iso_utc_epoch` — pinned UAT test exit 0
- `grep "X509Error|nom::|parse error at offset" src/preview.rs` — zero matches (oracle hygiene)
- `grep -r "x509_parser" src/` — only `src/preview.rs`, `src/payload/ingest.rs`, and `src/error.rs` (comment-only reference in error.rs docstring)

---
*Phase: 06-typed-material-x509cert*
*Completed: 2026-04-24*
