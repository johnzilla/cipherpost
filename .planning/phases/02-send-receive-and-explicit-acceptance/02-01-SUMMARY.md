---
phase: 02-send-receive-and-explicit-acceptance
plan: 01
subsystem: payload-schema
tags:
  - payload-schema
  - canonical-json
  - error-types
  - uri-parsing
  - rust
dependency_graph:
  requires:
    - phase-01 (Envelope/Material/ShareUri build on Phase 1's crypto::jcs_serialize, Error enum, record::SHARE_REF_HEX_LEN, PROTOCOL_VERSION, identity Keypair accessor)
  provides:
    - cipherpost::payload::Envelope (JCS round-trip; from_jcs_bytes maps parse failure to SignatureCanonicalMismatch)
    - cipherpost::payload::Material (serde tag='type', rename_all='snake_case'; GenericSecret wire-encoded via base64 STANDARD padded)
    - cipherpost::payload::strip_control_chars (C0+DEL+C1 removal via char::is_control)
    - cipherpost::payload::enforce_plaintext_cap (65_536 cap; Display contains actual+limit)
    - cipherpost::payload::PLAINTEXT_CAP (65536)
    - cipherpost::ShareUri::{parse, format} + cipherpost::SHARE_URI_SCHEME
    - cipherpost::Error::{ShareRefMismatch, WireBudgetExceeded{encoded,budget,plaintext}, InvalidShareUri(String)}
    - cipherpost::crypto::hkdf_infos::{SHARE_SENDER, SHARE_RECIPIENT, INNER_PAYLOAD} (reserved)
    - cipherpost::identity::Identity::signing_seed() -> Zeroizing<[u8;32]>
  affects:
    - Phase 2 Plan 02-02 (flow::run_send, flow::run_receive will consume every symbol above)
    - Phase 2 Plan 02-03 (CLI wiring depends on Error variants for exit-code mapping)
    - Phase 3 Plan (Receipt construction will reference share_ref_hex_len + Envelope JCS bytes → cleartext_hash)
tech-stack:
  added: []
  patterns:
    - serde(tag='type', rename_all='snake_case') for internally-tagged enum wire format
    - serde-with submodule for base64 STANDARD (padded) Vec<u8> codec (matches Phase 1 OuterRecord pattern)
    - Manual impl Debug (not derive) for Envelope and Material to redact GenericSecret.bytes (Pitfall 7)
    - Envelope::from_jcs_bytes maps ALL parse failures to Error::SignatureCanonicalMismatch (D-RECV-01 step 7; exit 3 on malformed post-decrypt envelope)
    - Hand-rolled ShareUri parser via str::strip_prefix + split_once (no url crate; strict-form rejection per D-URI-03)
    - Explicit exit_code arms before `_ => 1` fallback for auditability (Pitfall 7 on new Error variants)
key-files:
  created:
    - tests/phase2_envelope_round_trip.rs (3 tests; fixture-match + round-trip + #[ignore] regenerate)
    - tests/phase2_material_variants_unimplemented.rs (4 tests; X509Cert/PgpKey/SshKey reject + serde tag check)
    - tests/phase2_share_uri_parse.rs (9 tests; accept + 7 reject paths + format-round-trip)
    - tests/fixtures/envelope_jcs_generic_secret.bin (119 bytes; sha256 8a8ea877f1bce53bede8d721ccab0eee850080a4f173002adc538ae844ef1a8b)
    - .planning/phases/02-send-receive-and-explicit-acceptance/deferred-items.md
  modified:
    - src/error.rs (added ShareRefMismatch, WireBudgetExceeded, InvalidShareUri; updated PayloadTooLarge Display with actual+limit numbers; added explicit exit_code arms)
    - src/crypto.rs (added SHARE_SENDER, SHARE_RECIPIENT, INNER_PAYLOAD constants to hkdf_infos)
    - src/identity.rs (added signing_seed() accessor returning Zeroizing<[u8;32]>; preserved secret_key_bytes_for_leak_test)
    - src/payload.rs (full body replacement: Envelope, Material, strip_control_chars, enforce_plaintext_cap, base64_std codec, manual Debug impls, 7 unit tests)
    - src/lib.rs (added SHARE_URI_SCHEME const and ShareUri struct with parse/format methods)
    - Cargo.toml (added three new [[test]] entries; no new dependencies)
decisions:
  - D-WIRE-02 locked: Envelope field order matches alphabetical JCS convention (created_at, material, protocol_version, purpose)
  - D-WIRE-03 locked: Material serde uses internally-tagged enum with rename_all='snake_case'; wire shape {"type":"generic_secret","bytes":"<b64>"}
  - D-WIRE-04 locked: base64 STANDARD (padded) via base64::engine::general_purpose::STANDARD; URL_SAFE_NO_PAD banned at payload layer
  - D-ERR-01 locked: three new Error variants landed with distinct Display strings; D-16 unified 'signature verification failed' preserved (4 occurrences)
  - D-URI-03 locked: strict cipherpost://<52-z32>/<32-lowercase-hex> parser; bare z32 rejected with 'use the URI that `send` printed' hint
  - Envelope::from_jcs_bytes maps parse failure to SignatureCanonicalMismatch (not a new Error variant; inherits exit 3 from Phase 1 D-16)
metrics:
  duration_minutes: ~20
  completed_date: 2026-04-21
requirements-completed:
  - PAYL-01
  - PAYL-02
  - PAYL-03
  - PAYL-04
  - PAYL-05
---

# Phase 2 Plan 01: Payload Schema + URI + Error Variants Summary

**One-liner:** Payload schema (Envelope + Material with serde tag='type'), strict share URI parser, three new Error variants, three reserved HKDF info constants, and a byte-locked JCS fixture — all unit-testable with zero new dependencies, ready for Plans 02-02 and 02-03 to consume.

## Files Touched

**Created (5):**
- `tests/phase2_envelope_round_trip.rs`
- `tests/phase2_material_variants_unimplemented.rs`
- `tests/phase2_share_uri_parse.rs`
- `tests/fixtures/envelope_jcs_generic_secret.bin`
- `.planning/phases/02-send-receive-and-explicit-acceptance/deferred-items.md`

**Modified (6):**
- `src/error.rs`
- `src/crypto.rs`
- `src/identity.rs`
- `src/payload.rs` (full body replacement from placeholder stub)
- `src/lib.rs`
- `Cargo.toml`

## Envelope JCS Fixture

- **Path:** `tests/fixtures/envelope_jcs_generic_secret.bin`
- **Size:** 119 bytes
- **SHA-256:** `8a8ea877f1bce53bede8d721ccab0eee850080a4f173002adc538ae844ef1a8b`
- **Content:** JCS of `Envelope { created_at: 1_700_000_000, material: GenericSecret{bytes: [0,1,2,3]}, protocol_version: 1, purpose: "test" }`
- **Raw bytes (decoded):** `{"created_at":1700000000,"material":{"bytes":"AAECAw==","type":"generic_secret"},"protocol_version":1,"purpose":"test"}`

Any future change to Envelope/Material serde layout, JCS formatter behavior, or PROTOCOL_VERSION will flip the SHA-256 and fail `tests/phase2_envelope_round_trip.rs::envelope_jcs_bytes_match_committed_fixture`.

## Signing Seed Accessor

The new `Identity::signing_seed() -> Zeroizing<[u8;32]>` required zero downstream refactoring because no Phase 2 flow code exists yet. The older `secret_key_bytes_for_leak_test()` was **preserved** (Phase 1's `tests/debug_leak_scan.rs` still calls it to scan the Debug output for leaks). This keeps Plan 02-02 clean — `flow::run_receive` will call `signing_seed()` and never touch the test-smell accessor.

## Deviations from Plan

### Auto-fixed issues

**1. [Rule 1 - Bug] Invalid Rust escape `\x80`/`\x9F` in test string literal**
- **Found during:** Task 3 (src/payload.rs test `strip_control_chars_strips_c0_del_c1_preserves_unicode`)
- **Issue:** The plan's inline test used `\x80` and `\x9f` which Rust string literals reject ("out of range hex escape — must be a character in the range [\x00-\x7f]"). Hex escapes in Rust strings are restricted to ASCII; C1 control chars must use `\u{80}..\u{9f}`.
- **Fix:** Changed the literal to `"a\x00b\x1fc\x7fd\u{80}e\u{9f}z"` which encodes the same Unicode code points via unicode escape syntax. `char::is_control` still covers the full Cc category so `strip_control_chars` behavior is unchanged.
- **Files modified:** `src/payload.rs`
- **Commit:** 130a599 (folded into Task 3 commit)

**2. [Rule 2 - Critical functionality] Acceptance-grep zero-counts forced doc-comment wording fix**
- **Found during:** Task 3 post-implementation acceptance-grep check
- **Issue:** Two acceptance criteria require zero matches: `grep -cE 'derive\([^)]*Debug' src/payload.rs == 0` and `grep -c 'serde_json::to_vec' src/payload.rs == 0`. The plan-provided module doc-comment contained both literals as descriptive text (`"derive(Debug) is forbidden"` and `"never serde_json::to_vec"`), causing the greps to count them even though they were in comments.
- **Fix:** Rewrote the two doc-comment lines to avoid the forbidden literal strings while preserving intent: "deriving the Debug trait is forbidden" and "no raw serde_json byte serializers".
- **Files modified:** `src/payload.rs` (doc-comment lines only)
- **Commit:** 130a599 (folded into Task 3 commit)

**3. [Rule 1 - Bug] rustfmt reflow on new Error variant with 3 fields**
- **Found during:** Task 4 fmt check
- **Issue:** The plan-provided single-line `WireBudgetExceeded { encoded: usize, budget: usize, plaintext: usize }` exceeds rustfmt's struct-body line budget and must be multi-line.
- **Fix:** Reformatted to multi-line struct body; the new exit_code arm was also reformatted to single-line-arm form per rustfmt.
- **Files modified:** `src/error.rs`
- **Commit:** a6babd7 (folded into Task 4 commit)

### Out-of-scope discoveries (deferred)

**Pre-existing Phase 1 fmt deviations.** `cargo fmt --check` reports multiple diffs in files that predate Plan 02-01 (e.g., `src/error.rs` D-16 comments use two spaces before `//`, `src/transport.rs` and `src/crypto.rs` multi-line `.map_err` chains, multiple test files). These were present on `main` before this plan began and are out of scope per the scope-boundary rule. Logged to `.planning/phases/02-send-receive-and-explicit-acceptance/deferred-items.md` for a dedicated `chore(fmt)` cleanup pass. Plan 02-01's new/modified files are themselves fmt-clean on the lines Plan 02-01 authored.

## Verification

- `cargo build --release` — green (4.04s)
- `cargo test --all-features` — all tests pass across 18 test binaries (Phase 1 unchanged + 15 new Phase 2 tests: 3 integration binaries with 2+4+9 tests respectively, plus 7 new payload lib tests)
- `cargo clippy --all-features -- -D warnings` — green
- `cargo fmt --check` — pre-existing Phase 1 diffs remain (out of scope, documented in deferred-items.md); all lines Plan 02-01 authored are fmt-clean
- HKDF enumeration test passes with the three new reserved constants; debug_leak_scan passes unchanged

## Acceptance Criteria Status

All 5 REQ-IDs covered by this plan are implemented:

- **PAYL-01** — `Envelope { purpose, material, created_at, protocol_version }` with JCS via `crypto::jcs_serialize`
- **PAYL-02** — `Material::{GenericSecret{bytes}, X509Cert, PgpKey, SshKey}` with serde tag='type'; non-generic variants return NotImplemented{phase:2}
- **PAYL-03** — 64 KB plaintext cap enforced; Display contains actual+cap numbers; `PLAINTEXT_CAP: usize = 65536` pub const
- **PAYL-04** — `strip_control_chars` covers C0+DEL+C1 via `char::is_control`
- **PAYL-05** — Consumed existing Phase 1 `record::share_ref_from_bytes` (no new derivation); `ShareUri::parse` enforces 32-char hex share_ref_hex equal to `SHARE_REF_HEX_LEN`

## Handoff Notes to Plans 02-02 and 02-03

1. **`Envelope::from_jcs_bytes` returns `Error::SignatureCanonicalMismatch` on parse failure, not a new parse-error variant.** Flow code in 02-02 should propagate with `?`; the binary in 02-03 will naturally map this to exit code 3 via the existing Phase 1 exit_code table. No new variant needed.

2. **`Material::as_generic_secret_bytes(&self) -> Result<&[u8], Error>`** is the single accessor. Plan 02-02 `run_receive` should call this once after decrypt; a non-generic variant is a hard abort at pre-surfacing (NotImplemented{phase:2}, exit 1). This MUST happen inside the acceptance-screen code path so the user sees "Type: generic_secret" in the screen; a future-protocol cert share is rejected BEFORE the screen renders.

3. **`ShareUri::parse` returns `Error::InvalidShareUri(String)`** with a reason string. Display already formats as `invalid share URI: <reason>` via the `#[error("invalid share URI: {0}")]` thiserror attribute, so no special handling needed in 02-03's error-to-stderr path.

4. **`Identity::signing_seed()`** is the clean accessor — use it, not `secret_key_bytes_for_leak_test`. The old name is preserved ONLY for `tests/debug_leak_scan.rs`; never call it from `src/` code.

5. **Reserved HKDF constants (`SHARE_SENDER`, `SHARE_RECIPIENT`, `INNER_PAYLOAD`)** are registered but not yet referenced by any call site. Plans 02-02/03 don't need to introduce any new HKDF call — age handles its own internal KDF. If a future plan needs one of these, the enumeration test already enforces they be prefixed, distinct, and non-empty.

6. **No new dependencies added.** `chrono` (for Plan 02-03's TTL acceptance-screen formatting) is still pending per the plan's explicit note.

7. **Fmt fixes were isolated.** The deferred-items.md note documents the pre-existing Phase 1 fmt deviations — a later `chore(fmt)` pass can clean them up without touching Plan 02-01's logic.

## Commits

- `0ddaa54` — feat(02-01): extend Error enum with ShareRefMismatch, WireBudgetExceeded, InvalidShareUri
- `428123e` — feat(02-01): reserve Phase 2 HKDF info constants and add Identity::signing_seed
- `130a599` — feat(02-01): implement Envelope/Material payload schema and ShareUri parser
- `a6babd7` — test(02-01): wire three Phase 2 integration tests and commit JCS fixture

## Self-Check: PASSED

All 12 artifacts (6 modified + 5 created source/test/fixture files + SUMMARY.md itself) verified present on disk. All 4 commit hashes verified present in `git log --oneline --all`.
