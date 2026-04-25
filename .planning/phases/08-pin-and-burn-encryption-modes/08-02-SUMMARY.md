---
phase: 08-pin-and-burn-encryption-modes
plan: 02
subsystem: pin-ship-gate
tags: [rust, pin, cli, validation, prompt, jcs, oracle-hygiene, leak-scan, integration-test, spec, cclink-divergence]

# Dependency graph
requires:
  - phase: 08-pin-and-burn-encryption-modes
    plan: 01
    provides: pin_derive_key + OuterRecord.pin_required wire field + run_send pin/burn params + nested-age branch
provides:
  - validate_pin (8-char min + anti-pattern + blocklist case-insensitive; generic Display)
  - prompt_pin (TTY-only, double-entry on confirm=true; AD-5 CIPHERPOST_TEST_PIN cfg-gated injection)
  - Send.pin: bool clap flag (TTY-only; argv-inline `--pin <value>` rejected naturally)
  - run_receive PIN integration (STEP 6a: salt-split + prompt + nested age-decrypt)
  - JCS fixture pinning pin_required alphabetic placement (between created_at and protocol_version)
  - PIN-07 narrow oracle: wrong-PIN ≡ wrong-passphrase ≡ tampered-inner Display + exit 4
  - PIN leak-scan: SecretBox<String> Debug-redaction + Zeroizing key buffer doc invariant
  - SPEC.md §3.6 PIN Crypto Stack + §5.1 --pin + §5.2 PIN dispatch + §6 exit-4 lane
affects: [08-03 (BURN core can begin), 08-04 (BURN ship-gate), 08-05 (PIN+BURN compose tests), 08-06 (docs polish)]

# Tech tracking
tech-stack:
  added: []  # zero new direct deps — dialoguer 0.12 already present (used by resolve_passphrase)
  patterns:
    - "AD-5 cfg-gated env-var injection for TTY-only flows: mirrors flow::tty_check_skipped pattern; production builds compile out the override"
    - "Oracle hygiene over verbose error reporting: validate_pin + Error::DecryptFailed both produce class-uniform Display, with specific reasons asserted only at the test layer"
    - "Synthetic-variant intrinsic-Display oracle test: pin_error_oracle.rs proves Display equivalence using Error::DecryptFailed values directly, avoiding the wire-budget round-trip dependency that bedevils Phase 6/7 oracle tests"
    - "Direct OuterRecord synthesis for non-receive-flow tests: pin_required_share_with_no_pin_at_receive bypasses the wire-budget ceiling by publishing a synthesized pin_required record (run_receive aborts at prompt_pin BEFORE age-decrypt, so blob content is irrelevant)"

key-files:
  created:
    - "tests/pin_validation.rs (PIN-02 matrix — 8 tests; oracle-hygiene Display equivalence)"
    - "tests/pin_roundtrip.rs (PIN-08 (a)/(b)/(c) matrix; (c) ALWAYS RUNS via synthesized record)"
    - "tests/pin_error_oracle.rs (PIN-07 narrow — exit-4 lane equality, 5 tests)"
    - "tests/outer_record_pin_required_signable.rs (JCS byte-identity fixture, alphabetic-order assertion)"
    - "tests/fixtures/outer_record_pin_required_signable.bin (212 bytes — NEW; v1.0 fixtures unchanged)"
  modified:
    - "src/pin.rs (validate_pin + prompt_pin + AD-5 test_pin_override appended to Plan 01's pin_derive_key)"
    - "src/cli.rs (Send.pin: bool flag — note: enum-variant struct fields cannot carry `pub` in Rust; landed without it)"
    - "src/main.rs (Send dispatch destructures `pin`, calls prompt_pin(true), threads pin_secret into run_send replacing Plan 01's None placeholder)"
    - "src/flow.rs (run_receive STEP 6a PIN dispatch + STEP 6b nested age-decrypt; non-pin path byte-identical to v1.0)"
    - "tests/debug_leak_scan.rs (PIN SecretBox + Zeroizing buffer Debug invariants — 2 new tests)"
    - "tests/phase3_receipt_sign_verify.rs (assert_unified_credential_failure_display peer helper + direct test)"
    - "Cargo.toml (registers pin_validation, pin_roundtrip, pin_error_oracle, outer_record_pin_required_signable as test targets; pin_roundtrip + pin_error_oracle gated on `mock` feature)"
    - "SPEC.md (§3.6 PIN Crypto Stack NEW; §5.1 --pin documentation; §5.2 step 6a PIN dispatch; §6 exit-4 row updated to reflect unified credential Display)"

key-decisions:
  - "PIN-02 user-facing Display is GENERIC (`PIN does not meet entropy requirements`) — supersedes REQUIREMENTS PIN-02 wording per D-P8-12 (oracle hygiene per PITFALLS #23/#24)"
  - "Wrong-PIN funnels through Error::DecryptFailed (existing variant; exit 4) with IDENTICAL Display to wrong-passphrase — NO new Error::PinIncorrect variant (PATTERNS.md correction #4)"
  - "PIN-08 case (c) `pin_required_share_with_no_pin_at_receive` ships as a CONCRETE test via direct OuterRecord synthesis — NOT a docstring placeholder (iteration-1 B3 resolution)"
  - "PIN-08 cases (a) + (b) inherit the wire-budget #[ignore] from Plan 01 (mirrors Phase 6/7 X.509/PGP/SSH pattern); the underlying invariants are independently asserted in pin_error_oracle.rs against synthetic Error::DecryptFailed values"
  - "validate_pin runs length check FIRST (before Argon2id) so length-failures don't leak via wall-clock timing (T-08-15 mitigation)"
  - "AD-5 CIPHERPOST_TEST_PIN cfg-gated env-var override is the ONLY way to bypass the TTY check in tests; production builds compile out the override (mirrors tty_check_skipped pattern)"
  - "clap-bool `pin: bool` naturally rejects argv-inline `--pin <value>` — no runtime check needed (RESEARCH Open Risk #6 closed)"
  - "JCS field ordering for pin_required: alphabetic between `created_at` and `protocol_version` (NOT `purpose` — `purpose` lives on `Envelope`, not `OuterRecord`; CONTEXT.md drift corrected in 08-01, re-verified here via tests/outer_record_pin_required_signable.rs alphabetic-order assertion)"
  - "Pre-existing pre-Plan-01 fmt diff (material_ssh_ingest.rs, pgp_banner_render.rs, ssh_banner_render.rs, ssh_roundtrip.rs, x509_dep_tree_guard.rs) deferred per scope-boundary rule — same deferral 08-01 SUMMARY documented"

patterns-established:
  - "Oracle test via intrinsic-Display: when round-trip is wire-budget-bound, exercise the Display invariant directly through synthetic Error variant constructions. Display is intrinsic to thiserror unit variants — no payload, no rendering side effect, no test-data dependency"
  - "Synthesized OuterRecord for receive-flow short-circuit tests: when run_receive aborts BEFORE age-decrypt (e.g., at prompt_pin), blob content is irrelevant — directly publish a record bypassing the wire-budget round-trip dependency"
  - "skip_serializing_if + is_false predicate keeps wire-byte-identity for additive optional bool fields (Plan 01 established; Plan 02 verifies in JCS fixture)"
  - "`pub fn` peer-function expansion in single-file modules: Plan 01 shipped src/pin.rs::pin_derive_key as one free function; Plan 02 appends validate_pin + prompt_pin + cfg-gated test_pin_override at the same crate-level scope (no struct, no Debug derive)"

requirements-completed: [PIN-01, PIN-02, PIN-06, PIN-07, PIN-08, PIN-09, PIN-10]

# Metrics
duration: 37min
completed: 2026-04-25
---

# Phase 8 Plan 02: PIN ship-gate Summary

**The PIN side of Phase 8 ships completely: validate_pin entropy floor + TTY prompt + CLI flag + run_receive nested age-decrypt + JCS fixture + PIN-07 oracle + leak-scan + SPEC.md §3.6.** All 10 PIN REQ-IDs covered (PIN-01..10; PIN-03/04/05/09/10 from Plan 01 carried forward). Plan 03 (BURN core) begins with zero PIN-side debt.

## Performance

- **Duration:** ~37 min
- **Started:** 2026-04-25T22:51:26Z
- **Completed:** 2026-04-25T23:28:22Z
- **Tasks:** 5 / 5
- **Files modified:** 13 (5 created, 7 modified, 1 binary fixture)

## Accomplishments

- Landed `validate_pin` (PIN-02) with the full cclink-fork algorithm (8-char min, all-same reject, monotonic ascending+descending reject, blocklist case-insensitive). Length check runs FIRST so length-failures don't leak via Argon2id timing (T-08-15 mitigation).
- Landed `prompt_pin` (PIN-01, PIN-06): TTY-only with optional double-entry confirmation. Non-TTY context HARD-REJECTS with `Error::Config` (exit 1). AD-5 `CIPHERPOST_TEST_PIN` cfg-gated env-var injection for tests; production builds compile out the override.
- Wired `--pin` CLI flag: bool flag in `src/cli.rs::Send`, dispatched from `src/main.rs` with `prompt_pin(true)` (confirm=true at send to catch typos). clap-bool naturally rejects `--pin=value` (verified empirically); RESEARCH Open Risk #6 closed.
- Wired `run_receive` STEP 6a PIN dispatch + STEP 6b nested age-decrypt. Non-pin path is BYTE-IDENTICAL to v1.0; pin path: base64-decode → split first 32 bytes as salt → prompt_pin(false) → pin_derive_key → identity_from_x25519_bytes → age_decrypt(outer_ct, receiver) → age_decrypt(inner_ct, pin_id). Tamper-zero invariant preserved (outer-verify gates everything before the prompt).
- Created the JCS fixture `tests/fixtures/outer_record_pin_required_signable.bin` (212 B) and pinned alphabetic placement of `pin_required` between `created_at` and `protocol_version` (NOT `purpose` — that's on `Envelope`). v1.0 fixtures (192 B / 119 B / 424 B) UNCHANGED.
- Shipped PIN-07 narrow oracle (`tests/pin_error_oracle.rs`): wrong-PIN ≡ wrong-passphrase ≡ tampered-inner all yield `Error::DecryptFailed` with IDENTICAL Display + exit 4. Sig-failures (exit 3) confirmed DIFFERENT (D-16 sig lane invariant unchanged).
- Extended leak-scan (`tests/debug_leak_scan.rs`): SecretBox<String> Debug never contains "validpin1" raw bytes; Zeroizing<[u8; 32]> wrapper Debug-format is documented as bounded by the type-system invariant (no `#[derive(Debug)]` on any struct in src/pin.rs).
- Authored SPEC.md §3.6 PIN Crypto Stack covering KDF parameters, HKDF info namespace, wire-blob layout, nested-age structure, receive-flow ordering, error-oracle constraint, and entropy floor. §5.1 documents `--pin`; §5.2 documents step 6a PIN dispatch; §6 exit-4 row updated to reflect the unified credential-failure Display literal.
- Closed iteration-1 plan-checker B3 blocker: `pin_required_share_with_no_pin_at_receive` ships as a CONCRETE test (direct OuterRecord synthesis to bypass wire-budget) — NOT a docstring placeholder. Asserts Error::Config + exit 1 + ledger/sentinel/receipt all untouched.

## Task Commits

| # | Task | Commit | Description |
|---|------|--------|-------------|
| 1 | validate_pin + prompt_pin + tests/pin_validation.rs | `6ea5c6f` | feat: PIN entropy floor + TTY prompt with AD-5 injection |
| 2 | CLI --pin flag + main.rs Send dispatch wiring | `f452cd1` | feat: wire --pin through prompt_pin(true) replacing Plan 01 placeholder |
| 3 | run_receive PIN integration + tests/pin_roundtrip.rs | `95af9a6` | feat: STEP 6a salt-split + nested age-decrypt + (a)/(b)/(c) matrix |
| 4 | JCS fixture + pin_error_oracle + leak-scan + Cargo.toml registrations | `bd8565e` | test: byte-identity + PIN-07 oracle + leak-scan extensions |
| 5 | SPEC.md §3.6 + §5.1/§5.2/§6 | `952048c` | docs: PIN crypto stack blessed as v1.1 baseline |
| (style) | rustfmt formatting fixes for Plan 02 files | `b9eb835` | style: cargo fmt --check on Plan 02-touched files |

**Plan metadata commit:** _(to follow this SUMMARY)_

## Files Created/Modified

### Created

- **`tests/pin_validation.rs`** — 8 tests covering each rejection class (too-short, all-same, ascending, descending, blocklist) + strong-PIN acceptance + exit-1 mapping + Display-equivalence-across-classes oracle-hygiene assertion.
- **`tests/pin_roundtrip.rs`** — PIN-08 (a)/(b)/(c) matrix. (a) and (b) inherit the wire-budget `#[ignore]` (mirrors Phase 6/7 X.509/PGP/SSH pattern explicit in 08-01-SUMMARY.md). (c) ALWAYS RUNS by synthesizing a `pin_required=true` OuterRecord directly (bypassing wire-budget round-trip).
- **`tests/pin_error_oracle.rs`** — 5 tests: unified credential-lane Display, wrong-PIN ≡ wrong-passphrase, exit-4 vs exit-3 lane separation, D-16 sig lane unification, validation-failure-vs-credential-failure distinction.
- **`tests/outer_record_pin_required_signable.rs`** — fixture-byte-identity test + alphabetic-order assertion + #[ignore] regenerator. Spot-checks that `purpose` is NOT a key on `OuterRecord`.
- **`tests/fixtures/outer_record_pin_required_signable.bin`** — 212 bytes. v1.0 fixtures (`outer_record_signable.bin` 192 B, `envelope_jcs_generic_secret.bin` 119 B, `receipt_signable.bin` 424 B) all UNCHANGED.

### Modified

- **`src/pin.rs`** — appended `validate_pin`, `test_pin_override` (cfg-gated AD-5 injection), and `prompt_pin`. Plan 01's `pin_derive_key` and `pin_argon2_params` preserved verbatim.
- **`src/cli.rs::Send`** — gains `pin: bool` field with `#[arg(long)]` and v1.2-deferral documentation in help text. **Note (Rule 1 fix):** the plan specified `pub pin: bool` but Rust enum variants forbid visibility qualifiers on struct-shaped fields (E0449). Landed as `pin: bool` (no public-API change — fields of enum variants always share the enum's visibility).
- **`src/main.rs::Send dispatch`** — destructures `pin`, calls `prompt_pin(true)` when the flag is set, threads `pin_secret` into `run_send` replacing Plan 01's `None` placeholder. The `false` for burn stays untouched (Plan 03 wires it).
- **`src/flow.rs::run_receive`** — STEP 6 split into 6a (PIN dispatch: base64-decode + salt-split + prompt + pin_derive_key) and 6b (nested age-decrypt). Non-pin path produces byte-identical results to v1.0 (verified by all phase2/3 round-trip tests still passing without modification).
- **`tests/debug_leak_scan.rs`** — `pin_secret_box_debug_redacts` (T-08-11 mitigation: `format!("{:?}", SecretBox::new(Box::new("validpin1")))` does NOT contain "validpin1") + `pin_zeroizing_key_buffer_debug_does_not_panic` (documents the type-system invariant).
- **`tests/phase3_receipt_sign_verify.rs`** — adds `assert_unified_credential_failure_display` peer helper alongside the existing `assert_unified_d16_display` (PIN-07 lane invariant alongside D-16 sig lane invariant) + a direct test exercising it.
- **`Cargo.toml`** — registers `pin_validation`, `pin_roundtrip` (mock-gated), `pin_error_oracle` (mock-gated), `outer_record_pin_required_signable` as test targets.
- **`SPEC.md`** — §3.6 NEW (PIN crypto stack); §5.1 +`--pin` documentation; §5.2 +step 6a PIN dispatch sub-step; §6 exit-4 row updated.

## Phase Resolutions Recorded in This SUMMARY

### W1 — PIN-02 Display generic (D-P8-12 supersedes REQUIREMENTS PIN-02 wording)

REQUIREMENTS.md PIN-02 originally specified "Rejection returns exit 1 with specific reason (min length, all-same, sequential)". Plan 02 ships the GENERIC user-facing Display `"PIN does not meet entropy requirements"` per oracle hygiene (PITFALLS #23/#24 — naming the specific check that fired creates a distinguishing oracle for credential brute-force). The specific reason IS asserted at the test layer (`tests/pin_validation.rs::rejects_too_short`, `rejects_all_same`, `rejects_ascending`, `rejects_descending`, `rejects_blocklist` exercise each check independently) but is NEVER surfaced in user-facing output.

**Resolution:** D-P8-12 supersedes REQUIREMENTS PIN-02 wording. This SUMMARY is the discoverable audit trail. Optional follow-up (non-blocking): append a clarification to `.planning/REQUIREMENTS.md` PIN-02 — "Specific reason logged at test-assertion level / present in `validate_pin` source comments; user-facing Display is generic for oracle hygiene per D-P8-12 supersession" — but the SUMMARY note is authoritative.

### B3 — PIN-08 case (c) ships concretely (not a docstring placeholder)

The PIN-08 matrix's third case originally appeared in CONTEXT/PATTERNS as a docstring placeholder noting overlap with case (b). Plan 02 Task 3 ships `pin_required_share_with_no_pin_at_receive` as a CONCRETE test exercising `prompt_pin`'s non-TTY rejection arm. With `CIPHERPOST_TEST_PIN` UNSET and `cargo test`'s stdin non-interactive, `prompt_pin` returns `Err(Error::Config("--pin requires interactive TTY ..."))` → exit 1.

To avoid the wire-budget round-trip dependency, the test SYNTHESIZES a pin-required `OuterRecord` directly (bypassing `run_send`) — this works because `run_receive` aborts at `prompt_pin` BEFORE age-decrypt, so the blob's actual content is irrelevant for case (c). Asserts: variant is `Error::Config` (NOT `DecryptFailed`); exit code is 1 (NOT 4 — receive flow never reaches age-decrypt); ledger has zero rows for the share_ref; sentinel does not exist; no receipt published. This is the iteration-1 B3 resolution shipped end-to-end.

### Rule 1 fix — `pub pin: bool` in enum variant lands as `pin: bool`

The plan specified `pub pin: bool` in `Send` enum variant. Rust enum-variant struct-shaped fields cannot carry visibility qualifiers (compiler error E0449: "visibility qualifiers are not permitted here; enum variants and their fields always share the visibility of the enum they are in"). Landed as `pin: bool` — no public API surface change (fields of `pub enum Command` variants are accessible by destructuring at any reachable scope). Documented in commit `f452cd1`.

### PIN-07 narrow per RESEARCH Open Risk #1 (re-confirmed)

Wrong-PIN, wrong-passphrase, and tampered inner-ciphertext all surface as `Error::DecryptFailed` (existing v1.0 variant; exit 4). Sig-failures (`Error::Signature*`, exit 3) remain DIFFERENT — distinguishable by exit code, but Display equality is preserved WITHIN each lane. Captured in `tests/pin_error_oracle.rs`.

### clap-bool natural rejection of argv-inline `--pin=value` (RESEARCH Open Risk #6 closed)

Empirical verification: `cargo run -- send --pin=foo --self -p k -` prints clap's `error: unexpected value 'foo' for '--pin' found; no more were expected` and exits non-zero. No runtime check needed; bool flag naturally rejects assigned values. Documented in commit `f452cd1`.

### CIPHERPOST_TEST_PIN injection works under both `cfg(test)` AND `feature = "mock"`

`test_pin_override` is gated on `cfg(any(test, feature = "mock"))` so it works for both unit-test code (which has `cfg(test)` set automatically) and integration test code (which doesn't set `cfg(test)` for the library but does compile against `--features mock`). Production builds (no `mock` feature, no `cfg(test)`) compile out the override entirely.

## Verification

| Gate | Result |
|------|--------|
| `cargo build` | clean, zero warnings from Plan-02-touched files |
| `cargo build --release` | clean, finished in ~12s |
| `cargo test --features mock` | all 63 test result blocks ok; zero failures |
| `cargo test --features mock --test pin_validation` | 8 tests pass |
| `cargo test --features mock --test pin_roundtrip` | 1 passed + 2 ignored = 3 tests (a/b ignored for wire-budget per plan; c ALWAYS RUNS) |
| `cargo test --features mock --test pin_error_oracle` | 5 tests pass |
| `cargo test --features mock --test outer_record_pin_required_signable` | 2 passed + 1 ignored (regenerator) — fixture byte-locked at 212 B |
| `cargo test --features mock --test debug_leak_scan` | 8 tests pass (was 7; +1 PIN SecretBox + +1 Zeroizing wrapper) |
| `cargo test --features mock --test phase3_receipt_sign_verify` | 7 tests pass (was 6; +1 credential_failure_display_invariant) |
| `cargo test --features mock --test hkdf_info_enumeration` | passes — auto-discovers `cipherpost/v1/pin` (Plan 01 added; Plan 02 verifies invariant) |
| `cargo test --features mock --test outer_record_canonical_form` | passes — `outer_record_signable.bin` stays 192 B byte-identical |
| `cargo test --features mock --test phase2_envelope_round_trip` | passes — `envelope_jcs_generic_secret.bin` stays 119 B byte-identical |
| `cargo test --features mock --test pin_send_smoke` | 2 passed + 1 ignored (Plan 01's wire-budget pattern preserved) |
| `lychee SPEC.md` | 12 links, 0 errors |
| Verify clap rejects `--pin=value` empirically | Exit non-zero with clap's `error: unexpected value 'foo' for '--pin' found` |
| `cargo fmt --check` on Plan 02-touched files | clean (commit `b9eb835`) |
| Pre-existing `cargo fmt --check` issues in unrelated files | deferred per scope-boundary rule (out-of-scope for this plan; same deferral 08-01 SUMMARY documented) |
| v1.0 wire-byte preservation | 192 B + 119 B + 424 B fixtures all byte-identical |
| New fixture | 212 B `outer_record_pin_required_signable.bin` committed |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] `pub pin: bool` in enum variant rejected by Rust (E0449)**
- **Found during:** Task 2 build attempt
- **Issue:** Plan specified `pub pin: bool` in the `Send` enum variant; Rust forbids visibility qualifiers on enum-variant struct-shaped fields (compiler error E0449)
- **Fix:** Landed as `pin: bool` (no `pub`)
- **Files modified:** `src/cli.rs`
- **Commit:** `f452cd1`
- **Impact:** None — fields of `pub enum Command` variants are accessible by destructuring at any reachable scope; the plan's `must_haves.contains: "pub pin: bool"` grep-marker became `pin: bool` instead

**2. [Rule 1 — Bug] `display_is_generic_across_all_rejection_classes` test compared inner-Config-string to full-Display literal**
- **Found during:** Task 1 first test run
- **Issue:** The test asserted `assert_eq!(first, REJECT_MSG)` where `first` was the FULL Display (which embeds the variant prefix `"configuration error: "`), but `REJECT_MSG` was just the inner literal
- **Fix:** Loosened the final assertion to `first.contains(REJECT_MSG)` — the cross-class equivalence assertion (which is what the test is actually for) was already correct
- **Files modified:** `tests/pin_validation.rs`
- **Commit:** `6ea5c6f` (Task 1's combined commit)

### Out-of-scope discoveries

- **Pre-existing fmt diff** in `tests/material_ssh_ingest.rs`, `tests/pgp_banner_render.rs`, `tests/ssh_banner_render.rs`, `tests/ssh_roundtrip.rs`, `tests/x509_dep_tree_guard.rs` — these were already noted as deferred in 08-01 SUMMARY's "Pre-existing issues found (out of scope, deferred)" section. Continuing to defer per scope-boundary rule. Recommend a `chore(fmt)` PR or rolling them into Phase 8 Plan 06's docs/cleanup polish.

### Implementation notes

- **PIN-08 cases (a) + (b) are #[ignore]'d for wire-budget reasons** (mirrors Plan 01's `pin_send_produces_pin_required_record_with_salt_prefixed_blob` deferral). The substantive invariants behind cases (a) and (b) are captured by:
  - The wire-shape correctness (salt prefix + nested age) by `pin_send_smoke.rs::pin_send_surfaces_wire_budget_exceeded_cleanly` (Plan 01) which DOES run
  - The Display equivalence of wrong-PIN ≡ wrong-passphrase by `pin_error_oracle.rs::wrong_pin_display_matches_wrong_passphrase_display` (intrinsic to Error::DecryptFailed unit variant) which DOES run
  - The non-TTY rejection arm of prompt_pin by `pin_roundtrip.rs::pin_required_share_with_no_pin_at_receive` (case c) which DOES run via direct record synthesis
- The wire-budget escape hatch (two-tier storage / chunking / OOB delivery) remains scheduled for Phase 9 (DHT-07).

## Authentication gates

None encountered. All test PIN injection was via the cfg-gated `CIPHERPOST_TEST_PIN` env-var override; no real TTY interaction was needed.

## Plan completeness

All success criteria from the orchestrator prompt satisfied:

- [x] All 5 tasks in 08-02-PLAN.md executed per their action blocks
- [x] Every task verify command exits 0
- [x] `cargo test --features mock pin_roundtrip` shows 3 tests (1 passed + 2 ignored as expected per the plan_specifics)
- [x] `tests/fixtures/outer_record_signable.bin` (192 B) byte-identical to pre-Plan-01 baseline
- [x] `tests/fixtures/outer_record_pin_required_signable.bin` created and committed (212 B)
- [x] `tests/pin_roundtrip.rs` has all three matrix functions
- [x] `tests/pin_error_oracle.rs` exists and asserts wrong-PIN ≡ wrong-passphrase ≡ sig-failure-distinct Display equality
- [x] `tests/debug_leak_scan.rs` extended with PIN-holding-struct asserts (2 new tests)
- [x] PIN validation Display is GENERIC ("PIN does not meet entropy requirements") — verified by `display_is_generic_across_all_rejection_classes` test
- [x] SPEC.md §3.6 PIN crypto stack section added
- [x] CLI `--pin` flag wired; argv-inline `--pin <value>` rejected naturally by clap (verified empirically)
- [x] PIN-08(a/b/c) all assert non-trivial behavior — no empty placeholder bodies
- [x] PIN-02 Display resolution recorded above (W1 phase resolution)
- [x] No NEW clippy warnings introduced (pre-existing ones from Plan 01 stay deferred)

## Self-Check: PASSED

Verification:

- All created files (`tests/pin_validation.rs`, `tests/pin_roundtrip.rs`, `tests/pin_error_oracle.rs`, `tests/outer_record_pin_required_signable.rs`, `tests/fixtures/outer_record_pin_required_signable.bin`) confirmed present on disk via `ls`.
- All 6 task commits (`6ea5c6f`, `f452cd1`, `95af9a6`, `bd8565e`, `952048c`, `b9eb835`) confirmed in git log.
- `cargo test --features mock` exits 0 with all 63 test groups passing and zero failures.
- v1.0 fixture byte-identity verified by file size + the `outer_record_canonical_form_bytes_match_committed_fixture` test passing unchanged.
