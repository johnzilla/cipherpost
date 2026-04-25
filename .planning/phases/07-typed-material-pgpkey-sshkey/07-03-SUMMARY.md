---
phase: 07-typed-material-pgpkey-sshkey
plan: 03
subsystem: flow
tags: [rust, pgp, rpgp, flow, armor, acceptance-banner, dispatch, oracle-hygiene]
requires:
  - Phase 7 Plan 01 — `Material::PgpKey { bytes }`, `as_pgp_key_bytes`, live `run_send` dispatch
  - Phase 7 Plan 02 — `preview::render_pgp_preview`, `pgp_primary_is_secret` discriminator, `pgp_parse_error` funnel
  - Phase 6 Plan 03 — `Prompter::render_and_confirm(preview_subblock: Option<&str>, ...)` (signature unchanged), `pem_armor_certificate`, X.509 dispatch arm template
provides:
  - `pub fn preview::pgp_armor(bytes: &[u8]) -> Result<Vec<u8>, Error>` — RFC 4880 ASCII-armor emitter delegating to rpgp 0.19.0's `to_armored_bytes(ArmorOptions::default())`
  - Live `run_receive` arm for `Material::PgpKey { .. }`: parses bytes via `as_pgp_key_bytes`, pre-renders the SECRET-key warning + Fingerprint/UID/Key/Subkeys/Created subblock via `render_pgp_preview`, threads it through `Option<&str>` to the unchanged Phase 6 Prompter
  - Variant-aware armor output dispatch: `X509Cert → pem_armor_certificate`, `PgpKey → preview::pgp_armor`, `_ → unreachable!` (matrix already validated)
  - Widened `Error::Config` literal `"--armor requires --material x509-cert or pgp-key"` — full list of armor-permitted variants as of this plan
  - `run_receive` `Material::SshKey` arm split out cleanly (still `NotImplemented { phase: 7 }`) — Plan 07 extends
affects:
  - src/flow.rs (run_receive material match arm + armor output dispatch + literal)
  - src/preview.rs (new `pgp_armor` helper)
  - tests/x509_roundtrip.rs (Phase 6 widened-literal pin)
  - SPEC.md (§5.2 step 11 widened literal — straggler fix; Plan 04 owns the full PGP SPEC rewrite)
tech-stack:
  added: []
  patterns:
    - "rpgp 0.19.0 `SignedPublicKey::to_armored_bytes(ArmorOptions::default())` for `BEGIN PGP PUBLIC KEY BLOCK` emission"
    - "rpgp 0.19.0 `SignedSecretKey::to_armored_bytes(ArmorOptions::default())` for `BEGIN PGP PRIVATE KEY BLOCK` emission"
    - "BlockType auto-selected by rpgp from the dispatched composed type — no manual `BlockType::PublicKey` vs `PrivateKey` detection in our code"
    - "Tag-5/tag-6 dispatch via existing `pgp_primary_is_secret` (single-source-of-truth across `render_pgp_preview` + `pgp_armor`)"
    - "Variant-aware armor output match in `run_receive` with `unreachable!` for variants already-rejected at the material match — pattern extends mechanically when SshKey gains armor support (or doesn't, per D-P7-13)"
key-files:
  created: []
  modified:
    - src/flow.rs
    - src/preview.rs
    - tests/x509_roundtrip.rs
    - SPEC.md
key-decisions:
  - "pgp_armor location: `src/preview.rs` (Option A from the plan's discretion). Avoided a new `src/pgp_armor.rs` module — preview.rs already imports rpgp + has `pgp_primary_is_secret` and `pgp_parse_error`, both reused by the new helper. Keeps the rpgp surface area in two files (preview.rs + payload/ingest.rs) per D-P7-09."
  - "rpgp armor API used: `pgp::composed::ArmorOptions::default()` + `SignedPublicKey::to_armored_bytes` / `SignedSecretKey::to_armored_bytes`. Default ArmorOptions = `headers: None, include_checksum: true` (CRC24 line per RFC 4880 §6.1). The BEGIN/END headers are picked by rpgp from the dispatched type — `PublicKey` → `-----BEGIN PGP PUBLIC KEY BLOCK-----`, `Secret` → `-----BEGIN PGP PRIVATE KEY BLOCK-----`."
  - "Header-detection strategy: dispatch by tag via existing `pgp_primary_is_secret`, then call the matching composed-type constructor. Avoids a third parse path; reuses the same tag-5/tag-6 oracle the preview renderer uses for SECRET-key warning placement."
  - "Error funnel: every parse OR serialize failure routes through `pgp_parse_error()` — the same `\"malformed PGP packet stream\"` literal already used by `payload::ingest::pgp_key` and `render_pgp_preview`. Three call sites, ONE literal — oracle-hygiene single-source-of-truth."
  - "SPEC.md straggler fix: only the Phase 6 step-11 literal was widened. Plan 04 owns the full PGP SPEC.md section (new Material::PgpKey section, armor matrix, fingerprint format, error-reason table). Touching less in this plan keeps blast radius minimal."
patterns-established:
  - "rpgp armor delegation pattern: parse via composed type → emit via `to_armored_bytes(ArmorOptions::default())` → map errors to `pgp_parse_error()`. Reusable for any future PGP variant (signatures, certificates, messages) — same shape, different composed type."
  - "Variant-aware output dispatch: `if armor { match variant {...} } else { raw }` — extends mechanically as new variants gain armor support; the `unreachable!` arm is safe-by-construction because the material match above is the validation gate."
  - "Single-source-of-truth error literal across multiple call sites: the same curated `pgp_parse_error()` is reused by ingest, preview, and armor — Plan 04's `EXPECTED_REASONS` table only needs to track ONE PGP parse-error literal, not three."
requirements-completed: [PGP-03, PGP-05]
metrics:
  duration_minutes: 18
  tasks_completed: 1
  tests_added: 2
  test_suite_after: "165 passed / 0 failed / 9 ignored (existing wire-budget #[ignore]'d)"
  completed_date: "2026-04-25"
---

# Phase 7 Plan 03: Typed Material — PgpKey CLI Wiring Summary

**End-to-end wired the PGP variant into `cipherpost receive`: live `Material::PgpKey { .. }` arm in `run_receive` with pre-rendered acceptance subblock, `--armor` matrix widened to accept `pgp-key` via rpgp 0.19.0's `to_armored_bytes` (auto-selects `PUBLIC KEY` vs `PRIVATE KEY BLOCK` headers from the dispatched composed type), Phase 6 `Error::Config` rejection literal widened to `"--armor requires --material x509-cert or pgp-key"` across source + tests + SPEC.md, with rpgp imports source-grep-pinned to `src/preview.rs` + `src/payload/ingest.rs` only (D-P7-09 invariant intact).**

## Performance

- **Duration:** ~18 min
- **Started:** 2026-04-25 (during execute-phase)
- **Completed:** 2026-04-25
- **Tasks:** 1 (TDD — RED + GREEN commits)
- **Files modified:** 4

## Accomplishments

- `cipherpost receive` on a `PgpKey` share now renders the OpenPGP acceptance subblock (Fingerprint/UID/Key/Subkeys/Created, plus the `[WARNING: SECRET key — unlocks cryptographic operations]` first-line for tag-5 primaries) BEFORE the typed-z32 prompt — verify-before-reveal invariant preserved (T-07-18).
- `cipherpost receive --armor` on a `PgpKey` share emits ASCII-armored OpenPGP via rpgp's `to_armored_bytes(ArmorOptions::default())` — header automatically matches the primary tag (T-07-15 mitigated).
- `cipherpost receive` on a `PgpKey` share WITHOUT `--armor` emits the raw binary packet stream (bytes verbatim from `Material::PgpKey.bytes`) — D-P7-11 equivalent for PGP.
- `--armor` matrix updated: accepts `x509-cert` (Phase 6) + `pgp-key` (NEW). Rejects `generic-secret` and `ssh-key` with the widened literal.
- Phase 6 pinned test `armor_on_generic_secret_rejected_with_config_error` migrated cleanly to the widened literal — no false-fail on the existing X.509 test surface.
- D-P7-09 scope invariant intact: `grep -E "^use pgp|pgp::" src/flow.rs` returns 0 lines; rpgp confined to `src/preview.rs` + `src/payload/ingest.rs`.

## Task Commits

Single TDD task = two commits (RED → GREEN):

1. **Task 1 RED** — `83897b1` — `test(07-03): add failing tests for pgp_armor + widen Phase 6 armor reject literal`
   - 2 unit tests in `src/preview.rs::tests` pinning `pgp_armor` error contract
   - Updated `tests/x509_roundtrip.rs::armor_on_generic_secret_rejected_with_config_error` to expect the widened literal
   - Build fails with `E0425: cannot find function 'pgp_armor' in this scope` — RED confirmed

2. **Task 1 GREEN** — `589a08c` — `feat(07-03): wire PgpKey live arm in run_receive + pgp_armor helper`
   - `pub fn pgp_armor` in src/preview.rs (rpgp `to_armored_bytes` delegation)
   - `run_receive` PgpKey arm split out and made LIVE; SshKey arm preserved as `NotImplemented`
   - `--armor` matrix literal widened in src/flow.rs
   - Variant-aware armor output dispatch with `unreachable!` arm
   - SPEC.md §5.2 step 11 literal widened (straggler)
   - All 165 tests pass / 0 fail / 9 ignored (existing wire-budget `#[ignore]`s)

REFACTOR phase skipped — no cleanup needed; the GREEN implementation is direct and minimal.

_(No final metadata commit per parallel-executor convention; SUMMARY.md is committed as part of the executor close.)_

## Files Created/Modified

- `src/flow.rs` — Split `Material::PgpKey | Material::SshKey` arm: PgpKey LIVE (renders preview + threads subblock), SshKey still `NotImplemented`. Widened `Error::Config` literal. Variant-aware armor output dispatch with `unreachable!` for already-validated rejection arms.
- `src/preview.rs` — Added `pub fn pgp_armor(bytes) -> Result<Vec<u8>, Error>` delegating to rpgp 0.19.0's `to_armored_bytes(ArmorOptions::default())` on `SignedPublicKey` (tag-6) or `SignedSecretKey` (tag-5). Reuses `pgp_primary_is_secret` for tag dispatch and `pgp_parse_error()` for the curated error literal.
- `tests/x509_roundtrip.rs` — Updated the Phase 6 `armor_on_generic_secret_rejected_with_config_error` assertion to expect the widened literal `"--armor requires --material x509-cert or pgp-key"`. Updated docstring with widening rationale.
- `SPEC.md` — Updated §5.2 Receive step 11 to cite the widened literal (straggler — Plan 04 owns the full SPEC.md PGP rewrite).

## Critical Evidence for Plan 04

### Exact rpgp 0.19.0 armor API used in `pgp_armor`

```rust
use pgp::composed::ArmorOptions;

// Public-key path:
let key = SignedPublicKey::from_bytes(bytes).map_err(|_| pgp_parse_error())?;
key.to_armored_bytes(ArmorOptions::default())
    .map_err(|_| pgp_parse_error())

// Secret-key path:
let key = SignedSecretKey::from_bytes(bytes).map_err(|_| pgp_parse_error())?;
key.to_armored_bytes(ArmorOptions::default())
    .map_err(|_| pgp_parse_error())
```

`ArmorOptions::default()` = `{ headers: None, include_checksum: true }`. Verified at `~/.cargo/registry/src/index.crates.io-*/pgp-0.19.0/src/composed/message/types.rs:1325-1339`.

### BEGIN/END header determination

rpgp emits the BEGIN/END headers automatically from the dispatched composed type — NOT from a manual `BlockType` argument:

- `SignedPublicKey::to_armored_writer` → calls `armor::write(self, BlockType::PublicKey, ...)` → `-----BEGIN PGP PUBLIC KEY BLOCK-----` / `-----END PGP PUBLIC KEY BLOCK-----`
- `SignedSecretKey::to_armored_writer` → calls `armor::write(self, BlockType::PrivateKey, ...)` → `-----BEGIN PGP PRIVATE KEY BLOCK-----` / `-----END PGP PRIVATE KEY BLOCK-----`

Verified at `pgp-0.19.0/src/composed/signed_key/secret.rs:138` and `public.rs:132`.

**Implication for Plan 04's golden-string armor test:** assert that armored output for a public-key fixture starts with `-----BEGIN PGP PUBLIC KEY BLOCK-----\n` and a secret-key fixture starts with `-----BEGIN PGP PRIVATE KEY BLOCK-----\n`. Both end with the matching `-----END ...-----\n` after a CRC24 checksum line (`=` followed by 4 base64 chars). Default `include_checksum=true` produces the CRC24 — Plan 04 can opt out via `ArmorOptions { include_checksum: false, headers: None }` if golden-byte determinism becomes problematic, but matching `gpg --armor --export <key>` output is the cleaner contract.

### Acceptance grep matrix (post-GREEN)

```
preview::render_pgp_preview in flow.rs:                2 (1 call site + 1 docstring describing the call)
preview::pgp_armor in flow.rs:                         1 (call site)
as_pgp_key_bytes in flow.rs:                           1 (call site)
Material::PgpKey { .. } in flow.rs:                    3 (1 match arm + 1 armor dispatch arm + 1 in `material_type_string` from Plan 01)
Material::SshKey => in flow.rs:                        2 (run_receive arm + run_send arm; both NotImplemented)
"x509-cert or pgp-key" in flow.rs:                     1 (widened literal)
"x509-cert or pgp-key" in tests/x509_roundtrip.rs:     2 (assertion + docstring describing the widening)
old "x509-cert\"" literal anywhere in src + tests:     1 (only in the docstring on tests/x509_roundtrip.rs:275 explaining the historical change — no live assertion or Error::Config use)
pub fn pgp_armor in src/preview.rs:                    1
rpgp imports in flow.rs (^use pgp|pgp::):              0 ✓ (D-P7-09 invariant intact)
NotImplemented { phase: 7 } in flow.rs:                2 (run_send SshKey + run_receive SshKey; PgpKey-NotImplemented is GONE)
```

### Test results

- `cargo build --all-targets` → exit 0
- `cargo test --features mock` → 165 passed / 0 failed / 9 ignored (existing wire-budget `#[ignore]` marks; no new ignores introduced)
- New tests added (RED→GREEN):
  - `preview::tests::pgp_armor_rejects_garbage_with_curated_error` ✓
  - `preview::tests::pgp_armor_rejects_empty_input` ✓
- Updated tests:
  - `tests/x509_roundtrip.rs::armor_on_generic_secret_rejected_with_config_error` ✓ (passes against widened literal)

### Pinned regression matrix (verification step 5)

All green:
- `flow::tests::format_unix_as_iso_utc_epoch` ✓
- `phase2_envelope_round_trip` ✓
- `outer_record_canonical_form` ✓
- `phase3_receipt_canonical_form` ✓
- `hkdf_info_enumeration` ✓
- `debug_leak_scan` ✓
- `material_x509_envelope_round_trip` ✓
- `material_x509_ingest` ✓
- `x509_banner_render` ✓
- `x509_error_oracle` ✓

### `--armor` matrix literal exact wording (for Plan 07 hand-off)

Current literal as of this plan:
```
"--armor requires --material x509-cert or pgp-key"
```

**Plan 07 (D-P7-13) hand-off:** Plan 07 will REJECT `--armor` on `ssh-key` shares with a separate, more specific literal — likely `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"` per the plan's own spec. The current literal STAYS as the catch-all reject for `generic-secret`; Plan 07 may either:
1. Add a separate `Error::Config` raise inside the `Material::SshKey` arm in `run_receive` BEFORE returning `NotImplemented`, OR
2. Promote the literal into a per-variant lookup (cleaner but larger refactor).
The current `unreachable!()` arm in `run_receive`'s armor output dispatch STAYS unreachable because the SshKey path short-circuits at the material match (either via NotImplemented today or via the new Error::Config tomorrow).

## Decisions Made

1. **`pgp_armor` lives in `src/preview.rs` (Option A from the plan).** Reasoning:
   - Reuses the existing `pgp_primary_is_secret` discriminator and `pgp_parse_error()` funnel — both are private fns in preview.rs already.
   - Keeps rpgp surface in TWO files (preview.rs + payload/ingest.rs) — Option B (new module) would have made it three.
   - The "preview" module name is no longer purely about banner rendering after this addition, but the cohesion ("things involving the rpgp parser") is stronger than a name-purity concern.

2. **rpgp armor API selection: `to_armored_bytes(ArmorOptions::default())` on the composed key types.** Reasoning:
   - The other candidate (`pgp::armor::write` directly with explicit `BlockType`) requires us to make the BlockType decision in our code AND requires the bytes to round-trip through `Serialize` somehow. The composed-type API does both (parse + emit) in one call.
   - rpgp picks the right `BlockType` from the type itself — eliminates an entire class of bug (T-07-15 mitigation) where we could pass `BlockType::PublicKey` for a secret key.

3. **Tag-dispatch via existing `pgp_primary_is_secret` rather than a try-both-and-see fallback.** Reasoning:
   - Deterministic single path; no double-parse cost.
   - Errors funnel cleanly: malformed input fails at `pgp_primary_is_secret` (before even attempting the composed parse).

4. **Error funnel: every failure → `pgp_parse_error()`.** Reasoning:
   - Matches the literal already used by `payload::ingest::pgp_key` and `render_pgp_preview` — Plan 04's `EXPECTED_REASONS` only tracks ONE PGP parse-error literal.
   - Eliminates oracle leakage: a parse failure in `pgp_armor` is indistinguishable from one in `render_pgp_preview` is indistinguishable from one in ingest.

5. **SPEC.md straggler fix limited to the literal-only widening.** Reasoning:
   - Plan 04 owns the full PGP SPEC.md section (new `Material::PgpKey` section, armor matrix, fingerprint format, error-reason table). Touching less here keeps blast radius minimal.
   - Without the straggler fix the live source-of-truth literal in `flow.rs` would drift from SPEC.md — CI/lychee won't catch this but a careful reader would, and the existing literal is now flat-out wrong post-this-plan.

## Deviations from Plan

### Auto-fixed Issues

None. The plan's `<action>` block was followed step-by-step with no auto-fixes needed:
- Step A (helper location): selected Option A (preview.rs) per the plan's stated default.
- Step B (PgpKey/SshKey split): exact match to the plan's `<interfaces>` block.
- Step C (armor output): exact match to the plan's `<interfaces>` block.
- Step D (no rpgp in flow.rs): verified via grep — 0 matches.
- Step E (Phase 6 test update): exact literal swap; updated docstring with widening rationale.
- Step F (straggler check): one straggler in SPEC.md — fixed.
- Step G (full build + test): green.

### Documentation-level decisions (not code deviations)

**1. [Info] SPEC.md straggler fix scope-decision**

- **Where plan allowed discretion:** Step F says "If SPEC.md still has the old wording, fix it (Plan 04 does the full SPEC.md PGP section update; this step just catches stragglers)."
- **Choice made:** Updated the single offending literal at SPEC.md:422 (Phase 6 step-11 description) and added a one-sentence forward reference to "Plan 7's PGP/SSH SPEC sections" rather than rewriting the whole §5.2 paragraph. This is a strict straggler — the next sentence still says "PEM" specifically and Plan 04 will revisit.

**2. [Info] tests/x509_roundtrip.rs:275 docstring contains the OLD literal as historical context**

- **Why it appears in grep:** The docstring I added explains the widening: "Phase 7 Plan 03 widened the message from `\"--armor requires --material x509-cert\"` to `\"...x509-cert or pgp-key\"`". This is intentional historical documentation — the OLD form is cited explicitly so a future reader understands why the assertion is the wider form.
- **Net effect on the codebase:** Zero live `assert_eq!` or `Error::Config` references the old literal. The single docstring grep-hit is documentation, not code.

### Authentication gates

None encountered. Plan was fully autonomous.

## Issues Encountered

None during planned work. Two pre-existing out-of-scope issues observed but not fixed (per the executor's scope-boundary rule — "only auto-fix issues DIRECTLY caused by the current task's changes"):

## Deferred Issues

These exist BEFORE this plan and persist after; documented here so the verifier and downstream plans see them:

1. **`cargo fmt --check` reports 8 diffs in `src/payload/{ingest,mod}.rs` and `src/preview.rs`** at lines 281, 336, 437, 283, 346, 362, 422, 441. All are in code authored by Plan 01 + Plan 02 — verified by `git stash` revert showing the same 8 diffs without my changes. The new code I added in this plan introduces ZERO new fmt diffs (verified via `cargo fmt --check 2>&1 | grep -E "src/flow.rs|tests/x509_roundtrip.rs|SPEC.md"` → empty). Worth a small `cargo fmt` cleanup commit at phase close, but out of scope per Plan 03's stated file scope.

2. **`cargo clippy --all-targets --features mock -- -D warnings` reports `clippy::uninlined_format_args` in `build.rs:17`.** Pre-existing since `build.rs` was last touched by commit `70af7b1` (Phase 4 SPEC.md draft). Trivial one-line fix (`println!("...={sha}", sha)` → `println!("...={sha}")`) but out of scope per this plan's file list. Worth a separate chore commit at phase close.

Both fall under "pre-existing warnings in unrelated files — out of scope" per the executor scope-boundary rule. Logging here for downstream plans (Plan 04 verifier or a `chore: clippy + fmt cleanup` plan would resolve both in <5 min).

## User Setup Required

None — no external service configuration needed.

## Stubs Tracking

None. Every code path introduced by this plan is live:
- `pgp_armor` returns real ASCII-armored bytes via rpgp on the happy path, real `InvalidMaterial` on the error path.
- `run_receive`'s `Material::PgpKey { .. }` arm calls real `as_pgp_key_bytes()` + real `render_pgp_preview` + threads the resulting `String` through to the real `Prompter::render_and_confirm`.
- The variant-aware armor output dispatch invokes real `pem_armor_certificate` for X.509 and real `preview::pgp_armor` for PGP.
- The `unreachable!()` arm is a defensive no-op; the architectural argument (validated above the match) is sound and is enforced by the test suite (`armor_on_generic_secret_rejected_with_config_error`).

The fixture-backed integration tests for the full PGP send/receive round-trip (`pgp_self_round_trip_recovers_packet_stream`, `armor_on_pgp_share_emits_ascii_armor`, `armor_on_ssh_share_rejected_with_config_error`) land in Plan 04 once a real PGP fixture is committed. This is scope-documented (see plan `<behavior>` Test 2/3/4 + 07-02-SUMMARY.md hand-off) rather than a stub.

## Threat Flags

None. No new security-relevant surface introduced beyond what the plan's `<threat_model>` already enumerated. The `pgp_armor` helper output is bounded by the same `Material::PgpKey.bytes` already validated at ingest (Plan 01); the armor envelope is a UX format, not a cryptographic claim.

## Threat Model Status

All threats documented in the plan's `<threat_model>` are mitigated:

| Threat ID | Disposition | Status |
|-----------|-------------|--------|
| T-07-15 — PGP output-armor confusion attack (header mismatch on hand-rolled armor) | mitigate | Delegated to `SignedPublicKey::to_armored_bytes` / `SignedSecretKey::to_armored_bytes` — rpgp picks `BlockType::PublicKey` vs `PrivateKey` automatically from the dispatched type. We never construct the `BlockType` ourselves. |
| T-07-16 — error-oracle surface (widened literal accuracy) | mitigate | Single `Error::Config` raise site in `run_receive`'s GenericSecret arm; literal is the FULL list of armor-permitted variants. No drift between literal and accepted variants. |
| T-07-17 — rpgp scope creep into flow.rs | mitigate | `grep -E "^use pgp|pgp::" src/flow.rs` returns 0 lines. `pgp_armor` referenced as `preview::pgp_armor` — the only callable in flow.rs that touches rpgp is hidden behind the preview module boundary. |
| T-07-18 — pre-emit surface hygiene | mitigate | `preview::render_pgp_preview` returns `String`; `run_receive` passes it as `Option<&str>` to `Prompter::render_and_confirm` which is the FIRST side-effect-emitting call. Pattern unchanged from Phase 6 Plan 03. SECRET-key warning travels through the same channel — no `eprintln!` of PGP fields before the prompter opens. |
| T-07-19 — armor output mis-dispatch (unreachable! safety) | mitigate | `unreachable!()` arm is safe because: (a) GenericSecret + armor=true is rejected at the material match above; (b) SshKey early-returns NotImplemented at the material match before reaching the output block. Plan 07 (D-P7-13) keeps this invariant by rejecting armor on SSH BEFORE the output block runs. |

## Next Phase Readiness

**Plan 04 (PGP ship gate) is unblocked:**
- `preview::pgp_armor` is callable + has documented contract.
- `run_receive`'s PgpKey arm is LIVE — Plan 04's `pgp_self_round_trip_recovers_packet_stream` integration test under `AutoConfirmPrompter` will exercise the full path.
- The widened `Error::Config` literal is the assertion target for `armor_on_ssh_share_rejected_with_config_error` (Plan 04 may want a more specific literal per the Plan-07 hand-off note above).
- Golden-string armor test target: ASCII output starts with `-----BEGIN PGP PUBLIC KEY BLOCK-----\n` for tag-6 fixtures, `-----BEGIN PGP PRIVATE KEY BLOCK-----\n` for tag-5; trailing CRC24 line by default.

**Plan 04 inputs needed:**
- A real PGP fixture (≤200 B raw packet stream per Research GAP 5 — v4 Ed25519, ≤20-char UID, zero subkeys, minimal self-cert) committed to `tests/fixtures/`.
- Both public-key AND secret-key fixtures for the SECRET-warning + armor-header-PRIVATE assertions.

**Plan 07 (SSH foundation) hand-off:** the `--armor` matrix literal will be tightened once Plan 07 adds an SshKey-specific `Error::Config` raise BEFORE the existing NotImplemented short-circuit. The `unreachable!` arm in `run_receive`'s armor output stays unreachable — extending the matrix only adds another short-circuit `return Err(...)` at the material match.

## Self-Check: PASSED

- ✅ `src/preview.rs` — `pub fn pgp_armor(bytes: &[u8]) -> Result<Vec<u8>, Error>` present (1 match)
- ✅ `src/flow.rs` — `preview::render_pgp_preview` call site present (line 514)
- ✅ `src/flow.rs` — `preview::pgp_armor` call site present (1 match)
- ✅ `src/flow.rs` — `as_pgp_key_bytes` call site present (1 match)
- ✅ `src/flow.rs` — `Material::SshKey =>` arm in run_receive returns `NotImplemented { phase: 7 }`
- ✅ `src/flow.rs` — Widened literal `"--armor requires --material x509-cert or pgp-key"` present (1 match)
- ✅ `tests/x509_roundtrip.rs` — Updated assertion present (1 match)
- ✅ `src/flow.rs` — No `^use pgp|pgp::` imports (D-P7-09 scope invariant — 0 matches)
- ✅ `src/flow.rs` — No `Error::NotImplemented { phase: 7 }` for `Material::PgpKey` arm (PgpKey LIVE)
- ✅ Commit `83897b1` (Task 1 RED) present in `git log`
- ✅ Commit `589a08c` (Task 1 GREEN) present in `git log`
- ✅ All 2 new `pgp_armor` unit tests pass
- ✅ Updated Phase 6 widened-literal test passes
- ✅ Full `cargo test --features mock` suite green (165 passed / 0 failed / 9 ignored — pre-existing wire-budget `#[ignore]`s)
- ✅ Pinned regression matrix (10 tests) all green
- ✅ No file deletions in either commit
- ✅ Code I authored is fmt-clean (pre-existing fmt diffs in untouched preview.rs regions are out-of-scope)

---
*Phase: 07-typed-material-pgpkey-sshkey*
*Plan: 03*
*Completed: 2026-04-25*
