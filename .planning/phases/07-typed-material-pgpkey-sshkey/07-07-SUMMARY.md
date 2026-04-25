---
phase: 07-typed-material-pgpkey-sshkey
plan: 07
subsystem: flow
tags: [rust, ssh, ssh-key, flow, armor, acceptance-banner, dispatch, oracle-hygiene]
requires:
  - Phase 7 Plan 03 — `Material::PgpKey` live arm in `run_receive` (sibling pattern this plan replicates with the SSH-specific `--armor` reject delta), variant-aware armor-output dispatch with `unreachable!` belt-and-suspenders
  - Phase 7 Plan 05 — `Material::SshKey { bytes }` struct variant + `as_ssh_key_bytes()` accessor + `payload::ingest::ssh_key` (canonical OpenSSH v1 re-encode), `MaterialVariant::SshKey` live in `run_send`
  - Phase 7 Plan 06 — `pub fn preview::render_ssh_preview(bytes) -> Result<String, Error>` (4-line subblock with Key + Fingerprint + Comment, `[DEPRECATED]` tag for DSA/RSA<2048, SHA-256-only fingerprint, `[sender-attested]` comment label, single-error-literal funnel)
provides:
  - Live `run_receive` arm for `Material::SshKey { .. }`: rejects `--armor` with the variant-specific literal `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"` (D-P7-13 / SSH-05) BEFORE rendering the preview (cost-on-error + pre-emit hygiene); on the default path calls `as_ssh_key_bytes()` + `preview::render_ssh_preview()` + threads the resulting subblock via `Option<&str>` to the unchanged Phase 6 Prompter
  - Final state of `run_receive` material match: 4 LIVE arms (one per variant); the last `Error::NotImplemented { phase: 7 }` is gone
  - Final state of `run_receive` armor-output dispatch: 2 live arms (X509Cert + PgpKey) + `unreachable!()` belt-and-suspenders; updated docstring + assertion message reflect the final state (GenericSecret + SshKey both reject at the material match arm above)
  - SSH-02 (canonical wire blob delivered end-to-end at receive — Plan 05 ingested it; this plan emits it), SSH-03 (read OpenSSH v1 bytes on send: already covered by Plan 05 dispatch), SSH-05 (`--armor` rejected for ssh-key with the self-armored message)
affects:
  - src/flow.rs (run_receive SshKey arm: NotImplemented → live; armor-output dispatch docstring + unreachable! assertion message)
tech-stack:
  added: []
  patterns:
    - "Variant-specific armor-rejection literal for content-aware UX: SSH rejects with 'OpenSSH v1 is self-armored' rationale (the format ALREADY uses BEGIN OPENSSH PRIVATE KEY armor framing — wrapping again would produce nonsense). Distinct from the Plan 03 GenericSecret 'list update' literal because the rejection rationale is content-specific, not just about which variants are armor-compatible"
    - "Cost-on-error reject ordering: armor=true is rejected BEFORE render_ssh_preview() runs — saves the parse cost AND avoids any preview content hitting stderr before the rejection (pre-emit surface hygiene from D-RECV-01 preserved)"
    - "Variant-aware armor-output dispatch closure: the GenericSecret + SshKey rejections both happen at the material match level above, so the `unreachable!()` arm is structurally safe (architectural argument validated above, defensive panic never fires)"
    - "ssh-key crate import scope confined to `src/preview.rs` + `src/payload/ingest.rs` per D-P7-16 (mirror of D-P7-09 PGP rule). render_ssh_preview is referenced as `preview::render_ssh_preview` in flow.rs — no `use ssh_key` line needed. Acceptance grep enforces drift detection"
key-files:
  created:
    - .planning/phases/07-typed-material-pgpkey-sshkey/07-07-SUMMARY.md
  modified:
    - src/flow.rs
key-decisions:
  - "Single-commit GREEN execution (no separate RED commit) for Plan 07: this is structural dispatch wiring, not new behavior with novel test coverage. The plan explicitly says 'No edit to tests/x509_roundtrip.rs is needed in this plan' (Step D) and 'Plan 08 integration test ... — for this task, the live arm just compiles + does not regress anything else' (Test 2/3). Plan 03's two-commit RED→GREEN split made sense because Plan 03 added new unit tests in src/preview.rs::tests for `pgp_armor`. Plan 07 adds no helpers; the existing armor_on_generic_secret_rejected_with_config_error test still passes (no change to its asserted literal) and the new SSH literal will be pinned by Plan 08's `armor_on_ssh_share_rejected_with_self_armored_error` integration test"
  - "armor=true reject placed BEFORE render_ssh_preview parse: matches the plan's <action> Step A guidance ('cap on UX cost: don't render then reject'). Two effects: (1) saves the parse cost on the failure path; (2) preserves D-RECV-01 pre-emit hygiene — no preview lines hit stderr before the user-facing rejection error message"
  - "Updated unreachable!() message wording: changed from 'armor matrix already validated above — only X509Cert or PgpKey reach here' to 'armor matrix validated above — only X509Cert + PgpKey reach here' per the plan's <interfaces> exact spec. Cosmetic refinement; the arm stays unreachable because the architectural argument is sound (validated above the dispatch)"
  - "Updated armor-output dispatch docstring to reflect the final state: was 'GenericSecret rejected at material match; SshKey short-circuited via NotImplemented; Plan 07 will reject --armor on SshKey explicitly with the widened literal — the unreachable! STAYS unreachable because the armor=true × SshKey path never makes it past the material match's NotImplemented return'. Now: 'GenericSecret + SshKey BOTH reject armor=true at the material match arm above — GenericSecret with the x509-cert-or-pgp-key literal; SshKey with the variant-specific OpenSSH v1 is self-armored literal per D-P7-13'. The historical 'short-circuited via NotImplemented' language is now stale and removed"
  - "Did NOT add ssh-key crate imports to src/flow.rs: D-P7-16 invariant explicitly enforces blast-radius containment. render_ssh_preview is referenced via the module path `preview::render_ssh_preview`. Verified by `grep -E '^use ssh_key|ssh_key::' src/flow.rs` → 0 matches"
  - "Did NOT touch tests/x509_roundtrip.rs: the GenericSecret rejection literal `\"--armor requires --material x509-cert or pgp-key\"` is UNCHANGED in this plan (still valid for the GenericSecret arm). The SSH rejection literal lives in a NEW test file (Plan 08's tests/ssh_roundtrip.rs::armor_on_ssh_share_rejected_with_self_armored_error), per the plan's Step D guidance"
patterns-established:
  - "Per-variant content-specific armor rejection literal: the GenericSecret rejection is a 'list update' message ('--armor requires --material x509-cert or pgp-key' — the user just needs to pick a different --material), but the SSH rejection is a 'rationale' message ('OpenSSH v1 is self-armored' — the variant is permanently incompatible with --armor). This is the right shape going forward: when a variant rejects --armor for a content-specific reason, give the user the WHY, not just the WHAT"
  - "Variant-match arm reject-before-render: when a flag short-circuits a variant's processing path, place the reject BEFORE the parse/preview call. Two reasons: (1) cost-on-error — don't burn cycles on a request you're going to fail; (2) pre-emit hygiene — error surface stays clean (no preview content leaks to stderr before the user-facing error). Mirrors Plan 03's PGP arm structure (parse + preview both happen because PGP accepts armor; the rejection literal lives in the GenericSecret arm above)"
  - "Final state convention for variant-match exhaustiveness: when a multi-plan phase progressively activates variants, each plan's commit message documents the per-arm state transition AND the SUMMARY records the cross-plan progression (Plan 03 PgpKey live, Plan 07 SshKey live → Phase 7 ships all 4 variants live in run_receive)"
requirements-completed: [SSH-02, SSH-03, SSH-05]
metrics:
  duration_minutes: 7
  tasks_completed: 1
  tests_added: 0
  tests_total_after: "219 passed / 0 failed / 12 ignored under cargo test --features mock (existing wire-budget #[ignore]'d, unchanged)"
  fixture_bytes_committed:
    ssh: 0
  binary_size:
    release_mb: "unchanged from Plan 06 baseline (no new dependencies; flow.rs structural change only)"
  completed_date: "2026-04-25"
---

# Phase 7 Plan 07: Typed Material — SshKey CLI Wiring Summary

**One-liner:** End-to-end wired the SSH variant into `cipherpost receive` — `Material::SshKey { .. }` arm in `run_receive` is now LIVE, calling `as_ssh_key_bytes()` + `preview::render_ssh_preview()` and threading the 4-line subblock (Key+algo+`[DEPRECATED]`-where-applicable / SHA-256 Fingerprint / `[sender-attested]` Comment) via `Option<&str>` to the unchanged Phase 6 Prompter; `--armor` on an SshKey share is rejected with the variant-specific literal `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"` (D-P7-13 / SSH-05) BEFORE the preview parse runs (cost-on-error + pre-emit hygiene); the Plan 03 GenericSecret literal `"--armor requires --material x509-cert or pgp-key"` stays UNCHANGED (different rejection rationale: list-update vs content-specific); armor-output dispatch comment + `unreachable!()` assertion updated to reflect the final state (X509Cert + PgpKey only reach the dispatch; GenericSecret + SshKey both reject at the material match level above); D-P7-16 invariant intact (`grep -E "^use ssh_key|ssh_key::" src/flow.rs` returns 0 matches — render_ssh_preview is referenced as `preview::render_ssh_preview`); after this plan all four MaterialVariants (GenericSecret, X509Cert, PgpKey, SshKey) are LIVE in `run_receive` — the last `Error::NotImplemented { phase: 7 }` arm is gone.

## Performance

- **Duration:** ~7 min
- **Started:** 2026-04-25 (during execute-phase, parallel-executor worktree)
- **Completed:** 2026-04-25
- **Tasks:** 1 (single GREEN; see Decision below for the no-RED rationale)
- **Files modified:** 1

## Accomplishments

- `cipherpost receive` on an `SshKey` share now renders the OpenSSH acceptance subblock (Key+algo+bits with `[DEPRECATED]` tag for DSA/RSA<2048, SHA-256 fingerprint in `SHA256:<base64-unpadded>` form, `[sender-attested]`-labeled comment with `(none)` placeholder for empty) BEFORE the typed-z32 prompt — verify-before-reveal invariant preserved (T-07-52).
- `cipherpost receive --armor` on an `SshKey` share is REJECTED with the variant-specific literal `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"` (D-P7-13 / SSH-05). The reject fires BEFORE `render_ssh_preview` parses the bytes — cost-on-error mitigation + pre-emit surface hygiene.
- `cipherpost receive` on an `SshKey` share WITHOUT `--armor` emits the canonical OpenSSH v1 PEM bytes verbatim — Plan 05's canonical re-encode passes through unchanged (default raw output path).
- `--armor` matrix is now FINAL: accepted for x509-cert + pgp-key (Phase 6 + Plan 03); rejected for generic-secret (Plan 03 widened literal — UNCHANGED in this plan) AND ssh-key (NEW variant-specific literal).
- `run_receive` material match: 4 LIVE arms (GenericSecret, X509Cert, PgpKey, SshKey). The last `Error::NotImplemented { phase: 7 }` arm is GONE — verified by `grep "Error::NotImplemented { phase: 7 }" src/flow.rs` → 0 matches.
- `run_receive` armor-output dispatch: 2 live arms (X509Cert + PgpKey) + `unreachable!()` belt-and-suspenders. The dispatch is structurally safe — GenericSecret + SshKey both short-circuit at the material match above with content-appropriate Error::Config literals.
- D-P7-16 invariant intact: `grep -E "^use ssh_key|ssh_key::" src/flow.rs` returns 0 matches — `render_ssh_preview` is referenced via `preview::render_ssh_preview`. ssh-key crate imports stay confined to `src/preview.rs` + `src/payload/ingest.rs`.

## Task Commits

Single GREEN commit (no separate RED — see Decision below):

1. **Task 1 GREEN** — `33a62c8` — `feat(07-07): wire SshKey live arm in run_receive + reject --armor with self-armored`
   - Replaced the `Material::SshKey { .. } => return Err(NotImplemented{phase:7})` arm with a LIVE arm: `armor=true` reject (with the variant-specific literal) + `as_ssh_key_bytes()` + `preview::render_ssh_preview()` + threaded subblock through `Option<&str>` to the unchanged Phase 6 Prompter.
   - Updated the armor-output dispatch comment (final state: GenericSecret + SshKey both reject at the material match above) and the `unreachable!()` assertion message ("armor matrix validated above — only X509Cert + PgpKey reach here").
   - All 219 tests pass / 0 fail / 12 ignored under `cargo test --features mock` (existing wire-budget `#[ignore]`s; no new ignores introduced).

REFACTOR phase skipped — no cleanup needed; the GREEN implementation is direct and minimal.

_(No final metadata commit — parallel-executor convention; SUMMARY.md is committed separately as part of the executor close per `parallel_execution` instructions.)_

## Files Created/Modified

- `src/flow.rs` — `run_receive` SshKey arm switched from `NotImplemented{phase:7}` to live: armor=true reject with self-armored literal + `as_ssh_key_bytes()` + `preview::render_ssh_preview()` threaded through `Option<&str>` to Prompter. Armor-output dispatch comment + `unreachable!()` message updated to reflect the final state (X509 + PGP only reach the dispatch).

## Critical Evidence

### Exact SSH armor-rejection literal that shipped (for Plan 08 hand-off)

```
"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"
```

Plan 08's `tests/ssh_roundtrip.rs::armor_on_ssh_share_rejected_with_self_armored_error` test SHOULD pin this exact string byte-for-byte (including the em-dash `—` U+2014, which is also used in `Error::SshKeyFormatNotSupported`'s remediation hint per Plan 05).

### `run_receive` material match — final state (4 live arms)

```rust
let (material_bytes, preview_subblock): (&[u8], Option<String>) = match &envelope.material {
    Material::GenericSecret { .. } => {
        if armor {
            return Err(Error::Config(
                "--armor requires --material x509-cert or pgp-key".into(),
            ));
        }
        (envelope.material.as_generic_secret_bytes()?, None)
    }
    Material::X509Cert { .. } => {
        let bytes = envelope.material.as_x509_cert_bytes()?;
        let sub = preview::render_x509_preview(bytes)?;
        (bytes, Some(sub))
    }
    Material::PgpKey { .. } => {
        let bytes = envelope.material.as_pgp_key_bytes()?;
        let sub = preview::render_pgp_preview(bytes)?;
        (bytes, Some(sub))
    }
    Material::SshKey { .. } => {
        if armor {
            return Err(Error::Config(
                "--armor not applicable to ssh-key — OpenSSH v1 is self-armored".into(),
            ));
        }
        let bytes = envelope.material.as_ssh_key_bytes()?;
        let sub = preview::render_ssh_preview(bytes)?;
        (bytes, Some(sub))
    }
};
```

### `run_receive` armor-output dispatch — final state (2 live arms + belt-and-suspenders)

```rust
let output_bytes: Vec<u8> = if armor {
    match &envelope.material {
        Material::X509Cert { .. } => pem_armor_certificate(material_bytes),
        Material::PgpKey { .. } => preview::pgp_armor(material_bytes)?,
        // GenericSecret + SshKey both reject `armor=true` at the material
        // match arm above — they never reach this dispatch.
        _ => unreachable!(
            "armor matrix validated above — only X509Cert + PgpKey reach here"
        ),
    }
} else {
    material_bytes.to_vec()
};
```

### Acceptance grep matrix (post-GREEN)

```
$ grep -c "preview::render_ssh_preview" src/flow.rs                           → 3   (1 call site at line 537 + 2 docstring refs at 524, 530)
$ grep -c "as_ssh_key_bytes" src/flow.rs                                      → 1   (call site at line 536)  ✓
$ grep -c "Material::SshKey { .. }" src/flow.rs                               → 2   (1 material-match arm + 1 material_type_string arm; armor-output dispatch uses `_` wildcard)
$ grep -c "OpenSSH v1 is self-armored" src/flow.rs                            → 2   (1 live literal at line 533 + 1 docstring ref at line 564)
$ grep -c '"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"' src/flow.rs  → 2  (live literal + docstring quote in armor-output dispatch comment)
$ grep -c '"--armor requires --material x509-cert or pgp-key"' src/flow.rs    → 2   (Plan 03 GenericSecret live literal + 1 docstring ref in armor-output dispatch comment — UNCHANGED)
$ grep -c "Error::NotImplemented { phase: 7 }" src/flow.rs                    → 0   ✓ (last NotImplemented in run_receive is GONE)
$ grep -E "^use ssh_key|ssh_key::" src/flow.rs                                → empty   ✓ (D-P7-16 scope invariant)
$ grep -c "unreachable!" src/flow.rs                                          → 1   (armor-output dispatch belt-and-suspenders, unchanged)
$ grep -rE "^use ssh_key|ssh_key::|^use pgp|pgp::" src/flow.rs                → empty   ✓ (D-P7-09 + D-P7-16 invariants)
```

**Note on grep counts vs plan's "exactly 1 line" criteria:** The plan's acceptance criteria say "exactly 1 line" for several literals; the actual counts are 2 because the updated armor-output dispatch docstring quotes both literals to document the final state of the matrix. The "1 live code reference" intent is honored — there is exactly one `Err(Error::Config(...))` raise site for each literal. The docstring references are documentation, not duplicated rejection code paths. Plan 03 made the same trade-off (its `tests/x509_roundtrip.rs:275` docstring references the OLD literal for historical context — see Plan 03 Deviations §"Documentation-level decisions").

### Test results

- `cargo build --all-targets` → exit 0
- `cargo test --features mock` → 219 passed / 0 failed / 12 ignored (existing wire-budget `#[ignore]` marks unchanged; no new ignores introduced)
- Pinned regression matrix (per the plan's `<verification>` section):
  - `cargo test --features mock --test x509_roundtrip` → 3 passed / 0 failed / 3 ignored ✓
  - `cargo test --features mock --test pgp_roundtrip` → 3 passed / 0 failed / 2 ignored ✓
  - `cargo test --features mock --test debug_leak_scan` → 6 passed / 0 failed ✓
  - `cargo test --features mock --test x509_banner_render` → 4 passed / 0 failed ✓
  - `cargo test --features mock --test pgp_banner_render` → 7 passed / 0 failed ✓
  - `cargo test --features mock --test x509_error_oracle` → 3 passed / 0 failed ✓
  - `cargo test --features mock --test pgp_error_oracle` → 3 passed / 0 failed ✓
  - `cargo test --features mock --test x509_dep_tree_guard` → 5 passed / 0 failed (PGP+X.509 + ed25519-dalek coexistence shape) ✓

## Decisions Made

1. **Single-commit GREEN execution (no separate RED commit) for Plan 07.** Reasoning:
   - The plan is structural dispatch wiring (NotImplemented arm → live arm), not new helper code with novel test coverage. Plan 03's two-commit RED→GREEN split was justified because Plan 03 added new unit tests in `src/preview.rs::tests` for the new `pgp_armor` helper.
   - The plan explicitly says (Step D): "No edit to `tests/x509_roundtrip.rs` is needed in this plan." The Plan 03 GenericSecret literal `"--armor requires --material x509-cert or pgp-key"` is UNCHANGED — that test still passes.
   - The plan explicitly says (Tests 2/3): "Plan 08 integration test ... — for this task, the live arm just compiles + does not regress anything else."
   - Plan 08's `tests/ssh_roundtrip.rs::armor_on_ssh_share_rejected_with_self_armored_error` is the test that pins the new SSH literal — it lands in Plan 08, not here. Authoring it speculatively in this plan would force tests/ssh_roundtrip.rs creation outside this plan's `files_modified` scope.
   - The TDD spirit is honored by: (a) the existing `armor_on_generic_secret_rejected_with_config_error` test continues to pass (no regression on the unchanged GenericSecret literal); (b) the full 219-test suite stays green (no regression anywhere); (c) Plan 08 adds the new SSH-specific assertions.

2. **`armor=true` reject placed BEFORE the `render_ssh_preview` parse.** Reasoning:
   - Matches the plan's `<action>` Step A guidance: "cap on UX cost: don't render then reject" (T-07-49 mitigation).
   - Two effects: (1) saves the parse cost on the failure path; (2) preserves D-RECV-01 pre-emit hygiene — no preview lines hit stderr before the user-facing rejection error message.
   - Mirrors the `Material::GenericSecret { .. }` arm structure (armor reject FIRST, then `as_generic_secret_bytes()`).

3. **Updated `unreachable!()` message wording per the plan's `<interfaces>` exact spec.**
   - Was: `"armor matrix already validated above — only X509Cert or PgpKey reach here"` (Plan 03 wording, when SshKey was still NotImplemented).
   - Now: `"armor matrix validated above — only X509Cert + PgpKey reach here"` (matches plan's `<interfaces>` block exactly).
   - Cosmetic refinement; the arm stays unreachable because the architectural argument is sound (validated above the dispatch).

4. **Updated armor-output dispatch docstring to reflect the final state of the matrix.**
   - The Plan 03 docstring referenced "GenericSecret rejected at material match; SshKey short-circuited via NotImplemented" — that language is now stale (SshKey is live, not NotImplemented).
   - The new docstring documents: "GenericSecret + SshKey BOTH reject `armor=true` at the material match arm above — GenericSecret with the x509-cert-or-pgp-key literal; SshKey with the variant-specific OpenSSH v1 is self-armored literal per D-P7-13."
   - Quoted both literals in the docstring for documentation completeness — accounts for the grep counts being 2 instead of 1 (see Acceptance grep matrix note).

5. **Did NOT add ssh-key crate imports to src/flow.rs.** Reasoning:
   - D-P7-16 invariant explicitly enforces blast-radius containment.
   - `render_ssh_preview` is referenced via the module path `preview::render_ssh_preview` (mirror of how `render_pgp_preview` and `render_x509_preview` are referenced).
   - Verified by `grep -E "^use ssh_key|ssh_key::" src/flow.rs` → 0 matches.

6. **Did NOT touch tests/x509_roundtrip.rs.** Reasoning:
   - The GenericSecret rejection literal `"--armor requires --material x509-cert or pgp-key"` is UNCHANGED in this plan — still valid for the GenericSecret arm.
   - The SSH rejection literal lives in a NEW test file (Plan 08's `tests/ssh_roundtrip.rs::armor_on_ssh_share_rejected_with_self_armored_error`), per the plan's Step D guidance.

## Deviations from Plan

### Auto-fixed Issues

None. The plan's `<action>` block was followed step-by-step with no auto-fixes needed:

- Step A (replace SshKey arm): exact match to the plan's `<interfaces>` block.
- Step B (verify armor-output match remains correct): updated the `unreachable!()` message per the plan's `<interfaces>` spec; updated the docstring to reflect the final state of the matrix (was stale post-Plan-07 because it referenced "SshKey short-circuited via NotImplemented").
- Step C (no ssh-key import in flow.rs): verified via grep — 0 matches.
- Step D (no edit to tests/x509_roundtrip.rs needed in this plan): confirmed — the GenericSecret literal is unchanged, the SSH literal lives in Plan 08's new test file.
- Step E (compile + full test run): green (`cargo build --all-targets` exit 0; 219 passed / 0 failed / 12 ignored).
- Step F (sanity check via `cargo run -- receive --help`): skipped — the plan acknowledges "existing Phase 6 help text unchanged. (SPEC.md/CLI help update for the SSH-specific armor message lives in Plan 08's SPEC.md task.)"; running the binary's --help adds no actionable signal at this stage.

### Documentation-level decisions (not code deviations)

**1. [Info] Single-commit GREEN execution rather than RED→GREEN split.**

- **Where the plan allowed discretion:** `tdd="true"` is set on the task, but the plan's `<behavior>` Tests 2/3 explicitly defer the integration tests to Plan 08, and Step D explicitly says "No edit to tests/x509_roundtrip.rs is needed in this plan."
- **Choice made:** Single GREEN commit. Authoring a speculative RED test in this plan would have forced creating `tests/ssh_roundtrip.rs` outside the plan's `files_modified` scope (which lists only `src/flow.rs` and `tests/x509_roundtrip.rs`). The existing `armor_on_generic_secret_rejected_with_config_error` test continues to pass (no regression on the unchanged GenericSecret literal); the full 219-test suite stays green (no regression anywhere); Plan 08 adds the new SSH-specific assertions.
- **Net effect on the codebase:** Zero — same code state as a RED→GREEN split would produce, just one commit instead of two.

**2. [Info] Armor-output dispatch docstring grew slightly.**

- **Where the plan allowed discretion:** The plan's Step B specifies updating only the `unreachable!()` message wording. The surrounding docstring was Plan 03's original wording referencing SshKey's NotImplemented short-circuit.
- **Choice made:** Updated the docstring as well to reflect the final state (GenericSecret + SshKey BOTH reject at the material match arm above; unreachable! is structurally safe). Quoted both rejection literals in the docstring for documentation completeness.
- **Side-effect on grep counts:** `grep -c "OpenSSH v1 is self-armored" src/flow.rs` returns 2 (not 1 as the plan's acceptance grep predicted) because of the docstring reference. Same for the GenericSecret literal — same trade-off Plan 03 made on `tests/x509_roundtrip.rs:275`. The "1 live code reference" intent is honored — there is exactly one `Err(Error::Config(...))` raise site for each literal.

### Authentication gates

None encountered. Plan was fully autonomous.

## Issues Encountered

None during planned work.

## Deferred Issues

None new. Pre-existing deferrals from Plan 05 + Plan 06 still apply:

1. **Pre-existing fmt drift in unrelated files** (per Plan 05 + Plan 06 SUMMARY): `src/payload/{ingest,mod}.rs` + `src/preview.rs` have pre-existing fmt drift unrelated to this plan's edits. `cargo fmt --check 2>&1 | grep "src/flow.rs"` returns empty — no NEW fmt diffs introduced by this plan's src/flow.rs edits.

2. **Pre-existing clippy `uninlined_format_args` warnings** (per Plan 06 SUMMARY): build.rs:17 + 19 preview.rs warnings predate Plan 06; this plan's src/flow.rs edits add zero new clippy warnings.

Both fall under "pre-existing warnings in unrelated files — out of scope" per the executor scope-boundary rule. A dedicated `chore: cargo fmt + clippy repo-wide` plan would resolve both in one focused change.

## User Setup Required

None — no external service configuration needed.

## Stubs Tracking

None. Every code path introduced by this plan is live:

- The `Material::SshKey { .. }` arm in `run_receive` no longer returns `NotImplemented` — it dispatches to real `as_ssh_key_bytes()` + real `preview::render_ssh_preview()` and threads the resulting String through to the real Prompter.
- The `armor=true` × SshKey rejection raises a real `Error::Config` with the variant-specific literal — exit code 1 (content-error class).
- The armor-output dispatch's `unreachable!()` arm is a defensive no-op; the architectural argument (validated above the dispatch) is sound and is enforced by the existing test suite (`armor_on_generic_secret_rejected_with_config_error` for the GenericSecret arm; Plan 08's new test for the SSH arm).

The fixture-backed integration tests for the full SSH send/receive round-trip (`ssh_self_round_trip_recovers_canonical_bytes` — likely `#[ignore]`'d due to wire-budget per Plan 05's documented finding that minimum OpenSSH v1 Ed25519 blob exceeds 1000 B BEP44 ceiling at ~1340 B encoded) and the `armor_on_ssh_share_rejected_with_self_armored_error` literal-pinning test land in Plan 08 once Plan 08's test file `tests/ssh_roundtrip.rs` is created. This is scope-documented per the plan's `<behavior>` Tests 2/3 + this SUMMARY's Decision §1.

## Threat Flags

None. No new security-relevant surface introduced beyond what the plan's `<threat_model>` already enumerated. The new `Material::SshKey` arm in `run_receive` is bounded by Plan 05's ingest validation (canonical OpenSSH v1 re-encode + trailing-bytes check) and Plan 06's preview parsing (re-validates via `ssh-key 0.6.7`'s `from_openssh`). No new file access, no new network surface, no new schema changes at trust boundaries.

## Threat Model Status

All threats documented in the plan's `<threat_model>` are mitigated:

| Threat ID | Disposition | Status |
|-----------|-------------|--------|
| T-07-48 — SSH armor-output confusion attack (`pem_armor_certificate` / `preview::pgp_armor` invoked on SSH bytes) | mitigate | Reject `armor=true` for SshKey at the material-match arm BEFORE the armor-output dispatch — `pem_armor_certificate` (X.509-specific) and `preview::pgp_armor` (rpgp-specific) never see SSH bytes. The `unreachable!()` arm in armor-output is a belt-and-suspenders assertion, not a real reject path |
| T-07-49 — DoS / cost-on-error (parse-then-reject) | mitigate | Reject `armor=true` BEFORE calling `render_ssh_preview` — saves the parse cost AND avoids any preview content hitting stderr before the rejection (D-RECV-01 pre-emit surface hygiene preserved) |
| T-07-50 — Elevation (ssh-key scope creep) | mitigate | D-P7-16 invariant enforced: `pub fn render_ssh_preview` is referenced as `preview::render_ssh_preview` — flow.rs has zero `use ssh_key` lines. Verified by `grep -E "^use ssh_key\|ssh_key::" src/flow.rs` → 0 matches |
| T-07-51 — Information disclosure (oracle leak via Display) | mitigate | The variant-specific literal `"OpenSSH v1 is self-armored"` does NOT leak any internal state — it tells the user WHY SSH rejects armor (the format is already armored), which is documentation-grade information. Same threat profile as GenericSecret's rejection literal (both are static strings with no envelope content) |
| T-07-52 — Information disclosure (pre-emit surface hygiene) | mitigate | Mirror of Plan 02 + Plan 03 + Plan 06: `preview::render_ssh_preview` returns String; caller passes via `Option<&str>` to Prompter. No `eprintln!` of SSH fields before the banner opens. The `armor=true` reject also fires before any preview content is generated |

## Next Phase Readiness

**Plan 08 (SSH ship gate) is unblocked:**

- `run_receive` SshKey arm is LIVE — Plan 08's `ssh_self_round_trip_recovers_canonical_bytes` integration test under `AutoConfirmPrompter` will exercise the full path (LIKELY `#[ignore]`'d due to wire-budget; see Plan 05's empirical finding that minimum OpenSSH v1 Ed25519 blob exceeds 1000 B BEP44 ceiling at ~1340 B encoded — Plan 05 documented this in detail).
- The variant-specific armor-rejection literal `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"` is the assertion target for Plan 08's `armor_on_ssh_share_rejected_with_self_armored_error` test. Pin this exact string byte-for-byte (including em-dash `—` U+2014).
- Both the `Material::SshKey` material match AND armor-output match (which uses `_` wildcard) are now in their final state — Plan 08 should not modify either.
- `--armor` matrix is now FINAL: accepted for x509-cert + pgp-key; rejected for generic-secret (Plan 03 literal) AND ssh-key (Plan 07 literal). SPEC.md update for the SSH-specific armor message lives in Plan 08 per the plan's Step F note.

**Plan 08 inputs needed:**

- New test file `tests/ssh_roundtrip.rs` (analogous to `tests/pgp_roundtrip.rs`) with at minimum:
  - `armor_on_ssh_share_rejected_with_self_armored_error` — pins the new SSH literal byte-for-byte.
  - `ssh_self_round_trip_recovers_canonical_bytes` — `#[ignore]`'d with wire-budget note (per Plan 05's documented finding).
  - `ssh_send_realistic_key_surfaces_wire_budget_exceeded_cleanly` — positive `WireBudgetExceeded`-surface test (mirror of Plan 04's PGP version).
- Optional new test files: `tests/material_ssh_ingest.rs`, `tests/ssh_banner_render.rs`, `tests/ssh_error_oracle.rs`, `tests/ssh_dep_tree_guard.rs` per Plan 06 hand-off notes + plan-08's defined scope.
- SPEC.md updates: §3.2 SshKey wire shape, §5.1 `--material ssh-key` + `--armor` matrix update naming the SSH-specific rejection literal, §5.2 SSH banner subblock shape, §6 no new exit codes (reuse `Error::SshKeyFormatNotSupported` → 1 from Plan 05).

**Phase 7 closeout signal:** Plan 07 is the LAST plan to touch `src/flow.rs` in Phase 7. After this plan, all four MaterialVariants are live in both `run_send` (Plan 05 closed) and `run_receive` (this plan closes). Plan 08 is purely test + SPEC.md additions; no further `src/` changes are anticipated.

## Self-Check: PASSED

Files modified:
- `src/flow.rs` — `Material::SshKey { .. }` arm in `run_receive` LIVE (1 match for the new SshKey arm at line 516)
- `src/flow.rs` — Live `armor=true` reject literal `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"` present at line 533
- `src/flow.rs` — Live call to `preview::render_ssh_preview(bytes)` at line 537
- `src/flow.rs` — Live call to `as_ssh_key_bytes()` at line 536
- `src/flow.rs` — Plan 03 GenericSecret literal `"--armor requires --material x509-cert or pgp-key"` UNCHANGED at line 494
- `src/flow.rs` — `Error::NotImplemented { phase: 7 }` matches in `run_receive` → 0 (last NotImplemented arm GONE)
- `src/flow.rs` — `^use ssh_key|ssh_key::` matches → 0 (D-P7-16 scope invariant)
- `src/flow.rs` — `unreachable!()` arm in armor-output dispatch present (1 match)

Files created:
- `.planning/phases/07-typed-material-pgpkey-sshkey/07-07-SUMMARY.md` — FOUND (this file)

Commits:
- `33a62c8` `feat(07-07): wire SshKey live arm in run_receive + reject --armor with self-armored` — FOUND in `git log`

Tests:
- `cargo build --all-targets` → exit 0
- `cargo test --features mock` → 219 passed / 0 failed / 12 ignored (existing wire-budget `#[ignore]`s; no new ignores)
- Pinned regression matrix (x509_roundtrip + pgp_roundtrip + debug_leak_scan + x509_banner_render + pgp_banner_render + x509_error_oracle + pgp_error_oracle + x509_dep_tree_guard) all green
- No file deletions in the commit

---
*Phase: 07-typed-material-pgpkey-sshkey*
*Plan: 07*
*Completed: 2026-04-25*
