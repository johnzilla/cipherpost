---
phase: 06-typed-material-x509cert
plan: 03
subsystem: flow
tags: [rust, cli, clap, x509, acceptance-banner, armor, prompter, dispatch]

# Dependency graph
requires:
  - phase: 06
    plan: 01
    provides: "Material::X509Cert { bytes } struct variant; payload::ingest::{generic_secret,x509_cert}; Error::InvalidMaterial variant"
  - phase: 06
    plan: 02
    provides: "preview::render_x509_preview(bytes) -> Result<String, Error>; format_unix_as_iso_utc pub(crate)"
  - phase: 05-non-interactive-automation-e2e
    provides: "Prompter trait + TtyPrompter + AutoConfirmPrompter/DeclinePrompter; run_send/run_receive orchestration; MaterialSource/OutputSink/SendMode; passphrase resolution precedence"
provides:
  - "MaterialVariant ValueEnum (generic-secret [default], x509-cert, pgp-key, ssh-key) in src/cli.rs"
  - "--material <variant> clap flag on Send; --armor boolean flag on Receive"
  - "run_send(..., material_variant: MaterialVariant, ttl_seconds) — dispatches through payload::ingest"
  - "run_receive(..., armor: bool) — matches on envelope.material, pre-renders X509 preview subblock, --armor output path"
  - "Prompter trait extended with preview_subblock: Option<&str> parameter (AD-1 Option A)"
  - "TtyPrompter emits subblock between Size: and TTL: lines when Some"
  - "Error::Config(\"--armor requires --material x509-cert\") rejection on GenericSecret-armor combo (OQ-1 resolved)"
  - "pem_armor_certificate helper — hand-rolled base64 + CERTIFICATE header/footer, no new dep"
  - "PgpKey/SshKey dispatch returns Error::NotImplemented{phase:7} with exit 1 (defense in depth: main.rs + run_send)"
affects: [06-04, 07-pgp-ssh]

# Tech tracking
tech-stack:
  added: []  # no new Cargo dependencies
  patterns:
    - "Pre-render-in-caller pattern for Prompter subblocks (AD-1 Option A): run_receive matches on envelope.material, calls preview::render_x509_preview, passes Option<&str> to TtyPrompter. Phase 7 extends with PGP/SSH arms mechanically."
    - "Cap-check-on-decoded-size: material.plaintext_size() runs AFTER ingest so a 1MB PEM → 100KB DER fails the 64KB cap on DECODED size, not input size"
    - "Defense-in-depth dispatch rejection: PgpKey/SshKey rejected at main.rs dispatch (before identity load) AND at flow::run_send (library-level safety)"
    - "MaterialSource unchanged — every existing Phase 2/3/5 integration test works with a single-arg addition (MaterialVariant::GenericSecret between material_source and ttl_seconds)"

key-files:
  created: []
  modified:
    - "src/cli.rs — MaterialVariant ValueEnum + --material / --armor flags"
    - "src/main.rs — MaterialVariant import; Send/Receive destructuring threads new flags; PGP/SSH dispatch rejection"
    - "src/flow.rs — run_send signature + body (ingest dispatch); run_receive signature + body (match-on-material, preview pre-render, --armor output); Prompter trait + 3 impls extended with preview_subblock; pem_armor_certificate helper"
    - "tests/phase2_self_round_trip.rs — import MaterialVariant; add GenericSecret + false args"
    - "tests/phase2_share_round_trip.rs — same"
    - "tests/phase2_size_cap.rs — same (run_send only, no run_receive)"
    - "tests/phase2_tamper_aborts_before_decrypt.rs — same"
    - "tests/phase2_expired_share.rs — run_receive-only; +false arg"
    - "tests/phase2_idempotent_re_receive.rs — same as round-trip tests"
    - "tests/phase2_cli_declined_exit_7.rs — same"
    - "tests/phase2_state_perms.rs — same"
    - "tests/phase3_end_to_end_a_sends_b_receipt.rs — same"
    - "tests/phase3_coexistence_b_self_share_and_receipt.rs — same"
    - "tests/phase3_share_ref_filter.rs — same"
    - "tests/phase3_tamper_zero_receipts.rs — run_receive-only; +false arg"
    - "tests/pass09_scripted_roundtrip.rs — same as round-trip tests"

key-decisions:
  - "AD-1 resolved as Option A: pre-render preview subblock in run_receive; TtyPrompter stays ignorant of x509-parser. Prompter trait gains ONE new Option<&str> arg; test prompters ignore it. Phase 7 extends the caller's match arm mechanically for PGP/SSH."
  - "AD-3 resolved as Option A: run_send gains material_variant: MaterialVariant param. MaterialSource::{Bytes,Stdin,File} unchanged so every existing test call site needs only a one-line addition of MaterialVariant::GenericSecret."
  - "OQ-1 resolved: --armor on GenericSecret is REJECTED with Error::Config(\"--armor requires --material x509-cert\") (exit 1). Silent-ignore invites user surprise; reject at dispatch with a specific reason."
  - "pem_armor_certificate is hand-rolled (no new dep): base64-STANDARD + 64-char wrapping + CERTIFICATE header/footer. The existing base64 0.22 crate already pulled by Phase 1 handles encoding; no new Cargo.toml changes."
  - "PgpKey/SshKey dispatch rejection at BOTH main.rs (before identity load — cheap) AND flow::run_send (library-level safety for any non-CLI caller). Belt-and-suspenders matches project convention for load-bearing rejection paths."
  - "run_send needed #[allow(clippy::too_many_arguments)] after the 7→8-arg bump. The Prompter trait already had the same attribute pre-plan; consistent style."

patterns-established:
  - "`match &envelope.material { Material::X509Cert { .. } => { let bytes = envelope.material.as_x509_cert_bytes()?; let sub = preview::render_x509_preview(bytes)?; (bytes, Some(sub)) } ... }` — the banner-subblock wiring shape Phase 7 extends for PgpKey / SshKey"
  - "Cap check order: `ingest` → `material.plaintext_size()` → `enforce_plaintext_cap(...)` — so 64KB applies to DECODED bytes, not raw input"
  - "Plan 04's future integration tests drive the X509 round-trip via AutoConfirmPrompter and assert material_bytes equals canonical DER (default) or PEM-wrapped bytes (armor=true); rejection via `Error::Config` exact-string match"

requirements-completed: [X509-03, X509-04, X509-05]

# Metrics
duration: 19min
completed: 2026-04-24
---

# Phase 6 Plan 03: CLI Surface + run_send/run_receive Wiring Summary

**`cipherpost send --material x509-cert` and `cipherpost receive [--armor]` shipped end-to-end: clap MaterialVariant ValueEnum + --armor flag, main.rs dispatch threads both into run_send/run_receive, run_send dispatches through payload::ingest with cap on decoded size, run_receive matches on envelope.material and pre-renders the X.509 subblock via preview::render_x509_preview for the Prompter trait (now extended with preview_subblock: Option<&str>).**

## Performance

- **Duration:** ~19 min
- **Started:** 2026-04-24T18:59:45Z
- **Completed:** 2026-04-24T19:19:33Z
- **Tasks:** 3 / 3
- **Files modified:** 16 (3 `src/`, 13 `tests/`)
- **Tests:** 115 passing under `cargo test --features mock` (no change from Plan 02 baseline — Plan 04 adds the X509 round-trip + golden-banner tests)

## Accomplishments

- **src/cli.rs** — `MaterialVariant` ValueEnum (generic-secret [default], x509-cert, pgp-key, ssh-key) in kebab-case, derived via `#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]`. Send command gains `material: MaterialVariant` field with `default_value_t = MaterialVariant::GenericSecret`. Receive command gains `armor: bool` field. Both `long_about` blocks extended with new examples.
- **src/main.rs** — imports `MaterialVariant` from `cipherpost::cli`; `Command::Send` destructuring threads `material` into `run_send` call; `Command::Receive` destructuring threads `armor` into `run_receive` call. PGP/SSH rejection fires at the top of Send (before passphrase resolution, before identity load) returning `Error::NotImplemented { phase: 7 }` (exit 1).
- **src/flow.rs** — `run_send` signature gains `material_variant: MaterialVariant` between `material_source` and `ttl_seconds`; dispatches to `payload::ingest::{generic_secret,x509_cert}` based on variant; PGP/SSH also return `NotImplemented{phase:7}` here (defense in depth). Cap check now uses `material.plaintext_size()` — 64 KB applies to DECODED DER length, not raw PEM input size (D-P6-16 / D-P6-18).
- `run_receive` signature gains `armor: bool` as the last parameter. At STEP 8 (post-decrypt, post-JCS-parse, PRE-prompt), the code matches on `&envelope.material` to select the correct byte accessor and (for X509Cert only) pre-render the subblock via `preview::render_x509_preview(bytes)`. `--armor` on GenericSecret is rejected with `Error::Config("--armor requires --material x509-cert")` (OQ-1 resolved). The rendered `Option<String>` flows to the Prompter via `.as_deref()`.
- **Prompter trait** — gains one new parameter: `preview_subblock: Option<&str>` between `size_bytes` and `ttl_remaining_seconds`. `TtyPrompter::render_and_confirm` emits `eprintln!("{}", sub)` between the `Size:` and `TTL:` lines when `Some`. `AutoConfirmPrompter` and `DeclinePrompter` add the `_preview_subblock: Option<&str>` parameter (ignored).
- **`pem_armor_certificate(der: &[u8]) -> Vec<u8>`** — hand-rolled PEM armor (no new dep): `-----BEGIN CERTIFICATE-----\n` + base64-STANDARD (64-char-wrapped) + `-----END CERTIFICATE-----\n`. Called only when `armor=true` and the variant is X509Cert (GenericSecret case already rejected at match).
- **All 13 existing integration tests** migrated to the new signatures with mechanical one-line additions (add `MaterialVariant::GenericSecret,` between `material_source` and `ttl_seconds`; append `false` to every `run_receive` call). Import `use cipherpost::cli::MaterialVariant;` added to all 11 files that call `run_send`.

## Task Commits

1. **Task 1: MaterialVariant ValueEnum + --material/--armor CLI flags** — `d7449a5` (feat)
2. **Task 2: main.rs dispatch threading + PGP/SSH dispatch rejection** — `ca8babd` (feat)
3. **Task 3: run_send/run_receive rewiring + Prompter trait extension + 13 test migrations** — `b6bb989` (feat)

**Plan metadata commit:** pending (this SUMMARY.md + STATE.md + ROADMAP.md + REQUIREMENTS.md)

## Test File Migrations (Change 8 — exact edits per file)

Per the plan's output spec, the complete migration list:

| File | run_send edit | run_receive edit | Added import? |
|------|---------------|-------------------|---------------|
| `tests/phase2_self_round_trip.rs` | `MaterialVariant::GenericSecret,` between `Bytes(plaintext.clone()),` and `DEFAULT_TTL_SECONDS` | append `false,` after `&AutoConfirmPrompter` | yes |
| `tests/phase2_share_round_trip.rs` | same pattern (share-mode) | append `false,` after `&AutoConfirmPrompter` (×2 — B decrypts + C fails) | yes |
| `tests/phase2_size_cap.rs` | same pattern (×2 — 64K cap + wire-budget cap) | no run_receive calls | yes |
| `tests/phase2_tamper_aborts_before_decrypt.rs` | same | append `false,` after `&AutoConfirmPrompter` (converted from one-line to multi-line form) | yes |
| `tests/phase2_expired_share.rs` | no run_send calls (constructs OuterRecord directly) | append `false,` after `&AutoConfirmPrompter` | no |
| `tests/phase2_idempotent_re_receive.rs` | same | append `false,` (×2 — first receive + second short-circuit) | yes |
| `tests/phase2_cli_declined_exit_7.rs` | same | append `false,` after `&DeclinePrompter` | yes |
| `tests/phase2_state_perms.rs` | same | append `false,` | yes |
| `tests/phase3_end_to_end_a_sends_b_receipt.rs` | same (share-mode) | append `false,` | yes |
| `tests/phase3_coexistence_b_self_share_and_receipt.rs` | same (×2 — B self-send + A→B share) | append `false,` | yes |
| `tests/phase3_share_ref_filter.rs` | same (×2 — two A→B cycles) | append `false,` (×2) | yes |
| `tests/phase3_tamper_zero_receipts.rs` | no run_send calls | append `false,` after `&AutoConfirmPrompter` | no |
| `tests/pass09_scripted_roundtrip.rs` | same (share-mode) | append `false,` after `&AutoConfirmPrompter` | yes |

No unexpected test failures encountered during migration. Every test passes on first run after the signature-threading fix.

**Files NOT requiring `use cipherpost::cli::MaterialVariant;` import:** `tests/phase2_expired_share.rs` and `tests/phase3_tamper_zero_receipts.rs` — both call `run_receive` only (constructing the OuterRecord directly without `run_send`), so the `MaterialVariant` type never appears in these files.

## x509_parser Import Bounds

Per the plan's verification step 5 — `grep -r "x509_parser" src/ | awk -F: '{print $1}' | sort -u`:

```
src/payload/ingest.rs
src/preview.rs
```

Two files only — matches Plan 02's invariant. `x509-parser` does NOT leak into `flow.rs`, `cli.rs`, or `main.rs`.

## --armor Rejection Error Message (exact wording)

Per the plan's output spec — the GenericSecret-armor rejection string is exactly:

```
--armor requires --material x509-cert
```

Wrapped in `Error::Config(...)` which maps to exit 1. Test assertion (Plan 04) should match this string byte-for-byte via `Error::Config(msg) if msg == "--armor requires --material x509-cert"`.

## Acceptance Banner Subblock Emit Order (verified)

TtyPrompter's render_and_confirm now emits (in order):

```
=== CIPHERPOST ACCEPTANCE ===============================
Purpose:     "..."
Sender:      ed25519:SHA256:...
             <z32-pubkey>
Share ref:   ...
Type:        x509_cert
Size:        N bytes
--- X.509 -----------------------------------------------
Subject:     ...
Issuer:      ...
Serial:      0x...
NotBefore:   YYYY-MM-DD HH:MM UTC
NotAfter:    YYYY-MM-DD HH:MM UTC  [VALID]|[EXPIRED]
Key:         ...
SHA-256:     ...
TTL:         Xh YYm remaining (expires ... UTC / ... local)
=========================================================
To accept, paste the sender's z32 pubkey and press Enter:
```

The subblock is emitted ONLY when `preview_subblock` is `Some` — GenericSecret shares render the original banner unchanged. Plan 04's golden-string test will pin the exact bytes.

## Decisions Made

- **AD-1 chosen as Option A** (pre-render in caller): `run_receive` owns the match-on-envelope.material decision; the Prompter trait gets ONE new `Option<&str>` arg; `TtyPrompter` stays ignorant of `x509-parser`. Rejected Option B because it would force the Prompter trait to know about `MaterialVariant` and `x509-parser` — concerns creep. Phase 7's PGP/SSH arms slot in mechanically as new match arms in the same `run_receive` location.
- **AD-3 chosen as Option A** (MaterialVariant in run_send signature): preserves `MaterialSource::{Bytes,Stdin,File}` unchanged so every existing Phase 2/3/5 integration test needs a single-line addition (`MaterialVariant::GenericSecret,`) rather than a construct-Material refactor. Compile-time-safe; no runtime dispatch cost.
- **OQ-1 chosen as "reject"**: `Error::Config("--armor requires --material x509-cert")` rather than silent-ignore. Matches the project's error-surface-explicit convention — a user who passes `--armor` expects PEM output; silent-ignore hands them raw bytes and wastes debug time.
- **Defense-in-depth PGP/SSH rejection**: rejection fires in BOTH `main.rs::dispatch` (before passphrase resolve, cheap) AND `flow::run_send` (library-level safety). Any future non-CLI caller of `run_send` (e.g., an integration test) still gets the clean typed error rather than a potentially confusing `InvalidMaterial` from a later code path.
- **Hand-rolled pem_armor_certificate (no new dep)**: `base64 0.22` is already pulled by Phase 1 for OuterRecord `blob` encoding. Hand-wrapping the ASCII output adds ~10 lines and avoids the `pem 3.0` / `rustls-pemfile 2.1` dep decision. Output matches `openssl x509 -in cert.der -inform DER -outform PEM` byte-for-byte (verified manually).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] `#[allow(clippy::too_many_arguments)]` needed on run_send**
- **Found during:** Task 3 final `cargo clippy --all-targets -- -D warnings` pass
- **Issue:** `run_send` signature went from 7 args to 8 (over clippy's 7-arg default threshold). clippy errored with `this function has too many arguments (8/7)`.
- **Fix:** Added `#[allow(clippy::too_many_arguments)]` attribute above `pub fn run_send`. Matches the pre-existing `#[allow]` on the `Prompter::render_and_confirm` trait method that already has 10 args.
- **Files modified:** `src/flow.rs`
- **Verification:** `cargo clippy --all-targets -- -D warnings` exit 0; full test suite still green.
- **Committed in:** `b6bb989` (Task 3 commit — included in the run_send signature change)

**2. [Rule 1 - Bug] `run_receive` also needed the same `#[allow]`**
- **Found during:** Same clippy pass
- **Issue:** `run_receive` went from 6 args to 7. Clippy's default threshold is 7 — so 7 args is still at the boundary but fine. Actually verified: `run_receive` has 7 args and clippy does NOT flag it. The `#[allow]` was preemptively added for consistency with run_send, so this is more documentation than bug-fix.
- **Fix:** Added `#[allow(clippy::too_many_arguments)]` above `pub fn run_receive` defensively.
- **Files modified:** `src/flow.rs`
- **Verification:** Same as above.
- **Committed in:** `b6bb989`

---

**Total deviations:** 2 auto-fixed (clippy attribute additions — style/documentation only)
**Impact on plan:** None — the `<allow>` additions are cosmetic; no behavior change; no scope creep. The plan's `<action>` for Task 3 did not explicitly mention the clippy attribute additions, so I'm recording them here rather than silently applying.

## Issues Encountered

- None beyond the trivial clippy attributes above. Build compiled cleanly on first try after Task 3's set of edits; all 115 existing tests passed without modification (beyond the mechanical signature-threading additions specified in Change 8).
- The `<action>` text for Task 1 said the `use clap::{Parser, Subcommand, ValueEnum};` import was conditionally needed; I ended up writing the derive as `#[derive(clap::ValueEnum, ...)]` with the fully-qualified path (per the acceptance criterion grep `grep "#\[derive(clap::ValueEnum"`) and keeping `use clap::{Parser, Subcommand};` unchanged — no unused-import warning, matches the acceptance criterion byte-for-byte.

## Threat Flags

None introduced by this plan beyond what's already in the phase threat model. The `<threat_model>` in PLAN.md covered T-06-11..15:

- **T-06-11 (cap on decoded size)** — mitigated: `material.plaintext_size()` replaces the old `plaintext_bytes.len()` call. A PEM-encoded cert that decodes to <64 KB DER passes; a 1 MB PEM decoding to >64 KB DER fails on the DECODED size.
- **T-06-12 (pre-emit surface hygiene)** — mitigated: `preview::render_x509_preview` returns a `String`; caller (`run_receive`) threads it via `Option<&str>` into `Prompter::render_and_confirm` which is THE FIRST side-effect-emitting call path for any envelope field. No `eprintln!` of cert data before the banner opens.
- **T-06-13 (oracle hygiene on --armor rejection)** — mitigated: `Error::Config("--armor requires --material x509-cert")` is a stable literal; no branching on internal state; no x509-parser internals leaked.
- **T-06-14 (share_ref tamper via pem_armor_certificate)** — accepted (not mitigated because no threat): `pem_armor_certificate` is a pure output-formatting function that does NOT touch the stored `Material::X509Cert.bytes` (canonical DER). `share_ref` was computed at send-time over the CIPHERTEXT of the canonical-DER envelope; a receiver's `--armor` flag affects only the bytes written to the sink, not any cryptographic commitment.
- **T-06-15 (PGP/SSH dispatch)** — mitigated: rejection at BOTH main.rs (before identity load) AND flow::run_send (library-level). Also rejected in run_receive's match on `envelope.material` (for the hypothetical case where a Phase 7 sender publishes a PgpKey / SshKey envelope that a Phase 6 receiver tries to decode — clean `NotImplemented{phase:7}` rather than `InvalidMaterial`).

No new security-relevant surface introduced. The `pem_armor_certificate` output path is the only new byte-producing code path and it operates on already-verified, already-decrypted, already-typed canonical DER. No new threat boundaries.

## User Setup Required

None — library + CLI changes only. No new env vars, no new external services, no new credentials. The `--armor` and `--material` flags are user-visible but documented in `--help` output (examples added to `long_about` on both Send and Receive).

## Next Phase Readiness

- **Plan 04 (integration tests + JCS fixture + SPEC.md update) ready.** The full X509 CLI surface is in place; Plan 04 can:
  1. Check in `tests/fixtures/x509_cert_fixture.der` (minimal Ed25519 self-signed cert per CONTEXT.md §specifics — Subject `CN=cipherpost-fixture, O=cipherpost, C=XX`, validity 2026-01-01 → 2028-01-01, serial `0x01`).
  2. Add `tests/material_x509_ingest.rs` covering: happy DER, happy PEM LF, happy PEM CRLF, PEM wrong-label, malformed DER, trailing bytes, generic_secret symmetry.
  3. Add `tests/x509_roundtrip.rs` driving `run_send(MaterialVariant::X509Cert) → run_receive(armor=false)` under `MockTransport + AutoConfirmPrompter`, asserting byte-identical canonical DER on the sink.
  4. Add a golden-string banner test pinning the exact subblock rendering against the fixture.
  5. Add an `--armor` round-trip asserting `-----BEGIN CERTIFICATE-----` + base64 + `-----END CERTIFICATE-----\n` shape on the sink.
  6. Add a `--armor` + GenericSecret rejection test asserting the exact error string `"--armor requires --material x509-cert"`.
  7. Add an enumeration test for every `Error::InvalidMaterial` reason string (per Plan 01 SUMMARY's table).
  8. Update SPEC.md §3.2 with the X509Cert wire shape + normalization contract; SPEC.md §Exit-code taxonomy with the InvalidMaterial row.
- **No blockers.** Cap-on-decoded-size pattern works as designed; Plan 04 can trip it by committing a fixture PEM that's <64 KB text but >64 KB base64-decoded DER (edge case worth covering in T-06-11 exercise).

## Self-Check: PASSED

- Commit `d7449a5` — FOUND (`feat(06-03): add MaterialVariant ValueEnum + --material / --armor CLI flags`)
- Commit `ca8babd` — FOUND (`feat(06-03): thread MaterialVariant/armor through main.rs dispatch`)
- Commit `b6bb989` — FOUND (`feat(06-03): wire run_send/run_receive + Prompter for typed X509Cert material`)
- `src/cli.rs` contains `pub enum MaterialVariant` — FOUND (grep match count 1)
- `src/cli.rs` contains `material: MaterialVariant` — FOUND
- `src/cli.rs` contains `armor: bool` — FOUND
- `src/main.rs` contains `use cipherpost::cli::{Cli, Command, IdentityCmd, MaterialVariant}` — FOUND
- `src/main.rs` contains `MaterialVariant::PgpKey | MaterialVariant::SshKey` — FOUND
- `src/flow.rs` contains `material_variant: MaterialVariant` — FOUND
- `src/flow.rs` contains `armor: bool` — FOUND
- `src/flow.rs` contains `preview_subblock: Option<&str>` — FOUND (4 occurrences: trait + TtyPrompter + 2 test prompters)
- `src/flow.rs` contains `"--armor requires --material x509-cert"` — FOUND
- `src/flow.rs` contains `fn pem_armor_certificate` — FOUND
- `src/flow.rs` contains `material.plaintext_size()` — FOUND (replaces the old plaintext_bytes.len() at the cap site)
- `src/flow.rs` contains `payload::ingest::x509_cert` + `payload::ingest::generic_secret` + `preview::render_x509_preview` — FOUND (1 each)
- `cargo build --all-targets` — exit 0
- `cargo test --lib` — 34/34 passing
- `cargo test --features mock` — 115/115 passing, 5 ignored (pre-existing `regenerate_*_fixture` + `gen_spec_test_vectors`)
- `cargo fmt --check` — exit 0
- `cargo clippy --all-targets -- -D warnings` — exit 0
- `grep -r "x509_parser" src/ | sort -u` — exactly 2 files (`src/payload/ingest.rs`, `src/preview.rs`)
- Help text verification: `cargo run -- send --help | grep material` shows `--material <MATERIAL>` with possible values `[generic-secret, x509-cert, pgp-key, ssh-key]` and `[default: generic-secret]`; `cargo run -- receive --help | grep armor` shows `--armor` with `Emit PEM-armored certificate output` description.

---
*Phase: 06-typed-material-x509cert*
*Completed: 2026-04-24*
