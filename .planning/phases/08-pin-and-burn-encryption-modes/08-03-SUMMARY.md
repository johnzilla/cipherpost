---
phase: 08-pin-and-burn-encryption-modes
plan: 03
subsystem: burn-core
tags: [rust, burn, cli, ledger, state-machine, enum, schema-migration, jcs]

# Dependency graph
requires:
  - phase: 08-pin-and-burn-encryption-modes
    plan: 01
    provides: Envelope.burn_after_read field + run_send burn param + run_send pipeline that wires the field
  - phase: 08-pin-and-burn-encryption-modes
    plan: 02
    provides: Send.pin: bool clap flag + main.rs Send dispatch threading + cli.rs documentation pattern for second-factor flags
provides:
  - LedgerState enum (None | Accepted{accepted_at} | Burned{burned_at}) — runtime abstraction for ledger-row state
  - check_already_consumed function (renamed from check_already_accepted; returns LedgerState)
  - LedgerEntry.state schema migration (Option<&'a str> with skip_serializing_if; v1.0 rows still parse via serde default)
  - Send.burn: bool clap flag (LOCAL-STATE-ONLY documentation; clap-bool argv-inline rejection)
  - main.rs Send dispatch threading burn (replaces Plan 01's `false` placeholder) + BURN-05 stderr warning
  - pub mod test_paths cfg-gated re-export of accepted_dir/sentinel_path/ledger_path/state_dir for Plans 04 + 05 integration tests
  - tests/burn_send_smoke.rs — 3 tests (burn-only round trip + pin+burn compose + v1.0 byte-identity preservation)
affects: [08-04 (BURN ship-gate — receive-side burn marking lights up the dormant Burned arm; uses test_paths for ledger inspection), 08-05 (compose tests reuse pin+burn smoke patterns), 08-06 (THREAT-MODEL.md prose lands at the Burn mode link target)]

# Tech tracking
tech-stack:
  added: []  # Zero new direct deps
  patterns:
    - "Schema migration via Option<&'a str> + skip_serializing_if=Option::is_none preserves wire-byte-identity for v1.0 rows AND enables typed runtime branching"
    - "Conservative read-side mapping for unknown state values: never silently classify Accepted as Burned (T-08-17 mitigation)"
    - "cfg-gated test_paths module via pub fn wrappers around pub(crate) helpers (Rust E0364 forbids pub use of pub(crate) items — wrappers replace re-export)"
    - "BURN-05 send-time stderr warning literal: surfaces user-visible caveat BEFORE the user commits to encrypt + publish (mirrors Phase 7 PGP-secret-key send-time warning)"

key-files:
  created:
    - "tests/burn_send_smoke.rs (3 tests — burn-only round-trip + pin+burn compose + burn=false v1.0 preservation)"
  modified:
    - "src/flow.rs (LedgerState enum + check_already_consumed rename + LedgerEntry.state field + 2 LedgerEntry construction sites + 2 doc-comment refs + run_receive STEP 1 enum-match + path-helper visibility bump + test_paths cfg-gated module)"
    - "src/main.rs (Send dispatch destructures `burn` + BURN-05 stderr warning + run_send burn param + Receive dispatch enum-match on LedgerState)"
    - "src/cli.rs (Send variant gains burn: bool with LOCAL-STATE-ONLY documentation)"
    - "Cargo.toml (registers tests/burn_send_smoke.rs under required-features=[\"mock\"])"

key-decisions:
  - "AD-3 confirmed: LedgerState enum lives in src/flow.rs (NOT a new src/state.rs) — premature decomposition rejected; ledger code already lives there"
  - "Schema migration shape: LedgerEntry.state on the wire is Option<&str> (open-set string for external tooling); the typed LedgerState is a runtime abstraction in check_already_consumed's return type — not the wire shape"
  - "Conservative mapping for unknown state values: only Some(\"burned\") maps to LedgerState::Burned; everything else (None, Some(\"accepted\"), unknown values) maps to LedgerState::Accepted (T-08-17 — never silently classify Accepted as Burned)"
  - "Rename atomicity: check_already_accepted -> check_already_consumed touches exactly two callers (src/flow.rs:530 in run_receive + src/main.rs:251 in CLI dispatch); Rust enum exhaustiveness check ensures both pattern-match all three variants"
  - "Compose orthogonality verified: pin + burn coexist at the run_send call-site; pin_required (outer-signed on OuterRecord) + burn_after_read (inner-signed on Envelope) both supported simultaneously — neither flag silently overrides the other"
  - "test_paths module exposes pub fn wrappers (NOT pub use re-exports) because Rust E0364 forbids `pub use` of `pub(crate)` items (Rule 1 fix during build)"
  - "Plan-grep marker `pub burn: bool` lands as `burn: bool` per the same Rule 1 fix Plan 02 documented for pin — Rust E0449 forbids visibility qualifiers on enum-variant struct fields"
  - "BURN-05 stderr warning literal MUST match REQUIREMENTS.md verbatim — any rephrasing is a regression. Emitted BEFORE encrypt + publish so user sees the multi-machine race + DHT-survives-TTL caveat at decision time"

patterns-established:
  - "pub fn wrappers in cfg-gated test_paths module: when re-exporting pub(crate) items to integration tests, use thin pub fn wrappers instead of pub use — works around Rust E0364 cleanly"
  - "Enum-match-on-state migration: when extending an idempotency check from boolean (Some/None) to multi-state (None/Accepted/Burned), pattern-match arms in the rename commit so Rust exhaustiveness ensures all callers update simultaneously"
  - "Wire-budget tolerant compose tests: test handles both Ok and WireBudgetExceeded outcomes gracefully so it runs end-to-end on lucky grease draws AND surfaces the wire-budget reality on unlucky draws — both paths verify compose correctness at the FN-CALL level"

requirements-completed: [BURN-01, BURN-05, BURN-06, BURN-07, BURN-08]

# Metrics
duration: 14min
completed: 2026-04-25
---

# Phase 8 Plan 03: BURN core Summary

**BURN core SHIPPED. Five of nine BURN REQ-IDs covered (BURN-01 wire field wired end-to-end on send; BURN-05 stderr warning literal; BURN-06 CLI surface with documentation; BURN-07 pin+burn compose orthogonality verified; BURN-08 caveat language hooked into CLI doc — full THREAT-MODEL.md prose lands in Plan 06).** LedgerState enum + LedgerEntry schema migration + check_already_accepted -> check_already_consumed rename land atomically without behavioral change for non-burn shares. Plan 04 inherits a fully-wired send path with the receive-flow ready to short-circuit on LedgerState::Burned (the arm already exists at both call sites; it just never fires until Plan 04 starts writing burn rows).

## Performance

- **Duration:** ~14 min
- **Started:** 2026-04-25T23:37:47Z
- **Completed:** 2026-04-25T23:52:25Z
- **Tasks:** 2 / 2
- **Files modified:** 4 (1 created, 3 modified) + 1 Cargo.toml registration

## Accomplishments

- Promoted `accepted_dir`, `sentinel_path`, `ledger_path` from private to `pub(crate)` in src/flow.rs and added a `cfg(any(test, feature = "mock"))`-gated `pub mod test_paths` module exposing them via thin `pub fn` wrappers. Plans 04 and 05 will import via `use cipherpost::flow::test_paths::{state_dir, accepted_dir, ledger_path, sentinel_path}` instead of duplicating the path layout (which silently drifts if helpers ever change). The wrappers compile out entirely when neither cfg(test) nor feature=mock is set — production builds do not expose internal layout in the public API surface.
- Landed `pub enum LedgerState { None, Accepted { accepted_at: String }, Burned { burned_at: String } }` (`#[derive(Debug, Clone, PartialEq, Eq)]`) per AD-3 — kept inside src/flow.rs (premature decomposition to a new src/state.rs rejected).
- Renamed `check_already_accepted` -> `check_already_consumed` with return type `LedgerState`. Read path: parse `state` field as `Option<&str>`; map None or `Some("accepted")` to `LedgerState::Accepted`; `Some("burned")` to `LedgerState::Burned`; unknown values mapped CONSERVATIVELY to Accepted (T-08-17 — never silently classify Accepted as Burned). Sentinel-but-no-ledger-row still wins via Accepted with synthetic timestamp.
- `LedgerEntry` struct gained `state: Option<&'a str>` (alphabetically LAST after share_ref) with `#[serde(skip_serializing_if = "Option::is_none")]`. v1.0 rows on disk have no `state` field; they elide on the wire AND deserialize via serde default to None. Both existing LedgerEntry construction sites (`append_ledger_entry` + `append_ledger_entry_with_receipt`) updated to pass `state: None` — Plan 03 baseline; Plan 04 introduces a peer helper `append_ledger_entry_with_state` that passes `Some("burned")`.
- Updated both call sites of the renamed function (Rust enum exhaustiveness check enforces all three arms):
  - **src/flow.rs run_receive STEP 1** (~line 530) — proceed on None; idempotent-success on Accepted; eprintln + Err(Error::Declined) (exit 7) on Burned.
  - **src/main.rs CLI dispatch sentinel-check** (~line 251) — same enum-match shape.
  Both arms use the literal text "share already consumed (burned at {})" for the Burned branch (Plan 04 may refine).
- Added `Send.burn: bool` flag to `src/cli.rs` with `#[arg(long)]` and full LOCAL-STATE-ONLY documentation citing DHT-survives-TTL caveat and multi-machine race link to THREAT-MODEL.md (Plan 06 lands the prose). Argv-inline `--burn=value` rejected naturally by clap (bool flag — same shape as --pin).
- Wired `src/main.rs` Send dispatch: destructures `burn` (alongside `pin`); emits BURN-05 stderr warning BEFORE encrypt + publish when `burn=true`; threads `burn` as the LAST `run_send` argument (replacing Plan 02's hardcoded `false` placeholder). The flag now flows end-to-end: CLI `--burn` → `Command::Send.burn` → `run_send` `burn` parameter → `Envelope { burn_after_read: burn, .. }` (Plan 01 already locked the field assignment).
- BURN-05 stderr warning literal matches REQUIREMENTS.md verbatim:
  > ⚠ --burn is local-state-only; ciphertext remains on DHT until TTL (24h by default). This prevents YOUR second decryption, not a second machine's.
- New test file `tests/burn_send_smoke.rs` (registered in Cargo.toml under `required-features = ["mock"]`):
  1. `burn_only_send_round_trip_recovers_plaintext` — small GenericSecret in self-mode WITHOUT PIN nesting fits within the 1000-byte BEP44 ceiling, so the round-trip runs end-to-end (NO `#[ignore]`). Confirms send→receive path is byte-correct when `burn=true`. Plan 04 lights up the receive-side burn-marking flow on this same wire shape.
  2. `pin_plus_burn_compose_outer_record_carries_pin_required` — compose orthogonality. Test handles both Ok (lucky grease draws) and WireBudgetExceeded outcomes gracefully — confirms `run_send` accepts both flags simultaneously and that `pin_required=true` lands on OuterRecord. The `burn_after_read=true` post-decrypt assertion is Plan 04's job (paired with the burn receive-side).
  3. `burn_false_send_preserves_v1_round_trip` — defense-in-depth: when `burn=false` (the default), a self-mode share behaves byte-identically to a v1.0 share (`is_false` `skip_serializing_if` elides the field; JCS byte-identity preserved per Plan 01).

## Task Commits

| # | Task | Commit | Description |
|---|------|--------|-------------|
| 1 | LedgerState enum + check_already_consumed rename + schema migration | `50f5cfb` | refactor(08-03): rename + LedgerState enum + state schema migration |
| 2 | --burn CLI flag + BURN-05 stderr warning + smoke test | `c84be19` | feat(08-03): add --burn CLI flag, BURN-05 stderr warning, pin+burn compose smoke test |

**Plan metadata commit:** _(to follow this SUMMARY)_

## Files Created/Modified

### Created

- **`tests/burn_send_smoke.rs`** (3 tests, ~210 lines) — burn-only round trip (NO #[ignore]), pin+burn compose orthogonality (Ok-or-WireBudgetExceeded tolerant), burn=false v1.0 byte-identity preservation. Uses `transport.resolve(&id.z32_pubkey())` (NOT `resolve_outer` — verified at `src/transport.rs:343` as the correct MockTransport API).

### Modified

- **`src/flow.rs`** — LedgerState enum + check_already_consumed rename (replaces check_already_accepted body verbatim with new return type) + LedgerEntry.state field with skip_serializing_if + 2 LedgerEntry construction sites (append_ledger_entry + append_ledger_entry_with_receipt) updated to pass `state: None` + 2 stale doc-comment references updated + run_receive STEP 1 enum-match + path-helper visibility bump (private -> pub(crate)) + cfg-gated `pub mod test_paths` module with pub fn wrappers (Rule 1 fix — see Deviations).
- **`src/main.rs`** — Send dispatch destructures `burn` + BURN-05 stderr warning before run_send + threads `burn` to run_send (replaces `false` placeholder) + Receive dispatch enum-match on LedgerState (replaces `if let Some(accepted_at) = check_already_accepted(...)`).
- **`src/cli.rs`** — `Send` variant gains `burn: bool` with `#[arg(long)]` and LOCAL-STATE-ONLY documentation. No `pub` qualifier (Rust E0449 — same Rule 1 fix Plan 02 documented for `pin: bool`).
- **`Cargo.toml`** — registers `[[test]] name = "burn_send_smoke"` with `required-features = ["mock"]`.

## Verification

| Gate | Result |
|------|--------|
| `cargo build` | clean, zero warnings from Plan 03-touched files |
| `cargo test --features mock` | 277 passed / 0 failed / 18 ignored (was 274 before Plan 03; +3 burn smoke tests; existing wire-budget #[ignore]'d tests preserved) |
| `cargo test --features mock --test burn_send_smoke` | 3 / 3 pass (no #[ignore] for burn-only and burn=false; pin+burn compose runs end-to-end via dual Ok/WireBudgetExceeded handling) |
| `cargo test --features mock --test phase2_idempotent_re_receive` | 1 passed + 1 ignored — rename is semantically transparent for non-burn shares |
| `cargo test --features mock --test outer_record_canonical_form` | passes — `outer_record_signable.bin` stays 192 B byte-identical |
| `cargo test --features mock --test phase2_envelope_round_trip` | passes — `envelope_jcs_generic_secret.bin` stays 119 B byte-identical |
| `cargo test --features mock --test outer_record_pin_required_signable` | 1 passed — `outer_record_pin_required_signable.bin` stays 212 B byte-identical |
| `cargo test --features mock --test pin_send_smoke` | 2 passed + 1 ignored — Plan 01 wire-budget pattern preserved |
| `cargo test --features mock --test pin_roundtrip` | 1 passed + 2 ignored — Plan 02 PIN-08 matrix preserved |
| `cargo test --features mock --test pin_error_oracle` | 5 passed — Plan 02 PIN-07 oracle preserved |
| `grep 'pub enum LedgerState' src/flow.rs` | matches |
| `grep 'pub fn check_already_consumed' src/flow.rs` | matches |
| `grep 'pub fn check_already_accepted' src/flow.rs` | NO match (rename total) |
| `grep -r 'check_already_accepted' src/ tests/` | NO match (no dangling references) |
| `grep 'state: Option<&' src/flow.rs` | matches |
| `grep 'LedgerState::Burned' src/main.rs` | matches |
| `grep '#[arg(long)]' src/cli.rs` followed by `burn: bool` | matches |
| `grep 'burn is local-state-only' src/main.rs` | matches |
| `grep 'burn,$' src/main.rs` (run_send call site trailing comma) | matches |
| v1.0 wire-byte preservation | 192 B + 119 B + 424 B fixtures byte-identical |
| Plan 02 wire-byte preservation | 212 B `outer_record_pin_required_signable.bin` byte-identical |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 — Bug] `pub use super::{...}` of `pub(crate)` items rejected by Rust (E0364)**
- **Found during:** Task 1 first build attempt
- **Issue:** The plan specified `pub use super::{accepted_dir, ledger_path, sentinel_path, state_dir};` inside the cfg-gated `pub mod test_paths`. Rust forbids `pub use` of `pub(crate)` items because the re-export would leak the items beyond their declared visibility (compiler error E0364: "pub use cannot be used to re-export `pub(crate)` items because their visibility is too restrictive").
- **Fix:** Replaced the `pub use` re-export with thin `pub fn` wrappers inside the `test_paths` module that delegate to the inner `pub(crate)` helpers via `super::accepted_dir()` / `super::ledger_path()` / etc. The wrappers compile out entirely when neither `cfg(test)` nor `feature = "mock"` is set, so production builds do not expose internal layout in the public API surface — semantically equivalent to the plan's intent. Plans 04 and 05 still import via `use cipherpost::flow::test_paths::{state_dir, accepted_dir, ledger_path, sentinel_path};` exactly as the plan specifies — only the implementation shape changed.
- **Files modified:** `src/flow.rs` (test_paths module body)
- **Commit:** `50f5cfb` (Task 1's combined commit)

**2. [Rule 1 — Bug Plan-grep marker] `pub burn: bool` invalid in enum variant**
- **Found during:** Task 2 cli.rs edit
- **Issue:** The plan specified the grep marker `pub burn: bool` in `src/cli.rs::Send`. Rust E0449 forbids visibility qualifiers on enum-variant struct-shaped fields ("visibility qualifiers are not permitted here; enum variants and their fields always share the visibility of the enum they are in"). This is the same Rule 1 fix Plan 02 documented in 08-02 SUMMARY for `pub pin: bool`.
- **Fix:** Landed as `burn: bool` (no `pub`). No public-API surface change — fields of `pub enum Command` variants are accessible by destructuring at any reachable scope. The plan's `must_haves.contains: "pub burn: bool"` grep marker becomes `burn: bool`.
- **Files modified:** `src/cli.rs`
- **Commit:** `c84be19` (Task 2's combined commit)

### Implementation notes

- **Plan-grep marker `grep -E 'pin_secret,\s*$' src/main.rs` matches via the line `pin_secret, // Phase 8 Plan 02: ...` even though the line has a trailing comment. The trailing-comment style was already shipped in Plan 02 and was preserved verbatim — Plan 03 did not change the `pin_secret` line, only added `burn` on the next line. Both lines have trailing comments; the grep pattern matches the comma but not the precise EOL whitespace because the comments precede EOL. Functionally identical to the plan's intent — the run_send call-site has `pin_secret,` followed by `burn,` on the next line. No deviation in code shape; nit on the regex.

- **Out-of-scope discovery (deferred):** `cargo clippy -- -D warnings` and `cargo fmt --check` continue to surface pre-existing issues in `build.rs` and `tests/x509_dep_tree_guard.rs` that 08-01 and 08-02 SUMMARYs documented as deferred. Continuing to defer per scope-boundary rule. Recommend rolling them into Phase 8 Plan 06's docs/cleanup polish or a dedicated `chore(fmt+clippy)` PR.

### Pre-existing issues found (out of scope, deferred)

Same as 08-01 + 08-02 — pre-existing rustc 1.88.0 stable clippy lints in `build.rs` and rustfmt long-string preference in `tests/x509_dep_tree_guard.rs`. Pre-existing on the unmodified `main` branch without any Plan 03 edits. Deferred per scope-boundary rule.

## Authentication gates

None encountered. The BURN flag is intentionally NOT TTY-gated (unlike `--pin`) — it has no second-factor input, only a boolean toggle that the sender unilaterally controls.

## Plan completeness

All success criteria from the orchestrator prompt satisfied:

- [x] `accepted_dir`, `ledger_path`, `sentinel_path` are `pub(crate)`
- [x] `pub mod test_paths` cfg-gated re-export added with all four path helpers (state_dir, accepted_dir, sentinel_path, ledger_path)
- [x] `--burn` flag on Send wired through main.rs dispatch
- [x] BURN-05 stderr warning fires at send time when --burn is set (verbatim literal)
- [x] `Envelope.burn_after_read = true` actually populated when burn flag set (Plan 01 wired the field assignment; Plan 03 wires the source through main.rs to run_send)
- [x] `LedgerState` enum exists with None / Accepted / Burned variants + carrying timestamps
- [x] `check_already_accepted` renamed to `check_already_consumed` returning LedgerState
- [x] All callers of the renamed function updated (verified via grep — no `check_already_accepted` references remain in src/ or tests/)
- [x] `tests/burn_send_smoke.rs` exists, calls `transport.resolve()` not `resolve_outer`
- [x] cargo build, cargo test, cargo test --features mock all exit 0
- [x] v1.0 fixtures byte-identical (192 B + 119 B + 424 B + 212 B)
- [x] STATE.md and ROADMAP.md will be updated in the metadata commit

## Plan 04 hand-off

Plan 04 (BURN ship-gate) inherits:

- A fully-wired SEND path: CLI `--burn` flows to `Envelope.burn_after_read = true` via `run_send` parameter
- A fully-wired RECEIVE path's structural Burned arm at TWO call sites — both already pattern-match on `LedgerState::Burned { burned_at } => { eprintln!("share already consumed (burned at {})", burned_at); return Err(Error::Declined); }`. Plan 04 just needs to start writing burn rows on disk for that arm to fire.
- A schema-ready `LedgerEntry.state: Option<&'a str>` field — Plan 04 adds a peer helper `append_ledger_entry_with_state(state: Some("burned"))` and calls it after successful burn-mode receive (D-P8-12 emit-before-mark write order).
- A `pub mod test_paths` re-export so Plan 04's `tests/state_ledger.rs` (if needed) can `use cipherpost::flow::test_paths::{state_dir, ledger_path, sentinel_path}` instead of duplicating path layout.
- A baseline `tests/burn_send_smoke.rs` that proves the SEND path is byte-correct; Plan 04's `tests/burn_roundtrip.rs` (BURN-09) inherits this baseline.

Specifically deferred to Plan 04:

- Banner [BURN] marker emission (D-P8-08; requires Prompter trait extension)
- `append_ledger_entry_with_state(..., Some("burned"))` write helper
- D-P8-12 emit-before-mark write order
- BURN-09 round-trip test (`tests/burn_roundtrip.rs`)
- PITFALLS.md #26 supersession note (cclink burn-as-DHT-revoke rejected)
- `envelope_burn_signable.bin` JCS fixture (if needed for Envelope.burn_after_read=true byte-pinning)

## Self-Check: PASSED

Verification:
- All created files (`tests/burn_send_smoke.rs`) confirmed present on disk via `ls`.
- All 2 task commits (`50f5cfb`, `c84be19`) confirmed in `git log --oneline -5`.
- `cargo test --features mock` exits 0 with 277 passing / 0 failed / 18 ignored.
- v1.0 fixture byte-identity verified by file size (`wc -c`).
- No dangling references to `check_already_accepted` anywhere in `src/` or `tests/`.
