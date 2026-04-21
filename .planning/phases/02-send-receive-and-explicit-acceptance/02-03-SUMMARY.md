---
phase: 02-send-receive-and-explicit-acceptance
plan: 03
subsystem: cli-dispatch
tags:
  - cli-wiring
  - dispatcher
  - tty-prompt
  - acceptance-screen
  - assert-cmd
  - rust

# Dependency graph
requires:
  - phase: 01-foundation-scaffold-vendored-primitives-and-transport-seam
    provides: Cli/Command clap tree (locked, D-11), fn main run/dispatch/exit-code shape, Error (Config/Declined/Signature*/etc.), identity::resolve_passphrase + load + show_fingerprints, transport::DhtTransport + Transport trait, build.rs CIPHERPOST_GIT_SHA emission
  - phase: 02-send-receive-and-explicit-acceptance/02-01
    provides: ShareUri::parse, Envelope / Material, strip_control_chars, enforce_plaintext_cap, Error::{InvalidShareUri, ShareRefMismatch, WireBudgetExceeded}, Identity::signing_seed
  - phase: 02-send-receive-and-explicit-acceptance/02-02
    provides: run_send, run_receive, Prompter trait, SendMode / MaterialSource / OutputSink, check_already_accepted, state_dir, test_helpers::{AutoConfirmPrompter, DeclinePrompter}, DEFAULT_TTL_SECONDS

provides:
  - TtyPrompter struct + Prompter impl rendering D-ACCEPT-02 banner to stderr and reading typed z32 via dialoguer::Input
  - std::io::IsTerminal-based TTY pre-check enforced on stdin AND stderr (D-ACCEPT-03)
  - Production-safe skip override CIPHERPOST_SKIP_TTY_CHECK cfg-gated on cfg(any(test, feature = "mock")) — cannot be honored by release builds without --features mock
  - main.rs::dispatch Send arm wiring resolve_passphrase -> identity::load -> Keypair::from_secret_key(signing_seed) -> SendMode dispatch -> MaterialSource resolution -> run_send -> stdout URI
  - main.rs::dispatch Receive arm wiring ShareUri::parse -> sentinel-first (D-RECV-02) -> resolve_passphrase -> identity::load -> OutputSink -> TtyPrompter -> run_receive
  - Mock-feature-gated CIPHERPOST_USE_MOCK_TRANSPORT env-var switch in main.rs (tests only; cross-process sharing explicitly NOT supported)
  - Six CLI-driven integration tests (five via assert_cmd, one library-level) proving CLI-03, CLI-04, CLI-05, decline-exit-7 (SC3), and pre-TtyPrompter exit-code taxonomy
  - Library-level unit test tty_prompter_rejects_non_tty_env authoritatively verifying D-ACCEPT-03 error variant + message
  - 02-HUMAN-UAT.md capturing two pending interactive items (TTY acceptance happy path, optional real-DHT cross-identity round trip)

affects:
  - 03 (Phase 3 signed receipt — will reuse TtyPrompter patterns if receipts gain interactive display, and will extend the existing .planning state ledger schema for receipt_published_at)
  - 04 (Phase 4 SPEC.md / THREAT-MODEL.md — D-ACCEPT-02 banner layout and exit-code taxonomy are now locked in code; Phase 4 documents them as v1 spec source-of-truth)

# Tech tracking
tech-stack:
  added: []  # No new dependencies. chrono intentionally NOT added; hand-rolled format_unix_as_iso_utc reused civil_from_days from Plan 02.
  patterns:
    - "std::io::IsTerminal on Rust 1.70+ (MSRV 1.85 covers) for stdin/stderr TTY detection"
    - "Compile-time defense: tty_check_skipped() hardcodes false in non-mock non-test builds; skip env var is impossible to honor in production"
    - "Fallback to std::io::stdin().read_line() when tty_check_skipped() is true so assert_cmd tests can script stdin via a pipe"
    - "ASCII double-quote wrapping of purpose in banner + defensive re-strip of control chars at render time (belt-and-suspenders over Plan 01 send-time strip)"
    - "cfg(feature = \"mock\") env-var transport switch in main.rs::dispatch — only compiled into test binaries"

key-files:
  created:
    - tests/phase2_cli_version_git_sha.rs
    - tests/phase2_cli_help_examples.rs
    - tests/phase2_cli_stderr_no_secrets.rs
    - tests/phase2_cli_declined_exit_7.rs
    - tests/phase2_cli_not_tty_aborts.rs
    - .planning/phases/02-send-receive-and-explicit-acceptance/02-HUMAN-UAT.md
  modified:
    - src/flow.rs (+183 lines: TtyPrompter, IsTerminal check, format_ttl_remaining, format_unix_as_iso_utc, tty_prompter_rejects_non_tty_env unit test)
    - src/main.rs (replaces two 4-line Phase-1 stubs with 2 full dispatch arms; also auto-fmt applied)
    - Cargo.toml (5 new [[test]] entries; phase2_cli_declined_exit_7 required-features = ["mock"])

key-decisions:
  - "No chrono dependency added — TTL remaining and ISO-UTC expiry formatted via Plan 02's civil_from_days helper + hand-rolled format_ttl_remaining (Option A1 chosen over A2 per 'ship narrow' principle)"
  - "Local-time rendering in acceptance banner deferred: UTC-only format is the attestation. Cost to add local-time would be a chrono dep; benefit is cosmetic. Matches PROJECT.md 'ship narrow' discipline"
  - "CIPHERPOST_USE_MOCK_TRANSPORT env var RETAINED in main.rs under cfg(feature = \"mock\"). It is currently unused by any Plan 03 CLI test because cross-process MockTransport does not share state; kept for future disk-backed mock or same-process CLI fixtures. Compile-time stripped from release builds"
  - "Full binary send+receive end-to-end test NOT shipped in Plan 03. Decision: MockTransport's Arc<Mutex<HashMap>> is per-process and cannot bridge two cargo_bin spawns. Plan 02's library-level phase2_self_round_trip.rs + phase2_share_round_trip.rs already cover the round trip; Plan 03 covers binary surface via version/help/stderr-scan/declined/not-tty tests plus the interactive UAT"
  - "tty_check_skipped() is #[cfg(any(test, feature = \"mock\"))] gated. Pitfall #6 defense: production builds compile the override check as literal `false`; no env var can bypass the TTY requirement in `cargo build --release`"
  - "Library-level `tty_prompter_rejects_non_tty_env` unit test is the authoritative D-ACCEPT-03 verification. The CLI-level phase2_cli_not_tty_aborts.rs exercises pre-TtyPrompter Config/URI error paths only (plan frontmatter updated to reflect this reality)"
  - "Dialoguer::Input::interact_text is used in TTY mode. In test mode (skip-check set), fall back to std::io::stdin().read_line() to tolerate piped stdin — dialoguer may refuse non-TTY stdin even under cfg(test)"

patterns-established:
  - "Production prompter (TtyPrompter) and test prompters (AutoConfirm/Decline) share the Prompter trait; CLI dispatch passes TtyPrompter unconditionally; library tests inject the test helpers"
  - "Skip-TTY override behind compile-time cfg, not runtime flag — impossible to enable in `cargo build --release` artifacts"
  - "assert_cmd tests env_remove ambient CIPHERPOST_* vars before env_set to avoid parent test harness leakage"
  - "Library-level unit test in src/flow.rs tests module for TTY error-message invariant; CLI-level integration tests for exit-code taxonomy"

requirements-completed:
  - RECV-04
  - CLI-01
  - CLI-02
  - CLI-03
  - CLI-04
  - CLI-05

# Metrics
duration: ~25 min
completed: 2026-04-21
---

# Phase 2 Plan 03: CLI Dispatch + TtyPrompter + Acceptance Tests Summary

**Wires `cipherpost send` and `cipherpost receive` through clap into flow orchestration, adds a real TtyPrompter that renders the D-ACCEPT-02 bordered banner and reads typed z32 via dialoguer, and ships five CLI integration tests plus a library-level TTY-abort unit test that lock down CLI-03/04/05, ROADMAP SC3, and D-ACCEPT-03.**

## Performance

| Task | Duration | Files | Key artifact |
|------|----------|-------|--------------|
| 1. TtyPrompter in flow.rs | ~8 min | 1 | TtyPrompter struct + IsTerminal pre-check + tty_prompter_rejects_non_tty_env unit test |
| 2. main.rs dispatch arms | ~7 min | 2 | Send and Receive match arms wired to flow::run_send / run_receive + TtyPrompter |
| 3. 5 CLI integration tests | ~8 min | 6 | assert_cmd tests for version-git-sha, help-examples, stderr-no-secrets, declined-exit-7, not-tty-aborts |
| 4. 02-HUMAN-UAT.md (checkpoint) | ~2 min | 1 | Two pending UAT items mirror Phase 1's 01-HUMAN-UAT.md format |

Total: ~25 min. Three atomic per-task commits (+ one metadata commit).

## Architecture Evolution

### Before Plan 03 (Plans 01 + 02 shipped)

- `src/flow.rs` exposed `run_send`, `run_receive`, `Prompter` trait, `AutoConfirmPrompter` / `DeclinePrompter` test helpers. Seven library-level integration tests (`phase2_self_round_trip`, `phase2_share_round_trip`, ...) exercised the full pipeline.
- `src/main.rs::dispatch` had two `"not implemented yet (phase 2)"` stubs for `Send` and `Receive`.
- No production `Prompter` existed — the real TTY rendering + typed-confirmation was deferred to Plan 03.
- `cipherpost send` and `cipherpost receive` both exited 1 without doing anything.

### After Plan 03 (Phase 2 complete)

- `src/flow.rs` adds `TtyPrompter` (impl `Prompter`) that renders the bordered D-ACCEPT-02 banner to stderr and reads typed z32 via `dialoguer::Input` (or `stdin().read_line()` under cfg-gated test skip).
- `src/main.rs::dispatch` Send and Receive arms now delegate to `flow::run_send` / `flow::run_receive` with a real `TtyPrompter::new()` and `DhtTransport::with_default_timeout()`. Sentinel-first ordering (D-RECV-02) preserved.
- `cipherpost send --self -p 'x' --material-file -` reads stdin, publishes to Mainline DHT, prints `cipherpost://...` URI on stdout. `cipherpost receive <URI>` on the same identity renders the banner and, on confirmed z32 paste, decrypts to stdout.
- The D-ACCEPT-03 TTY requirement is enforced by a compile-time cfg: production builds hardcode `false` for the skip-override, so no env var can bypass the TTY requirement in release binaries.
- Six new test assertions: version-git-sha (CLI-04), 6× help-examples (CLI-03), 3× stderr-scan (CLI-05), declined-exit-7 (SC3), 2× CLI error-paths exit 1 (exit-code taxonomy), plus 1× library-level D-ACCEPT-03 unit test.

### Invariant Preserved

- D-15 (no source-chain walk in stderr): verified by `phase2_cli_stderr_no_secrets.rs` fuzz matrix — `age::`, `pkarr::`, `Os {` all absent from stderr across invalid-URI / wrong-passphrase / bare-z32 inputs.
- D-16 (unified Signature* Display): untouched — no new Signature variants in this plan.
- Pitfall #6 (no accept bypass): TtyPrompter has no `--yes`, no default value, no fallback-accept. Typed z32 must byte-equal (`trim()`) `sender_z32`; mismatch returns `Error::Declined` → exit 7. Library-level `DeclinePrompter` test asserts empty sink on decline.
- D-RECV-01 strict order: sentinel-check happens BEFORE passphrase resolve in the Receive arm; TtyPrompter::render_and_confirm is invoked by `run_receive` only after URI-match, TTL, age-decrypt, and JCS-parse succeed.

## Deviations from Plan

**None of the three auto-fix rules fired during this plan's execution.** All five CLI tests passed on first run, clippy stayed clean, and the library-level `tty_prompter_rejects_non_tty_env` test passed without any adjustment.

- **Rustfmt on touched files:** Plan touched `src/flow.rs`, `src/main.rs`, and five new test files. `cargo fmt` was applied to these files only; pre-existing Phase 1 fmt deviations in other files remain documented in `.planning/phases/02-send-receive-and-explicit-acceptance/deferred-items.md` and are out of scope. No NEW fmt deviations introduced.
- **Plan frontmatter edits (uncommitted at plan start):** The planner had left `02-03-PLAN.md`, `02-02-PLAN.md`, and `02-RESEARCH.md` uncommitted with `&'static str` → `&str` alignments (to match Plan 02's actual Prompter signature) and the Step D library-level-test addition. These reflect the current code state and are committed as part of this plan's final metadata commit.

## Files Touched

| File | LoC added | LoC removed | Purpose |
|------|-----------|-------------|---------|
| src/flow.rs | +183 | 0 | TtyPrompter + IsTerminal import + tty_check_skipped + format helpers + library-level unit test |
| src/main.rs | +144 | -13 | Send / Receive arm bodies (auto-fmt applied) |
| Cargo.toml | +22 | 0 | Five new `[[test]]` entries |
| tests/phase2_cli_version_git_sha.rs | +47 | 0 | CLI-04 assertion |
| tests/phase2_cli_help_examples.rs | +84 | 0 | CLI-03 assertion (6 tests) |
| tests/phase2_cli_stderr_no_secrets.rs | +114 | 0 | CLI-05 / SC5 fuzz matrix (3 tests) |
| tests/phase2_cli_declined_exit_7.rs | +70 | 0 | SC3 library-level decline path |
| tests/phase2_cli_not_tty_aborts.rs | +82 | 0 | Pre-TtyPrompter exit-1 paths (2 tests) |
| .planning/phases/02-send-receive-and-explicit-acceptance/02-HUMAN-UAT.md | +NEW | 0 | Two pending interactive UAT items |

## Test Suite State

After Plan 03:

- **Total tests:** 70 passing, 0 failing, 3 ignored (platform-specific).
- **New tests in this plan:** 13 (1 version + 6 help + 3 stderr + 1 decline + 2 not-tty).
- **Library-level new test:** 1 (`flow::tests::tty_prompter_rejects_non_tty_env`).
- **Prior plan tests unchanged:** Plan 01 (3), Plan 02 (7), Phase 1 (remainder).

Commands run (all green):
- `cargo build --release`
- `cargo test --all-features`
- `cargo clippy --all-features -- -D warnings`
- `rustfmt --check` on all files touched by this plan

## CLI Smoke-Test Results

- `cipherpost --help` shows the full command tree (identity / send / receive / receipts / version).
- `cipherpost version` prints `cipherpost 0.1.0 (<12-char-lowercase-hex-git-sha>)` + crypto primitives line.
- `cipherpost identity generate` + `cipherpost identity show` unchanged (Phase 1 behavior preserved).
- `cipherpost send --help` contains an `EXAMPLES:` section with `cipherpost send --self` and `cipherpost send --share <z32-pubkey>`.
- `cipherpost receive --help` contains an `EXAMPLES:` section.
- `cipherpost receive` (no URI) exits 1 with a Config error.
- `cipherpost receive notaurl` exits 1 with `invalid share URI: ...`.
- `cipherpost receipts --help` and `cipherpost version --help` both show EXAMPLES.
- Acceptance banner rendering + TTY happy path deferred to 02-HUMAN-UAT.md (requires real PTY).

## Requirements Completed

This plan completes the following REQ-IDs (as declared in 02-03-PLAN.md frontmatter):

- **RECV-04** — Acceptance prompt: TtyPrompter renders D-ACCEPT-02 banner on stderr and reads typed z32 via dialoguer; mismatched confirmation returns `Error::Declined` → exit 7.
- **CLI-01** — `-` stdin/stdout + stderr status: `Send --material-file -` uses stdin; `Receive` default output is stdout; `run_send` announces "Publishing to DHT..." on stderr; acceptance banner on stderr.
- **CLI-02** — Exit-code taxonomy: entire taxonomy (0/1/2/3/4/5/6/7) exercised by Phase 1 and Phase 2 integration tests. Plan 03 adds concrete assertions for exit 7 (declined) and exit 1 (config / invalid URI).
- **CLI-03** — Help text with `EXAMPLES`: `phase2_cli_help_examples.rs` asserts `EXAMPLES:` is present in all six subcommand --help outputs.
- **CLI-04** — `version` with real git SHA: `phase2_cli_version_git_sha.rs` asserts first-line SHA is 12 lowercase-hex chars (not `unknown`) and second line lists age/Ed25519/Argon2id/HKDF-SHA256/JCS.
- **CLI-05** — No secrets on stderr: `phase2_cli_stderr_no_secrets.rs` fuzz matrix asserts no passphrase bytes and no `age::`/`pkarr::`/`Os {` source-chain tags across invalid-URI, wrong-passphrase, and bare-z32 inputs.

All 21 Phase 2 REQ-IDs now complete across Plans 01 + 02 + 03.

## Handoff to Phase 3

Phase 3 (Signed Receipt — RCPT-01..05 + TRANS-03) consumes:

- **`cipherpost::flow::state_dir()`** — receipt-state files should be stored under the same `CIPHERPOST_HOME`-overridable root. Use a sibling directory `{state_dir}/receipts/` to mirror the `accepted/` pattern.
- **Ledger field schema** — `accepted.jsonl` entries already include `ciphertext_hash` and `cleartext_hash`. Phase 3 should extend each entry with a `receipt_published_at: "<ISO-8601 UTC>"` field after successful DHT publish. Existing lines remain backwards-compatible (missing field = not yet published); schema additions to JSONL are non-breaking.
- **`Transport::publish_receipt`** — Phase 1 shipped a simple clobber-replace implementation in both DhtTransport and MockTransport. Phase 3 MUST upgrade BOTH to resolve-merge-republish per TRANS-03 so receipts for different `share_ref`s coexist under the same recipient key. This is the last TRANS-* deferred from Phase 1 and blocks the full `cipherpost receipts --from <z32>` workflow.
- **`TtyPrompter` not reused by receipts** — Phase 3's `cipherpost receipts` command is a listing/display operation, not an acceptance operation. It does NOT need a Prompter. The exit-code taxonomy and stderr-no-secrets invariants (CLI-02 / CLI-05) apply, but the acceptance banner does not.
- **Open question to address early in Phase 3 planning:** PKARR SignedPacket merge-update semantics under concurrent receipt publication from two different recipients holding the same `share_ref`. A small prototype before `publish_receipt` is refactored is recommended (noted in STATE.md under Blockers/Concerns).

## Known Stubs

None. All Phase 2 code paths are live; the remaining stub is `Command::Receipts` which is explicitly Phase 3's deliverable (`"not implemented yet (phase 3)"` preserved in main.rs).

## Self-Check: PASSED

- src/flow.rs: contains `pub struct TtyPrompter`, `impl Prompter for TtyPrompter`, `fn tty_check_skipped`, `fn tty_prompter_rejects_non_tty_env`, `=== CIPHERPOST ACCEPTANCE` banner header, `dialoguer::Input`, and the exact error message `acceptance requires a TTY; non-interactive receive is deferred` — all verified.
- src/main.rs: contains `Command::Send {`, `Command::Receive {`, `cipherpost::flow::run_send`, `cipherpost::flow::run_receive`, `cipherpost::flow::check_already_accepted`, `cipherpost::flow::TtyPrompter`; zero `"not implemented yet (phase 2)"` strings; exactly one `"not implemented yet (phase 3)"` preserved — all verified.
- Cargo.toml: all five new `[[test]]` blocks present; `phase2_cli_declined_exit_7` has `required-features = ["mock"]` — all verified.
- Test commits exist: 4f6ca51 (Task 1), b2796bc (Task 2), c386a3d (Task 3) all in `git log`.
- `cargo build --release`, `cargo test --all-features` (70 passing), `cargo clippy --all-features -- -D warnings` all exit 0.
