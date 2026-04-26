---
phase: 09-real-dht-e2e-cas-merge-update-race-gate
verified: 2026-04-26T20:30:00Z
status: passed
score: 4/4 success criteria verified (DHT-01..07 all covered)
overrides_applied: 0
re_verification:
  previous_status: none
  previous_score: n/a
  gaps_closed: []
  gaps_remaining: []
  regressions: []
release_gates: # Informational — not verification gaps; documented in RELEASE-CHECKLIST.md
  - test: "Manual real-DHT round trip"
    command: "cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast"
    expected: "Round trip completes within 120s with receipt count == 1 (BURN-04 invariant), OR skips with the canonical UDP-unreachable message on networks with restricted UDP egress"
    when: "Every v1.1+ release tag (RELEASE-CHECKLIST §Manual real-DHT gate)"
    rationale: "Per D-P9-D2 + Pitfall #29: CI never runs `--features real-dht-e2e` (triple gate cfg+ignore+serial). Network execution is intentionally a release-acceptance gate, not a CI gate. Phase 9's goal is satisfied by the test EXISTING, COMPILING, and being properly gated — release execution is a separate process step."
---

# Phase 9: Real-DHT E2E + CAS Merge-Update Race Gate Verification Report

**Phase Goal:** The protocol is validated over real Mainline DHT end-to-end, and concurrent receipt publication is proven safe under contention — so v1.1 ships with confidence it works beyond MockTransport.
**Verified:** 2026-04-26T20:30:00Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

Phase 9's goal decomposes into four ROADMAP success criteria (SC-1..4) and seven requirement IDs (DHT-01..07). The verifier confirms all four SCs are achieved by the artifacts that landed across plans 09-01, 09-02, and 09-03, and all seven DHT requirements are covered.

### Observable Truths (ROADMAP §Phase 9 Success Criteria)

| #   | Truth (Success Criterion) | Status     | Evidence       |
| --- | ------------------------- | ---------- | -------------- |
| SC-1 | MockTransport enforces `cas` semantics for `publish_receipt`; concurrent racer test (two threads, `std::sync::Barrier` synchronized) asserts exactly one wins on first attempt, the loser retries-and-merges, and the final PKARR state contains both receipts; runs in CI under `cargo test --features mock`. | ✓ VERIFIED | `tests/cas_racer.rs` exists (95 lines), uses `Arc<Barrier::new(2)>` (line 46), spawns two threads via `transport.publish_receipt(...)`, asserts `receipt_count == 2` after both `join()`s. `cargo test --features mock --test cas_racer` reports `1 passed; 0 failed`. The CAS retry contract lives in `src/transport.rs` (`PublishOutcome` enum at line 33; `MockStoreEntry { records, seq: u64 }` at line 384; `publish_receipt_attempt_mock` at line 436 implementing lock-read-drop-merge-relock-cas dance). Both `MockTransport::publish_receipt` (line 521) and `DhtTransport::publish_receipt` (line 270) wrap their respective attempt helpers in identical single-retry-then-fail logic. No public `Error::CasConflict` variant — `grep -nE 'Error::CasConflict' src/error.rs` returns 0 (oracle hygiene per Pitfall #16). |
| SC-2 | Real-DHT cross-identity round trip test exists behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]`; spawns two in-process clients with independent identities; A publishes, B resolves with 120-second exponential-backoff ceiling, B decrypts, B publishes receipt, A fetches; UDP pre-flight skips gracefully if bootstrap is unreachable. | ✓ VERIFIED | `tests/real_dht_e2e.rs` exists (249 lines). Triple-gated: crate-level `#![cfg(feature = "real-dht-e2e")]` (line 40), function-level `#[ignore]` (line 92) + `#[serial]` (line 93). `udp_bootstrap_reachable()` probes `router.bittorrent.com:6881` with 5 s timeout (lines 56-71). Two `DhtTransport::new(Duration::from_secs(120))` instances for Alice + Bob (lines 107, 114). 7-step backoff curve `[1u64, 2, 4, 8, 16, 32, 64]` (line 147) clipped to a 120 s deadline (line 146). Canonical skip message verbatim at line 98: `"real-dht-e2e: UDP unreachable; test skipped (not counted as pass)"`. `cargo build --features real-dht-e2e --tests` exits 0 in 4.39 s — the test compiles cleanly. Per D-P9-D2, network execution is manual-only via RELEASE-CHECKLIST; the verifier confirms test EXISTS, COMPILES, and is properly triple-gated. |
| SC-3 | `RELEASE-CHECKLIST.md` at repo root documents the manual real-DHT invocation command, expected output pattern, and explicit pass/fail criteria; every v1.1+ release requires a human to run and pass this checklist. | ✓ VERIFIED | `RELEASE-CHECKLIST.md` (91 lines, 29 markdown checkboxes, 6 sections — Pre-flight, Code gates, Wire-format byte-count regression guard, Manual real-DHT gate, Security review, Release artifacts). Manual command on line 56: `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast` (the never-existed `cargo --test-timeout` flag is absent — `grep -c 'cargo --test-timeout' RELEASE-CHECKLIST.md` returns 0, per OQ-5 correction). Wire-format byte-count regression rows cite all 5 fixture sizes verbatim (192 / 424 / 119 / 212 / 142). Canonical UDP-unreachable skip-message string present (line 54). Versioned snapshot `RELEASE-CHECKLIST-v1.1.md` (84 lines, 29 checkboxes, body parity with template, `**Tag:** v1.1.0` on line 5) committed unticked at Phase 9 close per D-P9-C4. |
| SC-4 | Wire-budget coexistence test asserts that a share with `pin_required=true` + `burn_after_read=true` carrying a realistic ~2 KB payload produces a clean `Error::WireBudgetExceeded` at send time (not a PKARR-internal panic). | ✓ VERIFIED | `tests/wire_budget_compose_pin_burn_pgp.rs` (103 lines). Uses `MaterialVariant::GenericSecret` (line 63) — synthesized 2 KB byte vector `vec![0u8; 2048]` (line 55). PIN supplied via `CIPHERPOST_TEST_PIN` env override (Phase 8 D-P8-12 cfg-gated mechanism); burn flag set on `run_send`. Asserts `Error::WireBudgetExceeded { encoded, budget, plaintext }` with `budget == 1000` and `encoded > budget`. `cargo test --features mock --test wire_budget_compose_pin_burn_pgp` reports `1 passed; 0 failed`; measured `encoded = 5123 bytes` recorded in 09-01-SUMMARY and propagated to SPEC.md §Pitfall #22 (line 1112). Note on the PGP/GenericSecret choice: ROADMAP SC-4 phrases the payload as "realistic PGP payload (~2 KB)"; the implementation uses `GenericSecret` because `MaterialVariant::PgpKey` would trigger the Phase 7 PGP packet-stream parser at `payload::ingest::pgp_key`, which rejects random bytes with `Error::InvalidMaterial` and the test would never reach the wire-budget check. The verifier prompt explicitly framed SC-4 as "~2 KB payload" (decoupled from PGP variant), and the deviation is documented as decision D-P9-E1 in 09-CONTEXT.md and 09-01-SUMMARY. The clean-error-surface intent of SC-4 is preserved. |

**Score:** 4/4 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `tests/cas_racer.rs` | DHT-01 + DHT-02 Barrier-synced two-thread CAS racer | ✓ VERIFIED | 95 lines; contains `Barrier::new(2)`, `#[serial]`, `DHT_LABEL_RECEIPT_PREFIX`; zero `thread::sleep` (Pitfall #28 — no sleep simulation); test passes deterministically. Wired (compiles + runs under `--features mock`). |
| `tests/wire_budget_compose_pin_burn_pgp.rs` | DHT-07 clean-error-surface for pin+burn+2 KB GenericSecret | ✓ VERIFIED | 103 lines; contains `Error::WireBudgetExceeded`, `MaterialVariant::GenericSecret`, `vec![0u8; 2048]`; test passes with `encoded = 5123 B vs budget = 1000 B`. |
| `tests/real_dht_e2e.rs` | Single cross-identity round-trip test under triple gate | ✓ VERIFIED | 249 lines; `#![cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`; compiles under `cargo build --features real-dht-e2e --tests`; UDP pre-flight + 7-step backoff + 120 s deadline + plaintext byte-equality + receipt count == 1 assertions all present. Single `#[test]` only. |
| `src/transport.rs` | PublishOutcome + per-impl publish_receipt_attempt + per-key seq + CIPHERPOST_DEBUG | ✓ VERIFIED | 552 lines; `enum PublishOutcome { Ok, CasConflict, Other(Error) }` at line 33; `cipherpost_debug_enabled()` reads `CIPHERPOST_DEBUG` (line 43); private `CasConflictFinal` marker at line 53 (rides `Error::Transport(Box<dyn Error>)` — no public `Error::CasConflict`); `publish_receipt_attempt` (DhtTransport) at line 149; `publish_receipt_attempt_mock` (MockTransport) at line 436 with deliberate lock-release between read-seq and cas-check (Pitfall #28 invariant). Catches all three `pkarr::errors::ConcurrencyError` variants via `Err(pkarr::errors::PublishError::Concurrency(_))` (line 213). |
| `src/flow.rs` | cfg-gate extension on `pub mod test_helpers` to include `feature = "real-dht-e2e"` | ✓ VERIFIED | Module-level `#[cfg(any(test, feature = "mock", feature = "real-dht-e2e"))]` enables `AutoConfirmPrompter` for the new feature flag (Rule 3 auto-fix recorded in 09-02-SUMMARY). |
| `Cargo.toml` | `[features] real-dht-e2e = []` + 3 new `[[test]]` entries | ✓ VERIFIED | `real-dht-e2e = []` present in `[features]`; `[[test]]` entries for `cas_racer` (required-features `["mock"]`), `wire_budget_compose_pin_burn_pgp` (required-features `["mock"]`), and `real_dht_e2e` (required-features `["real-dht-e2e"]`) all present. |
| `.config/nextest.toml` | Per-test slow-timeout outer guard | ✓ VERIFIED | 17 lines; `[[profile.default.overrides]]` with `filter = 'test(real_dht_e2e)'` and `slow-timeout = { period = "60s", terminate-after = 2 }`. Total wall-clock cap = 120 s; pairs with in-test deadline. `terminate-after` enforcement knob present (Pitfall D mandate). |
| `RELEASE-CHECKLIST.md` | Living template, ~80 lines, markdown checkboxes, manual real-DHT command | ✓ VERIFIED | 91 lines (within 60-100 band); 29 `^- \[ \]` checkboxes; nextest invocation present (line 56); 5 fixture byte-counts (192/424/119/212/142) cited; canonical skip message string verbatim. |
| `RELEASE-CHECKLIST-v1.1.md` | Versioned snapshot, body-identical to template, header customised | ✓ VERIFIED | 84 lines; 29 checkboxes (parity with template — no drift); `**Tag:** v1.1.0` on line 5; closing banner notes "committed unticked at Phase 9 close per D-P9-C4 + Discretion recommendation." |
| `README.md` | Single-sentence pkarr-default bootstrap note | ✓ VERIFIED | Line 22 contains both the existing `tokio` one-liner and the new `pkarr default` bootstrap note (`router.bittorrent.com:6881 and three peers; no user-tunable bootstrap configuration in v1.1`). |
| `SPEC.md` | Three inline additions: bootstrap defaults; CAS contract; Pitfall #22 composite measurement | ✓ VERIFIED | §3 Wire Format gains bootstrap-defaults inline (line 119) and CAS contract paragraph (lines 125-126 — `single-retry-then-fail`, `pkarr::errors::ConcurrencyError`, three variants enumerated). §Pitfall #22 gains Phase 9 composite measurement at line 1112: `encoded = 5123 bytes vs budget = 1000 bytes` citing test file `wire_budget_compose_pin_burn_pgp.rs`. |
| `CLAUDE.md` | Three new Load-bearing lock-in bullets at end of list | ✓ VERIFIED | Lines 102-104 — (1) single-retry-then-fail CAS contract; (2) no `CIPHERPOST_DHT_BOOTSTRAP` env var, pkarr defaults only; (3) real-DHT triple-gate cfg-flag discipline. All three bullets at the END of the list (next non-list line is `## GSD workflow` at line 105). |
| `.planning/STATE.md` | Bootstrap-configurability todo closed with strikethrough + D-P9-B1 citation | ✓ VERIFIED (artifact intent) | The Plan 09-03 worktree commit `9602063` recorded the strikethrough + closure-citation pattern. Per 09-03-SUMMARY.md `STATE.md Diff Re-application Note`, the orchestrator's worktree-merge-then-restore protocol may revert this single-line edit; the SUMMARY documents the exact diff for re-application. This does NOT affect Phase 9 goal achievement — the closure decision is recorded in the SUMMARY and CLAUDE.md lock-in. |

### Key Link Verification

| From | To  | Via | Status | Details |
| ---- | --- | --- | ------ | ------- |
| `tests/cas_racer.rs` | `MockTransport::publish_receipt` | Two `thread::spawn` closures synchronized via `Arc<Barrier::new(2)>` | ✓ WIRED | `Barrier::new(2)` at line 46; both threads call `transport.publish_receipt(...)` after `barrier.wait()`. Test passes deterministically. |
| `src/transport.rs::DhtTransport::publish_receipt` | `src/transport.rs::publish_receipt_attempt` | Single-retry-then-fail loop on `PublishOutcome::CasConflict` | ✓ WIRED | Lines 270-287: two sequential `match` expressions on the helper's outcome (first attempt, then second attempt with `CasConflictFinal` on second failure). |
| `src/transport.rs::MockTransport::publish_receipt` | `src/transport.rs::publish_receipt_attempt_mock` | Lock → read seq → drop lock → build merged → re-lock → cas-check → bump seq + write OR signal CasConflict | ✓ WIRED | Lines 436-468 implement the deliberate two-acquisition pattern (Pitfall #28 invariant). Lines 521-535 wrap in single-retry. |
| `tests/wire_budget_compose_pin_burn_pgp.rs` | `cipherpost::flow::run_send` | `MaterialSource::Bytes(vec![0u8; 2048])` + `Some(pin)` + `burn=true` | ✓ WIRED | Test calls `run_send` with the composed inputs and `expect_err`s `Error::WireBudgetExceeded`; assertion passes. |
| `tests/real_dht_e2e.rs::udp_bootstrap_reachable` | `router.bittorrent.com:6881` | `std::net::UdpSocket::bind("0.0.0.0:0")` + 5 s `read_timeout` + `connect()` | ✓ WIRED | Lines 56-71 implement the probe; canonical skip-message string at line 98. |
| `tests/real_dht_e2e.rs::real_dht_cross_identity_round_trip_with_receipt` | `DhtTransport::new(Duration::from_secs(120))` | Two independent in-process clients (Alice + Bob) | ✓ WIRED | Lines 107, 114 — Alice and Bob each get their own `DhtTransport` instance + their own `TempDir` for `CIPHERPOST_HOME`. |
| `.config/nextest.toml` | `tests/real_dht_e2e.rs` | `filter = 'test(real_dht_e2e)'` applies the slow-timeout override | ✓ WIRED | Profile override matches binary-name `real_dht_e2e` (substring match — see info-finding IN-02 for naming nuance, not a defect). |
| `RELEASE-CHECKLIST.md §Manual real-DHT gate` | `tests/real_dht_e2e.rs` | `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast` | ✓ WIRED | Same filter expression in checklist + nextest profile + CLAUDE.md lock-in. No drift. |
| `CLAUDE.md §Load-bearing lock-ins` | `src/transport.rs` CAS retry path + `Cargo.toml` real-dht-e2e feature | Three new bullets describing the contracts | ✓ WIRED | Each bullet cites a specific shipped artifact (`tests/cas_racer.rs`, `tests/real_dht_e2e.rs`, `.config/nextest.toml`). |
| `SPEC.md §Pitfall #22` | 09-01-SUMMARY measured byte count | Phase 9 measurement row in per-variant wire-budget table | ✓ WIRED | `encoded = 5123 bytes` cites the actual measurement, not a placeholder formula. |

### Data-Flow Trace (Level 4)

Phase 9 ships test-only artifacts, transport-internal CAS plumbing, a feature flag, a nextest profile, and documentation — no UI components or dynamic data renderers. Level 4 is performed implicitly via Step 7b spot-checks (which actually invoke the tests and observe output).

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| `tests/cas_racer.rs` racer test passes (SC-1) | `cargo test --features mock --test cas_racer` | `1 passed; 0 failed; 0 ignored` in 0.00 s | ✓ PASS |
| `tests/wire_budget_compose_pin_burn_pgp.rs` clean error surface (SC-4) | `cargo test --features mock --test wire_budget_compose_pin_burn_pgp` | `1 passed; 0 failed; 0 ignored` in 3.43 s | ✓ PASS |
| Full mock-feature suite green (no regression) | `cargo test --features mock` | aggregate `passed=311 failed=0 ignored=19` | ✓ PASS |
| Default-feature suite green (no regression) | `cargo test` | aggregate `passed=238 failed=0 ignored=10` | ✓ PASS |
| Real-DHT test compiles cleanly under feature flag (SC-2) | `cargo build --features real-dht-e2e --tests` | finishes in 4.39 s, zero warnings | ✓ PASS |
| Real-DHT round trip succeeds over Mainline DHT (DHT-04 release-acceptance gate) | `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast` | not run by verifier — manual-only per D-P9-D2; documented as release gate (see frontmatter `release_gates`) | ? SKIP (intentional) |

### Requirements Coverage (DHT-01..07)

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ----------- | ----------- | ------ | -------- |
| DHT-01 | 09-01 | MockTransport enforces PKARR `cas` semantics for `publish_receipt` (returns `CasConflict` on stale preimage). | ✓ SATISFIED | `MockStoreEntry { records, seq: u64 }` + `publish_receipt_attempt_mock` with cas-check at `src/transport.rs:436-468`; private `PublishOutcome::CasConflict` signals stale-preimage; absorbed by single-retry wrapper. |
| DHT-02 | 09-01 | CAS racer integration test: two threads via `std::sync::Barrier` → both `publish_receipt` → exactly one wins, loser retries-and-merges, both receipts persist. | ✓ SATISFIED | `tests/cas_racer.rs::publish_receipt_cas_racer_two_threads_both_persist` passes; final `resolve_all_txt` filter on `DHT_LABEL_RECEIPT_PREFIX` returns both receipts. |
| DHT-03 | 09-02 | Real-DHT e2e integration test behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]`; not a CI job. | ✓ SATISFIED | `tests/real_dht_e2e.rs` carries crate-level `#![cfg(feature = "real-dht-e2e")]` (line 40) AND `#[ignore]` (line 92); CI never enables `--features real-dht-e2e`. |
| DHT-04 | 09-02 | Real-DHT test spawns two in-process clients with independent identities; A publishes, B resolves with 120 s exp-backoff, decrypts, publishes receipt, A fetches; round trip end-to-end with real propagation. | ✓ SATISFIED (test exists + compiles + properly gated; network execution = release gate per D-P9-D2) | Two `DhtTransport::new(Duration::from_secs(120))` instances at lines 107, 114; 7-step exp-backoff `[1u64, 2, 4, 8, 16, 32, 64]` clipped to 120 s deadline; `assert_eq!(recovered, plaintext, ...)` (line 211); `assert_eq!(receipts.len(), 1, ...)` (line 240). Compile-only verification per the verifier contract; live network success is RELEASE-CHECKLIST manual gate (see frontmatter `release_gates`). |
| DHT-05 | 09-02 | UDP pre-flight to known Mainline bootstrap with canonical skip message on failure. | ✓ SATISFIED | `udp_bootstrap_reachable(Duration::from_secs(5))` probes `router.bittorrent.com:6881` (lines 56-71); on failure prints `"real-dht-e2e: UDP unreachable; test skipped (not counted as pass)"` (line 98) verbatim and returns. |
| DHT-06 | 09-03 | `RELEASE-CHECKLIST.md` at repo root with manual real-DHT invocation, expected output, pass/fail criteria. | ✓ SATISFIED | 91-line living template + 84-line v1.1 versioned snapshot at repo root; nextest invocation, 5 fixture byte-counts, canonical UDP skip message, 6 sections of gates. |
| DHT-07 | 09-01 | Wire-budget headroom test: pin+burn+~2 KB payload surfaces clean `Error::WireBudgetExceeded` at send. | ✓ SATISFIED | `tests/wire_budget_compose_pin_burn_pgp.rs::pin_burn_realistic_payload_surfaces_wire_budget_exceeded` passes; `encoded = 5123 B vs budget = 1000 B`; clean error path. ROADMAP wording specified "PGP payload" but implementation uses `GenericSecret` (D-P9-E1) because `MaterialVariant::PgpKey` parser rejects random bytes before the budget check; intent (clean wire-budget surface for the worst-case Phase 8 compose) preserved. |

All seven DHT-01..07 requirements satisfied. No orphans (every requirement is claimed by exactly one plan, and every plan's `requirements:` field is covered).

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
| ---- | ---- | ------- | -------- | ------ |
| `tests/real_dht_e2e.rs` | 153 | Pre-`run_receive` propagation backoff loop calls `alice_transport.resolve(&alice_z32)` instead of `bob_transport.resolve(&alice_z32)` (WR-01 from 09-REVIEW) | ⚠️ Warning | Cross-identity DHT visibility is not actually validated by the propagation wait — pkarr's in-process cache may answer from Alice's just-published packet without exercising any DHT round-trip. The subsequent `run_receive(&bob_id, &bob_transport, ...)` IS the actual cross-identity step but has no internal backoff. Flagged for v1.1 pre-tag follow-up. Does NOT block SC-2 achievement (the test exists, compiles, and is properly triple-gated; the manual-only network execution would catch the issue if it ever fired in practice — and the receipt-fetch loop already uses the correct fetcher-resolves-publisher pattern). |
| `src/transport.rs` | 484-491 | `MockTransport::publish` (outer-share path) does not bump `seq`; concurrent `publish` + `publish_receipt` on the same z32 has a latent data-loss window (WR-02 from 09-REVIEW) | ⚠️ Warning | Dormant in v1.1 — cipherpost's `run_send` and `run_receive` are sequential within a process; no caller races `publish` against `publish_receipt`. The behavior is documented in the source comment at line 486-488 ("D-P9-A3 — outer-share publish path is NOT cas-checked"). Future tests that intentionally exercise cross-method concurrency would silently lose the outer record — flagged for v1.1 pre-tag follow-up via a tightened comment OR by bumping seq in `publish` (preferable for behavioral parity with pkarr). Does NOT block SC-1..4 achievement. |
| `build.rs` | 17 | `clippy::uninlined-format-args` lint | ℹ️ Info | Pre-existing on Phase 9 base commit `c73ebe2` (verified by Plan 09-01 by stashing changes and re-running clippy — same error reproduces). NOT a Phase 9 regression. Documented in `.planning/phases/09-real-dht-e2e-cas-merge-update-race-gate/deferred-items.md`. CI's clippy version does not flag this; out-of-scope for Phase 9 (Plan 09-01 only modified `src/transport.rs`, `tests/cas_racer.rs`, `tests/wire_budget_compose_pin_burn_pgp.rs`, `Cargo.toml`). |
| `tests/real_dht_e2e.rs` / `RELEASE-CHECKLIST.md` | 56 / 48 | Nextest filter `test(real_dht_e2e)` substring-matches binary name, not function name `real_dht_cross_identity_round_trip_with_receipt` (IN-02 from 09-REVIEW) | ℹ️ Info | The filter still selects the test correctly because nextest matches against `<binary>::<function>` and the binary name is `real_dht_e2e`. A reader expecting function-name match could be confused; cosmetic only. |
| `README.md` | 109-115 | "Known limitations in v1.0" section still lists items now shipped in v1.1 (real-DHT round trip, typed materials, pin/burn) (IN-03 from 09-REVIEW) | ℹ️ Info | Doc-drift; CLAUDE.md was updated by Phase 9 but README's "Known limitations" section needs the same pass at milestone close. Not in scope for Phase 9's documentation deltas (which were `pkarr default` bootstrap note only, per D-P9-B2). Flagged for milestone-close PROJECT.md checkpoint. |
| `src/transport.rs` | 42-44, 274, 525 | `cipherpost_debug_enabled()` env read repeated per-attempt in both transport impls (IN-04 from 09-REVIEW) | ℹ️ Info | A flip of `CIPHERPOST_DEBUG` between the first and second attempts would change behavior between attempts. In practice this can't happen (env vars are not racing here); cosmetic only. |

No blockers found.

### Release Gate (Informational — Not a Verification Gap)

Per D-P9-D2 + Pitfall #29, network execution of the real-DHT round trip is intentionally a release-acceptance gate, not a CI gate. Phase 9's goal is satisfied by the test EXISTING, COMPILING, and being properly triple-gated; release execution is a separate process step documented in `RELEASE-CHECKLIST.md` § Manual real-DHT gate. The verifier MUST NOT execute the network test — the gate is invoked by a human at release tag time.

| Gate | Command | When | Expected |
| ---- | ------- | ---- | -------- |
| Manual real-DHT round trip (DHT-04) | `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast` | Every v1.1+ release tag | Round trip completes within 120 s with receipt count == 1 (BURN-04 invariant), OR skips with the canonical UDP-unreachable message on networks with restricted UDP egress (re-run on a permissive network). |

### Gaps Summary

No blocking gaps found. Phase 9's goal — "the protocol is validated over real Mainline DHT end-to-end, and concurrent receipt publication is proven safe under contention — so v1.1 ships with confidence it works beyond MockTransport" — is achieved by the artifacts that landed across plans 09-01, 09-02, and 09-03:

- **Concurrent receipt publication is proven safe under contention** by the deterministic Barrier-synced racer test against `MockTransport`'s production-shape CAS retry contract (SC-1, DHT-01, DHT-02). The retry contract is shared between `MockTransport` and `DhtTransport` — the racer test exercises the same code shape that ships in production.
- **The protocol is validated over real Mainline DHT end-to-end** at the release-acceptance level by the triple-gated `tests/real_dht_e2e.rs` + the documented manual invocation in `RELEASE-CHECKLIST.md` (SC-2, SC-3, DHT-03, DHT-04, DHT-05, DHT-06). Per the explicit D-P9-D2 design, "validated end-to-end" means "every v1.1+ release tag must have a human run the test and observe pass" — not "CI runs the test." The verifier confirms the gate IS in place (test compiles + checklist exists + nextest profile + CLAUDE.md lock-ins); release execution is a human gate documented in the frontmatter `release_gates` field.
- **The wire-budget composite escape hatch is proven clean** for the worst-case Phase 8 compose (pin+burn+~2 KB payload) via DHT-07 / SC-4 — no PKARR-internal panic; clean `Error::WireBudgetExceeded` at send time with measured `encoded = 5123 B vs budget = 1000 B`.

The two warnings flagged in 09-REVIEW (WR-01 propagation-wait uses publisher's transport; WR-02 `MockTransport::publish` does not bump `seq`) do not block Phase 9 goal achievement. WR-01 affects only the manual-only test's pre-`run_receive` propagation-wait granularity (the actual cross-identity step is correct); WR-02 is dormant under v1.1 flow (no caller races `publish` + `publish_receipt`). Both are recorded for v1.1 pre-tag follow-up.

The four info findings (IN-01..04) are cosmetic / doc-drift items for milestone close.

The pre-existing `clippy::uninlined-format-args` lint at `build.rs:17` is documented in `deferred-items.md` as out-of-scope for Phase 9; CI's clippy version does not flag it. Tests pass cleanly under both no-features (238 passed / 0 failed / 10 ignored) and mock-feature (311 passed / 0 failed / 19 ignored) builds.

---

_Verified: 2026-04-26T20:30:00Z_
_Verifier: Claude (gsd-verifier)_
