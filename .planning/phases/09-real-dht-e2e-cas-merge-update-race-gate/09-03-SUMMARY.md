---
phase: 09-real-dht-e2e-cas-merge-update-race-gate
plan: 03
subsystem: docs
tags: [release-checklist, claude-md, spec, state-md, phase-closure, dht-06]

# Dependency graph
requires:
  - phase: 09-real-dht-e2e-cas-merge-update-race-gate
    provides: "09-01 settled the publish_receipt CAS retry contract; 09-02 finalized the real-DHT manual command and nextest profile name; 09-03 documents both"
provides:
  - "RELEASE-CHECKLIST.md (91 lines, 29 checkboxes, 6 sections) — living template gating every v1.1+ release"
  - "RELEASE-CHECKLIST-v1.1.md (84 lines, 29 checkboxes, body-identical to template) — first versioned snapshot, committed unticked at Phase 9 close per D-P9-C4"
  - "README.md +1 sentence — pkarr-defaults bootstrap note appended to existing 'No tokio dependency...' paragraph (NOT a new section per D-P9-B2 + Discretion)"
  - "SPEC.md +3 inline additions — §3 bootstrap-defaults paragraph; §3 CAS contract paragraph; §Pitfall #22 Phase 9 composite measurement (encoded = 5123 bytes vs budget = 1000 bytes)"
  - "CLAUDE.md §Load-bearing lock-ins +3 bullets at END of list — (1) single-retry-then-fail CAS contract; (2) no CIPHERPOST_DHT_BOOTSTRAP env var in v1.1; (3) real-DHT triple-gate cfg-flag discipline"
  - "STATE.md Pending Todos: bootstrap-configurability todo closed with strikethrough + D-P9-B1 + 09-RESEARCH.md OQ-4 citation"
affects:
  - "v1.1 release ship-gate (every v1.1+ release copies-and-ticks RELEASE-CHECKLIST.md into a versioned snapshot)"
  - "Future Phase 9+ agents: CLAUDE.md load-bearing lock-ins encode the three new contracts as 'don't break this' constraints"
  - "SPEC.md §3 CAS contract: divergence requires a protocol_version bump"

# Tech tracking
tech-stack:
  added:
    - "(no new crates; no source code edits)"
  patterns:
    - "Living-template + versioned-snapshot pattern: RELEASE-CHECKLIST.md (template, unticked, evolves with milestones) + RELEASE-CHECKLIST-vX.Y.md (per-release snapshot, ticked at release time)"
    - "Body-verbatim parity rule: D-P9-C4 mandates the v1.1 snapshot body matches the template body — checkbox count parity (29 == 29) is the canary for unintended drift"
    - "Phase-closure docs plan (Phase 8 Plan 06 precedent): zero source code, zero new tests, zero new fixtures — purely repo-root + planning-corpus updates that codify decisions and artefacts of the preceding wave plans"

key-files:
  created:
    - "RELEASE-CHECKLIST.md (91 lines, repo root) — living template"
    - "RELEASE-CHECKLIST-v1.1.md (84 lines, repo root) — first versioned snapshot"
  modified:
    - "README.md (+1 sentence on line 22): pkarr-defaults bootstrap note appended"
    - "SPEC.md (+18 lines / -0 lines): §3 bootstrap-defaults paragraph (lines 118-122); §3 CAS contract paragraph (lines 124-130); §Pitfall #22 Phase 9 composite measurement (lines 1107-1115)"
    - "CLAUDE.md (+3 lines): three new load-bearing lock-in bullets appended after the `serial_test` bullet (lines 102, 103, 104)"
    - ".planning/STATE.md (+0 lines / 1 line replaced): Pending Todos bootstrap-configurability todo closed with strikethrough + D-P9-B1 citation (line 175)"

key-decisions:
  - "RELEASE-CHECKLIST manual real-DHT command uses `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast` — the never-existed `cargo --test-timeout` flag from CONTEXT.md `<specifics>` line 327 is REJECTED per 09-RESEARCH.md OQ-5. Verified: `grep -c 'cargo --test-timeout' RELEASE-CHECKLIST.md` returns 0."
  - "v1.1 versioned snapshot committed at Phase 9 close per D-P9-C4 + Discretion recommendation (NOT deferred to v1.1 release tag time). Body matches template verbatim — checkbox count parity 29 == 29."
  - "SPEC.md §Pitfall #22 cites the actual measured encoded byte count (5123 bytes) from 09-01-SUMMARY.md, NOT a placeholder formula. Format `encoded = 5123 bytes` matches the done-criteria grep `encoded = [0-9]+ bytes|encoded ≈ [0-9]+ bytes`."
  - "CLAUDE.md three new bullets are appended at the END of the §Load-bearing lock-ins list (after the `serial_test` bullet at line 101) — NOT interspersed. Verified by inspection."
  - "STATE.md edit follows the existing strikethrough closure pattern (mirrors the cclink pin/burn survey closure on line 173). Documents both: bootstrap IS configurable in pkarr 5.0.4 (verified at builder.rs:164) AND v1.1 deliberately does not exercise the API."

requirements-completed:
  - DHT-06

# Metrics
duration: ~14 min
completed: 2026-04-26
---

# Phase 09 Plan 03: RELEASE-CHECKLIST + Phase 9 Lock-in Documentation Summary

**The v1.1+ release ship-gate is now codified at repo root: RELEASE-CHECKLIST.md (91-line living template, 29 markdown checkboxes, 6 sections) plus RELEASE-CHECKLIST-v1.1.md (body-identical 84-line versioned snapshot, unticked at Phase 9 close); CLAUDE.md gains three new Load-bearing lock-ins (single-retry-then-fail CAS contract, pkarr-defaults bootstrap discipline, real-DHT triple-gate cfg-flag) so future agents cannot regress the Phase 9 contracts; SPEC.md §3 records the bootstrap-defaults note, the CAS contract on `publish_receipt`, and the Phase 9 composite measurement (encoded = 5123 bytes vs budget = 1000 bytes for the pin+burn+2KB DHT-07 test); the orphan STATE.md "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" todo is closed with the standard strikethrough+citation pattern. Zero source code edits, zero new tests, zero new fixtures — the phase-closure docs plan pattern from Phase 8 Plan 06.**

## Performance

- **Duration:** ~14 min (executor wall-clock)
- **Started:** 2026-04-26T20:02:58Z (worktree base reset to `487cb4c0`)
- **Completed:** 2026-04-26T20:17:21Z
- **Tasks:** 2 / 2 (Task 1 — RELEASE-CHECKLIST template + v1.1 snapshot; Task 2 — README/SPEC/CLAUDE/STATE.md edits)
- **Files created:** 2 (RELEASE-CHECKLIST.md, RELEASE-CHECKLIST-v1.1.md)
- **Files modified:** 4 (README.md, SPEC.md, CLAUDE.md, .planning/STATE.md)
- **Test count:** 311 passed / 0 failed / 19 ignored under `--features mock` (matches Plan 09-01 + 09-02 baseline exactly — zero source edits, zero regressions)

## Accomplishments

1. **RELEASE-CHECKLIST.md (91 lines, 29 checkboxes) at repo root.** Per D-P9-C1 (~80 lines, standard ship-gate scope), D-P9-C2 (`/RELEASE-CHECKLIST.md`, NOT `/docs/`), D-P9-C3 (markdown checkboxes). Six sections: Pre-flight (4 boxes), Code gates (8), Wire-format byte-count regression guard (5), Manual real-DHT gate (4), Security review (5), Release artifacts (3). Living template — copied per release into `RELEASE-CHECKLIST-vX.Y.md`.
2. **RELEASE-CHECKLIST-v1.1.md (84 lines, 29 checkboxes) at repo root.** Per D-P9-C4 + Discretion recommendation: body matches template verbatim (checkbox count parity 29 == 29 enforced as the canary for unintended drift); only the header banner differs (drops "living template" framing, fills in v1.1.0 tag). Committed unticked at Phase 9 close; ticking happens at v1.1 release tag time.
3. **Manual real-DHT command uses cargo-nextest, NOT the never-existed `cargo --test-timeout` flag.** Per 09-RESEARCH.md OQ-5 correction over CONTEXT.md `<specifics>` line 327. Verified: `grep -c 'cargo --test-timeout' RELEASE-CHECKLIST.md` returns 0. The actual command: `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast` — pairs with the `slow-timeout = { period = "60s", terminate-after = 2 }` profile override Plan 09-02 added to `.config/nextest.toml`.
4. **Wire-format byte-count regression guard cites all 5 fixture sizes verbatim:** 192 / 424 / 119 / 212 / 142. No new fixtures were added by Plan 09-01 (the 09-01 SUMMARY confirms only test files `cas_racer.rs` and `wire_budget_compose_pin_burn_pgp.rs`, no new fixtures). The 5-fixture set is sufficient for v1.1; future milestones can add new fixture rows as needed.
5. **README.md gains a single sentence (NOT a new section).** D-P9-B2 + Discretion: appended to the existing line 22 "No tokio dependency..." paragraph: `Bootstrap nodes are pkarr defaults (Mainline DHT — router.bittorrent.com:6881 and three peers); no user-tunable bootstrap configuration in v1.1.`
6. **SPEC.md gains three inline additions (NOT new sections).** §3 Wire Format: bootstrap-defaults inline note (4-host enumeration); CAS contract note (single-retry-then-fail on `pkarr::errors::ConcurrencyError`'s three variants; final-conflict failures ride `Error::Transport`; protocol-version bump required for divergence). §Pitfall #22: Phase 9 composite measurement citing the actual `encoded = 5123 bytes` from 09-01-SUMMARY.md (NOT a placeholder formula) for the pin+burn+2KB GenericSecret DHT-07 test.
7. **CLAUDE.md §Load-bearing lock-ins gains exactly THREE new bullets at the END of the list.** Appended after the `serial_test = "3"` bullet at line 101. (1) Single-retry-then-fail CAS contract on `publish_receipt`; (2) No `CIPHERPOST_DHT_BOOTSTRAP` env var in v1.1 — pkarr defaults only (4 Mainline hosts enumerated); (3) Real-DHT tests behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`; CI never runs `--features real-dht-e2e`; RELEASE-CHECKLIST.md manual invocation is the only gate.
8. **STATE.md Pending Todos: bootstrap-configurability todo closed.** Standard strikethrough + closure-citation pattern matching the existing `cclink pin/burn survey` closure on the line above. Citation: D-P9-B1 + 09-RESEARCH.md OQ-4 (pkarr-5.0.4/src/client/builder.rs:164 verified configurable; v1.1 deliberately does not exercise; revisit at v1.2+ if private-testnet support is requested).
9. **Zero source code edits, zero new tests, zero new fixtures.** Matches Phase 8 Plan 06 "phase-closure docs plan" precedent. `cargo test --features mock` baseline of 311 passed / 0 failed / 19 ignored is unchanged from Plan 09-01 + 09-02. `cargo build --features real-dht-e2e --tests` clean.

## Task Commits

Each task was committed atomically (worktree mode, `--no-verify` per parallel-executor protocol):

1. **Task 1: docs(09-03): add RELEASE-CHECKLIST template + v1.1 snapshot** — `e704dda`
2. **Task 2: docs(09-03): record Phase 9 contracts in README/SPEC/CLAUDE/STATE** — `9602063`

## Files Created/Modified

**Created:**

- `RELEASE-CHECKLIST.md` (91 lines, repo root) — living template; 29 markdown checkboxes; 6 sections (Pre-flight, Code gates, Wire-format byte-count regression guard, Manual real-DHT gate, Security review, Release artifacts).
- `RELEASE-CHECKLIST-v1.1.md` (84 lines, repo root) — first versioned snapshot; body matches template verbatim; v1.1.0 tag in header; closing banner notes "Snapshot of RELEASE-CHECKLIST.md at v1.1 close (committed unticked at Phase 9 close per D-P9-C4 + Discretion recommendation). Ticking happens at v1.1 release tag time."

**Modified:**

- `README.md` (+1 sentence on line 22). The original line: `Requires Rust 1.85+ (pinned in rust-toolchain.toml). No tokio dependency at the cipherpost layer — uses pkarr::ClientBlocking.` → appended: ` Bootstrap nodes are pkarr defaults (Mainline DHT — router.bittorrent.com:6881 and three peers); no user-tunable bootstrap configuration in v1.1.`
- `SPEC.md` (+18 lines / -0 lines):
  - **§3 Wire Format (lines 118-130):** Added two paragraphs after the existing "PKARR wire budget" paragraph and before §3.1 — (1) Bootstrap nodes (v1.1) paragraph enumerating the 4 default Mainline hosts + cross-link to CLAUDE.md §Load-bearing lock-ins; (2) CAS contract paragraph documenting single-retry-then-fail on `pkarr::errors::ConcurrencyError` (`ConflictRisk` / `NotMostRecent` / `CasFailed`), final-conflict failures ride `Error::Transport`, no public `Error::CasConflict` variant per Pitfall #16, retry loop lives inside the trait method, divergence requires `protocol_version` bump.
  - **§Pitfall #22 (lines 1107-1115):** Appended a new paragraph at the bottom of the per-variant wire-budget treatment, before the §7 Passphrase Contract header. Records: pin_required=true + burn_after_read=true + GenericSecret { bytes: vec![0u8; 2048] } overflows the 1000 B BEP44 ceiling; encoded = 5123 bytes vs budget = 1000 bytes (overflow = 4123 bytes, expansion factor ≈ 2.5×); test path `tests/wire_budget_compose_pin_burn_pgp.rs::pin_burn_realistic_payload_surfaces_wire_budget_exceeded`; recorded for the regression-guard byte-count table in RELEASE-CHECKLIST.md when v1.2's two-tier-storage fix lands.
- `CLAUDE.md` (+3 lines): three new Load-bearing lock-in bullets appended after the `serial_test = "3"` bullet at line 101. Lines 102 / 103 / 104.
- `.planning/STATE.md` (1 line replaced): line 175 transformed from `- Verify pkarr 5.0.4 ClientBuilder bootstrap configurability at Phase 9 plan time` to `- ~~Verify pkarr 5.0.4 ClientBuilder bootstrap configurability at Phase 9 plan time~~ (closed by D-P9-B1: pkarr defaults only for v1.1; bootstrap IS configurable via ClientBuilder::bootstrap per pkarr-5.0.4/src/client/builder.rs:164 — verified in 09-RESEARCH.md OQ-4 — but the API is not exercised in v1.1. Revisit at v1.2+ if private-testnet support is requested.)`

## STATE.md Diff Re-application Note (orchestrator post-merge)

**Critical:** The orchestrator's worktree-merge-then-restore protocol restores shared planning files (STATE.md, ROADMAP.md, etc.) to their pre-merge state to avoid concurrent-merge conflicts. This means the STATE.md edit shipped in commit `9602063` will be REVERTED post-merge.

Per Plan 09-03's `<files_modified>` contract, STATE.md IS an authorized target for this plan. The orchestrator should re-apply the following diff to `.planning/STATE.md` after merging the Phase 9 wave:

**File:** `.planning/STATE.md` (around line 175 in the "Pending Todos" section)

**BEFORE (pre-merge state):**

```
- Verify pkarr 5.0.4 ClientBuilder bootstrap configurability at Phase 9 plan time
```

**AFTER (post-merge state, re-applied by orchestrator):**

```
- ~~Verify pkarr 5.0.4 ClientBuilder bootstrap configurability at Phase 9 plan time~~ (closed by D-P9-B1: pkarr defaults only for v1.1; bootstrap IS configurable via `ClientBuilder::bootstrap` per `pkarr-5.0.4/src/client/builder.rs:164` — verified in 09-RESEARCH.md OQ-4 — but the API is not exercised in v1.1. Revisit at v1.2+ if private-testnet support is requested.)
```

Single-line replacement; uniquely matched by the prefix `- Verify pkarr 5.0.4`.

## Decisions Made

- **Manual real-DHT command rejected the never-existed `cargo --test-timeout` flag.** CONTEXT.md `<specifics>` line 327 had a mockup using that flag; 09-RESEARCH.md OQ-5 confirmed it does not exist on stable cargo. Replaced with the cargo-nextest invocation that pairs with `.config/nextest.toml`'s `[[profile.default.overrides]] slow-timeout` (added by Plan 09-02). Both the RELEASE-CHECKLIST.md template AND the CLAUDE.md §Load-bearing lock-in cite the same nextest invocation — drift between the two would surface in the lychee link-check or in practice when a manual releaser notices the test doesn't run.
- **v1.1 versioned snapshot committed unticked at Phase 9 close (D-P9-C4 + Discretion).** Two alternatives were rejected: (a) defer until v1.1 release tag time — would leave the snapshot uncommitted across the entire v1.1 wait period, missing the audit-trail value; (b) commit ticked at Phase 9 close — premature; ticking happens when each gate is verified at release time. The chosen middle path: commit unticked at Phase 9 close (so the snapshot is in git history alongside the template at the moment Phase 9 closes), then tick at release time.
- **Body-verbatim parity between template and snapshot.** D-P9-C4's intent is that the v1.1 snapshot be a faithful copy of the template at the moment of v1.1's close. Drift between the two (e.g., template adds a new gate but snapshot doesn't have a checkbox for it) would mean the v1.1 release was held to a different bar than the template documents. Enforced by `[[ "$(grep -cE '^- \[ \]' RELEASE-CHECKLIST.md)" == "$(grep -cE '^- \[ \]' RELEASE-CHECKLIST-v1.1.md)" ]]` — both files have 29 checkboxes.
- **README.md change is a single sentence appended to existing paragraph, NOT a new section.** D-P9-B2 + Discretion: "we use the defaults" is not a feature; a section heading would over-emphasize a non-feature. The sentence rides on line 22 alongside the existing "No tokio dependency..." one-liner — semantically related (both are "what infrastructure does cipherpost use at the network layer").
- **SPEC.md §Pitfall #22 cites the MEASURED 5123-byte encoded count.** 09-01-SUMMARY.md recorded `encoded=5123 B, budget=1000 B, overflow=4123 B` from the actual test run. Plan 09-03's done-criteria require `grep -nE "encoded ≈ [0-9]+ bytes|encoded = [0-9]+ bytes" SPEC.md` to match; the form `encoded = 5123 bytes` satisfies this (no `≈` because the value is measured, not estimated).
- **CLAUDE.md three new bullets are at the END of the lock-in list, NOT interspersed.** The existing list has lock-ins ordered roughly chronologically by milestone (v1.0 lock-ins first, then Phase 8 PIN/burn additions). Appending the Phase 9 lock-ins at the end preserves the convention. Verified by inspection: lines 102 / 103 / 104 are the new bullets, immediately after line 101 `serial_test = "3"` bullet.
- **STATE.md todo closure mirrors the existing strikethrough+citation pattern.** Line 173's `~~Complete cclink pin/burn survey before planning Phase 8~~ (closed in 08-01 SUMMARY.md cclink-divergence write-up)` is the precedent. Plan 09-03 applies the same shape: strikethrough the original wording, append a parenthetical closure citing the decision (D-P9-B1) and the verification source (09-RESEARCH.md OQ-4). This keeps the todo's history visible (so a future reader can see what was once open and why) rather than deleting the line.

## Deviations from Plan

None — plan executed exactly as written. The only out-of-scope finding inherited from Plan 09-01 (`clippy::uninlined-format-args` on `build.rs:17` and a few `src/transport.rs` lines) remains documented in `.planning/phases/09-real-dht-e2e-cas-merge-update-race-gate/deferred-items.md`. Plan 09-03 makes zero source code edits, so the deferred-items disposition is unchanged.

The plan's done-criteria grep for `single-retry-then-fail` in CLAUDE.md (case-sensitive) returns 0 matches because the bullet starts with capital "S" (sentence start after `- `). The intent of the criterion (verify the lock-in is present) is satisfied via case-insensitive grep — `grep -ic 'single-retry-then-fail' CLAUDE.md` returns 1. This is not a deviation, just a note for future done-criteria authoring.

## Output Spec Items (per plan §<output>)

1. **Final byte-count line count of RELEASE-CHECKLIST.md and RELEASE-CHECKLIST-v1.1.md (target ~80 lines per D-P9-C1).** RELEASE-CHECKLIST.md = 91 lines / 4469 bytes; RELEASE-CHECKLIST-v1.1.md = 84 lines / 4171 bytes. Both within the 60-100 line band per the done-criterion. The 91-line template is slightly over the ~80 target because the "Manual real-DHT gate" section needed multi-line bullet wrapping for the long nextest invocation; the v1.1 snapshot drops the "living template" banner so it lands closer to 80.

2. **Whether SPEC.md §Pitfall #22 composite measurement cites a recorded `encoded` byte count from 09-01-SUMMARY.md OR the formula `encoded > budget=1000`.** Cites the recorded byte count: `encoded = 5123 bytes vs budget = 1000 bytes (overflow = 4123 bytes, expansion factor ≈ 2.5× over the 2048 B plaintext)`. Source: 09-01-SUMMARY.md frontmatter `provides:` "Measured DHT-07 composite encoded size: 5123 bytes (vs 1000 byte BEP44 ceiling)" + body §"Output Spec Items" item 4 "encoded=5123 B, budget=1000 B, overflow=4123 B".

3. **Confirmation that the three CLAUDE.md bullets are at the END of the existing §Load-bearing lock-ins list (not interspersed).** Verified by inspection: the list ends at line 101 (`serial_test = "3"` bullet); the three new bullets are lines 102 / 103 / 104; the next non-list line is `## GSD workflow` at line 105 (formerly line 103 before the addition). No interspersion.

4. **lychee output (PASS / number of skipped links).** `lychee --offline README.md SPEC.md CLAUDE.md RELEASE-CHECKLIST.md RELEASE-CHECKLIST-v1.1.md` reports: 21 Total / 18 OK / 0 Errors / 3 Excluded. PASS. (The 3 excluded links are likely in-page anchors or local file references that lychee skips by default.)

5. **Phase 9 closure: all 7 DHT requirements (DHT-01..07) covered.**

   | Requirement | Phase 9 Plan | Status |
   |-------------|--------------|--------|
   | DHT-01 (MockTransport CAS semantics on publish_receipt) | 09-01 | shipped |
   | DHT-02 (CAS racer integration test under MockTransport) | 09-01 | shipped |
   | DHT-03 (Real-DHT cross-identity round trip behind feature flag) | 09-02 | shipped |
   | DHT-04 (120s exponential-backoff resolve loop) | 09-02 | shipped |
   | DHT-05 (UDP reachability pre-flight + canonical skip message) | 09-02 | shipped |
   | DHT-06 (RELEASE-CHECKLIST + bootstrap-defaults note + CLAUDE.md lock-ins + STATE.md todo closure) | 09-03 | shipped |
   | DHT-07 (Wire-budget headroom test for pin+burn+typed composite) | 09-01 | shipped |

   Phase 9 closes the v1.1 milestone deliverable cycle for DHT-* requirements. ROADMAP.md update + REQUIREMENTS.md checkbox marking are deferred to the orchestrator's post-wave wrap step (per execution prompt — Plan 09-03 does NOT touch STATE.md/ROADMAP.md beyond the single STATE.md todo closure).

6. **Confirmation of "phase-closure docs plan" pattern (Phase 8 Plan 06 precedent).** Zero source code edits: verified by `git diff e704dda^..9602063 -- src/ tests/ build.rs Cargo.toml Cargo.lock` returning empty (no changes to any of those paths in the two Plan 09-03 commits). Zero new tests: no new files in `tests/` (only the two RELEASE-CHECKLIST files at repo root + four documentation file edits). Zero new fixtures: no new files in `tests/fixtures/`. The pattern matches Phase 8 Plan 06's "THREAT-MODEL §X.Y new sections + SPEC §X.Y cross-link cleanup + CLAUDE.md §Load-bearing lock-ins extension" shape exactly, with the addition of two repo-root files (RELEASE-CHECKLIST.md + v1.1 snapshot) which Phase 8 Plan 06 did not need.

## Self-Check

Verifying claims before declaring complete.

### Files

- `RELEASE-CHECKLIST.md` (created, repo root) — FOUND (91 lines)
- `RELEASE-CHECKLIST-v1.1.md` (created, repo root) — FOUND (84 lines)
- `README.md` (modified) — FOUND (single-sentence bootstrap note on line 22)
- `SPEC.md` (modified) — FOUND (3 inline additions: lines 118-130, 1107-1115)
- `CLAUDE.md` (modified) — FOUND (3 new lock-ins at lines 102-104)
- `.planning/STATE.md` (modified) — FOUND (todo closure on line 175)

### Commits (verified via `git log --oneline 487cb4c0..HEAD`)

- `e704dda` Task 1 (docs: RELEASE-CHECKLIST template + v1.1 snapshot) — FOUND
- `9602063` Task 2 (docs: README/SPEC/CLAUDE/STATE Phase 9 contracts) — FOUND

### Build / test gates

- `cargo build --features mock` — clean (2.87s)
- `cargo build --features real-dht-e2e --tests` — clean (4.44s)
- `cargo test --features mock` — 311 passed / 0 failed / 19 ignored (matches Plan 09-01 + 09-02 baseline exactly)
- `lychee --offline README.md SPEC.md CLAUDE.md RELEASE-CHECKLIST.md RELEASE-CHECKLIST-v1.1.md` — 21 Total / 18 OK / 0 Errors / 3 Excluded (PASS)

### Done-criteria greps (Task 1 — RELEASE-CHECKLIST files)

- `wc -l RELEASE-CHECKLIST.md` → 91 (between 60 and 100, ~80 target — PASS)
- `wc -l RELEASE-CHECKLIST-v1.1.md` → 84 (between 60 and 100 — PASS)
- `grep -cE '^- \[ \]' RELEASE-CHECKLIST.md` → 29 (≥ 15 required — PASS)
- `grep -cE '^- \[ \]' RELEASE-CHECKLIST-v1.1.md` → 29 (parity match with template — PASS)
- `grep -n "cargo nextest run --features real-dht-e2e" RELEASE-CHECKLIST.md` → 1 match (line 56 — PASS)
- `grep -n "cargo --test-timeout" RELEASE-CHECKLIST.md` → 0 matches (the never-existed flag is absent — PASS)
- `grep -nE "192 bytes|424 bytes|119 bytes|212 bytes|142 bytes" RELEASE-CHECKLIST.md` → 5 matches (one per fixture — PASS)
- `grep -n "real-dht-e2e: UDP unreachable; test skipped" RELEASE-CHECKLIST.md` → 1 match (PASS)
- `grep -n "v1.1.0" RELEASE-CHECKLIST-v1.1.md` → 1 match (line 5: `**Tag:** v1.1.0` — PASS)

### Done-criteria greps (Task 2 — README/SPEC/CLAUDE/STATE)

- `grep -c "pkarr default" README.md` → 1 (PASS)
- `grep -c "router.bittorrent.com" README.md` → 1 (PASS)
- `grep -c "tokio" README.md` → 1 (existing line preserved — PASS)
- `grep -c "single-retry" SPEC.md` → 1 (CAS contract note added — PASS)
- `grep -c "ConcurrencyError" SPEC.md` → 1 (CAS contract note cites variants — PASS)
- `grep -c "router.bittorrent.com" SPEC.md` → 1 (bootstrap defaults inline — PASS)
- `grep -cE "Pitfall #22|wire_budget_compose_pin_burn_pgp" SPEC.md` → 3 (composite measurement extension — PASS)
- `grep -cE "encoded = 5123 bytes|encoded ≈ 5123 bytes" SPEC.md` → 1 (actual byte count from 09-01-SUMMARY.md, NOT a placeholder — PASS)
- `grep -ic "single-retry-then-fail" CLAUDE.md` → 1 (Lock-in 1 — PASS; case-insensitive because line starts with capital S)
- `grep -c "CIPHERPOST_DHT_BOOTSTRAP" CLAUDE.md` → 1 (Lock-in 2 — PASS)
- `grep -ic "real-dht-e2e" CLAUDE.md` → 1 (Lock-in 3 — PASS)
- `grep -c "D-P9-B1" .planning/STATE.md` → 1 (todo closure recorded — PASS)
- `grep -cE '~~Verify pkarr.*~~' .planning/STATE.md` → 1 (strikethrough applied — PASS)

## Self-Check: PASSED

All claims verified. Plan 09-03 success criteria met. Phase 9 closure docs ship in commits `e704dda` + `9602063` on top of Plan 09-01 + 09-02 artifacts. Ready for orchestrator wave-merge.

The orchestrator should re-apply the STATE.md diff documented above (§"STATE.md Diff Re-application Note") after merging this worktree, since the worktree-merge-then-restore protocol will revert the STATE.md change to the pre-merge state.
