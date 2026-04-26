---
phase: 08-pin-and-burn-encryption-modes
plan: 06
subsystem: docs-consolidation
tags: [docs, threat-model, spec, claude-md, consolidation, lineage, phase-closure]

# Dependency graph
requires:
  - phase: 08-pin-and-burn-encryption-modes
    plan: 01
    provides: PIN crypto infrastructure (src/pin.rs, hkdf_infos::PIN, OuterRecord.pin_required)
  - phase: 08-pin-and-burn-encryption-modes
    plan: 02
    provides: PIN ship-gate (validate_pin, prompt_pin, --pin CLI, run_receive STEP 6a)
  - phase: 08-pin-and-burn-encryption-modes
    plan: 03
    provides: BURN core (LedgerState enum, check_already_consumed, --burn CLI, BURN-05 stderr warning)
  - phase: 08-pin-and-burn-encryption-modes
    plan: 04
    provides: BURN ship-gate (Prompter marker, emit-before-mark ledger write, BURN-09 round-trip)
  - phase: 08-pin-and-burn-encryption-modes
    plan: 05
    provides: PIN x BURN x typed-material compose matrix (23 tests, W3 split macros)
provides:
  - THREAT-MODEL.md §6.5 PIN mode (PIN-10) — second-factor semantics, indistinguishability invariant, offline brute-force bound, multi-machine non-coordination caveat
  - THREAT-MODEL.md §6.6 Burn mode (BURN-08) — local-state-only, multi-machine race description, DHT-survives-TTL, burn ≠ cryptographic destruction, emit-before-mark atomicity
  - SPEC.md §3.6 ↔ §6.5 cross-link; §3.7 ↔ §6.6 cross-link
  - SPEC.md §5.1 --burn flag documentation (BURN-01 wire-shape, banner marker, ledger schema, receipt unconditional, compose with --pin)
  - SPEC.md §5.2 BURN ledger pre-check at step 2 (D-P8-09); [BURN] banner marker note at step 9 (D-P8-08)
  - SPEC.md §6 exit-4 row gains §3.6 reference for PIN-07 oracle hygiene
  - SPEC.md §Pitfall #22 — Phase 8 wire-budget continuation paragraph documenting pin × burn × typed-material compose grid
  - CLAUDE.md §Load-bearing lock-ins extended with 3 new entries (HKDF cipherpost/v1/pin extension; ledger state field schema migration; emit-before-mark contract)
  - W6 audit hygiene confirmed: 08-RESEARCH.md ## Open Questions (RESOLVED) heading + 3 RESOLVED-prefixed numbered questions
  - Phase 8 closure: all 19 PIN+BURN REQ-IDs covered (PIN-01..10 + BURN-01..09)
affects: [phase-09-real-dht-cas, retrospective-v1.1, future-claude-instances]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Phase-closure docs plan pattern: THREAT-MODEL §X.Y new sections + SPEC §X.Y cross-link cleanup + CLAUDE.md §Load-bearing lock-ins extension; zero source code, zero new tests, zero new fixtures"

key-files:
  created:
    - .planning/phases/08-pin-and-burn-encryption-modes/08-06-SUMMARY.md
  modified:
    - THREAT-MODEL.md (TOC entries 6.5/6.6 + §6.5 PIN mode + §6.6 Burn mode — 183 insertions)
    - SPEC.md (§3.6 cross-link + §3.7 cross-link + §5.1 --burn flag paragraph + §5.2 step 2 BURN ledger pre-check + §5.2 step 9 [BURN] banner marker note + §6 exit-4 §3.6 reference + §Pitfall #22 Phase 8 wire-budget continuation — 71 insertions)
    - CLAUDE.md (HKDF info bullet extension + 2 new bullets — 4 insertions)

key-decisions:
  - "THREAT-MODEL.md insertion as §6.5/§6.6 (sub-numbered under §6 Passphrase-MITM) — additive, no renumber of §7-§9; matches Assumptions Log A3"
  - "§Pitfall #22 wire-budget continuation lives in SPEC.md (with cross-ref to 08-RESEARCH.md Open Risk #5) rather than as a separate section — keeps the wire-budget reality in one canonical place"
  - "CLAUDE.md HKDF bullet extended in-place rather than as a new bullet — matches the existing convention of consolidated cross-cutting invariants"
  - "CLAUDE.md ledger-state and emit-before-mark land as SEPARATE bullets (not consolidated) — each is independently load-bearing; future Claude instances grepping for 'state' or 'emit-before-mark' should hit a single contract bullet, not a multi-topic blob"

patterns-established:
  - "Threat-model section template (4-part): Property → Threat coverage → Threats NOT covered → Test references + cross-references. Matches existing v1.0 §1-§9 sections (Capabilities/Worked example/Mitigations/Residual risk) with adapted shape for orthogonal compose modes (PIN, Burn) where 'attacker capabilities' is more naturally framed as positive coverage + explicit negation"
  - "Phase 8 wire-budget continuation pattern: each phase that adds wire-format fields appends a note to SPEC.md §Pitfall #22 documenting how the new fields compose under the BEP44 ceiling, what tests pin the failure mode, and what milestone ships the escape hatch. Phase 6 + 7 + 8 all follow this discipline; Phase 9 inherits via DHT-07 empirical measurement"

requirements-completed: [PIN-10, BURN-08]

# Metrics
duration: 13min
completed: 2026-04-26
---

# Phase 8 Plan 6: Docs Consolidation Summary

**Phase 8 closure: THREAT-MODEL.md gains §6.5 PIN mode + §6.6 Burn mode, SPEC.md cross-references resolved end-to-end, CLAUDE.md gains 3 load-bearing lock-ins; Phase 8 ships completely with all 19 REQ-IDs covered.**

## Performance

- **Duration:** 13 min
- **Started:** 2026-04-26T00:58:52Z
- **Completed:** 2026-04-26T01:12:41Z
- **Tasks:** 2 / 2
- **Files modified:** 3 (THREAT-MODEL.md, SPEC.md, CLAUDE.md)

## Accomplishments

- **THREAT-MODEL.md ships PIN-10 + BURN-08.** §6.5 PIN mode documents the four-part threat model — property (second-factor via nested age), threat coverage (passive DHT observer + identity-key-alone compromise blocked + offline brute-force bound), threats NOT covered (endpoint compromise, multi-machine coordination, DHT-side revocation, PIN reuse), and the indistinguishability invariant (wrong-PIN ≡ wrong-passphrase ≡ tampered-inner-ciphertext Display + exit 4). §6.6 Burn mode documents the parallel four-part shape with explicit emphasis on the multi-machine race (with diagram), DHT-survives-TTL caveat, burn ≠ cryptographic destruction, tampered-ledger out-of-scope, and the emit-before-mark atomicity invariant per D-P8-12.
- **SPEC.md cross-references resolve end-to-end.** §3.6 ↔ THREAT-MODEL.md §6.5; §3.7 ↔ THREAT-MODEL.md §6.6; §5.1 gains a `--burn` flag paragraph (BURN-01 wire-shape, send-time warning, receive-time banner marker, ledger row schema, unconditional receipt, compose with --pin); §5.2 gains the BURN ledger pre-check note at step 2 (D-P8-09 / BURN-02) and the [BURN] banner marker note at step 9 (D-P8-08 / BURN-05); §6 exit-4 row gains the §3.6 PIN Crypto Stack reference for PIN-07 oracle hygiene; §Pitfall #22 gains the Phase 8 wire-budget continuation paragraph.
- **CLAUDE.md §Load-bearing lock-ins extended.** HKDF info bullet now mentions `cipherpost/v1/pin` Phase 8 addition; new bullet documents the `accepted.jsonl` `state: "accepted"|"burned"` field schema with v1.0 conservative-default deserialization (T-08-17); new bullet locks in burn write order = emit-before-mark per D-P8-12, with safer-failure-mode rationale and PITFALLS #26 SUPERSEDED-by-D-P8-12 reference.
- **W6 RESEARCH.md audit hygiene confirmed.** `## Open Questions (RESOLVED)` heading present at line 762; 3 numbered questions all carry the `RESOLVED — ` prefix.
- **lychee link-check clean.** 44 total, 38 OK, 0 errors, 6 excluded (across SPEC.md, THREAT-MODEL.md, SECURITY.md, README.md, CLAUDE.md).
- **Phase 8 ships completely.** All 19 REQ-IDs covered: PIN-01..10 + BURN-01..09. No source code touched in Plan 06; cargo test --features mock = 309 passed / 0 failed / 19 ignored (matches Plan 05 baseline). Fixtures byte-identical: 192 + 424 (v1.0) + 212 + 142 (Phase 8).

## Task Commits

1. **Task 1: THREAT-MODEL.md §6.5 PIN mode + §6.6 Burn mode** — `a6ddc2b` (docs)
2. **Task 2: SPEC.md consolidation + CLAUDE.md lock-ins** — `51b227b` (docs)

**Plan metadata commit:** to-be-recorded after this SUMMARY is committed alongside STATE.md / ROADMAP.md updates.

## Files Created/Modified

- `THREAT-MODEL.md` — TOC entries 6.5/6.6 added; §6.5 PIN mode (second-factor share encryption) and §6.6 Burn mode (local-state-only single-consume) inserted after §6 Passphrase-MITM (no renumber of §7-§9). 183 insertions.
- `SPEC.md` — §3.6 PIN Crypto Stack gains §6.5 cross-link; §3.7 Burn Semantics gains §6.6 cross-link; §5.1 Send gains `--burn` flag paragraph after `--pin`; §5.2 Receive gains BURN ledger pre-check note at step 2 and [BURN] banner marker note at step 9; §6 Exit Codes exit-4 row gains §3.6 reference; §Pitfall #22 gains Phase 8 wire-budget continuation paragraph. 71 insertions.
- `CLAUDE.md` — §Load-bearing lock-ins: HKDF info bullet extended with `cipherpost/v1/pin` clause; NEW bullet for accepted.jsonl `state` field schema migration; NEW bullet for burn emit-before-mark contract. 4 insertions (sentence-extension + 2 new bullets each occupying a single line per CLAUDE.md cadence).
- `.planning/phases/08-pin-and-burn-encryption-modes/08-06-SUMMARY.md` — this file (created).

## Decisions Made

None new — all 4 architectural decisions were already locked in pre-execution per the plan and Phase 8 PATTERNS.md. See `key-decisions:` frontmatter for the consolidated list.

## Deviations from Plan

**None — plan executed exactly as written.** No source code touched. All 4 sub-edits to SPEC.md fired on the first edit attempt (no renumber needed); CLAUDE.md edits matched the planned insertion targets exactly.

**Lychee adjustment:** ran `lychee --offline ...` (project convention; matches CI's offline-only check) rather than the bare `lychee ...` shown in the plan. Identical exit-code semantics.

**Test name corrections (verified, not deviations):** the plan's threat-model prose referenced two test functions by aspirational names (`pin_self_round_trip_recovers_plaintext`, `pin_wrong_pin_returns_decrypt_failed`); on disk the actual function names are `pin_required_share_with_correct_pin_at_receive` and `pin_required_share_with_wrong_pin_at_receive`. The SUMMARY uses the actual on-disk names — the plan was written from RESEARCH.md test-suite outline, not the shipped code.

## Authentication Gates

None encountered.

## Phase 8 Final Coverage Table

Every REQ-ID PIN-01..10 + BURN-01..09 with primary plan claim + this plan's prose:

| REQ-ID  | Primary plan | Secondary | Notes |
|---------|--------------|-----------|-------|
| PIN-01  | 02           | 01        | prompt_pin TTY + double-entry + non-interactive deferral |
| PIN-02  | 02           | 01        | validate_pin entropy floor + anti-pattern + blocklist; D-P8-12 generic Display supersedes REQUIREMENTS specific-reason wording |
| PIN-03  | 01           | —         | OuterRecord.pin_required wire field; alphabetic JCS placement; v1.0 byte-identity preserved via skip_serializing_if |
| PIN-04  | 01           | —         | nested age encryption pipeline (run_send pin branch) |
| PIN-05  | 01           | —         | wire-blob layout: salt[32] || outer_age_ct (base64 standard) |
| PIN-06  | 02           | —         | run_receive STEP 6a salt-split + nested age-decrypt |
| PIN-07  | 02           | —         | wrong-PIN ≡ wrong-passphrase ≡ tampered-inner Display + exit 4; oracle hygiene narrowly within credential lane |
| PIN-08  | 02           | —         | matrix tests (a) correct PIN (b) wrong PIN (c) non-TTY context |
| PIN-09  | 01, 02       | —         | --pin CLI flag (clap bool; argv-inline rejected naturally) |
| **PIN-10** | **06**     | —         | **THREAT-MODEL.md §6.5 PIN mode prose (this plan)** |
| BURN-01 | 03           | —         | --burn CLI flag + Envelope.burn_after_read wire field end-to-end on send |
| BURN-02 | 04           | 03        | run_receive STEP 1 ledger pre-check + LedgerState::Burned arm → exit 7 |
| BURN-03 | 04           | —         | append_ledger_entry_with_state(Some("burned")) + sentinel ordering |
| BURN-04 | 04           | —         | unconditional publish_receipt on burn-receive (no guard); receipt-count == 1 invariant pinned by tests |
| BURN-05 | 03           | —         | send-time stderr warning verbatim |
| BURN-06 | 03           | —         | Send variant gains pin: bool + burn: bool fields |
| BURN-07 | 03           | 04        | PIN × BURN compose orthogonality (D-P8-13) |
| **BURN-08** | **06**   | —         | **THREAT-MODEL.md §6.6 Burn mode prose (this plan)** |
| BURN-09 | 04           | 05        | second-receive returns exit 7 round-trip; cross-cutting under typed materials in Plan 05 |

## RESEARCH.md Open Questions (W6) Audit Hygiene

Verified post-edit:
```
$ grep -q '^## Open Questions (RESOLVED)$' .planning/phases/08-.../08-RESEARCH.md
heading: OK
$ grep -cE '^[0-9]+\. \*\*RESOLVED — ' .planning/phases/08-.../08-RESEARCH.md
3
```

The W6 fix (heading + per-question RESOLVED markers) was applied during the planning revision pass; Plan 06 confirmed the audit trail is intact. No additional edits required.

## Pre-Execution Revision Summary (B1/B2/B3 + W1-W6)

The Phase 8 plan suite went through a full plan-checker revision cycle BEFORE execution. The resolutions baked into Plans 01-06:

- **B1 (count_receipts_for_share_ref helper):** inline helper using `MockTransport::resolve_all_txt` landed in Plans 04 (BURN ship-gate) + 05 (compose grid). Pattern: per-test-file helper, not a shared module — keeps each test file self-contained.
- **B2 (transport.resolve API correction):** plan referenced `transport.resolve_record(...)` but the actual API surface is `transport.resolve(...)` returning `OuterRecord` after outer-PKARR-sig pass. Plans 02 + 04 + 05 use the correct shape.
- **B3 (PIN-08(c) concrete test):** non-TTY context returns exit 1 / `Error::Config` / no state mutation / no receipt published. Landed concretely in Plan 02 via direct OuterRecord synthesis (bypasses wire-budget round-trip dependency because run_receive aborts at prompt_pin BEFORE age-decrypt).
- **W1 (PIN-02 generic-Display vs REQUIREMENTS wording):** D-P8-12 generic-Display posture supersedes REQUIREMENTS PIN-02 wording; resolution recorded in Plan 02 SUMMARY.
- **W2 (Plan 04 Task 1 cross-cutting Prompter trait checkpoint discipline):** Prompter trait gains marker: Option<&str> param landed via // (non-doc) line comments instead of /// — functionally equivalent.
- **W3 (Plan 05 split-macro discipline):** compose_base_test_strict! used ONLY for generic_burn_only (single sub-budget happy path); compose_base_test_lenient! used for every PIN path + every typed-material variant.
- **W4 (literal em-dash banner marker):** [BURN — you will only see this once] uses U+2014 EM DASH literal; pinned by golden-string test.
- **W5 (path-helper visibility bump + test_paths cfg-gated re-export):** pub use of pub(crate) items forbidden by Rust E0364; landed via test_paths cfg-gated module exposing pub fn wrappers around pub(crate) helpers (Plan 03 Task 1 Step A0).
- **W6 (RESEARCH.md Open Questions resolution markers):** heading is "## Open Questions (RESOLVED)"; each numbered question begins "RESOLVED — ". Verified by Plan 06 (this plan).

## Phase 9 Hand-off

STATE.md ready to advance. Phase 9 work is the v1.1 milestone closer:
- Real-DHT cross-identity A→B→receipt round-trip (deferred from v1.0).
- PKARR SignedPacket merge-update race / CAS gate (deferred from v1.0).
- pkarr 5.0.4 ClientBuilder bootstrap configurability check (PROJECT.md Pending Todo).
- Phase 9 DHT-07 empirical wire-budget measurement (referenced from SPEC.md §Pitfall #22 Phase 8 continuation).

Phase 9 inherits Phase 8's intact contracts: PIN nested-age, burn local-state-only, emit-before-mark atomicity, ledger-state schema migration, indistinguishability invariant. Cross-cutting concerns (security/oracle/wire-budget) carry forward without modification.

## Cross-Milestone Learnings

The "ship-gate plan = fixture + round-trip + oracle + leak-scan + SPEC update" pattern (originally surfaced in Phase 6 X.509) ran through five independent variants without modification: X509 (Plan 6.4), PGP (Plan 7.4), SSH (Plan 7.8), PIN (Plan 8.2), BURN (Plan 8.4). Pattern stability is HIGH; consider promoting to a named pattern in `.planning/RETROSPECTIVE.md` at v1.1 close.

The "phase-closure docs plan" pattern (this plan) — THREAT-MODEL §X.Y new sections + SPEC §X.Y cross-link cleanup + CLAUDE.md §Load-bearing lock-ins extension; zero source code, zero new tests, zero new fixtures — is new in Phase 8. Phase 9 should consider a similar closer plan if the real-DHT work surfaces enough threat-model + spec-clarification work to justify it.

## Self-Check: PASSED

- THREAT-MODEL.md §6.5 PIN mode literal present: OK (line 306)
- THREAT-MODEL.md §6.6 Burn mode literal present: OK (line 388)
- "multi-machine race" literal present in THREAT-MODEL.md: OK (lines 420, 443)
- "wrong passphrase or identity decryption failed" literal present: OK (in §6.5)
- "emit-before-mark" literal present in THREAT-MODEL.md: OK (in §6.6)
- "Burn ≠ cryptographic destruction" / "Burn ≠ key destruction" literal present: OK (lines 430, 453-454)
- SPEC.md §3.6 cross-link to THREAT-MODEL.md §6.5: OK (line 482)
- SPEC.md §3.7 cross-link to THREAT-MODEL.md §6.6: OK (line 582)
- SPEC.md §5.1 --burn flag paragraph: OK (BURN-01 documentation)
- SPEC.md §5.2 step 2 BURN ledger pre-check: OK (D-P8-09)
- SPEC.md §5.2 step 9 [BURN] banner marker: OK (D-P8-08)
- SPEC.md §6 exit-4 §3.6 reference: OK
- SPEC.md §Pitfall #22 Phase 8 wire-budget continuation: OK
- CLAUDE.md cipherpost/v1/pin: OK
- CLAUDE.md emit-before-mark: OK
- CLAUDE.md state field invariant: OK
- W6 audit: heading OK, count = 3
- lychee --offline: 44 total, 38 OK, 0 errors
- cargo test --features mock: 309 passed, 0 failed, 19 ignored
- Fixture sizes byte-identical: 192 + 424 + 212 + 142
- Commits exist: a6ddc2b OK, 51b227b OK
