---
phase: 07-typed-material-pgpkey-sshkey
checked: 2026-04-24
checker: gsd-plan-checker
verdict: PASS_WITH_ADVISORIES
plans_reviewed: 8
requirements_covered: 19
requirements_total: 19
lock_ins_honored: 8
lock_ins_total: 8
self_flagged_concerns: 6
checker_advisories: 3
blockers: 0
---

# Phase 7 Plan Check — Goal-Backward Analysis

## Verdict: PASS WITH ADVISORIES

Plans WILL deliver the phase goal if executed correctly. All 5 success criteria trace to specific tasks. All 19 requirements (PGP-01..09, SSH-01..10) covered. Lock-in compliance: 8/8. The 6 planner-self-flagged concerns + 3 checker-raised advisories are accurately characterized — none are blockers. **Proceed to `/gsd-execute-phase 7`.**

## Goal Backward — Success Criteria

| # | Criterion | Delivered by |
|---|-----------|--------------|
| SC1 | `send --material pgp-key` ingests binary; armor reject; multi-primary reject (with N count); SECRET warning | Plans 01 (T3), 02 (T1), 03 (T1), 04 (T2,T3) |
| SC2 | `send --material ssh-key` OpenSSH-v1 only; legacy/RFC4716/FIDO rejected; banner shows type+SHA256+comment | Plans 05 (T3), 06 (T1), 07 (T1), 08 (T2,T4) |
| SC3 | JCS fixtures `material_pgp_signable.bin` and `material_ssh_signable.bin` byte-identical CI | Plan 04 (T1), Plan 08 (T1) |
| SC4 | `cargo tree -p ed25519-dalek` pre-flight documented in Plan 01 | Plan 01 (T1+SUMMARY), Plan 04 (T5), Plan 05 (T1), Plan 08 (T5) |
| SC5 | Malformed PGP/SSH at receive → exit 1 with generic Display | Plans 02, 04 (T5), 06, 08 (T5) |

## Requirement Coverage

**PGP (9/9):** 01→Plans 01,04 · 02→Plans 01,04 · 03→Plans 01,03,04 · 04→Plans 02,04 · 05→Plans 03,04 · 06→Plans 01,04 · 07→Plan 04 · 08→Plan 04 · 09→Plan 04 (round-trip ACTIVE)

**SSH (10/10):** 01→Plans 05,08 · 02→Plans 05,07,08 · 03→Plans 05,07 · 04→Plans 06,08 · 05→Plans 07,08 · 06→Plans 05,08 · 07→Plan 08 · 08→Plans 05,08 · 09→Plan 08 (#[ignore]'d per D-P7-03 amended) · 10→Plans 01,05,08

## Lock-in Compliance (CLAUDE.md load-bearing decisions)

| Lock-in | Honored |
|---------|---------|
| JCS via serde_canonical_json (no plain serde_json on signable paths) | YES |
| Manual Debug redaction extends to PgpKey + SshKey | YES |
| Error-oracle hygiene — generic Displays, no crate internals | YES (FORBIDDEN_DISPLAY_TOKENS covers `pgp::errors`, `PgpError`, `pgp::packet`, `ssh_key::Error`, `ssh_encoding`, `PemError`) |
| Dual-sig ordering (outer→inner→age-decrypt→from_jcs_bytes→preview) | YES |
| 64 KB plaintext cap via plaintext_size() on decoded bytes | YES |
| share_ref derivation unchanged | YES |
| No #[derive(Debug)] on key/byte-holding structs | YES |
| HKDF info `cipherpost/v1/<context>` (no new HKDF call sites) | YES |

## Six Planner-Self-Flagged Concerns

| # | Concern | Severity | Self-Correcting Within Phase? |
|---|---------|----------|-------------------------------|
| 1 | rpgp 0.19.0 packet-iteration API placeholder (Plans 01, 02) | LOW | YES — Plan 04 Task 4 forces real API |
| 2 | Plan 02 `todo!()` in `pgp_extract_metadata` | MEDIUM | YES — Plan 04 Task 4 calls render_pgp_preview against real fixture |
| 3 | Plan 04 Task 3 realistic-overflow PGP fixture under-specified (3 options) | LOW | Yes — acceptance forces choice |
| 4 | Plan 05 byte-determinism test depends on fixture committed in Plan 05 vs deferred to Plan 08 | LOW | Plan 05 default is to commit fixture; Plan 08 adjusts |
| 5 | Plan 08 DSA fixture generation may be blocked on modern ssh-keygen 9.0+ | LOW | YES — Plan 08 documents skip path; Plan 06 unit test still pins is_deprecated_ssh_algorithm logic |
| 6 | Plan 06 `ssh_public_key_bit_size` placeholder returns None | MEDIUM | YES — Plan 08 Task 4 catches via `Key:         ssh-ed25519 256` golden-string |

## Three Checker-Raised Advisories

### A1: Plan 02 `todo!()` not caught by Plan 02's own verify
Plan 02 ships green even with `todo!()` in `pgp_extract_metadata` — its inline tests don't exercise the metadata path. Plan 04 Task 4 catches it. Self-correcting within the phase. **Mitigation:** executor should treat each plan's SUMMARY.md API-substitution notes as load-bearing.

### A2: Plan 03 `todo!()` in `pgp_armor` analogous to A1
Same pattern — Plan 03 ships green with `todo!()`; Plan 04 Task 3 catches via `armor_on_pgp_share_emits_ascii_armor`. Acceptable.

### A3: Plan 08 SSH armor test is source-grep, not e2e
`armor_on_ssh_share_rejected_with_self_armored_error` reads `src/flow.rs` and grep-asserts the literal Error::Config message. Cannot run the full e2e flow because wire-budget blocks SSH delivery. Plan 08 acknowledges this honestly. Flag for v1.2 retrospective: add a synthetic-Envelope unit test that bypasses the wire layer.

## Inter-Plan Dependencies

Acyclic, monotonic. 8 waves strictly sequential per D-P7-19. Each plan's `depends_on` correctly reflects upstream artifacts. No forward references.

**Frontmatter requirement-claim discipline:** Plans claim primary-delivery requirements only; regression-test contributions are not double-claimed. Plan 04 doesn't list PGP-03/PGP-05 (those land in Plans 01/03 respectively); Plan 07 doesn't list SSH-04 (lands in Plan 06 + Plan 08 golden). Consistent.

## Per-Dimension Summary

| Dimension | Status |
|-----------|--------|
| Requirement Coverage | PASS (19/19) |
| Task Completeness | PASS |
| Dependency Correctness | PASS |
| Key Links Planned | PASS |
| Scope Sanity | PASS (8 plans, 1-6 tasks each) |
| Verification Derivation | PASS |
| Context Compliance | PASS (all 22 D-P7-XX decisions traced into plans) |
| Scope Reduction | PASS (no unilateral planner reduction; SSH `#[ignore]` is explicitly per D-P7-03 amended) |
| Architectural Tier | N/A |
| Nyquist Compliance | SKIPPED |
| Cross-Plan Data Contracts | PASS |
| CLAUDE.md Compliance | PASS |
| Research Resolution | PASS |
| Pattern Compliance | PASS |

## Final Verdict

**PASS WITH ADVISORIES.** Proceed to `/gsd-execute-phase 7`. The executor should be aware of the placeholder/todo!() pattern in Plans 02/03/06 — these self-correct via Plans 04/08 catches, but skipping ahead past plan SUMMARY.md API-substitution notes risks shipping placeholders into production.

---

_Reviewer: gsd-plan-checker_
_Method: goal-backward analysis with per-dimension scoring_
