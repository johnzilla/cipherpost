---
phase: 04-protocol-documentation-drafts
plan: "01"
subsystem: planning-docs
tags: [docs, planning-amendment, requirement-amendment, pre-write-blocker]
dependency_graph:
  requires: []
  provides: [amended-DOC-03, amended-phase4-SC3]
  affects: [04-02-PLAN.md, 04-03-PLAN.md, 04-04-PLAN.md, 04-05-PLAN.md]
tech_stack:
  added: []
  patterns: []
key_files:
  created: []
  modified:
    - .planning/REQUIREMENTS.md
    - .planning/ROADMAP.md
decisions:
  - "DOC-03 disclosure channel is GitHub Security Advisory (primary), email, or equivalent — not email-only"
  - "Phase 4 SC3 round-trip verification is a Security Advisory receipt, not a live email round-trip"
metrics:
  duration: "< 5 minutes"
  completed: "2026-04-22"
requirements-completed:
  - DOC-03  # pre-write wording amendment; full satisfaction in 04-04
---

# Phase 4 Plan 01: Amend DOC-03 and Phase 4 SC3 to disclosure-channel language — Summary

**One-liner:** Replaced "disclosure email" wording in REQUIREMENTS.md DOC-03 and ROADMAP.md Phase 4 SC3 with "disclosure channel (GitHub Security Advisory, email, or equivalent)" language, clearing the D-SEC-04 pre-write blocker for SECURITY.md.

## What Was Done

Plan 04-01 was a single-task pre-write amendment resolving the literal-text conflict between the existing planning docs (which used "email" as the sole disclosure channel) and the chosen GitHub Security Advisory channel documented in 04-CONTEXT.md D-SEC-01.

### Exact Lines Amended

**REQUIREMENTS.md — line 123 (DOC-03 row):**

Before:
```
- [ ] **DOC-03**: `SECURITY.md` has a working disclosure contact (email) and a 90-day embargo policy statement
```

After:
```
- [ ] **DOC-03**: `SECURITY.md` has a working disclosure channel (GitHub Security Advisory, email, or equivalent) and a 90-day embargo policy statement
```

**ROADMAP.md — line 80 (Phase 4 SC3):**

Before:
```
  3. `SECURITY.md` exists at repo root with a disclosure email that round-trips a live email (verified by a committed note of the test), a stated 90-day embargo policy, and a reference to the cclink lineage including the `cipherpost/v1` HKDF info prefix that matches the constants module from Phase 1.
```

After:
```
  3. `SECURITY.md` exists at repo root with a disclosure channel that round-trips a live test report (e.g., a Security Advisory receipt) (verified by a committed note of the test), a stated 90-day embargo policy, and a reference to the cclink lineage including the `cipherpost/v1` HKDF info prefix that matches the constants module from Phase 1.
```

### Commit

- **Commit SHA:** `7fbe90e`
- **Message:** `docs(req): amend DOC-03 and Phase 4 SC3 to say disclosure channel`
- **Files in commit:** `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md` (exactly two)

## Downstream Plans Cleared

The D-SEC-04 pre-write blocker is resolved. Downstream plans may now proceed:

- **04-02-PLAN.md** (SPEC.md draft) — unblocked
- **04-03-PLAN.md** (THREAT-MODEL.md draft) — unblocked
- **04-04-PLAN.md** (SECURITY.md draft + round-trip test) — unblocked; its DOC-03 acceptance criterion now reads "disclosure channel" consistently with the amended requirement
- **04-05-PLAN.md** (link-check CI + README + phase-close verification) — unblocked

## Deviations from Plan

None — plan executed exactly as written. Both line numbers (123 and 80) matched the plan's specified positions.

## Known Stubs

None — this plan produces no code or content files.

## Threat Surface Scan

No new network endpoints, auth paths, file access patterns, or schema changes introduced. Both files are public-by-design planning artifacts (T-04-01-04: accepted).

## Self-Check: PASSED

- `.planning/REQUIREMENTS.md` amended: `grep -c "disclosure channel (GitHub Security Advisory, email, or equivalent)" .planning/REQUIREMENTS.md` = 1
- `.planning/ROADMAP.md` amended: `grep -c "Security Advisory receipt" .planning/ROADMAP.md` = 1
- Old wording absent from REQUIREMENTS.md: `grep -c "working disclosure contact (email)" .planning/REQUIREMENTS.md` = 0
- Old wording absent from ROADMAP.md: `grep -c "disclosure email that round-trips a live email" .planning/ROADMAP.md` = 0
- Commit `7fbe90e` exists with exactly two files changed
- Commit subject matches `^docs\(req\): amend DOC-03 and Phase 4 SC3` pattern
