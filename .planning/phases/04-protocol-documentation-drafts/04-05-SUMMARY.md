---
phase: 04-protocol-documentation-drafts
plan: 05
subsystem: docs
tags: [docs, ci, link-check, lychee, readme-discoverability]

# Dependency graph
requires:
  - phase: 04-protocol-documentation-drafts
    provides: "Plan 04-02 SPEC.md — link-check target; anchor targets referenced by THREAT-MODEL.md"
  - phase: 04-protocol-documentation-drafts
    provides: "Plan 04-03 THREAT-MODEL.md — link-check source citing SPEC.md anchors"
  - phase: 04-protocol-documentation-drafts
    provides: "Plan 04-04 SECURITY.md + .planning/security-disclosure-test.md — link-check targets; auth-gated Advisory URL is the .lycheeignore rationale"
provides:
  - ".lycheeignore at repo root with the auth-gated GitHub Advisory URL pre-populated (D-SEC-03 justification)"
  - "README.md ## Documentation section linking SPEC.md, THREAT-MODEL.md, SECURITY.md"
  - ".github/workflows/ci.yml link-check job SHA-pinned to lycheeverse/lychee-action@8646ba30535128ac92d33dfc9133794bfdd9b411 (v2.8.0), --include-fragments, fail: true"
  - "Phase-close grep-and-lychee verification evidence for DOC-01..04"
affects:
  - Phase 4 completion — all DOC-* requirements evidenced
  - v1.0 walking-skeleton milestone close — /gsd-complete-milestone unblocked

# Tech tracking
tech-stack:
  added:
    - "lychee (installed via cargo install lychee --locked --version 0.21.0)"
    - "lycheeverse/lychee-action v2.8.0 in CI (SHA-pinned)"
  patterns:
    - "SHA-pinned GitHub Actions: prevent tag-swap supply-chain attacks by pinning to 40-hex commit SHA with trailing version comment (T-04-05-01 mitigation)"
    - ".lycheeignore as narrow escape-hatch: pre-populate only auth-gated URLs with rationale comments; fix source docs for legitimate breakage (T-04-05-03 mitigation)"
    - "Link-check with --include-fragments: verifies anchor targets, not just URLs — catches drift between SPEC.md headings and THREAT-MODEL.md references"

key-files:
  created:
    - .lycheeignore
    - .planning/phases/04-protocol-documentation-drafts/04-05-SUMMARY.md
  modified:
    - README.md (added ## Documentation section)
    - .github/workflows/ci.yml (appended link-check job)

key-decisions:
  - "lychee-action SHA pin bumped from plan's suggested v2.0.0 (7da8ec1f...) to current v2.8.0 (8646ba30...) resolved via GitHub API at execution time. The plan's SHA was stale; its own instructions said to verify current v2.x before pinning."
  - "README Status line left unchanged (intentionally stale 'Phase 1 underway'). Per 04-CONTEXT.md Claude's Discretion + plan recommendation: a future /gsd-transition updates it at milestone close."
  - "lychee 0.21.0 (not latest 0.23.0) because rustc 1.85.1 is the project's toolchain and 0.23.0 requires rustc 1.88.0+. The CI job uses lycheeverse/lychee-action@v2.8.0 which ships its own lychee binary — this mismatch only affects the local dev install, not CI."

patterns-established:
  - "Link-check pass as phase-close gate: every docs phase ending with lychee --include-fragments as verification that anchors between shipped docs resolve end-to-end"
  - "Pre-flight SHA verification for GitHub Actions: before pinning, fetch the current v-latest release SHA from the GitHub API and use that instead of the plan's suggested SHA (which can go stale between planning and execution)"

requirements-completed:
  - DOC-01
  - DOC-02
  - DOC-03
  - DOC-04

# Metrics
duration: ~10min (including lychee cargo install which dominated runtime)
completed: 2026-04-22
---

# Phase 4 Plan 05: Link-Check CI + README Discoverability + Phase-Close Summary

**Lychee link-check CI job (SHA-pinned to lycheeverse/lychee-action@8646ba30535128ac92d33dfc9133794bfdd9b411 v2.8.0), README Documentation section linking the three new docs, `.lycheeignore` pre-populated with the auth-gated GHSA URL, and a clean 36-OK / 0-Errors / 1-Excluded local lychee pass evidencing all four DOC-* requirements.**

## Performance

- **Duration:** ~10 min (dominated by `cargo install lychee` ~1m build time)
- **Completed:** 2026-04-22
- **Tasks:** 2 (both automated)
- **Files created:** 2 (`.lycheeignore`, this summary)
- **Files modified:** 2 (README.md, .github/workflows/ci.yml)

## Accomplishments

- `.lycheeignore` committed at repo root with the GitHub Advisory creation URL pre-populated and justified via D-SEC-03 comment
- README.md `## Documentation` section links SPEC.md, THREAT-MODEL.md, SECURITY.md with terse per-doc blurbs; PRD link preserved
- `.github/workflows/ci.yml` gains a `link-check` job SHA-pinned to `lycheeverse/lychee-action@8646ba30535128ac92d33dfc9133794bfdd9b411` (v2.8.0) with `--include-fragments`, `fail: true`, and explicit doc args
- Local lychee pass: **36 OK, 0 Errors, 1 Excluded** (the advisory URL) — exit 0
- DOC-01..04 all evidenced (see Step G capture below)
- `cargo fmt --check` + `cargo build --release` still pass (no source changes regressed)

## Task Commits

Each task was committed atomically:

1. **Task 1: Install lychee + pre-populate `.lycheeignore`** — `8c41ce8` (`docs(04): add .lycheeignore pre-populated with auth-gated GitHub Advisory URL`)
2. **Task 2: Update README + append CI link-check job + final pass** — `f1bba86` (`docs(04): link new SPEC/THREAT-MODEL/SECURITY docs from README + add lychee CI job`)

**Plan metadata:** this summary commit (`docs(04-05): complete plan — link-check CI, README discoverability, phase-close evidence`)

## Files Created/Modified

- `.lycheeignore` (new, 13 lines) — pre-populated with `https://github.com/johnzilla/cipherpost/security/advisories/new` and a D-SEC-03 rationale comment
- `README.md` (modified, +7 lines) — added `## Documentation` section with three repo-relative Markdown links; all prior content preserved including the intentionally-stale Status line
- `.github/workflows/ci.yml` (modified, +10 lines) — appended `link-check` job after `deny`; preserves existing fmt/clippy/test/audit/deny jobs unchanged
- `.planning/phases/04-protocol-documentation-drafts/04-05-SUMMARY.md` (this file)

## Decisions Made

- **SHA pin bumped to current v2.8.0 over plan's stale v2.0.0.** The plan explicitly said "verify the SHA is current" before committing. GitHub API resolved `lycheeverse/lychee-action@v2.8.0` → `8646ba30535128ac92d33dfc9133794bfdd9b411`. Using v2.8.0 preserves the plan's intent (pin to latest v2.x) without requiring a plan re-open.
- **lychee 0.21.0 for local dev, not 0.23.0.** Project toolchain is rustc 1.85.1; lychee 0.23.0 requires 1.88.0+. The local install is only used for pre-commit verification — CI uses `lycheeverse/lychee-action@v2.8.0` which bundles a current lychee binary independent of the project's toolchain. This asymmetry is acceptable.
- **README Status line left unchanged.** Plan explicitly recommended not touching it; `/gsd-transition` at milestone close owns README status updates.
- **`.lycheeignore` minimal content.** Only the auth-gated Advisory URL is pre-populated. The local lychee pass reported 0 Errors before `.lycheeignore` was added (the URL was a redirect, not an error) — so no additional slug-generation false positives needed adding. Keeping the file minimal makes it easier to reason about and harder to abuse as an error-hiding mechanism (T-04-05-03 mitigation).

## Deviations from Plan

### 1. [Rule 4 — Drift in referenced external resource] Bumped lychee-action SHA from v2.0.0 to v2.8.0

- **Found during:** Task 2 Step B (SHA pin verification via GitHub API)
- **Issue:** Plan's suggested SHA `7da8ec1fc4e01b5a12062ac6c589c10a4ce70d67` (v2.0.0) is several releases stale. The plan's own Step B instructed to verify and use the latest v2.x.
- **Fix:** Resolved `https://api.github.com/repos/lycheeverse/lychee-action/git/ref/tags/v2.8.0` → `8646ba30535128ac92d33dfc9133794bfdd9b411`. Used that SHA + updated trailing comment to `# v2.8.0`.
- **Files modified:** `.github/workflows/ci.yml` only.
- **Verification:** `grep -cE "lycheeverse/lychee-action@[0-9a-f]{40}" .github/workflows/ci.yml` returns `1`; the SHA is the 40-hex commit SHA for v2.8.0 confirmed via GitHub API.
- **Committed in:** `f1bba86` (Task 2 commit); SHA bump documented in the commit body.

### 2. [Rule 4 — Environment drift] Pinned lychee 0.21.0 locally (plan assumed latest)

- **Found during:** Task 1 Step A (`cargo install lychee --locked` failed)
- **Issue:** Latest lychee 0.23.0 requires rustc 1.88.0+, but this project pins rustc 1.85 (per `dtolnay/rust-toolchain@1.85` in ci.yml). The installer reported: "`lychee 0.21.0` supports rustc 1.85.0".
- **Fix:** `cargo install lychee --locked --version 0.21.0`. This is a dev-environment install only — CI uses `lycheeverse/lychee-action@v2.8.0` which ships its own lychee binary compiled against whatever toolchain GitHub Actions provides.
- **Impact:** None on CI behavior or shipped artifacts. Anchors and links verified via 0.21.0 locally resolve identically to what CI v2.8.0 will verify on PRs.
- **Committed in:** No source commit — the lychee install is external state. Documented in this summary for reproducibility.

---

**Total deviations:** 2 (both environmental — neither changes the plan's intent)
**Impact on plan:** None. Both deviations were anticipated by the plan's own "verify before use" and "verify current version" language. Plan executed as specified.

## Issues Encountered

None beyond the two environmental deviations above. Lychee's first pass against the docs found 33 OK + 1 Redirect (the advisory URL) + 0 Errors — no anchor or cross-doc link drift between SPEC.md and THREAT-MODEL.md, no missing target in SECURITY.md. The anchor-resolution gamble from 04-RESEARCH.md §Pitfall 3 paid off: GitHub's slug generation matched THREAT-MODEL.md's expected slugs exactly.

## Phase-Close Verification Capture (Task 2 Step G — verbatim)

```
--- DOC-01 (SPEC.md sections) ---
1    (## 3. Wire Format)
1    (## 4. Share URI)
1    (## 5. Flows)
1    (## 6. Exit Codes)
1    (## 7. Passphrase Contract)

--- DOC-02 (THREAT-MODEL.md sections) ---
1    (## 2. Identity Compromise)
1    (## 3. DHT Adversaries)
1    (## 4. Sender-Purpose Adversary)
1    (## 5. Acceptance-UX Adversary)
1    (## 6. Passphrase-MITM Adversary)
1    (## 7. Receipt-Replay / Race Adversary)
1    (## 8. Out of Scope Adversaries)

--- DOC-03 (SECURITY.md + evidence) ---
1    (security/advisories/new)
1    (Up to 90 days from first report, with negotiation available for complex fixes)
evidence file present: YES
5    (GHSA-36x8-r67j-hcw6 occurrences)

--- DOC-04 (cclink cross-doc lineage) ---
SPEC.md cclink refs: 1
THREAT-MODEL.md cclink refs: 1
SECURITY.md cclink refs: 1

--- ROADMAP SC4 (link-check pass) ---
🔍 37 Total (in 0s) ✅ 36 OK 🚫 0 Errors 👻 1 Excluded
EXIT=0
```

**Interpretation:** All four DOC-* requirements have grep-verifiable evidence in shipped docs. The lychee link-check exits 0, meaning every cross-reference between SPEC / THREAT-MODEL / SECURITY / README resolves (excluding only the one auth-gated URL justified by `.lycheeignore`).

## User Setup Required

None — no new environment variables or dashboard configuration. The CI job runs automatically on the next PR/push.

## Outstanding Items for Phase-Close Verifier

- **README Status line is intentionally stale** ("pre-implementation — Phase 1 underway"). Defer to `/gsd-transition` at milestone close. Not a plan defect.
- **Local lychee install is 0.21.0 not latest.** Tied to project's pinned rustc 1.85. When the project bumps rustc, a future maintenance plan can bump the local lychee install. CI is unaffected.
- **Test advisory GHSA-36x8-r67j-hcw6 remains in draft state** (from Plan 04-04). Not an issue for Phase 4 close; future release processes can clean it up.

## Next Phase Readiness

- Phase 4 is complete. All 5 plans have SUMMARY.md; all DOC-* requirements evidenced.
- v1.0 walking-skeleton milestone is complete pending `/gsd-verify-work` (optional) and `/gsd-complete-milestone` (required) — the milestone has 4/4 phases done and 15/15 plans done.
- CI link-check is now part of the standard build; future docs changes will be automatically verified.

---
*Phase: 04-protocol-documentation-drafts*
*Completed: 2026-04-22*
