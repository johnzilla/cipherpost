---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: Real v1
status: in_progress
stopped_at: "Milestone v1.1 Real v1 kickoff — PROJECT.md + STATE.md updated via /gsd-new-milestone. Scope locked (5 phases: non-interactive automation E2E → X509Cert → PgpKey+SshKey → --pin/--burn → real-DHT release-acceptance gate). Awaiting research decision, then REQUIREMENTS.md authoring, then roadmap generation."
last_updated: "2026-04-23T00:00:00.000Z"
last_activity: 2026-04-23
progress:
  total_phases: 5
  completed_phases: 0
  total_plans: 0
  completed_plans: 0
  percent: 0
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23 at v1.1 "Real v1" milestone kickoff)

**Core value:** Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.
**Current focus:** v1.1 "Real v1" — close the PRD's full v1 scope (all payload types + pin/burn modes) and de-risk the protocol over real Mainline DHT. v1.0 Walking Skeleton archived at `.planning/milestones/v1.0-*`.

## Current Position

Phase: Not started (defining requirements)
Plan: —
Status: Defining requirements
Last activity: 2026-04-23 — Milestone v1.1 started; PROJECT.md and STATE.md updated, research decision next.

Progress: [░░░░░░░░░░░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**

- Total plans completed (v1.1): 0
- Average duration: — (no data yet)
- Total execution time: 0 hours

**By Phase (v1.1 provisional; roadmapper may refine):**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 5. Non-interactive automation E2E | 0/TBD | — | — |
| 6. Typed Material: X509Cert | 0/TBD | — | — |
| 7. Typed Material: PgpKey + SshKey | 0/TBD | — | — |
| 8. --pin and --burn modes | 0/TBD | — | — |
| 9. Real-DHT E2E + merge-update race | 0/TBD | — | — |

**Recent Trend:**

- Last 5 plans (v1.0): 04-01, 04-02, 04-03, 04-04, 04-05 (archived)
- Trend: — (v1.1 begins)

*Historical v1.0 metrics archived at `.planning/milestones/v1.0-ROADMAP.md` and `.planning/RETROSPECTIVE.md`.*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

**v1.1 milestone kickoff (2026-04-23):**
- v1.1 milestone locked as "Real v1" — PRD closure + real-DHT de-risking; not a launch milestone
- Phase structure (provisional, pending roadmapper): 5 phases continuing from v1.0's Phase 4 → Phases 5–9 (no reset)
- Coarse-granularity rule held from v1.0 retrospective — every phase ends at a user-visible capability
- Phase 5 bundles housekeeping (pin-version reality-check, DHT label audit, traceability drift fix) with the `--passphrase-file` / `--passphrase-fd` plumbing so the phase lands a user-visible deliverable (scripted send/receive without TTY) rather than housekeeping-only
- 64 KB plaintext cap held across all typed payloads; `PgpKey` spec = single key, not keyring
- `--pin` and `--burn` modes: Phase 8 research must first survey `/home/john/vault/projects/github.com/cclink` for existing logic — fork-and-diverge, don't re-derive
- Real-DHT cross-identity round trip deliberately placed last (Phase 9) so network-class bugs don't cascade back into freshly-shipped payload + encryption-mode code
- Deferred to v1.2+: TUI wizard, exportable audit log, destruction attestation (PRD said v1.1 for the last one; shifted because v1.1 filled up with PRD-closure scope)
- Solo-builder hygiene: zero "Pending" rows in traceability — checkboxes and table stay in sync, or one of them goes away

**Inherited from v1.0 (retained for context):**
- Fork-and-diverge from mothballed cclink; no shared `cipherpost-core` crate until a second consumer exists.
- Default TTL = 24 hours (revised from PRD's 4h) to accommodate Mainline DHT latency distributions.
- Canonical JSON = RFC 8785 (JCS) via `serde_canonical_json` (shipped as 1.0.0, API matches planned 0.2).
- `share_ref` width = 128 bits; HKDF info namespace = `cipherpost/v1/<context>`; identity path = `~/.cipherpost/`.
- PKARR wire budget measured at 550 bytes (BEP44 limit for worst-case OuterRecord); pkarr transitive-resolved to 5.0.4.
- `resolve_passphrase(confirm_on_tty: bool)` — true on `identity generate`, false on unlock paths (show/send/receive).
- `publish_receipt` uses resolve-merge-republish via PKARR `cas`, not overwrite — preserves coexisting TXT records.
- Tamper-zero-receipts invariant: receipt publication happens strictly after outer verify + inner verify + typed-z32 acceptance.
- Acceptance requires typed z-base-32 (not y/N) to force fingerprint read off the acceptance banner.
- Error-oracle hygiene: all signature-verification errors share one identical user-facing Display and exit code 3.
- `serial_test = "3"` + `#[serial]` on any test that mutates process env (CIPHERPOST_HOME, etc.).
- `DhtTransport` via `pkarr::ClientBlocking` — no `tokio` dep at cipherpost layer.

### Pending Todos

None yet — awaiting research decision and REQUIREMENTS.md authoring.

### Blockers/Concerns

None yet. Items to surface during requirements/research:
- PGP key size vs 64 KB cap — confirm single-key scope covers realistic use cases (subkey-heavy keys + identity UIDs)
- PKARR merge-update race test (Phase 9) must decide whether to prove via test harness or an explicit tooling invariant
- Real-DHT test (Phase 9) needs a reliable way to observe propagation without long flaky waits

## Deferred Items

Items acknowledged and carried forward:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Tooling | Pre-existing Phase 1 `cargo fmt --check` deviations (see archived `.planning/milestones/v1.0-phases/02-send-receive-and-explicit-acceptance/deferred-items.md`) | Deferred to chore(fmt) pass | 2026-04-21 Plan 02-01 |
| Release-acceptance | Real-DHT A→B→receipt cross-identity round trip — never executed in v1.0, MockTransport only | Scheduled for v1.1 Phase 9 | 2026-04-22 v1.0 close |
| Concurrency | PKARR SignedPacket merge-update race under concurrent receipt publication — `cas` present but no explicit racer test | Scheduled for v1.1 Phase 9 | 2026-04-22 v1.0 close |
| Docs | Pin drift in SPEC/REQUIREMENTS (`serde_canonical_json 1.0.0` vs 0.2; `pkarr 5.0.4` vs 5.0.3; 550 B vs 600 B budget) | Scheduled for v1.1 Phase 5 (bless shipped reality) | 2026-04-22 v1.0 close |

## Session Continuity

Last session: 2026-04-23T00:00:00.000Z
Stopped at: Milestone v1.1 Real v1 kickoff in progress — PROJECT.md + STATE.md updated, about to commit and then run research decision.
Resume file: None

**Planned Phase:** 5 (Non-interactive automation E2E) — plan count TBD after roadmap generation
**Next action:** Research decision (step 8), then REQUIREMENTS.md authoring (step 9), then gsd-roadmapper spawn (step 10)
