---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: Real v1
status: planning
stopped_at: Phase 6 context gathered
last_updated: "2026-04-24T18:22:32.725Z"
last_activity: 2026-04-24
progress:
  total_phases: 5
  completed_phases: 1
  total_plans: 7
  completed_plans: 3
  percent: 43
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23 at v1.1 "Real v1" milestone kickoff)

**Core value:** Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.
**Current focus:** Phase 5 — Non-interactive automation E2E

## Current Position

Phase: 6
Plan: Not started
Status: Ready to plan
Last activity: 2026-04-24

Progress: [░░░░░░░░░░░░░░░░░░░░] 0%

## Performance Metrics

**Velocity:**

- Total plans completed (v1.1): 0
- Average duration: — (no data yet)
- Total execution time: 0 hours

**By Phase (v1.1):**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 5. Non-interactive automation E2E | 0/TBD | — | — |
| 6. Typed Material: X509Cert | 0/TBD | — | — |
| 7. Typed Material: PgpKey + SshKey | 0/TBD | — | — |
| 8. --pin and --burn modes | 0/TBD | — | — |
| 9. Real-DHT E2E + CAS race gate | 0/TBD | — | — |
| 5 | 3 | - | - |

**Recent Trend:**

- Last 5 plans (v1.0): 04-01, 04-02, 04-03, 04-04, 04-05 (archived)
- Trend: — (v1.1 begins)

*Historical v1.0 metrics archived at `.planning/milestones/v1.0-ROADMAP.md` and `.planning/RETROSPECTIVE.md`.*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

**v1.1 roadmap generation (2026-04-23):**

- Phase grouping locked: PASS+DOC → Phase 5; X509 → Phase 6; PGP+SSH → Phase 7; PIN+BURN → Phase 8; DHT → Phase 9
- Traceability format locked project-wide (DOC-03): inline phase tags on each requirement are canonical; no separate traceability table; phase VERIFICATION.md files are authoritative for implementation status
- Phase 6 before Phase 7: X509 pattern-establishes (Material module, JCS fixture discipline, per-variant size check, Debug redaction); Phase 7 applies mechanically
- Phase 7 before Phase 8: pin/burn have full semantic value over typed payloads; JCS fixture discipline for new Envelope/OuterRecord fields must not be interleaved with typed-variant fixture work
- Phase 9 last: CAS racer and real-DHT gate depend on all prior phases landing cleanly; network-class bugs must not cascade back into freshly-shipped payload and encryption-mode code
- cclink pin/burn survey is a hard prerequisite before Phase 8 can be planned (research agent was access-denied; must be done manually — see SUMMARY.md Open Questions)
- pkarr bootstrap configurability check deferred to Phase 9 plan time (verify via `cargo doc` whether `pkarr 5.0.4` ClientBuilder exposes a bootstrap field)
- Burn+receipt decision recorded: Option A — receipt IS published after successful burn-receive (receipt = delivery confirmation; burn does not suppress attestation)

**v1.1 milestone kickoff (2026-04-23):**

- v1.1 milestone locked as "Real v1" — PRD closure + real-DHT de-risking; not a launch milestone
- Phase structure confirmed: 5 phases continuing from v1.0's Phase 4 → Phases 5–9 (no phase-number reset)
- Coarse-granularity rule held from v1.0 retrospective — every phase ends at a user-visible capability
- Phase 5 bundles housekeeping (pin-version reality-check, DHT label audit, traceability drift fix) with `--passphrase-file` / `--passphrase-fd` plumbing so the phase lands a user-visible deliverable (scripted send/receive without TTY) rather than housekeeping-only
- 64 KB plaintext cap held across all typed payloads; `PgpKey` spec = single key, not keyring
- Real-DHT cross-identity round trip deliberately placed last (Phase 9) so network-class bugs do not cascade back into freshly-shipped payload + encryption-mode code
- Deferred to v1.2+: TUI wizard, exportable audit log, destruction attestation (PRD said v1.1 for the last; shifted because v1.1 filled up with PRD-closure scope)
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
- `serial_test = "3"` + `#[serial]` on any test that mutates process env (CIPHERPOST_HOME, CIPHERPOST_PIN, etc.).
- `DhtTransport` via `pkarr::ClientBlocking` — no `tokio` dep at cipherpost layer.

### Pending Todos

- Complete cclink pin/burn survey before planning Phase 8 (see SUMMARY.md Open Questions — manual bash commands provided)
- Run `cargo tree | grep ed25519-dalek` after adding `ssh-key` to Cargo.toml at Phase 7 plan time; document outcome in plan 01
- Verify pkarr 5.0.4 ClientBuilder bootstrap configurability at Phase 9 plan time

### Blockers/Concerns

None blocking Phases 5–7. Phase 8 is gated on cclink pin/burn survey (access-denied during research; manual survey required before planning). Phase 9 has a medium-confidence open question on pkarr bootstrap config.

## Deferred Items

Items acknowledged and carried forward:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Tooling | Pre-existing Phase 1 `cargo fmt --check` deviations (see archived `.planning/milestones/v1.0-phases/02-send-receive-and-explicit-acceptance/deferred-items.md`) | Deferred to chore(fmt) pass | 2026-04-21 Plan 02-01 |
| Release-acceptance | Real-DHT A→B→receipt cross-identity round trip — never executed in v1.0, MockTransport only | Scheduled for v1.1 Phase 9 | 2026-04-22 v1.0 close |
| Concurrency | PKARR SignedPacket merge-update race under concurrent receipt publication — `cas` present but no explicit racer test | Scheduled for v1.1 Phase 9 | 2026-04-22 v1.0 close |
| Docs | Pin drift in SPEC/REQUIREMENTS (`serde_canonical_json 1.0.0` vs 0.2; `pkarr 5.0.4` vs 5.0.3; 550 B vs 600 B budget) | Scheduled for v1.1 Phase 5 (bless shipped reality) | 2026-04-22 v1.0 close |

## Session Continuity

Last session: --stopped-at
Stopped at: Phase 6 context gathered
Resume file: --resume-file

**Planned Phase:** 6 (Typed Material — X509Cert) — 4 plans — 2026-04-24T18:22:32.720Z
**Next action:** `/gsd-plan-phase 5`
