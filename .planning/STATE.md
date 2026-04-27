---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: Real v1
status: archived
stopped_at: v1.1 milestone closed 2026-04-26
last_updated: "2026-04-27T11:55:00Z"
last_activity: 2026-04-27 -- Completed quick task 260427-axn: per-share_ref receive lock closes TOCTOU window
progress:
  total_phases: 5
  completed_phases: 5
  total_plans: 24
  completed_plans: 24
  percent: 100
---

# Project State

## Project Reference

See: `.planning/PROJECT.md` (updated 2026-04-26 at v1.1 "Real v1" milestone close)

**Core value:** Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.
**Current focus:** Between milestones — scope-lock for next milestone via `/gsd-new-milestone`.

## Current Position

Milestone: v1.1 — closed
Phase: — (none active)
Plan: — (none active)
Status: milestone archived
Last activity: 2026-04-27 — Completed quick task 260427-axn: per-share_ref receive lock closes TOCTOU window

Progress: [██████████] 100% — v1.1 closed; next milestone pending scope-lock.

## Cumulative Quality

| Milestone | Phases | Plans | Tests | LOC (src+tests) | Reqs validated |
|-----------|--------|-------|-------|-----------------|----------------|
| v1.0 Walking Skeleton | 4 | 15 | 86 | 6,407 | 49/49 |
| v1.1 Real v1 | 5 | 24 | 311 | 15,425 | 67/67 |

*Historical metrics archived at `.planning/milestones/v1.0-*` and `.planning/milestones/v1.1-*`. Per-phase metrics live in phase SUMMARY.md / VERIFICATION.md files.*

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table. Per-milestone decision archives live at `milestones/v1.0-ROADMAP.md` and `milestones/v1.1-ROADMAP.md` (Milestone Summary sections).

**Inherited from v1.0 (retained for context):**

- Fork-and-diverge from mothballed cclink; no shared `cipherpost-core` crate until a second consumer exists.
- Default TTL = 24 hours (revised from PRD's 4h) to accommodate Mainline DHT latency distributions.
- Canonical JSON = RFC 8785 (JCS) via `serde_canonical_json` (1.0.0; API matches planned 0.2).
- `share_ref` width = 128 bits; HKDF info namespace = `cipherpost/v1/<context>`; identity path = `~/.cipherpost/`.
- PKARR wire budget measured at 550 bytes (BEP44 limit for worst-case OuterRecord); pkarr transitively-resolved to 5.0.4.
- `resolve_passphrase(confirm_on_tty: bool)` — true on `identity generate`, false on unlock paths (show/send/receive/identity unlock).
- `publish_receipt` uses resolve-merge-republish via PKARR `cas` — preserves coexisting TXT records.
- Tamper-zero-receipts invariant: receipt publication happens strictly after outer verify + inner verify + typed-z32 acceptance.
- Acceptance requires typed z-base-32 (not y/N) to force fingerprint read off the acceptance banner.
- Error-oracle hygiene: all signature-verification errors share one identical user-facing Display and exit code 3.
- `serial_test = "3"` + `#[serial]` on any test that mutates process env (CIPHERPOST_HOME, CIPHERPOST_TEST_PIN, etc.).
- `DhtTransport` via `pkarr::ClientBlocking` — no `tokio` dep at cipherpost layer.

**Additions from v1.1 (carried forward into next milestone's context):**

- DOC-03: traceability format locked to inline phase tags; phase VERIFICATION.md is authoritative for implementation status; no separate traceability table. Eliminates the "Pending row" drift class.
- HKDF info namespace extension: `cipherpost/v1/pin` for PIN-derived X25519 scalar wrapped into age `Identity` (cipherpost stays inside `age` for AEAD — no direct `chacha20poly1305` calls).
- LedgerEntry schema migration: `state: Option<String>` field (open-set string for external tooling); typed `LedgerState` runtime enum {None, Accepted, Burned}; v1.0 rows missing the field deserialize via serde default to `None` and map CONSERVATIVELY to `Accepted` (T-08-17 — never silently classify Accepted as Burned).
- Burn emit-before-mark contract (D-P8-12): burn share's first receive emits decrypted bytes BEFORE marking ledger; opposite ordering from accepted-flow's mark-before-emit. Reflects opposite atomicity contract — burn = one-shot-consume (data-loss is worst outcome); accepted = idempotent persistence (re-emit on crash is fine).
- Single-retry-then-fail CAS contract on `Transport::publish_receipt` (D-P9-A1): retry lives inside the trait method; final-conflict failures collapse into `Error::Transport` (no public `Error::CasConflict` variant — Pitfall #16 hygiene preserved). Both DhtTransport + MockTransport mirror identical structure.
- pkarr defaults only — no `CIPHERPOST_DHT_BOOTSTRAP` env var in v1.x core. `pkarr::ClientBuilder::bootstrap` exists and is verified configurable; not exercised. Revisit at v1.2+ if private-testnet support is requested.
- Real-DHT triple-gate discipline: `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` + nextest slow-timeout outer guard. CI never enables the feature. Manual operator runs via `RELEASE-CHECKLIST.md`.

### Pending Todos

None blocking. Carry-forward items for next milestone:

- Reconcile `rust-toolchain.toml` (1.88) vs CI clippy pin (1.85). Either bump CI or revert local; either way, add a CI workflow that validates the pin gap.
- Auto-fix the 65+ remaining `uninlined_format_args` instances across `src/` + `tests/` (clippy 1.88 default lint; CI 1.85 silent). Mechanical `cargo clippy --fix --all-targets --all-features --allow-dirty` pass.
- Push 180 v1.1 commits to `origin/main` (or feature branch) so CI validates Phase 5–9 work — currently CI hasn't run on any v1.1 code.
- Tick `RELEASE-CHECKLIST-v1.1.md` and run the manual real-DHT gate before publishing the v1.1.0 git tag externally (the local tag is created at milestone close; pushing is the user's call).

### Blockers/Concerns

None. v1.1 closed cleanly. Next milestone scope-lock is the natural next step.

### Quick Tasks Completed

| # | Description | Date | Commit | Directory |
|---|-------------|------|--------|-----------|
| 260427-axn | Per-share_ref receive lock closes TOCTOU window between idempotency check and sentinel write in `run_receive` | 2026-04-27 | 3f3c821 | [260427-axn-introduce-a-process-level-lock-or-move-c](./quick/260427-axn-introduce-a-process-level-lock-or-move-c/) |

## Deferred Items

Items acknowledged and carried forward to the next milestone:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Tooling | Pre-existing Phase 1 `cargo fmt --check` deviations (see archived `.planning/milestones/v1.0-phases/02-send-receive-and-explicit-acceptance/deferred-items.md`) | Deferred to chore(fmt) pass | 2026-04-21 Plan 02-01 |
| Wire-budget | Two-tier storage / chunking / out-of-band escape hatch for typed Material exceeding 1000-byte BEP44 ceiling | Scheduled for v1.2+ (architecturally orthogonal to PRD-closure) | 2026-04-26 v1.1 close |
| Release-acceptance | Real-DHT cross-identity round trip is manual-only via RELEASE-CHECKLIST.md (per-release gate, not CI) | First execution at v1.1.0 release tag time | 2026-04-26 v1.1 close |
| Toolchain | rust-toolchain.toml=1.88 vs CI clippy=1.85 divergence; 65+ `uninlined_format_args` instances locally | Defer reconciliation to v1.2 maintenance pass | 2026-04-26 v1.1 close |
| Code review | WR-01 `tests/real_dht_e2e.rs:153` propagation wait via wrong transport (non-blocking advisory) | Carry-forward to v1.2+ | 2026-04-26 v1.1 close |
| Code review | WR-02 `MockTransport::publish` doesn't bump seq (dormant in v1.1; matters at future composition) | Carry-forward to v1.2+ | 2026-04-26 v1.1 close |
| Documentation | Fixture-regen reproducibility across OpenSSL versions (Phase 6 — documentation-promise, not automated test) | Accept as deferred — no v1.1+ release blocks on it | 2026-04-26 v1.1 close |
| Feature | Non-interactive PIN input (`--pin-file` / `--pin-fd`) — DEFER-PIN-01/02 | v1.2+ (revisit when concrete automation use case surfaces) | 2026-04-23 v1.1 scope-lock |
| Feature | Destruction attestation workflow (originally PRD v1.1; shifted because v1.1 filled with PRD-closure scope) | v1.2+ | 2026-04-23 v1.1 scope-lock |
| Feature | TUI wizard / exportable audit log | v1.2+ | 2026-04-23 v1.1 scope-lock |

## Session Continuity

Last session: v1.1 milestone close (2026-04-26)
Stopped at: archived
Resume file: --

**Next action:** `/gsd-new-milestone` — author fresh requirements + roadmap for the next milestone. Backlog candidates above ("Next Milestone Goals" in PROJECT.md) inform the questioning phase.
