---
gsd_state_version: 1.0
milestone: v1.0
milestone_name: milestone
status: planning
stopped_at: Phase 4 context gathered
last_updated: "2026-04-22T00:35:27.586Z"
last_activity: 2026-04-21
progress:
  total_phases: 4
  completed_phases: 3
  total_plans: 15
  completed_plans: 10
  percent: 67
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-20)

**Core value:** Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.
**Current focus:** Phase 3 — signed-receipt-the-cipherpost-delta

## Current Position

Phase: 4
Plan: Not started
Status: Ready to plan
Last activity: 2026-04-21

Progress: [██████████] 100%

## Performance Metrics

**Velocity:**

- Total plans completed: 9
- Average duration: — (no data yet)
- Total execution time: 0 hours

**By Phase:**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 1. Foundation | 3/3 | — | — |
| 2. Send/receive/acceptance | 2/3 | — | — |
| 3. Signed receipt | 0/TBD | — | — |
| 4. Protocol docs | 0/TBD | — | — |
| 03 | 4 | - | - |

**Recent Trend:**

- Last 5 plans: 01-01, 01-02, 01-03, 02-01, 02-02
- Trend: — (no data)

*Updated after each plan completion*
| Phase 01 P01 | 11 | 3 tasks | 20 files |
| Phase 01 P02 | 13 | 2 tasks | 14 files |
| Phase 01 P03 | 8 | 2 tasks | 8 files |
| Phase 02 P01 | ~20 | 4 tasks | 11 files |
| Phase 02 P02 | 40 | 2 tasks | 10 files |
| Phase 02 P03 | 25 min | 4 tasks | 10 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

- Initialization: Fork-and-diverge from mothballed cclink; no shared `cipherpost-core` crate until a second consumer exists.
- Initialization: Walking-skeleton scope = self + share + signed receipt on generic-secret payloads; TUI and other payload types deferred.
- Initialization: Default TTL = 24 hours (revised from PRD's 4h) to accommodate Mainline DHT latency distributions.
- Initialization: Canonical JSON = RFC 8785 (JCS) via `serde_canonical_json`, for cross-language re-implementation resilience.
- Initialization: `share_ref` width = 128 bits; HKDF info namespace = `cipherpost/v1/<context>`; identity path = `~/.cipherpost/`.
- serde_canonical_json upgraded to 1.0.0 (0.2 unavailable on crates.io — same CanonicalFormatter API)
- deny.toml tokio wrapper is async-compat (pkarr direct parent), chacha20poly1305 wrapper is age-core
- build.rs hand-rolled with git rev-parse — no vergen/built crate added
- cfg(test) does not propagate to integration tests — functions needed by integration tests must be unconditionally pub
- hkdf_info_enumeration filters bare prefix by requiring cap.len() > prefix.len()
- age Encryptor::with_recipients takes Iterator — use std::iter::once not Vec
- cfg(test) cross-crate: MockTransport requires --features mock for integration tests; [[test]] required-features in Cargo.toml
- 550-byte blob is BEP44 budget limit for worst-case OuterRecord; 600 exceeds dns_packet 1000-byte limit
- pkarr PublishError uses typed QueryError::Timeout enum (not string matching); resolve_most_recent returns Option, not Result
- Plan 02-01: Envelope JCS fixture locked at 119 bytes sha256 8a8ea877f1bce53bede8d721ccab0eee850080a4f173002adc538ae844ef1a8b
- Plan 02-01: Material serde tag='type' rename_all='snake_case'; wire = {"type":"generic_secret","bytes":"<b64-std-padded>"}
- Plan 02-01: Envelope::from_jcs_bytes maps parse failure to SignatureCanonicalMismatch (D-RECV-01 step 7; inherits exit 3)
- Plan 02-01: Rust string literals reject \x80..\xFF escapes; use \u{80}..\u{9F} for C1 controls in test strings
- Plan 02-01: ShareUri parser is hand-rolled (strip_prefix + split_once), no url crate; strict form per D-URI-03
- Plan 02-01: Identity::signing_seed() added as clean accessor; secret_key_bytes_for_leak_test preserved for debug_leak_scan.rs
- Plan 02-02: run_send retries age_encrypt up to 20 times to absorb grease-stanza size variance near the 1000-byte wire budget
- Plan 02-02: share_ref hashed over raw ciphertext per PAYL-05 (not base64 blob bytes)
- Plan 02-02: sentinel-first-then-ledger write order for crash-safe idempotency
- Plan 02-02: PacketTooLarge mapped directly to WireBudgetExceeded (preserves cipherpost-layer error taxonomy)
- Plan 02-02: share_round_trip test uses deterministic identity seeds (0xAA/0xBB/0xCC) to stabilize wire-budget footprint
- Plan 02-03: TtyPrompter uses cfg(any(test, feature = "mock"))-gated CIPHERPOST_SKIP_TTY_CHECK; production builds hardcode false — no env-var bypass possible
- Plan 02-03: chrono NOT added; reused civil_from_days + hand-rolled format_ttl_remaining + format_unix_as_iso_utc for D-ACCEPT-02 banner TTL rendering
- Plan 02-03: library-level tty_prompter_rejects_non_tty_env unit test is authoritative D-ACCEPT-03 coverage; CLI-level phase2_cli_not_tty_aborts.rs covers only pre-TtyPrompter Config/InvalidShareUri exit-1 paths
- Plan 02-03: CIPHERPOST_USE_MOCK_TRANSPORT kept in main.rs under cfg(feature = "mock") for future disk-backed mock; currently unused because cross-process MockTransport state is not shared
- Plan 02-03: no full-CLI binary round-trip test shipped — Plan 02 library-level tests cover the invariant; binary surface covered by version/help/stderr-scan/declined/not-tty tests plus human UAT

### Pending Todos

None yet.

### Blockers/Concerns

None yet. Research flagged one item to resolve during Phase 3 planning: PKARR SignedPacket merge-update semantics (race conditions on concurrent receipt publication) may warrant a small prototype before `publish_receipt` is implemented.

## Deferred Items

Items acknowledged and carried forward from previous milestone close:

| Category | Item | Status | Deferred At |
|----------|------|--------|-------------|
| Tooling | Pre-existing Phase 1 `cargo fmt --check` deviations (see .planning/phases/02-send-receive-and-explicit-acceptance/deferred-items.md) | Deferred to chore(fmt) pass | 2026-04-21 Plan 02-01 |

## Session Continuity

Last session: --stopped-at
Stopped at: Phase 4 context gathered
Resume file: --resume-file

**Planned Phase:** 04 (protocol-documentation-drafts) — 5 plans — 2026-04-22T00:35:27.582Z
