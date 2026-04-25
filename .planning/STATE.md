---
gsd_state_version: 1.0
milestone: v1.1
milestone_name: Real v1
status: verifying
stopped_at: Phase 7 planning complete (8 plans, PASS verdict)
last_updated: "2026-04-25T01:15:51.107Z"
last_activity: 2026-04-24
progress:
  total_phases: 5
  completed_phases: 2
  total_plans: 15
  completed_plans: 7
  percent: 47
---

# Project State

## Project Reference

See: .planning/PROJECT.md (updated 2026-04-23 at v1.1 "Real v1" milestone kickoff)

**Core value:** Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.
**Current focus:** Phase 06 — typed-material-x509cert

## Current Position

Phase: 06 (typed-material-x509cert) — EXECUTING
Plan: 4 of 4 (next — CLI surface: `--material` flag + `Receive --armor`)
Status: Phase complete — ready for verification
Last activity: 2026-04-24

Progress: [██████████] 100%

## Performance Metrics

**Velocity:**

- Total plans completed (v1.1): 0
- Average duration: — (no data yet)
- Total execution time: 0 hours

**By Phase (v1.1):**

| Phase | Plans | Total | Avg/Plan |
|-------|-------|-------|----------|
| 5. Non-interactive automation E2E | 0/TBD | — | — |
| 6. Typed Material: X509Cert | 2/4 | 24min | 12min |
| 7. Typed Material: PgpKey + SshKey | 0/TBD | — | — |
| 8. --pin and --burn modes | 0/TBD | — | — |
| 9. Real-DHT E2E + CAS race gate | 0/TBD | — | — |
| 5 | 3 | - | - |

**Recent Trend:**

- Last 5 plans (v1.0): 04-01, 04-02, 04-03, 04-04, 04-05 (archived)
- Trend: — (v1.1 begins)

*Historical v1.0 metrics archived at `.planning/milestones/v1.0-ROADMAP.md` and `.planning/RETROSPECTIVE.md`.*
| Phase 06 P02 | 7min | 1 tasks | 3 files |
| Phase 06 P03 | 19min | 3 tasks | 16 files |
| Phase 06 P04 | 21min | 6 tasks | 11 files |

## Accumulated Context

### Decisions

Decisions are logged in PROJECT.md Key Decisions table.
Recent decisions affecting current work:

**v1.1 Phase 6 Plan 01 (2026-04-24):**

- `Material::X509Cert` promoted from unit variant to `{ bytes: Vec<u8> }` struct variant; wire shape `{"type":"x509_cert","bytes":"<base64-std>"}` reuses existing `base64_std` serde helper with no configuration change
- AD-2 resolved: new `src/payload/ingest.rs` file (not inline `pub mod ingest { ... }`); `src/payload.rs` → `src/payload/mod.rs` directory module — first multi-file module under `src/`. Phase 7 adds `ingest::pgp_key()` + `ingest::ssh_key()` peer functions there
- `Error::InvalidMaterial { variant: String, reason: String }` with generic Display literal; no `#[source]` or `#[from]` — the `reason: String` is the oracle-hygiene gate (D-P6-03 / X509-08); exit 1 (distinct from exit 3 sig failures)
- `Error::InvalidMaterial` reason strings locked in code as short curated literals: `"malformed DER"`, `"PEM body decode failed"`, `"PEM label is not CERTIFICATE"`, `"trailing bytes after certificate"`, `"accessor called on wrong variant"` — Plan 04's enumeration test constructs these explicitly
- x509-parser 0.16.0 pulled with `default-features = false`, `verify` feature OFF; `cargo tree | grep -E "ring|aws-lc"` empty (verified T-06-06 mitigation)
- MSRV blocker: x509-parser 0.16's transitive `time 0.3.47` requires rustc 1.88.0 — cipherpost MSRV is 1.85; pinned `time 0.3.41` via Cargo.lock (Cargo.toml dep spec unchanged). Inform Phase 7 planners: any new crate addition should run `cargo build` against the project toolchain before committing
- Debug redaction uniform: `X509Cert([REDACTED N bytes])` mirrors `GenericSecret` shape — one rule for all byte-carrying variants (Pitfall #7)

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

**v1.1 Phase 6 Plan 02 (2026-04-24):**

- preview::render_x509_preview lives in a new src/preview.rs module (D-P6-17) with pure-function contract — no side effects, caller owns emission. x509-parser imports kept out of payload/ and flow.rs per architectural-responsibility map.
- DN rendering uses x509-parser's Display impl (OpenSSL-forward order) — RESEARCH CORRECTION 1 resolved OQ-3. The built-in Display matches `openssl x509 -noout -subject` output; no hand-rolled RDN reversal.
- Key-algorithm dispatch is OID-based (spki.algorithm.algorithm), not PublicKey-enum-based — RESEARCH CORRECTION 2. Ed25519/Ed448 come through PublicKey::Unknown so the enum would miss them; OID-first dispatch covers all top-10 algorithms with dotted-OID fallback for unknown.
- `format_unix_as_iso_utc` bumped from `fn` to `pub(crate) fn` — single source of truth across flow.rs banner emission and preview.rs NotBefore/NotAfter rendering. UAT-2 2026-04-21 pinned test (no double `" UTC"` suffix) still green.
- `secp256k1` curve uses dotted-OID string match (`"1.3.132.0.10"`) — no exported constant in oid-registry 0.7; documented fallback path per RESEARCH Focus 4.
- `[EXPIRED]` / `[VALID]` tag fails open on SystemTime clock error (returns `[VALID]`) — NotAfter ISO timestamp is always shown regardless, so the tag is UX decoration, not a block.
- v1.1 Phase 6 Plan 03 (2026-04-24): AD-1 resolved as Option A (pre-render preview subblock in run_receive caller; TtyPrompter stays ignorant of x509-parser). Prompter trait gains ONE Option<&str> arg; test prompters ignore it. Phase 7 extends via new match arms in run_receive.
- v1.1 Phase 6 Plan 03 (2026-04-24): AD-3 resolved as Option A (run_send gains material_variant: MaterialVariant param; MaterialSource unchanged). Every existing Phase 2/3/5 integration test needed only a one-line GenericSecret addition — no construct-Material refactor across 13 test files.
- v1.1 Phase 6 Plan 03 (2026-04-24): OQ-1 resolved to reject --armor on GenericSecret with Error::Config("--armor requires --material x509-cert") (exit 1). Silent-ignore rejected — wastes debug time when user expects PEM and gets raw bytes.
- v1.1 Phase 6 Plan 03 (2026-04-24): Cap-on-decoded-size pattern established — run_send ingests BEFORE the 64KB cap check, and the cap reads material.plaintext_size() so a 1MB PEM decoding to 100KB DER fails the cap on DECODED size. Phase 7 PGP/SSH inherit the pattern.
- v1.1 Phase 6 Plan 03 (2026-04-24): Defense-in-depth dispatch rejection for unimplemented typed variants — PgpKey/SshKey rejected at main.rs::dispatch (before identity load) AND at flow::run_send (library-level safety for non-CLI callers). NotImplemented{phase:7} with unified Display surfaces as exit 1.
- v1.1 Phase 6 Plan 03 (2026-04-24): pem_armor_certificate is hand-rolled (base64-STANDARD + CERTIFICATE header/footer) — no new Cargo dep. base64 0.22 already pulled by Phase 1 for OuterRecord blob. Output matches openssl x509 -in cert.der -inform DER -outform PEM byte-for-byte.
- v1.1 Phase 6 Plan 04 (2026-04-24): X509 full MockTransport round-trip tests marked #[ignore] due to BEP44 1000-byte ceiling — realistic Ed25519 cert (388 B DER) produces 1616 B packet; two-tier storage architectural fix scoped to later phase. Added positive WireBudgetExceeded-surfaces-cleanly test covering Pitfall #22.
- v1.1 Phase 6 Plan 04 (2026-04-24): Phase 6 ship-gate bundle pattern established for Phase 7 reuse — fixture DER + JCS byte-identity test + ingest negative matrix + golden-string banner + oracle-hygiene enumeration + leak-scan extension + CI dep-tree assertion + SPEC.md update.
- v1.1 Phase 6 Plan 04 (2026-04-24): Wire-budget deferral pattern (Option A): #[ignore] round-trip tests + add positive test asserting error surfaces as WireBudgetExceeded cleanly. Phase 7 PGP/SSH will hit the same ceiling; wire-budget escape hatch (two-tier storage / chunking / out-of-band) must be decided at Phase 7 plan time.

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
Stopped at: Phase 7 planning complete (8 plans, PASS verdict)
Resume file: --resume-file

**Planned Phase:** 6 (Typed Material — X509Cert) — 4 plans, 2 shipped — 2026-04-24T18:22:32.720Z
**Next action:** `/gsd-execute-phase 6` (continues with Plan 03 — CLI `--material` flag + `Receive --armor` + run_send/run_receive wiring)
