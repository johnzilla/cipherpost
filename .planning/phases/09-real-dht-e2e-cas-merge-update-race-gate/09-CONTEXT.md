# Phase 9: Real-DHT E2E + CAS merge-update race gate - Context

**Gathered:** 2026-04-26
**Status:** Ready for planning

<domain>
## Phase Boundary

Validate the cipherpost protocol over real Mainline DHT end-to-end and prove
concurrent receipt publication is safe under contention. This is the v1.1
release-acceptance gate — the "it's not just MockTransport" proof. No new
wire formats, no new crypto, no new payload variants — Phase 9 closes the v1.1
milestone by adding a CAS racer test (in CI under MockTransport), a
manual-only real-DHT cross-identity round trip (behind a feature flag), a
wire-budget headroom assertion for the pin+burn+typed-material composite, and
a versioned `RELEASE-CHECKLIST.md` at repo root that gates every v1.1+ release.

**In scope (this phase):**
- MockTransport gains explicit CAS semantics on `publish_receipt` (DHT-01) — per-key sequence number; mismatch returns `CasConflict`; matches `pkarr::Timestamp` semantics behaviorally.
- CAS racer integration test (DHT-02) — two `std::thread`s synchronized via `std::sync::Barrier`, both call `publish_receipt` on the same recipient key with different receipts, exactly one wins on first attempt, the loser retries-and-merges, final state contains both receipts. Runs in CI under `cargo test --features mock`.
- Single-retry-then-fail CAS contract (D-P9-A1): on `CasConflict`, transport resolves once, merges, republishes once. Second conflict surfaces as `Error` to caller. Recommended for v1.1 — receipt publish is rare-conflict territory; explicit failure is clearer than silent retry storms.
- Retry loop lives **inside the `Transport` trait method** (D-P9-A2). `publish_receipt()` internally retries; caller sees `Ok(())` or final `Err`. Both `DhtTransport` and `MockTransport` implement the same retry contract. `CasConflict` never escapes the trait boundary.
- Real-DHT cross-identity round trip behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` (DHT-03/04/05). Two in-process `pkarr::ClientBlocking` clients with independent identities; A publishes, B resolves with 120-second exponential-backoff ceiling, B decrypts, B publishes receipt, A fetches. Manual run only — **CI never runs real-DHT tests** (DHT-D2). RELEASE-CHECKLIST is the gate.
- UDP reachability pre-flight (DHT-05): probe a known Mainline bootstrap node; if unreachable within 5s, skip with `"real-dht-e2e: UDP unreachable; test skipped (not counted as pass)"`. Manual runs on a real network observe no skip.
- 120s test timeout enforced **both** in-test (`std::time::Instant`-based deadline in the resolve loop) and via `cargo --test-timeout` flag (D-P9-D3) — belt and suspenders.
- Wire-budget headroom test (DHT-07): pin+burn+pgp realistic-payload composite asserted to surface `Error::WireBudgetExceeded` cleanly at send (not a pkarr-internal panic). Continues the Phase 6/7 wire-budget test pattern.
- `RELEASE-CHECKLIST-v1.1.md` at repo root (D-P9-C2/C4): standard ship-gate scope (~80 lines, D-P9-C1) — real-DHT command + expected output + cargo test --features mock + clippy + audit + lychee + fixture byte-count assertions + recent RUSTSEC review. Markdown checkbox format (D-P9-C3). Versioned snapshot per release; living template at `/RELEASE-CHECKLIST.md` is the source-of-truth template.
- README + SPEC.md inline note (D-P9-B4) that v1.1 uses pkarr default Mainline bootstrap nodes only — no user-tunable bootstrap configuration in this milestone.

**Out of scope (deferred or rejected):**
- Real-DHT CAS racer (concurrent receipt-publish over real network). REQ DHT-02 binds the CAS racer to MockTransport only; real-DHT scope strictly cross-identity round trip per D-P9-D1.
- Multiple real-DHT tests in CI. Pitfall 29 hard-cap: zero real-DHT in PR/CI; nightly/release CI also avoids real-DHT this milestone (D-P9-D2). Defer if a multi-test real-DHT suite ever lands.
- `CIPHERPOST_DHT_BOOTSTRAP` env var. v1.1 = pkarr defaults only (D-P9-B1). Open question carried forward in STATE.md ("verify pkarr 5.0.4 ClientBuilder bootstrap configurability") is now closed for v1.1; revisit only if a v1.2+ user requests private testnet support.
- Multi-retry CAS schemes (3-attempt exp-backoff; deadline-bounded). Single-retry-then-fail per D-P9-A1.
- Verbose stderr on CAS retry. Default silent; opt-in via `CIPHERPOST_DEBUG=1` (D-P9-A4).
- New `Error::CasConflict` variant in the public API. CAS conflicts are absorbed inside the transport's single-retry; if both attempts fail, surface via the existing `Error::Transport` or `Error::Network` mapping. **Open for planner**: whether the second-conflict failure mode warrants a new `Error::CasConflictFinal` variant or rides existing variants. Default recommendation: ride `Error::Transport` (no new variant; preserves error-oracle hygiene).
- Wire-budget escape hatch for oversized pin+burn+typed composites. Phase 6/7 deferred this to v1.2 wire-budget delivery-mechanism milestone; Phase 9 only asserts the clean-error surface (DHT-07), never the success path.
- Bootstrap-default reachability test, multi-test real-DHT suite, CAS racer over real DHT. All deferred to a future "real-DHT hardening" phase if pursued.

</domain>

<decisions>
## Implementation Decisions

### A. CAS retry-and-merge contract (the resolve-merge-republish lock-in)

- **D-P9-A1 · Single retry-then-fail.** On `CasConflict` from `publish_receipt`: resolve once, merge, republish once. Second conflict surfaces as `Err` to caller; user re-runs cipherpost on persistent collision. Receipt publish is rare-conflict territory (PKARR p50 ≈ 1 minute makes meaningful contention rare); silent retry storms would mask real network issues. **Rejected:** 3-retry exp-backoff (50ms→200ms→800ms) — over-engineered for the contention domain. **Rejected:** unbounded-deadline retry (5s wall clock) — non-deterministic test surface; harder to reason about timeout interaction with PKARR's own retry logic.

- **D-P9-A2 · Retry loop lives inside the `Transport` trait method.** `publish_receipt()` internally does the resolve-merge-republish-once cycle; caller sees `Ok(())` or final `Err`. `CasConflict` is an internal signal that never crosses the trait boundary. Both `DhtTransport` (via `pkarr::Client::publish` + `cas: Option<Timestamp>`) and `MockTransport` (via per-key seq) implement the same retry contract. **Rejected:** retry in caller (flow.rs) — boilerplate at every call site; harder to ensure `MockTransport` racer test exercises the same code path as production. **Rejected:** hybrid `retry_with_merge()` helper — premature abstraction; only one call site (the receipt publish in `run_receive` step 13).

- **D-P9-A3 · `MockTransport` models CAS via per-key sequence number.** `MockStore` gains a `seq: u64` per `pubkey_z32`. `publish_receipt` accepts an `Option<u64>` cas token; mismatch returns an internal `CasConflict` that the trait method's retry loop catches and re-resolves. Behaviorally matches `pkarr::Timestamp` semantics — racer test reads-then-publishes via `Barrier`-synchronized threads; one wins, the other observes a stale seq, retries via the trait-internal merge, and republishes. Final state contains both receipts (DHT-02 invariant). **Rejected:** explicit `inject_conflict_once()` test hook — less faithful to real semantics; misses the contention path under the real trait method. **Rejected:** always-require-cas — requires a non-test contract change to the trait signature; conflicts with Phase 1's locked method signatures.

- **D-P9-A4 · CAS retry events log to stderr only when `CIPHERPOST_DEBUG=1`.** Default-silent on success (matches v1.0 ergonomics — `eprintln!("Publishing receipt to DHT...")` on entry; no per-attempt noise). Adds one new env var to the surface area; small cost; keeps default UX clean while preserving debuggability for users investigating slow publishes. **Rejected:** silent always — loses observability when contention does occur. **Rejected:** one-line-per-retry by default — adds noise to the happy path (every successful single-retry would log).

### B. Bootstrap configuration

- **D-P9-B1 · pkarr defaults only for v1.1.** No `CIPHERPOST_DHT_BOOTSTRAP` env var. No `--bootstrap` flag. `pkarr::ClientBuilder` is constructed with library defaults. STATE.md's "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" todo is closeable for v1.1: we don't use the API, so the verification gates v1.2+ if/when private-testnet support is requested. **Rejected:** hidden testing override — adds an undocumented env var that complicates real-DHT test invocation discipline; the test should run against the same defaults real users hit. **Rejected:** first-class user flag — wider surface than the milestone needs; harder to remove later.

- **D-P9-B2 · Bootstrap mechanism documented in README + SPEC.md inline.** Brief mention that v1.1 uses pkarr's default Mainline bootstrap nodes; no user-tunable bootstrap configuration in this milestone. Sets the expectation that future milestones may expose an override if demand surfaces. **Rejected:** SPEC.md §Bootstrap section + RELEASE-CHECKLIST entry — overkill for a non-feature; "we use defaults" doesn't need a section. **Rejected:** undocumented — leaves users guessing about bootstrap-related test failures on restricted networks.

### C. RELEASE-CHECKLIST.md scope and lifecycle

- **D-P9-C1 · Standard ship-gate scope (~80 lines).** Real-DHT command + expected output pattern + manual pass/fail tick + cargo test --features mock + clippy -D warnings + cargo audit + cargo deny check + lychee link-check + fixture byte-count assertions (192 / 424 / 119 / 212 / 142 / DHT-07-additions) + recent RUSTSEC review. Codifies what cipherpost already runs in CI plus the manual real-DHT step. Matches v1.0 close discipline; nothing surprising. **Rejected:** bare-minimum — leaves implicit gates implicit; risks future releases skipping unverified items. **Rejected:** full ship gate (CHANGELOG draft + version-bump verify + git-tag check + crate publish dry-run) — Phase 9 is closing v1.1, not building a release-engineering platform; defer the publish-platform pieces until a release pipeline is built.

- **D-P9-C2 · Lives at repo root: `/RELEASE-CHECKLIST.md`.** Per DHT-06 wording verbatim. Visible in repo browser at the same level as `SPEC.md` / `THREAT-MODEL.md` / `SECURITY.md` — matches v1.0's "top-level docs are first-class" convention. **Rejected:** `/docs/RELEASE-CHECKLIST.md` — diverges from DHT-06 literal wording; cipherpost has no `/docs/` directory yet. **Rejected:** `/.planning/RELEASE-CHECKLIST.md` — conflicts with "gates every v1.1+ release" framing in DHT-06; planning artifacts are pre-ship, not ship-gate.

- **D-P9-C3 · Markdown checkbox format with `[ ]`/`[x]`.** Per-step checkbox; releaser copies-and-ticks. Familiar pattern; pairs naturally with git commits showing the ticked file as part of the release commit. **Rejected:** numbered procedure with explicit pass/fail prose — more friction; checkbox already implies "did it pass". **Rejected:** hybrid (top checklist + bottom reference) — over-engineering for an 80-line document; the reference content fits inline next to each checkbox.

- **D-P9-C4 · Versioned snapshots per release (`RELEASE-CHECKLIST-v1.1.md`, `RELEASE-CHECKLIST-v1.2.md`, ...).** Living template at `/RELEASE-CHECKLIST.md` is the source-of-truth — every new milestone copies-and-ticks it into a versioned snapshot at release time. Preserves historical release evidence ("what we ran for v1.1") even as the template evolves. **Rejected:** living document only — loses per-release evidence; relying on git tag history is recoverable but operationally awkward. **Rejected:** living + tagged-in-git only — same issue; explicit committed snapshot is the "audit-the-process" artifact.

### D. Real-DHT test scope and serialization

- **D-P9-D1 · Cross-identity round trip ONLY for v1.1 real-DHT.** Single test matching DHT-04 verbatim: A sends, B receives, B publishes receipt, A fetches. Strictest interpretation of REQs; lowest CI flake risk; minimum viable proof. **CAS racer stays MockTransport-only per DHT-02** — no concurrent-receipt-publish over real DHT this milestone. **Rejected:** round trip + concurrent receipt race over real network — doubles real-DHT runtime; high flake risk if Mainline contention is unstable; CI doesn't run real-DHT anyway (D-P9-D2). **Rejected:** round trip + UDP-skip + bootstrap-default — three tests would 3x runtime and require coordinating three flake budgets; over-investment for v1.1 close.

- **D-P9-D2 · Zero real-DHT tests in CI; manual-only via RELEASE-CHECKLIST.** Real-DHT tests behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`; CI never runs `--features real-dht-e2e`. PR CI is mock-only. RELEASE-CHECKLIST manual run is the only gate. Matches Pitfall 29 strict reading; eliminates real-DHT CI flake entirely. **Rejected:** one test in nightly CI — adds CI infrastructure (nightly job, separate runner config) without enough payoff for v1.1; cipherpost has no nightly CI today. **Rejected:** Pitfall 29 hard cap with one-per-job — operationalizes the rule literally but still adds CI infrastructure not justified at v1.1 close.

- **D-P9-D3 · 120s timeout enforced both in-test and via `cargo --test-timeout`.** In-test deadline (`std::time::Instant` reads inside the resolve-with-exp-backoff loop; bail at 120s with a clear test-fail message) is the primary defense. `cargo --test-timeout 120` at invocation is the outer guard; documented in RELEASE-CHECKLIST manual command. Belt and suspenders — catches developer-machine misuse and CI invocation drift. Eliminates one class of "why did the test hang for an hour" debugging. **Rejected:** in-test only — relies on test author always remembering; one missed test would hang. **Rejected:** cargo flag only — depends on invocation discipline; if RELEASE-CHECKLIST drops the flag in v1.2 we lose the guard.

- **D-P9-D4 · Single file `tests/real_dht_e2e.rs`.** All real-DHT tests in one file; `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` on each. Mirrors v1.0 single-purpose-test-file convention (compare `tests/state_ledger.rs`, `tests/hkdf_info_enumeration.rs`). Easy to find; one cfg-gate per file is idiomatic. **Rejected:** `tests/real_dht/` subdirectory — premature; we have one test. **Rejected:** inline in existing test files — risks accidentally running real-DHT under default `cargo test` if cfg-gating slips.

### E. Wire-budget headroom test (DHT-07)

- **D-P9-E1 · DHT-07 ships in Phase 9 alongside the CAS racer (Plan 01 or Plan 02 — planner picks).** Continues the Phase 6/7 pattern: realistic-payload composite asserts clean `Error::WireBudgetExceeded` at send (not a pkarr-internal panic). Specifically: `pin_required=true` + `burn_after_read=true` + `Material::PgpKey { bytes: ~2KB }` → encrypted blob exceeds 1000-byte BEP44 ceiling → `run_send` surfaces `Error::WireBudgetExceeded` with concrete `encoded` and `budget` fields. **Open for planner**: whether the test uses the Phase 7 PGP fixture (`tests/fixtures/material_pgp_fixture.pgp`, 419 bytes) padded to ~2KB or a synthesized blob. Recommendation: synthesized 2048-byte byte vector wrapped in a minimal `Material::GenericSecret` (stay within Material variant invariants; assertion is byte-budget, not PGP-parser correctness).

### F. Plan structure (Claude's Discretion → planner picks)

- **D-P9-F1 · Phase 9 is smaller than Phase 8 (no new wire formats, no new crypto).** Candidate splits the planner should consider:
  - **3 plans (recommended)**: (1) CAS racer + MockTransport seq + retry-inside-trait + DHT-07 wire-budget assertion; (2) Real-DHT round trip (feature flag, in-test deadline, UDP pre-flight, single test file); (3) Docs (RELEASE-CHECKLIST-v1.1.md + README/SPEC bootstrap note + CLAUDE.md load-bearing additions for CAS retry contract + STATE.md todo closure).
  - **4 plans**: split (1) into "CAS racer" and "wire-budget assertion" — useful if CAS work compounds in scope.
  - **2 plans**: bundle (1)+(2) into a single "gates" plan and (3) as docs — too tight given CAS retry-inside-trait touches both Mock and Dht transports.
- Final selection deferred to `/gsd-plan-phase 9`. Planner reads this CONTEXT.md and picks based on the actual code-touch surface area at plan time.

### Claude's Discretion

- Whether `CasConflict` becomes a named internal variant (e.g., `TransportInternalError::CasConflict`) or stays as a sentinel returned by a private helper. Both satisfy "never escapes the trait" (D-P9-A2).
- Exact exponential-backoff curve for the real-DHT resolve loop (DHT-04: "120-second exponential-backoff ceiling"). Recommendation: 1s, 2s, 4s, 8s, 16s, 32s, 64s — caps at 120s on the seventh attempt with overall deadline check.
- UDP pre-flight technique (Pitfall 29 says "attempt to connect to a known Mainline DHT bootstrap node"). Recommendation: low-level `std::net::UdpSocket::connect()` to a bootstrap host with 5s read timeout; if the connect or the bind fails, skip with the canonical message.
- Whether `RELEASE-CHECKLIST-v1.1.md` is committed at Phase 9 close (preferred — same commit as the final phase commit) or at v1.1 release tag time. Recommendation: commit the snapshot at Phase 9 close so the v1.1 release branch already has it ticked; subsequent releases create new snapshots from the template.
- Whether the bootstrap mention in README is in a new section or a single sentence in an existing section (e.g., "Networking" or "Configuration"). Recommendation: single sentence — v1.1 doesn't need a section for "we use the defaults".
- Whether `CIPHERPOST_DEBUG` becomes a multi-purpose debug flag (logs at multiple sites) or stays narrowly scoped to CAS retry events. Recommendation: narrowly scoped for v1.1; broadens if v1.2 adds more debug-worthy paths.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` §Real-DHT + merge-update race gate (DHT) — DHT-01..07 (inline phase tags)
- `.planning/REQUIREMENTS.md` §Out of Scope — server/relay/operator (any introduction is out of scope for v1.x core)
- `.planning/REQUIREMENTS.md` §Deferred Requirements (v1.2+) — DEFER-FEAT-04 (multi-recipient broadcast), DEFER-FEAT-02 (audit log)
- `.planning/ROADMAP.md` §Phase 9 — goal + success criteria SC-1..4

### Domain pitfalls (load-bearing for Phase 9)
- `.planning/research/PITFALLS.md` #28 — PKARR concurrent-racer test correctness; mandates true `Barrier`-synced threads, not sleep simulation; MockTransport `cas` semantics requirement → directly drives D-P9-A3
- `.planning/research/PITFALLS.md` #29 — Real-DHT tests CI-hostile; mandates feature flag (not `#[ignore]` alone), pre-flight UDP check, 120s timeout, `#[serial]` discipline → drives D-P9-D2/D3/D4
- `.planning/research/PITFALLS.md` #25 — burn-is-local-state-only — Phase 9's wire-budget composite test (DHT-07) inherits the burn semantics established in Phase 8
- `.planning/research/PITFALLS.md` #22 — per-variant size checks before JCS encode; DHT-07 is the Phase 9 instance of this pattern (asserting clean `WireBudgetExceeded` for the worst-case composite)
- `.planning/research/PITFALLS.md` #16 — error-oracle hygiene; preserved across Phase 9 (no new error variants that distinguish CAS-conflict from other transport failures at the user-facing layer)
- `.planning/research/SUMMARY.md` §Open Questions — pkarr 5.0.4 ClientBuilder bootstrap configurability; CLOSED for v1.1 by D-P9-B1 (we don't use the API)

### Project conventions (CLAUDE.md load-bearing)
- `CLAUDE.md` §Load-bearing lock-ins — `serial_test = "3"` + `#[serial]` on tests that mutate process env (Phase 9 real-DHT tests inherit; both env-mutation and shared-network state); `pkarr::ClientBlocking` — no `tokio` dep at cipherpost layer (Phase 9 must NOT introduce tokio for the real-DHT test harness); error-oracle hygiene (preserved by absorbing CasConflict inside the trait, not surfacing a new user-facing variant)
- `CLAUDE.md` §Architectural lineage — fork-and-diverge from cclink (Phase 9 has no cclink lineage to survey; this is greenfield concurrent-racer + real-DHT work)
- `.planning/PROJECT.md` §Constraints — no servers (Phase 9 must NOT introduce a relay or operator even for testing); ciphertext-only-on-wire (preserved); 64KB plaintext cap held; default TTL 24h held
- `.planning/PROJECT.md` §Key Decisions — `publish_receipt` uses resolve-merge-republish via PKARR `cas`, not overwrite (Phase 9 hardens this with the racer test under contention)

### Phase 6/7/8 locked-in patterns (DO NOT re-derive)
- `.planning/phases/06-typed-material-x509cert/06-CONTEXT.md` §Wire-budget deferral pattern — `#[ignore]` round-trip tests + add positive `WireBudgetExceeded`-surfaces-cleanly test; Phase 9's DHT-07 is the third application of this pattern
- `.planning/phases/07-typed-material-pgpkey-sshkey/07-CONTEXT.md` §Wire-budget continuation — Pitfall #22 measured numbers per typed variant; Phase 9 inherits the budget table for the composite assertion
- `.planning/phases/08-pin-and-burn-encryption-modes/08-CONTEXT.md` §D-P8-13 plan-structure pattern — foundation → ship-gate per feature; docs plan at end. Phase 9's plan-structure recommendation in D-P9-F1 follows but compresses (smaller phase)
- `.planning/phases/08-pin-and-burn-encryption-modes/08-CONTEXT.md` §canonical_refs Source-of-truth lineage — Phase 8's cclink survey closure; Phase 9 has no equivalent lineage section (no cclink survey for concurrent racing)

### Existing code — primary edit sites (paths as of HEAD after Phase 8 close)
- `src/transport.rs::Transport` (line 32) — trait definition. Phase 9 adds internal CAS retry inside `publish_receipt` (no signature change to caller-visible API).
- `src/transport.rs::DhtTransport::publish_receipt` (lines 140-201) — already passes `cas: Option<pkarr::Timestamp>` to `pkarr::Client::publish` (line 198). Phase 9 wraps the publish with a single-retry resolve-merge-republish loop on `CasConflict`-class errors. **Open for planner**: which `pkarr::errors::PublishError` variant signals CAS conflict (likely `PublishError::CasConflict` or similar — verify at plan time).
- `src/transport.rs::MockTransport::publish_receipt` (lines 357-374) — currently overwrites; Phase 9 replaces with per-key seq + cas-check + internal retry. Mirrors DhtTransport's retry path so the racer test exercises the same code shape.
- `src/transport.rs::MockTransport::store` (line 301) — Phase 9 extends `MockStore` with per-key `seq: u64` (or wraps records with seq metadata). Internal change only; no test-API breakage if `resolve_all_txt` semantics preserved.
- `src/error.rs` — exit-code taxonomy unchanged. CAS conflict failures (after single-retry exhaustion) ride existing `Error::Transport` or `Error::Network` per error-oracle hygiene; no new public variant.
- NEW: `tests/cas_racer.rs` — DHT-02 racer test under MockTransport. Two `std::thread`s + `std::sync::Barrier`. `#[serial]` for shared-state hygiene. Asserts: exactly one wins on first attempt, loser retries internally and republishes, final state contains both receipts.
- NEW: `tests/real_dht_e2e.rs` — DHT-03/04/05 cross-identity round trip. `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`. UDP pre-flight; in-test 120s deadline; resolve-with-exponential-backoff loop.
- NEW: `tests/wire_budget_compose_pin_burn_pgp.rs` — DHT-07 clean-error-surface assertion. Synthesized ~2KB payload + `pin_required=true` + `burn_after_read=true` → `Error::WireBudgetExceeded`.
- NEW: `RELEASE-CHECKLIST.md` (template at repo root) and `RELEASE-CHECKLIST-v1.1.md` (versioned snapshot). Standard ship-gate scope; markdown checkboxes.
- `Cargo.toml` `[features]` — add `real-dht-e2e = []`; existing `mock = []` unchanged.
- `src/transport.rs` — likely add new env var read for `CIPHERPOST_DEBUG=1`; minimal stderr-log helper.
- `README.md` — single-sentence note that v1.1 uses pkarr default Mainline bootstrap nodes.
- `SPEC.md` — inline mention of bootstrap = pkarr defaults; new §"Wire-budget composite limits" or extension to existing Pitfall #22 section noting the pin+burn+typed verifier.
- `CLAUDE.md` §Load-bearing lock-ins — add: "single-retry-then-fail CAS contract on `publish_receipt`; retry lives inside the `Transport` trait method; `MockTransport` models CAS via per-key seq (matches `pkarr::Timestamp` semantics behaviorally)"; add: "no `CIPHERPOST_DHT_BOOTSTRAP` env var in v1.1 — pkarr defaults only"; add: "real-DHT tests behind `#[cfg(feature = \"real-dht-e2e\")]` + `#[ignore]` + `#[serial]` and never run in CI; gated only by RELEASE-CHECKLIST manual invocation".
- `.planning/STATE.md` — close the "Verify pkarr 5.0.4 ClientBuilder bootstrap configurability at Phase 9 plan time" todo (resolution: not needed for v1.1; deferred to v1.2+ if/when private testnet support is requested).

### Spec sections to edit in Phase 9
- `SPEC.md` — inline note in `§3 Wire formats` or `§5 CLI`: "v1.1 uses the pkarr default Mainline bootstrap node set; no user-tunable bootstrap configuration."
- `SPEC.md` §Pitfall #22 — extend with the pin+burn+typed-material composite measurement (DHT-07). Per-variant wire-budget table updated with the composite assertion.
- `SPEC.md` §3 (Wire formats) — note that `cas` semantics on `publish_receipt` are now contractual: receivers must implement single-retry-then-fail per the Phase 9 lock-in (or document divergence in `protocol_version`).
- `THREAT-MODEL.md` — no new sections in Phase 9. PIN/burn (§6.5/§6.6) cover the wire-budget composite already.
- `RELEASE-CHECKLIST.md` (NEW, repo root) — template. Standard ship-gate scope (~80 lines).
- `RELEASE-CHECKLIST-v1.1.md` (NEW, repo root) — first versioned snapshot, ticked at v1.1 release.
- `CLAUDE.md` §Load-bearing lock-ins — three new entries (CAS retry contract; bootstrap defaults; real-DHT cfg-flag discipline).
- `README.md` — single-sentence bootstrap note.

### Dependency additions
- **NONE.** Phase 9 uses already-present `pkarr` (cas semantics are existing API — verified at `src/transport.rs:168-198`), `std::sync::Barrier` (std), `std::thread` (std), `std::time::Instant` (std), `std::net::UdpSocket` (std for UDP pre-flight). No new crates.

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets (Phase 1-8 shipped)
- `src/transport.rs::Transport` trait (line 32) — `publish` / `resolve` / `publish_receipt` / `resolve_all_cprcpt` signatures locked since Phase 1; Phase 9 adds CAS internals to `publish_receipt` without changing the signature.
- `src/transport.rs::DhtTransport::publish_receipt` (lines 140-201) — already implements resolve-merge-republish via `cas: Option<pkarr::Timestamp>` (line 168). Phase 9 wraps the existing logic in a single-retry loop. The hard work (resolve, dedupe-by-label, rebuild builder, sign-with-budget-check) is already done — Phase 9 only adds the retry contract.
- `src/transport.rs::MockTransport` (lines 300-389) — internal `MockStore = Arc<Mutex<HashMap<String, Vec<(String, String)>>>>`. Phase 9 extends with per-key seq tracking. `resolve_all_txt` test helper preserved.
- `src/transport.rs::map_pkarr_publish_error` (lines 264-270) — maps `pkarr::PublishError`. Phase 9 either adds a CAS-conflict arm here or handles it earlier in the retry wrapper. **Verify at plan time**: which pkarr error variant signals CAS conflict.
- `cargo test --features mock` — existing 309 tests stay green; Phase 9 adds racer test (DHT-02) + wire-budget composite test (DHT-07) under this same feature flag.
- `serial_test = "3"` + `#[serial]` — existing convention; Phase 9 racer test uses `#[serial]` because shared MockStore state could otherwise race with other mock-transport tests.
- `tests/state_ledger.rs`, `tests/hkdf_info_enumeration.rs` — single-purpose-test-file convention; Phase 9's `tests/cas_racer.rs` and `tests/real_dht_e2e.rs` follow.
- `tests/fixtures/material_pgp_fixture.pgp` (Phase 7) — 419 bytes; Phase 9 may use as basis for synthesized 2KB composite payload, OR planner picks a synthesized byte vector.
- v1.0/v1.1 wire fixtures — 192 / 424 / 119 / 212 / 142 bytes; Phase 9 RELEASE-CHECKLIST asserts byte-counts as a regression guard.

### Established Patterns (Phase 6-8)
- Wire-budget assertion test: `#[ignore]`'d round-trip + positive `Error::WireBudgetExceeded`-surfaces-cleanly test. Phase 9 DHT-07 is the third instance (after Phase 6 X509 and Phase 7 PGP/SSH).
- `#[cfg(feature = ...)]` test gating: existing `mock` feature for MockTransport tests. Phase 9 adds `real-dht-e2e` feature with same discipline (cfg-gate at the test, not at the lib).
- `#[serial]` on env/network-mutating tests — Phase 9 inherits.
- `EXPECTED_REASONS`-style enumeration tests — Phase 9 has no new error variants reaching user-facing Display, so no enumeration test extension needed.
- Phase 8 D-P8-13 6-plan structure → Phase 9 compressed to 3 plans (D-P9-F1 recommendation).
- Per-phase `CONTEXT.md` → `RESEARCH.md` (optional) → `NN-NN-PLAN.md` × N → `VERIFICATION.md` workflow continues unchanged.

### Integration Points
- `src/transport.rs::Transport` — Phase 9's CAS retry contract is internal to the trait method; no caller-visible API change. `flow.rs::run_receive` step 13 (publish receipt) calls `publish_receipt(...)` and sees `Ok(())` or final `Err` exactly as today.
- `src/transport.rs::DhtTransport` and `MockTransport` — both gain the same retry contract; Phase 9 ensures behavioral parity so the MockTransport racer test exercises the same retry path that ships in production.
- `Cargo.toml` `[features]` — add `real-dht-e2e = []`. Existing `mock = []` unchanged. CI config (`.github/workflows/...`) does NOT run `--features real-dht-e2e`; PR CI stays mock-only.
- `tests/` — three new files: `tests/cas_racer.rs`, `tests/real_dht_e2e.rs`, `tests/wire_budget_compose_pin_burn_pgp.rs`. All `#[serial]` where appropriate.
- `RELEASE-CHECKLIST.md` (template) + `RELEASE-CHECKLIST-v1.1.md` (snapshot) at repo root — new top-level docs.
- `CLAUDE.md` — three new load-bearing lock-ins.
- `README.md` and `SPEC.md` — single-sentence bootstrap-defaults note (D-P9-B2).
- `STATE.md` — close the bootstrap-configurability todo with "deferred to v1.2+ if requested" resolution.

### Anti-patterns to avoid (carried from earlier phases + this discussion)
- Do NOT introduce a `tokio` dependency for the real-DHT test harness. `pkarr::ClientBlocking` is the cipherpost-layer API; Phase 9 uses it. CLAUDE.md load-bearing.
- Do NOT introduce a relay, operator, or "test server" for the real-DHT round trip. Real-DHT means real Mainline DHT; PROJECT.md §Constraints rules out any operator (even optional) for v1.x core.
- Do NOT run real-DHT tests in PR CI. D-P9-D2 + Pitfall 29. PR CI stays mock-only; real-DHT is RELEASE-CHECKLIST manual.
- Do NOT add a new public `Error::CasConflict` variant. Single-retry absorbs the conflict; surfacing it would distinguish CAS contention from other transport failures at the user level (oracle-hygiene risk + user confusion). Ride existing `Error::Transport` / `Error::Network`.
- Do NOT use `sleep`-based simulation for the racer test. Pitfall 28 is explicit: true `std::sync::Barrier`-synchronized threads, both reach the resolve-then-publish boundary together.
- Do NOT add a `CIPHERPOST_DHT_BOOTSTRAP` env var read in v1.1. D-P9-B1. The pkarr defaults are the contract; v1.2+ may revisit.
- Do NOT log CAS retry events to stderr by default. D-P9-A4. Default-silent; opt-in via `CIPHERPOST_DEBUG=1`.
- Do NOT spawn more than one real-DHT test per CI job (Pitfall 29). v1.1 has zero real-DHT in CI; if a future milestone adds them, the per-job cap applies.
- Do NOT delete or amend existing wire-format fixtures (192 / 424 / 119 / 212 / 142). Phase 9 RELEASE-CHECKLIST asserts byte-counts as a regression guard; any change would surface as red.
- Do NOT skip the in-test deadline check on the real-DHT test. D-P9-D3 explicitly requires both in-test and cargo-flag enforcement; relying on `cargo --test-timeout` alone leaves a hole if invocation discipline drifts.
- Do NOT promote bootstrap configurability to a first-class flag without a v1.2 milestone gate. The "we use defaults" decision is intentional ship-narrow discipline.
- Do NOT introduce a CAS racer test against real DHT. D-P9-D1: real-DHT scope is strictly cross-identity round trip; CAS racer is MockTransport-only per DHT-02.
- Do NOT relax the `#[serial]` requirement on real-DHT tests even though there's only one. Pitfall 29 says `#[serial]`; consistency matters if a future test joins the file.

</code_context>

<specifics>
## Specific Ideas

- **CAS racer test sketch (DHT-02, MockTransport):**
  ```rust
  // tests/cas_racer.rs — #[serial], requires --features mock
  use cipherpost::{transport::MockTransport, Receipt, ...};
  use std::sync::{Arc, Barrier};
  use std::thread;

  #[test]
  #[serial]
  fn publish_receipt_cas_racer_two_threads_both_persist() {
      let mock = Arc::new(MockTransport::new());
      let recipient_keypair = test_keypair("bob");
      let receipt_a = build_receipt("share_ref_a", &recipient_keypair);
      let receipt_b = build_receipt("share_ref_b", &recipient_keypair);
      let barrier = Arc::new(Barrier::new(2));

      let h_a = {
          let mock = mock.clone();
          let kp = recipient_keypair.clone();
          let barrier = barrier.clone();
          thread::spawn(move || {
              barrier.wait();
              mock.publish_receipt(&kp, "share_ref_a", &receipt_a).unwrap();
          })
      };
      let h_b = {
          let mock = mock.clone();
          let kp = recipient_keypair.clone();
          let barrier = barrier.clone();
          thread::spawn(move || {
              barrier.wait();
              mock.publish_receipt(&kp, "share_ref_b", &receipt_b).unwrap();
          })
      };

      h_a.join().unwrap();
      h_b.join().unwrap();

      let all = mock.resolve_all_txt(&recipient_keypair.public_key().to_z32());
      assert_eq!(all.iter().filter(|(l,_)| l.starts_with("_cprcpt-")).count(), 2,
                 "both receipts must persist after concurrent publish");
  }
  ```

- **Real-DHT round trip skeleton (DHT-03/04/05):**
  ```rust
  // tests/real_dht_e2e.rs — #[cfg(feature = "real-dht-e2e")] #[ignore] #[serial]
  #[cfg(feature = "real-dht-e2e")]
  #[test]
  #[ignore]
  #[serial]
  fn real_dht_cross_identity_round_trip_with_receipt() {
      // 1. UDP pre-flight (5s timeout); skip with canonical message if unreachable
      if !udp_bootstrap_reachable(std::time::Duration::from_secs(5)) {
          eprintln!("real-dht-e2e: UDP unreachable; test skipped (not counted as pass)");
          return;
      }

      // 2. Spawn two in-process clients; identity_a and identity_b
      let alice = pkarr::ClientBlocking::new(pkarr::ClientBuilder::default()).unwrap();
      let bob   = pkarr::ClientBlocking::new(pkarr::ClientBuilder::default()).unwrap();
      let dht_alice = DhtTransport::with_client(alice);
      let dht_bob   = DhtTransport::with_client(bob);

      // 3. A publishes share to B; A waits, then B resolves with exp-backoff (deadline 120s)
      let deadline = std::time::Instant::now() + std::time::Duration::from_secs(120);
      // ... send / resolve / verify / accept / decrypt / publish_receipt / fetch_receipts ...

      // 4. Assert: round trip completes within 120s; receipt count == 1
  }
  ```

- **RELEASE-CHECKLIST-v1.1.md mockup (~80 lines, standard ship gate):**
  ```markdown
  # Cipherpost v1.1 Release Checklist

  **Release date:** YYYY-MM-DD
  **Releaser:** @<github-username>
  **Tag:** v1.1.0

  ## Pre-flight

  - [ ] All Phase 5–9 VERIFICATION.md files signed off (pass)
  - [ ] PROJECT.md §Validated reflects shipped scope
  - [ ] Cargo.toml version = "1.1.0"

  ## Code gates (run in repo root)

  - [ ] `cargo fmt --check` — no diff
  - [ ] `cargo clippy --all-targets -- -D warnings` — clean
  - [ ] `cargo audit` — no advisories OR documented exceptions in deny.toml
  - [ ] `cargo deny check` — clean
  - [ ] `cargo test` (no features) — all green
  - [ ] `cargo test --features mock` — all green (309+ tests)
  - [ ] `lychee --offline SPEC.md THREAT-MODEL.md SECURITY.md README.md CLAUDE.md` — no broken links

  ## Wire-format byte-counts (regression guard)

  - [ ] `tests/fixtures/outer_record_signable.bin` — 192 bytes
  - [ ] `tests/fixtures/receipt_signable.bin` — 424 bytes
  - [ ] `tests/fixtures/envelope_jcs_generic_secret.bin` — 119 bytes
  - [ ] `tests/fixtures/outer_record_pin_required_signable.bin` — 212 bytes
  - [ ] `tests/fixtures/envelope_burn_signable.bin` — 142 bytes
  - [ ] (Phase 9-added fixtures, if any)

  ## Manual real-DHT gate (DHT-03/04/05)

  - [ ] Run on a network with outbound UDP allowed
  - [ ] `cargo test --features real-dht-e2e -- --ignored --test-timeout 120 dht_e2e`
  - [ ] Test passes within 120s (or skips with the canonical UDP-unreachable message — not a release blocker if local network is restricted; rerun on a permissive network)
  - [ ] Output includes "round trip completed" line; receipt count == 1

  ## Security review

  - [ ] Review RUSTSEC advisory list for any new advisories against v1.1 deps since v1.0
  - [ ] Confirm SECURITY.md disclosure channel is live
  - [ ] Verify `chacha20poly1305` does NOT appear as a direct dep (only transitive via age)
  - [ ] HKDF info enumeration test green (asserts `cipherpost/v1/<context>` prefix)

  ## Release artifacts

  - [ ] Tag v1.1.0 commit
  - [ ] Update MILESTONES.md with v1.1 close summary
  - [ ] Snapshot this file as RELEASE-CHECKLIST-v1.1.md (ticked) at release commit
  ```

- **MockTransport CAS extension sketch:**
  ```rust
  type MockStore = Arc<Mutex<HashMap<String, MockStoreEntry>>>;
  struct MockStoreEntry { records: Vec<(String, String)>, seq: u64 }

  // publish_receipt (excerpt):
  // 1. Lock store; get current seq for pubkey (default 0).
  // 2. Resolve current state (clone records).
  // 3. Drop lock; build new record set with the new receipt merged in.
  // 4. Re-lock; check seq still matches; if mismatch, return CasConflict.
  // 5. If match: bump seq, write merged records, release lock.
  // 6. Internal retry catches CasConflict and re-runs steps 2-5 once.
  ```

- **CAS retry inside trait method (pseudocode):**
  ```rust
  fn publish_receipt(&self, kp, share_ref, json) -> Result<(), Error> {
      match self.publish_receipt_attempt(kp, share_ref, json) {
          Ok(()) => Ok(()),
          Err(InternalCasConflict) => {
              // single retry: resolve-merge-republish
              if cipherpost_debug_enabled() {
                  eprintln!("Receipt publish: CAS conflict, retrying...");
              }
              self.publish_receipt_attempt(kp, share_ref, json)
                  .map_err(|e| match e {
                      InternalCasConflict => Error::Transport(...), // final failure
                      other => other.into(),
                  })
          }
          Err(other) => Err(other.into()),
      }
  }
  ```

- **Wire-budget composite (DHT-07) sketch:**
  ```rust
  // tests/wire_budget_compose_pin_burn_pgp.rs — under cargo test --features mock
  #[test]
  fn pin_burn_realistic_payload_surfaces_wire_budget_exceeded() {
      let payload = vec![0u8; 2048]; // synthesized 2KB; not parser-tested
      let result = run_send_with_options(payload, /* pin */ true, /* burn */ true, ...);
      match result {
          Err(Error::WireBudgetExceeded { encoded, budget, plaintext: _ }) => {
              assert!(encoded > budget, "wire budget exceeded as expected");
          }
          other => panic!("expected WireBudgetExceeded, got {:?}", other),
      }
  }
  ```

</specifics>

<deferred>
## Deferred Ideas

- **`CIPHERPOST_DHT_BOOTSTRAP` env override / `--bootstrap` flag** — pkarr defaults only for v1.1 (D-P9-B1). Revisit at v1.2+ if private-testnet support is requested. STATE.md "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" todo is closeable for v1.1.
- **Multi-retry CAS schemes** (3-attempt exp-backoff; deadline-bounded) — single-retry-then-fail per D-P9-A1. Revisit if real-world contention patterns surface that single-retry doesn't absorb.
- **CAS racer over real DHT** — REQ DHT-02 binds the racer to MockTransport. Real-DHT scope is strictly cross-identity round trip per D-P9-D1. If a future milestone adds real-DHT contention testing, it gets its own phase.
- **Multi-test real-DHT suite (round trip + UDP-skip + bootstrap-default + CAS racer)** — v1.1 ships round trip only. Future milestone if real-DHT hardening is pursued.
- **Real-DHT tests in nightly CI** — v1.1 ships zero real-DHT in CI per D-P9-D2. If a nightly job is added later, Pitfall 29's one-test-per-job cap applies.
- **`--bootstrap` CLI flag** — out of scope; v1.1 uses pkarr defaults only.
- **Public `Error::CasConflict` variant** — absorbed inside the transport's single-retry; never escapes. If user-visible CAS contention reporting is requested in a future milestone, revisit error-oracle hygiene at that time.
- **Multi-purpose `CIPHERPOST_DEBUG`** — narrowly scoped to CAS retry events for v1.1. May broaden in v1.2 if more debug-worthy paths surface.
- **RELEASE-CHECKLIST.md full ship-gate scope (CHANGELOG + version bump + git tag + crate publish dry-run)** — v1.1 ships standard scope per D-P9-C1. Promote to full scope when a release-engineering pipeline is built.
- **Wire-budget escape hatch (two-tier storage / chunking / OOB delivery)** — Phase 6/7 deferred to v1.2 wire-budget delivery-mechanism milestone. Phase 9 only asserts the clean-error surface (DHT-07).
- **Real-DHT bootstrap-default reachability test** — would assert pkarr defaults reach a quorum from a typical user network. Out of v1.1 real-DHT scope; revisit if real-world deployment patterns require it.
- **Multi-recipient receipt aggregation under contention** — v1.1's CAS racer covers same-key concurrent publish. Multi-recipient broadcast (DEFER-FEAT-04) is v1.2 PRD scope; contention semantics will need revisiting then.
- **Switching `MockTransport` to a behavior-faithful in-memory PKARR simulator** — v1.1's mock matches behavior at the trait-contract level only. A higher-fidelity simulator (full DNS packet building, real signing, real cas timestamps) would be valuable but is a substantial separate effort. Defer until a phase needs it.

</deferred>

---

*Phase: 09-real-dht-e2e-cas-merge-update-race-gate*
*Context gathered: 2026-04-26*
*STATE.md "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" todo closed for v1.1 by D-P9-B1.*
