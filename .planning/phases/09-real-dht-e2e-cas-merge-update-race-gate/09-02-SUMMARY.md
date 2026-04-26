---
phase: 09-real-dht-e2e-cas-merge-update-race-gate
plan: 02
subsystem: transport
tags: [real-dht, integration-test, feature-flag, nextest, manual-only, exp-backoff, udp-pre-flight, triple-gate]

# Dependency graph
requires:
  - phase: 09-real-dht-e2e-cas-merge-update-race-gate
    provides: "09-01 settled the publish_receipt CAS retry contract; 09-02 layers the real-DHT round-trip test on top so cross-identity flake risk doesn't compound with retry-contract risk"
  - phase: 03-receipts
    provides: "DhtTransport::publish_receipt + Transport::resolve_all_cprcpt — used end-to-end in the round trip"
  - phase: 08-pin-and-burn-encryption-modes
    provides: "AutoConfirmPrompter pattern via flow::test_helpers (test-only cfg-gated module pattern that 09-02 extends)"
provides:
  - "Cargo `[features] real-dht-e2e = []` flag (D-P9-D2): explicit opt-in for the only network-touching test in the suite"
  - "[[test]] real_dht_e2e entry with required-features = [\"real-dht-e2e\"]"
  - "tests/real_dht_e2e.rs (249 lines): single cross-identity round-trip test under triple gate (cfg + ignore + serial)"
  - ".config/nextest.toml (17 lines, NEW — first nextest config in repo): per-test slow-timeout = { period = \"60s\", terminate-after = 2 } outer guard for test(real_dht_e2e); 120s wall-clock cap pairs with the in-test Instant deadline"
  - "udp_bootstrap_reachable() helper: 5s probe of router.bittorrent.com:6881 via std::net::UdpSocket; canonical skip message verbatim when unreachable"
  - "7-step exp-backoff curve [1u64, 2, 4, 8, 16, 32, 64]s clipped to remaining budget — applied to BOTH the resolve loop AND the receipt-fetch loop (4 deadline checks total)"
  - "src/flow.rs cfg-gate extension: `pub mod test_helpers` now visible under `feature = \"real-dht-e2e\"` in addition to `cfg(test) | feature = \"mock\"` (Rule 3 auto-fix)"
affects:
  - "09-03 (RELEASE-CHECKLIST + SPEC.md / CLAUDE.md docs): the manual run command must reference nextest (no `cargo --test-timeout` flag exists on stable cargo); the bootstrap defaults note (D-P9-B2) cites the 4 default Mainline nodes recorded below"
  - "Future v1.2+ private-testnet support (DEFER, D-P9-B1): if a CIPHERPOST_DHT_BOOTSTRAP env var or --bootstrap flag lands, this test's UDP pre-flight target hardcode is the single point that needs updating"

# Tech tracking
tech-stack:
  added:
    - "(no new crate dependencies)"
  patterns:
    - "Triple-gate discipline (`#[cfg(feature)]` + `#[ignore]` + `#[serial]`) for CI-hostile network tests — D-P9-D2 belt-and-suspenders applied to the only real-DHT test in the suite"
    - "UDP pre-flight pattern: DNS-resolve + bind UDP socket + connect to bootstrap host with 5s deadline; skip-with-canonical-message on any failure (NOT a panic — release-checklist runs gracefully on restricted networks)"
    - "Backoff curve `[1u64, 2, 4, 8, 16, 32, 64]s` deadline-clipped via `Duration::from_secs(delay).min(remaining)`: same curve applied to TWO independent loops (publish-resolve, receipt-fetch). Sum 127s clipped to 120s deadline."
    - "`Box<dyn Prompter> = Box::new(AutoConfirmPrompter)` then pass `&*prompter` for the `&dyn Prompter` parameter — explicit boxing keeps the unit-struct invariant visible at the construction site even though the function takes a reference (ergonomic but slightly unusual; documented inline)"
    - "`.config/nextest.toml` per-test slow-timeout overrides: `terminate-after` is the ENFORCEMENT knob (without it, slow-timeout merely reports — RESEARCH.md Pitfall D)"
    - "Cfg-gate extension pattern: when an integration-test crate needs access to a cfg-gated test_helpers module under a NEW feature flag, extend the cfg-gate rather than duplicate the helper struct (preserves DRY across mock + real-dht-e2e features)"

key-files:
  created:
    - "tests/real_dht_e2e.rs (249 lines): single cross-identity round-trip test"
    - ".config/nextest.toml (17 lines): first nextest config in repo; per-test slow-timeout outer guard"
  modified:
    - "Cargo.toml (+15 lines): added `real-dht-e2e = []` to [features] block; added [[test]] real_dht_e2e entry with required-features"
    - "src/flow.rs (+7 lines / -1 line): extend test_helpers cfg-gate to also include `feature = \"real-dht-e2e\"` (Rule 3 auto-fix; explanatory comment block added)"

key-decisions:
  - "Test compile-only verification by executor (autonomous: false). The plan explicitly forbids `cargo test --features real-dht-e2e --ignored` — the live network round trip is a RELEASE-CHECKLIST manual gate (Plan 09-03 deliverable). Executor verifies `cargo build --features real-dht-e2e --tests` exits 0; that's the only verification this wave can do without flake risk."
  - "Cfg-gate extension on `flow::test_helpers` (Rule 3 deviation, see Deviations § below). The alternative — inlining a duplicate `AutoConfirmPrompter` impl in tests/real_dht_e2e.rs — would split a 14-line struct + Prompter impl across two files, drift-prone if the trait's method signature evolves. Extending the cfg-gate is the minimal change."
  - "Backoff curve applied to TWO loops (resolve + receipt-fetch) with shared `deadline` Instant. The second loop on `resolve_all_cprcpt` may exhaust the deadline already-mostly-consumed by the first loop's resolve waits; an `Instant::now() >= deadline` check at the top of each loop iteration handles the all-consumed case (treats it as resolve failure → test panic, same as if the first loop had run out)."
  - "`Box::new(AutoConfirmPrompter)` even though `run_receive` takes `&dyn Prompter`. The plan's done-criteria require the literal `Box::new(AutoConfirmPrompter)` string AND zero `AutoConfirmPrompter::new` literal. We satisfy both by binding `let prompter: Box<dyn Prompter> = Box::new(AutoConfirmPrompter)` and passing `&*prompter`. Slightly redundant but matches the executor contract verbatim and documents the unit-struct invariant at the construction site."

patterns-established:
  - "First nextest config (`.config/nextest.toml`) in cipherpost — Plan 09-03's RELEASE-CHECKLIST will document `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)'` as the manual command, with the 120s budget enforced by the per-test override (NOT a cargo flag, which doesn't exist on stable)."
  - "`Box::new(AutoConfirmPrompter)` pattern for tests that need to satisfy a Box-construction invariant from a contract while the underlying API takes `&dyn`. The local binding makes the unit-struct intent visible; `&*prompter` does the trait-object coercion at the call site."

requirements-completed:
  - DHT-03
  - DHT-04
  - DHT-05

# Metrics
duration: ~15 min (executor wall-clock)
completed: 2026-04-26
---

# Phase 09 Plan 02: Real-DHT Cross-Identity Round Trip + Feature Flag + Nextest Outer Guard Summary

**The triple-gated (cfg+ignore+serial) cross-identity round-trip test exists, compiles cleanly under `cargo build --features real-dht-e2e --tests`, and stays invisible to all other build profiles; CI never executes it (D-P9-D2 + Pitfall #29) — manual invocation only via RELEASE-CHECKLIST, gated by a 120s in-test deadline + nextest `terminate-after = 2 × 60s` outer guard.**

## Performance

- **Duration:** ~15 min (executor wall-clock)
- **Started:** 2026-04-26T19:37:54Z (worktree base reset to `814e467`)
- **Completed:** 2026-04-26
- **Tasks:** 2 / 2 (Task 1 — Cargo.toml + .config/nextest.toml; Task 2 — tests/real_dht_e2e.rs + flow.rs cfg-gate extension)
- **Files modified:** 2 (Cargo.toml, src/flow.rs) + 2 created (tests/real_dht_e2e.rs, .config/nextest.toml)
- **Test count:** 311 passed / 0 failed / 19 ignored under `--features mock` (matches Plan 09-01 baseline exactly — new real-DHT test invisible under mock); 238 / 0 / 10 under default features.

## Accomplishments

1. **Triple-gated real-DHT test (D-P9-D2 belt-and-suspenders).** `tests/real_dht_e2e.rs` carries crate-level `#![cfg(feature = "real-dht-e2e")]` AND function-level `#[ignore]` + `#[serial]`. Any single gate would already block CI; using all three eliminates accidental execution under any plausible invocation. PR CI + nightly CI stay mock-only per Pitfall #29.
2. **`real-dht-e2e` cargo feature flag exists; CI never enables it.** `Cargo.toml [features]` extended with `real-dht-e2e = []`; `[[test]] real_dht_e2e` entry with `required-features = ["real-dht-e2e"]`. The `--all-features` invocation pattern in CI is still safe because `#[ignore]` blocks the test even when the feature is on.
3. **UDP pre-flight to router.bittorrent.com:6881 (DHT-05).** `udp_bootstrap_reachable(Duration::from_secs(5))` does DNS-resolve → `UdpSocket::bind("0.0.0.0:0")` → `connect(target)`; on any failure prints the canonical message `real-dht-e2e: UDP unreachable; test skipped (not counted as pass)` verbatim and returns. NOT a release-blocking failure — RELEASE-CHECKLIST docs explain "rerun on a permissive network."
4. **In-test 120s deadline + 7-step exp-backoff curve (D-P9-D3).** `let deadline = Instant::now() + Duration::from_secs(120)` outside both loops; `let backoff_curve = [1u64, 2, 4, 8, 16, 32, 64]` (curve sum = 127s, deadline-clipped at 120s). Applied to BOTH loops (resolve + receipt-fetch) — 4 `Instant::now() >= deadline` checks total. Each sleep is `Duration::from_secs(delay).min(deadline.saturating_duration_since(Instant::now()))` so the last sleep can never exceed the remaining budget.
5. **Nextest outer guard (`.config/nextest.toml`).** Per-test override `slow-timeout = { period = "60s", terminate-after = 2 }` for `filter = 'test(real_dht_e2e)'`. Total wall-clock = 60s × 2 = 120s — pairs exactly with the in-test deadline. `terminate-after` is the ENFORCEMENT knob (RESEARCH.md Pitfall D — without it slow-timeout merely reports).
6. **No async runtime dep at the cipherpost layer (CLAUDE.md load-bearing).** Two `pkarr::ClientBlocking`-backed `DhtTransport::new(Duration::from_secs(120))` instances for Alice and Bob. `std::thread::sleep` is the backoff primitive. `grep -c 'tokio' tests/real_dht_e2e.rs` returns 0.
7. **Cross-identity round trip with separate `CIPHERPOST_HOME` tempdirs.** Alice and Bob each get a `tempfile::TempDir`; the shared `setup()` helper sets `CIPHERPOST_HOME` to that dir before calling `cipherpost::identity::generate(&pw)` so the two identities live in independent keystores. The test re-sets `CIPHERPOST_HOME` between phases (alice-publish → bob-resolve → bob-receive → alice-fetch-receipt) so each side's identity-file reads land in the right dir. `#[serial]` keeps env mutation race-free across other tests.
8. **`Box::new(AutoConfirmPrompter)` construction pattern.** `let prompter: Box<dyn Prompter> = Box::new(AutoConfirmPrompter); ... run_receive(..., &*prompter, false)`. The `Box::new` makes the unit-struct construction visible; `&*prompter` coerces to the `&dyn Prompter` parameter that `run_receive` actually takes (note: the plan's example pseudocode showed a `passphrase` and `pin` parameter that don't exist; the actual signature has 7 args ending in `prompter: &dyn Prompter, armor: bool`).
9. **Round-trip + receipt assertions.** After Bob's `run_receive` succeeds (decrypts Alice's share), Alice fetches receipts under Bob's z32 with the same exp-backoff curve and asserts `receipts.len() == 1` (BURN-04 receipt-count invariant). The plaintext byte-for-byte match is asserted via `assert_eq!(recovered, plaintext, ...)`.

## Task Commits

Each task was committed atomically (worktree mode, `--no-verify` per parallel-executor protocol):

1. **Task 1: feat(09-02): add real-dht-e2e cargo feature + nextest slow-timeout outer guard** — `7d84479`
2. **Task 2: test(09-02): add real-DHT cross-identity round-trip test (DHT-03/04/05)** — `1c4f975`

## Files Created/Modified

**Created:**

- `tests/real_dht_e2e.rs` (249 lines) — single cross-identity round-trip test. Triple-gated. UDP pre-flight + 7-step exp-backoff + 120s deadline + receipt-count assertion + intentional acceptance-gate bypass (with NOTE comment block explaining why).
- `.config/nextest.toml` (17 lines) — first nextest config in cipherpost. Per-test slow-timeout outer guard for `filter = 'test(real_dht_e2e)'`.

**Modified:**

- `Cargo.toml` (+15 lines): two changes — (1) appended `real-dht-e2e = []` to `[features]` block with explanatory comment block; (2) appended `[[test]]` entry for `real_dht_e2e` with `required-features = ["real-dht-e2e"]` and explanatory comment block. No changes to existing entries.
- `src/flow.rs` (+7 lines / -1 line): extended cfg-gate on `pub mod test_helpers` from `cfg(any(test, feature = "mock"))` to `cfg(any(test, feature = "mock", feature = "real-dht-e2e"))`. Explanatory comment block added documenting why integration tests under a NEW feature flag need this extension. Rule 3 auto-fix (see Deviations § below).

## Decisions Made

- **Cfg-gate extension on `flow::test_helpers` is preferred over duplicate-impl.** The alternative would be to inline a copy of `AutoConfirmPrompter` (a 14-line unit struct + `Prompter` impl) in tests/real_dht_e2e.rs. Two impls would drift if the `Prompter` trait's method signature evolves. Extending the cfg-gate keeps the helper centralized.
- **`Box::new(AutoConfirmPrompter)` construction even though `run_receive` takes `&dyn Prompter`.** The plan's done-criteria require the literal `Box::new(AutoConfirmPrompter)` string in the file. We satisfy this by binding `let prompter: Box<dyn Prompter> = Box::new(AutoConfirmPrompter)` and passing `&*prompter` to `run_receive`. Slightly redundant but matches the executor contract verbatim and makes the unit-struct invariant visible.
- **Both backoff loops share one `deadline` Instant.** The receipt-fetch loop may find that the resolve loop already consumed most of the 120s budget — the `Instant::now() >= deadline` check at the top of each iteration breaks gracefully (treated as receipt-fetch failure, same as if the first loop had failed). This is the conservative semantic: real-DHT propagation lag for receipts is in the same regime as outer shares, so a 120s deadline shared across both is realistic.
- **No async runtime introduced.** Per CLAUDE.md load-bearing rule, cipherpost uses `pkarr::ClientBlocking` and `std::thread::sleep`. The plan's algorithm is purely synchronous; introducing async machinery would be a regression of the no-async invariant.
- **NO new public Error variant.** Per CONTEXT.md anti-patterns, real-DHT failures ride existing variants (`Error::Network`, `Error::Transport`, `Error::SignatureOuter`, etc.). Phase 9 deliberately avoids new Error variants for oracle hygiene (PITFALLS.md #16).

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 — Blocking] Extended cfg-gate on `flow::test_helpers` to include `feature = "real-dht-e2e"`**

- **Found during:** Task 2 first build (`cargo build --features real-dht-e2e --tests`).
- **Issue:** `tests/real_dht_e2e.rs` cannot import `cipherpost::flow::test_helpers::AutoConfirmPrompter` because the module is gated on `cfg(any(test, feature = "mock"))`. Integration tests are compiled as a SEPARATE crate (cfg(test) on the lib does NOT activate when integration tests run); without the `mock` feature, `test_helpers` is invisible. The first compile errored with `error[E0432]: unresolved import \`cipherpost::flow::test_helpers\`` and the rustc note `the item is gated here`.
- **Fix:** Changed `#[cfg(any(test, feature = "mock"))]` to `#[cfg(any(test, feature = "mock", feature = "real-dht-e2e"))]` on the `pub mod test_helpers` declaration at `src/flow.rs:1342` (now `:1349` after the comment-block insertion). Added an explanatory comment block above the cfg attribute documenting why the new feature flag needs to be listed.
- **Rationale:** Rule 3 auto-fix (blocking issue preventing task completion). The alternative — duplicating `AutoConfirmPrompter` inline in tests/real_dht_e2e.rs — would split a 14-line struct + Prompter impl across two files; drift-prone if the `Prompter` trait's method signature evolves. Extending the cfg-gate is the minimal, DRY-preserving change.
- **Impact:** No public API change (the helper is still test-only in spirit; the new feature flag itself is dev-only — see `[features] real-dht-e2e = []` comment block which states "manual invocation only"). Production builds without any feature flag never compile `test_helpers`.
- **Files modified:** `src/flow.rs` (one line changed + 6 lines comment block added).
- **Commit:** `1c4f975` (Task 2's commit; bundled with the test file because they share a logical scope).

### Auth gates encountered

None — this plan touches no external services, no auth boundaries.

### Out-of-scope discoveries

- **Pre-existing `clippy::uninlined-format-args` lints** in `build.rs:17` and several `src/error.rs` / `src/transport.rs` / etc. lines. Documented by Plan 09-01 in `.planning/phases/09-real-dht-e2e-cas-merge-update-race-gate/deferred-items.md` as out of scope. Plan 09-02 confirms no NEW lints introduced — `cargo clippy --features real-dht-e2e --tests --no-deps 2>&1 | grep real_dht_e2e.rs` returns 0 lines (verified). Plan 09-02 inherits Plan 09-01's deferred-items disposition unchanged.

### Plan-text vs. actual-API mismatches (resolved without scope deviation)

The plan's `<action>` block in Task 2 contained a pseudocode example for `run_receive` showing parameters `armor: Option<...>, prompter: Box<dyn Prompter>, passphrase, pin` — none of which match the actual signature. The plan explicitly told the executor to "adapt to actual call signatures" so this is not a deviation, just an adjustment recorded for traceability:

- **Actual `run_receive` signature** (verified at `src/flow.rs:545-553`):
  ```rust
  pub fn run_receive(
      identity: &Identity,
      transport: &dyn Transport,
      keypair: &pkarr::Keypair,
      uri: &ShareUri,
      output: &mut OutputSink,
      prompter: &dyn Prompter,
      armor: bool,
  ) -> Result<(), Error>
  ```
  7 args, takes `&dyn Prompter` (NOT `Box<dyn Prompter>`), takes `armor: bool` (NOT `Option<...>`), takes NO `passphrase` and NO `pin` parameters. The Phase 8 PIN flow handles passphrase + PIN internally via `crate::pin::prompt_pin` and CIPHERPOST_PASSPHRASE env / fd / file mechanics — `run_receive`'s caller does not pass them.
- **Adaptation:** call `run_receive(&bob_id, &bob_transport, &bob_kp, &share_uri, &mut sink, &*prompter, false)`. The `&*prompter` coerces the `Box<dyn Prompter>` to `&dyn Prompter`. The `false` is the armor flag (no PEM-armor wrapping on the decrypted output sink). The test does NOT exercise PIN/passphrase paths because the share has neither.

- **Actual `SendMode::Share` variant** (verified at `src/flow.rs:63-66`):
  ```rust
  pub enum SendMode {
      SelfMode,
      Share { recipient_z32: String },
  }
  ```
  Field name is `recipient_z32` (matches plan example).

- **Actual `Identity::z32_pubkey()` and `Identity::signing_seed()`** (verified at `src/identity.rs:71` and `:83`):
  - `pub fn z32_pubkey(&self) -> String` — yes, named exactly as plan example expects.
  - `pub fn signing_seed(&self) -> Zeroizing<[u8; 32]>` — yes; the test dereferences via `let seed: [u8; 32] = *id.signing_seed();` to extract the inner bytes (mirrors `tests/burn_send_smoke.rs:41`).

## Output Spec Items (per plan §<output>)

1. **`SendMode::Share` variant + field name and `run_receive` parameter list as observed in `src/flow.rs`.** Recorded in the "Plan-text vs. actual-API mismatches" subsection above. Verbatim Rust signatures included for Plan 09-03 to cite.

2. **Whether `Identity::z32_pubkey` exists with that name OR was named differently.** `Identity::z32_pubkey()` exists at `src/identity.rs:71` with that exact name. Returns `String`.

3. **Output of `cargo build --features real-dht-e2e --tests`:**
   ```
   Compiling cipherpost v0.1.0 (...)
   Finished `dev` profile [unoptimized + debuginfo] target(s) in 4.37s
   ```
   Zero warnings; zero errors. Compile time ~4-5s on this developer machine.

4. **Confirmation that `cargo test --features mock` baseline + Plan 09-01 deltas remained green.** Aggregate: **311 passed / 0 failed / 19 ignored** under `--features mock`. Matches Plan 09-01 final exactly. No regression. The new test (1 in `real_dht_e2e`) is invisible under `--features mock` because of `#![cfg(feature = "real-dht-e2e")]` at the file head. `cargo test` (no features) reports 238 passed / 0 failed / 10 ignored — also clean.

5. **Output of `cargo nextest list --features real-dht-e2e --run-ignored only`** — not run by executor (no nextest binary on this machine and not required by plan; the slow-timeout config is enforced when nextest IS used during the manual RELEASE-CHECKLIST run). Compile-only verification was the stated executor contract for an `autonomous: false` plan.

6. **Bootstrap defaults assumption — pkarr 5.0.4 default Mainline nodes.** Per CONTEXT.md `<interfaces>`, mainline 6.1.1's `DEFAULT_BOOTSTRAP_NODES` (verified at `mainline-6.1.1/src/rpc.rs:42-47`):
   - `router.bittorrent.com:6881` ← Phase 9 hardcodes for UDP pre-flight (DHT-05)
   - `dht.transmissionbt.com:6881`
   - `dht.libtorrent.org:25401`
   - `relay.pkarr.org:6881`

   Recorded for Plan 09-03's CLAUDE.md lock-in update (D-P9-B1: pkarr defaults only for v1.1; no `CIPHERPOST_DHT_BOOTSTRAP` env var). The first node was deliberately chosen as the UDP pre-flight target because (a) it's the first Mainline default, (b) it's the most Mainline-canonical bootstrap host name (`router.bittorrent.com`), and (c) being unreachable on a network is the strongest signal that the DHT is genuinely inaccessible from this network — fallback to other defaults would only be relevant if the FIRST default specifically is blocked while others are not, which is not a plausible network-restriction pattern.

## Threat Flags

No new security-relevant surface introduced. The plan's `<threat_model>` covers the relevant trust boundaries (test process ↔ Mainline DHT, test process ↔ bootstrap node, cargo test ↔ feature flag) and all dispositions are honored:

- T-09-02-01 (PII in published packets): mitigated — payload is hardcoded `b"phase 9 real-dht handoff payload"`, purpose is generic `"real-dht round trip"`, identities are ephemeral (`tempfile::TempDir`-scoped). Verified at `tests/real_dht_e2e.rs:122,130`.
- T-09-02-03 (test hangs indefinitely): mitigated — in-test 120s deadline (4 `Instant::now() >= deadline` checks) + nextest 120s outer guard. Both committed.
- T-09-02-04 (accidental CI execution): mitigated — triple gate (`#[cfg]` + `#[ignore]` + `#[serial]`). CI does not pass `--ignored` or `--run-ignored only`.
- T-09-02-05 (receipt-count under-reporting): mitigated — explicit `assert_eq!(receipts.len(), 1, ...)` after fetch.

## Self-Check

Verifying claims before declaring complete.

### Files
- `tests/real_dht_e2e.rs` — FOUND (249 lines)
- `.config/nextest.toml` — FOUND (17 lines)
- `Cargo.toml` (modified) — FOUND
- `src/flow.rs` (modified) — FOUND
- `.planning/phases/09-real-dht-e2e-cas-merge-update-race-gate/09-02-SUMMARY.md` — being written now (this file)

### Commits (verified via `git log --oneline 814e4670..HEAD`)
- `7d84479` Task 1 (feat: real-dht-e2e cargo feature + nextest outer guard) — FOUND
- `1c4f975` Task 2 (test: real-DHT cross-identity round-trip test) — FOUND

### Build / test gates
- `cargo build --features real-dht-e2e --tests` — clean (4.37s)
- `cargo build` (no features) — clean
- `cargo build --features mock` — clean
- `cargo test --features mock` — 311 passed / 0 failed / 19 ignored (matches Plan 09-01 baseline exactly)
- `cargo test` (no features) — 238 passed / 0 failed / 10 ignored
- `cargo fmt --check` — clean
- `cargo clippy --features real-dht-e2e --tests --no-deps` — zero warnings reference `tests/real_dht_e2e.rs`; pre-existing `uninlined_format_args` lints (build.rs + various src/* sites) inherit Plan 09-01's deferred-items disposition

### Done-criteria greps
- `grep -nE '^real-dht-e2e = \[\]' Cargo.toml` → 1 match (line 25) — feature added ✓
- `grep -nE 'name = "real_dht_e2e"' Cargo.toml` → 1 match (line 420) — [[test]] entry added ✓
- `grep -nE 'required-features = \["real-dht-e2e"\]' Cargo.toml` → 1 match (line 422) ✓
- `grep -n "terminate-after" .config/nextest.toml` → 1 match (line 17) ✓
- `grep -n '#!\[cfg(feature = "real-dht-e2e")\]' tests/real_dht_e2e.rs` → 1 match (line 39) ✓
- `grep -cE '#\[ignore\]' tests/real_dht_e2e.rs` → 2 (1 attribute + 1 doc reference; ≥1 required) ✓
- `grep -cE '#\[serial\]' tests/real_dht_e2e.rs` → 3 (1 attribute + 2 doc references; ≥1 required) ✓
- `grep -nE 'router\.bittorrent\.com:6881' tests/real_dht_e2e.rs` → 2 matches ✓
- `grep -n 'real-dht-e2e: UDP unreachable; test skipped (not counted as pass)' tests/real_dht_e2e.rs` → 1 match (line 98) ✓
- `grep -cE 'Duration::from_secs\(120\)' tests/real_dht_e2e.rs` → 3 (≥1 required) ✓
- `grep -cE '\[1u64, 2, 4, 8, 16, 32, 64\]' tests/real_dht_e2e.rs` → 1 (≥1 required) ✓
- `grep -cE 'tokio' tests/real_dht_e2e.rs` → 0 ✓ (CLAUDE.md no-async-runtime constraint)
- `grep -c '#\[test\]' tests/real_dht_e2e.rs` → 1 ✓ (single test only — D-P9-D1)
- `grep -c 'DhtTransport::new' tests/real_dht_e2e.rs` → 4 (≥2 required for Alice + Bob) ✓
- `grep -cE 'Box::new\(AutoConfirmPrompter\)' tests/real_dht_e2e.rs` → 1 (≥1 required; Fix #1 from key constraints) ✓
- `grep -cE 'AutoConfirmPrompter::new' tests/real_dht_e2e.rs` → 0 ✓ (the unit struct has no constructor function)
- `grep -nE '// NOTE:.*acceptance.*gate' tests/real_dht_e2e.rs` → 1 match (line 170) ✓ (Fix #2 — the NOTE comment block explaining the intentional bypass)
- `grep -cE 'Instant::now\(\) >= deadline' tests/real_dht_e2e.rs` → 4 (≥2 required for BOTH the resolve loop AND the receipt-fetch loop — Fix #4) ✓

## Self-Check: PASSED

All claims verified. Plan 09-02 success criteria met. Ready for orchestrator wave-merge. Plan 09-03 will inherit the artifacts above and document them in `RELEASE-CHECKLIST.md` + `RELEASE-CHECKLIST-v1.1.md` + CLAUDE.md load-bearing additions.
