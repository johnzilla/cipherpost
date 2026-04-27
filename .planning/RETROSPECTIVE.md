# Project Retrospective

*A living document updated after each milestone. Lessons feed forward into future planning.*

## Milestone: v1.0 — Walking Skeleton

**Shipped:** 2026-04-22
**Phases:** 4 | **Plans:** 15 | **Commits:** 117 (19 `feat(` + 12 `fix(`)
**Timeline:** 2026-04-20 → 2026-04-22 (~48 hours wall time, 3 calendar days)
**Code:** 3,543 LOC in `src/` · 6,407 LOC incl. `tests/`
**Tests:** 86 pass under `cargo test --features mock`
**Requirements:** 49/49 v1 requirements validated

### What Was Built

- Fork-and-diverge Rust crate from mothballed `cclink`, vendored crypto/identity/transport/record primitives with exact v1.3.0 pins (`pkarr 5.0.3`, `ed25519-dalek =3.0.0-pre.5`, `age 0.11`).
- End-to-end keyshare round trip: `cipherpost send --self | --share <pubkey>` → PKARR SignedPacket on Mainline DHT → `cipherpost receive` with dual-signature verify + TTL + typed-z32 acceptance → `cipherpost receipts --from <z32>` fetches and verifies a signed receipt the sender can independently confirm.
- Wire format locked byte-for-byte via committed JCS fixtures: `outer_record_signable.bin` (192 bytes) and `receipt_signable.bin` (424 bytes) — any future re-implementer can produce byte-identical signatures.
- The cipherpost delta from cclink: recipient-signed `Receipt` published under recipient's PKARR key via resolve-merge-republish at `_cprcpt-<share_ref>` (no clobber of coexisting TXT records), with tamper-zero-receipts invariant.
- Protocol docs: `SPEC.md` (wire format + flows + exit codes + passphrase contract), `THREAT-MODEL.md` (9 adversary sections with decision-ID citations), `SECURITY.md` (live-tested GHSA disclosure channel + 90-day embargo).
- Full CI: `fmt`, `clippy -D warnings`, `nextest`, `audit`, `deny check`, `lychee` link-check — all green.

### What Worked

- **Research-heavy phase 0.** Spending the first plan on `research/PITFALLS.md`, `research/SUMMARY.md`, and the 15 skeleton-lock-in decisions meant every phase had explicit guard rails. No re-litigation of HKDF info strings, canonical-JSON choice, Argon2 param storage, or zeroize discipline during execution.
- **Lock wire format in Phase 1.** Committing `OuterRecordSignable` JCS fixture bytes before Phase 2 opened receive/send meant any byte-drift in later phases surfaced as a red test in CI immediately — impossible to paper over.
- **MockTransport as architectural delta.** A `Transport` trait + cfg-gated MockTransport was the cheapest single change that unlocked the full E2E test suite (86 tests, including SC1 tamper-zero-receipts) without ever touching Mainline DHT. Phase 3's tricky resolve-merge-republish semantics were provable in tests because the mock could inspect the published SignedPacket directly.
- **Coarse granularity (4 phases).** Each phase ended at a user-visible capability. Resisted the impulse to split "send" and "receive" into separate phases — they share state (sentinel + ledger) and had to land together or the seam calcifies wrong.
- **UAT-driven fixes.** The two interactive UAT tests found real issues (single-prompt passphrase footgun + double-UTC suffix in receipt render). Both were quick fixes (`2e29b74`, `e95c95e`) but would have been bugs in the wild. UAT was worth the overhead.
- **Atomic commits per plan.** `feat(01-02):`, `feat(01-03):`, etc. made the failure history readable and rollback trivial. `/gsd-undo` was never needed but the option was cheap.

### What Was Inefficient

- **Traceability table drift.** 29 requirement rows stayed at "Pending" in the body table through Phase 2+ even though checkboxes were checked and phase VERIFICATION reports confirmed implementation. The double-bookkeeping (body checkboxes + traceability table) meant one lagged the other. Next milestone: single source of truth, or automate traceability updates from body checkboxes.
- **`one_liner` SUMMARY.md frontmatter was inconsistent.** The milestone-complete CLI extractor pulled literal "One-liner:" placeholder strings from 11 of 15 SUMMARY files at close; I had to manually rewrite MILESTONES.md with the approved five-bullet summary. Fix at source: `gsd-planner` / `gsd-executor` should enforce a `one_liner:` key in SUMMARY frontmatter.
- **Phase 1 crate-pin drift.** Planned pins were `serde_canonical_json 0.2`, `pkarr 5.0.3`, 600-byte PKARR budget. Reality: 1.0.0 (unavailable on crates.io at 0.2; same API), 5.0.4 (transitive), 550 bytes (worst-case `OuterRecord` forced tightening). All documented, functionally correct, but should have been verified at plan time with `cargo search` before locking into REQUIREMENTS.md.
- **Three "cleanup" commits before `/gsd-complete-milestone`.** Bookkeeping debt accumulated (`e89fd41`, `08bd78b`, `a56d1d9`) that could have been done in-line during Phase 4 — or better, not accumulated in the first place.
- **Deferred real-DHT test.** The two-identity cross-process DHT round trip never ran. MockTransport exercised every code path but can't prove the packet actually propagates over Mainline. This is documented tech debt and belongs in a release-acceptance test for the next milestone.

### Patterns Established

- **Confirm-passphrase on key-creation paths only.** `resolve_passphrase(confirm_on_tty: bool)` — `true` on `identity generate`, `false` on unlock paths (`show`/`send`/`receive`) where a typo surfaces as `PassphraseIncorrect` against the existing identity. Codify in future crypto modules.
- **Tamper-zero-X invariants.** Any cryptographically-attested artifact (receipt, signed acknowledgement, etc.) must only be published strictly after full verification succeeds. Enforce by ordering in code + a dedicated integration test that flips bytes and asserts zero publications. This generalizes past receipts.
- **Resolve-merge-republish for any PKARR key that holds multiple record types.** Don't overwrite. Read existing packet, merge new TXT record, republish with `cas`. Generalizes to any future DHT-resident record type (destruction attestation, multi-recipient manifests).
- **Typed-z32 acceptance, not y/N.** Full-string confirmation forces the user to read the sender's z-base-32 fingerprint off the acceptance banner, making prompt-fatigue mis-acceptance meaningfully harder. Apply to any future "dangerous" confirmation (e.g., destruction trigger).
- **Unified signature-failure Display.** All signature-verification errors must Display-format identically to avoid distinguishable-oracle attacks (PITFALLS #16). Enforce with a single `thiserror` enum + a test that enumerates variants and asserts identical user-facing strings.
- **`serial_test` for env-mutating tests.** `CIPHERPOST_HOME` racing under nextest parallel runner cost half a session to diagnose. Any test that touches process env should carry `#[serial]`.

### Key Lessons

1. **Lock the wire format in the first phase, with a committed fixture.** Any phase that reads/writes a signed payload should sign a known-bytes fixture in a committed test file. The cost of freezing early is near-zero; the cost of unfreezing after three phases of dependent signed data is "redesign and re-sign everything."
2. **Coarse phases that end at a user-visible capability beat fine-grained functional phases.** Resist splitting tightly-coupled work. The walking skeleton's 4 phases were each independently demo-able; a 10-phase version would have calcified mid-flow choices mid-seam.
3. **MockTransport before DhtTransport.** The architectural delta (Transport trait) paid for itself on the first E2E test and continued paying through Phase 3's merge-republish verification. Any I/O boundary that will be tested should be trait-fronted and mock-able from plan 1.
4. **UAT on real TTYs finds real bugs.** Two outstanding UAT items at milestone close surfaced two real fixes — a passphrase footgun and a cosmetic render bug. Pretending UAT is optional because "unit tests cover it" is self-deception.
5. **Don't accept "Pending" rows drifting in a traceability table.** Requirements bookkeeping should update atomically with body checkboxes, or not exist in parallel. Dual representation invites dual drift.
6. **Every signed artifact needs a tamper-zero test.** Byte-flip the input, assert no publish. This is the cheapest defense against "we published the wrong thing" bugs, and it generalizes.
7. **Verify external crate versions at plan time, not at first build.** Phase 1's three pin drifts would have been caught with a 30-second `cargo search` pass during planning. Automate this into `/gsd-plan-phase`'s pre-flight checks.

### Cost Observations

- **Model profile:** `balanced` (`.planning/config.json`) — Opus for planning/research/discuss, Sonnet for most execution, Haiku rarely.
- **Sessions:** Estimated 8–12 distinct sessions across the 3 calendar days (plan + execute + verify per phase, plus milestone-close bookkeeping).
- **Notable efficiency:** The JCS-fixture lock-in in Phase 1 prevented rework across 3 downstream phases. One 30-minute commit in Plan 01-03 probably saved ~6–8 hours of sig-regression chasing later.
- **Notable waste:** The one_liner frontmatter inconsistency + the 29 stale traceability rows + the three cleanup commits pre-close represent ~1–2 hours of bookkeeping debt. Fixable by automation, not effort.

---

## Milestone: v1.1 — Real v1

**Shipped:** 2026-04-26
**Phases:** 5 (Phases 5–9) | **Plans:** 24 | **Commits:** 180 in milestone range
**Timeline:** 2026-04-23 → 2026-04-26 (~3.5 calendar days)
**Code:** +9,788 / -451 across 81 files; src/ now 14 files / 6,627 LOC; tests/ now 68 files / 8,798 LOC
**Tests:** 311 pass / 0 fail / 19 ignored under `cargo test --features mock` (vs. 86 at v1.0 close)
**Requirements:** 67/67 v1.1 requirements validated (PASS×9, DOC×4, X509×9, PGP×9, SSH×10, PIN×10, BURN×9, DHT×7)

### What Was Built

- Non-interactive automation E2E (Phase 5): `--passphrase-file`/`--passphrase-fd` on `send` and `receive`; argv-inline `--passphrase` rejected uniform with identity subcommands; PASS-09 CI integration test proves scripted send/receive without TTY.
- Three typed payload variants — X.509 cert, PGP key, SSH key — with **pattern-establish-then-apply** discipline (Phases 6–7). Phase 6 set the Material module conventions, per-variant size checks, JCS fixture discipline, Debug redaction rule, and CLI flag shape; Phase 7 mechanically applied the pattern twice. Three new JCS fixtures (X509 626 B, PGP, SSH) committed and byte-locked.
- `--pin` and `--burn` encryption modes orthogonal to all four Material variants (Phase 8). PIN crypto = cclink-fork-with-divergence (Argon2id+HKDF→X25519→age — preserves load-bearing "no direct chacha20poly1305" rule). Burn = single-consumption with state-ledger inversion via emit-before-mark (D-P8-12). 23-test pin × burn × {variant} compose matrix proves orthogonality; v1.0 byte-identity preserved via `is_false` skip-serializing-if; new fixtures `outer_record_pin_required_signable.bin` (212 B) + `envelope_burn_signable.bin` (142 B).
- Real-DHT release-acceptance gate + CAS retry-and-merge contract (Phase 9). `tests/cas_racer.rs` Barrier-synced two-thread racer asserts CAS contract under contention. `tests/real_dht_e2e.rs` cross-identity round-trip behind triple-gate `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`; CI never enables the feature; `RELEASE-CHECKLIST.md` (91 lines / 29 checkboxes) documents the manual gate. CLAUDE.md +3 load-bearing lock-ins.
- Solo-builder hygiene held: zero "Pending" rows survive into v1.1 archive. Inline phase-tag traceability (DOC-03) canonical; 3-source cross-reference (REQUIREMENTS + VERIFICATION + SUMMARY) clean.

### What Worked

- **Pattern-establish-then-apply across Phases 6 → 7.** Phase 6 deliberately scoped at one Material variant (`X509Cert`) so that fixture discipline, error-oracle enumeration, leak-scan extension, dep-tree guard, and SPEC.md-update rhythm could be locked in cheap. Phase 7 then shipped two more variants (`PgpKey`, `SshKey`) in 8 plans across two parallel waves with mechanical pattern-application. The cost of getting the first variant right paid for itself across the next two — and would pay forward for any future variant.
- **Coarse phase granularity held under pressure.** Phase 7 was 19 requirements across two crates (rPGP + ssh-key) and was tempting to split. Resisted; kept as one phase ending at "user can hand off PGP or SSH key end-to-end." The wire-budget #[ignore] pattern carried forward (D-P7-03 inheritance from D-P6) without re-litigation.
- **Compose matrix as architectural truth-test (Phase 8 Plan 05).** A 752-line / 23-test pin × burn × {GenericSecret, X509Cert, PgpKey, SshKey} matrix forced explicit orthogonality. Two negative-path safety tests (wrong-PIN-on-burn and typed-z32-declined-on-burn don't mark burned) caught a subtle ordering invariant that wouldn't have surfaced in unit tests.
- **Tamper-zero invariants generalized cleanly.** v1.0's tamper-zero-receipts pattern (publish strictly after verify+accept) generalized to Phase 8's emit-before-mark contract for burn (D-P8-12). The pattern — "any irreversible action must be ordered strictly after full verification" — is now reusable for future destruction attestation work.
- **Single-retry-then-fail CAS contract inside the trait (Phase 9).** Putting the retry inside `Transport::publish_receipt` rather than at the call site meant `MockTransport` and `DhtTransport` mirror identical two-attempt structure, the caller never sees `CasConflict`, and `Error::CasConflict` doesn't need to exist as a public variant (Pitfall #16 hygiene preserved). One architectural choice, three downstream simplifications.
- **Triple-gate discipline for Real-DHT (D-P9-D2 + Pitfall #29).** `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` + nextest slow-timeout outer guard means the test exists, compiles, and is properly gated, but cannot accidentally run in CI. The release execution is a process step (RELEASE-CHECKLIST), not a CI gate. Belt-and-suspenders is correct here — a single missing guard would brick CI on UDP-restricted networks.
- **DOC-03 (inline phase tags as canonical traceability).** The "Pending row" drift class from v1.0 (29 stale rows at close) was eliminated by dropping the parallel traceability table entirely. Phase VERIFICATION.md files are authoritative; checkboxes mirror VERIFICATION; no double-bookkeeping. At v1.1 close, all 67 reqs ticked atomically — zero drift.

### What Was Inefficient

- **Stale `09/deferred-items.md` claim.** Phase 9 plan-1 documented the `build.rs:17` `uninlined_format_args` lint as "the" lint to defer. Reality: 65+ instances exist across `src/` + `tests/` under clippy 1.88; CI's clippy 1.85 doesn't catch them. The deferred-items doc was wrong about scope. CI was green only because of the toolchain divergence, not because the lints were absent. Caught at milestone-close pre-flight; one-line `build.rs:17` fix shipped, rest deferred to v1.2 maintenance pass. **Lesson:** when a deferred-items doc claims "pre-existing" or "out-of-scope," verify the scope claim with a `cargo clippy --all-targets --all-features` pass, not just the specific file's lint.
- **Toolchain pin drift between `rust-toolchain.toml` (1.88) and `.github/workflows/ci.yml` (`dtolnay/rust-toolchain@1.85`).** Discovered at milestone close. CI is the source-of-truth release gate, but local-1.88 fails clippy gates that 1.85 silently passes. CLAUDE.md MSRV-1.85 statement still authoritative. **Lesson:** pin drift between local toolchain and CI is itself a class of drift. Future-Phase-1 should add a CI workflow that validates `rust-toolchain.toml` matches the CI clippy pin.
- **Phase 6 wire-budget discovery at Plan 04 execution.** The 1000-byte BEP44 ceiling was not surfaced until Plan 04 ran round-trip tests with a realistic cert. Should have been caught at Phase 6 plan-time research — `cargo run --features mock -- send` with a 1KB synthetic payload would have surfaced it. The deferral pattern (Option A — `#[ignore]` + clean-error-path pin) is correct, but the discovery point was too late. **Lesson:** for any phase that ships new wire-format content, plan-time research must include a back-of-envelope packet-size estimate against PKARR's 1000-byte BEP44 ceiling.
- **Phase 6 `human_needed` lingered through Phases 7–8.** WR-01 PEM-trailing-bytes was fixed in commit `a12d6ec` shortly after Phase 6 close, but `06-VERIFICATION.md` status stayed `human_needed` until milestone-close re-verification. The verification status should have flipped at the time of fix. **Lesson:** when a verification-flagged code defect is fixed in a later commit, re-run the phase verifier (or at minimum update the VERIFICATION.md status) at that commit, not at milestone close.
- **Local-only commits.** All 180 v1.1 commits were never pushed to `origin/main`. CI ran on the v1.0 close and the decoy-cleanup commits but never validated Phase 5–9 work. This means the "CI is green" claim relies on local `cargo test --features mock` runs only. **Lesson:** push to `origin/main` (or a feature branch with branch-protection-bypassing CI) regularly during milestone work, not just at milestone close. The cost of catching a CI-only failure at close is a cleanup commit; the cost of catching mid-milestone is a one-line edit.

### Patterns Established

- **Pattern-establish-then-apply cadence.** Pick the variant with the most distinguishing structure (X.509 — DN, validity dates, OID-keyed algorithm dispatch, ASN.1-vs-PEM duality), nail it in one phase, then mechanically apply across the rest. Generalizes to any future Material expansion (PGP v6 keys, post-quantum keys, etc.) and to any other one-of-many design surface.
- **Wire-budget escape-hatch deferral pattern (D-P7-03 / Option A).** When a phase delivers a feature that exceeds the PKARR BEP44 ceiling for realistic inputs: (1) ship the feature library/CLI-complete; (2) `#[ignore]` round-trip tests with explicit wire-budget notes; (3) ship a positive `Error::WireBudgetExceeded` clean-surface test; (4) document in SPEC.md as a Pitfall; (5) consolidate into a single multi-phase escape-hatch decision deferred to a future milestone. Avoids cascading deferrals across phases.
- **Compose matrix as orthogonality proof.** When two orthogonal flags (`--pin`, `--burn`) are introduced over an existing variant axis (`{Generic, X509, PGP, SSH}`), the compose matrix is N×M tests that prove pairwise orthogonality. Macros split between strict (sub-budget happy path) and lenient (gracefully surfaces wire-budget) paths reduce per-test boilerplate. Pattern reusable for any future flag expansion.
- **Single-retry-then-fail CAS, retry inside trait method.** When mocking a CAS-protected operation: (1) put the retry loop inside the trait method, not at the call site; (2) collapse final-conflict failures into the existing transport-error variant (no new public `CasConflict`); (3) the mock and real impl mirror identical retry structure; (4) error-oracle hygiene preserved.
- **Triple-gate discipline for tests requiring real I/O.** `#[cfg(feature = "...")]` + `#[ignore]` + `#[serial]` + nextest slow-timeout outer guard. CI never enables the feature; manual operator runs via documented checklist. Belt-and-suspenders is correct here — a single missing guard would break CI on restricted networks.
- **Schema migration via Option<&str> with conservative default mapping.** State-ledger evolution (`LedgerEntry.state` from v1.0's implicit `accepted` to v1.1's typed `{None, Accepted, Burned}`): wire field is `Option<&str>` (open-set string for external tooling); typed `LedgerState` is a runtime abstraction. v1.0 rows missing the field deserialize via serde default to `None` and map CONSERVATIVELY to `Accepted` — never silently classify Accepted as Burned (T-08-17). Generalizes to any future protocol-additive schema migration.
- **cclink fork-with-divergence pattern.** When forking primitives from an upstream, divergence boundaries should be explicit: HKDF info namespace adapted (cclink-pin-v1 → `cipherpost/v1/pin`); AEAD mechanism preserved (no direct chacha20poly1305 — stays inside age); architectural envelope preserved (Argon2id+HKDF→X25519→age `Identity`). Documented via per-divergence cargo-tree evidence. Reusable for any future cclink primitive port.

### Key Lessons

1. **Pattern-establish-then-apply works.** Phase 6 paid the variant-introduction cost once; Phase 7 shipped two more variants in 8 plans with the pattern intact. Resist scoping multiple variants in a single establish phase.
2. **Toolchain pins must match between rust-toolchain.toml and CI.** CI is the source-of-truth release gate, so the local toolchain MUST be at-or-stricter than CI. If `rust-toolchain.toml` is stricter (1.88 vs CI 1.85), local fails surface lints CI doesn't catch — meaning the lint-fix work is real but the CI-failure framing is wrong. Reconcile early.
3. **Verify deferred-item scope claims with a clean reproduction.** A deferred-items doc that names one specific instance ("`build.rs:17`") needs the broader scope check (`cargo clippy --all-targets --all-features`) to confirm it's the only instance. If the doc claims "pre-existing on commit X," reverting to commit X and reproducing is cheap insurance.
4. **Re-run phase verifiers when defects are fixed in later commits.** WR-01 was fixed shortly after Phase 6 close but `06-VERIFICATION.md` carried `human_needed` until milestone-close re-verification. Status drift is invisible until you go to close.
5. **Wire-format byte-budget research belongs at plan time.** The 1000-byte PKARR BEP44 ceiling was not surfaced until Phase 6 Plan 04 round-trip tests. A 30-second back-of-envelope at plan time would have flagged it.
6. **Push to origin regularly — don't accumulate 180 local commits before milestone close.** CI hasn't validated any v1.1 work; "CI is green" is a local-test claim. Future milestones: push at every phase-close at minimum.
7. **Inline phase-tag traceability (DOC-03) eliminates dual-bookkeeping drift.** The "Pending row" drift class that hit v1.0 (29 stale rows) is gone in v1.1. One canonical source (phase VERIFICATION.md), one mirror (REQUIREMENTS.md inline tags + checkboxes), updated atomically at close. Rule held.
8. **Tamper-zero invariants generalize.** v1.0's "publish receipt strictly after verify+accept" is the same shape as v1.1's "emit decrypted bytes strictly before ledger-mark" (D-P8-12) — both are "any irreversible action must be ordered strictly after a verification gate." Generalizes to future destruction attestation, multi-recipient broadcast, etc.
9. **Triple-gate is the correct discipline for real-network tests.** `#[cfg]` + `#[ignore]` + `#[serial]` + nextest profile slow-timeout. Anything less, and a future contributor will accidentally run it in CI on a restricted network.

### Cost Observations

- **Model profile:** `balanced` (`.planning/config.json` unchanged from v1.0) — Opus for planning/research/discuss, Sonnet for most execution, Haiku rarely.
- **Sessions:** Estimated 12–18 distinct sessions across 3.5 calendar days (5 phases × ~3 sessions per phase: discuss/plan/execute, plus milestone-close bookkeeping).
- **Notable efficiency:** Pattern-establish-then-apply across Phases 6 → 7 saved ~6–8 hours of pattern-rediscovery. The compose matrix in Phase 8 Plan 05 (752 lines / 23 tests) caught two orthogonality bugs in ~2 hours that would have cost days post-ship.
- **Notable waste:** The toolchain pin drift discovered at milestone close cost ~1 hour to triage and recommend a path forward (Option 3: accept divergence, defer reconciliation). Should have been caught at Phase 5 plan time when CLAUDE.md was being updated. The stale `09/deferred-items.md` claim about `build.rs:17` cost another ~30 minutes of misdirected scope estimation. Both fixable by automation: a CI workflow that validates `rust-toolchain.toml` matches CI's clippy pin would have caught the divergence at the moment it was introduced.

---

## Cross-Milestone Trends

### Process Evolution

| Milestone | Sessions | Phases | Plans | Key Change |
|-----------|----------|--------|-------|------------|
| v1.0 Walking Skeleton | ~10 | 4 | 15 | Baseline: research-heavy Phase 0, coarse 4-phase granularity, MockTransport as architectural delta, wire format JCS-locked in Phase 1. |
| v1.1 Real v1 | ~12–18 | 5 | 24 | Pattern-establish-then-apply across Phases 6→7 (X509 → PGP+SSH); compose matrix as orthogonality proof (Phase 8); triple-gate for real-network tests (Phase 9); inline phase-tag traceability (DOC-03) eliminates "Pending row" drift class from v1.0. |

### Cumulative Quality

| Milestone | Tests | Files (src+tests) | LOC (src+tests) | Requirements validated |
|-----------|-------|-------------------|-----------------|------------------------|
| v1.0 Walking Skeleton | 86 | 46 | 6,407 | 49/49 |
| v1.1 Real v1 | 311 | 82 | 15,425 | 67/67 (cumulative: 116/116) |

### Top Lessons (Verified Across Milestones)

1. **Wire-format JCS-lock-in early prevents downstream signature-regression chasing.** v1.0 locked OuterRecord + Receipt fixtures in Phase 1; v1.1 locked X509/PGP/SSH/PIN/BURN fixtures at each shipping phase. Both milestones held byte-identity across all subsequent code changes — zero re-sign events.
2. **Coarse phase granularity scales.** v1.0 (4 phases) and v1.1 (5 phases) both held the rule that every phase ends at a user-visible capability. v1.1's 5 phases were each independently demo-able. No phase was housekeeping-only.
3. **MockTransport pays for itself across milestones.** v1.0 ran 86 tests under `--features mock`; v1.1 ran 311 (3.6×), all without touching Mainline DHT. Phase 9's CAS racer test would have been impossible to write deterministically without MockTransport's per-key seq abstraction.
4. **UAT (verify-work / human_verification) finds real bugs.** v1.0: passphrase footgun + double-UTC suffix (2 fixes from interactive UAT). v1.1: WR-01 PEM trailing-bytes (caught by code-review at Phase 6 close, fixed in `a12d6ec`). Pretending UAT/code-review is optional because "unit tests cover it" is consistently wrong.
5. **Tamper-zero invariants generalize.** v1.0: tamper-zero-receipts (publish strictly after verify+accept). v1.1: emit-before-mark for burn (D-P8-12, opposite ordering for opposite atomicity contract). Same underlying principle — "any irreversible action must be ordered strictly after a verification gate" — applies across milestones.
6. **Solo-builder hygiene degrades silently.** v1.0 left 29 "Pending" rows in REQUIREMENTS.md traceability at close (caught at audit). v1.1's DOC-03 (inline phase tags as canonical) eliminated the class entirely — at v1.1 close, all 67 reqs ticked atomically. Drift-class fixes generalize: when bookkeeping has two parallel representations, drift is inevitable. Drop one.
7. **Verify external pin/version claims at plan time, not first build.** v1.0 had three crate-pin drifts (caught at Cargo.lock resolution); v1.1 had one (x509-parser → time 0.3.47 → rustc 1.88, caught by `cargo build`). Both shipped, but a 30-second `cargo search` pass at plan time would have prevented all four.
