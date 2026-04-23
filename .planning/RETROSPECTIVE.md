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

## Cross-Milestone Trends

*(First milestone — cross-milestone trends will populate as more milestones ship.)*

### Process Evolution

| Milestone | Sessions | Phases | Key Change |
|-----------|----------|--------|------------|
| v1.0 Walking Skeleton | ~10 | 4 | Baseline: research-heavy Phase 0, coarse 4-phase granularity, MockTransport as architectural delta, wire format JCS-locked in Phase 1. |

### Cumulative Quality

| Milestone | Tests | Files (src+tests) | LOC |
|-----------|-------|-------------------|-----|
| v1.0 Walking Skeleton | 86 | 46 | 6,407 |

### Top Lessons (Verified Across Milestones)

*Will populate after v1.1+ ships and lessons can be cross-validated.*
