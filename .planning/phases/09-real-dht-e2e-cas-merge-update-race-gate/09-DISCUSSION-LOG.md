# Phase 9: Real-DHT E2E + CAS merge-update race gate - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in 09-CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-26
**Phase:** 09-real-dht-e2e-cas-merge-update-race-gate
**Areas discussed:** CAS retry-and-merge contract, Real-DHT bootstrap config, RELEASE-CHECKLIST.md scope, Real-DHT test scope

---

## Area selection

| Option | Description | Selected |
|--------|-------------|----------|
| CAS retry-and-merge contract | DHT-02 says loser "retries-and-merges" but specifies neither retry count nor backoff. Affects MockTransport semantics AND DhtTransport real-DHT contention behavior. | ✓ |
| Real-DHT bootstrap config | STATE.md flagged this as Phase 9 plan-time open question. pkarr defaults bootstrap to public Mainline; should cipherpost expose CIPHERPOST_DHT_BOOTSTRAP, or hard-code defaults for v1.1? | ✓ |
| RELEASE-CHECKLIST.md scope | DHT-06 puts a checklist at repo root that gates every v1.1+ release. How comprehensive? | ✓ |
| Real-DHT test scope | Strictly cross-identity round trip, OR also include a concurrent-receipt-publish race over real DHT? | ✓ |

**User's choice:** All four selected.
**Notes:** None — user wanted full discussion of all gray areas.

---

## CAS retry-and-merge contract

### Q: How aggressive should CAS retry be on receipt publish contention?

| Option | Description | Selected |
|--------|-------------|----------|
| Single retry then fail | On CasConflict: resolve once, merge, republish once. Second conflict surfaces as Error to caller. Recommended. | ✓ |
| 3 retries, exp backoff | 50ms → 200ms → 800ms with full resolve-merge between each. Absorbs typical contention without user intervention. | |
| Bounded retry within deadline | Wall-clock budget (e.g., 5s); unlimited attempts within window; fail at deadline. | |

**User's choice:** Single retry then fail.
**Notes:** Receipt publish is rare-conflict territory; explicit failure is clearer than silent retry storms.

### Q: Where does the retry loop live?

| Option | Description | Selected |
|--------|-------------|----------|
| Inside Transport trait method | publish_receipt() internally retries; caller sees Ok(()) or final Err. CasConflict never escapes the trait. | ✓ |
| In caller (flow.rs) | Transport returns Err(CasConflict) on each conflict; run_receive does the explicit retry-and-merge. | |
| Hybrid | Transport surfaces CasConflict; a single retry_with_merge() helper in flow.rs wraps the call. | |

**User's choice:** Inside Transport trait method.
**Notes:** Encapsulates retry logic in one place; both DhtTransport and MockTransport implement the same retry contract.

### Q: How does MockTransport model CAS deterministically for the racer test?

| Option | Description | Selected |
|--------|-------------|----------|
| Per-key sequence number | MockTransport stores u64 seq per pubkey. Mismatch returns CasConflict. Matches pkarr::Timestamp semantics. | ✓ |
| Explicit conflict hook | Mock has a test-only inject_conflict_once() method; less faithful to real semantics. | |
| Always require cas | Mock requires cas: Option<Timestamp> matching the existing packet, never accepts None on existing keys. | |

**User's choice:** Per-key sequence number.
**Notes:** Most faithful to real cas semantics; racer test exercises the same code path as production.

### Q: Should DhtTransport log CAS retry events to stderr?

| Option | Description | Selected |
|--------|-------------|----------|
| Silent on success | Successful retry is transparent; only final failure surfaces. | |
| One line per retry | "Receipt publish: CAS conflict on attempt N, retrying..." on stderr. | |
| Only when CIPHERPOST_DEBUG=1 | Default silent; opt-in verbosity via env var. | ✓ |

**User's choice:** Only when CIPHERPOST_DEBUG=1.
**Notes:** Keeps default UX clean while preserving debuggability for users investigating slow publishes.

---

## Real-DHT bootstrap config

### Q: Should CIPHERPOST_DHT_BOOTSTRAP env be exposed in v1.1?

| Option | Description | Selected |
|--------|-------------|----------|
| Hidden testing override | Env var read by DhtTransport but NOT documented in --help. Mentioned in SPEC.md and tests/ only. | |
| First-class user flag | Either CIPHERPOST_DHT_BOOTSTRAP env or --bootstrap CLI flag, in --help, with a caveat. | |
| Defaults only for v1.1 | pkarr defaults; no override mechanism. Smallest surface; revisit if anyone asks. | ✓ |

**User's choice:** Defaults only for v1.1.
**Notes:** Closes STATE.md open question by deferring. Smallest surface; ship-narrow discipline holds.

### Q: If override exposed: bootstrap precedence relative to pkarr defaults?

| Option | Description | Selected |
|--------|-------------|----------|
| Override replaces defaults | Env present → use ONLY the env-listed bootstrap nodes. | |
| Override appends to defaults | Env-listed nodes added to pkarr defaults. | |
| N/A (defaults-only chosen above) | Skip if Q1 was "Defaults only for v1.1". | ✓ |

**User's choice:** N/A.

### Q: If override exposed: validation strictness?

| Option | Description | Selected |
|--------|-------------|----------|
| Strict format check | Comma-separated host:port pairs; cipherpost validates each; reject invalid with Error::Config. | |
| Lenient passthrough | cipherpost passes raw env value to pkarr ClientBuilder. | |
| N/A (defaults-only chosen above) | Skip. | ✓ |

**User's choice:** N/A.

### Q: Where to document the bootstrap mechanism?

| Option | Description | Selected |
|--------|-------------|----------|
| SPEC.md §Bootstrap + RELEASE-CHECKLIST | New SPEC.md section + RELEASE-CHECKLIST.md gate item. | |
| README + SPEC inline | Brief README mention; SPEC inline reference. | ✓ |
| Source comment + tests only | Undocumented for v1.1. | |

**User's choice:** README + SPEC inline.
**Notes:** Even though there's no override, document that v1.1 uses pkarr defaults only — sets the expectation that future milestones may expose an override if demand surfaces.

---

## RELEASE-CHECKLIST.md scope

### Q: How comprehensive should RELEASE-CHECKLIST.md be?

| Option | Description | Selected |
|--------|-------------|----------|
| Standard ship gate | Real-DHT + cargo test + clippy + audit + lychee + fixture byte-counts + RUSTSEC review (~80 lines). Recommended. | ✓ |
| Bare minimum | Real-DHT command + expected output + manual pass/fail tick (~30 lines). | |
| Full ship gate | Standard + CHANGELOG + version-bump + git-tag + release-notes template + crate publish dry-run (~150 lines). | |

**User's choice:** Standard ship gate.
**Notes:** Matches v1.0 close discipline; nothing surprising. Codifies what cipherpost already runs in CI plus the manual real-DHT step.

### Q: Where does RELEASE-CHECKLIST.md live?

| Option | Description | Selected |
|--------|-------------|----------|
| Repo root | /RELEASE-CHECKLIST.md. Per DHT-06 wording verbatim. | ✓ |
| /docs/ | /docs/RELEASE-CHECKLIST.md. Reduces root noise. | |
| /.planning/ | /.planning/RELEASE-CHECKLIST.md. Conflicts with "gates every v1.1+ release" framing. | |

**User's choice:** Repo root.
**Notes:** Matches v1.0 top-level docs convention.

### Q: Format style?

| Option | Description | Selected |
|--------|-------------|----------|
| Markdown checklist with [ ]/[x] | Per-step checkbox; releaser copies-and-ticks. | ✓ |
| Numbered procedure | Each step has explicit pass/fail criteria. | |
| Hybrid | Top section is checklist; bottom is reference. | |

**User's choice:** Markdown checklist with [ ]/[x].
**Notes:** Familiar; pairs naturally with git commits showing the ticked file.

### Q: Lifecycle across releases?

| Option | Description | Selected |
|--------|-------------|----------|
| Living document | Every release amends the same file with new findings. | |
| Versioned snapshot | Per-release immutable snapshot: RELEASE-CHECKLIST-v1.1.md, RELEASE-CHECKLIST-v1.2.md, etc. Living template at RELEASE-CHECKLIST.md. | ✓ |
| Living + tagged in git | Single living document; per-release ticked version captured by git tag. | |

**User's choice:** Versioned snapshot.
**Notes:** Preserves historical release evidence even as the template evolves.

---

## Real-DHT test scope

### Q: What's the real-DHT test surface for v1.1?

| Option | Description | Selected |
|--------|-------------|----------|
| Cross-identity round trip only | Single test matching DHT-04 verbatim. | ✓ |
| Round trip + concurrent receipt race | Adds a real-DHT CAS racer; doubles runtime; higher flake risk. | |
| Round trip + UDP-skip + bootstrap-default | Three tests covering full network-class surface. | |

**User's choice:** Cross-identity round trip only.
**Notes:** Strictest interpretation of REQs; lowest CI flake risk; minimum viable proof. CAS racer stays MockTransport-only per DHT-02.

### Q: How many real-DHT tests in CI per job?

| Option | Description | Selected |
|--------|-------------|----------|
| Zero — manual only | Real-DHT tests behind feature flag; CI never runs them. | ✓ |
| One (cross-identity round trip) | Nightly or pre-release CI job runs the round trip. | |
| Pitfall 29 hard cap | Max one real-DHT test per CI job; if more added, each gets its own job. | |

**User's choice:** Zero — manual only.
**Notes:** RELEASE-CHECKLIST manual run is the only gate. No CI flake risk. Matches Pitfall 29 strict reading.

### Q: 120s timeout enforcement mechanism?

| Option | Description | Selected |
|--------|-------------|----------|
| In-test deadline | Test reads std::time::Instant; the resolve-with-exp-backoff loop bails at 120s. | |
| cargo --test-timeout flag | Rely on cargo's --test-timeout 120 at invocation. | |
| Both — belt and suspenders | In-test deadline (primary) + cargo flag (outer guard). | ✓ |

**User's choice:** Both — belt and suspenders.
**Notes:** Catches developer-machine misuse and CI invocation drift. Tiny extra code.

### Q: Test crate location and #[serial] discipline?

| Option | Description | Selected |
|--------|-------------|----------|
| tests/real_dht_e2e.rs single file | All real-DHT tests in one file; cfg-gated. | ✓ |
| tests/real_dht/ subdirectory | Subdirectory for multi-file expansion. | |
| Inline in existing tests/ | Add to existing test files with cfg-gating. | |

**User's choice:** tests/real_dht_e2e.rs single file.
**Notes:** Mirrors v1.0 single-purpose-test-file convention. Easy to find.

---

## Wrap-up

### Q: Anything still unclear before writing CONTEXT.md?

| Option | Description | Selected |
|--------|-------------|----------|
| Ready for context | Decisions are clear; write CONTEXT.md. | ✓ |
| Plan structure | Discuss how the work splits into plans before writing context. | |
| DHT-07 wire-budget test | Discuss the pin+burn+pgp ~2KB clean-error test specifically. | |
| Error taxonomy | Discuss whether CasConflict gets its own Error variant. | |

**User's choice:** Ready for context.
**Notes:** Plan structure deferred to /gsd-plan-phase 9; the planner picks 3 plans (recommended) or 4 plans based on actual code-touch surface. DHT-07 details and error taxonomy captured as planner notes in 09-CONTEXT.md "Claude's Discretion" section.

---

## Claude's Discretion

- Whether `CasConflict` becomes a named internal variant or stays as a sentinel returned by a private helper.
- Exact exponential-backoff curve for the real-DHT resolve loop (1s, 2s, 4s, 8s, 16s, 32s, 64s recommended).
- UDP pre-flight technique (low-level UdpSocket connect with 5s timeout recommended).
- Whether RELEASE-CHECKLIST-v1.1.md is committed at Phase 9 close or at v1.1 release tag time.
- Whether the bootstrap mention in README is in a new section or a single sentence.
- Whether CIPHERPOST_DEBUG becomes multi-purpose or stays narrowly scoped to CAS retry events.
- Plan structure (3 plans recommended, 4 acceptable, 2 too tight).
- DHT-07 test fixture choice (synthesized 2KB byte vector recommended over Phase 7 PGP fixture).

## Deferred Ideas

- CIPHERPOST_DHT_BOOTSTRAP env override / --bootstrap flag — v1.2+ if requested
- Multi-retry CAS schemes — revisit if real-world contention surfaces
- CAS racer over real DHT — separate phase if pursued
- Multi-test real-DHT suite — future milestone
- Real-DHT tests in nightly CI — when nightly job is added
- Public Error::CasConflict variant — absorbed inside transport's single-retry
- Multi-purpose CIPHERPOST_DEBUG — broaden in v1.2 if more debug-worthy paths surface
- Full ship-gate scope — when release pipeline is built
- Wire-budget escape hatch — Phase 6/7 already deferred to v1.2
- Behavior-faithful PKARR simulator — substantial separate effort; defer
