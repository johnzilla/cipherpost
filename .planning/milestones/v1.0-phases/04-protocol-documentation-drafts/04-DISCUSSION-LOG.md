# Phase 4: Protocol documentation drafts - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in `04-CONTEXT.md` — this log preserves the alternatives considered.

**Date:** 2026-04-21
**Phase:** 04-protocol-documentation-drafts
**Areas discussed:** SPEC structure & test vectors, THREAT-MODEL structure, SECURITY.md disclosure logistics, cclink lineage & draft labeling

---

## SPEC structure & test vectors

### Q1: SPEC.md organization style?

| Option | Description | Selected |
|--------|-------------|----------|
| RFC-style with numbered sections | `## 3. Wire Format`, `### 3.1 Envelope`, field tables per struct. Matches security-engineer audience; best for independent re-implementation. | ✓ |
| Prose-first with tables where helpful | Narrative explanation with tables sprinkled in. Easier first read, harder mechanical re-implementation. | |
| Hybrid: numbered TOC + prose per section | Numbered outline for navigation; each section prose-driven. Middle ground. | |

**User's choice:** RFC-style with numbered sections
**Notes:** Recommended option. Aligns with PRD abandonment-resilience goal — an independent re-implementer needs a section-numbered, field-tabled reference.

### Q2: Where do the reference test vectors live?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline hex dumps in SPEC.md + link to tests/fixtures/ | SPEC Appendix with literal hex for both JCS fixtures + reconstructed signable JSON + Ed25519 sig. Re-implementers work from SPEC alone. | ✓ |
| Reference tests/fixtures/ by path only | SPEC says "see tests/fixtures/..." — requires cloning repo to reproduce. | |
| Separate spec/vectors/*.json (+.bin) | Dedicated directory; most extractable for downstream tooling but adds a new directory. | |

**User's choice:** Inline hex dumps + tests/fixtures/ link
**Notes:** Recommended option. Maximizes abandonment-resilience — a re-implementer can copy-paste the hex and verify without needing repo access.

### Q3: Where does the exit-code taxonomy live?

| Option | Description | Selected |
|--------|-------------|----------|
| Inline section in SPEC.md | `## Exit Codes` table (0/1/2/3/4/5/7) inside SPEC. Self-contained. | ✓ |
| Separate docs/exit-codes.md | Dedicated file referenced from SPEC and CLI --help. More modular but another file to maintain. | |

**User's choice:** Inline section in SPEC.md
**Notes:** Recommended option. Keeps SPEC self-contained; exit-code list is small and stable.

---

## THREAT-MODEL structure

### Q1: How should THREAT-MODEL.md be organized?

| Option | Description | Selected |
|--------|-------------|----------|
| Adversary-indexed | One section per adversary class (Identity compromise, DHT, Sender-purpose, Acceptance-UX, Passphrase-MITM, Receipt-replay) + bounded Out-of-Scope section. Matches ROADMAP SC2 wording almost verbatim. | ✓ |
| Flow-indexed | One section per flow (send, receive, accept, receipt publish, receipt fetch). Each lists adversaries; duplicates analysis across flows. | |
| STRIDE-indexed | Formal, auditable, but forced for a P2P protocol with no server (DoS/Elevation have little to bite on). | |

**User's choice:** Adversary-indexed
**Notes:** Recommended option. Reads naturally for security engineers; DoS/Elevation categories would be thin under STRIDE for a P2P protocol.

### Q2: How deep should each adversary/threat section go?

| Option | Description | Selected |
|--------|-------------|----------|
| Mitigation bullets + 1 worked example per adversary | 3-6 mitigation bullets citing locked decisions (D-RS-07, D-ACCEPT-01, etc.) + one concrete worked-example attack. | ✓ |
| Mitigation bullets only (terse) | 3-6 mitigation bullets, no worked examples. Shorter doc, less pedagogical. | |
| Full STRIDE-style per adversary | Attack preconditions / steps / defenses / residual risk / detection. Closer to an audit artifact than a draft. | |

**User's choice:** Mitigation bullets + 1 worked example
**Notes:** Recommended option. Concrete enough to be actionable; every mitigation cites a Phase 1-3 decision ID for traceability.

---

## SECURITY.md disclosure logistics

### Q1: Which disclosure email for SECURITY.md?

| Option | Description | Selected |
|--------|-------------|----------|
| johnturner@gmail.com (existing email) | Zero setup; mixes security + personal mail; Gmail vendor-locked. | |
| security@cipherpost.io or similar (new domain) | Professional separation; requires domain + DNS setup (~$12/yr, ~1 day scope). | |
| GitHub Security Advisory only (no email) | Point at `github.com/johnzilla/cipherpost/security/advisories/new`. Zero email; requires reporter has GitHub. | ✓ |
| Defer to follow-up | Write docs with TODO stub. Simplest but leaves SC3 unmet. | |

**User's choice:** GitHub Security Advisory only
**Notes:** Chose non-recommended option. Trade-off surfaced: the choice conflicts with DOC-03's literal "email" wording — see resolution Q1a.

### Q1a [follow-up]: Resolve GitHub-Security-Advisory-only vs DOC-03 "email" conflict?

| Option | Description | Selected |
|--------|-------------|----------|
| Amend DOC-03 + ROADMAP SC3 to say "disclosure channel" | Pre-task updates requirements; round-trip proof becomes test advisory + receipt. Cleanest. | ✓ |
| Add email fallback alongside GitHub Advisory | Dual channel; DOC-03 stays as-is. | |
| Switch Q1 to johnturner@gmail.com, GitHub as secondary | Smallest scope change; honors DOC-03 literal wording. | |

**User's choice:** Amend DOC-03 + ROADMAP SC3
**Notes:** Recorded as D-SEC-04 (pre-write blocker). Planner's Task 00 amends both docs in a dedicated `docs(req)` commit before any Phase 4 content commits.

### Q2: GPG key for encrypted reports?

| Option | Description | Selected |
|--------|-------------|----------|
| No GPG | Plain email/advisory flow; ask reporters to keep initial messages minimal. Industry norm for small projects. | ✓ |
| Publish GPG fingerprint + key | Overkill for skeleton; meaningful for high-target threats; ongoing key rotation burden. | |

**User's choice:** No GPG (v0)
**Notes:** Recommended option. Deferred for possible revisit if the project grows.

### Q3: 90-day embargo wording style?

| Option | Description | Selected |
|--------|-------------|----------|
| "Up to 90 days from first report, with negotiation available for complex fixes" | Project Zero-style; reporter/defender can request extension with mutual consent. Non-adversarial. | ✓ |
| "Strict 90 days from acknowledgement, after which disclosure proceeds" | Hard-line wording. Clear but less friendly. | |
| "We target 90 days; actual timing depends on severity and reporter agreement" | Softer, more flexible; may read as wishy-washy. | |

**User's choice:** Up to 90 days with negotiation
**Notes:** Recommended option. Matches industry norm, softened for a one-maintainer project.

### Q4: How to prove the email round-trips?

| Option | Description | Selected |
|--------|-------------|----------|
| Committed note in `.planning/security-disclosure-test.md` | Send test email/advisory, capture headers/receipt, commit ISO-dated note. | ✓ |
| One-line inline note in SECURITY.md | Simpler but less auditable. | |
| Trust the setup — no committed proof | Smallest scope; breaks SC3 "verified by a committed note". | |

**User's choice:** Committed note in `.planning/security-disclosure-test.md`
**Notes:** Recommended option. Evidence stays in-repo; proof procedure redefined as "file test advisory, capture receipt" per D-SEC-03 (Q1 resolution carried forward).

---

## cclink lineage & draft labeling

### Q1: How prominent should the cclink lineage attribution be?

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated `## Lineage` section in each of the 3 docs | 3-5 line section per doc citing cclink URL, fork-and-diverge relationship, `cipherpost/v1` HKDF scope. Satisfies DOC-04 visibly in every file. | ✓ |
| Single `## Lineage` in SPEC + footer link in others | SPEC holds full discussion; others link back. Less repetitive but relies on cross-file reading. | |
| Footer-only link in each doc | One-line attribution; minimal but also minimal context. | |

**User's choice:** Dedicated `## Lineage` section in each doc
**Notes:** Recommended option. Satisfies ROADMAP SC4 and DOC-04 in every file without cross-reference friction.

### Q2: How to label draft/skeleton status?

| Option | Description | Selected |
|--------|-------------|----------|
| Prominent banner at top of each doc | `> Status: DRAFT — skeleton milestone` blockquote; survives GitHub/search previews. | ✓ |
| Single NOTE at top of SPEC.md only | Cleaner look; some readers miss the signal. | |
| Git-tag only, no in-doc label | Tag repo `v0.1-skeleton`; avoids visual noise; relies on tag lookup. | |
| Version field in frontmatter per doc | `Version: 0.1-skeleton / 2026-04-NN`; terser than banner, more discoverable than git-tag-only. | |

**User's choice:** Prominent banner at top of each doc
**Notes:** Recommended option. Sets reader expectations immediately on the first screen.

---

## "Discuss more" check

### Q: Discuss link-check tooling & README linkage, or proceed to plan?

| Option | Description | Selected |
|--------|-------------|----------|
| Ready for context | Tactical items to Claude's Discretion; proceed to CONTEXT.md + plan. | ✓ |
| Discuss link-check & README linkage | One more round on lychee CI vs Makefile vs one-off; README `## Documentation` section. | |

**User's choice:** Ready for context
**Notes:** Recommended option. Link-check tool pick and README linkage deferred to planner discretion.

---

## Claude's Discretion

Decisions deferred to the planner without user input:
- Link-check tooling (CI step vs Makefile target vs one-off manual)
- Doc build order / wave assignment (three parallel plans vs SPEC-first-then-others)
- Whether to add a `## Documentation` section to README.md linking the 3 new docs
- SPEC.md sub-sub-section depth and field-table column format (high-level outline locked by D-SPEC-01)
- THREAT-MODEL.md adversary section ordering within the D-TM-01 list
- Specific wording of the draft-status banner (template provided in D-LIN-02)

## Deferred Ideas

Surfaced during discussion, noted for future phases:
- GPG key for encrypted reports — revisit when project grows
- Dedicated `security@cipherpost.io` domain — revisit when project has a dedicated domain
- Separate `docs/` or `spec/vectors/` directory — revisit when multi-version vectors accumulate
- Separate `docs/exit-codes.md` — revisit if exit-code taxonomy grows past ~10
- v1.0-final editorial polish pass — scheduled for post-skeleton milestone
- Full STRIDE analysis — rejected in favor of adversary-indexed model
- Destruction-attestation protocol doc — out of scope per PROJECT.md, deferred to v1.1
- `--chunk` multi-packet payloads — deferred in Phase 2 (D-PS-02); noted in SPEC "Deferred Ideas" appendix

---

*Log written: 2026-04-21*
