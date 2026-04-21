# Phase 4: Protocol documentation drafts - Context

**Gathered:** 2026-04-21
**Status:** Ready for planning

<domain>
## Phase Boundary

Produce three repo-root documents that (a) document every wire-format and trust-model decision the skeleton locked in across Phases 1–3 so cipherpost is independently re-implementable (PRD abandonment-resilience goal), (b) make the security model legible to a security-engineer reader, and (c) establish a working vulnerability-disclosure channel.

**Deliverables:**
- `SPEC.md` — protocol specification draft
- `THREAT-MODEL.md` — adversary model and mitigations draft
- `SECURITY.md` — disclosure policy + embargo (working, not draft)

All three are **drafts** for the skeleton milestone; v1.0-final review is a later phase. Wire-format decisions documented here are stable (locked in Phases 1–3) and must not drift from the implementation.

**Carry-forward from Phases 1–3 (documented, not re-decided here):**
- Wire constants (D-04 `CIPHPOSK`, D-05 `_cipherpost`, D-06 `_cprcpt-<share_ref>`, D-07 `PROTOCOL_VERSION=1`, D-08 `cipherpost/v1/<context>` HKDF namespace, 128-bit share_ref)
- Envelope / Material / OuterRecord / Receipt schemas (JCS-locked via committed fixtures)
- Share URI: `cipherpost://<z32>/<share_ref_hex>`
- Dual-signature model + D-16 unified sig-fail message
- Exit-code taxonomy (0/1/2/3/4/5/7) from D-14..17
- Default TTL = 24h (revised from PRD 4h)
- TTY-required passphrase + acceptance; full-z32 confirmation token
- `~/.cipherpost/` identity path + `~/.cipherpost/state/` ledger
- age + Argon2id (64MB, 3 iter) + HKDF-SHA256 + Ed25519/PKARR + Mainline DHT
- cclink lineage: fork-and-diverge from `johnzilla/cclink` (mothballed)

</domain>

<decisions>
## Implementation Decisions

### SPEC.md structure & content

- **D-SPEC-01:** **RFC-style with numbered sections.** Top-level: `## 1. Introduction`, `## 2. Terminology`, `## 3. Wire Format`, `## 4. Share URI`, `## 5. Flows`, `## 6. Exit Codes`, `## 7. Passphrase Contract`, `## 8. Appendix: Test Vectors`, `## 9. Lineage`. Each struct in §3 gets a numbered sub-section (`### 3.1 Envelope`, `### 3.2 Material`, `### 3.3 OuterRecord`, `### 3.4 Receipt`) with a field table (`Field | Type | Size | Description | Source-of-truth decision`). Source-of-truth column cites Phase 1–3 decision IDs (e.g., `D-04`, `D-RS-06`) so a reader can trace every field back to the locking decision. Rationale: matches security-engineer audience per CLAUDE.md; produces a spec a third-party can mechanically re-implement from.

- **D-SPEC-02:** **Reference test vectors = inline hex dumps in SPEC.md §8 Appendix + path link to `tests/fixtures/`.** For each of the two committed JCS fixtures:
  - Input: reconstructed signable struct shown as pretty JSON
  - Canonical bytes: full hex dump of the JCS-serialized bytes (`outer_record_signable.bin` and `receipt_signable.bin` = 424 bytes)
  - Ed25519 signature: base64-STANDARD over the canonical bytes
  - Test keypair: a deterministic `[0u8; 32]` seed (NOT a real key) for reproducibility — must be labelled `TEST VECTOR ONLY — DO NOT USE IN PRODUCTION`
  - Filesystem reference: `Fixture file: tests/fixtures/<name>.bin` so re-implementers can byte-compare
  A re-implementer must be able to paste the hex into their own JCS serializer and ed25519 verifier and reproduce the signature, without cloning this repo.

- **D-SPEC-03:** **Exit-code taxonomy lives inline in SPEC.md §6** as a single `## Exit Codes` table with columns `Code | Meaning | User-facing message | Error variants`. Covers 0 (success), 1 (generic error), 2 (TTL expired), 3 (signature verification failed — unified D-16), 4 (passphrase failed), 5 (NotFound), 7 (Declined). Keeps the spec self-contained.

### THREAT-MODEL.md structure & depth

- **D-TM-01:** **Adversary-indexed organization.** Top-level `## N. <Adversary Class>` sections:
  - `## 2. Identity Compromise` (disk passphrase, physical access, weak Argon2id params)
  - `## 3. DHT Adversaries`
    - `### 3.1 Sybil`
    - `### 3.2 Eclipse`
    - `### 3.3 Replay`
  - `## 4. Sender-Purpose Adversary` (purpose field is sender-attested, NOT independently verified — worked example: Mallory sends `purpose: "key backup for Alice"` while being himself)
  - `## 5. Acceptance-UX Adversary` (prompt fatigue, wrong-sender acceptance by muscle memory — mitigated by D-ACCEPT-01 full-z32 confirmation + D-ACCEPT-03 TTY requirement)
  - `## 6. Passphrase-MITM Adversary` (shoulder surfing, keylogger, malicious env-var injection)
  - `## 7. Receipt-Replay / Race Adversary` (D-MRG-02 documented-not-mitigated race; receipt replay via a fetched TXT record)
  - `## 8. Out of Scope Adversaries` (bounded list: quantum adversaries, nation-state forensics, compromised `rustc`, malicious libraries on crates.io, etc. — what this model does NOT cover)

  Plus a leading `## 1. Trust Model` section establishing the baseline (what we trust: sender's disk, recipient's disk, age + Ed25519 + Argon2id primitives, the Mainline DHT's liveness but NOT its integrity or confidentiality).

- **D-TM-02:** **Depth = 3–6 mitigation bullets per adversary + ONE worked-example attack per adversary.** Each section follows this template:
  ```
  ### N.X Adversary class name
  
  **Capabilities:** [what the adversary can do]
  
  **Worked example:** [one concrete attack scenario, 2-4 sentences]
  
  **Mitigations:**
  - Cite [D-XX-YY] from Phase 1–3 CONTEXT.md
  - Cite [D-AA-BB]
  - ...
  
  **Residual risk:** [what remains uncovered, 1 sentence]
  ```
  Every mitigation bullet MUST cite a specific decision ID from Phases 1–3 so a reader can trace the defense back to the locking decision and verify it's actually implemented. No hand-wavy mitigations.

### SECURITY.md disclosure logistics

- **D-SEC-01:** **Disclosure channel = GitHub Security Advisory only.** Primary URL: `https://github.com/johnzilla/cipherpost/security/advisories/new`. No email address published; no GPG key in v0. SECURITY.md explicitly tells reporters to use GitHub's private-advisory flow; mentions that a reporter without a GitHub account may open a public issue requesting a private channel (but this is discouraged). Rationale: zero infrastructure setup, GitHub encrypts in transit + at rest, built-in reporter/maintainer private conversation thread, CVE assignment workflow integrated.

- **D-SEC-02:** **Embargo wording:** "Up to 90 days from first report, with negotiation available for complex fixes." Reporter and maintainer may mutually request extension for genuinely complex fixes (e.g., cross-ecosystem changes, coordinated disclosure with upstream `age` / `pkarr` / `ed25519-dalek`). If no fix is released within 90 days and no extension has been negotiated, the reporter is free to disclose publicly. Matches industry norm (Project Zero style, softened for a one-maintainer project).

- **D-SEC-03:** **Round-trip proof = committed note in `.planning/security-disclosure-test.md`.** Test procedure:
  1. File a test Security Advisory on `github.com/johnzilla/cipherpost` (can be dismissed or marked test-only after verification)
  2. Capture: the advisory ID, the maintainer notification (Gmail/GitHub notification), timestamps of filing and receipt
  3. Commit `.planning/security-disclosure-test.md` with the test date, ISO timestamps of filing and receipt, and the dismissal / resolution action
  4. Reference this note from SECURITY.md (e.g., `_Disclosure channel verified round-trip 2026-04-NN (see `.planning/security-disclosure-test.md` in this repo)._`)
  Evidence stays in-repo for auditability without exposing private advisory contents.

- **D-SEC-04:** **[PRE-WRITE BLOCKER] REQUIREMENTS.md DOC-03 and ROADMAP.md Phase 4 SC3 MUST be amended BEFORE SECURITY.md is written.** Current wording says "disclosure **email** that round-trips a live email"; the chosen disclosure channel is GitHub Security Advisory, not email. The planner's first task (call it Task 00 or wave 1 pre-task) amends:
  - `REQUIREMENTS.md` DOC-03: change "working disclosure contact (email)" → "working disclosure channel (GitHub Security Advisory, email, or equivalent)"
  - `ROADMAP.md` Phase 4 success criterion 3: change "disclosure email that round-trips a live email" → "disclosure channel that round-trips a live test report (e.g., a Security Advisory receipt)"
  Commit the amendment in its own `docs(req)` commit before any Phase 4 docs commit. This resolves a literal-text conflict surfaced during discuss-phase; user chose to amend the requirement rather than adopt an email channel.

### cclink lineage & draft labeling

- **D-LIN-01:** **Dedicated `## Lineage` section (3–5 paragraphs) in each of SPEC.md, THREAT-MODEL.md, SECURITY.md.** Each section:
  - Cites `https://github.com/johnzilla/cclink` by full URL
  - States that cclink is mothballed (no active development) and cipherpost forked its crypto + transport primitives (age, Ed25519/PKARR, Argon2id, HKDF-SHA256, Mainline DHT) unchanged
  - Confirms the `cipherpost/v1/<context>` HKDF info prefix is a re-scoped domain separation from cclink's analog (so the two projects' keys are cryptographically distinct even though the primitives are shared)
  - Notes the delta: cipherpost adds typed cryptographic-material payloads, explicit acceptance, and signed receipts on top of the cclink protocol
  - Identifies the fork point: cclink `v1.3.0` (the last mothballed release)
  Satisfies ROADMAP SC4 and DOC-04 visibly in every doc — a reader opening any one file sees the lineage context without having to cross-reference.

- **D-LIN-02:** **Each of the three docs opens with a prominent blockquote banner:**
  ```
  > **Status: DRAFT — skeleton milestone**
  >
  > This document describes the walking-skeleton implementation shipped in Phases 1–3 of the first development milestone (2026-04).
  > Wire-format decisions documented here are **stable** — changes require a protocol version bump.
  > Editorial polish, completeness review, and v1.0-final sign-off are scheduled for a later phase.
  ```
  Placed immediately after the doc title, before the TOC / first section. Sets reader expectations on the first screen; survives search-engine and GitHub preview snippets.

### Claude's Discretion

The planner may decide without further user input:
- **Link-check tooling** — CI step (`lychee-action` or similar), local Makefile target, or one-off manual pre-merge pass. Pick whichever produces the lowest maintenance burden while satisfying ROADMAP SC4's "link-check pass".
- **Doc build order / wave assignment** — whether SPEC / THREAT-MODEL / SECURITY are three parallel plans in a single wave, or sequenced (SPEC first because THREAT-MODEL and SECURITY may reference §N.X anchors). Planner picks; verifier will check cross-doc references resolve.
- **README.md linkage** — whether to add a `## Documentation` section to README.md that links the three new docs (probably yes — discoverability — but the exact wording and placement is editorial).
- **SPEC.md section outline depth** — the top-level outline is locked by D-SPEC-01, but the full TOC depth (sub-sub-sections) and field-table formatting style are the planner's call as long as every Phase 1–3 decision ID is cited in a source-of-truth column.
- **THREAT-MODEL.md adversary section ordering** within the D-TM-01 list — planner may reorder for narrative flow as long as all listed adversaries are covered and the "Out of Scope" section comes last.
- **Specific wording of the draft-status banner** from D-LIN-02 — the banner text above is a template; the planner may refine grammar/tone as long as `Status: DRAFT — skeleton milestone` appears verbatim at the top.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project-level (all phases)
- `.planning/PROJECT.md` — vision, constraints, cclink lineage, Key Decisions table
- `.planning/REQUIREMENTS.md` — DOC-01 through DOC-04 (MUST amend DOC-03 per D-SEC-04 before writing SECURITY.md)
- `.planning/ROADMAP.md` — Phase 4 goal + success criteria (MUST amend SC3 per D-SEC-04)
- `./CLAUDE.md` — project coding standards; esp. PITFALLS and lock-in reminders list
- `./LICENSE` — MIT; referenced in SPEC.md §1 and SECURITY.md

### Prior phase context (carry-forward — source of every decision ID cited in SPEC and THREAT-MODEL)
- `.planning/phases/01-foundation-scaffold-vendored-primitives-and-transport-seam/01-CONTEXT.md` — wire constants (D-04..08), error model (D-14..17), CLI surface (D-09..13)
- `.planning/phases/02-send-receive-and-explicit-acceptance/02-CONTEXT.md` — payload size (D-PS-01..03), share URI (D-URI-01..03), Envelope wire (D-WIRE-01..05), receive flow order (D-RECV-01..02), acceptance UX (D-ACCEPT-01..03), local state (D-STATE-01..04), error additions (D-ERR-01)
- `.planning/phases/03-signed-receipt-the-cipherpost-delta/03-CONTEXT.md` — Receipt wire (D-RS-01..07), publish_receipt merge (D-MRG-01..06), publish sequencing (D-SEQ-01..07), receipts output (D-OUT-01..04), integration test scope (D-IT-01..03)
- `.planning/phases/01-foundation-scaffold-vendored-primitives-and-transport-seam/01-SUMMARY.md` ..`03-04-SUMMARY.md` — shipped-state confirmations for each plan

### Security & threat-model references (external, reference only — not dependencies)
- `https://github.com/johnzilla/cclink` — mothballed lineage source; cite in every doc per D-LIN-01
- RFC 8785 (JSON Canonicalization Scheme) — cited in SPEC §3 for JCS rules
- Project Zero disclosure policy — inspiration for D-SEC-02 wording (not copied verbatim)
- GitHub Security Advisory docs (`https://docs.github.com/en/code-security/security-advisories`) — referenced from SECURITY.md disclosure flow

### Committed fixtures (referenced in SPEC.md §8 Appendix)
- `tests/fixtures/outer_record_signable.bin` — JCS-canonical bytes locked in Phase 1
- `tests/fixtures/receipt_signable.bin` — JCS-canonical bytes locked in Phase 3 (424 bytes)

### Repo code referenced from SPEC for source-of-truth traceability
- `src/crypto.rs` — JCS serializer (`jcs_serialize`) and HKDF-info constants
- `src/record.rs` — OuterRecord / OuterRecordSignable types; sign_record / verify_record
- `src/receipt.rs` — Receipt / ReceiptSignable types; sign_receipt / verify_receipt
- `src/flow.rs` — run_send / run_receive / run_receipts; ledger schema
- `src/transport.rs` — DhtTransport / MockTransport; publish_receipt resolve-merge-republish
- `src/cli.rs` — clap command tree; exit-code dispatch in `src/main.rs`

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- **`tests/fixtures/*.bin`** — two committed JCS fixtures ready for SPEC.md Appendix inclusion (just need `xxd`/`hexdump` formatting for inline).
- **`src/crypto.rs` `jcs_serialize`** — use its doc comment and test cases as the basis for SPEC §3 JCS rules.
- **`src/cli.rs` and `src/main.rs`** — source-of-truth for the exit-code table in SPEC §6; error-enum-to-exit-code mapping is explicit in `main.rs` match arms.
- **Existing CI workflow (`.github/workflows/ci.yml`)** — a link-check job can be added alongside existing `fmt --check` / `clippy -D warnings` / `nextest` / `audit` / `deny check` steps.

### Established Patterns
- **Phase CONTEXT.md → decision IDs (D-XX-YY)** — every Phase 1–3 decision has a stable ID. SPEC source-of-truth columns and THREAT-MODEL mitigation bullets cite these IDs; the planner's task-writer must propagate this discipline.
- **Documentation banner style** — existing `README.md` is minimal; no prior banner pattern to match. D-LIN-02 establishes the pattern for these three docs.
- **No existing `SPEC.md` / `THREAT-MODEL.md` / `SECURITY.md`** at repo root — Phase 4 is pure net-new writing, not editing.

### Integration Points
- **README.md** — small file (426 bytes); add a `## Documentation` section linking the three new docs (planner's call per Claude's Discretion).
- **REQUIREMENTS.md + ROADMAP.md** — must be amended in a pre-task per D-SEC-04.
- **CI** — link-check tool integration point (one new workflow step).
- **CHANGELOG.md** (if it exists) — record the Phase 4 doc shipment; check if one exists.

</code_context>

<specifics>
## Specific Ideas

- **SPEC.md §8 Appendix test vector format** — include a reproducibility stanza that tells a third-party implementer exactly how to regenerate the fixture from the inputs (e.g., "to reproduce: serialize the above JSON via an RFC 8785 JCS implementation; sign with ed25519 over the resulting bytes using the test keypair; the signature MUST match the hex below"). This is the difference between a decorative test vector and one that actually proves independent re-implementation works.

- **D-SEC-04 commit sequence** — the REQUIREMENTS/ROADMAP amendment MUST land in a separate commit BEFORE any SECURITY.md commit, so reviewers see the requirement change followed by the implementation that honors it (not the other way around). Planner task ordering matters here.

- **Worked-example attacks** in THREAT-MODEL — keep them concrete and specific to cipherpost, not generic security-textbook scenarios. E.g., for "Sender-Purpose Adversary": "Mallory publishes a share to Alice with `purpose: \"emergency key rotation for the prod deploy key; see incident #4421\"` when there is no incident #4421 and Mallory is trying to get Alice to accept and use a key she shouldn't. Cipherpost's full-z32 acceptance (D-ACCEPT-01) does not prevent this — Alice still accepted the correct sender, just with a misleading purpose. Mitigation relies on Alice verifying the purpose out-of-band before using the material."

- **Draft status banner** language — user may want to reuse this exact phrasing on a future `CHANGELOG.md` or release-note entry; the wording is deliberately formal ("Status: DRAFT — skeleton milestone") rather than casual ("work in progress").

</specifics>

<deferred>
## Deferred Ideas

- **GPG key for encrypted security reports** — explicitly rejected for v0 per D-SEC-01 (GitHub Security Advisory handles encryption). Revisit if the project grows and encrypted email becomes a reporter expectation.

- **Security advisory with dedicated security@cipherpost.io domain** — considered and rejected per D-SEC-01 (adds scope and ongoing maintenance). Revisit when the project has a dedicated domain for other reasons.

- **Separate `docs/` directory or `spec/vectors/` directory** — test vectors live inline in SPEC.md per D-SPEC-02; a dedicated vectors directory is not needed for v0. Revisit if multi-protocol-version vectors accumulate.

- **Separate `docs/exit-codes.md` file** — rejected per D-SPEC-03; exit codes live inline in SPEC §6. Revisit if the exit-code taxonomy grows beyond ~10 codes or gets referenced from many places.

- **v1.0-final editorial polish pass** — explicitly deferred per the `Status: DRAFT — skeleton milestone` banner. Scheduled for a later milestone (post-skeleton). Completeness review, grammar pass, and formal sign-off happen there.

- **Full STRIDE analysis of every flow** — considered and rejected per D-TM-02 (chose adversary-indexed + worked-example depth instead). The adversary-indexed model covers the STRIDE concerns cipherpost actually faces (S, T, R, I) without the formalism that doesn't fit P2P.

- **Destruction-attestation protocol doc** — out of scope for v1.0 per PROJECT.md; deferred to v1.1. Not addressed by THREAT-MODEL beyond a one-line mention in "Out of Scope Adversaries" section.

- **Chunking / multi-packet payloads (`--chunk`)** — explicitly deferred in Phase 2 (D-PS-02). SPEC.md documents the 64KB plaintext cap + ~1000B wire budget as hard limits. `--chunk` is noted in the `Deferred Ideas` appendix of SPEC.md as a possible v1.1+ feature.

</deferred>

---

*Phase: 04-protocol-documentation-drafts*
*Context gathered: 2026-04-21*
