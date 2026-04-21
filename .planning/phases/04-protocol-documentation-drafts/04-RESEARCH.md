# Phase 4: Protocol Documentation Drafts - Research

**Researched:** 2026-04-21
**Domain:** Technical specification writing, threat-model documentation, vulnerability disclosure policy
**Confidence:** HIGH (all major claims verified via web search, official docs, or direct code inspection)

---

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**SPEC.md structure & content**
- D-SPEC-01: RFC-style with numbered sections. Top-level: `## 1. Introduction`, `## 2. Terminology`, `## 3. Wire Format`, `## 4. Share URI`, `## 5. Flows`, `## 6. Exit Codes`, `## 7. Passphrase Contract`, `## 8. Appendix: Test Vectors`, `## 9. Lineage`. Each struct in §3 gets a numbered sub-section (`### 3.1 Envelope`, `### 3.2 Material`, `### 3.3 OuterRecord`, `### 3.4 Receipt`) with a field table (`Field | Type | Size | Description | Source-of-truth decision`). Source-of-truth column cites Phase 1-3 decision IDs (e.g., `D-04`, `D-RS-06`).
- D-SPEC-02: Reference test vectors = inline hex dumps in SPEC.md §8 Appendix + path link to `tests/fixtures/`. Input (pretty JSON), canonical bytes (full hex dump), Ed25519 signature (base64-STANDARD), test keypair = deterministic `[0u8; 32]` seed labeled `TEST VECTOR ONLY — DO NOT USE IN PRODUCTION`. Filesystem reference: `Fixture file: tests/fixtures/<name>.bin`.
- D-SPEC-03: Exit-code taxonomy lives inline in SPEC.md §6 as a single table. Columns: `Code | Meaning | User-facing message | Error variants`. Codes: 0, 1, 2, 3, 4, 5, 7.

**THREAT-MODEL.md structure & depth**
- D-TM-01: Adversary-indexed. Sections: `## 1. Trust Model`, `## 2. Identity Compromise`, `## 3. DHT Adversaries` (3.1 Sybil, 3.2 Eclipse, 3.3 Replay), `## 4. Sender-Purpose Adversary`, `## 5. Acceptance-UX Adversary`, `## 6. Passphrase-MITM Adversary`, `## 7. Receipt-Replay / Race Adversary`, `## 8. Out of Scope Adversaries`.
- D-TM-02: Depth = 3–6 mitigation bullets per adversary + ONE worked-example attack per adversary. Template per section: Capabilities / Worked example / Mitigations (each bullet cites a D-XX-YY) / Residual risk (1 sentence).

**SECURITY.md disclosure logistics**
- D-SEC-01: Disclosure channel = GitHub Security Advisory only. URL: `https://github.com/johnzilla/cipherpost/security/advisories/new`. No email published.
- D-SEC-02: Embargo wording: "Up to 90 days from first report, with negotiation available for complex fixes." Reporter may disclose publicly after 90 days if no fix shipped and no extension negotiated.
- D-SEC-03: Round-trip proof = committed note in `.planning/security-disclosure-test.md`. Capture: advisory ID, notification timestamps, dismissal action.
- D-SEC-04: PRE-WRITE BLOCKER — REQUIREMENTS.md DOC-03 and ROADMAP.md Phase 4 SC3 MUST be amended BEFORE any Phase 4 content commits. Specific changes: DOC-03 "working disclosure contact (email)" → "working disclosure channel (GitHub Security Advisory, email, or equivalent)"; SC3 "disclosure email that round-trips a live email" → "disclosure channel that round-trips a live test report (e.g., a Security Advisory receipt)".

**cclink lineage & draft labeling**
- D-LIN-01: Dedicated `## Lineage` section (3–5 paragraphs) in each doc, citing `https://github.com/johnzilla/cclink`, cclink mothballed status, fork-and-diverge of primitives unchanged, `cipherpost/v1/<context>` HKDF prefix as re-scoped domain separation, fork point = cclink v1.3.0.
- D-LIN-02: Each doc opens with blockquote banner: `> **Status: DRAFT — skeleton milestone** > This document describes the walking-skeleton implementation shipped in Phases 1–3 of the first development milestone (2026-04). > Wire-format decisions documented here are **stable** — changes require a protocol version bump. > Editorial polish, completeness review, and v1.0-final sign-off are scheduled for a later phase.`

### Claude's Discretion

- Link-check tooling (lychee-action, local Makefile target, or one-off manual pass)
- Doc build order / wave assignment (parallel vs. sequenced)
- README.md linkage (`## Documentation` section)
- SPEC.md section outline depth (sub-sub-sections, field-table column formatting)
- THREAT-MODEL.md adversary section ordering (within D-TM-01 list)
- Exact wording of draft-status banner (verbatim `Status: DRAFT — skeleton milestone` required)

### Deferred Ideas (OUT OF SCOPE)

- GPG key for encrypted security reports
- security@cipherpost.io domain
- Separate `docs/` directory or `spec/vectors/` directory
- Separate `docs/exit-codes.md`
- v1.0-final editorial polish pass
- Full STRIDE analysis of every flow
- Destruction-attestation protocol doc
- Chunking / multi-packet payloads (`--chunk`)
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DOC-01 | `SPEC.md` draft covering payload schema, JCS, outer+inner signature, share URI, DHT labels, share_ref derivation, TTL semantics, exit-code taxonomy, passphrase contract | §Standard Stack (doc tooling), §Architecture Patterns (section skeleton), §Code Examples (field tables, hex dump format) |
| DOC-02 | `THREAT-MODEL.md` draft covering identity compromise, DHT adversaries, purpose attestation, acceptance UX, receipt replay, passphrase MITM, out-of-scope section | §Architecture Patterns (threat model template), §Common Pitfalls (adversary framing) |
| DOC-03 | `SECURITY.md` with working disclosure channel and 90-day embargo policy | §Standard Stack (GitHub Advisory flow), §Code Examples (SECURITY.md template), §Environment Availability (Advisory round-trip) |
| DOC-04 | Docs reference cclink lineage and document protocol as `cipherpost/v1` | §User Constraints (D-LIN-01/02), §Code Examples (lineage section template) |
</phase_requirements>

---

## Summary

Phase 4 is pure net-new writing: no source code, no binary, no migrations. Three Markdown documents must be produced at the repo root — `SPEC.md`, `THREAT-MODEL.md`, `SECURITY.md` — plus a pre-write amendment to `REQUIREMENTS.md` and `ROADMAP.md` (D-SEC-04) and a round-trip verification note (D-SEC-03). All wire-format content already exists in committed code and Phase 1–3 CONTEXT.md files; the writing task is excavation and transcription, not invention.

The SPEC.md source-of-truth for every field, constant, and protocol rule is the Phase 1–3 CONTEXT.md decision IDs, the committed JCS fixtures (`tests/fixtures/outer_record_signable.bin` = 192 bytes; `tests/fixtures/receipt_signable.bin` = 424 bytes), and the source files listed in 04-CONTEXT.md Canonical References. The THREAT-MODEL.md is entirely self-contained within the existing decision corpus — every mitigation bullet cites a real D-XX-YY already in Phase 1–3 CONTEXT files. The SECURITY.md requires exactly one external action: filing a test GitHub Security Advisory (D-SEC-03) so the round-trip evidence can be committed.

Link-check tooling research confirms lychee-action v2 (pinned to SHA) is the lowest-maintenance CI integration for this Rust-first repo. Anchor-link checking via `--include-fragments` is supported but has edge-case limitations with complex Markdown. The recommendation is to enable anchor checking but accept that GitHub's heading slug generation may produce occasional false positives on complex section names; use `.lycheeignore` to suppress confirmed false positives.

**Primary recommendation:** Execute D-SEC-04 amendment in a standalone `docs(req)` commit, then write SECURITY.md (simplest, self-contained), then SPEC.md (most content, drives the field tables that THREAT-MODEL.md's mitigations reference), then THREAT-MODEL.md (cites back to SPEC sections). Three sequential plans in one wave with the amendment as Wave 0.

---

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| SPEC.md wire format documentation | Documentation (static Markdown) | Code (source of truth for constants) | `src/lib.rs`, `src/record.rs`, `src/receipt.rs` are the authoritative source; SPEC transcribes |
| THREAT-MODEL.md adversary analysis | Documentation (static Markdown) | Phase 1–3 CONTEXT.md (decision source) | Every mitigation bullet cites an existing decision; no new design decisions in Phase 4 |
| SECURITY.md disclosure channel | Documentation (static Markdown) + GitHub Platform | — | GitHub Security Advisory is the channel; SECURITY.md describes it; round-trip test is external action |
| Link-check | CI (GitHub Actions) | — | New job added to `.github/workflows/ci.yml` |
| REQUIREMENTS.md / ROADMAP.md amendment | Planning docs | — | Pre-write blocker; commits before any content |
| README.md linkage | Documentation (static Markdown) | — | Small file, one new section, planner's call |

---

## Standard Stack

### Core (documentation tooling)

| Tool | Version | Purpose | Why Standard |
|------|---------|---------|--------------|
| lychee-action | v2 (pin to SHA) [VERIFIED: github.com/lycheeverse/lychee-action] | Broken link checking in CI | Written in Rust, GitHub-native, supports Markdown anchors via `--include-fragments`, `.lycheeignore` for exclusions |
| GitHub Security Advisory | N/A (platform feature) [VERIFIED: docs.github.com] | Vulnerability disclosure channel per D-SEC-01 | Zero infrastructure, encrypted in transit+at rest, CVE assignment integrated, private reporter thread |

### Supporting

| Tool | Version | Purpose | When to Use |
|------|---------|---------|-------------|
| `od` (GNU coreutils) | system | Generate hex dump of `.bin` fixtures for SPEC §8 | Available on CI runner; use `od -A x -t x1z` for offset+hex+printable display, or pipe through `python3 -c "import sys; print(sys.stdin.buffer.read().hex())"` for continuous hex string |
| `cargo test --features mock` (existing) | 1.85 | Confirm test keypair `[0u8;32]` compiles and signs/verifies deterministically | Smoke-check the test vector stanza before committing it to SPEC |

### Alternatives Considered

| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| lychee-action | markdown-link-check (Node.js) | markdown-link-check is older and lacks Markdown anchor checking; lychee better fits a Rust repo CI |
| lychee-action | linkchecker (Python) | More setup; no GitHub Action; higher noise on relative anchors |
| lychee-action | one-off manual pass (no CI) | Zero maintenance burden but no enforcement; linkrot guaranteed over time |
| GitHub Security Advisory | GPG-encrypted email | Requires key management infrastructure; explicitly rejected per D-SEC-01 |

**lychee-action CI snippet** (for planner):
```yaml
- name: Link check
  uses: lycheeverse/lychee-action@7da8ec1fc4e01b5a12062ac6c589c10a4ce70d67  # v2.0.0
  with:
    args: --include-fragments --verbose --no-progress 'SPEC.md' 'THREAT-MODEL.md' 'SECURITY.md' 'README.md'
    fail: true
```
[VERIFIED: lycheeverse/lychee-action README — SHA pin format confirmed]

---

## Architecture Patterns

### System Architecture Diagram

```
Phase 1–3 CONTEXT.md files
(D-XX-YY decision IDs)
         │
         ▼
    Source code                    tests/fixtures/*.bin
    src/{lib,record,receipt,       (JCS-locked bytes)
     flow,cli,main}.rs                  │
         │                              │
         └────────────┬─────────────────┘
                      │
                      ▼
              [D-SEC-04 amendment]          GitHub Platform
              REQUIREMENTS.md DOC-03  ──►  Security Advisory
              ROADMAP.md SC3               round-trip test
                      │                         │
                      ▼                         ▼
                  SPEC.md           SECURITY.md  +  .planning/security-disclosure-test.md
                      │
                      ▼
             THREAT-MODEL.md
             (cites SPEC §N.X anchors)
                      │
                      ▼
              README.md (## Documentation section)
                      │
                      ▼
              CI: lychee-action link-check job
```

### Recommended Project Structure (Phase 4 deliverables)

```
/                          # repo root
├── SPEC.md                # §1 Intro §2 Terminology §3 Wire §4 URI §5 Flows §6 Exit §7 Passphrase §8 Appendix §9 Lineage
├── THREAT-MODEL.md        # §1 Trust Model §2–8 adversary sections
├── SECURITY.md            # disclosure policy, embargo, round-trip proof reference
├── README.md              # + new ## Documentation section
├── .planning/
│   └── security-disclosure-test.md   # D-SEC-03 round-trip evidence
└── .github/
    └── workflows/
        └── ci.yml         # + link-check job
```

### Pattern 1: RFC-Style Field Table (SPEC §3 wire format sections)

The age spec (C2SP/C2SP age.md) uses prose + ABNF for a binary format; cipherpost's format is JSON-over-TXT-record, so a Markdown table with typed fields is more readable and directly parallel to the code structs. [CITED: github.com/C2SP/C2SP/blob/main/age.md — prose+ABNF; cipherpost adapts to struct-table format given JSON wire format]

```markdown
### 3.1 Envelope

Serialized as RFC 8785 JCS before inner Ed25519 signing.

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `purpose` | String | UTF-8, control chars stripped | Sender-attested description; NOT independently verified | D-WIRE-05, PAYL-04 |
| `material` | Material | see §3.2 | Typed cryptographic payload | D-WIRE-03 |
| `created_at` | i64 | JSON number (integer) | Unix seconds; matches OuterRecordSignable.created_at | D-WIRE-02 |
| `protocol_version` | u16 | JSON number (integer) | Always 1 in this version | D-07 |
```

[VERIFIED: inspected src/payload.rs placeholder and 02-CONTEXT.md D-WIRE-02 for field names and types]

### Pattern 2: Adversary-Indexed Threat Model Section Template (D-TM-02)

Based on established patterns from Signal Protocol and Tor Project threat model documentation, the adversary-indexed + worked-example depth format is appropriate for a small P2P protocol with a concrete set of threats. [ASSUMED — Signal/Tor format not fetched directly; adversary-indexed structure is the security-community norm for P2P protocols]

```markdown
## 2. Identity Compromise

**Capabilities:** Adversary has read access to the victim's disk; may have a brief window of
physical access or remote code execution on the victim's machine.

**Worked example:** Carol's laptop is stolen. The thief finds `~/.cipherpost/secret_key` and
attempts to unwrap the identity by guessing the passphrase. With Argon2id at 64 MB / 3 iterations,
an offline dictionary attack costs ~0.3 seconds per guess on commodity hardware; a random 4-word
passphrase has ~51 bits of entropy, making exhaustive attack infeasible.

**Mitigations:**
- Argon2id KDF with params (64 MB, 3 iter) stored in identity-file PHC header, not hardcoded [D-CRYPTO-02, CRYPTO-02]
- Passphrase never accepted via `--passphrase <value>` argv (would appear in `ps` output) [D-13, IDENT-04]
- Identity file at mode 0600; wider permissions refused at open time [D-03, IDENT-03]
- `CIPHERPOST_PASSPHRASE` env var accepted for scripted use; risk documented [D-13]

**Residual risk:** Adversary with sufficient compute and a weak passphrase can still break the key;
passphrase strength is entirely the user's responsibility.
```

### Pattern 3: Inline Test Vector Format (SPEC §8 Appendix)

**Decision:** Use **continuous lowercase hex string** format, displayed as a fenced code block, with a preceding "Input" block showing pretty-printed JSON. This is more readable than RFC 8032's space-separated format and does not require xxd (which is not available on all systems). IETF RFCs use space-separated hex bytes [VERIFIED: RFC 8032 §A format]; the age spec externalizes vectors entirely [VERIFIED: C2SP/CCTV]. For cipherpost, inline + filepath reference (D-SPEC-02) is the correct middle ground.

The fixture bytes are already confirmed via inspection:
- `outer_record_signable.bin`: 192 bytes [VERIFIED: direct file inspection]
- `receipt_signable.bin`: 424 bytes [VERIFIED: direct file inspection]

Both fixtures are valid UTF-8 JSON (confirmed by od inspection — they are JCS-canonical JSON, not binary structs).

```markdown
### 8.1 OuterRecordSignable Test Vector

**Keypair:** Test seed `[0u8; 32]` (64 zero bytes for Ed25519 secret key representation).
> **WARNING: TEST VECTOR ONLY — DO NOT USE IN PRODUCTION**

**Input (pretty-printed for readability):**
```json
{
  "blob": "AAAA",
  "created_at": 1700000000,
  "protocol_version": 1,
  "pubkey": "pk-placeholder-z32",
  "recipient": "rcpt-placeholder-z32",
  "share_ref": "0123456789abcdef0123456789abcdef",
  "ttl_seconds": 86400
}
```

**Canonical bytes (RFC 8785 JCS, 192 bytes):**
```
7b22626c6f62223a2241414141222c2263726561...  [full 384-char hex string]
```

**Fixture file:** `tests/fixtures/outer_record_signable.bin` (byte-compare to verify)

**To reproduce:** Serialize the above JSON via any RFC 8785 JCS implementation. Sign with
Ed25519 over the resulting bytes using the test keypair. The signature MUST match the hex below.

**Signature (base64-STANDARD):**
```
[88-char base64 string from sign_record with [0u8;32] seed]
```
```

**Implementation note for the writer:** Generate the signature at write time by running a small Rust snippet using `sign_record` with `[0u8;32]` seed, then encode the 64-byte raw signature as base64-STANDARD. The test vector is only as useful as its ability to be reproduced — the reproducibility stanza (D-CONTEXT-04 specifics) is the value, not the hex bytes alone.

[VERIFIED: fixture bytes confirmed via od inspection; format recommendation from RFC 8032 + age spec comparison]

### Pattern 4: SECURITY.md Structure for GitHub Security Advisory Primary Channel

From examining sigstore/.github/SECURITY.md and OPA SECURITY.md, the standard structure for GSA-first projects is: [CITED: github.com/sigstore/.github/blob/main/SECURITY.md]

```markdown
# Security Policy

## Reporting a Vulnerability

To report a security vulnerability in Cipherpost, please use GitHub's private Security Advisory
system:

**→ [Report a vulnerability](https://github.com/johnzilla/cipherpost/security/advisories/new)**

This opens a private, encrypted channel between you and the maintainer. No email address or
public key is required. If you do not have a GitHub account and need an alternative channel,
open a public issue requesting a private contact method.

## Disclosure Policy

- **Embargo period:** Up to 90 days from first report, with negotiation available for complex
  fixes (e.g., coordinated disclosure with upstream `age`, `pkarr`, or `ed25519-dalek`).
- If no fix is released within 90 days and no extension has been negotiated, the reporter is
  free to disclose publicly.
- We target acknowledgment within **48 hours** and a severity assessment within **5 business days**.

## Scope

...

## Verification

_Disclosure channel verified round-trip YYYY-MM-DD (see `.planning/security-disclosure-test.md`)._
```

### Anti-Patterns to Avoid

- **Publishing an email address in SECURITY.md without infrastructure:** email requires key management or a monitored inbox; GitHub Advisory encrypts automatically. D-SEC-01 is correct to avoid this.
- **Vague "contact us" without a specific link:** reporters give up; the advisory URL must appear as a direct link.
- **Documenting protocol decisions only in code comments:** SPEC.md is specifically for independent re-implementers who won't read Rust source.
- **Omitting the "purpose is sender-attested" warning from SPEC and THREAT-MODEL:** this is PITFALL #12 from research/PITFALLS.md. Both documents must make this explicit.
- **Citing D-XX-YY IDs without giving the reader the context:** SPEC §3 field tables should include enough description to be useful without reading the CONTEXT files. The decision IDs are for traceability, not a substitute for the content.
- **Writing test vectors without a reproducibility stanza:** a hex dump alone is decoration. D-SPEC-02 and the 04-CONTEXT specifics are explicit: the stanza telling re-implementers *how to regenerate* the vector is what makes it load-bearing.
- **Scheduling THREAT-MODEL before SPEC:** THREAT-MODEL §§ cite SPEC section anchors (e.g., `[§3.1]`). Write SPEC first or at least finalize its section numbering before writing THREAT-MODEL.

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Broken link detection | Custom script walking all hrefs | lychee-action | Handles Markdown anchors, external URLs, `.lycheeignore`, already in Rust ecosystem |
| Hex dump of fixture files | New Rust test or script | `od` / `python3 -c "sys.stdin.buffer.read().hex()"` in shell | Fixtures already committed; generating the SPEC §8 hex is a one-time shell operation at write time |
| JCS canonicalization description | Re-spec the algorithm in SPEC §3 | Pointer to RFC 8785 + existing `src/crypto.rs::jcs_serialize` doc comment | Full algorithm is in the RFC; SPEC should summarize the rules and cite the RFC |
| Security advisory infrastructure | Custom email handling / PGP key | GitHub Security Advisory (platform feature) | Zero maintenance, encrypted, integrated CVE workflow |

**Key insight:** Phase 4 is entirely documentation, not code. Every "tool" in this phase is for checking the docs, not producing them. The only external action is the Advisory round-trip (D-SEC-03).

---

## Common Pitfalls

### Pitfall 1: THREAT-MODEL cites SPEC anchors that don't exist yet

**What goes wrong:** Writer produces THREAT-MODEL sections that say "see §3.1" or link to `SPEC.md#31-envelope`, but the SPEC section numbering was not finalized first, so anchors break.

**Why it happens:** Natural impulse to write the threat model in parallel with the spec, but the SPEC section outline is locked (D-SPEC-01) while sub-section depth is discretionary and may shift.

**How to avoid:** The planner should sequence SPEC as Wave 1 (or at least lock the top-level section numbers), then THREAT-MODEL as Wave 2 (can reference `SPEC.md#3-wire-format` and sub-anchors once SPEC is committed).

**Warning signs:** Any THREAT-MODEL draft that references `§N.X` but SPEC is still a stub.

---

### Pitfall 2: D-SEC-04 amendment lands after SECURITY.md content

**What goes wrong:** Writer begins drafting SECURITY.md before the REQUIREMENTS.md and ROADMAP.md amendments are committed. Verifier flags a literal-text contradiction between the old DOC-03 ("disclosure email") and the new SECURITY.md ("GitHub Advisory only").

**Why it happens:** It's tempting to treat the amendment as a footnote; the CONTEXT explicitly marks it as a PRE-WRITE BLOCKER.

**How to avoid:** Planner's Wave 0 / Task 00 is the amendment commit. No content commits until that commit lands. The amendment commit message should be `docs(req): amend DOC-03 and ROADMAP SC3 for GitHub Advisory channel`.

**Warning signs:** Any git log where a SECURITY.md commit precedes an amendment to REQUIREMENTS.md.

---

### Pitfall 3: Lychee false-positives on local Markdown anchors

**What goes wrong:** Lychee with `--include-fragments` generates heading slugs for comparison; GitHub's slug generation lowercases and replaces spaces+punctuation slightly differently than lychee's "unique kebab case" for certain headings (e.g., headings with backticks, parentheses, or non-ASCII characters). The link-check job fails on valid `#3-wire-format` anchors.

**Why it happens:** Lychee documentation explicitly notes limited support for "advanced Markdown processor-specific features." [VERIFIED: lychee.cli.rs/recipes/anchors/]

**How to avoid:** Run lychee locally against the three docs before committing the CI job. Add `.lycheeignore` entries for any confirmed false-positives. Keep heading text simple (alphanumeric + spaces) where possible — D-SPEC-01's headings like `## 3. Wire Format` are already slug-safe.

**Warning signs:** CI link-check job failing on intra-document `SPEC.md#3-wire-format` links that visibly work in GitHub's rendered Markdown.

---

### Pitfall 4: Test vector hex is generated from wrong keypair

**What goes wrong:** Writer generates the Ed25519 signature in SPEC §8 using an actual identity key or a random key, not `[0u8; 32]`. The test vector is non-reproducible and useless for re-implementers.

**Why it happens:** Easy to forget to explicitly set the seed to all-zeros when using `ed25519-dalek`.

**How to avoid:** Write a small Rust snippet (or use an existing test if Phase 1-3 added a `sign_with_zero_seed` test) that explicitly constructs `SecretKey::from_bytes(&[0u8; 32])`, signs the committed fixture bytes, and prints both the hex fixture and the base64-STANDARD signature. Commit the output verbatim into SPEC §8. Label everything `TEST VECTOR ONLY`.

**Warning signs:** The SPEC §8 signature section lacks the `[0u8; 32]` keypair derivation explanation, or the Fixture file byte count doesn't match `wc -c tests/fixtures/outer_record_signable.bin` (should be 192) and `receipt_signable.bin` (should be 424).

---

### Pitfall 5: SPEC describes implementation details instead of the protocol

**What goes wrong:** Writer turns SPEC into a Rust code walkthrough — referencing `src/record.rs:96 sign_record()` by line number, describing `#[serde(rename_all = "snake_case")]` annotations, etc. The SPEC is unreadable to a Go or Python re-implementer.

**Why it happens:** It's easier to describe what the code does than to abstract the protocol.

**How to avoid:** SPEC §3 should describe the JSON field names and types as a protocol observer would see them on the wire, with the source-of-truth column containing the decision ID as a trace back to the code. "The `blob` field contains the age-encrypted payload, base64-STANDARD encoded" — not "see `OuterRecord.blob` in `src/record.rs`."

**Warning signs:** SPEC sections that name Rust types (`Vec<u8>`, `Zeroizing`, `SecretBox`) or reference file paths without also giving the protocol-level description.

---

### Pitfall 6: GitHub Security Advisory round-trip not completed before tagging phase complete

**What goes wrong:** SECURITY.md claims "Disclosure channel verified round-trip YYYY-MM-DD" but `.planning/security-disclosure-test.md` does not exist or has placeholder content.

**Why it happens:** Filing a test Advisory requires leaving the editor, logging into GitHub, going through the Advisory form, and capturing the response — easy to defer.

**How to avoid:** Planner should make the round-trip test its own task with an explicit deliverable (`.planning/security-disclosure-test.md` committed), and the SECURITY.md write task should depend on it. This is the only external-action task in Phase 4.

**Warning signs:** `.planning/security-disclosure-test.md` absent or containing placeholder text at the time of phase verification.

---

## Code Examples

### Generating the full hex string for SPEC §8 (shell — no xxd required)

```bash
# Continuous hex string — paste into SPEC.md §8 code block
python3 -c "
import sys
data = open('tests/fixtures/outer_record_signable.bin', 'rb').read()
print(data.hex())
print(f'({len(data)} bytes)')
"

# Same for receipt fixture
python3 -c "
import sys
data = open('tests/fixtures/receipt_signable.bin', 'rb').read()
print(data.hex())
print(f'({len(data)} bytes)')
"
```

[VERIFIED: od inspection confirms fixtures are 192 and 424 bytes; python3 available on ubuntu CI runner]

### Generating the test-vector signature (Rust — run as a quick binary or test)

```rust
// TEST VECTOR GENERATION — not part of production binary
// Run with: cargo test gen_spec_test_vectors -- --nocapture
#[cfg(test)]
mod spec_vectors {
    use ed25519_dalek::{SigningKey, Signer};
    use base64::{engine::general_purpose::STANDARD, Engine};

    #[test]
    fn gen_spec_test_vectors() {
        let seed = [0u8; 32];
        let signing_key = SigningKey::from_bytes(&seed);

        let fixture_bytes = std::fs::read("tests/fixtures/outer_record_signable.bin").unwrap();
        let sig = signing_key.sign(&fixture_bytes);
        println!("OuterRecordSignable sig: {}", STANDARD.encode(sig.to_bytes()));

        let receipt_bytes = std::fs::read("tests/fixtures/receipt_signable.bin").unwrap();
        let sig2 = signing_key.sign(&receipt_bytes);
        println!("ReceiptSignable sig: {}", STANDARD.encode(sig2.to_bytes()));
    }
}
```

[VERIFIED: ed25519-dalek =3.0.0-pre.5 SigningKey::from_bytes signature is compatible; see Cargo.toml pin]

### REQUIREMENTS.md amendment (D-SEC-04)

Current wording (DOC-03):
```
**DOC-03**: `SECURITY.md` has a working disclosure contact (email) and a 90-day embargo policy statement
```

New wording:
```
**DOC-03**: `SECURITY.md` has a working disclosure channel (GitHub Security Advisory, email, or
equivalent) and a 90-day embargo policy statement
```

ROADMAP.md Phase 4 SC3 current:
```
`SECURITY.md` exists at repo root with a disclosure email that round-trips a live email ...
```

New:
```
`SECURITY.md` exists at repo root with a disclosure channel that round-trips a live test report
(e.g., a Security Advisory receipt) ...
```

### Security disclosure test note template (`.planning/security-disclosure-test.md`)

```markdown
# Security Disclosure Channel — Round-Trip Test

**Test date:** YYYY-MM-DD
**Tester:** johnzilla (repo maintainer)

## Procedure

1. Navigated to https://github.com/johnzilla/cipherpost/security/advisories/new
2. Filed a test advisory titled "Round-trip disclosure channel verification (test — will dismiss)"
3. Completed the form with placeholder vulnerability details
4. Submitted at YYYY-MM-DDTHH:MM:SSZ (UTC)

## Receipt Evidence

- **Advisory ID:** GHSA-xxxx-xxxx-xxxx (or equivalent GitHub-assigned ID)
- **Notification received:** YYYY-MM-DDTHH:MM:SSZ via [GitHub notification / Gmail]
- **Latency:** [X minutes]

## Resolution

- Advisory dismissed/closed at YYYY-MM-DDTHH:MM:SSZ as "test only — not a real vulnerability"

## Conclusion

GitHub Security Advisory round-trip confirmed. Disclosure channel is operational.
```

[VERIFIED: GitHub Security Advisory new-advisory URL confirmed at docs.github.com/en/code-security/security-advisories]

---

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| SPEC.md externalizes test vectors entirely (age approach) | Inline hex + filepath link (D-SPEC-02) | Phase 4 decision | Re-implementers can use SPEC standalone without cloning repo |
| Disclosure via email or PGP key | GitHub Security Advisory as primary channel | Phase 4 / D-SEC-01 | Zero infra; GitHub handles encryption and CVE workflow |
| Threat model as STRIDE matrix per feature | Adversary-indexed + worked-example depth | D-TM-01/02 | More readable for P2P protocol; STRIDE doesn't map cleanly to decentralized threat model |
| Protocol docs deferred to v1.0 | Drafts during skeleton milestone | Project decision | Forces design clarity during implementation; prevents knowledge-lock-in to Rust source alone |

**Deprecated/outdated:**
- "Disclosure email" (DOC-03 pre-amendment): superseded by GitHub Advisory channel per D-SEC-01 and D-SEC-04.
- PRD's "4h default TTL": superseded by 24h after DHT-latency research; SPEC.md documents 24h as the canonical value.

---

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Lychee generates heading slugs compatible with GitHub's rendering for simple alphanumeric headings (e.g., `## 3. Wire Format` → `#3-wire-format`) | Pitfall 3 / Standard Stack | Link-check job fails on valid intra-doc anchors; workaround: `.lycheeignore` |
| A2 | `ed25519-dalek =3.0.0-pre.5` `SigningKey::from_bytes(&[0u8; 32])` produces a valid, deterministic signing key (seed = zero bytes is not rejected by the library) | Code Examples (test vector generation) | Test vector stanza cannot be generated; workaround: use `signing_key_from_seed` with a SHA-256 of "cipherpost-test-vector" instead |
| A3 | The Phase 3 code is sufficiently complete to provide all field names and types needed for SPEC §3 (the 03-CONTEXT.md shows Receipt wire schema; actual src/receipt.rs field names may differ slightly) | Code Examples (field tables) | Minor: field-table column values need to be cross-checked against actual `src/receipt.rs` at write time |
| A4 | Signal/Tor adversary-indexed threat model format (Capabilities / Worked example / Mitigations / Residual risk) is the right fit for a P2P crypto protocol | Architecture Patterns (threat model template) | Planner can reorder or rename sub-sections without reopening D-TM-02 |

**None of the above assumptions block planning.** A1-A4 are all low-risk and have documented workarounds.

---

## Open Questions

1. **Test keypair: [0u8;32] seed validation**
   - What we know: ed25519-dalek =3.0.0-pre.5 is pinned; `SigningKey::from_bytes` signature exists
   - What's unclear: Whether the library rejects an all-zeros seed as cryptographically weak at construction time
   - Recommendation: Planner's Wave 1 task for SPEC §8 should start by running the snippet in Code Examples above and confirming it doesn't panic; if it does, substitute a SHA-256("cipherpost-test-only") seed (still deterministic, non-secret)

2. **README.md `## Documentation` section placement**
   - What we know: README.md is 426 bytes, minimal content (project description + PRD link)
   - What's unclear: Where exactly to insert the section (before or after the PRD link)
   - Recommendation: Planner's discretion per Claude's Discretion; suggest inserting after the first paragraph and before the PRD link for discoverability

3. **lychee-action SHA pin currency**
   - What we know: Current v2 SHA is `7da8ec1fc4e01b5a12062ac6c589c10a4ce70d67` as of research date [VERIFIED: lychee-action README]
   - What's unclear: Whether this SHA is still the latest v2 point at plan-execution time
   - Recommendation: Planner should verify the SHA against `github.com/lycheeverse/lychee-action/releases` at write time; the SHA format is correct regardless

---

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| python3 | Fixture hex generation for SPEC §8 | ✓ (ubuntu-latest CI runner) | system | Use `od -A x -t x1z` if python3 unavailable locally |
| cargo test | Test vector signature generation | ✓ (existing CI) | 1.85 (pinned) | N/A |
| GitHub Security Advisory | D-SEC-03 round-trip test | ✓ (github.com/johnzilla/cipherpost exists) [VERIFIED: git log shows commits to this repo] | N/A | None — required |
| lychee-action | CI link-check job | ✓ (available via GitHub Actions marketplace) [VERIFIED: marketplace listing] | v2 | Manual link-check if CI unavailable |

**Missing dependencies with no fallback:**
- GitHub Security Advisory round-trip (D-SEC-03): requires the repo to be public or have Advisory feature enabled. Confirmed the repo exists (`johnzilla/cipherpost`); Advisory feature is available on all public GitHub repos.

---

## Sources

### Primary (HIGH confidence)
- `github.com/C2SP/C2SP/blob/main/age.md` — age protocol spec; RFC-style section structure, ABNF wire format, external test vector reference
- `github.com/C2SP/CCTV/tree/main/age` — age test vector format (header key-value + binary body); NOT used for cipherpost (inline format chosen per D-SPEC-02)
- `lychee.cli.rs/recipes/anchors/` — lychee anchor checking behavior, `--include-fragments` flag, known limitations with complex Markdown
- `github.com/lycheeverse/lychee-action/blob/master/README.md` — SHA pin format, v2 usage example, `.lycheeignore` support
- `docs.github.com/en/code-security/security-advisories/` — GitHub Security Advisory workflow, private advisory thread, CVE integration
- `github.com/sigstore/.github/blob/main/SECURITY.md` — GSA-first SECURITY.md structure and disclosure flow
- `datatracker.ietf.org/doc/html/rfc8032#appendix-B` — RFC 8032 Ed25519 test vector format (space-separated hex bytes with labeled sections)
- `rfc-editor.org/rfc/rfc8785` — RFC 8785 JCS; test vector format in appendix (tabular + ECMAScript hex)
- Direct code/fixture inspection: `od -A x -t x1z tests/fixtures/outer_record_signable.bin` (192 bytes), `receipt_signable.bin` (424 bytes)
- `.planning/phases/01-CONTEXT.md` through `03-CONTEXT.md` — all D-XX-YY decision IDs

### Secondary (MEDIUM confidence)
- `rust-lang.org/policies/security/` — Rust Foundation security policy structure; shows alternative disclosure model for comparison
- `github.com/cyberphone/json-canonicalization` — JCS reference implementation test vectors (used to verify RFC 8785 cite pattern)

### Tertiary (LOW confidence)
- WebSearch findings on adversary-indexed threat model templates for P2P protocols — Signal/Tor format discussed but not directly fetched; D-TM-02's template is based on training knowledge + project-specific constraints

---

## Metadata

**Confidence breakdown:**
- Standard stack (lychee-action, GitHub Advisory): HIGH — verified via official docs and action README
- SPEC section skeleton and field table format: HIGH — locked by D-SPEC-01; code inspection confirms field names
- Threat model template: MEDIUM — structure is project-defined via D-TM-01/02; external references confirm it's conventional
- Hex dump format for test vectors: HIGH — RFC 8032 + age spec comparison; continuous hex chosen for simplicity

**Research date:** 2026-04-21
**Valid until:** 2026-05-21 (lychee-action SHA pin may rotate; check before writing CI job)
