# Phase 4: Protocol Documentation Drafts — Pattern Map

**Mapped:** 2026-04-21
**Files analyzed:** 7 (5 new, 2 modified)
**Analogs found:** 3 / 7 (in-repo); remaining files have no close in-repo analog — patterns sourced from RESEARCH.md

---

## File Classification

| New / Modified File | Role | Data Flow | Closest In-Repo Analog | Match Quality |
|---------------------|------|-----------|------------------------|---------------|
| `SPEC.md` | specification doc | input: Phase 1–3 decisions → output: reader-facing protocol reference | none | no analog |
| `THREAT-MODEL.md` | threat model doc | input: Phase 1–3 decisions → output: adversary+mitigation narrative | none | no analog |
| `SECURITY.md` | policy doc | input: GitHub Advisory platform → output: reporter-facing disclosure policy | none | no analog |
| `.planning/security-disclosure-test.md` | evidence note | input: Advisory round-trip action → output: committed timestamp record | none | no analog |
| `.github/workflows/ci.yml` (modified) | CI config | request-response (push/PR trigger → link-check pass/fail) | `.github/workflows/ci.yml` (self) | exact |
| `README.md` (modified) | project index doc | static | `README.md` (self) | exact |
| `.planning/REQUIREMENTS.md` + `.planning/ROADMAP.md` (modified) | planning docs | static | self | exact |

---

## Pattern Assignments

### `SPEC.md` (specification doc)

**Analog:** None in-repo. Pattern drawn from RESEARCH.md §Architecture Patterns Pattern 1.

**Draft-status banner** (D-LIN-02 — required verbatim at top of file, after title, before TOC):
```markdown
> **Status: DRAFT — skeleton milestone**
>
> This document describes the walking-skeleton implementation shipped in Phases 1–3 of the
> first development milestone (2026-04).
> Wire-format decisions documented here are **stable** — changes require a protocol version bump.
> Editorial polish, completeness review, and v1.0-final sign-off are scheduled for a later phase.
```

**Top-level section skeleton** (D-SPEC-01 — locked, not discretionary):
```markdown
## 1. Introduction
## 2. Terminology
## 3. Wire Format
### 3.1 Envelope
### 3.2 Material
### 3.3 OuterRecord
### 3.4 Receipt
## 4. Share URI
## 5. Flows
## 6. Exit Codes
## 7. Passphrase Contract
## 8. Appendix: Test Vectors
### 8.1 OuterRecordSignable Test Vector
### 8.2 ReceiptSignable Test Vector
## 9. Lineage
```

**Field table pattern** (D-SPEC-01 — one table per struct in §3; source-of-truth column is mandatory):
```markdown
### 3.3 OuterRecord

Published as a JSON TXT record under DNS label `_cipherpost` (D-04) on the sender's
PKARR key. The wire struct is `OuterRecord`; Ed25519 signs `OuterRecordSignable` (same
fields minus `signature`), JCS-serialized per RFC 8785 (D-CRYPTO-04).

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `blob` | String | base64-STANDARD | age-encrypted JCS bytes of `Envelope` | D-WIRE-01 |
| `created_at` | i64 | JSON integer | Unix seconds, inner-signed timestamp for TTL | D-WIRE-02 |
| `protocol_version` | u16 | JSON integer | Always `1` in this version | D-07 |
| `pubkey` | String | z-base-32 | Sender's Ed25519/PKARR public key | D-04 |
| `recipient` | String or null | z-base-32 or JSON null | Recipient's public key; null for `--self` sends | D-WIRE-04 |
| `share_ref` | String | 32 lowercase hex chars | 128-bit share ID: sha256(ciphertext ‖ created_at_be)[..16] | D-06, PAYL-05 |
| `signature` | String | base64-STANDARD | Inner Ed25519 signature over JCS(OuterRecordSignable) | D-WIRE-03, SEND-04 |
| `ttl_seconds` | u64 | JSON integer | Share lifetime in seconds; default 86400 (24h) | D-WIRE-02, SEND-03 |
```

**Source of truth for field names:** `src/record.rs` lines 27–36 (`OuterRecord`) and lines 42–50 (`OuterRecordSignable`); `src/receipt.rs` lines 26–44 (`Receipt`) and lines 48–58 (`ReceiptSignable`); `src/payload.rs` lines 28–33 (`Envelope`).

**Envelope fields** (from `src/payload.rs:28–33`, for SPEC §3.1):
- `created_at: i64`
- `material: Material`
- `protocol_version: u16`
- `purpose: String`

**Receipt fields** (from `src/receipt.rs:26–44`, for SPEC §3.4):
- `accepted_at: i64`
- `ciphertext_hash: String`
- `cleartext_hash: String`
- `nonce: String`
- `protocol_version: u16`
- `purpose: String`
- `recipient_pubkey: String`
- `sender_pubkey: String`
- `share_ref: String`
- `signature: String`

**Test vector pattern** (D-SPEC-02 — §8 Appendix format):
```markdown
### 8.1 OuterRecordSignable Test Vector

**Keypair:** Test seed `[0u8; 32]` (32 zero bytes).
> **WARNING: TEST VECTOR ONLY — DO NOT USE IN PRODUCTION**

**Input (pretty-printed for readability):**
\`\`\`json
{ ... }
\`\`\`

**Canonical bytes (RFC 8785 JCS, 192 bytes):**
\`\`\`
<384-char continuous lowercase hex string>
\`\`\`

**Fixture file:** `tests/fixtures/outer_record_signable.bin` (byte-compare to verify)

**To reproduce:** Serialize the above JSON via any RFC 8785 JCS implementation.
Sign with Ed25519 over the resulting bytes using the test keypair seed `[0u8; 32]`.
The signature MUST match the hex below.

**Signature (base64-STANDARD):**
\`\`\`
<88-char base64 string>
\`\`\`
```

Generate the signature at write time using the Rust snippet from RESEARCH.md §Code Examples (the `gen_spec_test_vectors` test); generate the hex using the Python snippet in the same section. Fixture sizes: `outer_record_signable.bin` = 192 bytes, `receipt_signable.bin` = 424 bytes.

**Exit-code table** (D-SPEC-03 — §6, inline, no external file):
```markdown
## 6. Exit Codes

| Code | Meaning | User-facing message | Error variants |
|------|---------|---------------------|----------------|
| 0 | Success | — | — |
| 1 | Generic error | (anyhow message) | any unclassified |
| 2 | TTL expired | signature verification failed | Error::Expired |
| 3 | Signature verification failed | signature verification failed | Error::SignatureOuter, Error::SignatureInner, Error::SignatureCanonicalMismatch |
| 4 | Passphrase / decryption failure | passphrase failed | Error::Passphrase, Error::Decrypt |
| 5 | Not found on DHT | not found | Error::NotFound |
| 7 | User declined | declined | Error::Declined |
```

Source of truth for exit-code dispatch: `src/main.rs` match arms on `Error` variants (cross-check at write time).

---

### `THREAT-MODEL.md` (threat model doc)

**Analog:** None in-repo. Pattern drawn from RESEARCH.md §Architecture Patterns Pattern 2 (D-TM-01/02).

**Draft-status banner:** Same blockquote as SPEC.md (D-LIN-02).

**Top-level section skeleton** (D-TM-01 — locked):
```markdown
## 1. Trust Model
## 2. Identity Compromise
## 3. DHT Adversaries
### 3.1 Sybil
### 3.2 Eclipse
### 3.3 Replay
## 4. Sender-Purpose Adversary
## 5. Acceptance-UX Adversary
## 6. Passphrase-MITM Adversary
## 7. Receipt-Replay / Race Adversary
## 8. Out of Scope Adversaries
## 9. Lineage
```

**Per-adversary section template** (D-TM-02 — mandatory structure for §§2–7):
```markdown
## N. Adversary Class Name

**Capabilities:** [what the adversary can do — 1–3 sentences]

**Worked example:** [one concrete cipherpost-specific attack scenario — 2–4 sentences]

**Mitigations:**
- [bullet citing D-XX-YY or REQ-ID]
- [bullet citing D-XX-YY or REQ-ID]
- ...

**Residual risk:** [what remains uncovered — 1 sentence]
```

Every mitigation bullet MUST cite a specific Phase 1–3 decision ID (e.g., `[D-ACCEPT-01]`, `[D-CRYPTO-02]`). No bullet without a citation.

**Concrete worked example to copy from RESEARCH.md** (§Specifics — Sender-Purpose Adversary):
> Mallory publishes a share to Alice with `purpose: "emergency key rotation for the prod deploy key; see incident #4421"` when there is no incident #4421 and Mallory is trying to get Alice to accept and use a key she shouldn't. Cipherpost's full-z32 acceptance (D-ACCEPT-01) does not prevent this — Alice still accepted the correct sender, just with a misleading purpose. Mitigation relies on Alice verifying the purpose out-of-band before using the material.

Note: THREAT-MODEL.md references SPEC.md section anchors (e.g., `SPEC.md#3-wire-format`). SPEC must be written and committed first so anchors are stable (Pitfall 1 in RESEARCH.md).

---

### `SECURITY.md` (disclosure policy doc)

**Analog:** None in-repo. Pattern drawn from RESEARCH.md §Architecture Patterns Pattern 4 (sigstore SECURITY.md model).

**PRE-WRITE BLOCKER (D-SEC-04):** REQUIREMENTS.md DOC-03 and ROADMAP.md Phase 4 SC3 MUST be amended and committed before this file is written. See amendment text in RESEARCH.md §Code Examples.

**Draft-status banner:** Same blockquote (D-LIN-02).

**File structure** (D-SEC-01/02/03):
```markdown
# Security Policy

> **Status: DRAFT — skeleton milestone**
> ...

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

[list what is in scope — cipherpost binary, core protocol, key derivation, transport layer]

## Out of Scope

[list what is not in scope — third-party DHT infrastructure, OS key stores, reporter's own keys]

## Lineage

[D-LIN-01 section — cclink reference, fork point, HKDF prefix distinction]

## Verification

_Disclosure channel verified round-trip YYYY-MM-DD
(see `.planning/security-disclosure-test.md` in this repo)._
```

The verification line MUST NOT be added until D-SEC-03 round-trip is completed and `.planning/security-disclosure-test.md` is committed.

---

### `.planning/security-disclosure-test.md` (evidence note)

**Analog:** None in-repo. Template from RESEARCH.md §Code Examples.

This is a committed evidence note, not a draft doc. Content is determined by the actual round-trip result. Copy the template structure from RESEARCH.md §Code Examples ("Security disclosure test note template") and fill in real timestamps, advisory ID, and resolution action at time of filing.

---

### `.github/workflows/ci.yml` (modified — add link-check job)

**Analog:** `.github/workflows/ci.yml` (self) — exact match.

**Existing job pattern to follow** (lines 1–69, full file already read). Each job follows this structure: named job block → `runs-on: ubuntu-latest` → `steps:` → `uses: actions/checkout@v4` → tool install step or inline `run:`.

**New link-check job to add** (append after existing `deny` job; RESEARCH.md §Standard Stack):
```yaml
  link-check:
    name: lychee link check
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Link check
        uses: lycheeverse/lychee-action@7da8ec1fc4e01b5a12062ac6c589c10a4ce70d67  # v2.0.0
        with:
          args: --include-fragments --verbose --no-progress 'SPEC.md' 'THREAT-MODEL.md' 'SECURITY.md' 'README.md'
          fail: true
```

No `needs:` dependency on other jobs (link-check is independent). Add `.lycheeignore` at repo root if false-positives emerge on heading anchors (see Pitfall 3 in RESEARCH.md). Verify the SHA pin is still current at write time against `github.com/lycheeverse/lychee-action/releases`.

---

### `README.md` (modified — add `## Documentation` section)

**Analog:** `README.md` (self) — 7 lines, minimal.

Current content (lines 1–7): title, bold status line, one-paragraph description, PRD link. Tone is terse and declarative.

**Insertion point:** After the description paragraph, before or replacing the PRD link. Suggested placement:

```markdown
## Documentation

- [SPEC.md](./SPEC.md) — Protocol specification (wire format, signatures, test vectors)
- [THREAT-MODEL.md](./THREAT-MODEL.md) — Adversary model and mitigations
- [SECURITY.md](./SECURITY.md) — Vulnerability disclosure policy

See [cipherpost-prd.md](./cipherpost-prd.md) for the full product requirements document.
```

Match the existing file's terse style — no explanatory prose beyond the one-line description per link.

---

### `.planning/REQUIREMENTS.md` + `.planning/ROADMAP.md` (modified — D-SEC-04 amendment)

**Analog:** Self — both files already read.

**Amendment is a pre-write blocker** — must land in a standalone `docs(req): amend DOC-03 and ROADMAP SC3 for GitHub Advisory channel` commit before any Phase 4 content commit.

Exact text changes from RESEARCH.md §Code Examples:

`REQUIREMENTS.md` DOC-03 (line 123):
- Current: `has a working disclosure contact (email) and a 90-day embargo policy statement`
- Replace with: `has a working disclosure channel (GitHub Security Advisory, email, or equivalent) and a 90-day embargo policy statement`

`ROADMAP.md` Phase 4 SC3 (line 80, partial):
- Current: `a disclosure email that round-trips a live email`
- Replace with: `a disclosure channel that round-trips a live test report (e.g., a Security Advisory receipt)`

---

## Shared Patterns

### Draft-status banner (D-LIN-02)
**Apply to:** `SPEC.md`, `THREAT-MODEL.md`, `SECURITY.md` — all three docs.
**Placement:** Immediately after the `# Title` line, before any TOC or first section.
```markdown
> **Status: DRAFT — skeleton milestone**
>
> This document describes the walking-skeleton implementation shipped in Phases 1–3 of the
> first development milestone (2026-04).
> Wire-format decisions documented here are **stable** — changes require a protocol version bump.
> Editorial polish, completeness review, and v1.0-final sign-off are scheduled for a later phase.
```

### Lineage section (D-LIN-01)
**Apply to:** `SPEC.md` (§9), `THREAT-MODEL.md` (§9 or end), `SECURITY.md` (## Lineage).
**Required content per section:**
- Full URL: `https://github.com/johnzilla/cclink`
- cclink is mothballed (no active development)
- Cipherpost forked crypto + transport primitives (age, Ed25519/PKARR, Argon2id, HKDF-SHA256, Mainline DHT) unchanged
- `cipherpost/v1/<context>` HKDF info prefix is re-scoped domain separation from cclink's analog — keys are cryptographically distinct even if primitives are shared
- Delta: cipherpost adds typed cryptographic-material payloads, explicit acceptance, signed receipts
- Fork point: cclink `v1.3.0` (last mothballed release)

### Source-of-truth decision ID citation discipline
**Apply to:** Every field table in SPEC.md §3; every mitigation bullet in THREAT-MODEL.md §§2–7.
Pattern: cite `[D-XX-YY]` or `[REQ-ID]` from the Phase 1–3 CONTEXT.md files. Do not leave any field or mitigation without a traceable citation. The CONTEXT.md files are at:
- `.planning/phases/01-foundation-scaffold-vendored-primitives-and-transport-seam/01-CONTEXT.md`
- `.planning/phases/02-send-receive-and-explicit-acceptance/02-CONTEXT.md`
- `.planning/phases/03-signed-receipt-the-cipherpost-delta/03-CONTEXT.md`

---

## No Analog Found

| File | Role | Data Flow | Reason |
|------|------|-----------|--------|
| `SPEC.md` | specification doc | static | No prior protocol spec exists in this repo |
| `THREAT-MODEL.md` | threat model doc | static | No prior threat model exists in this repo |
| `SECURITY.md` | policy doc | static | No prior security policy exists in this repo |
| `.planning/security-disclosure-test.md` | evidence note | static | No prior round-trip test note; content determined by external action (GitHub Advisory filing) |

For these four files, the planner should use RESEARCH.md patterns exclusively (Pattern 1–4 in §Architecture Patterns and the full template in §Code Examples).

---

## Metadata

**Analog search scope:** `/home/john/vault/projects/github.com/cipherpost/` — all `.md`, `.yml`, `.rs` files
**Files read:** `README.md`, `.github/workflows/ci.yml`, `.planning/REQUIREMENTS.md`, `.planning/ROADMAP.md`, `src/record.rs` (lines 1–80), `src/receipt.rs` (lines 1–80), `src/payload.rs` (lines 1–60)
**Pattern extraction date:** 2026-04-21
