# Phase 7: Typed Material — PgpKey + SshKey - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-24
**Phase:** 07-typed-material-pgpkey-sshkey
**Areas discussed:** Wire-budget strategy, PGP crate + ingest, SSH crate + ed25519 coexistence, Phase structure

---

## Wire-budget strategy

| Option | Description | Selected |
|--------|-------------|----------|
| D. Ship with WireBudgetExceeded (Recommended) | Phase 6 pattern. Ingest/preview/CLI/acceptance/receipt all work; small keys succeed E2E; typical keys surface a clean WireBudgetExceeded error. SPEC.md documents the constraint and names v1.2 as the delivery-mechanism milestone. | ✓ |
| A. Two-tier: inline+external + hash commit | External blob URL + sha256 commit path for oversized payloads. Violates 'no server' unless user brings URL. Adds new OuterRecord field, fetch step on receive, blob TTL handling. ~2× phase scope. | |
| B. Chunking across PKARR packets | Keeps 'no server' intact. Chunk index in label, ordering, partial-fetch retry, chunk-level sig verify. Scales linearly with key size. New wire format all future milestones inherit. | |
| C. OOB + inline hash commit | Cipherpost becomes attestation channel: user delivers bytes OOB, cipherpost transports only hash commit + sigs + acceptance. Major PRD pivot. | |

**User's choice:** D. Ship with WireBudgetExceeded. Pragmatic — keeps scope tight, preserves protocol unchanged, defers delivery-mechanism decision to v1.2 with production data.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — one positive test per variant (Recommended) | `pgp_send_realistic_key_surfaces_wire_budget_exceeded_cleanly` and `ssh_send_realistic_key_surfaces_wire_budget_exceeded_cleanly`. Uses real-world-minimum fixtures. Mirrors Phase 6 pattern. | ✓ |
| Yes — plus #[ignore]'d full round-trip tests (like Phase 6) | Add full send→receive round-trip tests marked #[ignore] with explicit wire-budget notes, ready to un-ignore when v1.2 delivers the fix. More surface; more regression coverage. | |
| No — one shared wire-budget test across all three variants | Consolidate into a single `typed_material_wire_budget_surfaces_cleanly` test parameterized over X509/PGP/SSH. Less redundancy; failure-in-one-breaks-others risk. | |

**User's choice:** One positive test per variant. Keeps Phase 6's blast-radius-per-variant pattern uniform.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Yes — Ed25519-minimal fixtures must round-trip (Recommended) | Plan a PGP fixture (Ed25519 primary, single UID ≤32 chars, no subkeys) and SSH fixture (Ed25519 OpenSSH v1, empty comment, no passphrase) that DO fit under 1000 B encoded packet. Document 'what works today' floor in SPEC.md. | ✓ |
| No — defer to v1.2 entirely | Don't carve out a small-key success floor; Phase 7 ships library+CLI and every round-trip test is WireBudgetExceeded-or-ignored. | |
| Yes — but only for PGP (not SSH) | OpenSSH v1 has mandatory padding + 16-byte magic + checkint that push the floor higher than 1000 B regardless of key type. Measure at plan time; drop SSH small-key test if floor > ceiling. | |

**User's choice:** Ed25519-minimal fixtures must round-trip for BOTH variants. Locks the v1.1 success floor. Fallback if plan-01 measurement shows SSH floor > ceiling: downgrade SSH-only round-trip to `#[ignore]` with honest note (per D-P7-03).

---

## PGP crate + ingest

| Option | Description | Selected |
|--------|-------------|----------|
| `pgp` (rpgp) (Recommended) | Pure-Rust, parse-focused, active. Supports v4 + v5 fingerprints. Dep tree: rand_core, sha2, aes, block-modes. ~30 K LOC. | ✓ |
| `sequoia-openpgp` (with RustCrypto backend) | Full OpenPGP toolkit. ~180 K LOC. Brings signing/encryption/keyring management we won't use. Larger attack surface. | |
| Hand-roll minimal packet parser | No external crate. ~Protocol-bug risk; Phase 7-sized research cost. | |

**User's choice:** `pgp` (rpgp). Natural fit for parse-only scope.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Dedicated warning line above the subblock separator (Recommended) | `[WARNING: SECRET key — unlocks cryptographic operations]` on its own, between `Size:` and `--- OpenPGP ---`. High visual weight. | ✓ |
| Inline tag on the Key: line inside the subblock | `Key: Ed25519 [WARNING: SECRET key]`. Compact; skim-past risk. | |
| Prominent banner header (above Purpose:) | `!!! WARNING: SECRET KEY !!!` before banner border. Most emphatic; breaks Phase 6 banner symmetry. | |

**User's choice:** Dedicated warning line. Matches gravity of PGP-04 without breaking banner pattern.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Strict prefix check: reject if starts with `-----BEGIN PGP` (Recommended) | After trim_start(), check starts_with prefix. Returns `Error::InvalidMaterial` with explicit hint. Mirrors Phase 6 X.509 PEM sniff (inverted sense). | ✓ |
| Try-parse, fall through on packet-type mismatch | Feed input to `pgp` crate; rely on crate error. Couples error message to crate internals (oracle-hygiene risk). | |
| Dearmor and accept (contrary to PGP-01) | REJECTED: violates requirement explicitly. | |

**User's choice:** Strict prefix check. One grep, clear error, oracle-hygiene-safe.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Count of top-level Public-Key (tag 6) or Secret-Key (tag 5) packets > 1 (Recommended) | Parse packet stream, count tag-5 + tag-6 top-level packets. Subkeys (tag 7/14) not counted. Reject with exit 1 and exact string naming N primary keys. | ✓ |
| First-primary wins, silently truncate subsequent | Accept first primary + subkeys; drop later primaries. Violates PGP-03's explicit rejection; hides key-drift. | |
| Reject on any RFC 4880 §11 'OpenPGP message' concatenation of >1 | Stricter; complicates error messages. | |

**User's choice:** Top-level tag-5/tag-6 count > 1 rejection. Precise semantics matching PGP-03.

---

## SSH crate + ed25519 coexistence

| Option | Description | Selected |
|--------|-------------|----------|
| Disable `ssh-key`'s ed25519 feature (Recommended) | Plan 01: add `ssh-key = { default-features = false, features = ["alloc"] }`. Bypasses 2.x/3.0.0-pre.5 collision if feature-disable retains fingerprint extraction. | ✓ |
| Accept coexistence (2.x + 3.0.0-pre.5) | Document coexistence in plan 01 and SPEC.md. Binary carries two Ed25519 impls. | |
| Fall back to hand-rolled OpenSSH v1 parser | ~200 lines parsing OpenSSH v1. Protocol-bug risk. Substantial scope. | |

**User's choice:** Disable ed25519 feature (primary). Documented fallback: accept coexistence (NOT hand-roll) if plan-01 measurement shows feature-disable breaks fingerprint extraction.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Re-encode through `ssh-key` to produce canonical bytes (Recommended) | Parse user input, re-serialize via `PrivateKey::to_bytes_openssh()` with normalized comment + block-standard padding. Deterministic across re-sends. Mirrors Phase 6 canonical-DER pattern. | ✓ |
| Strict-match input bytes (no re-encode) | Store exactly what the user supplied. Reject any input with extra bytes after END marker. Two valid senders with different ssh-keygen versions → different share_refs. | |
| Parse-then-compare: require input already canonical | Parse, re-encode, check bytes match. Reject if not. Strictest correctness, worst UX. | |

**User's choice:** Re-encode through `ssh-key`. Canonical bytes on wire; share_ref determinism preserved.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Reject `--armor` for SSH (Recommended) | `Error::Config("--armor not applicable to ssh-key — OpenSSH v1 is self-armored")`. Parallel to Phase 6's x509-cert armor gating. | ✓ |
| Silently accept `--armor` for SSH (no-op) | Flag accepted but does nothing. Confusing UX. | |
| Use `--armor` to toggle armored vs raw-DER-of-SSH | `--no-armor` = extract base64 body, decode, emit raw binary. Out of scope for Phase 7. | |

**User's choice:** Reject `--armor` for SSH. Clean, explicit, UX-consistent with Phase 6.

---

| Option | Description | Selected |
|--------|-------------|----------|
| Display-only, never block (Recommended) | `[DEPRECATED]` tag on Key: line for DSA (any size) and RSA < 2048. Ingest accepts; banner warns; user types z32 to proceed. Consistent with X.509 [EXPIRED] pattern. | ✓ |
| Display + additional stderr warning line | Add `[WARNING: deprecated key algorithm]` above subblock. More emphatic. | |
| Hard-reject at ingest | Contrary to SSH-04. | |

**User's choice:** Display-only. Matches SSH-04 exactly.

---

## Phase structure

| Option | Description | Selected |
|--------|-------------|----------|
| A. Two Phase-6-style sequences — 8 plans (Recommended) | 07-01..04 PGP (foundation→preview→wiring→ship-gate); 07-05..08 SSH same structure. Clearest lesson-per-plan story; independent variant foundations. ~2× Phase 6 duration. | ✓ |
| B. Shared foundation + parallel variant tracks — 5 plans, 3 waves | Enables wall-clock parallelism IF worktrees enabled. Currently collapses to sequential. | |
| C. Split into 7a (PGP) and 7b (SSH) separate phases | Two clean phase artifacts. Roadmap renumbering. Most overhead. | |
| D. Interleaved 6 plans with shared foundation + paired plans | Tightest code reuse; highest coupling (PGP bug blocks SSH shipping). | |

**User's choice:** Two Phase-6-style sequences, 8 plans. Preserves working Phase 6 rhythm.

---

| Option | Description | Selected |
|--------|-------------|----------|
| No — keep sequential on main tree (Recommended) | Phase 6 shipped fine sequentially. 8 plans × Phase-6-pace ≈ 2 hours. Worktree overhead not worth it. | ✓ |
| Yes — flip worktrees on for Phase 7 | Meaningful only with structure option B. Parallel plans in isolated worktrees; merge conflicts on SPEC.md + Cargo.toml. | |
| Only for ship-gate plans (shared SPEC.md edits) | Logical opposite: ship-gate is the ONES that conflict. Too fiddly. | |

**User's choice:** Keep worktrees disabled. Sequential execution on main tree; re-evaluate for future phases with 6+ genuinely independent plans.

---

## Claude's Discretion

Areas where user explicitly deferred to planner (per D-P7 "Claude's Discretion" section of CONTEXT.md):

- Exact `pgp` and `ssh-key` crate versions (resolved via `cargo search` at plan time)
- Fixture byte layout and reproduction recipe details
- Error string wording for `Error::SshKeyFormatNotSupported` format-conversion hint
- Whether `render_pgp_preview` re-parses bytes or takes a pre-parsed struct
- Whether preview returns `{ warning, subblock }` struct or embeds the SECRET warning in the string
- UID truncation width tuning (~64 chars)
- Whether oracle-hygiene `EXPECTED_REASONS` moves to `tests/common.rs` or stays per-file
- Whether SPEC consolidation lands in plan 08 or per-variant ship-gate plans

## Deferred Ideas

Full list in CONTEXT.md `<deferred>`. Highlights from discussion:

- v1.2 milestone: wire-budget delivery mechanism (design the real fix with production data)
- PGP v3 / MD5-SHA1 fingerprints / PGP sig verification — permanent non-goals
- SSH FIDO keys / cert keys — rejected at ingest; future support would require new variants
- SSH `--no-armor` flag / multi-key handoff per envelope — out of scope
- Consolidated SPEC.md wire-budget section — land at v1.2 kickoff
