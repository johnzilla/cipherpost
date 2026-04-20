# Cipherpost

## What This Is

A self-sovereign, serverless, accountless CLI tool for handing off cryptographic material (private keys, certs, credentials, API tokens, passphrases) between parties. Uses Mainline DHT via PKARR for rendezvous, age for encryption, and Ed25519/PKARR keypairs as identity — so there is no operator, no account, and no subpoena target. Built for security engineers, OSS maintainers, researchers, and small teams who need to hand off keys with a receipt and without standing up a service.

## Core Value

**Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.** If nothing else works, that round trip must.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

(None yet — ship to validate)

### Active

<!-- Current milestone: walking skeleton. Each is a hypothesis until shipped. -->

**Identity & at-rest**
- [ ] User can generate an Ed25519/PKARR keypair and store it on disk passphrase-wrapped (Argon2id 64MB, 3 iter + HKDF-SHA256 with domain separation)
- [ ] User can unlock an existing identity with their passphrase

**Self-mode round trip**
- [ ] User can send a generic-secret payload to themselves via `cipherpost send --self`, publishing an encrypted PKARR SignedPacket to Mainline DHT
- [ ] User can retrieve and decrypt their own self-mode payload via `cipherpost receive` on the same identity

**Share-mode round trip**
- [ ] User can send a generic-secret payload to a recipient's public key via `cipherpost send --share <pubkey>`, age-encrypted to the recipient
- [ ] Recipient can retrieve and decrypt the payload via `cipherpost receive` using their own identity
- [ ] Every payload is dual-signed (PKARR packet + inner canonical JSON) and signature verification is required before any decryption

**Payload schema & acceptance**
- [ ] Payload schema supports typed cryptographic-material envelopes (generic-secret implemented; cert/PGP/SSH fields reserved)
- [ ] Sender attaches free-text purpose binding to each share
- [ ] Recipient sees purpose (and sender pubkey) and must explicitly accept before the inner material is revealed

**Signed receipt (the cipherpost delta from cclink)**
- [ ] On successful pickup + acceptance, recipient publishes a signed receipt back to the DHT referencing the original share
- [ ] Sender can fetch and verify the receipt via `cipherpost receipts`

**TTL & operational**
- [ ] Shares carry a short default TTL (4 hours) and honor a sender-supplied `--ttl`
- [ ] Payloads are capped at 64 KB; oversize inputs are rejected with a clear error
- [ ] Both payload and metadata are encrypted on the wire — the DHT sees only opaque blobs

**Protocol docs (drafts, not v1.0-final)**
- [ ] Draft `SPEC.md` describing the payload schema and flows implemented in the skeleton
- [ ] Draft `THREAT-MODEL.md` covering identity, DHT, acceptance, and receipt flows
- [ ] `SECURITY.md` with a working disclosure contact

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

**Deferred to v1.0 (after the skeleton proves out):**
- `--pin` and `--burn` encryption modes — validate the skeleton before adding flow breadth
- TUI wizard — skeleton is CLI-only to keep the surface small
- Additional payload types: X.509 cert + private key, PGP keypair, SSH keypair — schema reserves them, implementation comes with v1.0
- Exportable audit log for local compliance evidence
- Three-real-user launch criterion and independent public review — skeleton is personal validation, not a launch

**Deferred to v1.1+:**
- Destruction attestation workflow — v1.1
- Multi-recipient broadcast shares — v1.2
- HSM integration for sender-side generation — v1.3

**Never (per PRD non-goals):**
- Full key lifecycle management — that's a KMS
- Long-term secret storage — that's a vault
- Signing or cryptographic operations on behalf of users
- Incident response or CVE tracking
- General file transfer
- Central operator / relay / server of any kind (possible optional commercial feature *later*, never v1.x core)
- SSO / IdP federation, SIEM export — commercial tier, later
- Web UI in any v1.x — CLI (+ eventual TUI) only

## Context

**Architectural lineage.** Cipherpost is a generalization of `cclink` (https://github.com/johnzilla/cclink) focused on keyshare workflows rather than Claude Code session handoff. The crypto and transport primitives are reused unchanged (Ed25519/PKARR, age, Mainline DHT, Argon2id KDF, dual signatures). The delta from cclink is purely at the payload and flow layer: typed payload schema, explicit acceptance step, signed receipt, keyshare-oriented CLI.

**cclink is mothballed.** No further development. Treated as a reference / source repo only. The skeleton work will clone `johnzilla/cclink` from GitHub and vendor its crypto + DHT modules directly into this repo (fork-and-diverge), not depend on it as a live sibling.

**Pre-implementation.** The only substantive file prior to this initialization was `cipherpost-prd.md`. No source tree, no build system, no tests yet.

**Domain lineage.** The underlying protocol (E2E-encrypted payloads published to Mainline DHT via PKARR SignedPacket, age for payload encryption, Ed25519 for identity) is already implemented and exercised in `cclink`. Generalizing into keyshare is a small delta on existing code, not a new protocol.

## Constraints

- **Language & shape**: Rust crate + CLI binary, MIT-licensed — follows PRD and cclink lineage.
- **No servers**: Rendezvous is Mainline DHT only. Any proposal introducing an operator (even optional) is out of scope for v1.x core. Relay-assist is a *possible later commercial feature*, not an option here.
- **Key is identity**: No accounts, no email verification, no logins. Ed25519/PKARR keypair is the only identity.
- **Ciphertext only on the wire**: Both payload and metadata are encrypted; the DHT sees only opaque blobs.
- **Attestation first-class**: Receipt, destruction (v1.1), and purpose binding are core features, not afterthoughts.
- **Ship narrow**: Primitive first, workflows second. Enterprise features only if demand is proven.
- **Payload ceiling**: 64 KB.
- **Default TTL**: short — 4 hours for keyshare (vs. 24h in cclink).
- **Crypto choices (locked, conservative)**: age (X25519 derived from Ed25519), Argon2id (64 MB, 3 iter), HKDF-SHA256 with domain separation, dual signatures. Do not substitute.
- **Source of truth for primitives**: `johnzilla/cclink` on GitHub — fork code in, do not re-derive from scratch.
- **This milestone is a walking skeleton, not v1.0**: Self + Share + Receipt on generic-secret payloads. `--pin`, `--burn`, other payload types, and the TUI are deliberately deferred.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Lock name as "Cipherpost" | PRD working name; cost of renaming compounds the later it slips; alternatives (keyshare, dropkey, sigpost) rejected for now | — Pending |
| Fork-and-diverge from cclink, no shared core crate | cclink is mothballed — no active sibling to share a crate with; fork-and-diverge is lower overhead than extracting a library from a dead project | — Pending |
| Milestone target = walking skeleton, not full v1.0 | Validate the cclink extraction + the cipherpost-specific receipt flow end-to-end before committing to v1.0 breadth (TUI, all four modes, all payload types) | — Pending |
| Skeleton includes signed receipt, not just self/share | The receipt is the cipherpost delta from cclink. A skeleton without it just validates cclink, not cipherpost. | — Pending |
| Skeleton uses generic-secret payload type only | Other typed payloads (X.509, PGP, SSH) add parsing complexity without changing protocol shape; schema reserves them for v1.0 | — Pending |
| SPEC/THREAT-MODEL/SECURITY as drafts in skeleton | Writing them forces design clarity during skeleton work; final versions gate v1.0, not skeleton | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd-transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd-complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-04-20 after initialization*
