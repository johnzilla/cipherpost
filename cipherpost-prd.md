# PRD: Cipherpost

*A self-sovereign key and secret handoff primitive*

**Author:** John *(TrustEdge Labs)*
**Status:** Draft v0.1 · April 2026
**One-line:** Accountless, serverless, end-to-end encrypted handoff of cryptographic material between people and machines — the same primitive that powers `cclink`, generalized.

***

## Problem

Every security professional periodically needs to hand off cryptographic material — a private key, a certificate, a credential, an API token, a passphrase — to another party. Today they do this via PGP over email, Box shared folders, encrypted tarballs on SharePoint, or Teams messages with attachments. These practices are uneven, poorly attested, and often violate the security guarantees the material itself is meant to provide.

Existing alternatives (Bitwarden Send, SendSafely, 1Password Sharing, Tresorit Send, crypt.fyi) solve part of the problem but all depend on a central server operator. That operator is a trust dependency, an availability dependency, a subpoena target, and a continuity risk (see: Keybase → Zoom → neglect).

There is no purpose-built, open-source, self-sovereign tool for this workflow.

## Opportunity

A narrow, well-crafted tool for secure cryptographic handoff — with no servers, no accounts, and structured attestation primitives — occupies whitespace between generic secret-sharing apps and enterprise KMS platforms. The underlying protocol (E2E-encrypted payloads published to Mainline DHT via PKARR, age for encryption, Ed25519 for identity) is already implemented in `cclink`. Generalizing it into a keyshare-focused variant is a small delta on existing code, not a new project.

## Users

**Primary:**
- Security engineers and PSIRT practitioners handing off keys to partners, CMs, or labs
- Open-source maintainers distributing signing keys or credentials to co-maintainers
- Researchers and journalists exchanging sensitive material
- Small teams without enterprise KMS infrastructure

**Secondary (later):**
- Regulated-industry teams where "we can prove we never had your data" is a compliance feature
- Cypherpunk-adjacent communities (Pubky, Nostr, Bitcoin) adopting on principle
- Enterprise buyers seeking a serverless alternative for specific workflows

## Non-users (explicit scope exclusions)

- Full key lifecycle management (that's a KMS)
- Long-term secret storage (that's a vault)
- Signing or cryptographic operations on behalf of users
- Incident response or CVE tracking
- General file transfer

## Core Job-to-be-Done

*"I need to send this cryptographic material to that party, securely, with a receipt, and without setting up a service or relying on one."*

## Principles

1. **No servers.** Rendezvous via Mainline DHT. No operator, no subpoena target.
2. **Key is identity.** Ed25519/PKARR keypairs. No accounts, email verification, or logins.
3. **Ciphertext only on the wire.** Payload and metadata both encrypted; DHT sees only opaque blobs.
4. **Attestation first-class.** Receipt, destruction, and purpose binding are core features, not afterthoughts.
5. **Open source, open protocol.** MIT license. Protocol spec separate from implementation.
6. **Human in the loop.** Tool facilitates handoff; humans decide purpose, terms, and acceptance.
7. **Ship narrow.** Primitive first, workflows second, enterprise features only if demand proves real.

## MVP Scope (v1.0)

### Included

- Send and receive cryptographic payloads up to a practical ceiling (start: 64KB)
- Payload types: X.509 cert + private key, PGP keypair, SSH keypair, generic secret blob
- Identity via Ed25519/PKARR, passphrase-protected at rest (Argon2id + age)
- Four encryption modes inherited from cclink: self, `--share <pubkey>`, `--pin`, `--burn`
- TTL-bounded shares, default short (e.g., 4 hours for keyshare vs. 24 for cclink)
- Purpose binding: sender tags share with free-text purpose; recipient sees it before accepting
- Recipient acceptance step: explicit confirmation recorded before material is revealed
- Signed receipt: on successful pickup, recipient's signed acknowledgment is published back to DHT
- CLI-first, with a simple TUI wizard for interactive use
- Exportable audit log suitable for local compliance evidence

### Explicitly deferred

- Web UI (CLI + TUI only in v1.0)
- Destruction attestation workflow (v1.1)
- SSO / IdP federation (commercial tier, later)
- SIEM export (commercial tier, later)
- Multi-recipient broadcast shares (v1.2)
- HSM integration for sender-side generation (v1.3)
- Protocol governance structure (after real adoption)

## Architecture

Reuses cclink's existing primitives unchanged:

- **Identity:** Ed25519/PKARR keypair, passphrase-wrapped on disk
- **Transport:** Mainline DHT via PKARR SignedPacket
- **Encryption:** age (X25519, derived from Ed25519)
- **Signing:** Dual signatures (PKARR packet + inner canonical JSON)
- **KDF:** Argon2id (64MB, 3 iter) + HKDF-SHA256 with domain separation

Delta from cclink:

- New payload schema with typed cryptographic material fields + purpose + terms
- New pickup flow with explicit acceptance step and signed receipt
- New CLI surface focused on key/secret handoff rather than session handoff
- Shared core library (`cipherpost-core` or similar) that both cclink and the new tool depend on

## Success Criteria

**v1.0 launch (target: 3–4 months from kickoff):**
- Shipped as MIT-licensed Rust crate + CLI binary
- Working `send` / `receive` flow with all four encryption modes
- Published protocol spec (SPEC.md) and threat model (THREAT-MODEL.md)
- `SECURITY.md` with disclosure contact
- At least one independent public review invited and addressed
- Three real users who aren't the author, using it for real handoffs

**6 months post-launch:**
- 100+ GitHub stars, 10+ issues/discussions from non-author users
- First documented production use by an organization (even informally)
- Spoken at one security conference or published one detailed blog post
- Decision point: continue as pure OSS, add commercial layer, or maintain as-is

**12 months post-launch:**
- Signal for or against enterprise productization is clear
- Either: formalized governance around the protocol, or deliberate decision to keep it solo-maintained
- Either: at least 10 known organizational users, or acceptance that it's a niche tool

## Competitive Positioning

| Tool | Server needed | Accountless | Attestation primitives | Open source |
|------|---------------|-------------|------------------------|-------------|
| Bitwarden Send | Yes | No | Limited | Partial |
| 1Password Sharing | Yes | No | No | No |
| SendSafely | Yes | No | Some | No |
| crypt.fyi | Yes | Yes | Limited | Yes |
| FileKey | Yes (link delivery) | Yes | No | Yes |
| Keybase (historical) | Yes | No | Some | Mostly |
| PGP over email | No | Yes | No | Yes |
| **Cipherpost** | **No** | **Yes** | **Yes** | **Yes** |

The defensible position is the *combination*: no server + accountless + attestation primitives + purpose-built for cryptographic material. No existing tool occupies that intersection.

## Risks and Mitigations

| Risk | Mitigation |
|------|------------|
| DHT unreliability for time-sensitive handoffs | Document as best-effort; recipient retries; sender can republish; consider optional relay-assist as commercial feature later |
| Cryptographic bug undermines trust | Formal threat model, independent review, fuzzing, conservative choices (age, Ed25519, Argon2id) |
| Existing player (1Password, HashiCorp) adds equivalent feature | Accept as upside cap; differentiate on self-sovereign positioning and open protocol |
| Niche too small to sustain | Acceptable — project remains useful open-source infrastructure regardless of adoption scale |
| Enterprise compliance needs (SOC 2, data residency) | Out of scope for v1.0; addressable later via optional commercial tier with audited relay transport |
| IP conflict with employer | None — built entirely on public primitives (PKARR, age, Mainline DHT), outside employment scope, clean-room relative to any internal work |

## Open Questions

- Name: `Cipherpost`, `keyshare`, `dropkey`, `sigpost`, something else? (Not `cclink` — that stays with its Claude Code scope.)
- Protocol governance: own it alone, or donate to a foundation (e.g., Pubky ecosystem) once stable?
- Relationship to cclink: sibling project, same monorepo with shared core, or fully independent?
- First target community for launch: PSIRT/FIRST, r/cryptography, Pubky Discord, Hacker News, or all of the above in sequence?
- Commercial trajectory: decide now (signal shapes design) or later (design for flexibility, decide on evidence)?

## Next Actions (pre-v1.0)

0. Reference https://github.com/johnzilla/cclink for earlier work in this space
1. Extract cclink's crypto + DHT layer into `cipherpost-core` crate
2. Define payload schema for cryptographic material types
3. Draft `SPEC.md` and `THREAT-MODEL.md`
4. Add `SECURITY.md` and disclosure process
5. Build `cipherpost send` / `cipherpost receive` CLI on top of core
6. Recruit one independent reviewer before public launch
7. Write one launch post framing the self-sovereign positioning

***
