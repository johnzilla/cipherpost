# Cipherpost

## What This Is

A self-sovereign, serverless, accountless CLI tool for handing off cryptographic material (private keys, certs, credentials, API tokens, passphrases) between parties. Uses Mainline DHT via PKARR for rendezvous, age for encryption, and Ed25519/PKARR keypairs as identity — so there is no operator, no account, and no subpoena target. Built for security engineers, OSS maintainers, researchers, and small teams who need to hand off keys with a receipt and without standing up a service.

## Core Value

**Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.** If nothing else works, that round trip must.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

**Foundation (Phase 1 — 2026-04-21)**
- ✓ User can generate an Ed25519/PKARR keypair and store it on disk passphrase-wrapped (Argon2id + HKDF-SHA256 with `cipherpost/v1/<context>` domain separation; Argon2 params live in PHC-format identity-file header, not hardcoded)
- ✓ User can unlock an existing identity with their passphrase; wrong passphrase returns exit 4; identity files at mode > 0600 are refused
- ✓ Rust crate scaffold with exact cclink v1.3.0 crypto pins (`pkarr 5.0.3`, `ed25519-dalek =3.0.0-pre.5`, `age 0.11`), no `tokio` dep, plain `fn main()`, CI runs `fmt --check`, `clippy -D warnings`, `nextest`, `audit`, `deny check`
- ✓ `Transport` trait with `publish` / `resolve` / `publish_receipt` method signatures; `DhtTransport` over `pkarr::ClientBlocking` + `MockTransport` gated by `#[cfg(any(test, feature = "mock"))]` for integration tests without real DHT
- ✓ `OuterRecord` / `OuterRecordSignable` wire schema locked via committed JCS fixture (`tests/fixtures/outer_record_signable.bin`); 128-bit `share_ref`; protocol version 1
- ✓ Error-oracle hygiene: single `thiserror` enum with `#[source]` chains preserved but never Displayed to stderr; all signature-failure variants share one identical user-facing message and exit code 3
- ✓ 23 tests green in parallel (Pitfalls #1, #4, #7, #8, #9, #13, #15 each have a prevention test)

### Active

<!-- Current milestone: walking skeleton. Each remaining item is a hypothesis until shipped. -->

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
- [ ] Shares carry a default TTL of 24 hours and honor a sender-supplied `--ttl`
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

**Phase 1 complete (2026-04-21).** Rust crate scaffold + vendored crypto/identity/transport/record primitives shipped. Binary builds, 23 tests pass in parallel, `cipherpost identity generate/show/version` works end-to-end via env-var passphrase (interactive TTY flow captured as pending HUMAN-UAT). Foundation ready for Phase 2 (send/receive/acceptance).

**Domain lineage.** The underlying protocol (E2E-encrypted payloads published to Mainline DHT via PKARR SignedPacket, age for payload encryption, Ed25519 for identity) is already implemented and exercised in `cclink`. Generalizing into keyshare is a small delta on existing code, not a new protocol.

## Constraints

- **Language & shape**: Rust crate + CLI binary, MIT-licensed — follows PRD and cclink lineage.
- **No servers**: Rendezvous is Mainline DHT only. Any proposal introducing an operator (even optional) is out of scope for v1.x core. Relay-assist is a *possible later commercial feature*, not an option here.
- **Key is identity**: No accounts, no email verification, no logins. Ed25519/PKARR keypair is the only identity.
- **Ciphertext only on the wire**: Both payload and metadata are encrypted; the DHT sees only opaque blobs.
- **Attestation first-class**: Receipt, destruction (v1.1), and purpose binding are core features, not afterthoughts.
- **Ship narrow**: Primitive first, workflows second. Enterprise features only if demand is proven.
- **Payload ceiling**: 64 KB.
- **Default TTL**: 24 hours (revised from PRD's 4h after research showed Mainline DHT p50 lookup ≈ 1 minute with a long tail).
- **Crypto choices (locked, conservative)**: age (X25519 derived from Ed25519), Argon2id (64 MB, 3 iter), HKDF-SHA256 with domain separation, dual signatures. Do not substitute.
- **Source of truth for primitives**: `johnzilla/cclink` on GitHub — fork code in, do not re-derive from scratch.
- **This milestone is a walking skeleton, not v1.0**: Self + Share + Receipt on generic-secret payloads. `--pin`, `--burn`, other payload types, and the TUI are deliberately deferred.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Lock name as "Cipherpost" | PRD working name; cost of renaming compounds the later it slips; alternatives (keyshare, dropkey, sigpost) rejected for now | — Pending |
| Fork-and-diverge from cclink, no shared core crate | cclink is mothballed — no active sibling to share a crate with; fork-and-diverge is lower overhead than extracting a library from a dead project | ✓ Good (Phase 1) |
| Milestone target = walking skeleton, not full v1.0 | Validate the cclink extraction + the cipherpost-specific receipt flow end-to-end before committing to v1.0 breadth (TUI, all four modes, all payload types) | — Pending |
| Skeleton includes signed receipt, not just self/share | The receipt is the cipherpost delta from cclink. A skeleton without it just validates cclink, not cipherpost. | — Pending (Phase 3) |
| Skeleton uses generic-secret payload type only | Other typed payloads (X.509, PGP, SSH) add parsing complexity without changing protocol shape; schema reserves them for v1.0 | — Pending (Phase 2) |
| SPEC/THREAT-MODEL/SECURITY as drafts in skeleton | Writing them forces design clarity during skeleton work; final versions gate v1.0, not skeleton | — Pending (Phase 4) |
| Default TTL = 24h (PRD said 4h) | Research showed Mainline DHT p50 lookup ~1 min with long tail; 4h default would routinely expire before pickup | — Pending (Phase 2) |
| Canonical JSON = RFC 8785 (JCS) via serde_canonical_json | Future-proof for cross-language reimplementation; abandonment-resilience (independent re-implementers can produce byte-identical signatures) | ✓ Good (Phase 1 — note: shipped version 1.0.0, not 0.2 as originally planned; `CanonicalFormatter` API matches) |
| Fingerprint display = OpenSSH-style + z-base-32 | OpenSSH `ed25519:SHA256:<base64>` matches security-engineer audience; z-base-32 is the DHT address; showing both eliminates ambiguity in acceptance screens | ✓ Good (Phase 1 — `identity show` prints both) |
| Identity path = `~/.cipherpost/` | cclink-style simple path; skeleton keeps config discovery trivial; XDG can be added later if users ask | ✓ Good (Phase 1 — `CIPHERPOST_HOME` env overrides for tests) |
| HKDF info namespace = `cipherpost/v1/<context>` | Domain separation from cclink; versioned so v2 can rotate without ambiguity | ✓ Good (Phase 1 — enumeration test in CI enforces) |
| share_ref width = 128 bits | 16 more bytes per receipt; avoids a future protocol bump if 64-bit collision surface ever matters | ✓ Good (Phase 1 — `OuterRecordSignable` JCS fixture locks it) |
| `Transport` trait in src/transport/ | Only architectural delta from cclink; lets integration tests use MockTransport instead of real DHT | ✓ Good (Phase 1 — `MockTransport` is how Phase 2/3 integration tests will run without real DHT) |
| Error-oracle hygiene: single thiserror enum with identical sig-fail Display | PITFALLS #16 flagged distinguishable-oracle attacks; making all sig-verification failures surface the same user-facing message prevents distinguishing which part of the verifier tripped | ✓ Good (Phase 1 — test `lib::error::tests::signature_failure_variants_share_display` enforces) |
| serial_test for env-mutating tests | `CIPHERPOST_HOME` tests raced under Rust's default parallel test runner; `serial_test = "3"` + `#[serial]` on the 4 affected tests resolves cleanly | ✓ Good (Phase 1 — discovered during post-wave gate, fixed in commit d8fb202) |

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
*Last updated: 2026-04-21 after Phase 1 completion*
