# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

Pre-implementation. The only substantive file is `cipherpost-prd.md` (the product requirements doc). There is no source tree, build system, or test suite yet — so no build/lint/test commands exist to document. When implementation starts, this section should be replaced with the actual commands.

The intended shape (from the PRD): **MIT-licensed Rust crate + CLI binary**, eventually split into a shared `cipherpost-core` library plus `cipherpost` CLI.

## What Cipherpost is

A self-sovereign, serverless, accountless tool for handing off cryptographic material (private keys, certs, credentials, API tokens, passphrases) between parties. Positioned in the whitespace between generic secret-sharing apps (Bitwarden Send, 1Password Sharing, SendSafely) and enterprise KMS platforms. The defensible combination is: **no server + accountless + attestation primitives + purpose-built for cryptographic material**.

## Architectural lineage: this is a cclink derivative

**Read this before making any design decisions.** Cipherpost is not a new protocol — it is a generalization of `cclink` (https://github.com/johnzilla/cclink) focused on keyshare workflows. The crypto and transport primitives are reused unchanged:

- **Identity:** Ed25519/PKARR keypair, passphrase-wrapped on disk (Argon2id 64MB, 3 iter + HKDF-SHA256 with domain separation)
- **Transport:** Mainline DHT via PKARR SignedPacket — no servers, no operator
- **Encryption:** age (X25519, derived from Ed25519)
- **Signing:** Dual signatures (PKARR packet + inner canonical JSON)
- **Encryption modes:** `self`, `--share <pubkey>`, `--pin`, `--burn` (inherited from cclink)

The delta from cclink is purely at the payload and flow layer:

1. New payload schema with typed cryptographic-material fields, purpose binding, and terms
2. New pickup flow with **explicit acceptance step** before material is revealed
3. New **signed receipt** published back to DHT on successful pickup
4. CLI surface focused on key/secret handoff rather than session handoff
5. Shared core library both tools depend on

**Open question (unresolved):** whether cipherpost lives in the same monorepo as cclink with a shared `cipherpost-core`, or is fully independent. Treat this as undecided until the user says otherwise.

## Principles that constrain design

These are hard constraints from the PRD, not suggestions. Reject approaches that violate them:

1. **No servers.** Rendezvous is Mainline DHT only. Any proposal that introduces an operator, even an optional one, is out of scope for v1.0 (relay-assist is explicitly flagged as a *possible later commercial feature*, not a v1 option).
2. **Key is identity.** No accounts, no email verification, no logins.
3. **Ciphertext only on the wire.** Both payload and metadata are encrypted; the DHT sees only opaque blobs.
4. **Attestation first-class.** Receipt, destruction, and purpose binding are core features, not afterthoughts.
5. **Ship narrow.** Primitive first, workflows second. Enterprise features only if demand is proven.

## Explicit scope exclusions

The PRD lists these as **non-goals**. Do not propose features in these areas without flagging that they're out of scope:

- Full key lifecycle management (that's a KMS)
- Long-term secret storage (that's a vault)
- Signing/crypto operations on behalf of users
- Incident response or CVE tracking
- General file transfer
- Web UI in v1.0 (CLI + TUI only)
- Destruction attestation workflow (deferred to v1.1)
- Multi-recipient broadcast (v1.2)
- HSM integration (v1.3)
- SSO / IdP federation, SIEM export (commercial tier, later)

## v1.0 scope anchors

When sizing proposals, anchor to these concrete v1.0 targets:

- Payload ceiling: 64KB
- Default TTL: short (e.g., 4 hours for keyshare vs. 24 for cclink)
- Payload types: X.509 cert + private key, PGP keypair, SSH keypair, generic secret blob
- Interfaces: CLI-first, simple TUI wizard for interactive use
- Required artifacts at launch: `SPEC.md`, `THREAT-MODEL.md`, `SECURITY.md` with disclosure contact

## Things the PRD explicitly leaves undecided

Flag these when they come up rather than picking a direction unilaterally:

- **Protocol governance:** solo-maintain vs. donate to a foundation (e.g., Pubky ecosystem)
- **Commercial trajectory:** decide now (shapes design) or later (design for flexibility)

*Resolved during `/gsd-new-project` on 2026-04-20 (see `.planning/PROJECT.md` Key Decisions):*
- Project name: **Cipherpost** (locked)
- Repo layout: **fully independent, fork-and-diverge from mothballed cclink** (no shared core crate until a second consumer exists)

## GSD workflow

This project uses Get Shit Done (GSD) for planning and execution. Canonical state lives in `.planning/`:

- `PROJECT.md` — living project context, core value, active/validated/out-of-scope requirements, constraints, key decisions. **Read this first for any non-trivial change.**
- `REQUIREMENTS.md` — REQ-IDs with traceability to phases (SCAF-*, CRYPTO-*, IDENT-*, TRANS-*, PAYL-*, SEND-*, RECV-*, RCPT-*, CLI-*, DOC-*).
- `ROADMAP.md` — 4 coarse phases for the walking-skeleton milestone.
- `STATE.md` — current phase / plan position, last-activity cursor.
- `research/` — STACK, FEATURES, ARCHITECTURE, PITFALLS, SUMMARY. **Treat `research/SUMMARY.md` and `research/PITFALLS.md` as load-bearing** — they contain the 15 skeleton-lock-in decisions.
- `config.json` — workflow settings (coarse granularity, interactive mode, parallel plans, balanced model profile, research + plan-check + verifier all on).

**Lock-in reminders (from `research/PITFALLS.md`, propagated to `REQUIREMENTS.md`):**

- Canonical JSON = **RFC 8785 (JCS) via `serde_canonical_json`**. `serde_json` alone is NOT canonical.
- HKDF info strings = **`cipherpost/v1/<context>`**. Never empty, never `None`.
- Argon2id params live in the **identity file header (PHC string)**, never hardcoded.
- `chacha20poly1305` usage only via `age` — no direct calls.
- Every key-holding struct uses `Zeroize` / `secrecy::SecretBox`. **Ban `#[derive(Debug)]` on secret holders.**
- Dual-signature verification: **outer PKARR sig before decrypt; inner Ed25519 sig gates every surfaced field.**
- Signed receipt published only **after** acceptance AND post-decrypt inner-sig verify.
- Identity path = `~/.cipherpost/`, mode `0600`.
- Default TTL = **24 hours** (PRD's 4h was revised after DHT-latency research).
- Async runtime: **none at the cipherpost layer.** Use `pkarr::ClientBlocking`; no direct `tokio` dep.
- `ed25519-dalek =3.0.0-pre.5` exact pin is load-bearing (pkarr 5.0.3 depends on `^3.0.0-pre.1`; no stable 3.x exists yet).

**Common GSD commands:**

- `/gsd-progress` — where are we, what's next
- `/gsd-plan-phase <n>` — create detailed plan for phase n
- `/gsd-execute-phase <n>` — execute a planned phase
- `/gsd-discuss-phase <n>` — clarify phase scope before planning
- `/gsd-next` — auto-advance to the next logical step

Planning docs are committed to git (see `.planning/config.json`). Atomic commits per phase/plan are the norm.
