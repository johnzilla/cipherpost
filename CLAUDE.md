# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository status

**v1.0 Walking Skeleton shipped 2026-04-22.** The repo is a single Rust crate (`cipherpost`) that builds a CLI binary. MIT-licensed. No shared `cipherpost-core` crate — that was considered and explicitly rejected at project kickoff (cclink is mothballed, no second consumer exists to justify the split).

Build / test / lint commands:

```bash
cargo build --release                  # release binary: ./target/release/cipherpost
cargo test                             # unit + doc tests (no DHT-touching tests)
cargo test --features mock             # + MockTransport integration tests (86 tests at v1.0)
cargo fmt --check                      # CI-enforced
cargo clippy -- -D warnings            # CI-enforced
cargo audit                            # CI-enforced (deny.toml policy)
cargo deny check                       # CI-enforced supply-chain policy
```

CI runs all of the above plus `lychee` link-check across `SPEC.md`, `THREAT-MODEL.md`, `SECURITY.md`, and `README.md`. The binary is a plain `fn main()` — there is no `tokio` dependency at the cipherpost layer (uses `pkarr::ClientBlocking`).

## What Cipherpost is

A self-sovereign, serverless, accountless CLI for handing off cryptographic material (private keys, certs, credentials, API tokens, passphrases) between parties. Positioned in the whitespace between generic secret-sharing apps (Bitwarden Send, 1Password Sharing, SendSafely) and enterprise KMS platforms. The defensible combination is: **no server + accountless + attestation primitives + purpose-built for cryptographic material**.

## Architectural lineage: fork-and-diverge from cclink

**Read this before making any design decisions.** Cipherpost is not a new protocol — it was vendored from [`cclink`](https://github.com/johnzilla/cclink) (now mothballed) and specialized for keyshare workflows. The crypto and transport primitives were reused unchanged:

- **Identity:** Ed25519/PKARR keypair, passphrase-wrapped on disk (Argon2id 64MB, 3 iter + HKDF-SHA256 with domain separation)
- **Transport:** Mainline DHT via PKARR SignedPacket — no servers, no operator
- **Encryption:** age (X25519, derived from Ed25519). `chacha20poly1305` is only reachable via `age`; no direct calls anywhere in `src/`.
- **Signing:** Dual signatures (outer PKARR packet + inner Ed25519 over canonical JSON)

The delta from cclink (all shipped in v1.0 walking skeleton):

1. Typed payload schema — `Envelope { protocol_version, created_at, ttl_seconds, purpose, material }` with `Material::GenericSecret { bytes }` implemented. `X509Cert`, `PgpKey`, `SshKey` variants are schema-reserved and return `unimplemented` (deferred to a later milestone).
2. Explicit acceptance step — recipient sees a full-fingerprint acceptance screen on stderr and must type the sender's z-base-32 pubkey to unlock decrypt.
3. Signed receipt — recipient-signed `Receipt` published to the recipient's own PKARR key at DNS label `_cprcpt-<share_ref>` via resolve-merge-republish (coexists with outgoing shares, no clobber). Fetched + verified by the sender via `cipherpost receipts --from <z32>`.
4. CLI surface focused on key/secret handoff (`send --self | --share`, `receive`, `receipts`, `identity generate/show`, `version`).

**Repo layout (locked):** Fully independent, fork-and-diverge. No shared `cipherpost-core` crate — will only be extracted if a second consumer appears.

## Principles that constrain design

These are hard constraints from the PRD, not suggestions. Reject approaches that violate them:

1. **No servers.** Rendezvous is Mainline DHT only. Any proposal that introduces an operator (even an optional one) is out of scope. Relay-assist is explicitly flagged as a *possible later commercial feature*, not an open-source-core option.
2. **Key is identity.** No accounts, no email verification, no logins.
3. **Ciphertext only on the wire.** Both payload and metadata are encrypted; the DHT sees only opaque blobs.
4. **Attestation first-class.** Signed receipt, destruction attestation (deferred to v1.1), and purpose binding are core features, not afterthoughts.
5. **Ship narrow.** Primitive first, workflows second. Enterprise features only if demand is proven.

## Shipped vs deferred

**Shipped in v1.0 (walking skeleton, 2026-04-22):**
- `cipherpost send --self` and `cipherpost send --share <pubkey>` (generic-secret payloads)
- `cipherpost receive` with dual-signature verify → TTL → typed-z32 acceptance → decrypt → state-ledger idempotency
- `cipherpost receipts --from <z32> [--share-ref | --json]`
- `cipherpost identity generate/show` (TTY double-confirm on generate; mode-0600 enforcement)
- `cipherpost version` (crate version + embedded git SHA + crypto primitives list)
- 64 KB plaintext cap, 24-hour default TTL, `-` stdin/stdout, exit-code taxonomy {0, 2, 3, 4, 5, 6, 7, 1}
- Draft `SPEC.md`, `THREAT-MODEL.md`, `SECURITY.md` at repo root; `lychee` link-check CI

**Deferred to the next milestone (candidates — scope locked via `/gsd-new-milestone`):**
- `--pin` and `--burn` encryption modes
- `Material::X509Cert`, `Material::PgpKey`, `Material::SshKey` implementations
- TUI wizard
- Real-DHT cross-identity release-acceptance test
- Exportable local audit log for compliance evidence

**Deferred further:**
- Destruction attestation workflow (v1.1)
- Multi-recipient broadcast shares (v1.2)
- HSM integration for sender-side generation (v1.3)

**Never (per PRD non-goals):**
- Full key lifecycle management (that's a KMS) · long-term secret storage (that's a vault) · signing or crypto operations on behalf of users · incident response / CVE tracking · general file transfer · SSO / IdP federation / SIEM export · web UI

## Load-bearing lock-ins (from `research/PITFALLS.md`, enforced in code + tests)

Breaking any of these requires a protocol version bump. Don't touch without understanding why:

- Canonical JSON = **RFC 8785 (JCS) via `serde_canonical_json`** (shipped as 1.0.0 — API-compatible with the planned 0.2). `serde_json` alone is **not** canonical. Fixtures: `tests/fixtures/outer_record_signable.bin` (192 B), `tests/fixtures/receipt_signable.bin` (424 B). Property tests enforce byte-for-byte determinism.
- HKDF info strings = **`cipherpost/v1/<context>`**. Never empty, never `None`. An enumeration test walks every HKDF call-site and asserts the prefix.
- Argon2id params live in the **identity file header (PHC string)** — never hardcoded in code.
- `chacha20poly1305` usage only via `age` — no direct calls allowed.
- Every key-holding struct uses `Zeroize` / `secrecy::SecretBox`. **No `#[derive(Debug)]` on secret holders.** A leak-scan test enumerates keyed structs and asserts `format!("{:?}", x)` never contains key bytes.
- Dual-signature verification: **outer PKARR sig before age-decrypt; inner Ed25519 sig gates every surfaced field.** No envelope field (including `purpose`) may reach stdout/stderr before inner-sig verify passes.
- Signed receipt published **only after** full verification + typed-z32 acceptance. Byte-flipping between outer verify and acceptance must publish zero receipts (SC1 integration test).
- Identity path = `~/.cipherpost/` (mode 0600). `CIPHERPOST_HOME` overrides for tests.
- Default TTL = **24 hours** (PRD's 4h was revised after DHT-latency research showed Mainline DHT p50 lookup ≈ 1 minute with a long tail).
- Async runtime: **none at the cipherpost layer.** Use `pkarr::ClientBlocking`; no direct `tokio` dep.
- `ed25519-dalek =3.0.0-pre.5` exact pin is load-bearing (pkarr 5.0.3/5.0.4 depends on `^3.0.0-pre.1`; no stable 3.x exists yet).
- Error-oracle hygiene: all signature-verification errors (`Error::SignatureOuter`, `SignatureInner`, `SignatureCanonicalMismatch`) share one identical user-facing Display + exit code 3. A test enumerates variants and asserts identical messages.
- `share_ref` = 128-bit; derived as `sha256(ciphertext || created_at_be).truncate(16)`. Hex-encoded on the wire.
- Passphrase contract: argv-inline (`--passphrase <value>`) is rejected. Use `CIPHERPOST_PASSPHRASE` env, `--passphrase-file <path>` (mode 0600/0400), or `--passphrase-fd <fd>`.
- `serial_test = "3"` + `#[serial]` on any test that mutates process env (`CIPHERPOST_HOME`, etc.) — nextest parallel runner will race otherwise.

## GSD workflow

This project uses Get Shit Done (GSD) for planning and execution. Canonical state lives in `.planning/`:

- `PROJECT.md` — living project context, core value, validated/active/out-of-scope requirements, constraints, key decisions. **Read this first for any non-trivial change.**
- `ROADMAP.md` — milestone-grouped view. v1.0 phases collapsed under a `<details>` block; full archive at `milestones/v1.0-ROADMAP.md`.
- `MILESTONES.md` — shipped-version summary index.
- `RETROSPECTIVE.md` — per-milestone lessons, patterns, cross-milestone trends.
- `STATE.md` — current position, last-activity cursor, accumulated decisions.
- `research/` — STACK, FEATURES, ARCHITECTURE, PITFALLS, SUMMARY. **Treat `research/SUMMARY.md` and `research/PITFALLS.md` as load-bearing** — they contain the 15 skeleton-lock-in decisions.
- `milestones/v1.0-*` — archived ROADMAP / REQUIREMENTS / MILESTONE-AUDIT / phase execution directories for v1.0.
- `config.json` — workflow settings (coarse granularity, interactive mode, parallel plans, balanced model profile, research + plan-check + verifier + code-review all on).

Between milestones (current state), `.planning/REQUIREMENTS.md` does **not** exist — `/gsd-new-milestone` will author a fresh one scoped to the next milestone.

**Common GSD commands:**

- `/gsd-progress` — where are we, what's next
- `/gsd-new-milestone` — start next milestone cycle (questioning → research → requirements → roadmap)
- `/gsd-plan-phase <n>` — create detailed plan for phase n
- `/gsd-execute-phase <n>` — execute a planned phase
- `/gsd-discuss-phase <n>` — clarify phase scope before planning
- `/gsd-next` — auto-advance to the next logical step

Planning docs are committed to git (see `.planning/config.json`). Atomic commits per phase/plan are the norm.
