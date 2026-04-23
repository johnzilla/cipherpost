# Cipherpost

## What This Is

A self-sovereign, serverless, accountless CLI tool for handing off cryptographic material (private keys, certs, credentials, API tokens, passphrases) between parties. Uses Mainline DHT via PKARR for rendezvous, age for encryption, and Ed25519/PKARR keypairs as identity — so there is no operator, no account, and no subpoena target. Built for security engineers, OSS maintainers, researchers, and small teams who need to hand off keys with a receipt and without standing up a service.

**As of v1.0 (walking skeleton):** the end-to-end round trip works. `cipherpost send --self | --share <pubkey>` encrypts a generic-secret payload, publishes via PKARR; `cipherpost receive` dual-verifies signatures, enforces TTL, shows a full-fingerprint acceptance screen, decrypts on typed-z32 confirmation, and publishes a signed receipt the sender can independently verify via `cipherpost receipts --from <z32>`.

## Core Value

**Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.** If nothing else works, that round trip must.

**Status after v1.0:** Core value shipped end-to-end and exercised by 86 tests, including a two-identity Phase 3 E2E under MockTransport (SC1–SC4 all pass). Real-DHT cross-identity round trip is documented tech debt (see Context).

## Current Milestone: v1.1 Real v1

**Goal:** Close the PRD's full v1 scope (all payload types + pin/burn modes) and de-risk the protocol over real Mainline DHT — so cipherpost is no longer just a walking skeleton under MockTransport.

**Target features** (phases continue from v1.0's Phase 4 → Phases 5–9):

- **Phase 5 — Non-interactive automation E2E**: `--passphrase-file` / `--passphrase-fd` on `send` + `receive` (aligns with identity subcommands); bless shipped pin versions in SPEC/REQUIREMENTS; DHT label audit; collapse traceability-table to single source of truth so "Pending" drift can't recur. User-visible deliverable: scripted send/receive works without a TTY, proved by CI recipe + integration test.
- **Phase 6 — Typed Material: `X509Cert`**: pattern-establish one variant end-to-end (parse / validate / render / test).
- **Phase 7 — Typed Material: `PgpKey` + `SshKey`**: apply the X509 pattern. 64 KB plaintext cap held; `PgpKey` = single key, not keyring.
- **Phase 8 — `--pin` and `--burn` encryption modes**: on top of now-typed payloads. Research must first survey `/home/john/vault/projects/github.com/cclink` for existing pin/burn logic — fork-and-diverge, don't re-derive.
- **Phase 9 — Real-DHT E2E + merge-update race**: cross-identity Mainline-DHT round trip as release-acceptance gate; explicit concurrent-racer test for PKARR `cas` merge-republish.

**Design rules held over from v1.0:** coarse granularity (every phase ends at a user-visible capability), 64 KB plaintext cap, error-oracle hygiene, tamper-zero invariants, JCS wire-format lock-in, no async runtime at cipherpost layer.

**Solo-builder hygiene:** zero "Pending" rows in traceability — checkboxes and table stay in sync, or one of them goes away.

## Requirements

### Validated

<!-- Shipped and confirmed valuable. -->

**Foundation (Phase 1 — 2026-04-21)**
- ✓ User can generate an Ed25519/PKARR keypair and store it on disk passphrase-wrapped (Argon2id + HKDF-SHA256 with `cipherpost/v1/<context>` domain separation; Argon2 params live in PHC-format identity-file header, not hardcoded)
- ✓ User can unlock an existing identity with their passphrase; wrong passphrase returns exit 4; identity files at mode > 0600 are refused
- ✓ `identity generate` prompts for passphrase twice (dialoguer `with_confirmation`); UAT-driven fix — a single-prompt typo would have bricked the Argon2id-wrapped key with no recovery path
- ✓ Rust crate scaffold with exact cclink v1.3.0 crypto pins (`pkarr 5.0.3`, `ed25519-dalek =3.0.0-pre.5`, `age 0.11`), no `tokio` dep, plain `fn main()`, CI runs `fmt --check`, `clippy -D warnings`, `nextest`, `audit`, `deny check`
- ✓ `Transport` trait with `publish` / `resolve` / `publish_receipt` method signatures; `DhtTransport` over `pkarr::ClientBlocking` + `MockTransport` gated by `#[cfg(any(test, feature = "mock"))]` for integration tests without real DHT
- ✓ `OuterRecord` / `OuterRecordSignable` wire schema locked via committed JCS fixture (`tests/fixtures/outer_record_signable.bin`); 128-bit `share_ref`; protocol version 1
- ✓ Error-oracle hygiene: single `thiserror` enum with `#[source]` chains preserved but never Displayed to stderr; all signature-failure variants share one identical user-facing message and exit code 3
- ✓ 23 tests green in parallel (Pitfalls #1, #4, #7, #8, #9, #13, #15 each have a prevention test)

**Send/receive/acceptance (Phase 2 — 2026-04-21)**
- ✓ `cipherpost send --self` publishes a self-encrypted generic-secret via PKARR SignedPacket; `cipherpost receive` retrieves and decrypts it on the same identity
- ✓ `cipherpost send --share <pubkey>` age-encrypts to recipient's X25519 (derived from Ed25519); recipient decrypts via `cipherpost receive` using their own identity
- ✓ Dual-signature verification (outer PKARR + inner Ed25519 on JCS bytes) is required before *any* age-decrypt; tampering at either layer aborts with exit code 3 and no envelope field reaches stdout/stderr
- ✓ `Envelope` / `Material::GenericSecret` payload schema with JCS round-trip determinism; `Material::X509Cert`/`PgpKey`/`SshKey` reserved (unimplemented)
- ✓ Free-text purpose binding on every share; sender-attested (PITFALLS #16 — flagged in THREAT-MODEL.md as "not independently verified")
- ✓ Acceptance screen on stderr: sender fingerprints (OpenSSH + z32), control-stripped purpose, TTL remaining (local + UTC), payload type + size; requires typed-z32 confirmation or exit 7
- ✓ Default TTL 24h (revised from PRD's 4h after DHT-latency research); `--ttl` override honored; inner-signed `created_at + ttl_seconds` expiry yields exit 2
- ✓ 64 KB plaintext cap; oversize rejection names actual + limit; idempotent re-receive via state ledger (no second decrypt, no duplicate receipt)
- ✓ CLI ergonomics: `--help` examples per subcommand, `version` prints crate + git SHA + primitives, `-` stdin/stdout, status → stderr, full exit-code taxonomy {0, 2, 3, 4, 5, 6, 7, 1}, fuzz-verified no secret bytes in stderr

**Signed receipt — the cipherpost delta (Phase 3 — 2026-04-21)**
- ✓ `Receipt` / `ReceiptSignable` wire schema locked via committed JCS fixture (`tests/fixtures/receipt_signable.bin`, 424 bytes); 128-bit nonce; recipient-signed with Ed25519; verified with `verify_strict` + round-trip-reserialize guard
- ✓ `run_receive` step 13 publishes a signed receipt to the DHT under the recipient's PKARR key at DNS label `_cprcpt-<share_ref>`; tampering between outer verify and acceptance aborts before step 13 so zero receipts are published (MockTransport-verified)
- ✓ `DhtTransport::publish_receipt` uses resolve-merge-republish so a recipient's existing outgoing share (`_cipherpost`) and prior receipts (`_cprcpt-*`) coexist after a new receipt is published (no clobber)
- ✓ `cipherpost receipts --from <z32>` fetches + verifies + renders structured output; `--share-ref <hex>` returns a 10-field audit-detail view; `--json` emits pretty JSON on stdout; passphrase-free dispatch (D-OUT-04)
- ✓ 4 integration tests cover all ROADMAP success criteria (SC1 tamper-zero-receipts, SC2 filter, SC3 coexistence, SC4 two-identity E2E); 86 tests pass under `cargo test --features mock`

**Protocol documentation drafts (Phase 4 — 2026-04-22)**
- ✓ `SPEC.md` covers `Envelope`/`Material` schema, RFC 8785 JCS rules + reference vector, dual signature formats, share URI, DHT labels (`_cipherpost`, `_cprcpt-<share_ref>`), `share_ref` derivation, TTL semantics, full exit-code taxonomy, non-interactive passphrase contract (env/file/fd; argv-inline rejected)
- ✓ `THREAT-MODEL.md` enumerates adversaries + defenses for identity compromise, DHT adversaries (sybil, eclipse, replay), purpose-as-sender-attested with false-purpose example, acceptance-UX fatigue, receipt replay, passphrase-prompt MITM, and a bounded out-of-scope adversary section
- ✓ `SECURITY.md` documents disclosure channel (live-tested and recorded), 90-day embargo, cclink lineage + `cipherpost/v1/<context>` HKDF prefix reference
- ✓ `lychee` link-check CI job (pinned 0.21.0 for project rustc 1.85.1) blocks broken cross-references in future doc changes

### Active

<!-- Milestone v1.1 "Real v1" — finish the PRD's full v1 scope and de-risk the protocol on real Mainline DHT. Full requirements with REQ-IDs in .planning/REQUIREMENTS.md; phase structure in .planning/ROADMAP.md. -->

v1.1 delivers (see `## Current Milestone` above for phase structure):

- **Non-interactive passphrase flags** on `send` / `receive` — `--passphrase-file`, `--passphrase-fd` (align with identity subcommands; `resolve_passphrase()` already supports all four priorities — this is clap surface + plumbing only)
- **All three remaining `Material` variants** — `X509Cert`, `PgpKey` (single key, not keyring), `SshKey`
- **`--pin` and `--burn` encryption modes** on typed payloads
- **Real-DHT cross-identity round trip** + explicit PKARR `cas` merge-update race test as release-acceptance gate
- **Pin-version reality-check in docs** (`serde_canonical_json 1.0.0`, `pkarr 5.0.4`, 550 B budget — bless shipped reality, don't re-pin)
- **DHT label audit** (`_cipherpost`, `_cprcpt-<share_ref>`) + **traceability-table drift eliminated** (checkboxes and table stay in sync or one of them goes away)

### Out of Scope

<!-- Explicit boundaries. Includes reasoning to prevent re-adding. -->

**Deferred to v1.2+ (reclassified during v1.1 scope-lock 2026-04-23):**
- TUI wizard — CLI + non-interactive automation cover primary use cases; TUI waits on demand signal
- Exportable local audit log for compliance evidence — surface depends on first real enterprise contact, not pre-designed
- Destruction attestation workflow — originally PRD v1.1, shifted because v1.1 filled up with PRD-closure scope (pin/burn + typed payloads + real-DHT)
- Three-real-user launch criterion and independent public review — v1.1 is still scope completion, not launch

**Deferred further (PRD milestones):**
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

**Architectural lineage.** Cipherpost is a generalization of `cclink` (https://github.com/johnzilla/cclink) focused on keyshare workflows rather than Claude Code session handoff. The crypto and transport primitives are reused unchanged (Ed25519/PKARR, age, Mainline DHT, Argon2id KDF, dual signatures). The delta from cclink is at the payload and flow layer: typed payload schema, explicit acceptance step, signed receipt, keyshare-oriented CLI.

**cclink is mothballed.** No further development. Treated as a reference/source repo only. The skeleton work cloned `johnzilla/cclink` and vendored its crypto + DHT modules directly into this repo (fork-and-diverge), not as a live sibling crate.

**Walking skeleton shipped 2026-04-22.** 4 phases, 15 plans, 117 commits over ~48 hours. 3,543 LOC in `src/` (11 files), 6,407 LOC including `tests/` (46 files total). 86 tests pass under `cargo test --features mock`; CI green on `fmt`, `clippy -D warnings`, `nextest`, `audit`, `deny check`, and `lychee` link-check. The binary at `target/release/cipherpost` performs a full self-send round trip and signed-receipt round trip under MockTransport; manual TTY interactive UAT (IDENT-01 passphrase-prompt) verified on-host.

**Known tech debt at close:**
- Crate-pin drift — `serde_canonical_json 1.0.0` shipped instead of planned `0.2` (API matches); `pkarr 5.0.4` pulled instead of pinned `5.0.3` (transitive resolution); PKARR blob budget measured at 550 bytes (vs planned 600). All documented in `01-VERIFICATION.md`, functionally correct.
- Real-DHT A→B→receipt round trip across two physical identities never executed; MockTransport exercises the full code path but cannot reach Mainline DHT. Documented as `reason_documented` in the milestone audit.
- PKARR SignedPacket merge-update race under concurrent receipt publication uses `cas` (compare-and-swap) but has no explicit concurrent-racer test; not triggered by walking-skeleton usage.
- Test advisory `GHSA-36x8-r67j-hcw6` left in draft state as a permanent reproducibility record.
- Traceability-table rows in the archived `REQUIREMENTS.md` retained "Pending" labels for Phase 2/4 requirements that were body-checked and fully verified in phase VERIFICATION reports — bookkeeping, not coverage.

**Domain lineage.** The underlying protocol (E2E-encrypted payloads published to Mainline DHT via PKARR SignedPacket, age for payload encryption, Ed25519 for identity) was already exercised in `cclink`. Generalizing into keyshare was a small delta on existing code — protocol is unchanged, flow/semantics differ.

## Constraints

- **Language & shape**: Rust crate + CLI binary, MIT-licensed — follows PRD and cclink lineage.
- **No servers**: Rendezvous is Mainline DHT only. Any proposal introducing an operator (even optional) is out of scope for v1.x core. Relay-assist is a *possible later commercial feature*, not an option here.
- **Key is identity**: No accounts, no email verification, no logins. Ed25519/PKARR keypair is the only identity.
- **Ciphertext only on the wire**: Both payload and metadata are encrypted; the DHT sees only opaque blobs.
- **Attestation first-class**: Receipt, destruction (v1.1), and purpose binding are core features, not afterthoughts.
- **Ship narrow**: Primitive first, workflows second. Enterprise features only if demand is proven.
- **Payload ceiling**: 64 KB plaintext.
- **Default TTL**: 24 hours (revised from PRD's 4h after research showed Mainline DHT p50 lookup ≈ 1 minute with a long tail).
- **Crypto choices (locked, conservative)**: age (X25519 derived from Ed25519), Argon2id (64 MB, 3 iter), HKDF-SHA256 with domain separation, dual signatures. Do not substitute.
- **Source of truth for primitives**: `johnzilla/cclink` on GitHub — fork code in, do not re-derive from scratch.

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| Lock name as "Cipherpost" | PRD working name; cost of renaming compounds the later it slips; alternatives (keyshare, dropkey, sigpost) rejected for now | ✓ Good (shipped as `cipherpost` throughout v1.0 walking skeleton) |
| Fork-and-diverge from cclink, no shared core crate | cclink is mothballed — no active sibling to share a crate with; fork-and-diverge is lower overhead than extracting a library from a dead project | ✓ Good (v1.0 shipped with full fork; no re-derivation needed) |
| Milestone target = walking skeleton, not full v1.0 | Validate the cclink extraction + the cipherpost-specific receipt flow end-to-end before committing to v1.0 breadth (TUI, all four modes, all payload types) | ✓ Good (scope held; walking skeleton shipped in ~48h, validated end-to-end before broadening) |
| Skeleton includes signed receipt, not just self/share | The receipt is the cipherpost delta from cclink. A skeleton without it just validates cclink, not cipherpost. | ✓ Good (Phase 3 — JCS-locked Receipt + resolve-merge-republish + `cipherpost receipts` dispatch all shipped; SC1–SC4 pass) |
| Skeleton uses generic-secret payload type only | Other typed payloads (X.509, PGP, SSH) add parsing complexity without changing protocol shape; schema reserves them for the next milestone | ✓ Good (Phase 2 — `Envelope` schema with `Material` tag enum; `X509Cert`/`PgpKey`/`SshKey` return `unimplemented` until the next milestone) |
| SPEC/THREAT-MODEL/SECURITY as drafts in skeleton | Writing them forces design clarity during skeleton work; final versions gate a public v1.0, not the walking skeleton | ✓ Good (Phase 4 — all three shipped; `lychee` CI pins cross-ref validity; live-tested disclosure channel) |
| Default TTL = 24h (PRD said 4h) | Research showed Mainline DHT p50 lookup ~1 min with long tail; 4h default would routinely expire before pickup | ✓ Good (Phase 2 — `DEFAULT_TTL_SECONDS = 86400`; `--ttl` override works; expiry yields exit 2) |
| Canonical JSON = RFC 8785 (JCS) via serde_canonical_json | Future-proof for cross-language reimplementation; abandonment-resilience (independent re-implementers can produce byte-identical signatures) | ✓ Good (Phase 1 — shipped version 1.0.0, not planned 0.2; API matches; property test + committed fixture bytes prove determinism) |
| Fingerprint display = OpenSSH-style + z-base-32 | OpenSSH `ed25519:SHA256:<base64>` matches security-engineer audience; z-base-32 is the DHT address; showing both eliminates ambiguity in acceptance screens | ✓ Good (Phase 1 `identity show` prints both; Phase 2 acceptance screen D-ACCEPT-02 banner shows both) |
| Identity path = `~/.cipherpost/` | cclink-style simple path; skeleton keeps config discovery trivial; XDG can be added later if users ask | ✓ Good (Phase 1 — `CIPHERPOST_HOME` env override for tests; mode 0600 enforced on load) |
| HKDF info namespace = `cipherpost/v1/<context>` | Domain separation from cclink; versioned so v2 can rotate without ambiguity | ✓ Good (Phase 1 — enumeration test in CI enforces; Phase 2 reserved `SHARE_SENDER`/`SHARE_RECIPIENT`/`INNER_PAYLOAD` under same prefix) |
| share_ref width = 128 bits | 16 more bytes per receipt; avoids a future protocol bump if 64-bit collision surface ever matters | ✓ Good (Phase 1 — `OuterRecordSignable` JCS fixture locks it; Phase 3 receipts index by `share_ref_hex`) |
| `Transport` trait in src/transport/ | Only architectural delta from cclink; lets integration tests use MockTransport instead of real DHT | ✓ Good (Phase 1 — `MockTransport` carried Phase 2 + 3 E2E tests without touching Mainline DHT; Phase 3 extended with `resolve_all_cprcpt`) |
| Error-oracle hygiene: single thiserror enum with identical sig-fail Display | PITFALLS #16 flagged distinguishable-oracle attacks; making all sig-verification failures surface the same user-facing message prevents distinguishing which part of the verifier tripped | ✓ Good (Phase 1 — test `lib::error::tests::signature_failure_variants_share_display` enforces; Phase 2 extended with `ShareRefMismatch`, `WireBudgetExceeded`, `InvalidShareUri` preserving the invariant) |
| serial_test for env-mutating tests | `CIPHERPOST_HOME` tests raced under Rust's default parallel test runner; `serial_test = "3"` + `#[serial]` on the 4 affected tests resolves cleanly | ✓ Good (Phase 1 — discovered post-wave, fixed in `d8fb202`) |
| Confirm-passphrase on `identity generate` (added post-UAT) | Human UAT found single-prompt flow: a silent passphrase typo would brick the newly-created Argon2id-wrapped key with no recovery path. Unlock paths (`show`/`send`/`receive`) remain single-prompt because a typo surfaces as `PassphraseIncorrect` against the existing identity. | ✓ Good (fix `2e29b74`; UAT re-verified on real TTY at milestone close) |
| `publish_receipt` uses resolve-merge-republish, not overwrite | A recipient's outgoing share (`_cipherpost`) and prior receipts (`_cprcpt-*`) coexist on the same PKARR key. Overwrite would clobber. Merge preserves all existing TXT records and appends the new receipt atomically via `cas`. | ✓ Good (Phase 3 — coexistence integration test + unconditional MockTransport + DhtTransport parity) |
| Tamper-zero-receipts invariant | Receipt is the compliance-grade artifact. A receipt published after verification fails would signal delivery of ciphertext the recipient never actually accepted — worse than no receipt. Enforced by ordering: step 13 publish happens strictly after outer verify + inner verify + typed-z32 acceptance. | ✓ Good (Phase 3 SC1 test — any byte flip between outer verify and acceptance aborts before publication; zero receipts observed on MockTransport) |
| Acceptance requires typed z32 (not y/N) | Full-string confirmation force-reads the sender's z-base-32 fingerprint off the acceptance banner, making prompt-fatigue mis-acceptance meaningfully harder. | ✓ Good (Phase 2 D-ACCEPT-02 banner + D-ACCEPT-03 TTY pre-check; documented in THREAT-MODEL.md acceptance-UX section) |

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
*Last updated: 2026-04-23 at v1.1 "Real v1" milestone kickoff — scope locked via `/gsd-new-milestone` (5 phases: automation E2E + X509 + PGP/SSH + pin/burn + real-DHT gate). v1.0 archived at `.planning/milestones/v1.0-*`.*
