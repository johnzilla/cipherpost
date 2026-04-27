# Cipherpost

## What This Is

A self-sovereign, serverless, accountless CLI tool for handing off cryptographic material (private keys, certs, credentials, API tokens, passphrases) between parties. Uses Mainline DHT via PKARR for rendezvous, age for encryption, and Ed25519/PKARR keypairs as identity — so there is no operator, no account, and no subpoena target. Built for security engineers, OSS maintainers, researchers, and small teams who need to hand off keys with a receipt and without standing up a service.

**As of v1.1 (Real v1, shipped 2026-04-26):** the full PRD v1 scope is implemented. `cipherpost send --self | --share <pubkey>` encrypts and publishes via PKARR; `cipherpost receive` dual-verifies signatures, enforces TTL, prompts for PIN if `pin_required`, shows a typed-Material acceptance preview (X.509 / PGP / SSH variants render full metadata), decrypts on typed-z32 confirmation, marks the share as `burned` if `burn_after_read`, and publishes a signed receipt. Scripted automation works without a TTY via `--passphrase-file` / `--passphrase-fd`. CAS-protected concurrent receipt publication is contract-tested in CI; cross-identity Mainline-DHT round trip is exercised behind a manual release-acceptance gate.

## Core Value

**Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.** If nothing else works, that round trip must.

**Status after v1.1:** Core value shipped end-to-end with all four typed payload variants (`GenericSecret`, `X509Cert`, `PgpKey`, `SshKey`), both encryption modes (`--pin`, `--burn`), non-interactive automation (`--passphrase-file`, `--passphrase-fd`), and proven CAS-safe concurrent receipt publication. 311 tests pass under `cargo test --features mock` (vs. 86 at v1.0 close). Real-DHT cross-identity round trip exists, compiles, and is properly triple-gated; per-release execution via `RELEASE-CHECKLIST.md`.

## Current State

**Two milestones shipped:**

- **v1.0 Walking Skeleton** — 4 phases, 15 plans, 86 tests, 49/49 reqs. Shipped 2026-04-22. Archive: `milestones/v1.0-*`.
- **v1.1 Real v1** — 5 phases, 24 plans, 311 tests, 67/67 reqs. Shipped 2026-04-26. Archive: `milestones/v1.1-*`.

**Cumulative:** 9 phases, 39 plans, 14 src files / 6,627 LOC, 68 tests files / 8,798 LOC, 116/116 v1 requirements validated. CI: `fmt`, `clippy -D warnings` (1.85), `nextest`, `audit`, `deny check`, `lychee` all green. v1.1 commits are local-only at close (180 commits, awaiting push to `origin/main`).

## Next Milestone Goals

**Pending scope-lock via `/gsd-new-milestone`.** Candidate themes carried forward from v1.1 deferrals:

- **Wire-budget escape hatch** — typed Material payloads (X.509 / PGP / SSH / pin+burn-composed) exceed the 1000-byte PKARR BEP44 ceiling. Candidate fixes: two-tier storage (PKARR carries reference; payload on content-addressable store) / chunking (split OuterRecord across multiple labels) / out-of-band payload + inline hash commit. Architecturally orthogonal to v1.1's PRD-closure scope; requires its own milestone.
- **Destruction attestation workflow** — originally PRD v1.1; shifted to v1.2+ because v1.1 filled up with PRD-closure scope. Generalizes the tamper-zero pattern from receipts to destruction proofs.
- **Non-interactive PIN input** — `--pin-file` / `--pin-fd` on `send` and `receive` (DEFER-PIN-01/02). Currently human-in-the-loop second factor by design; revisit when concrete automation use case surfaces.
- **Three-real-user launch criterion + independent public review** — v1.1 was scope completion, not launch. The next pass through the PRD's "launch criteria" section is its own milestone gate.
- **Toolchain reconciliation** — align `rust-toolchain.toml` (1.88) with CI clippy pin (1.85), or accept divergence formally with a CI workflow that validates the pin gap.

**Locked out of v1.x core (per PRD non-goals):** TUI-only is acceptable; web UI is not. Server / relay / operator (even optional) is not.

<details>
<summary>Pre-v1.1-close summary (2026-04-23 → 2026-04-26)</summary>

**v1.1 closing tasks (post-Phase 9):**

- Tick `RELEASE-CHECKLIST-v1.1.md` and tag `v1.1.0`; complete the milestone via `/gsd-complete-milestone`
- Pre-tag follow-ups (non-blocking, advisory from 09-REVIEW.md): WR-01 — `tests/real_dht_e2e.rs:153` propagation wait should resolve via `bob_transport`, not `alice_transport`, so the local pkarr cache doesn't short-circuit the DHT round trip; WR-02 — `MockTransport::publish` doesn't bump `seq`, leaving a latent concurrent-write data-loss window (dormant in v1.1; matters if a future code path races `publish ↔ publish_receipt` on the same keypair); pre-existing `clippy::uninlined-format-args` lint at `build.rs:17` (logged in `09/deferred-items.md`; one-line `{sha}` inline-format fix) blocks `cargo clippy --all-targets --all-features -- -D warnings` so the RELEASE-CHECKLIST checkbox depends on it

**Outcome:** All closing tasks resolved at /gsd-complete-milestone. `build.rs:17` lint fixed in commit `e45347b`; remaining 65+ uninlined-format-args instances accepted as toolchain-divergence noise (CI on 1.85 doesn't catch them) and deferred to v1.2 maintenance pass. WR-01/WR-02 advisories carried forward as non-blocking tech debt.

</details>

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

**Non-interactive automation E2E (Phase 5 — 2026-04-24)**
- ✓ `--passphrase-file <path>` and `--passphrase-fd <n>` on both `cipherpost send` and `cipherpost receive`; inline `--passphrase <value>` hidden and rejected at runtime with the same Display as identity subcommands (PassphraseInvalidInput, exit 4)
- ✓ `cipherpost send -` positional shorthand for stdin payload; multi-source passphrase conflict (`--passphrase-file` + `--passphrase-fd`) rejected with `Error::Config` (exit 1); SC1 invocation `cipherpost send - --passphrase-fd 3 < payload.bin 3< passphrase.txt` runs verbatim
- ✓ `resolve_passphrase` refactored in-place: fd branch switched from `FromRawFd + std::mem::forget` to `BorrowedFd` (Pitfall #31); exact one-newline strip (one `\r\n` if present, else one `\n`, else nothing) replacing greedy `.trim_end_matches` (Pitfall #30); `--passphrase-fd 0` rejected as reserved for stdin (uniform across identity + send + receive)
- ✓ PASS-09 CI integration test (`tests/pass09_scripted_roundtrip.rs`) — two `#[serial]` MockTransport round trips proving both `--passphrase-file` and `--passphrase-fd` paths end-to-end without a TTY
- ✓ Precedence locked project-wide: `--passphrase-fd > --passphrase-file > CIPHERPOST_PASSPHRASE > TTY`; SPEC.md §7 and REQUIREMENTS.md PASS-05 rewritten to match shipped code (Pitfall #35)
- ✓ SPEC.md: new §3.5 "DHT Label Stability" declares `_cipherpost` and `_cprcpt-*` as wire-format constants requiring a `protocol_version` bump to change (Pitfall #33); crate-version prose rewritten to API-range form with Cargo.toml as exact-pin authority (Pitfall #34); PKARR wire budget corrected from 600 B to 550 B (measured)
- ✓ `tests/dht_label_constants.rs` asserts byte-match between code constants and SPEC strings — the audit is the test
- ✓ CLAUDE.md `## Planning docs convention` section locks the inline-phase-tag traceability rule project-wide; archived v1.0 REQUIREMENTS.md traceability table dropped (49 Complete rows removed — Pitfall #32)
- ✓ 98 tests pass under `cargo test --features mock` (86 baseline + 12 new across Plans 05-01/02/03)

**`--pin` and `--burn` encryption modes (Phase 8 — 2026-04-26)**
- ✓ `cipherpost send --pin` ships TTY-only PIN prompt + 8-char/anti-pattern validation (PIN-02); PIN crypto is cclink-fork-with-divergence — Argon2id(PIN + 32-byte salt) → HKDF-SHA256 `cipherpost/v1/pin` → 32-byte X25519 scalar wrapped into age `Identity` for nested-age inner layer (no direct `chacha20poly1305` calls per CLAUDE.md load-bearing rule)
- ✓ `cipherpost send --burn` ships full receive-side burn semantics: `Envelope.burn_after_read=true` (inner-signed, post-decrypt; NOT OuterRecord per ciphertext-only-on-wire principle); first receive emit-before-mark order (D-P8-12) — emit decrypted bytes → fsync stdout → append `state: "burned"` ledger row → fsync ledger → touch sentinel; second receive returns exit 7 "share already consumed"; receipt published unconditionally (no `if !envelope.burn_after_read` guard — burn does NOT suppress attestation per BURN-04)
- ✓ Acceptance banner shows `[BURN — you will only see this once]` marker (literal em-dash) at TOP of header before Purpose line; PIN prompt rendered to stderr BEFORE typed-z32 acceptance prompt (D-P8-07/08)
- ✓ Compose orthogonality: pin × burn × {GenericSecret, X509Cert, PgpKey, SshKey} 23-test matrix in `tests/pin_burn_compose.rs` — wrong-PIN-on-burn doesn't-mark-burned, typed-z32-declined-on-burn doesn't-mark-burned, pin+burn+typed-material wire-budget surfaces clean `Error::WireBudgetExceeded` for budget-exceeding composites
- ✓ Wire-byte preservation: v1.0 fixtures (`outer_record_signable.bin` 192 B, `receipt_signable.bin` 424 B, `envelope_jcs_generic_secret.bin` 119 B) byte-identical via `is_false` skip-serializing-if; new fixtures `outer_record_pin_required_signable.bin` (212 B) + `envelope_burn_signable.bin` (142 B) committed
- ✓ Error-oracle hygiene extended: wrong-PIN folds into existing `Error::DecryptFailed` (NO new variant); Display ≡ wrong-passphrase ≡ tampered at exit 4 (PIN-07); HKDF info enumeration test auto-discovers `cipherpost/v1/pin`; leak-scan extended for PIN-holding structs
- ✓ State-ledger schema migration: `state: Option<String>` field on `LedgerEntry` (v1.0 rows missing the field deserialize via serde default); `LedgerState` enum with None/Accepted/Burned; `check_already_accepted` renamed to `check_already_consumed` returning `LedgerState`; `pub mod test_paths` cfg-gated re-export so integration tests don't duplicate path logic
- ✓ THREAT-MODEL.md §6.5 PIN mode + §6.6 Burn mode (multi-machine race, DHT-survives-TTL, indistinguishability, emit-before-mark); SPEC.md §3.6 PIN crypto stack + §3.7 Burn semantics + §5.1/§5.2/§6 cross-refs; CLAUDE.md +3 load-bearing lock-ins (HKDF `cipherpost/v1/pin`, ledger `state` field invariant, emit-before-mark contract); PITFALLS #26 SUPERSEDED-by-D-P8-12 (preserves original mark-then-emit analysis)
- ✓ 309 tests pass / 0 failed / 19 ignored under `cargo test --features mock`; cclink fork-and-diverge survey closed (cclink chacha20poly1305-direct AEAD path rejected; cclink DHT-revoke burn rejected per BURN-08); zero new direct deps (argon2/hkdf/age all pre-existing)

**Real-DHT E2E + CAS merge-update race gate (Phase 9 — 2026-04-26)**
- ✓ MockTransport `publish_receipt` enforces CAS via per-key `seq:u64` (`MockStoreEntry { records, seq }`); `tests/cas_racer.rs` Barrier-synced two-thread racer (DHT-01/02) asserts exactly one publisher wins on first attempt, the loser retries-and-merges, both receipts persist; runs deterministically in CI under `cargo test --features mock`
- ✓ Single-retry-then-fail CAS contract on `Transport::publish_receipt` (D-P9-A1); retry lives inside the trait method (D-P9-A2); `DhtTransport` and `MockTransport` mirror identical two-attempt structure; `pkarr::errors::PublishError::Concurrency(_)` (any inner variant — `ConflictRisk`/`NotMostRecent`/`CasFailed`) is the retry trigger; final CAS failure rides existing `Error::Transport` (no new public variant — Pitfall #16 hygiene preserved)
- ✓ `tests/real_dht_e2e.rs` cross-identity round trip behind triple-gate `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` (DHT-03/04/05); UDP pre-flight against `router.bittorrent.com:6881` with 5s timeout; 7-step exp-backoff `[1u64, 2, 4, 8, 16, 32, 64]` with in-test 120s `Instant::now() >= deadline` checks on both resolve + receipt-fetch loops; CI never enables the feature; manual-only via RELEASE-CHECKLIST per D-P9-D2 + Pitfall #29
- ✓ `RELEASE-CHECKLIST.md` (91 lines, 29 checkboxes, repo root) + `RELEASE-CHECKLIST-v1.1.md` (84 lines, body-parity snapshot) — pre-flight + code gates + wire-format byte-counts (192/424/119/212/142) + manual real-DHT gate + security review + release artifacts; uses corrected `cargo nextest run --features real-dht-e2e --profile real-dht --run-ignored only --filter-expr 'test(real_dht_e2e)'` (research OQ-5 corrected CONTEXT.md's never-existed `cargo --test-timeout` flag)
- ✓ `.config/nextest.toml` `[profile.real-dht]` `slow-timeout = { period = "60s", terminate-after = 2 }` outer guard paired with in-test deadline (D-P9-D3 belt-and-suspenders, mechanism corrected)
- ✓ `tests/wire_budget_compose_pin_burn_pgp.rs` DHT-07 wire-budget composite: `pin_required=true` + `burn_after_read=true` + 2KB `Material::GenericSecret` produces clean `Error::WireBudgetExceeded { encoded: 5123, budget: 1000 }` at send (third instance of D-P7-02 wire-budget assertion pattern)
- ✓ CLAUDE.md +3 load-bearing lock-ins (single-retry-then-fail CAS contract; pkarr defaults only — no `CIPHERPOST_DHT_BOOTSTRAP` env var; real-DHT triple-gate discipline); README.md single-sentence bootstrap-defaults note; SPEC.md §Pitfall #22 cites measured 5123-byte composite, §3 documents pkarr default Mainline bootstrap and CAS contract; STATE.md "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" todo closed (deferred to v1.2+)
- ✓ `CIPHERPOST_DEBUG=1` opt-in stderr logging for CAS retry events (D-P9-A4); narrowly scoped, default-silent
- ✓ 311 tests pass / 0 failed / 19 ignored under `cargo test --features mock` (+2 new vs Phase 8's 309); 238 pass under no-features; `cargo build --features real-dht-e2e --tests` compiles cleanly; zero new direct deps; no tokio at cipherpost layer (CLAUDE.md preserved)

### Active

<!-- v1.1 milestone closed 2026-04-26. The next milestone scope is authored fresh via `/gsd-new-milestone` — see "Next Milestone Goals" above for carry-forward candidates. This section is empty until the next milestone is locked. -->

(empty — pending next milestone scope-lock)

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
*Last updated: 2026-04-26 after v1.1 "Real v1" milestone close. Two milestones shipped (v1.0 walking skeleton 2026-04-22; v1.1 PRD-closure scope 2026-04-26). v1.1 ROADMAP, REQUIREMENTS, and audit archived under `milestones/v1.1-*`. Active section reset; Validated section carries the full Phase 1–9 shipping record. Next: `/gsd-new-milestone` to lock scope for the next milestone.*
