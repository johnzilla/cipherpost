# Roadmap: Cipherpost (Walking Skeleton)

## Overview

Cipherpost's walking skeleton is a fork-and-diverge from mothballed `cclink`: vendor the proven crypto/identity/transport/record primitives, then add the cipherpost delta (typed payload schema, explicit acceptance step, signed receipt). The goal of this milestone is one end-to-end round trip — sender encrypts a generic-secret payload, publishes via PKARR, recipient resolves, verifies dual signatures, accepts explicitly, decrypts, and publishes a signed receipt the sender can independently verify — all without any server and without re-deriving a single cryptographic primitive from scratch. Granularity is coarse (4 phases). Each phase ends at a visibly verifiable capability; wire-format and signed-payload lock-in is concentrated in Phase 1 so it cannot leak forward. Non-skeleton work (`--pin`/`--burn`, TUI, other payload types, destruction attestation, multi-recipient, HSM) is deferred to v1.0 and beyond per PROJECT.md.

## Phases

**Phase Numbering:**
- Integer phases (1, 2, 3, 4): Planned skeleton work
- Decimal phases (2.1, 2.2): Reserved for urgent insertions post-planning

Phases execute strictly sequentially. Within a phase, plans may run in parallel where dependencies allow.

- [x] **Phase 1: Foundation — scaffold, vendored primitives, and transport seam** - Cargo scaffold + CI; vendor crypto/identity/record/transport from cclink with domain-separated HKDF, canonical JSON (JCS), Argon2 params in file header, zeroize discipline, `Transport` trait + `MockTransport`, `share_ref` in the outer record schema. (completed 2026-04-21)
- [ ] **Phase 2: Send, receive, and explicit acceptance** - Typed `Envelope` + `Material::GenericSecret`, `cipherpost send --self` and `--share <pubkey>`, `cipherpost receive` with outer+inner signature verification before decrypt, TTL enforcement on inner signed timestamp, acceptance prompt showing full fingerprints + purpose, CLI ergonomics (exit-code taxonomy, `-` for stdin/stdout, non-interactive passphrase contract, `cipherpost version`).
- [ ] **Phase 3: Signed receipt — the cipherpost delta** - Construct, sign, and publish a `Receipt` under the recipient's PKARR key at label `_cprcpt-<share_ref>` via the resolve-merge-republish `publish_receipt` pattern, and fetch + verify receipts from the sender side with `cipherpost receipts --from <recipient-pubkey>`.
- [ ] **Phase 4: Protocol documentation drafts** - Draft `SPEC.md` (payload schema, canonical JSON, share_ref, receipt format, DHT labels, HKDF namespace, fingerprint format, exit codes, passphrase contract), draft `THREAT-MODEL.md` (identity, DHT adversaries, acceptance UX, receipt replay, purpose-as-sender-attested), `SECURITY.md` (disclosure contact + embargo).

## Phase Details

### Phase 1: Foundation — scaffold, vendored primitives, and transport seam
**Goal**: Produce a single buildable `cipherpost` crate whose vendored crypto/identity/transport/record layers are byte-compatible with `cclink` reference vectors, with every wire-format and signed-payload lock-in already correct: domain-separated HKDF info strings (`cipherpost/v1/<context>`), RFC 8785 canonical JSON (JCS) for all signable structs, Argon2id parameters persisted in the identity file header, universally zeroized secrets with no `Debug` leaks, a `Transport` trait that admits both `DhtTransport` and `MockTransport`, and an `OuterRecord` schema carrying a 128-bit `share_ref` placeholder — so that Phases 2-3 cannot re-litigate any of these decisions. This consolidates research Phases 1-3 because the crypto/transport/record locks share one skeleton-level truth: they must be correct from the first signature onward or every past signature becomes unverifiable.
**Depends on**: Nothing (first phase)
**Requirements**: SCAF-01, SCAF-02, SCAF-03, SCAF-04, SCAF-05, CRYPTO-01, CRYPTO-02, CRYPTO-03, CRYPTO-04, CRYPTO-05, CRYPTO-06, IDENT-01, IDENT-02, IDENT-03, IDENT-04, IDENT-05, TRANS-01, TRANS-02, TRANS-04, TRANS-05
**Success Criteria** (what must be TRUE):
  1. `cargo build --release` on linux/x86_64 produces a single `cipherpost` binary linked against the exact cclink v1.3.0 crypto stack (`pkarr 5.0.3`, `ed25519-dalek =3.0.0-pre.5`, `age 0.11`), with no direct `tokio` dependency in `Cargo.toml` and `main.rs` declared as plain `fn main()`.
  2. A committed cross-implementation fixture test reproduces cclink's Ed25519→X25519 conversion byte-for-byte, and a property test signs a fixed `OuterRecordSignable` via `serde_canonical_json` and asserts the produced bytes match a committed byte-array on every CI invocation; a separate compile-or-test-time guard rejects floats inside any signable struct.
  3. `cipherpost identity generate` followed by `cipherpost identity show` on a fresh machine writes `~/.cipherpost/secret_key` at mode `0600`, prints both `ed25519:SHA256:<base64>` and z-base-32 fingerprints, refuses to open the file if a test externally `chmod 0644`s it, and rejects `--passphrase <value>` as an argv-inline form while accepting `CIPHERPOST_PASSPHRASE`, `--passphrase-file`, or `--passphrase-fd`.
  4. A unit test enumerates every HKDF call-site in `src/` and asserts each uses a distinct info string prefixed by `cipherpost/v1/`, never empty or `None`; a separate test attempts `format!("{:?}", <secret>)` on every key-holding struct and asserts no underlying bytes appear in the output.
  5. An integration test using `MockTransport` (keyed by PKARR pubkey, stored in-process) publishes and resolves an `OuterRecord` without touching the real DHT, confirming the `Transport` trait exposes `publish`, `resolve`, and `publish_receipt` method signatures that production `DhtTransport` also satisfies; a separate assertion confirms a representative built `SignedPacket` fits within the PKARR/BEP44 ~1000-byte budget.
**Plans**: 3 plans

Plans:
- [x] 01-01-PLAN.md — Scaffold + CI + error enum + full CLI command tree + module stubs (Wave 1)
- [x] 01-02-PLAN.md — Crypto primitives (Ed25519↔X25519, age, Argon2id+HKDF, JCS, CIPHPOSK envelope) + Identity (generate/show/0600/PHC-header/passphrase-argv-reject) + wire identity + version commands end-to-end (Wave 2)
- [x] 01-03-PLAN.md — Transport trait (publish/resolve/publish_receipt) + DhtTransport + MockTransport (cfg-gated) + OuterRecord/OuterRecordSignable with 128-bit share_ref + JCS canonical form fixture + SignedPacket 1000-byte budget test (Wave 2)

### Phase 2: Send, receive, and explicit acceptance
**Goal**: Deliver the user-visible core round trip — a sender can hand off a generic-secret payload to themselves or a named recipient via `cipherpost send`, and a recipient can retrieve, verify both signatures before any decryption, enforce TTL on the inner signed timestamp, see a full-fingerprint acceptance screen with the sender-attested purpose, and (only on explicit typed confirmation) receive the decrypted material on stdout or `-o <path>`. This consolidates research Phases 4-7 into one coarse phase because acceptance is inseparable from the receive flow in the skeleton requirements (RECV-04 gates material surfacing inside the same code path that runs RECV-01..03), and the CLI ergonomics (`-` stdin/stdout, exit-code taxonomy, `cipherpost version`, passphrase hygiene) must land alongside the first user-visible commands or the skeleton calcifies a different answer.
**Depends on**: Phase 1
**Requirements**: PAYL-01, PAYL-02, PAYL-03, PAYL-04, PAYL-05, SEND-01, SEND-02, SEND-03, SEND-04, SEND-05, RECV-01, RECV-02, RECV-03, RECV-04, RECV-05, RECV-06, CLI-01, CLI-02, CLI-03, CLI-04, CLI-05
**Success Criteria** (what must be TRUE):
  1. An end-to-end integration test using `MockTransport` runs `cipherpost send --self` with a 10 KB generic-secret input and a `--purpose` string, then `cipherpost receive` on the same identity, and asserts the decrypted payload matches the input byte-for-byte; a second integration test with two identities A and B asserts A→B via `--share <pubkey>` decrypts on B but fails to decrypt on a third identity C.
  2. Corrupting any byte of the `SignedPacket` (outer tampering) or the inner `OuterRecordSignable` (inner tampering) causes `cipherpost receive` to abort with exit code 3 before any age-decrypt is attempted, and no envelope field (including `purpose`) appears on stdout or stderr prior to the signature check passing; a share whose inner signed `created_at + ttl_seconds` is in the past exits with code 2, distinct from the signature-failure case.
  3. `cipherpost receive <share-uri>` on a valid share prints an acceptance screen on stderr containing sender's OpenSSH-style fingerprint, sender's z-base-32, control-char-stripped purpose, TTL remaining in local+UTC, payload type, and payload size; typing anything other than the full-word confirmation returns exit code 7 with no decrypted material written; repeating `receive` on an already-accepted share reports the prior acceptance timestamp from `~/.cipherpost/state/` and neither re-decrypts nor triggers a second receipt publication.
  4. A size-cap test feeds a 65537-byte plaintext to `cipherpost send` and asserts it is rejected with a clear error that names both the actual size and the 64 KB cap; a separate test asserts that any canonical-JSON encoding of `Envelope` re-serializes to byte-identical output across encode→decode→encode, and that `Material` variants `X509Cert`/`PgpKey`/`SshKey` return `unimplemented` on encode/decode.
  5. `cipherpost --help` and every subcommand `--help` print at least one complete example; `cipherpost version` prints crate version, embedded git commit hash, and a one-line list of crypto primitives; all payload I/O accepts `-` on stdin/stdout, status/progress go to stderr, exit codes follow the documented taxonomy {0, 2, 3, 4, 5, 6, 7, 1}, and a fuzz-driven stderr scan of bad inputs contains no passphrase bytes, key bytes, or raw payload bytes.
**Plans**: 3 plans

Plans:
- [ ] 02-01-PLAN.md — Payload schema (Envelope + Material + URI + Error variants + HKDF constants + identity signing_seed accessor) (Wave 1)
- [ ] 02-02-PLAN.md — Flow orchestration (run_send + run_receive + state ledger + Prompter trait + MockTransport integration tests) (Wave 2)
- [ ] 02-03-PLAN.md — CLI wiring (main.rs dispatch + TtyPrompter + CLI integration tests for help/version/stderr-scan + HUMAN-UAT) (Wave 3)

### Phase 3: Signed receipt — the cipherpost delta
**Goal**: Deliver the feature that differentiates cipherpost from cclink — a signed receipt published to the DHT under the *recipient's* PKARR key (because only the recipient can sign under it) at a per-share label, referencing the original share by its 128-bit `share_ref`, and independently fetchable and verifiable by the sender via `cipherpost receipts`. This phase stands alone rather than merging into Phase 2 because the cipherpost thesis must be verifiable independent of self/share/accept mechanics; this is also where the only non-vendored transport extension lives (resolve-merge-republish `publish_receipt` without clobbering coexisting TXT records). Research flagged PKARR SignedPacket merge semantics as needing a small prototype; the phase owns that work.
**Depends on**: Phase 2
**Requirements**: TRANS-03, RCPT-01, RCPT-02, RCPT-03
**Success Criteria** (what must be TRUE):
  1. After acceptance completes in `cipherpost receive`, a `Receipt { share_ref, sender_pubkey, recipient_pubkey, accepted_at, nonce, ciphertext_hash, cleartext_hash, purpose, protocol_version, signature }` is signed by the recipient's Ed25519 key and published under the recipient's PKARR key at DNS label `_cprcpt-<share_ref>`, and tampering with the ciphertext between outer verify and acceptance causes zero receipts to be published on the DHT (verified via `MockTransport` inspection).
  2. `cipherpost receipts --from <recipient-pubkey>` resolves the recipient's SignedPacket, filters TXT records by the `_cprcpt-` prefix, verifies each receipt's Ed25519 signature against its canonical-JSON serialization, and prints a structured summary on stdout including share_ref, accepted_at in local+UTC, and the recipient's fingerprint; filtering with `--share-ref <ref>` returns only that specific receipt.
  3. When `publish_receipt` runs under a recipient PKARR key that already holds an outgoing share record, an integration test asserts both TXT records coexist after publish (the outgoing share is not clobbered and the receipt is findable), confirming the resolve-merge-republish pattern preserves existing packet contents.
  4. A two-identity end-to-end integration test (A sends to B via `MockTransport`, B accepts via an injected scripted-confirm `Prompter`, B publishes receipt) asserts A can fetch and cryptographically verify B's receipt using only B's public PKARR key; the same test asserts fetch works even if A simultaneously holds their own unrelated outgoing share under A's key.
**Plans**: TBD

### Phase 4: Protocol documentation drafts
**Goal**: Produce the three protocol documents that make cipherpost independently re-implementable (an explicit abandonment-resilience requirement from the research) and that make the security model legible — `SPEC.md` draft, `THREAT-MODEL.md` draft, and a working `SECURITY.md` with a real disclosure contact and embargo policy. These are drafts, not v1.0-final, but they must capture every wire-format and trust-model decision the skeleton locked in across Phases 1-3 before the knowledge goes stale in the code alone. Research explicitly flags this phase as parallelizable with Phases 8-9 in the 10-phase sequence; consolidated here it remains the final sequential phase because it depends on Phase 3 decisions being stable enough to document.
**Depends on**: Phase 3
**Requirements**: DOC-01, DOC-02, DOC-03, DOC-04
**Success Criteria** (what must be TRUE):
  1. `SPEC.md` exists at repo root and covers, in verifiable sections: `Envelope` / `Material` payload schema, RFC 8785 canonical JSON (JCS) rules with a reference test vector, outer PKARR signature + inner Ed25519 signature formats, share URI format, DHT labels (`_cipherpost` and `_cprcpt-<share_ref>`), `share_ref` derivation formula, TTL semantics (inner signed `created_at + ttl_seconds`), the full exit-code taxonomy, and the non-interactive passphrase contract (env var / file / fd; inline argv rejected).
  2. `THREAT-MODEL.md` exists at repo root and explicitly enumerates adversaries and defenses for: identity compromise, DHT adversaries (sybil, eclipse, replay), purpose as sender-attested and not independently verified (with an example false-purpose attack), acceptance UX adversaries (prompt fatigue), receipt replay, MITM on passphrase prompt, and a bounded "out of scope" adversary section.
  3. `SECURITY.md` exists at repo root with a disclosure email that round-trips a live email (verified by a committed note of the test), a stated 90-day embargo policy, and a reference to the cclink lineage including the `cipherpost/v1` HKDF info prefix that matches the constants module from Phase 1.
  4. A link-check pass on all three documents succeeds and each document references the cclink source (`https://github.com/johnzilla/cclink`) at least once, making the fork-and-diverge lineage legible to a reader who never saw the PROJECT.md file.
**Plans**: TBD

## Progress

**Execution Order:**
Phases execute in numeric order: 1 → 2 → 3 → 4. Decimal insertions (e.g., 2.1) would run between 2 and 3.

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Foundation — scaffold, vendored primitives, and transport seam | 3/3 | Complete    | 2026-04-21 |
| 2. Send, receive, and explicit acceptance | 0/3 | Not started | - |
| 3. Signed receipt — the cipherpost delta | 0/TBD | Not started | - |
| 4. Protocol documentation drafts | 0/TBD | Not started | - |

---
*Roadmap created: 2026-04-20*
*Granularity: coarse (4 phases, 1-3 plans each)*
*Coverage: 49/49 v1 requirements mapped*
