# Requirements: Cipherpost v1.1 "Real v1"

**Defined:** 2026-04-23
**Milestone:** v1.1 "Real v1"
**Core Value:** Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.

**Structure note (DOC-03 transition):** This REQUIREMENTS.md does not include a separate traceability table. Each requirement is tagged inline with its phase, and phase `VERIFICATION.md` files are authoritative for implementation status. This change eliminates the drift class that hit v1.0 (29 "Pending" rows at milestone close).

---

## v1.1 Requirements

Target: 5 phases continuing from v1.0's Phase 4 → **Phases 5–9**.

Requirement ID format: `[CATEGORY]-[NUMBER] [Phase N]`. Categories cluster by feature area, not by phase — a few span multiple phases.

### Non-interactive passphrase automation (PASS)

Phase 5. Aligns `send`/`receive` with the `identity` subcommand non-interactive contract.

- [ ] **PASS-01 [Phase 5]**: User can pass `--passphrase-file <path>` to `cipherpost send`; file mode must be 0600 or 0400 or the command errors with `"passphrase file permissions too open (mode 0NNN); use chmod 600"`
- [ ] **PASS-02 [Phase 5]**: User can pass `--passphrase-fd <fd>` to `cipherpost send`; implementation uses `BorrowedFd`, not `FromRawFd` (no double-close)
- [ ] **PASS-03 [Phase 5]**: User can pass `--passphrase-file <path>` to `cipherpost receive` with identical semantics to `send`
- [ ] **PASS-04 [Phase 5]**: User can pass `--passphrase-fd <fd>` to `cipherpost receive` with identical semantics to `send`
- [ ] **PASS-05 [Phase 5]**: Passphrase source precedence on `send`/`receive` matches the shipped `resolve_passphrase` contract: `--passphrase-fd > --passphrase-file > CIPHERPOST_PASSPHRASE > TTY`. Argv-inline `--passphrase <value>` is rejected at parse and at runtime. Identity subcommands (`generate`/`show`) use the same ordering.
- [ ] **PASS-06 [Phase 5]**: `--passphrase <value>` inline flag on `send`/`receive` is `hide = true` and rejected at runtime with same message as identity subcommands
- [ ] **PASS-07 [Phase 5]**: Newline-strip contract: `--passphrase-file` and `--passphrase-fd` strip exactly one trailing `\n` or `\r\n`, never `.trim()` (which silently corrupts passphrases ending in space). Documented in SPEC.md and `--help`.
- [ ] **PASS-08 [Phase 5]**: `send`/`receive` `--help` lists all three non-interactive sources with scripting examples (env-var, file-with-mode, fd-with-pass_fds)
- [ ] **PASS-09 [Phase 5]**: CI integration test: end-to-end scripted `send -` → `receive` round trip using only `--passphrase-fd 3` (no TTY available), proving automation unlock

### Protocol documentation housekeeping (DOC)

Phase 5. Clears v1.0 bookkeeping debt; locks in anti-drift conventions.

- [ ] **DOC-01 [Phase 5]**: SPEC.md blesses actually-shipped crate versions as the v1.1 baseline: `serde_canonical_json 1.0.0` (not planned 0.2), `pkarr 5.0.4` (not pinned 5.0.3), PKARR wire budget 550 B (not 600); historical "planned version" references removed or marked as v1.0 notes
- [ ] **DOC-02 [Phase 5]**: DHT label audit written and committed: `_cipherpost` and `_cprcpt-<share_ref_hex>` reviewed, retained as-is; any future rename requires explicit protocol version bump (stated in SPEC.md §3.3)
- [ ] **DOC-03 [Phase 5]**: REQUIREMENTS.md traceability-table format dropped project-wide; phase tags inline on each requirement are canonical; phase `VERIFICATION.md` files are authoritative for implementation status. Convention documented in this file's Structure note and in CLAUDE.md.
- [ ] **DOC-04 [Phase 5]**: v1.0 archived REQUIREMENTS.md cleaned up — stale "Pending" rows in the traceability table removed (or the whole table dropped in the archive with a forward-reference to v1.0 phase VERIFICATION docs). No "Pending" row survives when implementation is complete.

### Typed Material: X.509 certificates (X509)

Phase 6. Pattern-establish variant — get the shape right here; Phase 7 is application.

- [ ] **X509-01 [Phase 6]**: `Material::X509Cert { bytes: Vec<u8> }` holds canonical DER bytes only. CLI accepts both DER and PEM inputs; PEM is normalized to DER at ingest (before JCS hashing and Envelope construction) so `share_ref` stays deterministic across re-sends. Indefinite-length BER and malformed DER are rejected at ingest with exit 1. **Open for Phase 7 planning:** whether to mirror this "CLI-accepts-common-encoding, normalize-before-hash" pattern for `PgpKey` (ASCII-armor acceptance → strip to binary packet stream) — defer to Phase 7 plan time.
- [ ] **X509-02 [Phase 6]**: Wire format: `{"type": "x509_cert", "bytes": "<base64-std-padded>"}`; JCS alphabetical ordering places `bytes` before `type` automatically (same shape as `GenericSecret`)
- [x] **X509-03
 [Phase 6]**: `cipherpost send --material x509-cert` reads DER from stdin (or file via `-` convention); wraps in Envelope; per-variant 64 KB size check before encryption
- [x] **X509-04
 [Phase 6]**: `cipherpost receive` on an `X509Cert` share renders acceptance-banner preview POST-decrypt: Subject (truncated), Issuer (truncated), SerialNumber (truncated to 16 hex chars), NotBefore/NotAfter (ISO UTC), key algorithm (e.g., `id-ecPublicKey P-256`), SHA-256 DER fingerprint (full 64 hex chars). Expired cert displays `[EXPIRED]` but is not blocked.
- [x] **X509-05
 [Phase 6]**: `cipherpost receive` emits raw DER bytes to stdout by default; `--armor` flag emits PEM-armored output
- [ ] **X509-06 [Phase 6]**: Per-variant size check: X509 DER > 64 KB rejected at send with clear error matching v1.0's `PayloadTooLarge` Display style
- [ ] **X509-07 [Phase 6]**: JCS fixture committed at `tests/fixtures/material_x509_signable.bin` (byte-locked; any drift surfaces as red CI test)
- [ ] **X509-08 [Phase 6]**: Malformed X509 DER on receive returns exit 1 (content error, distinct from exit 3 signature failures); Display message generic (does not leak `x509-parser` internals)
- [ ] **X509-09 [Phase 6]**: Integration test: round-trip `X509Cert` self-send under MockTransport verifies wire-byte determinism and acceptance-banner field set

### Typed Material: PGP keys (PGP)

Phase 7. Applies the Phase 6 pattern to rPGP.

- [ ] **PGP-01 [Phase 7]**: `Material::PgpKey { bytes: Vec<u8> }` holds binary OpenPGP packet stream; ASCII-armored keys rejected at `send` ingest (armor headers `Comment:`, `Version:` are non-deterministic — would break JCS byte-identity across re-sends)
- [ ] **PGP-02 [Phase 7]**: Wire format: `{"type": "pgp_key", "bytes": "<base64-std-padded>"}`
- [ ] **PGP-03 [Phase 7]**: `cipherpost send --material pgp-key` reads binary packet stream; strict single-primary-key — reject multi-primary keyrings with exit 1 `"PgpKey must contain exactly one primary key; keyrings are not supported in v1.1"`
- [ ] **PGP-04 [Phase 7]**: `cipherpost receive` on a `PgpKey` share renders: v4 fingerprint (40 hex) or v5 fingerprint (64 hex), primary UID, key algorithm (e.g., `Ed25519`, `RSA-4096`, `ECDSA-P256`), subkey count + types, creation time (ISO UTC). Secret keys display `[WARNING: SECRET key]` but are not rejected (secret-key handoff is a legitimate use case).
- [ ] **PGP-05 [Phase 7]**: `cipherpost receive` emits raw binary packet stream to stdout by default; `--armor` emits ASCII-armored output
- [ ] **PGP-06 [Phase 7]**: Per-variant size check: PGP packet stream > 64 KB rejected at send (keyrings with many subkeys or long UIDs could exceed; enforce)
- [ ] **PGP-07 [Phase 7]**: JCS fixture committed at `tests/fixtures/material_pgp_signable.bin`
- [ ] **PGP-08 [Phase 7]**: Malformed PGP packets on receive return exit 1; generic Display (does not leak `pgp` crate internals)
- [ ] **PGP-09 [Phase 7]**: Integration test: round-trip `PgpKey` self-send under MockTransport

### Typed Material: SSH keys (SSH)

Phase 7. Applies the pattern to `ssh-key` crate; narrow format scope.

- [ ] **SSH-01 [Phase 7]**: `Material::SshKey { bytes: Vec<u8> }` holds OpenSSH v1 format bytes (`-----BEGIN OPENSSH PRIVATE KEY-----` envelope); legacy PEM, RFC 4716, and FIDO-format keys return `Error::SshKeyFormatNotSupported` with exit 1 at ingest
- [ ] **SSH-02 [Phase 7]**: Wire format: `{"type": "ssh_key", "bytes": "<base64-std-padded>"}`; the stored bytes are the canonical OpenSSH v1 wire blob (no trailing comment drift, no padding-to-block variance)
- [ ] **SSH-03 [Phase 7]**: `cipherpost send --material ssh-key` reads OpenSSH v1 bytes
- [ ] **SSH-04 [Phase 7]**: `cipherpost receive` on an `SshKey` share renders: key type (`ssh-ed25519`, `ecdsa-sha2-nistp256`, `ssh-rsa`, etc.), SHA-256 fingerprint (`SHA256:<base64>`), comment (marked "sender-attested, not cryptographically verified" — matches `purpose` field treatment), key size in bits. DSA and RSA < 2048 display `[DEPRECATED]` but are not rejected.
- [ ] **SSH-05 [Phase 7]**: `cipherpost receive` emits raw OpenSSH v1 bytes to stdout
- [ ] **SSH-06 [Phase 7]**: Per-variant size check: SSH OpenSSH v1 > 64 KB rejected at send
- [ ] **SSH-07 [Phase 7]**: JCS fixture committed at `tests/fixtures/material_ssh_signable.bin`
- [ ] **SSH-08 [Phase 7]**: Malformed SSH bytes on receive return exit 1; generic Display
- [ ] **SSH-09 [Phase 7]**: Integration test: round-trip `SshKey` self-send under MockTransport
- [ ] **SSH-10 [Phase 7]**: `cargo tree | grep ed25519-dalek` pre-flight check in Phase 7 plan 01 — verify `ssh-key 0.6` does not pull `ed25519-dalek 2.x` alongside the existing `=3.0.0-pre.5` pin. Document outcome; either "no 2.x leak" or explicit coexistence acceptance.

### PIN encryption mode (PIN)

Phase 8. Forks cclink's PIN crypto shape; stays inside `age` for AEAD.

- [ ] **PIN-01 [Phase 8]**: `cipherpost send --pin` enables PIN-required mode; PIN prompted interactively on TTY at send time; non-interactive PIN input (`--pin-file`/`--pin-fd`) deliberately deferred to v1.2+ (human-in-the-loop second factor is intentional)
- [ ] **PIN-02 [Phase 8]**: PIN validation at send time (matching cclink's `validate_pin`): minimum 8 characters, rejects all-same (`"aaaaaaaa"`, `"00000000"`), rejects sequential (`"12345678"`, `"abcdefgh"` ascending or descending). Rejection returns exit 1 with specific reason (min length, all-same, sequential).
- [ ] **PIN-03 [Phase 8]**: PIN crypto stack: Argon2id(PIN + 32-byte random salt) → HKDF-SHA256 with info `cipherpost/v1/pin` → 32-byte X25519 scalar → age `Identity` built from scalar → `age::Encryptor::with_recipients([pin_recipient])`. Matches cclink shape; HKDF namespace adapted from `cclink-pin-v1` to `cipherpost/v1/pin` per existing domain-separation convention. No direct `chacha20poly1305` calls — CLAUDE.md constraint holds unchanged.
- [ ] **PIN-04 [Phase 8]**: `OuterRecord`/`OuterRecordSignable` gains `pin_required: bool` field (outer-signed, pre-decrypt readable); `#[serde(default, skip_serializing_if = "is_false")]` preserves byte-identity with v1.0 for non-pin shares (no protocol_version bump for this field alone)
- [ ] **PIN-05 [Phase 8]**: PIN salt (32 bytes random per send) embedded in the blob: `blob = base64(salt || age_ciphertext)`. Salt is stored inside the outer-signed data so it's authenticated.
- [ ] **PIN-06 [Phase 8]**: `cipherpost receive` on a `pin_required` share prompts for PIN on TTY BEFORE the typed-z32 acceptance banner; wrong PIN returns exit 4 with the same Display as wrong identity passphrase (error-oracle hygiene; PITFALL #16)
- [ ] **PIN-07 [Phase 8]**: Error-oracle enumeration test extended: wrong-PIN variant, wrong-identity-key variant, sig-failure variants (outer, inner, canonical-mismatch) all produce identical user-facing Display strings under `format!("{}", err)`. Existing `lib::error::tests::signature_failure_variants_share_display` test expanded to cover PIN.
- [ ] **PIN-08 [Phase 8]**: Integration test matrix for PIN: (a) send-with-pin → receive-no-pin attempts → exit 7 declined (PIN prompt bails before decrypt); (b) send-with-pin → receive-wrong-pin → exit 4 passphrase (same as wrong identity); (c) send-with-pin → receive-correct-pin → exit 0 + acceptance banner proceeds. Under MockTransport.
- [ ] **PIN-09 [Phase 8]**: SPEC.md documents PIN crypto: Argon2id params (matching cclink's — 64 MB, 3 iter), HKDF namespace, wire blob layout (salt || ciphertext), UX order (PIN before z32), error-oracle constraint, 8-char entropy floor + anti-pattern validation
- [ ] **PIN-10 [Phase 8]**: THREAT-MODEL.md adds §X.Y "PIN mode" — second-factor semantics (require BOTH PIN and identity key), offline brute-force bound (Argon2id params × entropy floor), intentional indistinguishability from wrong-key errors, no PIN logging anywhere

### Burn-after-read mode (BURN)

Phase 8. State-ledger inversion of v1.0 idempotency; orthogonal to PIN.

- [ ] **BURN-01 [Phase 8]**: `cipherpost send --burn` sets `Envelope.burn_after_read: bool = true` (inner-signed, `#[serde(default, skip_serializing_if = "is_false")]` — preserves byte-identity for non-burn shares)
- [ ] **BURN-02 [Phase 8]**: `cipherpost receive` on a `burn_after_read` share: first successful receive writes state-ledger entry with new `burned` state (distinct from v1.0's `accepted`); subsequent receives on same `share_ref` return exit 7 `"share already consumed"` — burn inverts v1.0's idempotency
- [ ] **BURN-03 [Phase 8]**: State-ledger atomicity: stdout emit happens BEFORE `burned` state write. Crash between emit and write leaves the share re-receivable — safer failure mode (user keeps access) than the reverse (user loses data to a crashed state-write).
- [ ] **BURN-04 [Phase 8]**: Receipt IS published on successful burn-receive (same semantics as non-burn). Burn does not prevent attestation; it only prevents a second local decryption. Sender still sees a single receipt via `receipts --from <z32>`.
- [ ] **BURN-05 [Phase 8]**: Send-time stderr warning when `--burn` is used: explicit `"⚠ --burn is local-state-only; ciphertext remains on DHT until TTL (24h by default). This prevents YOUR second decryption, not a second machine's."`
- [ ] **BURN-06 [Phase 8]**: Receive-time acceptance banner on a burn share: prepends `[BURN — you will only see this once]` marker before the typed-z32 prompt; user warned before commit
- [ ] **BURN-07 [Phase 8]**: `--burn` and `--pin` compose orthogonally; wire can carry both (`pin_required=true` + `burn_after_read=true` both serialized)
- [ ] **BURN-08 [Phase 8]**: THREAT-MODEL.md §X.Y "Burn mode" documents local-state-only semantics, DHT-packet-survives-TTL caveat, multi-machine race (two receivers with fresh ledgers can both decrypt), positioned as UX affordance not cryptographic destruction
- [ ] **BURN-09 [Phase 8]**: Integration test: two consecutive receives of same burn share return exit 0 then exit 7 in that order; ledger inspection confirms `burned` state after first; receipt count = 1 (not 2) after second attempt

### Real-DHT + merge-update race gate (DHT)

Phase 9. Release-acceptance: the "it's not just MockTransport" proof.

- [ ] **DHT-01 [Phase 9]**: MockTransport updated to enforce PKARR `cas` (compare-and-swap) semantics for `publish_receipt` — current overwrite-or-merge behavior replaced with an explicit `cas` that returns `Err(CasConflict)` on concurrent publish with stale preimage. Pre-req for DHT-02.
- [ ] **DHT-02 [Phase 9]**: CAS racer integration test: two threads synchronized via `std::sync::Barrier` both call `publish_receipt` under the same recipient PKARR key with different receipts; assert exactly one wins on first attempt, loser retries-and-merges, final state contains both receipts (resolve-merge-republish invariant holds under contention). Runs in CI under MockTransport.
- [ ] **DHT-03 [Phase 9]**: Real-DHT e2e integration test behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` — runs only via `cargo test --features real-dht-e2e -- --ignored dht_e2e`. Not a CI job.
- [ ] **DHT-04 [Phase 9]**: Real-DHT test spawns two in-process cipherpost clients with independent identities; publishes via client A, resolves via client B with 120-second exponential-backoff ceiling (not fixed sleep), decrypts, publishes receipt via B, fetches via A. Asserts round trip end-to-end with real Mainline DHT propagation.
- [ ] **DHT-05 [Phase 9]**: Real-DHT test pre-flight: UDP reachability probe to a known Mainline bootstrap node. If probe fails (GitHub Actions / corporate firewall), test skips with warning `"real-dht-e2e: UDP unreachable; test skipped (not counted as pass)"`. Manual runs on a real network have no such gate.
- [ ] **DHT-06 [Phase 9]**: `RELEASE-CHECKLIST.md` created at repo root with the manual real-DHT test invocation, expected output pattern, and pass/fail criteria. Gates every v1.1+ release.
- [ ] **DHT-07 [Phase 9]**: Wire-budget headroom test: a share with `pin_required=true` + `burn_after_read=true` carrying a realistic PGP payload (~2 KB) must fit within the 1000-byte PKARR dns_packet budget + follow-up receipt under the 550-byte `OuterRecord` budget. Assertion — explicit `Error::WireBudgetExceeded` path returned cleanly at send, not a PKARR-internal panic.

---

## Deferred Requirements (v1.2+)

Not in v1.1; tracked for future milestones.

### Non-interactive PIN input (DEFER-PIN)

- **DEFER-PIN-01**: `--pin-file <path>` on `send` and `receive` (matches passphrase-file semantics)
- **DEFER-PIN-02**: `--pin-fd <fd>` on `send` and `receive`

**Rationale:** v1.1 keeps PIN as an intentionally human-in-the-loop second factor. Automated-script receive of a PIN-required share is an anti-pattern for the threat model this mode targets. Revisit when a concrete automation use case surfaces.

### Typed Material expansions (DEFER-MAT)

- **DEFER-MAT-01**: `Material::PgpKey` multi-primary-key (keyring) support
- **DEFER-MAT-02**: `Material::SshKey` legacy PEM format
- **DEFER-MAT-03**: `Material::SshKey` RFC 4716 public-key format
- **DEFER-MAT-04**: `Material::SshKey` FIDO/U2F key format
- **DEFER-MAT-05**: PGP v6 key format (requires `pgp` crate upgrade from 0.14 → 0.19+)

### Feature-tier deferred (DEFER-FEAT)

- **DEFER-FEAT-01**: TUI wizard for interactive `send`/`receive` — CLI + automation covers v1.1 use cases
- **DEFER-FEAT-02**: Exportable local audit log for compliance evidence — surface depends on first real enterprise contact
- **DEFER-FEAT-03**: Destruction attestation workflow (originally PRD v1.1 — shifted because v1.1 filled up with PRD-closure scope)
- **DEFER-FEAT-04**: Multi-recipient broadcast shares — PRD v1.2
- **DEFER-FEAT-05**: HSM integration for sender-side generation — PRD v1.3

---

## Out of Scope

Explicitly excluded from v1.1. Documented to prevent scope creep.

| Feature | Reason |
|---------|--------|
| X.509 chain validation | Cipherpost transports a single cert; chain trust is the receiver's concern. Scope creep into CA store + revocation checking is explicitly rejected. |
| PGP signature verification | We transport keys, not signed messages. rPGP's verify APIs are out of scope — the receiver uses their own PGP tool. |
| SSH key format conversion | Sender sends what they have; receiver can convert with `ssh-keygen -f ... -m pem` etc. Cipherpost is transport, not conversion. |
| Cryptographic burn destruction | Burn is local-ledger-only; DHT ciphertext is self-sovereign and cannot be force-deleted. Documented invariant. |
| Server / relay / operator (even optional) | Any such introduction is out of scope for v1.x core (may be a later commercial feature). |
| PIN recovery | There is no recovery — wrong PIN is indistinguishable from wrong key. A lost PIN means a lost share. Documented contract. |
| Non-interactive PIN | Deferred (see DEFER-PIN) — PIN is a second factor, human-in-the-loop is intentional for v1.1. |
| `sequoia-openpgp` crate | LGPL-2.0-or-later; incompatible with cipherpost's MIT. Use `pgp` (rPGP — MIT/Apache). Hard reject, not preference. |
| Full key lifecycle management | That's a KMS. Explicit PRD non-goal. |
| Long-term secret storage | That's a vault. Explicit PRD non-goal. |
| Web UI | PRD non-goal for v1.x — CLI (+ eventual TUI) only. |

---

## Coverage Summary

| Category | Count | Phase |
|---|---:|---|
| PASS — Non-interactive passphrase automation | 9 | 5 |
| DOC — Protocol documentation housekeeping | 4 | 5 |
| X509 — X.509 certificate typed Material | 9 | 6 |
| PGP — PGP key typed Material | 9 | 7 |
| SSH — SSH key typed Material | 10 | 7 |
| PIN — `--pin` encryption mode | 10 | 8 |
| BURN — `--burn` encryption mode | 9 | 8 |
| DHT — Real-DHT + CAS merge-update race | 7 | 9 |
| **Total v1.1** | **67** | **5 phases** |

**Phase mapping is inline per requirement** (see Structure note at top). The roadmapper will create ROADMAP.md consuming these tags.

---

*Requirements defined: 2026-04-23 via `/gsd-new-milestone`*
*Research inputs: .planning/research/STACK.md · FEATURES.md · ARCHITECTURE.md · PITFALLS.md · SUMMARY.md*
*cclink survey completed in main orchestrator (PIN shape confirmed: Argon2id+HKDF → X25519 → age; fork-and-diverge per user guidance)*
