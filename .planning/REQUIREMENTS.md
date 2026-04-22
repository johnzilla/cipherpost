# Requirements: Cipherpost

**Defined:** 2026-04-20
**Core Value:** Hand off a key to someone, end-to-end encrypted, with a signed receipt, without standing up or depending on any server.
**Milestone:** Walking skeleton (v1 in this document = skeleton scope; v2 = skeleton→v1.0 follow-on)

## v1 Requirements

Requirements for the walking-skeleton milestone. Each maps to exactly one roadmap phase during roadmap creation.

### Scaffold

- [x] **SCAF-01
**: Repository has `Cargo.toml` with exact pins matching cclink v1.3.0's crypto/DHT stack (pkarr 5.0.3, `ed25519-dalek =3.0.0-pre.5`, age 0.11, argon2 0.5, hkdf 0.12, sha2 0.10, zeroize 1, clap 4.5, anyhow 1, thiserror 2, base64 0.22, bech32 0.9, dirs 5, dialoguer 0.12, serde + serde_json, serde_canonical_json)
- [x] **SCAF-02
**: Repository has `cargo build --release` producing a single `cipherpost` binary
- [x] **SCAF-03
**: CI runs `cargo fmt --check`, `cargo clippy -- -D warnings`, `cargo nextest run`, `cargo audit`, and `cargo deny check` on every pull request and on main
- [x] **SCAF-04
**: Repository contains `LICENSE` (MIT), a `README.md` stub linking to `cipherpost-prd.md`, and a top-level `.gitignore` that excludes `target/`
- [x] **SCAF-05
**: Async runtime decision enforced: `main.rs` is plain `fn main()` with no `#[tokio::main]`; no direct `tokio` dependency in `Cargo.toml`

### Crypto primitives (vendored from cclink)

- [x] **CRYPTO-01
**: Ed25519 keypair generation and X25519 derivation reproduces byte-identical outputs to cclink's reference vectors (test fixture committed)
- [x] **CRYPTO-02
**: Argon2id key derivation uses params stored in the identity file header as a PHC-format string (no hardcoded params in code)
- [x] **CRYPTO-03
**: HKDF-SHA256 info strings are domain-separated and versioned as `cipherpost/v1/<context>` (never empty, never `None`)
- [x] **CRYPTO-04
**: Canonical JSON for signed payloads uses RFC 8785 (JCS) via `serde_canonical_json`; a property test asserts determinism across re-serializations; floats in signed payloads are rejected with a compile-time-or-test-enforced guard
- [x] **CRYPTO-05
**: age encryption is used exclusively for payload encryption (no direct `chacha20poly1305` calls anywhere in `src/`)
- [x] **CRYPTO-06
**: Every key-holding struct (passphrase, secret key bytes, decrypted material) uses `Zeroize` / `secrecy::SecretBox`; `format!("{:?}", ...)` on any such struct in a test redacts the content

### Identity

- [x] **IDENT-01
**: User can generate a new Ed25519/PKARR identity with `cipherpost identity generate` and a TTY passphrase prompt; file is written to `~/.cipherpost/secret_key` with mode `0600`
- [x] **IDENT-02
**: User can unlock an existing identity with `cipherpost identity show` (or any command requiring identity) and a TTY passphrase prompt; wrong passphrase returns exit code 4 with no key-material hint in the error
- [x] **IDENT-03
**: Identity file refuses to open if permissions are wider than `0600` (surfaces a clear error and exit code)
- [x] **IDENT-04
**: Identity commands support non-interactive passphrase via `CIPHERPOST_PASSPHRASE` env var, `--passphrase-file <path>`, or `--passphrase-fd <n>`; inline `--passphrase <value>` is refused
- [x] **IDENT-05
**: `cipherpost identity show` prints both fingerprints: OpenSSH-style `ed25519:SHA256:<base64>` and z-base-32 PKARR pubkey

### Transport (DHT)

- [x] **TRANS-01
**: `src/transport/` defines a `Transport` trait with methods for `publish(packet)`, `resolve(pubkey)`, and `publish_receipt(share_ref, receipt)`; a `DhtTransport` impl wraps `pkarr::ClientBlocking`
- [x] **TRANS-02
**: A `MockTransport` in `src/transport/mock.rs` (or tests) provides an in-memory map keyed by PKARR pubkey so integration tests do not hit real DHT
- [x] **TRANS-03**: `publish_receipt` resolves the recipient's existing SignedPacket if any, merges the receipt TXT record under label `_cprcpt-<share_ref>`, re-signs with the recipient's key, and republishes
- [x] **TRANS-04
**: A default DHT request timeout of 30 seconds is enforced; `--dht-timeout <seconds>` overrides it; timeouts return exit code 6 distinct from "not found" (exit 5) and "network error"
- [x] **TRANS-05
**: DHT progress is written to stderr (so stdout can be piped); on success, the final stdout is the payload or a terse JSON status

### Payload schema

- [x] **PAYL-01**: `Envelope` struct carries `purpose: String`, `material: Material`, `created_at: i64` (unix seconds, inner signed timestamp), `protocol_version: u16`; canonicalized with JCS before signing
- [x] **PAYL-02**: `Material` is a Rust enum with `GenericSecret { bytes: Vec<u8> }` implemented; `X509Cert`, `PgpKey`, `SshKey` variants are defined but return `unimplemented` on encode/decode (reserved for v1.0)
- [x] **PAYL-03**: Plaintext payload is rejected if it exceeds 64 KB; error message names the actual size and the cap
- [x] **PAYL-04**: Purpose text is stripped of ASCII control characters (C0/C1) before canonicalization and acceptance display; purpose is documented as sender-attested (not independently verified) in SPEC.md
- [x] **PAYL-05**: `share_ref` is a 128-bit value derived as `sha256(ciphertext || created_at)[..16]`, hex-encoded (32 chars) in record fields and DHT labels

### Send

- [x] **SEND-01
**: `cipherpost send --self` reads the payload from `<path>` or `-` (stdin), builds an envelope with a sender-supplied `--purpose`, encrypts with age to the sender's own X25519 key, wraps in a dual-signed outer record, publishes to the sender's PKARR key, and prints the share URI on stdout
- [x] **SEND-02
**: `cipherpost send --share <pubkey>` does the same but encrypts to the recipient's X25519 key (derived from their Ed25519 PKARR pubkey); `<pubkey>` accepts z-base-32 or OpenSSH-style input
- [x] **SEND-03
**: `--ttl <duration>` overrides the default 24-hour TTL; TTL is stored as the inner-signed `created_at + ttl_seconds`, not as a DHT packet TTL
- [x] **SEND-04
**: Every outer record carries both signatures: outer PKARR SignedPacket signature and inner Ed25519 signature over JCS-canonical `OuterRecordSignable`
- [x] **SEND-05
**: Outer SignedPacket size stays under the PKARR/BEP44 budget (~1000 bytes); a build-time test asserts this for a representative payload

### Receive

- [x] **RECV-01
**: `cipherpost receive <share-uri>` resolves the share, verifies the outer PKARR signature, fetches and deserializes the outer record, then verifies the inner Ed25519 signature; any signature failure aborts before decryption with exit code 3 and a uniform error message
- [x] **RECV-02
**: TTL is enforced against the inner signed `created_at + ttl_seconds`; expired shares abort with exit code 2 (distinct from sig failure)
- [x] **RECV-03
**: After signature + TTL pass, the payload is age-decrypted into a `Zeroizing` buffer but not surfaced; the envelope inner signature is verified against the signed fields; any inner-sig failure aborts with exit code 3
- [x] **RECV-04
**: An acceptance prompt displays: purpose (with control chars stripped), sender's OpenSSH fingerprint, sender's z-base-32, TTL remaining (local + UTC), payload type, and payload size; user must type a full-word confirmation (not just `y`); declining returns exit code 7
- [x] **RECV-05
**: On acceptance, the decrypted payload is written to `--output <path>` or `-` (stdout) — default is stdout if a file is not specified
- [x] **RECV-06
**: Second `receive` of the same accepted share reports the prior acceptance timestamp from local state (`~/.cipherpost/state/`) and does NOT re-decrypt or re-publish a receipt

### Receipt (the cipherpost delta)

- [x] **RCPT-01**: On successful acceptance, a `Receipt { share_ref, sender_pubkey, recipient_pubkey, accepted_at, nonce, ciphertext_hash, cleartext_hash, purpose, protocol_version, signature }` is constructed, signed by the recipient's Ed25519 key, and published via `publish_receipt` under the recipient's PKARR key at label `_cprcpt-<share_ref>`
- [x] **RCPT-02**: `cipherpost receipts --from <recipient-pubkey> [--share-ref <ref>]` resolves the recipient's PKARR packet, extracts receipt TXT records, verifies each signature, and prints a structured summary on stdout
- [x] **RCPT-03**: A verified end-to-end integration test publishes a share from identity A to identity B, has B accept via `MockTransport`, verifies the receipt is published under B's key, and confirms A can fetch+verify it

### CLI ergonomics

- [x] **CLI-01
**: All `send` and `receive` payload I/O supports `-` for stdin/stdout; status output is written to stderr so stdout stays pipeable
- [x] **CLI-02
**: Exit codes follow a documented taxonomy: `0` success, `2` expired, `3` signature verification failure, `4` decryption / passphrase failure, `5` not found on DHT, `6` network / timeout, `7` user declined, `1` generic error
- [x] **CLI-03
**: `cipherpost --help` and every subcommand `--help` prints at least one worked example (`EXAMPLES` section)
- [x] **CLI-04
**: `cipherpost version` prints the crate version, the git commit hash (built in), and a one-line list of crypto primitives in use (age, Ed25519, Argon2id, HKDF-SHA256, JCS)
- [x] **CLI-05
**: Error messages never include passphrase bytes, key bytes, or raw payload bytes; a test asserts this by fuzzing bad inputs and grepping stderr for any secret marker

### Protocol documentation (drafts)

- [x] **DOC-01
**: `SPEC.md` draft covers: payload schema (Envelope / Material), canonical JSON (JCS), outer + inner signature formats, share URI format, DHT labels (`_cipherpost`, `_cprcpt-<ref>`), share_ref derivation, TTL semantics (inner signed timestamp), exit-code taxonomy, and non-interactive passphrase contract
- [x] **DOC-02
**: `THREAT-MODEL.md` draft covers: identity compromise, DHT adversaries (sybil, eclipse, replay), purpose as sender-attested (not verified), acceptance UX adversary model (prompt fatigue), receipt replay, MITM on passphrase prompt, and explicit "out of scope" adversary cases
- [x] **DOC-03
**: `SECURITY.md` has a working disclosure channel (GitHub Security Advisory, email, or equivalent) and a 90-day embargo policy statement
- [x] **DOC-04
**: Docs reference the cclink lineage (https://github.com/johnzilla/cclink) and document the v0 protocol as "cipherpost/v1" (HKDF info prefix matches)

## v2 Requirements

Deferred to the skeleton→v1.0 milestone (the PRD's full v1.0).

### Flow breadth

- **V2-FLOW-01**: `--pin` encryption mode (passphrase-gated share, not key-gated)
- **V2-FLOW-02**: `--burn` encryption mode (single-use self-destructing share)
- **V2-FLOW-03**: TUI wizard (`cipherpost wizard` or similar) covering the common send + receive + accept flow

### Payload types

- **V2-PAYL-01**: X.509 cert + private key payload type (PEM-aware parsing, sanity checks)
- **V2-PAYL-02**: PGP keypair payload type
- **V2-PAYL-03**: SSH keypair payload type

### Operational

- **V2-OPS-01**: Exportable audit log suitable for local compliance evidence
- **V2-OPS-02**: Non-interactive batch mode (scriptable end-to-end without TTY)
- **V2-OPS-03**: Shell completions (`cipherpost completion {bash,zsh,fish}`)
- **V2-OPS-04**: Reproducible release builds with `cargo-vet` imports and sigstore/cosign keyless signing
- **V2-OPS-05**: Cross-platform CI matrix (Linux, macOS, Windows)
- **V2-OPS-06**: `cipherpost receipts --watch` polling with documented interval and Ctrl-C behavior

### Launch criteria

- **V2-LAUNCH-01**: At least one independent public review invited and addressed
- **V2-LAUNCH-02**: Three real users (non-author) using cipherpost for real handoffs
- **V2-LAUNCH-03**: SPEC.md / THREAT-MODEL.md / SECURITY.md finalized (not drafts)

### Later milestones (v1.1+, tracked for completeness)

- **V3-ATTEST-01**: Destruction attestation workflow (v1.1)
- **V3-BROADCAST-01**: Multi-recipient broadcast shares (v1.2)
- **V3-HSM-01**: HSM integration for sender-side generation (v1.3)

## Out of Scope

| Feature | Reason |
|---------|--------|
| Central operator / relay / server | Violates "no servers" principle; possible optional commercial feature later, never v1.x core |
| Accounts / email verification / logins | Violates "key is identity" principle |
| Web UI | CLI (+ eventual TUI) only per PRD; no web UI in any v1.x |
| Full key lifecycle management | That's a KMS, not cipherpost's job |
| Long-term secret storage | That's a vault, not cipherpost's job |
| Signing or crypto operations on behalf of users | Cipherpost transports material; users do their own crypto with it |
| Incident response or CVE tracking | Out of domain |
| General file transfer | 64 KB payload cap is deliberate; tool is for cryptographic material, not files |
| SSO / IdP federation | Commercial tier, later; violates accountless principle |
| SIEM export | Commercial tier, later |
| Live sibling dependency on cclink | cclink is mothballed; we fork-and-diverge, not depend |
| Shared `cipherpost-core` crate | Deferred until a second consumer exists (per PROJECT.md Key Decision) |
| pkarr 5 → 6 upgrade | Post-skeleton; compounding cclink-fork risk with dep-upgrade risk is avoided |
| Coordinated hkdf/sha2/rand crate bumps | Post-skeleton; done as a deliberate separate milestone |

## Traceability

Populated by gsd-roadmapper on 2026-04-20. Every v1 requirement maps to exactly one phase.

| Requirement | Phase | Status |
|-------------|-------|--------|
| SCAF-01 | Phase 1 | Complete |
| SCAF-02 | Phase 1 | Complete |
| SCAF-03 | Phase 1 | Complete |
| SCAF-04 | Phase 1 | Complete |
| SCAF-05 | Phase 1 | Complete |
| CRYPTO-01 | Phase 1 | Complete |
| CRYPTO-02 | Phase 1 | Complete |
| CRYPTO-03 | Phase 1 | Complete |
| CRYPTO-04 | Phase 1 | Complete |
| CRYPTO-05 | Phase 1 | Complete |
| CRYPTO-06 | Phase 1 | Complete |
| IDENT-01 | Phase 1 | Complete |
| IDENT-02 | Phase 1 | Complete |
| IDENT-03 | Phase 1 | Complete |
| IDENT-04 | Phase 1 | Complete |
| IDENT-05 | Phase 1 | Complete |
| TRANS-01 | Phase 1 | Complete |
| TRANS-02 | Phase 1 | Complete |
| TRANS-03 | Phase 3 | Complete |
| TRANS-04 | Phase 1 | Complete |
| TRANS-05 | Phase 1 | Complete |
| PAYL-01 | Phase 2 | Complete |
| PAYL-02 | Phase 2 | Complete |
| PAYL-03 | Phase 2 | Complete |
| PAYL-04 | Phase 2 | Complete |
| PAYL-05 | Phase 2 | Complete |
| SEND-01 | Phase 2 | Complete |
| SEND-02 | Phase 2 | Complete |
| SEND-03 | Phase 2 | Complete |
| SEND-04 | Phase 2 | Complete |
| SEND-05 | Phase 2 | Complete |
| RECV-01 | Phase 2 | Complete |
| RECV-02 | Phase 2 | Complete |
| RECV-03 | Phase 2 | Complete |
| RECV-04 | Phase 2 | Complete |
| RECV-05 | Phase 2 | Complete |
| RECV-06 | Phase 2 | Complete |
| RCPT-01 | Phase 3 | Complete |
| RCPT-02 | Phase 3 | Complete |
| RCPT-03 | Phase 3 | Complete |
| CLI-01 | Phase 2 | Complete |
| CLI-02 | Phase 2 | Complete |
| CLI-03 | Phase 2 | Complete |
| CLI-04 | Phase 2 | Complete |
| CLI-05 | Phase 2 | Complete |
| DOC-01 | Phase 4 | Complete |
| DOC-02 | Phase 4 | Complete |
| DOC-03 | Phase 4 | Complete |
| DOC-04 | Phase 4 | Complete |

**Coverage:**
- v1 requirements: 49 total (note: the header count of "46" in the prior draft was stale — the actual enumerated REQ-IDs total 49 across SCAF(5) + CRYPTO(6) + IDENT(5) + TRANS(5) + PAYL(5) + SEND(5) + RECV(6) + RCPT(3) + CLI(5) + DOC(4))
- Mapped to phases: 49 (100%)
- Unmapped: 0
- **Complete: 49 (100%)** — all v1 requirements satisfied as of milestone v1.0 close (2026-04-22)

**Phase distribution:**
- Phase 1 (Foundation): 20 requirements — Complete
- Phase 2 (Send/receive/acceptance): 21 requirements — Complete
- Phase 3 (Signed receipt): 4 requirements — Complete
- Phase 4 (Protocol docs): 4 requirements — Complete

---
*Requirements defined: 2026-04-20*
*Last updated: 2026-04-22 — all 49 v1 requirements marked complete at milestone v1.0 close; 4 body checkboxes (TRANS-03, RCPT-01..03) and 29 traceability rows brought in sync with phase verifications*
