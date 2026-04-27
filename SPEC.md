# Cipherpost Protocol Specification

> **Status: DRAFT — current through v1.1 Real v1 (shipped 2026-04-26)**
>
> This document describes the protocol as shipped through v1.0 Walking Skeleton (Phases 1–4)
> and v1.1 Real v1 (Phases 5–9), covering all four `Material` variants, `--pin` / `--burn`
> encryption modes, non-interactive automation, and CAS-protected receipt publication.
> Wire-format decisions documented here are **stable** — changes require a protocol version bump.
> v1.0 fixtures remain byte-identical; v1.1 additive fields preserve v1.0 byte-shape via
> `#[serde(skip_serializing_if = "is_false")]`. Editorial polish across the full v1.x scope
> continues.

**Protocol version:** `cipherpost/v1`
**License:** MIT (see `LICENSE`)

## Table of Contents

1. [Introduction](#1-introduction)
2. [Terminology](#2-terminology)
3. [Wire Format](#3-wire-format)
4. [Share URI](#4-share-uri)
5. [Flows](#5-flows)
6. [Exit Codes](#6-exit-codes)
7. [Passphrase Contract](#7-passphrase-contract)
8. [Appendix: Test Vectors](#8-appendix-test-vectors)
9. [Lineage](#9-lineage)

## 1. Introduction

Cipherpost is a self-sovereign, serverless, accountless protocol for handing off cryptographic
material between parties. It is built on Mainline DHT via PKARR for rendezvous, age (X25519
derived from Ed25519) for payload encryption, and Ed25519/PKARR keypairs as identity — so there
is no operator, no account, and no subpoena target. The core value: hand off a key to someone,
end-to-end encrypted, with a signed receipt, without standing up or depending on any server.

Cipherpost is **not** a KMS, a vault, or a general file-transfer tool. It is purpose-built for
the handoff of cryptographic material (private keys, certificates, credentials, API tokens,
passphrases) between parties who already know each other's identity — that is, who can exchange
Ed25519 public keys out-of-band. Nothing in the protocol establishes trust in a counterparty's
identity; that trust is a pre-condition.

Every share carries a sender-attested `purpose` string — a human-readable label such as
`"prod deploy key rotation 2026-04-21"`. The purpose is signed by the sender so it cannot be
modified in transit without breaking the inner signature. However, **cipherpost does NOT verify
the truth value of the purpose**. A malicious sender can claim any purpose. This is
**sender-attested**, not independently verified. Recipients MUST verify the sender's identity
and corroborate the purpose out-of-band before relying on the material. This constraint is
stated again in §3.1 and in `THREAT-MODEL.md` §4 (Sender-Purpose Adversary).

Payload plaintext is capped at **64 KB** (PAYL-03, D-PS-01). The PKARR SignedPacket that
carries the encrypted payload must additionally fit within **~1000 bytes** (BEP44 wire budget).
These are two distinct enforcement layers with distinct error codes; see §3.1 for details.

The protocol uses a dual-signature model: an outer PKARR SignedPacket signature (handled by
`pkarr::ClientBlocking`) ensures the packet was published by the holder of the sender's
Ed25519 private key, and an inner Ed25519 signature over the JCS-canonical form of the signed
struct ensures the payload fields have not been altered inside a valid PKARR packet. Both
signatures are verified before any decryption occurs (D-RECV-01).

After a recipient successfully accepts a share, they publish a signed `Receipt` under their
own PKARR key. The receipt is publicly verifiable by the sender using only public information
and provides attestation that the recipient accepted the specific share at a specific time.

## 2. Terminology

- **age** — the payload encryption format (X25519 + ChaCha20-Poly1305). Cipherpost uses the
  `age` crate exclusively; no direct `chacha20poly1305` calls (CRYPTO-05).
- **Argon2id** — passphrase-based KDF for identity-file encryption; params stored in the
  identity file PHC-format header (CRYPTO-02).
- **BEP44** — BitTorrent Enhancement Proposal 44; defines the ~1000-byte SignedPacket size
  budget that `pkarr` inherits.
- **Ed25519** — signature algorithm used for identity, outer PKARR packet signature, and inner
  Envelope/Receipt signatures.
- **HKDF** — HMAC-based Key Derivation Function (SHA-256). All cipherpost HKDF call-sites use
  a domain-separated info string prefixed `cipherpost/v1/` (D-08, CRYPTO-03).
- **JCS** — JSON Canonicalization Scheme, RFC 8785. Used for every signable struct before
  Ed25519 signing (D-CRYPTO-04). Implementation: `serde_canonical_json` crate.
- **Mainline DHT** — the BitTorrent Distributed Hash Table used as rendezvous.
- **PKARR** — Public-Key Addressable Resource Records; a scheme for storing DNS-shaped
  records (TXT, etc.) signed by an Ed25519 key and resolved via Mainline DHT. Cipherpost uses
  `pkarr (>= 5.0.0)`; see `Cargo.toml` for the exact pin in effect.
- **sender-attested purpose** — the human-readable `purpose` string is signed by the sender
  but is NOT independently verified by any third party (D-WIRE-05, PITFALL #12).
- **Share** — one published `OuterRecord` carrying an age-encrypted payload.
- **share_ref** — 128-bit share identifier, 32-char lowercase hex (D-06, PAYL-05).
- **Receipt** — signed attestation published by the recipient under their own PKARR key after
  successful acceptance (D-RS-01..07).
- **z-base-32** — the encoding used by PKARR for public keys. An Ed25519/PKARR public key
  encodes as exactly 52 z-base-32 characters.

## 3. Wire Format

All cipherpost signable structs are canonicalized via RFC 8785 (JCS) before being signed with
Ed25519. Floats are forbidden in signable structs (CRYPTO-04). Struct fields are serialized
in alphabetical order by name (JCS invariant). Every Ed25519 signature is produced over the
JCS bytes of the `-Signable` projection of the wire struct (the wire struct minus its own
`signature` field).

**Source-of-truth code:** `src/record.rs`, `src/receipt.rs`, `src/payload.rs`, `src/crypto.rs::jcs_serialize`.
**Canonical rules:** See RFC 8785 (`rfc-editor.org/rfc/rfc8785`).
**Canonical JSON implementation:** `serde_canonical_json (>= 1.0.0, RFC 8785 JCS)`; see
`Cargo.toml` for the exact pin in effect.
**Hash algorithm:** SHA-256 via the `sha2` crate; see `Cargo.toml` for the exact pin in
effect. Hash outputs are rendered as lowercase hex.
**Signature algorithm:** Ed25519 via `ed25519-dalek`. The exact version pin is a build
constraint, not a protocol guarantee — it is locked in `Cargo.toml` to match `pkarr`'s
transitive `ed25519-dalek` dependency; see CLAUDE.md §Load-bearing lock-ins for the
rationale.
**Payload encryption:** `age (>= 0.10)`; see `Cargo.toml` for the exact pin in effect.
`age` is the only reachable path to `chacha20poly1305`; no direct calls are permitted.
**Base64 codec:** `base64::engine::general_purpose::STANDARD` (with padding) — applied
uniformly for signatures and for `OuterRecord.blob` and `Material::GenericSecret.bytes`
(D-WIRE-04). `URL_SAFE_NO_PAD` is banned at the wire layer.

**PKARR wire budget:** A representative `OuterRecord` blob (base64-encoded `age`
ciphertext) must fit within **550 bytes** (measured at v1.0 cut; see
`tests/signed_packet_budget.rs`). Within the ~1000-byte BEP44 DNS-packet envelope this
leaves room for the JSON structure and the recipient z-base-32. A blob exceeding this
ceiling surfaces `Error::WireBudgetExceeded` at publish time (§3.3, §3.4, §5.1 step 7).

**Bootstrap nodes (v1.1):** v1.1 uses the pkarr default Mainline bootstrap node set
(`router.bittorrent.com:6881`, `dht.transmissionbt.com:6881`,
`dht.libtorrent.org:25401`, `relay.pkarr.org:6881`); no user-tunable bootstrap
configuration is exposed in this milestone. Future milestones may revisit if private-
testnet support is requested (see CLAUDE.md §Load-bearing lock-ins).

**CAS contract on `publish_receipt` (Phase 9 lock-in):** `cas` semantics on
`publish_receipt` are contractual: implementations MUST single-retry-then-fail on
`pkarr::errors::ConcurrencyError` (`ConflictRisk` / `NotMostRecent` / `CasFailed` —
all three are conflict-class signals per pkarr 5.0.4). Final-conflict failures
surface via `Error::Transport` (no public `Error::CasConflict` variant — error-oracle
hygiene per Pitfall #16). The retry loop lives inside the `Transport` trait method;
callers see `Ok(())` or final `Err`. Divergence from this contract requires a
`protocol_version` bump.

### 3.1 Envelope

The plaintext payload. Serialized as JCS, then age-encrypted to produce `OuterRecord.blob`.
Encrypted with age to the recipient's X25519 key (derived from their Ed25519 pubkey);
for `--self` sends, encrypted to the sender's own X25519 key.

**Plaintext size cap:** 64 KB. Payloads exceeding this are rejected pre-encrypt (PAYL-03, D-PS-01).

**Wire budget:** The PKARR SignedPacket carrying this payload's `OuterRecord` must fit within
~1000 bytes (BEP44 budget). Two-layer enforcement per D-PS-01: plaintext > 64 KB aborts before
crypto; SignedPacket > wire budget aborts at publish time with `Error::WireBudgetExceeded`.

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `created_at` | i64 | JSON integer | Unix seconds; MUST equal `OuterRecord.created_at` (single timestamp) | D-WIRE-02, PAYL-01 |
| `material` | Material | tagged enum — see §3.2 | Typed cryptographic payload | D-WIRE-03, PAYL-02 |
| `protocol_version` | u16 | JSON integer | Always `1` in cipherpost/v1 | D-07 |
| `purpose` | String | UTF-8, control chars stripped | Sender-attested description; NOT independently verified | D-WIRE-05, PAYL-04 |

**Purpose normalization (D-WIRE-05):** Before JCS serialization, the `purpose` string has
ASCII C0 controls (0x00..0x1F), DEL (0x7F), and C1 controls (0x80..0x9F) removed. Stripping
happens once at `send` time so sender and recipient compute identical JCS bytes.

> **Security note (PITFALL #12 / D-WIRE-05):** `purpose` is signed by the sender, so it cannot
> be modified in flight without breaking the inner signature. However, cipherpost does NOT
> verify the truth value of the purpose. A malicious sender can claim any purpose. Recipients
> MUST verify the sender's identity and corroborate the purpose out-of-band before relying on
> the material. See `THREAT-MODEL.md` §4 Sender-Purpose Adversary.

### 3.2 Material

Tagged enum; Rust-level serde directives: `#[serde(tag = "type", rename_all = "snake_case")]`
(D-WIRE-03). Variant names on the wire: `generic_secret`, `x509_cert`, `pgp_key`, `ssh_key`.

**cipherpost/v1.0 shipped:** `generic_secret` only.
**cipherpost/v1.1 (Phase 6) adds:** `x509_cert { bytes }`.
**cipherpost/v1.1 (Phase 7) adds:** `pgp_key { bytes }` and `ssh_key { bytes }`.

**`generic_secret` wire form:**
```json
{"type": "generic_secret", "bytes": "<base64-STANDARD-padded>"}
```

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `type` | String | literal `"generic_secret"` | Variant discriminator | D-WIRE-03 |
| `bytes` | String | base64-STANDARD, padded | Arbitrary byte payload | D-WIRE-04 |

**`x509_cert` wire form (cipherpost/v1.1):**
```json
{"type": "x509_cert", "bytes": "<base64-STANDARD-padded>"}
```

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `type` | String | literal `"x509_cert"` | Variant discriminator | D-WIRE-03 |
| `bytes` | String | base64-STANDARD, padded — **canonical DER** per RFC 5280 strict profile | X.509 certificate bytes | D-P6-01, X509-01 |

The `bytes` field carries **canonical DER** (RFC 5280 strict profile, definite-length
encoding). CLI input MAY be DER or PEM; PEM is normalized to DER at ingest before JCS
hashing and Envelope construction so `share_ref` remains deterministic across re-sends
of semantically identical certificates (X509-01). Indefinite-length BER is rejected at
ingest (exit 1) with a generic user-facing message — NOT exit 3 (which is reserved for
signature failures per X509-08).

**Parser:** `x509-parser 0.16` with `default-features = false` and the `verify` feature
explicitly OFF. Enabling `verify` would pull `ring`, which is rejected by the supply-chain
policy (`.planning/research/SUMMARY.md §Phase 6`). A CI test
(`tests/x509_dep_tree_guard.rs`) runs `cargo tree` and fails the build if `ring` or
`aws-lc` ever appears in the dep graph — catches feature-flag regressions before they ship.

**DN rendering convention (OQ-3 resolved):** Subject / Issuer rendering in the
acceptance-banner subblock (§5.2) uses x509-parser's `Display` impl, which produces
**OpenSSL-forward ordering** (`C=US, O=..., CN=leaf`, matching `openssl x509 -noout -subject`)
— NOT strict RFC 4514 backward ordering. This matches security engineers' mental model.

**Oracle hygiene (X509-08):** Every parse / normalization / variant-mismatch failure path
returns `Error::InvalidMaterial { variant, reason }` with a short curated `reason` literal
(e.g., `"malformed DER"`, `"trailing bytes after certificate"`, `"PEM body decode failed"`,
`"PEM label is not CERTIFICATE"`, `"accessor called on wrong variant"`). The `reason` is
NEVER an `x509-parser` / `nom::` / `asn1-rs` / `der-parser` internal string — the enum
does not use `#[source]` or `#[from]` to prevent Display-chain leakage via `err.source()`.
A test (`tests/x509_error_oracle.rs`) enumerates every constructed reason across 4 variants
and asserts Display contains none of {`X509Error`, `parse error at`, `nom::`, `Incomplete`,
`Needed`, `PEMError`, `asn1-rs`, `der-parser`, `x509_parser::`}.

**Wire-budget note (cipherpost/v1.1 Phase 6 deferral):** Realistic X.509 certificates
exceed the 1000-byte BEP44 SignedPacket ceiling. Cipherpost surfaces this as a clean
`Error::WireBudgetExceeded { encoded, budget: 1000, plaintext }` at send time. See
§Pitfall #22 (consolidated below) for the cross-variant what-works-today matrix and
the v1.2 two-tier-storage architectural fix.

**`pgp_key` wire form (cipherpost/v1.1, Phase 7):**
```json
{"type": "pgp_key", "bytes": "<base64-STANDARD-padded>"}
```

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `type` | String | literal `"pgp_key"` | Variant discriminator | D-WIRE-03 |
| `bytes` | String | base64-STANDARD, padded — **binary OpenPGP packet stream** per RFC 4880 §4.2 / RFC 9580 §4.2 | OpenPGP key bytes (public TPK or secret TSK) | D-P7-01..09, PGP-01 |

The `bytes` field carries the **binary OpenPGP packet stream** verbatim from the
sender's input — no canonical re-encode. The RFC-defined packet stream IS canonical
(RFC 4880 §4.2); re-encoding through the `pgp` crate could alter insignificant
bits and drift `share_ref` across sender toolchains. CLI input MUST be binary;
**ASCII armor (`-----BEGIN PGP PUBLIC/PRIVATE KEY BLOCK-----`) is REJECTED at
ingest** with the exact reason `"ASCII-armored input rejected — supply binary
packet stream"` (D-P7-05 / PGP-01). Multi-primary keyrings (>1 top-level
PublicKey/SecretKey packet) are REJECTED at ingest with the count substituted
(D-P7-06 / PGP-03). Trailing bytes after the last valid packet are REJECTED
(WR-01 mirror; the `pgp` crate's `PacketParser` silently advances cursor past
0xFF stream-end magic, so the trailing-bytes oracle sums per-packet serialized
lengths via `pgp::ser::Serialize::to_writer` rather than relying on cursor
position).

**Parser:** `pgp 0.19.0` exact-pin with `default-features = false` (disables
`bzip2` and `asm` features). Pulls `rsa 0.9` transitively for RFC-4880 RSA
support (advisory RUSTSEC-2023-0071 accepted — see §Supply-Chain Deferrals).
Pulls `ed25519-dalek 2.x` transitively (coexists with cipherpost's
`=3.0.0-pre.5` pin — see §Supply-Chain Deferrals). Same dep-tree guard CI test
asserts no `ring` / `aws-lc` / `openssl-sys` leak.

**Oracle hygiene (PGP-08):** Every parse failure returns `Error::InvalidMaterial
{ variant: "pgp_key", reason }` with a short curated `reason` literal — never an
rpgp internal type or message. Audit set: `"ASCII-armored input rejected — supply
binary packet stream"`, `"PgpKey must contain exactly one primary key; keyrings
are not supported in v1.1 (found N primary keys)"` (N substituted), `"malformed
PGP packet stream"`, `"trailing bytes after PGP packet stream"`, `"accessor
called on wrong variant"`. A test (`tests/pgp_error_oracle.rs`) enumerates each
× 4 variants and asserts Display contains none of {`pgp::errors`, `PgpError`,
`pgp::packet`, `packet::Error`, `pgp::Error`, `rpgp`} plus the Phase 6 X.509
forbidden-token set.

**`ssh_key` wire form (cipherpost/v1.1, Phase 7 Plan 05+):**
```json
{"type": "ssh_key", "bytes": "<base64-STANDARD-padded>"}
```

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `type` | String | literal `"ssh_key"` | Variant discriminator | D-WIRE-03 |
| `bytes` | String | base64-STANDARD, padded — **canonical OpenSSH v1 PEM bytes** (UTF-8) | OpenSSH v1 private-key blob | D-P7-10..16, SSH-01..10 |

The `bytes` field carries the **canonical OpenSSH v1 PEM blob** (UTF-8) produced
by re-encoding the user's input through `ssh-key`'s `PrivateKey::to_openssh(LineEnding::LF)`
at ingest time (D-P7-11). Because OpenSSH v1 framing has historically tolerated
several superficial encoding variations (CRLF vs LF, different line widths,
whitespace trailers from text-editor saves), cipherpost re-encodes to a single
canonical byte stream so `share_ref` is deterministic across re-sends of
semantically identical keys.

CLI input MUST be OpenSSH v1 (`-----BEGIN OPENSSH PRIVATE KEY-----`). Other
formats are REJECTED at ingest with the distinct `Error::SshKeyFormatNotSupported`
variant (D-P7-12 — separate from `Error::InvalidMaterial` because the user-facing
message embeds a copy-pasteable `ssh-keygen -p -o -f <path>` conversion hint
that is variant-specific). Specifically rejected formats:
- Legacy PEM: `-----BEGIN RSA/DSA/EC PRIVATE KEY-----`
- RFC 4716 SSH2: `---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`
- OpenSSH-FIDO: `-----BEGIN OPENSSH-FIDO PRIVATE KEY-----`
- Arbitrary garbage / empty input

The Display of `Error::SshKeyFormatNotSupported` intentionally omits BOTH the
rejected format name (avoiding an info-disclosure oracle: "your input looked
like RSA-PEM") AND any ssh-key crate internal types — it is a single static
literal pointing the user at `ssh-keygen -p -o`. Maps to exit 1.

Trailing bytes after the `-----END OPENSSH PRIVATE KEY-----` marker are also
REJECTED (T-07-39 / WR-01 mirror) with `Error::InvalidMaterial { variant:
"ssh_key", reason: "trailing bytes after OpenSSH v1 blob" }` — guards against
attacker-appended trailers drifting `share_ref`. Whitespace-only trailers from
text-editor saves are tolerated (sliced off before parse).

**Parser:** `ssh-key 0.6.7` with `default-features = false, features = ["alloc"]`.
The `ed25519` feature is INTENTIONALLY OFF — D-P7-10 verified that Ed25519
parsing + `Fingerprint::compute(HashAlg::Sha256)` work without it (sha2 is
unconditional; only the ed25519-dalek interop `TryFrom` impls are gated). This
keeps the dep tree clean: ssh-key adds NO new ed25519-dalek version beyond the
existing pgp 0.19.0-transitive 2.x and pkarr-direct 3.0.0-pre.5 (verified by
`tests/x509_dep_tree_guard.rs::dep_tree_ssh_key_does_not_pull_ed25519_dalek_2_x_independently`).

**Oracle hygiene (SSH-08):** Every parse failure returns either
`Error::SshKeyFormatNotSupported` (format-rejection class) OR
`Error::InvalidMaterial { variant: "ssh_key", reason }` with a short curated
`reason` literal — never an ssh-key crate internal type or message. Audit set:
`"malformed OpenSSH v1 blob"`, `"trailing bytes after OpenSSH v1 blob"`,
`"accessor called on wrong variant"`. A test (`tests/ssh_error_oracle.rs`)
enumerates each × 4 variants and asserts Display contains none of
{`ssh_key::Error`, `ssh_key::`, `ssh_encoding`, `ssh_cipher`, `PemError`,
`ssh-key::`}.

**SHA-256-only fingerprint policy (D-P7-14):** The acceptance-banner subblock
(§5.2) renders ONLY the SHA-256 fingerprint via `Fingerprint::Display` (format
`SHA256:<base64-unpadded>`, matching `ssh-keygen -lf` byte-for-byte). MD5 and
SHA-1 fingerprints are NOT rendered — both are deprecated per OpenSSH 7.0+
release notes; surfacing them would invite users to verify against legacy
outputs that share-collide.

**Algorithm-deprecation `[DEPRECATED]` tag (D-P7-14):** When the parsed key's
algorithm is `ssh-dss` (any size) or `ssh-rsa` with bit length below 2048,
the banner Key line is suffixed with ` [DEPRECATED]`. The tag is **display-only**
— it does NOT block acceptance; senders MAY legitimately migrate legacy
infrastructure. The visible warning gives the recipient a chance to question
the handoff before the typed-z32 prompt completes.

### 3.3 OuterRecord

Published as a JSON TXT record under DNS label `_cipherpost` (D-05) on the sender's PKARR
key. The TXT value is the JSON serialization of `OuterRecord`. Inner signature is Ed25519
over JCS(`OuterRecordSignable`); outer signature is the PKARR SignedPacket signature handled
by `pkarr::ClientBlocking`.

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `blob` | String | base64-STANDARD | age-encrypted JCS bytes of `Envelope` | D-WIRE-01, D-WIRE-04 |
| `created_at` | i64 | JSON integer | Unix seconds, inner-signed; single TTL source | D-WIRE-02 |
| `protocol_version` | u16 | JSON integer | Always `1` | D-07 |
| `pubkey` | String | z-base-32, 52 chars | Sender Ed25519/PKARR public key | D-04, IDENT-05 |
| `recipient` | String OR JSON null | z-base-32 OR null | Recipient pubkey; null for `--self` sends | D-WIRE-04 |
| `share_ref` | String | 32 lowercase hex chars | 128-bit share ID: `sha256(blob_bytes ‖ created_at_be_bytes)[..16]` | D-06, PAYL-05 |
| `signature` | String | base64-STANDARD | Inner Ed25519 signature over JCS(`OuterRecordSignable`) | D-WIRE-03, SEND-04, D-16 |
| `ttl_seconds` | u64 | JSON integer | Share lifetime; default `86400` (24 h) | D-WIRE-02, SEND-03 |

**Signable projection:** `OuterRecordSignable` = `OuterRecord` minus `signature`. JCS-canonicalize
it, then Ed25519-sign. On verify, the receiver rebuilds `OuterRecordSignable` from the received
`OuterRecord`, re-serializes to JCS, and performs `verify_strict` against the decoded signature,
then additionally checks that re-serialization of the parsed input yields byte-identical JCS
output (canonicalization-bypass guard, defense against non-canonical-but-parseable input).

**share_ref derivation (D-06, PAYL-05):**
```
share_ref_bytes = SHA-256(ciphertext_blob_bytes || created_at_i64_big_endian_bytes)[0..16]
share_ref_hex   = lowercase_hex(share_ref_bytes)  // 32 chars
```
where `ciphertext_blob_bytes` = raw bytes obtained by base64-STANDARD-decoding `blob`
(i.e., the age ciphertext, not the base64 string), and `created_at_i64_big_endian_bytes` =
`i64::to_be_bytes(created_at)` (8 bytes).

### 3.4 Receipt

Published by the recipient under their own PKARR key at DNS label `_cprcpt-<share_ref_hex>`
(D-06). Signed with the recipient's Ed25519 identity key. Receipts are **public by design**:
no field is secret. Senders verify receipts using only public information.

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `accepted_at` | i64 | JSON integer | Unix seconds when acceptance completed | D-RS-02 |
| `ciphertext_hash` | String | lowercase hex, 64 chars | `SHA-256(blob_base64_decoded_bytes)` | D-RS-04 |
| `cleartext_hash` | String | lowercase hex, 64 chars | `SHA-256(JCS(Envelope))` — the decrypted canonical bytes | D-RS-04 |
| `nonce` | String | 32 lowercase hex chars | 128-bit random (OsRng) | D-RS-03 |
| `protocol_version` | u16 | JSON integer | Always `1` | D-07 |
| `purpose` | String | UTF-8, control chars already stripped at send | Verbatim copy of `Envelope.purpose` | D-RS-01, D-WIRE-05 |
| `recipient_pubkey` | String | z-base-32, 52 chars | Recipient Ed25519/PKARR public key | D-RS-01, D-RS-07 |
| `sender_pubkey` | String | z-base-32, 52 chars | Sender's PKARR public key (from `OuterRecord.pubkey`) | D-RS-01 |
| `share_ref` | String | 32 lowercase hex chars | Same `share_ref` as the originating OuterRecord | D-RS-01, D-06 |
| `signature` | String | base64-STANDARD | Ed25519 by recipient over JCS(`ReceiptSignable`) | D-RS-05, D-RS-07 |

**Signable projection:** `ReceiptSignable` = `Receipt` minus `signature`. Same sign/verify
discipline as `OuterRecordSignable` (D-RS-07).

**Receipt publication (TRANS-03, D-MRG-01..06):** Receipts are published via resolve-merge-
republish under the recipient's PKARR key. The recipient resolves their existing SignedPacket,
re-builds a new SignedPacket preserving all existing TXT records (including `_cipherpost`
outgoing shares and any prior `_cprcpt-*` receipts), adds or replaces the TXT under label
`_cprcpt-<this_share_ref_hex>` with the new receipt's JSON bytes, and re-signs. DNS TTL on
receipt TXT records = 300 seconds. The wire budget (~1000 bytes total SignedPacket) applies
to the merged packet; overflow surfaces `Error::WireBudgetExceeded { encoded, budget, plaintext: 0 }`
(plaintext=0 distinguishes receipt overflow from share overflow) — D-MRG-06.

**Publish sequencing (D-SEQ-01):** The recipient publishes the receipt only AFTER local state
commits (sentinel file + ledger line). Publish failure is degraded to a stderr warning with
exit code 0 (D-SEQ-02) — the material was delivered safely; receipt loss is a sender-visible
degradation. No auto-retry in cipherpost/v1 (D-SEQ-03).

### 3.5 DHT Label Stability

The DNS TXT record labels used in the wire format are part of the protocol surface:
- `_cipherpost` — published by senders carrying `OuterRecord` (§3.3)
- `_cprcpt-<share_ref_hex>` — published by recipients carrying `Receipt` (§3.4)

These label strings are part of the wire format. Renaming either — in whole or in part
— requires a `protocol_version` bump and a migration section in this SPEC. They are
not changed silently.

Code constants enforcing these labels are covered by a constant-match test
(`tests/dht_label_constants.rs`) that fails if code and SPEC drift.

### 3.6 PIN Crypto Stack (Phase 8 — D-P8-01..06)

PIN-protected shares (`OuterRecord.pin_required = true`) require BOTH the
receiver's identity passphrase AND a PIN to decrypt. The PIN is a second factor
layered via NESTED age encryption (CLAUDE.md `chacha20poly1305 only via age`
invariant — no direct AEAD calls). Non-pin shares (`pin_required` absent or
`false`) preserve the v1.0 wire shape byte-for-byte (the `pin_required` field
is elided from JCS via `skip_serializing_if = is_false`; no protocol_version
bump).

**Architectural lineage:** Forks cclink's `pin_derive_key` shape verbatim;
diverges on AEAD path (cclink uses raw `chacha20poly1305`; cipherpost wraps
the derived 32-byte scalar into an `age::x25519::Identity` and uses
`age::Encryptor::with_recipients`). HKDF namespace adapted from `cclink-pin-v1`
to `cipherpost/v1/pin` per cipherpost's domain-separation convention
(every HKDF info string starts with `cipherpost/v1/`; verified by
`tests/hkdf_info_enumeration.rs`).

**KDF parameters (locked):**

- **Argon2id** version 1.3 (`V0x13`): 64 MiB memory (`m_cost=65536`), 3
  iterations, 1 lane (`parallelism=1`), 32-byte output. Distinct lifecycle
  from the identity-KEK Argon2id params (which are READ FROM the identity
  file's PHC header per Pitfall #8). PIN params are share-level constants;
  bumping them requires a `protocol_version` bump.
- **HKDF-SHA256:** `salt = the same 32-byte random salt`; `ikm = Argon2id
  32-byte output`; `info = "cipherpost/v1/pin"` (referenced via
  `crate::crypto::hkdf_infos::PIN` constant — NEVER inline-literal). Output:
  32 bytes used as an X25519 scalar.
- **age `Identity`:** built from the 32-byte X25519 scalar via
  `crate::crypto::identity_from_x25519_bytes`. The `to_public()` recipient
  becomes the inner age-encryption recipient.

**Wire blob layout:**

- Non-pin shares: `blob = base64-STANDARD(outer_age_ct)` — exact v1.0 byte shape.
- PIN shares: `blob = base64-STANDARD(salt[32] || outer_age_ct)` — salt is the
  FIRST 32 raw bytes (read BEFORE any age-decrypt to derive `pin_recipient`).

**Nested age structure (PIN shares only):**

1. `inner_ct = age_encrypt(envelope_jcs, pin_recipient)`
2. `outer_ct = age_encrypt(inner_ct, receiver_recipient)`
3. `blob = base64(salt || outer_ct)`

**Receive flow ordering (D-P8-07).** PIN shares extend the §5.2 13-step
pipeline with a PIN dispatch step (6a) inserted BETWEEN outer-verify (steps
2/3) and outer age-decrypt (step 7). The TAMPER-ZERO INVARIANT is preserved:
outer-verify gates the PIN prompt, so a tampered share never reaches the
prompt — exit 3 sig failure with no PIN-prompt side effect. Concretely, when
`record.pin_required = true`, run_receive: (i) base64-decodes the blob,
(ii) splits the first 32 bytes as the salt, (iii) calls `prompt_pin(false)`
(no echo, single-shot — wrong PIN is the user's notification rather than a
re-prompt), (iv) derives `pin_identity` from PIN+salt, (v) age-decrypts the
outer ciphertext with the receiver identity to produce `inner_ct`,
(vi) age-decrypts `inner_ct` with `pin_identity` to produce `envelope_jcs`.
Only THEN does the §5.2 step 8 acceptance prompt run.

**Error-oracle constraint (PIN-07).** Wrong-PIN, wrong-passphrase, and
tampered inner-ciphertext all surface as `Error::DecryptFailed` with the
IDENTICAL user-facing Display (`"wrong passphrase or identity decryption
failed"`) and exit code 4. Sig-failures (`Error::Signature*`, exit 3) remain
a DIFFERENT lane — distinguishable by exit code, but both lanes preserve
user-facing Display equality WITHIN their lane (D-16 invariant for sig lane;
PIN-07 narrow invariant for credential lane).

**Entropy floor (PIN-02).** PIN must be ≥ 8 characters, not all-same
characters, not monotonic ascending, not monotonic descending, and not in
the blocklist (`password`, `qwerty`, `letmein`, `12345678`, `87654321`,
`qwertyui`, `asdfghjk` — case-insensitive). Rejection is GENERIC
(`"PIN does not meet entropy requirements"`, exit 1) — the specific reason
is NEVER named in user-facing output (oracle hygiene per PITFALLS #23/#24;
supersedes REQUIREMENTS PIN-02 wording per D-P8-12). The specific reason
IS asserted at the test layer (`tests/pin_validation.rs::rejects_*`), so
implementations remain testable. Length validation runs BEFORE Argon2id so
length-failures don't leak via wall-clock timing (T-08-15).

**Threat model.** See THREAT-MODEL.md §6.5 PIN mode for the threat-model
treatment — second-factor semantics, offline brute-force bound,
intentional indistinguishability invariant, and multi-machine
non-coordination caveat. PIN composes orthogonally with `--burn` (§3.7);
the two flags are independent and neither silently overrides the other.

### 3.7 Burn Semantics (Phase 8 — D-P8-04, D-P8-09..12)

Burn shares (`Envelope.burn_after_read = true`) are single-consumption from
the receiver's perspective. After a successful first receive, the local
ledger records `state: "burned"` and any subsequent receive against the same
`share_ref` returns exit 7 (`Error::Declined`) with stderr message
`share already consumed (burned at <timestamp>)`.

**Architectural choice — local-state-only.** Cipherpost burn is **local-state-only**
and explicitly REJECTS cclink's burn pattern (which publishes an empty PKARR
packet over the share's DHT slot to revoke it). Two reasons:

1. **Honest threat model.** Public DHT ciphertext cannot be force-deleted; it
   remains queryable until TTL expires (24h default). Cryptographic
   destruction is impossible without the receiver's identity passphrase.
2. **No DHT mutation.** Burn is a receiver-side semantics knob; mutating the
   DHT to enforce it would couple two threat surfaces unnecessarily, and would
   be ineffective against any observer who already cached the ciphertext.

**Wire shape:**

- `Envelope.burn_after_read: bool` — inner-signed, post-decrypt. DHT observers
  do NOT see this field (CLAUDE.md ciphertext-only-on-wire principle).
- `#[serde(default, skip_serializing_if = "is_false")]` — non-burn shares
  preserve v1.0 byte-identity (no `protocol_version` bump).
- JCS alphabetic placement: FIRST (before `created_at` because `b` < `c`).
- Pinned by `tests/fixtures/envelope_burn_signable.bin` (~142 B).

**Receive flow ordering (D-P8-12 emit-before-mark for burn).** §5.2's
13-step pipeline gains a STEP 1 ledger pre-check (Phase 8 Plan 03) and an
emit-then-mark dispatch at STEP 11/12 (Phase 8 Plan 04):

1. STEP 1 — early ledger pre-check returns `LedgerState`:
   - `LedgerState::Burned { burned_at }` → return `Error::Declined` (exit 7);
     stderr `share already consumed (burned at <ts>)`; NO new receipt
     published.
   - `LedgerState::Accepted { ... }` → existing v1.0 idempotent-success path
     (no re-decrypt, no new emit, no new receipt; exit 0).
   - `LedgerState::None` → proceed.
2-10. Standard receive flow (outer-verify → optional PIN prompt per §3.6 →
    nested age-decrypt when `pin_required` → inner-verify → JCS parse →
    typed-material preview render → acceptance banner with optional
    `[BURN — you will only see this once]` marker at TOP → typed-z32
    acceptance prompt). The marker emits ONLY when `burn_after_read=true`;
    non-burn shares see the v1.0 banner shape verbatim.
11. **Emit decrypted bytes to stdout / file / sink.**
12. **`create_sentinel(&share_ref)` then ledger row write.** The dispatch
    selects the helper by `envelope.burn_after_read`:
    - **Burn flow:** `append_ledger_entry_with_state(Some("burned"), ...)`.
      Crash sequence guarantee: emit (STEP 11) → sentinel (STEP 12 part 1)
      → ledger row with `state: "burned"` (STEP 12 part 2). A crash between
      STEP 11 (emit) and the ledger write leaves the share re-receivable
      on next invocation — this is the **safer failure mode** (the user
      keeps access to their data) compared to mark-then-emit, which would
      lose the user's data to a half-completed state write.
    - **Accepted flow (v1.0 unchanged):** `append_ledger_entry(...)`. The
      ledger row has no `state` field; deserializes via serde default to
      `state: None` and maps to `LedgerState::Accepted` on read.
13. **Publish receipt — UNCONDITIONAL (BURN-04).** No `if !envelope.burn_after_read`
    guard around `publish_receipt`. Receipt = delivery confirmation; burn does
    NOT suppress attestation. Asserted by `tests/burn_roundtrip.rs`'s
    receipt-count assertion (== 1 after first-then-second receive).

**Burn ≠ cryptographic destruction.** A second machine with a fresh
ledger can still decrypt the same share until TTL expires. Burn IS:

- A safeguard against accidental re-decryption on the same machine.
- A signal of intent (the sender wanted single-consumption).

Burn is NOT:

- Cryptographic erasure of the DHT ciphertext.
- Multi-machine consumption coordination.
- A replacement for TTL-based ciphertext expiry.

See THREAT-MODEL.md §Burn mode for the multi-machine race threat analysis
(Plan 06 lands the prose).

**PITFALLS.md #26 supersession.** Phase 8's emit-before-mark write order
supersedes the original mark-then-emit analysis in
`.planning/research/PITFALLS.md` section #26. The header in that file
documents the resolution; the original analysis is preserved as the
rejected alternative. The rejection rationale: data-loss-on-crash is the
worst outcome for burn (one-shot consume), while re-receivable-on-crash
is acceptable (the share is still TTL-bounded, and the user keeps their
data). v1.0's accepted flow keeps mark-then-emit unchanged (re-emit on
crash is fine for the idempotent-persistence contract).

**PIN × BURN compose orthogonality (D-P8-13).** PIN and BURN are
independent flags. PIN lives on `OuterRecord.pin_required` (outer-signed,
DHT-visible — see §3.6); BURN lives on `Envelope.burn_after_read`
(inner-signed, post-decrypt). A share can carry both flags simultaneously
without collision; neither flag silently overrides the other.

**Threat model.** See THREAT-MODEL.md §6.6 Burn mode for the threat-model
treatment — multi-machine race, DHT-survives-TTL, burn ≠ cryptographic
destruction, and the emit-before-mark atomicity invariant.
`.planning/research/PITFALLS.md` #26 carries the SUPERSEDED-by-D-P8-12
header preserving the rejected mark-then-emit alternative.

## 4. Share URI

A share URI is a single copy-paste token that identifies where to resolve a share and what
`share_ref` to expect:

```
cipherpost://<sender-z32>/<share_ref_hex>
```

- `<sender-z32>` is the sender's PKARR public key in z-base-32 (52 chars) — matches
  `OuterRecord.pubkey`.
- `<share_ref_hex>` is the 32-char lowercase hex share_ref.
- Total length ≈ 99 characters.

**Example:**
```
cipherpost://yhigci4xwmadibrmj8wzmf45f3i8xg8mht9abnprq3r5cfxihj8y/0123456789abcdef0123456789abcdef
```

The receiver MUST require the full `cipherpost://` URI form. Bare z-base-32 input is rejected
with `Error::InvalidShareUri` (D-URI-03). After resolving `OuterRecord`, the receiver MUST
check that `url_share_ref == OuterRecord.share_ref`; mismatch yields `Error::ShareRefMismatch`
(D-URI-02; exit code 1, distinct from signature failures exit 3 and NotFound exit 5).

No query string or fragment parameters are defined in cipherpost/v1; unknown trailing
components MUST be treated as `Error::InvalidShareUri`. Future versions may extend the URI
syntax under a bumped protocol version.

## 5. Flows

### 5.1 Send

1. Read payload from `<path>` or `-` (stdin). (SEND-01, PAYL-03)
2. **Ingest (cipherpost/v1.1):** dispatch on `--material <variant>` (default
   `generic-secret`). Accepted values: `generic-secret`, `x509-cert`,
   `pgp-key` (Phase 7 Plan 01-04 — LIVE), `ssh-key` (Phase 7 Plan 05-08 — LIVE).
   - `payload::ingest::x509_cert(raw)` sniffs PEM vs DER (ASCII-whitespace-
     trim + `-----BEGIN CERTIFICATE-----` header check), normalizes PEM →
     canonical DER, and validates via `x509-parser` strict profile with an
     explicit trailing-bytes check.
   - `payload::ingest::pgp_key(raw)` strict-rejects ASCII armor (any `-----BEGIN
     PGP` prefix after whitespace skip), iterates top-level packets via
     `pgp::packet::PacketParser`, counts top-level Tag::PublicKey + Tag::SecretKey
     packets (rejects keyrings with N substituted), and asserts the sum of
     per-packet serialized lengths equals `raw.len()` (trailing-bytes invariant
     resilient to rpgp's silent-0xFF parser quirk). Returns `Material::PgpKey
     { bytes: raw.to_vec() }` with no canonical re-encode — the binary packet
     stream IS canonical (RFC 4880 §4.2).
   - `payload::ingest::ssh_key(raw)` strict-rejects non-OpenSSH-v1 input with
     `Error::SshKeyFormatNotSupported` (legacy PEM RSA/DSA/EC, RFC 4716 SSH2,
     OpenSSH-FIDO, garbage), checks for trailing bytes after the
     `-----END OPENSSH PRIVATE KEY-----` marker, parses via `ssh-key`'s
     `PrivateKey::from_openssh`, and re-encodes canonically via
     `to_openssh(LineEnding::LF)` (D-P7-11). Returns `Material::SshKey
     { bytes: <canonical OpenSSH v1 PEM bytes> }`.
   - Parse failure → `Error::InvalidMaterial { variant, reason }` exit 1.
   - SSH-specific format-rejection → `Error::SshKeyFormatNotSupported` exit 1
     (distinct variant; user message embeds `ssh-keygen -p -o -f <path>` hint).
3. **Plaintext cap (D-P6-16 / X509-06):** reject if `material.plaintext_size() >
   65 536`. For `x509_cert`, this is the **decoded DER length** — a 1 MB
   PEM input that decodes to 100 KB DER fails the cap on the decoded size,
   not the input size (PAYL-03). For `pgp_key`, this is the **raw binary
   packet-stream length** (no PEM-style decode applies; armor is rejected).
   For `ssh_key`, this is the **canonical re-encoded UTF-8 PEM byte length**
   (i.e., the bytes stored in `Material::SshKey` after `to_openssh(LineEnding::LF)`,
   not the raw input).
4. Build `Envelope { purpose, material, created_at, protocol_version }` with `purpose` control-
   stripped (D-WIRE-05). JCS-serialize.
5. age-encrypt the JCS bytes to the recipient's X25519 (derived from their Ed25519 pubkey) or
   to the sender's own X25519 for `--self` (SEND-01, SEND-02). Base64-STANDARD-encode to produce `blob`.
6. Compute `share_ref = sha256(ciphertext_blob_bytes || created_at.to_be_bytes())[..16]` (D-06).
7. Build `OuterRecordSignable { blob, created_at, protocol_version, pubkey, recipient, share_ref, ttl_seconds }`.
8. JCS-serialize `OuterRecordSignable`; Ed25519-sign with the sender's identity key; base64-
   encode to produce `signature`. Assemble `OuterRecord` (D-WIRE-03, SEND-04).
9. Build PKARR SignedPacket with TXT record under `_cipherpost` carrying the `OuterRecord` JSON.
   Verify encoded SignedPacket size ≤ ~1000 bytes (BEP44 budget, SEND-05). Overflow = `Error::WireBudgetExceeded`.
10. `Transport::publish(signed_packet)`. Print the share URI (`cipherpost://<z32>/<hex>`) to stdout (D-URI-01, SEND-01).

**CLI flags (cipherpost/v1.1):**
- `--material <VALUE>` (default `generic-secret`) — selects the typed
  Material variant. Accepted: `generic-secret` (Phase 5), `x509-cert`
  (Phase 6), `pgp-key` (Phase 7 Plan 01-04 — LIVE), `ssh-key` (Phase 7
  Plan 05-08 — LIVE).

**`--material pgp-key` example:**
```
cipherpost send --self -p 'alice keyshare' --material pgp-key --material-file ./alice.pgp
```

**`--material ssh-key` example:**
```
cipherpost send --self -p 'server bootstrap' --material ssh-key --material-file ./id_ed25519
```

**`--armor` matrix (cipherpost/v1.1, FINAL):**
| `--material` | `--armor` accepted? | Behavior |
|--------------|---------------------|----------|
| `x509-cert` | YES | wraps as PEM `-----BEGIN CERTIFICATE-----` (Phase 6) |
| `pgp-key` | YES | wraps as ASCII armor via rpgp `to_armored_bytes` (Phase 7 Plan 03) |
| `generic-secret` | NO | `Error::Config("--armor requires --material x509-cert or pgp-key")` exit 1 (Plan 03 widened literal) |
| `ssh-key` | NO | `Error::Config("--armor not applicable to ssh-key — OpenSSH v1 is self-armored")` exit 1 (Plan 07; D-P7-13 — variant-specific rationale because OpenSSH v1 is ALREADY armored, wrapping again would produce nonsense) |

Both `--armor` rejection literals fire BEFORE the preview parse runs (cost-on-error
+ pre-emit surface hygiene per D-RECV-01 / T-07-49).

**`--pin` (cipherpost/v1.1, Phase 8 PIN-01):** Require a PIN as a second factor.
Bool flag — clap rejects argv-inline `--pin <value>` naturally (no
`Option<String>` shape). PIN is read from TTY at send time with double-entry
confirmation (`prompt_pin(confirm=true)` — a typo'd PIN bricks decryptability,
so confirmation matches the rationale of `identity generate`'s `confirm_on_tty=true`).
The receiver is prompted at receive time (single-shot — wrong PIN funnels through
`Error::DecryptFailed` exit 4, the user's notification). Both the receiver's
identity passphrase AND the PIN are required to decrypt PIN-protected shares.
Non-interactive PIN sources (`--pin-file`, `--pin-fd`, `CIPHERPOST_PIN` env)
are deferred to v1.2 — v1.1 keeps PIN as an intentionally human-in-the-loop
second factor. PIN entropy validation runs at send time and rejects with
exit 1 / generic `"PIN does not meet entropy requirements"` Display (oracle
hygiene per PIN-07; specific reason is NEVER named). See §3.6 for the full
KDF + wire-blob layout + receive-flow ordering.

```
cipherpost send --pin --self -p 'high-value backup' --material-file ./vault.key
```

**`--burn` (cipherpost/v1.1, Phase 8 BURN-01):** Mark the share as
single-consumption. Bool flag. Sets `Envelope.burn_after_read = true`
(inner-signed, post-decrypt — DHT observers cannot distinguish burn-marked
shares from regular shares on the wire). Send-time stderr surfaces a
warning that burn is **local-state-only** (BURN-05) — different machines
with fresh ledgers can each decrypt the share once until TTL expires; burn
is NOT cryptographic destruction. Receive-time prepends a
`[BURN — you will only see this once]` marker above the acceptance banner
(D-P8-08). On the FIRST successful receive, the local ledger writes
`state: "burned"`; subsequent receives against the same `share_ref` return
exit 7 (`Error::Declined`) with stderr message
`share already consumed (burned at <ts>)`. Receipt publication is
UNCONDITIONAL on burn-receive (BURN-04 — burn does not suppress
attestation). Composes orthogonally with `--pin` (D-P8-13); see §3.7 for
the receive-flow ordering, emit-before-mark atomicity contract, and the
ledger row schema migration path.

```
cipherpost send --burn --self -p 'one-shot bootstrap token' --material-file ./token.txt
cipherpost send --pin --burn --self -p 'pin+burn compose' --material-file ./secret.bin
```

### 5.2 Receive

Strict order (D-RECV-01 + D-SEQ-01 combined — 13 steps):

1. Parse URI; extract `sender_z32` and `url_share_ref`. Malformed → `Error::InvalidShareUri` (D-URI-03).

   **cipherpost/v1.1.x: Per-`share_ref` advisory lock (Quick 260427-axn).** Immediately
   after URI parse and BEFORE step 2's idempotency check, `run_receive` acquires an
   exclusive `flock` on `~/.cipherpost/state/locks/<url_share_ref>.lock` (file mode
   `0600`, directory mode `0700`). The lock spans steps 2–12 (idempotency check →
   resolve → verify → decrypt → accept → emit → sentinel + ledger row) and is
   released BEFORE step 13's `publish_receipt` so the receipt path's existing CAS
   contract handles concurrent receipt writes (D-P9-A1; `tests/cas_racer.rs`). The
   lock closes the same-host TOCTOU window where two concurrent `cipherpost receive`
   invocations on the same `share_ref` could both pass step 2's `check_already_consumed`,
   both decrypt + emit, and both append ledger rows. Lock granularity is per-`share_ref`,
   so distinct shares don't serialize. Lock-acquisition I/O failures collapse into
   `Error::Io` — no new public `Error` variant is introduced (Pitfall #16 oracle
   hygiene). Burn-flow emit-before-mark ordering (D-P8-12) is unchanged inside the
   lock; serialization is the only behavioral change. Cross-host coordination is still
   out of scope (D-STATE-01) — the lock is local-filesystem only. Regression coverage:
   `tests/state_ledger_concurrency.rs` (Barrier-synced accepted, burn, and
   distinct-share_ref cases).
2. Check sentinel file at `~/.cipherpost/state/accepted/<url_share_ref>`; if present, print
   prior acceptance timestamp and exit 0 (RECV-06, D-RECV-02, D-STATE-01). No network call.

   **cipherpost/v1.1: BURN ledger pre-check (Phase 8 D-P8-09 / BURN-02).** The sentinel
   step is augmented with a ledger-state probe: if the sentinel exists, look up the
   matching ledger row by `share_ref`. If the row carries `state: "burned"`, return
   `Error::Declined` (exit 7) with stderr message
   `share already consumed (burned at <timestamp>)`. v1.0 rows missing the `state`
   field deserialize via serde default to `LedgerState::Accepted` (T-08-17 conservative
   classification). See §3.7 for the receive-flow ordering and ledger schema details.
3. `Transport::resolve(sender_z32)` — returns `OuterRecord` only after the outer PKARR
   SignedPacket signature passes (verified inside `pkarr::ClientBlocking`). NotFound → exit 5.
4. Verify inner Ed25519 signature on `OuterRecord` via `verify_record` (round-trip-reserialize
   guard included). Any signature failure → unified message, exit 3 (D-16, RECV-01).
5. Check `url_share_ref == OuterRecord.share_ref`; mismatch → `Error::ShareRefMismatch`, exit 1 (D-URI-02).
6. TTL check against `OuterRecord.created_at + OuterRecord.ttl_seconds`. Expired → exit 2 (RECV-02).

   **cipherpost/v1.1: PIN dispatch (Phase 8 PIN-06).** When `OuterRecord.pin_required = true`,
   step 6a runs after TTL and BEFORE step 7's age-decrypt: (a) base64-decode `blob`
   (≥ 32 bytes required, else `Error::SignatureCanonicalMismatch` exit 3 — same oracle-
   hygiene treatment as a malformed blob); (b) split first 32 bytes as the PIN salt;
   (c) `prompt_pin(confirm=false)` — TTY-only, single-shot, no echo (non-TTY context →
   `Error::Config` exit 1, no state mutation, no receipt published — share remains
   re-receivable when a PIN is later available); (d) derive `pin_identity` from
   PIN + salt via Argon2id + HKDF-SHA256 with info `cipherpost/v1/pin` (§3.6);
   (e) step 7's age-decrypt becomes NESTED: outer with the receiver identity
   produces `inner_ct`, inner with `pin_identity` produces `envelope_jcs`.
   Wrong PIN at the inner step → `Error::DecryptFailed` exit 4 with the
   IDENTICAL Display as a wrong identity-passphrase failure (PIN-07).
7. age-decrypt `OuterRecord.blob` into a `Zeroizing<Vec<u8>>`. Decryption failure → exit 4 (RECV-03).
8. Parse decrypted bytes as JCS → `Envelope`. JCS parse failure → `Error::SignatureCanonicalMismatch`,
   exit 3 (D-RECV-01 step 7).
9. Render acceptance screen on **stderr** (D-ACCEPT-02). Layout:
   ```
   === CIPHERPOST ACCEPTANCE ===============================
   Purpose:     "<control-stripped purpose>"
   Sender:      ed25519:SHA256:<openssh-fingerprint>
                <sender z32 52 chars>
   Share ref:   <32-char hex>
   Type:        generic_secret
   Size:        <N> bytes
   TTL:         <Xh Ym> remaining (expires <ISO UTC> / <local>)
   =========================================================
   To accept, paste the sender's z32 pubkey and press Enter:
   >
   ```

   **cipherpost/v1.1: [BURN] banner marker (Phase 8 D-P8-08 / BURN-05).** When
   `Envelope.burn_after_read = true`, a single literal-em-dash marker line
   `[BURN — you will only see this once]` is prepended to the acceptance banner
   ABOVE the `Purpose:` line (and ABOVE any X.509 / OpenPGP / SSH subblock). The
   marker fires AFTER inner-verify gates (the verify-before-reveal invariant
   below — burn is an inner-signed `Envelope` field, not an outer field — so a
   tampered share never surfaces the marker). Non-burn shares see the v1.0
   banner shape verbatim. See §3.7 for the receive-flow ordering and the
   emit-before-mark atomicity contract.

   **cipherpost/v1.1: X.509 subblock** — when `Type: x509_cert`, a typed subblock
   is inserted between the `Size:` and `TTL:` lines (Phase 6 D-P6-09 / X509-04):
   ```
   --- X.509 -------------------------------------------------
   Subject:     CN=..., O=..., C=...           (OpenSSL-forward; truncated ≤80 chars)
   Issuer:      CN=..., O=..., C=...           (OpenSSL-forward; truncated ≤80 chars)
   Serial:      0x<hex>                         (truncated at 16 hex w/ `… (truncated)` if long)
   NotBefore:   YYYY-MM-DD HH:MM UTC
   NotAfter:    YYYY-MM-DD HH:MM UTC  [VALID]   (or `[EXPIRED]`)
   Key:         <human-readable>                (Ed25519, RSA-2048, ECDSA P-256, ...)
   SHA-256:     <64 hex chars lowercase>        (over canonical DER)
   ```
   The separator line is exactly `--- X.509 ` + 57 dashes = 61 chars, matching the
   `===` banner border width. Phase 7 added analogous `--- OpenPGP ---` and
   `--- SSH ---` subblocks (below). Parse failures on the banner render return
   `Error::InvalidMaterial { variant: "x509_cert", reason: "<short>" }` with
   the same generic-reason set as ingest.

   **cipherpost/v1.1: OpenPGP subblock (Phase 7 D-P7-07 / D-P7-08 / PGP-04)** —
   when `Type: pgp_key`, a typed subblock is inserted between the `Size:` and
   `TTL:` lines:
   ```
   --- OpenPGP -----------------------------------------------    (53 dashes after prefix)
   Fingerprint: <40-hex for v4 keys; 64-hex for v5/v6>            (UPPER-case hex via rpgp Fingerprint UpperHex impl)
   Primary UID: <UID, truncated at 64 chars w/ `…`>               (control chars stripped — banner-injection mitigation)
   Key:         <Ed25519 | EdDSA-Legacy | RSA-N | ECDSA P-N | ECDH-curve | …>
   Subkeys:     <N (alg1, alg2, ...)  or  "0">
   Created:     YYYY-MM-DD HH:MM UTC
   ```

   The separator line is exactly `--- OpenPGP ` + 53 dashes = 65 chars.

   **SECRET-key warning (D-P7-07).** When the primary packet is a Secret-Key
   packet (RFC 4880 §4.3 tag-5), the subblock is preceded by a warning line +
   blank line:
   ```
   [WARNING: SECRET key — unlocks cryptographic operations]

   --- OpenPGP -----------------------------------------------
   Fingerprint: ...
   ...
   ```

   The warning is visual emphasis only — it does NOT block acceptance. Senders
   MAY legitimately hand off secret keys (the core cipherpost use case); the
   typed-z32 acceptance gate still applies in either case.

   Parse failures on the PGP banner return `Error::InvalidMaterial { variant:
   "pgp_key", reason: "malformed PGP packet stream" }` — same single literal as
   ingest, so an oracle adversary cannot distinguish "ingest rejection" from
   "preview rejection" via the error string.

   **cipherpost/v1.1: SSH subblock (Phase 7 D-P7-14 / D-P7-15 / SSH-04)** —
   when `Type: ssh_key`, a typed subblock is inserted between the `Size:` and
   `TTL:` lines:
   ```
   --- SSH ---------------------------------------------------    (57 dashes after prefix)
   Key:         <ssh-ed25519 256 | ssh-rsa 2048 | ssh-rsa 1024 [DEPRECATED] | ssh-dss [DEPRECATED] | ecdsa-sha2-nistp256 256 | …>
   Fingerprint: SHA256:<43 base64-unpadded chars>                 (matches `ssh-keygen -lf` byte-for-byte)
   Comment:     [sender-attested] <comment, truncated 64 chars w/ `…`; `(none)` if empty>
   ```

   The separator line is exactly `--- SSH ` + 57 dashes = 65 chars (matching
   the `--- OpenPGP ---` width). Algorithm names use ssh-key 0.6.7's
   `Algorithm::as_str()` wire-form output (`ssh-ed25519`, `ssh-rsa`, `ssh-dss`,
   `ecdsa-sha2-nistp256/384/521`) — NOT a friendly-name remapping, so the
   recipient sees the same identifier they'd see in `~/.ssh/authorized_keys`
   and `ssh-keygen -lf` output.

   **`[DEPRECATED]` tag (D-P7-14):** Display-only. Triggered for `ssh-dss`
   (any size) and `ssh-rsa` keys with bit length below 2048. The tag does
   NOT block acceptance — senders MAY legitimately migrate legacy
   infrastructure. The user sees the warning before the typed-z32 prompt.

   **SHA-256-only fingerprint (D-P7-14):** MD5 and SHA-1 fingerprint forms
   are NOT rendered. Both are deprecated per OpenSSH 7.0+ release notes;
   surfacing them would invite users to verify against legacy outputs that
   share-collide.

   **`[sender-attested]` comment label (D-P7-15):** SSH key comments are
   attacker-mutable (any sender can put anything in the comment), so explicit
   labeling prevents user confusion ("I sent the alice key but it says bob
   in the comment"). The `(none)` placeholder for empty comments is rendered
   with the same `[sender-attested]` prefix for consistency.

   **No SECRET-key warning on SSH (D-P7-14):** Unlike the PGP subblock, SSH
   does NOT prepend a `[WARNING: SECRET key …]` line — OpenSSH v1 ALWAYS
   contains a private key, so warning every time is noise. The `[DEPRECATED]`
   algorithm tag is the softer concern the SSH subblock surfaces instead.

   Parse failures on the SSH banner return `Error::InvalidMaterial { variant:
   "ssh_key", reason: "malformed OpenSSH v1 blob" }` — same single literal as
   ingest, so an oracle adversary cannot distinguish "ingest rejection" from
   "preview rejection" via the error string.

   Stdin AND stderr MUST both be TTYs; else `Error::Config`, exit 1 (D-ACCEPT-03).
10. Read user input; compare byte-equal (after `trim()`) to the sender's full 52-char z-base-32
    pubkey. Mismatch → `Error::Declined`, exit 7 (D-ACCEPT-01, RECV-04).
11. Write decrypted payload to `--output <path>` or stdout (default) (RECV-05).
    With `--armor` (cipherpost/v1.1):
    - **`x509-cert`** → wrapped as PEM (`-----BEGIN CERTIFICATE-----` +
      base64-STANDARD body 64-char-wrapped + `-----END CERTIFICATE-----\n`),
      byte-compatible with `openssl x509 -in <der> -inform DER -outform PEM`.
    - **`pgp-key`** (Phase 7) → wrapped as RFC 4880 ASCII armor via rpgp's
      `SignedPublicKey::to_armored_bytes(ArmorOptions::default())` for tag-6
      primaries (header `-----BEGIN PGP PUBLIC KEY BLOCK-----`) or
      `SignedSecretKey::to_armored_bytes(ArmorOptions::default())` for tag-5
      primaries (header `-----BEGIN PGP PRIVATE KEY BLOCK-----`). Default
      `ArmorOptions` = `{ headers: None, include_checksum: true }` (CRC24 line
      per RFC 4880 §6.1).
    - **`generic-secret`** → REJECTED with
      `Error::Config("--armor requires --material x509-cert or pgp-key")`
      at exit 1 (Phase 7 Plan 03 widened literal).
    - **`ssh-key`** → REJECTED with
      `Error::Config("--armor not applicable to ssh-key — OpenSSH v1 is self-armored")`
      at exit 1 (Phase 7 Plan 07 / D-P7-13 — variant-specific rationale because
      OpenSSH v1 is ALREADY armored, wrapping again would produce nonsense).
      Both rejection literals fire BEFORE the preview parse runs (cost-on-error
      + pre-emit surface hygiene).

    Armor matrix (cipherpost/v1.1, FINAL):
    ```
    --armor accepted for:   x509-cert | pgp-key
    --armor rejected for:   generic-secret | ssh-key (each with a content-specific literal)
    ```
12. Create sentinel `~/.cipherpost/state/accepted/<share_ref>` (mode 0600); append a ledger
    line to `~/.cipherpost/state/accepted.jsonl` (mode 0600) with `receipt_published_at: null` (D-STATE-01, D-SEQ-04).
13. Construct `Receipt`, sign with recipient's Ed25519 key, call `Transport::publish_receipt`.
    On success: append a new ledger line with `receipt_published_at: <ISO-8601 UTC>` (D-SEQ-04,
    D-SEQ-05). On failure: print `receipt publish failed: <user_message>` to stderr, continue,
    exit 0 anyway (D-SEQ-02). No auto-retry (D-SEQ-03).

**No payload field** (including `purpose`) is printed to stdout or stderr before step 9 begins
(D-RECV-01). This is the "verify before reveal" invariant.

### 5.3 Receipts (sender-side fetch and verify)

1. `cipherpost receipts --from <recipient-z32> [--share-ref <ref>] [--json]` (RCPT-02).
2. `Transport::resolve_all_cprcpt(recipient_z32)` → iterator over all TXT records under
   recipient's PKARR key with label prefix `_cprcpt-` (D-OUT-03).
3. For each record: parse JSON → `Receipt`. Parse failure → increment `malformed_count`. Otherwise
   `verify_receipt(&r)`. Signature-failure → increment `invalid_count`. Otherwise include.
4. If `--share-ref <ref>` given, filter verified receipts to exact match after verification.
5. Render on stdout (human table by default; `--json` emits JSON array on stdout — D-OUT-01);
   progress `fetched N receipt(s); M valid, K malformed, L invalid-signature` on stderr
   (omit zero-count categories — D-OUT-03).
6. Exit codes (D-OUT-03):
   - ≥1 valid: exit 0
   - 0 valid + ≥1 invalid-signature: exit 3
   - 0 valid + only malformed: exit 1
   - 0 TXT records under `_cprcpt-`: exit 5

## 6. Exit Codes

Cipherpost exits with a narrow, fixed set of codes. All signature-verification failures
collapse to exit `3` with a single user-facing message to prevent distinguishing-oracle
attacks (D-16).

| Code | Meaning | User-facing message | Error variants (internal) |
|------|---------|---------------------|---------------------------|
| 0 | Success | — | — |
| 1 | Generic error | `<sanitized anyhow message>` | `Config`, `InvalidShareUri`, `ShareRefMismatch`, `WireBudgetExceeded`, `NotImplemented`, `PayloadTooLarge`, **`InvalidMaterial { variant, reason }`** (X509-08 — content error at ingest, distinct from exit 3 sig failures; Display is `invalid material: variant=..., reason=...` with no parser internals leaked), **`SshKeyFormatNotSupported`** (Phase 7 Plan 05 / D-P7-12 — input not OpenSSH v1; distinct variant because Display embeds the `ssh-keygen -p -o -f <path>` conversion hint that would be wrong for non-SSH content errors; SPEC §3.2 SshKey), any unclassified |
| 2 | TTL expired | `share expired` | `Expired` |
| 3 | Signature verification failed | `signature verification failed` | `SignatureOuter`, `SignatureInner`, `SignatureCanonicalMismatch` (D-16 unified) |
| 4 | Passphrase / decryption failure | `wrong passphrase or identity decryption failed` | `DecryptFailed` (Phase 8 PIN-07: covers wrong identity-passphrase OR wrong PIN OR tampered inner age ciphertext — IDENTICAL Display across all three credential-failure modes; oracle hygiene — see §3.6 PIN Crypto Stack), `IdentityPermissions`, `PassphraseInvalidInput` |
| 5 | Not found on DHT | `not found` | `NotFound` |
| 7 | User declined acceptance OR (Phase 8 BURN-02) share already consumed (burned). Stderr message: `declined` for typed-z32 mismatch; `share already consumed (burned at <timestamp>)` for the burn-already-consumed case (§3.7). | `declined` / `share already consumed (burned at <ts>)` | `Declined` |

**Source chains are never displayed** (D-15). The binary matches on the top-level `Error`
variant to pick exit code + sanitized user message; the `#[source]` chain (e.g., `age::DecryptError`,
`pkarr::Error`, `io::Error`) remains reachable for `RUST_LOG=debug` but never appears on stderr.
A test (`tests/debug_leak_scan.rs` and related) scans stderr output for variants of bad-input
invocations and asserts no `age::`, `pkarr::`, `Os {`, or similar substring leaks (D-15, CLI-05).

Network-layer errors (DHT request timeout, connection failure) surface as `Error::Network`
with exit code `6` — reserved for TRANS-04 `--dht-timeout` and transport failures that are
not `NotFound`.

CLI argument parse failures (e.g., `--passphrase <value>` inline argv) exit via clap's
default path (typically exit `2` from clap, distinct from cipherpost's `Error::Expired`
exit `2` — the clap-level exit only happens before cipherpost's dispatcher runs, so there
is no ambiguity at runtime).

## Supply-Chain Deferrals

Three acceptances documented here, with the rationale for each. Revisit when the noted
upstream condition is satisfied.

### MSRV bumped to Rust 1.88 (Phase 7 D-P7-20)

Required by `pgp 0.19.0`. Rust 1.88 has been stable since mid-2025 (~10 months at Phase 7
ship time), so low compat risk. No cipherpost downstream users yet (pre-v1.1 public);
MSRV bump is low-impact. The bump touches both `Cargo.toml` (`rust-version = "1.88"`)
and `rust-toolchain.toml` (`channel = "1.88"`) so the toolchain itself does not reject
its own MSRV pin. Revisit if rpgp's minimum lowers.

### RUSTSEC-2023-0071 (Marvin Attack via `rsa 0.9`) — ACCEPTED (Phase 7 D-P7-21)

Transitively pulled by `pgp 0.19.0` for RFC 4880 RSA key support. No patched `rsa` version
exists at Phase 7 ship time. Cipherpost uses the pgp crate **only for packet parsing and
metadata extraction** — NO RSA decryption/signing operations anywhere in the code. The
Marvin timing attack requires a network-observable decryption/signing oracle; no such
surface exists in cipherpost's parse-only code path. Impact: low. Accepted via
`deny.toml [advisories] ignore` entry. **Revisit** when upstream `rsa` crate ships a
constant-time patched version.

### ed25519-dalek dual-version coexistence (Phase 7 D-P7-22)

The `pgp 0.19.0` crate unconditionally pulls `ed25519-dalek 2.x` (the `>=2.1.1` cargo
constraint resolves upward to the current latest 2.x release — measured `2.2.0` at Plan 01
ship time); cipherpost's core identity uses `ed25519-dalek =3.0.0-pre.5` (pinned to match
`pkarr 5.0.x`'s required pre-release). The cipherpost binary therefore carries TWO
ed25519-dalek implementations.

- **Runtime risk: LOW** — each crate uses its own pinned version; no cross-crate interop
  of Ed25519 keys beyond what rpgp internally does for its own signatures.
- **Supply-chain signal: doubled** for Ed25519 (two audited implementations in the dep
  closure).
- **Audit-test coverage:** `tests/x509_dep_tree_guard.rs::dep_tree_ed25519_dalek_coexistence_shape`
  asserts BOTH versions are present and that no THIRD version has appeared.

**Revisit** when EITHER (a) `pgp` releases a version that drops `ed25519-dalek 2.x`, OR
(b) `pkarr` migrates to a stable `ed25519-dalek 3.x` release (the `=3.0.0-pre.5` pin can
then drop the `=` exact-pin requirement).

## Pitfall #22 — Wire-budget: what works today (consolidated)

Realistic typed-material payloads exceed the 1000-byte PKARR BEP44 ceiling.
The current cipherpost protocol surfaces this as a clean `Error::WireBudgetExceeded
{ encoded, budget: 1000, plaintext }` at send time — NOT as an `InvalidMaterial`
or PKARR-internal panic. The architectural fix (two-tier storage: small DHT
envelope pointing to encrypted blob in external store) belongs to the v1.2
milestone.

This consolidated matrix (Phase 7 Plan 08, replacing the per-variant scattered
notes from Phase 6 + Plan 04) tells users honestly which variants work today
and which surface `WireBudgetExceeded`:

| Variant | Min fixture | Predicted/measured encoded | Round-trip today? |
|---------|-------------|----------------------------|-------------------|
| `generic_secret` (trivial payload ~20 B) | ~20 B | ~800 B | **YES** (Phase 5 baseline) |
| `x509_cert` Ed25519 self-signed minimum | ~234 B | ~1290 B | NO (`#[ignore]`'d in `tests/x509_roundtrip.rs`) |
| `pgp_key` rpgp-minimal Ed25519 (UID ≤20 chars, no subkeys, empty pref-subpackets) | 202 B | **1236 B (measured)** | NO (`#[ignore]`'d in `tests/pgp_roundtrip.rs`) |
| `pgp_key` realistic key (UID >20 chars, RSA, OR subkeys) | ≥250 B | >1000 B | NO (positive `WireBudgetExceeded` test ACTIVE) |
| `ssh_key` Ed25519 OpenSSH v1 minimum (empty comment) | 387 B (raw) | **1589 B (measured Plan 08)** | NO (`#[ignore]`'d FROM DAY 1 in `tests/ssh_roundtrip.rs`) |
| `ssh_key` larger keys (RSA, longer comment) | ≥500 B | >2000 B | NO (positive `WireBudgetExceeded` test ACTIVE) |

**Behavior matrix today (Phase 7 ship state):**
- `x509_cert` realistic-fixture sends surface `Error::WireBudgetExceeded { encoded,
  budget: 1000, plaintext }` cleanly (Phase 6).
- `pgp_key` rpgp-minimal Ed25519 round-trip: `#[ignore]`'d (1236 B > 1000 B).
- `pgp_key` realistic-fixture sends surface `Error::WireBudgetExceeded` cleanly
  (Plan 04 positive test `pgp_send_realistic_key_surfaces_wire_budget_exceeded_cleanly`).
- `ssh_key` round-trip: `#[ignore]`'d FROM DAY 1 (D-P7-03 fallback active per
  research GAP for SSH; minimum 387 B Ed25519 OpenSSH v1 fixture encodes to
  ~1589 B per Plan 08 measurement).
- `ssh_key` realistic-fixture sends surface `Error::WireBudgetExceeded` cleanly
  (Plan 08 positive test `ssh_send_realistic_key_surfaces_wire_budget_exceeded_cleanly`).
- `generic_secret` + small payloads continue to round-trip as in Phase 5.

**Note on PGP wire-budget reality:** Research GAP-5 predicted `raw × 4.16 ≈ encoded`
(~840 B for a 202 B fixture). Actual measurement at Plan 04 implementation time:
**1236 B encoded**, expansion factor ≈ 6.1× — about 50% higher than predicted.
The overhead is split between JCS envelope framing (~180 B for `{created_at,
material: {type:pgp_key, bytes:b64}, protocol_version, purpose}` plus base64
expansion of the bytes field), age encryption framing, and OuterRecord JSON wrapping.

**Note on SSH wire-budget reality:** Research forecast ~1340 B (Plan 05 prediction
based on raw × 4.16). Actual Plan 08 measurement on the 387 B Ed25519 fixture:
**1589 B encoded** (plaintext 617 B; expansion factor ≈ 4.10× over raw and ≈ 2.58×
over plaintext). The forecast was within ~16% — closer than PGP's 50% miss because
SSH OpenSSH v1 PEM is already a fairly verbose format with limited compression
opportunity at the canonical-re-encode layer.

**Honest messaging discipline (D-P7-03):** Phase 7 ships with `#[ignore]`'d
round-trip tests + active `WireBudgetExceeded` tests for X.509 + PGP + SSH.
The `#[ignore]`'d tests are the regression suite for the v1.2 two-tier-storage
fix — do NOT remove them. Each carries a `wire-budget: …` `#[ignore]` reason
that points at this section + the v1.2 milestone.

**Phase 8 wire-budget continuation (pin × burn × typed-material compose):**
PIN-required shares add ~165 B per nested-age layer + 32 B salt prefix; the
worst-case `pin + burn + pgp_key (secret-key)` compose is predicted to brush
the 1000 B BEP44 ceiling (08-RESEARCH.md Open Risk #5). The compose-grid
test suite (`tests/pin_burn_compose.rs`, 23 tests covering pin × burn × {
GenericSecret, X509Cert, PgpKey, SshKey }) uses the W3 split-macro pattern:
`compose_base_test_strict!` for the single sub-budget happy path
(`generic_burn_only`), `compose_base_test_lenient!` for every PIN path and
every typed-material variant — lenient gracefully surfaces
`Error::WireBudgetExceeded` as `Ok` with a skip note, asserting the failure
mode is a CLEAN `WireBudgetExceeded` (NOT a panic, NOT a Transport-internal
error, NOT a partial publish). The pre-flight test
`tests/pin_burn_compose.rs::pin_plus_burn_plus_pgp_wire_budget_surfaces_cleanly_or_succeeds`
pins this contract explicitly. Phase 9 (DHT-07) measures the wire-budget
distribution empirically against the real DHT; v1.2 ships the wire-budget
escape hatch (chunking / two-tier storage / out-of-band).

**Phase 9 composite measurement (DHT-07):** `pin_required=true` +
`burn_after_read=true` + `Material::GenericSecret { bytes: vec![0u8; 2048] }`
exceeds the 1000-byte BEP44 ceiling and surfaces
`Error::WireBudgetExceeded { encoded, budget: 1000, plaintext }` cleanly at
send time — encoded = 5123 bytes vs budget = 1000 bytes (overflow = 4123
bytes, expansion factor ≈ 2.5× over the 2048 B plaintext). Test:
`tests/wire_budget_compose_pin_burn_pgp.rs::pin_burn_realistic_payload_surfaces_wire_budget_exceeded`.
Recorded for the regression-guard byte-count table in `RELEASE-CHECKLIST.md`
when v1.2's two-tier-storage fix lands.

## 7. Passphrase Contract

Cipherpost's identity file is encrypted with a passphrase-derived key (Argon2id → HKDF →
age). Passphrases are the only secret the user must remember; cipherpost enforces a strict
contract to prevent leaks.

### 7.1 Precedence

Passphrase sources are consulted in priority order: `fd > file > env > TTY`. Inline
`--passphrase <value>` is **rejected** at parse/runtime.

1. **`--passphrase-fd <N>`** — no process-table exposure; file descriptor inherited from
   the caller. Fd `0` (stdin) is reserved for payload I/O and is rejected with exit `1`.
2. **`--passphrase-file <PATH>`** — no process-table exposure; file must be mode `0600`
   or `0400` (inode permission gate). Wider permissions return `Error::IdentityPermissions`.
3. **`CIPHERPOST_PASSPHRASE` environment variable** — visible via `/proc/<pid>/environ`
   and `ps auxe` (PITFALL #35); use sparingly. Available primarily for CI contexts.
4. **TTY prompt** — interactive only; cannot be scripted. Requires both stdin and stderr
   to be TTYs; otherwise cipherpost exits with `Error::Config` and exit code `1` rather
   than falling back to piped stdin (which would conflate payload input with passphrase
   input).

Inline `--passphrase <value>` is **rejected** at parse time (via a hidden-from-help flag
whose value triggers `Error::PassphraseInvalidInput` at dispatch, exit `4`) and at runtime.
Inline argv bytes leak via `/proc/<pid>/cmdline`, `ps`, and shell history.

Setting both `--passphrase-file` and `--passphrase-fd` in a single invocation is rejected
with `Error::Config` and exit `1`. `CIPHERPOST_PASSPHRASE` plus one of the two flags is
permitted — the flag takes precedence per the ordering above.

### 7.2 Newline-strip rule

Both `--passphrase-fd` and `--passphrase-file` strip **exactly one** trailing newline:
one `\r\n`, else one `\n`, else nothing. Never a greedy `.trim()` (which would silently
corrupt passphrases ending in a space — PITFALL #30).

Truth table:

| Input bytes     | Stripped output |
|-----------------|-----------------|
| `hunter2\r\n`   | `hunter2`       |
| `hunter2\n`     | `hunter2`       |
| `hunter2\n\n`   | `hunter2\n`     |
| `hunter2 `      | `hunter2 `      |
| `hunter2`       | `hunter2`       |
| `hunter2\r`     | `hunter2\r`     |

The bare `\r` case is deliberately preserved (not stripped) — a passphrase file authored
by a text editor that emits CR-only line endings is a user-environment bug to fix at the
editor, not something cipherpost silently mutates.

### 7.3 Wrong passphrase

Incorrect passphrase yields exit code `4` with the user-facing message `passphrase failed`.
No hint about which character was wrong, no timing disclosure; the Argon2id KDF cost means
each wrong attempt takes ~0.3 seconds regardless.

### 7.4 Identity file permissions

`~/.cipherpost/secret_key` MUST be at mode `0600`. Identity files at wider permissions are
refused at open time with a clear error and exit code (IDENT-03, PITFALL #15). The identity
directory `~/.cipherpost/` is created at mode `0700`.

## 8. Appendix: Test Vectors

All test vectors use a deterministic Ed25519 keypair derived from the all-zeros seed
(`[0u8; 32]`). This key is labelled TEST VECTOR ONLY throughout this section.

> **WARNING: TEST VECTOR ONLY — DO NOT USE IN PRODUCTION.**
> The `[0u8; 32]` Ed25519 seed used in this appendix is a known, non-secret value used
> exclusively for reproducibility. Any cipherpost identity created with this seed is
> compromised by definition.

Re-implementers can use these vectors to confirm byte-level compatibility without cloning
this repository.

### 8.1 OuterRecordSignable Test Vector

**Keypair source:** Ed25519 `SigningKey::from_bytes(&[0u8; 32])`.

**Input — pretty-printed JSON (for readability):**

```json
{
  "blob": "AAAA",
  "created_at": 1700000000,
  "protocol_version": 1,
  "pubkey": "pk-placeholder-z32",
  "recipient": "rcpt-placeholder-z32",
  "share_ref": "0123456789abcdef0123456789abcdef",
  "ttl_seconds": 86400
}
```

**Canonical bytes (RFC 8785 JCS, 192 bytes):**

```
7b22626c6f62223a2241414141222c22637265617465645f6174223a313730303030303030302c2270726f746f636f6c5f76657273696f6e223a312c227075626b6579223a22706b2d706c616365686f6c6465722d7a3332222c22726563697069656e74223a22726370742d706c616365686f6c6465722d7a3332222c2273686172655f726566223a223031323334353637383961626364656630313233343536373839616263646566222c2274746c5f7365636f6e6473223a38363430307d
```

**Fixture file:** `tests/fixtures/outer_record_signable.bin` (byte-compare to verify).

**To reproduce:**
1. Serialize the pretty-printed JSON above through any RFC 8785 JCS implementation.
   The resulting bytes MUST equal the hex above (192 bytes).
2. Ed25519-sign those bytes with `SigningKey::from_bytes(&[0u8; 32])`.
3. The signature MUST match the base64 below.

**Signature (base64-STANDARD):**
```
B1KQKUwXEHBLlXNekjU23LM+hkwz2w1XGjYg/X27tZSbX9opQozRgxKoVaAFbxmvfP2+HbOssOJ4DblpgcPdDw==
```

### 8.2 ReceiptSignable Test Vector

**Keypair source:** Same `[0u8; 32]` seed as §8.1.

**Input — pretty-printed JSON:**

```json
{
  "accepted_at": 1700000000,
  "ciphertext_hash": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "cleartext_hash": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
  "nonce": "0123456789abcdef0123456789abcdef",
  "protocol_version": 1,
  "purpose": "canonical form fixture",
  "recipient_pubkey": "rcpt-placeholder-z32",
  "sender_pubkey": "sender-placeholder-z32",
  "share_ref": "0123456789abcdef0123456789abcdef"
}
```

**Canonical bytes (RFC 8785 JCS, 424 bytes):**

```
7b2261636365707465645f6174223a313730303030303030302c22636970686572746578745f68617368223a2261616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161616161222c22636c656172746578745f68617368223a2262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262626262222c226e6f6e6365223a223031323334353637383961626364656630313233343536373839616263646566222c2270726f746f636f6c5f76657273696f6e223a312c22707572706f7365223a2263616e6f6e6963616c20666f726d2066697874757265222c22726563697069656e745f7075626b6579223a22726370742d706c616365686f6c6465722d7a3332222c2273656e6465725f7075626b6579223a2273656e6465722d706c616365686f6c6465722d7a3332222c2273686172655f726566223a223031323334353637383961626364656630313233343536373839616263646566227d
```

**Fixture file:** `tests/fixtures/receipt_signable.bin` (byte-compare to verify).

**To reproduce:**
1. Serialize the pretty-printed JSON above through any RFC 8785 JCS implementation.
   The resulting bytes MUST equal the hex above (424 bytes).
2. Ed25519-sign those bytes with the same `[0u8; 32]` seed.
3. The signature MUST match the base64 below.

**Signature (base64-STANDARD):**
```
L8UWu/lYccsfB3pwZD6hoPu39ZWuNYt0/SRqDtI+xMpL7Z91Lof8vnFjFY2WtlQDDlZOH4H0srwf4LlmT6w7Aw==
```

### 8.3 Sanity check (implementer script)

A reference Rust test for regenerating both vectors is committed at
`tests/spec_test_vectors.rs` (gated `#[ignore]`); run it with:
```
cargo test --features mock gen_spec_test_vectors -- --ignored --nocapture
```
Output MUST match the base64 signatures above byte-for-byte.

## 9. Lineage

Cipherpost is a fork-and-diverge of [cclink](https://github.com/johnzilla/cclink), a prior
project by the same author that applied the same PKARR + age + Ed25519 + Mainline DHT
primitives to Claude Code session-ID handoff. **cclink is mothballed:** no further
development is planned upstream. Cipherpost was seeded in 2026-04 by vendoring cclink's
crypto, identity, record, and transport layers essentially unchanged and adding a new
payload and flow layer on top.

The primitives ported from cclink are reused without protocol-level modification:
`age 0.11` for payload encryption (X25519 derived from the identity Ed25519 key);
`ed25519-dalek =3.0.0-pre.5` for all signature operations; `argon2 0.5` with parameters
(64 MB memory, 3 iterations) stored in a PHC-format identity-file header; `hkdf 0.12` with
SHA-256 for key derivation; `pkarr 5.0.3` for Mainline DHT rendezvous via SignedPacket.
The crypto primitive stack MUST NOT be substituted; cipherpost/v1 takes cclink's v1.3.0
crypto pins verbatim.

Cryptographic keys produced by cipherpost and keys produced by cclink are **not**
interoperable despite sharing the primitive stack. All cipherpost HKDF call-sites use
info strings prefixed `cipherpost/v1/` (the `HKDF_INFO_PREFIX` constant in `src/lib.rs`
and D-08). cclink uses a different prefix; any attempt to decrypt a cclink share with a
cipherpost identity (or vice versa) will fail at the HKDF step. This domain separation is
deliberate and tested via `tests/hkdf_info_enumeration.rs`.

The cipherpost delta from cclink lives purely at the payload and flow layer:
1. **Typed payload schema** — `Envelope` with `Material` enum (`generic_secret` shipped in v1.0;
   `x509_cert` added in v1.1 Phase 6; `pgp_key` and `ssh_key` added in v1.1 Phase 7).
2. **Explicit acceptance step** — §5.2 step 9; the recipient MUST paste the sender's full
   52-char z-base-32 pubkey to confirm (no `y`, no `--yes` flag). This prevents
   MFA-fatigue-style prompt bombing.
3. **Signed receipt** — Receipt structure (§3.4) published under the recipient's PKARR key
   at `_cprcpt-<share_ref_hex>`, resolve-merge-republish to preserve coexisting records
   (TRANS-03).

**Fork point:** cclink v1.3.0 (the last release before mothballing).

See also: [`THREAT-MODEL.md`](./THREAT-MODEL.md) for the adversary model and
[`SECURITY.md`](./SECURITY.md) for the vulnerability disclosure policy.
