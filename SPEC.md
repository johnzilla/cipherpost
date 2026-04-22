# Cipherpost Protocol Specification

> **Status: DRAFT — skeleton milestone**
>
> This document describes the walking-skeleton implementation shipped in Phases 1–3 of the
> first development milestone (2026-04).
> Wire-format decisions documented here are **stable** — changes require a protocol version bump.
> Editorial polish, completeness review, and v1.0-final sign-off are scheduled for a later phase.

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
  `pkarr 5.0.3`.
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
**Hash algorithm:** SHA-256 via `sha2 0.10`; hash outputs rendered as lowercase hex.
**Base64 codec:** `base64::engine::general_purpose::STANDARD` (with padding) — applied
uniformly for signatures and for `OuterRecord.blob` and `Material::GenericSecret.bytes`
(D-WIRE-04). `URL_SAFE_NO_PAD` is banned at the wire layer.

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
Only `generic_secret` is implemented in cipherpost/v1; other variants are reserved and return
`Error::NotImplemented` on encode or decode (D-WIRE-03, PAYL-02).

**`generic_secret` wire form:**
```json
{"type": "generic_secret", "bytes": "<base64-STANDARD-padded>"}
```

| Field | Type | Wire encoding | Description | Source decision |
|-------|------|---------------|-------------|-----------------|
| `type` | String | literal `"generic_secret"` | Variant discriminator | D-WIRE-03 |
| `bytes` | String | base64-STANDARD, padded | Arbitrary byte payload | D-WIRE-04 |

Reserved variants (`x509_cert`, `pgp_key`, `ssh_key`) have no fields defined in cipherpost/v1
and will produce `Error::NotImplemented` on any attempt to encode or decode them. A future
`cipherpost/v2` MAY define their field shapes; such a change requires a `protocol_version` bump.

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

1. Read payload from `<path>` or `-` (stdin). Reject if > 64 KB (D-PS-01). (SEND-01, PAYL-03)
2. Build `Envelope { purpose, material, created_at, protocol_version }` with `purpose` control-
   stripped (D-WIRE-05). JCS-serialize.
3. age-encrypt the JCS bytes to the recipient's X25519 (derived from their Ed25519 pubkey) or
   to the sender's own X25519 for `--self` (SEND-01, SEND-02). Base64-STANDARD-encode to produce `blob`.
4. Compute `share_ref = sha256(ciphertext_blob_bytes || created_at.to_be_bytes())[..16]` (D-06).
5. Build `OuterRecordSignable { blob, created_at, protocol_version, pubkey, recipient, share_ref, ttl_seconds }`.
6. JCS-serialize `OuterRecordSignable`; Ed25519-sign with the sender's identity key; base64-
   encode to produce `signature`. Assemble `OuterRecord` (D-WIRE-03, SEND-04).
7. Build PKARR SignedPacket with TXT record under `_cipherpost` carrying the `OuterRecord` JSON.
   Verify encoded SignedPacket size ≤ ~1000 bytes (BEP44 budget, SEND-05). Overflow = `Error::WireBudgetExceeded`.
8. `Transport::publish(signed_packet)`. Print the share URI (`cipherpost://<z32>/<hex>`) to stdout (D-URI-01, SEND-01).

### 5.2 Receive

Strict order (D-RECV-01 + D-SEQ-01 combined — 13 steps):

1. Parse URI; extract `sender_z32` and `url_share_ref`. Malformed → `Error::InvalidShareUri` (D-URI-03).
2. Check sentinel file at `~/.cipherpost/state/accepted/<url_share_ref>`; if present, print
   prior acceptance timestamp and exit 0 (RECV-06, D-RECV-02, D-STATE-01). No network call.
3. `Transport::resolve(sender_z32)` — returns `OuterRecord` only after the outer PKARR
   SignedPacket signature passes (verified inside `pkarr::ClientBlocking`). NotFound → exit 5.
4. Verify inner Ed25519 signature on `OuterRecord` via `verify_record` (round-trip-reserialize
   guard included). Any signature failure → unified message, exit 3 (D-16, RECV-01).
5. Check `url_share_ref == OuterRecord.share_ref`; mismatch → `Error::ShareRefMismatch`, exit 1 (D-URI-02).
6. TTL check against `OuterRecord.created_at + OuterRecord.ttl_seconds`. Expired → exit 2 (RECV-02).
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
   Stdin AND stderr MUST both be TTYs; else `Error::Config`, exit 1 (D-ACCEPT-03).
10. Read user input; compare byte-equal (after `trim()`) to the sender's full 52-char z-base-32
    pubkey. Mismatch → `Error::Declined`, exit 7 (D-ACCEPT-01, RECV-04).
11. Write decrypted payload to `--output <path>` or stdout (default) (RECV-05).
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
| 1 | Generic error | `<sanitized anyhow message>` | `Config`, `InvalidShareUri`, `ShareRefMismatch`, `WireBudgetExceeded`, `NotImplemented`, `PayloadTooLarge`, any unclassified |
| 2 | TTL expired | `share expired` | `Expired` |
| 3 | Signature verification failed | `signature verification failed` | `SignatureOuter`, `SignatureInner`, `SignatureCanonicalMismatch` (D-16 unified) |
| 4 | Passphrase / decryption failure | `passphrase failed` | `Passphrase`, `Decrypt` |
| 5 | Not found on DHT | `not found` | `NotFound` |
| 7 | User declined acceptance | `declined` | `Declined` |

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

## 7. Passphrase Contract

Cipherpost's identity file is encrypted with a passphrase-derived key (Argon2id → HKDF →
age). Passphrases are the only secret the user must remember; cipherpost enforces a strict
contract to prevent leaks.

### 7.1 Acceptable passphrase sources

In priority order (highest wins):

1. `CIPHERPOST_PASSPHRASE` environment variable (for automated test/CI use).
2. `--passphrase-file <path>` reads the passphrase from a file (newline-trimmed).
3. `--passphrase-fd <n>` reads the passphrase from file descriptor `<n>`.
4. Interactive TTY prompt (default, when stdin is a TTY and none of the above is set).

### 7.2 Rejected passphrase sources

- `--passphrase <value>` inline argv is **refused at parse time**. Inline argv values
  appear in `ps` output and in shell history, so cipherpost will not accept them even if
  provided. Rejection message: a clap-level error explaining the rejection; exit via clap
  (non-zero).

### 7.3 TTY requirement

The interactive prompt requires stdin to be a TTY. In non-interactive contexts where none
of the env / file / fd sources is set, cipherpost exits with `Error::Config` and exit code
`1`; it does not fall back to reading piped stdin (which would conflate payload input with
passphrase input).

### 7.4 Wrong passphrase

Incorrect passphrase yields exit code `4` with the user-facing message `passphrase failed`.
No hint about which character was wrong, no timing disclosure; the Argon2id KDF cost means
each wrong attempt takes ~0.3 seconds regardless.

### 7.5 Identity file permissions

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
1. **Typed payload schema** — `Envelope` with `Material` enum (`generic_secret` implemented;
   `x509_cert`, `pgp_key`, `ssh_key` reserved for v1.0+).
2. **Explicit acceptance step** — §5.2 step 9; the recipient MUST paste the sender's full
   52-char z-base-32 pubkey to confirm (no `y`, no `--yes` flag). This prevents
   MFA-fatigue-style prompt bombing.
3. **Signed receipt** — Receipt structure (§3.4) published under the recipient's PKARR key
   at `_cprcpt-<share_ref_hex>`, resolve-merge-republish to preserve coexisting records
   (TRANS-03).

**Fork point:** cclink v1.3.0 (the last release before mothballing).

See also: [`THREAT-MODEL.md`](./THREAT-MODEL.md) for the adversary model and
[`SECURITY.md`](./SECURITY.md) for the vulnerability disclosure policy.
