# Architecture Research — Cipherpost Walking Skeleton

**Domain:** Self-sovereign cryptographic-material handoff (Rust CLI)
**Researched:** 2026-04-20
**Confidence:** HIGH — based on direct inspection of cclink source at github.com/johnzilla/cclink (commit on `main`), not inference.

---

## Source inspection summary (cclink, what we're forking)

Read directly from the cclink repo:

```
cclink/
├── Cargo.toml                 # Single crate. pkarr 5.0.3, ed25519-dalek =3.0.0-pre.5 (pinned),
│                              # age 0.11, clap 4.5, argon2, hkdf, sha2, zeroize, base64, bech32,
│                              # backon (retry), dialoguer, qr2term, owo-colors, serde/serde_json
├── src/
│   ├── main.rs                # Dispatch on Cli → commands::*
│   ├── lib.rs                 # Re-exports crypto/error/keys/record/transport/util — for integration tests
│   ├── cli.rs                 # clap derive: top-level args + Init/Whoami/Pickup/List/Revoke subcommands
│   ├── error.rs               # thiserror enum: NoKeypairFound, SignatureVerificationFailed, ...
│   ├── util.rs                # human_duration etc.
│   ├── crypto/mod.rs          # Ed25519↔X25519 bridge, age_encrypt/decrypt, pin_*, CCLINKEK envelope
│   ├── keys/
│   │   ├── store.rs           # ~/.pubky/secret_key, atomic write, 0600, passphrase load/save
│   │   ├── fingerprint.rs
│   │   └── mod.rs
│   ├── record/mod.rs          # HandoffRecord + HandoffRecordSignable + canonical_json + sign/verify
│   ├── transport/mod.rs       # DhtClient wraps pkarr::ClientBlocking, publish/resolve/revoke, TXT label `_cclink`
│   ├── session/mod.rs         # ← cclink-specific: Claude Code session discovery. Will NOT be copied.
│   └── commands/
│       ├── publish.rs         # send flow (pin validation, encrypt, sign, publish)
│       ├── pickup.rs          # receive flow (resolve w/ backon retry, verify, TTL check, decrypt, exec)
│       ├── init.rs, whoami.rs, list.rs, revoke.rs
│       └── mod.rs
└── tests/
    ├── integration_round_trip.rs   # Fixed seeds [42;32], [99;32] — no DHT. Uses lib re-exports.
    └── plaintext_leak.rs           # Byte-window + UTF-8 scan for known plaintext in ciphertext.
```

**Key facts that constrain cipherpost's design:**

1. **SignedPacket budget is ~1000 bytes encoded** — asserted in cclink's `test_build_signed_packet_fits_budget`. This is the hard ceiling for the outer JSON TXT record. Cipherpost's PRD says payloads are capped at 64 KB, but that's the *plaintext before encryption*; the encrypted ciphertext goes into `blob` as base64, and the whole record (including sig, pubkey, timestamps, receipt pointer, purpose) must fit in 1000 bytes encoded. **Two-tier storage will be needed** — see §4.3.
2. **Canonical JSON is achieved by alphabetical field order + compact serde_json** — no `preserve_order` feature. HandoffRecordSignable is a separate struct from HandoffRecord, omitting `signature`. Cipherpost must replicate this split pattern exactly.
3. **Two signatures, both Ed25519:**
   - Inner: `sign_record` signs canonical JSON of `HandoffRecordSignable` → base64 → stored in `.signature` field of outer record.
   - Outer: `pkarr::SignedPacket::builder().sign(&keypair)` signs the DNS packet.
   - Verifier checks both independently.
4. **Outer record leaves `hostname` and `project` empty** — all sensitive metadata is encrypted into the inner `Payload` blob. Cipherpost must do the same for purpose strings and any other sender context.
5. **Tests don't hit the DHT.** Integration tests exercise crypto + record round-trips with fixed seeds. DHT publish/resolve tested indirectly via `extract_txt` on a locally-built SignedPacket. This is the testing pattern we'll reuse.

---

## Recommended Cipherpost Architecture

### System Overview

```
┌───────────────────────────────────────────────────────────────────────┐
│                         cli.rs (clap derive)                           │
│    init · whoami · send · receive · receipts                           │
├───────────────────────────────────────────────────────────────────────┤
│                        flow/ (orchestration)                           │
│    send_flow · receive_flow · receipt_publish · receipt_fetch          │
│    (owns the policy: acceptance prompt, TTL check, two-tier blob)      │
├───────────────┬──────────────────────┬────────────────────────────────┤
│   payload/    │     receipt/         │        identity/                │
│ (cipherpost)  │   (cipherpost)       │      (keys/store derivative)    │
│ Envelope,     │   Receipt struct,    │      ~/.cipherpost/secret_key   │
│ Material enum │   sign/verify,       │      Argon2id passphrase wrap   │
│ purpose, ttl, │   share_ref hash     │      (CIPHPOSK envelope)        │
│ canonical JSON│                      │                                 │
├───────────────┴──────────────────────┴────────────────────────────────┤
│  record/  (cclink-vendored, thin rename)    crypto/  (cclink-vendored)│
│  OuterRecord + OuterRecordSignable          Ed25519↔X25519, age_*,    │
│  canonical_json, sign/verify_record         argon2+hkdf, key envelope │
├───────────────────────────────────────────────────────────────────────┤
│  transport/  (cclink-vendored)                                         │
│  DhtClient wraps pkarr::ClientBlocking · publish · resolve · revoke    │
│  (label `_cipherpost` instead of `_cclink`)                            │
└───────────────────────────────────────────────────────────────────────┘
                                │
                                ▼
                    Mainline DHT via PKARR
```

### Component Responsibilities

| Component | Origin | Responsibility |
|-----------|--------|----------------|
| `crypto/` | **vendored from cclink** (rename constants only) | Ed25519→X25519 derivation, `age_encrypt`/`age_decrypt`, `age_identity`/`age_recipient`, Argon2id + HKDF-SHA256 key envelope. Pure functions, no I/O. |
| `transport/` | **vendored from cclink** (rename label + a method) | `DhtClient` wraps `pkarr::ClientBlocking`. `publish`, `resolve_record`, `revoke`. No knowledge of payload semantics. |
| `record/` | **vendored from cclink** (generalized) | `OuterRecord` / `OuterRecordSignable` — the thing that goes in the PKARR TXT record. Dual-sig verify. No knowledge of cryptographic-material types. |
| `identity/` | **vendored from cclink** (rename + relocate) | Disk-backed keypair: `~/.cipherpost/secret_key` (CIPHPOSK envelope), atomic 0600 write, passphrase load/save. Roughly cclink's `keys/store.rs`. |
| `payload/` | **NEW — cipherpost delta** | `Envelope` struct (purpose, terms, ttl, material, created_at) + `Material` enum (GenericSecret for skeleton; Cert/Pgp/Ssh reserved). Canonical JSON encode/decode. |
| `receipt/` | **NEW — cipherpost delta** | `Receipt` struct (share_ref, recipient_pubkey, accepted_at, nonce) + sign/verify. Share-ref = SHA-256 of sender's outer record bytes (before publish). |
| `flow/` | **NEW — cipherpost delta** | Orchestrates the four flows. Owns acceptance prompt, TTL enforcement, and the two-tier blob indirection (if needed for bigger payloads). |
| `cli/` | **adapted from cclink** | clap derive. New subcommand surface: `init`, `whoami`, `send`, `receive`, `receipts`. |
| `error.rs` | adapted from cclink | `CipherpostError` enum. |
| `util.rs` | adapted from cclink | `human_duration` and small helpers. |

---

## Recommended Project Structure

```
cipherpost/
├── Cargo.toml                            # Single crate. Deps match cclink exactly (esp. pkarr 5.0.3
│                                         # + ed25519-dalek =3.0.0-pre.5 pin). Drop: arboard, qr2term,
│                                         # gethostname (not needed for skeleton). Add nothing new.
├── src/
│   ├── main.rs                           # thin: parse CLI, dispatch to flow::*
│   ├── lib.rs                            # pub mod re-exports for integration tests
│   ├── cli.rs                            # clap: init / whoami / send / receive / receipts
│   ├── error.rs                          # CipherpostError (thiserror)
│   ├── util.rs                           # human_duration, share_ref_hash helpers
│   │
│   ├── crypto/                           # ── VENDORED FROM cclink/src/crypto ───────────────
│   │   └── mod.rs                        # Identical to cclink except:
│   │                                     #   - ENVELOPE_MAGIC: b"CIPHPOSK" (was b"CCLINKEK")
│   │                                     #   - KEY_HKDF_INFO: b"cipherpost-key-v1"
│   │                                     #   - All `cclink-pin-v1` HKDF info strings renamed
│   │                                     #     (even though --pin is deferred, bake in the
│   │                                     #     domain separator now to avoid a protocol break later)
│   │
│   ├── transport/                        # ── VENDORED FROM cclink/src/transport ────────────
│   │   └── mod.rs                        # Identical to cclink except:
│   │                                     #   - CCLINK_LABEL → CIPHERPOST_LABEL = "_cipherpost"
│   │                                     #   - Add resolve_receipts(pubkey) helper (§4.4)
│   │
│   ├── identity/                         # ── VENDORED FROM cclink/src/keys ─────────────────
│   │   ├── mod.rs                        # pub use store::*;
│   │   ├── store.rs                      # Identical to cclink/keys/store.rs except:
│   │   │                                 #   - key_dir() → ~/.cipherpost (was ~/.pubky)
│   │   │                                 #   - drop homeserver_* (cclink-specific)
│   │   └── fingerprint.rs                # verbatim
│   │
│   ├── record/                           # ── VENDORED FROM cclink/src/record (generalized) ─
│   │   └── mod.rs                        # OuterRecord + OuterRecordSignable, renamed from
│   │                                     # HandoffRecord. Field changes:
│   │                                     #   - DROP: hostname, project (cclink-specific debris;
│   │                                     #           were already empty strings in cclink v1.1)
│   │                                     #   - KEEP: blob, created_at, pubkey, signature, ttl,
│   │                                     #           recipient (optional z32)
│   │                                     #   - ADD: share_ref: String (hex-encoded, 16 chars =
│   │                                     #          first 8 bytes of SHA-256) — stable reference
│   │                                     #          the receipt points at. Always present.
│   │                                     #   - DEFER: burn, pin_salt (skeleton scope drops these
│   │                                     #            modes; schema reserves the slots by NOT
│   │                                     #            using names that would collide)
│   │
│   ├── payload/                          # ── NEW: cipherpost-specific ──────────────────────
│   │   ├── mod.rs                        # pub use envelope::*; pub use material::*;
│   │   ├── envelope.rs                   # Envelope { version, purpose, terms, material, created_at,
│   │   │                                 #            ttl_secs } — the thing that gets age-encrypted
│   │   │                                 #            into record.blob. Serialized as canonical JSON
│   │   │                                 #            (alphabetical fields, compact). Has a signable
│   │   │                                 #            form (EnvelopeSignable) mirroring cclink's
│   │   │                                 #            HandoffRecord/HandoffRecordSignable pattern.
│   │   └── material.rs                   # #[serde(tag = "kind")] enum Material {
│   │                                     #    GenericSecret { data_b64: String },
│   │                                     #    // RESERVED (not implemented in skeleton):
│   │                                     #    // X509Pair { cert_pem, key_pem },
│   │                                     #    // PgpPair { public_armored, private_armored },
│   │                                     #    // SshPair { public_ssh, private_pem },
│   │                                     # }  Size cap 64KB enforced at encode time.
│   │
│   ├── receipt/                          # ── NEW: cipherpost-specific ──────────────────────
│   │   └── mod.rs                        # Receipt { share_ref: String,
│   │                                     #           sender_pubkey: String (z32),
│   │                                     #           recipient_pubkey: String (z32),
│   │                                     #           accepted_at: u64,
│   │                                     #           nonce: String (base64, 16B random),
│   │                                     #           signature: String (over ReceiptSignable) }
│   │                                     # published as a TXT record named `_cprcpt-<share_ref>`
│   │                                     # under the RECIPIENT's PKARR key (not the sender's).
│   │                                     # Sender fetches by resolving recipient's own pubkey +
│   │                                     # iterating TXT labels with the prefix. See §4.4.
│   │
│   ├── flow/                             # ── NEW: cipherpost-specific orchestration ────────
│   │   ├── mod.rs
│   │   ├── send.rs                       # run_send_self() / run_send_share()
│   │   │                                 #   1. identity::load_keypair()
│   │   │                                 #   2. payload::Envelope::new(...) + canonical encode
│   │   │                                 #   3. crypto::age_encrypt to self OR recipient
│   │   │                                 #   4. compute share_ref = hex(sha256(ciphertext || created_at)[..8])
│   │   │                                 #   5. record::OuterRecord + sign
│   │   │                                 #   6. transport::publish
│   │   │                                 #   7. print share_ref to sender
│   │   ├── receive.rs                    # run_receive(target_z32, share_ref_opt)
│   │   │                                 #   1. identity::load_keypair()
│   │   │                                 #   2. transport::resolve_record (w/ backon retry — reuse cclink pattern)
│   │   │                                 #   3. record::verify_record (inner sig) + rely on pkarr for outer sig
│   │   │                                 #   4. TTL check (flow owns this — see cclink/pickup.rs:3)
│   │   │                                 #   5. age_decrypt blob → Envelope
│   │   │                                 #   6. Display: sender_pubkey fingerprint + purpose + terms
│   │   │                                 #   7. PROMPT: explicit accept (dialoguer::Confirm, default No)
│   │   │                                 #   8. if accepted: print Material → stdout/file
│   │   │                                 #   9. receipt_publish::run(share_ref, sender_pubkey) — fire and note failures
│   │   │                                 #      as warnings but do NOT unwind acceptance
│   │   ├── receipt_publish.rs            # Build + sign Receipt, publish under recipient's
│   │   │                                 # PKARR key at TXT label `_cprcpt-<share_ref>`.
│   │   └── receipt_fetch.rs              # run_receipts(): list outstanding share_refs the
│   │                                     # sender has published; for each, resolve the
│   │                                     # recipient's key (if known from record.recipient);
│   │                                     # fetch the receipt TXT; verify signature; display.
│   │
│   └── commands/                         # Thin wrappers — kept separate so cli.rs stays minimal.
│       ├── mod.rs
│       ├── init.rs                       # calls identity::init
│       ├── whoami.rs                     # calls identity::current
│       ├── send.rs                       # calls flow::send
│       ├── receive.rs                    # calls flow::receive
│       └── receipts.rs                   # calls flow::receipt_fetch
│
└── tests/
    ├── crypto_roundtrip.rs               # Adapted from cclink/tests/integration_round_trip.rs
    ├── plaintext_leak.rs                 # Adapted from cclink — add Envelope-level scans
    ├── envelope_canonical_json.rs        # NEW: field order, compact output, re-sign stability
    ├── record_roundtrip.rs               # NEW: build OuterRecord, fit-in-1000-bytes, sig verify
    ├── receipt_roundtrip.rs              # NEW: issue + verify receipt; share_ref binding
    └── flow_two_identity.rs              # NEW: in-process two-identity test. NO DHT — uses a
                                          # mock transport trait (see §5) so send→receive+receipt
                                          # runs synchronously on one thread.
```

### Structure Rationale

- **Single crate, no workspace.** cclink is a single crate with `lib.rs` re-exporting all internals for integration tests — this exact pattern is what the skeleton needs. Splitting into `cipherpost-core` + `cipherpost` is premature; the PRD calls it out as "open question" and `.planning/PROJECT.md` has it as a pending Key Decision. Do the split only when a *second* consumer exists (TUI or another tool).
- **Vendored modules live at `src/crypto`, `src/transport`, `src/record`, `src/identity`.** These four directories are the vendored-from-cclink surface. Everything else (`payload/`, `receipt/`, `flow/`) is greenfield cipherpost code. This makes the boundary visually obvious: if a future cclink bug fix comes out, we know exactly which four directories to re-sync from.
- **`flow/` owns policy, `commands/` is glue.** cclink mixes policy and glue in `commands/publish.rs` and `commands/pickup.rs` — they do CLI parsing AND orchestrate the round-trip AND own TTL/retry logic. Splitting flow from commands lets tests exercise `flow::send_self()` directly without going through `clap`.
- **`payload/` and `receipt/` are peers, not nested.** The receipt references the share by `share_ref` (a hash), not by including the envelope. Keeping them peer modules prevents the receipt from taking a structural dependency on the envelope beyond that one string field.
- **`session/` from cclink is dropped entirely.** It's Claude-Code-specific directory scanning. Nothing in cipherpost replaces it for the skeleton — material comes from CLI args or stdin.

---

## Boundaries (vendored-vs-new)

| Boundary | Vendored from cclink? | Cipherpost-specific? |
|----------|:---------------------:|:--------------------:|
| Ed25519 key management (on disk) | YES | Only the `~/.cipherpost` path rename and dropping `homeserver_path`. |
| Ed25519 ↔ X25519 derivation | YES — identical | — |
| age encrypt/decrypt | YES — identical | — |
| Argon2id + HKDF key derivation | YES — identical algorithm; new HKDF info strings for domain separation | HKDF info `cipherpost-key-v1`, envelope magic `CIPHPOSK` |
| PKARR SignedPacket publish/resolve | YES — identical | TXT label `_cipherpost` (was `_cclink`); add `resolve_receipts` helper |
| Outer record struct (JSON in TXT) | Structural pattern vendored (signable split, alphabetical fields) | Fields change: drop hostname/project; add `share_ref` |
| Canonical JSON convention | YES (alphabetical declaration order, compact serde_json, no `preserve_order`) | Apply to both `OuterRecordSignable` and `EnvelopeSignable` |
| Dual signing model | YES (inner Ed25519 sig + outer PKARR sig) | Extend to third signature: receipt is independently signed by recipient |
| CLI subcommands (publish/pickup) | Architectural pattern | Completely new surface: send/receive/receipts |
| Payload schema | — | **All new.** Envelope + Material enum. |
| Acceptance step | — | **All new.** Lives in `flow/receive.rs`. |
| Receipt publishing | — | **All new.** `receipt/` + `flow/receipt_*`. |
| Session discovery | N/A — dropped | — |
| QR code output, clipboard | N/A — dropped for skeleton | Can be re-added post-skeleton |

---

## Data Flow — Each Skeleton Flow End-to-End

### 4.1 `cipherpost send --self`

```
CLI:          cipherpost send --self --purpose "backup my signing key" \
                              --material-file ./secret.txt --ttl 14400
│
├── cli::parse                           → SendArgs { mode: Self, purpose, material, ttl }
├── commands::send::run                  → calls flow::send::run_send_self
│
flow::send::run_send_self:
│
├── identity::store::load_keypair()      → pkarr::Keypair  (may prompt passphrase)
│                                          Source: identity/store.rs (vendored keys/store.rs)
├── payload::Envelope::build(...)        → Envelope { version: 1, purpose, terms, material:
│                                            Material::GenericSecret { data_b64 }, created_at, ttl }
│                                          Enforce plaintext size ≤ 64 KB here.
├── payload::canonical_envelope_bytes()  → Vec<u8> (alphabetical serde_json)
│
├── crypto::ed25519_to_x25519_public(&kp)→ [u8; 32]
├── crypto::age_recipient(...)           → age::x25519::Recipient  (self)
├── crypto::age_encrypt(env_bytes, rcpt) → Vec<u8> ciphertext
│
├── compute share_ref:                   → hex(sha256(ciphertext || created_at.to_be_bytes())[..8])
│                                          16-char hex string. Used as the receipt's pointer.
├── record::OuterRecordSignable { blob: b64(ciphertext), created_at,
│                                 pubkey: kp.z32(), recipient: None,
│                                 share_ref, ttl }
├── record::sign_record(signable, &kp)   → base64 Ed25519 signature
├── record::OuterRecord { ...signable fields..., signature }
│
├── transport::DhtClient::new()          → pkarr ClientBlocking
├── DhtClient::publish(&kp, &record)     → SignedPacket built + signed + published to DHT.
│                                          Outer sig is pkarr's; inner sig is record.signature.
│
└── print to stderr/stdout:              "Sent. Share ref: <16-hex>. Expires in 4h."
```

**Self mode does not surface a share-ref to give to another party** — the whole point is self-retrieval. The share_ref is still computed and stored so receipt logic has a uniform shape.

### 4.2 `cipherpost send --share <recipient_z32>`

Identical to 4.1 except:

- `crypto::age_recipient` call is replaced by `crypto::recipient_from_z32(&share_pubkey)` (already exists in cclink's crypto module).
- `OuterRecordSignable.recipient = Some(share_pubkey)`.
- Post-publish output: **print the share_ref to stdout** — sender gives recipient both their own pubkey and the share_ref. Pickup command becomes `cipherpost receive <sender_pubkey>` (share_ref optional because there's only ever one active record per PKARR key in the skeleton, matching cclink's model).

### 4.3 `cipherpost receive <sender_pubkey>`

```
CLI:          cipherpost receive <sender_z32>
│
flow::receive::run:
│
├── identity::store::load_keypair()          → own pkarr::Keypair
│
├── transport::DhtClient::new()
├── DhtClient::resolve_record(sender_z32)    → OuterRecord
│                                              Uses backon ExponentialBuilder retry (vendored).
│                                              Inside resolve_record, record::verify_record runs
│                                              the inner-sig check. The outer pkarr sig is already
│                                              enforced by pkarr's SignedPacket::resolve.
│
├── flow::receive::check_ttl(&record)        → Err(Expired) if now ≥ created_at+ttl
│
├── crypto::ed25519_to_x25519_secret(&kp)    → X25519 secret
├── crypto::age_identity(secret)             → age::Identity
├── base64 decode record.blob                → ciphertext bytes
├── crypto::age_decrypt(ct, &identity)       → Vec<u8> envelope_bytes
│                                              If recipient's key doesn't match: fail cleanly.
│                                              NO partial output, no side effects.
├── payload::Envelope::decode(&envelope_bytes)
│                                           → Envelope  (version check, size sanity)
│
├── flow::receive::display_preamble(&record, &envelope):
│         stderr: "From: <fp of sender_pubkey>"
│         stderr: "Purpose: <envelope.purpose>"
│         stderr: "Expires: <human_duration>"
│         (Material is NOT shown yet.)
│
├── dialoguer::Confirm::new()                → accept? default FALSE
│        .with_prompt("Accept and reveal material? (this publishes a signed receipt)")
│        .default(false)
│        .interact()
│
├── if not accepted:                         → print "Declined." + exit 0 with no receipt
│
├── MATERIAL REVEAL:
│         match envelope.material {
│             Material::GenericSecret { data_b64 } => {
│                 base64::decode → stdout (or --output <path>)
│             }
│             _ => Err("material type not supported in skeleton"),
│         }
│
└── flow::receipt_publish::run(
│       share_ref: record.share_ref,
│       sender_pubkey: record.pubkey,
│       recipient_kp: &own_kp,
│   )
│   Failure here must NOT unwind the material reveal — log warning, suggest retry.
│   Rationale: receipt is auxiliary; we've already shown the material to the user.
```

### 4.4 Receipt publish + fetch

**Publishing side (runs inside `flow::receive`, post-acceptance):**

```
flow::receipt_publish::run(share_ref, sender_z32, recipient_kp):
│
├── receipt::Receipt::new(share_ref, sender_z32, recipient_kp.z32(), now, rand_nonce)
├── receipt::ReceiptSignable::from(&r)
├── receipt::sign(&rs, recipient_kp)       → ed25519 sig over canonical JSON
├── r.signature = sig
│
├── Serialize r as compact JSON (≤1000 bytes — receipts are tiny so this is trivial)
├── transport::publish_receipt(
│       keypair: recipient_kp,
│       label: &format!("_cprcpt-{}", share_ref),  // e.g. _cprcpt-a1b2c3d4e5f6a7b8
│       json: &json,
│   )
│   Internally: builds a SignedPacket with one TXT record at that label and publishes
│   under the RECIPIENT's PKARR key. Crucially: this does not overwrite the recipient's
│   own outgoing share (if any) because pkarr's SignedPacket allows multiple TXT labels —
│   BUT pkarr replaces the whole packet on publish, so the transport layer must:
│       1. Resolve the current SignedPacket for recipient_kp (if any)
│       2. Extract all existing TXT records
│       3. Build a new SignedPacket containing the union + the new receipt label
│       4. Publish
│   This is a small extension of DhtClient and must be tested (see §5).
```

**Design note on receipt storage:** Receipts are published under the *recipient's* PKARR key (not the sender's) because:
1. The sender doesn't hold the recipient's private key — only the recipient can sign.
2. pkarr records are authored by their key owner. The sender fetches receipts by resolving the recipient's key, which they know (it was the `--share` target).
3. This means `receipts` command must be told which recipient to query. For the skeleton, `cipherpost receipts --from <recipient_z32>` is acceptable; a richer ledger comes later.

**Fetching side:**

```
flow::receipt_fetch::run(recipient_z32, share_ref_filter):
│
├── transport::DhtClient::new()
├── DhtClient::resolve_signed_packet(recipient_z32)
├── For each TXT record in the packet:
│     ├── If name starts with "_cprcpt-":
│     │     ├── Extract share_ref from label suffix
│     │     ├── If share_ref_filter set and != this one, skip
│     │     ├── Parse JSON → receipt::Receipt
│     │     ├── receipt::verify(&r, &pkarr::PublicKey::from_z32(recipient_z32))
│     │     └── Display: "<share_ref> accepted at <human time> by <recipient fp>"
```

### 4.5 Why `share_ref` works without leaking content

`share_ref = hex(sha256(ciphertext || created_at.to_be_bytes())[..8])`

- **Public:** anyone resolving the sender's DHT record sees the full OuterRecord (ciphertext blob + share_ref + recipient pubkey if shared mode). So `share_ref` is not a secret — it's a shortened hash of public data.
- **Unique enough for skeleton:** 64 bits of collision resistance is fine at skeleton scale (v1.0 can widen if needed).
- **Binding:** A receipt with `share_ref = X` verifiably references one specific `(ciphertext, created_at)` tuple. The sender, holding the original record, can confirm the match.
- **Doesn't leak content:** SHA-256 is preimage-resistant; the recipient can't produce a valid `share_ref` without the ciphertext, and the ciphertext is already public on the DHT anyway — so the receipt adds no information beyond "I, the holder of key K, acknowledge record X."

---

## Build Order (Justified by Dependency Graph)

```
                  ┌─────────────────────┐
                  │   util.rs, error.rs │  (trivial, first)
                  └──────────┬──────────┘
                             │
        ┌────────────────────┼────────────────────────┐
        │                    │                        │
        ▼                    ▼                        ▼
   ┌─────────┐         ┌──────────┐            ┌───────────┐
   │ crypto/ │         │ identity/│            │  record/  │
   └────┬────┘         └────┬─────┘            └─────┬─────┘
        │  (no deps)        │ (→ crypto)             │ (→ crypto for sig?)
        │                   │                        │ Actually sig is ed25519_dalek
        │                   │                        │ direct — record depends only
        │                   │                        │ on pkarr+base64+ed25519.
        └────────┬──────────┴──────────┬─────────────┘
                 │                     │
                 ▼                     ▼
           ┌──────────┐          ┌───────────┐
           │transport/│          │ payload/  │
           └────┬─────┘          └─────┬─────┘
                │ (→ record)           │ (→ crypto for material encoding)
                │                      │
                └──────────┬───────────┘
                           ▼
                     ┌──────────┐
                     │   flow/  │────► send_self → send_share → receive
                     └─────┬────┘            │            │        │
                           │                 ▼            ▼        ▼
                           │             receipt_publish  receipt_fetch
                           ▼
                     ┌──────────┐
                     │   cli/   │
                     │ commands/│
                     │  main.rs │
                     └──────────┘
```

**Recommended phase ordering for the skeleton milestone:**

1. **Phase: Scaffold** (< half a day)
   - Cargo.toml with cclink's exact dep versions (especially the `ed25519-dalek = "=3.0.0-pre.5"` pin — this is non-negotiable per cclink's Cargo.toml comment; pkarr 5.0.3 requires it).
   - Empty `src/lib.rs`, `src/main.rs`, `src/error.rs`, `src/util.rs`.
   - CI: `cargo check`, `cargo test`, `cargo clippy --deny warnings`.
   - *Dependency:* none.

2. **Phase: Vendor crypto + identity** (1 day)
   - Copy `cclink/src/crypto/mod.rs` verbatim into `src/crypto/mod.rs`, rename constants (`CCLINKEK` → `CIPHPOSK`, HKDF info strings). Update imports.
   - Copy `cclink/src/keys/` into `src/identity/`. Drop `homeserver_*`. Rename `~/.pubky` → `~/.cipherpost`.
   - Copy cclink's unit tests; they should pass as-is after rename.
   - *Dependency:* Phase 1.

3. **Phase: Vendor transport + record** (1 day)
   - Copy `cclink/src/transport/mod.rs`, rename label to `_cipherpost`.
   - Copy `cclink/src/record/mod.rs`. Generalize `HandoffRecord` → `OuterRecord`, drop `hostname`/`project`, add `share_ref` field (both in `OuterRecord` and `OuterRecordSignable`).
   - Adapt unit tests; the fit-in-1000-bytes test must be updated to reflect new field set.
   - *Dependency:* Phase 2.

4. **Phase: Payload schema** (1 day)
   - `payload/envelope.rs`: `Envelope` + `EnvelopeSignable` (mirror cclink's pattern — we don't actually need the envelope to be signed *separately* from the outer record, because the outer record signs the ciphertext which includes the envelope — but keep the signable-split pattern if we want future-proofing for envelope-only signing. Decide: **NO separate envelope signature in skeleton.** The outer record's inner-sig over the ciphertext blob is sufficient.)
   - `payload/material.rs`: `Material` enum with only `GenericSecret` implemented.
   - Unit tests: canonical JSON determinism (encode → decode → encode produces identical bytes), size cap at 64 KB.
   - *Dependency:* Phases 2, 3.

5. **Phase: Self-mode round trip** (1 day)
   - `flow/send.rs::run_send_self` + `flow/receive.rs::run_receive` (without acceptance prompt yet — just verify + decrypt).
   - `cli.rs` + `main.rs` just enough to drive these two commands.
   - Integration test: `tests/flow_two_identity.rs::test_self_mode` with a **mock transport** (see §5).
   - First real milestone demo: `cipherpost send --self` then `cipherpost receive` on same identity.
   - *Dependency:* Phase 4.

6. **Phase: Share-mode** (half day)
   - `flow/send.rs::run_send_share` — uses `crypto::recipient_from_z32`.
   - `receive` already works; just pass through.
   - Integration test: two identities, one sends to the other, recipient decrypts, sender cannot.
   - *Dependency:* Phase 5.

7. **Phase: Acceptance step** (half day)
   - Add `dialoguer::Confirm` gate in `flow/receive.rs` between display_preamble and material reveal.
   - Non-interactive behavior: if stdin is not a TTY, require `--yes` flag, else abort with a clear error.
   - Test: spawn a child process with piped stdin → send "y" or "n", verify stdout has material only in the "y" case.
   - *Dependency:* Phase 6.

8. **Phase: Receipt publishing** (1 day)
   - `receipt/mod.rs`: `Receipt`, `ReceiptSignable`, `sign`, `verify`.
   - `transport/mod.rs` extension: `publish_receipt` method that merges a new TXT record into recipient's existing SignedPacket without clobbering other records.
   - `flow/receipt_publish.rs`: wire into `flow/receive.rs` post-acceptance.
   - Tests: round-trip (sign, verify, tamper detection), coexistence (publish receipt under a key that already has a send-record; both TXT records survive).
   - *Dependency:* Phase 7.

9. **Phase: Receipt fetching** (half day)
   - `flow/receipt_fetch.rs` + `cipherpost receipts --from <z32>` CLI.
   - Test: integration test publishes a receipt, then fetches it, verifies the signature.
   - *Dependency:* Phase 8.

10. **Phase: Docs drafts** (1 day, can run in parallel with 8/9)
    - `SPEC.md` skeleton: payload schema, canonical JSON rules, share_ref derivation, receipt format, DHT label scheme.
    - `THREAT-MODEL.md` skeleton: identity-wrap, DHT as adversary, acceptance semantics, receipt replay.
    - `SECURITY.md`: disclosure contact.
    - *Dependency:* requires Phases 4, 7, 8 to be definitionally stable enough to document.

**Total walking-skeleton estimate: ~7 working days** if everything vendors cleanly. The pkarr/ed25519-dalek version pin is the single biggest external risk — if it breaks at any point, stop and pin to the exact versions cclink's Cargo.lock uses.

**Parallelism opportunities (what a second developer or a future phase split could hand off):**
- Phases 2 and 3 are independent of each other — they only share Phase 1. Could run concurrently.
- Phase 10 (docs) can run alongside Phases 8–9 once Phase 7 is complete.
- Nothing else parallelizes cleanly; receipt publishing depends transitively on almost everything.

---

## Testing Architecture

### The DHT problem

Hitting the real Mainline DHT from CI is slow and flaky — cclink explicitly avoids it. Their integration tests in `tests/integration_round_trip.rs` only use fixed-seed keypairs and exercise crypto + record, never `DhtClient::publish`. They test DHT packet structure by building a `SignedPacket` locally and calling `extract_txt` directly. **Adopt this pattern unchanged for cipherpost**, and add one extension for flows.

### Testing layers

| Layer | Scope | Tool | Where |
|-------|-------|------|-------|
| Unit | Pure functions inside a module | `#[cfg(test)] mod tests` inline | Each `src/**/mod.rs` |
| Integration — crypto | `age_encrypt`/`age_decrypt` round trip with fixed seeds; plaintext-leak byte-window scan | `#[test]` against `cipherpost::crypto::*` via `lib.rs` re-exports | `tests/crypto_roundtrip.rs`, `tests/plaintext_leak.rs` |
| Integration — record | Build OuterRecord, sign, verify, tamper-detect, fit-in-1000-bytes assertion | `#[test]` | `tests/record_roundtrip.rs` |
| Integration — payload | Canonical JSON determinism (encode/decode/encode bit-identical), size cap enforcement | `#[test]` | `tests/envelope_canonical_json.rs` |
| Integration — receipt | Issue + verify; tampering the share_ref, sender_pubkey, or nonce fails verification | `#[test]` | `tests/receipt_roundtrip.rs` |
| Integration — **flow** | End-to-end send→resolve→verify→decrypt→accept→receipt, **without real DHT** | `#[test]` with a `MockTransport` implementing a thin trait | `tests/flow_two_identity.rs` |
| Manual smoke test | Real DHT round-trip on one developer machine, two terminals | shell script | `scripts/smoke.sh` (manual, not in CI) |

### The MockTransport seam

Create a trait in `src/transport/mod.rs`:

```rust
pub trait Transport {
    fn publish(&self, kp: &pkarr::Keypair, record: &OuterRecord) -> anyhow::Result<()>;
    fn resolve_record(&self, z32: &str) -> anyhow::Result<OuterRecord>;
    fn publish_receipt(&self, kp: &pkarr::Keypair, label: &str, json: &str)
        -> anyhow::Result<()>;
    fn resolve_all_txt(&self, z32: &str) -> anyhow::Result<Vec<(String, String)>>;
    fn revoke(&self, kp: &pkarr::Keypair) -> anyhow::Result<()>;
}

pub struct DhtClient { /* real impl, wraps pkarr */ }
impl Transport for DhtClient { /* ... */ }
```

In `tests/`, write a `MockTransport` backed by a `HashMap<z32, SignedPacket>` (or just `HashMap<z32, Vec<(label, json)>>`). `flow::*` functions take `&dyn Transport` so tests inject the mock. This is the only interface change relative to cclink (which uses `DhtClient` concretely) — and it's cheap because the mock never needs to verify signatures or do async work; it just stores bytes.

**Critical:** the mock must enforce **the same size ceiling** (1000 bytes encoded) as the real DHT, or tests will pass locally and fail on publish. Add a debug-mode assert in `MockTransport::publish` that serializes and checks length.

### Property tests (optional for skeleton, recommended for v1.0)

`proptest` or `quickcheck` on:
- Canonical JSON: for any `Envelope`, `encode(e) == encode(decode(encode(e)))`.
- share_ref: same ciphertext + created_at → same share_ref; any byte change → different share_ref.
- Receipt: round-trip for any valid field combination; flipping any bit of the signable → verify fails.

These add dependency weight; defer to v1.0 unless a bug forces the issue earlier.

### What NOT to test in CI

- Real DHT publish. Ever. Keep the shell smoke test manual.
- Passphrase correctness timing. Argon2id is too slow for CI throughput; unit-test the key envelope round-trip with a fixed salt and lower `m_cost` via a `#[cfg(test)]` override if runtime becomes a problem.
- Interactive dialoguer prompts in CI directly. Instead, extract the prompting logic behind a `trait Prompter` so tests can inject a scripted answer.

---

## Anti-Patterns to Avoid

### Anti-Pattern 1: "Just take a dependency on cclink"

**What people do:** `cclink = "1.3"` in Cargo.toml, `use cclink::crypto::*;`
**Why it's wrong:** cclink is mothballed (per `.planning/PROJECT.md`). It will not receive security fixes. Any cipherpost bug reproducible in cclink is your problem to fix in both places, and you can't fix it upstream because upstream is unmaintained. Also, `cclink`'s record schema carries Claude Code session debris (the old `hostname`/`project` fields, `session/` module) that cipherpost shouldn't inherit into its type system.
**Do this instead:** Fork-and-diverge. Physically copy the four modules with clear provenance comments (`// Vendored from cclink@<commit-sha> on <date>. Do not edit in-place without documenting divergence.`).

### Anti-Pattern 2: Putting acceptance logic in `cli.rs`

**What people do:** The `cipherpost receive` clap handler prompts for acceptance before calling `flow::receive`.
**Why it's wrong:** Makes the policy untestable without spawning a subprocess. The acceptance gate is a security boundary — it needs property tests and unit tests.
**Do this instead:** `flow::receive` takes a `&dyn Prompter` (or an enum `AcceptancePolicy { Interactive, AutoAccept, AutoDecline }`). The CLI constructs `Interactive` for real use; tests construct `AutoAccept` or `AutoDecline`.

### Anti-Pattern 3: Publishing receipts under the sender's key

**What people do:** "The receipt is about the sender's share, so it belongs with the sender's record." → publish receipt as a TXT under sender's PKARR key.
**Why it's wrong:** The sender doesn't have the recipient's private key, so pkarr refuses to sign. Even if you tunnel it, you've just invented a side-channel that requires the recipient to hand the sender a signed blob, which is exactly the operator role the PRD forbids.
**Do this instead:** Receipt lives under the **recipient's** PKARR key at label `_cprcpt-<share_ref>`. Sender fetches by resolving the recipient's pubkey (which they know from the `--share` flag). §4.4 above.

### Anti-Pattern 4: Material reveal before acceptance

**What people do:** Decrypt, print to stdout, then prompt "did you want that?"
**Why it's wrong:** The material is on screen / in `less` scrollback / in terminal emulator history before the user decided. The acceptance step becomes cosmetic.
**Do this instead:** `flow/receive.rs` decrypts the Envelope, displays **only** the sender fingerprint + purpose + expiry, and holds the decrypted `Material` in a `Zeroizing<Vec<u8>>` until after the prompt returns `Yes`. On `No`, drop it.

### Anti-Pattern 5: Losing the canonical-JSON invariant

**What people do:** Refactor `OuterRecordSignable` to derive `Serialize` with a `#[serde(rename_all = "snake_case")]` or reorder fields "for readability."
**Why it's wrong:** Signatures are over the *bytes* of the JSON. Any field reordering or rename invalidates every previously issued signature. cclink enforces alphabetical field declaration order manually; a future Rust version or a well-meaning format pass could silently break this.
**Do this instead:** Add a `#[test] fn canonical_ordering_is_stable()` that hardcodes the expected field order and fails if `serde_json::to_string` of a known `OuterRecordSignable` deviates by a single byte. Same for `EnvelopeSignable` and `ReceiptSignable`.

---

## Integration Points

### External crates

| Crate | Integration Pattern | Notes |
|-------|---------------------|-------|
| `pkarr` 5.0.3 | `ClientBlocking`, `SignedPacket::builder().txt(label, txt, dns_ttl).sign(&keypair)` | Pinned. Requires `ed25519-dalek =3.0.0-pre.5`. Do not upgrade until pkarr releases on a stable ed25519-dalek 3.x. |
| `age` 0.11 | `Encryptor::with_recipients` for single X25519 recipient; `Decryptor::new` + `decrypt(iter(identity))` | Do not mix curve25519-dalek types across age + pkarr boundary — always go through raw `[u8;32]`. cclink comments this extensively; preserve the comments. |
| `ed25519-dalek` =3.0.0-pre.5 | Only for `SigningKey::from_bytes` (for X25519 secret derivation) and `Signature::from_bytes` (for verify_record) | Pre-release version. Pinned. Any version bump breaks signature compatibility — test exhaustively before touching. |
| `argon2` 0.5 | `Argon2::new(Argon2id, V0x13, Params::new(65536, 3, 1, Some(32)))` | Params go in CIPHPOSK envelope header for forward compat. |
| `hkdf` 0.12 + `sha2` 0.10 | HKDF-SHA256 with domain-separated `info` strings | Info strings: `cipherpost-key-v1` (key envelope), `cipherpost-pin-v1` (reserved for deferred --pin). |
| `zeroize` 1 | Wrap all secrets: `Zeroizing<[u8;32]>`, `Zeroizing<String>` for passphrases and PINs | Any Material byte buffer post-decrypt should be Zeroizing. |
| `clap` 4.5 | derive macros | Mirror cclink's pattern: top-level `Cli` struct, `Commands` subcommand enum. |
| `dialoguer` 0.12 | `Confirm::new().default(false).interact()` | Hide behind a `Prompter` trait so tests don't spawn subprocesses. |
| `backon` 1.6 | `ExponentialBuilder::default().with_min_delay(2s).with_max_delay(8s).with_total_delay(30s)` | Apply to `resolve_record` (and new `resolve_receipts`). Skip retry on `CipherpostError::RecordNotFound`. |
| `base64` 0.22 | `STANDARD` engine | Used for blob, signatures, pin_salt analogue, and receipt nonce. |
| `serde_json` 1.0 | default (no `preserve_order`) | **Critical.** `preserve_order` would break canonical JSON. Guard with a CI grep if necessary. |

### Internal boundaries

| Boundary | Communication | Notes |
|----------|---------------|-------|
| `flow/` ↔ `transport/` | `&dyn Transport` trait (new in cipherpost vs. cclink) | Only seam that distinguishes cipherpost from cclink architecturally. Enables MockTransport tests. |
| `flow/` ↔ `payload/` | Function calls: `Envelope::build`, `Envelope::decode`, `canonical_envelope_bytes` | No shared state. |
| `flow/` ↔ `record/` | Struct construction + `sign_record` / `verify_record` | `record/` never reaches into payload semantics; it only sees opaque `blob` base64. |
| `flow/` ↔ `receipt/` | Struct construction + `sign` / `verify` + `publish_receipt`/`resolve_all_txt` on transport | `receipt/` does not depend on `payload/` directly — only on the share_ref string. |
| `crypto/` ↔ everything | Pure functions, Vec<u8>/[u8;32] boundaries | Deliberately has zero dependency on `pkarr`'s types at the API boundary (takes `&pkarr::Keypair` as input but exposes raw bytes out). Keep it that way. |
| `identity/` ↔ filesystem | `~/.cipherpost/secret_key` (CIPHPOSK-wrapped seed) | 0600 permissions enforced in code, not relied on via umask (per SEC-02 in cclink). |

---

## Sources

- **cclink source (primary):** https://github.com/johnzilla/cclink — direct inspection of `src/` on default branch (2026-04-20). Files read: `Cargo.toml`, `src/lib.rs`, `src/main.rs`, `src/cli.rs`, `src/error.rs`, `src/crypto/mod.rs` (full), `src/record/mod.rs` (full header + structs + sign/verify), `src/transport/mod.rs` (full header + DhtClient impl), `src/keys/store.rs` (partial, enough for identity design), `src/session/mod.rs` (partial, confirmed Claude-specific and not carried forward), `src/commands/publish.rs` and `src/commands/pickup.rs` (partial, enough to understand flow), `tests/integration_round_trip.rs` and `tests/plaintext_leak.rs` (header + test patterns).
- **Cipherpost PRD:** `/home/john/vault/projects/github.com/cipherpost/cipherpost-prd.md` — Architecture section, scope anchors, non-goals.
- **Cipherpost PROJECT.md:** `/home/john/vault/projects/github.com/cipherpost/.planning/PROJECT.md` — Active requirements for the walking skeleton, constraints, Key Decisions.
- **Repo CLAUDE.md:** `/home/john/vault/projects/github.com/cipherpost/CLAUDE.md` — architectural lineage, hard constraints.
- **PKARR SignedPacket format / DNS TXT record semantics:** inferred from cclink's `transport/mod.rs` usage (`SignedPacket::builder().txt(label, rdata, dns_ttl).sign(kp)`; `resource_records(label)`; CAS via `resolve_most_recent(&pubkey).map(|p| p.timestamp())`; 1000-byte budget asserted in cclink's own fit-in-budget test). No additional PKARR-specific sources consulted — cclink's code is the reference implementation.

**Confidence:** HIGH. Every major claim here is backed by a specific file + line range in cclink's actual code, not by assumption or training data. The three places labeled as open design choices (envelope-level signing decision in §5 Phase 4, share_ref width at 64 bits, receipt storage under recipient's key) are flagged explicitly with rationale for the skeleton scope and the v1.0 decision point.

---
*Architecture research for: Cipherpost walking skeleton*
*Researched: 2026-04-20*
