# Phase 8: --pin and --burn encryption modes — Pattern Map

**Mapped:** 2026-04-25
**Files analyzed:** 17 (8 modified, 9 new)
**Analogs found:** 17 / 17 (every file has an in-tree analog; no net-new clap idiom this phase)

Phase 8 layers two orthogonal share-level features on the v1.0 walking skeleton via three discrete shapes that already exist in-tree:

1. **Per-variant ingest module** (`src/preview.rs` precedent — used here for `src/pin.rs`).
2. **Optional-field-with-`skip_serializing_if`** (no precedent yet for pure `bool` toggles, but `OuterRecord.recipient: Option<String>` and the Phase-6 `LedgerEntry.receipt_published_at: Option<&'a str>` show the JCS-stable optional shape).
3. **Per-variant ship-gate test bundle** (Phase 6 / 7 X.509 + PGP + SSH templates: fixture → JCS byte-identity → roundtrip → error-oracle).

Every Phase 8 file maps onto one of these shapes. The two genuinely new patterns are:

- The `is_false` serde helper free function — no in-tree analog because v1.0 has no bool-with-skip-serializing-if fields. Net-new but trivial (≤3 lines).
- The `LedgerState` enum + ledger-row `state` field migration — extends the existing private `LedgerEntry` shape with an `Option<&'a str>` field; Phase 6's `receipt_published_at: Option<&'a str>` (flow.rs:889-890) is the closest in-tree analog (also `Option<&str>` with `skip_serializing_if = "Option::is_none"`).

---

## File Classification

| New / Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---------------------|------|-----------|----------------|---------------|
| `src/pin.rs` (NEW) | crypto module / pure functions | transform (PIN → 32-byte scalar → age Identity → ciphertext) | `src/preview.rs` (new-module precedent) + `src/crypto.rs::derive_kek` (Argon2id+HKDF call shape) | exact (Argon2id+HKDF shape) + role-match (new-module file boundary) |
| `src/record.rs` (modify) | wire-format struct | transform (JCS bytes ↔ struct) | `OuterRecord.recipient: Option<String>` (record.rs:32) — the existing optional/skip-serializing-if pattern | partial — `Option<String>` not `bool`; need `is_false` helper |
| `src/payload/mod.rs` (modify) | wire-format struct | transform (JCS bytes ↔ struct) | same — `Envelope` shape from payload.rs:30-36 | exact (additive optional field) |
| `src/flow.rs::run_send` (modify) | controller / orchestrator | request-response | `run_send` itself (flow.rs:223-361) — extend the existing 14-step pipeline | exact (mechanical insertion) |
| `src/flow.rs::run_receive` (modify) | controller / orchestrator | request-response | `run_receive` itself (flow.rs:423-670) — extend the existing 13-step pipeline | exact (mechanical insertion) |
| `src/flow.rs::LedgerEntry` + new `LedgerState` enum | model / state schema | file I/O | `LedgerEntry` (flow.rs:883-893) + `receipt_published_at: Option<&'a str>` field shape | exact (Option<&str> + skip_serializing_if) |
| `src/flow.rs::TtyPrompter` + Prompter trait (modify) | UI / banner renderer | request-response | `Prompter::render_and_confirm` (flow.rs:83-97) + `preview_subblock: Option<&str>` param (Phase 6 precedent) | exact (mechanical: add one Option<&str> param) |
| `src/cli.rs::Send` (modify) | config / clap schema | request-response | `Send.armor: bool` (cli.rs:126) — exact bool flag precedent for typed-material gating | exact |
| `src/main.rs::Send` + `Receive` dispatch (modify) | controller / CLI dispatch | request-response | `main.rs::Send` arm (main.rs:80-212) — thread new flag into `run_send` | exact |
| `src/error.rs` (modify) | model / error taxonomy | — | Existing `Error::DecryptFailed` (error.rs:24-25) — wrong-PIN folds into this; NO new variant per RESEARCH.md correction | exact (zero-line change for oracle; one new variant only if planner needs `PinTooWeak`) |
| `src/lib.rs` (modify) | config / module graph | — | `src/lib.rs:8-17` `pub mod` block — Phase 6 added `preview;` here | exact (one line) |
| `tests/fixtures/outer_record_pin_required_signable.bin` (NEW) | fixture binary | file I/O | `tests/fixtures/outer_record_signable.bin` (192 B) | exact |
| `tests/fixtures/envelope_burn_signable.bin` (NEW) | fixture binary | file I/O | `tests/fixtures/envelope_jcs_generic_secret.bin` | exact |
| `tests/pin_roundtrip.rs` (NEW) | test / integration | request-response under MockTransport | `tests/phase2_self_round_trip.rs` (current Phase 7 signature) | exact |
| `tests/burn_roundtrip.rs` (NEW) | test / integration | request-response under MockTransport (TWO consecutive receives) | `tests/phase2_idempotent_re_receive.rs` (the only existing two-receive test) | exact |
| `tests/pin_burn_compose.rs` (NEW) | test / integration matrix | request-response under MockTransport | `tests/phase2_self_round_trip.rs` × 4 typed-material variants | exact (mechanical replication) |
| `tests/pin_error_oracle.rs` (NEW) | test / oracle hygiene | — | `tests/x509_error_oracle.rs` (EXPECTED_REASONS × FORBIDDEN_DISPLAY_TOKENS) + `tests/phase3_receipt_sign_verify.rs::assert_unified_d16_display` helper | exact (extend D-16 discipline to wrong-PIN ≡ wrong-passphrase ≡ tampered-ciphertext) |
| `tests/state_ledger.rs` (NEW — file does NOT exist today) | test / state-schema invariant | — | `tests/outer_record_canonical_form.rs` (the deserialize-default discipline) + `tests/phase2_idempotent_re_receive.rs` (ledger-line counting) | role-match (state schema migration test) |

Note on `tests/state_ledger.rs`: CONTEXT.md says "extend `tests/state_ledger.rs`" but this file does not currently exist. Plan 03 must CREATE it, not extend. The closest analog for the structural shape is `tests/outer_record_canonical_form.rs`.

---

## Pattern Assignments

### `src/pin.rs` (NEW — crypto module, transform)

**Analogs:**
- File-boundary precedent: `src/preview.rs` (Phase 6 added a brand-new file under `src/`).
- KDF-call-shape precedent: `src/crypto.rs::derive_kek` (crypto.rs:183-209) — Argon2id → HKDF-SHA256 → 32-byte output; `Zeroizing` on every secret buffer.

**Argon2id + HKDF call template** (crypto.rs:183-208) — copy verbatim with two changes (PIN as input, `hkdf_infos::PIN` as info string):

```rust
pub fn derive_kek(
    passphrase: &SecretBox<String>,
    salt: &[u8],
    params: &Params,
) -> Result<Zeroizing<[u8; 32]>, Error> {
    let argon = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        params.clone(),
    );
    let mut argon_out = Zeroizing::new([0u8; 32]);
    argon
        .hash_password_into(
            passphrase.expose_secret().as_bytes(),
            salt,
            &mut argon_out[..],
        )
        .map_err(str_err)?;

    let hk = Hkdf::<Sha256>::new(Some(salt), &argon_out[..]);
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(hkdf_infos::IDENTITY_KEK.as_bytes(), &mut okm[..])
        .map_err(|e| str_err(format!("hkdf expand: {}", e)))?;
    Ok(okm)
}
```

**Apply for PIN:** `pin_derive_key(pin: &SecretBox<String>, salt: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>, Error>`. Identical body, swap `hkdf_infos::IDENTITY_KEK` → `hkdf_infos::PIN`. PIN-09 params (64 MB, 3 iter) match `default_argon2_params()` (crypto.rs:175-177) exactly — reuse OR define `pin_argon2_params()` with the same numbers (RESEARCH §argon2 0.5.3 recommends local helper for documentation clarity).

**age Identity reuse** (crypto.rs:129-133) — call verbatim with the PIN-derived 32-byte scalar:
```rust
pub fn identity_from_x25519_bytes(bytes: &[u8; 32]) -> Result<x25519::Identity, Error> {
    let encoded =
        bech32::encode("age-secret-key-", bytes.to_base32(), Variant::Bech32).map_err(str_err)?;
    x25519::Identity::from_str(&encoded.to_uppercase()).map_err(str_err)
}
```

**age_encrypt reuse for nested encryption** (crypto.rs:139-148) — called TWICE in run_send when `pin_required=true`:
```rust
pub fn age_encrypt(plaintext: &[u8], recipient: &x25519::Recipient) -> Result<Vec<u8>, Error> {
    let encryptor =
        age::Encryptor::with_recipients(std::iter::once(recipient as &dyn age::Recipient))
            .map_err(str_err)?;
    let mut out = Vec::new();
    let mut writer = encryptor.wrap_output(&mut out).map_err(str_err)?;
    writer.write_all(plaintext).map_err(Error::Io)?;
    writer.finish().map_err(str_err)?;
    Ok(out)
}
```
**No new crypto API needed** — both layers go through this existing function. Inner: pin_recipient. Outer: receiver_recipient (existing v1.0 path).

**HKDF info constant addition** (crypto.rs:41-60) — append one line to `hkdf_infos` module:
```rust
pub mod hkdf_infos {
    pub const IDENTITY_KEK: &str = "cipherpost/v1/identity-kek";
    pub const SHARE_SENDER: &str = "cipherpost/v1/share-sender";
    pub const SHARE_RECIPIENT: &str = "cipherpost/v1/share-recipient";
    pub const INNER_PAYLOAD: &str = "cipherpost/v1/inner-payload";
    // Phase 8 Plan 01: add
    // pub const PIN: &str = "cipherpost/v1/pin";
}
```
The `tests/hkdf_info_enumeration.rs` grep test auto-discovers this on next run — no test code change needed.

**`validate_pin` for PIN-02** — direct fork of cclink's `validate_pin` (cclink/src/commands/publish.rs:19-67); blocklist + sequential + all-same algorithms reusable. Per CONTEXT.md "Claude's Discretion": Display should be GENERIC ("PIN does not meet entropy requirements") for oracle hygiene; specific reason on stderr but not in the `Error` Display path.

**Module visibility** — `pub mod pin;` added to `src/lib.rs:8-17` block.

**DO NOT WARNINGS:**
- DO NOT call `chacha20poly1305` directly. CLAUDE.md load-bearing. Verified by `tests/chacha20poly1305_direct_usage_ban.rs`.
- DO NOT `#[derive(Debug)]` on any struct holding the PIN, salt, or derived 32-byte scalar. Use `Zeroizing<[u8; 32]>` per the `derive_kek` template; if a struct is needed, write a manual Debug that emits `[REDACTED]`.
- DO NOT inline a literal `"cipherpost/v1/pin"` in a `hk.expand(...)` call — always reference `hkdf_infos::PIN`. The grep-based enumeration test only verifies the constant; non-constant info strings silently bypass the test.
- DO NOT pull a new `hkdf` Cargo.toml entry — already a direct dep at version 0.12.4 (Cargo.toml:32; verified by `use hkdf::Hkdf;` at crypto.rs:24). RESEARCH §"hkdf 0.12.4 — directly available" supersedes CONTEXT.md "transitive via age?" hedge.

---

### `src/record.rs::OuterRecord` + `OuterRecordSignable` (modify — wire-format struct)

**Analog:** `OuterRecord.recipient: Option<String>` (record.rs:32) — the existing JCS-stable optional field. v1.0 byte-identity is preserved when `recipient: None` because `serde_json` emits `"recipient":null` regardless — but the JCS fixture pins the exact shape today (192 B fixture includes `"recipient":"rcpt-placeholder-z32"`).

**For Phase 8, the analog is `bool` not `Option<String>`** — there is NO existing `bool` field with `skip_serializing_if` in the codebase. The `is_false` helper is therefore net-new but trivial.

**Struct addition pattern** (record.rs:26-36):
```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OuterRecord {
    pub blob: String,
    pub created_at: i64,
    pub protocol_version: u16,
    pub pubkey: String,
    pub recipient: Option<String>,
    pub share_ref: String,
    pub signature: String,
    pub ttl_seconds: u64,
}
```

**Apply for Phase 8** — insert `pin_required` between `created_at` and `protocol_version` (per RESEARCH JCS field-ordering verification: `pi` < `pr`, NOT between `created_at` and `purpose` as CONTEXT.md mistakenly says — `purpose` is on Envelope):
```rust
pub struct OuterRecord {
    pub blob: String,
    pub created_at: i64,
    #[serde(default, skip_serializing_if = "is_false")]
    pub pin_required: bool,
    pub protocol_version: u16,
    pub pubkey: String,
    pub recipient: Option<String>,
    pub share_ref: String,
    pub signature: String,
    pub ttl_seconds: u64,
}
```

**Apply identically for `OuterRecordSignable`** (record.rs:42-50) — same field, same attribute, same alphabetic position.

**`From<&OuterRecord>` projection** (record.rs:52-64) — thread the new field:
```rust
impl From<&OuterRecord> for OuterRecordSignable {
    fn from(r: &OuterRecord) -> Self {
        OuterRecordSignable {
            blob: r.blob.clone(),
            created_at: r.created_at,
            pin_required: r.pin_required,  // <-- new line
            protocol_version: r.protocol_version,
            pubkey: r.pubkey.clone(),
            recipient: r.recipient.clone(),
            share_ref: r.share_ref.clone(),
            ttl_seconds: r.ttl_seconds,
        }
    }
}
```

**`is_false` helper** — no in-tree precedent. Add to `src/record.rs` (or `src/lib.rs` as crate-scoped helper if the Envelope addition needs it too):
```rust
fn is_false(b: &bool) -> bool {
    !*b
}
```
Per RESEARCH §"Plan 03 (BURN core) anchors": planner picks file scope. If both `record.rs` and `payload/mod.rs` need it, hoist to `src/lib.rs` as `pub(crate) fn is_false(b: &bool) -> bool { !*b }`. Recommend the `lib.rs` placement to avoid duplication.

**DO NOT WARNINGS:**
- DO NOT change the existing field declaration order — JCS handles alphabetic regardless, but the "alphabetical declaration order belt-and-suspenders" comment at record.rs:25 is documentation discipline. Insert `pin_required` between `created_at` and `protocol_version` to keep the convention.
- DO NOT skip the `From` projection update — JCS bytes signed by sender will include `pin_required` (when true), so the inner-sig-verify path on receive MUST reconstruct the same Signable shape. Missing field in `From<&OuterRecord>` would silently produce wrong JCS bytes and trip `Error::SignatureCanonicalMismatch` with no clear cause.
- DO NOT promote `pin_required` into the inner `Envelope` — it MUST be outer-signed and pre-decrypt-readable per D-P8-03.

---

### `src/payload/mod.rs::Envelope` (modify — wire-format struct)

**Analog:** `Envelope` itself (payload/mod.rs:30-36) — extend with `burn_after_read: bool` field.

**Struct addition pattern** (payload/mod.rs:30-36):
```rust
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub created_at: i64,
    pub material: Material,
    pub protocol_version: u16,
    pub purpose: String,
}
```

**Apply for Phase 8** — `burn_after_read` lands FIRST alphabetically (`b` < `c`, per RESEARCH §JCS field-ordering verification):
```rust
pub struct Envelope {
    #[serde(default, skip_serializing_if = "is_false")]
    pub burn_after_read: bool,
    pub created_at: i64,
    pub material: Material,
    pub protocol_version: u16,
    pub purpose: String,
}
```

**Manual Debug impl update** (payload/mod.rs:38-47) — thread new field:
```rust
impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("burn_after_read", &self.burn_after_read)  // <-- new
            .field("created_at", &self.created_at)
            .field("material", &self.material)
            .field("protocol_version", &self.protocol_version)
            .field("purpose", &self.purpose)
            .finish()
    }
}
```

**DO NOT WARNINGS:**
- DO NOT promote `burn_after_read` to OuterRecord. CLAUDE.md principle 3 ("metadata encrypted") + D-P8-04 — DHT observers must NOT see which shares are burn-marked.
- DO NOT skip the `is_false` import — both `record.rs` and `payload/mod.rs` reference it; if hoisted to `lib.rs`, both modules `use crate::is_false;`.

---

### `src/flow.rs::run_send` (modify — orchestrator, request-response)

**Analog:** `run_send` itself (flow.rs:223-361) — extend the existing 14-step pipeline with two insertions: PIN nested-age branch (between steps 6 and 8) + `pin_required` field on the Signable.

**Existing wire-budget retry block** (flow.rs:303-352):
```rust
let mut last_err: Option<(usize, usize)> = None;
for _attempt in 0..WIRE_BUDGET_RETRY_ATTEMPTS {
    // 6. age_encrypt (grease stanza re-sampled each call)
    let ciphertext = crypto::age_encrypt(&jcs_bytes, &recipient)?;

    // 7. share_ref — hash raw ciphertext bytes per PAYL-05.
    let share_ref = record::share_ref_from_bytes(&ciphertext, created_at);

    // 8. blob (base64 STANDARD)
    use base64::Engine;
    let blob = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

    // 9 + 10 + 11. signable → sign → record
    let signable = OuterRecordSignable {
        blob: blob.clone(),
        created_at,
        protocol_version: PROTOCOL_VERSION,
        pubkey: identity.z32_pubkey(),
        recipient: recipient_z32_option.clone(),
        share_ref: share_ref.clone(),
        ttl_seconds,
    };
    // ... sign + build OuterRecord + check_wire_budget + publish ...
}
```

**Apply for Phase 8 — three changes inside the retry loop:**

1. **Step 6 becomes nested-age when `pin_required=true`**:
```rust
let outer_ct = if let Some((salt, pin_recipient)) = &pin_setup {
    // Inner: age-encrypt to PIN-derived recipient
    let inner_ct = crypto::age_encrypt(&jcs_bytes, pin_recipient)?;
    // Outer: age-encrypt inner_ct to receiver identity (existing v1.0 path)
    crypto::age_encrypt(&inner_ct, &recipient)?
} else {
    // v1.0 path: single age-encrypt
    crypto::age_encrypt(&jcs_bytes, &recipient)?
};
```

2. **Step 7 share_ref** — hashes the OUTER ciphertext (NOT salt-prefixed bytes); PAYL-05 invariant unchanged.

3. **Step 8 blob conditional salt prefix**:
```rust
let blob = if let Some((salt, _)) = &pin_setup {
    let mut buf = Vec::with_capacity(32 + outer_ct.len());
    buf.extend_from_slice(&salt[..]);
    buf.extend_from_slice(&outer_ct);
    base64::engine::general_purpose::STANDARD.encode(&buf)
} else {
    base64::engine::general_purpose::STANDARD.encode(&outer_ct)
};
```

4. **Steps 9-11 Signable** — add `pin_required: pin_setup.is_some()`.

**Function signature change** — add two new parameters:
```rust
pub fn run_send(
    identity: &Identity,
    transport: &dyn Transport,
    keypair: &pkarr::Keypair,
    mode: SendMode,
    purpose: &str,
    material_source: MaterialSource,
    material_variant: MaterialVariant,
    ttl_seconds: u64,
    pin: Option<SecretBox<String>>,    // <-- new
    burn: bool,                         // <-- new (set Envelope.burn_after_read)
) -> Result<String, Error> { ... }
```

Phase 6/7 added a `MaterialVariant` parameter without a default-arg pattern — every test call site updated explicitly. Phase 8 mirrors: every existing test call site (`tests/phase2_self_round_trip.rs:37-46`, `tests/phase2_share_round_trip.rs`, etc.) gets `None, false` appended. ~10 call sites total.

**Pin setup pre-loop** (before line 303 retry loop):
```rust
let pin_setup: Option<([u8; 32], age::x25519::Recipient)> = if let Some(pin) = &pin {
    let mut salt = [0u8; 32];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);
    let pin_key = crate::pin::pin_derive_key(pin, &salt)?;
    let pin_id = crypto::identity_from_x25519_bytes(&pin_key)?;
    let pin_rcpt = pin_id.to_public();
    Some((salt, pin_rcpt))
} else {
    None
};
```
The salt is derived ONCE outside the retry loop — grease stanza variance only affects ciphertext bytes, not the KDF output. Salt regen on each grease retry would needlessly waste Argon2id work (~250ms × 20 retries = 5s false-budget overhead).

**DO NOT WARNINGS:**
- DO NOT call `pin_derive_key` inside the wire-budget retry loop. Argon2id is ~250ms; 20 retries would burn 5 seconds. Salt + KDF result are stable across grease draws.
- DO NOT use `rand::thread_rng()` without verifying `rand` is in Cargo.toml. RESEARCH does not list `rand` as already-pulled — verify at Plan 01 time. If absent, `getrandom = "0.2"` (already a transitive via `argon2`) is the supply-chain-safer alternative.
- DO NOT call `crypto::age_encrypt` ONCE and try to derive the inner from the outer afterwards. The two layers are independent — inner consumes `jcs_bytes`, outer consumes `inner_ct`.

---

### `src/flow.rs::run_receive` (modify — orchestrator, request-response)

**Analog:** `run_receive` itself (flow.rs:423-670) — the existing 13-step pipeline becomes the 16-step pipeline per D-P8-07.

**Existing step ordering** (flow.rs:432-591):
```rust
// STEP 1: sentinel-check (no network, no passphrase)
// STEP 2 + 3: transport.resolve() — outer PKARR sig + inner Ed25519 sig
// STEP 4: URI/record share_ref match
// STEP 5: TTL check
// STEP 6: age-decrypt
// STEP 7: parse decrypted bytes as JCS → Envelope
// STEP 8: acceptance prompt (Prompter)
// STEP 11: write material to output sink
// STEP 12: sentinel FIRST, ledger SECOND  <-- Phase 8 INVERTS for burn (D-P8-12)
// STEP 13: publish_receipt
```

**Apply for Phase 8 — five insertions / changes:**

1. **STEP 1 becomes ledger pre-check returning `LedgerState`** (D-P8-09):
```rust
match check_already_consumed(&uri.share_ref_hex) {
    LedgerState::None => { /* proceed */ }
    LedgerState::Accepted { accepted_at } => {
        eprintln!("already accepted at {}; not re-decrypting", accepted_at);
        return Ok(());
    }
    LedgerState::Burned { burned_at } => {
        eprintln!("share already consumed (burned at {})", burned_at);
        return Err(Error::Declined); // exit 7 per BURN-02
    }
}
```

2. **NEW STEP 5a — PIN prompt after outer-verify, BEFORE age-decrypt** (D-P8-07 step 5):
```rust
// Read OuterRecord.pin_required (already in `record` from STEP 2/3 resolve()).
// If true: split blob bytes; prompt for PIN.
let (ciphertext, pin_setup): (Vec<u8>, Option<age::x25519::Identity>) = if record.pin_required {
    let blob_bytes = base64::engine::general_purpose::STANDARD
        .decode(&record.blob)
        .map_err(|_| Error::SignatureCanonicalMismatch)?;
    if blob_bytes.len() < 32 {
        return Err(Error::SignatureCanonicalMismatch);
    }
    let (salt, outer_ct) = blob_bytes.split_at(32);
    let salt: [u8; 32] = salt.try_into().expect("just sliced 32 bytes");
    // PIN prompt — TTY-only, no echo, BEFORE age-decrypt
    let pin = crate::pin::prompt_pin(false)?;
    let pin_key = crate::pin::pin_derive_key(&pin, &salt)?;
    let pin_id = crypto::identity_from_x25519_bytes(&pin_key)?;
    (outer_ct.to_vec(), Some(pin_id))
} else {
    let ct = base64::engine::general_purpose::STANDARD
        .decode(&record.blob)
        .map_err(|_| Error::SignatureCanonicalMismatch)?;
    (ct, None)
};
```

3. **STEP 6 nested age-decrypt** — when `pin_setup.is_some()`, decrypt outer first, then inner with PIN identity:
```rust
let jcs_plain: Zeroizing<Vec<u8>> = if let Some(pin_id) = &pin_setup {
    // Outer: age-decrypt with receiver identity → produces inner_ct
    let inner_ct = crypto::age_decrypt(&ciphertext, &age_id)?;
    // Inner: age-decrypt inner_ct with PIN-derived identity → envelope_json
    crypto::age_decrypt(&inner_ct, pin_id)?
} else {
    // v1.0 path: single age-decrypt
    crypto::age_decrypt(&ciphertext, &age_id)?
};
```
Both wrong-PIN and wrong-passphrase produce `Error::DecryptFailed` (crypto.rs:153-164 maps every age decryption failure to this) — Display unified at "wrong passphrase or identity decryption failed" (error.rs:24). PIN-07 oracle hygiene satisfied without a new variant.

4. **STEP 8 banner — `[BURN]` marker insertion** — extend Prompter call:
```rust
prompter.render_and_confirm(
    &envelope.purpose,
    &sender_openssh_fp,
    &record.pubkey,
    &record.share_ref,
    material_type_string(&envelope.material),
    material_bytes.len(),
    preview_subblock.as_deref(),
    if envelope.burn_after_read {
        Some("[BURN — you will only see this once]")
    } else {
        None
    },  // <-- new param: marker
    ttl_remaining,
    expires_at,
)?;
```

5. **STEP 12 ordering INVERSION for burn** (D-P8-11, D-P8-12 — emit-before-mark for burn ONLY):
```rust
if envelope.burn_after_read {
    // BURN: emit FIRST, then mark (D-P8-12 emit-before-mark)
    write_output(output, &output_bytes)?;
    append_ledger_entry_burned(&record.share_ref, &record.pubkey, &envelope.purpose, &ciphertext, &jcs_plain)?;
    create_sentinel(&record.share_ref)?;
} else {
    // v1.0 ACCEPTED: sentinel + ledger first, then emit (existing flow.rs:583-591 ordering)
    create_sentinel(&record.share_ref)?;
    append_ledger_entry(&record.share_ref, &record.pubkey, &envelope.purpose, &ciphertext, &jcs_plain)?;
    write_output(output, &output_bytes)?;
}
```

Wait — re-reading flow.rs:582 — current code is `write_output` BEFORE `create_sentinel`. So v1.0 is already emit-then-mark for accepted. The Phase 8 INVERSION is the OTHER direction: BURN must emit-then-mark, but **the row written must include `state: "burned"`** so a crash between emit and ledger write leaves the share in a re-receivable state (per D-P8-12 rationale). The "inversion" is the SEMANTIC inversion (which row is written), not strict line ordering.

Re-reading flow.rs more carefully — the existing order is: STEP 11 write_output (line 581) → STEP 12 create_sentinel (line 584) → append_ledger_entry (line 585). So v1.0 is already write-then-sentinel-then-ledger. Phase 8 BURN keeps the same order but writes `state: "burned"` on the ledger row; v1.0 ACCEPTED keeps `state: "accepted"` (or no state field, defaulting via serde to `Accepted`).

**Corrected understanding — STEP 11/12 for Phase 8:**
```rust
// STEP 11: write_output (unchanged)
write_output(output, &output_bytes)?;

// STEP 12: sentinel + ledger (extended — selects which state value to write)
create_sentinel(&record.share_ref)?;
if envelope.burn_after_read {
    append_ledger_entry_with_state(&record.share_ref, &record.pubkey, &envelope.purpose, &ciphertext, &jcs_plain, Some("burned"))?;
} else {
    append_ledger_entry(&record.share_ref, &record.pubkey, &envelope.purpose, &ciphertext, &jcs_plain)?;  // implicit state=None → Accepted on read
}
```

**STEP 13 — receipt always published** (BURN-04). Existing publish_outcome closure (flow.rs:612-662) unchanged.

**DO NOT WARNINGS:**
- DO NOT prompt for PIN before STEP 2/3 outer-verify. Tamper-zero invariant: outer-verify is the gate; failures here must produce exit 3 with NO PIN-prompt side effect.
- DO NOT publish a receipt for a burn share that failed inner-verify or wrong-PIN. The publish_outcome closure runs AFTER full verify + acceptance + emit (flow.rs:612). Nothing to change here — but DO NOT shortcut by publishing earlier.
- DO NOT log PIN bytes anywhere — not stderr, not Debug, not panic messages. PIN-10 leak-scan extension covers this.
- DO NOT mark `burned` BEFORE emit. Crash between mark-and-emit loses user data. v1.0's existing emit-then-mark order at flow.rs:581-585 ALREADY satisfies D-P8-12 — verify Plan 04 doesn't accidentally change it.
- DO NOT remove the existing `check_already_accepted` function until both call sites (flow.rs:433 + main.rs:237) are migrated to `check_already_consumed` returning `LedgerState`.

---

### `src/flow.rs::Prompter` trait + `TtyPrompter` impl + test prompters (modify)

**Analog:** Prompter trait (flow.rs:83-97) + TtyPrompter impl (flow.rs:1165-1239) + AutoConfirmPrompter / DeclinePrompter (flow.rs:1041-1078).

**Existing trait signature** (flow.rs:83-97):
```rust
pub trait Prompter {
    #[allow(clippy::too_many_arguments)]
    fn render_and_confirm(
        &self,
        purpose: &str,
        sender_openssh_fp: &str,
        sender_z32: &str,
        share_ref_hex: &str,
        material_type: &str,
        size_bytes: usize,
        preview_subblock: Option<&str>,
        ttl_remaining_seconds: u64,
        expires_unix_seconds: i64,
    ) -> Result<(), Error>;
}
```

**Apply for Phase 8** — add `marker: Option<&str>` parameter (BURN marker; future-extensible to other top-of-banner alerts). Position: between `share_ref_hex` and `material_type` so the rendering loop is straightforward (header → marker → Purpose → ... → preview_subblock → TTL → footer).

```rust
pub trait Prompter {
    #[allow(clippy::too_many_arguments)]
    fn render_and_confirm(
        &self,
        purpose: &str,
        sender_openssh_fp: &str,
        sender_z32: &str,
        share_ref_hex: &str,
        marker: Option<&str>,             // <-- new (D-P8-08 [BURN] marker)
        material_type: &str,
        size_bytes: usize,
        preview_subblock: Option<&str>,
        ttl_remaining_seconds: u64,
        expires_unix_seconds: i64,
    ) -> Result<(), Error>;
}
```

**TtyPrompter banner emission** (flow.rs:1196-1213) — insert marker line BEFORE the Purpose line per D-P8-08:
```rust
eprintln!("=== CIPHERPOST ACCEPTANCE ===============================");
if let Some(m) = marker {
    eprintln!("{}", m);  // <-- new: "[BURN — you will only see this once]"
}
eprintln!("Purpose:     \"{}\"", safe_purpose);
eprintln!("Sender:      {}", sender_openssh_fp);
// ... rest unchanged ...
```

**Test prompter signature updates** (flow.rs:1043-1058 AutoConfirmPrompter; 1063-1077 DeclinePrompter) — both impls add `_marker: Option<&str>` underscore-prefixed. Mirrors how Phase 6 added `_preview_subblock`.

**DO NOT WARNINGS:**
- DO NOT place the marker AFTER Purpose (D-P8-08 explicitly rejects that — skim-past risk).
- DO NOT render the marker only when `preview_subblock.is_some()` — they are independent banner extensions.
- DO NOT update the trait without updating EVERY impl. Compiler enforces this, but the cross-cutting touchpoints (TtyPrompter + AutoConfirmPrompter + DeclinePrompter + every test that hand-implements Prompter, if any) need a single coordinated edit.

---

### `src/flow.rs::LedgerEntry` + new `LedgerState` enum (modify — state schema)

**Analog:** `LedgerEntry` struct (flow.rs:883-893) + the existing `Option<&'a str>` skip-serializing-if pattern at `receipt_published_at` (line 889-890):
```rust
#[derive(serde::Serialize)]
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_published_at: Option<&'a str>,
    sender: &'a str,
    share_ref: &'a str,
}
```

**Apply for Phase 8** — add `state: Option<&'a str>` with the same `skip_serializing_if = "Option::is_none"`:
```rust
#[derive(serde::Serialize)]
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_published_at: Option<&'a str>,
    sender: &'a str,
    share_ref: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    state: Option<&'a str>,  // <-- new (None | Some("accepted") | Some("burned"))
}
```

When `state` is `None`, the field elides — v1.0 byte-identity preserved on the wire. v1.0 rows on disk parse via serde default (no field) → `state: None` → `LedgerState::Accepted` semantics in the read path.

**`LedgerState` enum** — NEW; place in `src/flow.rs` (existing module; ledger code is already here):
```rust
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LedgerState {
    None,
    Accepted { accepted_at: String },
    Burned { burned_at: String },
}
```

**`check_already_consumed`** — RENAME of existing `check_already_accepted` (flow.rs:128-150). Two callers update: flow.rs:433 (in run_receive) and main.rs:237 (CLI dispatch idempotency check).

```rust
pub fn check_already_consumed(share_ref_hex: &str) -> LedgerState {
    if !sentinel_path(share_ref_hex).exists() {
        return LedgerState::None;
    }
    if let Ok(data) = fs::read_to_string(ledger_path()) {
        for line in data.lines() {
            if !line.contains(share_ref_hex) { continue; }
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v.get("share_ref").and_then(|s| s.as_str()) == Some(share_ref_hex) {
                    let state_field = v.get("state").and_then(|s| s.as_str());
                    let accepted_at = v.get("accepted_at")
                        .and_then(|s| s.as_str())
                        .unwrap_or("<unknown>")
                        .to_string();
                    return match state_field {
                        Some("burned") => LedgerState::Burned { burned_at: accepted_at },
                        _ => LedgerState::Accepted { accepted_at },  // None or "accepted" → Accepted
                    };
                }
            }
        }
    }
    LedgerState::Accepted { accepted_at: "<unknown; sentinel exists but ledger missing>".to_string() }
}
```

**DO NOT WARNINGS:**
- DO NOT add `state` as a typed enum field on `LedgerEntry` itself. JSONL rows are read by both this code AND external tooling; JSON's open-set extensibility favors a string. The TYPED `LedgerState` enum is a runtime abstraction in `check_already_consumed`'s return type — NOT the wire shape. (Per RESEARCH §"Ledger schema migration shape".)
- DO NOT rename the existing `accepted.jsonl` file. v1.0 path is locked; rename rejected per D-P8-10 ("would break existing receivers").
- DO NOT delete `check_already_accepted` until both call sites compile against the renamed function. Recommendation: keep a thin wrapper for one phase, deprecate, then remove.
- DO NOT skip the v1.0-row default-deserialization test. v1.0 rows have NO `state` field; they MUST parse as `LedgerState::Accepted`. The new `tests/state_ledger.rs` file pins this invariant.

---

### `src/cli.rs::Send` (modify — clap schema)

**Analog:** `Send.armor: bool` (cli.rs:126) + `Send` struct boolean flag pattern (cli.rs:62-64 `self_: bool`).

**Existing bool flag pattern** (cli.rs:122-126):
```rust
/// Emit PEM-armored certificate output (`-----BEGIN CERTIFICATE-----` envelope).
/// Only valid when the share's Material is `x509_cert`; rejected otherwise.
#[arg(long)]
armor: bool,
```

**Apply for Phase 8** — add `pin: bool` and `burn: bool` to `Send` (cli.rs:61-101):
```rust
/// Require a PIN as a second factor on receive. PIN is read from TTY at send
/// time (with confirmation); receiver is prompted at receive time. PIN-protected
/// shares require BOTH the receiver's identity passphrase AND the PIN to decrypt.
/// Non-interactive PIN sources (--pin-file, --pin-fd, CIPHERPOST_PIN env) are
/// deferred to v1.2.
#[arg(long)]
pub pin: bool,

/// Mark the share single-consumption. After the receiver successfully decrypts
/// and accepts, the local ledger records `state: "burned"` and any subsequent
/// receive attempt against the same share_ref returns exit 7. Note: burn is
/// LOCAL-STATE-ONLY; the encrypted payload remains on the DHT until TTL.
/// See THREAT-MODEL.md §Burn mode for the multi-machine race caveat.
#[arg(long)]
pub burn: bool,
```

**DO NOT WARNINGS:**
- DO NOT add `--pin <value>` argv-inline (a hidden `Option<String>` clap arg, like `passphrase: Option<String>`). PIN-01 defers all non-interactive PIN to v1.2 — single bool flag is enough. CONTEXT.md `<deferred>` last bullet: "Argv-inline `--pin <value>` rejected at parse and runtime."
- DO NOT add `--pin` or `--burn` to `Receive`. Receiver auto-detects pin_required + burn_after_read from the share metadata. NO new receive flags (CONTEXT.md `<code_context>` Integration Points).

---

### `src/main.rs` Send + Receive dispatch (modify — CLI dispatch)

**Analog:** `main.rs::Send` arm (main.rs:80-212) — extend the destructuring + thread the new flags into `run_send`.

**Existing destructuring + run_send call** (main.rs:80-208):
```rust
Command::Send {
    self_,
    share,
    purpose,
    material_file,
    ttl,
    material,
    passphrase,
    passphrase_file,
    passphrase_fd,
    material_stdin,
} => {
    // ... validation + identity load + transport build ...
    let uri = cipherpost::flow::run_send(
        &id,
        transport.as_ref(),
        &kp,
        mode,
        purpose_str,
        material_source,
        material,
        ttl_seconds,
    )?;
    println!("{}", uri);
    Ok(())
}
```

**Apply for Phase 8** — add `pin, burn` to destructuring; PIN prompt logic before run_send call; thread both into run_send:
```rust
Command::Send {
    self_,
    share,
    purpose,
    material_file,
    ttl,
    material,
    pin,                   // <-- new
    burn,                  // <-- new
    passphrase,
    passphrase_file,
    passphrase_fd,
    material_stdin,
} => {
    // ... existing validation ...

    // Phase 8: PIN prompt at send time (TTY-only, with confirmation).
    let pin_secret: Option<SecretBox<String>> = if pin {
        Some(cipherpost::pin::prompt_pin(true)?)  // confirm=true for send
    } else {
        None
    };

    // Phase 8 BURN-05: send-time stderr warning when --burn is set.
    if burn {
        eprintln!("warning: --burn is local-state-only; ciphertext remains on DHT until TTL");
    }

    // ... existing identity load + transport build ...

    let uri = cipherpost::flow::run_send(
        &id,
        transport.as_ref(),
        &kp,
        mode,
        purpose_str,
        material_source,
        material,
        ttl_seconds,
        pin_secret,            // <-- new
        burn,                  // <-- new
    )?;
    println!("{}", uri);
    Ok(())
}
```

**Receive dispatch** — main.rs:237 (the existing `check_already_accepted` call) renames to `check_already_consumed` and pattern-matches on `LedgerState`:
```rust
match cipherpost::flow::check_already_consumed(&uri.share_ref_hex) {
    cipherpost::flow::LedgerState::None => { /* proceed */ }
    cipherpost::flow::LedgerState::Accepted { accepted_at } => {
        eprintln!("already accepted at {}; not re-decrypting", accepted_at);
        return Ok(());
    }
    cipherpost::flow::LedgerState::Burned { burned_at } => {
        eprintln!("share already consumed (burned at {})", burned_at);
        return Err(cipherpost::Error::Declined.into());
    }
}
```

**DO NOT WARNINGS:**
- DO NOT prompt for PIN BEFORE the passphrase prompt in send dispatch. Order doesn't strictly matter (both fail-fast), but keeping passphrase first preserves the "unlock-then-act" mental model. Recommendation: passphrase resolve first, then PIN prompt before run_send.
- DO NOT skip the `--burn` stderr warning. BURN-05 is a hard requirement; the multi-machine race caveat must surface BEFORE the user commits to send.

---

### `src/error.rs` (modify — error taxonomy)

**Analog:** `Error::DecryptFailed` (error.rs:24-25) — wrong-PIN and wrong-passphrase BOTH map to this variant per RESEARCH §"Error-oracle Display equality" (line 220-227).

**KEY FINDING from RESEARCH (supersedes CONTEXT.md):** No new `Error::PinIncorrect` variant is needed. `crypto::age_decrypt` (crypto.rs:153-164) already maps every age decryption failure (including wrong recipient = wrong PIN at the inner layer) to `Error::DecryptFailed`. PIN-07 oracle hygiene satisfied via the EXISTING `Error::DecryptFailed` Display.

**Existing Display** (error.rs:24):
```rust
#[error("wrong passphrase or identity decryption failed")]
DecryptFailed,
```
**Exit code** (error.rs:118): exit 4. Already correct.

**Optional: `Error::PinTooWeak { reason: String }`** for PIN-02 entropy-floor violations at SEND time (different oracle class — sender-side validation, NOT receive-side decrypt). Per CONTEXT.md "Claude's Discretion": planner picks. If added, follow the `InvalidMaterial` shape (error.rs:64-73):
```rust
/// PIN-02 / D-P8-XX: PIN does not meet entropy requirements.
/// Display is GENERIC ("PIN does not meet entropy requirements") — the specific
/// reason is logged to stderr by the CLI dispatch BEFORE the Error is constructed,
/// so the Display itself does not leak which check fired (oracle hygiene).
///
/// Maps to exit 1 (validation error, not credential failure).
#[error("PIN does not meet entropy requirements")]
PinTooWeak,
```
NB: per CONTEXT.md "PIN does not meet entropy requirements" generic Display — no `{ reason }` field on the variant. Specific reason on stderr only.

**Exit-code mapping** (error.rs:111-127) — PinTooWeak falls into `_ => 1` default arm; explicit arm not strictly needed but recommended for grep-ability.

**DO NOT WARNINGS:**
- DO NOT add `Error::PinIncorrect` or any wrong-PIN-distinguishing variant. PIN-07 + Pitfall #23 oracle hygiene REQUIRES wrong-PIN to be indistinguishable from wrong-passphrase. Existing `Error::DecryptFailed` is the canonical home.
- DO NOT use `#[source]` or `#[from]` on `PinTooWeak` (if added). Same hygiene rule as `InvalidMaterial` (error.rs:69-71): a wrapped error chain is Display-leak bait.
- DO NOT add a new exit code for `share already consumed`. BURN-02 reuses exit 7 (`Error::Declined` → `eprintln!("share already consumed")` + return `Err(Error::Declined)`). Exit-code taxonomy unchanged.

---

### `src/lib.rs` (modify — module graph)

**Analog:** `src/lib.rs:8-17` — existing `pub mod` block. Phase 6 added `preview;` here; Phase 8 adds `pin;` (alphabetical placement: between `payload` and `preview`):

```rust
pub mod cli;
pub mod crypto;
pub mod error;
pub mod flow;
pub mod identity;
pub mod payload;
pub mod pin;            // <-- NEW (Phase 8 Plan 01)
pub mod preview;
pub mod receipt;
pub mod record;
pub mod transport;
```

If the `is_false` helper is hoisted to crate scope (recommended for shared use across `record.rs` and `payload/mod.rs`), add:
```rust
/// Phase 8 helper: serde `skip_serializing_if` predicate for boolean
/// "default-elide-on-false" fields (OuterRecord.pin_required + Envelope.burn_after_read).
/// v1.0 byte-identity is preserved when the field is `false`.
pub(crate) fn is_false(b: &bool) -> bool {
    !*b
}
```

**DO NOT WARNINGS:**
- DO NOT make `is_false` `pub` (instead of `pub(crate)`). External consumers don't need it; the function is a serde implementation detail.

---

### `tests/fixtures/outer_record_pin_required_signable.bin` (NEW — fixture binary)

**Analog:** `tests/fixtures/outer_record_signable.bin` (192 B) — produced by `tests/outer_record_canonical_form.rs` regen helper.

**Pattern — fixture loading + JCS byte-locked test + `#[ignore]` regen** (tests/outer_record_canonical_form.rs:13-44):
```rust
const FIXTURE_PATH: &str = "tests/fixtures/outer_record_signable.bin";

fn fixture_signable() -> OuterRecordSignable {
    OuterRecordSignable {
        blob: "AAAA".into(),
        created_at: 1_700_000_000,
        protocol_version: 1,
        pubkey: "pk-placeholder-z32".into(),
        recipient: Some("rcpt-placeholder-z32".into()),
        share_ref: "0123456789abcdef0123456789abcdef".into(),
        ttl_seconds: 86400,
    }
}

#[test]
fn outer_record_signable_bytes_match_committed_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_fixture` to create it",
    );
    assert_eq!(bytes, expected, "OuterRecordSignable JCS bytes changed — past signatures invalidated!");
}

#[test]
#[ignore]
fn regenerate_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {}", FIXTURE_PATH);
}
```

**Apply for Phase 8** — new test file `tests/outer_record_pin_required_signable.rs` (or fold into `outer_record_canonical_form.rs` as a sibling test pair). The fixture builds an `OuterRecordSignable { pin_required: true, ..fixture_signable() }`:
```rust
const FIXTURE_PATH_PIN: &str = "tests/fixtures/outer_record_pin_required_signable.bin";

fn fixture_signable_pin_required() -> OuterRecordSignable {
    OuterRecordSignable {
        blob: "AAAA".into(),
        created_at: 1_700_000_000,
        pin_required: true,                      // <-- new field
        protocol_version: 1,
        pubkey: "pk-placeholder-z32".into(),
        recipient: Some("rcpt-placeholder-z32".into()),
        share_ref: "0123456789abcdef0123456789abcdef".into(),
        ttl_seconds: 86400,
    }
}
```
**Estimated fixture size:** ~218 bytes (192-byte v1.0 fixture + ~22 bytes for `,"pin_required":true`).

**DO NOT WARNINGS:**
- DO NOT regenerate `outer_record_signable.bin` (the v1.0 fixture). Phase 8 is byte-additive — non-pin shares MUST produce the SAME 192-byte fixture. If Phase 8 work changes that fixture, `is_false` is misconfigured.
- DO NOT commit a fixture without running BOTH the byte-match assert AND the regen helper at least once. The byte-match test is the gate; the regen helper produces the bytes the gate compares against.

---

### `tests/fixtures/envelope_burn_signable.bin` (NEW — fixture binary)

**Analog:** `tests/fixtures/envelope_jcs_generic_secret.bin` + the `tests/material_x509_envelope_round_trip.rs` template.

**Pattern** (material_x509_envelope_round_trip.rs:14-69) — verbatim shape, swap the burn case:
```rust
const FIXTURE_PATH: &str = "tests/fixtures/envelope_burn_signable.bin";

fn fixture_envelope_burn() -> Envelope {
    Envelope {
        burn_after_read: true,                     // <-- new (lands first alphabetically)
        created_at: 1_700_000_000,
        material: Material::generic_secret(vec![0, 1, 2, 3]),
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}

#[test]
fn envelope_burn_fixture_bytes_match() {
    let bytes = fixture_envelope_burn().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_envelope_burn_fixture` to create it",
    );
    assert_eq!(bytes, expected, "Burn Envelope JCS bytes changed — past signatures invalidated!");
}

#[test]
fn envelope_burn_jcs_shape_contains_burn_flag() {
    let bytes = fixture_envelope_burn().to_jcs_bytes().unwrap();
    let as_str = std::str::from_utf8(&bytes).expect("JCS output is valid UTF-8");
    assert!(as_str.starts_with(r#"{"burn_after_read":true,"#),
        "JCS must encode burn_after_read FIRST (alphabetic), got: {}", as_str);
}

#[test]
#[ignore]
fn regenerate_envelope_burn_fixture() {
    let bytes = fixture_envelope_burn().to_jcs_bytes().unwrap();
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
}
```

**Estimated fixture size:** ~140 bytes (envelope_jcs_generic_secret.bin shape + ~22 bytes for `"burn_after_read":true,`).

---

### `tests/pin_roundtrip.rs` (NEW — integration test, request-response under MockTransport)

**Analog:** `tests/phase2_self_round_trip.rs` (current Phase 7 signature with `MaterialVariant`).

**Template** (phase2_self_round_trip.rs:1-69) — copy verbatim, add PIN parameter, add `pin_required` invariant assertion:
```rust
use cipherpost::cli::MaterialVariant;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS};
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn pin_self_round_trip_recovers_plaintext() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);

    let plaintext = b"topsecret1".to_vec();
    let transport = MockTransport::new();
    let pin = SecretBox::new(Box::new("correct-horse-battery".to_string()));

    let uri_str = run_send(
        &id, &transport, &kp,
        SendMode::SelfMode, "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        Some(pin),       // <-- new param
        false,           // <-- new param: burn=false
    ).expect("run_send self-mode + pin");

    let uri = ShareUri::parse(&uri_str).unwrap();

    // PIN-08 (a): correct PIN — round-trip succeeds.
    let mut sink = OutputSink::InMemory(Vec::new());
    // ... run_receive with pin-aware prompter (TBD — Plan 02 prompter design) ...
    // ... assert sink contains plaintext ...
}
```

**Test-prompter PIN integration:** the existing `AutoConfirmPrompter` does not handle PIN prompts. Plan 02 adds `AutoConfirmPinPrompter` (or extends the test_helpers module) that returns the supplied PIN automatically. Closest analog: the AutoConfirmPrompter's role of "no TTY, return Ok(()) without rendering". Recommended: add `pub struct AutoPinSource(SecretBox<String>);` + a side-channel to `crate::pin::prompt_pin` for test mode (CIPHERPOST_TEST_PIN env var, mirroring CIPHERPOST_SKIP_TTY_CHECK at flow.rs:1118-1127).

**`#[serial]` invariant:** all PIN tests mutate `CIPHERPOST_HOME` → MUST carry `#[serial]`. CLAUDE.md load-bearing.

**PIN-08 matrix** — three test cases:
- (a) correct PIN → round-trip succeeds, plaintext recovered
- (b) wrong PIN → `Error::DecryptFailed`, exit 4, Display = "wrong passphrase or identity decryption failed"
- (c) no PIN supplied on a PIN-required share → `Error::DecryptFailed` (same Display)

---

### `tests/burn_roundtrip.rs` (NEW — integration test, two consecutive receives)

**Analog:** `tests/phase2_idempotent_re_receive.rs` (the only existing test that does TWO `run_receive` calls back-to-back on the same share).

**Template** (phase2_idempotent_re_receive.rs:14-98) — copy verbatim, replace `Ok(())` second-receive with `Err(Error::Declined)` + assert state="burned":
```rust
#[test]
#[serial]
fn burn_share_first_receive_succeeds_second_returns_exit_7() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    // ... identity setup (verbatim from idempotent_re_receive) ...

    let uri_str = run_send(
        &id, &transport, &kp,
        SendMode::SelfMode, "i",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,        // pin
        true,        // burn=true  <-- BURN-09
    ).unwrap();
    let uri = ShareUri::parse(&uri_str).unwrap();

    // First receive — succeeds.
    let mut sink1 = OutputSink::InMemory(Vec::new());
    run_receive(&id, &transport, &kp, &uri, &mut sink1, &AutoConfirmPrompter, false).unwrap();
    match sink1 {
        OutputSink::InMemory(buf) => assert_eq!(buf, plaintext),
        _ => panic!(),
    }

    // Ledger row must carry state=burned (BURN-09 assertion).
    let ledger_path = dir.path().join("state").join("accepted.jsonl");
    let ledger = std::fs::read_to_string(&ledger_path).unwrap();
    assert!(ledger.contains(r#""state":"burned""#),
        "burn ledger row must carry state=burned, got: {}", ledger);

    // Second receive — returns exit 7 (Error::Declined).
    let mut sink2 = OutputSink::InMemory(Vec::new());
    let err = run_receive(&id, &transport, &kp, &uri, &mut sink2, &AutoConfirmPrompter, false).unwrap_err();
    assert!(matches!(err, cipherpost::Error::Declined), "expected Declined (exit 7), got {:?}", err);

    // Receipt count = 1 (BURN-04: receipt published exactly once on first receive).
    // ... receipt count assertion via MockTransport ...
}
```

---

### `tests/pin_burn_compose.rs` (NEW — compose matrix)

**Analog:** `tests/phase2_self_round_trip.rs` × 4 typed-material variants × {pin, burn, pin+burn}.

**Pattern — parametric matrix.** Plan 05 task: enumerate ~12 cases (4 variants × 3 modes). Mirror Phase 7's `tests/pgp_roundtrip.rs` shape but with `pin` + `burn` as the orthogonal axes instead of `armor`. Per CONTEXT.md `<decisions>` Plan 05 list:
- pin alone (one per variant, 4 cases)
- burn alone (one per variant, 4 cases)
- pin + burn (one per variant, 4 cases)
- wrong-PIN-on-burn-share-doesn't-mark-burned (1 case)
- typed-z32-declined-on-burn-doesn't-mark-burned (1 case)
- second-receive-on-burned-share returns exit 7 (subsumed by `burn_roundtrip.rs`; included as verification)
- receipt-published-on-burn (BURN-04 explicit assertion, MockTransport receipt count == 1)

**Helper-prompter strategy** — a `DeclinePrompter` already exists (flow.rs:1063-1077) for the typed-z32-declined branch. Combine with PIN-correct test-prompter to verify: declined-z32 → no ledger touch → no `state: burned` row.

---

### `tests/pin_error_oracle.rs` (NEW — oracle hygiene)

**Analog:** `tests/x509_error_oracle.rs` (the EXPECTED_REASONS × FORBIDDEN_DISPLAY_TOKENS shape) + `tests/phase3_receipt_sign_verify.rs::assert_unified_d16_display` helper for sig-failure Display equality.

**Pattern** (x509_error_oracle.rs:1-71):
```rust
const EXPECTED_REASONS: &[&str] = &[
    "malformed DER", "trailing bytes after certificate",
    "PEM body decode failed", "PEM label is not CERTIFICATE",
    "accessor called on wrong variant",
];
const FORBIDDEN_DISPLAY_TOKENS: &[&str] = &[
    "X509Error", "parse error at", "nom::", /* ... */
];
```

**Apply for Phase 8** — assert wrong-PIN, wrong-passphrase, and tampered-ciphertext all produce identical `Error::DecryptFailed` Display:
```rust
#[test]
#[serial]
fn wrong_pin_display_matches_wrong_passphrase_display() {
    // Build a pin-required share; attempt receive with WRONG PIN.
    let err_wrong_pin = receive_with_wrong_pin(...).unwrap_err();
    let err_wrong_pw = receive_with_wrong_passphrase(...).unwrap_err();

    // Both must be Error::DecryptFailed (no PinIncorrect variant).
    assert!(matches!(err_wrong_pin, Error::DecryptFailed));
    assert!(matches!(err_wrong_pw, Error::DecryptFailed));

    // D-16 / PIN-07: identical Display string.
    assert_eq!(format!("{}", err_wrong_pin), format!("{}", err_wrong_pw));
    assert_eq!(format!("{}", err_wrong_pin), "wrong passphrase or identity decryption failed");

    // Exit code 4 in both cases.
    assert_eq!(exit_code(&err_wrong_pin), 4);
    assert_eq!(exit_code(&err_wrong_pw), 4);
}
```

**Per RESEARCH §"Note on CONTEXT.md ambiguity":** PIN-07's "identical Display to wrong-identity (PIN-07)" applies to wrong-passphrase (exit 4), NOT to sig-failures (exit 3). Test asserts the Display equality WITHOUT requiring exit-code equality.

---

### `tests/state_ledger.rs` (NEW — state-schema invariant)

**Analog:** `tests/outer_record_canonical_form.rs` (the structural shape — assert wire-format-with-default-deserialization) + the v1.0 ledger row read pattern in `flow.rs::check_already_accepted`.

**This file does NOT exist today** — CONTEXT.md says "extend tests/state_ledger.rs" but listing confirms it's a new file.

**Pattern — assert v1.0 rows (no `state` field) deserialize to LedgerState::Accepted:**
```rust
use cipherpost::flow::{check_already_consumed, LedgerState};
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn v1_0_ledger_row_without_state_field_deserializes_as_accepted() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());

    // Hand-craft a v1.0 ledger row (no `state` field) — what existing on-disk
    // ledgers contain after Phase 7.
    let v1_row = r#"{"accepted_at":"2026-04-25T13:11:42Z","ciphertext_hash":"abc","cleartext_hash":"def","purpose":"k","sender":"pk-placeholder","share_ref":"0123456789abcdef0123456789abcdef"}"#;
    let state_dir = dir.path().join("state");
    std::fs::create_dir_all(state_dir.join("accepted")).unwrap();
    std::fs::write(state_dir.join("accepted.jsonl"), format!("{}\n", v1_row)).unwrap();
    // Touch sentinel so check_already_consumed walks the ledger.
    std::fs::write(state_dir.join("accepted").join("0123456789abcdef0123456789abcdef"), "").unwrap();

    let state = check_already_consumed("0123456789abcdef0123456789abcdef");
    match state {
        LedgerState::Accepted { .. } => { /* ok */ }
        _ => panic!("v1.0 row (no state field) must deserialize to Accepted, got {:?}", state),
    }
}

#[test]
#[serial]
fn burned_row_deserializes_as_burned() {
    // Mirror above with `"state":"burned"` field; assert LedgerState::Burned.
}
```

---

## Shared Patterns

### HKDF info enumeration test (auto-detection)

**Source:** `tests/hkdf_info_enumeration.rs` — grep-based source walker; auto-discovers any string literal matching `cipherpost/v1/<context>` in `src/`.

**Apply to:** Plan 01. Adding `pub const PIN: &str = "cipherpost/v1/pin";` to `crypto.rs::hkdf_infos` is sufficient — NO test code changes. The walker (lines 49-72) finds the literal via `src.split('"').step_by(2)` and the assertion logic (lines 21-44) checks distinctness + non-empty + prefix.

### D-16 unified Display for credential failures

**Source:** Three distributed enforcement points (per RESEARCH §"Error-oracle Display equality"):
1. `src/error.rs:27-37` — `#[error("signature verification failed")]` literal on all Signature* variants.
2. `src/record.rs:224` — inline assertion `assert_eq!(format!("{}", err), "signature verification failed");`.
3. `tests/phase3_receipt_sign_verify.rs:64-71` — `assert_unified_d16_display(err)` helper.

**Apply to:** Plan 02 (PIN ship-gate). Extend the discipline to wrong-PIN ≡ wrong-passphrase, all funnel through `Error::DecryptFailed` (Display: "wrong passphrase or identity decryption failed", exit 4). New `tests/pin_error_oracle.rs` mirrors the assertion shape.

### Wire-budget retry for nested-age overhead

**Source:** `flow.rs::WIRE_BUDGET_RETRY_ATTEMPTS = 20` (flow.rs:58) — covers age's grease-stanza variance (0..=265 random bytes per layer).

**Apply to:** PIN-required shares have TWO age layers — grease appears twice. RESEARCH §"age 0.11.2 — Encryptor::with_recipients" predicts ~165 bytes/layer + variance. The existing 20-retry budget covers grease re-sampling per Plan 01 design.

### `serial_test = "3"` + `#[serial]` on env-mutating tests

**Source:** Every test in `tests/phase2_*.rs` and `tests/x509_roundtrip.rs` that calls `std::env::set_var("CIPHERPOST_HOME", ...)` carries `#[serial]`. Nextest's parallel runner races without it (CLAUDE.md load-bearing).

**Apply to:** ALL Phase 8 round-trip tests (`tests/pin_roundtrip.rs`, `tests/burn_roundtrip.rs`, `tests/pin_burn_compose.rs`, `tests/state_ledger.rs`, `tests/pin_error_oracle.rs`). Pure ingest tests need NO `#[serial]` — but every Phase 8 test touches the ledger or identity, so all need it.

### Manual Debug redaction (Pitfall #7)

**Source:** `payload/mod.rs::Material` (payload/mod.rs:92-100) — manual `impl Debug` that emits `[REDACTED N bytes]` for byte-carrying variants. `Identity` struct uses `Zeroizing` everywhere.

**Apply to:** Any new struct in `src/pin.rs` that holds the PIN, salt, or derived 32-byte scalar. Recommended: use `Zeroizing<[u8; 32]>` directly (no struct). If a struct is unavoidable, write a manual `impl Debug` per the `Material` template — NEVER `#[derive(Debug)]`.

### JCS fixture regen pattern (`#[ignore]` helper)

**Source:** `tests/outer_record_canonical_form.rs:38-44` + every `tests/material_*_envelope_round_trip.rs` test.

**Apply to:** Both new fixtures (`outer_record_pin_required_signable.bin` + `envelope_burn_signable.bin`). Run `cargo test -- --ignored regenerate_<name>_fixture`; commit the resulting `.bin`. Byte-match assertion in non-ignored sibling test is the gate.

---

## No Analog Found

| File / Pattern | Reason | Mitigation |
|----------------|--------|------------|
| `is_false` serde helper free function | No bool-with-skip-serializing-if field exists in v1.0 (only `Option::is_none` patterns) | Trivial 3-line function; no risk |
| `LedgerState` enum (3 variants) | v1.0 returns `Option<String>` from `check_already_accepted`; no enum precedent for state schema | Plan 03 introduces; structural — not load-bearing on a fragile pattern |
| Test-mode PIN injection (CIPHERPOST_TEST_PIN env var or AutoConfirmPinPrompter) | v1.0 has no PIN; the existing `AutoConfirmPrompter` doesn't handle PIN | Mirror flow.rs:1115-1127's `tty_check_skipped()` cfg-gated env-var pattern |
| Burn-share state migration test | v1.0 ledger has no schema migration history | New `tests/state_ledger.rs` is the first — `outer_record_canonical_form.rs` is the structural template |

Every other file maps onto an exact in-tree analog.

---

## Architectural Decisions Surfaced

These are places where the existing patterns do not uniquely determine the approach; the planner picks.

### AD-1 — `src/pin.rs` new file vs extension to `src/crypto.rs`

**Question:** Does PIN crypto live in a new `src/pin.rs` file or as a sub-module/extension inside `src/crypto.rs`?

**Existing evidence:** `src/preview.rs` (Phase 6) and `src/payload/ingest.rs` (Phase 6 — submodule of `payload`) both set new-file precedents. `src/crypto.rs` is already 800+ lines; adding ~150 lines of PIN code grows it further.

**Planner recommendation:** New `src/pin.rs` file. Aligns with the new-module precedent (`preview.rs`); keeps `crypto.rs` focused on identity-KEK + age + Ed25519↔X25519. PIN-specific helpers (`validate_pin`, `prompt_pin`, `pin_argon2_params`) cluster naturally in one file. The HKDF info constant stays in `crypto::hkdf_infos` (registry boundary).

### AD-2 — `is_false` helper file scope

**Question:** Does `is_false` live in `src/record.rs` (only OuterRecord uses it), in `src/payload/mod.rs` (only Envelope uses it), in BOTH, or hoisted to `src/lib.rs` as `pub(crate)`?

**Existing evidence:** No precedent — first cross-module helper of this kind. `src/lib.rs` already holds crate-scope constants (`PROTOCOL_VERSION`, `HKDF_INFO_PREFIX`).

**Planner recommendation:** Hoist to `src/lib.rs` as `pub(crate) fn is_false(b: &bool) -> bool { !*b }`. Both `record.rs` and `payload/mod.rs` `use crate::is_false;`. Avoids duplication; documents the crate-wide invariant in one place.

### AD-3 — `LedgerState` enum location

**Question:** New `src/state.rs` module OR keep inside `src/flow.rs`?

**Existing evidence:** All ledger code (sentinel_path, ledger_path, append_ledger_entry, check_already_accepted) lives in `flow.rs`. No `src/state.rs` exists.

**Planner recommendation:** Keep inside `src/flow.rs`. Coupled to ledger I/O which already lives here. A new `src/state.rs` for one enum + one rename is premature decomposition. Revisit if Phase 9 / 10 adds more state-machine surface.

### AD-4 — Salt RNG source

**Question:** `rand::thread_rng().fill_bytes()` (popular but `rand` crate not yet in Cargo.toml per RESEARCH §"Standard Stack") OR `getrandom::getrandom()` (transitive via `argon2`)?

**Existing evidence:** Verify at Plan 01 via `cargo tree | grep -E "^rand|^getrandom"`. RESEARCH does not list `rand` as already-pulled.

**Planner recommendation:** `getrandom = "0.2"` (likely already transitive via `argon2`). Cleaner supply chain, no new direct dep. If `rand` IS already pulled (planner verifies), use `rand::thread_rng()` for ergonomics.

### AD-5 — Test-mode PIN injection mechanism

**Question:** Cfg-gated env var (CIPHERPOST_TEST_PIN, mirroring `CIPHERPOST_SKIP_TTY_CHECK` at flow.rs:1118-1127) OR a new `AutoConfirmPinPrompter` injected via constructor?

**Existing evidence:** Existing `AutoConfirmPrompter` (flow.rs:1041-1058) is a no-op trait impl — doesn't fit a stateful PIN. The CIPHERPOST_SKIP_TTY_CHECK pattern (cfg-gated, env-var-driven) DOES fit "test-mode credential override".

**Planner recommendation:** Cfg-gated env var `CIPHERPOST_TEST_PIN`. Mirrors the existing test-shim pattern; no Prompter trait redesign. Production builds (no `mock` feature, no `cfg(test)`) cannot honor the override — same belt-and-suspenders as `tty_check_skipped()`.

---

## Metadata

**Analog search scope:** `src/`, `tests/`, `tests/fixtures/`, `Cargo.toml`, `.planning/phases/06-typed-material-x509cert/`, `.planning/phases/07-typed-material-pgpkey-sshkey/`, `cclink/src/{commands,crypto}/`

**Files scanned:** 12 source files (cipherpost) + 23 test files + 14 fixture files + 2 Phase 6/7 PATTERNS.md + 4 cclink reference files

**Pattern extraction date:** 2026-04-25

**Phase 8 ship-gate template** (per D-P8-13): "PIN crypto core → PIN ship-gate (fixture + JCS byte-identity + roundtrip + oracle hygiene + SPEC) → BURN core → BURN ship-gate (fixture + roundtrip + PITFALLS resolution) → Compose matrix → Docs consolidation". Matches Phase 6's 4-plan template applied twice + 2 integration plans.

## PATTERN MAPPING COMPLETE
