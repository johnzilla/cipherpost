# Phase 3: Signed receipt — the cipherpost delta - Pattern Map

**Mapped:** 2026-04-21
**Files analyzed:** 11 (6 src + 5 tests)
**Analogs found:** 11 / 11 (all in-tree; no greenfield modules)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `src/receipt.rs` (REPLACE body) | wire-format module | transform (struct-pair sign/verify) | `src/record.rs` | exact (explicit D-RS-01 mirror) |
| `src/transport.rs::DhtTransport::publish_receipt` (BODY) | transport impl | request-response (DHT publish w/ merge) | `src/transport.rs::DhtTransport::publish` + `::resolve` | exact (same crate, same trait, upgrades existing stub) |
| `src/transport.rs::MockTransport::publish_receipt` (confirm only) | transport impl | CRUD append | `src/transport.rs::MockTransport::publish_receipt` (already correct) | same-function (D-MRG-05: test-only, no body change) |
| `src/transport.rs` — new `Transport::resolve_all_cprcpt` trait method | transport trait | streaming (multi-record fetch) | `Transport::resolve` + `MockTransport::resolve_all_txt` | role-match (adds 4th trait method; follows existing shape) |
| `src/flow.rs::run_receive` (+ step 13) | orchestration | request-response (multi-step pipeline) | `src/flow.rs::run_receive` (Phase 2) | same-function (Phase 2 extension) |
| `src/flow.rs::LedgerEntry` (+ `receipt_published_at`) | state model | CRUD | `src/flow.rs::LedgerEntry` | same-struct (1-field extension) |
| `src/flow.rs::append_ledger_entry` (2-row update) | state writer | CRUD append | `src/flow.rs::append_ledger_entry` (Phase 2) | same-function |
| `src/flow.rs::run_receipts` (NEW) | orchestration | streaming (fetch → verify → render) | `src/flow.rs::run_send` / `run_receive` (signature shape) | role-match (new function, established pattern) |
| `src/main.rs::dispatch::Receipts` (REPLACE stub) | CLI dispatcher | request-response | `src/main.rs::dispatch::Receive` | role-match (but no Identity — D-OUT-04) |
| `src/main.rs::dispatch::Receive` (pass keypair) | CLI dispatcher | request-response | `src/main.rs::dispatch::Send` (already reconstructs kp from seed) | exact (3-line idiom lift) |
| `src/cli.rs::Command::Receipts` (add `--json: bool`) | CLI schema | config | existing `Receipts { from, share_ref }` | same-enum (1-field extension) |
| `tests/phase3_receipt_sign_verify.rs` (NEW) | unit test | transform | `src/record.rs::tests::sign_verify_round_trip` + `tampered_blob_fails_verify` | exact (mirror test set) |
| `tests/phase3_receipt_canonical_form.rs` (NEW) | unit test | transform | `tests/outer_record_canonical_form.rs` | exact (mirror fixture test) |
| `tests/fixtures/receipt_signable.bin` (NEW) | test fixture | binary asset | `tests/fixtures/outer_record_signable.bin` | exact |
| `tests/phase3_end_to_end_a_sends_b_receipt.rs` (NEW) | integration test | event-driven (round trip) | `tests/phase2_share_round_trip.rs` | exact (two-identity pattern) |
| `tests/phase3_coexistence_b_self_share_and_receipt.rs` (NEW) | integration test | CRUD (multi-label coexistence) | `tests/mock_transport_roundtrip.rs::mock_publish_receipt_stores_under_cprcpt_label` + `phase2_self_round_trip.rs` | role-match (extends with multi-label assertions) |
| `tests/phase3_share_ref_filter.rs` (NEW) | integration test | request-response (filter) | `tests/phase2_share_round_trip.rs` | role-match |

## Pattern Assignments

### `src/receipt.rs` (wire-format module, transform) — REPLACE body

**Analog:** `src/record.rs` (D-RS-01 locked-in mirror; the decisions document the file as "mirroring `OuterRecord` / `OuterRecordSignable` exactly").

**Imports pattern** (copy from `src/record.rs:14-19`, drop `sha2` since receipts carry precomputed hashes, add `rand`):

```rust
use crate::error::Error;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
// NOTE: do NOT import serde_canonical_json::CanonicalFormatter locally —
// call crate::crypto::jcs_serialize per State-of-the-Art note in RESEARCH §"State of the Art".
```

**Struct-pair pattern** (`src/record.rs:24-64`) — exact shape to mirror:

```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OuterRecord {
    pub blob: String,
    pub created_at: i64,
    pub protocol_version: u16,
    pub pubkey: String,
    pub recipient: Option<String>,
    pub share_ref: String,
    pub signature: String,        // alphabetical insertion after share_ref
    pub ttl_seconds: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OuterRecordSignable {
    pub blob: String,
    pub created_at: i64,
    pub protocol_version: u16,
    pub pubkey: String,
    pub recipient: Option<String>,
    pub share_ref: String,
    pub ttl_seconds: u64,
}

impl From<&OuterRecord> for OuterRecordSignable {
    fn from(r: &OuterRecord) -> Self {
        OuterRecordSignable {
            blob: r.blob.clone(),
            created_at: r.created_at,
            protocol_version: r.protocol_version,
            pubkey: r.pubkey.clone(),
            recipient: r.recipient.clone(),
            share_ref: r.share_ref.clone(),
            ttl_seconds: r.ttl_seconds,
        }
    }
}
```

For `Receipt` / `ReceiptSignable`, swap the field set per D-RS-01 (9 alphabetical fields: `accepted_at: i64`, `ciphertext_hash: String`, `cleartext_hash: String`, `nonce: String`, `protocol_version: u16`, `purpose: String`, `recipient_pubkey: String`, `sender_pubkey: String`, `share_ref: String`; `Receipt` adds `signature: String` after `share_ref`). The derive set is identical.

**Sign pattern** (`src/record.rs:96-104`) — mirror verbatim, but call `crypto::jcs_serialize` instead of the local `jcs()` helper (RESEARCH §"State of the Art" drops the local copy):

```rust
pub fn sign_record(
    signable: &OuterRecordSignable,
    keypair: &pkarr::Keypair,
) -> Result<String, Error> {
    let bytes = jcs(signable)?;
    // pkarr::Keypair::sign delegates to ed25519_dalek::SigningKey::sign
    let sig = keypair.sign(&bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}
```

For `sign_receipt`: signature `(&ReceiptSignable, &pkarr::Keypair) -> Result<String, Error>`; body replaces `jcs(signable)?` with `crate::crypto::jcs_serialize(signable)?`.

**Verify pattern** (`src/record.rs:115-146`) — mirror exactly, including the 5-step comment block and the round-trip-reserialize guard:

```rust
pub fn verify_record(record: &OuterRecord) -> Result<(), Error> {
    // 1. Parse pubkey from z-base-32 → VerifyingKey
    let pk = pkarr::PublicKey::try_from(record.pubkey.as_str())
        .map_err(|_| Error::SignatureInner)?;
    let vk = VerifyingKey::from_bytes(pk.as_bytes())
        .map_err(|_| Error::SignatureInner)?;

    // 2. Decode signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&record.signature)
        .map_err(|_| Error::SignatureInner)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| Error::SignatureInner)?;

    // 3. Build signable, JCS-serialize
    let signable = OuterRecordSignable::from(record);
    let bytes = jcs(&signable)?;

    // 4. Verify strict (no legacy relaxed Ed25519 behaviour)
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| Error::SignatureInner)?;

    // 5. Re-canonicalize — protects against the parse-then-reserialize mauling
    //    attack class. If round-trip bytes differ from what was signed, reject.
    let parsed: OuterRecordSignable =
        serde_json::from_slice(&bytes).map_err(|_| Error::SignatureCanonicalMismatch)?;
    let round = jcs(&parsed)?;
    if round != bytes {
        return Err(Error::SignatureCanonicalMismatch);
    }

    Ok(())
}
```

For `verify_receipt`: identical structure. Parse `recipient_pubkey` instead of `pubkey` (receipts are signed by the recipient). Use `ReceiptSignable::from(receipt)` at step 3. Route `jcs` calls through `crate::crypto::jcs_serialize`. All error returns stay on the existing `Error::SignatureInner` / `Error::SignatureCanonicalMismatch` variants (D-RS-07 explicitly rejects a new `Error::SignatureReceipt`).

**Unit-test pattern** (`src/record.rs:148-224`) — the existing `#[cfg(test)] mod tests` block has three tests that Phase 3 duplicates in `tests/phase3_receipt_sign_verify.rs`:
- `sign_verify_round_trip` (lines 169-194) — seeded keypair, build signable, sign, assemble Receipt, verify.
- `tampered_blob_fails_verify` (lines 196-224) — mutate a field in Receipt after signing, assert `Err(Error::SignatureInner)` and `format!("{}", err) == "signature verification failed"` (D-16 unification check).

**Nonce helper pattern** (new; no analog — D-RS-03 + RESEARCH §"Example 1"):

```rust
pub fn nonce_hex() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    out
}
```

Shape echoes `record::share_ref_from_bytes` (`src/record.rs:68-79`) — 32-char lowercase hex encoder.

---

### `src/transport.rs::DhtTransport::publish_receipt` (transport impl, request-response) — REPLACE body

**Analog:** `src/transport.rs::DhtTransport::publish` (lines 88-107) for the publish half; `src/transport.rs::DhtTransport::resolve` (lines 109-126) for the resolve half. D-MRG-01 locks the "resolve → rebuild builder → re-sign" strategy; RESEARCH §"Example 2" supplies the exact merged body.

**Resolve-half pattern** (`src/transport.rs:109-116`):

```rust
fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error> {
    eprintln!("Resolving from DHT..."); // TRANS-05
    let pk = pkarr::PublicKey::try_from(pubkey_z32).map_err(|_| Error::NotFound)?;
    let packet = self
        .client
        .resolve_most_recent(&pk)
        .ok_or(Error::NotFound)?;
    ...
}
```

Key reuse: `client.resolve_most_recent(&pk)` is the fresh-resolve path (not cache-fast `resolve`; Pitfall #5 in RESEARCH). `publish_receipt` uses `keypair.public_key()` (not a user-provided z32) as the resolve target.

**Publish-half pattern** (`src/transport.rs:88-107`):

```rust
fn publish(&self, keypair: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error> {
    eprintln!("Publishing to DHT..."); // TRANS-05
    let rdata = serde_json::to_string(record)
        .map_err(|e| Error::Transport(Box::new(e)))?;
    let name: pkarr::dns::Name<'_> = DHT_LABEL_OUTER
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;
    let txt: pkarr::dns::rdata::TXT<'_> = rdata
        .as_str()
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;
    let packet = pkarr::SignedPacket::builder()
        .txt(name, txt, 300)
        .sign(keypair)
        .map_err(|e| Error::Transport(Box::new(e)))?;
    self.client
        .publish(&packet, None)
        .map_err(map_pkarr_publish_error)?;
    Ok(())
}
```

Key reuses (D-MRG-03 + D-MRG-06): TTL = `300` (matches `:100` and `:146` — single-constant convention); `map_dns_err` (existing at `:188`) and `map_pkarr_publish_error` (existing at `:179`) are the error-mapping helpers.

**Wire-budget pattern** (`src/flow.rs::check_wire_budget` lines 347-388) — D-MRG-06 surfaces `Error::WireBudgetExceeded { encoded, budget, plaintext: 0 }` (plaintext=0 indicates receipt, not share) if signing fails with `PacketTooLarge`:

```rust
let packet = match pkarr::SignedPacket::builder()
    .txt(name, txt, 300)
    .sign(keypair)
{
    Ok(p) => p,
    Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) => {
        return Err(Error::WireBudgetExceeded {
            encoded,
            budget: WIRE_BUDGET_BYTES,
            plaintext: plaintext_len,
        });
    }
    Err(other) => return Err(Error::Transport(Box::new(other))),
};
```

`WIRE_BUDGET_BYTES` is `pub const` at `src/flow.rs:39` (already public, importable as `crate::flow::WIRE_BUDGET_BYTES`).

**Resolve-merge-republish new body pattern** (RESEARCH §"Example 2"; API verified against pkarr 5.0.4 source):

```rust
fn publish_receipt(
    &self,
    keypair: &pkarr::Keypair,
    share_ref_hex: &str,
    receipt_json: &str,
) -> Result<(), Error> {
    eprintln!("Publishing receipt to DHT..."); // TRANS-05

    let receipt_label = format!("{}{}", crate::DHT_LABEL_RECEIPT_PREFIX, share_ref_hex);
    let new_name: pkarr::dns::Name<'_> = receipt_label
        .as_str()
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;
    let new_txt: pkarr::dns::rdata::TXT<'_> = receipt_json
        .try_into()
        .map_err(|e| Error::Transport(map_dns_err(e)))?;

    // 1. Resolve most recent — may be None if recipient has never published.
    let pk = keypair.public_key();
    let existing = self.client.resolve_most_recent(&pk);

    // 2. Rebuild builder from existing records, replacing same-label entries.
    let mut builder = pkarr::SignedPacket::builder();
    let mut cas: Option<pkarr::Timestamp> = None;
    if let Some(ref packet) = existing {
        cas = Some(packet.timestamp());
        for rr in packet.all_resource_records() {
            let rr_name = rr.name.to_string();
            if matches_receipt_label(&rr_name, &receipt_label, &pk.to_z32()) {
                continue;
            }
            builder = builder.record(rr.clone());
        }
    }
    builder = builder.txt(new_name, new_txt, 300);

    // 3. Sign (D-MRG-06: PacketTooLarge → WireBudgetExceeded with plaintext=0)
    let packet = match builder.sign(keypair) {
        Ok(p) => p,
        Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) => {
            return Err(Error::WireBudgetExceeded {
                encoded,
                budget: crate::flow::WIRE_BUDGET_BYTES,
                plaintext: 0,
            });
        }
        Err(other) => return Err(Error::Transport(Box::new(other))),
    };

    // 4. Publish with optional CAS (D-MRG-02: no retry in skeleton).
    self.client
        .publish(&packet, cas)
        .map_err(map_pkarr_publish_error)?;
    Ok(())
}

fn matches_receipt_label(rr_name: &str, receipt_label: &str, origin_z32: &str) -> bool {
    let trimmed = rr_name.trim_end_matches('.');
    trimmed == format!("{}.{}", receipt_label, origin_z32)
        || trimmed == receipt_label
}
```

**Anti-pattern to avoid** (verified by reading the current `publish_receipt` body at `src/transport.rs:128-153`): the current body builds a SignedPacket containing only the new receipt TXT and publishes — this clobbers any other labels under the key (notably the recipient's own outgoing `_cipherpost` share, breaking ROADMAP SC3). The resolve-merge-republish loop is the fix.

---

### `src/transport.rs::MockTransport::publish_receipt` (D-MRG-05: no body change)

**Analog:** `src/transport.rs::MockTransport::publish_receipt` (lines 271-288) — already correct.

Existing body (append-preserving per-share_ref via `retain(|(l, _)| l != &label)` then `push`):

```rust
fn publish_receipt(
    &self,
    kp: &pkarr::Keypair,
    share_ref_hex: &str,
    receipt_json: &str,
) -> Result<(), Error> {
    let z32 = kp.public_key().to_z32();
    let label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex);
    let mut store = self.store.lock().unwrap();
    let entry = store.entry(z32).or_default();
    entry.retain(|(l, _)| l != &label);
    entry.push((label, receipt_json.to_string()));
    Ok(())
}
```

Per D-MRG-05 the gap is in `DhtTransport`, not `MockTransport`. Phase 3 adds a confirming integration test (`tests/phase3_coexistence_b_self_share_and_receipt.rs`) but no code change.

---

### `src/transport.rs` — NEW `Transport::resolve_all_cprcpt` trait method

**Analog:** the existing `Transport::resolve` signature (line 40) defines the trait-method shape; `MockTransport::resolve_all_txt` (line 226) already implements the underlying data-surface for the mock.

**Existing trait** (`src/transport.rs:32-54`):

```rust
pub trait Transport {
    fn publish(&self, keypair: &pkarr::Keypair, record: &OuterRecord) -> Result<(), Error>;
    fn resolve(&self, pubkey_z32: &str) -> Result<OuterRecord, Error>;
    fn publish_receipt(
        &self,
        keypair: &pkarr::Keypair,
        share_ref_hex: &str,
        receipt_json: &str,
    ) -> Result<(), Error>;
}
```

**Add** (per RESEARCH §"Open Questions" #1 recommendation):

```rust
/// Resolve all receipt TXT records (label prefix `_cprcpt-`) under the given pubkey.
/// Returns the raw JSON bodies in insertion/resolve order. MockTransport filters
/// its in-memory store by label prefix; DhtTransport calls `resolve_most_recent`
/// and iterates `all_resource_records()` with a `starts_with(DHT_LABEL_RECEIPT_PREFIX)`
/// filter.
fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error>;
```

**MockTransport impl** — wraps existing `resolve_all_txt` (at `:226-232`):

```rust
fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error> {
    let entries = self.resolve_all_txt(pubkey_z32);
    if entries.is_empty() {
        return Err(Error::NotFound);
    }
    Ok(entries
        .into_iter()
        .filter(|(label, _)| label.starts_with(crate::DHT_LABEL_RECEIPT_PREFIX))
        .map(|(_, json)| json)
        .collect())
}
```

**DhtTransport impl** — mirrors `resolve()`'s pattern (`:109-126`):

```rust
fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error> {
    eprintln!("Resolving receipts from DHT..."); // TRANS-05
    let pk = pkarr::PublicKey::try_from(pubkey_z32).map_err(|_| Error::NotFound)?;
    let packet = self.client.resolve_most_recent(&pk).ok_or(Error::NotFound)?;
    let mut out = Vec::new();
    for rr in packet.all_resource_records() {
        let name = rr.name.to_string();
        let trimmed = name.trim_end_matches('.');
        // After pkarr normalization, labels are either bare "<label>" or
        // "<label>.<origin-z32>". Both start with the bare label.
        if trimmed.starts_with(crate::DHT_LABEL_RECEIPT_PREFIX) {
            if let Some(json) = extract_txt_string(&rr.rdata) {
                out.push(json);
            }
        }
    }
    Ok(out)
}
```

`extract_txt_string` already exists at `src/transport.rs:163-170` and is reusable as-is.

---

### `src/flow.rs::run_receive` — EXTEND with step 13 + keypair param

**Analog:** existing `src/flow.rs::run_receive` (lines 398-479) — Phase 2 12-step body. D-SEQ-01 appends step 13 after step 12; D-SEQ-07 grows the signature to accept `&pkarr::Keypair`.

**Existing signature** (`src/flow.rs:398-404`):

```rust
pub fn run_receive(
    identity: &Identity,
    transport: &dyn Transport,
    uri: &ShareUri,
    output: &mut OutputSink,
    prompter: &dyn Prompter,
) -> Result<(), Error> {
```

**Extended signature** (D-SEQ-07):

```rust
pub fn run_receive(
    identity: &Identity,
    transport: &dyn Transport,
    keypair: &pkarr::Keypair,         // NEW — recipient's keypair for publish_receipt
    uri: &ShareUri,
    output: &mut OutputSink,
    prompter: &dyn Prompter,
) -> Result<(), Error> {
```

**Existing step-12 pattern** (lines 468-476) — keep verbatim:

```rust
// STEP 12: sentinel FIRST, ledger SECOND (crash-safe; see fn-doc rationale).
create_sentinel(&record.share_ref)?;
append_ledger_entry(
    &record.share_ref,
    &record.pubkey,
    &envelope.purpose,
    &ciphertext,
    &jcs_plain,
)?;
```

**NEW step-13 pattern** (D-SEQ-01 + D-SEQ-02 warn+degrade):

```rust
// STEP 13: publish_receipt — best-effort. D-SEQ-02: warn+degrade on failure,
// do NOT propagate via `?`. Ledger `receipt_published_at` is set to
// Some(ISO-8601-UTC) on success or stays None on failure; D-SEQ-05 appends
// a new ledger line rather than rewriting (check_already_accepted last-wins).
use sha2::{Digest, Sha256};
let ciphertext_hash = format!("{:x}", Sha256::digest(&ciphertext));
let cleartext_hash = format!("{:x}", Sha256::digest(&jcs_plain));
let accepted_at_unix = now_unix_seconds()?;
let signable = crate::receipt::ReceiptSignable {
    accepted_at: accepted_at_unix,
    ciphertext_hash: ciphertext_hash.clone(),
    cleartext_hash: cleartext_hash.clone(),
    nonce: crate::receipt::nonce_hex(),
    protocol_version: PROTOCOL_VERSION,
    purpose: envelope.purpose.clone(),
    recipient_pubkey: keypair.public_key().to_z32(),
    sender_pubkey: record.pubkey.clone(),
    share_ref: record.share_ref.clone(),
};
let signature = crate::receipt::sign_receipt(&signable, keypair)?;
let receipt = crate::receipt::Receipt { /* all signable fields + signature */ };
let receipt_json = serde_json::to_string(&receipt)
    .map_err(|e| Error::Config(format!("receipt encode: {}", e)))?;
match transport.publish_receipt(keypair, &record.share_ref, &receipt_json) {
    Ok(()) => {
        // D-SEQ-05: append a new ledger line with receipt_published_at set.
        let _ = append_ledger_entry_with_receipt(
            &record.share_ref,
            &record.pubkey,
            &envelope.purpose,
            &ciphertext,
            &jcs_plain,
            Some(&iso8601_utc_now()?),
        );
    }
    Err(e) => {
        eprintln!("receipt publish failed: {}", crate::error::user_message(&e));
        // fall through — exit 0 (D-SEQ-02)
    }
}
Ok(())
```

**Pitfall #4 guard** (from RESEARCH): do NOT call `Sha256::digest` inside `receipt.rs`; pass the existing hashes through. The Phase 2 `append_ledger_entry` (lines 543-578) already computes `sha256(ciphertext)` and `sha256(jcs_plain)` — Phase 3 sources them from here, at the same step.

---

### `src/flow.rs::LedgerEntry` (struct, CRUD) — ADD `receipt_published_at` field

**Analog:** existing `LedgerEntry` at `src/flow.rs:533-541` (private serde struct with 6 `&'a str` / `String` fields).

**Existing struct**:

```rust
#[derive(serde::Serialize)]
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    sender: &'a str,
    share_ref: &'a str,
}
```

**Extended struct** (D-SEQ-04 — alphabetical insertion between `purpose` and `sender`):

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

`#[serde(skip_serializing_if = "Option::is_none")]` keeps the on-disk format quiet for failed-publish rows (matches D-SEQ-04's "backwards-compatible: old Phase 2 ledger lines without the field parse cleanly via `Option`").

---

### `src/flow.rs::append_ledger_entry` (writer, CRUD append) — EXTEND signature for 2-row update

**Analog:** existing `append_ledger_entry` (lines 543-578). D-SEQ-05 appends a second row with `receipt_published_at = Some(ISO-8601-UTC)` after a successful publish.

**Existing body** (verbatim — Phase 3 should keep this path unchanged for the step-12 first-write):

```rust
fn append_ledger_entry(
    share_ref: &str,
    sender_z32: &str,
    purpose: &str,
    ciphertext: &[u8],
    jcs_plain: &[u8],
) -> Result<(), Error> {
    ensure_state_dirs()?;
    use sha2::{Digest, Sha256};
    let ch = format!("{:x}", Sha256::digest(ciphertext));
    let ph = format!("{:x}", Sha256::digest(jcs_plain));
    let accepted_at = iso8601_utc_now()?;
    let entry = LedgerEntry {
        accepted_at: &accepted_at,
        ciphertext_hash: ch,
        cleartext_hash: ph,
        purpose,
        sender: sender_z32,
        share_ref,
    };
    let mut line = crypto::jcs_serialize(&entry)?;
    line.push(b'\n');
    let path = ledger_path();
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .map_err(Error::Io)?;
    f.write_all(&line).map_err(Error::Io)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
    Ok(())
}
```

**New helper** `append_ledger_entry_with_receipt` — mirrors the existing body, sets `receipt_published_at: Some(&iso)`:

```rust
fn append_ledger_entry_with_receipt(
    share_ref: &str,
    sender_z32: &str,
    purpose: &str,
    ciphertext: &[u8],
    jcs_plain: &[u8],
    receipt_published_at: Option<&str>,
) -> Result<(), Error> {
    // ...same body as append_ledger_entry, but the LedgerEntry literal sets
    // receipt_published_at: receipt_published_at  instead of omitting.
}
```

The alternative planner-discretion path (D-SEQ-05: "planner may propose rewrite if crash-safety can be preserved via atomic rename") is **not recommended** — the strong default is append-only per "Specifics".

**`check_already_accepted` compatibility** (lines 125-147) is already linear-scan with last-match-wins semantics — 2 rows per share is handled transparently.

---

### `src/flow.rs::run_receipts` (NEW function, streaming) — fetch → verify → render

**Analog:** `run_send` (lines 220-337) and `run_receive` (lines 398-479) define the flow-function signature shape; RESEARCH §"Example 3" supplies the full body.

**Signature** (D-OUT-04 — no Identity param):

```rust
pub fn run_receipts(
    transport: &dyn Transport,
    from_z32: &str,
    share_ref_filter: Option<&str>,
    json_mode: bool,
) -> Result<(), Error> {
    // 1. Fetch candidates
    let candidate_receipts = transport.resolve_all_cprcpt(from_z32)?;
    if candidate_receipts.is_empty() {
        return Err(Error::NotFound); // exit 5 (D-OUT-03)
    }
    // 2. Parse + verify — D-OUT-03 exit-code taxonomy
    let mut valid: Vec<crate::receipt::Receipt> = Vec::new();
    let mut malformed = 0usize;
    let mut invalid_sig = 0usize;
    for raw_json in &candidate_receipts {
        let parsed: crate::receipt::Receipt = match serde_json::from_str(raw_json) {
            Ok(r) => r,
            Err(_) => { malformed += 1; continue; }
        };
        if crate::receipt::verify_receipt(&parsed).is_err() {
            invalid_sig += 1;
            continue;
        }
        valid.push(parsed);
    }
    // 3. Summary on stderr (CLI-01)
    eprintln!(
        "fetched {} receipt(s); {} valid{}{}",
        candidate_receipts.len(),
        valid.len(),
        if malformed > 0 { format!(", {} malformed", malformed) } else { String::new() },
        if invalid_sig > 0 { format!(", {} invalid-signature", invalid_sig) } else { String::new() },
    );
    // 4. D-OUT-02: filter AFTER verify (Pitfall #6)
    if let Some(filter) = share_ref_filter {
        valid.retain(|r| r.share_ref == filter);
    }
    // 5. Exit-code taxonomy
    if valid.is_empty() {
        if invalid_sig > 0 {
            return Err(Error::SignatureInner); // exit 3
        }
        if malformed > 0 {
            return Err(Error::Config("all receipts malformed".into())); // exit 1
        }
        return Err(Error::NotFound); // exit 5
    }
    // 6. Render (stdout)
    if json_mode {
        let out = serde_json::to_string_pretty(&valid)
            .map_err(|e| Error::Config(format!("json encode: {}", e)))?;
        println!("{}", out);
    } else {
        render_receipts_table(&valid, share_ref_filter.is_some() && valid.len() == 1)?;
    }
    Ok(())
}
```

**Render helpers** — reuse Phase 2 formatters:

- `format_unix_as_iso_utc` (`src/flow.rs:742-749`) — reusable as-is.
- `format_unix_as_iso_local` (`src/flow.rs:755-761`) — reusable as-is.
- `sender_openssh_fingerprint_and_z32` (`src/flow.rs:622-636`) — reusable; note the "sender" in the name is Phase-2 historical — it accepts any z32 and returns the OpenSSH fingerprint. For receipts it's called with `&r.recipient_pubkey`.

**Control-char strip idiom** (`src/flow.rs:788`, D-OUT-01 defense-in-depth):

```rust
let safe_purpose: String = purpose.chars().filter(|c| !c.is_control()).collect();
```

---

### `src/main.rs::dispatch::Receipts` (CLI dispatcher) — REPLACE stub

**Analog:** `src/main.rs::dispatch::Receive` (lines 165-215) defines the clap-arm shape. The critical divergence per D-OUT-04: **no passphrase resolution, no Identity load**.

**Current stub** (lines 216-219):

```rust
Command::Receipts { .. } => {
    eprintln!("not implemented yet (phase 3)");
    std::process::exit(1);
}
```

**Replacement** — mirror the transport-construction block from Receive but skip Identity:

```rust
Command::Receipts { from, share_ref, json } => {
    // D-OUT-04: no passphrase prompt — receipts listing requires no decryption key.
    let transport: Box<dyn cipherpost::transport::Transport> = {
        #[cfg(feature = "mock")]
        {
            if std::env::var("CIPHERPOST_USE_MOCK_TRANSPORT").is_ok() {
                Box::new(cipherpost::transport::MockTransport::new())
            } else {
                Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
            }
        }
        #[cfg(not(feature = "mock"))]
        {
            Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
        }
    };
    cipherpost::flow::run_receipts(
        transport.as_ref(),
        &from,
        share_ref.as_deref(),
        json,
    )?;
    Ok(())
}
```

The transport-construction block is identical to lines 137-150 (Send) and 198-211 (Receive) — copy-paste pattern.

---

### `src/main.rs::dispatch::Receive` — ADD keypair reconstruction

**Analog:** `src/main.rs::dispatch::Send` (lines 94-96) — the existing 3-line seed→keypair reconstruction:

```rust
let seed = id.signing_seed();
let seed_bytes: [u8; 32] = *seed;
let kp = pkarr::Keypair::from_secret_key(&seed_bytes);
```

D-SEQ-07: move these 3 lines into the Receive arm (after `let id = ...load(...)?;` at line 189), then pass `&kp` into `run_receive`:

```rust
cipherpost::flow::run_receive(&id, transport.as_ref(), &kp, &uri, &mut sink, &prompter)?;
```

---

### `src/cli.rs::Command::Receipts` — ADD `--json: bool` flag

**Analog:** existing `Command::Receipts` at `src/cli.rs:81-89`:

```rust
Receipts {
    /// Recipient pubkey (z-base-32) to query
    #[arg(long)]
    from: String,

    /// Filter by share_ref (32-char hex)
    #[arg(long)]
    share_ref: Option<String>,
},
```

**Extended** (D-OUT-01; one-line addition):

```rust
Receipts {
    #[arg(long)]
    from: String,

    #[arg(long)]
    share_ref: Option<String>,

    /// Emit machine-readable JSON to stdout (status stays on stderr).
    #[arg(long)]
    json: bool,
},
```

---

### `tests/phase3_receipt_sign_verify.rs` (unit test) — NEW

**Analog:** `src/record.rs::tests` (lines 148-224) — three tests: share_ref shape, share_ref determinism, sign_verify_round_trip, tampered_blob_fails_verify. Phase 3 promotes these to a top-level `tests/` integration file (matches Phase 2 pattern where verification fixtures live in `tests/`).

**Sign/verify round-trip pattern** (`src/record.rs:169-194`) — clone into `tests/phase3_receipt_sign_verify.rs`, swap field set:

```rust
#[test]
fn sign_verify_round_trip() {
    let seed = [42u8; 32];
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let signable = OuterRecordSignable {
        blob: "dGVzdA".into(),
        created_at: 1_700_000_000,
        protocol_version: PROTOCOL_VERSION,
        pubkey: kp.public_key().to_z32(),
        recipient: None,
        share_ref: "0123456789abcdef0123456789abcdef".into(),
        ttl_seconds: 86400,
    };
    let sig = sign_record(&signable, &kp).unwrap();
    let record = OuterRecord { /* copy from signable + sig */ };
    verify_record(&record).unwrap();
}
```

Replace with `ReceiptSignable` fields from D-RS-01. Reuse `[42u8; 32]` seed; populate `sender_pubkey == recipient_pubkey == kp.public_key().to_z32()` for the self-receipt path (D-SEQ-06 says this is valid).

**Tampered pattern** (`src/record.rs:196-224`) — mutate a field in the assembled `Receipt` after signing:

```rust
let err = verify_record(&record).unwrap_err();
assert!(matches!(err, Error::SignatureInner));
// D-16: Display is unified across all signature variants
assert_eq!(format!("{}", err), "signature verification failed");
```

D-16 assertion is load-bearing — the test is also a canary for the unified-Display invariant.

---

### `tests/phase3_receipt_canonical_form.rs` (fixture test) — NEW

**Analog:** `tests/outer_record_canonical_form.rs` — the full 52-line file is the exact template.

**Imports + fixture** pattern (lines 1-23):

```rust
use cipherpost::record::OuterRecordSignable;
use std::fs;

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
```

**Assertion pattern** (lines 25-35):

```rust
#[test]
fn outer_record_signable_bytes_match_committed_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_fixture` to create it",
    );
    assert_eq!(bytes, expected, "...JCS bytes changed — past signatures invalidated!");
}
```

**Regenerate pattern** (lines 37-44) — keep the `#[ignore]` + `regenerate_fixture` idiom so the fixture is reproducible:

```rust
#[test]
#[ignore]
fn regenerate_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
}
```

For Phase 3: swap `OuterRecordSignable` → `ReceiptSignable`, fixture path → `tests/fixtures/receipt_signable.bin`, populate deterministic string fields. Helper `serde_json_jcs` (lines 46-52) copies verbatim.

---

### `tests/phase3_end_to_end_a_sends_b_receipt.rs` (integration test) — NEW

**Analog:** `tests/phase2_share_round_trip.rs` — the deterministic-identity + MockTransport harness is reusable verbatim.

**Deterministic identity helper** (`tests/phase2_share_round_trip.rs:27-47`) — reusable as-is:

```rust
fn deterministic_identity_at(home: &std::path::Path, seed: [u8; 32]) -> (Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", home);
    fs::create_dir_all(home).unwrap();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    let pw = SecretBox::new(Box::new("pw".to_string()));
    let seed_z = Zeroizing::new(seed);
    let blob = crypto::encrypt_key_envelope(&seed_z, &pw).unwrap();
    let path = home.join("secret_key");
    let mut f = fs::OpenOptions::new()
        .create(true).truncate(true).write(true).mode(0o600)
        .open(&path).unwrap();
    f.write_all(&blob).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let id = cipherpost::identity::load(&pw).unwrap();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}
```

**Round-trip body pattern** (`tests/phase2_share_round_trip.rs:49-98`) — two-identity A→B with distinct `CIPHERPOST_HOME` dirs + `MockTransport::new()` + `AutoConfirmPrompter`. Phase 3 test extends it with:

```rust
// After B accepts:
// 1. Assert a receipt TXT exists under B's key at _cprcpt-<share_ref>
let all = transport.resolve_all_txt(&id_b.z32_pubkey());
let receipt_entry = all.iter()
    .find(|(label, _)| label == &format!("_cprcpt-{}", uri.share_ref_hex));
assert!(receipt_entry.is_some(), "receipt must be published under B's key");

// 2. A calls run_receipts(transport, b_z32, None, false)
run_receipts(&transport, &id_b.z32_pubkey(), None, false).expect("A fetches B's receipts");

// 3. Decode the stored JSON + verify + assert fields
let (_, receipt_json) = receipt_entry.unwrap();
let receipt: Receipt = serde_json::from_str(receipt_json).unwrap();
verify_receipt(&receipt).unwrap();
assert_eq!(receipt.sender_pubkey, id_a.z32_pubkey());
assert_eq!(receipt.recipient_pubkey, id_b.z32_pubkey());
assert_eq!(receipt.share_ref, uri.share_ref_hex);
```

Covers RCPT-01 + RCPT-02 + RCPT-03 per D-IT-01 test 1.

---

### `tests/phase3_coexistence_b_self_share_and_receipt.rs` (integration test) — NEW

**Analogs:**
- `tests/phase2_self_round_trip.rs` for the "B does a self-mode send" half.
- `tests/phase2_share_round_trip.rs` for the A→B send half (deterministic-identity pattern).
- `tests/mock_transport_roundtrip.rs::mock_publish_receipt_stores_under_cprcpt_label` (lines 63-78) for the multi-label assertion shape.

**Assertion shape** (from `mock_transport_roundtrip.rs:73-77`):

```rust
let all = transport.resolve_all_txt(&kp.public_key().to_z32());
assert_eq!(all.len(), 1);
assert_eq!(all[0].0, format!("_cprcpt-{}", share_ref));
```

Phase 3's coexistence test asserts TWO entries under B's key after the A→B→accept round trip:
- one `_cipherpost` entry (B's own prior outgoing self-share)
- one `_cprcpt-<share_ref>` entry (the new receipt from B's acceptance)

```rust
let all = transport.resolve_all_txt(&id_b.z32_pubkey());
let has_outgoing = all.iter().any(|(l, _)| l == "_cipherpost");
let has_receipt = all.iter().any(|(l, _)| l == &format!("_cprcpt-{}", uri.share_ref_hex));
assert!(has_outgoing, "B's own outgoing _cipherpost share must survive publish_receipt");
assert!(has_receipt, "B's receipt must be published");
```

Covers TRANS-03 + ROADMAP SC3 per D-IT-01 test 2.

---

### `tests/phase3_share_ref_filter.rs` (integration test) — NEW

**Analog:** `tests/phase2_share_round_trip.rs` for the two-identity harness; extended to two sequential sends A→B with different share_refs.

**Filter pattern** (NEW — no direct analog; derived from D-OUT-02 + RESEARCH §"Example 3"):

```rust
// With share_ref filter: exactly 1 receipt returned, matching share_ref
run_receipts(&transport, &id_b.z32_pubkey(), Some(&share_ref_1), false).expect("filter ok");
// Without filter: both receipts returned
run_receipts(&transport, &id_b.z32_pubkey(), None, false).expect("no filter ok");
```

Also asserts A's own outgoing `_cipherpost` share under A's key is still resolvable (ROADMAP SC4). Covers RCPT-02 + SC4 per D-IT-01 test 3.

---

## Shared Patterns

### Error unification (D-16)
**Source:** `src/error.rs:27-37` (4 Signature* variants all share `"signature verification failed"` Display); `src/error.rs:85-99` (`exit_code`: all Signature* → 3).
**Apply to:** `verify_receipt` (`src/receipt.rs`), `run_receipts` exit taxonomy (`src/flow.rs`), all Phase 3 sig-fail tests.

```rust
#[error("signature verification failed")]  // D-16: same Display for all sig-fail variants
SignatureInner,
#[error("signature verification failed")]  // D-16
SignatureCanonicalMismatch,
```

**Test invariant** — every sig-fail test asserts:
```rust
assert_eq!(format!("{}", err), "signature verification failed");
```

Phase 3 adds ZERO new error variants (D-RS-07 + D-SEQ-02 explicit: reuse `SignatureInner`, `SignatureCanonicalMismatch`, `Transport`, `Network`, `NotFound`, `Config`).

### JCS canonicalization
**Source:** `src/crypto.rs:378-385` — `crypto::jcs_serialize<T: Serialize>(&T) -> Result<Vec<u8>, Error>`.
**Apply to:** `sign_receipt`, `verify_receipt`, `append_ledger_entry_with_receipt`.

```rust
pub fn jcs_serialize<T: Serialize + ?Sized>(value: &T) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value.serialize(&mut ser).map_err(|e| Error::Crypto(Box::new(e)))?;
    ...
}
```

Per RESEARCH §"State of the Art": Phase 3's receipt signer calls `crypto::jcs_serialize` directly — do NOT copy `record.rs`'s local `jcs()` helper. A third copy is churn.

### Stderr/stdout discipline (CLI-01)
**Source:** `src/flow.rs:409` (already-accepted → stderr), `src/flow.rs:793-804` (acceptance banner → stderr), `src/main.rs:162` (share URI → stdout), `src/transport.rs:89, 110, 136` (`eprintln!("...DHT...")` for network status).
**Apply to:** `run_receipts` (summary on stderr, table/JSON on stdout), `publish_receipt` TRANS-05 trace, `run_receive` step-13 warn.

### Transport-swap block (mock/DHT selection)
**Source:** `src/main.rs:137-150` (Send arm) and `src/main.rs:198-211` (Receive arm) — identical 14-line `#[cfg(feature = "mock")]` block.
**Apply to:** `src/main.rs::dispatch::Receipts` — paste verbatim.

### Deterministic-identity test harness
**Source:** `tests/phase2_share_round_trip.rs:27-47` — `deterministic_identity_at(home, seed)` returns `(Identity, pkarr::Keypair)`.
**Apply to:** all three `tests/phase3_*.rs` integration tests.

### `#[serial]` + `TempDir` + `CIPHERPOST_HOME` env swap
**Source:** `tests/phase2_share_round_trip.rs:49-65` — `#[test] #[serial]` annotation; `TempDir::new()` per identity; `std::env::set_var("CIPHERPOST_HOME", dir_a.path())` switch before each run_send/run_receive call.
**Apply to:** all three `tests/phase3_*.rs` integration tests (tests touch `~/.cipherpost/state/` via `CIPHERPOST_HOME` and must serialize to avoid cross-test state collision).

### Control-char defense-in-depth
**Source:** `src/flow.rs:788` — `purpose.chars().filter(|c| !c.is_control()).collect::<String>()`.
**Apply to:** `render_receipts_table` (D-OUT-01).

### Fixture-test pair
**Source:** `tests/outer_record_canonical_form.rs` + `tests/fixtures/outer_record_signable.bin`.
**Apply to:** `tests/phase3_receipt_canonical_form.rs` + `tests/fixtures/receipt_signable.bin`.

### `#[cfg(any(test, feature = "mock"))]` gating
**Source:** `src/transport.rs:194-197, 212-215` (MockTransport under cfg gate); `src/flow.rs:640-683` (test_helpers module under cfg gate).
**Apply to:** any Phase 3 MockTransport helpers; `run_receipts` itself stays public (it's not test-only — it's the production Receipts handler).

## No Analog Found

No files in Phase 3 lack a close in-tree analog. Two low-novelty helpers are effectively new but derive patterns from adjacent code:

| Sub-pattern | Nature | Basis |
|------|------|--------|
| `matches_receipt_label` helper (in `src/transport.rs`) | Free function, ~5 lines | pkarr name-normalization fact documented in RESEARCH §"Example 2" citation (pkarr 5.0.4 `signed_packet.rs:256-271`); trivial `trim_end_matches('.') + ==` comparison |
| `nonce_hex` helper (in `src/receipt.rs`) | Free function, ~7 lines | Shape echoes `record::share_ref_from_bytes` (`src/record.rs:68-79`) — 32-char lowercase hex encoder; source swaps `Sha256::digest` for `OsRng.fill_bytes` |

Both are single-concept helpers with no policy — no analog needed beyond the shape they already mirror.

## Metadata

**Analog search scope:**
- `/home/john/vault/projects/github.com/cipherpost/src/` (11 source files, 6 relevant: `receipt.rs`, `record.rs`, `transport.rs`, `flow.rs`, `main.rs`, `cli.rs`; 5 supporting: `lib.rs`, `crypto.rs`, `error.rs`, `identity.rs`, `payload.rs`)
- `/home/john/vault/projects/github.com/cipherpost/tests/` (27 test files, 5 relevant as analogs: `phase2_share_round_trip.rs`, `phase2_self_round_trip.rs`, `mock_transport_roundtrip.rs`, `outer_record_canonical_form.rs`, `fixtures/outer_record_signable.bin`)

**Files scanned:** 38 (11 src + 27 tests)
**Pattern extraction date:** 2026-04-21

---

## PATTERN MAPPING COMPLETE

**Phase:** 3 - Signed receipt — the cipherpost delta
**Files classified:** 17 (including 2 in-place extensions counted as separate entries for the planner)
**Analogs found:** 17 / 17

### Coverage
- Files with exact analog: 13 (receipt.rs mirrors record.rs; all test files mirror existing Phase 2 tests; transport body changes mirror existing publish/resolve; main.rs/cli.rs changes are in-file extensions)
- Files with role-match analog: 4 (`run_receipts` — new flow function; `Transport::resolve_all_cprcpt` — new trait method; two integration tests extend existing harness with new assertions)
- Files with no analog: 0

### Key Patterns Identified
- **Signable/Signed struct pair** with alphabetical fields, `From<&Signed> for Signable`, base64-STANDARD Ed25519 signature, JCS-serialized signing bytes, and a 5-step verify including a round-trip-reserialize byte-compare guard (T-01-03-02). `src/record.rs` is the verbatim mirror for `src/receipt.rs`.
- **Resolve-merge-republish for PKARR SignedPacket** using `resolve_most_recent` + `all_resource_records()` + `builder.record(rr.clone())` + `builder.txt(name, txt, 300)` + `sign(keypair)` + `client.publish(&packet, cas)`. Canonical pattern direct from pkarr 5.0.4 rustdoc.
- **Strict RECV flow step-ordering** extends from 12 steps (Phase 2) to 13 (Phase 3), with `publish_receipt` strictly after `create_sentinel` + `append_ledger_entry` so RECV-06 idempotence holds even on publish failure.
- **Warn+degrade publish failure** — catch at the call site, print `eprintln!("receipt publish failed: {}", user_message(&e))`, continue; exit 0 because core value (material delivered) succeeded.
- **Append-only ledger with last-match-wins scan** — adding `receipt_published_at: Option<String>` (alphabetical between `purpose` and `sender`) writes a second ledger row instead of rewriting; `check_already_accepted` linear-scan already handles multi-row per share_ref.
- **Unified D-16 Display** on all sig-fail variants reused for `verify_receipt` — no new `Error::SignatureReceipt` variant.
- **No Identity required for `run_receipts`** (D-OUT-04) — Receipts dispatch skips passphrase resolution entirely, unlike Send/Receive.
- **Deterministic-identity + MockTransport + AutoConfirmPrompter + `#[serial]` + `CIPHERPOST_HOME` TempDir** is the Phase 2 integration-test harness that drops in unmodified for all three Phase 3 MockTransport tests.

### File Created
`/home/john/vault/projects/github.com/cipherpost/.planning/phases/03-signed-receipt-the-cipherpost-delta/03-PATTERNS.md`

### Ready for Planning
Pattern mapping complete. Planner can now reference analog line-ranges directly in PLAN.md action sections. The two-wave split recommended in RESEARCH §"Summary" (Wave 1 = `receipt.rs` body + `publish_receipt` upgrade + `run_receive` step 13 + ledger field; Wave 2 = `run_receipts` + Receipts CLI dispatch + `--json` flag + 3 integration tests) is pattern-supported — Wave 1 touches only exact-analog files, Wave 2 introduces the single new trait method + the single new flow function with role-match analogs.
