---
phase: 03-signed-receipt-the-cipherpost-delta
plan: "02"
subsystem: transport
tags:
  - transport
  - pkarr
  - resolve-merge-republish
  - ledger
  - rust
dependency_graph:
  requires:
    - src/transport.rs (DhtTransport, MockTransport, Transport trait — Phase 1)
    - src/flow.rs (LedgerEntry, append_ledger_entry — Phase 2)
    - src/error.rs (WireBudgetExceeded, NotFound, Transport variants)
    - src/lib.rs (DHT_LABEL_RECEIPT_PREFIX, DHT_LABEL_OUTER)
  provides:
    - src/transport.rs (upgraded DhtTransport::publish_receipt + Transport::resolve_all_cprcpt + both impls)
    - src/flow.rs (LedgerEntry.receipt_published_at + append_ledger_entry_with_receipt)
    - tests/phase3_mock_publish_receipt_coexistence.rs (3 coexistence tests)
  affects:
    - Cargo.toml (new [[test]] entry)
    - Plan 03 (run_receive step 13 will call publish_receipt + append_ledger_entry_with_receipt)
tech_stack:
  added: []
  patterns:
    - "resolve-merge-republish: resolve_most_recent → all_resource_records() → builder.record() → builder.txt() → sign → publish(cas)"
    - "matches_receipt_label() helper: trim_end_matches('.') + dual-equality for pkarr normalized name forms"
    - "WireBudgetExceeded{plaintext:0} convention: plaintext=0 marks receipt overflow vs share overflow"
    - "append-only ledger with last-match-wins semantics (D-SEQ-05)"
    - "Option<&str> with skip_serializing_if for backwards-compatible ledger extension"
key_files:
  created:
    - tests/phase3_mock_publish_receipt_coexistence.rs
  modified:
    - src/transport.rs
    - src/flow.rs
    - Cargo.toml
decisions:
  - "matches_receipt_label() handles both bare <label> and <label>.<z32> pkarr normalized forms (T-03-02-04 mitigation)"
  - "append_ledger_entry_with_receipt takes pre-computed hashes as &str args (Pitfall #4 guard — no recomputation)"
  - "MockTransport::publish_receipt body left unchanged per D-MRG-05 — already correct semantics"
  - "append_ledger_entry_with_receipt is private fn (not pub(crate)) since all callers are in src/flow.rs"
metrics:
  duration_minutes: 12
  completed_date: "2026-04-21"
  tasks_completed: 2
  tasks_total: 2
  files_created: 1
  files_modified: 3
---

# Phase 3 Plan 02: Transport Merge-Republish + Ledger Extension Summary

**One-liner:** DhtTransport::publish_receipt upgraded from Phase-1 clobber to resolve-merge-republish via pkarr 5.0.4 `all_resource_records()` + CAS, new `Transport::resolve_all_cprcpt` 4th trait method on both impls, LedgerEntry extended with backwards-compatible `receipt_published_at: Option<&str>`, and 3-test MockTransport coexistence suite proving D-MRG-05.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Upgrade DhtTransport::publish_receipt + add resolve_all_cprcpt trait method + both impls | 31310ee | src/transport.rs |
| 2 | Extend LedgerEntry + add append_ledger_entry_with_receipt + coexistence test + Cargo.toml | 8d577bb | src/flow.rs, tests/phase3_mock_publish_receipt_coexistence.rs, Cargo.toml |

## File Inventory

### src/transport.rs (modifications)

**Before (Phase-1 placeholder, lines 128-153):** Simple clobber — built a single-TXT `SignedPacket::builder().txt(...).sign(keypair)` with no merge step and `publish(&packet, None)`.

**After (resolve-merge-republish body, replacing lines 128-153):**

```rust
fn publish_receipt(&self, keypair: &pkarr::Keypair, share_ref_hex: &str, receipt_json: &str) -> Result<(), Error> {
    // 1. Resolve most recent — may be None if recipient has never published.
    let pk = keypair.public_key();
    let existing = self.client.resolve_most_recent(&pk);

    // 2. Rebuild builder from existing RRs, skipping same-label duplicates.
    let mut builder = pkarr::SignedPacket::builder();
    let mut cas: Option<pkarr::Timestamp> = None;
    if let Some(ref packet) = existing {
        cas = Some(packet.timestamp());
        let origin_z32 = pk.to_z32();
        for rr in packet.all_resource_records() {
            let rr_name = rr.name.to_string();
            if matches_receipt_label(&rr_name, &receipt_label, &origin_z32) { continue; }
            builder = builder.record(rr.clone());
        }
    }
    builder = builder.txt(new_name, new_txt, 300);

    // 3. Sign — PacketTooLarge → WireBudgetExceeded{plaintext:0}
    let packet = match builder.sign(keypair) {
        Ok(p) => p,
        Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) =>
            return Err(Error::WireBudgetExceeded { encoded, budget: crate::flow::WIRE_BUDGET_BYTES, plaintext: 0 }),
        Err(other) => return Err(Error::Transport(Box::new(other))),
    };

    // 4. Publish with optional CAS.
    self.client.publish(&packet, cas).map_err(map_pkarr_publish_error)?;
    Ok(())
}
```

**New `Transport::resolve_all_cprcpt` trait method (4th method in trait):**

```rust
fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error>;
```

**DhtTransport impl:**

```rust
fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error> {
    let pk = pkarr::PublicKey::try_from(pubkey_z32).map_err(|_| Error::NotFound)?;
    let packet = self.client.resolve_most_recent(&pk).ok_or(Error::NotFound)?;
    let mut out = Vec::new();
    for rr in packet.all_resource_records() {
        let name = rr.name.to_string();
        let trimmed = name.trim_end_matches('.');
        if trimmed.starts_with(DHT_LABEL_RECEIPT_PREFIX) {
            if let Some(json) = extract_txt_string(&rr.rdata) { out.push(json); }
        }
    }
    if out.is_empty() { return Err(Error::NotFound); }
    Ok(out)
}
```

**MockTransport impl:**

```rust
fn resolve_all_cprcpt(&self, pubkey_z32: &str) -> Result<Vec<String>, Error> {
    let store = self.store.lock().unwrap();
    let entries = store.get(pubkey_z32).ok_or(Error::NotFound)?;
    let out: Vec<String> = entries
        .iter()
        .filter(|(label, _)| label.starts_with(DHT_LABEL_RECEIPT_PREFIX))
        .map(|(_, json)| json.clone())
        .collect();
    if out.is_empty() { return Err(Error::NotFound); }
    Ok(out)
}
```

**MockTransport::publish_receipt body at lines 271-288 was NOT modified** — D-MRG-05 invariant held. The existing `entry.retain(|(l, _)| l != &label); entry.push(...)` semantics already satisfy TRANS-03's coexistence contract.

**New private helper:**

```rust
fn matches_receipt_label(rr_name: &str, receipt_label: &str, origin_z32: &str) -> bool {
    let trimmed = rr_name.trim_end_matches('.');
    trimmed == format!("{}.{}", receipt_label, origin_z32) || trimmed == receipt_label
}
```

### src/flow.rs (modifications)

**LedgerEntry** — extended from 6 to 7 fields (alphabetical insertion between `purpose` and `sender`):

```rust
#[derive(serde::Serialize)]
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_published_at: Option<&'a str>,   // NEW
    sender: &'a str,
    share_ref: &'a str,
}
```

`append_ledger_entry` struct literal updated to set `receipt_published_at: None` (step 12 null placeholder).

`append_ledger_entry_with_receipt` added as private `fn` (Plan 03 step 13 caller lives in the same file):

- Accepts pre-computed `ciphertext_hash: &str` and `cleartext_hash: &str` — no recomputation (Pitfall #4)
- Appends a second ledger row with `receipt_published_at: Some(receipt_published_at_iso)`
- Same 0o600 permissions enforcement as `append_ledger_entry`

### tests/phase3_mock_publish_receipt_coexistence.rs (new, 3 tests)

| Test | What It Proves |
|------|----------------|
| `outgoing_share_and_receipts_coexist` | After outer publish + 2 receipt publishes, `resolve_all_txt` returns 3 entries; `resolve_all_cprcpt` returns exactly 2 |
| `republishing_same_share_ref_replaces_only_that_label` | Republishing share_ref_1 with new JSON keeps entry count at 3; old body gone, new body present |
| `resolve_all_cprcpt_returns_not_found_on_empty` | No-key store → NotFound; outer-only store → NotFound |

### Cargo.toml

Added `[[test]] name = "phase3_mock_publish_receipt_coexistence"` with `required-features = ["mock"]`.

## Test Results

| Suite | Command | Result |
|-------|---------|--------|
| New coexistence tests | `cargo test --features mock --test phase3_mock_publish_receipt_coexistence` | 3 passed, 0 failed |
| Pre-existing mock roundtrip | `cargo test --features mock --test mock_transport_roundtrip` | 3 passed, 0 failed |
| Full mock suite | `cargo test --features mock` | All ok, 0 failures |

## Verification Invariants (all passing)

| Check | Result |
|-------|--------|
| `cargo build --release` | ok (1 expected dead_code warning on append_ledger_entry_with_receipt — called by Plan 03 step 13) |
| `cargo clippy --lib --bins -- -D warnings` | clean |
| `grep -c "fn resolve_all_cprcpt" src/transport.rs` | 3 (trait + DhtTransport + MockTransport) |
| `grep -c "all_resource_records" src/transport.rs` | 3 (publish_receipt body + resolve_all_cprcpt body + comment) |
| `grep -c "receipt_published_at" src/flow.rs` | 6 (struct field + skip attr + two literals + function body + doc) |
| `grep -c "skip_serializing_if" src/flow.rs` | 1 |
| `grep -cE "(Error::SignatureReceipt|Error::ReceiptPublish|Error::PublishFailed)" src/` | 0 (no new error variants) |
| MockTransport::publish_receipt body modified | No (D-MRG-05 invariant held) |
| `cargo test --features mock --test mock_transport_roundtrip` | 3 passed (pre-existing Phase 1 test) |

Note: `cargo clippy --all-targets` reports the pre-existing `format_collect` lint in `tests/debug_leak_scan.rs` — not introduced by this plan (same as Phase 3 Plan 01).

## Deviations from Plan

None — plan executed exactly as written.

- DhtTransport::publish_receipt body matches the plan's exact specification.
- matches_receipt_label helper placed exactly as specified (after extract_txt_string).
- MockTransport::publish_receipt body left unchanged per D-MRG-05 (plan explicitly said "no body change expected").
- append_ledger_entry_with_receipt uses plain `fn` (private) rather than `pub(crate)` — plan's own note at the end of sub-step 2.2 specifies plain `fn` since all callers are in src/flow.rs.

## Known Stubs

None. All implemented functionality is fully wired. The `dead_code` warning on `append_ledger_entry_with_receipt` is expected — it will be called by Plan 03 step 13 (`run_receive` extension).

## Threat Flags

No new trust boundaries introduced beyond those in the plan's threat model. The `matches_receipt_label` helper mitigates T-03-02-04 (DNS name-normalization bypass). No new network endpoints, auth paths, or schema changes outside planned scope.

## Self-Check: PASSED

- `src/transport.rs` modified: FOUND
- `src/flow.rs` modified: FOUND
- `tests/phase3_mock_publish_receipt_coexistence.rs` created: FOUND
- `Cargo.toml` updated with phase3_mock_publish_receipt_coexistence [[test]]: FOUND
- Commit 31310ee (feat(03-02): upgrade DhtTransport::publish_receipt...): FOUND
- Commit 8d577bb (feat(03-02): extend LedgerEntry...): FOUND
- 3 new coexistence tests passing: CONFIRMED
- Pre-existing mock_transport_roundtrip tests passing: CONFIRMED
