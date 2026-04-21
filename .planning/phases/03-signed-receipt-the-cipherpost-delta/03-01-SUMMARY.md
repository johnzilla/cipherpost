---
phase: 03-signed-receipt-the-cipherpost-delta
plan: "01"
subsystem: receipt
tags:
  - receipt
  - jcs
  - ed25519
  - signature
  - cipherpost-delta
  - rust
dependency_graph:
  requires:
    - src/crypto.rs (jcs_serialize)
    - src/error.rs (SignatureInner, SignatureCanonicalMismatch)
    - src/lib.rs (PROTOCOL_VERSION, DHT_LABEL_RECEIPT_PREFIX)
  provides:
    - src/receipt.rs (Receipt, ReceiptSignable, sign_receipt, verify_receipt, nonce_hex)
    - tests/fixtures/receipt_signable.bin (JCS canonical byte vector)
  affects:
    - Cargo.toml (two new [[test]] entries)
tech_stack:
  added: []
  patterns:
    - "struct-pair (Signed + Signable) with alphabetical fields + From<&Signed> for Signable"
    - "5-step Ed25519 verify_strict + round-trip-reserialize guard (T-01-03-02)"
    - "JCS fixture test (committed binary + regenerate_fixture ignored test)"
key_files:
  created:
    - src/receipt.rs
    - tests/phase3_receipt_sign_verify.rs
    - tests/phase3_receipt_canonical_form.rs
    - tests/fixtures/receipt_signable.bin
  modified:
    - Cargo.toml
decisions:
  - "Receipt signs with Ed25519 identity key directly — no new HKDF call-site (D-RS-07)"
  - "crate::crypto::jcs_serialize reused — no third local jcs() copy (RESEARCH State-of-the-Art)"
  - "No new Error variants: SignatureInner + SignatureCanonicalMismatch reused (D-RS-07)"
  - "Fixture at 424 bytes — well above 200-byte minimum; all 9 fields alphabetically ordered"
metrics:
  duration_minutes: 4
  completed_date: "2026-04-21"
  tasks_completed: 2
  tasks_total: 2
  files_created: 4
  files_modified: 1
---

# Phase 3 Plan 01: Receipt Wire Schema + Sign/Verify + JCS Fixture Summary

**One-liner:** Receipt struct pair (10/9 fields, alphabetical), Ed25519 sign/verify via `crate::crypto::jcs_serialize`, 128-bit OsRng nonce, 5-step round-trip-reserialize guard, 424-byte committed JCS fixture, 6 unit tests asserting D-16 unified Display.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Implement src/receipt.rs body | eb25139 | src/receipt.rs |
| 2 | Write tests + generate JCS fixture | e9d1b65 | tests/phase3_receipt_sign_verify.rs, tests/phase3_receipt_canonical_form.rs, tests/fixtures/receipt_signable.bin, Cargo.toml |

## File Inventory

### src/receipt.rs (133 lines, replacing 4-line placeholder)

- `pub struct Receipt` — 10 alphabetical fields: `accepted_at: i64`, `ciphertext_hash: String`, `cleartext_hash: String`, `nonce: String`, `protocol_version: u16`, `purpose: String`, `recipient_pubkey: String`, `sender_pubkey: String`, `share_ref: String`, `signature: String`
- `pub struct ReceiptSignable` — same 9 fields, no `signature`
- `impl From<&Receipt> for ReceiptSignable` — field-by-field clone
- `pub fn nonce_hex() -> String` — `OsRng.fill_bytes` 16 bytes → 32 lowercase hex chars
- `pub fn sign_receipt(&ReceiptSignable, &pkarr::Keypair) -> Result<String, Error>` — JCS + Ed25519 + base64-STANDARD
- `pub fn verify_receipt(&Receipt) -> Result<(), Error>` — 5-step: parse `recipient_pubkey`, decode sig, JCS signable, `verify_strict`, round-trip-reserialize byte-compare

### tests/phase3_receipt_sign_verify.rs (116 lines)

Six tests: `sign_verify_round_trip`, `self_receipt_round_trip` (D-SEQ-06: sender==recipient), `tampered_nonce_fails_verify`, `tampered_ciphertext_hash_fails_verify`, `tampered_purpose_fails_verify`, `nonce_hex_shape`. All tampered-* tests assert `matches!(err, Error::SignatureInner)` AND `format!("{}", err) == "signature verification failed"` (D-16 canary).

### tests/phase3_receipt_canonical_form.rs (64 lines)

Mirror of `tests/outer_record_canonical_form.rs`: `receipt_signable_bytes_match_committed_fixture` (non-ignored) reads `tests/fixtures/receipt_signable.bin` and byte-compares against fresh JCS serialization; `regenerate_fixture` (#[ignore]) writes the file.

### tests/fixtures/receipt_signable.bin

- **Exact byte count: 424 bytes**
- JSON field order (verified by Python): `['accepted_at', 'ciphertext_hash', 'cleartext_hash', 'nonce', 'protocol_version', 'purpose', 'recipient_pubkey', 'sender_pubkey', 'share_ref']`
- This is the canonical reference vector for Phase 4 SPEC.md.

### Cargo.toml (2 new [[test]] entries)

```toml
[[test]]
name = "phase3_receipt_sign_verify"
path = "tests/phase3_receipt_sign_verify.rs"

[[test]]
name = "phase3_receipt_canonical_form"
path = "tests/phase3_receipt_canonical_form.rs"
```

No `required-features` (these tests do not depend on `--features mock`).

## Test Results

| Suite | Command | Result |
|-------|---------|--------|
| Sign/verify unit tests | `cargo test --test phase3_receipt_sign_verify` | 6 passed, 0 failed |
| Canonical form fixture | `cargo test --test phase3_receipt_canonical_form` | 1 passed, 1 ignored |
| Fixture regeneration | `cargo test --test phase3_receipt_canonical_form -- --ignored regenerate_fixture` | 1 passed |
| Full suite (no features) | `cargo test` | All `ok`, 0 failures across all test harnesses |

## Verification Invariants (all passing)

| Check | Result |
|-------|--------|
| `cargo build --release` | 0 warnings new to this plan |
| `cargo clippy -- -D warnings` (lib+bin) | clean |
| `grep -c "Error::SignatureReceipt" src/receipt.rs src/error.rs` | 0, 0 (D-RS-07) |
| `grep -c "chacha20poly1305\|tokio::" src/receipt.rs` | 0 |
| `grep -c "fn jcs(" src/receipt.rs` | 0 (uses `crate::crypto::jcs_serialize`) |
| `grep -c "HKDF_INFO_PREFIX\|hkdf::Hkdf" src/receipt.rs` | 0 (no new HKDF call-sites) |
| `test -f tests/fixtures/receipt_signable.bin` && size >= 200 | 424 bytes |

Note: `cargo clippy --all-targets` reports a pre-existing `format_collect` lint in `tests/debug_leak_scan.rs` (not introduced by this plan). Deferred — see below.

## Deviations from Plan

None — plan executed exactly as written. All shapes are exact clones of `src/record.rs`.

## Known Stubs

None. `src/receipt.rs` exposes fully functional sign/verify/nonce_hex with no placeholder implementations.

## Deferred Items

**Pre-existing clippy lint in `tests/debug_leak_scan.rs`** (out of scope per deviation Rule scope boundary):

```
error: use a `write!` macro instead of a `format!(..)` call followed by a collect
  --> tests/debug_leak_scan.rs:32:46
```

This lint existed before Phase 3 and is not caused by this plan's changes (`git diff HEAD~2 -- tests/debug_leak_scan.rs` shows no changes). Filed for a future chore(fmt/lint) pass.

## Self-Check: PASSED

- `src/receipt.rs` exists: FOUND
- `tests/phase3_receipt_sign_verify.rs` exists: FOUND
- `tests/phase3_receipt_canonical_form.rs` exists: FOUND
- `tests/fixtures/receipt_signable.bin` exists (424 bytes): FOUND
- Commit eb25139 (feat(03-01): implement receipt.rs): FOUND
- Commit e9d1b65 (test(03-01): add receipt sign/verify tests): FOUND
