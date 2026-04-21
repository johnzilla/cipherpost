---
phase: 03-signed-receipt-the-cipherpost-delta
reviewed: 2026-04-21T00:00:00Z
depth: standard
files_reviewed: 21
files_reviewed_list:
  - src/receipt.rs
  - src/flow.rs
  - src/transport.rs
  - src/main.rs
  - src/cli.rs
  - Cargo.toml
  - tests/phase3_receipt_sign_verify.rs
  - tests/phase3_receipt_canonical_form.rs
  - tests/phase3_mock_publish_receipt_coexistence.rs
  - tests/phase3_end_to_end_a_sends_b_receipt.rs
  - tests/phase3_coexistence_b_self_share_and_receipt.rs
  - tests/phase3_share_ref_filter.rs
  - tests/phase3_tamper_zero_receipts.rs
  - tests/phase2_cli_declined_exit_7.rs
  - tests/phase2_expired_share.rs
  - tests/phase2_idempotent_re_receive.rs
  - tests/phase2_self_round_trip.rs
  - tests/phase2_share_round_trip.rs
  - tests/phase2_state_perms.rs
  - tests/phase2_tamper_aborts_before_decrypt.rs
  - tests/debug_leak_scan.rs
findings:
  critical: 0
  warning: 3
  info: 6
  total: 9
status: issues_found
source_augmented_from: [03-HUMAN-UAT.md]
---

# Phase 3: Code Review Report

**Reviewed:** 2026-04-21T00:00:00Z
**Depth:** standard
**Files Reviewed:** 21
**Status:** issues_found

## Summary

Phase 3 delivers the Receipt wire schema (`src/receipt.rs`), the resolve-merge-republish `DhtTransport::publish_receipt` (TRANS-03), `run_receive` step 13 wiring, `run_receipts` fetch-verify-render, and the CLI dispatch for `cipherpost receipts`. Cryptographic primitives are correctly applied: JCS canonicalization via `serde_canonical_json` (confirmed RFC 8785 usage in `crypto::jcs_serialize`), `verify_strict` on Ed25519, 5-step verify including the round-trip-reserialize guard that mirrors `record::verify_record` line-for-line, 128-bit `OsRng`-sourced nonce, SHA-256 binding over ciphertext and cleartext. The D-16 unified Display invariant is upheld — both `SignatureInner` and `SignatureCanonicalMismatch` produce the same user-facing string. Receipt/ReceiptSignable derive `Debug`, which is safe because every field is public data (no key material, no ciphertext).

Three warnings worth attention:

1. **D-SEQ-02 warn-on-failure is not fully honored.** The step 13 block in `run_receive` uses `?` on four pre-publish operations (`now_unix_seconds`, `sign_receipt`, `serde_json::to_string`, and an implicit serialize inside `sign_receipt`). If any of these fail, `run_receive` returns `Err` rather than warning to stderr and returning `Ok(())` — even though the material was already delivered (step 11) and locally recorded (step 12). Only the final `transport.publish_receipt` call is wrapped in `match … Err(e) => eprintln!`. This is a semantic gap vs. CONTEXT.md D-SEQ-02.

2. **Unused-variable error propagation in `run_receive` step 6.** A base64-decode failure on `record.blob` maps to `Error::SignatureCanonicalMismatch`, which produces the D-16 "signature verification failed" user message. This is acceptable under oracle-hygiene rules but is semantically imprecise — the record just passed inner-sig verify in step 2+3, so a decode failure here indicates tampering between `resolve()` and this line, or a sender-side malformed blob.

3. **Potential confusion-of-identity consideration in receipt provenance.** `Receipt.sender_pubkey` is recipient-attested (signed by the recipient alongside the rest of the struct). An attacker publishing under their own z32 can claim any `sender_pubkey` they wish; only the combination of "receipt found under z32 X" + "receipt signature verifies with X" + "receipt claims sender = Y" provides the attestation. This is by design (D-RS-07), but the receipt semantics would benefit from an inline code comment.

No Critical findings. Crypto primitives, ordering (sentinel before receipt publish per D-SEQ-01), oracle-hygiene (D-16), ciphertext/cleartext binding (sha256 over the exact bytes step 11 wrote), and nonce entropy are all correct.

## Warnings

### WR-01: `run_receive` step 13 violates D-SEQ-02 "warn + degrade, exit 0" on pre-publish failures

**File:** `src/flow.rs:497-525`
**Issue:** The step 13 block documents (flow.rs:490-492) that `transport.publish_receipt` failure must exit 0 per D-SEQ-02. However, four operations inside the block use `?` to propagate errors BEFORE the publish call:

- Line 497: `let accepted_at_unix = now_unix_seconds()?;`
- Line 511: `let signature = crate::receipt::sign_receipt(&signable, keypair)?;` (which internally calls `jcs_serialize?`)
- Line 524-525: `let receipt_json = serde_json::to_string(&receipt).map_err(|e| Error::Config(…))?;`

If any of these fail (e.g., `sign_receipt` returns `Err` because JCS serialize of the signable struct fails, or the system clock is before epoch), `run_receive` returns `Err` and the CLI exits non-zero — even though the material has already been written to the output sink (step 11) and sentinel+ledger already committed (step 12). Per D-SEQ-02 the core-value delivery is complete at step 12 and step 13 is best-effort.

In practice these errors are extremely rare (clock pre-epoch, serde_json failing on a pure-`String`/`i64`/`u16` struct), but the invariant is still violated.

**Fix:** Wrap the entire step 13 block's Result-returning operations in a helper closure and match on its outcome the same way `transport.publish_receipt` is currently matched:

```rust
let publish_outcome: Result<(), Error> = (|| {
    let ciphertext_hash = format!("{:x}", Sha256::digest(&ciphertext));
    let cleartext_hash = format!("{:x}", Sha256::digest(&jcs_plain));
    let accepted_at_unix = now_unix_seconds()?;
    let recipient_z32 = keypair.public_key().to_z32();
    let signable = crate::receipt::ReceiptSignable { /* … */ };
    let signature = crate::receipt::sign_receipt(&signable, keypair)?;
    let receipt = crate::receipt::Receipt { /* … */, signature };
    let receipt_json = serde_json::to_string(&receipt)
        .map_err(|e| Error::Config(format!("receipt encode: {}", e)))?;
    transport.publish_receipt(keypair, &record.share_ref, &receipt_json)?;
    // D-SEQ-05 ledger update on success
    let iso = iso8601_utc_now()?;
    append_ledger_entry_with_receipt(/* … */)?;
    Ok(())
})();

if let Err(e) = publish_outcome {
    eprintln!("receipt publish failed: {}", crate::error::user_message(&e));
}
```

### WR-02: Step-6 base64 decode error maps to `SignatureCanonicalMismatch` without comment

**File:** `src/flow.rs:434-436`
**Issue:** 

```rust
let ciphertext = base64::engine::general_purpose::STANDARD
    .decode(&record.blob)
    .map_err(|_| Error::SignatureCanonicalMismatch)?;
```

The inner-signature verification in `resolve()` signs over the base64 *string* (not the decoded bytes), so it's theoretically possible for a record to pass inner-sig verify yet fail base64 decode here. Mapping to `SignatureCanonicalMismatch` is oracle-hygienic (produces the unified D-16 "signature verification failed" string, matching Phase 2 test `phase2_tamper_aborts_before_decrypt`), but it's semantically imprecise — base64 decode failure is not a signature-canonicalization issue. A future reader may be confused by the error-variant choice.

**Fix:** Add a code comment explaining the D-16 oracle-hygiene rationale for choosing a Signature* variant even for a non-signature error class, and confirm no test distinguishes between the two. Example:

```rust
// D-16: base64 decode failure maps to a Signature* variant to preserve oracle
// hygiene — the inner sig signed over the base64 string, so a malformed blob
// reaching here must have been introduced by the sender (invalid record) or
// by post-verify tampering. Both produce the same user-facing message.
let ciphertext = base64::engine::general_purpose::STANDARD
    .decode(&record.blob)
    .map_err(|_| Error::SignatureCanonicalMismatch)?;
```

### WR-03: Receipt `sender_pubkey` is recipient-attested but undocumented in the struct

**File:** `src/receipt.rs:25-37`
**Issue:** The `Receipt` struct includes `sender_pubkey` as a plain `String` field alongside `recipient_pubkey`. The signature covers both (via `ReceiptSignable`), so the recipient effectively swears "this is who I received from". But an attacker controlling their own z32 key can craft a Receipt with any `sender_pubkey` value they like and publish it under their own key — the crypto will verify. Only the *composition* of "receipt found under z32 X" + "receipt signed by X" + "claimed sender is Y" provides provenance.

This is by design (D-RS-07 and CONTEXT.md §"Receipt wire schema"), but the struct-level doc comment does not mention the asymmetry. A future consumer reading `verify_receipt` might assume `sender_pubkey` is authenticated *by the sender*, which it isn't.

**Fix:** Add a doc comment on `Receipt.sender_pubkey`:

```rust
pub struct Receipt {
    // …
    /// Recipient's attestation of who they received from. NOT signed by the
    /// sender — only the recipient signs the receipt. Provenance comes from
    /// the receipt being found under `recipient_pubkey`'s DHT packet AND the
    /// signature verifying with that pubkey.
    pub sender_pubkey: String,
    // …
}
```

This surfaces the subtlety to THREAT-MODEL.md (Phase 4) writers and to SDK consumers.

## Info

### IN-01: Transport construction duplicated three times in `main.rs`

**File:** `src/main.rs:137-150`, `src/main.rs:204-217`, `src/main.rs:226-239`
**Issue:** The `Box<dyn Transport>` construction with the `#[cfg(feature = "mock")]` branch is copy-pasted in three CLI handlers (Send, Receive, Receipts). Each block is identical modulo braces.

**Fix:** Extract to a helper:

```rust
fn build_transport() -> Result<Box<dyn cipherpost::transport::Transport>, cipherpost::Error> {
    #[cfg(feature = "mock")]
    {
        if std::env::var("CIPHERPOST_USE_MOCK_TRANSPORT").is_ok() {
            return Ok(Box::new(cipherpost::transport::MockTransport::new()));
        }
    }
    Ok(Box::new(
        cipherpost::transport::DhtTransport::with_default_timeout()?,
    ))
}
```

### IN-02: `nonce_hex` uses manual loop instead of a standard formatter

**File:** `src/receipt.rs:73-82`
**Issue:** `nonce_hex()` constructs the hex string via `for b in &bytes { out.push_str(&format!("{:02x}", b)); }`. Each iteration allocates a 2-byte `String` and then copies. This mirrors the pattern in `record::share_ref_from_bytes` (record.rs:75) so it's stylistically consistent with the codebase, but it is less efficient than `write!(out, "{:02x}", b)` using `std::fmt::Write`. Not a correctness issue.

**Fix:** Optional cleanup for both call sites:

```rust
use std::fmt::Write;
let mut out = String::with_capacity(32);
for b in &bytes {
    let _ = write!(out, "{:02x}", b);
}
```

Or use `hex::encode(&bytes)` if the `hex` crate is already in the dep tree. Skip if consistency with `record.rs` is preferred.

### IN-03: `format_unix_as_iso_local` silently swallows chrono TZ failure

**File:** `src/flow.rs:1007-1013`
**Issue:** On chrono TZ lookup failure, the function returns "?". For the acceptance banner this is correct (D-ACCEPT-02 allows degraded display), but when the same formatter is used in `render_receipts_table` (flow.rs:649), a "?" in the acceptance-detail output may confuse users without explaining why.

**Fix:** Add a stderr hint when the fallback triggers in the receipts path, or accept it as a silent UX degradation and add a doc comment.

### IN-04: Cargo.toml `pkarr` version is 5.0.3 but transport.rs comments reference 5.0.4

**File:** `Cargo.toml:23`, `src/transport.rs:12`, `src/transport.rs:187`, `src/transport.rs:235`
**Issue:** The dependency line specifies `pkarr = { version = "5.0.3" }` (semver `^5.0.3` — Cargo may resolve to 5.0.4). The module-level comments in `transport.rs` reference 5.0.4 API details ("pkarr 5.0.4 normalizes names …"). No bug — 5.0.4 is semver-compatible. If the intent is to pin exactly to 5.0.4 (which would match the comments), use `=5.0.4`. If the intent is to accept 5.0.3+, update the comments to say "5.0.3+".

**Fix:** Reconcile the pin and the comments, e.g., change Cargo.toml line 23 to `pkarr = { version = "5.0.4", …` (matching what `cargo tree` actually resolves to) or update the comments.

### IN-05: `sender_openssh_fingerprint_and_z32` in `render_receipts_table` returns `Result` despite verified input

**File:** `src/flow.rs:664`
**Issue:** Inside `render_receipts_table`, the call `sender_openssh_fingerprint_and_z32(&r.recipient_pubkey)?` can in principle fail (the function returns `Err(Error::SignatureInner)` on z32 parse failure), but `r` has already passed `verify_receipt`, which parsed the same z32 successfully (receipt.rs:105-106). The `?` is effectively unreachable, and if it were ever reached, returning `Error::SignatureInner` from the renderer would produce "signature verification failed" to the user during display — misleading.

**Fix:** Either unwrap with a clarifying `.expect("verified receipt has parseable recipient_pubkey")`, or change `sender_openssh_fingerprint_and_z32` to take a `&[u8; 32]` (already-parsed pubkey bytes) to make the infallibility type-enforced.

### IN-06: `--share-ref` audit-detail view emits double "UTC" suffix on `accepted_at` (surfaced by real-DHT UAT)

**File:** `src/flow.rs` (render_receipts_detail / audit-detail block)
**Issue:** Real-DHT UAT (2026-04-21, see `03-HUMAN-UAT.md` Test 1) observed the audit view rendering:

```
accepted_at:        2026-04-21 22:49 UTC UTC (2026-04-21 18:49 local)
```

The formatter `format_unix_as_iso_utc` already emits `... UTC` as part of its output (it's ISO-8601-with-UTC-suffix), and the audit-detail render path appends an additional `UTC` literal after it. The JSON view is unaffected (`"accepted_at": 1776811764` — integer unix seconds). The table view is unaffected (single `UTC` in the column header).

**Fix:** In the audit-detail render path, either drop the trailing `UTC` literal OR call a helper that emits the timestamp without the inline suffix. Recommended form:

```
accepted_at:        2026-04-21 22:49 UTC (2026-04-21 18:49 local)
```

**Severity:** cosmetic — does not affect parseability, signature verification, or JSON output. Caught only by human UAT because MockTransport tests assert on structured fields, not rendered strings.

---

_Reviewed: 2026-04-21T00:00:00Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
