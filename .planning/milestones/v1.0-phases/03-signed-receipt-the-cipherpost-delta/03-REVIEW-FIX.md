---
phase: 03-signed-receipt-the-cipherpost-delta
fixed_at: 2026-04-21T00:00:00Z
review_path: .planning/phases/03-signed-receipt-the-cipherpost-delta/03-REVIEW.md
iteration: 1
findings_in_scope: 3
fixed: 3
skipped: 0
status: all_fixed
---

# Phase 3: Code Review Fix Report

**Fixed at:** 2026-04-21T00:00:00Z
**Source review:** `.planning/phases/03-signed-receipt-the-cipherpost-delta/03-REVIEW.md`
**Iteration:** 1

**Summary:**
- Findings in scope (critical + warning): 3
- Fixed: 3
- Skipped: 0

No Critical findings existed in REVIEW.md. All three Warning findings were fixed.
Info findings (IN-01 through IN-06) are out of scope for this pass per
`fix_scope: critical_warning`.

## Fixed Issues

### WR-01: `run_receive` step 13 violates D-SEQ-02 "warn + degrade, exit 0" on pre-publish failures

**Files modified:** `src/flow.rs`
**Commit:** `be23ba9`
**Applied fix:** Replaced the bare `{ ... }` block at step 13 with an
inline IIFE closure `let publish_outcome: Result<(), Error> = (|| { ... })();`
so every `?`-propagation inside (now_unix_seconds, sign_receipt → JCS
serialize, serde_json::to_string, transport.publish_receipt, iso8601_utc_now,
append_ledger_entry_with_receipt) is contained. A single
`if let Err(e) = publish_outcome` outside the closure emits the
`eprintln!("receipt publish failed: {}", user_message(&e))` warn and
`run_receive` still returns `Ok(())`. Behaviour change: a pre-publish
failure (clock pre-epoch, serde_json failure, sign_receipt failure) now
warn+degrades instead of surfacing an Err from `run_receive`. The original
inner distinction between "publish failed" and "ledger update after
publish failed" was collapsed into the single warn — this is intentional
per D-SEQ-02 (core-value delivery is complete at step 12; step 13 is
entirely best-effort). The comment block above step 13 was updated to
reflect the new shape. All 13 phase3 integration tests still pass (with
`--features mock`).

### WR-02: Step-6 base64 decode error maps to `SignatureCanonicalMismatch` without comment

**Files modified:** `src/flow.rs`
**Commit:** `2a55427`
**Applied fix:** Added a 9-line comment immediately before the
`.map_err(|_| Error::SignatureCanonicalMismatch)?` call at flow.rs step 6.
The comment cites D-16 oracle hygiene, explains that the inner signature
(verified in step 2–3 of the transport resolve) signs over the base64
string (not decoded bytes), notes that a malformed blob reaching this
point was introduced by either a valid-signing sender or post-verify
tampering, and confirms both paths must funnel through the same unified
user-facing "signature verification failed" message so no test
discriminates the two. No behaviour change.

### WR-03: Receipt `sender_pubkey` is recipient-attested but undocumented in the struct

**Files modified:** `src/receipt.rs`
**Commit:** `6b40762`
**Applied fix:** Added a 6-line doc comment on
`Receipt.sender_pubkey` explaining: (a) the field is the recipient's
attestation of who they received from; (b) it is NOT signed by the
sender — only the recipient signs the receipt; (c) provenance requires
the composition "receipt found under `recipient_pubkey`'s DHT packet +
signature verifying with that pubkey + claimed sender = Y" per D-RS-07;
(d) an attacker controlling their own z32 can publish a receipt claiming
any `sender_pubkey` value, so this field alone is not authenticated.
Doc-only change; no behaviour change. Compiles clean; no test changes
required.

## Skipped Issues

None.

## Verification

- `cargo check --lib --all-targets --features mock` — clean (no warnings, no errors).
- Phase 3 integration tests, all passing:
  - `phase3_end_to_end_a_sends_b_receipt` — 1/1 ok
  - `phase3_receipt_sign_verify` — 6/6 ok
  - `phase3_mock_publish_receipt_coexistence` — 3/3 ok
  - `phase3_coexistence_b_self_share_and_receipt` — 1/1 ok
  - `phase3_share_ref_filter` — 1/1 ok
  - `phase3_tamper_zero_receipts` — 1/1 ok
  - `phase3_receipt_canonical_form` — 1/1 ok (1 ignored: regenerate_fixture, as expected)
- Total: 13 phase3 tests pass after all three fixes applied.

Each fix was committed atomically in reverse-dependence order
(WR-03 doc-only → WR-02 comment-only → WR-01 semantic change),
with `cargo check --lib` gating each commit. WR-01 additionally gated
on the full phase3 integration suite passing.

---

_Fixed: 2026-04-21T00:00:00Z_
_Fixer: Claude (gsd-code-fixer)_
_Iteration: 1_
