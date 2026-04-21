---
phase: 03-signed-receipt-the-cipherpost-delta
verified: 2026-04-21T00:00:00Z
status: human_needed
score: 4/4 must-haves verified
overrides_applied: 0
human_verification:
  - test: "Real-DHT A→B→receipt round trip"
    expected: "A generates identity, sends to B via Mainline DHT, B accepts, B's stderr shows 'Publishing receipt to DHT...', A runs `cipherpost receipts --from <z32_b>` and sees a table row whose share_ref matches the URI, purpose matches, recipient_fp is B's OpenSSH fingerprint. `--share-ref` returns the 10-field audit-detail view. `--json` returns valid pretty-printed JSON."
    why_human: "MockTransport tests exercise the full flow code path but cannot reach Mainline DHT. RCPT-03 requires an actual network round-trip across two real identities to prove the published-SignedPacket is resolvable by a third party using only the recipient's public z-base-32."
---

# Phase 3: Signed Receipt (the Cipherpost Delta) Verification Report

**Phase Goal:** Deliver the signed-receipt feature that differentiates cipherpost from cclink — a Receipt signed by the recipient's Ed25519 key, published under the recipient's PKARR key at DNS label `_cprcpt-<share_ref>` via resolve-merge-republish (preserving coexisting TXT records), and independently fetchable and verifiable by the sender via `cipherpost receipts`.
**Verified:** 2026-04-21
**Status:** human_needed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | After acceptance in `cipherpost receive`, a Receipt is signed by the recipient's Ed25519 key and published under the recipient's PKARR key at `_cprcpt-<share_ref>`; tampering between outer verify and acceptance causes zero receipts to be published (verified via MockTransport) | ✓ VERIFIED | `src/flow.rs` step 13 (lines 479–549): `receipt::sign_receipt` + `transport.publish_receipt` called after step 12 only; `tests/phase3_tamper_zero_receipts.rs` asserts `resolve_all_cprcpt(b_z32)` returns `Err(NotFound)` on garbage-blob injection; `tests/phase3_end_to_end_a_sends_b_receipt.rs` asserts receipt exists under B's key after clean accept. All pass under `cargo test --features mock`. |
| 2 | `cipherpost receipts --from <recipient-pubkey>` resolves + filters + verifies + prints structured summary; `--share-ref <ref>` returns only that receipt | ✓ VERIFIED | `run_receipts` in `src/flow.rs:568` implements full D-OUT-03 taxonomy (resolves via `transport.resolve_all_cprcpt`, verifies via `receipt::verify_receipt`, filter-after-verify per Pitfall #6, renders table or audit-detail view). CLI dispatch in `src/main.rs:222` wires `--from`, `--share-ref`, `--json` without Identity/passphrase load. `tests/phase3_share_ref_filter.rs` exercises both `Some(filter)` and `None` paths and both return `Ok`. |
| 3 | `publish_receipt` under a recipient key holding an outgoing share record preserves both (coexistence) | ✓ VERIFIED | `DhtTransport::publish_receipt` uses resolve-merge-republish (`resolve_most_recent` → iterate `all_resource_records()` → `builder.record(rr.clone())` skipping same-label → `builder.txt(new_name, new_txt, 300)` → `sign` → `publish(cas)`). `tests/phase3_coexistence_b_self_share_and_receipt.rs` asserts `resolve_all_txt(b_z32).len() == 2` (one `_cipherpost` + one `_cprcpt-*`) after B establishes a self-share then accepts an incoming share. `tests/phase3_mock_publish_receipt_coexistence.rs` tests direct MockTransport three-scenario coexistence. All pass. |
| 4 | Two-identity E2E integration test asserts A can fetch and verify B's receipt using only B's public PKARR key; fetch works even if A holds their own outgoing share under A's key | ✓ VERIFIED | `tests/phase3_end_to_end_a_sends_b_receipt.rs`: A sends to B, B accepts via `AutoConfirmPrompter`, receipt verified via `verify_receipt` + field assertions (`sender_pubkey == a_z32`, `recipient_pubkey == b_z32`, `ciphertext_hash == sha256(resolved_ciphertext)`), `run_receipts(&transport, &b_z32, None, false)` returns `Ok`. `tests/phase3_share_ref_filter.rs`: A's `_cipherpost` entry under A's key coexists throughout both receipts fetches. |

**Score:** 4/4 truths verified

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `src/receipt.rs` | Receipt wire schema + sign/verify + nonce_hex | ✓ VERIFIED | 134 lines; `pub struct Receipt` (10 alphabetical fields), `pub struct ReceiptSignable` (9 fields), `impl From<&Receipt> for ReceiptSignable`, `pub fn sign_receipt`, `pub fn verify_receipt` (5-step, round-trip-reserialize guard), `pub fn nonce_hex`. Reuses `crate::crypto::jcs_serialize`; no local `jcs()` copy; no new Error variants. |
| `tests/phase3_receipt_sign_verify.rs` | 6 unit tests for sign/verify round-trip + tamper rejection + D-16 Display | ✓ VERIFIED | All 6 tests pass: `sign_verify_round_trip`, `self_receipt_round_trip`, `tampered_nonce_fails_verify`, `tampered_ciphertext_hash_fails_verify`, `tampered_purpose_fails_verify`, `nonce_hex_shape`. Every tampered-* test asserts `matches!(err, Error::SignatureInner)` AND `format!("{}", err) == "signature verification failed"`. |
| `tests/phase3_receipt_canonical_form.rs` | JCS byte fixture test | ✓ VERIFIED | `receipt_signable_bytes_match_committed_fixture` passes; `regenerate_fixture` (ignored) present. |
| `tests/fixtures/receipt_signable.bin` | Committed JCS bytes | ✓ VERIFIED | 424 bytes, exists at `tests/fixtures/receipt_signable.bin`. |
| `src/transport.rs` | Upgraded `DhtTransport::publish_receipt` + `resolve_all_cprcpt` trait method | ✓ VERIFIED | 4-method `Transport` trait; DhtTransport uses `all_resource_records()` merge; `matches_receipt_label` helper handles both pkarr name forms; `resolve_all_cprcpt` on both DhtTransport and MockTransport returns `Err(NotFound)` on empty. |
| `src/flow.rs` | run_receive step 13 + run_receipts + LedgerEntry.receipt_published_at + append_ledger_entry_with_receipt | ✓ VERIFIED | Step 13 at lines 479–549, no `?`-propagation on `publish_receipt`. `run_receipts` at line 568, filter-after-verify. `LedgerEntry.receipt_published_at: Option<&'a str>` with `skip_serializing_if = "Option::is_none"`. `append_ledger_entry_with_receipt` accepts pre-computed hashes (Pitfall #4). |
| `src/cli.rs` | Receipts variant with `--json` flag | ✓ VERIFIED | `json: bool` field present at line 93. |
| `src/main.rs` | Receive dispatch passes `&kp`; Receipts dispatch wires `run_receipts` without Identity | ✓ VERIFIED | Receive arm reconstructs `kp = pkarr::Keypair::from_secret_key(&seed_bytes)` and passes `&kp` to `run_receive`. Receipts arm destructures `{ from, share_ref, json }` and calls `run_receipts`; no `resolve_passphrase` or `identity::load` in the Receipts arm. |
| `tests/phase3_end_to_end_a_sends_b_receipt.rs` | D-IT-01 test 1 — two-identity round trip | ✓ VERIFIED | 1 test passing. Asserts receipt under B's key, `verify_receipt` ok, field values correct, `ciphertext_hash == sha256(resolved_ciphertext)`, `run_receipts` returns Ok. |
| `tests/phase3_coexistence_b_self_share_and_receipt.rs` | D-IT-01 test 2 — ROADMAP SC3 coexistence | ✓ VERIFIED | 1 test passing. Asserts 2 entries under B after self-share + incoming accept. |
| `tests/phase3_share_ref_filter.rs` | D-IT-01 test 3 — --share-ref filter + A's own share | ✓ VERIFIED | 1 test passing. Two share_ref cycles, both filters work, A's `_cipherpost` entry survives. |
| `tests/phase3_tamper_zero_receipts.rs` | ROADMAP SC1 invariant — tamper produces zero receipts | ✓ VERIFIED | 1 test passing. `resolve_all_cprcpt(b_z32)` returns `Err(NotFound)` after garbage-blob inject. |
| `.planning/phases/03-signed-receipt-the-cipherpost-delta/03-HUMAN-UAT.md` | D-IT-02 real-DHT UAT script | ✓ VERIFIED | File exists with status: pending, concrete commands, expected outputs, result: pending rows ready for execution. |

### Key Link Verification

| From | To | Via | Status | Details |
|------|----|-----|--------|---------|
| `src/flow.rs::run_receive step 13` | `src/receipt.rs::sign_receipt` | Receipt construction + signing | ✓ WIRED | `crate::receipt::sign_receipt(&signable, keypair)` at flow.rs:511 |
| `src/flow.rs::run_receive step 13` | `src/transport.rs::Transport::publish_receipt` | publish under recipient's keypair | ✓ WIRED | `transport.publish_receipt(keypair, &record.share_ref, &receipt_json)` at flow.rs:527; called via trait, no downcast |
| `src/flow.rs::run_receipts` | `src/transport.rs::Transport::resolve_all_cprcpt` | fetch all `_cprcpt-*` TXT bodies | ✓ WIRED | `transport.resolve_all_cprcpt(from_z32)?` at flow.rs:574 |
| `src/flow.rs::run_receipts` | `src/receipt.rs::verify_receipt` | per-receipt Ed25519 sig verify | ✓ WIRED | `crate::receipt::verify_receipt(&parsed).is_err()` at flow.rs:584 |
| `src/main.rs::Command::Receipts` | `src/flow.rs::run_receipts` | CLI dispatch | ✓ WIRED | `cipherpost::flow::run_receipts(transport.as_ref(), &from, share_ref.as_deref(), json)?` at main.rs:240 |
| `src/receipt.rs::sign_receipt` | `src/crypto.rs::jcs_serialize` | canonical JSON serialization | ✓ WIRED | `crate::crypto::jcs_serialize(signable)` in receipt.rs:90 |
| `src/receipt.rs::verify_receipt` | `src/error.rs::Error::SignatureInner` | D-16 unified sig-fail variant | ✓ WIRED | All error returns in verify_receipt use `Error::SignatureInner` or `Error::SignatureCanonicalMismatch` |
| `src/transport.rs::DhtTransport::publish_receipt` | `pkarr::ClientBlocking::resolve_most_recent` | resolve half of resolve-merge-republish | ✓ WIRED | `self.client.resolve_most_recent(&pk)` at transport.rs:164 |
| `src/transport.rs::DhtTransport::publish_receipt` | `pkarr::SignedPacketBuilder::record` | re-add each existing resource record | ✓ WIRED | `builder.record(rr.clone())` at transport.rs:178 |
| `LedgerEntry` | `append_ledger_entry_with_receipt` | second ledger row with receipt_published_at | ✓ WIRED | Called at flow.rs:533 on Ok arm of publish_receipt match |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
|----------|---------------|--------|--------------------|--------|
| `run_receipts` (render path) | `valid: Vec<Receipt>` | `transport.resolve_all_cprcpt(from_z32)` → `verify_receipt` | Yes — MockTransport tests demonstrate real receipts signed by real keypairs flow end-to-end | ✓ FLOWING |
| `run_receive` step 13 (receipt publish) | `receipt_json: String` | `crate::receipt::sign_receipt(&signable, keypair)` | Yes — E2E test verifies `ciphertext_hash == sha256(resolved_ciphertext)` proving hashes come from real ciphertext bytes | ✓ FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| `cargo test --features mock` full suite | `cargo test --features mock` | 0 failures, 0 errors, 3 ignored tests across all harnesses | ✓ PASS |
| Phase 3 receipt sign/verify tests (6) | Observed in test output | 6 passed, 0 failed | ✓ PASS |
| Phase 3 end-to-end (1) | Observed in test output | 1 passed | ✓ PASS |
| Phase 3 coexistence (1) | Observed in test output | 1 passed | ✓ PASS |
| Phase 3 share_ref_filter (1) | Observed in test output | 1 passed (8s, includes 1s sleep) | ✓ PASS |
| Phase 3 tamper-zero-receipts (1) | Observed in test output | 1 passed | ✓ PASS |
| Phase 3 mock coexistence (3) | Observed in test output | 3 passed | ✓ PASS |
| Phase 3 canonical form fixture (1+ignored) | Observed in test output | 1 passed, 1 ignored | ✓ PASS |
| No `?`-propagation on publish_receipt | `grep "transport\.publish_receipt.*\?" src/flow.rs` | 0 matches | ✓ PASS |

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|------------|-------------|--------|----------|
| TRANS-03 | 03-02, 03-03, 03-04 | `publish_receipt` resolves existing SignedPacket, merges receipt TXT, re-signs with recipient key, republishes | ✓ SATISFIED | `DhtTransport::publish_receipt` body in transport.rs:141–202 implements full resolve-merge-republish; coexistence test passes |
| RCPT-01 | 03-01, 03-03, 03-04 | Receipt constructed + signed by recipient Ed25519 + published via `publish_receipt` under recipient's PKARR key | ✓ SATISFIED | `src/receipt.rs` + `run_receive` step 13 + E2E test asserting receipt at `_cprcpt-<share_ref>` under B's key |
| RCPT-02 | 03-03, 03-04 | `cipherpost receipts --from <pubkey> [--share-ref <ref>]` resolves + verifies + prints structured summary | ✓ SATISFIED | `run_receipts` + CLI dispatch + `phase3_share_ref_filter` test exercising both filter paths |
| RCPT-03 | 03-04 | Verified E2E integration test: A sends to B, B accepts, A fetches+verifies B's receipt | ✓ SATISFIED (code-level) | `phase3_end_to_end_a_sends_b_receipt.rs` passes under MockTransport; real-DHT portion requires human UAT (see below) |

**Note on RCPT-03:** The requirement says "verified end-to-end integration test" — the MockTransport test satisfies this at the code level. The ROADMAP SC4 text states "Two-identity E2E integration test asserts A can fetch and verify B's receipt using only B's public PKARR key" which the `phase3_end_to_end_a_sends_b_receipt.rs` test fully satisfies. The real-DHT round-trip is the UAT item below, not a gap.

### Anti-Patterns Found

| File | Line | Pattern | Severity | Impact |
|------|------|---------|----------|--------|
| None found | — | — | — | — |

**Anti-pattern scan results:**
- No `TODO/FIXME/PLACEHOLDER` in any Phase 3 production source files (`src/receipt.rs`, `src/transport.rs`, `src/flow.rs`, `src/main.rs`, `src/cli.rs`)
- No `return null`, `return {}`, `return []` in new flow.rs functions (confirmed by code inspection)
- `transport.publish_receipt` is in a `match` expression with no `?`-propagation (D-SEQ-02)
- No direct `chacha20poly1305` or `tokio::` imports in Phase 3 files
- No new `Error` variants introduced (D-RS-07 invariant)
- No local `fn jcs()` copy in receipt.rs (reuses `crate::crypto::jcs_serialize`)
- No new HKDF call-sites in receipt.rs

Pre-existing lint in `tests/debug_leak_scan.rs` was fixed in Plan 03-04 (clippy::format_collect). Not introduced by Phase 3.

### Human Verification Required

#### 1. Real-DHT A→B→receipt round trip

**Test:** Follow `03-HUMAN-UAT.md` Section 1 using the release binary. In Shell A: generate identity A, run `cipherpost send --share <z32_b>` with a payload on stdin. In Shell B: generate identity B, run `cipherpost receive <URI>`, accept with z32_a. Verify B's stderr contains `Publishing receipt to DHT...`. Then from Shell A: `cipherpost receipts --from <z32_b>` to list receipts; `cipherpost receipts --from <z32_b> --share-ref <hex>` for audit-detail view; `cipherpost receipts --from <z32_b> --json` for JSON output.

**Expected:**
- B's stdout receives the original payload bytes after acceptance
- B's stderr includes `Publishing receipt to DHT...` (TRANS-05 trace)
- A's `receipts --from <z32_b>` prints a table row with share_ref prefix matching the URI, purpose field, and B's OpenSSH fingerprint as `recipient_fp`
- A's `receipts --from <z32_b> --share-ref <full-hex>` prints the 10-field audit-detail view
- A's `receipts --from <z32_b> --json` emits valid pretty-printed JSON array on stdout
- Entire flow exits 0 throughout

**Why human:** MockTransport tests prove all code paths execute correctly, including that receipts are signed, serialized, and stored. Real-DHT testing is required to confirm that (a) the `DhtTransport::publish_receipt` resolve-merge-republish survives a real Mainline DHT publish/resolve cycle, (b) the receipt TXT record is resolvable from an independent DHT node (not just locally), and (c) the `--from <z32>` flag correctly resolves a real PKARR packet published under a live key.

### Gaps Summary

No gaps. All four ROADMAP success criteria have passing automated tests (MockTransport). The sole item requiring human action is the real-DHT round-trip UAT per `03-HUMAN-UAT.md`, which is by design a manual verification step (not a code gap).

---

_Verified: 2026-04-21_
_Verifier: Claude (gsd-verifier)_
