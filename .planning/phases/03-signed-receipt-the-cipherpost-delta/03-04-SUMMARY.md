---
phase: 03-signed-receipt-the-cipherpost-delta
plan: "04"
subsystem: integration-tests
tags:
  - integration-test
  - mock-transport
  - end-to-end
  - human-uat
  - rust
dependency_graph:
  requires:
    - src/receipt.rs (verify_receipt, Receipt — Plan 03-01)
    - src/transport.rs (MockTransport, resolve_all_txt, resolve_all_cprcpt — Plan 03-02)
    - src/flow.rs (run_send, run_receive, run_receipts, AutoConfirmPrompter — Plans 03-01..03-03)
    - src/record.rs (sign_record, share_ref_from_bytes, OuterRecord, OuterRecordSignable — Plan 03-01)
    - src/lib.rs (DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX, PROTOCOL_VERSION, ShareUri)
  provides:
    - tests/phase3_end_to_end_a_sends_b_receipt.rs (D-IT-01 test 1 — RCPT-01+02+03 happy path)
    - tests/phase3_coexistence_b_self_share_and_receipt.rs (D-IT-01 test 2 — ROADMAP SC3)
    - tests/phase3_share_ref_filter.rs (D-IT-01 test 3 — ROADMAP SC4)
    - tests/phase3_tamper_zero_receipts.rs (ROADMAP SC1 invariant)
    - .planning/phases/03-signed-receipt-the-cipherpost-delta/03-HUMAN-UAT.md (D-IT-02 real-DHT script)
  affects:
    - tests/phase2_idempotent_re_receive.rs (clippy fix — manual_range_contains)
    - tests/debug_leak_scan.rs (clippy fix — format_collect)
tech_stack:
  added: []
  patterns:
    - "interleaved send-accept-send-accept to handle MockTransport single-slot _cipherpost semantic"
    - "hand-built OuterRecord with garbage blob for SC1 tamper invariant (sign_record over garbage, fails at age-decrypt)"
    - "resolve_all_txt inspection for white-box coexistence assertion"
    - "resolve_all_cprcpt expects Err(NotFound) to prove zero receipts after tamper"
key_files:
  created:
    - tests/phase3_end_to_end_a_sends_b_receipt.rs
    - tests/phase3_coexistence_b_self_share_and_receipt.rs
    - tests/phase3_share_ref_filter.rs
    - tests/phase3_tamper_zero_receipts.rs
    - .planning/phases/03-signed-receipt-the-cipherpost-delta/03-HUMAN-UAT.md
  modified:
    - Cargo.toml (4 new [[test]] entries with required-features = ["mock"])
    - tests/phase2_idempotent_re_receive.rs (clippy fix)
    - tests/debug_leak_scan.rs (clippy fix)
decisions:
  - "MaterialSource::Bytes used in all tests (not File) — run_send returns String; ShareUri::parse() called to get ShareUri struct"
  - "Tamper approach: Option B (hand-built OuterRecord with garbage blob, valid inner sig) — cleanest, no new MockTransport surface; fails at step 6 age-decrypt"
  - "Clippy fixes applied to phase2_idempotent_re_receive and debug_leak_scan — pre-existing warnings blocking verification gate"
  - "03-HUMAN-UAT.md UAT script verified against actual CLI: --from, --share-ref, --json flags confirmed via cipherpost receipts --help"
metrics:
  duration_minutes: 8
  completed_date: "2026-04-21"
  tasks_completed: 3
  tasks_total: 4
  files_created: 5
  files_modified: 3
---

# Phase 3 Plan 04: Integration Tests + HUMAN-UAT Script Summary

**One-liner:** Four MockTransport integration tests prove Phase 3 end-to-end: D-IT-01 happy-path (RCPT-01+02+03), ROADMAP SC3 coexistence, ROADMAP SC4 filter+own-share, and SC1 tamper-zero-receipts invariant; 03-HUMAN-UAT.md ships the real-DHT verification script.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Create phase3_end_to_end_a_sends_b_receipt.rs — D-IT-01 test 1 | 22e36e1 | tests/phase3_end_to_end_a_sends_b_receipt.rs, Cargo.toml |
| 2 | Create coexistence + share_ref_filter integration tests | 32af862 | tests/phase3_coexistence_b_self_share_and_receipt.rs, tests/phase3_share_ref_filter.rs, Cargo.toml |
| 3 | Create tamper-zero-receipts test + 03-HUMAN-UAT.md + clippy fixes | ba39819 | tests/phase3_tamper_zero_receipts.rs, 03-HUMAN-UAT.md, Cargo.toml, 2 clippy fixes |
| 4 | Human checkpoint — all tests green + UAT ready | (pending) | — |

## Test Results

All Phase 3 tests green under `cargo test --features mock`:

| Test file | Tests | Result |
|-----------|-------|--------|
| phase3_receipt_sign_verify | 6 | ok |
| phase3_receipt_canonical_form | 1 passed, 1 ignored | ok |
| phase3_mock_publish_receipt_coexistence | 3 | ok |
| phase3_end_to_end_a_sends_b_receipt | 1 | ok |
| phase3_coexistence_b_self_share_and_receipt | 1 | ok |
| phase3_share_ref_filter | 1 | ok |
| phase3_tamper_zero_receipts | 1 | ok |

Full suite (`cargo test --features mock`): 0 failures, 0 errors.
Clippy (`cargo clippy --all-targets --features mock -- -D warnings`): exit 0.

## ROADMAP SC Coverage

| SC | Description | Test |
|----|-------------|------|
| SC1 | Tampered ciphertext → zero receipts | phase3_tamper_zero_receipts.rs |
| SC2 | receipts filter + verify + structured output | phase3_share_ref_filter.rs + run_receipts |
| SC3 | Coexistence under recipient's key | phase3_coexistence_b_self_share_and_receipt.rs |
| SC4 | Two-identity round trip; A's own share preserved | phase3_end_to_end_a_sends_b_receipt.rs + phase3_share_ref_filter.rs |

## Design Notes

**Task 1 adaptation:** The plan's template used `MaterialSource::File` and showed `run_send` returning `ShareUri` directly. The actual codebase has `MaterialSource::Bytes` (test-only) and `run_send` returns `String`. All tests use `MaterialSource::Bytes` and call `ShareUri::parse()` on the returned string.

**Task 2 (share_ref_filter) interleaving:** MockTransport's `_cipherpost` slot is single-valued per key (each `publish` replaces it). The test uses interleaved send-accept-send-accept ordering so B can resolve each share before A overwrites the `_cipherpost` entry. Receipts under B's key accumulate per share_ref because `publish_receipt` retains existing labels.

**Task 3 (tamper):** Option B chosen — build a structurally valid `OuterRecordSignable` + `OuterRecord` with garbage `blob`, sign it with `sign_record`, publish via `MockTransport::publish` (which skips outer crypto in mock mode). `run_receive` fails at step 6 (age-decrypt) because the blob is not valid age ciphertext. Step 13 is never reached. `resolve_all_cprcpt(b_z32)` returns `Err(NotFound)`.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] MaterialSource variant mismatch**
- **Found during:** Task 1
- **Issue:** Plan template used `MaterialSource::File(path)` and helper `write_material_file`. The codebase has `MaterialSource::Bytes(Vec<u8>)` as the test-only variant (no `File`-based test helper needed).
- **Fix:** All tests use `MaterialSource::Bytes(bytes.to_vec())` directly. No file helpers needed.
- **Files modified:** tests/phase3_end_to_end_a_sends_b_receipt.rs, tests/phase3_coexistence_b_self_share_and_receipt.rs, tests/phase3_share_ref_filter.rs
- **Commit:** 22e36e1, 32af862

**2. [Rule 1 - Bug] run_send return type mismatch**
- **Found during:** Task 1
- **Issue:** Plan template cast `run_send(...)` result directly to `ShareUri`. Actual signature is `Result<String, Error>`. `ShareUri::parse` must be called on the returned string.
- **Fix:** All tests call `ShareUri::parse(&uri_str).expect(...)`.
- **Files modified:** All 4 integration test files
- **Commit:** 22e36e1, 32af862, ba39819

**3. [Rule 1 - Bug] phase2_idempotent_re_receive.rs clippy::manual_range_contains**
- **Found during:** Task 3 — clippy gate verification
- **Issue:** `lines_after_first >= 1 && lines_after_first <= 2` triggers `manual_range_contains` lint under `-D warnings`.
- **Fix:** Replaced with `(1..=2).contains(&lines_after_first)`.
- **Files modified:** tests/phase2_idempotent_re_receive.rs
- **Commit:** ba39819

**4. [Rule 1 - Bug] debug_leak_scan.rs clippy::format_collect**
- **Found during:** Task 3 — clippy gate verification
- **Issue:** `.map(|b| format!("{:02x}", b)).collect::<String>()` triggers `format_collect` lint under `-D warnings`.
- **Fix:** Replaced with `fold(String::new(), |mut s, b| { write!(s, "{:02x}", b); s })`.
- **Files modified:** tests/debug_leak_scan.rs
- **Commit:** ba39819

## Known Stubs

None. All four integration tests exercise real production code paths end-to-end via MockTransport.

## Threat Flags

No new trust boundaries introduced beyond those in the plan's threat model. All T-03-04-01..05 mitigations verified:
- T-03-04-01: phase3_tamper_zero_receipts.rs injects garbage-blob OuterRecord and asserts zero _cprcpt-* entries
- T-03-04-02: phase3_end_to_end_a_sends_b_receipt.rs asserts verify_receipt + ciphertext_hash independently
- T-03-04-03: phase3_share_ref_filter.rs uses interleaved ordering per MockTransport single-slot semantic
- T-03-04-04: 03-HUMAN-UAT.md uses mktemp -d HOMEs (throwaway ephemeral identities)
- T-03-04-05: all four tests use #[serial] + TempDir per identity

## Self-Check: PASSED

- tests/phase3_end_to_end_a_sends_b_receipt.rs: FOUND
- tests/phase3_coexistence_b_self_share_and_receipt.rs: FOUND
- tests/phase3_share_ref_filter.rs: FOUND
- tests/phase3_tamper_zero_receipts.rs: FOUND
- .planning/phases/03-signed-receipt-the-cipherpost-delta/03-HUMAN-UAT.md: FOUND
- Commit 22e36e1 (feat(03-04): add phase3_end_to_end_a_sends_b_receipt.rs): FOUND
- Commit 32af862 (feat(03-04): add coexistence + share_ref_filter integration tests): FOUND
- Commit ba39819 (feat(03-04): add tamper-zero-receipts test + 03-HUMAN-UAT.md): FOUND
- cargo test --features mock — 0 failures: CONFIRMED
- cargo clippy --all-targets --features mock -- -D warnings — exit 0: CONFIRMED
- 03-HUMAN-UAT.md has status: pending and 2 test sections with result: pending: CONFIRMED
