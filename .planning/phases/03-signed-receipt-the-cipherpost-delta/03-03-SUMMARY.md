---
phase: 03-signed-receipt-the-cipherpost-delta
plan: "03"
subsystem: flow-orchestration
tags:
  - flow-orchestration
  - run_receive
  - run_receipts
  - cli-dispatch
  - rust
dependency_graph:
  requires:
    - src/receipt.rs (sign_receipt, verify_receipt, Receipt, ReceiptSignable, nonce_hex — Plan 03-01)
    - src/transport.rs (publish_receipt, resolve_all_cprcpt — Plan 03-02)
    - src/flow.rs (append_ledger_entry_with_receipt — Plan 03-02)
    - src/error.rs (user_message free fn)
    - src/lib.rs (PROTOCOL_VERSION)
  provides:
    - src/flow.rs (run_receive step 13, run_receipts, render_receipts_table, truncate_purpose)
    - src/main.rs (Receive arm keypair passthrough, Receipts dispatch)
    - src/cli.rs (Receipts --json flag)
  affects:
    - tests/phase2_*.rs (7 test files updated for new 6-arg run_receive signature)
tech_stack:
  added: []
  patterns:
    - "step-13 warn+degrade: match on transport.publish_receipt, Err → eprintln + fallthrough (D-SEQ-02)"
    - "run_receipts D-OUT-03 exit-code taxonomy via returned Error variants"
    - "filter-after-verify: retain applied after verify loop (Pitfall #6 / D-OUT-02)"
    - "control-char defense-in-depth: chars().filter(!is_control()) at display time"
key_files:
  created: []
  modified:
    - src/flow.rs
    - src/main.rs
    - src/cli.rs
    - tests/phase2_cli_declined_exit_7.rs
    - tests/phase2_expired_share.rs
    - tests/phase2_idempotent_re_receive.rs
    - tests/phase2_self_round_trip.rs
    - tests/phase2_share_round_trip.rs
    - tests/phase2_state_perms.rs
    - tests/phase2_tamper_aborts_before_decrypt.rs
decisions:
  - "user_message form: free fn crate::error::user_message(&e) (found at src/error.rs:103)"
  - "Step 13 inserted at flow.rs lines 479-549, before trailing Ok(())"
  - "run_receipts, render_receipts_table, truncate_purpose inserted at flow.rs lines 554-693, before material_type_string"
  - "phase2_idempotent_re_receive ledger assertion updated from exact-1 to 1-or-2 lines (D-SEQ-05: step 13 appends success row)"
  - "Two clippy lints fixed: doc_lazy_continuation in run_receipts docstring; print_literal in render_receipts_table header"
metrics:
  duration_minutes: 12
  completed_date: "2026-04-21"
  tasks_completed: 3
  tasks_total: 3
  files_created: 0
  files_modified: 10
---

# Phase 3 Plan 03: Flow Wiring — run_receive Step 13 + run_receipts + CLI Dispatch Summary

**One-liner:** Wired Receipt primitives into end-to-end flow: run_receive extended to 6-arg signature with step 13 best-effort publish_receipt (warn+degrade on failure), run_receipts implemented with D-OUT-03 exit-code taxonomy + filter-after-verify + table/JSON render, and cipherpost receipts dispatch wired without passphrase prompt.

## Tasks Completed

| Task | Description | Commit | Files |
|------|-------------|--------|-------|
| 1 | Extend run_receive: 6-arg signature + step 13 + update 7 Phase 2 test files | d9445f2 | src/flow.rs, 7 test files |
| 2 | Add --json to cli.rs Receipts + wire main.rs Receive keypair + Receipts dispatch | b9fe9d7 | src/cli.rs, src/main.rs |
| 3 | Implement run_receipts + render_receipts_table + truncate_purpose (in flow.rs) | d9445f2 | src/flow.rs (committed with Task 1) |

Note: Tasks 1 and 3 both modified src/flow.rs in the same editing session, so they were committed together in d9445f2. The commit message covers Task 1 semantics; run_receipts was added in the same diff.

## Sub-step 1.2: user_message form chosen

`crate::error::user_message(&e)` — free function at `src/error.rs:103`:
```rust
pub fn user_message(err: &Error) -> String { ... }
```
Used in both eprintlns in step 13:
- `eprintln!("ledger update after receipt publish failed: {}", crate::error::user_message(&e));`
- `eprintln!("receipt publish failed: {}", crate::error::user_message(&e));`

## Step 13 Location

Inserted at `src/flow.rs` lines 479–549, between the existing step 12 `append_ledger_entry` call and the function's trailing `Ok(())`.

```
line 469: // STEP 12: sentinel FIRST, ledger SECOND
line 470-477: create_sentinel + append_ledger_entry
line 479: // STEP 13: publish_receipt — best-effort, warn+degrade on failure
line 493-549: { use sha2...; build signable/receipt, match publish_receipt }
line 551: Ok(())
```

## run_receipts (src/flow.rs lines 568–636)

```rust
pub fn run_receipts(
    transport: &dyn Transport,
    from_z32: &str,
    share_ref_filter: Option<&str>,
    json_mode: bool,
) -> Result<(), Error> {
    let candidate_jsons = transport.resolve_all_cprcpt(from_z32)?;
    let mut valid: Vec<crate::receipt::Receipt> = Vec::new();
    let mut malformed = 0usize;
    let mut invalid_sig = 0usize;
    for raw in &candidate_jsons {
        let parsed: crate::receipt::Receipt = match serde_json::from_str(raw) {
            Ok(r) => r,
            Err(_) => { malformed += 1; continue; }
        };
        if crate::receipt::verify_receipt(&parsed).is_err() {
            invalid_sig += 1;
            continue;
        }
        valid.push(parsed);
    }
    // summary on stderr (CLI-01)
    let mut summary = format!("fetched {} receipt(s); {} valid", candidate_jsons.len(), valid.len());
    if malformed > 0 { summary.push_str(&format!(", {} malformed", malformed)); }
    if invalid_sig > 0 { summary.push_str(&format!(", {} invalid-signature", invalid_sig)); }
    eprintln!("{}", summary);
    // D-OUT-02: filter AFTER verify
    if let Some(filter) = share_ref_filter { valid.retain(|r| r.share_ref == filter); }
    // D-OUT-03 exit-code taxonomy
    if valid.is_empty() {
        if invalid_sig > 0 { return Err(Error::SignatureInner); }
        if malformed > 0 { return Err(Error::Config("all receipts malformed".into())); }
        return Err(Error::NotFound);
    }
    // render
    if json_mode {
        let out = serde_json::to_string_pretty(&valid)...;
        println!("{}", out);
    } else {
        let audit_detail = share_ref_filter.is_some() && valid.len() == 1;
        render_receipts_table(&valid, audit_detail)?;
    }
    Ok(())
}
```

## render_receipts_table (src/flow.rs lines 637–677)

10-field audit-detail view when `audit_detail=true` (single result + filter given). 4-column table (share_ref_short/16, accepted_at UTC, purpose/40, recipient_fp) otherwise.

## truncate_purpose (src/flow.rs lines 678–693)

Strips control chars, truncates by char count (not bytes) to `max` with `…` suffix.

## Phase 2 Test Call Sites Updated to 6-arg run_receive

| File | Line (before) | Change |
|------|---------------|--------|
| tests/phase2_cli_declined_exit_7.rs:49 | `run_receive(&id, &transport, &uri, ...)` | Added `&kp` as 3rd arg |
| tests/phase2_expired_share.rs:62 | `run_receive(&id, &transport, &uri, ...)` | Added `&kp` as 3rd arg |
| tests/phase2_idempotent_re_receive.rs:41 | `run_receive(&id, &transport, &uri, ...)` | Added `&kp` as 3rd arg |
| tests/phase2_idempotent_re_receive.rs:59 | `run_receive(&id, &transport, &uri, ...)` | Added `&kp` as 3rd arg |
| tests/phase2_self_round_trip.rs:50 | `run_receive(&id, &transport, &uri, ...)` | Added `&kp` as 3rd arg |
| tests/phase2_share_round_trip.rs:83 | `run_receive(&id_b, &transport, &uri, ...)` | Added `&kp_b` as 3rd arg; renamed `_kp_b` → `kp_b` |
| tests/phase2_share_round_trip.rs:92 | `run_receive(&id_c, &transport, &uri, ...)` | Added `&kp_c` as 3rd arg; renamed `_kp_c` → `kp_c` |
| tests/phase2_state_perms.rs:39 | `run_receive(&id, &transport, &uri, ...)` | Added `&kp` as 3rd arg |
| tests/phase2_tamper_aborts_before_decrypt.rs:62 | `run_receive(&id, &transport, &uri, ...)` | Added `&kp` as 3rd arg |

## Test Results (cargo test --features mock)

Pre-plan test count: all passing (from 03-02-SUMMARY).
Post-plan test count: all passing — 0 failures.

All test suites: `test result: ok. N passed; 0 failed` across all harnesses.

Key suites:
- Phase 2 round-trip tests (self, share, idempotent, state perms, tamper, expired, declined): all pass
- Phase 3 receipt sign/verify (6 tests): all pass
- Phase 3 canonical form fixture: 1 passed, 1 ignored
- Phase 3 mock coexistence (3 tests): all pass

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] phase2_idempotent_re_receive ledger line count assertion**
- **Found during:** Task 1 — after adding step 13 which appends a second ledger row on successful receipt publish
- **Issue:** Test asserted `lines_after_first == 1` (exact match). With step 13, MockTransport publish_receipt succeeds, causing `append_ledger_entry_with_receipt` to append a second row (D-SEQ-05). The assertion was now incorrect.
- **Fix:** Updated assertion to `lines_after_first >= 1 && lines_after_first <= 2` with explanatory comment. Second-receive assertion updated to compare against `lines_after_first` (not hardcoded 1) to preserve the idempotence invariant.
- **Files modified:** tests/phase2_idempotent_re_receive.rs
- **Commit:** d9445f2

**2. [Rule 1 - Bug] Two clippy warnings in new flow.rs code**
- **Found during:** Task 3 clippy run
- **Issue 1:** `doc_lazy_continuation` in run_receipts doc comment (bullet list after non-blank line)
- **Issue 2:** `print_literal` in render_receipts_table header (last format arg was a string literal)
- **Fix:** Added blank lines between doc paragraphs; changed `println!("{}", "recipient_fp")` → inline literal in format string
- **Files modified:** src/flow.rs
- **Commit:** d9445f2 (fixes applied before commit)

## Known Stubs

None. All implemented functionality is fully wired end-to-end.

## Threat Flags

No new trust boundaries introduced beyond those in the plan's threat model. All T-03-03-01..07 mitigations implemented:
- T-03-03-01: step 13 strictly after step 12 (D-SEQ-01 ordering confirmed in code)
- T-03-03-02: match on publish_receipt, no `?`-propagation (D-SEQ-02 confirmed by grep)
- T-03-03-03: control-char strip in truncate_purpose + render_receipts_table (defense-in-depth)
- T-03-03-04: invalid_sig counter only, returned as Error::SignatureInner (D-16 unified)
- T-03-03-05: filter applied after verify loop (Pitfall #6 / D-OUT-02)
- T-03-03-06: step 13 runs only after steps 7-12 gate chain
- T-03-03-07: no `if self_mode { skip }` branch; same path always

## Self-Check: PASSED

- `src/flow.rs` modified: FOUND
- `src/main.rs` modified: FOUND
- `src/cli.rs` modified: FOUND
- Commit d9445f2 (feat(03-03): extend run_receive with step 13...): FOUND
- Commit b9fe9d7 (feat(03-03): add --json flag to Receipts CLI...): FOUND
- `cargo build --release` exits 0: CONFIRMED
- `cargo test --features mock` — 0 failures across all harnesses: CONFIRMED
- `grep -n "pub fn run_receive" src/flow.rs` shows 6-arg signature at line 398: CONFIRMED
- `grep -n "STEP 13: publish_receipt" src/flow.rs` returns 1 match at line 479: CONFIRMED
- `grep -c "transport.publish_receipt(keypair" src/flow.rs` returns 1: CONFIRMED
- `grep -n "transport.publish_receipt.*?;" src/flow.rs` returns no match: CONFIRMED
- `grep -n "pub fn run_receipts" src/flow.rs` returns 1 match at line 568: CONFIRMED
- `grep -n "json: bool" src/cli.rs` returns 1 match in Receipts variant: CONFIRMED
- `grep -n "not implemented yet (phase 3)" src/main.rs` returns no match: CONFIRMED
- `grep -c "cipherpost::flow::run_receipts" src/main.rs` returns 1: CONFIRMED
- `grep -c "Keypair::from_secret_key(&seed_bytes)" src/main.rs` returns 2: CONFIRMED
