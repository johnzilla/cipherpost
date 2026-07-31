//! Phase 8 Plan 04 (D-P8-10): state-schema migration invariants.
//!
//! Asserts the conservative read-side mapping for the LedgerEntry.state
//! field that Plan 03 added:
//!
//!   - v1.0 row (no `state` field) → LedgerState::Accepted (default elide
//!     preserved; v1.0 ledger files MUST continue to deserialize correctly)
//!   - v1.1 row with `"state":"accepted"` → LedgerState::Accepted (explicit)
//!   - v1.1 row with `"state":"burned"` → LedgerState::Burned (Plan 04 write
//!     side fires this; Plan 03 baseline only covers the read-side branching)
//!   - sentinel-but-no-ledger-row → LedgerState::Accepted with synthetic
//!     "<unknown>" timestamp (preserves v1.0 sentinel-wins fallback)
//!   - no sentinel → LedgerState::None
//!
//! W5 fix: imports path helpers via `cipherpost::flow::test_paths` (Plan 03
//! cfg-gated re-export) rather than reconstructing
//! `dir.path().join("state")...` inline — keeps tests in lock-step with
//! src/flow.rs's actual layout.
//!
//! All tests carry `#[serial]` because they mutate process-global env
//! (`CIPHERPOST_HOME`).

#![cfg(feature = "mock")]

use cipherpost::flow::test_paths::{
    accepted_dir, ledger_path, lock_path, prune_consumed_locks, sentinel_path,
};
use cipherpost::flow::{check_already_consumed, LedgerState};
use serial_test::serial;
use tempfile::TempDir;

fn write_ledger(dir: &TempDir, content: &str) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    std::fs::create_dir_all(accepted_dir()).unwrap();
    std::fs::write(ledger_path(), content).unwrap();
}

fn touch_sentinel(dir: &TempDir, share_ref: &str) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    std::fs::create_dir_all(accepted_dir()).unwrap();
    std::fs::write(sentinel_path(share_ref), "").unwrap();
}

#[test]
#[serial]
fn v1_0_ledger_row_without_state_field_deserializes_as_accepted() {
    let dir = TempDir::new().unwrap();
    let share_ref = "0123456789abcdef0123456789abcdef";
    let row = format!(
        r#"{{"accepted_at":"2026-04-25T13:11:42Z","ciphertext_hash":"abc","cleartext_hash":"def","purpose":"k","sender":"pk","share_ref":"{share_ref}"}}"#
    );
    write_ledger(&dir, &format!("{row}\n"));
    touch_sentinel(&dir, share_ref);

    match check_already_consumed(share_ref) {
        LedgerState::Accepted { .. } => {} // ok — v1.0 default-deserialize lands here
        other => panic!("v1.0 row (no state field) must be Accepted; got {other:?}"),
    }
}

#[test]
#[serial]
fn explicit_state_accepted_deserializes_as_accepted() {
    let dir = TempDir::new().unwrap();
    let share_ref = "fedcba9876543210fedcba9876543210";
    let row = format!(
        r#"{{"accepted_at":"2026-04-25T14:00:00Z","ciphertext_hash":"a","cleartext_hash":"b","purpose":"x","sender":"pk","share_ref":"{share_ref}","state":"accepted"}}"#
    );
    write_ledger(&dir, &format!("{row}\n"));
    touch_sentinel(&dir, share_ref);

    match check_already_consumed(share_ref) {
        LedgerState::Accepted { .. } => {}
        other => panic!("explicit state=accepted must be Accepted; got {other:?}"),
    }
}

#[test]
#[serial]
fn explicit_state_burned_deserializes_as_burned() {
    let dir = TempDir::new().unwrap();
    let share_ref = "deadbeefcafebabe00112233deadbeef";
    let row = format!(
        r#"{{"accepted_at":"2026-04-25T15:00:00Z","ciphertext_hash":"a","cleartext_hash":"b","purpose":"x","sender":"pk","share_ref":"{share_ref}","state":"burned"}}"#
    );
    write_ledger(&dir, &format!("{row}\n"));
    touch_sentinel(&dir, share_ref);

    match check_already_consumed(share_ref) {
        LedgerState::Burned { .. } => {}
        other => panic!("state=burned must be Burned; got {other:?}"),
    }
}

/// Regression: burn is MONOTONIC and ORDER-INDEPENDENT. A burned row plus a
/// step-13 receipt row (state absent → Accepted) must read Burned regardless of
/// which comes first. `check_already_consumed` scans ALL matching rows with
/// "burned" dominating, so a later Accepted-flavored receipt row can never
/// silently downgrade a burned share (the old first-match-wins read only worked
/// because the burned row is written before the receipt row — a fragile
/// order-dependency the docstrings even claimed was "last-match-wins").
#[test]
#[serial]
fn burned_dominates_receipt_row_regardless_of_order() {
    let share_ref = "abcdefabcdefabcdefabcdefabcdefab";
    let burned = format!(
        r#"{{"accepted_at":"2026-04-25T15:00:00Z","ciphertext_hash":"a","cleartext_hash":"b","purpose":"x","sender":"pk","share_ref":"{share_ref}","state":"burned"}}"#
    );
    // step-13 receipt row: no `state` field (→ Accepted), with receipt_published_at.
    let receipt = format!(
        r#"{{"accepted_at":"2026-04-25T15:00:01Z","ciphertext_hash":"a","cleartext_hash":"b","purpose":"x","receipt_published_at":"2026-04-25T15:00:01Z","sender":"pk","share_ref":"{share_ref}"}}"#
    );

    // (1) burned then receipt — the natural write order.
    let dir1 = TempDir::new().unwrap();
    write_ledger(&dir1, &format!("{burned}\n{receipt}\n"));
    touch_sentinel(&dir1, share_ref);
    assert!(
        matches!(
            check_already_consumed(share_ref),
            LedgerState::Burned { .. }
        ),
        "burned-then-receipt must read Burned"
    );

    // (2) receipt then burned — reversed. Must STILL be Burned (order-independent).
    let dir2 = TempDir::new().unwrap();
    write_ledger(&dir2, &format!("{receipt}\n{burned}\n"));
    touch_sentinel(&dir2, share_ref);
    assert!(
        matches!(
            check_already_consumed(share_ref),
            LedgerState::Burned { .. }
        ),
        "receipt-then-burned must STILL read Burned (burned dominates)"
    );
}

#[test]
#[serial]
fn sentinel_without_matching_ledger_row_returns_accepted_unknown() {
    let dir = TempDir::new().unwrap();
    let share_ref = "11111111111111112222222222222222";
    write_ledger(&dir, "");
    touch_sentinel(&dir, share_ref);

    match check_already_consumed(share_ref) {
        LedgerState::Accepted { accepted_at } => {
            assert!(
                accepted_at.contains("unknown"),
                "fallback must mark accepted_at as unknown; got: {accepted_at}"
            );
        }
        other => panic!("sentinel without ledger row must be Accepted; got {other:?}"),
    }
}

/// Quick: `prune_consumed_locks` unlinks lock files ONLY for share_refs present
/// in the ledger (consumed → will never re-lock), and leaves locks for
/// unknown/in-flight share_refs untouched. Bounds the otherwise-unbounded
/// `locks/` directory.
#[test]
#[serial]
fn prune_removes_consumed_lock_files_only() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());

    let consumed = "aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbb";
    let live = "ccccccccccccccccdddddddddddddddd"; // absent from the ledger

    // Ledger holds a row for `consumed` only.
    let row = format!(
        r#"{{"accepted_at":"2026-04-25T13:11:42Z","ciphertext_hash":"a","cleartext_hash":"b","purpose":"k","sender":"pk","share_ref":"{consumed}"}}"#
    );
    std::fs::create_dir_all(accepted_dir()).unwrap();
    std::fs::write(ledger_path(), format!("{row}\n")).unwrap();

    // Create both lock files (locks_dir = the lock path's parent).
    std::fs::create_dir_all(lock_path(consumed).parent().unwrap()).unwrap();
    std::fs::write(lock_path(consumed), "").unwrap();
    std::fs::write(lock_path(live), "").unwrap();

    let removed = prune_consumed_locks();
    assert_eq!(removed, 1, "exactly the consumed-share lock is removed");
    assert!(
        !lock_path(consumed).exists(),
        "consumed-share lock must be pruned"
    );
    assert!(
        lock_path(live).exists(),
        "unknown/in-flight lock must be left untouched"
    );
}

#[test]
#[serial]
fn no_sentinel_returns_none() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    match check_already_consumed("0000000000000000aaaaaaaaaaaaaaaa") {
        LedgerState::None => {}
        other => panic!("no sentinel must be None; got {other:?}"),
    }
}
