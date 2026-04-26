//! Phase 9 Plan 01 (DHT-01 + DHT-02): MockTransport CAS racer.
//!
//! Two `std::thread`s synchronized via `std::sync::Barrier::new(2)` both
//! call `publish_receipt(...)` on the same recipient PKARR key with
//! different receipts. Asserts:
//!   - Both calls return `Ok(())` (the trait-internal single-retry
//!     resolves the CAS conflict without surfacing it to callers — D-P9-A1
//!     + D-P9-A2).
//!   - The final MockStore state contains BOTH receipts (resolve-merge-
//!     republish invariant holds under contention — TRANS-03 +
//!     PITFALLS.md #28).
//!
//! ## Pitfall #28 mandate
//!
//! True `Barrier`-synced threads, NEVER sleep-based simulation. The
//! Barrier is reached AFTER each thread has built its receipt JSON
//! locally (no shared state touched yet), and BEFORE the
//! `publish_receipt` call (which inside the trait does
//! lock-read-seq → drop-lock → merge → re-lock-cas-check). One thread
//! wins on first attempt; the other observes a stale seq when it
//! re-acquires the lock, returns CasConflict internally, and the trait
//! method's single-retry path resolves and republishes (this time with
//! the fresh seq).
//!
//! `#[serial]` per CLAUDE.md load-bearing — other mock-feature tests
//! also touch shared MockStore-style state.

#![cfg(feature = "mock")]

use cipherpost::transport::{MockTransport, Transport};
use cipherpost::DHT_LABEL_RECEIPT_PREFIX;
use serial_test::serial;
use std::sync::{Arc, Barrier};
use std::thread;

fn deterministic_keypair(seed_byte: u8) -> pkarr::Keypair {
    pkarr::Keypair::from_secret_key(&[seed_byte; 32])
}

#[test]
#[serial]
fn publish_receipt_cas_racer_two_threads_both_persist() {
    let transport = Arc::new(MockTransport::new());
    let kp = Arc::new(deterministic_keypair(0xAB));
    let z32 = kp.public_key().to_z32();
    let barrier = Arc::new(Barrier::new(2));

    // Build receipt JSON strings BEFORE the barrier wait so the contention
    // window is purely the publish_receipt call (Pitfall B in
    // 09-RESEARCH.md). The receipt content is opaque to MockTransport —
    // it just stores the string under `_cprcpt-<share_ref>`.
    let receipt_a = r#"{"share_ref":"aa","kind":"a"}"#.to_string();
    let receipt_b = r#"{"share_ref":"bb","kind":"b"}"#.to_string();

    let h_a = {
        let transport = transport.clone();
        let kp = kp.clone();
        let barrier = barrier.clone();
        let receipt = receipt_a.clone();
        thread::spawn(move || {
            barrier.wait();
            transport
                .publish_receipt(&kp, "aa", &receipt)
                .expect("publish_receipt(aa) must succeed via trait-internal retry");
        })
    };
    let h_b = {
        let transport = transport.clone();
        let kp = kp.clone();
        let barrier = barrier.clone();
        let receipt = receipt_b.clone();
        thread::spawn(move || {
            barrier.wait();
            transport
                .publish_receipt(&kp, "bb", &receipt)
                .expect("publish_receipt(bb) must succeed via trait-internal retry");
        })
    };

    h_a.join().unwrap();
    h_b.join().unwrap();

    // Both receipts must coexist after concurrent publish + internal retry.
    let all = transport.resolve_all_txt(&z32);
    let receipt_count = all
        .iter()
        .filter(|(l, _)| l.starts_with(DHT_LABEL_RECEIPT_PREFIX))
        .count();
    assert_eq!(
        receipt_count,
        2,
        "both receipts must persist after concurrent publish; got {:?}",
        all.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>()
    );
}
