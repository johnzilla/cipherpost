//! Phase 3 Plan 02 — Coexistence integration test for MockTransport.
//!
//! Asserts D-MRG-05: MockTransport's existing per-share_ref append-preserving
//! publish_receipt body (src/transport.rs:271-288) already satisfies TRANS-03's
//! coexistence invariant without modification. Uses MockTransport directly —
//! no Identity, no run_send, no run_receive — to keep the test isolated from
//! Plan 03's step-13 wiring.
//!
//! Also asserts the new `Transport::resolve_all_cprcpt` trait method filters
//! correctly.

#![cfg(feature = "mock")]

use cipherpost::record::{OuterRecord, OuterRecordSignable};
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::{DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX, PROTOCOL_VERSION};

fn deterministic_keypair(seed_byte: u8) -> pkarr::Keypair {
    pkarr::Keypair::from_secret_key(&[seed_byte; 32])
}

/// Build a minimal valid OuterRecord so MockTransport::publish's inner-sig
/// verify on later resolve() would succeed. We don't actually resolve() this
/// one in the test (we use resolve_all_txt to inspect labels directly), so we
/// just need the bytes to pass serde_json::to_string.
fn minimal_outer_record(kp: &pkarr::Keypair) -> OuterRecord {
    let signable = OuterRecordSignable {
        blob: "AAAA".to_string(),
        created_at: 1_700_000_000,
        pin_required: false,
        protocol_version: PROTOCOL_VERSION,
        pubkey: kp.public_key().to_z32(),
        recipient: None,
        share_ref: "ffffffffffffffffffffffffffffffff".to_string(),
        ttl_seconds: 86_400,
    };
    let sig = cipherpost::record::sign_record(&signable, kp).expect("sign_record");
    OuterRecord {
        blob: signable.blob,
        created_at: signable.created_at,
        pin_required: signable.pin_required,
        protocol_version: signable.protocol_version,
        pubkey: signable.pubkey,
        recipient: signable.recipient,
        share_ref: signable.share_ref,
        signature: sig,
        ttl_seconds: signable.ttl_seconds,
    }
}

#[test]
fn outgoing_share_and_receipts_coexist() {
    let kp = deterministic_keypair(0xAA);
    let z32 = kp.public_key().to_z32();
    let transport = MockTransport::new();

    // 1. Publish an outgoing _cipherpost share under kp's key.
    let outer = minimal_outer_record(&kp);
    transport.publish(&kp, &outer).expect("publish outer");

    // 2. Publish two receipts under kp's key at different share_refs.
    let share_ref_1 = "0000000000000000000000000000aaaa";
    let share_ref_2 = "0000000000000000000000000000bbbb";
    let receipt_json_1 = r#"{"share_ref":"0000000000000000000000000000aaaa"}"#;
    let receipt_json_2 = r#"{"share_ref":"0000000000000000000000000000bbbb"}"#;
    transport
        .publish_receipt(&kp, share_ref_1, receipt_json_1)
        .expect("publish_receipt 1");
    transport
        .publish_receipt(&kp, share_ref_2, receipt_json_2)
        .expect("publish_receipt 2");

    // 3. Assert three entries coexist under kp's key.
    let all = transport.resolve_all_txt(&z32);
    assert_eq!(
        all.len(),
        3,
        "expected 3 entries (1 outer + 2 receipts), got {:?}",
        all.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>()
    );
    assert_eq!(
        all.iter().filter(|(l, _)| l == DHT_LABEL_OUTER).count(),
        1,
        "outer _cipherpost entry must survive publish_receipt"
    );
    assert_eq!(
        all.iter()
            .filter(|(l, _)| l.starts_with(DHT_LABEL_RECEIPT_PREFIX))
            .count(),
        2,
        "both _cprcpt-* receipts must coexist"
    );

    // 4. resolve_all_cprcpt returns exactly the two receipt bodies.
    let receipts = transport
        .resolve_all_cprcpt(&z32)
        .expect("resolve_all_cprcpt");
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().any(|j| j == receipt_json_1));
    assert!(receipts.iter().any(|j| j == receipt_json_2));
}

#[test]
fn republishing_same_share_ref_replaces_only_that_label() {
    let kp = deterministic_keypair(0xBB);
    let z32 = kp.public_key().to_z32();
    let transport = MockTransport::new();

    // Seed: outer + receipt1 + receipt2
    transport
        .publish(&kp, &minimal_outer_record(&kp))
        .expect("publish outer");
    transport
        .publish_receipt(&kp, "0000000000000000000000000000aaaa", r#"{"v":"OLD"}"#)
        .unwrap();
    transport
        .publish_receipt(&kp, "0000000000000000000000000000bbbb", r#"{"v":"B"}"#)
        .unwrap();

    // Republish receipt1 with new JSON.
    transport
        .publish_receipt(&kp, "0000000000000000000000000000aaaa", r#"{"v":"NEW"}"#)
        .unwrap();

    // Assert: still 3 total entries; receipt1's body is now NEW not OLD; receipt2 and outer unchanged.
    let all = transport.resolve_all_txt(&z32);
    assert_eq!(all.len(), 3, "republish must not grow entry count beyond 3");
    let receipts = transport.resolve_all_cprcpt(&z32).unwrap();
    assert_eq!(receipts.len(), 2);
    assert!(receipts.iter().any(|j| j == r#"{"v":"NEW"}"#));
    assert!(receipts.iter().any(|j| j == r#"{"v":"B"}"#));
    assert!(
        !receipts.iter().any(|j| j == r#"{"v":"OLD"}"#),
        "stale receipt body must be replaced, not kept alongside"
    );
}

#[test]
fn resolve_all_cprcpt_returns_not_found_on_empty() {
    let kp = deterministic_keypair(0xCC);
    let z32 = kp.public_key().to_z32();
    let transport = MockTransport::new();

    // No publishes at all.
    let err = transport
        .resolve_all_cprcpt(&z32)
        .expect_err("empty store must be NotFound");
    assert!(matches!(err, cipherpost::Error::NotFound));

    // Publish only an outer share (no receipts) — still NotFound for receipts.
    transport.publish(&kp, &minimal_outer_record(&kp)).unwrap();
    let err = transport
        .resolve_all_cprcpt(&z32)
        .expect_err("outer-only must be NotFound for receipts");
    assert!(matches!(err, cipherpost::Error::NotFound));
}
