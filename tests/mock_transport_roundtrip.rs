//! MockTransport integration test — publish, resolve, verify round trip.
//! Asserts the `Transport` trait's publish/resolve are symmetric on the mock,
//! and that an OuterRecord written by a sender is decoded + verified on resolve.
//!
//! TRANS-01 + TRANS-02.

use cipherpost::record::{share_ref_from_bytes, sign_record, OuterRecord, OuterRecordSignable};
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::PROTOCOL_VERSION;

fn make_record(kp: &pkarr::Keypair) -> OuterRecord {
    let blob = "dGhpc2lzYWdlY2lwaGVydGV4dA==".to_string();
    let created_at = 1_700_000_000_i64;
    let share_ref = share_ref_from_bytes(blob.as_bytes(), created_at);
    let signable = OuterRecordSignable {
        blob: blob.clone(),
        created_at,
        protocol_version: PROTOCOL_VERSION,
        pubkey: kp.public_key().to_z32(),
        recipient: None,
        share_ref: share_ref.clone(),
        ttl_seconds: 86400,
    };
    let signature = sign_record(&signable, kp).unwrap();
    OuterRecord {
        blob: signable.blob,
        created_at: signable.created_at,
        protocol_version: signable.protocol_version,
        pubkey: signable.pubkey,
        recipient: signable.recipient,
        share_ref: signable.share_ref,
        signature,
        ttl_seconds: signable.ttl_seconds,
    }
}

#[test]
fn mock_publish_then_resolve_roundtrips_verified_record() {
    let seed = [42u8; 32];
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let original = make_record(&kp);
    let transport = MockTransport::new();

    transport.publish(&kp, &original).unwrap();
    let resolved = transport.resolve(&kp.public_key().to_z32()).unwrap();

    assert_eq!(resolved, original, "resolved record differs from published");
}

#[test]
fn mock_resolve_unpublished_returns_not_found() {
    let transport = MockTransport::new();
    let seed = [99u8; 32];
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let err = transport.resolve(&kp.public_key().to_z32()).unwrap_err();
    assert!(
        matches!(err, cipherpost::Error::NotFound),
        "expected NotFound, got {:?}",
        err
    );
}

#[test]
fn mock_publish_receipt_stores_under_cprcpt_label() {
    let seed = [7u8; 32];
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let transport = MockTransport::new();
    let share_ref = "0123456789abcdef0123456789abcdef";
    let receipt_json =
        r#"{"accepted_at":1700000000,"share_ref":"0123456789abcdef0123456789abcdef"}"#;
    transport
        .publish_receipt(&kp, share_ref, receipt_json)
        .unwrap();
    let all = transport.resolve_all_txt(&kp.public_key().to_z32());
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].0, format!("_cprcpt-{}", share_ref));
    assert_eq!(all[0].1, receipt_json);
}
