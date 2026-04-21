//! Pitfall #3: canonical JSON must be deterministic across re-serializations and
//! match the committed fixture bytes. Also proptest-checks determinism.
//!
//! The struct below mirrors the shape of `OuterRecordSignable` (Plan 03). If that
//! struct gains new fields, update both this test and the fixture file — the bytes
//! MUST NOT change for any existing fixed input.

use proptest::prelude::*;
use serde::Serialize;
use std::fs;

#[derive(Serialize)]
struct Fixture {
    blob: String,
    created_at: u64,
    pubkey: String,
    recipient: Option<String>,
    share_ref: String,
    ttl: u64,
}

#[test]
fn jcs_fixture_bytes_match_committed() {
    let fx = Fixture {
        blob: "AAAA".to_string(),
        created_at: 1_700_000_000,
        pubkey: "test_pubkey_z32".to_string(),
        recipient: None,
        share_ref: "0123456789abcdef0123456789abcdef".to_string(),
        ttl: 86400,
    };
    let got = cipherpost::crypto::jcs_serialize(&fx).unwrap();
    let expected = fs::read("tests/fixtures/jcs_signing_bytes.bin").unwrap();
    assert_eq!(
        got, expected,
        "JCS bytes changed — this invalidates every past signature! \
         Got: {}, Expected: {}",
        String::from_utf8_lossy(&got),
        String::from_utf8_lossy(&expected)
    );
}

proptest! {
    #[test]
    fn jcs_round_trip_determinism(
        blob in "[A-Za-z0-9+/=]{4,80}",
        created_at in 0u64..u32::MAX as u64,
        ttl in 1u64..86400*30u64,
        share_ref in "[0-9a-f]{32}",
    ) {
        let fx = Fixture {
            blob: blob.clone(),
            created_at,
            pubkey: "pk".to_string(),
            recipient: None,
            share_ref: share_ref.clone(),
            ttl,
        };
        let bytes1 = cipherpost::crypto::jcs_serialize(&fx).unwrap();
        let bytes2 = cipherpost::crypto::jcs_serialize(&fx).unwrap();
        prop_assert_eq!(bytes1, bytes2);
    }
}

/// Run with `cargo test -- --ignored regenerate_jcs_fixture` to regenerate the
/// committed fixture file. Only run this when the JCS serialization is known-good
/// and you want to update the fixture. Commit the result.
#[test]
#[ignore]
fn regenerate_jcs_fixture() {
    let fx = Fixture {
        blob: "AAAA".to_string(),
        created_at: 1_700_000_000,
        pubkey: "test_pubkey_z32".to_string(),
        recipient: None,
        share_ref: "0123456789abcdef0123456789abcdef".to_string(),
        ttl: 86400,
    };
    let bytes = cipherpost::crypto::jcs_serialize(&fx).unwrap();
    std::fs::write("tests/fixtures/jcs_signing_bytes.bin", bytes).unwrap();
    println!("Fixture regenerated.");
}
