//! Phase 8 Plan 02 (PIN-04): JCS byte-identity fixture for OuterRecordSignable
//! with pin_required=true.
//!
//! Pins alphabetic placement of `pin_required` between `created_at` and
//! `protocol_version` (NOT between `created_at` and `purpose` — `purpose`
//! lives on `Envelope`, not `OuterRecord`. RESEARCH Open Risk #2 / 08-01
//! placement correction).
//!
//! Pitfall #3: the exact bytes `jcs(OuterRecordSignable)` produces are the
//! thing Ed25519 signs. If those bytes ever change for the pin_required=true
//! shape — field add/remove/rename/reorder, serde attribute change, library
//! update — every previously issued pin-share signature becomes
//! unverifiable. This test commits a fixture of those bytes and asserts
//! equality.

use cipherpost::record::OuterRecordSignable;
use serde_canonical_json::CanonicalFormatter;
use std::fs;

const FIXTURE_PATH: &str = "tests/fixtures/outer_record_pin_required_signable.bin";

fn signable() -> OuterRecordSignable {
    OuterRecordSignable {
        blob: "AAAA".into(),
        created_at: 1_700_000_000,
        pin_required: true,
        protocol_version: 1,
        pubkey: "pk-placeholder-z32".into(),
        recipient: Some("rcpt-placeholder-z32".into()),
        share_ref: "0123456789abcdef0123456789abcdef".into(),
        ttl_seconds: 86400,
    }
}

fn jcs(s: &OuterRecordSignable) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    serde::Serialize::serialize(s, &mut ser).unwrap();
    buf
}

#[test]
fn pin_required_signable_bytes_match_committed_fixture() {
    let bytes = jcs(&signable());
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture missing — run `cargo test --test outer_record_pin_required_signable -- --ignored regenerate_pin_required_fixture` to create",
    );
    assert_eq!(
        bytes, expected,
        "OuterRecordSignable JCS bytes for pin_required=true changed — past pin-share signatures invalidated"
    );
}

#[test]
fn pin_required_jcs_field_order_is_alphabetic_correct() {
    let bytes = jcs(&signable());
    let s = std::str::from_utf8(&bytes).expect("JCS output is valid UTF-8");
    // Alphabetic order:
    //   blob, created_at, pin_required, protocol_version, pubkey, recipient,
    //   share_ref, ttl_seconds
    let blob_idx = s.find(r#""blob":"#).expect("blob key present");
    let created_idx = s.find(r#""created_at":"#).expect("created_at key present");
    let pin_idx = s.find(r#""pin_required":"#).expect("pin_required key present");
    let proto_idx = s
        .find(r#""protocol_version":"#)
        .expect("protocol_version key present");

    assert!(blob_idx < created_idx, "blob must precede created_at");
    assert!(
        created_idx < pin_idx,
        "created_at must precede pin_required"
    );
    assert!(
        pin_idx < proto_idx,
        "pin_required must precede protocol_version (NOT purpose — that's on Envelope)"
    );

    // Spot-check: NO 'purpose' key on OuterRecord (purpose is Envelope-only).
    assert!(
        !s.contains(r#""purpose":"#),
        "OuterRecord must not contain 'purpose' key (it lives on Envelope)"
    );
}

#[test]
#[ignore]
fn regenerate_pin_required_fixture() {
    let bytes = jcs(&signable());
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, &bytes).unwrap();
    println!("wrote {} bytes to {}", bytes.len(), FIXTURE_PATH);
}
