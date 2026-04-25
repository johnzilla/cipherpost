//! PAYL-01 / PAYL-02: Envelope JCS bytes must be byte-identical across runs and
//! match a committed fixture. Any library update that changes the bytes is a
//! protocol break — caught here.

use cipherpost::payload::{Envelope, Material};
use cipherpost::PROTOCOL_VERSION;
use std::fs;

const FIXTURE_PATH: &str = "tests/fixtures/envelope_jcs_generic_secret.bin";

fn fixture_envelope() -> Envelope {
    Envelope {
        // Phase 8 Plan 01: burn_after_read defaults to false; `is_false`
        // skip_serializing_if elides this from JCS bytes — fixture stays
        // byte-for-byte identical to v1.0.
        burn_after_read: false,
        created_at: 1_700_000_000,
        material: Material::generic_secret(vec![0, 1, 2, 3]),
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}

#[test]
fn envelope_jcs_bytes_match_committed_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_envelope_fixture` to create it",
    );
    assert_eq!(
        bytes, expected,
        "Envelope JCS bytes changed — past signatures invalidated!"
    );
}

#[test]
fn envelope_jcs_round_trip_byte_identical() {
    let e = fixture_envelope();
    let bytes1 = e.to_jcs_bytes().unwrap();
    let parsed = Envelope::from_jcs_bytes(&bytes1).unwrap();
    let bytes2 = parsed.to_jcs_bytes().unwrap();
    assert_eq!(bytes1, bytes2, "JCS round-trip must be byte-identical");
}

#[test]
#[ignore] // run with --ignored to regenerate; commit result
fn regenerate_envelope_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {}", FIXTURE_PATH);
}
