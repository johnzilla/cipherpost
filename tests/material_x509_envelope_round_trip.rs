//! X509-07: Envelope JCS bytes carrying a Material::X509Cert variant must be
//! byte-identical across runs and match the committed fixture. Any library
//! update that changes the bytes is a protocol break — caught here.
//!
//! Mirrors tests/phase2_envelope_round_trip.rs (the GenericSecret counterpart).

use cipherpost::payload::{Envelope, Material};
use cipherpost::PROTOCOL_VERSION;
use std::fs;

const FIXTURE_PATH: &str = "tests/fixtures/material_x509_signable.bin";
const DER_FIXTURE: &[u8] = include_bytes!("fixtures/x509_cert_fixture.der");

fn fixture_envelope() -> Envelope {
    Envelope {
        created_at: 1_700_000_000,
        material: Material::X509Cert {
            bytes: DER_FIXTURE.to_vec(),
        },
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}

#[test]
fn material_x509_envelope_fixture_bytes_match() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_material_x509_envelope_fixture` to create it",
    );
    assert_eq!(
        bytes, expected,
        "X509 Envelope JCS bytes changed — past signatures invalidated!"
    );
}

#[test]
fn material_x509_envelope_jcs_round_trip_byte_identical() {
    let e = fixture_envelope();
    let bytes1 = e.to_jcs_bytes().unwrap();
    let parsed = Envelope::from_jcs_bytes(&bytes1).unwrap();
    let bytes2 = parsed.to_jcs_bytes().unwrap();
    assert_eq!(bytes1, bytes2, "JCS round-trip must be byte-identical");
}

#[test]
fn material_x509_envelope_jcs_shape_contains_x509_cert_tag() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let as_str = std::str::from_utf8(&bytes).expect("JCS output is valid UTF-8");
    assert!(
        as_str.contains("\"type\":\"x509_cert\""),
        "JCS must encode the snake_case tag `x509_cert`, got: {}",
        as_str
    );
    assert!(
        as_str.contains("\"bytes\":\""),
        "JCS must encode the base64-STANDARD bytes field, got: {}",
        as_str
    );
}

#[test]
#[ignore] // run with --ignored to regenerate; commit result
fn regenerate_material_x509_envelope_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {}", FIXTURE_PATH);
}
