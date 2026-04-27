//! SSH-07: Envelope JCS bytes carrying Material::SshKey must be byte-identical
//! across runs and match the committed fixture. Any library update that changes
//! the bytes is a protocol break — caught here.
//!
//! IMPORTANT: bytes stored in Material::SshKey are the CANONICAL re-encoded
//! form per D-P7-11 (ssh-key::PrivateKey::to_openssh(LineEnding::LF)). The JCS
//! fixture pins this canonical form, NOT the raw input bytes. To regenerate
//! the JCS fixture, the canonical bytes must be re-derived first via the
//! ingest::ssh_key pipeline.

use cipherpost::payload::{ingest, Envelope, Material};
use cipherpost::PROTOCOL_VERSION;
use std::fs;

const FIXTURE_PATH: &str = "tests/fixtures/material_ssh_signable.bin";
const SSH_FIXTURE: &[u8] = include_bytes!("fixtures/material_ssh_fixture.openssh-v1");

fn canonical_ssh_bytes() -> Vec<u8> {
    match ingest::ssh_key(SSH_FIXTURE).expect("valid OpenSSH v1 fixture") {
        Material::SshKey { bytes } => bytes,
        other => panic!("ingest::ssh_key produced non-SshKey variant: {other:?}"),
    }
}

fn fixture_envelope() -> Envelope {
    Envelope {
        burn_after_read: false,
        created_at: 1_700_000_000,
        material: Material::SshKey {
            bytes: canonical_ssh_bytes(),
        },
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}

#[test]
fn material_ssh_envelope_fixture_bytes_match() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test --test material_ssh_envelope_round_trip -- --ignored regenerate_material_ssh_envelope_fixture` to create it",
    );
    assert_eq!(
        bytes, expected,
        "SSH Envelope JCS bytes changed — past signatures invalidated!"
    );
}

#[test]
fn material_ssh_envelope_jcs_round_trip_byte_identical() {
    let e = fixture_envelope();
    let bytes1 = e.to_jcs_bytes().unwrap();
    let parsed = Envelope::from_jcs_bytes(&bytes1).unwrap();
    let bytes2 = parsed.to_jcs_bytes().unwrap();
    assert_eq!(bytes1, bytes2, "JCS round-trip must be byte-identical");
}

#[test]
fn material_ssh_envelope_jcs_shape_contains_ssh_key_tag() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    let as_str = std::str::from_utf8(&bytes).expect("JCS output is valid UTF-8");
    assert!(
        as_str.contains("\"type\":\"ssh_key\""),
        "JCS must encode the snake_case tag `ssh_key`, got: {as_str}"
    );
    assert!(
        as_str.contains("\"bytes\":\""),
        "JCS must encode the base64-STANDARD bytes field, got: {as_str}"
    );
}

#[test]
#[ignore] // run with --ignored to regenerate; commit result
fn regenerate_material_ssh_envelope_fixture() {
    let bytes = fixture_envelope().to_jcs_bytes().unwrap();
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {FIXTURE_PATH}");
}
