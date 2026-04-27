//! Phase 8 Plan 04 (BURN-01 + D-P8-04): JCS byte-identity fixture for
//! Envelope with `burn_after_read=true`. Pins alphabetic placement: per
//! RESEARCH §"JCS field-ordering verification", `burn_after_read` lands
//! FIRST (before `created_at`) because `b` < `c` in alphabetic order.
//!
//! Pitfall #3: the exact bytes `jcs(Envelope)` produces are the thing
//! Ed25519 signs (post-decrypt inner sig). If those bytes ever change for
//! the burn=true shape — field add/remove/rename/reorder, serde attribute
//! change, library update — every previously issued burn-share signature
//! becomes unverifiable. This test commits a fixture of those bytes and
//! asserts equality.
//!
//! Counterpart fixtures already shipped:
//!   - tests/fixtures/envelope_jcs_generic_secret.bin (v1.0; non-burn baseline)
//!   - tests/fixtures/outer_record_pin_required_signable.bin (Plan 02 PIN)

use cipherpost::payload::{Envelope, Material};
use cipherpost::PROTOCOL_VERSION;
use std::fs;

const FIXTURE_PATH: &str = "tests/fixtures/envelope_burn_signable.bin";

fn fixture_envelope_burn() -> Envelope {
    Envelope {
        burn_after_read: true,
        created_at: 1_700_000_000,
        material: Material::GenericSecret {
            bytes: vec![0, 1, 2, 3],
        },
        protocol_version: PROTOCOL_VERSION,
        purpose: "test".to_string(),
    }
}

#[test]
fn envelope_burn_fixture_bytes_match_committed_fixture() {
    let bytes = fixture_envelope_burn().to_jcs_bytes().unwrap();
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture missing — run `cargo test --test envelope_burn_signable -- --ignored regenerate_envelope_burn_fixture` to create",
    );
    assert_eq!(
        bytes, expected,
        "Envelope JCS bytes for burn_after_read=true changed — past burn-share signatures invalidated"
    );
}

#[test]
fn envelope_burn_jcs_shape_starts_with_burn_after_read() {
    let bytes = fixture_envelope_burn().to_jcs_bytes().unwrap();
    let s = std::str::from_utf8(&bytes).expect("JCS output is valid UTF-8");
    assert!(
        s.starts_with(r#"{"burn_after_read":true,"#),
        "JCS must encode burn_after_read FIRST alphabetically; got: {}",
        &s[..40.min(s.len())]
    );
}

#[test]
fn envelope_burn_false_elides_field() {
    // Non-burn Envelope MUST NOT serialize burn_after_read at all
    // (#[serde(skip_serializing_if = "is_false")] elides). This preserves
    // v1.0 byte-identity for non-burn shares.
    let env = Envelope {
        burn_after_read: false,
        created_at: 1_700_000_000,
        material: Material::GenericSecret { bytes: vec![] },
        protocol_version: PROTOCOL_VERSION,
        purpose: "x".to_string(),
    };
    let bytes = env.to_jcs_bytes().unwrap();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(
        !s.contains("burn_after_read"),
        "burn_after_read=false MUST elide on the wire (is_false skip); got: {s}"
    );
}

#[test]
#[ignore]
fn regenerate_envelope_burn_fixture() {
    let bytes = fixture_envelope_burn().to_jcs_bytes().unwrap();
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, &bytes).unwrap();
    println!("wrote {} bytes to {}", bytes.len(), FIXTURE_PATH);
}
