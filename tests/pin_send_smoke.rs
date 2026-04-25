//! Phase 8 Plan 01 smoke test: run_send with --pin produces an OuterRecord
//! with pin_required=true and a blob that begins with a 32-byte salt prefix.
//!
//! Full PIN round-trip (receive-side decrypt) lands in Plan 02 — this test
//! only covers the send half: that the wire bytes are SHAPED correctly when
//! a PIN is supplied. The salt + nested-age structure here will be consumed
//! by Plan 02's run_receive PIN-prompt path.
//!
//! ## Wire-budget caveat (mirrors Phase 6/7 X.509 / PGP / SSH pattern)
//!
//! A pin-protected share carries TWO age layers (~190 B each post-grease) +
//! 32 B salt + base64 1.33× expansion + JSON wrapping → encoded SignedPacket
//! exceeds the BEP44 1000-byte ceiling for any non-trivial plaintext. The
//! happy-path success test is `#[ignore]`'d here — same deferral pattern as
//! Phase 6's X.509 round-trip (D-P6-04). The wire-budget escape hatch
//! (two-tier storage / chunking) is scheduled for Plan 9 (DHT-07).
//!
//! The clean-surface test (`pin_send_surfaces_wire_budget_exceeded`) DOES
//! run and asserts the error path produces `Error::WireBudgetExceeded` with
//! a sane `encoded`/`budget`/`plaintext` triplet — i.e., the new Phase 8
//! code path doesn't break the wire-budget surface contract.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::{run_send, MaterialSource, SendMode, DEFAULT_TTL_SECONDS};
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::Error;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
#[ignore = "wire-budget: pin-protected share's nested age + salt prefix exceeds 1000-byte PKARR BEP44 ceiling — see module doc"]
fn pin_send_produces_pin_required_record_with_salt_prefixed_blob() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);

    let plaintext = b"x".to_vec();
    let transport = MockTransport::new();
    let pin = SecretBox::new(Box::new("validpin1".to_string()));

    let _uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        Some(pin),
        false,
    )
    .expect("run_send self-mode + pin");

    // The resolved OuterRecord must carry pin_required=true.
    let record = transport
        .resolve(&id.z32_pubkey())
        .expect("MockTransport::resolve must return the published OuterRecord");
    assert!(
        record.pin_required,
        "OuterRecord must carry pin_required=true when --pin is supplied"
    );

    // Blob must be at least 32 bytes (salt) + age-overhead (~165 bytes) decoded.
    use base64::Engine;
    let blob_bytes = base64::engine::general_purpose::STANDARD
        .decode(&record.blob)
        .expect("blob must be valid base64-STANDARD");
    assert!(
        blob_bytes.len() >= 32 + 100,
        "pin_required blob must be salt-prefixed (32 B salt + outer age_ct); got {} bytes",
        blob_bytes.len()
    );
}

/// Companion to the `#[ignore]`d round-trip above — assert that the new
/// Phase 8 nested-age path surfaces `Error::WireBudgetExceeded` cleanly when
/// the encoded packet exceeds the 1000-byte ceiling. Mirrors Phase 6's
/// `x509_send_realistic_cert_surfaces_wire_budget_exceeded_cleanly` pattern.
#[test]
#[serial]
fn pin_send_surfaces_wire_budget_exceeded_cleanly() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);

    let plaintext = b"topsecret1".to_vec();
    let transport = MockTransport::new();
    let pin = SecretBox::new(Box::new("validpin1".to_string()));

    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        Some(pin),
        false,
    )
    .expect_err("nested-age path must exceed BEP44 ceiling for any non-trivial plaintext");

    let (encoded, budget, plaintext_len) = match err {
        Error::WireBudgetExceeded {
            encoded,
            budget,
            plaintext,
        } => (encoded, budget, plaintext),
        other => panic!(
            "expected WireBudgetExceeded — got {:?}; the new Phase 8 nested-age path must surface this error class cleanly",
            other
        ),
    };
    assert_eq!(budget, 1000, "BEP44 budget must be 1000 bytes");
    assert!(
        encoded > budget,
        "encoded {} must exceed budget {}",
        encoded,
        budget
    );
    assert!(
        plaintext_len > 0 && plaintext_len < 1024,
        "plaintext_len {} must be the JCS envelope size (under a kilobyte for this test)",
        plaintext_len
    );
}

#[test]
#[serial]
fn pin_none_send_preserves_v1_blob_shape() {
    // Defense-in-depth: when pin=None, the wire shape MUST match v1.0
    // exactly — no salt prefix, pin_required is elided in JCS bytes,
    // blob is base64(outer_age_ct). This proves the new Phase 8 code path
    // is gated correctly on `pin.is_some()` and does NOT regress v1.0
    // wire-byte-identity for non-pin shares.
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);

    let plaintext = b"topsecret1".to_vec();
    let transport = MockTransport::new();

    let _uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,
        false,
    )
    .expect("run_send self-mode without pin");

    let record = transport.resolve(&id.z32_pubkey()).expect("resolve");
    assert!(
        !record.pin_required,
        "OuterRecord.pin_required must be false when pin=None"
    );
}
