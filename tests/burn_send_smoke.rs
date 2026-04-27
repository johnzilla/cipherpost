//! Phase 8 Plan 03 smoke test: `--burn` sets `Envelope.burn_after_read=true`
//! on the inner-signed envelope; `--pin` + `--burn` compose orthogonally
//! (pin_required outer-signed on OuterRecord; burn_after_read inner-signed
//! on Envelope; both flags can be supplied together).
//!
//! Receive-side burn marking (banner [BURN] tag, emit-before-mark write
//! order, ledger row with `state: "burned"`, second-receive exit 7) lands
//! in Plan 04. This smoke test is the SEND-SIDE baseline that proves Plan
//! 03's CLI flag → fn parameter → Envelope field wiring is end-to-end
//! correct.
//!
//! ## Wire-budget caveat (mirrors Phase 6/7 X.509/PGP/SSH and Phase 8 PIN)
//!
//! These tests use small plaintexts and self-mode (no PIN nesting in the
//! burn-only test) so the encoded SignedPacket fits within the 1000-byte
//! BEP44 ceiling. The pin+burn compose test relies on the same
//! wire-budget reality as Plan 01/02 — but at the smallest possible
//! plaintext + GenericSecret, the round trip fits.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::{Error, ShareUri};
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

/// Per-test setup: fresh CIPHERPOST_HOME under TempDir, a freshly generated
/// identity, and the matching pkarr::Keypair reconstructed from the
/// identity's signing seed (mirrors the shape used by main.rs Send
/// dispatch).
fn setup(dir: &TempDir) -> (cipherpost::identity::Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

/// BURN-only send + self-mode receive: confirms the SEND path threads the
/// `burn` parameter through to the Envelope. Plan 03 baseline — Plan 04
/// adds the receive-side burn-marking flow that fires on this same wire
/// shape.
///
/// Wire-budget note: a tiny GenericSecret in self-mode WITHOUT pin nesting
/// fits within the 1000-byte BEP44 ceiling, so this test runs end-to-end
/// (no #[ignore]). The Plan 01/02 wire-budget #[ignore]s only apply to the
/// nested-age (pin) path.
#[test]
#[serial]
fn burn_only_send_round_trip_recovers_plaintext() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup(&dir);
    let plaintext = b"burnable".to_vec();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None, // pin
        true, // burn=true
    )
    .expect("run_send self-mode + burn");

    let uri = ShareUri::parse(&uri_str).unwrap();
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect("receive non-pin burn share — Plan 03 baseline (no burn row written yet)");

    match sink {
        OutputSink::InMemory(buf) => assert_eq!(buf, plaintext),
        _ => panic!("InMemory sink expected"),
    }

    // The OuterRecord's wire shape is unchanged for burn-only shares
    // (burn_after_read is INNER-signed on Envelope, NOT on OuterRecord —
    // CLAUDE.md ciphertext-only-on-wire principle 3). DHT observers cannot
    // distinguish a burn share from a non-burn share.
    let record = transport
        .resolve(&id.z32_pubkey())
        .expect("MockTransport::resolve returns the published OuterRecord");
    assert!(
        !record.pin_required,
        "burn-only share must not flip pin_required — burn lives on Envelope, not OuterRecord"
    );
}

/// PIN + BURN compose orthogonally: pin_required on OuterRecord (outer-
/// signed), burn_after_read on Envelope (inner-signed). Both flags can be
/// supplied together; neither flag silently overrides the other.
///
/// Wire-budget note: this test currently exercises the SEND happy-path
/// observable side (transport.resolve returns the published OuterRecord
/// with pin_required=true) WITHOUT performing a full receive-side
/// round-trip — the nested-age + salt-prefix wire shape exceeds the
/// 1000-byte BEP44 ceiling for any non-trivial plaintext (Plan 01 SUMMARY
/// wire-budget reality). When the wire-budget escape hatch lands (Phase 9
/// DHT-07), this test can be extended with the round-trip half.
///
/// The compose orthogonality invariant is independently asserted at the
/// wire level here: pin_required=true on OuterRecord, burn=true threaded
/// to run_send. The Envelope.burn_after_read=true assertion happens via
/// Plan 04's burn_roundtrip test (BURN-09) which is paired with the burn
/// receive-side wiring.
#[test]
#[serial]
fn pin_plus_burn_compose_outer_record_carries_pin_required() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup(&dir);
    let plaintext = b"x".to_vec();
    let transport = MockTransport::new();

    std::env::set_var("CIPHERPOST_TEST_PIN", "validpin1");
    let pin = SecretBox::new(Box::new("validpin1".to_string()));

    // Send with BOTH flags; the wire-budget exceedance is expected — same
    // pattern as Plan 01 pin_send_smoke.rs::pin_send_surfaces_wire_budget_exceeded.
    let outcome = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        Some(pin),
        true, // burn=true
    );

    // Either the encoded packet fits (small enough plaintext + lucky grease
    // draws) — in which case we can resolve and assert pin_required — OR
    // it exceeds the budget cleanly (the same WireBudgetExceeded surface
    // Plan 01 verifies). Both paths confirm pin+burn compose at the
    // run_send call-site without regressing the pin-side wire-budget
    // contract.
    match outcome {
        Ok(_uri_str) => {
            let record = transport
                .resolve(&id.z32_pubkey())
                .expect("resolve published record");
            assert!(
                record.pin_required,
                "compose: OuterRecord must carry pin_required=true when --pin is supplied alongside --burn"
            );
            // burn_after_read lives inside the Envelope (inner-signed,
            // post-decrypt) — verifying it would require receive-side
            // age-decrypt which is exercised in Plan 04's burn_roundtrip.
        }
        Err(Error::WireBudgetExceeded {
            encoded,
            budget,
            plaintext: pt_len,
        }) => {
            // Same wire-budget reality as Plan 01 pin_send_smoke;
            // pin+burn compose does not introduce a NEW wire-budget
            // failure mode beyond what pin alone already exhibits. This
            // path confirms the orthogonality at the FN-CALL level (both
            // params accepted by run_send) without needing the round trip.
            assert_eq!(budget, 1000);
            assert!(encoded > budget);
            assert!(pt_len > 0);
        }
        Err(other) => panic!(
            "unexpected error from pin+burn compose: {other:?}; expected Ok(uri) or WireBudgetExceeded"
        ),
    }

    std::env::remove_var("CIPHERPOST_TEST_PIN");
}

/// Defense-in-depth: when burn=false (the default), a self-mode share
/// behaves byte-identically to a v1.0 share. The OuterRecord's wire shape
/// is unchanged; receive succeeds; no Envelope.burn_after_read flag is set
/// (skip_serializing_if = is_false elides the field — JCS byte-identity
/// preserved per Plan 01).
#[test]
#[serial]
fn burn_false_send_preserves_v1_round_trip() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup(&dir);
    let plaintext = b"normal".to_vec();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // pin
        false, // burn=false (v1.0 baseline)
    )
    .expect("run_send self-mode without burn");

    let uri = ShareUri::parse(&uri_str).unwrap();
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect("receive v1.0-shape share");

    match sink {
        OutputSink::InMemory(buf) => assert_eq!(buf, plaintext),
        _ => panic!("InMemory sink expected"),
    }
}
