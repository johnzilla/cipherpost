//! SC4: two size-cap error paths with distinct Error variants.
//!
//! (a) 65537-byte plaintext rejected pre-crypto with `PayloadTooLarge` whose
//!     Display contains both 65537 and 65536.
//! (b) A plaintext small enough for the 64 KB cap but whose encrypted
//!     SignedPacket exceeds the 1000-byte PKARR wire budget is rejected with
//!     `WireBudgetExceeded` whose Display contains all three of: encoded,
//!     budget, plaintext sizes.

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::{run_send, MaterialSource, SendMode, DEFAULT_TTL_SECONDS};
use cipherpost::transport::MockTransport;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

fn fresh_identity() -> (cipherpost::identity::Identity, pkarr::Keypair) {
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

#[test]
#[serial]
fn plaintext_above_64k_rejected_with_actual_and_cap_in_display() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let (id, kp) = fresh_identity();
    let transport = MockTransport::new();

    let huge = vec![0u8; 65537];
    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "too big",
        MaterialSource::Bytes(huge),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .unwrap_err();

    assert!(
        matches!(
            err,
            cipherpost::Error::PayloadTooLarge {
                actual: 65537,
                limit: 65536
            }
        ),
        "expected PayloadTooLarge{{actual:65537,limit:65536}}, got {err:?}"
    );
    let disp = format!("{err}");
    assert!(
        disp.contains("65537"),
        "Display must contain actual size, got: {disp}"
    );
    assert!(
        disp.contains("65536"),
        "Display must contain cap, got: {disp}"
    );
}

#[test]
#[serial]
fn plaintext_under_64k_but_over_wire_budget_rejected_with_wire_budget_error() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let (id, kp) = fresh_identity();
    let transport = MockTransport::new();

    // Phase 1's tests/signed_packet_budget.rs measured a 550-byte blob →
    // 999-byte dns_packet; 600-byte blob → >1000. 2000-byte plaintext
    // guarantees the wire budget triggers before any other error.
    let big = vec![b'X'; 2000];

    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "wire-budget test",
        MaterialSource::Bytes(big),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .unwrap_err();

    let (encoded, budget, plaintext) = match err {
        cipherpost::Error::WireBudgetExceeded {
            encoded,
            budget,
            plaintext,
        } => (encoded, budget, plaintext),
        other => panic!("expected WireBudgetExceeded, got {other:?}"),
    };
    assert!(encoded > 1000, "encoded should be > budget");
    assert_eq!(budget, 1000);
    assert!(plaintext > 0);

    // Display must contain all three numbers
    let disp = format!(
        "{}",
        cipherpost::Error::WireBudgetExceeded {
            encoded,
            budget,
            plaintext
        }
    );
    assert!(
        disp.contains(&encoded.to_string()),
        "Display must contain encoded size, got: {disp}"
    );
    assert!(
        disp.contains("1000"),
        "Display must contain budget, got: {disp}"
    );
    assert!(
        disp.contains(&plaintext.to_string()),
        "Display must contain plaintext size, got: {disp}"
    );
}
