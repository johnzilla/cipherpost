//! Phase 9 Plan 01 (DHT-07): pin × burn × ~2KB GenericSecret wire-budget
//! composite — third instance of the PITFALLS.md #22 per-variant size-
//! check pattern after Phase 6 X.509 and Phase 7 PGP/SSH.
//!
//! Asserts: a share with `pin_required=true` + `burn_after_read=true`
//! carrying a 2 KB synthesized GenericSecret payload surfaces
//! `Error::WireBudgetExceeded` cleanly at send (NOT a pkarr-internal
//! panic; NOT InvalidMaterial — the payload is GenericSecret per D-P9-E1
//! and Pitfall E in 09-RESEARCH.md).
//!
//! ## Why GenericSecret, not PgpKey
//!
//! The phase tag "pin+burn+pgp" reads as "use the PGP material variant",
//! but `MaterialVariant::PgpKey` would trigger Phase 7's PGP packet-
//! stream ingest parser at `payload::ingest::pgp_key`, which rejects
//! random bytes with `Error::InvalidMaterial { variant: "pgp_key", .. }`
//! (exit 1) — the test would never reach the wire-budget check.
//! GenericSecret skips the parser entirely and exercises the byte-budget
//! path directly. CONTEXT.md D-P9-E1 + 09-RESEARCH.md Pitfall E both
//! call this out.
//!
//! `#[serial]` — env mutation (CIPHERPOST_TEST_PIN, CIPHERPOST_HOME).

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::{run_send, MaterialSource, SendMode, DEFAULT_TTL_SECONDS};
use cipherpost::transport::MockTransport;
use cipherpost::Error;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

fn setup(dir: &TempDir) -> (cipherpost::identity::Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

#[test]
#[serial]
fn pin_burn_realistic_payload_surfaces_wire_budget_exceeded() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup(&dir);
    let transport = MockTransport::new();

    // CIPHERPOST_TEST_PIN injection — Phase 8 D-P8-12 cfg-gated env override
    // for non-TTY test environments.
    std::env::set_var("CIPHERPOST_TEST_PIN", "validpin1");
    let pin = SecretBox::new(Box::new("validpin1".to_string()));

    let plaintext = vec![0u8; 2048]; // synthesized 2KB; not parser-tested
    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "pin+burn+2KB compose",
        MaterialSource::Bytes(plaintext),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        Some(pin),
        true, // burn
    )
    .expect_err("pin + burn + 2 KB GenericSecret must overflow wire budget");

    match err {
        Error::WireBudgetExceeded {
            encoded,
            budget,
            plaintext: _,
        } => {
            assert_eq!(budget, 1000);
            assert!(
                encoded > budget,
                "encoded ({}) must exceed budget ({})",
                encoded,
                budget
            );
            // Phase 9 Plan 01: surface the actual encoded byte count for
            // SPEC.md §Pitfall #22 update (Plan 09-03). Visible only with
            // `cargo test --features mock wire_budget_compose -- --nocapture`.
            eprintln!(
                "DHT-07 wire-budget composite: encoded={} budget={} (overflow={})",
                encoded,
                budget,
                encoded - budget
            );
        }
        other => panic!(
            "expected WireBudgetExceeded, got {:?} — either budget protocol \
             changed, ingest rejected before budget check (regression), OR \
             the 2KB synthesized payload no longer overflows (pin nesting + \
             burn-flag + JCS overhead must always exceed 1000 B)",
            other
        ),
    }

    std::env::remove_var("CIPHERPOST_TEST_PIN");
}
