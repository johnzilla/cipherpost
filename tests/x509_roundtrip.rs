//! X509-09: MockTransport self-mode round-trip for Material::X509Cert.
//!
//! Mirrors tests/phase2_self_round_trip.rs. Covers:
//!   - Raw-DER send -> raw-DER receive (armor=false)  [#[ignore] — wire budget]
//!   - Raw-DER send -> PEM-armored receive (armor=true)  [#[ignore] — wire budget]
//!   - PEM send -> DER receive (ingest normalizes PEM to canonical DER)  [#[ignore]]
//!   - --armor on a non-X509 (GenericSecret) share rejected
//!   - Malformed DER rejected at ingest (pre-wire-budget)
//!   - Realistic X.509 cert → clean `WireBudgetExceeded` error (covers the
//!     "expected-to-fail" case flagged in `.planning/phases/06-typed-material-x509cert/
//!     06-CONTEXT.md §Wire-budget note (Pitfall #22)`)
//!
//! **DEFERRED (Phase 6 Plan 04 → a future milestone):**
//! Full round-trip of a realistic X.509 certificate (388-byte fixture DER)
//! exceeds the 1000-byte PKARR BEP44 wire budget. The minimum Ed25519 cert
//! with any standard DN is ~234 bytes DER → ~420 B JCS envelope → ~640 B age
//! ciphertext → ~850 B base64 blob → ~1290 B OuterRecord JSON → >1000 B
//! encoded packet. This is not a cipherpost bug — it's the BEP44 mutable-item
//! signed-packet protocol ceiling. The architectural fix (two-tier storage:
//! small envelope in DHT points to encrypted blob in external store) belongs
//! in a later phase. See SUMMARY.md §Deviations for the full decision record.
//!
//! The tests that *would* exercise the full round-trip are `#[ignore]`'d here
//! (not removed) so Phase 7+ can opt them in when two-tier storage lands. The
//! code paths they cover are exercised at unit-test granularity via
//! `src/flow.rs` run_send / run_receive match-arm tests + `material_x509_ingest.rs`.

use base64::Engine;
use cipherpost::cli::MaterialVariant;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::{Error, ShareUri};
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

const FIXTURE_DER: &[u8] = include_bytes!("fixtures/x509_cert_fixture.der");

fn fresh_identity() -> (cipherpost::identity::Identity, pkarr::Keypair, TempDir) {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed_zeroizing = id.signing_seed();
    let seed: [u8; 32] = *seed_zeroizing;
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp, dir)
}

fn pem_armor(der: &[u8]) -> Vec<u8> {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::new();
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

/// **DEFERRED:** Full DER round-trip requires a plaintext cert small enough to
/// fit under the 1000-byte PKARR BEP44 wire budget, which is impossible for
/// any standard X.509 cert (min ~234 B DER; ciphertext+framing blows past 1000 B).
/// Re-enable when two-tier storage lands. Test logic is preserved so the ship
/// gate is ready the moment the infra fix ships.
#[test]
#[ignore = "wire-budget: realistic X.509 cert exceeds 1000-byte PKARR BEP44 ceiling — see module doc"]
#[serial]
fn x509_self_round_trip_recovers_der_bytes() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "leaf cert",
        MaterialSource::Bytes(FIXTURE_DER.to_vec()),
        MaterialVariant::X509Cert,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("run_send X509 self-mode");

    let uri = ShareUri::parse(&uri_str).expect("valid URI");
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        /*armor=*/ false,
    )
    .expect("run_receive X509 self-mode");

    match sink {
        OutputSink::InMemory(buf) => {
            assert_eq!(
                buf, FIXTURE_DER,
                "recovered DER bytes must equal original fixture"
            );
        }
        _ => panic!("expected InMemory sink"),
    }
}

/// **DEFERRED:** same wire-budget constraint as the non-armor round-trip above.
#[test]
#[ignore = "wire-budget: realistic X.509 cert exceeds 1000-byte PKARR BEP44 ceiling"]
#[serial]
fn x509_self_round_trip_with_armor_produces_pem() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "leaf cert",
        MaterialSource::Bytes(FIXTURE_DER.to_vec()),
        MaterialVariant::X509Cert,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .unwrap();

    let uri = ShareUri::parse(&uri_str).unwrap();
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        /*armor=*/ true,
    )
    .unwrap();

    match sink {
        OutputSink::InMemory(buf) => {
            let s = std::str::from_utf8(&buf).expect("PEM output is ASCII");
            assert!(
                s.starts_with("-----BEGIN CERTIFICATE-----\n"),
                "armor output must start with CERTIFICATE header, got: {}",
                &s[..std::cmp::min(64, s.len())]
            );
            assert!(
                s.ends_with("-----END CERTIFICATE-----\n"),
                "armor output must end with CERTIFICATE footer, got tail: {}",
                &s[s.len().saturating_sub(64)..]
            );
            let body: String = s
                .lines()
                .filter(|l| !l.starts_with("-----"))
                .collect::<Vec<_>>()
                .join("");
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(body.as_bytes())
                .expect("base64 decode of PEM body");
            assert_eq!(
                decoded, FIXTURE_DER,
                "armor body decoded must equal original DER"
            );
        }
        _ => panic!("expected InMemory sink"),
    }
}

/// **DEFERRED:** same wire-budget constraint.
#[test]
#[ignore = "wire-budget: realistic X.509 cert exceeds 1000-byte PKARR BEP44 ceiling"]
#[serial]
fn x509_pem_input_normalizes_to_canonical_der() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let pem_input = pem_armor(FIXTURE_DER);

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "leaf cert via PEM",
        MaterialSource::Bytes(pem_input),
        MaterialVariant::X509Cert,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("PEM ingest must succeed");

    let uri = ShareUri::parse(&uri_str).unwrap();
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        /*armor=*/ false,
    )
    .unwrap();

    match sink {
        OutputSink::InMemory(buf) => {
            assert_eq!(
                buf, FIXTURE_DER,
                "PEM ingest normalized to canonical DER; recovered bytes must equal original DER (not the PEM wrapper)"
            );
        }
        _ => panic!("expected InMemory sink"),
    }
}

/// X509 send of a realistic cert surfaces `Error::WireBudgetExceeded` cleanly,
/// NOT `Error::InvalidMaterial`, NOT a PKARR-internal panic. Covers the
/// CONTEXT.md §"Wire-budget note (Pitfall #22)" requirement and serves as the
/// "expected-to-fail" case from research §line 228.
#[test]
#[serial]
fn x509_send_realistic_cert_surfaces_wire_budget_exceeded_cleanly() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "leaf cert",
        MaterialSource::Bytes(FIXTURE_DER.to_vec()),
        MaterialVariant::X509Cert,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect_err("realistic X.509 cert must overflow wire budget");

    // Must be WireBudgetExceeded — not InvalidMaterial, not a PKARR internal.
    let (encoded, budget, plaintext) = match err {
        Error::WireBudgetExceeded {
            encoded,
            budget,
            plaintext,
        } => (encoded, budget, plaintext),
        other => panic!(
            "expected WireBudgetExceeded, got {other:?}. This means either the wire budget \
             protocol changed or ingest failed before the budget check (which is a regression)."
        ),
    };
    assert_eq!(budget, 1000, "PKARR BEP44 budget is 1000 bytes");
    assert!(
        encoded > budget,
        "encoded must exceed budget ({encoded} > {budget})"
    );
    assert!(
        plaintext >= FIXTURE_DER.len(),
        "plaintext ({}) should be at least fixture DER length ({}) — JCS envelope adds framing",
        plaintext,
        FIXTURE_DER.len()
    );
}

/// `--armor` on a non-X509 (GenericSecret) share is rejected at run_receive
/// with a stable `Error::Config` literal. This path runs BEFORE wire budget
/// is consulted (tiny 9-byte plaintext easily fits). Phase 7 Plan 03 widened
/// the message from `"--armor requires --material x509-cert"` to
/// `"--armor requires --material x509-cert or pgp-key"` as PGP gained
/// armor-output support — the literal is the FULL list of armor-permitted
/// variants so users see the accurate accept-set on rejection.
#[test]
#[serial]
fn armor_on_generic_secret_rejected_with_config_error() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    // Send a plain GenericSecret.
    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "plain secret",
        MaterialSource::Bytes(b"topsecret".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .unwrap();

    let uri = ShareUri::parse(&uri_str).unwrap();
    let mut sink = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        /*armor=*/ true,
    )
    .expect_err("armor on non-X509 must be rejected");

    match err {
        Error::Config(msg) => {
            assert_eq!(msg, "--armor requires --material x509-cert or pgp-key");
        }
        other => panic!("expected Error::Config, got {other:?}"),
    }
}

/// Malformed DER is rejected at ingest (pre-wire-budget) with
/// `Error::InvalidMaterial{variant:"x509_cert", reason:"malformed DER"}`.
#[test]
#[serial]
fn x509_malformed_der_send_rejected_at_ingest() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "bogus",
        MaterialSource::Bytes(b"not a DER cert".to_vec()),
        MaterialVariant::X509Cert,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect_err("malformed DER send must fail at ingest");

    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "x509_cert");
            assert_eq!(reason, "malformed DER");
        }
        other => panic!("expected InvalidMaterial, got {other:?}"),
    }
}
