//! SSH-09: MockTransport self-mode round-trip for Material::SshKey.
//!
//! D-P7-03 fallback active from day 1: SSH OpenSSH v1 (even Ed25519-minimal)
//! exceeds the 1000-byte PKARR BEP44 ceiling per research GAP. The full
//! round-trip test is `#[ignore]`'d with the EXACT wire-budget note text. The
//! POSITIVE WireBudgetExceeded test (D-P7-02 mirror for SSH) is ACTIVE and
//! verifies the error path is clean.
//!
//! Mirrors tests/pgp_roundtrip.rs (Plan 04 sibling) and
//! tests/x509_roundtrip.rs (Phase 6 #[ignore]'d round-trip pattern).

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

const SSH_FIXTURE: &[u8] = include_bytes!("fixtures/material_ssh_fixture.openssh-v1");

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

/// SSH-09 / D-P7-03 fallback active from day 1: SSH OpenSSH v1 exceeds the
/// 1000-byte BEP44 ceiling. Re-enable when v1.2 two-tier storage lands.
#[test]
#[ignore = "wire-budget: minimum OpenSSH v1 Ed25519 blob exceeds 1000-byte BEP44 ceiling (~1340 B encoded) — see Pitfall #22 / v1.2 milestone"]
#[serial]
fn ssh_self_round_trip_recovers_canonical_bytes() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();
    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "ssh handoff",
        MaterialSource::Bytes(SSH_FIXTURE.to_vec()),
        MaterialVariant::SshKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect("would pass if wire budget were larger");
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
    // On re-enable: bytes match the CANONICAL re-encoded form per D-P7-11,
    // NOT necessarily the input bytes. Plan 05 documented this invariant.
}

/// D-P7-02 positive WireBudgetExceeded mirror: ANY OpenSSH v1 fixture exceeds
/// the budget. This test verifies the error surface is clean (NOT InvalidMaterial,
/// NOT panic) — the user gets a specific `WireBudgetExceeded { encoded, budget,
/// plaintext }` they can act on (e.g., wait for v1.2 two-tier storage).
#[test]
#[serial]
fn ssh_send_realistic_key_surfaces_wire_budget_exceeded_cleanly() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();
    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "ssh handoff",
        MaterialSource::Bytes(SSH_FIXTURE.to_vec()),
        MaterialVariant::SshKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect_err("SSH OpenSSH v1 must overflow wire budget");
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
        }
        other => panic!(
            "expected WireBudgetExceeded, got {:?} — SSH ingest may have rejected before \
             the budget check (regression), or the fixture is no longer over-budget",
            other
        ),
    }
}

/// SSH-05 / D-P7-13: --armor rejected with the variant-specific self-armored
/// rationale. The full e2e --armor receive path is blocked by the wire budget
/// (we can't construct a real SshKey share to call run_receive against), so
/// this test pins the literal at the source level — the same approach Plan 03
/// took for the GenericSecret literal in tests/x509_roundtrip.rs documentation
/// reference. Plan 07's GREEN commit landed this literal in src/flow.rs's
/// run_receive Material::SshKey arm; this test is the regression guard.
#[test]
#[serial]
fn armor_on_ssh_share_rejected_with_self_armored_error() {
    let src = std::fs::read_to_string("src/flow.rs")
        .expect("src/flow.rs must be readable in test environment");
    assert!(
        src.contains("\"--armor not applicable to ssh-key — OpenSSH v1 is self-armored\""),
        "Plan 07 SSH armor-rejection literal missing in src/flow.rs — \
         the variant-specific rationale (D-P7-13) is the regression target"
    );
}

/// SSH-01 / D-P7-12: legacy PEM at send time → SshKeyFormatNotSupported.
/// Verifies the error fires at INGEST (before wire budget). Same shape as
/// Plan 04's `pgp_malformed_packet_send_rejected_at_ingest`.
#[test]
#[serial]
fn ssh_legacy_pem_send_rejected_at_ingest() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();
    let legacy = b"-----BEGIN RSA PRIVATE KEY-----\nMIIEow...\n-----END RSA PRIVATE KEY-----\n";
    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "legacy",
        MaterialSource::Bytes(legacy.to_vec()),
        MaterialVariant::SshKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect_err("legacy PEM must fail at ingest");
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "legacy PEM via --material ssh-key must trigger SshKeyFormatNotSupported, got: {:?}",
        err
    );
}

/// SSH-08: malformed OpenSSH v1 body at send time → InvalidMaterial generic
/// reason (different remediation class than format-rejection).
#[test]
#[serial]
fn ssh_malformed_openssh_v1_send_rejected_at_ingest() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();
    let malformed = b"-----BEGIN OPENSSH PRIVATE KEY-----\nGARBAGE\n-----END OPENSSH PRIVATE KEY-----\n";
    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "malformed",
        MaterialSource::Bytes(malformed.to_vec()),
        MaterialVariant::SshKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect_err("malformed body must fail at ingest");
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "ssh_key");
            assert_eq!(reason, "malformed OpenSSH v1 blob");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}
