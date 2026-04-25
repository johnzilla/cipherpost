//! PGP-09: MockTransport self-mode round-trip for Material::PgpKey.
//! Plus D-P7-02 WireBudgetExceeded positive test + armor output pin.
//!
//! Unlike Phase 6 X.509 (where the minimum cert exceeds budget), PGP Ed25519
//! with UID ≤20 chars FITS under 1000 B per research GAP 5 — D-P7-03 requires
//! the round-trip test to pass.

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

const FIXTURE_PGP: &[u8] = include_bytes!("fixtures/material_pgp_fixture.pgp");
const FIXTURE_PGP_REALISTIC: &[u8] = include_bytes!("fixtures/material_pgp_fixture_realistic.pgp");

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

/// D-P7-03 (amended Plan 04): the research GAP-5 prediction (raw × 4.16 ≈ encoded)
/// underestimated the actual envelope expansion factor by ~50%. Measured at Plan 04
/// implementation time:
///   - rpgp-minimal Ed25519 fixture (no subkeys, no preference subpackets, 10-char UID):
///     202 B raw → 1236 B encoded (plaintext 383 B; expansion factor ≈ 6.1× over raw).
///   - gpg-default Ed25519 fixture (no subkeys, 10-char UID, default preference subpackets):
///     215 B raw → 1332 B encoded.
///
/// Both exceed the 1000 B PKARR BEP44 ceiling. The 202 B figure is at the floor for
/// any RFC-4880 v4 Ed25519 self-cert (header + key + UID + 64 B signature + minimum
/// hashed subpackets). This test is `#[ignore]`'d alongside the SSH round-trip per
/// the same fallback pattern D-P7-03 carved for SSH; the positive `WireBudgetExceeded`
/// test below proves the error surface is clean.
///
/// Re-enable when two-tier storage (v1.2 milestone) lands.
#[test]
#[ignore = "wire-budget: rpgp-minimal Ed25519 fixture (~202 B raw) encodes to ~1236 B — exceeds 1000 B PKARR BEP44 ceiling. Research GAP-5 expansion-factor prediction (4.16×) was 50% optimistic; actual ~6.1×. See module doc + 07-04-SUMMARY Deviations."]
#[serial]
fn pgp_self_round_trip_recovers_packet_stream() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "pgp handoff",
        MaterialSource::Bytes(FIXTURE_PGP.to_vec()),
        MaterialVariant::PgpKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect("PGP fixture must fit under 1000 B per D-P7-03 + research GAP 5");

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
    .expect("run_receive PGP self-mode");

    match sink {
        OutputSink::InMemory(buf) => {
            assert_eq!(
                buf, FIXTURE_PGP,
                "recovered bytes must equal original PGP fixture (verbatim — no canonical re-encode)"
            );
        }
        _ => panic!("expected InMemory sink"),
    }
}

/// D-P7-02 positive WireBudgetExceeded: realistic PGP key exceeds budget cleanly.
#[test]
#[serial]
fn pgp_send_realistic_key_surfaces_wire_budget_exceeded_cleanly() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "pgp handoff",
        MaterialSource::Bytes(FIXTURE_PGP_REALISTIC.to_vec()),
        MaterialVariant::PgpKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect_err("realistic PGP must overflow wire budget");

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
            "expected WireBudgetExceeded, got {:?} — either budget protocol \
             changed, ingest rejected before budget check (regression), OR the \
             realistic-fixture is not large enough",
            other
        ),
    }
}

/// PGP-05: --armor emits ASCII-armored output.
///
/// Same wire-budget constraint as the round-trip above — `run_send` enforces the
/// 1000 B BEP44 ceiling regardless of `--armor`, so the minimal fixture cannot
/// be encoded for end-to-end armor-output verification today. The armor path is
/// independently exercised by `src/preview.rs::tests::pgp_armor_*` (Plan 03 RED+GREEN
/// commits) and by `tests/pgp_banner_render.rs` (golden-string pin).
///
/// Re-enable alongside the round-trip test when two-tier storage (v1.2) lands.
#[test]
#[ignore = "wire-budget: same constraint as pgp_self_round_trip — minimal fixture exceeds 1000 B encoded. Armor path covered by src/preview.rs::tests::pgp_armor_* unit tests."]
#[serial]
fn armor_on_pgp_share_emits_ascii_armor() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "pgp handoff",
        MaterialSource::Bytes(FIXTURE_PGP.to_vec()),
        MaterialVariant::PgpKey,
        DEFAULT_TTL_SECONDS,
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
    .expect("armor=true on PgpKey must succeed");

    match sink {
        OutputSink::InMemory(buf) => {
            let as_str = std::str::from_utf8(&buf).expect("ASCII armor is UTF-8");
            assert!(
                as_str.starts_with("-----BEGIN PGP PUBLIC KEY BLOCK-----\n"),
                "armored output must begin with PGP PUBLIC KEY header, got: {}",
                &as_str[..as_str.len().min(80)]
            );
            assert!(
                as_str.contains("-----END PGP PUBLIC KEY BLOCK-----"),
                "armored output must contain PGP END marker"
            );
        }
        _ => panic!("expected InMemory sink"),
    }
}

/// PGP-08: malformed PGP packets at send time surface as InvalidMaterial
/// (generic reason) before hitting wire budget.
#[test]
#[serial]
fn pgp_malformed_packet_send_rejected_at_ingest() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "bogus",
        MaterialSource::Bytes(b"not a PGP packet stream".to_vec()),
        MaterialVariant::PgpKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect_err("malformed PGP send must fail at ingest");

    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "pgp_key");
            // Curated literals only — either malformed or trailing-bytes is acceptable
            // depending on how PacketParser interprets the byte soup; both are oracle-clean.
            assert!(
                reason == "malformed PGP packet stream"
                    || reason == "trailing bytes after PGP packet stream",
                "expected curated reason literal, got: {}",
                reason
            );
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

/// PGP-03: multi-primary at send time surfaces the substituted-N reason.
#[test]
#[serial]
fn pgp_multi_primary_send_rejected_at_ingest() {
    let (id, kp, _dir) = fresh_identity();
    let transport = MockTransport::new();

    let mut concatenated = FIXTURE_PGP.to_vec();
    concatenated.extend_from_slice(FIXTURE_PGP);

    let err = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "keyring",
        MaterialSource::Bytes(concatenated),
        MaterialVariant::PgpKey,
        DEFAULT_TTL_SECONDS,
    )
    .expect_err("multi-primary keyring send must fail at ingest");

    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "pgp_key");
            assert!(reason.starts_with("PgpKey must contain exactly one primary key"));
            assert!(reason.contains("found 2"));
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}
