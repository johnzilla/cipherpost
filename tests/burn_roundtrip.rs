//! Phase 8 Plan 04 (BURN-09): two consecutive receives of the same burn
//! share return exit 0 then exit 7. Receipt published exactly ONCE on
//! the first successful receive (BURN-04).
//!
//! Mirrors tests/phase2_idempotent_re_receive.rs but with exit-7
//! (Declined) expected on the second call instead of idempotent Ok(()).
//!
//! ## Receipt-on-burn lock (RESEARCH Open Risk #4)
//!
//! Plan 04 deliberately does NOT add a `if !envelope.burn_after_read {
//! publish_receipt(...) }` guard. The receipt-count assertion below
//! encodes that lock: exactly ONE receipt under
//! `_cprcpt-<share_ref_hex>` after the first burn-receive, even after a
//! subsequent declined re-receive. Receipt = delivery confirmation;
//! burn does NOT suppress attestation.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::error::exit_code;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::test_paths::ledger_path;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::{Error, ShareUri};
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

/// Phase 8 Plan 04 (B1 fix): receipt-count helper. MockTransport does NOT
/// expose a `count_receipts_for(share_ref)` method. The actual API
/// surface is `MockTransport::resolve_all_txt(pubkey_z32) -> Vec<(label,
/// json)>` (verified at src/transport.rs:313-321 — the test helper for
/// Phase 3 receipts integration tests). Receipt labels follow the format
/// `_cprcpt-<share_ref_hex>`, so we filter on exact-match label. The
/// recipient pubkey for SelfMode shares is the sender identity itself.
fn count_receipts_for_share_ref(
    transport: &MockTransport,
    recipient_z32: &str,
    share_ref_hex: &str,
) -> usize {
    let label_prefix = format!("_cprcpt-{}", share_ref_hex);
    transport
        .resolve_all_txt(recipient_z32)
        .iter()
        .filter(|(label, _json)| label == &label_prefix)
        .count()
}

#[test]
#[serial]
fn burn_share_first_receive_succeeds_second_returns_exit_7() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);

    let plaintext = b"burnable_payload".to_vec();
    let transport = MockTransport::new();

    // Send with --burn (no --pin). Tiny GenericSecret in self-mode WITHOUT
    // PIN nesting fits within the 1000-byte BEP44 ceiling, so the round
    // trip runs end-to-end (matches the Plan 03 burn_send_smoke pattern).
    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None, // pin=None
        true, // burn=true
    )
    .expect("run_send burn-only");
    let uri = ShareUri::parse(&uri_str).unwrap();

    // First receive: succeeds; plaintext recovered.
    let mut sink1 = OutputSink::InMemory(Vec::new());
    run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink1,
        &AutoConfirmPrompter,
        false,
    )
    .expect("first receive of burn share");
    match sink1 {
        OutputSink::InMemory(buf) => {
            assert_eq!(buf, plaintext, "first receive must recover plaintext");
        }
        _ => panic!("InMemory sink expected"),
    }

    // Ledger row must carry state=burned. Use the test_paths re-export
    // (W5 fix; flow.rs path layout is the source of truth).
    let lp = ledger_path();
    let ledger =
        std::fs::read_to_string(&lp).expect("ledger file must exist after first burn receive");
    assert!(
        ledger.contains(r#""state":"burned""#),
        "burn ledger row must carry state=burned; ledger contents: {}",
        ledger
    );

    // Second receive: returns Err(Declined) (exit 7). The Plan 03 dormant
    // LedgerState::Burned arm in run_receive STEP 1 fires here because
    // Plan 04 just wrote the burn row.
    let mut sink2 = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink2,
        &AutoConfirmPrompter,
        false,
    )
    .expect_err("second receive of burn share must error");
    assert!(
        matches!(err, Error::Declined),
        "second receive must yield Error::Declined (exit 7); got {:?}",
        err
    );
    assert_eq!(exit_code(&err), 7, "exit_code(Declined) must be 7");

    // Second receive must NOT have produced any output bytes — STEP 1
    // short-circuit precedes STEP 11 emit. (Defensive assert; loss of
    // this property would mean burn gives up its single-consumption
    // contract under re-receive.)
    match sink2 {
        OutputSink::InMemory(buf) => assert!(
            buf.is_empty(),
            "declined second receive must not emit any bytes; got {} bytes",
            buf.len()
        ),
        _ => panic!("InMemory sink expected"),
    }

    // Receipt count == 1: BURN-04 explicit assertion. The receipt was
    // published on the FIRST successful receive; the second (declined)
    // call must NOT publish a second receipt — no publish_outcome
    // closure runs after the STEP 1 Declined return. Recipient = sender
    // identity in SelfMode.
    let recipient_z32 = id.z32_pubkey();
    let receipt_count =
        count_receipts_for_share_ref(&transport, &recipient_z32, &uri.share_ref_hex);
    assert_eq!(
        receipt_count, 1,
        "exactly one receipt published after burn round-trip (BURN-04 lock); got {}",
        receipt_count
    );
}
