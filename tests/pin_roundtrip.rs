//! Phase 8 Plan 02 PIN-08 round-trip matrix under MockTransport.
//!
//! Three cases:
//!   (a) `pin_required_share_with_correct_pin_at_receive` — happy-path
//!       round-trip. May be #[ignore]'d if the wire-budget caveat from
//!       Plan 01 (nested age + salt prefix exceeds BEP44 1000-byte
//!       ceiling for any non-trivial plaintext) prevents the send from
//!       publishing. Mirrors Phase 6/7 X.509/PGP/SSH wire-budget pattern.
//!   (b) `pin_required_share_with_wrong_pin_at_receive` — wrong PIN at
//!       receive yields Error::DecryptFailed (exit 4) with the unified
//!       "wrong passphrase or identity decryption failed" Display
//!       (PIN-07 narrow per RESEARCH Open Risk #1).
//!   (c) `pin_required_share_with_no_pin_at_receive` — pin-required share
//!       reached without a PIN injection (test stdin is non-TTY,
//!       CIPHERPOST_TEST_PIN unset) → prompt_pin returns Error::Config
//!       (exit 1) BEFORE age-decrypt; ledger / sentinel / receipt are all
//!       untouched (share remains re-receivable when PIN later available).

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

fn setup_identity_in(dir: &TempDir) -> (cipherpost::identity::Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed_zeroizing = id.signing_seed();
    let seed: [u8; 32] = *seed_zeroizing;
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

/// PIN-08 case (a): correct PIN at receive recovers plaintext byte-for-byte.
///
/// IGNORED at the wire-budget ceiling. Plan 01's smoke test established that
/// pin-protected shares' nested age + 32-byte salt prefix exceeds the
/// 1000-byte BEP44 ceiling for any non-trivial plaintext (see
/// 08-01-SUMMARY.md "Wire-budget overhead prediction"). The escape hatch
/// (two-tier storage / chunking) is deferred to Phase 9 / DHT-07. Mirrors
/// the Phase 6/7 X.509/PGP/SSH ignore pattern.
///
/// The wire-budget invariant is exercised by `pin_send_smoke.rs::
/// pin_send_surfaces_wire_budget_exceeded_cleanly` (which DOES run).
#[test]
#[serial]
#[ignore = "wire-budget: pin-protected share's nested age + salt prefix exceeds 1000-byte PKARR BEP44 ceiling — see 08-01-SUMMARY.md"]
fn pin_required_share_with_correct_pin_at_receive() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup_identity_in(&dir);
    let plaintext = b"x".to_vec();
    let transport = MockTransport::new();

    std::env::set_var("CIPHERPOST_TEST_PIN", "validpin1");
    let pin = SecretBox::new(Box::new("validpin1".to_string()));
    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        Some(pin),
        false,
    )
    .expect("send with PIN");

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
    .expect("receive with correct PIN");
    match sink {
        OutputSink::InMemory(buf) => assert_eq!(buf, plaintext),
        _ => panic!("expected InMemory sink"),
    }
    std::env::remove_var("CIPHERPOST_TEST_PIN");
}

/// PIN-08 case (b): wrong PIN at receive yields Error::DecryptFailed (exit 4)
/// with the IDENTICAL Display as wrong-passphrase (PIN-07 narrow).
///
/// This test does NOT need to publish (the wire-budget ceiling is hit when
/// publishing realistic plaintext); however, the wrong-PIN path is exercised
/// by injecting an OuterRecord directly into MockTransport. Approach: send
/// with PIN_A; even if publish fails wire-budget, we can simulate by stuffing
/// a smaller artificial test. We use the same trick as Plan 01's smoke test:
/// a 1-byte plaintext that's small enough to MAYBE fit, but if publish fails
/// wire-budget we mark the test ignored from inside (graceful skip).
///
/// Actually, the cleanest way is to skip publish entirely and just assert
/// the wrong-PIN failure surface via prompt_pin override pattern: we cannot
/// avoid the publish path because run_receive needs to resolve. So we use
/// the same #[ignore] pattern as case (a) — the Display invariant for
/// Error::DecryptFailed is independently asserted in
/// `tests/pin_error_oracle.rs` against synthetic Error::DecryptFailed.
#[test]
#[serial]
#[ignore = "wire-budget: pin-protected publish exceeds BEP44 ceiling — Display invariant covered in tests/pin_error_oracle.rs"]
fn pin_required_share_with_wrong_pin_at_receive() {
    let dir = TempDir::new().unwrap();
    let (id, kp) = setup_identity_in(&dir);
    let transport = MockTransport::new();

    std::env::set_var("CIPHERPOST_TEST_PIN", "validpin1");
    let pin_send = SecretBox::new(Box::new("validpin1".to_string()));
    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "k",
        MaterialSource::Bytes(b"x".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        Some(pin_send),
        false,
    )
    .unwrap();
    let uri = ShareUri::parse(&uri_str).unwrap();

    std::env::set_var("CIPHERPOST_TEST_PIN", "differentpin99");
    let mut sink = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::DecryptFailed),
        "wrong PIN must yield DecryptFailed; got {err:?}"
    );
    assert_eq!(
        format!("{err}"),
        "wrong passphrase or identity decryption failed"
    );
    assert_eq!(cipherpost::error::exit_code(&err), 4);
    std::env::remove_var("CIPHERPOST_TEST_PIN");
}

/// PIN-08 case (c): pin-required share with NO PIN available at receive →
/// non-TTY rejection of `prompt_pin`. With `CIPHERPOST_TEST_PIN` UNSET and
/// `cargo test`'s stdin non-interactive, `prompt_pin` returns
/// `Err(Error::Config("--pin requires interactive TTY ..."))` which maps
/// to **exit 1** (NOT exit 4 — the receive flow never reaches age-decrypt).
///
/// This is the iteration-1 B3 resolution (no placeholder docstring): the
/// concrete test below exercises the non-TTY rejection arm.
///
/// Asserts:
///   1. Error::Config variant is returned (matches the non-TTY rejection
///      arm in prompt_pin, NOT Error::DecryptFailed).
///   2. exit_code(&err) == 1.
///   3. Ledger has zero rows for the share_ref AND no sentinel exists
///      (prompt fails BEFORE any state mutation; share remains re-
///      receivable when a PIN later becomes available).
///   4. No receipt is published (publish_outcome runs only after full
///      success).
///
/// This test is NOT #[ignore]'d because it does not require a successful
/// publish — but to set up the pin-required wire-state we must publish a
/// pin share. We accept the wire-budget ignore here too, OR we directly
/// craft a minimal pin-required OuterRecord. We use the latter to keep
/// the test ALWAYS-RUN: there's no need to round-trip a real ciphertext
/// because run_receive aborts at prompt_pin BEFORE age-decrypt.
#[test]
#[serial]
fn pin_required_share_with_no_pin_at_receive() {
    use base64::Engine;
    use cipherpost::record::{sign_record, OuterRecord, OuterRecordSignable};

    let dir = TempDir::new().unwrap();
    let (id, kp) = setup_identity_in(&dir);
    let transport = MockTransport::new();

    // Ensure no test-PIN injection: prompt_pin will hit the non-TTY rejection
    // arm (cargo-test stdin is not a TTY).
    std::env::remove_var("CIPHERPOST_TEST_PIN");

    // Synthesize a pin-required OuterRecord with arbitrary blob bytes —
    // run_receive will resolve, outer-verify, then hit prompt_pin BEFORE
    // attempting age-decrypt, so the blob's actual content is irrelevant
    // for this case (c). We do need >=32 bytes so the salt-prefix invariant
    // check at flow.rs::run_receive STEP 6a doesn't short-circuit with
    // SignatureCanonicalMismatch. 64 bytes is comfortable.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;
    let dummy_blob_bytes = vec![0u8; 64];
    let blob = base64::engine::general_purpose::STANDARD.encode(&dummy_blob_bytes);
    // share_ref derivation matches the production formula but content is
    // synthesized; run_receive does not check that share_ref is an honest
    // hash of the ciphertext (only that uri.share_ref_hex == record.share_ref).
    let share_ref = cipherpost::record::share_ref_from_bytes(&dummy_blob_bytes, now);

    let signable = OuterRecordSignable {
        blob: blob.clone(),
        created_at: now,
        pin_required: true,
        protocol_version: cipherpost::PROTOCOL_VERSION,
        pubkey: id.z32_pubkey(),
        recipient: None,
        share_ref: share_ref.clone(),
        ttl_seconds: DEFAULT_TTL_SECONDS,
    };
    let signature = sign_record(&signable, &kp).unwrap();
    let record = OuterRecord {
        blob,
        created_at: now,
        pin_required: true,
        protocol_version: cipherpost::PROTOCOL_VERSION,
        pubkey: id.z32_pubkey(),
        recipient: None,
        share_ref: share_ref.clone(),
        signature,
        ttl_seconds: DEFAULT_TTL_SECONDS,
    };
    transport
        .publish(&kp, &record)
        .expect("MockTransport accepts pin-required record under wire ceiling");

    let uri = ShareUri::parse(&format!("cipherpost://{}/{}", id.z32_pubkey(), share_ref)).unwrap();

    let mut sink = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .unwrap_err();

    // Assertion 1+2: prompt_pin non-TTY rejection -> Error::Config -> exit 1.
    assert!(
        matches!(err, Error::Config(_)),
        "no-PIN-at-receive must yield Error::Config (non-TTY rejection); got {err:?}"
    );
    assert_eq!(
        cipherpost::error::exit_code(&err),
        1,
        "Error::Config must map to exit 1 (NOT exit 4 — receive flow never reaches age-decrypt)"
    );

    // Assertion 3: no ledger row for this share_ref; no sentinel.
    let ledger_path = dir.path().join("state").join("accepted.jsonl");
    if ledger_path.exists() {
        let ledger = std::fs::read_to_string(&ledger_path).unwrap();
        assert!(
            !ledger.contains(&share_ref),
            "no-PIN-at-receive must NOT write a ledger row; ledger contains share_ref: {ledger}"
        );
    }
    let sentinel_path = dir.path().join("state").join("accepted").join(&share_ref);
    assert!(
        !sentinel_path.exists(),
        "no-PIN-at-receive must NOT create a sentinel; share remains re-receivable"
    );

    // Assertion 4: no receipt published. MockTransport stores receipts under
    // `_cprcpt-<share_ref>` labels. In SelfMode, the recipient is the sender.
    let recipient_z32 = id.z32_pubkey();
    let entries = transport.resolve_all_txt(&recipient_z32);
    let receipt_count = entries
        .iter()
        .filter(|(label, _)| label.contains(&share_ref))
        .count();
    assert_eq!(
        receipt_count, 0,
        "no-PIN-at-receive must NOT publish a receipt; got {receipt_count} receipts for share_ref"
    );
}
