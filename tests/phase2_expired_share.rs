//! SC2: expired share aborts with Error::Expired (exit 2), distinct from
//! signature failures. TTL is enforced against the inner signed
//! `created_at + ttl_seconds`.

use base64::Engine;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{run_receive, OutputSink};
use cipherpost::record::{share_ref_from_bytes, sign_record, OuterRecord, OuterRecordSignable};
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::{ShareUri, PROTOCOL_VERSION};
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn expired_share_aborts_with_error_expired_exit_2() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);

    // Synthesize an expired OuterRecord directly. Inner verify only checks the
    // signature over the SIGNABLE struct, not that the blob is decryptable age
    // ciphertext — so a short non-age placeholder works. TTL is checked BEFORE
    // decrypt in D-RECV-01 step 5.
    let blob = base64::engine::general_purpose::STANDARD.encode(b"placeholder");
    let created_at = 1_000_000_i64; // 1970-01-12 — long past
    let ttl_seconds = 1_u64;
    let share_ref = share_ref_from_bytes(blob.as_bytes(), created_at);
    let signable = OuterRecordSignable {
        blob: blob.clone(),
        created_at,
        pin_required: false,
        protocol_version: PROTOCOL_VERSION,
        pubkey: kp.public_key().to_z32(),
        recipient: None,
        share_ref: share_ref.clone(),
        ttl_seconds,
    };
    let signature = sign_record(&signable, &kp).unwrap();
    let record = OuterRecord {
        blob,
        created_at,
        pin_required: false,
        protocol_version: PROTOCOL_VERSION,
        pubkey: kp.public_key().to_z32(),
        recipient: None,
        share_ref: share_ref.clone(),
        signature,
        ttl_seconds,
    };

    let transport = MockTransport::new();
    transport.publish(&kp, &record).unwrap();

    let uri = ShareUri {
        sender_z32: kp.public_key().to_z32(),
        share_ref_hex: share_ref,
    };
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
        matches!(err, cipherpost::Error::Expired),
        "expected Expired, got {err:?}"
    );
    assert_eq!(cipherpost::error::exit_code(&err), 2);
}
