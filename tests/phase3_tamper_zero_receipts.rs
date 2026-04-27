//! Phase 3 Plan 03-04 — ROADMAP SC1 invariant: tampering with the ciphertext
//! between outer-verify and acceptance causes zero receipts to be published
//! on the DHT. Verified via MockTransport inspection — B's key should have
//! zero _cprcpt-* entries after a failed receive.
//!
//! Approach: construct a hand-built OuterRecord whose `blob` does NOT decrypt
//! cleanly (pre-inject a mutated age ciphertext), manually publish it under
//! A's key via MockTransport, then have B run_receive. The run_receive step
//! sequence aborts at step 6 (age-decrypt failure) — step 13 (publish_receipt)
//! is never reached.

#![cfg(feature = "mock")]

use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{run_receive, OutputSink};
use cipherpost::identity::Identity;
use cipherpost::record::{share_ref_from_bytes, sign_record, OuterRecord, OuterRecordSignable};
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::{Error, ShareUri, PROTOCOL_VERSION};
use secrecy::SecretBox;
use serial_test::serial;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tempfile::TempDir;
use zeroize::Zeroizing;

fn deterministic_identity_at(home: &std::path::Path, seed: [u8; 32]) -> (Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", home);
    fs::create_dir_all(home).unwrap();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    let pw = SecretBox::new(Box::new("pw".to_string()));
    let seed_z = Zeroizing::new(seed);
    let blob = crypto::encrypt_key_envelope(&seed_z, &pw).unwrap();
    let path = home.join("secret_key");
    let mut f = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    f.write_all(&blob).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let id = cipherpost::identity::load(&pw).unwrap();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}

#[test]
#[serial]
fn tampered_ciphertext_produces_zero_receipts() {
    let dir_a = TempDir::new().unwrap();
    let (_id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let a_z32 = kp_a.public_key().to_z32();

    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();

    let transport = MockTransport::new();

    // 1. Build an INVALID OuterRecord whose inner signature is valid over the Signable
    //    but whose `blob` is garbage that won't age-decrypt. The inner
    //    OuterRecordSignable sig verifies (it's over the blob string including
    //    the garbage); MockTransport's publish() accepts it (no outer crypto check
    //    in mock mode). run_receive will fail at step 6 (age-decrypt) with
    //    Error::DecryptFailed.
    use base64::Engine;
    let created_at: i64 = 1_700_000_000;
    let garbage_ciphertext: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01, 0x02, 0x03];
    let garbage_blob_b64 = base64::engine::general_purpose::STANDARD.encode(&garbage_ciphertext);
    let share_ref = share_ref_from_bytes(&garbage_ciphertext, created_at);
    let signable = OuterRecordSignable {
        blob: garbage_blob_b64.clone(),
        created_at,
        pin_required: false,
        protocol_version: PROTOCOL_VERSION,
        pubkey: a_z32.clone(),
        recipient: Some(b_z32.clone()),
        share_ref: share_ref.clone(),
        ttl_seconds: 86_400,
    };
    let sig = sign_record(&signable, &kp_a).expect("sign_record over garbage blob");
    let tampered_record = OuterRecord {
        blob: signable.blob,
        created_at: signable.created_at,
        pin_required: signable.pin_required,
        protocol_version: signable.protocol_version,
        pubkey: signable.pubkey,
        recipient: signable.recipient,
        share_ref: signable.share_ref.clone(),
        signature: sig,
        ttl_seconds: signable.ttl_seconds,
    };
    transport
        .publish(&kp_a, &tampered_record)
        .expect("publish tampered record");

    // 2. Construct the share URI so B's run_receive can look it up.
    let uri_str = ShareUri::format(&a_z32, &share_ref);
    let uri = ShareUri::parse(&uri_str).expect("parse share URI");

    // 3. B receives. Expect an error — step 6 (age-decrypt) fails because the blob
    //    is garbage and cannot be decrypted by age. SC1's contract: step 13 NEVER runs.
    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id_b,
        &transport,
        &kp_b,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect_err("tampered ciphertext must reject before step 13");
    // Accept any non-success error — the important invariant is ZERO-RECEIPTS below.
    let _err_str = format!("{err:?}");

    // 4. SC1 invariant: B's key has ZERO _cprcpt-* entries.
    let b_entries = transport.resolve_all_txt(&b_z32);
    let receipt_count = b_entries
        .iter()
        .filter(|(l, _)| l.starts_with(cipherpost::DHT_LABEL_RECEIPT_PREFIX))
        .count();
    assert_eq!(
        receipt_count, 0,
        "ROADMAP SC1 invariant violated: tampered ciphertext produced {receipt_count} receipt(s); expected 0"
    );

    // 5. resolve_all_cprcpt under B's key must return NotFound (nothing to list).
    let lookup_err = transport
        .resolve_all_cprcpt(&b_z32)
        .expect_err("must be NotFound when no receipts");
    assert!(
        matches!(lookup_err, Error::NotFound),
        "expected NotFound, got {lookup_err:?}"
    );
}
