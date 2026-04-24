//! Phase 3 Plan 03-04 — D-IT-01 test 1: end-to-end two-identity round trip
//! asserting RCPT-01 (receipt published) + RCPT-02 (run_receipts fetches it)
//! + RCPT-03 (cryptographic verify succeeds).
//!
//! Harness pattern copied from tests/phase2_share_round_trip.rs:1-47.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receipts, run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::identity::Identity;
use cipherpost::receipt::{verify_receipt, Receipt};
use cipherpost::transport::MockTransport;
use cipherpost::{ShareUri, DHT_LABEL_RECEIPT_PREFIX};
use secrecy::SecretBox;
use serial_test::serial;
use sha2::{Digest, Sha256};
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
fn a_sends_to_b_receipt_published_and_verifiable() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let a_z32 = kp_a.public_key().to_z32();

    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();

    let transport = MockTransport::new();

    // 1. A switches CIPHERPOST_HOME and publishes to B.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let material_bytes = b"e2e phase3 secret";
    let uri_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "e2e test",
        MaterialSource::Bytes(material_bytes.to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
    )
    .expect("A run_send");
    let uri = ShareUri::parse(&uri_str).expect("parse share URI");

    // 2. B switches CIPHERPOST_HOME and receives + accepts.
    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(
        &id_b,
        &transport,
        &kp_b,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .expect("B run_receive with AutoConfirm");

    // Assert material was written to B's sink byte-for-byte.
    if let OutputSink::InMemory(ref buf) = sink {
        assert_eq!(
            buf.as_slice(),
            material_bytes,
            "B's decrypted output must equal A's input"
        );
    } else {
        panic!("sink was not InMemory");
    }

    // 3. Assert receipt is published under B's key at _cprcpt-<share_ref>.
    let entries = transport.resolve_all_txt(&b_z32);
    let label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, uri.share_ref_hex);
    let receipt_entry = entries
        .iter()
        .find(|(l, _)| l == &label)
        .expect("_cprcpt-<share_ref> must exist under B's key after accept");

    // 4. Parse + verify the receipt.
    let receipt: Receipt = serde_json::from_str(&receipt_entry.1).expect("receipt JSON must parse");
    verify_receipt(&receipt).expect("verify_receipt must succeed on freshly-published receipt");

    // 5. Assert receipt field values.
    assert_eq!(
        receipt.sender_pubkey, a_z32,
        "receipt.sender_pubkey must be A"
    );
    assert_eq!(
        receipt.recipient_pubkey, b_z32,
        "receipt.recipient_pubkey must be B"
    );
    assert_eq!(
        receipt.share_ref, uri.share_ref_hex,
        "receipt.share_ref must match URI"
    );
    assert_eq!(receipt.purpose, "e2e test");
    assert_eq!(receipt.nonce.len(), 32);
    assert!(receipt
        .nonce
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    // 6. Assert ciphertext_hash matches sha256 of what B actually resolved.
    //    Pull the outer record from the mock and hash its decoded blob.
    let outer_entries = transport.resolve_all_txt(&a_z32);
    let outer_entry = outer_entries
        .iter()
        .find(|(l, _)| l == cipherpost::DHT_LABEL_OUTER)
        .expect("A's outer _cipherpost entry must exist");
    let outer_record: cipherpost::record::OuterRecord =
        serde_json::from_str(&outer_entry.1).unwrap();
    let ciphertext_bytes = {
        use base64::Engine;
        base64::engine::general_purpose::STANDARD
            .decode(&outer_record.blob)
            .unwrap()
    };
    let expected_ch = format!("{:x}", Sha256::digest(&ciphertext_bytes));
    assert_eq!(
        receipt.ciphertext_hash, expected_ch,
        "receipt.ciphertext_hash must match sha256(ciphertext) that B received"
    );

    // 7. A fetches B's receipts via run_receipts (no Identity needed — D-OUT-04).
    //    This is stdout-printing so we just assert it returns Ok(()).
    run_receipts(&transport, &b_z32, None, false).expect("A run_receipts must succeed");
    run_receipts(&transport, &b_z32, Some(&uri.share_ref_hex), false)
        .expect("filter match must succeed");
}
