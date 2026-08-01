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
use cipherpost::ShareUri;
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
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
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

    // 3. Receipt is published at its own derived key derive(B_pub, share_ref).
    let b_pub = pkarr::PublicKey::try_from(b_z32.as_str())
        .unwrap()
        .to_bytes();
    let derived = cipherpost::derive::derive_public(&b_pub, &uri.share_ref_hex).unwrap();
    let receipt_json = {
        use cipherpost::transport::Transport;
        transport
            .resolve_derived(&derived, cipherpost::DHT_LABEL_RECEIPT)
            .unwrap()
            .expect("receipt must exist at its derived key after accept")
    };

    // 4. Parse + verify the receipt.
    let receipt: Receipt = serde_json::from_str(&receipt_json).expect("receipt JSON must parse");
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
    // No receipt.purpose — the purpose is intentionally NOT published (privacy);
    // it is bound (not exposed) via cleartext_hash, verified below.
    assert_eq!(receipt.nonce.len(), 32);
    assert!(receipt
        .nonce
        .chars()
        .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));

    // 6. Assert ciphertext_hash matches sha256 of what B actually resolved.
    //    Pull the outer record from A's derived share key and hash its decoded blob.
    let a_pub = pkarr::PublicKey::try_from(a_z32.as_str())
        .unwrap()
        .to_bytes();
    let a_share_key = cipherpost::derive::derive_public(&a_pub, &uri.share_ref_hex).unwrap();
    let outer_rdata = {
        use cipherpost::transport::Transport;
        transport
            .resolve_derived(&a_share_key, cipherpost::DHT_LABEL_OUTER)
            .unwrap()
            .expect("A's outer share must exist at its derived key")
    };
    let outer_record: cipherpost::record::OuterRecord = serde_json::from_str(&outer_rdata).unwrap();
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

    // 7. A fetches B's receipt via run_receipts --share-ref (v2: per-share
    //    addressing; no Identity needed — D-OUT-04). Without --share-ref it errors.
    run_receipts(&transport, &b_z32, Some(&uri.share_ref_hex), false)
        .expect("run_receipts by share_ref must succeed");
    assert!(
        run_receipts(&transport, &b_z32, None, false).is_err(),
        "v2 run_receipts requires --share-ref",
    );
}
