//! v2 (derived-key addressing): a recipient can hold MANY receipts — one per
//! share_ref, each under its own derived key — and each is fetched by
//! `run_receipts --share-ref <ref>`. Without a share_ref, receipts are NOT
//! enumerable (the unlinkability that is the point). A's own outgoing shares also
//! coexist (each its own derived key). Replaces the v1.2-alpha
//! one-receipt-per-identity (packet-budget) test.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receipts, run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::identity::Identity;
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::ShareUri;
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
fn recipient_holds_multiple_receipts_one_per_share_ref() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();
    let transport = MockTransport::new();

    // A sends TWO distinct shares to B; B accepts each. Each receipt lands under
    // its own derived key derive(B, share_ref).
    let mut uris = Vec::new();
    for payload in [b"payload one distinct".as_slice(), b"payload two different"] {
        std::env::set_var("CIPHERPOST_HOME", dir_a.path());
        let uri = ShareUri::parse(
            &run_send(
                &id_a,
                &transport,
                &kp_a,
                SendMode::Share {
                    recipient_z32: b_z32.clone(),
                },
                "p",
                MaterialSource::Bytes(payload.to_vec()),
                MaterialVariant::GenericSecret,
                DEFAULT_TTL_SECONDS,
                None,
                false,
            )
            .expect("A send"),
        )
        .unwrap();
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
        .expect("B accept");
        uris.push(uri);
    }
    assert_ne!(
        uris[0].share_ref_hex, uris[1].share_ref_hex,
        "two sends must produce distinct share_refs"
    );

    // BOTH receipts are fetchable by share_ref (v2: per-share addressing).
    for uri in &uris {
        run_receipts(&transport, &b_z32, Some(&uri.share_ref_hex), false)
            .expect("receipt fetchable by its own share_ref");
    }

    // Without --share-ref, receipts are not enumerable → error.
    assert!(
        run_receipts(&transport, &b_z32, None, false).is_err(),
        "receipts requires --share-ref in v2 (not enumerable)",
    );
    // An unknown share_ref → NotFound.
    assert!(
        matches!(
            run_receipts(&transport, &b_z32, Some(&"ff".repeat(16)), false),
            Err(cipherpost::Error::NotFound),
        ),
        "unknown share_ref must be NotFound",
    );

    // A's own outgoing shares also coexist, each at its own derived key.
    let a_pub = kp_a.public_key().to_bytes();
    for uri in &uris {
        let key = cipherpost::derive::derive_public(&a_pub, &uri.share_ref_hex).unwrap();
        assert!(
            transport
                .resolve_derived(&key, cipherpost::DHT_LABEL_OUTER)
                .unwrap()
                .is_some(),
            "A's outgoing share must remain resolvable",
        );
    }
}
