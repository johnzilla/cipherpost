//! Phase 3 Plan 03-04 — D-IT-01 test 3 / ROADMAP SC4: run_receipts with and
//! without --share-ref filter; A's own outgoing _cipherpost under A's key
//! continues to be resolvable during receipts fetch.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receipts, run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::identity::Identity;
use cipherpost::transport::MockTransport;
use cipherpost::{ShareUri, DHT_LABEL_OUTER};
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
fn receipts_filter_and_senders_own_share_coexists() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let a_z32 = kp_a.public_key().to_z32();

    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();

    let transport = MockTransport::new();

    // Interleaved send-accept-send-accept to work around MockTransport's
    // per-label single-slot _cipherpost semantic (publish replaces the entry
    // wholesale). This mirrors real-world flow: A sends, hands URI to B, B
    // accepts, then A sends again.

    // Share 1 full cycle: A sends, B accepts.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri1_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "p1",
        MaterialSource::Bytes(b"payload one distinct".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("A send 1");
    let uri1 = ShareUri::parse(&uri1_str).expect("parse uri1");

    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink1 = OutputSink::InMemory(Vec::new());
    run_receive(
        &id_b,
        &transport,
        &kp_b,
        &uri1,
        &mut sink1,
        &AutoConfirmPrompter,
        false,
    )
    .expect("B accept 1");

    // Between cycles, sleep 1s so created_at differs (share_ref = sha256(ciphertext || created_at)[..16]).
    // Different bytes already guarantee different share_ref, but the sleep makes it rock-solid.
    std::thread::sleep(std::time::Duration::from_secs(1));

    // Share 2 full cycle: A sends again (replaces A's _cipherpost entry), B accepts.
    // B's _cprcpt-<uri1.share_ref> receipt under B's key persists because
    // MockTransport::publish_receipt uses retain+push per share_ref label.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri2_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "p2",
        MaterialSource::Bytes(b"payload two different".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("A send 2");
    let uri2 = ShareUri::parse(&uri2_str).expect("parse uri2");
    assert_ne!(
        uri1.share_ref_hex, uri2.share_ref_hex,
        "two sends must produce distinct share_refs"
    );

    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink2 = OutputSink::InMemory(Vec::new());
    run_receive(
        &id_b,
        &transport,
        &kp_b,
        &uri2,
        &mut sink2,
        &AutoConfirmPrompter,
        false,
    )
    .expect("B accept 2");

    // Assert B's key has exactly 2 receipts.
    let b_entries = transport.resolve_all_txt(&b_z32);
    let b_receipts: Vec<_> = b_entries
        .iter()
        .filter(|(l, _)| l.starts_with(cipherpost::DHT_LABEL_RECEIPT_PREFIX))
        .collect();
    assert_eq!(
        b_receipts.len(),
        2,
        "B should have 2 distinct receipts; got {:?}",
        b_entries.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>()
    );

    // run_receipts with share_ref_1 filter — exactly 1 receipt expected.
    run_receipts(&transport, &b_z32, Some(&uri1.share_ref_hex), false)
        .expect("filter-1 should succeed with 1 match");
    run_receipts(&transport, &b_z32, Some(&uri2.share_ref_hex), false)
        .expect("filter-2 should succeed with 1 match");

    // run_receipts with no filter — both receipts returned.
    run_receipts(&transport, &b_z32, None, false).expect("no-filter should succeed with 2 matches");

    // A's own outgoing _cipherpost share under A's key is STILL resolvable
    // (ROADMAP SC4 invariant). The _cipherpost entry is the LAST uri2.
    let a_entries = transport.resolve_all_txt(&a_z32);
    assert!(
        a_entries.iter().any(|(l, _)| l == DHT_LABEL_OUTER),
        "A's _cipherpost outgoing share must remain resolvable during receipts fetch"
    );
}
