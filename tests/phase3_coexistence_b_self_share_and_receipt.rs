//! Phase 3 Plan 03-04 — D-IT-01 test 2 / ROADMAP SC3: after publish_receipt,
//! the recipient's own outgoing _cipherpost share is NOT clobbered. Proves
//! TRANS-03's coexistence invariant end-to-end via the full run_send +
//! run_receive pipeline (not just direct MockTransport calls like Plan 03-02's
//! coexistence test — this test exercises the production path).

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::identity::Identity;
use cipherpost::transport::MockTransport;
use cipherpost::{ShareUri, DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX};
use secrecy::SecretBox;
use serial_test::serial;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tempfile::TempDir;
use zeroize::Zeroizing;

// Reuse the same helper as the end-to-end test. Duplicated here rather than
// factored into a shared module because Rust integration tests don't share
// test-only modules cleanly (each tests/*.rs is its own binary).
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
fn bs_self_share_survives_publish_receipt() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);

    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();

    let transport = MockTransport::new();

    // 1. B does a self-mode run_send first — establishes B's own _cipherpost entry.
    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let _b_self_uri_str = run_send(
        &id_b,
        &transport,
        &kp_b,
        SendMode::SelfMode,
        "b self",
        MaterialSource::Bytes(b"b self note".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("B self-send");

    // Pre-condition: B has exactly 1 entry under its key, a _cipherpost.
    let pre = transport.resolve_all_txt(&b_z32);
    assert_eq!(pre.len(), 1, "pre-condition: B should have exactly 1 entry");
    assert_eq!(pre[0].0, DHT_LABEL_OUTER);

    // 2. A sends a share to B.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "a to b",
        MaterialSource::Bytes(b"a-to-b share".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .expect("A run_send share mode");
    let uri = ShareUri::parse(&uri_str).expect("parse share URI");

    // 3. B receives + accepts — step 13 publishes a receipt under B's key.
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
    .expect("B run_receive");

    // 4. Assert coexistence: B's key now holds 2 entries — one _cipherpost (B's self-share)
    //    AND one _cprcpt-<share_ref> (the new receipt).
    let post = transport.resolve_all_txt(&b_z32);
    assert_eq!(
        post.len(),
        2,
        "expected 2 entries under B (1 outgoing + 1 receipt), got {:?}",
        post.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>()
    );
    let has_outgoing = post.iter().any(|(l, _)| l == DHT_LABEL_OUTER);
    let expected_receipt_label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, uri.share_ref_hex);
    let has_receipt = post.iter().any(|(l, _)| l == &expected_receipt_label);
    assert!(
        has_outgoing,
        "TRANS-03 invariant violated: B's outgoing _cipherpost share clobbered by publish_receipt"
    );
    assert!(
        has_receipt,
        "receipt must be published under B's key at {expected_receipt_label}"
    );
}

/// Regression for the reverse direction (the actual bug): B first accrues a
/// receipt (as a recipient), THEN publishes its own share (as a sender). The
/// share publish must NOT clobber the receipt. Before the fix, `DhtTransport::
/// publish` rebuilt the packet from scratch and silently deleted every
/// `_cprcpt-*` — and `MockTransport::publish` hid it by preserving receipts;
/// now both merge-republish, so this test faithfully exercises the fixed path.
#[test]
#[serial]
fn receipt_survives_subsequent_share_publishes() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xCC; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xDD; 32]);
    let b_z32 = kp_b.public_key().to_z32();
    let transport = MockTransport::new();

    // 1. A sends to B; B receives → B publishes a receipt. B has NO _cipherpost yet.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri_str = run_send(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        "a to b",
        MaterialSource::Bytes(b"a-to-b".to_vec()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,
        false,
    )
    .expect("A send");
    let uri = ShareUri::parse(&uri_str).unwrap();
    let receipt_label = format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, uri.share_ref_hex);

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
    .expect("B receive");
    let after_receipt = transport.resolve_all_txt(&b_z32);
    assert!(
        after_receipt.iter().any(|(l, _)| l == &receipt_label),
        "precondition: B should hold a receipt"
    );
    assert!(
        !after_receipt.iter().any(|(l, _)| l == DHT_LABEL_OUTER),
        "precondition: B has not published a share yet"
    );

    // 2. B publishes its OWN share. The receipt MUST survive.
    let self_send = |note: &[u8]| {
        run_send(
            &id_b,
            &transport,
            &kp_b,
            SendMode::SelfMode,
            "b self",
            MaterialSource::Bytes(note.to_vec()),
            MaterialVariant::GenericSecret,
            DEFAULT_TTL_SECONDS,
            None,
            false,
        )
        .expect("B self-send");
    };
    self_send(b"b self 1");
    let after_share = transport.resolve_all_txt(&b_z32);
    assert!(
        after_share.iter().any(|(l, _)| l == DHT_LABEL_OUTER),
        "B's share must be published"
    );
    assert!(
        after_share.iter().any(|(l, _)| l == &receipt_label),
        "REGRESSION: B's share publish clobbered its receipt (got {:?})",
        after_share
            .iter()
            .map(|(l, _)| l.clone())
            .collect::<Vec<_>>()
    );

    // 3. A SECOND share publish: receipt still survives, and the share is REPLACED
    //    (one outstanding _cipherpost, not accumulated).
    self_send(b"b self 2");
    let after_share2 = transport.resolve_all_txt(&b_z32);
    assert!(
        after_share2.iter().any(|(l, _)| l == &receipt_label),
        "REGRESSION: second share publish clobbered the receipt"
    );
    let cipherpost_count = after_share2
        .iter()
        .filter(|(l, _)| l == DHT_LABEL_OUTER)
        .count();
    assert_eq!(
        cipherpost_count, 1,
        "the second share should REPLACE the first _cipherpost, not accumulate"
    );
}
