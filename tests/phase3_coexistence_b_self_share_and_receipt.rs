//! v2 (derived-key addressing): a recipient's own outgoing share and the receipts
//! it accrues no longer share a packet, so they COEXIST — each under its own
//! derived key derive(pub, share_ref). Replaces the v1.2-alpha packet-budget-
//! collision tests (which asserted the now-removed "one record per key" ceiling).

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
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

fn send_share(
    id: &Identity,
    transport: &MockTransport,
    kp: &pkarr::Keypair,
    mode: SendMode,
    payload: &[u8],
) -> ShareUri {
    ShareUri::parse(
        &run_send(
            id,
            transport,
            kp,
            mode,
            "p",
            MaterialSource::Bytes(payload.to_vec()),
            MaterialVariant::GenericSecret,
            DEFAULT_TTL_SECONDS,
            None,
            false,
        )
        .expect("run_send"),
    )
    .unwrap()
}

/// v2: a self-share and a cross-identity receipt coexist — each under its own
/// derived key. (Was `bs_self_share_blocks_receipt_accrual_over_budget`.)
#[test]
#[serial]
fn self_share_and_cross_receipt_coexist_on_separate_derived_keys() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();
    let b_pub = kp_b.public_key().to_bytes();
    let transport = MockTransport::new();

    // 1. B self-sends → share at derive(B, ref_self).
    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let b_self = send_share(&id_b, &transport, &kp_b, SendMode::SelfMode, b"b self note");

    // 2. A sends a share to B.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri = send_share(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        b"a-to-b share",
    );

    // 3. B receives A's share → receipt at derive(B, uri.share_ref).
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
    match sink {
        OutputSink::InMemory(buf) => assert_eq!(buf, b"a-to-b share"),
        _ => panic!("InMemory sink expected"),
    }

    // 4. No collision: B's self-share AND the receipt both exist, distinct keys.
    let self_share_key = cipherpost::derive::derive_public(&b_pub, &b_self.share_ref_hex).unwrap();
    let receipt_key = cipherpost::derive::derive_public(&b_pub, &uri.share_ref_hex).unwrap();
    assert_ne!(self_share_key, receipt_key, "distinct derived keys");
    assert!(
        transport
            .resolve_derived(&self_share_key, cipherpost::DHT_LABEL_OUTER)
            .unwrap()
            .is_some(),
        "B's self-share is still present",
    );
    assert!(
        transport
            .resolve_derived(&receipt_key, cipherpost::DHT_LABEL_RECEIPT)
            .unwrap()
            .is_some(),
        "receipt accrued alongside it (no budget collision in v2)",
    );
}

/// v2: accruing a receipt does NOT block a later self-send. (Was
/// `accrued_receipt_blocks_self_share_with_packet_budget_error`.)
#[test]
#[serial]
fn accrued_receipt_does_not_block_self_send() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xCC; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xDD; 32]);
    let b_z32 = kp_b.public_key().to_z32();
    let b_pub = kp_b.public_key().to_bytes();
    let transport = MockTransport::new();

    // 1. A→B; B receives → B accrues a receipt.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri = send_share(
        &id_a,
        &transport,
        &kp_a,
        SendMode::Share {
            recipient_z32: b_z32.clone(),
        },
        b"a-to-b",
    );
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
    let receipt_key = cipherpost::derive::derive_public(&b_pub, &uri.share_ref_hex).unwrap();
    assert!(
        transport
            .resolve_derived(&receipt_key, cipherpost::DHT_LABEL_RECEIPT)
            .unwrap()
            .is_some(),
        "precondition: B holds a receipt",
    );

    // 2. B self-sends → SUCCEEDS (own derived key; no collision).
    let self_share = send_share(&id_b, &transport, &kp_b, SendMode::SelfMode, b"b self 1");
    let self_share_key =
        cipherpost::derive::derive_public(&b_pub, &self_share.share_ref_hex).unwrap();
    assert!(
        transport
            .resolve_derived(&receipt_key, cipherpost::DHT_LABEL_RECEIPT)
            .unwrap()
            .is_some(),
        "receipt survives the self-send",
    );
    assert!(
        transport
            .resolve_derived(&self_share_key, cipherpost::DHT_LABEL_OUTER)
            .unwrap()
            .is_some(),
        "self-share was published",
    );
}

/// Parent-binding: an attacker replays A's validly-signed record under B's derived
/// key and hands a victim a URI claiming B as the sender. run_receive must REFUSE
/// (ShareRefMismatch) BEFORE decrypt/acceptance — the record's own pubkey (A) does
/// not match the URI's parent (B), even though the derived location + inner sig are
/// internally valid.
#[test]
#[serial]
fn parent_z32_mismatch_rejected_before_decrypt() {
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xA1; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xB1; 32]);
    let a_pub = kp_a.public_key().to_bytes();
    let b_pub = kp_b.public_key().to_bytes();
    let b_z32 = kp_b.public_key().to_z32();
    let transport = MockTransport::new();

    // A self-sends a valid share; grab A's validly-signed record from its key.
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri_a = send_share(&id_a, &transport, &kp_a, SendMode::SelfMode, b"a secret");
    let a_key = cipherpost::derive::derive_public(&a_pub, &uri_a.share_ref_hex).unwrap();
    let rdata = transport
        .resolve_derived(&a_key, cipherpost::DHT_LABEL_OUTER)
        .unwrap()
        .unwrap();

    // Attacker replays it under B's derived key + forges a URI claiming B is sender.
    let b_key = cipherpost::derive::derive_public(&b_pub, &uri_a.share_ref_hex).unwrap();
    transport.inject_derived_record_for_test(&b_key, cipherpost::DHT_LABEL_OUTER, &rdata);
    let forged =
        ShareUri::parse(&format!("cipherpost://{}/{}", b_z32, uri_a.share_ref_hex)).unwrap();

    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id_b,
        &transport,
        &kp_b,
        &forged,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(err, cipherpost::Error::ShareRefMismatch),
        "record.pubkey (A) != uri.sender_z32 (B) must reject; got {err:?}",
    );
    match sink {
        OutputSink::InMemory(buf) => assert!(buf.is_empty(), "no material written on refusal"),
        _ => panic!("InMemory sink expected"),
    }
}
