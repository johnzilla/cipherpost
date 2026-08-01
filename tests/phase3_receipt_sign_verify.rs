//! Phase 3 — Receipt sign/verify round-trip + tampered-rejection + D-16 Display
//! invariant unit tests. Mirrors src/record.rs tests module shape.

use cipherpost::receipt::{sign_receipt, verify_receipt, Receipt, ReceiptSignable};
use cipherpost::{Error, PROTOCOL_VERSION};

fn deterministic_keypair(seed_byte: u8) -> pkarr::Keypair {
    let seed = [seed_byte; 32];
    pkarr::Keypair::from_secret_key(&seed)
}

// v2 slim signable: no nonce / pubkeys. The recipient pubkey is verify CONTEXT.
fn sample_signable() -> ReceiptSignable {
    ReceiptSignable {
        accepted_at: 1_700_000_000,
        ciphertext_hash: "a".repeat(64),
        cleartext_hash: "b".repeat(64),
        protocol_version: PROTOCOL_VERSION,
        share_ref: "0123456789abcdef0123456789abcdef".to_string(),
    }
}

fn signed_receipt(kp: &pkarr::Keypair) -> Receipt {
    let signable = sample_signable();
    let sig = sign_receipt(&signable, kp).expect("sign_receipt");
    Receipt {
        accepted_at: signable.accepted_at,
        ciphertext_hash: signable.ciphertext_hash,
        cleartext_hash: signable.cleartext_hash,
        protocol_version: signable.protocol_version,
        share_ref: signable.share_ref,
        signature: sig,
    }
}

#[test]
fn sign_verify_round_trip() {
    let kp = deterministic_keypair(0xAA);
    let r = signed_receipt(&kp);
    verify_receipt(&r, &kp.public_key().to_z32())
        .expect("verify_receipt on freshly-signed receipt");
}

#[test]
fn verify_fails_under_wrong_recipient_context() {
    // v2: recipient pubkey is CONTEXT — a different pubkey must not verify.
    let kp = deterministic_keypair(0xAA);
    let r = signed_receipt(&kp);
    let wrong = deterministic_keypair(0xBB).public_key().to_z32();
    assert!(
        verify_receipt(&r, &wrong).is_err(),
        "wrong recipient context must fail verify",
    );
}

fn assert_unified_d16_display(err: &Error) {
    // D-16: every sig-fail variant Display is "signature verification failed".
    assert_eq!(
        format!("{err}"),
        "signature verification failed",
        "D-16 unified Display invariant violated"
    );
}

/// Phase 8 Plan 02 (PIN-07 narrow): credential-failure Display invariant.
/// Wrong-PIN, wrong-passphrase, and inner age-decrypt failures all produce
/// this string with exit 4.
///
/// Distinct from `assert_unified_d16_display` (the exit-3 sig lane); both
/// invariants coexist — different lane, different Display, but Display is
/// uniform WITHIN each lane. PIN-07 narrow per RESEARCH Open Risk #1.
#[allow(dead_code)]
pub fn assert_unified_credential_failure_display(err: &cipherpost::Error) {
    assert_eq!(
        format!("{err}"),
        "wrong passphrase or identity decryption failed",
        "PIN-07 unified credential-failure Display invariant violated"
    );
    assert_eq!(
        cipherpost::error::exit_code(err),
        4,
        "credential failure must map to exit 4"
    );
}

#[test]
fn credential_failure_display_invariant() {
    // Direct check: synthetic Error::DecryptFailed honors the credential-
    // lane Display + exit-4 invariant.
    assert_unified_credential_failure_display(&cipherpost::Error::DecryptFailed);
}

#[test]
fn tampered_share_ref_fails_verify() {
    let kp = deterministic_keypair(0xAA);
    let mut r = signed_receipt(&kp);
    r.share_ref = "ffffffffffffffffffffffffffffffff".to_string(); // mutate after sign
    let err =
        verify_receipt(&r, &kp.public_key().to_z32()).expect_err("tampered share_ref must reject");
    assert!(
        matches!(err, Error::SignatureInner),
        "expected SignatureInner, got {err:?}"
    );
    assert_unified_d16_display(&err);
}

#[test]
fn tampered_ciphertext_hash_fails_verify() {
    let kp = deterministic_keypair(0xAA);
    let mut r = signed_receipt(&kp);
    r.ciphertext_hash = "c".repeat(64);
    let err = verify_receipt(&r, &kp.public_key().to_z32())
        .expect_err("tampered ciphertext_hash must reject");
    assert!(matches!(err, Error::SignatureInner));
    assert_unified_d16_display(&err);
}

#[test]
fn tampered_cleartext_hash_fails_verify() {
    // (Was tampered_purpose_fails_verify; purpose was removed from the receipt —
    // cleartext_hash is now the field that binds the envelope, incl. its purpose.)
    let kp = deterministic_keypair(0xAA);
    let mut r = signed_receipt(&kp);
    r.cleartext_hash = "e".repeat(64);
    let err = verify_receipt(&r, &kp.public_key().to_z32())
        .expect_err("tampered cleartext_hash must reject");
    assert!(matches!(err, Error::SignatureInner));
    assert_unified_d16_display(&err);
}
