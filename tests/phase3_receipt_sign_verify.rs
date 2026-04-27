//! Phase 3 — Receipt sign/verify round-trip + tampered-rejection + D-16 Display
//! invariant unit tests. Mirrors src/record.rs tests module shape.

use cipherpost::receipt::{nonce_hex, sign_receipt, verify_receipt, Receipt, ReceiptSignable};
use cipherpost::{Error, PROTOCOL_VERSION};

fn deterministic_keypair(seed_byte: u8) -> pkarr::Keypair {
    let seed = [seed_byte; 32];
    pkarr::Keypair::from_secret_key(&seed)
}

fn sample_signable(kp: &pkarr::Keypair, self_mode: bool) -> ReceiptSignable {
    let z32 = kp.public_key().to_z32();
    ReceiptSignable {
        accepted_at: 1_700_000_000,
        ciphertext_hash: "a".repeat(64),
        cleartext_hash: "b".repeat(64),
        nonce: "0123456789abcdef0123456789abcdef".to_string(),
        protocol_version: PROTOCOL_VERSION,
        purpose: "unit test".to_string(),
        recipient_pubkey: z32.clone(),
        sender_pubkey: if self_mode {
            z32.clone()
        } else {
            // Use a different keypair's z32
            deterministic_keypair(0xBB).public_key().to_z32()
        },
        share_ref: "0123456789abcdef0123456789abcdef".to_string(),
    }
}

fn signed_receipt(kp: &pkarr::Keypair, self_mode: bool) -> Receipt {
    let signable = sample_signable(kp, self_mode);
    let sig = sign_receipt(&signable, kp).expect("sign_receipt");
    Receipt {
        accepted_at: signable.accepted_at,
        ciphertext_hash: signable.ciphertext_hash,
        cleartext_hash: signable.cleartext_hash,
        nonce: signable.nonce,
        protocol_version: signable.protocol_version,
        purpose: signable.purpose,
        recipient_pubkey: signable.recipient_pubkey,
        sender_pubkey: signable.sender_pubkey,
        share_ref: signable.share_ref,
        signature: sig,
    }
}

#[test]
fn sign_verify_round_trip() {
    let kp = deterministic_keypair(0xAA);
    let r = signed_receipt(&kp, false);
    verify_receipt(&r).expect("verify_receipt on freshly-signed receipt");
}

#[test]
fn self_receipt_round_trip() {
    // D-SEQ-06: sender_pubkey == recipient_pubkey is a valid Receipt state.
    let kp = deterministic_keypair(0xAA);
    let r = signed_receipt(&kp, true);
    verify_receipt(&r).expect("self-receipt must verify");
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
fn tampered_nonce_fails_verify() {
    let kp = deterministic_keypair(0xAA);
    let mut r = signed_receipt(&kp, false);
    r.nonce = "ffffffffffffffffffffffffffffffff".to_string(); // mutate after sign
    let err = verify_receipt(&r).expect_err("tampered nonce must reject");
    assert!(
        matches!(err, Error::SignatureInner),
        "expected SignatureInner, got {err:?}"
    );
    assert_unified_d16_display(&err);
}

#[test]
fn tampered_ciphertext_hash_fails_verify() {
    let kp = deterministic_keypair(0xAA);
    let mut r = signed_receipt(&kp, false);
    r.ciphertext_hash = "c".repeat(64);
    let err = verify_receipt(&r).expect_err("tampered ciphertext_hash must reject");
    assert!(matches!(err, Error::SignatureInner));
    assert_unified_d16_display(&err);
}

#[test]
fn tampered_purpose_fails_verify() {
    let kp = deterministic_keypair(0xAA);
    let mut r = signed_receipt(&kp, false);
    r.purpose = "EVIL".to_string();
    let err = verify_receipt(&r).expect_err("tampered purpose must reject");
    assert!(matches!(err, Error::SignatureInner));
    assert_unified_d16_display(&err);
}

#[test]
fn nonce_hex_shape() {
    let n1 = nonce_hex();
    let n2 = nonce_hex();
    assert_eq!(n1.len(), 32, "nonce_hex must be 32 chars");
    assert!(
        n1.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "nonce_hex must be lowercase hex only; got {n1}"
    );
    assert_ne!(n1, n2, "two OsRng draws must differ (entropy check)");
}
