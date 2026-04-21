//! Receipt — the cipherpost delta from cclink. Published to the *recipient's*
//! PKARR key at DNS label `_cprcpt-<share_ref_hex>` after run_receive step 13
//! (post-sentinel, post-ledger; D-SEQ-01). Signed by the recipient's Ed25519
//! key; verifiable by any party using only the recipient's public z-base-32.
//!
//! Struct schema locked by D-RS-01..07 (Phase 3 CONTEXT.md). Mirrors
//! src/record.rs line-for-line: alphabetical fields, From<&Signed> for Signable,
//! JCS-serialized signing bytes, 5-step verify with round-trip-reserialize guard
//! (T-01-03-02). All signature-verification failures return Error::SignatureInner
//! or Error::SignatureCanonicalMismatch — both share the D-16 unified
//! Display "signature verification failed".
//!
//! No new HKDF call-sites (receipts sign with the Ed25519 identity key directly).
//! No new Error variants (D-RS-07 mandates reuse of existing sig-fail variants).

use crate::error::Error;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};

/// Signed form — what goes in a DNS TXT record under label
/// `_cprcpt-<share_ref_hex>`. Fields are in alphabetical order (belt-and-
/// suspenders for JCS stability — mirrors record::OuterRecord).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub accepted_at: i64,
    pub ciphertext_hash: String,
    pub cleartext_hash: String,
    pub nonce: String,
    pub protocol_version: u16,
    pub purpose: String,
    pub recipient_pubkey: String,
    pub sender_pubkey: String,
    pub share_ref: String,
    pub signature: String, // alphabetical insertion after share_ref
}

/// Unsigned form — the exact bytes Ed25519 signs are `jcs(ReceiptSignable)`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSignable {
    pub accepted_at: i64,
    pub ciphertext_hash: String,
    pub cleartext_hash: String,
    pub nonce: String,
    pub protocol_version: u16,
    pub purpose: String,
    pub recipient_pubkey: String,
    pub sender_pubkey: String,
    pub share_ref: String,
}

impl From<&Receipt> for ReceiptSignable {
    fn from(r: &Receipt) -> Self {
        ReceiptSignable {
            accepted_at: r.accepted_at,
            ciphertext_hash: r.ciphertext_hash.clone(),
            cleartext_hash: r.cleartext_hash.clone(),
            nonce: r.nonce.clone(),
            protocol_version: r.protocol_version,
            purpose: r.purpose.clone(),
            recipient_pubkey: r.recipient_pubkey.clone(),
            sender_pubkey: r.sender_pubkey.clone(),
            share_ref: r.share_ref.clone(),
        }
    }
}

/// Generate a 128-bit random nonce encoded as 32 lowercase hex chars (D-RS-03).
///
/// Source: `rand::rngs::OsRng` reads /dev/urandom via getrandom. Purpose: defense
/// against attacker-synthesized receipt-like data, not replay (RECV-06 handles replay).
pub fn nonce_hex() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    let mut out = String::with_capacity(32);
    for b in &bytes {
        out.push_str(&format!("{:02x}", b));
    }
    debug_assert_eq!(out.len(), 32);
    out
}

/// Sign a `ReceiptSignable` with the recipient's PKARR keypair.
/// Returns base64-STANDARD-encoded Ed25519 signature over the JCS bytes (D-RS-05).
pub fn sign_receipt(
    signable: &ReceiptSignable,
    keypair: &pkarr::Keypair,
) -> Result<String, Error> {
    let bytes = crate::crypto::jcs_serialize(signable)?;
    let sig = keypair.sign(&bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

/// Verify a Receipt's inner Ed25519 signature (D-RS-07).
///
/// Steps (mirror record::verify_record):
///   1. Parse recipient_pubkey z-base-32 → VerifyingKey.
///   2. Decode base64 signature.
///   3. Rebuild ReceiptSignable via From, JCS-serialize.
///   4. verify_strict (no legacy relaxed Ed25519).
///   5. Round-trip-reserialize + byte-compare (T-01-03-02 canonicalization-bypass defense).
pub fn verify_receipt(receipt: &Receipt) -> Result<(), Error> {
    // 1. Parse recipient_pubkey z-base-32 → VerifyingKey
    let pk = pkarr::PublicKey::try_from(receipt.recipient_pubkey.as_str())
        .map_err(|_| Error::SignatureInner)?;
    let vk = VerifyingKey::from_bytes(pk.as_bytes()).map_err(|_| Error::SignatureInner)?;

    // 2. Decode base64 signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&receipt.signature)
        .map_err(|_| Error::SignatureInner)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| Error::SignatureInner)?;

    // 3. Build signable, JCS-serialize
    let signable = ReceiptSignable::from(receipt);
    let bytes = crate::crypto::jcs_serialize(&signable)?;

    // 4. Verify strict (no legacy relaxed Ed25519 behaviour)
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| Error::SignatureInner)?;

    // 5. Re-canonicalize — protects against the parse-then-reserialize mauling
    //    attack class. If round-trip bytes differ from what was signed, reject.
    let parsed: ReceiptSignable =
        serde_json::from_slice(&bytes).map_err(|_| Error::SignatureCanonicalMismatch)?;
    let round = crate::crypto::jcs_serialize(&parsed)?;
    if round != bytes {
        return Err(Error::SignatureCanonicalMismatch);
    }

    Ok(())
}
