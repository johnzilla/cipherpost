//! Receipt — the cipherpost delta from cclink. In v2 (derived-key addressing) it
//! is published at DNS label `_cprcpt` under the derived key
//! `derive(recipient_pub, share_ref)` (run_receive step 13). Inner-signed by the
//! recipient's Ed25519 identity key; `verify_receipt` takes the recipient's public
//! z-base-32 as CONTEXT (the caller already holds it — it derived the receipt key
//! from it), so the pubkey no longer travels inside the receipt.
//!
//! Provenance is the composition: **receipt found at `derive(recipient_pub,
//! share_ref)` + outer BEP44 sig valid under that derived key (transport) + inner
//! Ed25519 sig valid under `recipient_pub` (here)**. Only the recipient's master
//! secret can satisfy all three.
//!
//! JCS-serialized signing bytes, 5-step verify with round-trip-reserialize guard
//! (T-01-03-02). All signature-verification failures return Error::SignatureInner
//! or Error::SignatureCanonicalMismatch — both share the D-16 unified Display
//! "signature verification failed".
//!
//! **v2 schema slim (protocol_version 2).** `nonce`, `recipient_pubkey`, and
//! `sender_pubkey` were dropped: under derived addressing the derived location +
//! two signatures make them redundant (nonce's anti-synthesis job is subsumed by
//! the per-share derived-key signature; the pubkeys are the derivation
//! inputs/context), and dropping them shrinks the cleartext receipt + its
//! handoff-graph exposure.

use crate::error::Error;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};

/// Signed form — the TXT record at label `_cprcpt` under the derived key. Fields
/// in alphabetical order (belt-and-suspenders for JCS stability).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Receipt {
    pub accepted_at: i64,
    pub ciphertext_hash: String,
    pub cleartext_hash: String,
    pub protocol_version: u16,
    pub share_ref: String,
    pub signature: String, // alphabetical insertion after share_ref
}

/// Unsigned form — the exact bytes Ed25519 signs are `jcs(ReceiptSignable)`.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct ReceiptSignable {
    pub accepted_at: i64,
    pub ciphertext_hash: String,
    pub cleartext_hash: String,
    pub protocol_version: u16,
    pub share_ref: String,
}

impl From<&Receipt> for ReceiptSignable {
    fn from(r: &Receipt) -> Self {
        ReceiptSignable {
            accepted_at: r.accepted_at,
            ciphertext_hash: r.ciphertext_hash.clone(),
            cleartext_hash: r.cleartext_hash.clone(),
            protocol_version: r.protocol_version,
            share_ref: r.share_ref.clone(),
        }
    }
}

/// Sign a `ReceiptSignable` with the recipient's PKARR keypair.
/// Returns base64-STANDARD-encoded Ed25519 signature over the JCS bytes (D-RS-05).
pub fn sign_receipt(signable: &ReceiptSignable, keypair: &pkarr::Keypair) -> Result<String, Error> {
    let bytes = crate::crypto::jcs_serialize(signable)?;
    let sig = keypair.sign(&bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

/// Verify a Receipt's inner Ed25519 signature under `recipient_pub_z32` (D-RS-07).
/// In v2 the pubkey is supplied as CONTEXT (the caller derived the receipt key from
/// it) rather than read from the receipt.
///
/// Steps (mirror record::verify_record):
///   1. Parse `recipient_pub_z32` → VerifyingKey.
///   2. Decode base64 signature.
///   3. Rebuild ReceiptSignable via From, JCS-serialize.
///   4. verify_strict (no legacy relaxed Ed25519).
///   5. Round-trip-reserialize + byte-compare (T-01-03-02 canonicalization-bypass defense).
pub fn verify_receipt(receipt: &Receipt, recipient_pub_z32: &str) -> Result<(), Error> {
    // 1. Parse recipient pubkey (context) z-base-32 → VerifyingKey
    let pk = pkarr::PublicKey::try_from(recipient_pub_z32).map_err(|_| Error::SignatureInner)?;
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
