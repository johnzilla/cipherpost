//! OuterRecord — dual-signed outer wire format. Published to the sender's PKARR
//! key at DNS label `_cipherpost` (crate::DHT_LABEL_OUTER). Inner signature is
//! Ed25519 over the JCS-canonical serialization of `OuterRecordSignable` (this
//! module). Outer signature is PKARR's SignedPacket signature (transport layer).
//!
//! Pitfalls addressed:
//!   #3  — canonical JSON via serde_canonical_json (JCS / RFC 8785)
//!   #11 — share_ref is bound to ciphertext + created_at (no server-side enforcement)
//!
//! D-16: all signature-verification failures return an Error variant that
//! Displays as "signature verification failed"; internal variants are distinct
//! so tests can assert which check fired.

use crate::error::Error;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_canonical_json::CanonicalFormatter;
use sha2::{Digest, Sha256};

pub const SHARE_REF_BYTES: usize = 16;
pub const SHARE_REF_HEX_LEN: usize = SHARE_REF_BYTES * 2;

/// Signed form — what goes in a DNS TXT record under label `_cipherpost`.
/// Fields are in alphabetical order (belt-and-suspenders for JCS stability).
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OuterRecord {
    pub blob: String,
    pub created_at: i64,
    /// Phase 8 Plan 01 (D-P8-03, PIN-04): true ⇒ this share is PIN-protected.
    /// Outer-signed; pre-decrypt readable so the receiver knows to prompt for PIN
    /// BEFORE attempting age-decrypt. `is_false` elides on the wire when false,
    /// preserving v1.0 byte-identity for non-pin shares.
    #[serde(default, skip_serializing_if = "crate::is_false")]
    pub pin_required: bool,
    pub protocol_version: u16,
    pub pubkey: String,
    pub recipient: Option<String>,
    pub share_ref: String,
    pub signature: String,
    pub ttl_seconds: u64,
}

/// Unsigned form — the exact bytes Ed25519 signs are `jcs(OuterRecordSignable)`.
/// JCS sorts keys regardless, but we also keep declaration order alphabetical
/// as belt-and-suspenders.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct OuterRecordSignable {
    pub blob: String,
    pub created_at: i64,
    /// Phase 8 Plan 01 (D-P8-03, PIN-04): mirror of `OuterRecord.pin_required`;
    /// included in JCS bytes that the inner Ed25519 signature covers.
    #[serde(default, skip_serializing_if = "crate::is_false")]
    pub pin_required: bool,
    pub protocol_version: u16,
    pub pubkey: String,
    pub recipient: Option<String>,
    pub share_ref: String,
    pub ttl_seconds: u64,
}

impl From<&OuterRecord> for OuterRecordSignable {
    fn from(r: &OuterRecord) -> Self {
        OuterRecordSignable {
            blob: r.blob.clone(),
            created_at: r.created_at,
            pin_required: r.pin_required,
            protocol_version: r.protocol_version,
            pubkey: r.pubkey.clone(),
            recipient: r.recipient.clone(),
            share_ref: r.share_ref.clone(),
            ttl_seconds: r.ttl_seconds,
        }
    }
}

/// Compute the 128-bit share_ref, hex-encoded to 32 chars (D-06, PAYL-05).
/// Formula: sha256(ciphertext || created_at_be_bytes)[..16] as lowercase hex.
pub fn share_ref_from_bytes(ciphertext: &[u8], created_at: i64) -> String {
    let mut hasher = Sha256::new();
    hasher.update(ciphertext);
    hasher.update(created_at.to_be_bytes());
    let digest = hasher.finalize();
    let mut out = String::with_capacity(SHARE_REF_HEX_LEN);
    for b in &digest[..SHARE_REF_BYTES] {
        out.push_str(&format!("{b:02x}"));
    }
    debug_assert_eq!(out.len(), SHARE_REF_HEX_LEN);
    out
}

/// Serialize any Serialize value to canonical JSON per RFC 8785 (JCS).
/// Inlined here so this module does not depend on src/crypto.rs (parallel-safe
/// with Plan 02). Can be consolidated to crypto::jcs_serialize after merge.
fn jcs(value: &impl Serialize) -> Result<Vec<u8>, Error> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    value
        .serialize(&mut ser)
        .map_err(|e| Error::Config(format!("jcs: {e}")))?;
    Ok(buf)
}

/// Sign an `OuterRecordSignable` using the given PKARR keypair.
///
/// Returns a base64-encoded Ed25519 signature over the JCS bytes.
pub fn sign_record(
    signable: &OuterRecordSignable,
    keypair: &pkarr::Keypair,
) -> Result<String, Error> {
    let bytes = jcs(signable)?;
    // pkarr::Keypair::sign delegates to ed25519_dalek::SigningKey::sign
    let sig = keypair.sign(&bytes);
    Ok(base64::engine::general_purpose::STANDARD.encode(sig.to_bytes()))
}

/// Verify the inner Ed25519 signature of an `OuterRecord`.
///
/// Steps:
///  1. Parse pubkey from z-base-32.
///  2. Decode the base64 signature.
///  3. Reconstruct `OuterRecordSignable` and JCS-serialize.
///  4. Verify the Ed25519 signature via `verify_strict`.
///  5. Re-canonicalize: parse JCS bytes back, re-serialize, assert byte-identical
///     (guards against the canonicalization-bypass attack, T-01-03-02).
pub fn verify_record(record: &OuterRecord) -> Result<(), Error> {
    // 1. Parse pubkey from z-base-32 → VerifyingKey
    let pk =
        pkarr::PublicKey::try_from(record.pubkey.as_str()).map_err(|_| Error::SignatureInner)?;
    let vk = VerifyingKey::from_bytes(pk.as_bytes()).map_err(|_| Error::SignatureInner)?;

    // 2. Decode signature
    let sig_bytes = base64::engine::general_purpose::STANDARD
        .decode(&record.signature)
        .map_err(|_| Error::SignatureInner)?;
    let sig = Signature::from_slice(&sig_bytes).map_err(|_| Error::SignatureInner)?;

    // 3. Build signable, JCS-serialize
    let signable = OuterRecordSignable::from(record);
    let bytes = jcs(&signable)?;

    // 4. Verify strict (no legacy relaxed Ed25519 behaviour)
    vk.verify_strict(&bytes, &sig)
        .map_err(|_| Error::SignatureInner)?;

    // 5. Re-canonicalize — protects against the parse-then-reserialize mauling
    //    attack class. If round-trip bytes differ from what was signed, reject.
    let parsed: OuterRecordSignable =
        serde_json::from_slice(&bytes).map_err(|_| Error::SignatureCanonicalMismatch)?;
    let round = jcs(&parsed)?;
    if round != bytes {
        return Err(Error::SignatureCanonicalMismatch);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::PROTOCOL_VERSION;

    #[test]
    fn share_ref_is_32_hex_chars() {
        let r = share_ref_from_bytes(b"hello", 1_700_000_000);
        assert_eq!(r.len(), 32);
        assert!(r
            .chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }

    #[test]
    fn share_ref_is_deterministic() {
        let a = share_ref_from_bytes(b"hello", 1);
        let b = share_ref_from_bytes(b"hello", 1);
        assert_eq!(a, b);
        let c = share_ref_from_bytes(b"hello", 2);
        assert_ne!(a, c); // created_at changes → share_ref changes
    }

    #[test]
    fn sign_verify_round_trip() {
        let seed = [42u8; 32];
        let kp = pkarr::Keypair::from_secret_key(&seed);
        let signable = OuterRecordSignable {
            blob: "dGVzdA".into(),
            created_at: 1_700_000_000,
            pin_required: false,
            protocol_version: PROTOCOL_VERSION,
            pubkey: kp.public_key().to_z32(),
            recipient: None,
            share_ref: "0123456789abcdef0123456789abcdef".into(),
            ttl_seconds: 86400,
        };
        let sig = sign_record(&signable, &kp).unwrap();
        let record = OuterRecord {
            blob: signable.blob.clone(),
            created_at: signable.created_at,
            pin_required: signable.pin_required,
            protocol_version: signable.protocol_version,
            pubkey: signable.pubkey.clone(),
            recipient: signable.recipient.clone(),
            share_ref: signable.share_ref.clone(),
            signature: sig,
            ttl_seconds: signable.ttl_seconds,
        };
        verify_record(&record).unwrap();
    }

    #[test]
    fn tampered_blob_fails_verify() {
        let seed = [42u8; 32];
        let kp = pkarr::Keypair::from_secret_key(&seed);
        let signable = OuterRecordSignable {
            blob: "dGVzdA".into(),
            created_at: 1,
            pin_required: false,
            protocol_version: 1,
            pubkey: kp.public_key().to_z32(),
            recipient: None,
            share_ref: "ff".repeat(16),
            ttl_seconds: 1,
        };
        let sig = sign_record(&signable, &kp).unwrap();
        let record = OuterRecord {
            blob: "TAMPERED".into(), // differs from what was signed
            created_at: 1,
            pin_required: false,
            protocol_version: 1,
            pubkey: signable.pubkey.clone(),
            recipient: None,
            share_ref: "ff".repeat(16),
            signature: sig,
            ttl_seconds: 1,
        };
        let err = verify_record(&record).unwrap_err();
        assert!(matches!(err, Error::SignatureInner));
        // D-16: Display is unified across all signature variants
        assert_eq!(format!("{err}"), "signature verification failed");
    }
}
