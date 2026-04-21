//! Envelope + Material — Phase 2 payload schema (D-WIRE-01..05).
//!
//! Envelope is the cleartext struct that gets JCS-serialized then age-encrypted
//! into OuterRecord.blob. Material is the tagged enum for supported payload types;
//! GenericSecret is implemented in Phase 2, other variants are reserved (encode is
//! allowed for protocol fingerprinting, decode returns Error::NotImplemented).
//!
//! Pitfalls addressed:
//!   #3  — all serialization goes through crypto::jcs_serialize (no raw serde_json byte serializers)
//!   #7  — Material::GenericSecret.bytes carries plaintext; manual Debug redacts it
//!   #12 — purpose is stripped of control chars at send time (strip_control_chars)

use crate::crypto::jcs_serialize;
use crate::error::Error;
use serde::{Deserialize, Serialize};

/// Plaintext payload cap (D-PS-01, PAYL-03). Pre-encrypt check.
pub const PLAINTEXT_CAP: usize = 65536;

/// The cleartext envelope. Canonicalized with JCS before age-encryption.
///
/// Fields are in alphabetical declaration order (belt-and-suspenders; JCS sorts
/// regardless). This matches the Phase 1 OuterRecordSignable convention.
///
/// Note: deriving the Debug trait is forbidden here because Material::GenericSecret.bytes
/// is pre-encryption plaintext. A manual impl Debug below redacts the material.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub created_at: i64,
    pub material: Material,
    pub protocol_version: u16,
    pub purpose: String,
}

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("created_at", &self.created_at)
            .field("material", &self.material) // Material has its own redacting Debug
            .field("protocol_version", &self.protocol_version)
            .field("purpose", &self.purpose)
            .finish()
    }
}

impl Envelope {
    /// JCS-serialize this Envelope. This is the byte string that gets age-encrypted.
    pub fn to_jcs_bytes(&self) -> Result<Vec<u8>, Error> {
        jcs_serialize(self)
    }

    /// Parse JCS bytes into an Envelope. Failure maps to SignatureCanonicalMismatch
    /// per D-RECV-01 step 7 — a malformed envelope post-decrypt is an inner-sig class
    /// failure (exit 3), not a generic parse error.
    pub fn from_jcs_bytes(bytes: &[u8]) -> Result<Self, Error> {
        serde_json::from_slice(bytes).map_err(|_| Error::SignatureCanonicalMismatch)
    }
}

/// Typed cryptographic-material variants. Wire shape: `{"type":"<snake>","bytes":"<b64>"}`
/// (GenericSecret carries bytes; other variants have no associated data in Phase 2).
///
/// Non-GenericSecret variants encode (and decode) their `{"type": ...}` tag but any
/// attempt to READ the material bytes returns Error::NotImplemented { phase: 2 }.
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Material {
    GenericSecret {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,
    },
    X509Cert,
    PgpKey,
    SshKey,
}

// Manual Debug — redacts GenericSecret bytes (Pitfall #7).
impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Material::GenericSecret { bytes } => {
                write!(f, "GenericSecret([REDACTED {} bytes])", bytes.len())
            }
            Material::X509Cert => write!(f, "X509Cert"),
            Material::PgpKey => write!(f, "PgpKey"),
            Material::SshKey => write!(f, "SshKey"),
        }
    }
}

impl Material {
    /// Return the Vec<u8> of a GenericSecret variant. Other variants return
    /// Error::NotImplemented { phase: 2 } — they are reserved for v1.0.
    pub fn as_generic_secret_bytes(&self) -> Result<&[u8], Error> {
        match self {
            Material::GenericSecret { bytes } => Ok(bytes.as_slice()),
            _ => Err(Error::NotImplemented { phase: 2 }),
        }
    }

    /// Construct a GenericSecret; non-generic-secret constructors are rejected at
    /// the public-API level in Phase 2.
    pub fn generic_secret(bytes: Vec<u8>) -> Self {
        Material::GenericSecret { bytes }
    }
}

/// Strip C0 (0x00..=0x1F), DEL (0x7F), and C1 (0x80..=0x9F) control characters.
/// `char::is_control` covers the Unicode "Cc" category which matches exactly this range.
/// Applied ONCE at send time (D-WIRE-05) so sender and recipient see byte-identical purpose.
pub fn strip_control_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

/// Enforce the 64 KB plaintext cap (PAYL-03, D-PS-01). Pure client-side, pre-encrypt.
/// Error Display contains both the actual size and the cap per D-PS-03.
pub fn enforce_plaintext_cap(len: usize) -> Result<(), Error> {
    if len > PLAINTEXT_CAP {
        return Err(Error::PayloadTooLarge {
            actual: len,
            limit: PLAINTEXT_CAP,
        });
    }
    Ok(())
}

/// serde-with module for Vec<u8> ↔ base64 standard with padding (D-WIRE-04).
/// Ban URL_SAFE_NO_PAD at this layer — the crate uses STANDARD everywhere else too.
mod base64_std {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_envelope() -> Envelope {
        Envelope {
            created_at: 1_700_000_000,
            material: Material::generic_secret(vec![0, 1, 2, 3]),
            protocol_version: crate::PROTOCOL_VERSION,
            purpose: "test".to_string(),
        }
    }

    #[test]
    fn envelope_jcs_round_trip_is_byte_identical() {
        let e = sample_envelope();
        let bytes1 = e.to_jcs_bytes().unwrap();
        let parsed = Envelope::from_jcs_bytes(&bytes1).unwrap();
        let bytes2 = parsed.to_jcs_bytes().unwrap();
        assert_eq!(bytes1, bytes2, "JCS round-trip must be byte-identical");
        assert_eq!(e, parsed, "Envelope round-trip must be structurally equal");
    }

    #[test]
    fn envelope_from_malformed_bytes_returns_sig_canonical_mismatch() {
        let err = Envelope::from_jcs_bytes(b"not json").unwrap_err();
        assert!(matches!(err, Error::SignatureCanonicalMismatch));
    }

    #[test]
    fn material_generic_secret_serde_round_trip() {
        let m = Material::generic_secret(vec![0xde, 0xad, 0xbe, 0xef]);
        let s = serde_json::to_string(&m).unwrap();
        assert!(
            s.contains("\"type\":\"generic_secret\""),
            "serde tag should be snake_case: {}",
            s
        );
        assert!(
            s.contains("\"bytes\":\""),
            "GenericSecret.bytes should serialize as base64 string: {}",
            s
        );
        let back: Material = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn material_non_generic_variants_return_not_implemented_on_bytes_access() {
        for m in [Material::X509Cert, Material::PgpKey, Material::SshKey] {
            let err = m.as_generic_secret_bytes().unwrap_err();
            assert!(
                matches!(err, Error::NotImplemented { phase: 2 }),
                "expected NotImplemented{{phase:2}}, got {:?}",
                err
            );
        }
    }

    #[test]
    fn strip_control_chars_strips_c0_del_c1_preserves_unicode() {
        assert_eq!(
            strip_control_chars("a\x00b\x1fc\x7fd\u{80}e\u{9f}z"),
            "abcdez"
        );
        assert_eq!(strip_control_chars("Hello, 世界! 🎉"), "Hello, 世界! 🎉");
        assert_eq!(strip_control_chars(""), "");
    }

    #[test]
    fn enforce_plaintext_cap_allows_64k_and_rejects_above() {
        assert!(enforce_plaintext_cap(0).is_ok());
        assert!(enforce_plaintext_cap(65536).is_ok());
        let err = enforce_plaintext_cap(65537).unwrap_err();
        assert!(matches!(
            err,
            Error::PayloadTooLarge {
                actual: 65537,
                limit: 65536
            }
        ));
        let disp = format!("{}", err);
        assert!(
            disp.contains("65537"),
            "error Display must contain actual size, got: {}",
            disp
        );
        assert!(
            disp.contains("65536"),
            "error Display must contain 65536 cap, got: {}",
            disp
        );
    }

    #[test]
    fn envelope_debug_redacts_material_bytes() {
        let e = sample_envelope();
        let dbg = format!("{:?}", e);
        assert!(
            dbg.contains("REDACTED"),
            "Envelope Debug must redact Material bytes, got: {}",
            dbg
        );
        // 4 bytes [0,1,2,3] are short but MATCH patterns like "00010203" would not appear;
        // strong check: no raw hex sequence of the material appears
        assert!(
            !dbg.contains("00010203"),
            "Envelope Debug leaked material bytes: {}",
            dbg
        );
    }
}
