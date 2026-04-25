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

// Phase 6: raw-bytes → typed Material normalization (per-variant ingest functions).
pub mod ingest;

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

/// Typed cryptographic-material variants. Wire shape: `{"type":"<snake>","bytes":"<b64>"}`.
/// GenericSecret + X509Cert + PgpKey carry bytes. SshKey is reserved (Phase 7 Plan 05
/// upgrades it to `{ bytes: Vec<u8> }`).
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Material {
    GenericSecret {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,
    },
    X509Cert {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,
    },
    PgpKey {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,
    },
    SshKey,
}

// Manual Debug — redacts data-carrying variants (Pitfall #7). Phase 6: X509Cert
// gains byte data so its arm mirrors GenericSecret's `[REDACTED N bytes]` shape
// (even though leaf certs are typically public, the same shell holds Phase 7
// SSH/PGP *secret* keys — one uniform rule beats per-variant carve-outs).
// Phase 7 Plan 01: PgpKey upgraded to struct variant; gets the same redaction.
impl std::fmt::Debug for Material {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Material::GenericSecret { bytes } => {
                write!(f, "GenericSecret([REDACTED {} bytes])", bytes.len())
            }
            Material::X509Cert { bytes } => {
                write!(f, "X509Cert([REDACTED {} bytes])", bytes.len())
            }
            Material::PgpKey { bytes } => {
                write!(f, "PgpKey([REDACTED {} bytes])", bytes.len())
            }
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

    /// Return the Vec<u8> of an X509Cert variant. Other variants return
    /// `Error::InvalidMaterial { variant, reason: "accessor called on wrong variant" }`
    /// — D-P6-15. This is developer-facing and should never fire in normal flow
    /// (callers match the variant before calling).
    pub fn as_x509_cert_bytes(&self) -> Result<&[u8], Error> {
        match self {
            Material::X509Cert { bytes } => Ok(bytes.as_slice()),
            other => Err(Error::InvalidMaterial {
                variant: variant_tag(other).to_string(),
                reason: "accessor called on wrong variant".to_string(),
            }),
        }
    }

    /// Return the `Vec<u8>` of a `PgpKey` variant. Other variants return
    /// `Error::InvalidMaterial { variant, reason: "accessor called on wrong variant" }`
    /// — mirrors `as_x509_cert_bytes` (D-P6-15 pattern). Developer-facing;
    /// callers match the variant before calling.
    pub fn as_pgp_key_bytes(&self) -> Result<&[u8], Error> {
        match self {
            Material::PgpKey { bytes } => Ok(bytes.as_slice()),
            other => Err(Error::InvalidMaterial {
                variant: variant_tag(other).to_string(),
                reason: "accessor called on wrong variant".to_string(),
            }),
        }
    }

    /// Plaintext byte length of this variant's data field. Feeds `enforce_plaintext_cap`
    /// pre-encrypt (D-P6-16 / X509-06). Unit variants return 0; Phase 7 extends.
    pub fn plaintext_size(&self) -> usize {
        match self {
            Material::GenericSecret { bytes } => bytes.len(),
            Material::X509Cert { bytes } => bytes.len(),
            Material::PgpKey { bytes } => bytes.len(),
            Material::SshKey => 0,
        }
    }
}

/// Wire tag (snake_case) for a variant — mirrors `#[serde(rename_all = "snake_case")]`
/// on the Material enum. Used for Error::InvalidMaterial's `variant` field.
fn variant_tag(m: &Material) -> &'static str {
    match m {
        Material::GenericSecret { .. } => "generic_secret",
        Material::X509Cert { .. } => "x509_cert",
        Material::PgpKey { .. } => "pgp_key",
        Material::SshKey => "ssh_key",
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
        // X509Cert and PgpKey are struct variants after Phase 6 / Phase 7 Plan 01.
        // Their cross-accessor behavior (as_generic_secret_bytes) is tested
        // individually below. Only SshKey remains as the unit-variant placeholder
        // until Phase 7 Plan 05.
        for m in [Material::SshKey] {
            let err = m.as_generic_secret_bytes().unwrap_err();
            assert!(
                matches!(err, Error::NotImplemented { phase: 2 }),
                "expected NotImplemented{{phase:2}}, got {:?}",
                err
            );
        }
    }

    #[test]
    fn material_pgp_key_generic_secret_accessor_returns_not_implemented() {
        let m = Material::PgpKey {
            bytes: vec![0x99, 0x0d],
        };
        let err = m.as_generic_secret_bytes().unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented { phase: 2 }),
            "expected NotImplemented{{phase:2}}, got {:?}",
            err
        );
    }

    #[test]
    fn material_x509_cert_generic_secret_accessor_returns_not_implemented() {
        let m = Material::X509Cert {
            bytes: vec![0xDE, 0xAD],
        };
        let err = m.as_generic_secret_bytes().unwrap_err();
        assert!(
            matches!(err, Error::NotImplemented { phase: 2 }),
            "expected NotImplemented{{phase:2}} from as_generic_secret_bytes on X509Cert, got {:?}",
            err
        );
    }

    #[test]
    fn material_x509_cert_serde_round_trip() {
        let m = Material::X509Cert {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(
            s.contains("\"type\":\"x509_cert\""),
            "serde tag must be snake_case: {}",
            s
        );
        assert!(
            s.contains("\"bytes\":\""),
            "X509Cert.bytes must serialize as base64 string: {}",
            s
        );
        let back: Material = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn material_x509_cert_debug_redacts_bytes() {
        let m = Material::X509Cert {
            bytes: vec![0xAA; 42],
        };
        let dbg = format!("{:?}", m);
        assert_eq!(dbg, "X509Cert([REDACTED 42 bytes])");
        assert!(!dbg.contains("aa"), "Debug leaked byte sequence: {}", dbg);
    }

    #[test]
    fn material_plaintext_size_matches_variant_byte_length() {
        assert_eq!(Material::generic_secret(vec![0; 50]).plaintext_size(), 50);
        assert_eq!(
            Material::X509Cert {
                bytes: vec![0; 123]
            }
            .plaintext_size(),
            123
        );
        assert_eq!(
            Material::PgpKey {
                bytes: vec![0; 77]
            }
            .plaintext_size(),
            77
        );
        assert_eq!(Material::SshKey.plaintext_size(), 0);
    }

    #[test]
    fn material_as_x509_cert_bytes_mismatch_returns_invalid_material() {
        let m = Material::generic_secret(vec![1, 2, 3]);
        let err = m.as_x509_cert_bytes().unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "generic_secret");
                assert_eq!(reason, "accessor called on wrong variant");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn material_as_x509_cert_bytes_happy_returns_slice() {
        let m = Material::X509Cert {
            bytes: vec![0xCA, 0xFE],
        };
        let bytes = m.as_x509_cert_bytes().unwrap();
        assert_eq!(bytes, &[0xCA, 0xFE]);
    }

    #[test]
    fn material_pgp_key_serde_round_trip() {
        let m = Material::PgpKey {
            bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let s = serde_json::to_string(&m).unwrap();
        assert!(
            s.contains("\"type\":\"pgp_key\""),
            "serde tag must be snake_case: {}",
            s
        );
        assert!(
            s.contains("\"bytes\":\""),
            "PgpKey.bytes must serialize as base64 string: {}",
            s
        );
        let back: Material = serde_json::from_str(&s).unwrap();
        assert_eq!(m, back);
    }

    #[test]
    fn material_pgp_key_debug_redacts_bytes() {
        let m = Material::PgpKey {
            bytes: vec![0xAA; 42],
        };
        let dbg = format!("{:?}", m);
        assert_eq!(dbg, "PgpKey([REDACTED 42 bytes])");
        assert!(
            !dbg.to_lowercase().contains("aa"),
            "Debug leaked byte sequence: {}",
            dbg
        );
    }

    #[test]
    fn material_pgp_key_plaintext_size_matches_byte_length() {
        assert_eq!(
            Material::PgpKey {
                bytes: vec![0; 123]
            }
            .plaintext_size(),
            123
        );
    }

    #[test]
    fn material_as_pgp_key_bytes_mismatch_returns_invalid_material() {
        let m = Material::generic_secret(vec![1, 2, 3]);
        let err = m.as_pgp_key_bytes().unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "generic_secret");
                assert_eq!(reason, "accessor called on wrong variant");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
        }
    }

    #[test]
    fn material_as_pgp_key_bytes_happy_returns_slice() {
        let m = Material::PgpKey {
            bytes: vec![0xCA, 0xFE],
        };
        let bytes = m.as_pgp_key_bytes().unwrap();
        assert_eq!(bytes, &[0xCA, 0xFE]);
    }

    #[test]
    fn material_as_x509_cert_bytes_on_pgp_key_returns_invalid_material() {
        let m = Material::PgpKey {
            bytes: vec![0x99],
        };
        let err = m.as_x509_cert_bytes().unwrap_err();
        match err {
            Error::InvalidMaterial { variant, reason } => {
                assert_eq!(variant, "pgp_key");
                assert_eq!(reason, "accessor called on wrong variant");
            }
            other => panic!("expected InvalidMaterial, got {:?}", other),
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
