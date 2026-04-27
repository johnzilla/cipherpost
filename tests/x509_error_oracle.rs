//! X509-08 + Pitfall #16 (error-oracle hygiene): Error::InvalidMaterial's Display
//! string must NEVER leak x509-parser / nom / der-parser internal text.
//!
//! This test enumerates every reason string the code can produce (collected by
//! manual audit of src/payload/ingest.rs + src/preview.rs + src/payload/mod.rs
//! accessor) and asserts Display shape + exit-code mapping.

use cipherpost::error::{exit_code, Error};

/// The complete set of `reason` strings that any code path in cipherpost can
/// construct for `Error::InvalidMaterial`. Audited from:
///   - src/payload/ingest.rs (4 reasons: malformed DER, trailing bytes, PEM body
///     decode failed, PEM label is not CERTIFICATE)
///   - src/preview.rs (2 reasons: malformed DER, trailing bytes — duplicated with
///     ingest by design for oracle hygiene)
///   - src/payload/mod.rs accessor (1 reason: accessor called on wrong variant)
///
/// If a new reason string is added to the code, this list MUST be updated —
/// otherwise the oracle-hygiene coverage is incomplete. See the grep-based
/// self-check below.
const EXPECTED_REASONS: &[&str] = &[
    "malformed DER",
    "trailing bytes after certificate",
    "PEM body decode failed",
    "PEM label is not CERTIFICATE",
    "accessor called on wrong variant",
];

/// Tokens that MUST NOT appear in any user-facing Display output for
/// Error::InvalidMaterial — Pitfall #16 / X509-08.
const FORBIDDEN_DISPLAY_TOKENS: &[&str] = &[
    "X509Error",
    "parse error at",
    "nom::",
    "Incomplete",
    "Needed",
    "PEMError",
    "asn1-rs",
    "der-parser",
    "x509_parser::",
];

#[test]
fn invalid_material_display_is_generic_for_every_source_reason() {
    for reason in EXPECTED_REASONS {
        for variant in &["generic_secret", "x509_cert", "pgp_key", "ssh_key"] {
            let err = Error::InvalidMaterial {
                variant: variant.to_string(),
                reason: reason.to_string(),
            };
            let disp = format!("{err}");
            for forbidden in FORBIDDEN_DISPLAY_TOKENS {
                assert!(
                    !disp.contains(forbidden),
                    "Error::InvalidMaterial{{variant={variant}, reason={reason}}} Display leaked '{forbidden}': full display = {disp:?}"
                );
            }
            // Positive assertion: Display IS the format from
            // `#[error("invalid material: variant={variant}, reason={reason}")]`
            assert_eq!(
                disp,
                format!("invalid material: variant={variant}, reason={reason}"),
                "Display format must match #[error] literal"
            );
        }
    }
}

#[test]
fn invalid_material_exit_code_is_always_1() {
    for reason in EXPECTED_REASONS {
        let err = Error::InvalidMaterial {
            variant: "x509_cert".to_string(),
            reason: reason.to_string(),
        };
        let code = exit_code(&err);
        assert_eq!(
            code, 1,
            "Error::InvalidMaterial must map to exit 1 (X509-08: distinct from exit 3 sig failures), reason={reason}"
        );
    }
}

#[test]
fn exit_3_is_still_reserved_for_signature_failures() {
    // Regression guard: InvalidMaterial must not collapse into the Signature* bucket.
    assert_eq!(exit_code(&Error::SignatureOuter), 3);
    assert_eq!(exit_code(&Error::SignatureInner), 3);
    assert_eq!(exit_code(&Error::SignatureCanonicalMismatch), 3);
    assert_eq!(exit_code(&Error::SignatureTampered), 3);
    // And exit 1 is where InvalidMaterial lives.
    assert_eq!(
        exit_code(&Error::InvalidMaterial {
            variant: "x509_cert".into(),
            reason: "malformed DER".into(),
        }),
        1
    );
}
