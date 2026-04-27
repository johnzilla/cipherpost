//! PGP-08: Error::InvalidMaterial Display must NEVER leak rpgp / nom / parser
//! internal text.
//!
//! Enumerates every reason string `payload::ingest::pgp_key` and
//! `preview::render_pgp_preview` can produce (audited manually from src/).

use cipherpost::error::{exit_code, Error};

/// PGP-specific reason strings (Phase 7 Plan 01 + Plan 02 + Plan 04 audit).
const PGP_EXPECTED_REASONS: &[&str] = &[
    "ASCII-armored input rejected — supply binary packet stream",
    "PgpKey must contain exactly one primary key; keyrings are not supported in v1.1 (found 2 primary keys)",
    "PgpKey must contain exactly one primary key; keyrings are not supported in v1.1 (found 3 primary keys)",
    "malformed PGP packet stream",
    "trailing bytes after PGP packet stream",
    "accessor called on wrong variant", // shared with Phase 6
];

/// Tokens that MUST NOT appear in user-facing Display for Error::InvalidMaterial.
/// Extends Phase 6's X.509 list with rpgp-specific markers.
const FORBIDDEN_DISPLAY_TOKENS: &[&str] = &[
    // Phase 6 X.509 (keep):
    "X509Error",
    "parse error at",
    "nom::",
    "Incomplete",
    "Needed",
    "PEMError",
    "asn1-rs",
    "der-parser",
    "x509_parser::",
    // Phase 7 PGP (NEW):
    "pgp::errors",
    "PgpError",
    "pgp::packet",
    "packet::Error",
    "pgp::Error",
    "rpgp",
];

#[test]
fn pgp_invalid_material_display_is_generic_for_every_source_reason() {
    for reason in PGP_EXPECTED_REASONS {
        for variant in &["generic_secret", "x509_cert", "pgp_key", "ssh_key"] {
            let err = Error::InvalidMaterial {
                variant: variant.to_string(),
                reason: reason.to_string(),
            };
            let disp = format!("{err}");
            for forbidden in FORBIDDEN_DISPLAY_TOKENS {
                assert!(
                    !disp.contains(forbidden),
                    "Error::InvalidMaterial{{variant={variant}, reason={reason}}} Display leaked '{forbidden}': {disp:?}"
                );
            }
            assert_eq!(
                disp,
                format!("invalid material: variant={variant}, reason={reason}"),
                "Display format must match #[error] literal"
            );
        }
    }
}

#[test]
fn pgp_invalid_material_exit_code_is_always_1() {
    for reason in PGP_EXPECTED_REASONS {
        let err = Error::InvalidMaterial {
            variant: "pgp_key".to_string(),
            reason: reason.to_string(),
        };
        assert_eq!(
            exit_code(&err),
            1,
            "PGP InvalidMaterial must map to exit 1, reason={reason}"
        );
    }
}

#[test]
fn pgp_exit_3_is_still_reserved_for_signature_failures() {
    // Regression guard — Phase 6 same check, extended to cover Phase 7.
    assert_eq!(exit_code(&Error::SignatureOuter), 3);
    assert_eq!(exit_code(&Error::SignatureInner), 3);
    assert_eq!(exit_code(&Error::SignatureCanonicalMismatch), 3);
    assert_eq!(exit_code(&Error::SignatureTampered), 3);
    assert_eq!(
        exit_code(&Error::InvalidMaterial {
            variant: "pgp_key".into(),
            reason: "malformed PGP packet stream".into(),
        }),
        1
    );
}
