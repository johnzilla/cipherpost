//! SSH-08: Error::SshKeyFormatNotSupported + Error::InvalidMaterial Display
//! must NEVER leak ssh-key / ssh_encoding / pem internal text.
//!
//! Mirrors tests/pgp_error_oracle.rs (Plan 04) and tests/x509_error_oracle.rs
//! (Phase 6) — extends the FORBIDDEN_DISPLAY_TOKENS set with ssh-key crate
//! markers + adds dedicated SshKeyFormatNotSupported regression tests
//! (the new Error variant introduced by Plan 05 — exit 1, no fields).

use cipherpost::error::{exit_code, Error};

/// SSH-specific reason strings audited from src/payload/ingest.rs::ssh_key
/// (Plan 05) — matches the curated literals the function emits.
const SSH_EXPECTED_REASONS: &[&str] = &[
    "malformed OpenSSH v1 blob",
    "trailing bytes after OpenSSH v1 blob",
    "accessor called on wrong variant", // shared with Phase 6 / Plan 04
];

/// Tokens that MUST NOT appear in user-facing Display for SSH error paths.
/// Extends Phase 6 X.509 + Plan 04 PGP lists with ssh-key crate markers.
const SSH_FORBIDDEN_DISPLAY_TOKENS: &[&str] = &[
    // ssh-key crate Error / module paths (T-07-60):
    "ssh_key::Error",
    "ssh_key::",
    "ssh_encoding",
    "ssh_cipher",
    "PemError",
    "ssh-key::",
];

#[test]
fn ssh_invalid_material_display_is_generic_for_every_source_reason() {
    for reason in SSH_EXPECTED_REASONS {
        for variant in &["generic_secret", "x509_cert", "pgp_key", "ssh_key"] {
            let err = Error::InvalidMaterial {
                variant: variant.to_string(),
                reason: reason.to_string(),
            };
            let disp = format!("{err}");
            for forbidden in SSH_FORBIDDEN_DISPLAY_TOKENS {
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
fn ssh_invalid_material_exit_code_is_always_1() {
    for reason in SSH_EXPECTED_REASONS {
        let err = Error::InvalidMaterial {
            variant: "ssh_key".to_string(),
            reason: reason.to_string(),
        };
        assert_eq!(
            exit_code(&err),
            1,
            "SSH InvalidMaterial must map to exit 1, reason={reason}"
        );
    }
}

/// SshKeyFormatNotSupported is the NEW Error variant introduced by Plan 05
/// (D-P7-12). Its Display must include the user-facing ssh-keygen hint
/// AND must NOT leak any ssh-key crate internals.
#[test]
fn ssh_key_format_not_supported_display_omits_internals() {
    let err = Error::SshKeyFormatNotSupported;
    let disp = format!("{err}");
    assert!(
        disp.contains("ssh-keygen -p -o"),
        "Display must include the ssh-keygen conversion hint, got: {disp}"
    );
    for tok in SSH_FORBIDDEN_DISPLAY_TOKENS {
        assert!(
            !disp.contains(tok),
            "SshKeyFormatNotSupported Display leaked forbidden token '{tok}': {disp}"
        );
    }
    // Variant has zero fields — Display must NOT include `variant=` or `reason=`
    // (those would imply an info-disclosure oracle: "your input looked like RSA-PEM").
    assert!(
        !disp.contains("variant=") && !disp.contains("reason="),
        "SshKeyFormatNotSupported has no fields; Display must not include `variant=` or `reason=`, got: {disp}"
    );
}

#[test]
fn ssh_key_format_not_supported_exit_code_is_1() {
    assert_eq!(
        exit_code(&Error::SshKeyFormatNotSupported),
        1,
        "SshKeyFormatNotSupported must map to exit 1 (content-error class, distinct from sig-fail exit 3)"
    );
}

/// Regression guard: SSH error variants must NOT collide with the exit-3
/// signature-failure class. Mirror of pgp_error_oracle.rs's check.
#[test]
fn ssh_exit_3_is_still_reserved_for_signature_failures() {
    assert_eq!(exit_code(&Error::SignatureOuter), 3);
    assert_eq!(exit_code(&Error::SignatureInner), 3);
    assert_eq!(exit_code(&Error::SignatureCanonicalMismatch), 3);
    assert_eq!(exit_code(&Error::SignatureTampered), 3);
    assert_eq!(exit_code(&Error::SshKeyFormatNotSupported), 1);
    assert_eq!(
        exit_code(&Error::InvalidMaterial {
            variant: "ssh_key".into(),
            reason: "malformed OpenSSH v1 blob".into(),
        }),
        1
    );
}
