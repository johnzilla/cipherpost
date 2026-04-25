//! SSH-01, SSH-02, SSH-08: ingest pipeline coverage.
//!
//! Exercises payload::ingest::ssh_key across happy OpenSSH v1, format-rejection
//! (legacy PEM × 3 + RFC 4716 + FIDO), malformed body, trailing bytes,
//! cross-variant accessor mismatch, and Display oracle hygiene for both
//! Error::SshKeyFormatNotSupported and Error::InvalidMaterial.
//!
//! Mirrors tests/material_pgp_ingest.rs (Plan 04 sibling) and
//! tests/material_x509_ingest.rs (Phase 6 sibling).

use cipherpost::payload::{ingest, Material};
use cipherpost::Error;

const SSH_FIXTURE: &[u8] = include_bytes!("fixtures/material_ssh_fixture.openssh-v1");

#[test]
fn ssh_key_happy_path_produces_ssh_variant_with_canonical_bytes() {
    let m = ingest::ssh_key(SSH_FIXTURE).expect("valid OpenSSH v1 fixture");
    match m {
        Material::SshKey { bytes } => {
            // Bytes are the canonical re-encode (D-P7-11) — they must re-parse
            // cleanly. ssh-key 0.6.7's from_openssh accepts impl AsRef<[u8]>;
            // canonical UTF-8 PEM is acceptable directly.
            let _ = ssh_key::PrivateKey::from_openssh(&bytes)
                .expect("canonical bytes must re-parse");
            // Stored bytes must contain the OpenSSH v1 BEGIN/END markers.
            assert!(
                bytes.starts_with(b"-----BEGIN OPENSSH PRIVATE KEY-----"),
                "canonical bytes must start with OpenSSH v1 BEGIN marker"
            );
        }
        other => panic!("expected SshKey variant, got {:?}", other),
    }
}

#[test]
fn ssh_key_canonical_re_encode_round_trip() {
    let m1 = ingest::ssh_key(SSH_FIXTURE).expect("first parse");
    let bytes1 = match m1 {
        Material::SshKey { bytes } => bytes,
        other => panic!("expected SshKey, got {:?}", other),
    };
    let m2 = ingest::ssh_key(&bytes1).expect("second parse on canonical bytes");
    let bytes2 = match m2 {
        Material::SshKey { bytes } => bytes,
        other => panic!("expected SshKey, got {:?}", other),
    };
    assert_eq!(
        bytes1, bytes2,
        "D-P7-11 canonical re-encode must be byte-deterministic across re-ingests"
    );
}

#[test]
fn ssh_key_legacy_pem_rsa_rejected() {
    let err = ingest::ssh_key(
        b"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----\n",
    )
    .unwrap_err();
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "legacy RSA-PEM must trigger SshKeyFormatNotSupported, got: {:?}",
        err
    );
}

#[test]
fn ssh_key_legacy_pem_dsa_rejected() {
    let err = ingest::ssh_key(b"-----BEGIN DSA PRIVATE KEY-----\nstuff\n-----END DSA PRIVATE KEY-----\n").unwrap_err();
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "legacy DSA-PEM must trigger SshKeyFormatNotSupported, got: {:?}",
        err
    );
}

#[test]
fn ssh_key_legacy_pem_ec_rejected() {
    let err = ingest::ssh_key(b"-----BEGIN EC PRIVATE KEY-----\nstuff\n-----END EC PRIVATE KEY-----\n").unwrap_err();
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "legacy EC-PEM must trigger SshKeyFormatNotSupported, got: {:?}",
        err
    );
}

#[test]
fn ssh_key_rfc4716_rejected() {
    let err = ingest::ssh_key(b"---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----\nstuff\n---- END SSH2 ENCRYPTED PRIVATE KEY ----\n").unwrap_err();
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "RFC 4716 SSH2 must trigger SshKeyFormatNotSupported, got: {:?}",
        err
    );
}

#[test]
fn ssh_key_fido_rejected() {
    let err = ingest::ssh_key(b"-----BEGIN OPENSSH-FIDO PRIVATE KEY-----\nstuff\n-----END OPENSSH-FIDO PRIVATE KEY-----\n").unwrap_err();
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "OPENSSH-FIDO must trigger SshKeyFormatNotSupported, got: {:?}",
        err
    );
}

#[test]
fn ssh_key_garbage_rejected_as_format_not_supported() {
    let err = ingest::ssh_key(b"random bytes that are not any kind of key").unwrap_err();
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "garbage must trigger SshKeyFormatNotSupported (format-sniff first), got: {:?}",
        err
    );
}

#[test]
fn ssh_key_empty_input_rejected_as_format_not_supported() {
    let err = ingest::ssh_key(b"").unwrap_err();
    assert!(
        matches!(err, Error::SshKeyFormatNotSupported),
        "empty input must trigger SshKeyFormatNotSupported, got: {:?}",
        err
    );
}

#[test]
fn ssh_key_malformed_openssh_v1_body_rejected_as_invalid_material() {
    // Header IS OpenSSH-v1 → format check passes → body is garbage →
    // InvalidMaterial (NOT SshKeyFormatNotSupported, because the user
    // supplied the right format — different remediation class).
    let err = ingest::ssh_key(
        b"-----BEGIN OPENSSH PRIVATE KEY-----\nGARBAGE_NOT_BASE64\n-----END OPENSSH PRIVATE KEY-----\n",
    )
    .unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "ssh_key");
            assert_eq!(reason, "malformed OpenSSH v1 blob");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn ssh_key_trailing_bytes_rejected() {
    // Append non-whitespace bytes after the END marker — guards against
    // share_ref drift via attacker-appended trailers (T-07-39).
    let mut tampered = SSH_FIXTURE.to_vec();
    tampered.extend_from_slice(b"\nGARBAGE_AFTER_END_MARKER\n");
    let err = ingest::ssh_key(&tampered).unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "ssh_key");
            assert_eq!(reason, "trailing bytes after OpenSSH v1 blob");
        }
        other => panic!("expected InvalidMaterial trailing-bytes, got {:?}", other),
    }
}

#[test]
fn ssh_key_accessor_wrong_variant_returns_invalid_material() {
    let m = Material::generic_secret(vec![1, 2, 3]);
    let err = m.as_ssh_key_bytes().unwrap_err();
    match err {
        Error::InvalidMaterial { variant, reason } => {
            assert_eq!(variant, "generic_secret");
            assert_eq!(reason, "accessor called on wrong variant");
        }
        other => panic!("expected InvalidMaterial, got {:?}", other),
    }
}

#[test]
fn ssh_key_error_display_contains_no_parser_internals() {
    // Forbidden tokens — ssh-key crate internal types, ssh_encoding, PEM
    // crate types. The user-facing Display must NEVER include these.
    let forbidden: &[&str] = &[
        "ssh_key::Error",
        "ssh_key::",
        "ssh_encoding",
        "ssh_cipher",
        "PemError",
        "ssh-key::",
    ];

    let errors = vec![
        ingest::ssh_key(
            b"-----BEGIN RSA PRIVATE KEY-----\n...\n-----END RSA PRIVATE KEY-----\n",
        )
        .unwrap_err(),
        ingest::ssh_key(b"random garbage with no header").unwrap_err(),
        ingest::ssh_key(
            b"-----BEGIN OPENSSH PRIVATE KEY-----\nGARBAGE\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap_err(),
        {
            let mut t = SSH_FIXTURE.to_vec();
            t.extend_from_slice(b"\nbad");
            ingest::ssh_key(&t).unwrap_err()
        },
    ];

    for err in errors {
        let disp = format!("{}", err);
        for tok in forbidden {
            assert!(
                !disp.contains(tok),
                "SSH ingest Error::Display leaked forbidden token '{}': {:?}",
                tok,
                disp
            );
        }
    }
}
