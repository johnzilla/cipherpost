//! CRYPTO-06 / Pitfall #7: secret-holding structs must not leak bytes via Debug.
//!
//! `format!("{:?}", identity)` must contain "REDACTED" and must NOT contain any
//! 8-byte window of the secret key in hex form.
//!
//! `format!("{:?}", passphrase)` must not contain the passphrase string.

use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn identity_debug_does_not_leak_bytes() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("passphrase123".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();

    let debug_str = format!("{:?}", id);

    // Must contain the REDACTED marker.
    assert!(
        debug_str.contains("REDACTED"),
        "Debug impl must show [REDACTED], got: {:?}",
        debug_str
    );

    // Must not contain any 8-byte window of the secret key in hex.
    let secret_bytes = id.secret_key_bytes_for_leak_test();
    for win in secret_bytes.windows(8) {
        let hex: String = win.iter().fold(String::new(), |mut s, b| {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
            s
        });
        assert!(
            !debug_str.contains(&hex),
            "Debug leak: seed bytes {:?} found in format!({{:?}}, identity). Full debug: {:?}",
            hex,
            debug_str
        );
    }
}

#[test]
fn passphrase_debug_does_not_leak() {
    let pass =
        cipherpost::identity::Passphrase::from_string("my-correct-horse-battery".to_string());
    let debug_str = format!("{:?}", pass);
    assert!(
        !debug_str.contains("my-correct-horse-battery"),
        "Passphrase leaked in Debug: {:?}",
        debug_str
    );
    assert!(
        debug_str.contains("REDACTED") || debug_str.contains("Secret"),
        "Debug impl should show [REDACTED] or Secret, got: {:?}",
        debug_str
    );
}

// -----------------------------------------------------------------------------
// Phase 6 Plan 04: extend leak-scan to cover all 4 Material variants.
// The redaction rule is blanket — no byte-holding variant may Debug-print its
// contents, regardless of secrecy class. X509Cert carries public bytes but
// the same Debug shell holds PGP/SSH secret keys in Phase 7 (Pitfall #7).
// -----------------------------------------------------------------------------

#[test]
fn material_generic_secret_debug_redacts_bytes() {
    use cipherpost::payload::Material;
    let m = Material::generic_secret(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
    let dbg = format!("{:?}", m);
    assert!(
        dbg.contains("REDACTED"),
        "GenericSecret Debug must show REDACTED, got: {:?}",
        dbg
    );
    // No 8-byte window of the input in hex (the input is exactly 8 bytes).
    assert!(
        !dbg.contains("deadbeefcafebabe"),
        "GenericSecret Debug leaked bytes: {:?}",
        dbg
    );
}

#[test]
fn material_x509_cert_debug_redacts_bytes() {
    use cipherpost::payload::Material;
    let m = Material::X509Cert {
        bytes: vec![0xAB, 0xCD, 0xEF, 0x12, 0x34, 0x56, 0x78, 0x9A],
    };
    let dbg = format!("{:?}", m);
    assert!(
        dbg.contains("REDACTED"),
        "X509Cert Debug must show REDACTED, got: {:?}",
        dbg
    );
    assert!(
        !dbg.contains("abcdef123456789a"),
        "X509Cert Debug leaked bytes: {:?}",
        dbg
    );
}

#[test]
fn material_pgp_and_ssh_unit_variant_debug_no_bytes() {
    use cipherpost::payload::Material;
    // Unit variants have nothing to leak — the Debug string is just the variant name.
    assert_eq!(format!("{:?}", Material::PgpKey), "PgpKey");
    assert_eq!(format!("{:?}", Material::SshKey), "SshKey");
}
