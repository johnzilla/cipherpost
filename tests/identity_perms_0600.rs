//! IDENT-03 / Pitfall #15: identity file permissions must be 0600.
//!
//! `generate` must write the file at mode 0600.
//! `load` must refuse any file not at exactly 0600 (chmod 0644 → IdentityPermissions, exit 4).

use secrecy::SecretBox;
use serial_test::serial;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

#[test]
#[serial]
fn load_refuses_0644_identity_file() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("correct horse".to_string()));
    let _id = cipherpost::identity::generate(&pw).unwrap();

    let path = cipherpost::identity::key_path();
    // Sanity: just-generated file must be 0600.
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "generate must write mode 0600");

    // Tamper: chmod 0644.
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o644);
    std::fs::set_permissions(&path, perms).unwrap();

    // load() must refuse with IdentityPermissions.
    let err = cipherpost::identity::load(&pw).unwrap_err();
    assert!(
        matches!(err, cipherpost::Error::IdentityPermissions),
        "expected IdentityPermissions, got {err:?}"
    );
}

#[test]
#[serial]
fn generate_writes_0600() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("x".to_string()));
    cipherpost::identity::generate(&pw).unwrap();
    let path = cipherpost::identity::key_path();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "key file must be mode 0600");
}
