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
        let hex: String = win.iter().fold(String::new(), |mut s, b| { use std::fmt::Write; let _ = write!(s, "{:02x}", b); s });
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
    let pass = cipherpost::identity::Passphrase::from_string("my-correct-horse-battery".to_string());
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
