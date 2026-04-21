//! Pitfall #8 / CRYPTO-02: unlock reads Argon2 params from file header, not code constants.
//!
//! We write an identity envelope with non-default, weaker Argon2 params (m=19456, t=2, p=1)
//! and verify that `load()` successfully decrypts it — proving it reads params from the PHC
//! header rather than using hardcoded defaults (which are m=65536, t=3, p=1).

use argon2::Params;
use secrecy::SecretBox;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;
use zeroize::Zeroizing;

#[test]
fn unlock_uses_header_params_not_code_constants() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));

    // Non-default WEAKER params to prove unlock reads them from header.
    let weak = Params::new(19456, 2, 1, Some(32)).unwrap();
    let seed = [7u8; 32];
    let blob = cipherpost::crypto::encrypt_key_envelope_with_params(
        &Zeroizing::new(seed),
        &pw,
        &weak,
    )
    .unwrap();

    let path = cipherpost::identity::key_path();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, &blob).unwrap();

    // Set file mode to 0600 so load() accepts it.
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(&path, perms).unwrap();

    // load() must succeed using header params (weak), not code defaults (strong).
    let id = cipherpost::identity::load(&pw).unwrap();

    // Verify we got the seed back by checking the derived pubkey.
    let recovered_pub = id.public_key_bytes();
    let expected_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        recovered_pub, expected_pub,
        "recovered pubkey must match seed's derived pubkey"
    );
}
