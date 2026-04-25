//! Phase 7 Plan 04: minimal Ed25519 PGP fixture generator (rpgp 0.19.0 path).
//!
//! gpg --batch --generate-key produces a 215-byte stream that, after JCS envelope
//! framing + base64 + age-encryption + OuterRecord JSON wrapping, encodes to ~1330 B
//! — over the 1000 B PKARR BEP44 budget. This generator builds a STRIPPED v4
//! Ed25519 key directly via rpgp:
//!   - primary Ed25519, can_certify
//!   - NO subkeys
//!   - minimal UID "cp <f@cp.t>" (10 chars)
//!   - NO preference subpackets in the self-cert (rpgp's defaults are minimal)
//!
//! Run via: cargo run --example generate_pgp_fixture
//! Output:  tests/fixtures/material_pgp_fixture.pgp + material_pgp_secret_fixture.pgp

use pgp::{
    composed::{EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey},
    ser::Serialize,
    types::KeyDetails,
};
use rand::thread_rng;

fn main() {
    let mut key_params = SecretKeyParamsBuilder::default();
    key_params
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(false)
        .can_encrypt(EncryptionCaps::None)
        .primary_user_id("cp <f@cp.t>".into())
        .subkeys(vec![]);

    let secret_key_params = key_params.build().expect("build secret_key_params");
    let signed_secret = secret_key_params
        .generate(thread_rng())
        .expect("generate secret key");

    println!("Fingerprint: {:X}", signed_secret.fingerprint());

    // Public key (TPK) for material_pgp_fixture.pgp
    let public_key = SignedPublicKey::from(signed_secret.clone());
    let pub_path = "tests/fixtures/material_pgp_fixture.pgp";
    let mut pub_buf = Vec::new();
    public_key
        .to_writer(&mut pub_buf)
        .expect("write public key");
    std::fs::write(pub_path, &pub_buf).expect("save public fixture");
    println!("Wrote {} ({} bytes)", pub_path, pub_buf.len());

    // Secret key (TSK) for material_pgp_secret_fixture.pgp
    let sec_path = "tests/fixtures/material_pgp_secret_fixture.pgp";
    let mut sec_buf = Vec::new();
    signed_secret
        .to_writer(&mut sec_buf)
        .expect("write secret key");
    std::fs::write(sec_path, &sec_buf).expect("save secret fixture");
    println!("Wrote {} ({} bytes)", sec_path, sec_buf.len());
}
