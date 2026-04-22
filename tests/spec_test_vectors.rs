/// SPEC.md §8 test-vector generator.
///
/// Run with:
///   cargo test --features mock gen_spec_test_vectors -- --ignored --nocapture
///
/// Output: OUTER_SIG_B64 and RECEIPT_SIG_B64 lines. The base64 strings are
/// embedded verbatim in SPEC.md §8 and serve as reproducibility anchors for
/// third-party implementers.
///
/// Keypair: Ed25519 SigningKey::from_bytes(&[0u8; 32]) — TEST VECTOR ONLY.
/// This is a known-compromised key. Never use for any real cipherpost identity.
#[test]
#[ignore]
fn gen_spec_test_vectors() {
    use base64::{engine::general_purpose::STANDARD, Engine};
    use ed25519_dalek::{Signer, SigningKey};

    let signing_key = SigningKey::from_bytes(&[0u8; 32]);

    let outer_bytes =
        std::fs::read("tests/fixtures/outer_record_signable.bin").expect("outer fixture missing");
    let outer_sig = signing_key.sign(&outer_bytes);
    println!("OUTER_SIG_B64 = {}", STANDARD.encode(outer_sig.to_bytes()));

    let receipt_bytes =
        std::fs::read("tests/fixtures/receipt_signable.bin").expect("receipt fixture missing");
    let receipt_sig = signing_key.sign(&receipt_bytes);
    println!(
        "RECEIPT_SIG_B64 = {}",
        STANDARD.encode(receipt_sig.to_bytes())
    );
}
