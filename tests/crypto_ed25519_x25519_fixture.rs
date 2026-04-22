//! Test Ed25519→X25519 conversion against committed fixture vectors. Pitfall #1.
//!
//! These vectors were generated using ed25519-dalek 3.0.0-pre.5 (pinned in Cargo.toml).
//! If this test fails after a dep upgrade, it means key derivation has changed —
//! every past identity becomes unreachable. Do NOT re-generate silently.

#[derive(serde::Deserialize)]
struct Vector {
    seed_hex: String,
    ed25519_pub_hex: String,
    x25519_pub_hex: String,
    x25519_secret_hex: String,
}

#[test]
fn ed25519_x25519_matches_committed_vectors() {
    let raw = std::fs::read_to_string("tests/fixtures/ed25519_x25519_vectors.json").unwrap();
    let vectors: Vec<Vector> = serde_json::from_str(&raw).unwrap();
    assert!(vectors.len() >= 3, "need at least 3 vectors");
    for v in &vectors {
        let seed: [u8; 32] = hex_decode_32(&v.seed_hex);
        let ed_pub_expected: [u8; 32] = hex_decode_32(&v.ed25519_pub_hex);
        let x_pub_expected: [u8; 32] = hex_decode_32(&v.x25519_pub_hex);
        let x_sec_expected: [u8; 32] = hex_decode_32(&v.x25519_secret_hex);

        let ed_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        assert_eq!(
            ed_pub, ed_pub_expected,
            "ed25519 pub mismatch for seed {}",
            v.seed_hex
        );

        let x_pub = cipherpost::crypto::ed25519_to_x25519_public(&ed_pub).unwrap();
        assert_eq!(
            x_pub, x_pub_expected,
            "x25519 pub mismatch for seed {}",
            v.seed_hex
        );

        let x_sec = cipherpost::crypto::ed25519_to_x25519_secret(&seed);
        assert_eq!(
            &x_sec[..],
            &x_sec_expected[..],
            "x25519 secret mismatch for seed {}",
            v.seed_hex
        );
    }
}

fn hex_decode_32(s: &str) -> [u8; 32] {
    let bytes: Vec<u8> = (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect();
    bytes.try_into().unwrap()
}
