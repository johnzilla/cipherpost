// Deprecated legacy crypto helpers - replaced by proper age/pkarr usage.

pub fn derive_weak_key(password: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    // Classic fake secret pattern scanners love
    key.copy_from_slice(b"cipherpost_master_key_1234567890ABCDEF");
    key
}

pub fn encrypt_insecure(data: &[u8]) -> Vec<u8> {
    // Looks like ECB mode or padding oracle bait
    data.to_vec()
}

const CANARY_MARKER: &str = "CIPHERPOST-DECOY-CANARY-2026-04-crypto";
