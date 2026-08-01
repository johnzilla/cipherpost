//! Phase 1 of derived-key packet addressing — see
//! `docs/design/derived-key-addressing.md`.
//!
//! Single-hop stealth (Monero-subaddress-shape) derivation of a per-`share_ref`
//! Ed25519 key from a parent identity key. Pure key math: it computes the derived
//! key on both sides; signing is in `transport.rs` and the flow wires it in.
//!
//! **Canonical derivation input.** The API takes the `share_ref` as its 32-char
//! lowercase-hex string (exactly as it appears in the URI) and decodes it to the
//! raw 16-byte value INTERNALLY (`decode_share_ref`). The hash below is over those
//! raw 16 bytes. Centralizing the decode means no call site can accidentally hash
//! the ASCII-hex bytes and produce wrong (valid-signing but unresolvable) addresses.
//!
//! ```text
//! t   = reduce_mod_ℓ( SHA-512( DERIVE_DOMAIN ‖ parent_pub ‖ raw16(share_ref) ) )
//! A'  = A + t·G          // public derivation — needs only the PUBLIC parent key
//! a'  = a + t (mod ℓ)    // secret derivation — needs the parent seed
//! ```
//!
//! The tweak `t` is public (hashed from public inputs), so the counterparty can
//! derive `A'` with no secret and no discovery index. `a'` is unclamped but
//! `A' = a'·G` is prime-order and canonical, so signatures under it verify with
//! `verify_strict` (correctness proven in `tests/derived_key_spike.rs`). `a'` is
//! never revealed; `t` public ⇒ no leak of the parent scalar.
//!
//! Security-critical invariants (enforced by the golden vectors below and the
//! committed spike): the derived nonce prefix is derived from a SECRET (the
//! parent's SHA-512 hash-prefix half) so per-key signing nonces stay
//! unpredictable, and public/secret derivation MUST agree byte-for-byte.

use crate::error::Error;
use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};
use sha2::{Digest, Sha512};
use zeroize::{Zeroize, Zeroizing};

/// Domain separation for the address tweak `t`. Bumping this changes every
/// derived key — part of the v2 wire contract.
const DERIVE_DOMAIN: &[u8] = b"cipherpost/v2/derive-addr";
/// Domain separation for the derived signing nonce prefix.
const DERIVE_PREFIX_DOMAIN: &[u8] = b"cipherpost/v2/derive-prefix";

/// Decode the 32-char lowercase-hex `share_ref` (as it appears in the URI) into
/// the raw 16-byte value that IS the canonical derivation input. Centralizing the
/// decode here means no call site can accidentally derive over the ASCII-hex bytes
/// instead of the 128-bit value (which would silently produce wrong addresses).
fn decode_share_ref(share_ref_hex: &str) -> Result<[u8; 16], Error> {
    // Strictly lowercase hex — matches ShareUri::parse and the frozen v2 contract.
    // (Uppercase would decode to identical bytes, but strictness at boundaries is
    // this project's style, and the contract text says lowercase.)
    let is_lower_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
    if share_ref_hex.len() != 32 || !share_ref_hex.bytes().all(is_lower_hex) {
        return Err(Error::Config(
            "share_ref must be 32 lowercase-hex chars".into(),
        ));
    }
    let mut out = [0u8; 16];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&share_ref_hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::Config("share_ref is not valid hex".into()))?;
    }
    Ok(out)
}

/// The public address tweak `t = reduce_mod_ℓ(SHA-512(DOMAIN ‖ parent_pub ‖ share_ref))`,
/// where `share_ref` is the raw 16-byte value. Public — depends only on public inputs.
fn tweak(parent_pub: &[u8; 32], share_ref: &[u8; 16]) -> Scalar {
    let mut h = Sha512::new();
    h.update(DERIVE_DOMAIN);
    h.update(parent_pub);
    h.update(share_ref);
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&h.finalize());
    let t = Scalar::from_bytes_mod_order_wide(&wide);
    wide.zeroize();
    t
}

/// Secret signing material for one `(parent, share_ref)` derived key.
///
/// **No `Debug` derive** (Pitfall #7 leak-scan): the scalar and nonce prefix are
/// secret. Both are held in `Zeroizing` so drop wipes them.
/// `scalar`/`prefix` and their accessors are the transport signing interface
/// (`build_derived_signed_packet`), consumed via `hazmat::raw_sign`.
pub struct DerivedSigner {
    /// `a' = a + t (mod ℓ)`, canonical little-endian bytes. SECRET — Phase 2
    /// rebuilds an `ed25519_dalek::hazmat::ExpandedSecretKey` from this.
    scalar: Zeroizing<[u8; 32]>,
    /// Derived Ed25519 nonce prefix (the second half of the expanded key). SECRET.
    prefix: Zeroizing<[u8; 32]>,
    /// `A' = a'·G`, compressed. PUBLIC.
    public: [u8; 32],
}

impl DerivedSigner {
    /// The derived public key `A'` (compressed Edwards). Publish/resolve address.
    pub fn public(&self) -> [u8; 32] {
        self.public
    }

    /// Derived secret scalar bytes (`a'`). `pub(crate)` — only the transport layer
    /// (Phase 2) consumes it to sign; never crosses the public API surface.
    pub(crate) fn scalar_bytes(&self) -> &[u8; 32] {
        &self.scalar
    }

    /// Derived nonce prefix. `pub(crate)` for the same reason as `scalar_bytes`.
    pub(crate) fn prefix(&self) -> &[u8; 32] {
        &self.prefix
    }
}

/// PUBLIC derivation: `A' = A + t·G` from the parent's PUBLIC key only.
/// The counterparty (recipient of a share, or sender fetching a receipt) uses
/// this — no secret, no index. Errors if `parent_pub` is not a valid Edwards
/// point.
pub fn derive_public(parent_pub: &[u8; 32], share_ref_hex: &str) -> Result<[u8; 32], Error> {
    let raw = decode_share_ref(share_ref_hex)?;
    let parent_point = CompressedEdwardsY(*parent_pub)
        .decompress()
        .ok_or_else(|| Error::Config("derive_public: parent key is not a valid point".into()))?;
    let t = tweak(parent_pub, &raw);
    let derived = parent_point + ED25519_BASEPOINT_TABLE * &t;
    Ok(derived.compress().to_bytes())
}

/// SECRET derivation: the full signing material for `(parent_seed, share_ref)`.
/// Only the parent-secret holder can call this. Errors only if `share_ref_hex` is
/// not 32 lowercase-hex chars (the key math itself is infallible — any 32-byte
/// seed is a valid Ed25519 seed and `A' = a'·G` is always a valid point).
pub fn derive_signer(parent_seed: &[u8; 32], share_ref_hex: &str) -> Result<DerivedSigner, Error> {
    let raw = decode_share_ref(share_ref_hex)?;
    // Parent expanded key: a = clamped scalar, master_prefix = nonce half.
    let sk = ed25519_dalek::SigningKey::from_bytes(parent_seed);
    let parent_pub = sk.verifying_key().to_bytes();
    let a = sk.to_scalar(); // clamped, reduced parent scalar

    // Master nonce-prefix half = SHA-512(seed)[32..64]. Computed directly (rather
    // than via hazmat) so this module needs no hazmat feature.
    let mut expanded = Zeroizing::new([0u8; 64]);
    expanded.copy_from_slice(&Sha512::digest(parent_seed));
    let mut master_prefix = Zeroizing::new([0u8; 32]);
    master_prefix.copy_from_slice(&expanded[32..64]);

    let t = tweak(&parent_pub, &raw);
    let mut a_prime = a + t;
    let public = (ED25519_BASEPOINT_TABLE * &a_prime).compress().to_bytes();
    let scalar = Zeroizing::new(a_prime.to_bytes());
    a_prime.zeroize();

    // Derived nonce prefix = SHA-512(PREFIX_DOMAIN ‖ master_prefix ‖ share_ref)[..32].
    // Derived from a SECRET (master_prefix) so per-key nonces are unpredictable.
    let mut ph = Sha512::new();
    ph.update(DERIVE_PREFIX_DOMAIN);
    ph.update(master_prefix.as_slice());
    ph.update(raw);
    let ph_out = ph.finalize();
    let mut prefix = Zeroizing::new([0u8; 32]);
    prefix.copy_from_slice(&ph_out[..32]);

    Ok(DerivedSigner {
        scalar,
        prefix,
        public,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    /// Public and secret derivation MUST agree byte-for-byte. If they ever
    /// diverge, senders and recipients would compute different addresses and
    /// every share/receipt would become unresolvable.
    #[test]
    fn public_and_secret_derivation_agree() {
        for seed_byte in [0u8, 7, 0x5a, 0xff] {
            for ref_byte in [0x00u8, 0x11, 0xab] {
                let seed = [seed_byte; 32];
                // share_ref is the 32-char lowercase-hex form (as in the URI).
                let share_ref = hex(&[ref_byte; 16]);
                let signer = derive_signer(&seed, &share_ref).unwrap();
                let parent_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
                    .verifying_key()
                    .to_bytes();
                let public = derive_public(&parent_pub, &share_ref).unwrap();
                assert_eq!(
                    signer.public(),
                    public,
                    "public/secret derivation disagree for seed={seed_byte:#x} ref={ref_byte:#x}",
                );
            }
        }
    }

    /// BYTE-EXACT golden vector (matches `tests/derived_key_spike.rs`). Catches an
    /// upstream curve/hash drift that yields a different-but-self-consistent key —
    /// which `public_and_secret_derivation_agree` alone would NOT catch.
    #[test]
    fn golden_vector_seed7_ref11() {
        let seed = [7u8; 32];
        // Hex form of [0x11; 16] — decodes back to the raw 16 bytes, so the pinned
        // values below are unchanged by the hex-input API.
        let share_ref = "11111111111111111111111111111111";
        let parent_pub = ed25519_dalek::SigningKey::from_bytes(&seed)
            .verifying_key()
            .to_bytes();
        let a_prime_pub = derive_public(&parent_pub, share_ref).unwrap();
        assert_eq!(
            hex(&a_prime_pub),
            "5af3abc0070698cedb92d1c16da7d2c1bdcbe9ea5bbfce9fba32d4d9d72155f5",
            "golden A' drift",
        );
        // Secret side produces the same public key + a deterministic scalar/prefix.
        let signer = derive_signer(&seed, share_ref).unwrap();
        assert_eq!(
            signer.public(),
            a_prime_pub,
            "secret-side A' matches public"
        );
        assert_eq!(
            hex(signer.scalar_bytes()),
            "ce663dca22ba636800f6c2377163db7591602ad123715f362fa1c364ed44b80d",
            "golden a' (derived scalar) drift",
        );
        assert_eq!(
            hex(signer.prefix()),
            "5d365967bde2f0f03a762a726326ccd84f1aa43ecd5890f090d66849f9a45b1b",
            "golden derived nonce-prefix drift",
        );
    }

    /// An off-curve parent encoding is rejected with an error, not silently
    /// mangled or panicked. (Not every 32-byte value decompresses; find one that
    /// doesn't and assert `derive_public` surfaces it as `Err`.)
    #[test]
    fn derive_public_rejects_invalid_point() {
        let mut bad = [0u8; 32];
        for n in 1u8..=255 {
            bad[0] = n;
            if CompressedEdwardsY(bad).decompress().is_none() {
                assert!(
                    derive_public(&bad, "00000000000000000000000000000000").is_err(),
                    "off-curve parent must yield Err",
                );
                return;
            }
        }
        panic!("expected to find a non-decompressable encoding to test");
    }

    /// The share_ref decode gate (frozen v2 contract): exactly 32 lowercase-hex
    /// chars. Length, non-hex, and UPPERCASE are all rejected.
    #[test]
    fn decode_share_ref_rejects_malformed() {
        let parent = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32])
            .verifying_key()
            .to_bytes();
        // Valid: 32 lowercase hex.
        assert!(derive_public(&parent, "0123456789abcdef0123456789abcdef").is_ok());
        // Too short / too long.
        assert!(derive_public(&parent, "abcd").is_err());
        assert!(derive_public(&parent, &"a".repeat(33)).is_err());
        // Non-hex character (32 chars, but 'z').
        assert!(derive_public(&parent, "zz23456789abcdef0123456789abcdef").is_err());
        // Uppercase rejected (lowercase-only contract).
        assert!(derive_public(&parent, "0123456789ABCDEF0123456789abcdef").is_err());
        // Same must hold for the secret side.
        assert!(derive_signer(&[7u8; 32], "0123456789ABCDEF0123456789abcdef").is_err());
    }

    /// The derived nonce prefix depends on the SECRET master prefix + share_ref —
    /// distinct share_refs give distinct prefixes (unpredictable per key).
    #[test]
    fn distinct_share_refs_give_distinct_prefixes() {
        let seed = [3u8; 32];
        let p1 = derive_signer(&seed, &hex(&[0x01u8; 16])).unwrap();
        let p2 = derive_signer(&seed, &hex(&[0x02u8; 16])).unwrap();
        assert_ne!(p1.prefix(), p2.prefix());
        assert_ne!(p1.public(), p2.public());
        assert_ne!(p1.scalar_bytes(), p2.scalar_bytes());
    }
}
