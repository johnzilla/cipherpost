//! Pubky `AuthToken` construction — feature-gated (`large-payload`, v2).
//!
//! Replicates pubky-common's `AuthToken` postcard wire format so cipherpost can
//! authenticate to a pubky homeserver WITHOUT depending on the `pubky`/`pubky-common`
//! crates (which pull pkarr 6 → `ed25519-dalek 3.0.0-pre.6`, conflicting with our
//! pinned pkarr 5 → `=3.0.0-pre.5`). We sign with the `pkarr::Keypair` we already
//! hold; ed25519 is deterministic, so the bytes match pubky-common's exactly.
//!
//! Wire layout (postcard), verified byte-for-byte against pubky-common v0.9.1
//! (see the golden-vector test below):
//! ```text
//!   [0..64]     signature    ed25519 over bytes[65..] (== tail[1..])
//!   [64..74]    namespace    b"PUBKY:AUTH"
//!   [74]        version      0x00
//!   [75..83]    timestamp    u64 big-endian, unix MICROseconds
//!   [83..115]   public_key   32 raw ed25519 bytes
//!   [115..]     capabilities postcard string: varint-len ++ utf8 (e.g. "/:rw")
//! ```
//! The homeserver verifies a ±3-minute timestamp window and rejects replays, so a
//! fresh token (new timestamp) must be built for every request that carries one.

use crate::error::Error;
use pkarr::Keypair;
use std::time::{SystemTime, UNIX_EPOCH};

const PUBKY_AUTH_NAMESPACE: &[u8; 10] = b"PUBKY:AUTH";
const AUTH_TOKEN_VERSION: u8 = 0;

/// Capability string: read+write to the whole of the caller's own space.
/// Sufficient for cipherpost to PUT/GET under `/priv/cipherpost/…`.
pub const CAP_ROOT_RW: &str = "/:rw";

/// Encode an unsigned postcard varint (LEB128). Capability strings are short, but
/// the loop is correct for any `u64`.
fn postcard_varint(mut n: u64, out: &mut Vec<u8>) {
    loop {
        let mut byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            byte |= 0x80;
        }
        out.push(byte);
        if n == 0 {
            break;
        }
    }
}

/// Current unix time in microseconds (the pubky `AuthToken` timestamp unit).
pub fn now_micros() -> Result<u64, Error> {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| Error::Config(format!("system clock before unix epoch: {e}")))?;
    Ok(d.as_micros() as u64)
}

/// Build a signed pubky `AuthToken` (postcard wire bytes) ready to POST to the
/// homeserver's `/signup` or `/signin` endpoint.
pub fn build_auth_token(keypair: &Keypair, capabilities: &str, timestamp_micros: u64) -> Vec<u8> {
    // tail = namespace ++ version ++ timestamp_be ++ pubkey ++ caps
    let mut tail = Vec::with_capacity(10 + 1 + 8 + 32 + 1 + capabilities.len());
    tail.extend_from_slice(PUBKY_AUTH_NAMESPACE);
    tail.push(AUTH_TOKEN_VERSION);
    tail.extend_from_slice(&timestamp_micros.to_be_bytes());
    tail.extend_from_slice(keypair.public_key().as_bytes());
    postcard_varint(capabilities.len() as u64, &mut tail);
    tail.extend_from_slice(capabilities.as_bytes());

    // full = signature(64) ++ tail. pubky-common signs full[65..], which is
    // exactly tail[1..] (the tail begins at byte 64 of the full token).
    let signature = keypair.sign(&tail[1..]);

    let mut token = Vec::with_capacity(64 + tail.len());
    token.extend_from_slice(&signature.to_bytes());
    token.extend_from_slice(&tail);
    token
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Ground truth captured from pubky-common v0.9.1 `AuthToken::sign` for
    /// seed=[7;32], caps=`Capability::root()` ("/:rw"), timestamp=1782175001334521.
    /// Because ed25519 is deterministic, our hand-rolled encoder must reproduce
    /// these 120 bytes EXACTLY — signature included.
    const GOLDEN_SEED: [u8; 32] = [7u8; 32];
    const GOLDEN_TS: u64 = 1782175001334521;
    const GOLDEN_HEX: &str = "9f8cc81c8cb31d50ef469576d2ec088c09f29b6f40bee8702d1862a75b9c2b313b9377a6b6a38ecf4f4d8933e27f34a0c10af0eb672f793b7611e649592609045055424b593a4155544800000654e0f3e1d2f9ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c042f3a7277";

    #[test]
    fn golden_vector_matches_pubky_common_v0_9_1() {
        let kp = Keypair::from_secret_key(&GOLDEN_SEED);
        // sanity: same identity pubky-common derived from this seed
        assert_eq!(
            kp.public_key().to_z32(),
            "7jfgaa9nutjyixzikb7tgmsf9gkwq7iqz498zr1nd5ig1fng4esy"
        );
        let token = build_auth_token(&kp, CAP_ROOT_RW, GOLDEN_TS);
        let hex: String = token.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, GOLDEN_HEX, "AuthToken bytes must match pubky-common");
    }

    #[test]
    fn field_layout_offsets() {
        let kp = Keypair::from_secret_key(&GOLDEN_SEED);
        let t = build_auth_token(&kp, CAP_ROOT_RW, 1);
        assert_eq!(&t[64..74], b"PUBKY:AUTH");
        assert_eq!(t[74], 0);
        assert_eq!(&t[75..83], &1u64.to_be_bytes());
        assert_eq!(&t[83..115], kp.public_key().as_bytes());
        assert_eq!(&t[115..], &[0x04, b'/', b':', b'r', b'w']);
        assert_eq!(t.len(), 120);
    }

    #[test]
    fn varint_encoding() {
        let enc = |n| {
            let mut v = Vec::new();
            postcard_varint(n, &mut v);
            v
        };
        assert_eq!(enc(4), [0x04]);
        assert_eq!(enc(127), [0x7f]);
        assert_eq!(enc(128), [0x80, 0x01]);
        assert_eq!(enc(300), [0xac, 0x02]);
    }
}
