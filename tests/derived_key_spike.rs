//! Feasibility spike for `docs/design/derived-key-addressing.md` (§14).
//!
//! Both tests are `#[ignore]`'d — this is scratch/spike coverage that Phase 1/2
//! will reorganize (§10 promotes the signable-replication check to a non-ignored
//! R1 guard, and the derivation vectors into a committed `derive` module). They
//! are committed now so the "green spike" is reproducible and re-verifiable
//! (`cargo test --test derived_key_spike -- --ignored`) if `pkarr` or the
//! pre-release curve stack is ever bumped.
//!
//! `derived_key_publish_resolve_verify` pins BYTE-EXACT golden vectors (t, A',
//! derived z32) as hex literals — a property assertion (A + t·G == a'·G) alone
//! would not catch an upstream behavioral drift that produces different-but-
//! self-consistent derived keys. The hex literals do.
//!
//! Uses TEST-ONLY dev-deps (ed25519-dalek hazmat+digest, curve25519-dalek, bytes)
//! so the shipped binary stays hazmat-free until Phase 1.

use curve25519_dalek::{
    constants::ED25519_BASEPOINT_TABLE, edwards::CompressedEdwardsY, scalar::Scalar,
};
use ed25519_dalek::hazmat::{raw_sign, ExpandedSecretKey};
// ed25519-dalek re-exports its own Sha512 (sha2 0.11-rc) whose `digest` version
// raw_sign's CtxDigest bound requires — sha2 0.10 does NOT satisfy it. Gated
// behind the `digest` feature (enabled for tests via dev-deps).
use ed25519_dalek::Sha512 as HazmatSha512;
use ed25519_dalek::{SigningKey, VerifyingKey};
use pkarr::dns::{rdata::RData, rdata::TXT, Name, Packet, ResourceRecord, CLASS};
use pkarr::{PublicKey, SignedPacket};
use sha2::{Digest, Sha512};

const DOMAIN: &[u8] = b"cipherpost/v2/derive-addr";
const DOMAIN_PREFIX: &[u8] = b"cipherpost/v2/derive-prefix";

fn sha512_64(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&h.finalize());
    out
}

/// pkarr's private `signable(ts, v)` = b"3:seqi{ts}e1:v{len}:" ‖ v — replicated.
fn signable(ts: u64, v: &[u8]) -> Vec<u8> {
    let mut s = format!("3:seqi{}e1:v{}:", ts, v.len()).into_bytes();
    s.extend_from_slice(v);
    s
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

// NOTE: the signable-replication R1 guard was PROMOTED (design §10.2) to a
// non-ignored unit test — `src/transport.rs::derived_tests::
// signable_replication_matches_pkarr` — which tests the production
// `bep44_signable()`. It is intentionally not duplicated here.

/// End-to-end seam + BYTE-EXACT golden vectors for single-hop stealth derivation.
#[test]
#[ignore = "spike; run with --ignored"]
fn derived_key_publish_resolve_verify() {
    // 1. Master identity (fixed seed).
    let seed = [7u8; 32];
    let sk = SigningKey::from_bytes(&seed);
    let a_pub = sk.verifying_key();
    let master_esk = ExpandedSecretKey::from_bytes(&sha512_64(&[&seed]));
    let a = master_esk.scalar; // clamped master scalar
    assert_eq!(
        (ED25519_BASEPOINT_TABLE * &a).compress().to_bytes(),
        a_pub.to_bytes(),
        "master a·G must equal the verifying key",
    );

    // 2. Single-hop stealth derivation for a fixed share_ref.
    let share_ref = [0x11u8; 16];
    let t = Scalar::from_bytes_mod_order_wide(&sha512_64(&[DOMAIN, &a_pub.to_bytes(), &share_ref]));
    let a_prime = a + t;
    let a_prime_point = ED25519_BASEPOINT_TABLE * &a_prime;
    let a_prime_bytes = a_prime_point.compress().to_bytes();
    let a_prime_vk = VerifyingKey::from_bytes(&a_prime_bytes).expect("A' is a valid point");
    let derived_pk = PublicKey::from(a_prime_vk);
    let origin = derived_pk.to_z32();

    // 3. PUBLIC derivation (parent pubkey + share_ref, no secret) must agree.
    let a_pub_point = CompressedEdwardsY(a_pub.to_bytes())
        .decompress()
        .expect("decompress A");
    let pub_derived = (a_pub_point + ED25519_BASEPOINT_TABLE * &t)
        .compress()
        .to_bytes();
    assert_eq!(
        pub_derived, a_prime_bytes,
        "public derivation (A + t·G) must equal secret derivation (a'·G)",
    );

    // 4. BYTE-EXACT GOLDEN VECTORS (§10.1). seed=[7;32], share_ref=[0x11;16],
    //    DOMAIN="cipherpost/v2/derive-addr". A pre-release curve/hash drift that
    //    changes derivation — even to a different-but-self-consistent key — fails
    //    HERE, which the property assertions above alone would not catch.
    assert_eq!(
        hex(t.as_bytes()),
        "2185bc56ddef40eedb96c18599425a2177332575dbc836ace0227719230b9005",
        "golden vector drift: tweak scalar t",
    );
    assert_eq!(
        hex(&a_prime_bytes),
        "5af3abc0070698cedb92d1c16da7d2c1bdcbe9ea5bbfce9fba32d4d9d72155f5",
        "golden vector drift: derived public key A'",
    );
    assert_eq!(
        origin, "mm34zoy8y4cc7sh148ys5j61ag6hz4xkmq9h7874gmkpui3bkz4o",
        "golden vector drift: derived z32",
    );

    // 5. Derived signing nonce prefix from a SECRET (master prefix), unique per key.
    let mut prefix = [0u8; 32];
    prefix.copy_from_slice(&sha512_64(&[DOMAIN_PREFIX, &master_esk.hash_prefix, &share_ref])[..32]);
    let esk_derived = ExpandedSecretKey {
        scalar: a_prime,
        hash_prefix: prefix,
    };

    // 6. Build a one-TXT DNS packet at the DERIVED origin.
    let rec_name = format!("_cipherpost.{origin}");
    let mut packet = Packet::new_reply(0);
    let txt: TXT = "derived-key-share-payload".try_into().unwrap();
    packet.answers.push(ResourceRecord::new(
        Name::new(&rec_name).unwrap(),
        CLASS::IN,
        300,
        RData::TXT(txt),
    ));
    let v = packet.build_bytes_vec_compressed().unwrap();

    // 7. Hand-sign the BEP44 signable under the DERIVED scalar; self-verify
    //    (mandatory: ed25519-unsafe-libs footgun if A' != a'·G).
    let ts: u64 = 1_700_000_000_000_000;
    let s = signable(ts, &v);
    let sig = raw_sign::<HazmatSha512>(&esk_derived, &s, &a_prime_vk);
    a_prime_vk
        .verify_strict(&s, &sig)
        .expect("self-verify: signature must verify under A' = a'·G");

    // 8. Assemble via pkarr's PUBLIC from_relay_payload — which itself runs
    //    public_key.verify(signable, sig). Ok ⇒ pkarr accepts our derived packet.
    let mut payload = Vec::with_capacity(64 + 8 + v.len());
    payload.extend_from_slice(&sig.to_bytes());
    payload.extend_from_slice(&ts.to_be_bytes());
    payload.extend_from_slice(&v);
    let sp = SignedPacket::from_relay_payload(&derived_pk, &bytes::Bytes::from(payload))
        .expect("pkarr must accept + verify our hand-signed derived-key packet");

    // 9. Resolve back: public key is A', and the TXT is present.
    assert_eq!(sp.public_key().to_bytes(), a_prime_bytes);
    let got_txt = sp
        .all_resource_records()
        .filter_map(|rr| match &rr.rdata {
            RData::TXT(t) => Some(t.clone().try_into().unwrap_or_default()),
            _ => None,
        })
        .collect::<Vec<String>>();
    assert!(
        got_txt.iter().any(|x| x == "derived-key-share-payload"),
        "resolved packet must carry our TXT payload; got {got_txt:?}",
    );

    // 10. serialize→deserialize re-verifies the BEP44 signature under A'.
    let raw = sp.serialize();
    let sp2 = SignedPacket::deserialize(&raw).expect("deserialize re-verifies signature under A'");
    assert_eq!(sp2.public_key().to_bytes(), a_prime_bytes);

    eprintln!("t     = {}", hex(t.as_bytes()));
    eprintln!("A'    = {}", hex(&a_prime_bytes));
    eprintln!("z32   = {origin}");
    eprintln!("v     = {} bytes (budget 1000)", v.len());
}
