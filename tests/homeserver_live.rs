//! Live HomeserverBlobStore round-trip against a real pubky homeserver.
//!
//! Manual-only (like `real_dht_e2e`): `#[ignore]` so CI never runs it. Exercises
//! the full authenticated write path — signup (fresh random identity) → PUT
//! `/priv/cipherpost/…` → GET → byte-equality.
//!
//! Run:
//!   CIPHERPOST_HS=https://hs.trustedgelabs.com \
//!     cargo test --features large-payload --test homeserver_live -- --ignored --nocapture

use cipherpost::blobstore::{BlobStore, HomeserverBlobStore};

fn homeserver_url() -> String {
    std::env::var("CIPHERPOST_HS").unwrap_or_else(|_| "https://hs.trustedgelabs.com".to_string())
}

#[test]
#[ignore = "live homeserver round-trip; run manually with --ignored"]
fn live_signup_put_get_round_trip() {
    let keypair = pkarr::Keypair::random();
    let store = HomeserverBlobStore::new(homeserver_url(), keypair);

    let payload = b"cipherpost large-payload live test ciphertext";
    // v0.9.1 only permits writes under /pub/ (see authz.rs); /priv/ writes 403.
    let path = "pub/cipherpost/live-roundtrip-test";

    let location = store.put(path, payload).expect("PUT should succeed");
    eprintln!("stored at: {location}");

    let fetched = store.get(&location).expect("GET should succeed");
    assert_eq!(fetched, payload, "round-tripped bytes must match");
}
