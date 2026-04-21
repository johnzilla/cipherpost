//! Pitfall #3: the exact bytes `jcs(OuterRecordSignable)` produces are the thing
//! Ed25519 signs. If those bytes ever change — field add/remove/rename, serde
//! attribute change, library update — every previously issued signature becomes
//! unverifiable. This test commits a fixture of those bytes and asserts equality.
//!
//! T-01-03-01 mitigation.

use cipherpost::record::OuterRecordSignable;
use std::fs;

const FIXTURE_PATH: &str = "tests/fixtures/outer_record_signable.bin";

fn fixture_signable() -> OuterRecordSignable {
    OuterRecordSignable {
        blob: "AAAA".into(),
        created_at: 1_700_000_000,
        protocol_version: 1,
        pubkey: "pk-placeholder-z32".into(),
        recipient: Some("rcpt-placeholder-z32".into()),
        share_ref: "0123456789abcdef0123456789abcdef".into(),
        ttl_seconds: 86400,
    }
}

#[test]
fn outer_record_signable_bytes_match_committed_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    let expected = fs::read(FIXTURE_PATH).expect(
        "Fixture file missing — run `cargo test -- --ignored regenerate_fixture` to create it",
    );
    assert_eq!(
        bytes, expected,
        "OuterRecordSignable JCS bytes changed — past signatures invalidated!"
    );
}

#[test]
#[ignore] // run with --ignored to regenerate; commit result
fn regenerate_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    std::fs::create_dir_all("tests/fixtures").unwrap();
    std::fs::write(FIXTURE_PATH, bytes).unwrap();
    println!("Fixture written to {}", FIXTURE_PATH);
}

fn serde_json_jcs<T: serde::Serialize>(v: &T) -> Vec<u8> {
    use serde_canonical_json::CanonicalFormatter;
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    v.serialize(&mut ser).unwrap();
    buf
}
