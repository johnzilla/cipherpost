//! Phase 3 — JCS byte fixture for `ReceiptSignable`. Mirrors
//! tests/outer_record_canonical_form.rs line-for-line.
//!
//! The fixture is a committed binary snapshot of the JCS-serialized bytes for
//! a deterministic ReceiptSignable. A CI failure here means the canonical form
//! changed — past signatures become unverifiable. If the fixture genuinely
//! needs to be regenerated, run:
//!     cargo test --test phase3_receipt_canonical_form -- --ignored regenerate_fixture

use cipherpost::receipt::ReceiptSignable;
use serde::Serialize;
use serde_canonical_json::CanonicalFormatter;
use std::fs;

const FIXTURE_PATH: &str = "tests/fixtures/receipt_signable.bin";

fn fixture_signable() -> ReceiptSignable {
    ReceiptSignable {
        accepted_at: 1_700_000_000,
        ciphertext_hash: "a".repeat(64),
        cleartext_hash: "b".repeat(64),
        nonce: "0123456789abcdef0123456789abcdef".to_string(),
        protocol_version: 1,
        purpose: "canonical form fixture".to_string(),
        recipient_pubkey: "rcpt-placeholder-z32".to_string(),
        sender_pubkey: "sender-placeholder-z32".to_string(),
        share_ref: "0123456789abcdef0123456789abcdef".to_string(),
    }
}

fn serde_json_jcs<T: Serialize>(v: &T) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut ser = serde_json::Serializer::with_formatter(&mut buf, CanonicalFormatter::new());
    v.serialize(&mut ser).expect("JCS serialize");
    buf
}

#[test]
fn receipt_signable_bytes_match_committed_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    let expected = fs::read(FIXTURE_PATH).unwrap_or_else(|_| {
        panic!(
            "Fixture file missing at {FIXTURE_PATH}. Run:\n  cargo test --test phase3_receipt_canonical_form -- --ignored regenerate_fixture\nto create it, then commit the result."
        )
    });
    assert_eq!(
        bytes, expected,
        "Receipt JCS bytes changed — past receipt signatures would no longer verify! If the schema change is intentional, regenerate the fixture and bump PROTOCOL_VERSION."
    );
}

#[test]
#[ignore]
fn regenerate_fixture() {
    let bytes = serde_json_jcs(&fixture_signable());
    std::fs::create_dir_all("tests/fixtures").expect("create_dir_all");
    std::fs::write(FIXTURE_PATH, &bytes).expect("write fixture");
    eprintln!("wrote {} bytes to {}", bytes.len(), FIXTURE_PATH);
}
