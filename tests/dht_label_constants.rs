//! DOC-02 / Pitfall #33: DHT label strings are wire-protocol constants.
//! Renaming either requires a protocol_version bump. This test is the
//! "confirm, don't change" audit — it byte-matches code constants against
//! the values documented in SPEC.md §3.5 DHT Label Stability.

use cipherpost::{DHT_LABEL_OUTER, DHT_LABEL_RECEIPT, DHT_LABEL_RECEIPT_PREFIX};

#[test]
fn dht_label_outer_is_cipherpost_literal() {
    assert_eq!(
        DHT_LABEL_OUTER, "_cipherpost",
        "SPEC.md §3.5 locks this label; renaming requires a protocol_version bump"
    );
}

#[test]
fn dht_label_receipt_v2_is_cprcpt_literal() {
    // v2 derived-key addressing: the receipt label is the fixed "_cprcpt" (the
    // derived KEY encodes the share_ref, so no suffix). SPEC.md §3.5.
    assert_eq!(
        DHT_LABEL_RECEIPT, "_cprcpt",
        "SPEC.md §3.5 locks the v2 receipt label; renaming requires a protocol_version bump"
    );
}

#[test]
fn dht_label_receipt_prefix_v1_legacy_is_cprcpt_dash_literal() {
    // v1.1 legacy label (retained for reference; the v2 flow uses DHT_LABEL_RECEIPT).
    assert_eq!(
        DHT_LABEL_RECEIPT_PREFIX, "_cprcpt-",
        "SPEC.md §3.5 documents this as the v1.1 legacy label"
    );
}
