//! DOC-02 / Pitfall #33: DHT label strings are wire-protocol constants.
//! Renaming either requires a protocol_version bump. This test is the
//! "confirm, don't change" audit — it byte-matches code constants against
//! the values documented in SPEC.md §3.5 DHT Label Stability.

use cipherpost::{DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX};

#[test]
fn dht_label_outer_is_cipherpost_literal() {
    assert_eq!(
        DHT_LABEL_OUTER, "_cipherpost",
        "SPEC.md §3.5 locks this label; renaming requires a protocol_version bump"
    );
}

#[test]
fn dht_label_receipt_prefix_is_cprcpt_literal() {
    assert_eq!(
        DHT_LABEL_RECEIPT_PREFIX, "_cprcpt-",
        "SPEC.md §3.5 locks this label; renaming requires a protocol_version bump"
    );
}
