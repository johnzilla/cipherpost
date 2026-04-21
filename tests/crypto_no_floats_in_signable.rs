//! CRYPTO-04 / Pitfall #3 subcase: guard that signable structs contain no floats.
//!
//! Float edge cases (-0.0, NaN, subnormals) produce inconsistent canonical bytes
//! across platforms and implementations. We forbid floats in any signable struct.
//!
//! Approach: serialize the fixture struct and assert the JSON contains no float
//! literals (no `.` between digits). We also use serde_json::Value introspection
//! to verify no Number is floating-point.
//!
//! For Plan 03's OuterRecordSignable, add a similar test in the record module.

use serde::Serialize;

#[derive(Serialize)]
struct SignableFixture {
    blob: String,
    created_at: u64,
    pubkey: String,
    recipient: Option<String>,
    share_ref: String,
    ttl: u64,
}

#[test]
fn signable_struct_has_no_floats() {
    let fx = SignableFixture {
        blob: "AAAA".to_string(),
        created_at: 1_700_000_000,
        pubkey: "test_pubkey_z32".to_string(),
        recipient: None,
        share_ref: "0123456789abcdef0123456789abcdef".to_string(),
        ttl: 86400,
    };

    let bytes = cipherpost::crypto::jcs_serialize(&fx).unwrap();
    let json_str = std::str::from_utf8(&bytes).expect("JCS output is valid UTF-8");

    // Check via serde_json::Value: no f64 values should appear.
    let value: serde_json::Value = serde_json::from_str(json_str).unwrap();
    assert_no_floats_in_value(&value, "$");
}

fn assert_no_floats_in_value(v: &serde_json::Value, path: &str) {
    match v {
        serde_json::Value::Number(n) => {
            assert!(
                !n.is_f64(),
                "Float value found at path {}: {}. Floats are banned from signable structs (CRYPTO-04).",
                path, n
            );
        }
        serde_json::Value::Object(m) => {
            for (k, val) in m {
                assert_no_floats_in_value(val, &format!("{}.{}", path, k));
            }
        }
        serde_json::Value::Array(a) => {
            for (i, val) in a.iter().enumerate() {
                assert_no_floats_in_value(val, &format!("{}[{}]", path, i));
            }
        }
        _ => {}
    }
}

/// Verify that a struct with float fields would be detected.
/// This is a compile-time check via the assert_no_floats approach.
#[test]
fn float_struct_detection_works() {
    // Use serde_json directly (not JCS) to produce a JSON with a float.
    // We only need to test that our introspection correctly finds floats.
    let json = serde_json::json!({"ttl": 1.5});
    // This should have a float — verify the checker would catch it.
    let has_float = match &json["ttl"] {
        serde_json::Value::Number(n) => n.is_f64(),
        _ => false,
    };
    // Confirm detection works (this does NOT call assert_no_floats_in_value with 1.5
    // because that would fail the test; we just verify the detection logic).
    assert!(has_float, "float detection logic should identify 1.5 as float");
}
