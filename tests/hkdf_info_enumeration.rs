//! Enumerate every HKDF info string in src/ and assert:
//!   - each is prefixed "cipherpost/v1/"
//!   - all are distinct
//!   - all are non-empty
//!
//! INVARIANT: every `Hkdf::<Sha256>::new` / `hk.expand(info, ...)` call in this
//! crate MUST pass its info argument as a reference to a constant in the
//! `cipherpost::crypto::hkdf_infos` module. That module lives in `src/crypto.rs`
//! and is grep-visible. Passing a non-literal info string (e.g., `format!(...)`
//! result or a runtime-computed value) would bypass this test.
//!
//! If Phase 2 or Phase 3 needs runtime-derived info strings, upgrade this test to
//! use `syn`-based AST walking (tracked as Phase-2+ todo, NOT a blocker for Phase 1).
//!
//! Pitfall #4 / CRYPTO-03.

use std::fs;
use std::path::Path;

#[test]
fn all_hkdf_info_strings_are_versioned_and_distinct() {
    let mut infos: Vec<String> = Vec::new();
    walk(Path::new("src"), &mut infos);
    assert!(
        !infos.is_empty(),
        "expected at least one HKDF info string in src/"
    );
    for info in &infos {
        assert!(!info.is_empty(), "empty HKDF info string found");
        assert!(
            info.starts_with("cipherpost/v1/"),
            "HKDF info {info:?} does not start with cipherpost/v1/"
        );
    }
    let mut sorted = infos.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        infos.len(),
        "duplicate HKDF info strings found: {infos:?}"
    );
}

/// Walk all .rs files under `dir`, collect any string literal starting with
/// "cipherpost/v1/". These are all the HKDF info strings in the codebase.
fn walk(dir: &Path, out: &mut Vec<String>) {
    let entries = fs::read_dir(dir).expect("failed to read src/");
    for entry in entries {
        let entry = entry.unwrap();
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
            continue;
        }
        if path.extension().and_then(|e| e.to_str()) != Some("rs") {
            continue;
        }
        let src = fs::read_to_string(&path).unwrap();
        // Find every string literal matching "cipherpost/v1/<context>" in the source.
        // We split on '"' and take every other token (odd-indexed = inside quotes).
        // We require the context part (after the final "/") to be non-empty, so the
        // HKDF_INFO_PREFIX constant ("cipherpost/v1/") is excluded — it's the
        // namespace prefix, not an info string itself.
        for cap in src.split('"').skip(1).step_by(2) {
            if cap.starts_with("cipherpost/v1/") && cap.len() > "cipherpost/v1/".len() {
                out.push(cap.to_string());
            }
        }
    }
}
