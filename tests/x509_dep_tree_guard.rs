//! Phase 6 Plan 04: CI-visible guard that `ring` and `aws-lc` do NOT appear in
//! the cargo dependency tree. Prevents an accidental feature flag addition
//! (e.g., `x509-parser` `verify` feature, or an `age` feature that pulls ring)
//! from sneaking through review.
//!
//! Runs `cargo tree` as a subprocess. If the test env has no network or
//! offline mode, the first build after clone may be slow; subsequent runs
//! use the committed Cargo.lock.

use std::process::Command;

fn cargo_tree_text() -> String {
    let out = Command::new("cargo")
        .arg("tree")
        .output()
        .expect("cargo tree must run in test environment");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).expect("cargo tree output is UTF-8")
}

#[test]
fn dep_tree_contains_no_ring() {
    let tree = cargo_tree_text();
    // Match `ring v...` on a line (standard `cargo tree` output format).
    // Accept `fake-ring` / `ring-algorithms` etc. — we only reject the exact
    // `ring` crate.
    for line in tree.lines() {
        let stripped = line.trim_start_matches(['├', '└', '─', '│', ' ']);
        assert!(
            !stripped.starts_with("ring v"),
            "FORBIDDEN: `ring` crate present in dep tree — X509-parser's `verify` feature or another dep leaked it.\nFull tree:\n{}",
            tree
        );
    }
}

#[test]
fn dep_tree_contains_no_aws_lc() {
    let tree = cargo_tree_text();
    for line in tree.lines() {
        let stripped = line.trim_start_matches(['├', '└', '─', '│', ' ']);
        assert!(
            !stripped.starts_with("aws-lc v")
                && !stripped.starts_with("aws-lc-sys v")
                && !stripped.starts_with("aws-lc-rs v"),
            "FORBIDDEN: `aws-lc` family crate present in dep tree.\nFull tree:\n{}",
            tree
        );
    }
}

#[test]
fn dep_tree_contains_x509_parser_0_16_x() {
    let out = Command::new("cargo")
        .arg("tree")
        .arg("-p")
        .arg("x509-parser")
        .output()
        .expect("cargo tree -p x509-parser must run");
    assert!(
        out.status.success(),
        "cargo tree -p x509-parser failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("UTF-8");
    // First line is something like "x509-parser v0.16.0".
    let first_line = stdout.lines().next().expect("cargo tree output non-empty");
    assert!(
        first_line.starts_with("x509-parser v0.16."),
        "Expected x509-parser v0.16.x (not 0.17, not 0.18), got: {:?}",
        first_line
    );
}

// Phase 7 Plan 04: pgp crate version pin assertion.
// Asserts the locked exact-pin from D-P7-04 (Cargo.toml: `pgp = "=0.19.0"`).
// If `cargo update -p pgp` accidentally bumps the major/minor, this fails first.
#[test]
fn dep_tree_contains_pgp_0_19_x() {
    let out = Command::new("cargo")
        .arg("tree")
        .arg("-p")
        .arg("pgp")
        .output()
        .expect("cargo tree -p pgp must run");
    assert!(
        out.status.success(),
        "cargo tree -p pgp failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("UTF-8");
    let first_line = stdout
        .lines()
        .next()
        .expect("non-empty cargo tree output");
    assert!(
        first_line.starts_with("pgp v0.19."),
        "Expected pgp v0.19.x (not 0.18, not 0.20), got: {:?}",
        first_line
    );
}

// Phase 7 Plan 04: assert ed25519-dalek coexistence is the DOCUMENTED shape
// (2.x from pgp 0.19.0 + 3.0.0-pre.5 from pkarr). If a third version appears,
// SOMETHING upstream changed — fail loudly so we re-run research.
//
// Note: Plan 01 SUMMARY documented that pgp 0.19.0 actually pulls 2.2.0 (not
// 2.1.1 as research GAP predicted). The assertion below checks `v2.` prefix
// rather than a specific patch level — version-class invariance per D-P7-22.
#[test]
fn dep_tree_ed25519_dalek_coexistence_shape() {
    let out = Command::new("cargo")
        .arg("tree")
        .output()
        .expect("cargo tree must run");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).expect("UTF-8");

    let mut versions = std::collections::HashSet::new();
    for line in stdout.lines() {
        if let Some(start) = line.find("ed25519-dalek v") {
            let rest = &line[start + "ed25519-dalek v".len()..];
            let end = rest
                .find(|c: char| c == ' ' || c == '\n' || c == '(')
                .unwrap_or(rest.len());
            versions.insert(rest[..end].to_string());
        }
    }

    let has_2x = versions.iter().any(|v| v.starts_with("2."));
    let has_3_0_0_pre5 = versions.iter().any(|v| v == "3.0.0-pre.5");

    assert!(
        has_2x,
        "ed25519-dalek 2.x (from pgp 0.19.0 transitive) must be present, got versions: {:?}",
        versions
    );
    assert!(
        has_3_0_0_pre5,
        "ed25519-dalek =3.0.0-pre.5 (from pkarr) must be present, got versions: {:?}",
        versions
    );
    assert!(
        versions.len() <= 2,
        "Expected ≤2 distinct ed25519-dalek versions (2.x + 3.0.0-pre.5), got {}: {:?}",
        versions.len(),
        versions
    );
}
