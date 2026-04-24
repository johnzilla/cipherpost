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
