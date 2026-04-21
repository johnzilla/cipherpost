//! CLI-04: `cipherpost version` prints crate version, a 12-char lowercase-hex git SHA
//! (NOT the fallback "unknown"), and a crypto primitives line.

use assert_cmd::Command;

#[test]
fn version_prints_real_git_sha() {
    let mut cmd = Command::cargo_bin("cipherpost").unwrap();
    let output = cmd.arg("version").output().unwrap();
    assert!(output.status.success(), "version command must exit 0");
    let stdout = String::from_utf8_lossy(&output.stdout);

    // First line: cipherpost X.Y.Z (<12-char-sha>)
    let first_line = stdout.lines().next().expect("stdout has lines");
    let paren_open = first_line.find('(').expect("first line must contain '('");
    let paren_close = first_line.find(')').expect("first line must contain ')'");
    let sha = &first_line[paren_open + 1..paren_close];
    assert_eq!(
        sha.len(),
        12,
        "git sha must be 12 chars, got {:?}: full line={:?}",
        sha,
        first_line
    );
    assert!(
        sha.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()),
        "git sha must be lowercase hex, got {:?}",
        sha
    );
    assert!(
        !first_line.contains("(unknown)"),
        "build.rs fallback 'unknown' in version output: {:?}",
        first_line
    );

    // Second line: crypto primitives list (CLI-04 content).
    let second_line = stdout.lines().nth(1).expect("stdout has second line");
    for needle in &["age", "Ed25519", "Argon2id", "HKDF-SHA256", "JCS"] {
        assert!(
            second_line.contains(needle),
            "crypto primitives line missing {:?}: {:?}",
            needle,
            second_line
        );
    }
}
