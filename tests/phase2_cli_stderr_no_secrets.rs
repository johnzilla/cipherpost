//! CLI-05 / ROADMAP SC5: fuzz bad inputs and assert stderr contains no secret bytes,
//! passphrase bytes, or raw payload bytes. Also no source-chain leak tags like
//! `age::`, `pkarr::`, or `Os {` (D-15).

use assert_cmd::Command;
use serial_test::serial;
use tempfile::TempDir;

fn stderr_of(args: &[&str], env: &[(&str, &str)]) -> String {
    let mut cmd = Command::cargo_bin("cipherpost").unwrap();
    cmd.args(args);
    // Clear inherited CIPHERPOST_* env so the parent test harness does not
    // influence the child's resolution paths.
    cmd.env_remove("CIPHERPOST_HOME");
    cmd.env_remove("CIPHERPOST_PASSPHRASE");
    cmd.env_remove("CIPHERPOST_SKIP_TTY_CHECK");
    cmd.env_remove("CIPHERPOST_USE_MOCK_TRANSPORT");
    for (k, v) in env {
        cmd.env(k, v);
    }
    let out = cmd.output().unwrap();
    String::from_utf8_lossy(&out.stderr).to_string()
}

fn assert_no_source_chain(stderr: &str, context: &str) {
    for tag in &["age::", "pkarr::", "Os {"] {
        assert!(
            !stderr.contains(tag),
            "[{}] source-chain leak: stderr contains {:?}\nstderr:\n{}",
            context,
            tag,
            stderr
        );
    }
}

#[test]
#[serial]
fn invalid_uri_input_no_secret_in_stderr() {
    let dir = TempDir::new().unwrap();
    let stderr = stderr_of(
        &["receive", "not-a-valid-uri"],
        &[
            ("CIPHERPOST_HOME", dir.path().to_str().unwrap()),
            ("CIPHERPOST_PASSPHRASE", "super-secret-passphrase-XYZ-123"),
        ],
    );
    assert!(
        !stderr.contains("super-secret-passphrase-XYZ-123"),
        "passphrase leaked: {}",
        stderr
    );
    assert_no_source_chain(&stderr, "invalid_uri");
}

#[test]
#[serial]
fn wrong_passphrase_no_secret_in_stderr() {
    let dir = TempDir::new().unwrap();
    // Generate identity with one passphrase
    let mut cmd = Command::cargo_bin("cipherpost").unwrap();
    cmd.env_remove("CIPHERPOST_HOME");
    cmd.env_remove("CIPHERPOST_PASSPHRASE");
    cmd.env("CIPHERPOST_HOME", dir.path())
        .env("CIPHERPOST_PASSPHRASE", "correct-passphrase-ABCDEFGH")
        .args(["identity", "generate"])
        .assert()
        .success();

    // Try to use a subcommand with the WRONG passphrase. `identity show` loads
    // the identity. Expected: exit 4 (DecryptFailed).
    let stderr = stderr_of(
        &["identity", "show"],
        &[
            ("CIPHERPOST_HOME", dir.path().to_str().unwrap()),
            ("CIPHERPOST_PASSPHRASE", "wrong-passphrase-ZZZZ"),
        ],
    );
    assert!(
        !stderr.contains("correct-passphrase-ABCDEFGH"),
        "correct passphrase leaked: {}",
        stderr
    );
    assert!(
        !stderr.contains("wrong-passphrase-ZZZZ"),
        "wrong passphrase leaked: {}",
        stderr
    );
    assert_no_source_chain(&stderr, "wrong_passphrase");
}

#[test]
#[serial]
fn bare_z32_as_uri_no_source_chain() {
    let dir = TempDir::new().unwrap();
    // 52-char z-base-32 — D-URI-03 rejects bare z32, expects cipherpost:// URI.
    let stderr = stderr_of(
        &[
            "receive",
            "yhigci4xwmadibrmj8wzmf45f3i8xg8mht9abnprq3r5cfxihj8y",
        ],
        &[
            ("CIPHERPOST_HOME", dir.path().to_str().unwrap()),
            ("CIPHERPOST_PASSPHRASE", "pass"),
        ],
    );
    // Should be rejected (InvalidShareUri → exit 1) before any passphrase use
    assert!(
        stderr.contains("cipherpost://") || stderr.contains("bare pubkey"),
        "expected URI-hint error, got: {}",
        stderr
    );
    assert_no_source_chain(&stderr, "bare_z32_as_uri");
}
