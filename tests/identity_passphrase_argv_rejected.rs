//! IDENT-04 / Pitfall #14: --passphrase <value> (inline argv) must be rejected at runtime.
//!
//! The `--passphrase` flag is declared in src/cli.rs with `hide = true` so it
//! doesn't appear in `--help`. It exists only so the runtime can detect and reject it
//! with exit code 4 and an error containing "inline argv".
//!
//! Uses assert_cmd + predicates (declared in Cargo.toml [dev-dependencies] by Plan 01).

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn argv_passphrase_rejected() {
    let mut cmd = Command::cargo_bin("cipherpost").unwrap();
    cmd.args(["identity", "generate", "--passphrase", "hunter2"])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("inline argv"));
}

#[test]
fn argv_passphrase_rejected_on_show_too() {
    let mut cmd = Command::cargo_bin("cipherpost").unwrap();
    cmd.args(["identity", "show", "--passphrase", "hunter2"])
        .assert()
        .failure()
        .code(4)
        .stderr(predicate::str::contains("inline argv"));
}
