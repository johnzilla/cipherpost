//! CLI error-path coverage (NOT D-ACCEPT-03 TTY verification — see NOTE below).
//!
//! This test spawns `cipherpost receive` and exercises the pre-TtyPrompter
//! error branches in main.rs::dispatch:
//!   (a) no URI argument → Error::Config("share URI required") → exit 1
//!   (b) malformed URI  → Error::InvalidShareUri(_) → exit 1
//! In both cases the binary short-circuits in cli.rs / main.rs argument
//! handling BEFORE flow::run_receive is invoked, so the TtyPrompter TTY
//! check is never reached by this test.
//!
//! NOTE: the authoritative D-ACCEPT-03 assertion that TtyPrompter itself
//! returns
//!   Err(Error::Config("acceptance requires a TTY; non-interactive receive is deferred"))
//! when stdin/stderr are not TTYs and CIPHERPOST_SKIP_TTY_CHECK is unset is
//! done by a library-level unit test in `src/flow.rs` named
//! `tty_prompter_rejects_non_tty_env`. This integration test intentionally does
//! NOT duplicate that coverage; its value is asserting that the CLI exit-code
//! taxonomy (ROADMAP SC5) holds for the pre-TtyPrompter Config/URI-error paths
//! — exit 1 with a meaningful stderr message, not 3/4/5/6/7.

use assert_cmd::Command;
use predicates::prelude::*;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn receive_without_uri_exits_1_with_config_error() {
    let dir = TempDir::new().unwrap();

    // Generate an identity first so the passphrase path has something to unlock
    // if execution reaches it. (It should not — URI check fails first.)
    Command::cargo_bin("cipherpost")
        .unwrap()
        .env_remove("CIPHERPOST_HOME")
        .env_remove("CIPHERPOST_PASSPHRASE")
        .env("CIPHERPOST_HOME", dir.path())
        .env("CIPHERPOST_PASSPHRASE", "pass")
        .args(["identity", "generate"])
        .assert()
        .success();

    // No URI provided → Config error, exit 1
    Command::cargo_bin("cipherpost")
        .unwrap()
        .env_remove("CIPHERPOST_HOME")
        .env_remove("CIPHERPOST_PASSPHRASE")
        .env("CIPHERPOST_HOME", dir.path())
        .env("CIPHERPOST_PASSPHRASE", "pass")
        .args(["receive"])
        .assert()
        .failure()
        .code(1);
}

#[test]
#[serial]
fn receive_with_bad_uri_exits_1_with_invalid_share_uri() {
    let dir = TempDir::new().unwrap();

    Command::cargo_bin("cipherpost")
        .unwrap()
        .env_remove("CIPHERPOST_HOME")
        .env_remove("CIPHERPOST_PASSPHRASE")
        .env("CIPHERPOST_HOME", dir.path())
        .env("CIPHERPOST_PASSPHRASE", "pass")
        .args(["identity", "generate"])
        .assert()
        .success();

    Command::cargo_bin("cipherpost")
        .unwrap()
        .env_remove("CIPHERPOST_HOME")
        .env_remove("CIPHERPOST_PASSPHRASE")
        .env("CIPHERPOST_HOME", dir.path())
        .env("CIPHERPOST_PASSPHRASE", "pass")
        .args(["receive", "notaurl"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("invalid share URI"));
}
