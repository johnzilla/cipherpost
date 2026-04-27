//! CLI-03: `cipherpost <subcommand> --help` prints an EXAMPLES section with at least
//! one worked example.

use assert_cmd::Command;

fn help_for(args: &[&str]) -> String {
    let mut cmd = Command::cargo_bin("cipherpost").unwrap();
    let out = cmd.args(args).arg("--help").output().unwrap();
    assert!(out.status.success(), "--help must exit 0 for args {args:?}");
    // Clap prints help to stdout.
    String::from_utf8_lossy(&out.stdout).to_string()
}

#[test]
fn send_help_has_examples_section() {
    let h = help_for(&["send"]);
    assert!(
        h.contains("EXAMPLES:"),
        "send --help missing EXAMPLES section:\n{h}"
    );
    assert!(
        h.contains("cipherpost send"),
        "send --help examples must show cipherpost send invocation"
    );
}

#[test]
fn receive_help_has_examples_section() {
    let h = help_for(&["receive"]);
    assert!(
        h.contains("EXAMPLES:"),
        "receive --help missing EXAMPLES section:\n{h}"
    );
    assert!(
        h.contains("cipherpost receive"),
        "receive --help examples must show cipherpost receive invocation"
    );
}

#[test]
fn receipts_help_has_examples_section() {
    let h = help_for(&["receipts"]);
    assert!(
        h.contains("EXAMPLES:"),
        "receipts --help missing EXAMPLES section:\n{h}"
    );
}

#[test]
fn version_help_has_examples_section() {
    let h = help_for(&["version"]);
    assert!(
        h.contains("EXAMPLES:"),
        "version --help missing EXAMPLES section:\n{h}"
    );
}

#[test]
fn identity_generate_help_has_examples_section() {
    let h = help_for(&["identity", "generate"]);
    assert!(
        h.contains("EXAMPLES:"),
        "identity generate --help missing EXAMPLES:\n{h}"
    );
}

#[test]
fn identity_show_help_has_examples_section() {
    let h = help_for(&["identity", "show"]);
    assert!(
        h.contains("EXAMPLES:"),
        "identity show --help missing EXAMPLES:\n{h}"
    );
}
