//! PASS-07 / D-P5-08: exact one-newline strip rule (not greedy .trim()).
//! Six-case truth table from 05-CONTEXT.md — each case is a distinct Rust unit test.

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use tempfile::TempDir;

fn strip_case(input_bytes: &[u8]) -> String {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pw.txt");
    let mut f = fs::File::create(&path).unwrap();
    f.write_all(input_bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let pw = cipherpost::identity::resolve_passphrase(
        None,
        None, // disable env lookup so file-branch is taken deterministically
        Some(&path),
        None,
        false,
    )
    .unwrap();
    pw.expose().to_string()
}

#[test]
fn strip_crlf() {
    assert_eq!(strip_case(b"hunter2\r\n"), "hunter2");
}

#[test]
fn strip_lf() {
    assert_eq!(strip_case(b"hunter2\n"), "hunter2");
}

#[test]
fn strip_one_of_two_lf() {
    assert_eq!(strip_case(b"hunter2\n\n"), "hunter2\n");
}

#[test]
fn preserve_trailing_space() {
    assert_eq!(strip_case(b"hunter2 "), "hunter2 ");
}

#[test]
fn preserve_no_trailer() {
    assert_eq!(strip_case(b"hunter2"), "hunter2");
}

#[test]
fn preserve_bare_cr() {
    assert_eq!(strip_case(b"hunter2\r"), "hunter2\r");
}
