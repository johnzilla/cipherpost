//! Q4 tripwire: the three test-only escape-hatch env vars must never be honored
//! by a production build (no `mock` feature, no `cfg(test)`).
//!
//! Each is a deliberate test seam:
//!   - `CIPHERPOST_USE_MOCK_TRANSPORT` — swaps `DhtTransport` for the in-process
//!     `MockTransport` (main.rs, every subcommand that builds a transport).
//!   - `CIPHERPOST_TEST_PIN` — bypasses the interactive PIN prompt (pin.rs).
//!   - `CIPHERPOST_SKIP_TTY_CHECK` — bypasses the D-ACCEPT-03 TTY pre-check
//!     (flow.rs).
//!
//! Every compiled read of them lives behind a cfg gate that excludes production:
//! `#[cfg(any(test, feature = "mock"))]` for the pin/tty seams, `#[cfg(feature =
//! "mock")]` for the transport switch, or an enclosing `#[cfg(test)] mod tests`
//! for the unit-test scaffolding that saves/restores the var. A build that is
//! neither `test` nor `mock` therefore never compiles the read at all: the env
//! var is silently ignored and the hardened path (real DHT / TTY-required PIN /
//! TTY-required acceptance) always wins.
//!
//! The risk this guards is a *silent cfg regression* — someone ungating one of
//! these reads (or moving it out from under the test/mock gate) so the escape
//! hatch goes live in release binaries. That is an invisible security downgrade:
//! `cargo build --release` would suddenly honor `CIPHERPOST_SKIP_TTY_CHECK` &c.
//!
//! Why a source-structure assertion rather than "build --no-default-features and
//! grep the binary": CI's only test pass is `cargo nextest run --all-features`
//! (mock ON), so a test gated `#[cfg(not(feature = "mock"))]` would never run in
//! CI, and an `--all-features` binary legitimately contains these strings. This
//! test is feature-independent — it reads `src/` and asserts the cfg gate that
//! *makes* a no-mock build ignore the vars is present — so it runs and bites
//! under `--all-features` all the same. Mirrors the repo's existing
//! enumeration-test idiom (hkdf_info_enumeration, debug_leak_scan).

use std::path::{Path, PathBuf};

/// The escape-hatch env vars. Every compiled read of each MUST sit inside a
/// scope gated by `test` or `feature = "mock"`.
const TRIPWIRE_VARS: &[&str] = &[
    "CIPHERPOST_USE_MOCK_TRANSPORT",
    "CIPHERPOST_TEST_PIN",
    "CIPHERPOST_SKIP_TTY_CHECK",
];

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// All `.rs` files under `src/`, recursively.
fn rust_sources(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir src/") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rust_sources(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Strip line/block comments from `line`, tracking `/* ... */` across lines via
/// `in_block`. Returns two views of the comment-free code:
///   - `code`: string/char literals kept verbatim — used to detect a real
///     `env::var("X")` read (a commented-out read is already gone).
///   - `braces`: string/char literal *contents* blanked — used for `{` / `}`
///     counting so a brace inside a string literal never skews block structure.
fn sanitize(line: &str, in_block: &mut bool) -> (String, String) {
    let bytes = line.as_bytes();
    let mut code = String::with_capacity(line.len());
    let mut braces = String::with_capacity(line.len());
    let mut i = 0;
    let mut in_str = false;
    let mut in_char = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        let next = bytes.get(i + 1).map(|b| *b as char);
        if *in_block {
            if c == '*' && next == Some('/') {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
            continue;
        }
        if in_str {
            code.push(c);
            if c == '\\' {
                // keep the escaped char in `code`, drop from `braces`
                if let Some(n) = next {
                    code.push(n);
                }
                i += 2;
            } else {
                if c == '"' {
                    in_str = false;
                    braces.push('"');
                }
                i += 1;
            }
            continue;
        }
        if in_char {
            code.push(c);
            if c == '\\' {
                if let Some(n) = next {
                    code.push(n);
                }
                i += 2;
            } else {
                if c == '\'' {
                    in_char = false;
                    braces.push('\'');
                }
                i += 1;
            }
            continue;
        }
        // not in any literal/comment
        if c == '/' && next == Some('/') {
            break; // rest of line is a comment
        }
        if c == '/' && next == Some('*') {
            *in_block = true;
            i += 2;
            continue;
        }
        if c == '"' {
            in_str = true;
            code.push('"');
            braces.push('"');
            i += 1;
            continue;
        }
        if c == '\'' {
            in_char = true;
            code.push('\'');
            braces.push('\'');
            i += 1;
            continue;
        }
        code.push(c);
        braces.push(c);
        i += 1;
    }
    (code, braces)
}

/// Does `cfg_line` name a gate that excludes production, i.e. mentions `test` or
/// `feature = "mock"`? (Both `cfg(test)` and `cfg(any(test, feature = "mock"))`
/// and `cfg(feature = "mock")` qualify.)
fn is_prod_excluding_cfg(cfg_line: &str) -> bool {
    cfg_line.contains("test") || cfg_line.contains("feature = \"mock\"")
}

/// True if `raw_line` is a compiled read of `env::var`/`env::var_os` for `var`
/// (comments already stripped in `sanitized`, but we match on the sanitized form
/// so a commented-out read never counts).
fn reads_var(sanitized: &str, var: &str) -> bool {
    let Some(call_at) = sanitized.find("env::var") else {
        return false;
    };
    sanitized[call_at..].contains(&format!("\"{var}\""))
}

#[test]
fn escape_hatch_env_vars_are_prod_excluded() {
    let mut files = Vec::new();
    rust_sources(&src_dir(), &mut files);
    assert!(!files.is_empty(), "found no .rs files under src/");

    // var -> number of compiled reads found, so a rename that makes the scan
    // vacuous is caught rather than silently passing.
    let mut read_counts: Vec<(&str, usize)> = TRIPWIRE_VARS.iter().map(|v| (*v, 0usize)).collect();

    for file in &files {
        let text = std::fs::read_to_string(file)
            .unwrap_or_else(|e| panic!("read {}: {e}", file.display()));

        // Walk the file tracking a stack of open braces, each tagged with whether
        // it (or any enclosing scope) is gated by a production-excluding cfg.
        // `pending_gate` accumulates cfg attribute(s) awaiting the scope/item they
        // apply to.
        let mut scope_gated: Vec<bool> = Vec::new();
        let mut pending_gate = false;
        let mut in_block_comment = false;

        for (idx, raw) in text.lines().enumerate() {
            let trimmed = raw.trim_start();
            let (code, braces) = sanitize(raw, &mut in_block_comment);

            // Accumulate cfg attributes; they attach to the next block/item.
            if trimmed.starts_with("#[cfg(") {
                if is_prod_excluding_cfg(raw) {
                    pending_gate = true;
                }
                continue;
            }

            let enclosing_gated = scope_gated.iter().any(|g| *g);

            // Check reads BEFORE mutating brace state: the read token sits inside
            // the scopes already open on entry to this line. A `pending_gate` set
            // by an attribute on the immediately preceding line(s) also protects a
            // read on this line (statement-attribute form).
            for (var, count) in read_counts.iter_mut() {
                if !reads_var(&code, var) {
                    continue;
                }
                *count += 1;
                assert!(
                    enclosing_gated || pending_gate,
                    "{}:{}: read of `{var}` is NOT inside a `test` / `feature = \"mock\"` cfg \
                     scope — the test-only escape hatch has escaped into code that ships in \
                     production (no-mock, non-test) builds, a silent security regression. Guard \
                     it with `#[cfg(any(test, feature = \"mock\"))]` (or `#[cfg(feature = \
                     \"mock\")]`), or keep it inside a `#[cfg(test)]` module.\n  {}",
                    file.display(),
                    idx + 1,
                    trimmed,
                );
            }

            // Update brace stack from this line's (literal-blanked) braces.
            let mut consumed_pending = false;
            for ch in braces.chars() {
                match ch {
                    '{' => {
                        let inherited = scope_gated.last().copied().unwrap_or(false);
                        let own = pending_gate;
                        pending_gate = false;
                        consumed_pending = true;
                        scope_gated.push(inherited || own);
                    }
                    '}' => {
                        scope_gated.pop();
                    }
                    _ => {}
                }
            }
            // An attribute that attached to a non-block item (no `{` opened on the
            // line it applies to) is spent; don't leak it onto a later scope.
            if !consumed_pending && !braces.trim().is_empty() {
                pending_gate = false;
            }
        }
    }

    for (var, count) in &read_counts {
        assert!(
            *count > 0,
            "no compiled read of `{var}` found anywhere in src/. If this seam was intentionally \
             removed, drop it from TRIPWIRE_VARS; otherwise the env-var name drifted and this \
             tripwire has gone vacuous.",
        );
    }
}
