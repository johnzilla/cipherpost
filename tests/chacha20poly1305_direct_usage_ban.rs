//! Assert no source file in src/ directly imports chacha20poly1305 or aes_gcm.
//!
//! age uses these internally; cipherpost must only touch them via age's API.
//! Direct AEAD imports risk nonce misuse — age's API handles nonce safety.
//!
//! Pitfall #9 / CRYPTO-05.
//! See also deny.toml which bans the direct crate dep (Plan 01).

use std::fs;
use std::path::Path;

#[test]
fn no_direct_aead_imports() {
    let mut violations = Vec::new();
    walk(Path::new("src"), &mut violations);
    assert!(
        violations.is_empty(),
        "direct AEAD imports found (must go through age API): {:?}",
        violations
    );
}

fn walk(dir: &Path, out: &mut Vec<(String, usize)>) {
    let entries = fs::read_dir(dir).expect("failed to read src/");
    for entry in entries {
        let e = entry.unwrap();
        let p = e.path();
        if p.is_dir() {
            walk(&p, out);
            continue;
        }
        if p.extension().and_then(|x| x.to_str()) != Some("rs") {
            continue;
        }
        let src = fs::read_to_string(&p).unwrap();
        for (i, line) in src.lines().enumerate() {
            let t = line.trim_start();
            if t.starts_with("use chacha20poly1305")
                || t.starts_with("use aes_gcm")
                || t.starts_with("extern crate chacha20poly1305")
                || t.starts_with("extern crate aes_gcm")
            {
                out.push((p.display().to_string(), i + 1));
            }
        }
    }
}
