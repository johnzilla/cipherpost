# Phase 5: Non-Interactive Automation E2E — Pattern Map

**Mapped:** 2026-04-23
**Files analyzed:** 11 (4 source modified, 4 docs modified, 4 tests new)
**Analogs found:** 11 / 11

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `src/identity.rs` (MOD) | utility (passphrase helper) | file-I/O + fd-I/O (sync) | self — `resolve_passphrase` existing impl lines 258-320 | exact (rewrite in place) |
| `src/cli.rs` (MOD) | config (clap surface) | request-response (argv parse) | `IdentityCmd::Generate` lines 110-122 | exact |
| `src/main.rs` (MOD) | controller (dispatcher) | request-response | `IdentityCmd::Generate` dispatch lines 37-58 | exact |
| `src/transport.rs` (MOD) | config (label constants) — optional unit test home | N/A | inline `#[cfg(test)] mod tests` (target location) | N/A |
| `tests/passphrase_strip_rule.rs` (NEW) | test (unit — strip cases) | transform (byte-in, byte-out) | `tests/mock_transport_roundtrip.rs` (plain `#[test]`, no serial, no env) | role-match |
| `tests/passphrase_fd_borrowed.rs` (NEW) | test (fd-lifecycle runtime) | file-I/O + fd-I/O | `tests/identity_perms_0600.rs` (env-mutating + `#[serial]` + tempdir) | role-match |
| `tests/dht_label_constants.rs` (NEW) | test (constant byte-match) | transform (string compare) | `tests/mock_transport_roundtrip.rs` (plain `#[test]`) | role-match |
| `tests/pass09_scripted_roundtrip.rs` (NEW) | test (CLI integration via MockTransport) | request-response | `tests/phase3_end_to_end_a_sends_b_receipt.rs` + `tests/phase2_share_round_trip.rs` | exact (two-identity + MockTransport + env-mutating + serial) |
| `SPEC.md` (MOD) | docs | N/A | existing SPEC.md prose style | exact (in-place rewrite) |
| `CLAUDE.md` (MOD) | docs | N/A | existing CLAUDE.md §Load-bearing lock-ins heading style | exact |
| `.planning/milestones/v1.0-REQUIREMENTS.md` (MOD) | docs (archived) | N/A | N/A — destructive edit only | N/A |

## Pattern Assignments

### `src/identity.rs` — `resolve_passphrase` rewrite (utility, file-I/O + fd-I/O)

**Analog:** self — current implementation at `src/identity.rs:258-320` is the "before" code. The rewrite is *in place*, NOT a new function. Keep the same signature, Result return type, priority-order comment block, and TTY-prompt fallthrough. Only the fd branch (lines 270-288) and the file-branch strip (line 299) change.

**Imports pattern — already present at file top** (lines 11-19):
```rust
use crate::crypto;
use crate::error::Error;
use secrecy::{ExposeSecret, SecretBox};
use std::fs;
use std::io::Write as IoWrite;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;
```

**New import to add for BorrowedFd** (D-P5-07):
```rust
use std::os::unix::io::{AsRawFd, BorrowedFd};
```

**Precedence-order reaffirmation** (D-P5-01) — preserve the existing doc-comment order `fd > file > env > TTY` verbatim; the check order in the function body already matches. No code re-ordering, just doc-comment reaffirmation and the argv-rejection stays at priority 1.

**fd-branch rewrite target** (current code at lines 271-288, to be replaced):
```rust
    // Priority 2: fd.
    if let Some(n) = fd {
        use std::io::BufRead;
        use std::os::unix::io::FromRawFd;
        // SAFETY: we trust the caller-provided fd. We do NOT close the fd after reading
        // because the caller (main.rs) might share stdin (fd=0). We rely on the process
        // exiting to clean up. If n == 0 that's stdin, which is fine.
        let file = unsafe { fs::File::from_raw_fd(n) };
        let mut reader = std::io::BufReader::new(file);
        let mut line = String::new();
        reader.read_line(&mut line).map_err(Error::Io)?;
        // Prevent the file from being closed (drop would close the raw fd).
        std::mem::forget(reader);
        return Ok(Passphrase::from_string(
            line.trim_end_matches('\n')
                .trim_end_matches('\r')
                .to_string(),
        ));
    }
```

**Replacement shape** (D-P5-07 BorrowedFd + D-P5-03 fd=0 rejection + D-P5-08 exact strip):
```rust
    // Priority 2: fd.
    if let Some(n) = fd {
        use std::io::BufRead;
        use std::os::unix::io::BorrowedFd;
        if n == 0 {
            return Err(Error::Config(
                "--passphrase-fd 0 reserved for stdin; use fd >= 3 or --passphrase-file".into(),
            ));
        }
        // SAFETY: caller guarantees `n` is an open fd for the duration of this call.
        // BorrowedFd does NOT take ownership, so the original fd remains valid for the
        // caller to close (or for the process to clean up). Pitfall #31.
        let borrowed = unsafe { BorrowedFd::borrow_raw(n) };
        let file = std::fs::File::from(borrowed.try_clone_to_owned().map_err(Error::Io)?);
        let mut reader = std::io::BufReader::new(file);
        let mut buf = Vec::new();
        reader.read_until(b'\n', &mut buf).map_err(Error::Io)?;
        // Exact one-newline strip (D-P5-08): one \r\n, else one \n, else nothing.
        if buf.ends_with(b"\r\n") {
            buf.truncate(buf.len() - 2);
        } else if buf.ends_with(b"\n") {
            buf.truncate(buf.len() - 1);
        }
        let s = String::from_utf8(buf).map_err(|_| Error::PassphraseInvalidInput)?;
        return Ok(Passphrase::from_string(s));
    }
```

> **Note to planner:** the exact `try_clone_to_owned()` shape is Claude's discretion — the load-bearing property is that the caller-owned fd is NOT closed by this function's drop path. An alternative is to keep `BorrowedFd` and read directly from `&borrowed` via a custom `Read` impl; choose whichever compiles cleanly against our `ed25519-dalek =3.0.0-pre.5`-pinned toolchain. The test at `tests/passphrase_fd_borrowed.rs` is what enforces the contract.

**File-branch strip rewrite** (lines 297-300 currently; D-P5-08):
```rust
// Current (greedy — corrupts "hunter2 \n" by stripping only one \n, but corrupts "hunter2\r" case):
let s = fs::read_to_string(path).map_err(Error::Io)?;
return Ok(Passphrase::from_string(
    s.trim_end_matches('\n').trim_end_matches('\r').to_string(),
));
```

**Replacement shape:**
```rust
let bytes = fs::read(path).map_err(Error::Io)?;
let mut buf = bytes;
if buf.ends_with(b"\r\n") {
    buf.truncate(buf.len() - 2);
} else if buf.ends_with(b"\n") {
    buf.truncate(buf.len() - 1);
}
let s = String::from_utf8(buf).map_err(|_| Error::PassphraseInvalidInput)?;
return Ok(Passphrase::from_string(s));
```

**Error-oracle hygiene** (CLAUDE.md lock-in): `Error::PassphraseInvalidInput` reused for argv-inline rejection (already wired) and for UTF-8 decode failures. `Error::Config` reused for fd=0 rejection (same exit-1 bucket as other CLI-validation errors — D-P5-04 confirms this is the right bucket).

---

### `src/cli.rs` — Send and Receive flag additions (config, request-response)

**Analog:** `IdentityCmd::Generate` at lines 110-122 — already has the exact three-field shape for `passphrase_file` / `passphrase_fd` / hidden `passphrase`. Clone this block into `Command::Send` and `Command::Receive`.

**Field-block pattern to clone** (lines 110-122):
```rust
Generate {
    /// Read passphrase from the given file (newline-terminated, file must be mode 0600 or 0400)
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<std::path::PathBuf>,
    /// Read passphrase from the given file descriptor (for scripting)
    #[arg(long, value_name = "N")]
    passphrase_fd: Option<i32>,
    /// REJECTED — inline passphrases leak via argv / /proc/<pid>/cmdline / ps.
    /// Use CIPHERPOST_PASSPHRASE env, --passphrase-file, or --passphrase-fd instead.
    /// This flag exists only so the runtime rejection path returns a clear error (exit 4).
    #[arg(long, value_name = "VALUE", hide = true)]
    passphrase: Option<String>,
},
```

**long_about EXAMPLES pattern to clone** (lines 105-109):
```rust
#[command(long_about = "Generate identity.\n\nEXAMPLES:\n  \
          cipherpost identity generate\n  \
          CIPHERPOST_PASSPHRASE=hunter2 cipherpost identity generate\n  \
          cipherpost identity generate --passphrase-file ./pw.txt\n  \
          cipherpost identity generate --passphrase-fd 3 3</tmp/pw")]
```

**Send-struct target** (current lines 35-58, MUST add the three passphrase fields and one positional):
```rust
/// Send a cryptographic-material payload (phase 2)
#[command(long_about = "Send a payload.\n\nEXAMPLES:\n  \
          cipherpost send --self -p 'backup signing key' --material-file ./key.age\n  \
          cipherpost send --share <z32-pubkey> -p 'onboarding token' -")]
Send {
    // ... existing fields self_, share, purpose, material_file, ttl ...
}
```

**Send-struct post-change shape** (D-P5-05 adds positional `-`; D-P5-10 adds three scripting EXAMPLES lines):
```rust
#[command(long_about = "Send a payload.\n\nEXAMPLES:\n  \
          cipherpost send --self -p 'backup signing key' --material-file ./key.age\n  \
          cipherpost send --share <z32-pubkey> -p 'onboarding token' -\n  \
          CIPHERPOST_PASSPHRASE=hunter2 cipherpost send --self -p 'x' -\n  \
          cipherpost send --self -p 'x' --passphrase-file ./pw.txt -\n  \
          cipherpost send --self -p 'x' --passphrase-fd 3 - 3</tmp/pw")]
Send {
    #[arg(long, conflicts_with = "share")]
    self_: bool,
    #[arg(long, conflicts_with = "self_")]
    share: Option<String>,
    #[arg(short, long)]
    purpose: Option<String>,
    #[arg(long)]
    material_file: Option<String>,
    #[arg(long)]
    ttl: Option<u64>,
    // NEW — passphrase trio (clone of IdentityCmd::Generate lines 110-122):
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<std::path::PathBuf>,
    #[arg(long, value_name = "N")]
    passphrase_fd: Option<i32>,
    #[arg(long, value_name = "VALUE", hide = true)]
    passphrase: Option<String>,
    // NEW — positional `-` for stdin (D-P5-05); only `-` accepted:
    #[arg(value_name = "STDIN")]
    material_stdin: Option<String>,
},
```

**Receive-struct post-change shape** (D-P5-06 says NO positional stdin for receive; only add passphrase trio):
```rust
#[command(long_about = "Receive a share.\n\nEXAMPLES:\n  \
          cipherpost receive <share-uri>\n  \
          cipherpost receive <share-uri> -o ./recovered.key\n  \
          CIPHERPOST_PASSPHRASE=hunter2 cipherpost receive <share-uri>\n  \
          cipherpost receive <share-uri> --passphrase-file ./pw.txt\n  \
          cipherpost receive <share-uri> --passphrase-fd 3 3</tmp/pw")]
Receive {
    share: Option<String>,
    #[arg(short, long)]
    output: Option<String>,
    #[arg(long)]
    dht_timeout: Option<u64>,
    // NEW — passphrase trio:
    #[arg(long, value_name = "PATH")]
    passphrase_file: Option<std::path::PathBuf>,
    #[arg(long, value_name = "N")]
    passphrase_fd: Option<i32>,
    #[arg(long, value_name = "VALUE", hide = true)]
    passphrase: Option<String>,
},
```

---

### `src/main.rs` — Send and Receive dispatch plumbing (controller, request-response)

**Analog:** `IdentityCmd::Generate` dispatch at lines 37-58 — the canonical four-source `resolve_passphrase` call already in place for identity generate. Clone the argument-threading shape exactly.

**Dispatch-call pattern to clone** (lines 45-51):
```rust
let pw = cipherpost::identity::resolve_passphrase(
    passphrase.as_deref(),
    Some("CIPHERPOST_PASSPHRASE"),
    passphrase_file.as_deref(),
    passphrase_fd,
    true,  // confirm_on_tty — Generate uses true; Send/Receive use false.
)?;
```

**Send-dispatch target** (current lines 80-96 — the four-source call is already there but threads `None, None, None`):
```rust
Command::Send {
    self_,
    share,
    purpose,
    material_file,
    ttl,
} => {
    // Phase 2 does not add passphrase flags to Send — pulls from env / TTY only.
    let pw = cipherpost::identity::resolve_passphrase(
        None,
        Some("CIPHERPOST_PASSPHRASE"),
        None,
        None,
        false,
    )?;
    ...
```

**Send-dispatch post-change shape** (thread new fields + D-P5-04 multi-source conflict check + D-P5-05 positional `-` handling):
```rust
Command::Send {
    self_,
    share,
    purpose,
    material_file,
    ttl,
    passphrase,
    passphrase_file,
    passphrase_fd,
    material_stdin,
} => {
    // D-P5-04: reject --passphrase-file AND --passphrase-fd together.
    if passphrase_file.is_some() && passphrase_fd.is_some() {
        return Err(cipherpost::Error::Config(
            "--passphrase-file and --passphrase-fd are mutually exclusive".into(),
        ).into());
    }
    // D-P5-05: positional `-` means "--material-file -"; any other positional value is error.
    if let Some(ref v) = material_stdin {
        if v != "-" {
            return Err(cipherpost::Error::Config(
                "positional argument must be `-` (stdin); use --material-file <path> for files".into(),
            ).into());
        }
    }
    let effective_material = match (material_file.as_deref(), material_stdin.as_deref()) {
        (Some(_), Some(_)) => return Err(cipherpost::Error::Config(
            "--material-file and positional `-` are mutually exclusive".into(),
        ).into()),
        (Some(p), None) => Some(p.to_string()),
        (None, Some("-")) => Some("-".to_string()),
        (None, None) => None,
        (None, Some(_)) => unreachable!("validated above"),
    };
    let pw = cipherpost::identity::resolve_passphrase(
        passphrase.as_deref(),
        Some("CIPHERPOST_PASSPHRASE"),
        passphrase_file.as_deref(),
        passphrase_fd,
        false,  // unlock path — no confirmation.
    )?;
    // ... rest of existing Send dispatch unchanged, substituting effective_material for material_file ...
}
```

**Receive-dispatch post-change shape** (lines 172-237; no positional, just the passphrase trio + multi-source guard):
```rust
Command::Receive {
    share,
    output,
    dht_timeout: _,
    passphrase,
    passphrase_file,
    passphrase_fd,
} => {
    if passphrase_file.is_some() && passphrase_fd.is_some() {
        return Err(cipherpost::Error::Config(
            "--passphrase-file and --passphrase-fd are mutually exclusive".into(),
        ).into());
    }
    let share_str = share.ok_or_else(|| cipherpost::Error::Config("share URI required".into()))?;
    let uri = cipherpost::ShareUri::parse(&share_str)?;
    if let Some(accepted_at) = cipherpost::flow::check_already_accepted(&uri.share_ref_hex) {
        eprintln!("already accepted at {}; not re-decrypting", accepted_at);
        return Ok(());
    }
    let pw = cipherpost::identity::resolve_passphrase(
        passphrase.as_deref(),
        Some("CIPHERPOST_PASSPHRASE"),
        passphrase_file.as_deref(),
        passphrase_fd,
        false,
    )?;
    // ... rest unchanged ...
}
```

---

### `src/transport.rs` — DHT label constant-match inline test (optional location; test module)

**Analog:** inline `#[cfg(test)] mod tests { ... }` pattern. The DHT label constants `DHT_LABEL_OUTER` and `DHT_LABEL_RECEIPT_PREFIX` are defined in `src/lib.rs:34` and `src/lib.rs:38` (not in transport.rs itself — transport.rs imports them via `use crate::{DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX};` at line 20).

**Current label definitions** (`src/lib.rs:33-38`):
```rust
/// DHT label for outer share records (under the SENDER's PKARR key). D-05.
pub const DHT_LABEL_OUTER: &str = "_cipherpost";

/// DHT label prefix for receipts (under the RECIPIENT's PKARR key). D-06.
/// Full label: format!("{}{}", DHT_LABEL_RECEIPT_PREFIX, share_ref_hex).
pub const DHT_LABEL_RECEIPT_PREFIX: &str = "_cprcpt-";
```

**Decision on test location** (D-P5-12): either `tests/dht_label_constants.rs` (integration) OR inline `#[cfg(test)] mod tests` in `src/transport.rs`. **Recommend the integration test file** (see next section) — cleaner grep, same strictness, matches the precedent set by `tests/chacha20poly1305_direct_usage_ban.rs` for other wire-format audits. If the planner prefers inline, the unit-test module scaffold in the project is standard — nothing novel to inject.

---

### `tests/passphrase_strip_rule.rs` (NEW — unit test for 5 strip cases)

**Analog:** `tests/mock_transport_roundtrip.rs` — plain `#[test]` functions, no `#[serial]`, no env-var mutation, no tempdir. The strip rule is pure byte-in/byte-out and can be tested via `resolve_passphrase` with a `--passphrase-file` pointing to a tempfile (which forces the file-branch path; no need to touch fd).

**Imports pattern to clone** (from `tests/mock_transport_roundtrip.rs:7-9`, plus file utilities from `tests/identity_perms_0600.rs:6-9`):
```rust
use std::os::unix::fs::PermissionsExt;
use std::io::Write;
use tempfile::TempDir;
```

**Test scaffold** (using the five cases from D-P5-08):
```rust
fn strip_case(input_bytes: &[u8]) -> String {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("pw.txt");
    let mut f = std::fs::File::create(&path).unwrap();
    f.write_all(input_bytes).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let pw = cipherpost::identity::resolve_passphrase(
        None,
        None,  // disable env lookup so file-branch is taken deterministically
        Some(&path),
        None,
        false,
    ).unwrap();
    pw.expose().to_string()
}

#[test]
fn strip_crlf() { assert_eq!(strip_case(b"hunter2\r\n"), "hunter2"); }

#[test]
fn strip_lf() { assert_eq!(strip_case(b"hunter2\n"), "hunter2"); }

#[test]
fn strip_one_of_two_lf() { assert_eq!(strip_case(b"hunter2\n\n"), "hunter2\n"); }

#[test]
fn preserve_trailing_space() { assert_eq!(strip_case(b"hunter2 "), "hunter2 "); }

#[test]
fn preserve_no_trailer() { assert_eq!(strip_case(b"hunter2"), "hunter2"); }

#[test]
fn preserve_bare_cr() { assert_eq!(strip_case(b"hunter2\r"), "hunter2\r"); }
```

> **Note:** these tests touch `CIPHERPOST_HOME` ONLY if `identity::resolve_passphrase` consults it internally — it does not (only `key_dir()` does, and resolve_passphrase's file-branch bypasses key_dir entirely). Therefore `#[serial]` is NOT required for this file. But the env-var fallback at priority 4 must be disabled by passing `env_var_name = None` above, otherwise ambient `CIPHERPOST_PASSPHRASE` could mask the file-branch. That's why the helper passes `None` for arg 2.

---

### `tests/passphrase_fd_borrowed.rs` (NEW — fd-lifecycle runtime test)

**Analog:** `tests/identity_perms_0600.rs` for the `#[serial]` + tempdir + env-mutating shape; `tests/phase3_end_to_end_a_sends_b_receipt.rs:27-47` for the deterministic-identity-at helper (not needed here but same dir-handling style).

**Imports pattern** (cloned from `tests/identity_perms_0600.rs:6-9` + `nix` or raw `libc` for `fcntl`):
```rust
use serial_test::serial;
use std::os::unix::io::AsRawFd;
use tempfile::TempDir;
```

**Runtime fd-check pattern** — use `fcntl(fd, F_GETFD)` via libc (or `nix::fcntl::fcntl`) to assert the fd is still open after `resolve_passphrase` returns. If Cargo.toml lacks `nix` or `libc` as a dev-dep, use this syscall wrapper (stdlib-only):
```rust
fn fd_is_open(fd: i32) -> bool {
    // F_GETFD = 1 on Linux; EBADF = 9.
    // SAFETY: fcntl is a stable syscall with no memory effects for F_GETFD.
    let ret = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    ret != -1
}
```

**Test shape** (D-P5-09 spec):
```rust
#[test]
#[serial]
fn fd_remains_open_after_resolve() {
    // Create a pipe: write_fd → read_fd.
    let mut fds: [libc::c_int; 2] = [0; 2];
    let rc = unsafe { libc::pipe(fds.as_mut_ptr()) };
    assert_eq!(rc, 0, "pipe() must succeed");
    let (read_fd, write_fd) = (fds[0], fds[1]);

    // Write "hunter2\n" to the write end.
    let payload = b"hunter2\n";
    let n = unsafe { libc::write(write_fd, payload.as_ptr() as *const _, payload.len()) };
    assert_eq!(n, payload.len() as isize);
    unsafe { libc::close(write_fd) };  // EOF for the read side.

    // Call resolve_passphrase with the read fd.
    // Disable env-var so the fd path is taken deterministically.
    let pw = cipherpost::identity::resolve_passphrase(
        None,
        None,
        None,
        Some(read_fd),
        false,
    ).expect("resolve_passphrase must succeed on a valid fd");
    assert_eq!(pw.expose(), "hunter2", "strip rule must fire on fd read");

    // The load-bearing assertion: read_fd is STILL open after the call returns.
    // BorrowedFd did not close it. Pitfall #31.
    assert!(fd_is_open(read_fd), "resolve_passphrase must not close the caller's fd");

    // Caller cleans up.
    unsafe { libc::close(read_fd) };
}

#[test]
#[serial]
fn fd_zero_rejected() {
    // D-P5-03: fd 0 reserved for stdin.
    let err = cipherpost::identity::resolve_passphrase(None, None, None, Some(0), false).unwrap_err();
    assert!(matches!(err, cipherpost::Error::Config(_)), "fd 0 must be rejected as Config, got {:?}", err);
}
```

> **Dependency note:** if `libc` is not in dev-dependencies, add it — it is on stable, MIT/Apache, and already transitive via `tempfile`. Alternatively, `nix` already appears in some transitive closure; pick whichever is already on the workspace to avoid a new direct dep.

---

### `tests/dht_label_constants.rs` (NEW — constant byte-match test)

**Analog:** `tests/chacha20poly1305_direct_usage_ban.rs` for the "wire-constant audit test" pattern, and `tests/mock_transport_roundtrip.rs` for the plain `#[test]` shape (no env, no serial).

**Test scaffold** (D-P5-12):
```rust
//! DOC-02 / Pitfall #33: DHT label strings are wire-protocol constants.
//! Renaming either requires a protocol_version bump. This test is the
//! "confirm, don't change" audit — it byte-matches code constants against
//! the values documented in SPEC.md §3.3.

use cipherpost::{DHT_LABEL_OUTER, DHT_LABEL_RECEIPT_PREFIX};

#[test]
fn dht_label_outer_is_cipherpost_literal() {
    assert_eq!(DHT_LABEL_OUTER, "_cipherpost",
        "SPEC.md §3.3 locks this label; renaming requires a protocol_version bump");
}

#[test]
fn dht_label_receipt_prefix_is_cprcpt_literal() {
    assert_eq!(DHT_LABEL_RECEIPT_PREFIX, "_cprcpt-",
        "SPEC.md §3.3 locks this label; renaming requires a protocol_version bump");
}
```

---

### `tests/pass09_scripted_roundtrip.rs` (NEW — PASS-09 CI integration test)

**Analog:** `tests/phase3_end_to_end_a_sends_b_receipt.rs` — two identities, MockTransport, env-mutating `CIPHERPOST_HOME`, `#[serial]`, deterministic seeds. Cite `tests/phase2_share_round_trip.rs` for the minimal-payload variant.

**Canonical invocation to quote at the top of the file** (per specifics block of CONTEXT.md):
```
# SC1 scripted round-trip (no TTY):
#   cipherpost send - --passphrase-fd 3 < payload.bin 3< passphrase.txt
#   cipherpost receive <uri> --passphrase-file ~/.cipherpost/pp.txt
```

**Imports pattern to clone** (from `tests/phase3_end_to_end_a_sends_b_receipt.rs:1-25`):
```rust
#![cfg(feature = "mock")]

use cipherpost::crypto;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receipts, run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::identity::Identity;
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use tempfile::TempDir;
use zeroize::Zeroizing;
```

**deterministic_identity_at helper to clone verbatim** (from `tests/phase3_end_to_end_a_sends_b_receipt.rs:27-47`):
```rust
fn deterministic_identity_at(home: &std::path::Path, seed: [u8; 32]) -> (Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", home);
    fs::create_dir_all(home).unwrap();
    fs::set_permissions(home, fs::Permissions::from_mode(0o700)).unwrap();
    let pw = SecretBox::new(Box::new("pw".to_string()));
    let seed_z = Zeroizing::new(seed);
    let blob = crypto::encrypt_key_envelope(&seed_z, &pw).unwrap();
    let path = home.join("secret_key");
    let mut f = fs::OpenOptions::new()
        .create(true).truncate(true).write(true).mode(0o600)
        .open(&path).unwrap();
    f.write_all(&blob).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let id = cipherpost::identity::load(&pw).unwrap();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}
```

**PASS-09 test pattern** — exercise `resolve_passphrase` with `--passphrase-file` (file path) and `--passphrase-fd` (pipe fd) variants, then call `run_send` + `run_receive` end-to-end through MockTransport. Two test functions — one per scripting mechanism:
```rust
#[test]
#[serial]
fn scripted_roundtrip_via_passphrase_file() {
    // Setup two identities (deterministic seeds).
    let dir_a = TempDir::new().unwrap();
    let (id_a, kp_a) = deterministic_identity_at(dir_a.path(), [0xAA; 32]);
    let dir_b = TempDir::new().unwrap();
    let (id_b, kp_b) = deterministic_identity_at(dir_b.path(), [0xBB; 32]);
    let b_z32 = kp_b.public_key().to_z32();

    // Write a passphrase file at mode 0600.
    let pw_dir = TempDir::new().unwrap();
    let pw_path = pw_dir.path().join("pp.txt");
    {
        let mut f = fs::OpenOptions::new()
            .create(true).write(true).mode(0o600)
            .open(&pw_path).unwrap();
        f.write_all(b"pw\n").unwrap();
    }

    // CRITICAL: CIPHERPOST_PASSPHRASE must NOT be set, otherwise env would mask the file.
    std::env::remove_var("CIPHERPOST_PASSPHRASE");

    // Resolve via file (proves the file-branch path lands the correct strip).
    let pw = cipherpost::identity::resolve_passphrase(
        None, Some("CIPHERPOST_PASSPHRASE"), Some(&pw_path), None, false,
    ).expect("resolve via --passphrase-file");
    assert_eq!(pw.expose(), "pw", "file-branch must yield the same bytes the identity was written with");

    // A sends → MockTransport → B receives.
    let transport = MockTransport::new();
    std::env::set_var("CIPHERPOST_HOME", dir_a.path());
    let uri_str = run_send(
        &id_a, &transport, &kp_a,
        SendMode::Share { recipient_z32: b_z32.clone() },
        "pass09", MaterialSource::Bytes(b"secret".to_vec()),
        DEFAULT_TTL_SECONDS,
    ).expect("A run_send");
    let uri = ShareUri::parse(&uri_str).unwrap();

    std::env::set_var("CIPHERPOST_HOME", dir_b.path());
    let mut sink = OutputSink::InMemory(Vec::new());
    run_receive(&id_b, &transport, &kp_b, &uri, &mut sink, &AutoConfirmPrompter)
        .expect("B run_receive");
    match sink { OutputSink::InMemory(buf) => assert_eq!(buf, b"secret"),
                 _ => panic!("InMemory expected") };
}

#[test]
#[serial]
fn scripted_roundtrip_via_passphrase_fd() {
    // Parallel test using an open pipe fd in place of the file.
    // [use the libc::pipe pattern from tests/passphrase_fd_borrowed.rs]
}
```

> **Scope note:** per the "one test surface" principle of D-P5-07, this file covers both the file and fd scripting variants. The goal is to prove the dispatcher threads the flags through correctly — strip-rule and fd-lifecycle correctness are proven by the unit tests above. PASS-09 is the "round-trip no TTY" integration guarantee.

---

### `SPEC.md` — §3.3 wire-stability note, §7 precedence rewrite, §3+§4 version-prose

**Changes required:**

- **§7.1** — rewrite precedence section to `fd > file > env > TTY` with one-line rationale per source (D-P5-01). Reference Pitfall #35 rationale inline.
- **§7** — add the D-P5-08 strip rule (exact wording from CONTEXT.md) with the six-case truth table.
- **§3.3** — append the wire-stability note: *"These label strings are part of the wire format. Renaming either requires a `protocol_version` bump and a migration section in this SPEC. Under no circumstances are they changed silently."*
- **§3 + §4** — rewrite version prose to API-range form: e.g. `serde_canonical_json (>= 1.0.0, RFC 8785 JCS); see Cargo.toml for the exact pin in effect`. Same treatment for `pkarr`, `ed25519-dalek`, `age` (D-P5-11).
- **§3 or §4** — update PKARR wire-budget prose from 600 → 550 bytes at v1.0 cut (D-P5-11 final paragraph; matches the measured budget from `tests/signed_packet_budget.rs:21-23`).

**No code excerpts — this is prose editing.** The planner should reference the exact-pin authority file `Cargo.toml` and the wire-budget witness at `tests/signed_packet_budget.rs` in the SPEC prose.

---

### `CLAUDE.md` — new "Planning docs convention" section

**Change:** append a new top-level `## Planning docs convention` heading (D-P5-14) with the exact paragraph given in CONTEXT.md §D-P5-14. Place it after the existing `## GSD workflow` section so it sits near related meta-instructions.

---

### `.planning/milestones/v1.0-REQUIREMENTS.md` — drop traceability table

**Change:** delete the traceability table section outright; prepend the forward-pointer note from CONTEXT.md §D-P5-13 where that section used to live. No code excerpts. Commit message locked: `docs(archive): drop v1.0 traceability table (DOC-04)`.

---

## Shared Patterns

### Passphrase-helper call signature
**Source:** `src/identity.rs:258-264` (function signature), `src/main.rs:45-51` (canonical call site)
**Apply to:** Send and Receive dispatchers in `src/main.rs` (the only remaining callers that pass `None, None, None`).
```rust
pub fn resolve_passphrase(
    inline_argv: Option<&str>,
    env_var_name: Option<&str>,
    file: Option<&Path>,
    fd: Option<i32>,
    confirm_on_tty: bool,
) -> Result<Passphrase, Error>
```

### hide-passphrase-then-reject (Error::PassphraseInvalidInput)
**Source:** `src/cli.rs:120-121` (hide=true attr), `src/identity.rs:265-268` (runtime reject), `tests/identity_passphrase_argv_rejected.rs:14-19` (CLI-level test)
**Apply to:** `Send` and `Receive` clap structs; the Display text `"inline argv"` must appear in stderr on rejection so the existing predicate test pattern works.

### Error-oracle hygiene (CLAUDE.md load-bearing lock-in)
**Source:** CLAUDE.md §Load-bearing lock-ins "Error-oracle hygiene" bullet + `src/error.rs` `user_message()` function
**Apply to:** new `Error::Config` variants for fd=0 and multi-source conflict — both go through the existing `Error::Config(String)` variant, reuse exit-1 bucket. DO NOT introduce a new exit code (CONTEXT.md anti-patterns).

### Env-mutating test discipline
**Source:** every file in `tests/` that calls `std::env::set_var("CIPHERPOST_HOME", ...)` or `CIPHERPOST_PASSPHRASE` — all use `use serial_test::serial;` + `#[serial]` attribute on each test function (CLAUDE.md load-bearing lock-in).
**Apply to:** `tests/passphrase_fd_borrowed.rs` (env-mutating — D-P5-09 says `#[serial]`), `tests/pass09_scripted_roundtrip.rs` (env-mutating via deterministic_identity_at). NOT required for `tests/passphrase_strip_rule.rs` (no env mutation — the helper disables env-var lookup by passing `None`) or `tests/dht_label_constants.rs` (pure constant comparison).

### MockTransport for integration tests
**Source:** `tests/phase3_end_to_end_a_sends_b_receipt.rs:60`, `tests/phase2_share_round_trip.rs:59`, `tests/mock_transport_roundtrip.rs:42`
**Apply to:** `tests/pass09_scripted_roundtrip.rs` (D-P5-09 mandates MockTransport — no real DHT in CI).
```rust
let transport = MockTransport::new();
```
Gated at the top of the test file with `#![cfg(feature = "mock")]` — required, not optional.

### deterministic_identity_at helper
**Source:** `tests/phase3_end_to_end_a_sends_b_receipt.rs:27-47` (verbatim) — writes a deterministic-seed `CIPHPOSK` envelope + loads it, returning `(Identity, Keypair)`. Uses `crypto::encrypt_key_envelope`, fixed passphrase `"pw"`, mode 0600.
**Apply to:** `tests/pass09_scripted_roundtrip.rs` — clone verbatim (don't generalize prematurely; this helper is repeated in 4 test files already).

### EXAMPLES block shape in clap long_about
**Source:** `src/cli.rs:35-37` (Send today), `src/cli.rs:105-109` (Generate — the scripting-examples target).
**Apply to:** `Send` and `Receive` `long_about` additions. Keep the `\n  \` line-continuation shape; verified by `tests/phase2_cli_help_examples.rs:19-44`.

### CLI-03 help-examples assertion
**Source:** `tests/phase2_cli_help_examples.rs:19-44` — asserts both subcommands' `--help` output contains `"EXAMPLES:"` and `"cipherpost <subcommand>"`.
**Apply to:** existing tests still pass with the expanded long_about. No test change required (existing assertions are lenient — they only require `"EXAMPLES:"` and `"cipherpost send"` / `"cipherpost receive"` substrings, both of which survive the expansion).

---

## No Analog Found

All files have strong analogs. One design note:

| File | Role | Status |
|------|------|--------|
| `tests/passphrase_fd_borrowed.rs` | test (fd-lifecycle via raw syscall) | **fcntl/pipe call is novel in this repo.** No existing test uses `libc::pipe` or `libc::fcntl`. Either add `libc` to `[dev-dependencies]` (small, ubiquitous) or use `nix::unistd::pipe` + `nix::fcntl::fcntl` if `nix` is already transitive. This is Claude's discretion per CONTEXT.md. |

---

## Metadata

**Analog search scope:** `src/**/*.rs`, `tests/**/*.rs`, `src/lib.rs`, `src/identity.rs`, `src/transport.rs`, `src/main.rs`, `src/cli.rs`
**Files scanned:** ~12 source + ~36 test files (full `tests/` listing read; 8 read in full)
**Pattern extraction date:** 2026-04-23

---

## PATTERN MAPPING COMPLETE

**Phase:** 5 — non-interactive-automation-e2e
**Files classified:** 11
**Analogs found:** 11 / 11

### Coverage
- Files with exact analog: 8 (identity.rs, cli.rs, main.rs, transport.rs test location, pass09_scripted_roundtrip, SPEC.md, CLAUDE.md, v1.0-REQUIREMENTS.md)
- Files with role-match analog: 3 (passphrase_strip_rule.rs, passphrase_fd_borrowed.rs, dht_label_constants.rs)
- Files with no analog: 0 (one novel dependency — `libc` for fcntl — flagged for planner)

### Key Patterns Identified
- `resolve_passphrase` has ONE call signature and ONE body; Phase 5 edits the body in place — no parallel `resolve_passphrase_strict()`. Single code path guarantees Send/Receive/identity inherit the same strip + fd semantics.
- `IdentityCmd::Generate` at `src/cli.rs:110-122` is the canonical clap-field template for the passphrase trio; clone into Send and Receive verbatim.
- `tests/phase3_end_to_end_a_sends_b_receipt.rs` is the two-identity + MockTransport + `#[serial]` + deterministic_seed template; clone for PASS-09.
- Env-mutating tests are uniformly `#[serial]`-guarded in this repo (17 test files confirmed). New fd-lifecycle + PASS-09 tests follow the same rule; strip-rule and label-constant tests do not need it.
- Error-oracle hygiene: reuse `Error::Config` (exit 1) and `Error::PassphraseInvalidInput` (exit 4) — no new exit codes.
