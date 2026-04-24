---
phase: 05-non-interactive-automation-e2e
plan: 01
subsystem: identity/passphrase-helper
tags: [passphrase, fd, strip-rule, BorrowedFd, security-correctness]
requires:
  - "src/error.rs :: Error::Config(String) (existing, unchanged)"
  - "src/error.rs :: Error::PassphraseInvalidInput (existing, unchanged)"
  - "src/identity.rs :: Passphrase::expose/from_string (existing, unchanged)"
provides:
  - "src/identity.rs :: resolve_passphrase — rewritten fd + file branches (same signature)"
  - "tests/passphrase_strip_rule.rs :: D-P5-08 six-case truth table (6 tests)"
  - "tests/passphrase_fd_borrowed.rs :: fd-lifecycle + fd=0 rejection (2 tests)"
affects:
  - "identity generate/show, send, receive — all inherit the fix through the one shared resolve_passphrase path"
tech_stack_added:
  - "libc = 0.2 ([dev-dependencies]) — used only by tests/passphrase_fd_borrowed.rs for pipe/write/close/fcntl"
patterns:
  - "BorrowedFd::borrow_raw + try_clone_to_owned — no-ownership fd read"
  - "Exact one-newline strip (one \\r\\n, else one \\n, else nothing) — no greedy .trim()"
  - "Error-oracle hygiene: UTF-8 decode failure maps to Error::PassphraseInvalidInput (same exit-4 bucket as argv-inline rejection)"
key_files:
  created:
    - "tests/passphrase_strip_rule.rs"
    - "tests/passphrase_fd_borrowed.rs"
    - ".planning/phases/05-non-interactive-automation-e2e/05-01-SUMMARY.md"
  modified:
    - "src/identity.rs"
    - "Cargo.toml"
    - "Cargo.lock"
decisions:
  - "Kept the function signature of resolve_passphrase unchanged; identity generate/show, send, receive all inherit the fix through one code path (D-P5-07)."
  - "try_clone_to_owned() on the BorrowedFd produces an owned File so BufReader can drop cleanly without closing the caller's fd. Alternative was a custom Read impl on &BorrowedFd; the try_clone_to_owned shape compiles cleaner and matches 05-PATTERNS.md."
  - "UTF-8 decode failures on fd/file content map to Error::PassphraseInvalidInput, not Error::Io. Intentional: same exit-4 bucket as argv-inline rejection preserves error-oracle uniformity."
  - "Module docstring and inline comment in tests/passphrase_fd_borrowed.rs were rephrased to avoid the literal string 'BorrowedFd' (was tripping the plan's strict ! grep invariant; the test exercises the public API and does not import the type). Context to Pitfall #31 is preserved by name-of-invariant rather than name-of-Rust-type."
metrics:
  duration: "9m 31s"
  completed: "2026-04-24"
  tasks_completed: 3
  files_created: 2
  files_modified: 3
  commits: 4
  tests_added: 8
  tests_passing: { base: 75, mock: 94 }
---

# Phase 5 Plan 01: Passphrase helper hardening (BorrowedFd + exact strip + fd=0 reject) — Summary

**One-liner:** Rewrote `resolve_passphrase`'s fd and file branches to eliminate the `FromRawFd` double-close hazard (Pitfall #31), replace greedy `.trim_end_matches` with an exact one-newline strip (Pitfall #30 / D-P5-08), and reject `--passphrase-fd 0` as `Error::Config` (D-P5-03) — all via one shared code path that identity generate/show, send, and receive inherit (D-P5-07).

## What shipped

### src/identity.rs — fd branch rewrite

Before:
```rust
let file = unsafe { fs::File::from_raw_fd(n) };
let mut reader = std::io::BufReader::new(file);
let mut line = String::new();
reader.read_line(&mut line).map_err(Error::Io)?;
std::mem::forget(reader);                  // suppress drop to avoid close
return Ok(Passphrase::from_string(
    line.trim_end_matches('\n')
        .trim_end_matches('\r')
        .to_string(),
));
```

After:
```rust
if n == 0 {
    return Err(Error::Config(
        "--passphrase-fd 0 reserved for stdin; use fd >= 3 or --passphrase-file".into(),
    ));
}
let borrowed = unsafe { BorrowedFd::borrow_raw(n) };
let file = std::fs::File::from(borrowed.try_clone_to_owned().map_err(Error::Io)?);
let mut reader = std::io::BufReader::new(file);
let mut buf = Vec::new();
reader.read_until(b'\n', &mut buf).map_err(Error::Io)?;
if buf.ends_with(b"\r\n") { buf.truncate(buf.len() - 2); }
else if buf.ends_with(b"\n") { buf.truncate(buf.len() - 1); }
let s = String::from_utf8(buf).map_err(|_| Error::PassphraseInvalidInput)?;
return Ok(Passphrase::from_string(s));
```

**Contract with callers:** `BorrowedFd::borrow_raw` does not take ownership. The owned `File` used internally is a *duplicated* handle (via `try_clone_to_owned`), so its drop closes only the duplicate. The caller's original fd remains open after `resolve_passphrase` returns — verified at runtime by `fd_remains_open_after_resolve`.

### src/identity.rs — file branch strip rewrite

Replaced `fs::read_to_string(path) → .trim_end_matches('\n').trim_end_matches('\r')` (greedy — silently corrupted trailing spaces and bare CR) with `fs::read(path) → ends_with check → truncate → String::from_utf8`. File-mode 0600/0400 check unchanged at lines 299-303.

### Strip-rule truth table (D-P5-08)

The new behavior for the six load-bearing cases:

| Input bytes | Old behavior (greedy) | New behavior (exact) | Delta |
|---|---|---|---|
| `b"hunter2\r\n"` | `"hunter2"` | `"hunter2"` | — |
| `b"hunter2\n"` | `"hunter2"` | `"hunter2"` | — |
| `b"hunter2\n\n"` | `"hunter2"` | `"hunter2\n"` | **FIXED** (was eating both LFs) |
| `b"hunter2 "` | `"hunter2 "` | `"hunter2 "` | — (old code already preserved; strip was only for \n/\r) |
| `b"hunter2"` | `"hunter2"` | `"hunter2"` | — |
| `b"hunter2\r"` | `"hunter2"` | `"hunter2\r"` | **FIXED** (bare CR no longer silently stripped) |

The two "FIXED" rows above were the silent passphrase-corruption paths before this plan. Combined with the fd branch's matching rewrite, both the file and fd input surfaces now apply the same exact strip rule.

### tests/passphrase_strip_rule.rs (NEW — 6 tests)

Each row of the truth table is a distinct `#[test]` function: `strip_crlf`, `strip_lf`, `strip_one_of_two_lf`, `preserve_trailing_space`, `preserve_no_trailer`, `preserve_bare_cr`. The helper `strip_case(&[u8]) -> String` writes bytes to a tempfile at mode 0600 and routes through `resolve_passphrase(None, None, Some(&path), None, false)` — the `None` for env_var_name is load-bearing, so the file-branch is taken deterministically even if `CIPHERPOST_PASSPHRASE` leaks in from CI. No `#[serial]` needed because no process env is mutated.

### tests/passphrase_fd_borrowed.rs (NEW — 2 tests, both `#[serial]`)

- `fd_remains_open_after_resolve`: constructs a real pipe with `libc::pipe`, writes `"hunter2\n"` to the write end (closes write end → EOF for the reader), passes the read end's fd into `resolve_passphrase`, asserts (a) `pw.expose() == "hunter2"` (strip rule fired correctly), and (b) `fcntl(read_fd, F_GETFD) != -1` (caller's fd is still open — Pitfall #31).
- `fd_zero_rejected`: asserts `resolve_passphrase(None, None, None, Some(0), false)` returns `Err(Error::Config(_))` (D-P5-03).

Both tests carry `#[serial]` per the CLAUDE.md load-bearing lock-in — process-global fd table + env are serial-test-only.

### Cargo.toml — libc dev-dep

`libc = "0.2"` added under `[dev-dependencies]`. Used only by the new fd-lifecycle test (pipe / write / close / fcntl / F_GETFD). MIT/Apache-2.0 — covered by the existing deny.toml license allowlist.

## Migration note for users

Users who have a passphrase file containing `"hunter2\n\n"` (two trailing newlines — e.g., from a text editor that auto-appends a blank line) previously unlocked successfully as `"hunter2"`. After this plan, they unlock as `"hunter2\n"` and will get `Error::DecryptFailed` (exit 4) against their existing identity.

Mitigation: re-generate the pw file with `printf '%s' "$PW" > pw.txt` (no trailing newline) or `echo "$PW" > pw.txt` (exactly one trailing LF — stripped correctly). This was documented in the plan's D-P5-07 migration note; expected impact is very low (standard `echo`-produced pw files are unaffected).

## Identity generate/show inherit transparently

`src/main.rs`'s `IdentityCmd::Generate` / `Show` dispatchers already called `resolve_passphrase` with all four sources. They get the BorrowedFd / exact-strip / fd=0-rejection fixes with zero code change in their paths. This is the `D-P5-07` "one code path" property being banked on Plan 05-02 will plumb the same call-site pattern through `send` and `receive`.

## Grep invariants proved green

- `! grep "FromRawFd" src/identity.rs` → 0 hits (old unsafe import deleted)
- `! grep "std::mem::forget" src/identity.rs` → 0 hits
- `! grep -E "trim_end_matches\([^)]*\\\\[rn]|trim_end_matches\([^)]*'\\\\[rn]'" src/identity.rs` → 0 hits (no newline-trim variants remain)
- `grep -c "BorrowedFd" src/identity.rs` → 3 (use stmt + `borrow_raw` + `try_clone_to_owned` call site)
- `grep -c "passphrase-fd 0" src/identity.rs` → 1 (rejection message)
- `! grep "AsRawFd" tests/passphrase_fd_borrowed.rs` → 0 hits (unused import not introduced)
- `! grep "BorrowedFd" tests/passphrase_fd_borrowed.rs` → 0 hits (test uses the public API through `Option<i32>`, not the Rust type)
- `grep -c "#[serial]" tests/passphrase_fd_borrowed.rs` → 2
- `grep -c "#[serial]" tests/passphrase_strip_rule.rs` → 0 (intentional — no env mutation)
- `grep -c "libc = " Cargo.toml` → 1

## Verification gates — all green

| Gate | Result |
|---|---|
| `cargo build --release` | exit 0 |
| `cargo test` (default features) | 75 passed, 0 failed |
| `cargo test --features mock` | 94 passed, 0 failed |
| `cargo test --test passphrase_strip_rule` | 6 passed, 0 failed |
| `cargo test --test passphrase_fd_borrowed` | 2 passed, 0 failed |
| `cargo fmt --check` | exit 0 |
| `cargo clippy -- -D warnings` | exit 0 |
| `cargo clippy --tests -- -D warnings` | exit 0 (WARNING-10 check clean — no unused imports) |

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 — Clarity-of-invariant vs strict grep]  Rephrased two comments in tests/passphrase_fd_borrowed.rs to omit the literal string "BorrowedFd"**

- **Found during:** Task 3 invariant check.
- **Issue:** The plan's `<done>` block for Task 3 asserts `! grep -q "BorrowedFd" tests/passphrase_fd_borrowed.rs` (strict literal grep). The initial file had two comments — the module docstring and an inline assertion comment — that referenced `BorrowedFd` as a documentation pointer to Pitfall #31. The comments tripped the grep even though the test itself (a) does not `use` the type and (b) does not annotate any binding with it — it exercises `resolve_passphrase`'s public API via `Option<i32>`.
- **Fix:** Rephrased both comments to reference "the fd branch must borrow, not take ownership" and cite "Pitfall #31" by name, without naming the Rust type. Intent of the invariant (no import / no type reference) is preserved; readability for future maintainers is preserved.
- **Files modified:** `tests/passphrase_fd_borrowed.rs` (two comment lines only — no logic change).
- **Commit:** 378b435 (committed as part of Task 3, before the comment edits; edits were on the same set of untracked-then-committed lines).

**2. [Rule 3 — Cargo.lock completeness] Separate commit for Cargo.lock**

- **Found during:** Task 3 commit staging.
- **Issue:** Adding `libc = "0.2"` to `[dev-dependencies]` mutates `Cargo.lock`; I staged `Cargo.toml` for commit but not `Cargo.lock`, producing an inconsistent working tree.
- **Fix:** Followed the task_commit_protocol prefer-new-commit rule and added a `chore(05-01): update Cargo.lock for libc dev-dep` commit (`353000a`). Hash appears as TASK3B_HASH. No git history rewrite.
- **Files modified:** `Cargo.lock`.
- **Commit:** 353000a.

No architectural (Rule 4) changes. No out-of-scope fixes.

## Commits

| Hash | Subject | Files |
|---|---|---|
| 85043cb | refactor(05-01): rewrite resolve_passphrase fd+file branches (BorrowedFd, exact strip, fd=0 reject) | src/identity.rs |
| 1dbb3c6 | test(05-01): add passphrase_strip_rule.rs (D-P5-08 six-case truth table) | tests/passphrase_strip_rule.rs, Cargo.toml |
| 378b435 | test(05-01): add passphrase_fd_borrowed.rs (fd-lifecycle + fd=0 reject) and libc dev-dep | tests/passphrase_fd_borrowed.rs, Cargo.toml |
| 353000a | chore(05-01): update Cargo.lock for libc dev-dep | Cargo.lock |

## Requirements satisfied

- **PASS-02** — BorrowedFd lifetime: `tests/passphrase_fd_borrowed.rs::fd_remains_open_after_resolve` is the runtime witness.
- **PASS-07** — Exact one-newline strip: `tests/passphrase_strip_rule.rs` is the six-case truth table; `src/identity.rs` lines 271-314 are the implementation.

## Forward pointers (for Plan 05-02)

- The `resolve_passphrase` signature is unchanged. Plan 05-02 threads `passphrase`, `passphrase_file`, `passphrase_fd` through send/receive's clap structs + dispatchers, reusing the same call-site shape (see `src/main.rs` IdentityCmd::Generate dispatch).
- The `Error::Config` variant is the bucket for the upcoming D-P5-04 multi-source conflict ("--passphrase-file and --passphrase-fd are mutually exclusive"). No new error variant needed.
- `assert_cmd` + `predicates` are already wired for CLI-exit-code tests (used by `tests/identity_passphrase_argv_rejected.rs`); Plan 05-02's `tests/pass09_scripted_roundtrip.rs` and send/receive argv-rejection tests should follow the same pattern.

## Self-Check: PASSED

- [x] `src/identity.rs` exists and contains `BorrowedFd`, `passphrase-fd 0`, no `FromRawFd`, no `std::mem::forget`.
- [x] `tests/passphrase_strip_rule.rs` exists with 6 `#[test]` functions named per the plan; no `#[serial]`.
- [x] `tests/passphrase_fd_borrowed.rs` exists with 2 `#[test]` functions, both `#[serial]`, no `AsRawFd` / `BorrowedFd`.
- [x] `Cargo.toml` has `libc = "0.2"` under `[dev-dependencies]`.
- [x] Commits 85043cb, 1dbb3c6, 378b435, 353000a are in `git log`.
- [x] No `cargo test` regression (75 passed, 0 failed; 94 passed, 0 failed under `--features mock`).
