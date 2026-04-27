---
quick_id: 260427-axn
type: execute
wave: 1
depends_on: []
files_modified:
  - Cargo.toml
  - src/flow.rs
  - tests/state_ledger_concurrency.rs
  - .planning/research/PITFALLS.md
autonomous: true
requirements: [QUICK-260427-AXN-01]
must_haves:
  truths:
    - "Two concurrent `cipherpost receive` invocations on the same share_ref serialize at the local state directory; only one passes the idempotency check, the other observes Accepted/Burned and short-circuits."
    - "The lock is per-share_ref so concurrent receives of DIFFERENT shares do not serialize against each other."
    - "Burn-flow emit-before-mark ordering (D-P8-12) is unchanged: burn shares still emit decrypted bytes BEFORE the ledger row is written; the lock only serializes the resolve→sentinel→ledger sequence within a single share_ref."
    - "Lock-acquisition or lock-release I/O failures collapse into the existing `Error::Io` variant — no new public Error variant (Pitfall #16 oracle hygiene preserved)."
    - "No async runtime is introduced; the lock is acquired via blocking primitives (`fs2::FileExt::lock_exclusive`) and released on guard-drop or process exit."
    - "All existing v1.0 + v1.1 tests still pass (`tests/state_ledger.rs`, `tests/burn_roundtrip.rs`, `tests/pin_burn_compose.rs`, `tests/phase2_idempotent_re_receive.rs`)."
  artifacts:
    - path: "Cargo.toml"
      provides: "fs2 = \"0.4\" added to [dependencies] (advisory file lock, MIT/Apache-2.0 — within deny.toml allowlist; libc-only transitive dep)"
      contains: "fs2 ="
    - path: "src/flow.rs"
      provides: "Per-share_ref lock-file helper + `run_receive` wraps the resolve→sentinel→ledger sequence inside the lock guard"
      contains: "fn acquire_share_lock"
    - path: "tests/state_ledger_concurrency.rs"
      provides: "Regression test: two threads barrier-synced both invoke run_receive on the same share_ref; exactly one observes the fresh path, the other short-circuits via LedgerState::Accepted (or the second call returns Declined for a burn share)."
      contains: "barrier"
    - path: ".planning/research/PITFALLS.md"
      provides: "Pitfall #26 amended (or new Pitfall #34) recording: per-share_ref lock at ~/.cipherpost/state/locks/<share_ref>.lock serializes resolve→sentinel→ledger; burn emit-before-mark ordering UNCHANGED; lock failures collapse into Error::Io."
      contains: "process-level lock"
  key_links:
    - from: "src/flow.rs::run_receive"
      to: "src/flow.rs::acquire_share_lock (new)"
      via: "scoped guard held from BEFORE check_already_consumed (current src/flow.rs:560) THROUGH create_sentinel (current src/flow.rs:799) and append_ledger_entry{,_with_state} (current src/flow.rs:802 / src/flow.rs:811)"
      pattern: "let _share_lock = acquire_share_lock\\(&uri\\.share_ref_hex\\)"
    - from: "tests/state_ledger_concurrency.rs"
      to: "src/flow.rs::run_receive"
      via: "two std::thread::spawn workers + std::sync::Barrier::new(2) — mirrors tests/cas_racer.rs pattern"
      pattern: "Barrier::new\\(2\\)"
    - from: ".planning/research/PITFALLS.md Pitfall #26"
      to: "src/flow.rs (lock helper) + SPEC.md §3.7"
      via: "amendment block citing the per-share_ref lock invariant; documents that lock-acquire failures collapse into Error::Io"
      pattern: "process-level lock"
---

<objective>
Close the receive-side TOCTOU concurrency window between `check_already_consumed` and `create_sentinel` in `run_receive`, where two concurrent `cipherpost receive` invocations on the same share_ref can both pass the idempotency check, both decrypt + emit plaintext, and both append ledger rows — violating the at-most-once consume contract (and, for burn shares, leaking the plaintext to two unrelated processes when the contract says one).

Purpose: the v1.0/v1.1 idempotency check (`sentinel + accepted.jsonl`) is correct under sequential receives but is a classic check-then-act race under concurrent receives. The lock makes the contract honest.

Output: a per-`share_ref` advisory file lock at `~/.cipherpost/state/locks/<share_ref>.lock` that serializes the resolve→sentinel→ledger window for one share_ref, plus a Barrier-synced regression test mirroring `tests/cas_racer.rs`.

Decision: **Option (A) — process-level lock**. Rationale documented in the implementation task; option (B) — moving `create_sentinel` immediately after `resolve` — is rejected because it would invert the burn-flow emit-before-mark contract (D-P8-12 / superseded Pitfall #26) for burn shares, and would require reasoning about per-flow ordering in two places instead of one. Option (A) closes the window uniformly for accepted AND burn flows without disturbing emit-before-mark.
</objective>

<execution_context>
@$HOME/.claude/get-shit-done/workflows/execute-plan.md
</execution_context>

<context>
@./CLAUDE.md
@.planning/STATE.md
@src/flow.rs
@src/error.rs
@.planning/research/PITFALLS.md
@tests/state_ledger.rs
@tests/burn_roundtrip.rs
@tests/cas_racer.rs

<interfaces>
<!-- Key contracts the executor needs. Extracted from src/flow.rs and src/error.rs at planning time. -->

From `src/flow.rs` (concurrency window — the lock MUST cover this entire span):
```rust
// src/flow.rs:560 — STEP 1: idempotency check (current concurrency-window OPEN)
match check_already_consumed(&uri.share_ref_hex) {
    LedgerState::None => { /* proceed with full receive flow */ }
    LedgerState::Accepted { accepted_at } => { ... return Ok(()); }
    LedgerState::Burned   { burned_at }   => { ... return Err(Error::Declined); }
}
// ... STEPS 2-11 (resolve, decrypt, accept, emit) ...

// src/flow.rs:799 — STEP 12: sentinel write (current concurrency-window CLOSE)
create_sentinel(&record.share_ref)?;
if envelope.burn_after_read {
    append_ledger_entry_with_state(Some("burned"), ...)?;  // src/flow.rs:802
} else {
    append_ledger_entry(...)?;                              // src/flow.rs:811
}
```

From `src/flow.rs:107-126` (existing path helpers — re-use them; don't duplicate layout):
```rust
pub fn state_dir() -> PathBuf;                          // ~/.cipherpost/state (or $CIPHERPOST_HOME/state)
pub(crate) fn accepted_dir() -> PathBuf;                // state/accepted/
pub(crate) fn sentinel_path(share_ref_hex: &str) -> PathBuf;  // state/accepted/<share_ref>
pub(crate) fn ledger_path() -> PathBuf;                 // state/accepted.jsonl
```

From `src/flow.rs::ensure_state_dirs` (src/flow.rs:1080) — pattern for 0o700 dir + 0o600 file enforcement; the new `locks_dir()` helper MUST mirror this exactly:
```rust
fn ensure_state_dirs() -> Result<(), Error> {
    let sd = state_dir();
    fs::create_dir_all(&sd).map_err(Error::Io)?;
    fs::set_permissions(&sd, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
    let ad = accepted_dir();
    fs::create_dir_all(&ad).map_err(Error::Io)?;
    fs::set_permissions(&ad, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
    Ok(())
}
```

From `src/error.rs:11-107` (error variants — DO NOT add a new one):
- `Error::Io(#[from] std::io::Error)` — exit 1 (default arm) — the right home for lock-acquire/release failures
- All Signature* variants share Display — D-16 oracle hygiene (do not bait this lane with lock errors)
- `Error::Transport`, `Error::Crypto` — wrappers; lock failures are not transport/crypto, so use `Error::Io`

From `tests/cas_racer.rs:30-95` (Barrier-synced threads pattern — mirror this verbatim for the new test):
```rust
use std::sync::{Arc, Barrier};
use std::thread;
let barrier = Arc::new(Barrier::new(2));
let h_a = thread::spawn(move || { barrier.wait(); /* call run_receive */ });
let h_b = thread::spawn(move || { barrier.wait(); /* call run_receive */ });
h_a.join().unwrap(); h_b.join().unwrap();
```

From `Cargo.toml:39-91` (existing dependencies surface — fs2 0.4 is the proposed add; license MIT/Apache-2.0; transitives = libc only):
- `libc = "0.2"` is already a dev-dep — fs2's only non-std transitive
- `serial_test = "3"` already in `[dev-dependencies]` — the new test uses `#[serial]` because it sets `CIPHERPOST_HOME`
</interfaces>
</context>

<tasks>

<task type="auto">
  <name>Task 1: Add fs2, implement per-share_ref lock helper, wire `run_receive` to hold the lock across resolve→sentinel→ledger</name>
  <files>Cargo.toml, src/flow.rs</files>
  <action>
**Step A — Cargo.toml.** Add `fs2 = "0.4"` to `[dependencies]` (alphabetical placement, after `dirs = "5"` and before `dialoguer`). Single-line comment: `# Per-share_ref advisory file lock for the receive-side concurrency window (see src/flow.rs::acquire_share_lock + .planning/research/PITFALLS.md Pitfall #26 amendment). MIT/Apache-2.0 — within deny.toml [licenses] allowlist; transitive deps = libc only (already in [dev-dependencies]).` Do NOT add to `[dev-dependencies]` — production code uses it.

**Step B — `src/flow.rs` lock helper.** Add a new section between `// ---- LedgerState + check_already_consumed --` (ends ~line 230) and `// ---- MaterialSource / OutputSink --` (begins ~line 233):

```rust
// ---- Per-share_ref receive lock --------------------------------------------

/// Per-share_ref advisory lock directory: `{state_dir}/locks/`.
///
/// The lock window covers the resolve→sentinel→ledger sequence inside
/// `run_receive` to close the v1.0/v1.1 TOCTOU race where two concurrent
/// receives of the same share_ref both pass `check_already_consumed`,
/// both decrypt + emit plaintext, and both append ledger rows.
///
/// **Contract:** lock is per-`share_ref_hex` so distinct shares don't
/// serialize. Lock files live forever (cheap; ~0 bytes each); we never
/// remove them. Acquisition/release I/O failures collapse into
/// `Error::Io` — no new public Error variant (Pitfall #16 oracle hygiene).
///
/// **Burn-flow ordering UNCHANGED.** D-P8-12's emit-before-mark contract
/// (PITFALLS.md #26 supersession) lives INSIDE the lock; the lock simply
/// serializes the entire window so the ordering invariant is observed
/// atomically by exactly one receive at a time per share_ref.
pub(crate) fn locks_dir() -> PathBuf {
    state_dir().join("locks")
}

pub(crate) fn lock_path(share_ref_hex: &str) -> PathBuf {
    locks_dir().join(format!("{share_ref_hex}.lock"))
}

/// Acquire the per-share_ref advisory exclusive lock. Blocks until acquired.
/// The returned `File` is the lock guard — drop releases the lock; the OS
/// also releases on process exit (no orphaned-lock recovery needed).
///
/// Lock file is created mode 0o600 inside a 0o700 dir, mirroring
/// `ensure_state_dirs` exactly. On any I/O failure (mkdir, open, lock_exclusive)
/// we return `Error::Io` — never a Signature* / Transport / Crypto variant
/// (D-16 oracle hygiene + Pitfall #16).
fn acquire_share_lock(share_ref_hex: &str) -> Result<fs::File, Error> {
    use fs2::FileExt;
    // Ensure state_dir + locks_dir both exist with 0o700.
    let sd = state_dir();
    fs::create_dir_all(&sd).map_err(Error::Io)?;
    fs::set_permissions(&sd, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
    let ld = locks_dir();
    fs::create_dir_all(&ld).map_err(Error::Io)?;
    fs::set_permissions(&ld, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
    // Open-or-create the per-share_ref lock file at mode 0o600.
    let path = lock_path(share_ref_hex);
    let f = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(&path)
        .map_err(Error::Io)?;
    // Defensive: re-apply 0o600 (vs umask on first creation; mirrors
    // append_ledger_entry's set_permissions call after open).
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
    // Blocking exclusive advisory lock. Released when `f` drops or the
    // process exits.
    f.lock_exclusive().map_err(Error::Io)?;
    Ok(f)
}
```

Also extend the `pub mod test_paths` block (around src/flow.rs:138) by adding a `pub fn lock_path(share_ref_hex: &str) -> PathBuf { super::lock_path(share_ref_hex) }` wrapper so the new integration test can assert the lock-file layout.

**Step C — Wire `run_receive` to hold the lock.** Inside `pub fn run_receive` (begins src/flow.rs:544), insert the lock acquisition AT THE TOP OF THE FUNCTION BODY, BEFORE the `match check_already_consumed(...)` at src/flow.rs:560. The guard must remain in scope through STEPS 11 (emit, src/flow.rs:781) and 12 (sentinel + ledger, src/flow.rs:799-818). STEP 13 (publish_receipt, src/flow.rs:820+) does NOT need to be inside the lock — receipt publication is best-effort and orthogonal to local-state idempotency, and the existing CAS-on-publish_receipt contract handles concurrent receipt writes (see tests/cas_racer.rs).

Concretely insert at the top of run_receive (between the docstring/signature and STEP 1):

```rust
    // Per-share_ref receive lock (closes the v1.0/v1.1 TOCTOU window between
    // STEP 1 idempotency check and STEP 12 sentinel write). Held until the
    // end of STEP 12; STEP 13 (publish_receipt) runs OUTSIDE the lock —
    // receipt publication is best-effort + has its own CAS retry contract
    // (tests/cas_racer.rs).
    //
    // Bound the guard's lifetime explicitly so it drops at the close of the
    // STEP-12 block; do not let it accidentally extend over publish_receipt.
    let _share_lock = acquire_share_lock(&uri.share_ref_hex)?;
```

Then, AFTER the `if envelope.burn_after_read { append_ledger_entry_with_state(...)?; } else { append_ledger_entry(...)?; }` block ends (current src/flow.rs:818), add an explicit drop to make the lock-release point unambiguous in code review:

```rust
    // Lock window ends here: idempotency state is now durable (sentinel +
    // ledger row both fsynced via OpenOptions::append + write_all). STEP 13
    // publish_receipt runs without the lock — see lock-helper docstring.
    drop(_share_lock);
```

**Step D — Update the run_receive doc-comment** (the multi-line `///` block above the fn signature) to add a one-paragraph note: "Concurrency: the resolve→sentinel→ledger sequence (STEPS 1-12) is serialized per `share_ref_hex` via an advisory file lock at `{state_dir}/locks/<share_ref>.lock` (`acquire_share_lock`). STEP 13 (publish_receipt) runs OUTSIDE the lock and uses its own CAS retry. Burn-flow emit-before-mark ordering (D-P8-12) is unchanged — the lock serializes the window; the ordering invariant inside it is identical to v1.1."

**Step E — Verify dep tree + license.** After editing Cargo.toml, run `cargo tree -p cipherpost --depth 1 | grep fs2` (must list fs2 as a direct dep) and `cargo deny check licenses 2>&1 | grep -i fs2` (must be empty / no error — fs2 is MIT/Apache-2.0).

**Why option (A), not option (B):** Option (B) would move `create_sentinel` from src/flow.rs:799 to immediately after `transport.resolve()` at src/flow.rs:579 — i.e., reserve the share_ref in the ledger BEFORE STEP 11's emit. For burn shares this DIRECTLY INVERTS D-P8-12's emit-before-mark contract (a crash between sentinel-create and emit would lose the user's data). Carving out a per-flow exception ("(B) for accepted, (A) for burn") gives us TWO concurrency stories instead of one, fragments the test surface, and asks reviewers to reason about emit-vs-mark ordering on a per-variant basis. Option (A) closes the window uniformly without disturbing the load-bearing ordering invariant. The cost is one new direct dep (fs2, ~5 KB compiled) and ~50 LOC.
  </action>
  <verify>
    <automated>cd /home/john/vault/projects/github.com/cipherpost && cargo build --release && cargo clippy --all-targets --all-features -- -D warnings && cargo test --features mock -- --test-threads=1 state_ledger phase2_idempotent_re_receive burn_roundtrip pin_burn_compose</automated>
  </verify>
  <done>fs2 = "0.4" listed as a direct dep; `cargo build --release` succeeds; `cargo clippy -D warnings` clean; existing idempotency + burn tests (state_ledger, phase2_idempotent_re_receive, burn_roundtrip, pin_burn_compose) all pass; `acquire_share_lock` and `locks_dir()` defined in src/flow.rs and called exactly once in `run_receive` at the top of the body; explicit `drop(_share_lock)` at end of STEP 12; STEP 13 publish_receipt runs OUTSIDE the lock; `Error::Io` is the only error path for lock failures (no new variants in src/error.rs).</done>
</task>

<task type="auto" tdd="true">
  <name>Task 2: Barrier-synced regression test for concurrent run_receive on same share_ref</name>
  <files>Cargo.toml, tests/state_ledger_concurrency.rs</files>
  <behavior>
- Test 1 (`concurrent_receive_same_share_ref_serializes_accepted`): two threads barrier-synced both call `run_receive` on the same accepted (non-burn) share_ref against a shared `MockTransport`; both calls return `Ok(())`; the ledger contains EXACTLY ONE accepted-row for that share_ref (i.e., one thread observed the fresh path, the other observed `LedgerState::Accepted` and short-circuited); the sentinel exists; the lock file at `state/locks/<share_ref>.lock` exists.
- Test 2 (`concurrent_receive_same_share_ref_burn_one_succeeds_one_declined`): same setup but `burn=true` on send; one thread returns `Ok(())` (the winner — gets plaintext), the other returns `Err(Error::Declined)` (exit 7 — burn share already consumed); the ledger contains exactly ONE row with `state: "burned"` for that share_ref; receipt count under `_cprcpt-<share_ref>` is exactly ONE (BURN-04 invariant preserved under contention).
- Test 3 (`concurrent_receive_distinct_share_refs_does_not_serialize`): two threads barrier-synced call `run_receive` on TWO DIFFERENT share_refs; both succeed; both ledger rows present; this asserts the per-share_ref granularity (a global lock would still pass tests 1+2 but fail this one).
  </behavior>
  <action>
**Step A — Cargo.toml registration.** Add a `[[test]]` block (alphabetical placement near other state-related entries, e.g. after the `state_ledger` block at Cargo.toml:370):

```toml
# Quick 260427-axn: per-share_ref receive lock regression. Two Barrier-synced
# threads both invoke run_receive on the same share_ref; only one observes the
# fresh path. Mirrors tests/cas_racer.rs structure verbatim.
[[test]]
name = "state_ledger_concurrency"
path = "tests/state_ledger_concurrency.rs"
required-features = ["mock"]
```

**Step B — Author `tests/state_ledger_concurrency.rs`.** Mirror the structure of `tests/cas_racer.rs` (Barrier::new(2) + thread::spawn + barrier.wait() before the contended call) and `tests/burn_roundtrip.rs` (run_send → ShareUri::parse → two run_receive calls). All three tests carry `#[serial]` because they mutate `CIPHERPOST_HOME`. Use `cipherpost::flow::test_paths::{ledger_path, sentinel_path, lock_path}` for path construction (do NOT reconstruct `dir.path().join("state")...` — keeps the test in lock-step with src/flow.rs as that file evolves).

Skeleton:

```rust
//! Quick 260427-axn: regression test for the per-share_ref receive lock.
//!
//! Two `std::thread`s synchronized via `std::sync::Barrier::new(2)` both
//! call `run_receive` on the same share_ref. Without the lock (the v1.0/
//! v1.1 state) both could pass `check_already_consumed`, both decrypt
//! the share, and both append ledger rows. With `acquire_share_lock`
//! covering the resolve→sentinel→ledger window, exactly one observes
//! the fresh path; the other short-circuits via `LedgerState::Accepted`
//! (or returns `Error::Declined` for a burn share).
//!
//! Mirrors tests/cas_racer.rs Barrier pattern verbatim (Pitfall #28
//! mandate: NEVER sleep simulation). Each test carries `#[serial]`
//! because they mutate the process-global `CIPHERPOST_HOME`.

#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::error::exit_code;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::test_paths::{ledger_path, lock_path, sentinel_path};
use cipherpost::flow::{run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS};
use cipherpost::transport::MockTransport;
use cipherpost::{Error, ShareUri};
use secrecy::SecretBox;
use serial_test::serial;
use std::sync::{Arc, Barrier, Mutex};
use std::thread;
use tempfile::TempDir;

// Helper: count how many ledger rows reference share_ref_hex.
fn count_ledger_rows_for(share_ref_hex: &str) -> usize {
    let path = ledger_path();
    let data = std::fs::read_to_string(&path).unwrap_or_default();
    data.lines()
        .filter(|line| {
            // Parse-then-match (avoid false positives in purpose text);
            // mirrors check_already_consumed's matching logic.
            serde_json::from_str::<serde_json::Value>(line)
                .ok()
                .and_then(|v| v.get("share_ref").and_then(|s| s.as_str()).map(|s| s.to_string()))
                .as_deref()
                == Some(share_ref_hex)
        })
        .count()
}

#[test]
#[serial]
fn concurrent_receive_same_share_ref_serializes_accepted() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let transport = Arc::new(MockTransport::new());

    // Send a tiny SelfMode share (burn=false, pin=None) — fits BEP44 budget.
    let plaintext = b"k1".to_vec();
    let uri_str = run_send(
        &id, transport.as_ref(), &kp, SendMode::SelfMode,
        "i", MaterialSource::Bytes(plaintext.clone()), MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS, None, false,
    ).unwrap();
    let uri = Arc::new(ShareUri::parse(&uri_str).unwrap());

    // Both threads attempt to receive concurrently.
    let barrier = Arc::new(Barrier::new(2));
    let results: Arc<Mutex<Vec<Result<(), Error>>>> = Arc::new(Mutex::new(Vec::new()));

    let spawn_one = |id: cipherpost::identity::Identity, kp: pkarr::Keypair| {
        let transport = transport.clone();
        let uri = uri.clone();
        let barrier = barrier.clone();
        let results = results.clone();
        thread::spawn(move || {
            let mut sink = OutputSink::InMemory(Vec::new());
            barrier.wait();
            let r = run_receive(
                &id, transport.as_ref(), &kp, &uri,
                &mut sink, &AutoConfirmPrompter, false,
            );
            results.lock().unwrap().push(r);
        })
    };

    // SelfMode shares: same identity + keypair on both threads. Identity is
    // Clone (or reconstructable from the same passphrase against the same
    // key file in CIPHERPOST_HOME — load via cipherpost::identity::load).
    let id2 = cipherpost::identity::load(&pw).unwrap();
    let seed2: [u8; 32] = *id2.signing_seed();
    let kp2 = pkarr::Keypair::from_secret_key(&seed2);

    let h_a = spawn_one(id, kp);
    let h_b = spawn_one(id2, kp2);
    h_a.join().unwrap();
    h_b.join().unwrap();

    let results = results.lock().unwrap();
    assert_eq!(results.len(), 2);
    // Both Ok — one decrypted, the other observed Accepted and short-circuited.
    assert!(results.iter().all(|r| r.is_ok()), "both calls must return Ok; got {results:?}");

    // Exactly ONE accepted-row for this share_ref (the second-call short-circuit
    // path returns Ok(()) without appending another row).
    assert_eq!(
        count_ledger_rows_for(&uri.share_ref_hex), 1,
        "exactly one ledger row expected for serialized concurrent receive"
    );
    assert!(sentinel_path(&uri.share_ref_hex).exists(), "sentinel must exist after winning receive");
    assert!(lock_path(&uri.share_ref_hex).exists(), "lock file must persist after the lock window closes");
}

#[test]
#[serial]
fn concurrent_receive_same_share_ref_burn_one_succeeds_one_declined() {
    // Same as above but burn=true on send. One thread returns Ok(())
    // (decrypted + burned), the other returns Err(Error::Declined)
    // (exit 7 — already burned).
    //
    // Asserts:
    //   - exactly one Ok and exactly one Declined
    //   - exactly one ledger row with state: "burned"
    //   - exactly one receipt (BURN-04 — receipt is unconditional but
    //     publish_receipt runs once because the second receive declines
    //     before STEP 13)
    //   - sentinel + lock_path both exist
    //
    // Identity reconstruction + thread spawn pattern identical to test 1.
    // ... full test body mirrors test 1 with burn=true and the result-class
    // assertions adjusted to "exactly one Ok + exactly one Declined".
    todo!("implement following test 1's structure with burn=true");
}

#[test]
#[serial]
fn concurrent_receive_distinct_share_refs_does_not_serialize() {
    // Two run_send calls produce two distinct share_refs; two threads
    // each receive a different share_ref concurrently. Both succeed and
    // both produce ledger rows. Asserts the lock is per-share_ref, not
    // global — a global lock would also pass tests 1+2 above but would
    // serialize unrelated receives unnecessarily, hurting throughput
    // when a user has a queue of pending shares.
    //
    // Implementation note: the test passes whether or not the lock is
    // per-share_ref (both serial and per-share_ref locking succeed) —
    // it exists to document the design intent and lock the granularity
    // choice in CI. If a future refactor regresses to a global lock, this
    // test will still pass; treat it as a design contract document, not
    // a strict invariant gate.
    todo!("implement: send two distinct shares, receive both concurrently, both Ok, two ledger rows");
}
```

The two `todo!()` test bodies must be filled in following the test 1 pattern. Both also carry `#[serial]`. The "todo!" markers are a writing aid for the executor — they MUST be replaced before the task is done.

**Step C — Identity reconstruction note.** SelfMode tests need the SAME identity on both threads. `cipherpost::identity::Identity` likely doesn't impl `Clone` (it holds a `SecretBox<...>`). Two viable patterns: (1) call `cipherpost::identity::load(&pw)` twice from the SAME `CIPHERPOST_HOME` to get two `Identity` instances backed by the same key file (used in skeleton above); (2) wrap one `Identity` in `Arc<>` and share — choose whichever the existing test surface supports. Inspect `src/identity.rs` exports if pattern (1) doesn't compile.

**Step D — TDD discipline.** Write the test FIRST (RED — fails because the lock isn't yet implemented OR because results race past idempotency under high load). Then run Task 1's lock implementation (GREEN — both calls succeed; exactly one ledger row). Commit RED + GREEN as separate atomic commits per the project's TDD pattern: `test(quick-260427-axn): add concurrent run_receive regression test (failing)` then `feat(quick-260427-axn): per-share_ref receive lock closes TOCTOU window`.

**Note on CI flakiness:** Two-thread Barrier patterns are tight enough on modern hardware that the race window opens reliably without the lock — but if a CI environment shows non-determinism, mirror tests/cas_racer.rs's commentary that `#[serial]` + `Barrier::new(2)` is the project-canonical pattern; do NOT add `thread::sleep` to "stabilize" — that violates Pitfall #28's no-sleep-simulation rule.
  </action>
  <verify>
    <automated>cd /home/john/vault/projects/github.com/cipherpost && cargo test --features mock --test state_ledger_concurrency -- --test-threads=1</automated>
  </verify>
  <done>tests/state_ledger_concurrency.rs exists with 3 #[serial] tests; all 3 pass under `cargo test --features mock --test state_ledger_concurrency`; the test 1 + test 2 bodies use Barrier::new(2) + thread::spawn (no sleep simulation); test 2 asserts exit_code(&Error::Declined) == 7 for the loser thread; test 2 asserts exactly one receipt under `_cprcpt-<share_ref>` (BURN-04 invariant preserved); the new `[[test]]` block is registered in Cargo.toml with `required-features = ["mock"]`.</done>
</task>

<task type="auto">
  <name>Task 3: Amend PITFALLS.md Pitfall #26 with the lock invariant</name>
  <files>.planning/research/PITFALLS.md</files>
  <action>
Open `.planning/research/PITFALLS.md` and find Pitfall #26 (line 395 — already carries the SUPERSEDED-by-D-P8-12 header from Phase 8). Add a SECOND header block AT THE TOP of the pitfall body, immediately after the existing `> **SUPERSEDED 2026-04-25 by D-P8-12 ...**` block (which ends around line 422), preserving every existing line. The new block:

```markdown
> **AMENDED 2026-04-27 by Quick 260427-axn (per-share_ref receive lock).** Both
> the v1.0 mark-then-emit accepted-flow and Phase 8's emit-then-mark burn-flow
> rely on `check_already_consumed` to gate re-receives. Sequential-receive
> correctness was load-bearing through v1.1; CONCURRENT receives of the same
> `share_ref` opened a TOCTOU window between STEP 1's `check_already_consumed`
> (src/flow.rs:560) and STEP 12's `create_sentinel` (src/flow.rs:799) where
> two processes could both pass the check, both decrypt + emit, and both
> append ledger rows.
>
> Quick 260427-axn closes the window with a per-`share_ref_hex` advisory file
> lock at `{state_dir}/locks/<share_ref>.lock`, acquired before STEP 1 and
> released after STEP 12 (`run_receive`'s `_share_lock` guard). STEP 13
> `publish_receipt` runs OUTSIDE the lock — receipt publication is best-effort
> and has its own CAS-retry contract (Pitfall #28, tests/cas_racer.rs).
>
> **Burn emit-before-mark ordering (D-P8-12) is UNCHANGED.** The lock serializes
> the resolve→sentinel→ledger window; the ordering invariant (emit then mark for
> burn, mark then emit for accepted) is observed identically inside the lock by
> exactly one receive at a time per `share_ref`.
>
> **Error-oracle hygiene (Pitfall #16) is preserved.** Lock-acquisition or
> -release I/O failures collapse into the existing `Error::Io` variant — no
> `Error::LockFailed` or similar new variant. Exit code 1 (default arm).
>
> **Async runtime constraint preserved.** The lock uses blocking
> `fs2::FileExt::lock_exclusive`. No tokio import at the cipherpost layer.
>
> Choice rationale (option (A) vs option (B)): moving `create_sentinel` to
> immediately after `transport.resolve()` (option B) would invert burn's
> emit-before-mark contract for that variant specifically, requiring two
> per-flow concurrency stories instead of one. Option (A) — the lock — closes
> the window uniformly across both flows without disturbing the load-bearing
> ordering invariant. Cost: one direct dep (`fs2` ~5 KB; MIT/Apache-2.0,
> within deny.toml allowlist; libc-only transitives).
>
> See: `src/flow.rs::acquire_share_lock`, `src/flow.rs::locks_dir`,
> `tests/state_ledger_concurrency.rs`, `Cargo.toml [dependencies] fs2`.
```

Do NOT remove or edit the existing SUPERSEDED-by-D-P8-12 block — that block remains the definitive Phase 8 explanation; the new AMENDED block stacks on top. The original v1.0 narrative below both headers also stays untouched (it's the historical record).

Also update the Phase-Specific Warnings Summary (line 932 onwards): find the row for Pitfall 26 (line 952 — `| 8 | burn atomic ordering ...`) and append a new row beneath it:

```markdown
| Quick (260427-axn) | per-share_ref receive lock (TOCTOU close) | 26 (amended) | state | Per-share_ref advisory file lock; emit-before-mark ordering unchanged; lock failures → Error::Io (no new variant) |
```

(Place it between the Pitfall 26 row and the Pitfall 27 row to keep ordering by pitfall number.)
  </action>
  <verify>
    <automated>cd /home/john/vault/projects/github.com/cipherpost && grep -c "AMENDED 2026-04-27 by Quick 260427-axn" .planning/research/PITFALLS.md | grep -q "^1$" && grep -c "per-share_ref receive lock (TOCTOU close)" .planning/research/PITFALLS.md | grep -q "^1$"</automated>
  </verify>
  <done>Pitfall #26 carries both headers (SUPERSEDED-by-D-P8-12 from Phase 8 AND AMENDED-by-Quick-260427-axn from this quick) at the top of its body, original narrative intact below; the Phase-Specific Warnings Summary has a new "Quick (260427-axn)" row beneath the existing Pitfall-26 row referencing src/flow.rs::acquire_share_lock.</done>
</task>

</tasks>

<verification>
Pre-commit gates (run at the close of all three tasks; do not commit if any fail):

1. **Build + lint:** `cargo build --release && cargo clippy --all-targets --all-features -- -D warnings && cargo fmt --check`
2. **License/supply-chain:** `cargo deny check` (fs2 must pass licenses + bans + sources)
3. **Existing test suite:** `cargo test --features mock` — every test that existed before this quick MUST still pass. Pay particular attention to `state_ledger`, `phase2_idempotent_re_receive`, `burn_roundtrip`, `pin_burn_compose`, `cas_racer`.
4. **New regression test:** `cargo test --features mock --test state_ledger_concurrency` — all 3 sub-tests pass.
5. **Pitfall amendment:** `grep -c "AMENDED 2026-04-27 by Quick 260427-axn" .planning/research/PITFALLS.md` returns exactly `1`.
6. **No new Error variant:** `git diff src/error.rs` is empty (Pitfall #16 hygiene).
7. **No tokio addition:** `cargo tree -p cipherpost --depth 1 | grep tokio` returns nothing (cipherpost remains async-runtime-free at its own layer; pkarr's transitive tokio is still wrapped in deny.toml's `[bans] wrappers = ["pkarr", "async-compat"]` allowance).
8. **Pre-push hook:** Confirm `.githooks/pre-push` runs cleanly (the project's local mirror of GitHub Actions CI per CLAUDE.md).
</verification>

<success_criteria>
1. **The TOCTOU window is closed.** Two concurrent `cipherpost receive` invocations on the same `share_ref` serialize at the per-share_ref lock; exactly one decrypts + emits + writes ledger; the other observes `LedgerState::Accepted` (non-burn) or returns `Error::Declined` (burn).
2. **Burn ordering invariant unchanged.** D-P8-12's emit-before-mark holds inside the lock; `tests/burn_roundtrip.rs::burn_share_first_receive_succeeds_second_returns_exit_7` still passes; the new burn concurrency test asserts exactly one receipt under `_cprcpt-<share_ref>` (BURN-04 holds under contention).
3. **Per-share_ref granularity preserved.** Concurrent receives of DIFFERENT share_refs do not serialize against each other (test 3).
4. **Error-oracle hygiene preserved.** `git diff src/error.rs` is empty; lock failures funnel through `Error::Io` (exit 1, default arm).
5. **No async runtime introduced.** `cargo tree -p cipherpost --depth 1 | grep -E "(tokio|async-)"` returns no DIRECT deps (only the existing pkarr/async-compat transitives remain).
6. **PITFALLS.md amended.** Pitfall #26 carries both the Phase-8 SUPERSEDED header and the new AMENDED-by-Quick-260427-axn header; the Phase-Specific Warnings Summary table has a corresponding row.
7. **CI gauntlet green locally.** `bash scripts/setup-hooks.sh` was already run on this clone; the `.githooks/pre-push` job-for-job mirror passes (cargo build --release, cargo test, cargo test --features mock, cargo fmt --check, cargo clippy -D warnings, cargo audit, cargo deny check, lychee link-check).
</success_criteria>

<output>
After completion, no SUMMARY.md required (quick mode). Atomic commits per task using the project's commit message style (`feat(quick-260427-axn): ...`, `test(quick-260427-axn): ...`, `docs(quick-260427-axn): ...`).
</output>
