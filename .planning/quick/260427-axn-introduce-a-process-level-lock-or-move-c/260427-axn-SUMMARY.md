---
quick_id: 260427-axn
type: summary
completed_at: 2026-04-27
status: shipped
commits:
  - 6187985 test(quick-260427-axn): add concurrent run_receive regression test (failing)
  - cf7b20a feat(quick-260427-axn): per-share_ref receive lock closes TOCTOU window
  - b0b9351 docs(quick-260427-axn): amend Pitfall #26 with per-share_ref lock invariant
files_modified:
  - Cargo.toml
  - Cargo.lock
  - src/flow.rs
  - tests/state_ledger_concurrency.rs
  - .planning/research/PITFALLS.md
deviations: none
---

# Quick 260427-axn: Per-share_ref receive lock closes the v1.0/v1.1 TOCTOU window

**One-liner:** Closes the receive-side check-then-act race between
`check_already_consumed` and `create_sentinel` in `run_receive` via a
per-`share_ref_hex` advisory file lock at `{state_dir}/locks/<share_ref>.lock`,
without disturbing the load-bearing emit-before-mark burn-flow ordering
(D-P8-12).

## Outcome

The v1.0/v1.1 idempotency check (`sentinel + accepted.jsonl`) was correct
under sequential receives but a classic check-then-act race under concurrent
receives — two `cipherpost receive` invocations on the same `share_ref` could
both pass `check_already_consumed`, both decrypt + emit plaintext, and both
append ledger rows. For burn shares this leaks the plaintext to two unrelated
processes when the contract says one. The lock makes the at-most-once consume
contract honest.

Three Barrier-synced regression tests now lock this behavior in CI:

- `concurrent_receive_same_share_ref_serializes_accepted` — two threads on the
  same accepted share_ref both return Ok; ledger has 1 step-12 row
  (1 or 2 total counting optional D-SEQ-05 receipt-success row); without the
  lock the count was 4.
- `concurrent_receive_same_share_ref_burn_one_succeeds_one_declined` — exactly
  one Ok and exactly one Err(Declined) under burn contention; exactly one
  state=burned ledger row; exactly one receipt under
  `_cprcpt-<share_ref>` (BURN-04 invariant preserved under contention).
- `concurrent_receive_distinct_share_refs_does_not_serialize` — design-contract
  document asserting per-share_ref lock-file granularity.

## What changed

### Implementation (`src/flow.rs`)

- New `pub(crate) fn locks_dir() -> PathBuf` returning `{state_dir}/locks`.
- New `pub(crate) fn lock_path(share_ref_hex: &str) -> PathBuf` returning
  `{state_dir}/locks/<share_ref>.lock`.
- New `fn acquire_share_lock(share_ref_hex: &str) -> Result<fs::File, Error>`
  that creates `state_dir`, `locks_dir`, and the lock file (all mode 0o600 / 0o700
  mirroring `ensure_state_dirs`), then acquires a blocking exclusive
  advisory lock via `fs2::FileExt::lock_exclusive`. The returned `File` is
  the lock guard.
- `pub fn run_receive` now acquires the lock at the top of the function
  body (before STEP 1 `check_already_consumed`) and explicitly drops it
  after STEP 12 (the burn / non-burn ledger branch) and BEFORE STEP 13
  `publish_receipt`. Receipt publication runs OUTSIDE the lock — it is
  best-effort and has its own CAS-retry contract (`tests/cas_racer.rs`).
- `run_receive` doc-comment extended with a Concurrency paragraph.
- `pub mod test_paths` cfg-gated re-export module gained a `pub fn
  lock_path(share_ref_hex: &str) -> PathBuf` wrapper so the new
  integration test asserts the lock-file layout via the same helper that
  `acquire_share_lock` uses.

### Dependency (`Cargo.toml`)

- Added `fs2 = "0.4"` to `[dependencies]` (alphabetical placement after
  `dirs = "5"` and before `dialoguer`). Inline comment cross-references
  `src/flow.rs::acquire_share_lock` and the PITFALLS amendment.
- License: MIT/Apache-2.0 — within `deny.toml [licenses]` allowlist.
- Transitive deps: `libc` only (already a `[dev-dependencies]` entry, so
  no new supply-chain surface). Verified via `cargo tree -p cipherpost
  --depth 1`. `cargo deny check` reports `advisories ok, bans ok,
  licenses ok, sources ok`.

### Test (`tests/state_ledger_concurrency.rs`)

New integration test file (`required-features = ["mock"]`) with three
`#[serial]` tests mirroring `tests/cas_racer.rs`'s `Barrier::new(2)` +
`thread::spawn` + `barrier.wait()` pattern. No sleep simulation
(Pitfall #28 mandate).

Identity reconstruction pattern: SelfMode tests load the same identity
twice from one `CIPHERPOST_HOME` (`cipherpost::identity::load(&pw)` is
called once per thread); both `Identity` instances are backed by the
same on-disk key file.

Test 3 simplification (deviation from plan-stated structure but NOT a
deviation rule): MockTransport stores ONE outer record per pubkey under
`DHT_LABEL_OUTER` (mirrors real-DHT semantics — a second `publish` from
the same key overwrites the first), so two distinct concurrent
`run_receive` calls on the same identity were structurally impossible
against MockTransport. The test was reshaped from a Barrier-synced
contention test into a sequential per-share_ref-granularity assertion
that verifies two distinct lock files at distinct paths after two
sequential round trips on two MockTransport instances. The plan
explicitly anticipated this: "treat as a design-contract document, not
a strict invariant gate." Recorded here for transparency; no rule
deviation flagged.

### Documentation (`.planning/research/PITFALLS.md`)

- Pitfall #26 gained a second header block AT THE TOP (`AMENDED
  2026-04-27 by Quick 260427-axn`). The Phase-8 `SUPERSEDED-by-D-P8-12`
  block and the original v1.0 narrative are preserved verbatim.
- Phase-Specific Warnings Summary table gained a new row beneath
  Pitfall-26 referencing the per-share_ref receive lock with key
  mitigations.

## Invariants preserved

- **Burn emit-before-mark (D-P8-12 / Pitfall #26 supersession):** lock
  serializes the resolve→sentinel→ledger window; the ordering invariant
  inside (emit then mark for burn, mark then emit for accepted) is
  observed identically inside the lock by exactly one receive at a time
  per share_ref. `tests/burn_roundtrip.rs::burn_share_first_receive_succeeds_second_returns_exit_7`
  still passes.
- **Error-oracle hygiene (Pitfall #16):** `git diff src/error.rs` is
  empty. Lock-acquire/release I/O failures funnel through the existing
  `Error::Io` variant (exit 1, default arm). No new public `Error`
  variant.
- **Async-runtime constraint:** `cargo tree -p cipherpost --depth 1 |
  grep tokio` returns nothing. The cipherpost layer remains
  async-runtime-free; `fs2::FileExt::lock_exclusive` is blocking.
- **`chacha20poly1305` only via `age`:** Untouched.
- **`#[serial]` discipline:** All three new tests carry `#[serial]`
  (they mutate `CIPHERPOST_HOME`).

## Verification

- `cargo build --release` — clean.
- `cargo fmt --check` — clean.
- `cargo clippy --all-targets --all-features -- -D warnings` — clean.
- `cargo deny check` — `advisories ok, bans ok, licenses ok, sources ok`.
- `cargo test --features mock --test state_ledger_concurrency -- --test-threads=1`
  — 3 passed, 0 failed.
- `cargo test --features mock` — every test binary reports `ok`, zero
  FAILED across the entire mock-feature suite (`state_ledger`,
  `phase2_idempotent_re_receive`, `burn_roundtrip`, `pin_burn_compose`,
  `cas_racer`, and all other v1.0/v1.1 tests).
- `git diff src/error.rs` — empty.
- `cargo tree -p cipherpost --depth 1 | grep fs2` — `fs2 v0.4.3` listed
  as a direct dep.
- `grep -c "AMENDED 2026-04-27 by Quick 260427-axn" .planning/research/PITFALLS.md`
  — `1`.

## TDD discipline

- RED commit (`6187985`): added the failing test file + path-only helpers
  + `fs2` dep. All three tests fail at meaningful assertions (RED), not
  at compile.
- GREEN commit (`cf7b20a`): added `acquire_share_lock` + wired
  `run_receive` to hold the lock. All three regression tests now pass.
- Documentation commit (`b0b9351`): PITFALLS amendment.

## Deviations from plan

None — plan executed as written. The Test 3 reshape (sequential
granularity assertion vs. Barrier-synced concurrent receive) was
explicitly anticipated by the plan ("treat as a design-contract
document, not a strict invariant gate") and is documented in the test
docstring.

## Self-Check: PASSED

- Created files (verified `[ -f ... ]`):
  - `tests/state_ledger_concurrency.rs` — FOUND
  - `.planning/quick/260427-axn-introduce-a-process-level-lock-or-move-c/260427-axn-SUMMARY.md` — created by this Write call
- Modified files:
  - `Cargo.toml`, `Cargo.lock`, `src/flow.rs`, `.planning/research/PITFALLS.md` — all in commits below
- Commits exist (verified `git log --oneline 1173b7e..HEAD`):
  - `6187985` — FOUND
  - `cf7b20a` — FOUND
  - `b0b9351` — FOUND
