# Phase 9 Deferred Items

Out-of-scope discoveries during plan execution. Tracked here for visibility;
NOT fixed by the plan that found them.

## From Plan 09-01 execution (2026-04-26)

### `clippy::uninlined-format-args` lint in `build.rs:17`

**Pre-existing on the Phase 9 base commit `c73ebe2`** — verified by reverting
working tree changes and re-running `cargo clippy --all-targets --features mock
-- -D warnings`; the same error reproduces.

**Lint output:**

```
error: variables can be used directly in the `format!` string
  --> build.rs:17:5
   |
17 |     println!("cargo:rustc-env=CIPHERPOST_GIT_SHA={}", sha);
   |     ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
   = note: `-D clippy::uninlined-format-args` implied by `-D warnings`
```

**Why deferred:** The lint is triggered by a newer rustc/clippy than the
project's pinned MSRV / CI clippy version. CI did not flag this on the Phase 8
close, suggesting the developer environment runs a stricter clippy build. Plan
09-01 only modified `src/transport.rs`, `tests/cas_racer.rs`,
`tests/wire_budget_compose_pin_burn_pgp.rs`, and `Cargo.toml` — `build.rs` is
out of scope.

**Owner:** A future plan that touches `build.rs` (or a maintenance commit) can
inline the format arg. Not a release blocker (CI's clippy version is the gate).

**Verification command after fix:**

```bash
cargo clippy --all-targets --features mock -- -D warnings
```

(Should exit 0.)
