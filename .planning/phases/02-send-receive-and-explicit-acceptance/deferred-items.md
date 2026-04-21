# Phase 2 — Deferred Items

Items discovered during Phase 2 execution that are out of scope for the current plan (per scope boundary rules) and deferred to a future plan or cleanup pass.

## Pre-existing formatting deviations in Phase 1 code

Discovered during Plan 02-01 execution. `cargo fmt --check` reports diffs in multiple Phase 1 source files that shipped without running `cargo fmt` strictly:

- `build.rs` — multi-line `.and_then` closure would be reflowed
- `src/crypto.rs` — several `.map_err` chains and multi-line expressions
- `src/error.rs` lines 27-37 — `#[error("signature verification failed")]  // D-16` comments use two spaces before `//` (rustfmt wants one)
- `src/identity.rs` — `Passphrase::from_string(...)` multi-line calls
- `src/record.rs` — `pkarr::PublicKey::try_from` multi-line, assertion closure reflow
- `src/transport.rs` — `serde_json::to_string` and `map_dns_err` signature reflow
- `tests/hkdf_info_enumeration.rs` — `assert!` macro formatting
- `tests/identity_phc_header.rs` — multi-line function call
- `tests/debug_leak_scan.rs` — `assert!` macro formatting

None of these are regressions caused by Plan 02-01; they were already committed on `main` before this plan started. Plan 02-01 ships fmt-clean code in all new files (`src/payload.rs`, `tests/phase2_*.rs`, lib.rs additions, error.rs additions).

**Recommended cleanup:** A dedicated `chore(fmt): run cargo fmt across entire tree` commit at the top of Phase 2 or Phase 4 to bring the codebase fully `cargo fmt --check` clean. Avoided inside Plan 02-01 because it would touch files out of scope for this plan's `files_modified`.

## Pre-existing clippy warning in Phase 1 test

Discovered during Plan 02-02 execution. `cargo clippy --all-features --tests -- -D warnings` fires `clippy::format_collect` on `tests/debug_leak_scan.rs:32`:

```rust
let hex: String = win.iter().map(|b| format!("{:02x}", b)).collect();
```

This is a Phase 1 test file not touched by Plan 02-02 (scope limited to `src/flow.rs`, `src/identity.rs`, `Cargo.toml`, and the seven new `tests/phase2_*.rs` files). Fix belongs in a Phase 1 cleanup pass alongside the pre-existing fmt deviations above. Plan 02-02 targets (lib + seven new integration tests) are individually clippy-clean under `-D warnings`.
