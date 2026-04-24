---
phase: 05-non-interactive-automation-e2e
verified: 2026-04-24T15:16:44Z
status: passed
score: 13/13 must-haves verified
overrides_applied: 0
re_verification: false
requirements_covered:
  - PASS-01
  - PASS-02
  - PASS-03
  - PASS-04
  - PASS-05
  - PASS-06
  - PASS-07
  - PASS-08
  - PASS-09
  - DOC-01
  - DOC-02
  - DOC-03
  - DOC-04
---

# Phase 5: Non-interactive automation E2E Verification Report

**Phase Goal:** Users can send and receive secret material without any TTY interaction, enabling scripted pipelines and CI automation.
**Verified:** 2026-04-24T15:16:44Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP.md Phase 5 Success Criteria)

| #   | Truth | Status | Evidence |
| --- | ----- | ------ | -------- |
| SC1 | User can run `cipherpost send - --passphrase-fd 3 < payload.bin 3< passphrase.txt` and `cipherpost receive --passphrase-file ~/.cipherpost/pp.txt` end-to-end without TTY, proven by CI test | VERIFIED | `tests/pass09_scripted_roundtrip.rs` — 2 tests pass under `--features mock`; both fd and file variants exercised with `libc::pipe`/mode-0600 file; `run_send`→`run_receive` round trip through MockTransport asserts byte equality |
| SC2 | Inline `--passphrase` on send/receive rejected with identity-subcommand message; `--help` shows all three non-interactive sources | VERIFIED | Smoke: `send --passphrase foo` exits 4 with `invalid passphrase input method (inline argv rejected)` (same Display as identity); `send --help` and `receive --help` each show 5 EXAMPLES lines including env-var, passphrase-file, passphrase-fd |
| SC3 | `--passphrase-file` strips exactly one trailing newline (not greedy); mode > 0600 refused; `--passphrase-fd` uses `BorrowedFd` | VERIFIED | `src/identity.rs:282` uses `BorrowedFd::borrow_raw`; `tests/passphrase_strip_rule.rs` 6 tests exercise D-P5-08 truth table (CRLF/LF/LF+LF/space/none/bare CR); `tests/passphrase_fd_borrowed.rs::fd_remains_open_after_resolve` asserts `fcntl(fd, F_GETFD) != -1` after call; mode check at `src/identity.rs:301` returns `Error::IdentityPermissions` |
| SC4 | SPEC.md API-range version prose; DHT label constants documented as wire-stable | VERIFIED | `grep -q "fd > file > env > TTY" SPEC.md` green; SPEC.md §3.5 contains "Renaming either" + "protocol_version" inside the section (awk range match); PKARR budget updated to 550 B (no 600 B remnant); no `serde_canonical_json 1.0.0`/`0.2` in prose |
| SC5 | REQUIREMENTS.md inline phase tags only; no separate traceability table; no surviving "Pending" row | VERIFIED | Archive `.planning/milestones/v1.0-REQUIREMENTS.md`: 0 traceability header, 0 `\| Complete \|` cells, 0 REQ-ID-style rows, forward-pointer blockquote present; `.planning/REQUIREMENTS.md` PASS-05 rewritten to match shipped precedence |

**Score:** 5/5 Success Criteria verified

### Required Artifacts

| Artifact | Expected | Status | Details |
| -------- | -------- | ------ | ------- |
| `src/identity.rs` | `BorrowedFd`, exact one-newline strip, fd=0 reject, single code path | VERIFIED | Line 18: `use std::os::unix::io::BorrowedFd`; Line 274-277: fd=0 `Error::Config`; Line 282: `BorrowedFd::borrow_raw`; Lines 287-292, 306-311: exact strip; no `FromRawFd`, no `std::mem::forget`, no `trim_end_matches('\n'/'\r')` |
| `src/cli.rs` | passphrase trio + positional `-` on Send; passphrase trio on Receive | VERIFIED | Lines 63-76: Send has `passphrase_file`/`passphrase_fd`/hidden `passphrase`/`material_stdin`; Lines 100-108: Receive has the trio (no positional per D-P5-06); both `long_about` blocks have 5 EXAMPLES lines |
| `src/main.rs` | Dispatch threads flags, multi-source conflict, positional `-` mapping | VERIFIED | Lines 80-90: Send destructure; Lines 92-97: multi-source conflict; Lines 99-120: positional validation; Lines 122-130: resolve_passphrase call with `confirm_on_tty=false`; Lines 205-242: Receive parallel |
| `tests/passphrase_strip_rule.rs` | 6 tests covering D-P5-08 truth table | VERIFIED | 6 `#[test]` fns: `strip_crlf`, `strip_lf`, `strip_one_of_two_lf`, `preserve_trailing_space`, `preserve_no_trailer`, `preserve_bare_cr`; `cargo test --test passphrase_strip_rule` → 6 passed |
| `tests/passphrase_fd_borrowed.rs` | fd-lifecycle + fd=0 rejection, both `#[serial]` | VERIFIED | 2 `#[test]` fns `fd_remains_open_after_resolve` and `fd_zero_rejected`; both `#[serial]`; `cargo test --test passphrase_fd_borrowed` → 2 passed; no `AsRawFd` import; no `BorrowedFd` literal in the test file |
| `tests/pass09_scripted_roundtrip.rs` | 2 MockTransport round-trip tests (file + fd) | VERIFIED | `#![cfg(feature = "mock")]` gate; `scripted_roundtrip_via_passphrase_file` + `scripted_roundtrip_via_passphrase_fd`; both `#[serial]`; uses `MockTransport::new()` + `deterministic_identity_at`; `cargo test --features mock --test pass09_scripted_roundtrip` → 2 passed |
| `tests/dht_label_constants.rs` | 2 tests byte-matching DHT labels with SPEC.md §3.5 breadcrumb | VERIFIED | `dht_label_outer_is_cipherpost_literal` + `dht_label_receipt_prefix_is_cprcpt_literal`; 3 `SPEC.md §3.5` refs (2 failure-messages + 1 module docstring); 0 `SPEC.md §3.3` refs |
| `SPEC.md` | §7 precedence + strip truth table; §3.5 DHT wire-stability; §3/§4 API-range versions; 550 B budget | VERIFIED | `fd > file > env > TTY` present; §3.5 section-bounded grep `protocol_version` + `Renaming either` both green; 6 `hunter2`-truth-table rows; 550 byte budget; no 600 byte remnant; no pinned version numbers in prose |
| `CLAUDE.md` | `## Planning docs convention` adjacent to `## GSD workflow` | VERIFIED | Section present; adjacency verified (line of "Planning docs convention" > line of "GSD workflow"); BLOCKER-3 rewrite — no "29 stale" counterfactual |
| `.planning/milestones/v1.0-REQUIREMENTS.md` | 49-row table deleted, forward-pointer installed | VERIFIED | No `## Traceability` header; 0 REQ-ID rows; 0 "Complete" cells; `Traceability format deprecated in v1.1` blockquote with CLAUDE.md forward-pointer present |
| `.planning/REQUIREMENTS.md` | PASS-05 text matches shipped precedence | VERIFIED | `passphrase-fd > --passphrase-file > CIPHERPOST_PASSPHRASE > TTY` text present; old contradictory text gone; `[ ]` checkbox preserved (Phase 5 did not check it off — the phase is what verifies it) |
| `Cargo.toml` | `libc = "0.2"` in `[dev-dependencies]`; `ed25519-dalek =3.0.0-pre.5` pin preserved | VERIFIED | Line 22-26: `ed25519-dalek = "=3.0.0-pre.5"` exact pin preserved with CLAUDE.md comment; `libc = "0.2"` under `[dev-dependencies]` |

### Key Link Verification

| From | To | Via | Status | Details |
| ---- | -- | --- | ------ | ------- |
| `src/cli.rs` Send/Receive variants | `src/main.rs` dispatchers | Field destructuring (`passphrase_file`, `passphrase_fd`, `passphrase`) | WIRED | `grep -c "passphrase_file.as_deref()" src/main.rs` → 4 (Generate, Show, Send, Receive) |
| `src/main.rs` dispatchers | `src/identity.rs::resolve_passphrase` | Call threading `passphrase.as_deref(), Some("CIPHERPOST_PASSPHRASE"), passphrase_file.as_deref(), passphrase_fd, false` | WIRED | 4 call sites present; all use the single shared code path (D-P5-07) |
| `tests/pass09_scripted_roundtrip.rs` | `src/identity.rs` + `src/flow.rs::run_send/run_receive` | MockTransport + deterministic_identity_at + 2 passphrase-source variants | WIRED | Test passes end-to-end; round-trip asserts byte equality; both tests remove `CIPHERPOST_PASSPHRASE` from env before resolving |
| `SPEC.md §3.5` | `tests/dht_label_constants.rs` | Byte-match on `_cipherpost` and `_cprcpt-` literals; failure messages cite §3.5 | WIRED | SPEC.md §3.5 forward-references the test file; test passes |
| `SPEC.md §7 precedence` | `src/identity.rs::resolve_passphrase` | SPEC documents `fd > file > env > TTY`; code ships same order | WIRED | BLOCKER-1 resolved — SPEC now matches code |
| `.planning/REQUIREMENTS.md PASS-05` | `src/identity.rs::resolve_passphrase` | REQ text names actual precedence; code enforcement from Plan 05-02 | WIRED | PASS-05 rewritten (BLOCKER-1); 05-02 dispatch closes the code side |
| `CLAUDE.md Planning docs convention` | `.planning/REQUIREMENTS.md:7` Structure note | CLAUDE.md references convention; REQUIREMENTS.md defines it | WIRED | Both anchors present |

### Data-Flow Trace (Level 4)

| Artifact | Data Variable | Source | Produces Real Data | Status |
| -------- | ------------- | ------ | ------------------ | ------ |
| `run_send`/`run_receive` via dispatch | `pw: Passphrase` | `resolve_passphrase(...)` in main.rs | Yes — fd branch reads real bytes, file branch reads real file, env branch reads real env | FLOWING |
| `effective_material` (Send) | `Option<String>` | Composed from `material_file` + `material_stdin` with validation | Yes — mapped to `MaterialSource::Stdin`/`File(PathBuf)` | FLOWING |
| MockTransport round-trip payload | `Vec<u8>` b"secret" | `MaterialSource::Bytes(b"secret".to_vec())` in pass09 test | Yes — round-trip asserts `buf == b"secret"` on receive | FLOWING |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
| -------- | ------- | ------ | ------ |
| cargo build --release | `cargo build --release` | exit 0 (Finished `release` profile) | PASS |
| Full suite, default features | `cargo test` | 77 passed, 0 failed | PASS |
| Full suite with mock | `cargo test --features mock` | 98 passed, 0 failed | PASS |
| New Phase 5 tests — strip rule | `cargo test --test passphrase_strip_rule` | 6 passed, 0 failed | PASS |
| New Phase 5 tests — fd lifecycle | `cargo test --test passphrase_fd_borrowed` | 2 passed, 0 failed | PASS |
| New Phase 5 tests — PASS-09 | `cargo test --features mock --test pass09_scripted_roundtrip` | 2 passed, 0 failed | PASS |
| New Phase 5 tests — DHT labels | `cargo test --test dht_label_constants` | 2 passed, 0 failed | PASS |
| CLAUDE.md lock-in test — debug leak | `cargo test --test debug_leak_scan` | 2 passed, 0 failed | PASS |
| CLAUDE.md lock-in test — chacha20 direct-use ban | `cargo test --test chacha20poly1305_direct_usage_ban` | 1 passed, 0 failed | PASS |
| CLAUDE.md lock-in test — HKDF enumeration | `cargo test --test hkdf_info_enumeration` | 1 passed, 0 failed | PASS |
| Clippy --features mock --tests | `cargo clippy --features mock --tests -- -D warnings` | exit 0 | PASS |
| Clippy default | `cargo clippy -- -D warnings` | exit 0 | PASS |
| Format check | `cargo fmt --check` | exit 0 | PASS |
| CLI smoke — argv-inline rejection | `cipherpost send --self -p t --passphrase foo -` | exit 4, `invalid passphrase input method (inline argv rejected)` | PASS |
| CLI smoke — multi-source conflict | `cipherpost send --self -p t --passphrase-file X --passphrase-fd 99 -` | exit 1, `--passphrase-file and --passphrase-fd are mutually exclusive` | PASS |
| CLI smoke — bad positional | `cipherpost send --self -p t ./foo.bin` | exit 1, `positional argument must be '-' ...` | PASS |
| CLI smoke — send --help scripting sources | `cipherpost send --help` | Shows `--passphrase-file`, `--passphrase-fd`, `CIPHERPOST_PASSPHRASE=hunter2`; 5 EXAMPLES lines | PASS |
| CLI smoke — receive --help scripting sources | `cipherpost receive --help` | Shows `--passphrase-file`, `--passphrase-fd`, `CIPHERPOST_PASSPHRASE`; 5 EXAMPLES lines | PASS |

### Requirements Coverage (13 / 13)

| Requirement | Source Plan | Description | Status | Evidence |
| ----------- | ----------- | ----------- | ------ | -------- |
| PASS-01 | 05-02 | `--passphrase-file <path>` on send | SATISFIED | `src/cli.rs:64` field; `src/main.rs:127` thread; mode check inherited from 05-01 |
| PASS-02 | 05-01 | `--passphrase-fd <fd>` with BorrowedFd | SATISFIED | `src/identity.rs:282` uses `BorrowedFd::borrow_raw`; `tests/passphrase_fd_borrowed.rs::fd_remains_open_after_resolve` is the runtime witness |
| PASS-03 | 05-02 | `--passphrase-file` on receive | SATISFIED | `src/cli.rs:100` field; `src/main.rs:239` thread |
| PASS-04 | 05-02 | `--passphrase-fd` on receive | SATISFIED | `src/cli.rs:103` field; `src/main.rs:240` thread |
| PASS-05 | 05-02 (code); 05-03 (text) | Precedence fd > file > env > TTY; argv-inline rejected | SATISFIED | Code path enforced at `src/identity.rs:267-333`; REQUIREMENTS.md text rewritten to match (BLOCKER-1 fix) |
| PASS-06 | 05-02 | Hidden `--passphrase` + runtime rejection | SATISFIED | `hide = true` at `src/cli.rs:71` (Send) and `:107` (Receive); rejected at Priority 1 via `Error::PassphraseInvalidInput` (exit 4) |
| PASS-07 | 05-01 | Exact one-newline strip (never `.trim()`) | SATISFIED | `src/identity.rs:287-292` (fd), `306-311` (file); `tests/passphrase_strip_rule.rs` — 6-case truth table all passing |
| PASS-08 | 05-02 | `--help` lists three non-interactive sources with scripting examples | SATISFIED | Both send and receive `long_about` have 5 EXAMPLES lines; scripting variants env/file/fd all shown |
| PASS-09 | 05-02 | CI integration test exercises scripted round trip without TTY | SATISFIED | `tests/pass09_scripted_roundtrip.rs` — 2 tests under `--features mock`; MockTransport round trip for both file and fd variants |
| DOC-01 | 05-03 | SPEC.md API-range versions + 550 B budget | SATISFIED | SPEC.md §3 intro + §2 rewritten; 550 B PKARR budget cited with test reference; no hard-pinned numbers remain in prose |
| DOC-02 | 05-03 | DHT label audit committed | SATISFIED | `tests/dht_label_constants.rs` constant-match test + SPEC.md §3.5 wire-stability prose |
| DOC-03 | 05-03 | Traceability convention documented in CLAUDE.md | SATISFIED | CLAUDE.md `## Planning docs convention` section (adjacent to GSD workflow); REQUIREMENTS.md:7 Structure note referenced |
| DOC-04 | 05-03 | v1.0 archived REQUIREMENTS.md cleaned up (traceability format dropped) | SATISFIED | Archive table fully deleted (0 rows, 0 Complete cells, no `## Traceability` header); forward-pointer blockquote references CLAUDE.md convention |

**Orphaned requirements:** None. Every REQ-ID listed on Phase 5 in ROADMAP.md appears in at least one plan's `requirements` field.

### Anti-Patterns Found

No blocking or warning anti-patterns detected. Files reviewed:

- `src/identity.rs`: no TODO/FIXME/PLACEHOLDER; no `return null`/`return {}` stubs; no console.log-only bodies; no hardcoded empty returns. The only `return null`/empty matches are in tests where arrays are expected to be empty.
- `src/cli.rs`: additive-only changes; no reorder of existing fields.
- `src/main.rs`: dispatch prologue adds real validation; all error paths route through `Error::Config` or propagate from `resolve_passphrase`.
- `tests/*.rs`: all 4 new test files have real assertions, real data flow.
- `SPEC.md`, `CLAUDE.md`: documentation rewrites only.

### Load-Bearing Lock-In Preservation (from CLAUDE.md)

| Lock-in | Status |
| ------- | ------ |
| No `#[derive(Debug)]` on secret holders | PRESERVED — `cargo test --test debug_leak_scan` passes; `Passphrase` uses manual redacted Debug (identity.rs:237) |
| No direct `chacha20poly1305` calls | PRESERVED — `cargo test --test chacha20poly1305_direct_usage_ban` passes; `grep -rn "chacha20poly1305::" src/` returns 0 matches |
| HKDF info strings use `cipherpost/v1/<context>` | PRESERVED — `cargo test --test hkdf_info_enumeration` passes; no new HKDF call sites in Phase 5 |
| `serial_test` on env/fd-mutating tests | APPLIED — `tests/passphrase_fd_borrowed.rs` both tests `#[serial]`; `tests/pass09_scripted_roundtrip.rs` both tests `#[serial]` |
| Error-oracle hygiene (no new Display variants) | PRESERVED — zero changes to `src/error.rs` this phase; all new rejection paths route through existing `Error::Config` / `Error::PassphraseInvalidInput` / `Error::IdentityPermissions` |
| `ed25519-dalek =3.0.0-pre.5` exact pin | PRESERVED — `Cargo.toml:26` still `"=3.0.0-pre.5"` with CLAUDE.md comment |
| No async runtime at cipherpost layer | PRESERVED — no new `tokio` direct dep; continues to use `pkarr::ClientBlocking` |
| `share_ref` derivation unchanged | PRESERVED — no changes to `src/crypto.rs` or `src/record.rs` in Phase 5 |
| Argon2id params in PHC header | PRESERVED — no changes to identity file format |

### D-P5-XX Decision Honor (CONTEXT.md)

All 14 decisions from 05-CONTEXT.md honored:

| Decision | Verified |
| -------- | -------- |
| D-P5-01 (precedence fd > file > env > TTY) | YES — identity.rs, SPEC.md §7, REQUIREMENTS.md PASS-05 all aligned |
| D-P5-02 (no stderr warning for env-var) | YES — no warning added; procedural mitigation in SPEC.md only |
| D-P5-03 (fd=0 rejected) | YES — identity.rs:274-277 |
| D-P5-04 (multi-source conflict) | YES — main.rs:92 and :214 |
| D-P5-05 (positional `-` on send) | YES — cli.rs `material_stdin` field + main.rs:99-120 |
| D-P5-06 (no positional on receive) | YES — Receive has only `share` positional |
| D-P5-07 (single code path) | YES — identity/send/receive all call the same `resolve_passphrase` |
| D-P5-08 (strip truth table) | YES — 6 rows in SPEC.md §7.2 + 6 tests in passphrase_strip_rule.rs |
| D-P5-09 (test coverage) | YES — unit tests + fd-lifecycle + PASS-09 integration |
| D-P5-10 (scripting examples in --help) | YES — 3 new EXAMPLES lines on both subcommands |
| D-P5-11 (API-range versions in SPEC.md) | YES — SPEC.md §2 + §3 rewritten; §9 lineage intentionally preserved (cclink markers, not runtime pins) |
| D-P5-12 (DHT label audit = test + §3.5) | YES — tests/dht_label_constants.rs + SPEC.md §3.5 |
| D-P5-13 (archive table dropped) | YES — 49-row table removed; forward-pointer installed |
| D-P5-14 (CLAUDE.md convention) | YES — `## Planning docs convention` section added |

### Known Pitfalls Addressed

| Pitfall | Addressed By |
| ------- | ------------ |
| #30 — greedy strip corrupts trailing-space passphrases | exact one-newline strip in identity.rs; `preserve_trailing_space` test |
| #31 — FromRawFd double-close hazard | `BorrowedFd::borrow_raw` + `try_clone_to_owned`; `fd_remains_open_after_resolve` runtime test |
| #32 — traceability-table drift | 49-row table deleted from archive; forward-pointer to per-phase VERIFICATION.md |
| #33 — DHT label rename is protocol break | `tests/dht_label_constants.rs` byte-match; SPEC.md §3.5 requires protocol_version bump |
| #34 — pin-version hard-pin in SPEC.md | SPEC.md §2/§3 rewritten to API-range form |
| #35 — `CIPHERPOST_PASSPHRASE` process-table visibility | SPEC.md §7 lists env as priority 3 with `/proc/<pid>/environ` rationale; fd/file preferred |

### BLOCKER Resolutions (from plan-check)

- **BLOCKER 1** — PASS-05 text contradicted shipped behavior: Resolved by Plan 05-03 Task 5 rewrite to `--passphrase-fd > --passphrase-file > CIPHERPOST_PASSPHRASE > TTY`.
- **BLOCKER 2** — PATTERNS.md cited §3.3 for DHT wire-stability note but §3.3 is OuterRecord: Resolved with NEW §3.5 subsection covering both labels; test failure messages cite §3.5.
- **BLOCKER 3** — "29 stale Pending rows" narrative was counterfactual: Resolved with drift-class wording in CLAUDE.md; archive cleanup uses positive assertions (0 Complete cells).
- **BLOCKER 6** — `Command::Send {` / `Command::Receive {` construction outside main.rs/cli.rs: Verified 0 hits.
- **BLOCKER 7** — `trim_end_matches('\n'/'\r')` tightened grep: 0 hits remain in identity.rs.

### Gaps Summary

None. All 5 ROADMAP Success Criteria verified; all 13 REQ-IDs satisfied with concrete code/test/doc evidence; all 14 D-P5-XX decisions honored; all 6 relevant pitfalls addressed; all CLAUDE.md load-bearing lock-ins preserved.

The phase ships a real deliverable: SC1's canonical invocation `cipherpost send - --passphrase-fd 3 < payload.bin 3< passphrase.txt` now parses cleanly, resolves the passphrase through `BorrowedFd` without closing the caller's fd, applies an exact one-newline strip (not greedy), and round-trips end-to-end under MockTransport with a CI test (`tests/pass09_scripted_roundtrip.rs::scripted_roundtrip_via_passphrase_fd`) enforcing the invariant on every push.

Real-DHT verification of SC1 is intentionally deferred to Phase 9 (per 05-CONTEXT.md out-of-scope note) — the flow-layer proof under MockTransport is equivalent because the CLI dispatcher is pure plumbing and the DHT transport has been exercised separately by earlier phases.

---

_Verified: 2026-04-24T15:16:44Z_
_Verifier: Claude (gsd-verifier)_
