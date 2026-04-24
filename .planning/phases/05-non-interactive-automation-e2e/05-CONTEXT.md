# Phase 5: Non-interactive automation E2E - Context

**Gathered:** 2026-04-23
**Status:** Ready for planning

<domain>
## Phase Boundary

Deliver scripted, TTY-free `cipherpost send` / `cipherpost receive` by aligning their passphrase surface with the existing `identity generate` / `identity show` non-interactive contract, and close three v1.0 documentation debts (pin-version prose, DHT label audit, traceability-table drift) that would otherwise keep compounding.

**In scope:**
- `--passphrase-file <path>` and `--passphrase-fd <n>` on `send` and `receive` (PASS-01..04)
- `--passphrase <value>` argv flag `hide = true` + runtime rejection on send/receive (PASS-06)
- Exact one-newline strip and `BorrowedFd` fd lifetime in `resolve_passphrase` (PASS-02, PASS-07)
- `send` positional `-` as shorthand for `--material-file -`
- Scripting examples in `--help` for send/receive (PASS-08)
- CI integration test proving scripted send → receive round trip with no TTY (PASS-09)
- SPEC.md pin-version prose blessed in API-range form (DOC-01)
- SPEC.md §3.3 DHT-label wire-stability note + constant-match unit test (DOC-02)
- Traceability-format convention documented in CLAUDE.md (DOC-03)
- Traceability table dropped from archived v1.0 REQUIREMENTS.md (DOC-04)

**Out of scope (noted for deferral):**
- `--pin` / `--pin-file` / `--pin-fd` — Phase 8
- Typed Material variants — Phases 6–7
- Real-DHT end-to-end tests — Phase 9

</domain>

<decisions>
## Implementation Decisions

### D-P5-01 · Passphrase precedence order (resolves SPEC/code/Pitfall-35 three-way conflict)

**Precedence:** `fd > file > env (CIPHERPOST_PASSPHRASE) > TTY prompt`. `--passphrase <value>` inline-argv is rejected at parse/runtime.

**Why:** Current `src/identity.rs:258-319` ships this ordering today; `research/PITFALLS.md` #35 endorses it on security grounds (env visible via `/proc/<pid>/environ` and `ps auxe`). SPEC.md §7.1 and PASS-05 text presently describe the opposite (`env > file > fd > TTY`); both will be rewritten to match code, not the reverse. Rewriting code would silently change unlock behavior for existing users who set `CIPHERPOST_PASSPHRASE` + `--passphrase-fd` together — unacceptable on an unlock path.

**Action:** Edit SPEC.md §7.1 to read `fd > file > env > TTY` in priority order; rewrite PASS-05 in `.planning/REQUIREMENTS.md` to state the chosen ordering explicitly (not "matches identity subcommands").

### D-P5-02 · No stderr warning when `CIPHERPOST_PASSPHRASE` is used

Keep stderr clean; rely on SPEC.md §7 preference-ordering prose to guide users. The env-var pattern is already common in CI contexts; a warning on every run is noisy and hurts the UX that Phase 5 is specifically delivering.

### D-P5-03 · `--passphrase-fd 0` rejected with `Error::Config`

`fd 0` is stdin. Stdin is reserved for payload I/O on send/receive and for consistency the rejection applies uniformly across all subcommands (identity generate/show also). This deviates from the current `if n == 0 that's stdin, which is fine` comment at `src/identity.rs:276` — that comment and the permissive branch go away. Message suggestion: `"--passphrase-fd 0 reserved for stdin; use fd >= 3 or --passphrase-file"`.

**Migration note for planner:** This is a silent behavior change for any existing script passing `--passphrase-fd 0` to identity subcommands. No known caller does this (identity docs have always shown `fd 3`), but it warrants a CHANGELOG note.

### D-P5-04 · Multiple-source passphrase flags error; env-var + flag is permitted

If two or more of `{--passphrase-fd, --passphrase-file}` are set together, exit 1 with `Error::Config` naming the conflict. `CIPHERPOST_PASSPHRASE` + one flag is permitted — env is the explicit fallback.

**Why:** Catches script bugs where CI inherits `CIPHERPOST_PASSPHRASE` silently overriding the intended `--passphrase-file`. Still leaves the common "env is default, flag overrides for this command" pattern working.

### D-P5-05 · `cipherpost send` accepts positional `-` as shorthand for `--material-file -`

Positional `-` (only) means "read payload from stdin." A real path still requires `--material-file <path>`. SC1 in ROADMAP.md runs verbatim. Existing `--material-file -` users unaffected.

**Clap shape change at `src/cli.rs:38-58`:** Add `material_stdin: Option<String>` positional (only `-` accepted; any other value → `Error::Config`).

### D-P5-06 · `cipherpost receive` CLI surface: no positional stdin, only add passphrase flags

Adding URI-on-stdin (`echo <uri> | receive - --passphrase-fd 3`) is net-new surface and belongs in roadmap backlog, not Phase 5. Existing `receive <uri> -o - --passphrase-fd 3 3<pp.txt` already composes.

### D-P5-07 · Fix `resolve_passphrase` in-place — single code path for identity + send + receive

One edit to `src/identity.rs:271-287` covers: (a) `BorrowedFd` replacing `FromRawFd + std::mem::forget`; (b) exact one-newline strip replacing greedy `.trim_end_matches('\n').trim_end_matches('\r')`. Identity generate/show inherit the fix. No parallel `resolve_passphrase_strict()` — one passphrase contract, one test surface.

**Migration note for planner:** Existing users with pathological pw files (e.g., `"hunter2\n\n"` — two trailing newlines from an editor that adds a blank line) previously unlocked as `"hunter2"`; after this change they unlock as `"hunter2\n"` and get exit 4. Document in the PR that described this fix. Very low expected impact — PW files are typically written by `echo $PW > pw.txt` which produces exactly one `\n`.

### D-P5-08 · Strip rule: one `\r\n` if present, else one `\n`, else nothing

- `"hunter2\r\n"` → `"hunter2"` (CRLF stripped)
- `"hunter2\n"` → `"hunter2"` (LF stripped)
- `"hunter2\n\n"` → `"hunter2\n"` (exactly one LF stripped; inner LF preserved)
- `"hunter2 "` → `"hunter2 "` (trailing space preserved — this is the Pitfall-30 case)
- `"hunter2"` → `"hunter2"` (no trailer, untouched)
- `"hunter2\r"` → `"hunter2\r"` (bare CR NOT stripped — reject at user's text editor, not silently mutate)

Pseudocode:
```
if bytes.ends_with(b"\r\n") { bytes.truncate(len - 2) }
else if bytes.ends_with(b"\n") { bytes.truncate(len - 1) }
```

### D-P5-09 · Test coverage: unit tests + one integration test for strip; explicit fd-lifecycle test

**Unit tests** in `src/identity.rs` (or `tests/passphrase_strip_rule.rs` if cleaner) for the five cases in D-P5-08.

**Integration test** under `tests/` using `--passphrase-file` on `send` or `receive` end-to-end to prove the strip lands correctly through the dispatcher (part of PASS-09's CI test matrix — not a separate test).

**fd-lifecycle test:** open a pipe, write pw to write-end, pass read-end fd via `--passphrase-fd`, after the call returns assert `fcntl(fd, F_GETFD) != EBADF` (fd still open — `BorrowedFd` preserved ownership). Named per Pitfall #31. Likely `tests/passphrase_fd_borrowed.rs` with `#[serial]` (touches process fd state).

### D-P5-10 · Scripting examples in `--help` mirror identity subcommands

Add three EXAMPLES lines each to `Send` and `Receive` `long_about` in `src/cli.rs` showing env, file, and fd variants (parity with `IdentityCmd::Generate` at `src/cli.rs:105-109`). Per-invocation help should stand alone; no "see SPEC §7" indirection.

No Python/bash-specific snippets in `--help` — those go in SPEC.md §7 if anywhere.

### D-P5-11 · DOC-01: SPEC.md crate-version prose uses API ranges, not exact versions

SPEC.md prose reads e.g. `serde_canonical_json (>= 1.0.0, RFC 8785 JCS); see Cargo.toml for the exact pin in effect`. No exact numbers in SPEC prose. Cargo.toml and deny.toml carry exact-version authority.

**Applies to:** `serde_canonical_json`, `pkarr`, `ed25519-dalek`, `age`. The load-bearing `ed25519-dalek =3.0.0-pre.5` pin stays exact in Cargo.toml with a comment citing CLAUDE.md's "load-bearing lock-ins"; SPEC.md prose mentions it only as "build constraint, not protocol guarantee."

**PKARR wire budget:** update SPEC.md from the v1.0 "600 byte" prose to "550 bytes (measured at v1.0 cut)." Numeric constant stays cited because it's a protocol constraint, not a crate version.

### D-P5-12 · DOC-02: DHT label audit = constant-match unit test + SPEC.md §3.3 wire-stability note

**Unit test** asserting code constants byte-match their SPEC.md strings: `DNS_LABEL_SHARE == "_cipherpost"`, `DNS_LABEL_RECEIPT_PREFIX == "_cprcpt-"` (per Pitfall #33). Test lives in `tests/dht_label_constants.rs` or inlined in `src/transport.rs` tests module.

**SPEC.md §3.3 prose addition:** "These label strings are part of the wire format. Renaming either requires a `protocol_version` bump and a migration section in this SPEC. Under no circumstances are they changed silently."

No standalone `docs/dht-label-audit.md` — the test IS the audit.

### D-P5-13 · DOC-04: archived v1.0 REQUIREMENTS.md — drop the traceability table entirely

Open `.planning/milestones/v1.0-REQUIREMENTS.md`, delete the traceability table section, prepend a note at the deprecated section's former location:

```
> Traceability format deprecated in v1.1.
> Per-requirement implementation status: see
> .planning/milestones/v1.0-phases/<NN>/VERIFICATION.md per phase.
> (Convention change documented in CLAUDE.md "Planning docs convention.")
```

No "Pending" row can survive because the table doesn't exist. Clean cut. Commit: `docs(archive): drop v1.0 traceability table (DOC-04)`.

### D-P5-14 · DOC-03: convention documented in REQUIREMENTS.md Structure note (already done) + CLAUDE.md

`.planning/REQUIREMENTS.md:7` already has the Structure note locking the convention. Phase 5 adds a short paragraph to `CLAUDE.md` under a new heading `## Planning docs convention`:

```markdown
## Planning docs convention

**Requirements traceability.** Each requirement in .planning/REQUIREMENTS.md carries
an inline `[Phase N]` tag and a checkbox. Phase `.planning/phases/<NN>/VERIFICATION.md`
files are authoritative for implementation status. Do not add or regenerate a separate
traceability table — the drift that produced 29 stale "Pending" rows at v1.0 close is
what this convention prevents.
```

CLAUDE.md is where future Claude sessions read working instructions; REQUIREMENTS.md is where the rule is defined. Two-places, one-source-of-truth.

### Claude's Discretion

- Exact error-message strings for new rejection paths (`--passphrase-fd 0`, multiple-source conflict, inline `--passphrase` on send/receive). Follow error-oracle hygiene: argv-inline rejection reuses the existing `Error::PassphraseInvalidInput` Display.
- Exact shape of the CI integration test for PASS-09 — whether it lives in `tests/pass09_scripted_roundtrip.rs` or folds into an existing mock-transport integration file. Must use MockTransport (no real DHT in CI).
- Whether to generate a helper fixture/script at `tests/fixtures/passphrase_strip_cases.txt` or inline the strip-rule cases as Rust string literals. Inline is probably cleaner.
- Ordering of execution across the 14 decisions above when splitting into plans.

</decisions>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Requirements & Roadmap
- `.planning/REQUIREMENTS.md` §Non-interactive passphrase automation (PASS) — PASS-01..09
- `.planning/REQUIREMENTS.md` §Protocol documentation housekeeping (DOC) — DOC-01..04
- `.planning/ROADMAP.md` §Phase 5 — success criteria 1–5 (SC1 drives positional-stdin decision)

### Domain pitfalls (load-bearing, each cited by a specific decision above)
- `.planning/research/PITFALLS.md` #30 — greedy-strip corrupts trailing-space passphrases → D-P5-08
- `.planning/research/PITFALLS.md` #31 — `FromRawFd` double-close hazard → D-P5-07, D-P5-09
- `.planning/research/PITFALLS.md` #32 — traceability-table drift fix must not silently break tooling → D-P5-13
- `.planning/research/PITFALLS.md` #33 — DHT label audit is confirm-not-change → D-P5-12
- `.planning/research/PITFALLS.md` #34 — SPEC.md must not hard-pin crate versions in prose → D-P5-11
- `.planning/research/PITFALLS.md` #35 — `CIPHERPOST_PASSPHRASE` process-table visibility → D-P5-01

### Research synthesis
- `.planning/research/SUMMARY.md` §Phase 5 — Non-Interactive Automation E2E
- `.planning/research/SUMMARY.md` §Watch Out For — Phase 5 block

### Project convention
- `CLAUDE.md` §Load-bearing lock-ins — passphrase contract, serial_test pattern, error-oracle hygiene
- `.planning/PROJECT.md` §Key Decisions — "Confirm-passphrase on identity generate" row
- `.planning/REQUIREMENTS.md:7` — Structure note (DOC-03 prerequisite; already in place)

### Spec sections to edit in Phase 5
- `SPEC.md` §7 Passphrase Contract — rewrite precedence ordering (D-P5-01), add newline-strip spec (D-P5-08)
- `SPEC.md` §3.3 DHT Labels — add wire-stability note (D-P5-12)
- `SPEC.md` §3 + §4 — rewrite version-prose to API-range form (D-P5-11)
- `.planning/milestones/v1.0-REQUIREMENTS.md` — drop traceability table (D-P5-13)
- `CLAUDE.md` — add Planning docs convention section (D-P5-14)

### Existing code — primary edit sites
- `src/identity.rs:258-319` — `resolve_passphrase` (single code path; D-P5-07 rewrites fd branch and strip; D-P5-01 enforces precedence order)
- `src/cli.rs:38-58` — `Send` struct (add `passphrase_file`, `passphrase_fd`, hidden `passphrase`, positional `material_stdin`)
- `src/cli.rs:60-75` — `Receive` struct (add `passphrase_file`, `passphrase_fd`, hidden `passphrase`)
- `src/main.rs:80-171` — Send dispatch (thread new flags into `resolve_passphrase`; handle positional `-`)
- `src/main.rs:172-220` — Receive dispatch (thread new flags)
- `src/transport.rs` — DHT label constants (target of D-P5-12 constant-match test)

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `cipherpost::identity::resolve_passphrase(inline_argv, env_var_name, file, fd, confirm_on_tty)` at `src/identity.rs:258` — already supports all four sources; Phase 5 is plumbing + two internal fixes (BorrowedFd, strip rule), not a rewrite.
- `Error::PassphraseInvalidInput` — already used for argv-inline rejection; reuse for send/receive rejection path so error-oracle hygiene stays uniform (same Display, same exit code).
- `Error::Config(String)` — already the escape hatch for CLI-level validation errors; use for `--passphrase-fd 0` rejection and multi-source conflict.
- MockTransport at `src/transport.rs` — carries PASS-09's integration test without touching real DHT.
- `serial_test = "3"` + `#[serial]` pattern — already in place for env-mutating tests; new fd-lifecycle test should adopt it.

### Established Patterns
- Clap surface locked at Phase 1 (D-11) — additions only, no rearranging. Phase 5 is purely additive.
- Hidden `passphrase: Option<String>` with `hide = true` attribute → runtime rejection in `resolve_passphrase` (see `src/cli.rs:117-121`). Same pattern for send/receive.
- `--help` EXAMPLES blocks are embedded in `#[command(long_about = "...")]` with `\n  \` line continuations (see `src/cli.rs:105-109`). Copy shape for send/receive.
- Identity path mode enforcement — `mode != 0o600 && mode != 0o400 → Error::IdentityPermissions` at `src/identity.rs:293-296`. Same check applies verbatim to `--passphrase-file` (it's the same code path after D-P5-07).

### Integration Points
- `src/main.rs` Send/Receive dispatchers currently call `resolve_passphrase(None, Some("CIPHERPOST_PASSPHRASE"), None, None, false)` — just thread `passphrase.as_deref()`, `passphrase_file.as_deref()`, `passphrase_fd` in from the clap structs.
- No change needed in `src/flow.rs::run_send` / `::run_receive` — passphrase is consumed before either is called.
- No change to `Transport`, `Envelope`, `OuterRecord`, `Receipt` — Phase 5 is purely CLI-surface + passphrase-helper + docs.
- JCS fixtures (`tests/fixtures/outer_record_signable.bin`, `tests/fixtures/receipt_signable.bin`) are unaffected — no wire-format change.

### Anti-patterns to avoid (from prior phases)
- Do NOT add a new HKDF call site in Phase 5 (none is needed). If one appears in review, stop — the enumeration test will flag it and the answer is "remove it."
- Do NOT introduce a new exit code for multi-source conflict; exit 1 (`Error::Config`) reuses the existing CLI-validation bucket.
- Do NOT `#[derive(Debug)]` on any new struct that touches the passphrase bytes — `Passphrase` already has a manual redacting impl; don't shadow it.

</code_context>

<specifics>
## Specific Ideas

- **SC1 runs verbatim:** `cipherpost send - --passphrase-fd 3 < payload.bin 3< passphrase.txt` must execute exactly as written after D-P5-05 (positional `-`). Phase 5's CI test (PASS-09) should quote this line in a comment at the top so future readers see the canonical shape.
- **`cipherpost receive --passphrase-file ~/.cipherpost/pp.txt`** is the other SC1 half; the file must be mode 0600 (reuse `Error::IdentityPermissions`).
- **Python subprocess recipe** for SPEC.md §7 (not --help): `subprocess.run(["cipherpost", "send", "-"], pass_fds=[3], stdin=payload_bytes_fd)` — shows the correct `pass_fds` wiring.
- **Per Pitfall #35**, SPEC.md §7 lists sources in this exact order with one-line rationale each: `fd (no process-table exposure) > file (no process-table exposure, inode permission) > env (visible via /proc/<pid>/environ, ps auxe) > TTY (interactive only; cannot be scripted)`.

</specifics>

<deferred>
## Deferred Ideas

- **URI-on-stdin for `receive`** (`echo <uri> | receive - --passphrase-fd 3`): useful for pipelines that produce the URI upstream. Net-new surface beyond PASS-01..09 scope. → roadmap backlog.
- **Python subprocess + bash `pass_fds` examples in `--help`**: mentioned in Pitfall 31; deferred to SPEC.md §7 only to keep `--help` compact.
- **CI step that greps SPEC.md and code for DHT label strings** (belt-and-suspenders beyond the unit test): the unit test alone is sufficient per D-P5-12. → deferred.
- **Dated baseline snapshot appendix in SPEC.md** listing exact crate versions at v1.1 cut: rejected — Cargo.toml is the snapshot authority; SPEC.md stays version-neutral. → not revisited unless an auditor asks.
- **`.planning/CONVENTIONS.md` aggregation doc**: single convention doesn't justify a file. Revisit when the second one shows up.
- **Stderr warning on `CIPHERPOST_PASSPHRASE` use**: deliberately declined in D-P5-02. If a security review later demands it, revisit.
- **Non-interactive PIN (`--pin-fd`, `--pin-file`)**: already deferred to v1.2+ per DEFER-PIN-01/02 in REQUIREMENTS.md. Phase 8 will not surface these.

</deferred>

---

*Phase: 05-non-interactive-automation-e2e*
*Context gathered: 2026-04-23*
