# Phase 5: Non-interactive automation E2E - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in 05-CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-23
**Phase:** 05-non-interactive-automation-e2e
**Areas discussed:** Passphrase precedence conflict, Stdin + fd composition & CLI shape, Strip + BorrowedFd refactor scope, DOC deliverables shape

---

## Area Selection

| Option | Description | Selected |
|---|---|---|
| Passphrase precedence conflict | Resolve SPEC vs code vs Pitfall-35 three-way disagreement on fd/file/env ordering | ✓ |
| Stdin + fd composition & CLI shape | Positional `-` for send; scripting examples in --help; conflict handling | ✓ |
| Strip + BorrowedFd refactor scope | Fix resolve_passphrase once or fork a new path for send/receive | ✓ |
| DOC deliverables shape | DOC-01 pin-blessing phrasing; DOC-02 audit form; DOC-04 archive cleanup | ✓ |

**User's choice:** All four areas selected (multiSelect).

---

## Passphrase precedence conflict

### Q1: Which passphrase precedence should Phase 5 lock in?

| Option | Description | Selected |
|---|---|---|
| fd > file > env > TTY (code+Pitfall 35) | Edit SPEC.md §7.1 and PASS-05 wording to match code. Security guidance aligned. | ✓ |
| env > file > fd > TTY (SPEC+PASS-05) | Edit src/identity.rs to reorder. Silent behavior shift on unlock path. | |
| Error on multiple sources set | Require exactly one non-TTY source; Error::Config if two or more set together. | |

**User's choice:** fd > file > env > TTY — code wins. Edit SPEC and PASS-05 to match.

### Q2: Emit a stderr warning when CIPHERPOST_PASSPHRASE is the effective source?

| Option | Description | Selected |
|---|---|---|
| Yes, one-line warning | Pitfall 35 recommendation; noisy stderr in CI. | |
| No, document in SPEC.md §7 only | Keep stderr clean; rely on preference-ordering prose. | ✓ |
| Only warn when both TTY and env present | Narrow warning — only interactive runs. | |

**User's choice:** No — document in SPEC.md §7 only.

### Q3: Where does PASS-05's "matches identity subcommands" wording end up?

| Option | Description | Selected |
|---|---|---|
| Rewrite PASS-05 inline | Update REQUIREMENTS.md with explicit ordering; one authoritative place. | ✓ |
| Keep "matches identity" wording | Leave REQUIREMENTS.md pointing to identity behavior; SPEC §7.1 canonical. | |

**User's choice:** Rewrite PASS-05 inline.

### Q4: `--passphrase-fd 0` behavior?

| Option | Description | Selected |
|---|---|---|
| Accept — fd 0 is stdin | Matches current identity.rs comment ("if n == 0 that's stdin, which is fine"). | |
| Reject fd 0 with Error::Config | Refuse because stdin is reserved for payload I/O in send/receive. | ✓ |
| Accept on identity, reject on send/receive | Asymmetric: only ban where it'd conflict. | |

**User's choice:** Reject fd 0 with Error::Config (uniform across all subcommands).

**Notes:** This deviates from the current identity.rs:276 comment; the permissive fd=0 branch is removed. Migration note flagged in CONTEXT.md.

---

## Stdin + fd composition & CLI shape

### Q1: How do we square SC1's `cipherpost send - --passphrase-fd 3` with current `--material-file` surface?

| Option | Description | Selected |
|---|---|---|
| Add positional `-` = stdin | Positional-only shorthand for `--material-file -`; existing form still works. | ✓ |
| Rephrase SC1 to use --material-file - | Keep CLI shape; rewrite SC1 prose. | |
| Full positional: `send <path\|->` | Replace --material-file entirely; breaking change. | |

**User's choice:** Add positional `-` = stdin.

### Q2: Does `receive` need a scripting-shape decision?

| Option | Description | Selected |
|---|---|---|
| No change — current shape works | Only add --passphrase-file / --passphrase-fd flags. | ✓ |
| Accept URI on stdin when share arg is `-` | Net-new surface; belongs in backlog. | |

**User's choice:** No change.

### Q3: How should conflicts between passphrase sources surface?

| Option | Description | Selected |
|---|---|---|
| Silent — highest-priority source wins | Matches current resolve_passphrase behavior. | |
| Error on multiple flag sources | Exit 1 on fd + file together; env + flag still permitted. | ✓ |
| Error on ANY multiple sources including env | Stricter; breaks common env-as-default pattern. | |

**User's choice:** Error on multiple flag sources.

### Q4: Scripting examples in --help (PASS-08) — how much detail?

| Option | Description | Selected |
|---|---|---|
| One canonical example per source in send/receive | Three examples (env, file, fd); parity with identity generate EXAMPLES. | ✓ |
| Minimal: one FD example + pointer to SPEC §7 | Single example; users click through. | |
| Rich: add Python subprocess + bash pass_fds | Language-specific snippets; inflates --help. | |

**User's choice:** One canonical example per source.

---

## Strip + BorrowedFd refactor scope

### Q1: Scope of the fix in `resolve_passphrase`?

| Option | Description | Selected |
|---|---|---|
| Fix in resolve_passphrase itself | One edit covers identity + send + receive; uniform behavior. | ✓ |
| Fork: new path for send/receive only | Two code paths, two test sets; drift risk. | |
| Fix only in identity subcommands | Same as option 1 — user flagged as the explicit read. | |

**User's choice:** Fix in resolve_passphrase itself.

### Q2: Exact strip rule?

| Option | Description | Selected |
|---|---|---|
| One \r\n if present, else one \n, else nothing | Pitfall 30 prescription; space preserved. | ✓ |
| One \n OR one \r OR one \r\n at end | Also strips bare \r (Mac-era text editors). | |
| One \n only (reject files containing \r) | Strictest; breaks Windows-authored files. | |

**User's choice:** One \r\n if present, else one \n, else nothing.

### Q3: Test coverage for strip rule?

| Option | Description | Selected |
|---|---|---|
| Unit tests + one integration test | Unit for five cases; integration proves end-to-end. | ✓ |
| Unit + integration + assert_cmd CLI test | Binary-level; slower CI; overlaps PASS-09. | |
| Integration only (covered by PASS-09) | Faster; regression risk. | |

**User's choice:** Unit tests + one integration test.

### Q4: fd-lifecycle runtime test?

| Option | Description | Selected |
|---|---|---|
| Yes, write an fd-lifecycle test | Pipe + fcntl assertion; Pitfall 31's named prevention. | ✓ |
| No, rely on BorrowedFd type safety | Borrow checker enforces ownership at compile time. | |

**User's choice:** Yes — explicit runtime test.

---

## DOC deliverables shape

### Q1: DOC-01 — SPEC.md crate-version style?

| Option | Description | Selected |
|---|---|---|
| API-range only, point to Cargo.toml | Pitfall 34 prescription; no exact numbers in prose. | ✓ |
| API-range + dated baseline snapshot appendix | Snapshot for auditors; risks staleness. | |
| Exact versions, CHANGELOG pointer | Simplest edit; fails Pitfall 34's guidance. | |

**User's choice:** API-range only.

### Q2: DOC-02 — DHT label audit deliverable?

| Option | Description | Selected |
|---|---|---|
| Constant-match test + SPEC §3.3 note | Executable audit; Pitfall 33 prescription. | ✓ |
| + standalone docs/dht-label-audit.md | Paper trail; ~30 min extra. | |
| + audit memo + CI grep assertion | Belt-and-suspenders; overkill for 5 labels. | |

**User's choice:** Constant-match test + SPEC §3.3 note only.

### Q3: DOC-04 — archived v1.0 REQUIREMENTS.md cleanup?

| Option | Description | Selected |
|---|---|---|
| Drop the traceability table from archive | Delete table; forward-pointer note to VERIFICATION.md files. | ✓ |
| Edit rows to match shipped state | Walk each row; ~hour of drudgery; table dies next release anyway. | |
| Add `[Deprecated]` prefix, leave rows | Cheap but leaves "Pending" smell. | |

**User's choice:** Drop the table.

### Q4: DOC-03 — where is the convention documented?

| Option | Description | Selected |
|---|---|---|
| REQUIREMENTS.md Structure note + CLAUDE.md | CLAUDE.md is where future sessions read working instructions. | ✓ |
| REQUIREMENTS.md + dedicated CONVENTIONS.md | More scaffolding for one rule; premature. | |
| Only REQUIREMENTS.md Structure note | Current state; Claude sessions may miss it. | |

**User's choice:** REQUIREMENTS.md Structure note + CLAUDE.md.

---

## Claude's Discretion

- Exact error-message strings for new rejection paths (`--passphrase-fd 0`, multi-source conflict, inline `--passphrase` on send/receive) — follow error-oracle hygiene; reuse `Error::PassphraseInvalidInput` Display for argv-inline.
- CI integration test file layout for PASS-09 (new file vs fold into existing mock-transport test).
- Inline strip-rule cases as Rust literals vs fixtures file.
- Plan-split ordering across the 14 decisions (planner's call).

## Deferred Ideas

- URI-on-stdin for `receive` → roadmap backlog.
- Python/bash snippets in --help → deferred to SPEC.md §7 only.
- Dated baseline snapshot appendix in SPEC.md → declined.
- `.planning/CONVENTIONS.md` aggregation → revisit when second convention appears.
- Stderr warning on `CIPHERPOST_PASSPHRASE` use → revisit if security review demands.
- CI grep-based label audit → unit test is sufficient.
