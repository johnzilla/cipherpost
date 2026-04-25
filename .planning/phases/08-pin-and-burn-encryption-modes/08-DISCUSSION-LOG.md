# Phase 8: --pin and --burn encryption modes - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-25
**Phase:** 08-pin-and-burn-encryption-modes
**Areas discussed:** HKDF info conflict resolution, Burn ordering conflict resolution, Plan structure & sequencing, Wire shape (salt placement & burn field encoding), Compose semantics (pin × burn × typed-material), State-ledger `burned` shape

---

## Pre-Discussion: cclink survey (resolves blocked research prerequisite)

**Action taken:** Surveyed `/home/john/vault/projects/github.com/cclink/src/` (was access-denied during research; reachable at this phase).

**Findings:**
- `cclink/src/crypto/mod.rs::pin_derive_key()` — Argon2id → HKDF-SHA256 with info `cclink-pin-v1` → 32-byte key.
- `cclink/src/crypto/mod.rs::pin_encrypt()` — calls `chacha20poly1305` directly with the derived key. **Cipherpost cannot copy verbatim** (CLAUDE.md prohibits).
- `cclink/src/commands/pickup.rs::252` — burn publishes empty packet over DHT slot (revoke-style). **Cipherpost rejects DHT mutation** (BURN-08 local-state-only).

**Captured into:** CONTEXT.md D-P8-01 (full divergence write-up).

---

## Conflict resolutions (locked before deep-dive)

### HKDF info string conflict

REQUIREMENTS.md PIN-03: `cipherpost/v1/pin`
research/SUMMARY.md: `cipherpost/v1/pin_wrap`

| Option | Description | Selected |
|--------|-------------|----------|
| `cipherpost/v1/pin` | Matches REQUIREMENTS.md PIN-03 (canonical lock). Shorter, parallels cclink's `cclink-pin-v1` (one segment). Treat SUMMARY.md as outdated draft. | ✓ |
| `cipherpost/v1/pin_wrap` | Matches research SUMMARY.md. The `_wrap` suffix signals 'wraps the inner age envelope' — slightly more descriptive of what this key does. | |

**User's choice:** `cipherpost/v1/pin` (Recommended — REQUIREMENTS.md canonical)
**Notes:** Captured as D-P8-02. Plan 01 must extend the HKDF info enumeration test with this literal.

### Burn-mode atomicity conflict

REQUIREMENTS.md BURN-03: stdout emit BEFORE `burned` state write
research/PITFALLS.md #26: keep v1.0 mark-then-emit ordering

| Option | Description | Selected |
|--------|-------------|----------|
| Emit BEFORE mark (REQUIREMENTS BURN-03) | decrypt → emit bytes → write `burned` state. Crash between emit-and-mark = share re-receivable (user keeps access). Matches REQUIREMENTS.md as locked. | ✓ |
| Mark BEFORE emit (Pitfall #26 / v1.0 parity) | Write `burned` → emit bytes. Crash between mark-and-emit = share consumed but never delivered (user loses data). | |
| Two-phase commit (pending → emitted-not-acked → burned) | Three-state ledger: strongest guarantee but adds a third state. Probably overkill for v1.1. | |

**User's choice:** Emit BEFORE mark (Recommended — REQUIREMENTS BURN-03)
**Notes:** Captured as D-P8-12. Resolution: PITFALLS #26 is OUTDATED; superseded by BURN-03 lock-in. v1.0's `accepted` ordering is unchanged (mark-then-emit there). The two state types have OPPOSITE atomicity contracts.

### Areas to deep-dive

| Option | Description | Selected |
|--------|-------------|----------|
| Plan structure & sequencing | # of plans, PIN-then-BURN vs interleaved, where cclink-divergence write-up lands, where THREAT-MODEL.md edits land. | ✓ |
| Wire shape: salt placement & burn field encoding | PIN-05 says salt embedded in blob; alternative is separate field. Both fit JCS. | ✓ |
| Compose semantics: pin + burn + typed-material | Receive flow ordering, banner UX for compose case. | ✓ |
| State-ledger `burned` shape | New field on existing entry, new entry kind, or separate file? | ✓ |

---

## Plan structure & sequencing

| Option | Description | Selected |
|--------|-------------|----------|
| 6 plans — PIN core / PIN ship-gate / BURN core / BURN ship-gate / compose / docs | Each feature gets a 2-plan core+ship-gate sequence (mirrors Phase 6 X.509). Plan 5 covers compose tests. Plan 6 lands THREAT-MODEL.md + SPEC.md + cclink-divergence. | ✓ |
| 4 plans — tight: PIN end-to-end / BURN end-to-end / compose / docs | Each feature is one plan from foundation through ship-gate. Faster but each plan is bigger; risk of churn cascading. | |
| 8 plans — mirror Phase 7 (4 PIN + 4 BURN) | Most granular, clearest commits, but BURN's 9 reqs spread thin across 4 plans — make-work. | |
| 5 plans — PIN crypto / PIN UX+tests / BURN ledger+UX / compose+ship-gate / docs | PIN gets crypto-isolation; BURN compresses; compose+ship-gate combined to keep total small. | |

**User's choice:** 6 plans (Recommended)
**Notes:** Captured as D-P8-13.

| Option | Description | Selected |
|--------|-------------|----------|
| PIN-first; cclink write-up in Plan 01 SUMMARY | PIN is crypto-heavy half; tackle hard part first while context fresh. cclink survey + divergence rationale go into Plan 01 SUMMARY.md. | ✓ |
| BURN-first; survey lives in pre-flight task | BURN is mostly state-ledger plumbing; quick win first. cclink survey becomes Plan 00 pre-flight. | |
| Parallel-track (interleave PIN and BURN plans) | Keeps both features moving but increases per-plan context-switching. Premature optimization. | |

**User's choice:** PIN-first (Recommended)
**Notes:** Captured as D-P8-14.

---

## Wire shape: salt placement & burn field encoding

| Option | Description | Selected |
|--------|-------------|----------|
| Embedded, conditional on pin_required (follows PIN-05) | When pin_required=true: `blob = base64(salt[32] \|\| age_ct)`. When false: v1.0 wire shape. Receiver dispatches on flag. | ✓ |
| Separate `pin_salt: Option<[u8;32]>` field on OuterRecord | Cleaner: blob never changes shape; salt is its own outer-signed field. Diverges from PIN-05 wording. | |
| Embedded, always two-tone (32-byte zero-prefix when no pin) | Simplest extraction (always strip 32 bytes). Breaks v1.0 byte-identity for ALL shares — protocol_version bump. Hard reject. | |

**User's choice:** Embedded, conditional on pin_required (Recommended — follows PIN-05)
**Notes:** Captured as D-P8-05.

| Option | Description | Selected |
|--------|-------------|----------|
| Lock as written — inner-signed bool with skip-if-false | `Envelope.burn_after_read: bool`, post-decrypt visibility, skip_serializing_if=is_false. v1.0 byte-identity preserved for non-burn shares. | ✓ |
| Promote to OuterRecord (so observer sees burn flag pre-decrypt) | Diverges from BURN-01. Lets DHT observers see which shares are burn-marked — explicit anti-goal. Hard reject. | |

**User's choice:** Lock as written (Recommended)
**Notes:** Captured as D-P8-04.

---

## Compose semantics: pin + burn + typed-material

| Option | Description | Selected |
|--------|-------------|----------|
| Outer = identity, Inner = pin | `inner = age_encrypt(pin, envelope)` then `outer = age_encrypt(identity, inner)` then `blob = base64(salt \|\| outer)`. v1.0 byte-identity preserved for non-pin. Wrong-identity fails outer; wrong-PIN fails inner. | ✓ |
| Outer = pin, Inner = identity | Reverses layers. Wrong-PIN fails first. Slightly more conceptually natural ('PIN is outer gate') but changes v1.0's outer-most layer. | |

**User's choice:** Outer = identity, Inner = pin (Recommended)
**Notes:** Captured as D-P8-06.

| Option | Description | Selected |
|--------|-------------|----------|
| Earliest possible: right after share_ref derived, before any decrypt | Saves PIN prompt + decrypts on already-burned share. | ✓ |
| After all decrypts, before banner | Wastes PIN prompt + decrypts. Probably overengineered for v1.1. | |
| After typed-z32 acceptance, before emit | Last-possible-moment. Closer to TOCTOU-safe but worse UX. | |

**User's choice:** Earliest possible (Recommended)
**Notes:** Captured as D-P8-09.

| Option | Description | Selected |
|--------|-------------|----------|
| Top of header, before Purpose line | Maximum visibility; user sees `[BURN]` warning before reading anything else. Mirrors Phase 7's elevated SECRET-key warning. | ✓ |
| Inline with Type: line | `Type: pgp_key [BURN]` — compact but skim-past risk. | |
| Above typed-z32 prompt (just before commit) | Strongest 'final warning' but user already mentally committed. | |

**User's choice:** Top of header (Recommended)
**Notes:** Captured as D-P8-08. Banner mockup committed to CONTEXT.md `<specifics>`.

---

## State-ledger `burned` shape

| Option | Description | Selected |
|--------|-------------|----------|
| Add `state: "accepted"\|"burned"` to ledger rows | Single `accepted.jsonl`. v1.0 rows default to `accepted` via serde. `check_already_consumed()` returns enum {None, Accepted, Burned}. | ✓ |
| Separate `burned/<share_ref>` sentinel + `burned.jsonl` ledger | Mirror v1.0 structure for burn. Two parallel state directories. Doubles state-management surface. | |
| Reuse `accepted/<share_ref>` sentinel; differentiate via JSONL row only | Sentinel stays at `accepted/<share_ref>` for both. Ledger row carries state. Conflates 'accepted' and 'burned' at sentinel layer. | |

**User's choice:** Add `state` field to ledger rows (Recommended)
**Notes:** Captured as D-P8-10.

| Option | Description | Selected |
|--------|-------------|----------|
| ledger row appended FIRST, then sentinel touched | Burn sequence: emit → fsync → append `state: burned` row → fsync → touch sentinel. Crash between ledger-and-sentinel = next receive scans ledger, sees burned row. | ✓ |
| sentinel touched first (matches v1.0) | Contradicts BURN-03 (emit-before-mark). Listed only to confirm rejection. | |
| Single atomic write (sentinel filename embeds state) | `accepted/<share_ref>.burned`. Atomic on POSIX. Hides state from ledger inspection; awkward to audit. | |

**User's choice:** ledger row first, then sentinel (Recommended)
**Notes:** Captured as D-P8-11.

---

## Claude's Discretion

The following items the user explicitly or implicitly deferred to Claude's choice during planning:
- Argon2id salt-buffer reuse strategy (`Zeroizing<[u8; 32]>` vs new buffer per call)
- Whether `src/pin.rs` is a new file or extension to `src/crypto.rs` (Phase 6/7 precedent suggests new file)
- Exact `Error::PinTooWeak` reason literals (curated short strings, oracle-hygiene matrix)
- `LedgerState` enum location (`src/state.rs` new, vs `src/flow.rs` existing)
- PIN retry behavior on wrong PIN (recommendation: single-shot fail; matches v1.0 passphrase prompt)
- Hard-fail on `--pin` in non-TTY context (recommendation: yes, exit 1 with informative message)
- Banner separator widths (matches Phase 7 conventions)
- Whether burn receipts carry distinguishing markers (recommendation: NO — receipt shape is identical)

## Deferred Ideas

Ideas mentioned during discussion that were noted for future milestones (full list in CONTEXT.md `<deferred>`):

- Non-interactive PIN sources (`--pin-file`, `--pin-fd`, `CIPHERPOST_PIN`) — DEFER-PIN v1.2+
- DHT-side burn (cclink-style revoke) — explicit BURN-08 rejection, contract
- Cryptographic burn destruction — out-of-scope per REQUIREMENTS
- PIN recovery — explicit non-feature
- PIN retry counter / lockout — single-shot fail for v1.1
- Wire-budget escape hatch for pin+burn+typed-material composites — v1.2 wire-budget milestone
- `--pin` rotation / change-PIN — impossible without re-send
- Burn confirmation prompt (extra "are you sure?") — `[BURN]` banner is the warning
- Burn sentinel TTL / cleanup tooling — until disk usage matters
- Different state-ledger format (SQLite) — v2.0 at earliest
- Dedicated `cipherpost burn <share-ref>` command — receive-mode property, not separate command
- Send-time `--pin <value>` argv-inline — rejected at parse + runtime per CLAUDE.md
