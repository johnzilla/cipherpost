---
phase: 09-real-dht-e2e-cas-merge-update-race-gate
reviewed: 2026-04-26T00:00:00Z
depth: standard
files_reviewed: 11
files_reviewed_list:
  - .config/nextest.toml
  - CLAUDE.md
  - Cargo.toml
  - README.md
  - RELEASE-CHECKLIST-v1.1.md
  - RELEASE-CHECKLIST.md
  - SPEC.md
  - src/flow.rs
  - src/transport.rs
  - tests/cas_racer.rs
  - tests/real_dht_e2e.rs
  - tests/wire_budget_compose_pin_burn_pgp.rs
findings:
  critical: 0
  warning: 2
  info: 4
  total: 6
status: issues_found
---

# Phase 9: Code Review Report

**Reviewed:** 2026-04-26
**Depth:** standard
**Files Reviewed:** 11
**Status:** issues_found

## Summary

Phase 9 ships a clean single-retry CAS contract and a triple-gated real-DHT
release-acceptance test. The `MockTransport` `lock-read-drop-merge-relock-cas`
dance correctly models pkarr's `Timestamp`-based CAS for the contended
`publish_receipt` path under Barrier-synced contention, and oracle hygiene is
preserved end-to-end (no public `Error::CasConflict` variant; the private
`CasConflictFinal` marker rides `Error::Transport(Box<dyn Error>)` whose
`Display` is the generic `"transport error"` string and whose source chain is
never walked by `error::user_message`).

Two warnings worth resolving before v1.1:

1. **`tests/real_dht_e2e.rs` uses `alice_transport` to wait for Alice's published
   share to propagate, not `bob_transport`.** The test's stated purpose is
   "Bob resolves Alice's share" via a 7-step exp-backoff propagation loop, but
   the loop calls `alice_transport.resolve(&alice_z32)`. pkarr's local cache may
   short-circuit and return Alice's just-published packet without ever leaving
   her process — so the propagation wait does not actually validate
   cross-client DHT visibility. The subsequent `run_receive` does use
   `bob_transport` (via the `&bob_transport` argument) but with no internal
   backoff, so a slow propagation could break the test even though the
   pre-wait succeeded. The symmetric receipt-fetch loop at line 223
   (`alice_transport.resolve_all_cprcpt(&bob_z32)`) is correct because it
   tests Alice's view of Bob's published receipt.

2. **`MockTransport::publish` does not bump `seq`, creating a concurrent
   `publish` + `publish_receipt` data-loss window.** Under racing
   `publish` (outer share) + `publish_receipt` (receipt) on the same z32, the
   `publish_receipt_attempt_mock` clones records under lock at step 1 and
   commits the merged set at step 3 without the seq having advanced — so a
   `publish` that landed in between would be silently dropped. Production
   `DhtTransport` does not have this gap (pkarr's real Timestamp covers all
   mutations), and current cipherpost flow never publishes from the same
   keypair concurrently, so the bug is dormant in v1.1. Worth a code comment
   so a future expansion of MockTransport's contract does not silently
   regress.

The four info items are documentation/cosmetic and do not block the phase.

## Warnings

### WR-01: real-DHT propagation wait uses Alice's transport, not Bob's

**File:** `tests/real_dht_e2e.rs:153`
**Issue:** The 7-step exp-backoff loop that establishes "Alice's share has
propagated to the DHT before Bob attempts receive" calls
`alice_transport.resolve(&alice_z32)` rather than `bob_transport.resolve(&alice_z32)`.

The doc comment at lines 102 + 141 frames the loop as "Bob resolves Alice's
published share with a 7-step exp-backoff." Because the resolve uses Alice's
own client handle, pkarr's in-process cache may answer from the just-published
packet without exercising any DHT round-trip. The test could pass on a host
where Bob would actually fail to resolve.

The actual cross-identity step is `run_receive(&bob_id, &bob_transport, ...)`
on line 195, which does use Bob's transport, but `run_receive` does not
implement its own propagation backoff — a single resolve attempt that fails
yields a hard `Error::NotFound` and the test panics. So the pre-`run_receive`
backoff loop is the only propagation-wait, and it is talking to the wrong DHT
client.

**Fix:**
```rust
// Use bob_transport (the receiving client) to verify cross-identity
// propagation, not alice_transport (the publishing client).
match bob_transport.resolve(&alice_z32) {
    Ok(record) => {
        resolved = Some(record);
        break;
    }
    Err(_) => {
        let remaining = deadline.saturating_duration_since(Instant::now());
        let sleep_for = Duration::from_secs(delay_secs).min(remaining);
        if sleep_for.is_zero() {
            panic!("real-dht-e2e: deadline exhausted between attempts");
        }
        std::thread::sleep(sleep_for);
    }
}
```

The receipt-fetch loop at line 223 already follows this pattern correctly
(`alice_transport.resolve_all_cprcpt(&bob_z32)` — the *fetcher's* client
resolves the *publisher's* z32). Mirror that asymmetry in the share-resolve
loop.

---

### WR-02: MockTransport.publish does not bump seq — concurrent publish + publish_receipt has a data-loss window

**File:** `src/transport.rs:484-491`
**Issue:** `publish_receipt_attempt_mock` (line 436) implements CAS via
per-key `seq:u64`, but `MockTransport::publish` (line 484) writes outer-share
records without bumping `entry.seq`. The lock-read at the top of
`publish_receipt_attempt_mock` (line 446) clones records, drops the lock,
re-acquires it, and commits the merged set — so any record inserted by a
concurrent `publish` between the lock-drop and re-acquire would be silently
overwritten by the `entry.records = merged` assignment on line 467, because
the seq did not change and the CAS check passed.

The comment on line 486-488 acknowledges this:
> Phase 9: D-P9-A3 — outer-share publish path is NOT cas-checked
> (only `publish_receipt` is). Clobber-replace the same-label
> entry; do not bump seq (seq is receipt-publish bookkeeping).

The behavior is correct for current cipherpost flow (a single keypair never
concurrently calls `publish` and `publish_receipt` — `run_send` and
`run_receive` are sequential within a process). But the MockTransport's
documented invariant is "model pkarr CAS behaviorally," and pkarr's real
Timestamp covers ALL mutations under a key. Future tests that exercise
`publish` ↔ `publish_receipt` concurrency would silently lose the outer
record without any test signal.

**Fix:** Either bump seq in `publish` (cheapest; aligns with pkarr's
"every mutation advances the timestamp" contract):
```rust
let mut store = self.store.lock().unwrap();
let entry = store.entry(z32).or_default();
entry.records.retain(|(label, _)| label != DHT_LABEL_OUTER);
entry.records.push((DHT_LABEL_OUTER.to_string(), rdata));
entry.seq = entry.seq.saturating_add(1); // ADD: model pkarr Timestamp
Ok(())
```

OR, if the invariant is intentionally narrower than pkarr's, expand the
comment to explicitly forbid concurrent `publish` + `publish_receipt` on the
same z32 in tests:

```rust
// Phase 9: D-P9-A3 — outer-share publish path is NOT cas-checked
// (only `publish_receipt` is). Clobber-replace the same-label
// entry; do not bump seq (seq is receipt-publish bookkeeping).
//
// CONTRACT: callers MUST NOT race `publish` against `publish_receipt`
// on the same keypair — there is no CAS guard for outer-share writes,
// and a concurrent publish_receipt could clobber the outer record by
// committing its cloned-records snapshot. Cipherpost's real flow never
// does this; future tests that need cross-method concurrency must
// re-evaluate this contract.
```

Either path resolves the latent gap. The first is preferable because it
keeps MockTransport's behavioral parity with pkarr.

## Info

### IN-01: Documentation claim "the trait method's outer single-retry loop" is mildly misleading — there is no loop, just two sequential match expressions

**File:** `src/transport.rs:265-287` (DhtTransport), `src/transport.rs:519-535`
(MockTransport); also CLAUDE.md:102 ("the retry loop lives **inside** the
`Transport` trait method")

**Issue:** Both `publish_receipt` impls and the CLAUDE.md lock-in description
talk about a "retry loop," but the implementation is two sequential `match`
expressions on the helper's `PublishOutcome` (first attempt, then second
attempt with no looping construct). This is correct — single-retry-then-fail
is exactly what was specified — but a future reader scanning for `for` /
`while` / `loop` to confirm the behavior will not find one.

**Fix:** Either rename the doc string to "retry path" / "single-retry sequence,"
or add a one-line comment at the top of each `publish_receipt` body:

```rust
// Single-retry sequence: try once, on CasConflict try once more, on second
// CasConflict surface CasConflictFinal via Error::Transport. NOT a loop —
// strictly two attempts max.
```

Cosmetic; does not affect correctness.

---

### IN-02: `nextest --filter-expr 'test(real_dht_e2e)'` filter relies on substring-match against the binary name, not the test function name

**File:** `RELEASE-CHECKLIST.md:56`, `RELEASE-CHECKLIST-v1.1.md:48`
**Issue:** The test function is named
`real_dht_cross_identity_round_trip_with_receipt`; the binary
(integration-test crate) is `real_dht_e2e`. Nextest's `test()` predicate
matches against the qualified `<binary>::<function>` test name as a
substring. The substring `real_dht_e2e` appears in the binary-name prefix,
so the filter does select the test — but a reader expecting the filter to
match the function name would be confused.

**Fix:** Either rename the test function to include `real_dht_e2e` as a
prefix (e.g. `real_dht_e2e_cross_identity_round_trip_with_receipt`), or add
a one-line note in the checklist that the filter matches the binary name:

```markdown
- [ ] Run: `cargo nextest run --features real-dht-e2e --run-ignored only \
        --filter-expr 'test(real_dht_e2e)' --no-fail-fast`
        (the filter matches the integration-test BINARY name `real_dht_e2e`,
        which is the file basename `tests/real_dht_e2e.rs`; the test
        function inside is `real_dht_cross_identity_round_trip_with_receipt`)
```

---

### IN-03: README "Known limitations in v1.0" still lists deferred items as-of-v1.0; v1.1 ships some of them

**File:** `README.md:109-115`
**Issue:** The "Known limitations in v1.0" section still claims:

> - Real-DHT cross-identity round trip is documented tech debt — MockTransport exercises the full code path but the two-identity A→B→receipt flow across separate processes over Mainline DHT is pending a future release-acceptance test.
> - Only `Material::GenericSecret` is implemented. ...
> - `--pin` and `--burn` encryption modes are not implemented — targeted for the next milestone.

Phases 6 / 7 / 8 / 9 in the v1.1 milestone shipped the real-DHT release-
acceptance test (Phase 9 — the file under review), `Material::X509Cert`,
`PgpKey`, `SshKey` (Phases 6/7), and `--pin` / `--burn` (Phase 8). The
README still says they are deferred.

**Fix:** Update the section to "Known limitations in v1.1" and re-scope the
list. CLAUDE.md was already updated for Phase 9 (line 102 + 104) — README
needs the same pass. This is the kind of doc drift the PROJECT.md
checkpoint catches at milestone close.

---

### IN-04: `cipherpost_debug_enabled()` env read is repeated per-attempt in both transport impls

**File:** `src/transport.rs:42-44, 274, 525`
**Issue:** `cipherpost_debug_enabled()` reads `std::env::var("CIPHERPOST_DEBUG")`
on every CAS-retry path. A read is cheap, and the racer test does not exercise
this code path (default-silent), so the cost is irrelevant. But two readers
will see the boolean twice (once in DhtTransport, once in MockTransport) —
which means a CIPHERPOST_DEBUG flip between the first and second attempts
would change behavior between attempts.

In practice this can't happen (env vars are not racing here), but it is a
pattern worth flagging for future hardening: read once, plumb the boolean
to the helper. Cosmetic; current behavior is correct.

**Fix:** None required for v1.1. If revisited:
```rust
fn publish_receipt(&self, ...) -> Result<(), Error> {
    let debug = cipherpost_debug_enabled();
    match self.publish_receipt_attempt(...) {
        PublishOutcome::Ok => return Ok(()),
        PublishOutcome::Other(e) => return Err(e),
        PublishOutcome::CasConflict => {
            if debug { eprintln!("Receipt publish: CAS conflict, retrying once..."); }
        }
    }
    // ... retry
}
```

---

_Reviewed: 2026-04-26_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
