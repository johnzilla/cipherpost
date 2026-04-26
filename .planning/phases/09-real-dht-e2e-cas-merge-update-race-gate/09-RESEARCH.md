# Phase 9: Real-DHT E2E + CAS merge-update race gate - Research

**Researched:** 2026-04-26
**Domain:** PKARR concurrent-publish CAS semantics; real-DHT cross-identity round trip discipline; cargo-nextest timeout configuration; pkarr 5.0.4 internal behavior
**Confidence:** HIGH for pkarr API surface (verified against `~/.cargo/registry/src/.../pkarr-5.0.4/src/`); HIGH for nextest config; HIGH for Mainline bootstrap defaults (verified against mainline 6.1.1 source)

## Summary

CONTEXT.md locks D-P9-A1..F1; this RESEARCH.md fills the explicit open items the planner needs at plan time. Five findings dominate:

1. **`PublishError::Concurrency(ConcurrencyError::CasFailed)` is the variant.** Verified in `pkarr-5.0.4/src/client.rs:567-624`. There are actually three `ConcurrencyError` variants — `ConflictRisk`, `NotMostRecent`, `CasFailed` — and ALL THREE indicate a "lost-update risk; resolve and retry" situation per upstream's own docstrings. The retry-inside-trait should treat all three as the conflict signal, not just `CasFailed`.

2. **pkarr 5.0.4 does NOT retry publish internally on either Query or Concurrency errors.** Verified by full `grep -rn 'retry' pkarr-5.0.4/src/`. The only retry path is `should_retry_with_cache_disabled` in `client/relays.rs:481` — that's relay-side cache invalidation, and we use `no_relays()` anyway. **There is no double-backoff stacking risk.** Our cipherpost-layer single-retry is the only retry layer.

3. **`cargo --test-timeout` does not exist on stable cargo or libtest.** Verified by `cargo test --help` and `cargo test -- --help`. The recommendation in CONTEXT.md D-P9-D3 conflated this with cargo-nextest's `slow-timeout` + `terminate-after` config-file syntax. **CI uses nextest** (`.github/workflows/ci.yml:35-46`), so the outer timeout guard belongs in `.config/nextest.toml` (new file), not as an invocation flag.

4. **pkarr 5.0.4's default Mainline bootstrap nodes are 4 hosts, all UDP/IPv4.** Verified at `mainline-6.1.1/src/rpc.rs:42-47`: `router.bittorrent.com:6881`, `dht.transmissionbt.com:6881`, `dht.libtorrent.org:25401`, `relay.pkarr.org:6881`. The UDP pre-flight should target one of these (recommend `router.bittorrent.com:6881` for max stability — the most widely deployed Mainline bootstrap host).

5. **`pkarr::Timestamp::as_u64` returns wall-clock microseconds.** Verified at `ntimestamp-1.0.0/src/lib.rs:79-101`. `SignedPacket::timestamp()` returns the packet's authored timestamp; passing `Some(packet.timestamp())` as `cas` to `client.publish()` says "fail if a more recent packet has been published since I read this one." This matches D-P9-A2's intent exactly. Existing `src/transport.rs:168` already does this — Phase 9 only needs to wrap the `publish` call in a single-retry loop.

**Primary recommendation:** Pick the 3-plan structure from D-P9-F1 candidate 2 (split CAS work into "MockTransport CAS internals + retry-inside-trait" and "DHT-07 wire-budget assertion") because the CAS retry touches both `MockTransport` AND `DhtTransport` AND the `map_pkarr_publish_error` helper — three edit sites in `src/transport.rs` plus a new test file. The wire-budget composite test is fixture-and-assertion only (one new test file, no source edits). Bundling them risks plan-check rejection for "two distinct ship-gate concerns in one plan."

## User Constraints (from CONTEXT.md)

### Locked Decisions

**A. CAS retry-and-merge contract:**
- D-P9-A1: Single retry-then-fail. On `CasConflict`: resolve once, merge, republish once. Second conflict → `Err` to caller.
- D-P9-A2: Retry loop lives INSIDE `Transport::publish_receipt`. `CasConflict` never crosses the trait boundary. Both `DhtTransport` and `MockTransport` implement the same retry contract.
- D-P9-A3: `MockTransport` models CAS via per-key `seq: u64`; mismatch returns internal `CasConflict`; `Barrier`-synced racer test exercises the trait method end-to-end.
- D-P9-A4: CAS retry events log to stderr only when `CIPHERPOST_DEBUG=1`. Default-silent.

**B. Bootstrap configuration:**
- D-P9-B1: pkarr defaults only for v1.1. No `CIPHERPOST_DHT_BOOTSTRAP` env var. STATE.md "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" todo CLOSEABLE.
- D-P9-B2: Bootstrap mechanism documented as a single sentence in README + SPEC.md inline note.

**C. RELEASE-CHECKLIST.md:**
- D-P9-C1: Standard ship-gate scope (~80 lines). Codifies what cipherpost already runs in CI plus the manual real-DHT step.
- D-P9-C2: Lives at repo root: `/RELEASE-CHECKLIST.md`.
- D-P9-C3: Markdown checkbox format with `[ ]`/`[x]`.
- D-P9-C4: Versioned snapshots per release (`RELEASE-CHECKLIST-v1.1.md`); template lives at `/RELEASE-CHECKLIST.md`.

**D. Real-DHT scope:**
- D-P9-D1: Cross-identity round trip ONLY. CAS racer stays MockTransport per DHT-02.
- D-P9-D2: Zero real-DHT tests in CI (PR or nightly). RELEASE-CHECKLIST manual run is the only gate. Behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`.
- D-P9-D3: 120s timeout enforced both in-test (`std::time::Instant` deadline) AND via test-runner timeout (belt-and-suspenders). **NB: see Open Question 5 resolution — outer guard is nextest config, not a `--test-timeout` flag.**
- D-P9-D4: Single file `tests/real_dht_e2e.rs` with `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` per test.

**E. Wire-budget headroom (DHT-07):**
- D-P9-E1: Synthesized 2KB byte vector (or padded PGP fixture) with `pin_required=true` + `burn_after_read=true` → assert clean `Error::WireBudgetExceeded` at send.

**F. Plan structure:**
- D-P9-F1: Planner picks 2/3/4 plans. CONTEXT.md recommends 3.

### Claude's Discretion

- Whether `CasConflict` is a named internal variant or a sentinel returned by a private helper.
- Exact exponential-backoff curve for the real-DHT resolve loop. CONTEXT recommends 1s, 2s, 4s, 8s, 16s, 32s, 64s.
- UDP pre-flight technique. CONTEXT recommends `std::net::UdpSocket::connect()` with 5s read timeout.
- Whether `RELEASE-CHECKLIST-v1.1.md` is committed at Phase 9 close (preferred) or at v1.1 release tag time.
- Whether bootstrap mention is a new section or single sentence (CONTEXT recommends single sentence).
- Whether `CIPHERPOST_DEBUG` becomes multi-purpose (CONTEXT recommends narrow scope for v1.1).

### Deferred Ideas (OUT OF SCOPE)

- `CIPHERPOST_DHT_BOOTSTRAP` env override / `--bootstrap` flag (revisit v1.2+ for private-testnet support)
- Multi-retry CAS schemes (3-attempt exp-backoff; deadline-bounded)
- CAS racer over real DHT (REQ DHT-02 binds to MockTransport)
- Multi-test real-DHT suite
- Real-DHT tests in nightly CI
- Public `Error::CasConflict` variant
- Multi-purpose `CIPHERPOST_DEBUG`
- RELEASE-CHECKLIST.md full ship-gate scope (CHANGELOG + version bump + git tag + crate publish dry-run)
- Wire-budget escape hatch (two-tier storage / chunking / OOB)
- Real-DHT bootstrap-default reachability test
- Multi-recipient receipt aggregation under contention
- Switching MockTransport to a behavior-faithful in-memory PKARR simulator

## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| DHT-01 | MockTransport enforces PKARR `cas` semantics on `publish_receipt` (per-key seq; mismatch → CasConflict). | Pattern Decision 1: per-key seq:u64 in MockStoreEntry; lock-check-bump-release inside publish_receipt; pkarr `Timestamp::as_u64()` semantics confirmed at `ntimestamp-1.0.0/src/lib.rs:98` — `seq: u64` is behaviorally faithful. |
| DHT-02 | CAS racer test: 2 threads via `Barrier`, both publish receipts to same key, 1 wins on first attempt, loser retries-and-merges, final state has both receipts. CI under `--features mock`. | Pattern Decision 2: `tests/cas_racer.rs` skeleton verified — `std::sync::Barrier::new(2)` + `std::thread::spawn` exercises the trait-internal retry path. Pitfall #28 prevention. |
| DHT-03 | Real-DHT e2e behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]`. Not a CI job. | Verified pkarr 5.0.4 `ClientBlocking` is sync-API (`futures_lite::future::block_on` internally — NO tokio runtime needed at our layer). New `[features] real-dht-e2e = []` in Cargo.toml. |
| DHT-04 | Real-DHT test: A publishes, B resolves with 120s exp-backoff, B decrypts, B publishes receipt, A fetches. | Pattern Decision 3: 1s/2s/4s/8s/16s/32s/64s curve (sum=127s, deadline-clipped at 120s); `std::time::Instant` deadline check before each sleep. pkarr does NOT retry publish internally — no double-backoff stacking. |
| DHT-05 | UDP pre-flight; canonical skip message if unreachable. | Pattern Decision 4: `std::net::UdpSocket::bind("0.0.0.0:0")` then `connect("router.bittorrent.com:6881")` with 5s read_timeout; pkarr's first default bootstrap (`mainline-6.1.1/src/rpc.rs:43`). |
| DHT-06 | RELEASE-CHECKLIST.md at repo root. Gates every v1.1+ release. | Pattern Decision 5: ~80-line checklist + versioned snapshot. CI uses cargo-nextest 0.9.100 (`.github/workflows/ci.yml:42-46`); manual release-DHT step uses `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)'` with profile-level slow-timeout. |
| DHT-07 | Wire-budget headroom: pin+burn+~2KB realistic payload → clean `Error::WireBudgetExceeded` at send (not pkarr panic). | Pitfall #22 third instance. `tests/wire_budget_compose_pin_burn_pgp.rs` reuses `Error::WireBudgetExceeded { encoded, budget, plaintext }` matching pattern from Phase 6/7/8. `WIRE_BUDGET_BYTES = 1000` (`src/flow.rs:41`). |

## Project Constraints (from CLAUDE.md)

- **`pkarr::ClientBlocking`, no tokio** — Phase 9 must NOT introduce a `tokio` direct dep for the real-DHT test harness. `ClientBlocking::publish` uses `futures_lite::future::block_on` internally (verified at `pkarr-5.0.4/src/client/blocking.rs:122`). Our test calls `client.publish(...)` synchronously. [VERIFIED: `pkarr-5.0.4/src/client/blocking.rs:1-150`]
- **`ed25519-dalek =3.0.0-pre.5` exact pin** — `pkarr 5.0.4 → ed25519-dalek 3.0.0-pre.5` (verified `cargo tree`). Phase 9 adds NO new crypto deps; the pin is preserved. [VERIFIED: `cargo tree -p pkarr` output]
- **`serial_test = "3"` + `#[serial]` discipline** — racer test mutates shared `MockStore` state via `Arc<Mutex<...>>`; real-DHT test mutates network state and is `#[serial]`-required by Pitfall #29. dev-dep already present. [VERIFIED: `Cargo.toml:401`]
- **Error-oracle hygiene (Pitfall #16)** — preserved by absorbing CAS conflict inside the trait method. NO new public `Error::CasConflict` variant. Final-failure case rides existing `Error::Transport` (no oracle drift; CAS-final has the same Display as any other transport failure). [CITED: `.planning/research/PITFALLS.md` #16, CONTEXT.md D-P9-anti-pattern]
- **`chacha20poly1305` only via age** — invariant unchanged; Phase 9 adds NO new crypto code. [VERIFIED: phase has no crypto edits]
- **No new wire formats, no new fixtures (other than the planner's choice for the 2KB synthesized PGP payload — which is NOT a fixture but inline test data per D-P9-E1)** — RELEASE-CHECKLIST asserts byte-counts of existing fixtures (192/424/119/212/142) as a regression guard.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| CAS retry-merge contract | Transport trait (impl detail of `publish_receipt`) | — | D-P9-A2: retry stays inside trait; no caller-visible API change. `flow::run_receive` step 13 sees Ok/Err only. |
| MockTransport CAS state machine | `mod transport::mock` (cfg-gated) | — | Per-key `seq: u64` is internal to the mock; doesn't touch the public test API (`resolve_all_txt` preserved). |
| Real-DHT round trip | `tests/real_dht_e2e.rs` (cfg+ignored) | `pkarr::ClientBlocking` | Test owns network setup, deadline, UDP pre-flight; pkarr provides the transport. NO new crate-level abstraction. |
| UDP pre-flight | `tests/real_dht_e2e.rs` helper fn | `std::net::UdpSocket` | std-only; never imports pkarr's bootstrap list (we hardcode `router.bittorrent.com:6881` to avoid coupling our pre-flight to pkarr internals). |
| Wire-budget headroom assertion | `tests/wire_budget_compose_pin_burn_pgp.rs` | `cipherpost::flow::run_send` | Pure assertion test against the existing `Error::WireBudgetExceeded` surface; no source edits. |
| RELEASE-CHECKLIST | repo root markdown | — | Top-level docs (matches v1.0 SPEC/THREAT-MODEL/SECURITY convention per D-P9-C2). |
| Bootstrap-defaults note | README.md + SPEC.md inline | — | Single sentence each (D-P9-B2 + Discretion recommendation). |
| `CIPHERPOST_DEBUG=1` env read | `src/transport.rs` private helper | `std::env::var` | Narrowly-scoped; only consumed at the CAS-retry log site (D-P9-A4). |

## Open Questions Resolved

### OQ-1. Which `pkarr::errors::PublishError` variant signals CAS conflict in pkarr 5.0.4?

**Resolution: `PublishError::Concurrency(ConcurrencyError::CasFailed)` is the *literal* CAS conflict, but the retry should also catch `ConcurrencyError::ConflictRisk` and `ConcurrencyError::NotMostRecent`.**

[VERIFIED: `~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pkarr-5.0.4/src/client.rs:565-624`]

The full enum surface (verbatim from source):

```rust
// src/client.rs:565-582
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, Hash)]
pub enum PublishError {
    #[error(transparent)]
    Query(#[from] QueryError),

    #[error(transparent)]
    /// A different [SignedPacket] is being concurrently published for the same [PublicKey].
    /// This risks a lost update, you should resolve most recent [SignedPacket] before publishing again.
    Concurrency(#[from] ConcurrencyError),

    #[error("All relays responded with unexpected responses, check debug logs.")]
    UnexpectedResponses,
}

// src/client.rs:604-624
#[derive(thiserror::Error, Debug, Clone, PartialEq, Eq, Hash)]
pub enum ConcurrencyError {
    #[error("A different SignedPacket is being concurrently published for the same PublicKey.")]
    ConflictRisk,
    #[error("Found a more recent SignedPacket in the client's cache")]
    NotMostRecent,
    #[error("Compare and swap failed; there is a more recent SignedPacket than the one seen before publishing")]
    CasFailed,
}
```

All three variants share the same docstring guidance: *"This risks a lost update, you should resolve most recent [SignedPacket] before publishing again."* The cipherpost retry must therefore treat all three as the conflict signal.

**Re-export path:** `pkarr::errors::ConcurrencyError` (visible via `pkarr-5.0.4/src/lib.rs:60`).

**Implication for `map_pkarr_publish_error`:** the existing helper at `src/transport.rs:264-270` collapses all non-Timeout `PublishError`s into `Error::Transport(Box::new(...))`. Phase 9 must add a new arm that catches `PublishError::Concurrency(_)` and signals the trait-internal retry path BEFORE the Transport collapse runs. Recommendation: introduce a private `enum PublishOutcome { Ok, CasConflict, Other(Error) }` returned by a private `publish_receipt_attempt()` helper; the public trait method's retry loop handles the dispatch. This keeps `map_pkarr_publish_error` unchanged for non-publish_receipt callers (`publish` step at line 117).

[CITED: `pkarr-5.0.4/src/client/blocking.rs:107-115` — pkarr's own docs say "If you get a [super::ConcurrencyError]; you should resolver the most recent packet again, and repeat the steps in the previous example."]

### OQ-2. Exact exponential-backoff curve for the real-DHT resolve loop. Does pkarr already retry internally?

**Resolution: Recommended curve `1s, 2s, 4s, 8s, 16s, 32s, 64s` (sum=127s) clipped at the 120s in-test deadline. pkarr 5.0.4 does NOT retry publish internally on Concurrency or Query errors.**

[VERIFIED: `grep -rn 'retry\|backoff' pkarr-5.0.4/src/`]

Full retry inventory in pkarr 5.0.4:
- `pkarr-5.0.4/src/client/relays.rs:481` — `should_retry_with_cache_disabled` — relay-side cache invalidation only. Bypassed because we use `no_relays()`.
- `pkarr-5.0.4/src/client.rs:234` — docstring saying *the user* must retry on `QueryError`. Not an internal retry.

Mainline (pkarr's transport): `grep -rn 'retry' mainline-6.1.1/src/` returns nothing relevant to publish/resolve flow.

**Implication: there is NO double-backoff stacking risk.** The cipherpost-layer single-retry on `Concurrency` errors (Phase 9) and the cipherpost-layer 7-step exponential resolve loop (this OQ) are the only retry mechanisms in the stack.

**Curve sizing (1, 2, 4, 8, 16, 32, 64):**
- Total without final sleep: 1+2+4+8+16+32 = 63 seconds
- After 7th attempt (cumulative 63s wall-clock), would sleep 64s if it failed → exceeds 120s deadline
- Deadline check (`Instant::now() >= deadline`) before each sleep clips the 7th sleep to `min(64, remaining)`
- p50 PKARR lookup ≈ 60s per v1.0 PITFALLS.md #10, so attempts 1-5 (cumulative 31s) are likely too aggressive but harmless (just early reads); attempts 6-7 cover the long tail

Alternative considered: `2s, 4s, 8s, 16s, 32s, 60s` (sum=122s) — fewer attempts, simpler. **Recommended:** stick with the CONTEXT-suggested 7-step curve because it gives more chances during the p10-p50 window (where DHT propagation is partial).

[CITED: `pkarr-5.0.4/src/client.rs:230-238` — the `## Errors` docstring tells callers to retry on QueryError]

### OQ-3. UDP pre-flight technique and target host

**Resolution: `std::net::UdpSocket::bind("0.0.0.0:0")` + `socket.set_read_timeout(Some(Duration::from_secs(5)))` + `socket.connect("router.bittorrent.com:6881")`. If `bind` fails or `connect` fails (NXDOMAIN, no route), skip with the canonical message.**

[VERIFIED: `mainline-6.1.1/src/rpc.rs:42-47`]

Mainline 6.1.1 `DEFAULT_BOOTSTRAP_NODES` (verbatim):
```rust
pub const DEFAULT_BOOTSTRAP_NODES: [&str; 4] = [
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "dht.libtorrent.org:25401",
    "relay.pkarr.org:6881",
];
```

**Recommended target: `router.bittorrent.com:6881`** — it's the most widely deployed of the four (operated by BitTorrent Inc., served as the canonical Mainline bootstrap since DHT was added to the BitTorrent protocol). Using the same host pkarr's first bootstrap-list entry uses keeps our pre-flight aligned with what pkarr will actually try first.

**Connect-then-probe semantics for UDP:** `UdpSocket::connect()` on Linux/macOS does NOT send packets (UDP is connectionless), but it DOES bind the socket to the destination address and resolve DNS — so DNS failure (`AddrParseError` / `io::ErrorKind::NotFound`) and route failure (`io::ErrorKind::NetworkUnreachable`) surface immediately. This is the right primitive for "is the remote address reachable from our network namespace at all?" without sending traffic the bootstrap host might rate-limit or log.

**Pre-flight code skeleton:**
```rust
fn udp_bootstrap_reachable(timeout: Duration) -> bool {
    use std::net::{ToSocketAddrs, UdpSocket};
    use std::time::Instant;
    let deadline = Instant::now() + timeout;
    // Resolve DNS within the timeout
    let mut addrs = match "router.bittorrent.com:6881".to_socket_addrs() {
        Ok(it) => it,
        Err(_) => return false,
    };
    let target = match addrs.next() {
        Some(a) => a,
        None => return false,
    };
    if Instant::now() >= deadline {
        return false;
    }
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = socket.set_read_timeout(Some(timeout));
    socket.connect(target).is_ok()
}
```

[CITED: Rust std docs `std::net::UdpSocket::connect` — "If addr yields multiple addresses, connect will be attempted with each of the addresses until the underlying OS function returns no error."]

### OQ-4. `pkarr::ClientBuilder` defaults — can we construct ClientBlocking without specifying bootstrap nodes?

**Resolution: Yes. `pkarr::Client::builder().no_relays().build()?.as_blocking()` produces a fully-configured `ClientBlocking` using the 4 default Mainline bootstrap nodes. This is what `DhtTransport::new` already does (`src/transport.rs:84-92`), so the real-DHT test reuses `DhtTransport` rather than constructing the client inline.**

[VERIFIED: `pkarr-5.0.4/src/client/builder.rs:56-83` (Config::default sets `dht: Some(mainline::Dht::builder())` → mainline applies its own DEFAULT_BOOTSTRAP_NODES); `pkarr-5.0.4/src/client/builder.rs:284` (`pub fn build(&self) -> Result<Client, BuildError>`)]

**STATE.md todo "verify pkarr 5.0.4 ClientBuilder bootstrap configurability": CLOSEABLE.** Bootstrap IS configurable via `ClientBuilder::bootstrap<T: ToSocketAddrs>(&mut self, bootstrap: &[T])` (verified at `client/builder.rs:164`), but D-P9-B1 says we don't use the API in v1.1 — pkarr defaults only. The verification confirms a v1.2+ private-testnet-support feature would be straightforward (one method call), but that's deferred per CONTEXT.md.

**Reuse pattern for real-DHT test:**
```rust
let alice_transport = DhtTransport::new(Duration::from_secs(120))?;
let bob_transport   = DhtTransport::new(Duration::from_secs(120))?;
```
Each `DhtTransport::new` builds an independent `pkarr::Client`. The 120s `request_timeout` matches the in-test deadline (D-P9-D3). Each client gets its own DHT routing table — true independence.

**Caveat (Discretion item, not a blocker):** two in-process `pkarr::Client` instances each spin up their own `mainline::Dht` background. On a heavily-NATed network this might cause both to share the same external UDP source port. Recommend: don't worry about it for v1.1 — the test runs on the developer's network, not behind exotic NAT. Document in RELEASE-CHECKLIST as "run on a network with normal outbound UDP egress."

### OQ-5. Cargo `--test-timeout` flag — does it exist for stable cargo?

**Resolution: NO. `cargo --test-timeout` does not exist on stable cargo. The libtest harness has `--ensure-time` + `RUST_TEST_TIME_INTEGRATION` env var, BUT only under `-Z unstable-options` (nightly-only). The CONTEXT.md D-P9-D3 recommendation conflated this with cargo-nextest's `slow-timeout` config. CI uses nextest (verified `.github/workflows/ci.yml:35-46`), so the outer-guard belongs in `.config/nextest.toml`.**

[VERIFIED: `cargo test --help`, `cargo test -- --help` (libtest harness), `~/.cargo/bin/cargo-nextest --version` → `0.9.100`]

cargo-nextest config syntax (verified via [nexte.st docs](https://nexte.st/docs/configuration/per-test-overrides/)):

```toml
# .config/nextest.toml (NEW FILE — recommended for Phase 9)
[[profile.default.overrides]]
filter = 'test(real_dht_e2e)'
slow-timeout = { period = "60s", terminate-after = 2 }
```

This says: tests matching name `real_dht_e2e` are marked slow after 60s; nextest forcefully terminates them after the 2nd slow-period (i.e., 120s total wall-clock). Combined with the in-test `Instant`-deadline, this gives the belt-and-suspenders D-P9-D3 wants.

**Implication for D-P9-D3 wording:** the planner should rewrite the lock-in as "120s timeout enforced both in-test AND via nextest profile config" rather than "via `cargo --test-timeout` flag." The intent is preserved; the mechanism is correct.

**Implication for RELEASE-CHECKLIST manual command:** the CONTEXT.md mockup line `cargo test --features real-dht-e2e -- --ignored --test-timeout 120 dht_e2e` is wrong on stable cargo. Replace with:
```
cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast
```
or, if a developer prefers `cargo test`:
```
cargo test --features real-dht-e2e -- --ignored --nocapture real_dht_e2e
```
(The `--test-timeout` flag is silently dropped by stable cargo's argument parser because it's only used by nextest. Easy footgun.)

### OQ-6. `pkarr::Timestamp` semantics — what does `cas: Option<Timestamp>` mean?

**Resolution: `Some(Timestamp)` says "publish only if no SignedPacket more recent than this timestamp has been published since I read it." `None` says "publish unconditionally; risk lost-update on concurrent writers." The current timestamp can be obtained from `SignedPacket::timestamp()` after a `resolve_most_recent` call. Existing `src/transport.rs:168` already does the right thing — Phase 9 wraps it in a single-retry loop.**

[VERIFIED: `pkarr-5.0.4/src/client.rs:289-316` (publish_inner CAS check); `ntimestamp-1.0.0/src/lib.rs:79-101` (Timestamp(u64) microseconds since epoch); `pkarr-5.0.4/src/client/blocking.rs:38-106` (lost-update example in docstring)]

The `publish_inner` CAS check (verbatim):
```rust
// pkarr-5.0.4/src/client.rs:294-310
let cache_key: CacheKey = signed_packet.public_key().into();
if let Some(cached) = self.cache().as_ref().and_then(|cache| cache.get(&cache_key)) {
    if cached.more_recent_than(signed_packet) {
        return Err(ConcurrencyError::NotMostRecent)?;
    } else if let Some(cas) = cas {
        if cached.timestamp() != cas {
            return Err(ConcurrencyError::CasFailed)?;
        }
    }
}
```

Two-stage check:
1. **Local-cache check (`NotMostRecent`):** if pkarr's in-memory cache holds a packet newer than the one being published → fail. Affects same-process concurrent publishers.
2. **CAS-token check (`CasFailed`):** if `cas` is `Some(t)` but the cached timestamp ≠ `t` → fail. Affects the case where another writer landed a packet between our resolve and our publish.

After this in-process gate, the publish proceeds to mainline DHT (which has its own write-write conflict semantics — `mainline::errors::ConcurrencyError::ConflictRisk` surfaces as `pkarr::ConcurrencyError::ConflictRisk` per `pkarr-5.0.4/src/client.rs:638`).

**Existing transport.rs:168 path (confirmed correct, no change needed except the retry wrap):**
```rust
// src/transport.rs:160-180 (Phase 3 / D-MRG-01)
let existing = self.client.resolve_most_recent(&pk);
let mut builder = pkarr::SignedPacket::builder();
let mut cas: Option<pkarr::Timestamp> = None;
if let Some(ref packet) = existing {
    cas = Some(packet.timestamp());
    // ... rebuild builder from existing RRs ...
}
```

This is textbook resolve-merge-republish-with-CAS. Phase 9 only adds: if the subsequent `self.client.publish(&packet, cas)` returns `Err(PublishError::Concurrency(_))`, retry the whole block once (re-resolve, re-merge, re-publish, this time with the FRESH `cas` token).

**Implication for the `MockTransport` parity:** since `Timestamp` is `u64`-microseconds-since-epoch, and `pkarr::Timestamp::now()` is monotonic-ish per call, the mock's `seq: u64` counter is behaviorally equivalent. We don't need to use timestamps in the mock — a simple incrementing counter is faithful (the mock doesn't model wall-clock semantics; it models the CAS *protocol*).

[CITED: `ntimestamp-1.0.0/src/lib.rs:48` — `pub fn now(&mut self) -> Timestamp` ensures monotonic ordering within a single `TimestampFactory`]

## Standard Stack

### Core (already present — no version changes)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `pkarr` | =5.0.3 spec, 5.0.4 resolved | DHT transport with CAS-aware publish API | Only crate that wraps Mainline DHT with PKARR signed-packet semantics; ed25519-dalek pin compatibility |
| `ed25519-dalek` | =3.0.0-pre.5 | Identity keypair | Pre-stable but pinned because pkarr's transitive constraint is `^3.0.0-pre.1` and no stable 3.x exists |
| `serial_test` | "3" (dev-dep) | Test serialization for env-mutating + network-mutating tests | Already present at `Cargo.toml:401`; reused for both racer test (shared mock state) and real-DHT test (Pitfall #29 mandate) |

### Supporting (present)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `tempfile` | "3" (dev-dep) | Temporary `CIPHERPOST_HOME` for tests | Both new tests use `TempDir::new()` — racer test for state hygiene; real-DHT for fresh identity per run |
| `assert_cmd` | "2" (dev-dep) | Process-level CLI assertion | Not needed for Phase 9 — Phase 9 tests call `cipherpost::flow::*` directly under MockTransport, not via subprocess |

### Alternatives Considered (and rejected)
| Instead of | Could Use | Tradeoff (why rejected) |
|------------|-----------|----------|
| `std::sync::Barrier` for racer test | `crossbeam::channel` rendezvous | std-only is preferred (no new dep); Barrier is exactly the right primitive for "both threads arrive at the synchronization point before either proceeds" — Pitfall #28's mandated pattern. |
| `std::net::UdpSocket` for pre-flight | `tokio::net::UdpSocket` with `tokio::time::timeout` | Tokio is forbidden at the cipherpost layer (CLAUDE.md). std's `set_read_timeout` is sufficient — UDP `connect()` on Linux returns immediately on DNS+route resolution; no async needed. |
| Reusing pkarr's bootstrap list | Hardcoding `router.bittorrent.com:6881` | Coupling our pre-flight to pkarr internals would require accessing `mainline::DEFAULT_BOOTSTRAP_NODES` (might not be re-exported). Hardcoding the same first-list-entry is more transparent and matches what pkarr will try first. |
| `cargo-nextest` config for the only timeout | `cargo --test-timeout` flag | Doesn't exist on stable cargo (OQ-5 finding). nextest config IS available because CI already uses nextest 0.9.100. |

### Dependency additions
**NONE.** Phase 9 introduces no new crate deps. New edits are:
- `Cargo.toml` `[features]` block: add `real-dht-e2e = []`
- `Cargo.toml` `[[test]]` entries: add `cas_racer`, `real_dht_e2e`, `wire_budget_compose_pin_burn_pgp` per single-purpose-test-file convention
- `.config/nextest.toml` (NEW FILE): per-test slow-timeout for real-DHT (recommended)

**Version verification:**
```bash
$ cargo tree -p pkarr | head -1
pkarr v5.0.4
$ cargo tree -p ed25519-dalek | head -1
ed25519-dalek v3.0.0-pre.5
$ cargo tree -p mainline | head -1
mainline v6.1.1
$ ~/.cargo/bin/cargo-nextest --version
cargo-nextest 0.9.100 (7e6129fe2 2025-07-07)
```
[VERIFIED: shell output 2026-04-26 against `Cargo.lock` resolution]

## Architecture Patterns

### System Architecture Diagram (Phase 9 deltas only)

```
                          ┌─────────────────────────────────┐
   tests/cas_racer.rs     │  CAS RACER TEST (CI, mock)      │
   ─────────────────►     │  Two std::thread::spawn         │
                          │  Sync via Arc<Barrier::new(2)>  │
                          │  Both call publish_receipt()    │
                          └────────────┬────────────────────┘
                                       │
                                       ▼
                  ┌────────────────────────────────────────────┐
                  │  Transport::publish_receipt (RETRY-INSIDE) │
                  │                                            │
                  │  loop:                                     │
                  │   attempt #1 ───► CasConflict? ─yes─► loop │
                  │   attempt #2 ───► CasConflict? ─yes─► Err  │
                  │           └────► Ok ────────────────► Ok   │
                  └─────┬─────────────────┬────────────────────┘
                        │                 │
              MockTransport         DhtTransport
              (per-key seq:u64)     (pkarr::Client::publish + cas)
                                    │
                                    └──► PublishError::Concurrency(_)
                                          → internal CasConflict signal
                                          → retry (resolve-merge-republish)


   tests/real_dht_e2e.rs (manual, behind cfg+ignore+serial)
   ──────────────────────────────────────────────────────
                        │
                        ▼
                   ┌──────────────────┐
                   │ udp_bootstrap_   │
                   │ reachable(5s)    │ ─── unreachable ──► skip (canonical msg)
                   └────────┬─────────┘
                            │ reachable
                            ▼
                   ┌──────────────────┐
                   │ Alice DhtTransport ─publish─►  Mainline DHT
                   │ Bob DhtTransport   ◄─resolve  with 7-step
                   │                                exp-backoff,
                   │                                deadline 120s
                   └────────┬─────────┘
                            │ resolved
                            ▼
                   ┌──────────────────┐
                   │ Bob: verify→     │
                   │ accept→decrypt→  │
                   │ publish_receipt  │
                   │ Alice: fetch     │
                   │ receipts         │
                   └──────────────────┘
                            │
                            ▼
                   assert receipt.count == 1


   tests/wire_budget_compose_pin_burn_pgp.rs (CI, mock)
   ──────────────────────────────────────────────────────
   2KB synthesized GenericSecret + pin + burn → run_send → assert
   Error::WireBudgetExceeded { encoded, budget=1000, plaintext } cleanly
   (Pitfall #22 third instance)
```

### Pattern 1: Retry-inside-trait-method with internal sentinel

**What:** Both `MockTransport` and `DhtTransport` implement `publish_receipt` as a public method that wraps a private `publish_receipt_attempt` helper. The helper returns a private `PublishOutcome` enum with arms: `Ok`, `CasConflict`, `Other(Error)`. The public method's retry loop pattern-matches:

```rust
// Sketch (per-impl, NOT a shared helper — D-P9-A2 rejected the helper pattern)
impl Transport for DhtTransport {
    fn publish_receipt(&self, kp, share_ref, json) -> Result<(), Error> {
        match self.publish_receipt_attempt(kp, share_ref, json)? {
            PublishOutcome::Ok => return Ok(()),
            PublishOutcome::Other(e) => return Err(e),
            PublishOutcome::CasConflict => {
                if std::env::var("CIPHERPOST_DEBUG").as_deref() == Ok("1") {
                    eprintln!("Receipt publish: CAS conflict, retrying once...");
                }
            }
        }
        // Single retry: resolve-merge-republish from scratch
        match self.publish_receipt_attempt(kp, share_ref, json)? {
            PublishOutcome::Ok => Ok(()),
            PublishOutcome::Other(e) => Err(e),
            PublishOutcome::CasConflict => Err(Error::Transport(Box::new(
                CasConflictFinalError, // private struct; Display = generic "transport error"
            ))),
        }
    }
}
```

**When to use:** Only place this pattern lives is `publish_receipt`. The `publish` step (line 100-119) deliberately doesn't use CAS — that's a fresh OuterRecord publish, not a receipt-merge.

**Why a private `CasConflictFinalError` struct:** absorbs the "second attempt also failed" path into `Error::Transport`'s existing Display ("transport error"), preserving error-oracle hygiene (Pitfall #16 — no oracle drift). The private struct's own `Display` is what `Error::Transport(Box<...>)` would print IF source chains were Displayed, but `error::user_message` doesn't walk source chains (`src/error.rs:131-134`), so the user sees only "transport error".

[CITED: src/error.rs:106 (`Transport(#[source] Box<dyn std::error::Error + Send + Sync>)`); src/error.rs:131 (no source-chain walk in user_message)]

### Pattern 2: Barrier-synced concurrent racer test

**What:** Two `std::thread::spawn`s, each holding a clone of `Arc<MockTransport>` and `Arc<Barrier>`. The Barrier is constructed with capacity 2 (`Barrier::new(2)`). Each thread:
1. Builds its receipt JSON before the barrier
2. Calls `barrier.wait()` — blocks until both threads have arrived
3. Both call `publish_receipt(...)` "simultaneously"
4. One wins on first attempt; the other observes a stale seq, retries internally, and republishes the merged state

**Critical detail (Pitfall #28):** the Barrier MUST be reached AFTER each thread has loaded the current seq from the mock and built the merged record set, BUT BEFORE the publish-with-cas-check. If the barrier is reached BEFORE the load, the test degrades to sequential because one thread's load happens after the other's publish — no contention. If the barrier is reached AFTER the publish, the test is trivially serial. The right place is between (lock-and-read-seq) and (lock-and-cas-check-and-write).

**Implementation note:** since `MockTransport`'s internal locking is owned by the mock, the Barrier can't be inside the mock. Instead, structure the mock so that:
- `publish_receipt_attempt` does: lock, read seq, clone records, drop lock, BUILD merged set, re-lock, cas-check, write-or-conflict, release
- The Barrier is in the test, called between "build-receipt-json-locally" and "publish_receipt-call-which-internally-retries"

This is sufficient: both threads enter `publish_receipt` simultaneously; the underlying lock then serializes their access to the shared store, and the second one will observe a stale seq when it gets the lock — exactly the race we want to test.

```rust
// Sketch only
let barrier = Arc::new(std::sync::Barrier::new(2));
let mock = Arc::new(MockTransport::new());
let kp = test_keypair("bob");

let h_a = {
    let (mock, kp, barrier) = (mock.clone(), kp.clone(), barrier.clone());
    let receipt = build_receipt_json("share_ref_a", &kp);
    std::thread::spawn(move || {
        barrier.wait();
        mock.publish_receipt(&kp, "share_ref_a", &receipt).unwrap();
    })
};
let h_b = {
    let (mock, kp, barrier) = (mock.clone(), kp.clone(), barrier.clone());
    let receipt = build_receipt_json("share_ref_b", &kp);
    std::thread::spawn(move || {
        barrier.wait();
        mock.publish_receipt(&kp, "share_ref_b", &receipt).unwrap();
    })
};
h_a.join().unwrap();
h_b.join().unwrap();

// Both receipts must persist after concurrent publish + internal retry
let all = mock.resolve_all_txt(&kp.public_key().to_z32());
let receipt_count = all.iter().filter(|(l, _)| l.starts_with("_cprcpt-")).count();
assert_eq!(receipt_count, 2);
```

[CITED: `tests/state_ledger.rs:23` `#![cfg(feature = "mock")]` — same gate; existing pattern]

### Pattern 3: Real-DHT test with deadline-clipped exp-backoff

**What:**

```rust
#[cfg(feature = "real-dht-e2e")]
#[test]
#[ignore]
#[serial]
fn real_dht_cross_identity_round_trip() {
    use std::time::{Duration, Instant};

    if !udp_bootstrap_reachable(Duration::from_secs(5)) {
        eprintln!("real-dht-e2e: UDP unreachable; test skipped (not counted as pass)");
        return;
    }

    let alice = DhtTransport::new(Duration::from_secs(120)).unwrap();
    let bob = DhtTransport::new(Duration::from_secs(120)).unwrap();

    // ... build alice_identity, bob_identity, send share to bob ...
    let share_uri = alice_send(...);

    let deadline = Instant::now() + Duration::from_secs(120);
    let backoff = [1u64, 2, 4, 8, 16, 32, 64];
    let mut record: Option<OuterRecord> = None;
    for delay in backoff {
        if Instant::now() >= deadline {
            panic!("real-dht-e2e: 120s deadline reached without resolve");
        }
        match bob.resolve(&alice_z32) {
            Ok(r) => { record = Some(r); break; }
            Err(_) => {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let sleep_for = Duration::from_secs(delay).min(remaining);
                std::thread::sleep(sleep_for);
            }
        }
    }
    let record = record.expect("resolve never succeeded within 120s");

    // ... bob receives, accepts, publishes receipt; alice fetches; assert count == 1 ...
}
```

**When to use:** ONE test in the file. D-P9-D1 binds Phase 9's real-DHT scope to a single cross-identity round trip.

### Anti-Patterns to Avoid (Phase 9-specific)

- **Sleep-based simulated racer test.** Pitfall #28 explicit: must use `std::sync::Barrier`. Sleeping `Duration::from_millis(0)` between two sequential `publish_receipt` calls does NOT exercise the race condition (the second resolve happens AFTER the first publish, so cas matches).
- **Surfacing CAS conflict to the caller.** D-P9-A2 + Pitfall #16 (error-oracle hygiene). If both attempts fail, ride existing `Error::Transport`. Do NOT add a public `Error::CasConflict` variant.
- **Adding `tokio` for the real-DHT test harness.** `pkarr::ClientBlocking` is a sync API (`futures_lite::future::block_on` internal at `pkarr-5.0.4/src/client/blocking.rs:122`). Phase 9 uses the blocking API with `std::thread`. CLAUDE.md load-bearing.
- **Using `cargo --test-timeout 120` in commands.** Doesn't exist on stable cargo (OQ-5). Use nextest config or rely on the in-test deadline.
- **Spawning multiple real-DHT tests in one file or across files.** D-P9-D1 + Pitfall #29 (one-test-per-job cap; v1.1 has zero in CI anyway). One test is the whole real-DHT scope.
- **Including the full pkarr bootstrap list in the UDP pre-flight.** Probing all 4 hosts compounds the 5s timeout into 20s worst-case. Probe ONE host (`router.bittorrent.com:6881`); if that host is down on the day of the release, the user reruns. Aligned with D-P9-D2 ("RELEASE-CHECKLIST manual run is the only gate" — manual users can rerun).
- **Logging on every retry by default.** D-P9-A4: silent default; opt-in via `CIPHERPOST_DEBUG=1`. Adding stderr noise to the happy path would mislead users into thinking conflicts are common.
- **Conditionally guarding `publish_receipt` on `!burn_after_read`.** Phase 8 BURN-04 explicit: receipt IS published on burn. Phase 9 must NOT introduce any "skip receipt on burn" branch even though the new retry path tempts it. (Verified: `src/transport.rs::publish_receipt` doesn't branch on Envelope state today; Phase 9 retry preserves this.)

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| CAS protocol | A homegrown sequence-number protocol on top of pkarr's `cas: Option<Timestamp>` | `pkarr::Timestamp` directly via `SignedPacket::timestamp()` | pkarr 5.0.4 already exposes the right primitive at line 168 of transport.rs. Reinventing this would diverge from upstream's semantics and break under future pkarr upgrades. |
| UDP reachability probe | A `ping` subprocess or raw socket | `std::net::UdpSocket::bind() + connect()` | std-only; works in any sandbox that allows outbound UDP; pings ICMP which is blocked even more often than UDP. |
| Test-timeout enforcement | A `std::thread::spawn` watchdog that panics | nextest `slow-timeout = { period, terminate-after }` config | nextest is already in CI (verified `.github/workflows/ci.yml:42-46`); homegrown watchdog wouldn't kill tests cleanly under panic=abort. |
| Concurrent thread synchronization | Spinning + atomic flags + sleeps | `std::sync::Barrier::new(2)` | Pitfall #28 mandated pattern; sleeps are non-deterministic and CI-flaky. |
| pkarr error-variant matching | String-matching `format!("{}", err)` | Direct enum match: `match e { PublishError::Concurrency(_) => ..., other => ... }` | All three `ConcurrencyError` variants are `#[derive(PartialEq, Eq)]` (line 565 of `pkarr-5.0.4/src/client.rs`); pattern-match is type-checked. |
| RELEASE-CHECKLIST automation | A `release.sh` script that runs everything | Markdown checkbox file with copy-pasteable commands | D-P9-C3 + D-P9-C1 (~80 lines, manual ticking). Scripted release is deferred to a future "release pipeline" effort; v1.1 ships the standard ship-gate. |

**Key insight:** Phase 9 is almost entirely about *integrating existing primitives correctly under contention/network conditions* — there is virtually no new code to write at the cipherpost layer. The CAS retry loop is ~20 lines per impl; the racer test is ~40 lines; the real-DHT test is ~80 lines including pre-flight; the wire-budget composite test is ~30 lines; the RELEASE-CHECKLIST is markdown. Total new Rust LOC across the phase is well under 300, but the *correctness of integration* is delicate.

## Runtime State Inventory

> N/A — this is not a rename/refactor/migration phase. Phase 9 adds new code paths and a new feature flag; no string substitution across the repo, no datastore-key changes, no OS-registered state churn.

## Common Pitfalls (Phase 9 specific)

### Pitfall A: Treating only `CasFailed` as the retry trigger

**What goes wrong:** Match on `PublishError::Concurrency(ConcurrencyError::CasFailed)` only, leaving `ConflictRisk` and `NotMostRecent` to fall through to `Error::Transport`. User sees a final error on what should have been a successful retry.

**Why it happens:** `CasFailed` is the most "obvious" CAS failure name. The other two variants have different upstream wording ("ConflictRisk" suggests pre-emptive caution, "NotMostRecent" suggests a stale read) but the docstrings explicitly group them under the same advice.

**How to avoid:** Match on `PublishError::Concurrency(_)` (any inner variant) as the conflict signal.

**Warning signs:** Test that CAS-conflicts on `NotMostRecent` from a stale local cache passes intermittently — or fails silently with `Err(Error::Transport)` despite a successful in-DHT publish.

### Pitfall B: Forgetting the Barrier placement requirement

**What goes wrong:** Thread spawns include the Barrier wait BEFORE building the receipt JSON. Both threads block on the Barrier; one hits the barrier-release lottery; both then build receipts; both call publish_receipt. The first publish wins instantly with no contention because the second hasn't started its lock cycle yet. Test passes but doesn't exercise the CAS retry path.

**Why it happens:** Thinking of the Barrier as "make sure both threads are running before we do anything" instead of "synchronize past the local-prep step into the contention window."

**How to avoid:** Build the receipt JSON BEFORE the barrier wait. Barrier is the lockstep across the publish_receipt call, not the spawn itself.

**Warning signs:** racer test passes 100% of the time on first introduction, even before the CAS retry code is in `publish_receipt`. (A correct racer test against a non-CAS mock would fail with "expected 2 receipts, got 1.")

### Pitfall C: pkarr ClientBlocking lifecycle on test re-runs

**What goes wrong:** Each `DhtTransport::new` spawns a `mainline::Dht` background. If the test panics or returns early (e.g., UDP pre-flight skip), the `Drop` impl on the Dht runs, which on some systems holds the test process open for several seconds while UDP sockets are torn down. Multiple back-to-back real-DHT runs can stutter.

**Why it happens:** Mainline DHT clients hold a routing table and a UDP socket; tearing down cleanly takes a few seconds.

**How to avoid:** Don't worry about it for v1.1 — the test runs `#[serial]` and the manual-only invocation pattern means there's no back-to-back stress. Document in RELEASE-CHECKLIST: "Allow ~10s between consecutive real-DHT test runs for socket teardown."

**Warning signs:** Second invocation of the same real-DHT test panics with `bind: address already in use` or hangs on the UDP pre-flight.

### Pitfall D: nextest slow-timeout vs. test-process exit

**What goes wrong:** Setting `slow-timeout = "120s"` without `terminate-after = N` causes nextest to mark the test slow but NOT terminate it — the test would still hang for the full default 60-minute test process timeout if the in-test deadline check is broken.

**Why it happens:** nextest's default behavior is to *report* slowness, not enforce it. `terminate-after` is the enforcement knob.

**How to avoid:** Use the object syntax: `slow-timeout = { period = "60s", terminate-after = 2 }` (slow at 60s, terminated at 120s).

**Warning signs:** A test stuck on a non-responsive bootstrap node hangs the whole `cargo nextest run` invocation. Check `.config/nextest.toml` for the `terminate-after` knob.

### Pitfall E: Synthesized PGP payload picking the wrong wire variant

**What goes wrong:** D-P9-E1 says "synthesized 2048-byte byte vector wrapped in a minimal `Material::GenericSecret`." Wrapping in `Material::PgpKey` would trigger Phase 7's PGP packet-stream parser at ingest, which would reject random bytes with `Error::InvalidMaterial` (exit 1) — the test never reaches `Error::WireBudgetExceeded`.

**Why it happens:** The phase tag "pin+burn+pgp wire-budget" reads as "use a PGP variant for the payload."

**How to avoid:** Use `Material::GenericSecret { bytes: vec![0u8; 2048] }`. The wire-budget concern is byte-budget, not parser-correctness. CONTEXT.md D-P9-E1 already calls this out — preserve.

**Warning signs:** Test fails with `Error::InvalidMaterial { variant: "pgp_key", reason: "..." }` instead of `Error::WireBudgetExceeded`.

## Code Examples

### Example 1: ConcurrencyError variant catch (DhtTransport side)

```rust
// src/transport.rs (Phase 9 addition; pseudocode-precise)
//
// Source: pkarr 5.0.4 — pkarr-5.0.4/src/client.rs:565-624 (PublishError + ConcurrencyError)
// Source: pkarr 5.0.4 — pkarr-5.0.4/src/client/blocking.rs:107-115 (lost-update guidance)

use pkarr::errors::{PublishError, ConcurrencyError};

enum PublishOutcome {
    Ok,
    CasConflict,
    Other(Error),
}

impl DhtTransport {
    fn publish_receipt_attempt(&self, kp, share_ref_hex, receipt_json) -> PublishOutcome {
        // ... existing resolve-merge-build-sign logic from src/transport.rs:160-194 ...
        match self.client.publish(&packet, cas) {
            Ok(()) => PublishOutcome::Ok,
            Err(PublishError::Concurrency(_)) => PublishOutcome::CasConflict,
            Err(other) => PublishOutcome::Other(map_pkarr_publish_error(other)),
        }
    }
}
```

[CITED: pkarr-5.0.4/src/client/blocking.rs:107-115; src/transport.rs:160-201 existing implementation]

### Example 2: nextest config for the real-DHT test

```toml
# .config/nextest.toml (NEW FILE — Phase 9)
#
# Source: https://nexte.st/docs/configuration/per-test-overrides/

[[profile.default.overrides]]
filter = 'test(real_dht_e2e)'
slow-timeout = { period = "60s", terminate-after = 2 }
# Note: --features real-dht-e2e is NOT enabled by CI; this override only applies
# when a developer explicitly invokes the test with the feature flag. The
# override is a safety net for the manual RELEASE-CHECKLIST run.
```

### Example 3: Single-test-file convention

```rust
// tests/cas_racer.rs (NEW FILE)
//
// CI under `cargo test --features mock` (or `cargo nextest run --features mock`).
// #[serial] because the test mutates a shared MockTransport instance and other
// `#[serial]` mock tests would interfere if parallelism were allowed.

#![cfg(feature = "mock")]

use cipherpost::transport::{MockTransport, Transport};
use serial_test::serial;
use std::sync::{Arc, Barrier};
use std::thread;

#[test]
#[serial]
fn publish_receipt_cas_racer_two_threads_both_persist() {
    // ... per Pattern 2 above ...
}
```

[CITED: `tests/state_ledger.rs:23` (`#![cfg(feature = "mock")]`); `Cargo.toml:401` (`serial_test = "3"`)]

## State of the Art

| Old Approach (within cipherpost) | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `publish_receipt` returns whatever `pkarr::publish` returns (CAS conflict surfaces as opaque `Error::Transport`) | Trait-internal single-retry-then-fail; CAS conflict never escapes | Phase 9 | Receipts now resolve under contention without caller boilerplate; error-oracle hygiene preserved |
| Real-DHT integration unverified (MockTransport-only since v1.0) | Real-DHT cross-identity round trip behind feature flag, manual gate | Phase 9 | First time the protocol is exercised against actual Mainline DHT propagation; gates v1.1 release |
| Wire-budget escape hatch postponed (Phase 6/7/8 each closed with `#[ignore]`'d round trip) | Phase 9 reaffirms the ceiling; pin+burn+typed composite asserts clean error surface | Phase 9 | No new escape hatch — explicitly deferred to v1.2 wire-budget delivery-mechanism milestone |

**Deprecated/outdated (within Phase 9 scope):**
- The CONTEXT.md D-P9-D3 mention of `cargo --test-timeout 120` is mechanically incorrect on stable cargo. Replace with nextest profile config OR rely on in-test `Instant`-deadline.
- The CONTEXT.md "RELEASE-CHECKLIST.md mockup" line `cargo test --features real-dht-e2e -- --ignored --test-timeout 120 dht_e2e` should be replaced with nextest invocation (or have the `--test-timeout 120` removed).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | "Probing one bootstrap host is sufficient pre-flight" | OQ-3 | Low: if `router.bittorrent.com` is the one host down, manual user reruns; D-P9-D2 makes the test manual-only anyway. |
| A2 | "p50 PKARR lookup ≈ 60s" — basis for the 7-step backoff curve | OQ-2 | Low: cited from v1.0 PITFALLS.md #10 (already accepted research). Curve is conservative (p99 within 120s). |
| A3 | "Two `mainline::Dht` instances in one process don't conflict on UDP source port" | OQ-4 | Medium: if they do conflict, Bob's resolve might miss Alice's recently-published packet. Mitigation: 7-step backoff covers up to 127s of propagation lag. |
| A4 | "Single `Material::GenericSecret { bytes: vec![0u8; 2048] }` is the right test payload for DHT-07" — confirms D-P9-E1 recommendation | DHT-07 row | Low: matches CONTEXT.md explicitly. |

**Confirmation needed before plan-time:** none. All assumptions are low-risk and aligned with CONTEXT.md.

## Recommended Plan-Structure Refinement

### Recommendation: D-P9-F1 candidate 2 (4 plans), with the docs plan merged into the 3rd, yielding **3 plans total**.

The CONTEXT.md "3 plans" recommendation bundles "CAS racer + DHT-07 wire-budget assertion" into one plan. **This research recommends splitting them** for the following reasons:

1. **The CAS retry-and-merge work touches BOTH `MockTransport` AND `DhtTransport`** AND adds a new private enum (`PublishOutcome`) AND adds an env-var read (`CIPHERPOST_DEBUG`). That's four edit sites in `src/transport.rs` plus `tests/cas_racer.rs`. By itself this is one cohesive ship-gate.
2. **The DHT-07 wire-budget composite test is purely a NEW test file with no source edits** — it's an assertion about behavior that already exists (Phase 6/7/8 infrastructure handles `Error::WireBudgetExceeded` correctly; Phase 9 just adds a third assertion site). Bundling it with CAS work risks plan-check rejection for "two unrelated ship-gate concerns."
3. **The real-DHT plan is structurally distinct** — feature flag, UDP pre-flight, exp-backoff loop, single test file, nextest config addition — none of these touch `src/transport.rs`'s production code. It's its own plan.
4. **The docs plan (RELEASE-CHECKLIST + CLAUDE.md + STATE.md + README + SPEC inline)** is small enough (~80 lines RELEASE-CHECKLIST + ~30 lines of doc edits) to fold into the real-DHT plan as its closing section, OR to keep separate. CONTEXT.md F1 candidate 3 already recognizes this.

**Final 3-plan recommendation:**

- **Plan 09-01: CAS retry-and-merge contract + MockTransport per-key seq + DHT-07 wire-budget composite.** Covers DHT-01, DHT-02, DHT-07.
  - Edit `src/transport.rs`: add `PublishOutcome` enum, refactor `MockTransport::publish_receipt` to use per-key seq, refactor `DhtTransport::publish_receipt` to use the same pattern, add `CIPHERPOST_DEBUG` env read for stderr log.
  - Add `tests/cas_racer.rs` (Barrier-synced, `#[serial]`, `#[cfg(feature = "mock")]`).
  - Add `tests/wire_budget_compose_pin_burn_pgp.rs` (mock-feature, no `#[serial]` needed — synthesized payload, no shared state).
  - Bundle rationale: both touch the trait/transport layer; both ship as MockTransport-only assertions; both fit the existing single-purpose-test-file convention.
- **Plan 09-02: Real-DHT cross-identity round trip + cfg-feature + UDP pre-flight + nextest config.** Covers DHT-03, DHT-04, DHT-05.
  - Add `[features] real-dht-e2e = []` to Cargo.toml.
  - Add `[[test]] real_dht_e2e` entry to Cargo.toml.
  - Add `tests/real_dht_e2e.rs` with single test, `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]`, UDP pre-flight, exp-backoff, deadline.
  - Add `.config/nextest.toml` with the per-test slow-timeout override.
- **Plan 09-03: Docs + RELEASE-CHECKLIST + CLAUDE.md lock-ins + STATE.md todo closure.** Covers DHT-06.
  - Add `/RELEASE-CHECKLIST.md` template (~80 lines, markdown checkbox).
  - Add `/RELEASE-CHECKLIST-v1.1.md` versioned snapshot at Phase 9 close (preferred per Discretion).
  - Edit `CLAUDE.md` §Load-bearing lock-ins: 3 new entries (CAS retry contract; bootstrap-defaults discipline; real-DHT cfg-flag discipline).
  - Edit `README.md`: single-sentence bootstrap-defaults note.
  - Edit `SPEC.md`: inline mention of bootstrap defaults; Pitfall #22 composite update.
  - Close STATE.md "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" todo.

**Why not 4 plans:** splitting docs into its own 4th plan adds overhead (one more PLAN.md, one more VERIFICATION.md, one more execution cycle) for a ~2-hour docs-only effort. Phase 8's Plan 06 set the precedent: docs-only plan as final phase plan. Phase 9 follows that pattern.

**Why not 2 plans:** bundling the real-DHT plan with the CAS plan would create a >300-LOC plan touching the transport layer AND adding network test infrastructure AND changing Cargo.toml's feature surface — too broad for a single ship-gate. Plan-check would likely flag.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| `cargo` (stable) | All build/test | ✓ | per `rust-version = "1.88"` in Cargo.toml | — |
| `cargo-nextest` | CI test runner; recommended for real-DHT timeout enforcement | ✓ | 0.9.100 | `cargo test` (loses per-test timeout enforcement) |
| `cargo audit` | RELEASE-CHECKLIST gate | ✓ (via taiki-e/install-action in CI) | latest | manually review RUSTSEC advisories |
| `cargo deny` | RELEASE-CHECKLIST gate | ✓ (via taiki-e/install-action in CI) | latest | manually review deny.toml policy |
| `lychee` | RELEASE-CHECKLIST link-check | ✓ (via lycheeverse/lychee-action in CI) | per CI pin | none — link-check is a release gate |
| `pkarr` 5.0.4 | DhtTransport | ✓ | 5.0.4 (via Cargo.lock; spec is 5.0.3) | none — load-bearing dep |
| `serial_test` 3 | New tests | ✓ | per dev-dep | none — load-bearing for both new tests |
| `tempfile` 3 | Test isolation | ✓ | per dev-dep | none |
| Outbound UDP to `router.bittorrent.com:6881` | Real-DHT manual run | depends on network (CI: NO; dev: USUALLY) | — | UDP pre-flight skips with canonical message |

**Missing dependencies with no fallback:** none — Phase 9 is purely additive on top of an already-functional v1.1 stack.

**Missing dependencies with fallback:** outbound UDP for real-DHT; pre-flight already handles the skip case per D-P9-D5.

## Sources

### Primary (HIGH confidence)
- **`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pkarr-5.0.4/src/client.rs`** — PublishError, ConcurrencyError, publish() signature, lost-update docstring (lines 220-316, 565-624)
- **`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pkarr-5.0.4/src/client/blocking.rs`** — ClientBlocking::publish, futures_lite::block_on internal usage (lines 1-150)
- **`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pkarr-5.0.4/src/client/builder.rs`** — Config::default with mainline::Dht::builder default; bootstrap method existence (lines 56-170)
- **`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/mainline-6.1.1/src/rpc.rs:42-47`** — DEFAULT_BOOTSTRAP_NODES list (router.bittorrent.com, dht.transmissionbt.com, dht.libtorrent.org:25401, relay.pkarr.org)
- **`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/ntimestamp-1.0.0/src/lib.rs:79-103`** — Timestamp(u64) microseconds API
- **`/home/john/vault/projects/github.com/cipherpost/src/transport.rs`** — existing publish_receipt with cas: Option<pkarr::Timestamp> at line 168
- **`/home/john/vault/projects/github.com/cipherpost/Cargo.toml`** — existing features block, dev-deps, [[test]] entries
- **`/home/john/vault/projects/github.com/cipherpost/.github/workflows/ci.yml:35-46`** — CI uses `cargo nextest run --all-features --no-fail-fast`
- **`cargo test --help` and `cargo test -- --help`** (verified 2026-04-26 against installed cargo) — no `--test-timeout` flag on stable cargo or libtest
- **`cargo-nextest --version`** (0.9.100, installed at `~/.cargo/bin/cargo-nextest`)

### Secondary (MEDIUM confidence)
- **https://nexte.st/docs/configuration/per-test-overrides/** — slow-timeout + terminate-after override syntax (verified via WebFetch)

### Tertiary (LOW confidence — none in this research)
- All claims are verified against pkarr / mainline / ntimestamp source code in the local Cargo registry, against running `cargo` and `cargo-nextest` outputs, or against CONTEXT.md / PITFALLS.md / CLAUDE.md project docs. No claims rest on training-data recall alone.

## Metadata

**Confidence breakdown:**
- pkarr 5.0.4 API surface (PublishError variants, ClientBlocking, Timestamp, ClientBuilder defaults): HIGH — full source read at `~/.cargo/registry/src/.../pkarr-5.0.4/src/`
- mainline 6.1.1 default bootstrap nodes: HIGH — verbatim from `mainline-6.1.1/src/rpc.rs:42-47`
- pkarr does not retry publish internally: HIGH — exhaustive `grep -rn 'retry'` across pkarr/mainline source
- cargo `--test-timeout` does not exist on stable: HIGH — `cargo test --help` and `cargo test -- --help` directly verified
- nextest config syntax: MEDIUM-HIGH — official docs via WebFetch; nextest 0.9.100 installed locally; existing CI uses nextest already
- 7-step exp-backoff curve adequacy: MEDIUM — based on v1.0 PITFALLS.md #10's p50 = 1min figure; curve is conservative
- UDP pre-flight host choice (`router.bittorrent.com:6881`): MEDIUM — pkarr/mainline canonical first-list-entry; alternative hosts available in the same list if it goes down

**Research date:** 2026-04-26
**Valid until:** 2026-05-26 (30 days; pkarr is stable post-1.0; nextest is stable; mainline bootstrap list rarely changes — but if pkarr ships 5.1.0 in this window the PublishError variants and Timestamp module location should be re-verified against the new source)

---

*Phase 9 research complete. The planner can now author 09-01-PLAN.md, 09-02-PLAN.md, 09-03-PLAN.md per the recommended structure above. Open Questions OQ-1 through OQ-6 are resolved with explicit citations to pkarr 5.0.4 source code at `~/.cargo/registry/src/.../`.*
