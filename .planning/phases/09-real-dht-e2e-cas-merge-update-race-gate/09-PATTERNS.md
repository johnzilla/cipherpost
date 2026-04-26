# Phase 9: Real-DHT E2E + CAS merge-update race gate — Pattern Map

**Mapped:** 2026-04-26
**Files analyzed:** 12 (5 NEW + 7 modified)
**Analogs found:** 11 / 12 (only `.config/nextest.toml` has no in-tree analog — first nextest config file)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|-------------------|------|-----------|----------------|---------------|
| `tests/cas_racer.rs` (NEW) | integration-test | event-driven (concurrent threads) | `tests/phase3_mock_publish_receipt_coexistence.rs` + `tests/state_ledger.rs` | role-match |
| `tests/real_dht_e2e.rs` (NEW) | integration-test | request-response (network round trip) | `tests/mock_transport_roundtrip.rs` | role-match (cfg+ignored gating is novel) |
| `tests/wire_budget_compose_pin_burn_pgp.rs` (NEW) | integration-test | transform (assertion-only) | `tests/pgp_roundtrip.rs` lines 93-135 + `tests/burn_send_smoke.rs` lines 130-191 + `tests/pin_burn_compose.rs` | exact (third instance of D-P7-02 pattern) |
| `RELEASE-CHECKLIST.md` (NEW, repo root) | top-level-docs | n/a | `SECURITY.md` (134 lines, top-level draft-banner doc) | role-match (template lifecycle is novel) |
| `RELEASE-CHECKLIST-v1.1.md` (NEW, repo root) | top-level-docs | n/a | `SECURITY.md` + the to-be-authored `RELEASE-CHECKLIST.md` template | role-match |
| `.config/nextest.toml` (NEW) | config | n/a | **NO ANALOG** — first nextest config file in repo (CI uses defaults today) | none — use RESEARCH.md OQ-5 verbatim |
| `Cargo.toml` (modified) | config | n/a | `Cargo.toml:18-19` (`mock = []`) — verbatim mirror | exact |
| `src/transport.rs::publish_receipt` (modified) | service | request-response w/ retry | `src/transport.rs:140-201` itself (DhtTransport::publish_receipt; existing CAS-aware shape) | exact (extend in place) |
| `src/transport.rs::MockTransport` (modified) | service | event-driven (in-memory store) | `src/transport.rs:300-389` itself (existing MockTransport) | exact (extend in place) |
| `src/transport.rs::map_pkarr_publish_error` (modified) | utility | transform (error mapping) | `src/transport.rs:264-270` itself (existing helper) | exact |
| `README.md` (modified — single sentence) | top-level-docs | n/a | `README.md:22` (`No tokio dependency...` one-liner under Build) | exact |
| `SPEC.md` (modified — Pitfall #22 extension + bootstrap inline + CAS contract note) | top-level-docs | n/a | `SPEC.md` §3 Wire Format + existing Pitfall references | exact |
| `CLAUDE.md` (modified — three new lock-ins) | project-instructions | n/a | `CLAUDE.md` §"Load-bearing lock-ins" (existing bullet list) | exact |
| `.planning/STATE.md` (modified — close bootstrap todo) | planning-state | n/a | existing STATE.md todo cursor entries | exact |

## Pattern Assignments

### `tests/cas_racer.rs` (NEW; integration-test, event-driven concurrent threads)

**Primary analog:** `tests/phase3_mock_publish_receipt_coexistence.rs` (deterministic-keypair pattern + receipt-coexistence assertion shape)
**Secondary analog:** `tests/state_ledger.rs` (`#[serial]` discipline with `#![cfg(feature = "mock")]` crate-level gate + serial_test imports)

**File-level cfg + imports** (copy from `tests/state_ledger.rs:23-28`):
```rust
#![cfg(feature = "mock")]

use cipherpost::transport::{MockTransport, Transport};
use cipherpost::DHT_LABEL_RECEIPT_PREFIX;
use serial_test::serial;
use std::sync::{Arc, Barrier};
use std::thread;
```

**Deterministic keypair helper** (copy from `tests/phase3_mock_publish_receipt_coexistence.rs:18-20`):
```rust
fn deterministic_keypair(seed_byte: u8) -> pkarr::Keypair {
    pkarr::Keypair::from_secret_key(&[seed_byte; 32])
}
```

**Concurrent racer pattern** — there is NO existing `Barrier`-synced thread test in the repo, so synthesize from CONTEXT.md `<specifics>` block (lines 219-261). Key invariants the planner must preserve:
- `Arc::new(MockTransport::new())` — shared store across threads
- `Arc::new(Barrier::new(2))` — synchronizes both threads at the resolve-then-publish boundary (Pitfall #28: NO `sleep`-based simulation)
- Two `thread::spawn` closures each clone `Arc<Transport>` + `Arc<Barrier>` + a fresh `keypair.clone()` (note: `pkarr::Keypair` is `Clone`)
- After `.join()`, assert `resolve_all_txt(&z32).iter().filter(|(l,_)| l.starts_with(DHT_LABEL_RECEIPT_PREFIX)).count() == 2`
- Apply `#[serial]` because `MockTransport`'s `Arc<Mutex<HashMap<...>>>` could race with other mock-transport tests if nextest schedules them in the same crate group

**Receipt-count + coexistence assertion** (copy shape from `tests/phase3_mock_publish_receipt_coexistence.rs:73-90`):
```rust
let all = transport.resolve_all_txt(&z32);
assert_eq!(
    all.iter()
        .filter(|(l, _)| l.starts_with(DHT_LABEL_RECEIPT_PREFIX))
        .count(),
    2,
    "both receipts must persist after concurrent publish; got {:?}",
    all.iter().map(|(l, _)| l.clone()).collect::<Vec<_>>()
);
```

**Cargo.toml `[[test]]` entry** (copy shape from `Cargo.toml:85-88`):
```toml
[[test]]
name = "cas_racer"
path = "tests/cas_racer.rs"
required-features = ["mock"]
```

---

### `tests/real_dht_e2e.rs` (NEW; integration-test, network round trip)

**Primary analog:** `tests/mock_transport_roundtrip.rs` (publish-then-resolve assertion shape — same trait calls, real client substituted for mock)
**Secondary analog (gating discipline):** `tests/state_ledger.rs:23` (`#![cfg(feature = "mock")]` crate-level gate — this file uses `feature = "real-dht-e2e"` instead)

**File-level cfg pattern** (NEW; mirrors mock-feature gating but uses Phase 9's flag):
```rust
#![cfg(feature = "real-dht-e2e")]

use cipherpost::transport::{DhtTransport, Transport};
use serial_test::serial;
use std::time::{Duration, Instant};
```

**Test attribute stack** (D-P9-D2 mandates all three):
```rust
#[test]
#[ignore]   // Belt-and-suspenders — even with cfg-feature off, --ignored gates manual run
#[serial]   // Pitfall #29 — shared network state; never relax even though there's only one test
fn real_dht_cross_identity_round_trip_with_receipt() { ... }
```

**Two-client construction** (per RESEARCH.md OQ-4 — reuse `DhtTransport::new`, do NOT inline `pkarr::Client::builder()`):
```rust
let alice_transport = DhtTransport::new(Duration::from_secs(120))
    .expect("DhtTransport::new alice");
let bob_transport = DhtTransport::new(Duration::from_secs(120))
    .expect("DhtTransport::new bob");
```

**UDP pre-flight helper** (NEW per RESEARCH.md OQ-3 — no in-tree analog; `std::net::UdpSocket` not used elsewhere in tests):
```rust
fn udp_bootstrap_reachable(timeout: Duration) -> bool {
    use std::net::{ToSocketAddrs, UdpSocket};
    let deadline = Instant::now() + timeout;
    let mut addrs = match "router.bittorrent.com:6881".to_socket_addrs() {
        Ok(it) => it,
        Err(_) => return false,
    };
    let target = match addrs.next() {
        Some(a) => a,
        None => return false,
    };
    if Instant::now() >= deadline { return false; }
    let socket = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return false,
    };
    let _ = socket.set_read_timeout(Some(timeout));
    socket.connect(target).is_ok()
}
```

**Skip message — canonical wording** (from CONTEXT.md decisions §"DHT-05"):
```rust
if !udp_bootstrap_reachable(Duration::from_secs(5)) {
    eprintln!("real-dht-e2e: UDP unreachable; test skipped (not counted as pass)");
    return;
}
```

**In-test deadline + exp-backoff resolve loop** (per RESEARCH.md OQ-2 — recommended curve `1s, 2s, 4s, 8s, 16s, 32s, 64s` clipped at 120s; no in-tree analog for resolve loops with backoff):
```rust
let deadline = Instant::now() + Duration::from_secs(120);
let mut attempt_sleep = Duration::from_secs(1);
let resolved = loop {
    if Instant::now() >= deadline {
        panic!("real-dht-e2e: resolve deadline exceeded (120s)");
    }
    match bob_transport.resolve(&alice_z32) {
        Ok(record) => break record,
        Err(_) => {
            let remaining = deadline.saturating_duration_since(Instant::now());
            std::thread::sleep(attempt_sleep.min(remaining));
            attempt_sleep = attempt_sleep.saturating_mul(2);
        }
    }
};
```

**Round-trip assertion shape** (copy from `tests/mock_transport_roundtrip.rs:39-50`):
```rust
transport.publish(&kp, &original).unwrap();
let resolved = transport.resolve(&kp.public_key().to_z32()).unwrap();
assert_eq!(resolved, original, "...");
```

**Cargo.toml `[[test]]` entry** (mirror `mock_transport_roundtrip` pattern at `Cargo.toml:86-88` but with the new feature):
```toml
[[test]]
name = "real_dht_e2e"
path = "tests/real_dht_e2e.rs"
required-features = ["real-dht-e2e"]
```

---

### `tests/wire_budget_compose_pin_burn_pgp.rs` (NEW; integration-test, transform / assertion-only)

**Primary analog:** `tests/pgp_roundtrip.rs:93-135` (the D-P7-02 positive `WireBudgetExceeded` test — Phase 9 DHT-07 is the third instance of the same pattern)
**Secondary analogs:** `tests/burn_send_smoke.rs:130-191` (pin+burn compose call shape) and `tests/pin_burn_compose.rs` (mock + `#[serial]` discipline)

**File-level cfg + imports** (copy from `tests/burn_send_smoke.rs:20-31`):
```rust
#![cfg(feature = "mock")]

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::{run_send, MaterialSource, SendMode, DEFAULT_TTL_SECONDS};
use cipherpost::transport::MockTransport;
use cipherpost::Error;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;
```

**Setup helper** (copy verbatim from `tests/burn_send_smoke.rs:37-44` — lands the same `(Identity, Keypair)` shape every wire-budget test uses):
```rust
fn setup(dir: &TempDir) -> (cipherpost::identity::Identity, pkarr::Keypair) {
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    (id, kp)
}
```

**Wire-budget assertion pattern** (copy from `tests/pgp_roundtrip.rs:114-134` — this is the D-P7-02 template; Phase 9 DHT-07 is the third instance after Phase 6 X.509 and Phase 7 PGP/SSH):
```rust
match err {
    Error::WireBudgetExceeded { encoded, budget, plaintext: _ } => {
        assert_eq!(budget, 1000);
        assert!(
            encoded > budget,
            "encoded ({}) must exceed budget ({})",
            encoded,
            budget
        );
    }
    other => panic!(
        "expected WireBudgetExceeded, got {:?} — either budget protocol \
         changed, ingest rejected before budget check (regression), OR the \
         realistic-fixture is not large enough",
        other
    ),
}
```

**Pin+burn compose call** (copy `run_send` arg shape from `tests/burn_send_smoke.rs:138-149`; per D-P9-E1 use a synthesized `vec![0u8; 2048]` as `MaterialSource::Bytes` with `MaterialVariant::GenericSecret`, NOT the PGP fixture — the test asserts byte-budget, not parser correctness):
```rust
let plaintext = vec![0u8; 2048]; // synthesized 2KB; not parser-tested
let pin = SecretBox::new(Box::new("validpin1".to_string()));

let err = run_send(
    &id,
    &transport,
    &kp,
    SendMode::SelfMode,
    "compose",
    MaterialSource::Bytes(plaintext),
    MaterialVariant::GenericSecret,
    DEFAULT_TTL_SECONDS,
    Some(pin),  // pin
    true,       // burn
)
.expect_err("pin+burn+2KB must overflow wire budget");
```

**Test attribute** (copy from `tests/pgp_roundtrip.rs:94-96`):
```rust
#[test]
#[serial]
fn pin_burn_realistic_payload_surfaces_wire_budget_exceeded() { ... }
```

**Cargo.toml `[[test]]` entry** (mirror PIN/burn test entries):
```toml
[[test]]
name = "wire_budget_compose_pin_burn_pgp"
path = "tests/wire_budget_compose_pin_burn_pgp.rs"
required-features = ["mock"]
```

---

### `RELEASE-CHECKLIST.md` (NEW, repo root; top-level-docs template)

**Primary analog:** `SECURITY.md` (top-level-docs convention: draft banner + sectioned headings + checklist-friendly bullet structure)
**Reference content:** CONTEXT.md `<specifics>` lines 291-343 contains a 50-line mockup that the planner extends to ~80 lines per D-P9-C1.

**Top-of-file banner pattern** (copy header style from `SECURITY.md:1-8`):
```markdown
# Cipherpost Release Checklist (template)

> **Status: living template — copied per release into `RELEASE-CHECKLIST-vX.Y.md`**
>
> This template is the source-of-truth for every v1.1+ release. At ship time,
> `cp RELEASE-CHECKLIST.md RELEASE-CHECKLIST-v<version>.md`, fill in the
> release-specific fields, and tick each box as the gate is verified.
```

**Markdown checkbox sections** (D-P9-C3 — `[ ]`/`[x]` per item; ~80 lines total per D-P9-C1). Section structure (per CONTEXT.md `<specifics>`):
1. **Pre-flight** — VERIFICATION.md sign-off, PROJECT.md scope reflection, Cargo.toml version
2. **Code gates** — `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, `cargo audit`, `cargo deny check`, `cargo nextest run`, `cargo test --doc`, `lychee --offline ...`
3. **Wire-format byte-counts (regression guard)** — five fixture sizes (192 / 424 / 119 / 212 / 142) per CONTEXT.md `<canonical_refs>` and any DHT-07-additions
4. **Manual real-DHT gate (DHT-03/04/05)** — `cargo nextest run --features real-dht-e2e --run-ignored only --filter-expr 'test(real_dht_e2e)' --no-fail-fast` per RESEARCH.md OQ-5 (NOT `cargo test --test-timeout` — that flag does not exist on stable cargo)
5. **Security review** — RUSTSEC list scan, `chacha20poly1305 only via age` audit, HKDF info enumeration test green
6. **Release artifacts** — git tag, MILESTONES.md update, snapshot ticked file as `RELEASE-CHECKLIST-vX.Y.md`

**Anti-pattern from CONTEXT.md** (line 268-276 of RESEARCH.md): the CONTEXT.md `<specifics>` mockup at line 327 says `cargo test --features real-dht-e2e -- --ignored --test-timeout 120 dht_e2e` — **that command is wrong on stable cargo** (RESEARCH.md OQ-5). Replace with the nextest invocation above when authoring the actual file.

---

### `RELEASE-CHECKLIST-v1.1.md` (NEW, repo root; first versioned snapshot)

**Primary analog:** the to-be-authored `RELEASE-CHECKLIST.md` template (verbatim copy with v1.1-specific fields filled)
**Lifecycle (D-P9-C4):** committed at Phase 9 close per Discretion recommendation (not deferred to v1.1 release tag time).

**Header difference vs template** (drop the "living template" banner; replace with):
```markdown
# Cipherpost v1.1 Release Checklist

**Release date:** YYYY-MM-DD (filled at tag time)
**Releaser:** @<github-username>
**Tag:** v1.1.0
```

Body identical to template at Phase 9 close (boxes unticked); `[ ]` → `[x]` ticking happens at v1.1 release time.

---

### `.config/nextest.toml` (NEW)

**Primary analog:** **NO IN-TREE ANALOG.** This is the first nextest config file in the repo. Use RESEARCH.md OQ-5 (line 257-264) verbatim:
```toml
# .config/nextest.toml
# Phase 9: outer guard for real-DHT round-trip test (D-P9-D3 belt-and-suspenders).
# Pairs with the in-test `Instant`-deadline check; nextest force-terminates after
# 2 × 60s slow periods = 120s wall clock. Stable cargo has no equivalent flag
# (RESEARCH.md OQ-5).
[[profile.default.overrides]]
filter = 'test(real_dht_e2e)'
slow-timeout = { period = "60s", terminate-after = 2 }
```

---

### `Cargo.toml` (modified — add `real-dht-e2e = []` feature)

**Analog (verbatim mirror):** `Cargo.toml:18-19`:
```toml
[features]
mock = []
```

**Phase 9 addition** (single-line append; no new dependencies per CONTEXT.md `<canonical_refs>` §"Dependency additions"):
```toml
[features]
mock = []
real-dht-e2e = []
```

Plus three new `[[test]]` entries (shapes documented per-test-file above).

---

### `src/transport.rs` — `DhtTransport::publish_receipt` (modified, lines 140-201)

**Analog:** the existing function at `src/transport.rs:140-201` itself. Phase 9 wraps the existing publish call (line 197-199) in a single-retry loop on `pkarr::errors::ConcurrencyError::{ConflictRisk, NotMostRecent, CasFailed}` per RESEARCH.md OQ-1.

**Existing pattern to preserve** (lines 162-180): resolve-most-recent → rebuild builder skipping same-label RRs → set `cas: Option<pkarr::Timestamp>` from `packet.timestamp()` → sign. The retry replays steps 1-4 once on `ConcurrencyError`.

**Pattern to add (single-retry-then-fail per D-P9-A1)** — pseudocode from CONTEXT.md `<specifics>` lines 359-378:
```rust
fn publish_receipt(&self, kp, share_ref, json) -> Result<(), Error> {
    match self.publish_receipt_attempt(kp, share_ref, json) {
        Ok(()) => Ok(()),
        Err(InternalCasConflict) => {
            if cipherpost_debug_enabled() {
                eprintln!("Receipt publish: CAS conflict, retrying...");
            }
            // Single retry (D-P9-A1): resolve-merge-republish ONCE.
            // Second conflict → final failure rides Error::Transport
            // (D-P9-anti-pattern: no new public Error::CasConflict variant).
            self.publish_receipt_attempt(kp, share_ref, json)
                .map_err(|e| match e {
                    InternalCasConflict => Error::Transport(/* ... */),
                    other => other.into(),
                })
        }
        Err(other) => Err(other.into()),
    }
}
```

**Existing `publish_receipt` signature is LOCKED** (Phase 1) — D-P9-A2: retry stays inside the trait method; caller signature unchanged.

**`map_pkarr_publish_error` extension at line 264-270** — per RESEARCH.md OQ-1, add a new arm catching `PublishError::Concurrency(_)` BEFORE the `Transport` collapse. Recommendation from RESEARCH.md: introduce a private `enum PublishOutcome { Ok, CasConflict, Other(Error) }` returned by a private `publish_receipt_attempt()` helper; keeps `map_pkarr_publish_error` signature unchanged for the non-receipt `publish` callsite at line 117.

---

### `src/transport.rs` — `MockTransport` + `MockStore` (modified, lines 285-389)

**Analog:** the existing module at `src/transport.rs:285-389` itself.

**Existing `MockStore` type** (line 291):
```rust
type MockStore = Arc<Mutex<HashMap<String, Vec<(String, String)>>>>;
```

**Phase 9 extension** — replace the `Vec<(String, String)>` value with a struct that adds per-key `seq: u64` (sketch from CONTEXT.md `<specifics>` lines 346-356):
```rust
type MockStore = Arc<Mutex<HashMap<String, MockStoreEntry>>>;

struct MockStoreEntry {
    records: Vec<(String, String)>,
    seq: u64,
}
```

**Existing `resolve_all_txt` API at lines 313-321 MUST stay green** (CONTEXT.md `<canonical_refs>` line 174 — internal change only; no test-API breakage). The helper now reads `entry.records` instead of `entry` directly.

**`publish_receipt` CAS extension** (replace existing body at lines 357-374) — per CONTEXT.md `<specifics>` lines 350-356:
1. Lock store; get current seq for pubkey (default 0)
2. Read current records (clone)
3. Drop lock; build new record set with new receipt merged in
4. Re-lock; check seq still matches; if mismatch, return `InternalCasConflict`
5. If match: bump seq, write merged records, release lock
6. The trait-method outer wrapper catches `InternalCasConflict` and re-runs steps 2-5 once

**`MockTransport::publish` (lines 324-341) and `resolve_all_cprcpt` (lines 376-388) require minor adjustment** to read/write through the new `MockStoreEntry` shape but the existing semantics (clobber-replace for `_cipherpost`; filter on `_cprcpt-` prefix) are preserved.

---

### `README.md` (modified — single-sentence bootstrap note)

**Analog:** `README.md:22` (existing one-liner under Build):
```markdown
Requires Rust 1.85+ (pinned in `rust-toolchain.toml`). No `tokio` dependency at the cipherpost layer — uses `pkarr::ClientBlocking`.
```

**Pattern to add** (D-P9-B2 + Discretion recommendation: single sentence, NOT a new section). Recommended insertion point: same paragraph as line 22 or a new bullet under the "No servers" bullet at line 7. Suggested wording:
```markdown
Bootstrap nodes are pkarr defaults (Mainline DHT — `router.bittorrent.com:6881` and three peers) — no user-tunable bootstrap configuration in v1.1.
```

---

### `SPEC.md` (modified — three inline additions)

**Analog:** existing `SPEC.md` §3 (Wire Format) and the §Pitfalls reference style.

**Three additions per CONTEXT.md `<specifics>` "Spec sections to edit":**

1. **§3 (Wire Format) inline note** — bootstrap-defaults sentence (mirrors README single-sentence wording).
2. **§3 (Wire Format) CAS contract note** — `cas` semantics on `publish_receipt` are now contractual: receivers MUST implement single-retry-then-fail per the Phase 9 lock-in (or document divergence in `protocol_version`). Reference RESEARCH.md OQ-1 for the three `ConcurrencyError` variants that signal conflict.
3. **§Pitfall #22 extension** — extend the per-variant wire-budget table with the `pin_required=true + burn_after_read=true + ~2KB GenericSecret` composite measurement (DHT-07 assertion result).

No new section headings; all three are inline additions per D-P9-B2 spirit (avoid section sprawl for non-features).

---

### `CLAUDE.md` (modified — three new load-bearing lock-ins)

**Analog:** existing `CLAUDE.md` §"Load-bearing lock-ins" bullet list (e.g., the entry on `serial_test = "3"`, the `pkarr::ClientBlocking` no-tokio entry, the error-oracle hygiene entry). Phase 9 appends three new bullets in the same prose style:

1. **CAS retry contract** — "Single-retry-then-fail CAS contract on `publish_receipt`; retry lives inside the `Transport` trait method (`CasConflict` never escapes the trait); `MockTransport` models CAS via per-key seq:u64 (matches `pkarr::Timestamp` semantics behaviorally). `pkarr::errors::ConcurrencyError::{ConflictRisk, NotMostRecent, CasFailed}` are all treated as the conflict signal."
2. **Bootstrap defaults** — "No `CIPHERPOST_DHT_BOOTSTRAP` env var in v1.1 — pkarr defaults only (4 Mainline hosts: `router.bittorrent.com`, `dht.transmissionbt.com`, `dht.libtorrent.org`, `relay.pkarr.org`)."
3. **Real-DHT cfg-flag discipline** — "Real-DHT tests behind `#[cfg(feature = \"real-dht-e2e\")]` + `#[ignore]` + `#[serial]`; CI never runs `--features real-dht-e2e`. RELEASE-CHECKLIST manual invocation is the only gate (Pitfall #29)."

---

### `.planning/STATE.md` (modified — close bootstrap-configurability todo)

**Analog:** existing STATE.md todo cursor entries with `[CLOSED]` / `[OPEN]` markers (search for "verify pkarr 5.0.4 ClientBuilder bootstrap configurability" entry).

**Pattern:** mark todo CLOSED with resolution note: "Closed by D-P9-B1: pkarr defaults only for v1.1; bootstrap is configurable via `ClientBuilder::bootstrap` (verified at `pkarr-5.0.4/src/client/builder.rs:164` per Phase 9 RESEARCH.md OQ-4) but the API is not exercised in v1.1. Revisit at v1.2+ if private-testnet support is requested."

---

## Shared Patterns

### `#![cfg(feature = "...")]` crate-level test gating

**Source:** `tests/state_ledger.rs:23` (`#![cfg(feature = "mock")]`)
**Apply to:** `tests/cas_racer.rs` (use `feature = "mock"`), `tests/real_dht_e2e.rs` (use `feature = "real-dht-e2e"`), `tests/wire_budget_compose_pin_burn_pgp.rs` (use `feature = "mock"`)

```rust
#![cfg(feature = "<feature-name>")]
```

Convention: file-level cfg attribute as the first non-doc-comment line. Pairs with `required-features` in the corresponding `Cargo.toml [[test]]` entry.

### `#[serial]` on shared-state tests

**Source:** `tests/state_ledger.rs:27` (`use serial_test::serial;`) + `tests/burn_send_smoke.rs:30` + `tests/pin_burn_compose.rs:48`
**Apply to:** every new test in Phase 9 (env mutation, network mutation, or shared `MockStore` state)

```rust
use serial_test::serial;

#[test]
#[serial]
fn my_test() { ... }
```

CLAUDE.md load-bearing: `serial_test = "3"` is dev-dep at `Cargo.toml:401`; nextest parallel runner races without `#[serial]` on env/network mutators.

### Deterministic-keypair test helper

**Source:** `tests/phase3_mock_publish_receipt_coexistence.rs:18-20`

```rust
fn deterministic_keypair(seed_byte: u8) -> pkarr::Keypair {
    pkarr::Keypair::from_secret_key(&[seed_byte; 32])
}
```

Use for `tests/cas_racer.rs` where Identity setup is overkill (mock-only test). For tests that need a real `Identity` (e.g., `tests/wire_budget_compose_pin_burn_pgp.rs`), use the `setup(&dir)` pattern from `tests/burn_send_smoke.rs:37-44` instead.

### `WireBudgetExceeded` assertion match shape

**Source:** `tests/pgp_roundtrip.rs:114-134`
**Apply to:** `tests/wire_budget_compose_pin_burn_pgp.rs` (DHT-07 — third instance after Phase 6 X.509 and Phase 7 PGP/SSH)

Already excerpted above under that file's pattern assignment.

### Top-level docs draft banner

**Source:** `SECURITY.md:1-8`, `SPEC.md:1-8`, `THREAT-MODEL.md` (all share the same `> **Status: DRAFT...` banner)
**Apply to:** `RELEASE-CHECKLIST.md` (template) — use a "living template" banner instead of "DRAFT"; `RELEASE-CHECKLIST-v1.1.md` — drop the banner (versioned snapshot is not draft).

### `Cargo.toml [[test]]` entry shape

**Source:** `Cargo.toml:85-88` (canonical 4-line shape)

```toml
[[test]]
name = "<test_name>"
path = "tests/<test_name>.rs"
required-features = ["<feature>"]
```

Apply to all three new test files. The `required-features` line is mandatory for cfg-gated tests so `cargo test` (no features) does not even attempt to compile them.

## Anti-patterns to Avoid (from CONTEXT.md `<code_context>` §"Anti-patterns to avoid")

The planner MUST NOT generate plans that:
1. Introduce a `tokio` direct dep for the real-DHT test harness (use `pkarr::ClientBlocking`).
2. Introduce a relay/operator/test-server for the real-DHT round trip.
3. Run real-DHT tests in PR CI (mock-only in CI).
4. Add a public `Error::CasConflict` variant (single-retry absorbs; final failure rides existing `Error::Transport`).
5. Use `sleep`-based simulation for the racer test (Pitfall #28: true `Barrier`-synced threads only).
6. Add `CIPHERPOST_DHT_BOOTSTRAP` env var read in v1.1.
7. Log CAS retry events to stderr by default (gate behind `CIPHERPOST_DEBUG=1`).
8. Spawn more than one real-DHT test per CI job (zero in v1.1; future cap is one-per-job).
9. Delete or amend existing wire-format fixtures (192 / 424 / 119 / 212 / 142).
10. Skip the in-test deadline check on the real-DHT test (D-P9-D3: both in-test AND nextest-config).
11. Promote bootstrap configurability to a first-class flag without a v1.2 milestone gate.
12. Introduce a CAS racer test against real DHT (D-P9-D1: real-DHT scope is round trip only).
13. Relax the `#[serial]` requirement on real-DHT tests even though there's only one.
14. Use `cargo --test-timeout` (does not exist on stable cargo per RESEARCH.md OQ-5; use `.config/nextest.toml` slow-timeout instead).
15. Use the PGP fixture directly for the DHT-07 wire-budget composite test (D-P9-E1 + RESEARCH.md: synthesized 2KB byte vector wrapped in `Material::GenericSecret` — assertion is byte-budget, not parser correctness).

## No Analog Found

| File | Role | Reason | Source for pattern |
|------|------|--------|--------------------|
| `.config/nextest.toml` | nextest config | First nextest config file in repo (CI uses defaults today) | RESEARCH.md OQ-5 — copy the 5-line `[[profile.default.overrides]]` block verbatim |
| `tests/real_dht_e2e.rs` UDP pre-flight helper | std::net helper | `std::net::UdpSocket` not used elsewhere in tests | RESEARCH.md OQ-3 — copy the 18-line `udp_bootstrap_reachable` helper verbatim |
| `tests/cas_racer.rs` `Barrier`-synced threads | concurrent test | No existing `std::sync::Barrier`-synchronized thread test in the repo | CONTEXT.md `<specifics>` lines 219-261 — synthesize the racer harness; preserve invariants enumerated above |
| `tests/real_dht_e2e.rs` exp-backoff resolve loop | retry loop | No existing exp-backoff resolve loop in the repo (cipherpost layer relies on pkarr's request_timeout) | RESEARCH.md OQ-2 — copy the 7-step `1s, 2s, 4s, 8s, 16s, 32s, 64s` curve clipped at the 120s `Instant`-deadline |

## Metadata

**Analog search scope:** `tests/`, `src/transport.rs`, `Cargo.toml`, repo-root `*.md` files
**Files scanned:** 70+ test files, `src/transport.rs` (391 lines), 4 top-level markdown docs, full `Cargo.toml`
**Pattern extraction date:** 2026-04-26
**Pkarr API surface verified:** RESEARCH.md OQ-1..6 (already confirmed by gsd-phase-researcher; treated as authoritative)
**Phase 9 scope per CONTEXT.md:** 3 plans recommended (D-P9-F1) — pattern map supports either the 3-plan or 4-plan split.
