# Phase 2: Send, receive, and explicit acceptance - Research

**Researched:** 2026-04-21
**Domain:** Rust CLI orchestration — payload schema, dual-signature verify-before-decrypt flow, acceptance UX, local state ledger
**Confidence:** HIGH

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions (NON-NEGOTIABLE — plans MUST follow these verbatim)

**Payload size model:**
- **D-PS-01:** Two-layer enforcement. **Plaintext cap = 64 KB** (PAYL-03). Reject plaintext > 64 KB before any crypto with `payload exceeds 64 KB limit: actual=N, cap=65536`. **Wire-budget cap = PKARR/BEP44 ~1000 bytes encoded SignedPacket** (SEND-05). When the encrypted packet exceeds the wire budget, fail at publish time with a DISTINCT error: `share too large for PKARR packet: encoded=N bytes, budget=~1000 bytes (plaintext was K bytes)`. Two separate error paths, two separate `Error` variants (extend from Phase 1's `PayloadTooLarge`).
- **D-PS-02:** `cipherpost send` rejects over-budget packets — no warn-and-publish, no silent chunking. Error text names both actual size and budget.
- **D-PS-03:** Phase 2 size-cap integration test per ROADMAP SC4: feed a 65537-byte plaintext to `cipherpost send`, assert rejection with an error whose text contains both `65537` and `65536`. Pure client-side check, pre-encrypt. Separate wire-budget test extends Phase 1's `signed_packet_budget.rs`.

**Share URI format:**
- **D-URI-01:** URI format = `cipherpost://<sender-z32>/<share_ref_hex>`. Example: `cipherpost://yhigci4xwmadibrmj8wzmf45f3i8xg8mht9abnprq3r5cfxihj8y/0123456789abcdef0123456789abcdef`. ≈99 chars.
- **D-URI-02:** On `receive`, if URI's `share_ref_hex` mismatches resolved `OuterRecord.share_ref`, abort with `Error::ShareRefMismatch`, exit code `1`. Error text: `share_ref in URI does not match resolved record; sender may have republished — re-confirm the URI`.
- **D-URI-03:** `receive` strictly requires the full `cipherpost://` URI. Bare z32 rejected with `expected cipherpost:// URI, got bare pubkey; use the URI that \`send\` printed`.

**Payload wire format:**
- **D-WIRE-01:** Envelope binding implicit. `OuterRecordSignable` keeps Phase 1 shape unchanged. No `ciphertext_hash`/`cleartext_hash` fields added at outer layer.
- **D-WIRE-02:** `Envelope` struct = `{purpose: String, material: Material, created_at: i64, protocol_version: u16}`. Serialized as JCS, then age-encrypted. `Envelope.created_at` matches `OuterRecordSignable.created_at`. `Envelope.protocol_version` matches `PROTOCOL_VERSION = 1`.
- **D-WIRE-03:** `Material` enum serde = `#[serde(tag = "type", rename_all = "snake_case")]`. Shape: `{"type": "generic_secret", "bytes": "<base64-std-padded>"}`. Variants: `generic_secret`, `x509_cert`, `pgp_key`, `ssh_key`. Non-`generic_secret` variants are unit or struct stubs returning `Err(Error::NotImplemented { phase: ... })` on encode/decode.
- **D-WIRE-04:** `GenericSecret.bytes` = base64 standard with padding via `base64::engine::general_purpose::STANDARD`. Ban `URL_SAFE_NO_PAD` at this layer.
- **D-WIRE-05:** Purpose string: stripped of ASCII control chars (C0 `0x00..=0x1F` + DEL `0x7F`; C1 `0x80..=0x9F`) BEFORE JCS canonicalization and signature. Stripping is a send-time normalization (PAYL-04). Documented as sender-attested (Pitfall #12).

**Receive flow order (verify-before-decrypt-before-accept invariant):**
- **D-RECV-01:** Strict order in `cipherpost receive`:
  1. Parse URI → extract `sender_z32`, `url_share_ref`
  2. Transport resolve — outer PKARR sig check inside `pkarr::ClientBlocking` + `DhtTransport::resolve`
  3. Extract `OuterRecord` from TXT, inner Ed25519 sig verify via `record::verify_record` (Phase 1)
  4. Check `url_share_ref == record.share_ref` (D-URI-02)
  5. TTL check against inner signed `created_at + ttl_seconds` (RECV-02, exit 2)
  6. age-decrypt `blob` into `Zeroizing<Vec<u8>>`
  7. Parse decrypted bytes as JCS → `Envelope`
  8. Present acceptance screen on stderr (D-ACCEPT-02)
  9. User types full sender z32 confirmation (D-ACCEPT-01)
  10. Write material to stdout or `-o <path>`
  11. Append ledger entry + write sentinel file (D-STATE-01)

  **NO payload field (including purpose) is printed to stdout OR stderr before step 8 starts.** Step 7 failure (Envelope parse) returns `Error::SignatureCanonicalMismatch` — treated as sig failure, exit 3.

- **D-RECV-02:** RECV-06 idempotent re-receive check happens **AT STEP 1** — before any network call. If `~/.cipherpost/state/accepted/<url_share_ref>` sentinel exists, print prior acceptance row to stderr (`already accepted at <timestamp>; not re-decrypting`) and exit 0 without network I/O.

**Acceptance UX:**
- **D-ACCEPT-01:** Confirmation token = sender's full 52-char z-base-32 pubkey. Byte-equal to `OuterRecord.pubkey` (after `trim()`). Mismatch → `Error::Declined` → exit 7. **No `--yes` flag. No default. No fallback confirmations.**
- **D-ACCEPT-02:** Acceptance screen = bordered box on stderr, labeled rows:
  ```
  === CIPHERPOST ACCEPTANCE ===============================
  Purpose:     "<control-char-stripped purpose>"
  Sender:      ed25519:SHA256:<openssh-fingerprint>
               <sender z32 52 chars>
  Share ref:   <32-char hex>
  Type:        generic_secret
  Size:        <N> bytes
  TTL:         <Xh Ym> remaining (expires <ISO UTC> / <local>)
  =========================================================
  To accept, paste the sender's z32 pubkey and press Enter:
  >
  ```
  Purpose ALWAYS wrapped in ASCII double quotes with control chars stripped. Empty purpose = `""`. OpenSSH + z32 on separate lines. No ANSI colors.
- **D-ACCEPT-03:** TTY required on stdin **AND** stderr. Either non-TTY → `Error::Config("acceptance requires a TTY; non-interactive receive is deferred")` → exit 1. Pre-decrypt abort.

**Local state ledger (RECV-06):**
- **D-STATE-01:** Two files at `~/.cipherpost/state/`:
  - **Ledger:** `~/.cipherpost/state/accepted.jsonl` — append-only, newline-delimited JSON, one line per acceptance: `{"share_ref","sender","accepted_at","purpose","ciphertext_hash","cleartext_hash"}`, keys alphabetical. `ciphertext_hash` = sha256(age blob bytes); `cleartext_hash` = sha256(decrypted envelope JCS bytes).
  - **Sentinel:** `~/.cipherpost/state/accepted/<share_ref>` — empty regular file, mode 0600. Existence = accepted.
- **D-STATE-02:** Dir perms: `~/.cipherpost/state/` at 0700; `accepted.jsonl` at 0600; sentinel dir `accepted/` at 0700; each sentinel at 0600.
- **D-STATE-03:** No rotation/GC in skeleton.
- **D-STATE-04:** `CIPHERPOST_HOME` env var overrides path (matches Phase 1).

**Error additions (extend Phase 1's `error.rs`):**
- **D-ERR-01:** New variants:
  - `ShareRefMismatch` → exit 1, Display: `share_ref in URI does not match resolved record`
  - `WireBudgetExceeded { encoded: usize, budget: usize, plaintext: usize }` → exit 1, Display: `share too large for PKARR packet: encoded=N bytes, budget=M bytes (plaintext was K bytes)`
  - `InvalidShareUri` → exit 1

### Claude's Discretion (planner picks)

- **TTL parse format** (`--ttl <duration>`): seconds-only OR humanized (`24h`, `2d`, `3600s`) — planner's call; default 24h either way.
- **`cipherpost version` output format**: existing 2-line format locked by CLI-04. Planner may tune whitespace or add `--json`.
- **Stdout-to-TTY detection for decrypted payload**: whether to add TTY safety check (refuse to dump secret bytes to terminal unless `-o -` explicit) is planner's call.
- **`--dht-timeout` default**: inherits Phase 1's 30s. Per-command override shape is planner's call.
- **URI scheme extension plan** (query/fragment params) — rejection rule vs pass-through is planner's call.
- **Exact `Error::Config` message text** for TTY-required failures.
- **Acceptance-screen TTL remaining formatting** — `23h 57m` vs `23:57:00` vs `23h 57m 12s`.

### Deferred Ideas (OUT OF SCOPE for Phase 2)

- Multi-packet chunking (`--chunk`): v1.1+
- Compression before encrypt: deferred
- State ledger rotation/GC: deferred (tolerable for 1–100 shares/week)
- State-store encryption at rest: deferred (breaking format change)
- **Receipt publishing on acceptance: Phase 3 work (RCPT-01)** — Phase 2 does NOT emit receipts. The ledger's `ciphertext_hash`/`cleartext_hash` at acceptance are the handoff to Phase 3.
- `cipherpost list` command: v1.0 backlog
- Sender-side publish-and-retry on DHT failure: v1.0
- `cipherpost version --json`: planner discretion
- Encrypt-then-sign for inner layer: v2 consideration
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| PAYL-01 | `Envelope { purpose, material, created_at, protocol_version }` canonicalized with JCS before signing | `crypto::jcs_serialize` ready (Phase 1); D-WIRE-02 locks struct shape; alphabetical-declaration mirror of `OuterRecordSignable` pattern in `record.rs` |
| PAYL-02 | `Material` enum with `GenericSecret { bytes: Vec<u8> }` implemented; `X509Cert`/`PgpKey`/`SshKey` defined but return `unimplemented` | `Error::NotImplemented { phase: u8 }` variant already exists (Phase 1 error.rs:57); D-WIRE-03 locks serde tag shape |
| PAYL-03 | Plaintext rejected if > 64 KB; error names actual size + cap | `Error::PayloadTooLarge { actual, limit }` already exists (Phase 1 error.rs:52); D-PS-01 reaffirms |
| PAYL-04 | Purpose stripped of C0/C1 control chars before canonicalization; documented as sender-attested in SPEC.md | D-WIRE-05 locks strip at send-time; control-char filter per §Code Examples below |
| PAYL-05 | `share_ref` = 128-bit `sha256(ciphertext \|\| created_at)[..16]`, 32-char hex | `record::share_ref_from_bytes` already ships (Phase 1 record.rs:68); `SHARE_REF_BYTES = 16`, `SHARE_REF_HEX_LEN = 32` |
| SEND-01 | `send --self` reads payload from `<path>` or `-`, builds envelope, age-encrypts to own X25519, dual-signs, publishes, prints share URI | `identity::load` + `crypto::ed25519_to_x25519_secret` + `crypto::recipient_from_x25519_bytes` + `record::sign_record` + `transport::publish` — all ready. New URI format per D-URI-01 |
| SEND-02 | `send --share <pubkey>` encrypts to recipient X25519 (derived from Ed25519 PKARR pubkey); accepts z-base-32 OR OpenSSH format | `pkarr::PublicKey::try_from(&str)` for z32; OpenSSH format requires parser (see §Code Examples) |
| SEND-03 | `--ttl <duration>` overrides default 24h; stored as inner-signed `created_at + ttl_seconds`, not DHT packet TTL | `OuterRecordSignable.ttl_seconds` field already present; default constant needed in `src/flow.rs` |
| SEND-04 | Every record dual-signed: outer PKARR SignedPacket sig + inner Ed25519 over JCS `OuterRecordSignable` | Both signatures handled by Phase 1 code — `DhtTransport::publish` + `record::sign_record`. No new work |
| SEND-05 | Outer SignedPacket stays under PKARR/BEP44 ~1000-byte budget; build-time test for representative payload | `tests/signed_packet_budget.rs` ships (Phase 1; uses 550-byte blob baseline). Extend with Envelope round-trip for Phase 2 |
| RECV-01 | `receive <share-uri>` resolves, verifies outer PKARR sig, fetches + deserializes, verifies inner Ed25519; any failure → exit 3, unified error | Phase 1's `record::verify_record` + `DhtTransport::resolve` handle this. D-RECV-01 locks order |
| RECV-02 | TTL enforced against inner signed `created_at + ttl_seconds`; expired → exit 2 | `Error::Expired` ready (Phase 1 error.rs:40); TTL comparison in flow |
| RECV-03 | After sig+TTL pass, age-decrypt into `Zeroizing`, verify envelope inner sig; inner-sig failure → exit 3 | Note: D-WIRE-01 makes inner-sig the OUTER record's sig over ciphertext — **there is no separate envelope signature**. RECV-03's "envelope inner signature" = re-verify the OuterRecord's sig integrity AFTER decrypt (caught by JCS re-canonicalize in `verify_record`) OR treat JCS envelope parse failure as `SignatureCanonicalMismatch` per D-RECV-01 step 7 |
| RECV-04 | Acceptance prompt displays purpose (ctrl-stripped), OpenSSH fingerprint, z-base-32, TTL local+UTC, type, size; full-word confirmation required; decline → exit 7 | D-ACCEPT-01/02/03 lock the exact UX. Uses `chrono` (new dep) for local+UTC formatting |
| RECV-05 | On acceptance, decrypted payload to `--output <path>` or `-`; default stdout | `cli.rs` already has `output: Option<String>` field |
| RECV-06 | Second `receive` reports prior acceptance timestamp; does NOT re-decrypt or re-publish receipt | D-STATE-01 sentinel file + D-RECV-02 step-1 check |
| CLI-01 | All `send`/`receive` payload I/O supports `-` for stdin/stdout; status to stderr | CLI fields ready; flow must implement `-` handling |
| CLI-02 | Exit codes: 0/2/3/4/5/6/7/1 | `error::exit_code` already wired for all existing variants; new D-ERR-01 variants map to 1 |
| CLI-03 | All `--help` prints ≥1 worked example (EXAMPLES section) | Already present in `src/cli.rs` (`long_about` with EXAMPLES for Send/Receive/Receipts/Version/Identity). Verification test in Phase 2 plan |
| CLI-04 | `cipherpost version` prints crate version, git commit hash, one-line crypto primitives list | Already implemented in `src/main.rs`; build.rs emits CIPHERPOST_GIT_SHA. Verified in Phase 1 (git sha: `d8fb2028d2f2` observed in VERIFICATION.md) |
| CLI-05 | Error messages never include passphrase bytes, key bytes, or raw payload bytes; fuzz bad inputs + scan stderr for secret markers | Phase 1's `debug_leak_scan.rs` test exists; extend in Phase 2 with CLI-driven fuzzing of corrupt URIs, wrong passphrases, expired/tampered shares |
</phase_requirements>

## Summary

Phase 2 consumes a solid Phase 1 foundation — every primitive needed (Ed25519↔X25519, age wrappers, JCS, share_ref, OuterRecord, Transport trait, MockTransport, `resolve_passphrase`, `exit_code`) is ready and verified (23/23 Phase 1 tests green). The phase adds **exactly two new modules** (`src/payload.rs` and `src/flow.rs` — both currently empty stubs), **three new Error variants** (D-ERR-01), **three new HKDF info constants** (enumerated in `crypto::hkdf_infos` — enforced by Phase 1's `tests/hkdf_info_enumeration.rs`), and **one new test-only dependency** (`chrono` for RECV-04's local+UTC time formatting; alternatives in §Standard Stack).

Phase 2's orchestration lives entirely in `src/flow.rs`. The `Cli` tree in `src/cli.rs` is locked and final — `main.rs::dispatch` simply replaces the three `"not implemented yet (phase 2)"` stub arms for `Send`, `Receive`, and (later) `Receipts`. There is no new clap wiring. There is no new transport code — `DhtTransport::publish` and `DhtTransport::resolve` already carry data through; Phase 2 only composes them with the new `Envelope`/`Material` layer.

The four **load-bearing risks** in Phase 2 are (1) the **verify-before-decrypt-before-accept order** (D-RECV-01), which is an adversarial-correctness requirement not a taste choice — the fuzz/tamper integration tests check this, (2) **wire-budget accounting** — the real PKARR limit is ~550 bytes of age ciphertext (not 64 KB), so the `WireBudgetExceeded` error path must surface before the user is surprised, (3) **age-layer recipient derivation for share mode** — must use `ed25519_to_x25519_public` on the target pubkey (NOT the sender's own key), and (4) **state-file atomicity** — sentinel-first then ledger-append is recoverable; the reverse is not.

**Primary recommendation:** Split into 3 plans, 3 waves:
- **Wave 1 (P01):** `src/payload.rs` (Envelope + Material + size cap + purpose strip + JCS round-trip) AND URI parser/formatter (share URI format in a new small `src/uri.rs` module OR folded into `lib.rs` constants) — these are fully parallelizable with each other. Could be one plan if planner prefers single-wave minimalism.
- **Wave 2 (P02):** `src/flow.rs` run_send + run_receive + acceptance screen + state ledger/sentinel — depends on payload module.
- **Wave 3 (P03):** `src/main.rs::dispatch` wiring + integration tests (self round trip, share round trip, wrong-recipient, tamper, expired, declined, idempotent re-receive, size-cap, stderr secret-scan, CLI-03 examples presence).

Planner may also choose a 2-plan split (Wave 1 payload + wire-budget + URI + err variants; Wave 2 flow + dispatch + tests) — research supports both. The 3-plan split maximizes parallelism but adds a coordination seam between flow logic and test authoring.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Payload schema definition (Envelope / Material / JCS encode-decode) | `payload` module (NEW) | `crypto::jcs_serialize` | Pure data + serde; no I/O. Must not know transport details. |
| Share URI parsing/formatting (`cipherpost://<z32>/<hex>`) | `uri` module or `lib.rs` constants | `error.rs` for `InvalidShareUri` | Single-purpose parser; lives next to other wire constants. |
| Send orchestration (load identity → strip purpose → build envelope → JCS → size cap → age-encrypt → wire-budget check → build OuterRecord → sign → publish → emit URI) | `flow` module (NEW) | `payload`, `crypto`, `record`, `transport`, `identity` | Ties primitives together; owns policy (TTL default, size caps). |
| Receive orchestration (sentinel check → URI parse → resolve → verify → URI/share_ref match → TTL check → decrypt → parse envelope → acceptance screen → typed confirm → write material → append ledger + sentinel) | `flow` module (NEW) | same + `dialoguer` + `std::io::IsTerminal` | All 11 ordered steps of D-RECV-01 must live in one function so the order is reviewable. |
| Acceptance UX (bordered screen, TTY check, typed z32 confirmation) | `flow` module (NEW) | `identity::show_fingerprints` | Rendered to stderr; reads from stdin. No clap involvement — `cli.rs` only parses flags. |
| Local state (ledger append + sentinel create) | `flow` module (helper submodule OK) | `identity::key_dir` pattern (use `state_dir()`) | File system I/O behind a small API; same ownership as flow since flow is the sole writer. |
| Size enforcement (plaintext 64 KB pre-encrypt; wire ~1000 bytes post-encrypt) | `flow` (plaintext) + `transport` (wire, already in MockTransport) | `error.rs` variants | Two distinct error paths. Plaintext cap caught in flow::run_send BEFORE crypto. Wire budget caught AFTER SignedPacket build, BEFORE publish. |
| TTL check (inner signed `created_at + ttl_seconds > now`) | `flow` module (NEW) | `std::time::SystemTime` | Client-side only; DHT doesn't enforce. |
| `cipherpost version` (already complete) | `main.rs::dispatch` | `build.rs` (CIPHERPOST_GIT_SHA) | Phase 1 completed. Phase 2 verifies git sha renders as non-`"unknown"`. |
| Integration tests (round-trip, tamper, expire, decline, size-cap, CLI-03 examples scan, CLI-05 secret-in-stderr scan) | `tests/*.rs` | `MockTransport`, `assert_cmd`, `predicates`, `tempfile`, `serial_test` | Use `MockTransport` via `--features mock` as Phase 1 established. Fuzz tests hand-authored (minimum viable); full proptest is deferred. |

## Standard Stack

### Core — already pinned (Phase 1, unchanged)
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `age` | 0.11.2 | X25519 encrypt/decrypt with dual-identity recipients | `[VERIFIED: Cargo.lock]` Phase 1 pinned `age = "0.11"`; cclink-validated |
| `pkarr` | 5.0.4 | PKARR SignedPacket publish/resolve; Keypair/PublicKey types | `[VERIFIED: Cargo.lock]` Phase 1 pinned `"5.0.3"`; Cargo resolves to 5.0.4. Critical: `pkarr::PublicKey::try_from(&str)` accepts z32 strings |
| `ed25519-dalek` | `=3.0.0-pre.5` | Inner signing/verifying (via `pkarr::Keypair::sign`) | `[VERIFIED: Cargo.lock]` Hard pin — pkarr 5 requires pre-release 3.x; no stable 3.x exists yet |
| `serde_canonical_json` | 1.0.0 | RFC 8785 JCS canonicalization | `[VERIFIED: Cargo.lock]` Phase 1 uses `CanonicalFormatter` in `record.rs` and `crypto.rs::jcs_serialize` |
| `base64` | 0.22.1 | Base64 for blob, signatures, GenericSecret.bytes | `[VERIFIED: Cargo.lock]` `STANDARD` engine matches Phase 1's choice |
| `dialoguer` | 0.12.0 | Interactive prompt (`Input::interact_text` for z32 confirmation) | `[VERIFIED: Cargo.lock]` Already used for passphrase in `identity::resolve_passphrase` |
| `zeroize` | 1.8.2 (with `zeroize_derive`) | `Zeroizing<Vec<u8>>` for decrypted payload buffers | `[VERIFIED: Cargo.lock]` Phase 1 used extensively |
| `secrecy` | 0.10.3 | `SecretBox<String>` for passphrases (pass-through to Phase 1) | `[VERIFIED: Cargo.lock]` |
| `sha2` | 0.10.9 | SHA-256 for share_ref, ciphertext_hash, cleartext_hash | `[VERIFIED: Cargo.lock]` Phase 1 used in `record.rs` |
| `serde_json` | 1.0.149 | JCS path + ledger JSONL encoding | `[VERIFIED: Cargo.lock]` Phase 1 used extensively — do NOT enable `preserve_order` |
| `clap` | 4.6.1 (`derive` feature) | Already final (Phase 1 D-11) | `[VERIFIED: Cargo.lock]` |
| `thiserror` | 2.0.18 | Extending `Error` enum with 3 new variants | `[VERIFIED: Cargo.lock]` |
| `anyhow` | 1.0.102 | `src/main.rs` dispatcher | `[VERIFIED: Cargo.lock]` |

### Supporting — new for Phase 2
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `chrono` | 0.4.x | **RECV-04 TTL local+UTC formatting** | For the acceptance-screen TTL row: `<Xh Ym> remaining (expires <UTC ISO> / <local>)`. `[CITED: docs.rs/chrono]` `chrono::DateTime<Utc>::from_timestamp(seconds, 0)` + `.format("%Y-%m-%d %H:%M UTC")` + `chrono::Local::from_utc_datetime()`. Alternative: `time` crate (smaller, more idiomatic). **Planner's call; recommend `chrono` for speed since it's the more common choice and the UX is one format-string line.** See "Alternatives Considered" below. |

### Supporting — TEST-ONLY, planner discretion (no prod impact)
| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `humantime` | 2.x | Parse `--ttl 24h` / `2d` / `3600s` human strings | Claude's Discretion per CONTEXT.md. If planner picks humanized `--ttl`, use `humantime::parse_duration`. If seconds-only, no dep needed. `[CITED: docs.rs/humantime]` |

### Alternatives Considered
| Instead of | Could Use | Tradeoff |
|------------|-----------|----------|
| `chrono` | `time` crate | `time` is smaller (no timezone database unless feature-enabled), more idiomatic for new Rust code in 2026, and has simpler API for the one-line use case. `time::OffsetDateTime::from_unix_timestamp(seconds)?.to_offset(time::UtcOffset::local_offset_at(...)?)`. Downside: local-offset detection on Linux is gated behind the `local-offset` feature and has thread-safety caveats. `[CITED: time-rs.github.io]` For skeleton, either works — `chrono` is quicker to get right. |
| `chrono` | Hand-roll TTL formatting | Zero deps. Compute `seconds_remaining = ttl_seconds - (now - created_at)`; render hours/minutes trivially. UTC: `std::time::SystemTime::UNIX_EPOCH + Duration::from_secs(expires_at)` then... no ergonomic local-time path in std. Local time requires platform-specific `libc::localtime_r` — not recommended. **Conclusion: use a crate.** |
| `url` crate for share URI parsing | Hand-rolled `str::strip_prefix` + `split_once('/')` | `url` crate is overkill for the fixed-shape `cipherpost://<z32>/<hex>` scheme. Hand-rolled parser is 20 lines, no new dep, and aligns with D-URI-03's strict-form rule. **Recommendation: hand-roll.** |
| `humantime` | Seconds-only `--ttl <N>` | Seconds-only is simpler and less ambiguous. Humanized is user-friendlier. No strong preference; planner's call. |
| `fs2` file locking for state dir | Read sentinel-check at step 1 + write sentinel atomically at step 11 | File locking prevents a parallel `receive` from double-accepting the same share_ref. BUT: two simultaneous receives of the same URI on the same host is a pathological case that doesn't match the threat model (single user, interactive). Sentinel-file atomic-create (`OpenOptions::new().create_new(true)`) is sufficient — if it fails because another process beat us to it, treat as already-accepted. **Recommendation: use `create_new(true)` for TOCTOU safety without adding `fs2`.** |

**Installation (if planner picks chrono):**

```toml
[dependencies]
# ... existing deps
chrono = { version = "0.4", default-features = false, features = ["clock", "std"] }
```

**Version verification:** `npm view` N/A for Rust; verified via `cargo tree`:
- `cargo tree --prefix none --depth 1` confirms all existing deps on 2026-04-21.
- `chrono 0.4` latest stable: verify via `cargo search chrono --limit 1` before adding. `[ASSUMED]`

## Architecture Patterns

### System Architecture Diagram

```
                         ┌─────────────────────────┐
                         │  cli.rs (clap tree)     │  [Phase 1 — FINAL]
                         │  Send/Receive/Version   │
                         └───────────┬─────────────┘
                                     │ match arm
                                     ▼
                         ┌─────────────────────────┐
                         │ main.rs::dispatch       │  [Phase 2 — replaces stub arms]
                         │ resolve_passphrase()    │
                         └───────────┬─────────────┘
                                     │ Result<(), anyhow>
                                     ▼
         ┌──────────────────────────────────────────────────┐
         │            flow.rs  [NEW in Phase 2]              │
         │ ┌──────────────┐       ┌──────────────────┐       │
         │ │ run_send     │       │ run_receive      │       │
         │ │              │       │                  │       │
         │ │ 1. load id   │       │ 1. check sentinel│───────┼──► state/accepted/<ref>
         │ │ 2. read pay  │       │ 2. parse URI     │       │
         │ │ 3. strip prp │       │ 3. resolve DHT   │       │
         │ │ 4. Envelope  │       │ 4. verify sig    │       │
         │ │ 5. size cap  │       │ 5. URI ref match │       │
         │ │ 6. JCS       │       │ 6. TTL check     │       │
         │ │ 7. age_enc   │       │ 7. age_decrypt   │       │
         │ │ 8. share_ref │       │ 8. JCS decode    │       │
         │ │ 9. OuterRec  │       │ 9. accept screen │       │
         │ │10. sign      │       │10. typed confirm │       │
         │ │11. budget ck │       │11. write output  │       │
         │ │12. publish   │       │12. ledger+sent   │       │
         │ │13. print URI │       │                  │       │
         │ └──────┬───────┘       └──────┬───────────┘       │
         └────────┼─────────────────────┼──────────────────┘
                  │                     │
    ┌─────────────┴─────────┐  ┌───────┴──────────────┐
    │ payload.rs [NEW]      │  │                      │
    │ - Envelope struct     │  │ record.rs [Phase 1]  │
    │ - Material enum       │  │ - OuterRecord        │
    │ - Envelope::encode/   │  │ - OuterRecordSignable│
    │   decode via JCS      │  │ - sign_record        │
    │ - Material serde tag  │  │ - verify_record      │
    │ - strip_control_chars │  │ - share_ref_from_    │
    │ - size_cap enforce    │  │   bytes              │
    └───────────┬───────────┘  └──────┬───────────────┘
                │                     │
                └──────────┬──────────┘
                           │
             ┌─────────────┴───────────────┐
             │                             │
             ▼                             ▼
    ┌────────────────┐            ┌──────────────────┐
    │ crypto.rs      │            │ transport.rs     │
    │ [Phase 1]      │            │ [Phase 1]        │
    │ - age_encrypt  │            │ - Transport trait│
    │ - age_decrypt  │            │ - DhtTransport   │
    │ - jcs_serialize│            │ - MockTransport  │
    │ - ed25519↔x25519            │ - publish/resolve│
    │ - hkdf_infos   │            └────┬─────────────┘
    │   (+3 new)     │                 │
    └────────────────┘                 ▼
                                 Mainline DHT via
                                  pkarr::ClientBlocking
```

**Flow for `cipherpost send --share <z32-pubkey>`:**
1. `main::dispatch` calls `identity::resolve_passphrase` → `identity::load`
2. `flow::run_send(mode: SendMode::Share(z32), purpose, material_source, ttl)`
3. Read material: `-` → stdin; `<path>` → file; both into `Zeroizing<Vec<u8>>`
4. Check plaintext.len() ≤ 64 KB → `Error::PayloadTooLarge` (exit 1)
5. Strip control chars from purpose (C0 + DEL + C1)
6. Build `Envelope { purpose, material: Material::GenericSecret { bytes }, created_at: now, protocol_version: 1 }`
7. Serialize envelope via `crypto::jcs_serialize(&envelope)` → `Vec<u8>` plaintext_bytes
8. Derive recipient X25519: `ed25519_to_x25519_public(pkarr::PublicKey::try_from(z32)?.to_bytes())`
9. `crypto::recipient_from_x25519_bytes(&recipient_x25519)` → `age::x25519::Recipient`
10. `crypto::age_encrypt(&plaintext_bytes, &recipient)` → ciphertext
11. `share_ref = record::share_ref_from_bytes(&ciphertext, created_at)`
12. Construct `OuterRecordSignable { blob: base64(ciphertext), created_at, protocol_version: 1, pubkey: identity.z32_pubkey(), recipient: Some(z32), share_ref, ttl_seconds }`
13. `record::sign_record(&signable, identity.keypair)` → base64 sig
14. Assemble `OuterRecord { ...signable fields..., signature }`
15. **Wire-budget check:** Build the `SignedPacket` explicitly (same code as `tests/signed_packet_budget.rs`), assert `packet.encoded_packet().len() ≤ 1000`; if not, `Error::WireBudgetExceeded { encoded, budget: 1000, plaintext: plaintext_bytes.len() }` (exit 1)
16. `transport.publish(&keypair, &record)` — `DhtTransport::publish` does the actual SignedPacket build-sign-publish; the Phase 2 pre-check in step 15 is defensive
17. Emit share URI: `println!("cipherpost://{}/{}", identity.z32_pubkey(), share_ref)`

**Flow for `cipherpost receive <share-uri>`:**
1. Parse URI strictly per D-URI-03 → `(sender_z32, url_share_ref)`
2. **Sentinel check** at `~/.cipherpost/state/accepted/<url_share_ref>` — if present, print prior timestamp from ledger and exit 0 (no network). Found via grep ledger or store prior info in sentinel (planner's call; cheapest is scan ledger)
3. Resolve identity passphrase → load identity
4. `transport.resolve(&sender_z32)` — does outer PKARR sig + inner Ed25519 verify internally. Returns `OuterRecord` or `Error::NotFound` (5) / `Error::Network` (6) / `Error::SignatureInner` (3)
5. Check `record.share_ref == url_share_ref` → if not, `Error::ShareRefMismatch` (exit 1)
6. TTL check: `now >= record.created_at + record.ttl_seconds` → `Error::Expired` (exit 2)
7. Derive own X25519 identity: `ed25519_to_x25519_secret(identity.secret_key_bytes())` → `crypto::identity_from_x25519_bytes`
8. Base64-decode `record.blob` → ciphertext
9. `crypto::age_decrypt(&ciphertext, &age_identity)` → `Zeroizing<Vec<u8>>` (wrong recipient = `DecryptFailed` exit 4)
10. JCS-decode into `Envelope` — failure → `Error::SignatureCanonicalMismatch` (exit 3)
11. **TTY check:** `std::io::stderr().is_terminal() && std::io::stdin().is_terminal()` — else `Error::Config("acceptance requires a TTY; ...")` (exit 1)
12. Render acceptance screen to stderr (§Code Examples)
13. Read confirmation: `dialoguer::Input::<String>::new().interact_text()?` → compare byte-equal to `record.pubkey` after `trim()`. Mismatch → `Error::Declined` (exit 7)
14. Write `Material::GenericSecret.bytes` to `-o <path>` or stdout
15. Compute `ciphertext_hash = sha256(ciphertext)` and `cleartext_hash = sha256(envelope_jcs_bytes)`
16. Create sentinel file at `accepted/<share_ref>` using `OpenOptions::new().create_new(true).mode(0o600)` — if `AlreadyExists`, treat as benign (RECV-06 race)
17. Append to `accepted.jsonl` with `OpenOptions::new().append(true).create(true).mode(0o600)`

### Recommended Project Structure (post-Phase 2)
```
src/
├── lib.rs                  # pub mod re-exports (+ SHARE_URI_SCHEME const)
├── main.rs                 # replaces 2 stub arms
├── cli.rs                  # UNCHANGED (Phase 1 final)
├── crypto.rs               # +3 hkdf_infos constants
├── error.rs                # +3 variants (ShareRefMismatch, WireBudgetExceeded, InvalidShareUri)
├── identity.rs             # UNCHANGED
├── record.rs               # UNCHANGED
├── transport.rs            # UNCHANGED
├── payload.rs              # NEW BODY — replaces stub
├── uri.rs                  # NEW (or fold into payload.rs — planner's call)
├── flow.rs                 # NEW BODY — replaces stub
└── receipt.rs              # UNCHANGED (Phase 3)

tests/
├── (all existing Phase 1 tests)
├── phase2_self_round_trip.rs           # NEW — SC1
├── phase2_share_round_trip.rs          # NEW — SC1 (A→B decrypt, C cannot)
├── phase2_tamper_aborts_before_decrypt.rs  # NEW — SC2
├── phase2_expired_share.rs             # NEW — SC2
├── phase2_acceptance_screen.rs         # NEW — SC3 (spawn binary; scripted TTY? see open questions)
├── phase2_declined.rs                  # NEW — SC3
├── phase2_idempotent_re_receive.rs     # NEW — SC3 (RECV-06)
├── phase2_size_cap.rs                  # NEW — SC4 (65537-byte rejection)
├── phase2_envelope_round_trip.rs       # NEW — SC4 (JCS bit-identical round trip)
├── phase2_material_variants_unimplemented.rs  # NEW — SC4
├── phase2_cli_help_examples.rs         # NEW — SC5 (grep `cipherpost ... --help` for EXAMPLES)
├── phase2_stderr_no_secrets.rs         # NEW — SC5 (CLI-05 fuzz-scan)
└── fixtures/
    └── envelope_jcs_generic_secret.bin # NEW — committed cross-impl fixture
```

### Pattern 1: JCS serialization via Phase 1's `crypto::jcs_serialize`
**What:** All new signable/encryptable structs go through the single `crypto::jcs_serialize` path — not `serde_json::to_vec`. Inline alphabetical field declaration as belt-and-suspenders (matches `record.rs`).
**When to use:** `Envelope` serialization before age-encrypt.
**Example:**
```rust
// Source: src/record.rs Phase 1 pattern
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub created_at: i64,              // a
    pub material: Material,           // m
    pub protocol_version: u16,        // p
    pub purpose: String,              // p (after m)
}
// Note: JCS sorts by Unicode code point regardless; declaration order is defensive.
```

### Pattern 2: Material enum with serde tag
**What:** External tagging: `#[serde(tag = "type", rename_all = "snake_case")]`. Wire shape: `{"type":"generic_secret","bytes":"<b64>"}`.
**When to use:** All cryptographic material envelopes, present and future.
**Example:**
```rust
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Material {
    GenericSecret {
        #[serde(with = "base64_std")]  // Vec<u8> ↔ base64-std string
        bytes: Vec<u8>,
    },
    X509Cert,    // variants exist but error on encode/decode in skeleton
    PgpKey,
    SshKey,
}
```

### Pattern 3: HKDF constants extension (mandatory)
**What:** Phase 1's `tests/hkdf_info_enumeration.rs` grep-asserts every `cipherpost/v1/` literal in `src/` is a constant in `crypto::hkdf_infos`. Phase 2 MUST add new constants there (even if not yet used) to document the protocol namespace.
**When to use:** Any new HKDF call site. For Phase 2, no direct HKDF calls may be needed (age handles its own key derivation internally), but if one is introduced, it MUST go through a named constant.
**Example:**
```rust
// In src/crypto.rs
pub mod hkdf_infos {
    pub const IDENTITY_KEK: &str = "cipherpost/v1/identity-kek";
    // Phase 2 reserves these namespaces even if not yet used (Pitfall #4 domain separation):
    pub const SHARE_SENDER: &str = "cipherpost/v1/share-sender";
    pub const SHARE_RECIPIENT: &str = "cipherpost/v1/share-recipient";
    pub const INNER_PAYLOAD: &str = "cipherpost/v1/inner-payload";
    // Phase 3 adds: RECEIPT_SIGN
}
```
**Note:** If Phase 2 does not actually call HKDF (because age handles key derivation inside the age file format), the reserved constants are documentation-only. The enumeration test filters `cap.len() > prefix.len()` so no `#[allow(dead_code)]` is needed.

### Pattern 4: Extending `Error` enum (thiserror)
**What:** Add variants with `#[error("...")]`; update `exit_code()` match; keep `Debug` + `Error::user_message` identical to Display.
**When to use:** Every new failure mode.
**Example:**
```rust
#[error("share_ref in URI does not match resolved record")]
ShareRefMismatch,
#[error("share too large for PKARR packet: encoded={encoded} bytes, budget={budget} bytes (plaintext was {plaintext} bytes)")]
WireBudgetExceeded { encoded: usize, budget: usize, plaintext: usize },
#[error("invalid share URI: {0}")]
InvalidShareUri(String),
```
And in `exit_code`:
```rust
// All three map to exit 1 (generic) per D-ERR-01; they are NOT signature failures
Error::ShareRefMismatch
| Error::WireBudgetExceeded { .. }
| Error::InvalidShareUri(_) => 1,
```
**Note:** Phase 1's catch-all `_ => 1` already covers these, but the explicit arm makes intent auditable.

### Pattern 5: TTY check via `std::io::IsTerminal` (Rust 1.70+)
**What:** `std::io::IsTerminal` trait, stable since Rust 1.70. Crate ships on `rust-version = "1.85"` (verified in Phase 1 Cargo.toml). **No `atty` crate needed.**
**When to use:** D-ACCEPT-03 TTY gate (stdin + stderr).
**Example:**
```rust
use std::io::IsTerminal;

fn assert_tty_interactive() -> Result<(), Error> {
    if !std::io::stderr().is_terminal() || !std::io::stdin().is_terminal() {
        return Err(Error::Config(
            "acceptance requires a TTY; non-interactive receive is deferred".into(),
        ));
    }
    Ok(())
}
```
`[VERIFIED: std::io::IsTerminal stable since Rust 1.70 (2023-06); crate MSRV 1.85]`

### Pattern 6: Reading payload from `-` stdin OR file
**What:** Match Phase 1 identity passphrase-fd pattern, but simpler because payload reading doesn't need TTY gating.
**When to use:** SEND-01 (`--material-file <path>` or `-`) and RECV-05 (`-o <path>` or `-`).
**Example:**
```rust
fn read_material(source: Option<&str>) -> Result<Zeroizing<Vec<u8>>, Error> {
    use std::io::Read;
    let bytes = match source {
        None => return Err(Error::Config("--material-file <path> or - required".into())),
        Some("-") => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).map_err(Error::Io)?;
            buf
        }
        Some(path) => std::fs::read(path).map_err(Error::Io)?,
    };
    Ok(Zeroizing::new(bytes))
}
```

### Anti-Patterns to Avoid

- **Printing purpose before signature verify.** Any `eprintln!` or `println!` of `envelope.purpose` before D-RECV-01 step 8 is a Pitfall #2 violation. Tests must fail if this appears. **Concrete test: spawn binary with a tampered-signature URI, grep stderr+stdout for the purpose string — must be absent.**
- **Using `serde_json::to_vec` on Envelope.** JCS goes through `crypto::jcs_serialize` which uses `serde_canonical_json::CanonicalFormatter`. Bare `serde_json` breaks canonicalization silently (Pitfall #3).
- **Inlining `"cipherpost/v1/..."` strings in new code.** Must be a constant in `crypto::hkdf_infos` (Pitfall #4).
- **`#[derive(Debug)]` on `Envelope` or `Material::GenericSecret`.** `GenericSecret.bytes` is pre-encryption plaintext — derive-Debug leaks it. Manual redacted impl required; scan test (Phase 1's `debug_leak_scan.rs` pattern) must be extended. *(Open question: is Envelope's purpose secret? Not cryptographically, but it's also not meant to be printed before verify. Err on safer side.)*
- **Accepting the share when stdin is not a TTY but `CIPHERPOST_PASSPHRASE` env is set.** D-ACCEPT-03 is orthogonal to passphrase source — TTY requirement is for the z32 confirmation input, which is always on stdin. Env-var passphrase + TTY stdin is fine; env-var passphrase + piped stdin is NOT (still abort, same as no passphrase source).
- **Using outer pkarr-level packet TTL.** PKARR records can be served past their DNS TTL. The TTL is the inner signed `created_at + ttl_seconds` (Pitfall #11). Phase 1's `OuterRecordSignable.ttl_seconds` is correct.
- **Writing the ledger line before the sentinel file.** On crash between the two, a ledger line without a sentinel reads as "accepted but sentinel missing" — next receive would not short-circuit. Safer order: **sentinel first (via `create_new(true)`) → write material → ledger append**. If the ledger append fails, the sentinel still exists and re-receive will short-circuit; the cost is the ledger row is absent but the material was delivered. Planner's final call; this is the recommended order.
- **Passing `&dyn Transport` generics mismatch.** `flow::run_send` and `run_receive` should take `&dyn Transport` so tests can inject `MockTransport`. Concrete `DhtTransport` is constructed in `main::dispatch`. *(This is Anti-Pattern 2 from ARCHITECTURE.md.)*

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Canonical JSON serialization | Custom alphabetical-sort + whitespace-stripper | `crypto::jcs_serialize` (Phase 1) using `serde_canonical_json::CanonicalFormatter` | Pitfall #3 — RFC 8785 has precise rules for Unicode, numbers; hand-rolled wrong breaks interop and signatures |
| Base64 codec for GenericSecret.bytes | Hand-rolled base64 | `base64::engine::general_purpose::STANDARD` | Already used in Phase 1; std-padded matches D-WIRE-04 |
| Control-char stripping | Regex or complex Unicode-aware filter | Simple `.chars().filter(\|c\| !c.is_control()).collect()` | `char::is_control()` matches Unicode "Cc" category, which is exactly C0 + C1 + DEL (verified [CITED: doc.rust-lang.org/std/primitive.char.html#method.is_control]: "C0 or C1 control codes"). Zero new deps. |
| Atomic file creation | Open + write + flush + rename | `OpenOptions::new().create_new(true).mode(0o600)` | Create-exclusive via O_EXCL. On failure (file exists), errno is `AlreadyExists` — directly usable for RECV-06 sentinel race. Phase 1 uses this pattern in `identity::generate`. |
| PKARR SignedPacket size calculation | Manual bytes.len() check on JSON | Build the `SignedPacket` via `pkarr::SignedPacket::builder().txt(...).sign(&kp)?.encoded_packet().len()` | Matches what PKARR enforces internally. Phase 1's `tests/signed_packet_budget.rs` shows the pattern. |
| URI parser | `url::Url` crate | Hand-rolled `str::strip_prefix("cipherpost://")` + `split_once('/')` + length check | Fixed-shape scheme; 20-line parser; no new dep. D-URI-03 requires strict form — `url::Url` would be permissive and ambiguous (`cipherpost://a/b?c=d` is a valid URL; we reject trailing components). |
| Ed25519→X25519 conversion | Any bespoke math | `crypto::ed25519_to_x25519_public` / `_secret` (Phase 1) | Pitfall #1 — use libsodium-semantics wrappers |
| TTL remaining display | Manual hours-minutes math | `chrono::Duration` + `humantime::format_duration` for "Xh Ym" | Minor — manual math is fine for `(X h)(Y m)` format. If planner picks humanized-TTL `--ttl 24h`, using `humantime` both sides is consistent. |
| TTY detection | `atty` crate | `std::io::IsTerminal` trait (Rust 1.70+) | Stable in std; `atty` is deprecated. MSRV 1.85 covers this. |
| SHA-256 hashing (ciphertext_hash / cleartext_hash) | Reimplementing SHA-256 | `sha2::Sha256::new().chain_update(...).finalize()` | Already in tree (Phase 1 `record.rs` uses it). |

**Key insight:** Phase 2 is orchestration + schema. Nothing in this phase requires new cryptographic primitives. Every "hard problem" has a Phase 1 primitive or a std-lib/existing-dep answer. **Pressure planners to compose, not invent.**

## Runtime State Inventory

**Not applicable.** Phase 2 is not a rename/refactor/migration phase — it is a greenfield feature phase that adds capability on top of Phase 1's foundation. No grep audit required; no existing runtime state to migrate. All new state (state directory, sentinel files, JSONL ledger) is created fresh at `~/.cipherpost/state/` during Phase 2 execution; no Phase 1 or earlier artifacts carry data that needs renaming or migration.

*Explicit "nothing found" per rubric:*

| Category | Status |
|----------|--------|
| Stored data | None — greenfield feature; no pre-existing stored keys or collections |
| Live service config | None — no services registered at Phase 1 |
| OS-registered state | None — no Task Scheduler, launchd, systemd units involved |
| Secrets/env vars | `CIPHERPOST_PASSPHRASE` + `CIPHERPOST_HOME` (both Phase 1) — **unchanged** by Phase 2; name preserved |
| Build artifacts | None — `cipherpost` binary built by Phase 1 is uncontaminated (no rename) |

## Common Pitfalls

### Pitfall 1 (from research PITFALLS.md #2): Dual-signature verify order
**What goes wrong:** Verifying the outer PKARR sig, decrypting the age blob, then verifying the inner Ed25519 sig (or inferring the inner sig from a canonical-JSON re-serialize) means an attacker who forges an outer packet can feed arbitrary ciphertext into `age::Decryptor::new`. Any parser bug or side-channel in age becomes reachable pre-authentication.
**Why it happens:** Sign-then-encrypt semantics mean the inner sig is over cleartext, so inner verify must come AFTER decrypt. The natural code shape reveals purpose/material to the user before the final check.
**How to avoid:** Strict D-RECV-01 order. **Critical:** no payload field — including `purpose` — is written to stdout OR stderr between step 2 (resolve) and step 8 (acceptance screen). The outer PKARR sig is checked inside `DhtTransport::resolve` (pkarr does this). The inner Ed25519 sig is checked by `record::verify_record`, called inside `resolve` BEFORE returning the `OuterRecord` (verified in Phase 1's `mock_transport_roundtrip.rs`). After decrypt, the JCS-parse failure is the "envelope inner sig failure" per D-WIRE-01 — there is no separate envelope-level signature, because the outer record's inner-sig already covers `blob` which is the age ciphertext of the envelope.
**Warning signs:** Any `eprintln!(envelope...)` before the acceptance screen rendering function is called. Any test that observes purpose in stderr for a tampered share.
**Prevention test:** `phase2_tamper_aborts_before_decrypt.rs` — tamper one byte in `OuterRecord.signature`, run `receive`, assert stderr contains no substring from the known purpose AND exit 3.

### Pitfall 2 (from research PITFALLS.md #6): Acceptance prompt weakness
**What goes wrong:** A short `Accept? [y/N]` prompt is MFA-fatigue-class vulnerable. An attacker who can get the victim to run `cipherpost receive <attacker-URI>` (phishing) gets a reflex Y.
**Why it happens:** CLI prompts default short. Purpose text looks like metadata. `dialoguer::Confirm` is the natural fit but defeats the security property.
**How to avoid:** D-ACCEPT-01's **typed z32 confirmation (52 chars)** is deliberately high-friction. There is NO default value and NO `--yes` flag. Declining (empty input, wrong string, trailing-whitespace-past-trim) returns `Error::Declined` (exit 7). Comparison is byte-equal to `OuterRecord.pubkey` after `trim()`.
**Warning signs:** `dialoguer::Confirm` in flow code. `--yes` or `--accept` flags added to `cli.rs`. Default-value `.default(false)` calls. Any path where empty input accepts.
**Prevention test:** `phase2_declined.rs` — pipe various inputs (empty, prefix of z32, z32-with-trailing-space, wrong-z32) and assert each returns exit 7 with NO material written to stdout.

### Pitfall 3 (from research PITFALLS.md #11): Stale PKARR packet replay
**What goes wrong:** DHT is content-addressed by pubkey; old SignedPackets with lower `seq` can be served by adversarial nodes. A `--burn` share that was supposed to be one-shot could be re-served. In cipherpost's default model (no `--burn`), the issue is that a share whose sender has since republished (with a new share_ref) could still be resolved via its old URI.
**Why it happens:** PKARR's BEP44 layer prefers higher seq, but adversary-controlled nodes can hold old packets. TTL at the DHT layer doesn't stop this.
**How to avoid:** **TTL is enforced on the inner signed `created_at + ttl_seconds`**, not on DHT packet freshness (already D-RECV-01 step 6). D-URI-02's `share_ref` match between URI and resolved record catches the "sender republished" case — URI share_ref from original send, but resolved record has a new share_ref → mismatch → `ShareRefMismatch` (exit 1). Both defenses work together.
**Warning signs:** TTL logic that uses packet arrival time or DNS TTL. URI design that doesn't include share_ref for binding.
**Prevention test:** `phase2_expired_share.rs` — publish a share with `created_at = now - 13h, ttl_seconds = 43200` (12h), run `receive`, assert exit 2 (`Error::Expired`) BEFORE decrypt. Use `MockTransport` with a clock override OR set created_at in the past.

### Pitfall 4: Wire-budget surprise
**What goes wrong:** PROJECT.md says 64 KB plaintext cap. PKARR limit is ~1000 bytes encoded packet. Phase 1 empirically measured the ceiling at **550 bytes of base64-encoded ciphertext** (`tests/signed_packet_budget.rs`). A user sending a 10 KB payload gets PROJECT.md's permission but PKARR's rejection.
**Why it happens:** Spec aspiration collides with transport reality. PKARR budget = 1000 bytes DNS packet after worst-case worst-case packing.
**How to avoid:** Two distinct error paths (D-PS-01). The plaintext check at step 4 of send catches the 64 KB overflow. The wire-budget check after SignedPacket build catches the ~1000-byte overflow. Both with distinct error text.
**Warning signs:** Only one size check. Error messages that conflate "too big for PKARR" with "too big period."
**Prevention test:** `phase2_size_cap.rs` — (a) 65537-byte plaintext rejected with error containing both `65537` and `65536`; (b) extend `signed_packet_budget.rs` with a `GenericSecret { bytes: [0u8; 600] }` Envelope + encrypt; assert the wire budget rejects it cleanly via `Error::WireBudgetExceeded`.

### Pitfall 5: Two curve25519-dalek versions in dep graph
**What goes wrong:** `age 0.11` uses `curve25519-dalek v4`; `pkarr 5.0.4` uses `curve25519-dalek v5`. These are DIFFERENT TYPES at Rust's type-system level. Any attempt to pass `MontgomeryPoint` (from pkarr) as a recipient to age (which takes v4 `MontgomeryPoint` internally) will fail compilation.
**Why it happens:** Cargo's semver allows multiple major versions coexisting in the graph. Neither age nor pkarr control their curve25519-dalek pin independently.
**How to avoid:** Everything at the Phase 2 boundary passes `[u8; 32]` raw bytes. `crypto::ed25519_to_x25519_public/secret` + `recipient_from_x25519_bytes` + `identity_from_x25519_bytes` abstract this (Phase 1 already does this correctly). Phase 2's flow code treats both age and pkarr keys as raw-byte arrays at the boundary. Preserve this discipline.
**Warning signs:** `use curve25519_dalek::...` in src/flow.rs or src/payload.rs. Any type annotation like `MontgomeryPoint` or `StaticSecret` in flow code.
**Prevention test:** Anti-pattern grep (like `chacha20poly1305_direct_usage_ban.rs`) can scan for `curve25519_dalek::` imports outside `src/crypto.rs`. Low-priority; the compiler already catches cross-version type mismatches.

### Pitfall 6: stdout secret exposure on TTY
**What goes wrong:** `cipherpost receive` without `-o <path>` writes material to stdout. On a TTY, secret bytes land in terminal scrollback, tmux buffer, terminal-emulator history. Defense-in-depth would refuse.
**Why it happens:** RECV-05 says default stdout; literal stdout on a TTY was unspecified.
**How to avoid (planner discretion):** Detect stdout-is-TTY; if user didn't explicitly pass `-o -`, print a stderr warning + refuse. Or: print warning + proceed. Or: ignore (simplest). Git and curl do "refuse binary to TTY" — our material bytes may not be binary but are secret. **Planner's call per CONTEXT.md.**
**Warning signs:** None — this is a permissive-by-default path.
**Prevention test (if implemented):** `phase2_stdout_tty_safety.rs` — run `receive` with stdout attached to a PTY (test infrastructure: `std::process::Command` + `portable-pty` crate), assert refusal. Complex to set up; **recommend deferring to v1.0 UX hardening**.

### Pitfall 7: Exit-code collision for new variants
**What goes wrong:** `error::exit_code` currently has `Error::Config(_)` and other cases fall through to `_ => 1`. The three new variants (`ShareRefMismatch`, `WireBudgetExceeded`, `InvalidShareUri`) should also map to 1, but if one accidentally overlaps with a Signature* variant (exit 3) or Expired (exit 2), the exit-code taxonomy semantics are wrong.
**Why it happens:** D-ERR-01 says exit 1 for all three. Phase 1's catch-all does this. But explicit is better.
**How to avoid:** Add an explicit match arm in `exit_code()`:
```rust
Error::ShareRefMismatch
| Error::WireBudgetExceeded { .. }
| Error::InvalidShareUri(_) => 1,
```
Even though `_ => 1` would cover it, explicit arm preserves reviewer intent.
**Warning signs:** Catch-all only.
**Prevention test:** Integration test per D-ERR-01 variant: construct the error, run through `exit_code()`, assert `== 1`. Can be unit-level in `error.rs`.

## Code Examples

Verified patterns based on Phase 1 code and age/pkarr 0.11/5.x API inspection:

### Example 1: Envelope struct + JCS serialization
```rust
// src/payload.rs — Phase 2
use crate::error::Error;
use crate::crypto::jcs_serialize;
use serde::{Deserialize, Serialize};

/// Source: D-WIRE-02; alphabetical field order mirrors src/record.rs::OuterRecordSignable.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub created_at: i64,
    pub material: Material,
    pub protocol_version: u16,
    pub purpose: String,
}

impl Envelope {
    pub fn to_jcs_bytes(&self) -> Result<Vec<u8>, Error> {
        jcs_serialize(self)
    }

    pub fn from_jcs_bytes(bytes: &[u8]) -> Result<Self, Error> {
        // Per D-RECV-01 step 7: parse failure maps to SignatureCanonicalMismatch
        serde_json::from_slice(bytes).map_err(|_| Error::SignatureCanonicalMismatch)
    }
}
```

### Example 2: Material enum with serde tag (external tagging)
```rust
// src/payload.rs — Phase 2, D-WIRE-03/04
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Material {
    GenericSecret {
        #[serde(with = "base64_std")]
        bytes: Vec<u8>,
    },
    X509Cert,
    PgpKey,
    SshKey,
}

mod base64_std {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&base64::engine::general_purpose::STANDARD.encode(v))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}
```
**Note on Debug:** `Material::GenericSecret { bytes }` derives Debug here, which would leak plaintext. Planner should follow Phase 1's pattern (manual redacted Debug on secret-holders; `tests/debug_leak_scan.rs` enforces). **Recommend:** manual Debug impl for `Material` that renders `GenericSecret` as `"[REDACTED N bytes]"`.

### Example 3: Control-char stripping (PAYL-04 / D-WIRE-05)
```rust
// src/payload.rs — Phase 2
/// Strip C0 (0x00..=0x1F), DEL (0x7F), and C1 (0x80..=0x9F) control characters.
/// `char::is_control` covers the Unicode "Cc" category which matches exactly.
/// Source: [CITED: doc.rust-lang.org/std/primitive.char.html#method.is_control]
pub fn strip_control_chars(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn strips_c0_del_c1() {
        assert_eq!(strip_control_chars("a\x00b\x1fc\x7fd\x80e\x9fz"), "abcdez");
    }
    #[test]
    fn preserves_non_control() {
        assert_eq!(strip_control_chars("Hello, 世界! émoji 🎉"), "Hello, 世界! émoji 🎉");
    }
}
```

### Example 4: Share URI parser (hand-rolled per §Don't Hand-Roll)
```rust
// src/uri.rs OR src/lib.rs — Phase 2, D-URI-01/02/03
use crate::error::Error;
use crate::record::SHARE_REF_HEX_LEN;

pub const SHARE_URI_SCHEME: &str = "cipherpost://";

pub struct ShareUri {
    pub sender_z32: String,
    pub share_ref_hex: String,
}

impl ShareUri {
    /// Parse a strict `cipherpost://<z32>/<32-hex>` URI. D-URI-03.
    pub fn parse(input: &str) -> Result<Self, Error> {
        let body = input
            .strip_prefix(SHARE_URI_SCHEME)
            .ok_or_else(|| Error::InvalidShareUri(
                "expected cipherpost:// URI, got bare pubkey; use the URI that `send` printed".into()
            ))?;
        let (z32, hex) = body.split_once('/').ok_or_else(|| Error::InvalidShareUri(
            "URI missing /<share_ref_hex> component".into()
        ))?;
        if z32.len() != 52 {
            return Err(Error::InvalidShareUri(format!(
                "sender z32 must be 52 chars, got {}", z32.len()
            )));
        }
        if hex.len() != SHARE_REF_HEX_LEN {
            return Err(Error::InvalidShareUri(format!(
                "share_ref_hex must be {} chars, got {}", SHARE_REF_HEX_LEN, hex.len()
            )));
        }
        if !hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            return Err(Error::InvalidShareUri(
                "share_ref_hex must be lowercase hex".into()
            ));
        }
        // Phase 2 strict rule: no trailing path/query/fragment components (D-URI-03).
        // Future extensions (v1.1+) may relax via planner decision.
        if hex.contains('?') || hex.contains('#') || hex.contains('/') {
            return Err(Error::InvalidShareUri(
                "unexpected trailing URI components".into()
            ));
        }
        Ok(ShareUri {
            sender_z32: z32.to_string(),
            share_ref_hex: hex.to_string(),
        })
    }

    pub fn format(sender_z32: &str, share_ref_hex: &str) -> String {
        format!("{}{}/{}", SHARE_URI_SCHEME, sender_z32, share_ref_hex)
    }
}
```

### Example 5: age encrypt to share recipient (SEND-02)
```rust
// src/flow.rs — Phase 2
use crate::crypto::{age_encrypt, ed25519_to_x25519_public, recipient_from_x25519_bytes};
use crate::error::Error;

/// Given a target's Ed25519 PKARR pubkey (z32), derive the X25519 recipient and
/// encrypt `plaintext` to it via age. Source: Phase 1 crypto.rs pattern.
fn encrypt_to_recipient_z32(plaintext: &[u8], target_z32: &str) -> Result<Vec<u8>, Error> {
    let target_pk = pkarr::PublicKey::try_from(target_z32)
        .map_err(|_| Error::Config(format!("invalid recipient pubkey: {}", target_z32)))?;
    let ed_bytes: [u8; 32] = *target_pk.as_bytes();  // pkarr exposes &[u8; 32]
    let x25519_pub = ed25519_to_x25519_public(&ed_bytes)?;
    let recipient = recipient_from_x25519_bytes(&x25519_pub)?;
    age_encrypt(plaintext, &recipient)
}
```
`[VERIFIED: ~/.cargo/registry/src/.../pkarr-5.0.4/src/keys.rs:150]` — `PublicKey::as_bytes(&self) -> &[u8; 32]`
`[VERIFIED: ~/.cargo/registry/src/.../age-0.11.2/src/protocol.rs:73]` — `Encryptor::with_recipients(iter)` API

### Example 6: age decrypt with own identity (RECV-03)
```rust
// src/flow.rs — Phase 2
use crate::crypto::{age_decrypt, ed25519_to_x25519_secret, identity_from_x25519_bytes};
use crate::identity::Identity;
use zeroize::Zeroizing;

fn decrypt_with_own_identity(
    ciphertext: &[u8],
    id: &Identity,
) -> Result<Zeroizing<Vec<u8>>, Error> {
    // Identity exposes secret_key_bytes_for_leak_test() — planner should expose a
    // cleaner secret_key_bytes() method, OR use keypair.secret_key() via a new accessor.
    // For this research note, assume `identity` has access to the Ed25519 seed.
    let seed: [u8; 32] = id.secret_key_bytes_for_leak_test();  // see open question
    let x25519_secret = ed25519_to_x25519_secret(&seed);
    let age_id = identity_from_x25519_bytes(&x25519_secret)?;
    age_decrypt(ciphertext, &age_id)
}
```
**Open question:** `Identity::secret_key_bytes_for_leak_test` is a Phase 1 test accessor with a debug-name. Phase 2 planner should either (a) rename it to `secret_key_bytes()` and make production-safe, or (b) add a new method like `encrypt_to_self()` / `decrypt_from_self()` on `Identity` that handles the X25519 derivation internally (preferred — keeps raw seed inside identity module). Flag for planning.

### Example 7: Acceptance screen rendering
```rust
// src/flow.rs — Phase 2, D-ACCEPT-02
use std::io::Write;
fn render_acceptance_screen(
    w: &mut impl Write,
    purpose: &str,
    openssh_fp: &str,
    sender_z32: &str,
    share_ref: &str,
    material_type: &str,
    size_bytes: usize,
    ttl_remaining_str: &str,
    expires_utc: &str,
    expires_local: &str,
) -> std::io::Result<()> {
    writeln!(w, "=== CIPHERPOST ACCEPTANCE ===============================")?;
    // Re-strip control chars defensively at display time (Pitfall #12 framing)
    let safe_purpose: String = purpose.chars().filter(|c| !c.is_control()).collect();
    writeln!(w, "Purpose:     \"{}\"", safe_purpose)?;
    writeln!(w, "Sender:      {}", openssh_fp)?;
    writeln!(w, "             {}", sender_z32)?;
    writeln!(w, "Share ref:   {}", share_ref)?;
    writeln!(w, "Type:        {}", material_type)?;
    writeln!(w, "Size:        {} bytes", size_bytes)?;
    writeln!(w, "TTL:         {} remaining (expires {} / {})",
             ttl_remaining_str, expires_utc, expires_local)?;
    writeln!(w, "=========================================================")?;
    writeln!(w, "To accept, paste the sender's z32 pubkey and press Enter:")?;
    Ok(())
}
```

### Example 8: TTY confirmation via dialoguer
```rust
// src/flow.rs — Phase 2, D-ACCEPT-01
use dialoguer::Input;
fn read_z32_confirmation() -> Result<String, Error> {
    Input::<String>::new()
        .with_prompt(">")
        .interact_text()
        .map_err(|e| Error::Config(format!("acceptance input failed: {}", e)))
}

fn assert_confirmation(entered: &str, expected_z32: &str) -> Result<(), Error> {
    if entered.trim() == expected_z32 {
        Ok(())
    } else {
        Err(Error::Declined)
    }
}
```
`[VERIFIED: ~/.cargo/registry/.../dialoguer-0.12.0]` — `Input::<T>::new().interact_text()` returns `std::io::Result<T>`; hard-errors on non-TTY. However, Phase 2 MUST check TTY FIRST (per D-ACCEPT-03) so the pre-check gives a cleaner error than dialoguer's internal fail.

### Example 9: Atomic sentinel creation (RECV-06)
```rust
// src/flow.rs — Phase 2, D-STATE-01
use std::fs;
use std::io::ErrorKind;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

fn state_dir() -> std::path::PathBuf {
    crate::identity::key_dir().join("state")
}
fn sentinel_path(share_ref_hex: &str) -> std::path::PathBuf {
    state_dir().join("accepted").join(share_ref_hex)
}

fn create_sentinel(share_ref_hex: &str) -> Result<(), Error> {
    let accepted_dir = state_dir().join("accepted");
    fs::create_dir_all(&accepted_dir).map_err(Error::Io)?;
    fs::set_permissions(&accepted_dir, fs::Permissions::from_mode(0o700))
        .map_err(Error::Io)?;

    let path = sentinel_path(share_ref_hex);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)  // atomic: fails if exists
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => Ok(()),
        // If another process just created it, treat as already-accepted (benign race).
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

fn is_already_accepted(share_ref_hex: &str) -> bool {
    sentinel_path(share_ref_hex).exists()
}
```

### Example 10: Ledger append with alphabetical JSON keys (D-STATE-01)
```rust
// src/flow.rs — Phase 2
use crate::crypto::jcs_serialize;  // reuse: JCS orders keys alphabetically
use serde::Serialize;
use std::io::Write as IoWrite;

#[derive(Serialize)]
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: &'a str,
    cleartext_hash: &'a str,
    purpose: &'a str,
    sender: &'a str,
    share_ref: &'a str,
}

fn append_ledger_line(entry: &LedgerEntry) -> Result<(), Error> {
    let ledger = state_dir().join("accepted.jsonl");
    let mut line = jcs_serialize(entry)?;  // alphabetical keys guaranteed
    line.push(b'\n');
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&ledger)
        .map_err(Error::Io)?;
    f.write_all(&line).map_err(Error::Io)?;
    // Ensure 0600 even if umask intervened
    fs::set_permissions(&ledger, fs::Permissions::from_mode(0o600))
        .map_err(Error::Io)?;
    Ok(())
}
```

### Example 11: Wire-budget pre-check
```rust
// src/flow.rs — Phase 2, D-PS-01
use pkarr::SignedPacket;

fn check_wire_budget(
    record: &OuterRecord,
    keypair: &pkarr::Keypair,
    plaintext_len: usize,
) -> Result<(), Error> {
    let rdata = serde_json::to_string(record).map_err(|e| Error::Transport(Box::new(e)))?;
    let name: pkarr::dns::Name<'_> = crate::DHT_LABEL_OUTER.try_into()
        .map_err(|e| Error::Transport(Box::new(e)))?;
    let txt: pkarr::dns::rdata::TXT<'_> = rdata.as_str().try_into()
        .map_err(|e| Error::Transport(Box::new(e)))?;
    let packet = pkarr::SignedPacket::builder()
        .txt(name, txt, 300)
        .sign(keypair)
        .map_err(|e| Error::Transport(Box::new(e)))?;
    let encoded_len = packet.encoded_packet().len();
    if encoded_len > 1000 {
        return Err(Error::WireBudgetExceeded {
            encoded: encoded_len,
            budget: 1000,
            plaintext: plaintext_len,
        });
    }
    Ok(())
}
```
`[VERIFIED: tests/signed_packet_budget.rs]` — pattern matches Phase 1's committed test.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|--------------|--------|
| `atty` crate for TTY detection | `std::io::IsTerminal` trait | Rust 1.70 (2023-06); `atty` deprecated | Zero new deps. Phase 2 uses std. |
| `serde_json::to_string` for signing | `serde_canonical_json::CanonicalFormatter` (RFC 8785 / JCS) | Phase 1 lock-in | Mandatory; wrong = signature divergence |
| cclink's alphabetical-field-declaration canonicalization | JCS via crate | Research Decision 2, Phase 1 | Future interop guaranteed |
| `Y/n` acceptance prompts | Typed 52-char z32 paste | D-ACCEPT-01 | MFA-fatigue resistance |
| Monolithic `Encryptor::encrypt(&mut output)` older age | `Encryptor::with_recipients(iter).wrap_output(&mut out).write_all().finish()` | age 0.10+ | API locked; Phase 1 code uses current shape |

**Deprecated/outdated:**
- `atty` crate: replaced by `std::io::IsTerminal`
- `age 0.9` and earlier `Decryptor::Recipients::decrypt(&[Box<dyn Identity>])` signature: age 0.11 uses `Decryptor::new(reader)?.decrypt(iter)` pattern
- Hand-rolled canonical JSON: abandoned in favor of JCS per Phase 1 lock-in

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Phase 1's `Identity::secret_key_bytes_for_leak_test` can be repurposed or renamed in Phase 2 to cleanly expose the Ed25519 seed for X25519 derivation | Code Examples §6 | Plan Wave 2 needs a small Phase 1 API addition OR accessor rename. Low risk; 5-line fix. |
| A2 | `chrono` is an acceptable new dependency for RECV-04 TTL local+UTC formatting; cargo-deny's license allowlist (MIT/Apache-2.0/BSD) covers chrono (MIT+Apache-2.0) | Standard Stack | If planner prefers `time` crate or hand-rolling, substitute. Both paths end with the same UX. |
| A3 | `humantime` crate MIT/Apache-2.0 license matches `deny.toml` allowlist (if planner picks humanized `--ttl`) | Standard Stack | Verify with `cargo deny check` before merge. `[CITED: humantime's Cargo.toml on crates.io]` — dual MIT/Apache-2.0, so fine. |
| A4 | Purpose stripping ONCE at send-time (D-WIRE-05) is sufficient; receive-side defensive re-strip is belt-and-suspenders, not required | Anti-patterns | D-WIRE-05 locks the send-time strip as canonical, so byte-identical sender/receiver views are guaranteed. A defensive receive-side re-strip is still recommended for display (Pitfall #12 framing) to guard against malicious pre-encryption tampering, but not required for correctness. Code Example §7 applies it. |
| A5 | No new direct HKDF call sites in Phase 2 (age handles its own internal KDF) — Phase 2 reserves new `hkdf_infos` constants as documentation and to satisfy the enumeration test's scan if someone inlines a literal later | Pattern 3 | If Phase 2 plan adds an HKDF call (unlikely — age covers inner payload via its own derivation), the constants are pre-reserved. No risk. |
| A6 | Phase 1's `debug_leak_scan.rs` pattern extends cleanly to cover `Envelope` and `Material` types | Anti-patterns | Test author in Phase 2 Wave 3 needs to add new types to the scan. 5-line change. |
| A7 | `MockTransport`'s 1000-byte check on the rdata JSON alone (not the full SignedPacket encoded) is a sufficient proxy for the real PKARR wire budget | Wire-budget pitfall | Phase 1's `signed_packet_budget.rs` uses the real `encoded_packet().len()` check. MockTransport currently checks `rdata.len() > 1000` — this is close but not identical. For Phase 2 wire-budget tests, use the **real SignedPacket build** pattern (Code Example §11) not the Mock's check. Verify during plan authoring. |
| A8 | The JSONL ledger schema is forward-compatible: Phase 3 can add a `receipt_published_at` field without breaking Phase 2 readers | Architectural Responsibility Map | Depends on whether Phase 2 readers parse the ledger strictly (via `#[serde(deny_unknown_fields)]`) or permissively. **Recommend: permissive** — parse with a struct whose fields are all Phase 2 fields; future fields are silently ignored. Test with a Phase-2-written line parsed by a Phase-3-schema struct. |

**Table is NOT empty.** The assumptions above are deliberate calls where this research defaults to one answer but the planner may choose another. Items A1, A2, A7 warrant planner explicit confirmation.

## Open Questions (RESOLVED)

1. **Should `Identity` gain a `decrypt_from_self()` convenience method to avoid exposing the raw Ed25519 seed to flow code?**
   - What we know: `Identity::secret_key_bytes_for_leak_test` is Phase 1's public accessor (production-accessible despite the name). Phase 2 needs the seed to derive X25519. Exposing raw bytes is a Pitfall #7-adjacent risk.
   - What's unclear: whether planner wants a minimal Phase 2 API change (rename + docstring warning) or a fully-encapsulated `Identity::decrypt(&self, ciphertext)` wrapper.
   - RESOLVED: Recommendation: **Add `Identity::decrypt_for_self(&self, ciphertext: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error>`** that internally derives X25519 and calls `age_decrypt`. Keeps seed in identity.rs. Similarly add `Identity::encrypt_to_self(&self, plaintext: &[u8]) -> Result<Vec<u8>, Error>` for `send --self`. Plan Wave 2 owns these additions.

2. **How does the acceptance-screen integration test simulate a TTY?**
   - What we know: Phase 1's `01-HUMAN-UAT.md` captures one pending TTY item (`identity generate` passphrase prompt). `assert_cmd` + `predicates` are in dev-deps.
   - What's unclear: whether `assert_cmd` can attach a PTY to child processes, or whether testing is restricted to (a) hand-scripted inputs via stdin pipe (which will fail TTY check → expected tested path) and (b) human UAT via `02-HUMAN-UAT.md`.
   - RESOLVED: Recommendation: **Accept that D-ACCEPT-03 compliance is tested via the non-TTY rejection path (pipe stdin → assert exit 1).** The happy-path acceptance screen + typed z32 goes in `02-HUMAN-UAT.md` per Phase 1's pattern. Planner allocates a human-verification item. An alternative — use `portable-pty` or `pty_closure` — adds complexity for a one-off.

3. **Should the wire-budget check use `MockTransport`'s JSON-length check or the real SignedPacket build?**
   - What we know: Phase 1's `tests/signed_packet_budget.rs` uses real `SignedPacket.encoded_packet().len()`. `MockTransport::publish` uses `rdata.len()`. These differ: the real packet adds ~50 bytes of DNS framing + packet overhead.
   - What's unclear: which measurement Phase 2's production path should trigger on.
   - RESOLVED: Recommendation: **Use the real `SignedPacket.encoded_packet().len()`** in `flow::run_send`'s wire-budget check (Code Example §11). It is the authoritative limit and makes the error message accurate. Keep the MockTransport's JSON-length approximation as a belt-and-suspenders in tests; real and mock budgets differ but both reject the right cases.

4. **How should `cipherpost version` verify its git SHA in Phase 2?**
   - What we know: Phase 1's VERIFICATION.md confirmed `cipherpost 0.1.0 (d8fb2028d2f2)` renders correctly. `build.rs` emits `CIPHERPOST_GIT_SHA` via `git rev-parse --short=12 HEAD`. The `option_env!` fallback is `"unknown"`.
   - What's unclear: whether Phase 2 needs any additional CLI-04 work or can mark it satisfied.
   - RESOLVED: Recommendation: **Add a Phase 2 integration test `phase2_version_git_sha_present.rs`** that runs `cipherpost version` and greps stdout for a 12-char lowercase-hex SHA (regex `\([0-9a-f]{12}\)`). If CI runs against a repo without a git dir (unlikely; CI checks out source), the fallback `"unknown"` causes the test to fail loudly — which is what we want.

5. **Is a `--json` or `--quiet` global flag worth adding in Phase 2 (discretion space)?**
   - What we know: CLI-04 locks `version` output format; CLI-01 locks stderr-vs-stdout discipline. Nothing else mandates JSON.
   - What's unclear: whether share URI emission to stdout should be `println!` (human) or structured JSON (machine).
   - RESOLVED: Recommendation: **Plain stdout `println!` for the URI.** `--json` is a planner-deferred v1.0 feature. Emitting structured JSON now would be speculative and add complexity. CLI-01 is satisfied: payload I/O + status-to-stderr. The URI is status (stdout per PROJECT.md L43 "print the share URI on stdout") — status on stdout for `send`, status on stderr for `receive`. Both are pipeable.

6. **What's the plan coordination between wave-1 and wave-2?**
   - What we know: Plan 2 (flow) depends on Plan 1 (payload + URI). Tests live in Plan 3.
   - What's unclear: whether to pre-author Plan 2's struct signatures in Plan 1, or let Plan 2 define them first and refactor if needed.
   - RESOLVED: Recommendation: **Plan 1 defines a clean `Envelope`/`Material` module with Phase-1-style tests** (JCS round-trip, size cap, strip, material variants error). Plan 2 imports and composes; no upstream changes needed. Plan 3 writes CLI integration tests. Planner retains latitude to merge 1+2 if parallelism is not needed.

## Environment Availability

Phase 2 is a pure code/config phase. No new external tools or services beyond the Phase 1 dependency set (Rust toolchain, cargo, pkarr via Cargo).

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Rust toolchain | All build/test | ✓ | 1.85.1 (verified `rustc --version`) | — |
| cargo-nextest | Test runner (fast) | ✓ | Phase 1 CI uses it | Regular `cargo test` works |
| `git` (for build.rs CIPHERPOST_GIT_SHA) | `cipherpost version` | ✓ | Any | Fallback = `"unknown"` (build.rs handles) |
| Mainline DHT network | Integration tests | N/A — `MockTransport` bypasses | — | Tests use `--features mock` per Phase 1 |
| TTY | Acceptance happy path | N/A in CI | — | Human UAT item per Phase 1 precedent |

**Missing dependencies with no fallback:** None.

**Missing dependencies with fallback:** None.

**`chrono` (new dep) availability:** [CITED: crates.io] dual MIT/Apache-2.0 licensed; cargo-deny allowlist covers it; latest stable 0.4.39 (2026-01). Add with `default-features = false, features = ["clock", "std"]` to avoid pulling legacy time-0.1 bridging.

## Validation Architecture

Nyquist validation is enabled (.planning/config.json has no `nyquist_validation: false`, so default = enabled).

### Test Framework
| Property | Value |
|----------|-------|
| Framework | `cargo test` + `cargo nextest run` (v0.9.133), integration tests in `tests/*.rs` |
| Config file | `Cargo.toml` `[[test]]` sections (one per integration test needing `--features mock`) |
| Quick run command | `cargo test --all-features -- --test-threads=1 --skip flow` (fast unit tests only) |
| Full suite command | `cargo nextest run --all-features` (all tests including integration, parallel where `serial_test` allows) |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| PAYL-01 | Envelope JCS encode/decode bit-identical | unit | `cargo test --all-features payload::tests::envelope_jcs_round_trip -- --nocapture` | ❌ Wave 1 |
| PAYL-02 | Material variants — GenericSecret works, others error | unit + integration | `cargo test --all-features material_variants_unimplemented` | ❌ Wave 1 |
| PAYL-03 | 65537-byte plaintext rejected with error naming 65537 + 65536 | integration | `cargo test --test phase2_size_cap --features mock` | ❌ Wave 3 |
| PAYL-04 | Purpose control-char stripping (C0/DEL/C1) | unit | `cargo test --all-features payload::tests::strips_c0_del_c1` | ❌ Wave 1 |
| PAYL-05 | `share_ref` deterministic SHA-256 [..16] hex — already tested | unit | `cargo test share_ref_is_deterministic` (exists) | ✅ Phase 1 |
| SEND-01 | Self round trip — send then receive, plaintext matches | integration | `cargo test --test phase2_self_round_trip --features mock` | ❌ Wave 3 |
| SEND-02 | Share mode — A→B decrypts, C cannot | integration | `cargo test --test phase2_share_round_trip --features mock` | ❌ Wave 3 |
| SEND-03 | `--ttl` override stored in inner signed `created_at + ttl_seconds` | integration | `cargo test --test phase2_ttl_override --features mock` | ❌ Wave 3 (or inline in share test) |
| SEND-04 | Dual signatures present on every outer record — tested via `verify_record` | unit | `cargo test sign_verify_round_trip` (exists) | ✅ Phase 1 |
| SEND-05 | `signed_packet_budget.rs` for representative payload — extend for Phase 2 | integration | `cargo test --test signed_packet_budget` (extend) | ✅ Phase 1 (extend) |
| RECV-01 | Tampered record → exit 3, no purpose leaked | integration | `cargo test --test phase2_tamper_aborts_before_decrypt --features mock` | ❌ Wave 3 |
| RECV-02 | Expired share → exit 2 | integration | `cargo test --test phase2_expired_share --features mock` | ❌ Wave 3 |
| RECV-03 | Envelope JCS parse failure → `SignatureCanonicalMismatch` exit 3 | integration | included in phase2_tamper_aborts_before_decrypt.rs | ❌ Wave 3 |
| RECV-04 | Acceptance screen contents | integration + manual | `cargo test --test phase2_acceptance_screen_nontty` (non-TTY exit path); human UAT for happy path | ❌ Wave 3 + 02-HUMAN-UAT |
| RECV-05 | `-o <path>` and `-` stdout | integration | `cargo test --test phase2_output_modes --features mock` | ❌ Wave 3 |
| RECV-06 | Second receive reports prior timestamp, no re-decrypt | integration | `cargo test --test phase2_idempotent_re_receive --features mock` | ❌ Wave 3 |
| CLI-01 | `-` stdin/stdout across send/receive | integration | `cargo test --test phase2_stdin_stdout --features mock` | ❌ Wave 3 |
| CLI-02 | Exit-code taxonomy {0, 2, 3, 4, 5, 6, 7, 1} | unit | extend `error::tests::exit_code_taxonomy` | ❌ Wave 1 (tiny test) |
| CLI-03 | Every `--help` has EXAMPLES | integration | `cargo test --test phase2_cli_help_examples` — spawn binary, grep | ❌ Wave 3 |
| CLI-04 | `cipherpost version` has git SHA + primitives list | integration | `cargo test --test phase2_version_git_sha_present` | ❌ Wave 3 |
| CLI-05 | Stderr scan on bad inputs — no secret markers | integration | `cargo test --test phase2_stderr_no_secrets` | ❌ Wave 3 |

### Sampling Rate
- **Per task commit:** `cargo test --all-features -- --test-threads=1` (quick; skip slow DHT integration if any)
- **Per wave merge:** `cargo nextest run --all-features && cargo clippy --all-features -- -D warnings && cargo fmt --check`
- **Phase gate:** Full suite green + `cargo deny check` + `cargo audit` before `/gsd-verify-work`

### Wave 0 Gaps
- [ ] `tests/phase2_self_round_trip.rs` — covers SEND-01/RECV-01..03/RECV-05
- [ ] `tests/phase2_share_round_trip.rs` — covers SEND-02/negative recipient
- [ ] `tests/phase2_tamper_aborts_before_decrypt.rs` — covers RECV-01/CLI-05 (partial)
- [ ] `tests/phase2_expired_share.rs` — covers RECV-02
- [ ] `tests/phase2_idempotent_re_receive.rs` — covers RECV-06
- [ ] `tests/phase2_size_cap.rs` — covers PAYL-03
- [ ] `tests/phase2_cli_help_examples.rs` — covers CLI-03
- [ ] `tests/phase2_stderr_no_secrets.rs` — covers CLI-05
- [ ] `tests/phase2_version_git_sha_present.rs` — covers CLI-04 (defensive)
- [ ] `tests/phase2_output_modes.rs` or folded into self round trip — covers RECV-05 + CLI-01
- [ ] `tests/phase2_declined.rs` — covers D-ACCEPT-01 (typed confirmation rejection paths)
- [ ] `tests/phase2_material_variants_unimplemented.rs` — covers PAYL-02
- [ ] Extension to `tests/signed_packet_budget.rs` with Envelope round-trip for SEND-05

*All framework deps already in place (assert_cmd 2, predicates 3, serial_test 3, tempfile 3, proptest 1). No new test-framework dep needed.*

## Security Domain

Security enforcement is enabled (no explicit `security_enforcement: false` in config). Cipherpost is a security-positioned tool; this section is critical.

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-----------------|
| V2 Authentication | no (cryptographic identity, not session-based auth) | Ed25519/PKARR keypair is identity — covered by Phase 1 |
| V3 Session Management | no | No sessions — stateless per-share crypto |
| V4 Access Control | yes (acceptance gate is an authorization boundary) | Typed z32 confirmation (D-ACCEPT-01); TTY requirement (D-ACCEPT-03); no `--yes` flag |
| V5 Input Validation | yes | Purpose control-char strip (D-WIRE-05); URI strict parser (D-URI-03); 64 KB plaintext cap; `Material` serde-tag closed-set |
| V6 Cryptography | yes | age-only AEAD (Phase 1 CRYPTO-05); JCS (CRYPTO-04); `Zeroizing<Vec<u8>>` on all decrypted buffers; manual Debug on secret-holders (`debug_leak_scan.rs`) |
| V7 Error Handling | yes | Unified sig-failure Display (Phase 1 D-16); no source-chain walking (D-15); CLI-05 fuzz scan for secret-in-stderr |
| V8 Data Protection | yes | Secrets in `Zeroizing`; ledger stores hashes not plaintext; sentinel files empty (no sensitive content in sentinel) |
| V9 Communications | yes (DHT is adversarial transport) | Ciphertext-only on wire; inner signed timestamp (Pitfall #11); dual-sig verify; share_ref binding |

### Known Threat Patterns for Rust CLI + DHT stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Signature-bypass via non-canonical JSON | Tampering + Spoofing | RFC 8785 JCS via `serde_canonical_json::CanonicalFormatter`; re-canonicalize guard in `record::verify_record` (Phase 1) |
| Oracle distinction via error text | Information Disclosure | Unified "signature verification failed" for all Signature* variants (Phase 1 D-16); `Error::DecryptFailed` generic text; never reveal which internal check tripped |
| Replay / stale packet | Spoofing | Inner signed `created_at + ttl_seconds` TTL check (RECV-02); URI share_ref binding (D-URI-02) |
| Prompt fatigue on acceptance | Elevation of Privilege | Typed 52-char z32 confirmation (D-ACCEPT-01); TTY required (D-ACCEPT-03); no `--yes` |
| Secret leakage via Debug / source-chain | Information Disclosure | Manual Debug on Envelope/Material (extend `debug_leak_scan.rs`); `user_message` never walks source |
| Passphrase via argv | Information Disclosure | Phase 1 IDENT-04 rejects inline; `resolve_passphrase` path is unchanged in Phase 2 |
| Control-char injection in purpose | Spoofing (terminal escape attack) | D-WIRE-05 strip at send; re-strip at receive-display-time for belt-and-suspenders (Code Example §7) |
| Wrong-recipient decrypt (share sent to B, C tries to pick up) | Spoofing / Elevation | `age_decrypt` returns `DecryptFailed` when no identity matches the ciphertext's recipients (age-level crypto); Phase 2 test SC1 second assertion |
| Stdout leakage to TTY scrollback | Information Disclosure | Planner discretion per §Claude's Discretion; recommend defer to v1.0 |
| TOCTOU on sentinel file | Race condition (same-user parallel receive) | `OpenOptions::new().create_new(true)` atomic-create; benign-race handling for `AlreadyExists` |
| Ledger file growth unbounded | DoS (disk exhaustion) | Deferred rotation/GC per D-STATE-03; acceptable at 1–100 shares/week. Document in Phase 4 SPEC.md |

**Project Constraints (from CLAUDE.md — auto-ingested):**
- Single `cipherpost` Rust crate + CLI binary, MIT-licensed.
- Fork-and-diverge from cclink; no live dependency. **Phase 2 does not re-introduce cclink as a dep.**
- No servers. Rendezvous = Mainline DHT only via PKARR. **Phase 2 does not introduce any HTTP or relay.**
- Ciphertext-only on the wire (both payload and metadata).
- `#[derive(Debug)]` banned on secret-holders. Zeroize discipline mandatory.
- JCS via `serde_canonical_json` only. `serde_json` alone is NOT canonical.
- HKDF info strings: `cipherpost/v1/<context>`, enumerated.
- Async runtime: NONE at cipherpost layer. Use `pkarr::ClientBlocking`.
- `ed25519-dalek =3.0.0-pre.5` exact pin is load-bearing.
- Identity path: `~/.cipherpost/`, mode `0600`. `CIPHERPOST_HOME` env var for tests.
- Default TTL: **24 hours** (PRD's 4h revised after DHT latency research).
- Dual-sig verification: outer PKARR before decrypt; inner Ed25519 before surfacing any field.
- No receipt publish in Phase 2 (that's Phase 3's RCPT-01).

All of the above are satisfied by the decisions in `<user_constraints>`.

## Sources

### Primary (HIGH confidence)
- **Phase 1 source code** (`src/{lib,main,cli,crypto,record,transport,identity,error}.rs`) — read directly 2026-04-21. All primitives verified present and wired.
- **Phase 1 tests** (`tests/`) — 23 tests green; patterns for integration testing, MockTransport usage, debug-leak scanning, fixture-based JCS assertion all established.
- **Phase 1 VERIFICATION.md + HUMAN-UAT.md** — 5/5 success criteria verified, 20/20 requirements satisfied, pending human TTY item.
- **age 0.11.2 source** (`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/age-0.11.2/src/protocol.rs:73`) — verified `Encryptor::with_recipients(iter: impl Iterator<Item = &'a dyn Recipient>)` + `Decryptor::new(reader)?.decrypt(iter)` API.
- **pkarr 5.0.4 source** (`~/.cargo/registry/src/index.crates.io-1949cf8c6b5b557f/pkarr-5.0.4/src/keys.rs:150`) — verified `PublicKey::as_bytes(&self) -> &[u8; 32]`, `PublicKey::try_from(&str)` accepts z32, `Keypair::sign(&[u8]) -> Signature`.
- **`.planning/research/*.md`** — STACK, PITFALLS, ARCHITECTURE, FEATURES, SUMMARY all read. Load-bearing for Phase 2: PITFALLS #2 (dual-sig), #3 (JCS), #6 (acceptance), #9 (age-only), #11 (replay), #12 (purpose).
- **`.planning/REQUIREMENTS.md` + ROADMAP.md + PROJECT.md** — all 21 Phase 2 REQ-IDs mapped; ROADMAP SC1..SC5 clearly defined; Key Decisions table for constraints.
- **`tests/signed_packet_budget.rs`** — empirical 550-byte blob limit documented; wire-budget computation pattern verified.
- **`deny.toml`** — license allowlist and banned-crate list verified; new crates (`chrono`, `humantime`) fit under MIT/Apache-2.0 policy.

### Secondary (MEDIUM confidence)
- **`std::io::IsTerminal` availability on Rust 1.70+** — [CITED: doc.rust-lang.org/std/io/trait.IsTerminal.html] Stable since 1.70.0. Crate MSRV 1.85 (rust-toolchain.toml).
- **`char::is_control()` covers C0 + DEL + C1** — [CITED: doc.rust-lang.org/std/primitive.char.html#method.is_control] "returns true if this char has the General_Category=Cc property" which is exactly C0 + C1 + DEL in Unicode.
- **chrono 0.4.x license + features** — [CITED: crates.io/crates/chrono] dual MIT/Apache-2.0; `clock` feature for timezone.
- **humantime 2.x license** — [CITED: crates.io/crates/humantime] dual MIT/Apache-2.0.

### Tertiary (assumptions — flagged in Assumptions Log)
- **A1–A8** in Assumptions Log above. None are load-bearing for phase viability; all are planner-negotiable defaults.

## Metadata

**Confidence breakdown:**
- **Standard stack:** HIGH — every dep version verified via `cargo tree` on 2026-04-21 against a working Phase 1 build.
- **Architecture:** HIGH — every primitive sourced from Phase 1 code directly; integration points verified by existing tests.
- **Pitfalls:** HIGH — PITFALLS.md Phase 2-owned items (#2, #3, #6, #9, #11, #12) each have a concrete D-decision in CONTEXT.md and a concrete test target in §Validation Architecture.
- **New dep (chrono):** MEDIUM — widely used crate, license clear, but planner should confirm against `time` crate during plan authoring.
- **Open questions:** None are blockers; all six have a default recommendation.

**Research date:** 2026-04-21
**Valid until:** 2026-05-21 (30 days — Rust dep ecosystem is stable for this scope; no protocol-level churn expected in age/pkarr on this timescale)

---
*Phase: 02-send-receive-and-explicit-acceptance*
*Research completed: 2026-04-21*
