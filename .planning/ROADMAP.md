# Roadmap: Cipherpost

## Milestones

- ✅ **v1.0 Walking Skeleton** — Phases 1–4 (shipped 2026-04-22) — [archive](milestones/v1.0-ROADMAP.md)
- 🔄 **v1.1 Real v1** — Phases 5–9 (in progress)

## Phases

<details>
<summary>✅ v1.0 Walking Skeleton (Phases 1–4) — SHIPPED 2026-04-22</summary>

- [x] Phase 1: Foundation — scaffold, vendored primitives, and transport seam (3/3 plans) — completed 2026-04-21
- [x] Phase 2: Send, receive, and explicit acceptance (3/3 plans) — completed 2026-04-21
- [x] Phase 3: Signed receipt — the cipherpost delta (4/4 plans) — completed 2026-04-21
- [x] Phase 4: Protocol documentation drafts (5/5 plans) — completed 2026-04-22

Full detail: [`milestones/v1.0-ROADMAP.md`](milestones/v1.0-ROADMAP.md) · Accomplishments: [`MILESTONES.md`](MILESTONES.md) · Requirements archive: [`milestones/v1.0-REQUIREMENTS.md`](milestones/v1.0-REQUIREMENTS.md) · Audit: [`milestones/v1.0-MILESTONE-AUDIT.md`](milestones/v1.0-MILESTONE-AUDIT.md)

</details>

### v1.1 Real v1 (Phases 5–9)

- [x] **Phase 5: Non-interactive automation E2E** — scripted send/receive without TTY; passphrase-file/fd on send+receive; SPEC pin-version blessing; DHT label audit; traceability format locked (completed 2026-04-24)
- [x] **Phase 6: Typed Material — X509Cert** — pattern-establish: DER-normalized X.509 end-to-end (parse, validate, render acceptance screen, JCS fixture, integration test) — completed 2026-04-24
- [x] **Phase 7: Typed Material — PgpKey + SshKey** — apply Phase 6 pattern twice; ed25519-dalek conflict pre-flight; JCS fixtures for both variants — completed 2026-04-25
- [x] **Phase 8: --pin and --burn encryption modes** — cclink-fork PIN crypto (Argon2id+HKDF→X25519→age); burn-after-read state-ledger inversion; THREAT-MODEL.md additions; pin/burn compose orthogonally [COMPLETE 2026-04-26 — pending verifier sign-off; all 19 PIN+BURN REQ-IDs covered]
- [x] **Phase 9: Real-DHT E2E + CAS merge-update race gate** — CAS racer in CI; real-DHT cross-identity round trip as manual release-acceptance gate; RELEASE-CHECKLIST.md (completed 2026-04-26)

## Phase Details

### Phase 5: Non-interactive automation E2E
**Goal**: Users can send and receive secret material without any TTY interaction, enabling scripted pipelines and CI automation.
**Depends on**: Nothing (continues directly from v1.0 Phase 4)
**Requirements**: PASS-01, PASS-02, PASS-03, PASS-04, PASS-05, PASS-06, PASS-07, PASS-08, PASS-09, DOC-01, DOC-02, DOC-03, DOC-04
**Success Criteria** (what must be TRUE):
  1. User can run `cipherpost send - --passphrase-fd 3 < payload.bin 3< passphrase.txt` and `cipherpost receive --passphrase-file ~/.cipherpost/pp.txt` end-to-end without a TTY, proven by a CI integration test
  2. Passing `--passphrase` inline to `send` or `receive` is rejected with the same error message used by `identity` subcommands; `--help` on both shows all three non-interactive sources with scripting examples
  3. `--passphrase-file` strips exactly one trailing newline (never greedy `.trim()`), and file mode > 0600 is refused with a message naming the actual mode; `--passphrase-fd` uses `BorrowedFd` (no double-close)
  4. SPEC.md records actually-shipped crate versions in API-range form (not exact version prose); DHT label constants `_cipherpost` and `_cprcpt-<share_ref_hex>` are confirmed stable and documented as requiring a protocol-version bump to change
  5. REQUIREMENTS.md traceability format is locked to inline phase tags; no separate traceability table exists anywhere in the planning corpus; no "Pending" row survives when implementation is complete
**Plans**: 3 plans
- [x] 05-01-PLAN.md — resolve_passphrase refactor (BorrowedFd + exact one-newline strip + fd=0 rejection)
- [x] 05-02-PLAN.md — CLI surface + dispatch + PASS-09 scripted-roundtrip CI test
- [x] 05-03-PLAN.md — DOC housekeeping (SPEC.md §7/§3.3/§3-4, CLAUDE.md convention, DHT label test, v1.0 archive cleanup)

### Phase 6: Typed Material — X509Cert
**Goal**: Users can securely hand off an X.509 certificate with full context visible on the acceptance screen before decryption commits.
**Depends on**: Phase 5 (scripted automation CI recipe used by integration tests)
**Requirements**: X509-01, X509-02, X509-03, X509-04, X509-05, X509-06, X509-07, X509-08, X509-09
**Success Criteria** (what must be TRUE):
  1. User can `cipherpost send --material x509-cert` with either a DER or PEM file; PEM is accepted at the CLI surface and normalized to DER **before JCS hashing and storage** (stored bytes are always canonical DER so `share_ref` remains deterministic across re-sends); indefinite-length BER is rejected at ingest with exit 1
  2. The acceptance screen shows Subject, Issuer, SerialNumber (truncated), NotBefore/NotAfter (UTC), key algorithm, and full SHA-256 DER fingerprint before the typed-z32 prompt; expired certs display `[EXPIRED]` but are not blocked
  3. Raw DER bytes reach stdout by default; `--armor` produces PEM-wrapped output
  4. JCS fixture `tests/fixtures/material_x509_signable.bin` is committed and asserted byte-for-byte identical on every CI run (any drift surfaces as a red test)
  5. Malformed X.509 DER at receive time returns exit 1 with a message naming the variant — never exit 3 (reserved for signature failures)
**Plans**: 4 plans (4 / 4 complete)
- [x] 06-01-PLAN.md — Foundation: x509-parser dep + Material::X509Cert struct variant + as_x509_cert_bytes + plaintext_size + Error::InvalidMaterial + payload::ingest module [2026-04-24]
- [x] 06-02-PLAN.md — preview.rs module: render_x509_preview with DN/Serial/fingerprint/key-alg rendering + format_unix_as_iso_utc visibility bump [2026-04-24]
- [x] 06-03-PLAN.md — CLI surface + dispatch: --material flag + --armor flag + run_send/run_receive wiring + Prompter trait extension [2026-04-24]
- [x] 06-04-PLAN.md — Fixtures + integration tests + error-oracle enumeration + leak-scan extension + dep-tree guard + SPEC.md update [2026-04-24]
**Phase 6 wire-budget deferral (discovered at Plan 04 execution):** Realistic X.509 certs (min ~234 B DER) exceed the 1000-byte PKARR BEP44 ceiling. Full round-trip tests are `#[ignore]`'d pending a wire-budget escape hatch (two-tier storage / chunking / out-of-band). Positive test `x509_send_realistic_cert_surfaces_wire_budget_exceeded_cleanly` pins the clean error-path surface. **Phase 7 planning MUST address this before PGP/SSH round-trip coverage.**
**UI hint**: no

### Phase 7: Typed Material — PgpKey + SshKey
**Goal**: Users can securely hand off OpenPGP keys and OpenSSH private keys with full metadata visible on the acceptance screen; both variants apply the Phase 6 pattern.
**Depends on**: Phase 6 (Material module conventions, per-variant size checks, Debug redaction pattern, JCS fixture discipline — apply here without re-deriving)
**Requirements**: PGP-01, PGP-02, PGP-03, PGP-04, PGP-05, PGP-06, PGP-07, PGP-08, PGP-09, SSH-01, SSH-02, SSH-03, SSH-04, SSH-05, SSH-06, SSH-07, SSH-08, SSH-09, SSH-10
**Success Criteria** (what must be TRUE):
  1. User can `cipherpost send --material pgp-key` with a binary OpenPGP packet stream and receive it; ASCII-armored input is rejected (non-deterministic headers); multi-primary keyrings are rejected with exit 1 naming the count; secret keys display `[WARNING: SECRET key]` on the acceptance screen but are not blocked
  2. User can `cipherpost send --material ssh-key` with an OpenSSH v1 format key; legacy PEM, RFC 4716, and FIDO-format keys are rejected at ingest; the acceptance screen shows key type, SHA-256 fingerprint (OpenSSH-style), and comment labeled as sender-attested
  3. JCS fixtures `tests/fixtures/material_pgp_signable.bin` and `tests/fixtures/material_ssh_signable.bin` are committed and asserted byte-for-byte identical on every CI run
  4. `cargo tree | grep ed25519-dalek` pre-flight result is documented in Phase 7 plan 01 — either "no 2.x leak" or explicit coexistence acceptance recorded before any `ssh-key` code ships
  5. Malformed PGP packets and malformed SSH bytes at receive time each return exit 1 with a generic message that does not leak crate internals
**Plans**: 8 plans
- [x] 07-01-PLAN.md — pgp foundation (rpgp dep, MSRV bump, Material::PgpKey, ingest, run_send wiring) [2026-04-25]
- [x] 07-02-PLAN.md — render_pgp_preview helper (banner subblock, SECRET-key warning) [2026-04-25]
- [x] 07-03-PLAN.md — run_receive PGP wiring + pgp_armor helper [2026-04-25]
- [x] 07-04-PLAN.md — PGP ship-gate (fixtures + 23 tests + SPEC.md update + dep-tree guard) [2026-04-25]
- [x] 07-05-PLAN.md — ssh-key foundation (Material::SshKey, ingest, run_send wiring, main.rs guard removed) [2026-04-25]
- [x] 07-06-PLAN.md — render_ssh_preview helper (banner subblock, [DEPRECATED] tag) [2026-04-25]
- [x] 07-07-PLAN.md — run_receive SSH wiring + --armor reject [2026-04-25]
- [x] 07-08-PLAN.md — SSH ship-gate (fixtures + 28 tests + SPEC.md update + dep-tree guard) [2026-04-25]
**Phase 7 wire-budget continuation:** Realistic PGP and SSH keys also exceed the 1000-byte PKARR BEP44 ceiling; round-trip tests `#[ignore]`'d per D-P7-03 (positive `WireBudgetExceeded` paths ship ACTIVE). Wire-budget escape hatch consolidated into SPEC.md §Pitfall #22 with measured numbers.
**UI hint**: no

### Phase 8: --pin and --burn encryption modes
**Goal**: Senders can require a PIN as a second factor for decryption, and can mark a share as single-consumption; both modes compose orthogonally and layer cleanly on all typed Material variants.
**Depends on**: Phase 7 (pin/burn have full semantic value over typed payloads; JCS fixture discipline for new Envelope and OuterRecord fields is established; cclink pin/burn survey must be completed before this phase is planned — see SUMMARY.md Open Questions)
**Requirements**: PIN-01, PIN-02, PIN-03, PIN-04, PIN-05, PIN-06, PIN-07, PIN-08, PIN-09, PIN-10, BURN-01, BURN-02, BURN-03, BURN-04, BURN-05, BURN-06, BURN-07, BURN-08, BURN-09
**Success Criteria** (what must be TRUE):
  1. User can `cipherpost send --pin` (TTY prompt, no echo); the PIN crypto stack is **cclink-fork**: Argon2id(PIN + 32-byte random salt) → HKDF-SHA256 `cipherpost/v1/pin` → X25519 scalar → age `Identity` → `age_encrypt` to the derived recipient. Stays inside `age` for AEAD — no direct `chacha20poly1305` calls (CLAUDE.md constraint holds unchanged). PIN AND identity key are both required to decrypt (true second factor).
  2. A recipient of a `pin_required` share is prompted for PIN before the typed-z32 acceptance banner; wrong PIN returns exit 4 with the identical user-facing message as wrong identity passphrase (error-oracle hygiene); the HKDF info enumeration test is extended to cover `cipherpost/v1/pin`
  3. User can `cipherpost send --burn`; first receive decrypts and writes a `burned` state-ledger entry; second receive on the same share returns exit 7 "share already consumed"; a receipt IS published after successful burn-receive (burn does not suppress attestation)
  4. `--pin` and `--burn` compose: a share with both flags set carries `pin_required=true` in OuterRecord and `burn_after_read=true` in Envelope; `skip_serializing_if = is_false` preserves byte-identity with v1.0 for non-pin/non-burn shares
  5. THREAT-MODEL.md documents PIN mode (second-factor semantics, Argon2id offline-brute-force bound, intentional indistinguishability from wrong-key errors) and burn mode (local-state-only semantics, DHT-ciphertext-survives-TTL caveat, multi-machine race explicitly described)
**Plans**: 6 plans (6 / 6 complete)
- [x] 08-01-PLAN.md — PIN crypto core: src/pin.rs (pin_derive_key + Argon2id+HKDF), hkdf_infos::PIN constant, OuterRecord.pin_required + Envelope.burn_after_read fields, is_false helper, run_send nested-age branch, cclink-divergence write-up + cargo-tree evidence [2026-04-25]
- [x] 08-02-PLAN.md — PIN ship-gate: validate_pin + prompt_pin (TTY-only, confirm-on-send, CIPHERPOST_TEST_PIN cfg-gated test injection), --pin CLI flag + main.rs wiring, run_receive PIN integration (salt-split + nested age-decrypt), JCS fixture (212 B), error-oracle Display equality (exit-4 lane), leak-scan PIN entries, SPEC.md §3.6 [2026-04-25]
- [x] 08-03-PLAN.md — BURN core: --burn CLI flag + BURN-05 stderr warning, LedgerState enum {None, Accepted, Burned}, check_already_consumed rename, LedgerEntry.state Option<&str> schema migration (v1.0 default-deserialization preserved); test_paths cfg-gated re-export for Plan 04+5 integration tests; pin+burn compose smoke test [2026-04-25]
- [x] 08-04-PLAN.md — BURN ship-gate: Prompter::marker param + [BURN] banner marker, append_ledger_entry_with_state helper + emit-before-mark for burn (D-P8-12), JCS fixture (142 B; burn_after_read FIRST alphabetic), BURN-09 round-trip + receipt-count==1, state_ledger schema tests, PITFALLS.md #26 SUPERSEDED header, SPEC.md §3.7 Burn Semantics [2026-04-26]
- [x] 08-05-PLAN.md — Compose: tests/pin_burn_compose.rs (752 lines / 23 tests) walks pin × burn × {GenericSecret, X509Cert, PgpKey, SshKey} matrix (12 base + 4 receipt-count + 4 second-receive cross-cutting); 2 negative-path safety (wrong-PIN-on-burn + typed-z32-declined-on-burn don't mark burned); pin+burn+pgp wire-budget pre-flight surfaces cleanly (RESEARCH Open Risk #5); W3 split macros — strict for generic_burn_only only, lenient for every PIN path + typed-material variant; full suite 309 passed / 0 failed / 19 ignored [2026-04-26]
- [x] 08-06-PLAN.md — Docs: THREAT-MODEL.md §6.5 PIN mode + §6.6 Burn mode (multi-machine race + indistinguishability + offline brute-force bound), SPEC.md consolidation (§3.6/§3.7 cross-links + §5.1 --burn flag + §5.2 ledger pre-check / banner marker + §6 exit-4 §3.6 ref + §Pitfall #22 wire-budget continuation), CLAUDE.md +3 load-bearing lock-ins (cipherpost/v1/pin HKDF clause; accepted.jsonl state field migration; emit-before-mark contract); W6 audit hygiene confirmed; all 19 PIN+BURN REQ-IDs covered [2026-04-26]
**UI hint**: no

### Phase 9: Real-DHT E2E + CAS merge-update race gate
**Goal**: The protocol is validated over real Mainline DHT end-to-end, and concurrent receipt publication is proven safe under contention — so v1.1 ships with confidence it works beyond MockTransport.
**Depends on**: Phase 8 (all payload types and encryption modes landed; CAS racer tests the most complex merge scenario: concurrent receipt publish after burn + pin share with typed payload)
**Requirements**: DHT-01, DHT-02, DHT-03, DHT-04, DHT-05, DHT-06, DHT-07
**Success Criteria** (what must be TRUE):
  1. MockTransport enforces `cas` semantics for `publish_receipt`: a concurrent racer test (two threads, `std::sync::Barrier` synchronized) asserts exactly one wins on first attempt, the loser retries-and-merges, and the final PKARR state contains both receipts — runs in CI under `cargo test --features mock`
  2. A real-DHT cross-identity round trip test exists behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]`; it spawns two in-process clients with independent identities, publishes via client A, resolves via client B with 120-second exponential-backoff ceiling, decrypts, publishes receipt via B, fetches via A; UDP pre-flight skips gracefully if bootstrap is unreachable
  3. `RELEASE-CHECKLIST.md` at repo root documents the manual real-DHT invocation command, expected output pattern, and explicit pass/fail criteria; every v1.1+ release requires a human to run and pass this checklist
  4. A wire-budget coexistence test asserts that a share with `pin_required=true` + `burn_after_read=true` carrying a realistic PGP payload (~2 KB) produces a clean `Error::WireBudgetExceeded` at send time (not a PKARR-internal panic) if the payload exceeds the 550-byte `OuterRecord` budget
**Plans**: 3 plans
- [x] 09-01-PLAN.md — CAS retry-and-merge contract + MockTransport per-key seq + DHT-07 wire-budget composite (DHT-01 + DHT-02 + DHT-07; wave 1; autonomous)
- [x] 09-02-PLAN.md — Real-DHT cross-identity round trip + cfg-feature + UDP pre-flight + nextest config (DHT-03 + DHT-04 + DHT-05; wave 1; autonomous=false — manual real-DHT invocation via RELEASE-CHECKLIST)
- [x] 09-03-PLAN.md — Docs: RELEASE-CHECKLIST template + v1.1 snapshot + CLAUDE.md +3 lock-ins + README/SPEC bootstrap notes + STATE.md todo closure (DHT-06; wave 2; depends on 09-01 + 09-02; autonomous)
**UI hint**: no

## Progress

| Phase | Milestone | Plans Complete | Status | Completed |
|-------|-----------|----------------|--------|-----------|
| 1. Foundation | v1.0 | 3/3 | Complete | 2026-04-21 |
| 2. Send/receive/acceptance | v1.0 | 3/3 | Complete | 2026-04-21 |
| 3. Signed receipt | v1.0 | 4/4 | Complete | 2026-04-21 |
| 4. Protocol docs | v1.0 | 5/5 | Complete | 2026-04-22 |
| 5. Non-interactive automation E2E | v1.1 | 3/3 | Complete    | 2026-04-24 |
| 6. Typed Material: X509Cert | v1.1 | 4/4 | Complete    | 2026-04-24 |
| 7. Typed Material: PgpKey + SshKey | v1.1 | 8/8 | Complete    | 2026-04-25 |
| 8. --pin and --burn modes | v1.1 | 6/6 | Complete | 2026-04-26 |
| 9. Real-DHT E2E + CAS race gate | v1.1 | 3/3 | Complete | 2026-04-26 |

---
*Last updated: 2026-04-26 after Phase 9 plans landed — 3 plans following the Phase 8 plan-structure compression pattern (D-P9-F1 + 09-RESEARCH.md refinement). Wave 1: 09-01 (CAS racer + DHT-07 wire-budget) and 09-02 (real-DHT cross-identity round trip + nextest config) — independent file sets. Wave 2: 09-03 (docs: RELEASE-CHECKLIST + CLAUDE.md lock-ins + STATE.md todo closure) depends on 09-01 + 09-02 because RELEASE-CHECKLIST cites the nextest invocation finalised in 09-02 and the SPEC.md §Pitfall #22 composite measurement cites 09-01-SUMMARY.md. All 7 DHT-01..07 REQ-IDs covered. Ready to execute Phase 9.*
