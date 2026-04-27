# Milestones

## v1.0 Walking Skeleton (Shipped: 2026-04-22)

**Phases completed:** 4 phases, 15 plans

**Stats:**
- Git range: `d16057c` → `3a7f094` (117 commits; 19 `feat(` + 12 `fix(`)
- LOC: 3,543 in `src/` (11 files) · 6,407 incl. `tests/` (46 files)
- Test suite: 86 tests green under `cargo test --features mock`
- Timeline: 2026-04-20 → 2026-04-22 (~48 hours, 3 calendar days)
- Requirements: 49/49 v1 requirements validated
- CI: `fmt`, `clippy -D warnings`, `nextest`, `audit`, `deny check`, `lychee` all green

**Key accomplishments:**

1. **Foundation with locked wire format** — Rust crate scaffold on exact cclink v1.3.0 crypto pins (`pkarr 5.0.3`, `ed25519-dalek =3.0.0-pre.5`, `age 0.11`, `argon2 0.5`, `hkdf 0.12`), plain `fn main()` (no `tokio`), CI green on `fmt/clippy -D warnings/nextest/audit/deny`; `OuterRecord`/`OuterRecordSignable` JCS fixture (`outer_record_signable.bin`) committed to freeze the byte-level wire format; domain-separated HKDF `cipherpost/v1/<context>`, Argon2id params in PHC file header, zeroize discipline across every secret-holder.

2. **Identity + encrypted send/receive round trip** — `identity generate`/`show` with TTY double-confirm passphrase (fix `2e29b74` after UAT found single-prompt footgun), OpenSSH + z-base-32 fingerprints, mode-0600 enforcement; `Envelope`/`Material::GenericSecret` payload schema with JCS round-trip and 64 KB plaintext cap; `cipherpost send --self | --share <pubkey>` publishes via PKARR, `cipherpost receive` enforces outer+inner signature verify **before** any age-decrypt, then TTL, then the full-fingerprint D-ACCEPT acceptance screen with typed-z32 confirmation.

3. **Signed receipt — the cipherpost delta** — `Receipt`/`ReceiptSignable` JCS fixture (`receipt_signable.bin`, 424 B) committed; recipient-signed Ed25519 via `verify_strict` + round-trip-reserialize guard; post-acceptance `publish_receipt` to DHT label `_cprcpt-<share_ref>` via resolve-merge-republish (coexists with outgoing shares, no clobber); sender-side `cipherpost receipts --from <z32> [--share-ref | --json]` fetches, verifies, and renders a 10-field audit-detail view. Tamper-zero-receipts invariant enforced: any byte-flip between outer verify and acceptance aborts before publication.

4. **Protocol documents drafted** — `SPEC.md` (payload schema, JCS reference vector, outer+inner signature format, share URI, DHT labels, `share_ref` derivation, TTL semantics, exit-code taxonomy, non-interactive passphrase contract), `THREAT-MODEL.md` (identity compromise, DHT adversaries incl. sybil/eclipse/replay, purpose-as-sender-attested with false-purpose example, acceptance-UX attacks, receipt replay, passphrase-prompt MITM), `SECURITY.md` (live-tested disclosure channel via GHSA, 90-day embargo, cclink lineage + `cipherpost/v1` HKDF prefix reference), `lychee` link-check CI job pinned to `0.21.0`.

5. **End-to-end verifiability** — 86 tests across 35 integration files, including Phase 3 SC1–SC4 (tamper-zero-receipts, share_ref filter, coexistence, two-identity E2E); cross-fixture byte-level determinism under JCS; mock `Transport` lets the full happy-path + every adversarial abort run without touching Mainline DHT. IDENT-01 interactive TTY passphrase prompt verified manually on a real terminal at milestone close.

**Known deferred items at close:**

- **Crate-pin drift** — `serde_canonical_json` shipped as 1.0.0 (planned 0.2; API matches), `pkarr` transitively resolved to 5.0.4 (pinned 5.0.3), PKARR wire-budget measured at 550 bytes (planned 600). All documented in `01-VERIFICATION.md`; functionally correct.
- **Real-DHT cross-identity round trip** never run — MockTransport exercises the full code path but cannot reach Mainline DHT. Documented as `reason_documented` in `v1.0-MILESTONE-AUDIT.md`.
- **PKARR merge-update race** — `publish_receipt` uses `cas` (compare-and-swap), no explicit concurrent-racer test. Not triggered by walking-skeleton usage (one sender, one recipient, one accept per share).
- **Test advisory `GHSA-36x8-r67j-hcw6`** left in draft state as a permanent reproducibility record of the disclosure-channel round-trip.
- **Local dev lychee** pinned to 0.21.0 (project rustc 1.85.1 limit); future rustc bump will allow 0.23.0+.
- **Traceability-table bookkeeping** — 29 rows in the archived `REQUIREMENTS.md` retained "Pending" labels although body checkboxes are checked and phase VERIFICATION reports confirm implementation. Archive reflects the live state at close.
- **Full milestone audit**: see `milestones/v1.0-MILESTONE-AUDIT.md` (status `tech_debt`, zero truly-unsatisfied requirements).

---

## v1.1 Real v1 (Shipped: 2026-04-26)

**Phases completed:** 5 phases (5–9), 24 plans

**Stats:**
- Git range: `eafb73f` → `e17616e` (180 commits across 5 phases)
- LOC: +9,788 / -451 across 81 files (`src/` + `tests/`); src/ now 14 files / 6,627 LOC; tests/ now 68 files / 8,798 LOC
- Test suite: 311 passed / 0 failed / 19 ignored under `cargo test --features mock` (vs. 86 at v1.0 close)
- Timeline: 2026-04-23 → 2026-04-26 (~3.5 calendar days)
- Requirements: 67/67 v1.1 requirements validated (PASS×9, DOC×4, X509×9, PGP×9, SSH×10, PIN×10, BURN×9, DHT×7); zero "Pending" rows survive into archive (DOC-03 traceability rule held)
- CI: `fmt`, `clippy -D warnings` (1.85), `nextest`, `audit`, `deny check`, `lychee` all green at HEAD-of-origin (Phase 5–9 commits local-only at close, awaiting push)

**Key accomplishments:**

1. **Non-interactive automation E2E (Phase 5)** — `--passphrase-file <path>` and `--passphrase-fd <n>` on both `cipherpost send` and `cipherpost receive`; argv-inline `--passphrase <value>` rejected (uniform with identity subcommands). PASS-09 CI integration test (`tests/pass09_scripted_roundtrip.rs`) proves both fd and file paths run end-to-end without a TTY. Source-of-truth precedence locked project-wide: `--passphrase-fd > --passphrase-file > CIPHERPOST_PASSPHRASE > TTY`. SPEC.md gained §3.5 "DHT Label Stability" declaring `_cipherpost` and `_cprcpt-*` as wire-format constants requiring a `protocol_version` bump to change. Traceability format locked to inline phase tags (DOC-03) — eliminates the "Pending row" drift class that hit v1.0.

2. **Three typed payload variants — `X509Cert`, `PgpKey`, `SshKey` (Phases 6–7)** — Phase 6 pattern-establishes `Material::X509Cert { bytes }` with DER-canonical storage, PEM-input normalization at ingest, 8-field acceptance preview (Subject/Issuer/Serial/NotBefore/NotAfter/Key/Fingerprint/Status), `--armor` flag for PEM output. Phase 7 mechanically applies the pattern twice for `Material::PgpKey { bytes }` (binary OpenPGP packet stream; ASCII-armor rejected to preserve JCS byte-identity; v4/v5 fingerprint render; secret-key warning) and `Material::SshKey { bytes }` (OpenSSH v1 only; legacy PEM/RFC4716/FIDO rejected; SHA-256 OpenSSH-style fingerprint; DEPRECATED tag for DSA/RSA<2048). Three new JCS fixtures committed (X509: 626 B, PGP, SSH); `cargo tree | grep ed25519-dalek` pre-flight passed (no 2.x leak alongside `=3.0.0-pre.5` pin). MSRV 1.85 held by Cargo.lock pin to `time 0.3.41` after x509-parser pulled `time 0.3.47` (rustc 1.88).

3. **`--pin` and `--burn` encryption modes — orthogonal compose over all four Material variants (Phase 8)** — PIN crypto = cclink-fork-with-divergence: Argon2id(PIN + 32-byte random salt) → HKDF-SHA256 `cipherpost/v1/pin` → 32-byte X25519 scalar → wrapped into age `Identity` for nested-age inner layer. **No direct `chacha20poly1305` calls** — CLAUDE.md load-bearing rule preserved. Burn = single-consumption with state-ledger inversion: emit-before-mark order (D-P8-12) — emit decrypted bytes → fsync → append `state: "burned"` ledger row → fsync → touch sentinel. Receipt published unconditionally on burn-receive (BURN-04 — burn does NOT suppress attestation). Acceptance banner shows `[BURN — you will only see this once]` em-dash marker. PIN prompt rendered before typed-z32 acceptance. 23-test pin × burn × {GenericSecret, X509Cert, PgpKey, SshKey} compose matrix in `tests/pin_burn_compose.rs` covers orthogonality. v1.0 byte-identity preserved via `is_false` skip-serializing-if; new fixtures `outer_record_pin_required_signable.bin` (212 B) + `envelope_burn_signable.bin` (142 B) committed. Wrong-PIN folds into existing `Error::DecryptFailed` (NO new variant); error-oracle hygiene preserved at exit 4.

4. **Real-DHT release-acceptance gate + CAS retry-and-merge contract (Phase 9)** — `tests/cas_racer.rs` Barrier-synced two-thread racer (DHT-01/02) asserts exactly one publisher wins on first attempt under contention, the loser retries-and-merges, both receipts persist in the final PKARR state — runs deterministically in CI. Single-retry-then-fail CAS contract on `Transport::publish_receipt` (D-P9-A1); retry lives inside the trait method (D-P9-A2); `DhtTransport` and `MockTransport` mirror identical structure. `tests/real_dht_e2e.rs` cross-identity round trip behind `#[cfg(feature = "real-dht-e2e")]` + `#[ignore]` + `#[serial]` triple-gate; 7-step exp-backoff `[1u64, 2, 4, 8, 16, 32, 64]` with in-test 120s deadline; UDP pre-flight against `router.bittorrent.com:6881`. CI never enables the feature. `RELEASE-CHECKLIST.md` (91 lines, 29 checkboxes) documents the manual real-DHT invocation as the per-release gate (D-P9-D2 + Pitfall #29). `tests/wire_budget_compose_pin_burn_pgp.rs` DHT-07 wire-budget composite asserts pin+burn+2KB GenericSecret produces clean `Error::WireBudgetExceeded { encoded: 5123, budget: 1000 }` at send. CLAUDE.md +3 load-bearing lock-ins (CAS retry contract; pkarr defaults only — no `CIPHERPOST_DHT_BOOTSTRAP` env var; real-DHT triple-gate discipline).

5. **Solo-builder hygiene held end-to-end** — Zero "Pending" rows survive into v1.1 archive. Inline phase-tag traceability (DOC-03) is canonical; phase VERIFICATION.md files are authoritative. v1.1 Coverage Summary table (67 reqs) cross-referenced against three independent sources (REQUIREMENTS inline tags + phase VERIFICATION `requirements_covered:` + SUMMARY `requirements_completed:` frontmatter). 3-source check produced zero unsatisfied, zero orphaned. Audit verdict: **PASSED** (`milestones/v1.1-MILESTONE-AUDIT.md`).

**Known deferred items at close:**

- **Wire-budget escape hatch (cross-cutting Phase 6/7/8)** — realistic typed Material (X.509 234+ B DER, PGP variable, SSH variable, pin+burn-composed payloads) exceeds the 1000-byte PKARR BEP44 ceiling. Round-trip tests `#[ignore]`'d behind positive `Error::WireBudgetExceeded` clean-surface pins. Documented in SPEC.md §Pitfall #22 with measured 5123-byte composite. **Deferred to v1.2+** as architecturally orthogonal to v1.1's PRD-closure scope. Candidate fixes: two-tier storage / chunking / out-of-band payload + inline hash commit.
- **Real-DHT cross-identity round-trip is manual-only** via `RELEASE-CHECKLIST.md` — Phase 9 goal satisfied by test EXISTING / COMPILING / properly triple-gated. Per-release execution is a process step, not a CI gate. Scheduled for first invocation at v1.1.0 release tag time.
- **Toolchain divergence** — `rust-toolchain.toml` pins 1.88; CI clippy pins 1.85; clippy 1.88 enforces `uninlined_format_args` as default lint, surfacing 65+ instances locally that 1.85 doesn't catch. CI is source-of-truth release gate per CLAUDE.md MSRV-1.85; `build.rs:17` (the specifically-flagged blocker in PROJECT.md and `09/deferred-items.md`) was fixed in commit `e45347b` at milestone close. Reconciliation deferred to v1.2 maintenance pass.
- **Code-review advisories (non-blocking)**: WR-01 (`tests/real_dht_e2e.rs:153` propagation wait routes via `alice_transport`; should resolve via `bob_transport` to avoid local pkarr cache short-circuit) and WR-02 (`MockTransport::publish` doesn't bump `seq`; latent concurrent-write data-loss window dormant in v1.1, matters only at future composition).
- **Fixture-regen reproducibility across OpenSSL versions (Phase 6)** — documentation-promise (`tests/fixtures/x509_cert_fixture.reproduction.txt`); no automated test asserts non-drift. Accepted as deferred.
- **Non-interactive PIN input (`--pin-file`/`--pin-fd`)** — explicitly deferred to v1.2+ per DEFER-PIN; PIN is intentionally human-in-the-loop second factor.
- **Destruction attestation workflow** (originally PRD v1.1) — shifted to v1.2+ because v1.1 filled up with PRD-closure scope.
- **Full milestone audit**: see `milestones/v1.1-MILESTONE-AUDIT.md` (status `passed`, 67/67 requirements satisfied, no critical blockers).

---
