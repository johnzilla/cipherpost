---
phase: 3
slug: signed-receipt-the-cipherpost-delta
status: verified
threats_open: 0
threats_total: 23
threats_closed: 23
threats_mitigated: 18
threats_accepted: 5
asvs_level: 2
created: 2026-04-21
verified: 2026-04-21
---

# Phase 3 — Security

> Per-phase security contract: threat register, accepted risks, and audit trail.

---

## Trust Boundaries

| Boundary | Description | Data Crossing |
|----------|-------------|---------------|
| DHT → cipherpost process (receipt body) | Any party can publish bytes under a pubkey they control; receipt body parse + sig verify must reject every non-recipient-signed or canonicalization-divergent variant before any field is surfaced | Public Receipt (signed by recipient Ed25519) |
| cipherpost process → DHT (step 13 publish) | Receipt signed by recipient's Ed25519 key before leaving the process; attacker cannot forge a receipt under a key they do not hold | Signed Receipt (public) |
| Third-party publisher → recipient's DHT key | Only the keypair's holder can publish a SignedPacket under that key (pkarr signature gate); external spam under the recipient's key is impossible | Nothing — external writes rejected |
| Concurrent publisher within the recipient's own process → DHT | Two simultaneous `publish_receipt` calls under the same key may race; D-MRG-02 documents, does not mitigate | Last-writer-wins merge |
| pkarr packet size → wire | 1000-byte BEP44 ceiling; receipt overflow maps to `Error::WireBudgetExceeded { plaintext: 0 }` | Encoded packet bytes |
| stdout vs stderr | Payload / structured data goes to stdout; status / progress / warnings go to stderr (CLI-01) | Receipt table, JSON; warnings |
| Rust attacker → serde round-trip | A tampered receipt whose JCS bytes parse-then-reserialize to something different is a canonicalization-bypass attempt | Parsed Receipt → reserialized JCS bytes |
| Test-injected tampered OuterRecord → run_receive | Proves SC1: tampered ciphertext MUST NOT surface a receipt to the DHT (step 13 never runs) | Malformed OuterRecord |

---

## Threat Register

| Threat ID | Category | Component | Disposition | Mitigation | Status |
|-----------|----------|-----------|-------------|------------|--------|
| T-03-01-01 | Spoofing | `verify_receipt` signature path | mitigate | `VerifyingKey::from_bytes(recipient_pubkey)` + `verify_strict` on JCS bytes (src/receipt.rs:105-121) | closed |
| T-03-01-02 | Tampering | `verify_receipt` step 5 round-trip-reserialize | mitigate | Parse-then-reserialize byte-compare via `crypto::jcs_serialize`; mismatch → `Error::SignatureCanonicalMismatch` (src/receipt.rs:125-130) | closed |
| T-03-01-03 | Info Disclosure | Signature-failure error-oracle | mitigate | D-16 unified Display: all four sig-fail variants share `"signature verification failed"` (src/error.rs:31-34); asserted in phase3_receipt_sign_verify.rs tampered-* tests | closed |
| T-03-01-04 | Tampering | JCS canonical form drift between Rust versions | mitigate | Committed `tests/fixtures/receipt_signable.bin` (424 bytes); `receipt_signable_bytes_match_committed_fixture` fails on drift | closed |
| T-03-01-05 | Info Disclosure | Receipt fields (purpose, hashes, pubkeys) | accept | Public substrate design (D-RS-06); receipts are social-layer attestations on a public DHT; no field is secret; Zeroize correctly omitted | closed |
| T-03-01-06 | Tampering | nonce entropy | mitigate | `OsRng.fill_bytes` (getrandom) → 128 bits; collision negligible at skeleton traffic scale; `nonce_hex_shape` test asserts two calls differ | closed |
| T-03-02-01 | Tampering | `DhtTransport::publish_receipt` clobbering outgoing `_cipherpost` share | mitigate | D-MRG-01 resolve-merge-republish in src/transport.rs; `phase3_mock_publish_receipt_coexistence::outgoing_share_and_receipts_coexist` asserts coexistence | closed |
| T-03-02-02 | DoS | Concurrent publish race under same recipient key | accept | D-MRG-02 documented limitation; CAS `Some(packet.timestamp())` threaded through so v1.1+ can enable retry without protocol change | closed |
| T-03-02-03 | DoS | Wire-budget exhaustion via receipt accumulation | mitigate | `SignedPacketBuildError::PacketTooLarge` → `Error::WireBudgetExceeded { plaintext: 0 }`; step 13 warn-and-degrade surfaces without hard-failing receive | closed |
| T-03-02-04 | Tampering | DNS name-normalization bypass | mitigate | `matches_receipt_label` trims trailing `.` and checks both `<label>` and `<label>.<z32>` forms (src/transport.rs:237-240) | closed |
| T-03-02-05 | Info Disclosure | Ledger rows leak on disk | accept | Inherited Phase 2 posture: `~/.cipherpost/state/` at mode 0600, local-only; `receipt_published_at` is public-substrate timestamp | closed |
| T-03-03-01 | Tampering | Receipt published BEFORE sentinel + ledger (RECV-06 break) | mitigate | D-SEQ-01 strict ordering: step 13 strictly after step 12 in src/flow.rs:479; crash between steps leaves material + ledger but no receipt (acceptable degradation) | closed |
| T-03-03-02 | DoS | Receipt-publish failure propagates as non-zero exit | mitigate | D-SEQ-02 warn+degrade: `match transport.publish_receipt(...)` with no `?`; `Err` arm `eprintln` + fallthrough; overall `run_receive` returns `Ok(())` (src/flow.rs:527) | closed |
| T-03-03-03 | Spoofing | Receipt `purpose` surfaces control chars in recipient's table | mitigate | D-OUT-01 + PAYL-04 defense-in-depth: stripped at send (Phase 2 D-WIRE-05) AND at display in `render_receipts_table` + `truncate_purpose` (src/flow.rs:651,679) | closed |
| T-03-03-04 | Info Disclosure | Error-oracle distinguishes sig subtype in run_receipts | mitigate | D-16 unified Display; `run_receipts` aggregates as `invalid_sig` counter only; surfaces `Error::SignatureInner` uniformly (src/flow.rs:590-614) | closed |
| T-03-03-05 | Spoofing | Filter-before-verify leaks unverified receipt | mitigate | Pitfall #6 / D-OUT-02: `--share-ref` filter applied AFTER `verify_receipt`; invalid-sig receipts counted but never surfaced (src/flow.rs:606-608) | closed |
| T-03-03-06 | Tampering | Receipt published BEFORE recipient has material | mitigate | Inherits Phase 2 D-RECV-01 step ordering; step 13 runs only after steps 2/3 (dual sig), 7 (JCS parse), 8 (acceptance), 11 (material write), 12 (sentinel+ledger) | closed |
| T-03-03-07 | Tampering | Self-mode receipt as branch-elision point | mitigate | D-SEQ-06: step 13 block has no `if self_mode { skip }`; `self_receipt_round_trip` test asserts identical verify path | closed |
| T-03-04-01 | Tampering | Tampered ciphertext produces a receipt (SC1 violation) | mitigate | `phase3_tamper_zero_receipts.rs` injects garbage-blob `OuterRecord`; asserts run_receive errors + zero `_cprcpt-*` entries under B's key | closed |
| T-03-04-02 | Spoofing | Test coverage gap allows regression accepting receipt without verify | mitigate | `phase3_end_to_end_a_sends_b_receipt.rs:109` asserts `verify_receipt(&r).expect()`; lines 125-143 independently compute sha256 and assert `ciphertext_hash` equality | closed |
| T-03-04-03 | DoS | MockTransport single-slot limitation leaks into real-DHT assumptions | accept | Test-harness limitation only; `phase3_share_ref_filter.rs` uses interleaved send-accept; `03-HUMAN-UAT.md` is canonical real-DHT accumulation check | closed |
| T-03-04-04 | Info Disclosure | HUMAN-UAT script leaks user data in committed results | accept | Ephemeral `mktemp -d` HOMEs per UAT session; throwaway identities have no long-term value disclosure; pattern is explicit and consistent with Phase 2 UAT | closed |
| T-03-04-05 | Tampering | Cross-test `CIPHERPOST_HOME` pollution causes flaky state | mitigate | All Phase 3 integration tests use `#[serial]` + `TempDir::new()` per identity + explicit `std::env::set_var` at each flow boundary | closed |

*Status: open · closed*
*Disposition: mitigate (implementation required) · accept (documented risk) · transfer (third-party)*

---

## Accepted Risks Log

| Risk ID | Threat Ref | Rationale | Accepted By | Date |
|---------|------------|-----------|-------------|------|
| AR-03-01 | T-03-01-05 | Receipts are social-layer attestations on a public DHT substrate (D-RS-06). All fields are public by design; no secret fields exist on `Receipt`. Zeroize discipline deliberately omitted. Shipped code confirmed to have no `#[serde(skip)]` secret fields. | johnzilla | 2026-04-21 |
| AR-03-02 | T-03-02-02 | Concurrent `publish_receipt` under the same recipient key may race (last-writer-wins) at the relay level. PKARR's `ConcurrencyError::{CasFailed,NotMostRecent,ConflictRisk}` is available but not adopted in the skeleton per D-MRG-02. CAS argument `Some(packet.timestamp())` is threaded through so v1.1+ can enable retry without a protocol change. Phase 4 THREAT-MODEL.md owns the prose. | johnzilla | 2026-04-21 |
| AR-03-03 | T-03-02-05 | Ledger rows at `~/.cipherpost/state/` (mode 0600, local-only) are the same disclosure surface as the decrypted material the user already chose to receive. `receipt_published_at` is a public-substrate timestamp, not a secret. Inherited Phase 2 posture. | johnzilla | 2026-04-21 |
| AR-03-04 | T-03-04-03 | MockTransport per-label single-slot is a test-harness limitation only, not production behavior. `phase3_share_ref_filter.rs` interleaves send-accept to work around it. The canonical real-DHT accumulation invariant is checked in `03-HUMAN-UAT.md`. | johnzilla | 2026-04-21 |
| AR-03-05 | T-03-04-04 | HUMAN-UAT scripts use `mktemp -d` for ephemeral `$HOME` per session; identities generated inside are throwaway with no long-term value disclosure. Pattern is explicit and matches Phase 2 UAT precedent. | johnzilla | 2026-04-21 |

---

## Security Audit Trail

| Audit Date | Threats Total | Closed | Open | Run By |
|------------|---------------|--------|------|--------|
| 2026-04-21 | 23 | 23 | 0 | gsd-security-auditor (sonnet) |

---

## Sign-Off

- [x] All threats have a disposition (mitigate / accept / transfer)
- [x] Accepted risks documented in Accepted Risks Log
- [x] `threats_open: 0` confirmed
- [x] `status: verified` set in frontmatter

**Approval:** verified 2026-04-21
