---
phase: 04-protocol-documentation-drafts
plan: "02"
subsystem: documentation
tags: [docs, spec, wire-format, test-vectors, lineage]
dependency_graph:
  requires: [04-01]
  provides: [SPEC.md]
  affects: [04-03-PLAN.md, 04-04-PLAN.md]
tech_stack:
  added: []
  patterns: [RFC 8785 JCS, inline test vectors, decision-ID citation discipline]
key_files:
  created:
    - SPEC.md
    - tests/spec_test_vectors.rs
  modified:
    - Cargo.toml
decisions:
  - "SPEC.md §8 test vectors use [0u8;32] seed — ed25519-dalek 3.0.0-pre.5 accepts all-zero seed at construction time; SHA-256 fallback not needed"
  - "Cargo fmt applied to all pre-existing formatting drift in one commit alongside SPEC.md to keep CI green"
metrics:
  duration: "~25 minutes"
  completed: "2026-04-22"
  tasks_completed: 2
  files_changed: 24
---

# Phase 04 Plan 02: Draft SPEC.md Summary

**One-liner:** Wrote 535-line SPEC.md draft documenting all 9 protocol sections — wire format,
share URI, receive flow, exit codes, passphrase contract, inline test vectors, lineage — with
74 Phase 1–3 decision ID citations and reproducible Ed25519 test-vector signatures.

## What Was Built

`SPEC.md` at the repo root is a complete protocol specification covering:

- §1 Introduction: purpose, dual-signature model, sender-attested purpose caveat (PITFALL #12),
  64 KB plaintext cap, ~1000-byte wire budget, receipt attestation
- §2 Terminology: 12 terms defined including JCS, PKARR, share_ref, sender-attested purpose
- §3 Wire Format: 4 sub-sections with field tables for Envelope, Material, OuterRecord, Receipt;
  share_ref derivation; `OuterRecordSignable` and `ReceiptSignable` signable projections;
  receipt resolve-merge-republish semantics
- §4 Share URI: `cipherpost://<z32>/<hex>` format, strict parsing, ShareRefMismatch error
- §5 Flows: 8-step send, 13-step receive (strict verify-before-reveal), 6-step receipts dispatch
- §6 Exit Codes: 7-row table matching `src/error.rs::exit_code` verbatim
- §7 Passphrase Contract: 5 sub-sections covering 4 acceptable sources, inline argv rejection,
  TTY requirement, wrong passphrase behavior, identity file permissions
- §8 Appendix Test Vectors: inline hex for both JCS fixtures + reproducible Ed25519 signatures
  with committed `#[ignore]` test to regenerate
- §9 Lineage: cclink citation, v1.3.0 fork point, `cipherpost/v1` HKDF domain separation delta

## Decision IDs Cited in §3 Field Tables

The following decision IDs appear in the `Source decision` columns of §3's field tables.
This roll-call helps THREAT-MODEL.md (Plan 04-03) avoid re-citing or missing these:

**§3.1 Envelope:** D-WIRE-02, PAYL-01, D-WIRE-03, PAYL-02, D-07, D-WIRE-05, PAYL-04

**§3.2 Material:** D-WIRE-03, D-WIRE-04

**§3.3 OuterRecord:** D-WIRE-01, D-WIRE-04, D-WIRE-02, D-07, D-04, IDENT-05, D-06, PAYL-05,
D-WIRE-03, SEND-04, D-16, SEND-03

**§3.4 Receipt:** D-RS-02, D-RS-04, D-RS-03, D-07, D-RS-01, D-WIRE-05, D-RS-07, D-06, D-RS-05

**Additional citations in §5 Flows (step annotations):**
D-PS-01, SEND-01, PAYL-03, D-URI-03, RECV-06, D-RECV-02, D-STATE-01, D-ACCEPT-02,
D-ACCEPT-03, D-ACCEPT-01, RECV-04, RECV-05, D-SEQ-04, D-SEQ-05, D-SEQ-02, D-SEQ-03,
D-URI-02, D-MRG-01..06, D-SEQ-01

**Total D-citation occurrences in SPEC.md:** 74 (grep -cE pattern from acceptance criteria)

## Test Vector Signatures (for regression reference)

These are the base64 Ed25519 signatures committed in SPEC.md §8.
Keypair: `SigningKey::from_bytes(&[0u8; 32])` — TEST VECTOR ONLY.

**OUTER_SIG_B64 (OuterRecordSignable, 192 bytes):**
```
B1KQKUwXEHBLlXNekjU23LM+hkwz2w1XGjYg/X27tZSbX9opQozRgxKoVaAFbxmvfP2+HbOssOJ4DblpgcPdDw==
```

**RECEIPT_SIG_B64 (ReceiptSignable, 424 bytes):**
```
L8UWu/lYccsfB3pwZD6hoPu39ZWuNYt0/SRqDtI+xMpL7Z91Lof8vnFjFY2WtlQDDlZOH4H0srwf4LlmT6w7Aw==
```

Regenerate with:
```
cargo test --features mock gen_spec_test_vectors -- --ignored --nocapture
```

## Fixture Size Verification

- `tests/fixtures/outer_record_signable.bin`: 192 bytes (matches §8.1 — no drift)
- `tests/fixtures/receipt_signable.bin`: 424 bytes (matches §8.2 — no drift)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 2 - Missing CI compliance] Apply pre-existing cargo fmt drift**
- **Found during:** Task 1 — `cargo fmt --all -- --check` failed on existing source files
- **Issue:** Many files in `src/` and `tests/` had formatting that didn't match `rustfmt`'s
  current output; these were pre-existing from earlier phases. Running fmt --check would
  fail CI for any PR that touched these files.
- **Fix:** Applied `cargo fmt --all` to normalize all drift. No logic changes — formatting only.
- **Files modified:** build.rs, src/crypto.rs, src/error.rs, src/flow.rs, src/identity.rs,
  src/main.rs, src/receipt.rs, src/record.rs, src/transport.rs, and 13 test files.
- **Commit:** 70af7b1 (included in the same SPEC.md commit)

**2. No all-zero seed rejection** — `ed25519-dalek =3.0.0-pre.5` accepts `[0u8; 32]` without
error. SHA-256 fallback seed derivation documented in the plan was not needed. SPEC.md §8
correctly documents the `[0u8; 32]` direct path.

## Known Stubs

None — SPEC.md is a documentation artifact with no data flow to UI. All inline content
(field values, hex, signatures) is derived from committed fixtures and live test output.

## Threat Flags

None — SPEC.md is a read-only document that adds no execution surface, network endpoints,
or auth paths.

## Self-Check: PASSED

- `SPEC.md` exists at `/home/john/vault/projects/github.com/cipherpost/SPEC.md`: FOUND
- `tests/spec_test_vectors.rs` exists: FOUND
- Commit 70af7b1 exists: FOUND
- `wc -l SPEC.md` = 535 (≥400 requirement: PASS)
- `grep -c "| Source decision |" SPEC.md` = 4 (4 field tables, one per §3 sub-section: PASS)
- `grep -c "github.com/johnzilla/cclink" SPEC.md` = 1: PASS
- `grep -c "cclink v1.3.0" SPEC.md` = 1: PASS
- D-citation count (grep -cE pattern) = 74 (≥30 requirement: PASS)
- No `<paste` placeholder text: PASS
- Base64 signature lines (88 chars): 2: PASS
- `cargo build --release`: PASS
- `cargo fmt --all -- --check`: PASS
- `cargo clippy --all-targets --all-features -- -D warnings`: PASS
- `cargo test gen_spec_test_vectors -- --ignored --nocapture`: signatures match SPEC.md §8: PASS
