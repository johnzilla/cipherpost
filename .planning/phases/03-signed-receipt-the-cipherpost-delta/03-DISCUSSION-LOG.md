# Phase 3: Signed receipt — the cipherpost delta - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-21
**Phase:** 03-signed-receipt-the-cipherpost-delta
**Areas discussed:** Receipt wire schema, publish_receipt merge, Publish sequencing + failure, receipts output + verify

---

## Gray area selection

| Option | Description | Selected |
|--------|-------------|----------|
| Receipt wire schema | Field ordering, nonce semantics, accepted_at encoding, sig encoding. Locks bytes Ed25519 signs. | ✓ |
| publish_receipt merge | TRANS-03 resolve-merge-republish preserving existing TXT records. Concurrent-publish races. Research-flagged prototype. | ✓ |
| Publish sequencing + failure | Where in run_receive the publish goes; failure handling (warn/retry/fail); ledger evolution. | ✓ |
| receipts output + verify | Output format (table/JSON), fields shown, bad-sig handling, integration test scope. | ✓ |

**User's choice:** all four selected.

---

## Receipt wire schema

### Q1: How should `accepted_at` be encoded in the signed Receipt on the wire?

| Option | Description | Selected |
|--------|-------------|----------|
| i64 unix seconds | Matches OuterRecord.created_at precedent; int on wire; JCS-stable; ledger's ISO-8601 stays local. | ✓ |
| ISO-8601 UTC string | Mirrors ledger format; adds string-format fragility on wire. | |
| Both fields | accepted_at_unix + accepted_at_iso; belt-and-suspenders; redundancy risk. | |

**User's choice:** i64 unix seconds (Recommended).

### Q2: Nonce width + encoding + purpose?

| Option | Description | Selected |
|--------|-------------|----------|
| 128-bit random, hex | Same codec as share_ref; birthday bound at 2^64 receipts. | ✓ |
| 256-bit random, hex | More headroom; 16 more wire bytes. | |
| 128-bit random, base64 STANDARD | Consistent with blob/sig codec; less consistent with share_ref hex. | |

**User's choice:** 128-bit random, hex (Recommended).

### Q3: Receipt struct split pattern?

| Option | Description | Selected |
|--------|-------------|----------|
| Receipt + ReceiptSignable | Two structs mirror OuterRecord/OuterRecordSignable; alphabetical; JCS-sign Signable form. | ✓ |
| Single Receipt with Option<String> signature | One struct; risks serializing with sig=Some during signing. | |

**User's choice:** Receipt + ReceiptSignable (Recommended).

### Q4: How should `ciphertext_hash` and `cleartext_hash` be encoded?

| Option | Description | Selected |
|--------|-------------|----------|
| Raw sha256 hex | 64-char lowercase; matches Phase 2 ledger exactly; algorithm gated by protocol_version. | ✓ |
| Prefixed `sha256:<hex>` | Multihash-lite; 7 extra chars per hash; forward-compat (but protocol_version already gates). | |

**User's choice:** Raw sha256 hex (Recommended).

### Q5: Additions to the RCPT-01 field list?

| Option | Description | Selected |
|--------|-------------|----------|
| Lock RCPT-01 exactly | 10 fields as enumerated; alphabetical; simple SPEC.md. | ✓ |
| Add receipt_version | Separate from protocol_version; lets receipts evolve independently. | |
| Add sender_share_uri | Makes receipt self-contained; costs ~99 bytes per receipt. | |

**User's choice:** Lock RCPT-01 exactly (Recommended).

### Q6: Receipt wire schema — done, or more to discuss?

**User's choice:** Done — next area (Recommended).

---

## publish_receipt merge

### Q1: How should DhtTransport::publish_receipt preserve existing TXT records under the recipient's PKARR key?

| Option | Description | Selected |
|--------|-------------|----------|
| Resolve → rebuild builder → re-sign | resolve_most_recent; iterate all records; re-add via builder.txt(...); replace existing _cprcpt-<ref>; re-sign. | ✓ |
| Resolve → copy raw records via builder().rrs() | Bulk-copy API if pkarr exposes it; spike needed. | |
| Do not merge — clobber | Simpler code; violates TRANS-03 and breaks coexistence. Not viable. | |

**User's choice:** Resolve → rebuild builder → re-sign (Recommended).

### Q2: How should concurrent publish_receipt calls be handled?

| Option | Description | Selected |
|--------|-------------|----------|
| Document as known limitation | 1-100 shares/week/user; concurrent accepts rare; SPEC.md/THREAT-MODEL.md note. | ✓ |
| Retry on PublishError — re-resolve + re-publish up to N times | Optimistic concurrency loop; doesn't eliminate cross-DHT race. | |
| In-process mutex | Serializes same-process only; doesn't help cross-process. | |

**User's choice:** Document as known limitation (Recommended).

### Q3: TXT TTL on published receipts?

| Option | Description | Selected |
|--------|-------------|----------|
| 300 seconds | Matches outer-share TTL; one constant; consistent. | ✓ |
| 86400 (24h) | Longer stale-serving; receipts are signed + public, staleness OK. | |
| 3600 (1h) | Compromise; no rationale; third TTL constant. | |

**User's choice:** 300 seconds (Recommended).

### Q4: The pkarr 5.0.3 SignedPacket iteration API is unconfirmed — how should planning handle it?

| Option | Description | Selected |
|--------|-------------|----------|
| Planner researches + small prototype | First task: confirm all-records iterator + builder round-trip; fallback to known-labels if needed. | ✓ |
| Enumerate known labels only | Explicit _cipherpost + _cprcpt-* walk; forward-compat foot-gun. | |
| Assume builder API supports pass-through | Plan as if .rrs(slice) works; fix during execution. | |

**User's choice:** Planner researches + small prototype (Recommended).

### Q5: publish_receipt merge — done, or more to discuss?

**User's choice:** Done — next area (Recommended).

---

## Publish sequencing + failure

### Q1: Where in run_receive does the receipt publish fit?

| Option | Description | Selected |
|--------|-------------|----------|
| After ledger write | write_output → sentinel → ledger → publish_receipt; local state durable first. | ✓ |
| Before sentinel, as part of acceptance | decrypt → confirm → publish → write_output → sentinel → ledger; receipt load-bearing; risk losing material on network failure. | |
| Between sentinel and ledger | Tri-state reasoning; subtle. | |

**User's choice:** After ledger write (Recommended).

### Q2: Receipt publish fails — how to handle?

| Option | Description | Selected |
|--------|-------------|----------|
| Warn + degrade, exit 0 | Material already delivered; stderr warn; ledger records null; sender can request republish. | ✓ |
| Hard-fail, exit 6 | Confusing semantics — material already on stdout. | |
| Auto-retry N times with backoff | Complexity for rare case. | |

**User's choice:** Warn + degrade, exit 0 (Recommended).

### Q3: How should the ledger record the receipt-publish outcome?

| Option | Description | Selected |
|--------|-------------|----------|
| Add receipt_published_at field only | Optional ISO-8601 UTC on success; null on failure; backwards-compat. | ✓ |
| Add receipt_published_at + receipt_publish_error | Error details persisted; leaks internal strings. | |
| Side-log to receipts_published.jsonl | Keeps Phase 2 ledger untouched; two files. | |

**User's choice:** Add receipt_published_at field only (Recommended).

### Q4: In self-mode (sender == recipient), should the receipt still be published?

| Option | Description | Selected |
|--------|-------------|----------|
| Yes, same path | Personal audit log; no special case. | ✓ |
| Skip publish in self-mode | Redundant with ledger; saves round-trip; adds branch + SPEC.md note. | |

**User's choice:** Yes, same path (Recommended).

### Q5: Publish sequencing + failure — done?

**User's choice:** Done — next area (Recommended).

---

## receipts output + verify

### Q1: `cipherpost receipts --from <z32>` default output shape?

| Option | Description | Selected |
|--------|-------------|----------|
| Human table; --json flag | Table default; JCS JSON array on --json; status to stderr; pipeable. | ✓ |
| JSON default; --table flag | Machine-first; costs humans. | |
| Both streams | Two streams; complex. | |

**User's choice:** Human table; --json flag (Recommended).

### Q2: Which fields go in the default human table row?

| Option | Description | Selected |
|--------|-------------|----------|
| share_ref (16-hex) + accepted_at local+UTC + purpose truncated + recipient fp | Matches RCPT-02 literal + purpose context; --json for full fields. | ✓ |
| Above + ciphertext_hash + cleartext_hash | Audit completeness; table gets wide. | |
| Minimal: share_ref + accepted_at only | Strict RCPT-02 literal; no purpose context. | |

**User's choice:** share_ref (16-hex), accepted_at local+UTC, purpose (truncated), recipient fp (Recommended).

### Q3: A fetched receipt fails signature verification — how?

| Option | Description | Selected |
|--------|-------------|----------|
| Warn to stderr, skip, exit 0 if any verify | Valid listed; stderr summary; exit 3 only if all fail. | ✓ |
| Abort on first failure, exit 3 | Paranoid; loses benign-corruption info. | |
| Include in output marked `INVALID` | Extra column; risk of user missing distinction. | |

**User's choice:** Warn to stderr, skip, exit 0 if any verify (Recommended).

### Q4: Minimum RCPT-03 / TRANS-03 integration test scope?

| Option | Description | Selected |
|--------|-------------|----------|
| Three MockTransport + 1 Human UAT | A→B round trip; TRANS-03 coexistence; --share-ref filter + sender self-share; plus real-DHT UAT. | ✓ |
| Three MockTransport only | Deferred real-DHT test; breaks Phase 1/2 pattern. | |
| Above + tamper test | Fourth test for byte-flipped receipt; good defense-in-depth. | |

**User's choice:** Three MockTransport + 1 Human UAT (Recommended).

### Q5: All four gray areas discussed — ready to write CONTEXT.md?

**User's choice:** Write CONTEXT.md (Recommended).

---

## Claude's Discretion

Areas explicitly flagged for planner/executor latitude in CONTEXT.md `<decisions>`:

- pkarr 5.0.3 SignedPacket iteration API (actual method names; prototype owns this)
- rand source wiring for nonce generation (OsRng vs HKDF-derived)
- Table column widths / truncation lengths
- Ledger append-line strategy vs in-place rewrite for `receipt_published_at`
- Error variant choice for publish failure (Transport vs Network vs new)
- `--json` output canonicalization (JCS vs pretty-printed)
- Receipts stable ordering (by share_ref vs by accepted_at vs resolve order)
- Human-UAT exact script

## Deferred Ideas

See CONTEXT.md `<deferred>` section for the full list (12 deferred items).
