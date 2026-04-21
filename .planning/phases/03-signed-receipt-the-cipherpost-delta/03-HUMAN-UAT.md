---
status: pending
phase: 03-signed-receipt-the-cipherpost-delta
source: [03-VERIFICATION.md]
started: 2026-04-21T00:00:00Z
updated: 2026-04-21T00:00:00Z
---

## Current Test

Pending — waiting on Plan 03-04 checkpoint approval before running.

## Tests

### 1. Real-DHT A→B→receipt round trip across two identities (RCPT-03 + TRANS-03)

expected: Two shells (or two distinct `CIPHERPOST_HOME` directories) simulate sender A and recipient B, both connected to Mainline DHT. A generates identity A (prints z32_a). B generates identity B (prints z32_b). A runs `cipherpost send --share <z32_b> -p 'phase3 receipt test' --material-file -` with a payload on stdin; Mainline DHT publish succeeds; the printed URI is handed to B out-of-band. B runs `cipherpost receive <URI>`, the acceptance banner shows A's fingerprint, B pastes A's z32 to accept, and B's stdout receives the payload bytes. B's stderr contains `Publishing receipt to DHT...` (step 13 TRANS-05 trace). A then runs `cipherpost receipts --from <z32_b>` and observes a structured table with at least one row whose `share_ref` prefix matches the URI's share_ref, `purpose` == `phase3 receipt test`, and `recipient_fp` == B's OpenSSH fingerprint. A re-runs with `--share-ref <full-hex>` and confirms the single-row audit-detail view shows ALL 10 Receipt fields. A re-runs with `--json` and confirms valid pretty-printed JSON on stdout.
result: pending
notes: —

**How to run:**
```
# Shell A (sender):
export HOME=$(mktemp -d); export CIPHERPOST_PASSPHRASE=alice
./target/release/cipherpost identity generate
# Note z32_a from the stderr output.

# Shell B (recipient), in a separate terminal:
export HOME=$(mktemp -d); export CIPHERPOST_PASSPHRASE=bob
./target/release/cipherpost identity generate
# Note z32_b from the stderr output.

# Back in Shell A: share to B.
URI=$(printf 'phase3 receipt payload' | ./target/release/cipherpost send --share <z32_b> -p 'phase3 receipt test' --material-file -)
echo "URI: $URI"

# In Shell B: receive with B's identity.
./target/release/cipherpost receive "$URI"
# Paste A's z32_a when prompted. Expect 'phase3 receipt payload' on stdout.
# Expect stderr line: 'Publishing receipt to DHT...' (TRANS-05)

# Back in Shell A: fetch + verify B's receipt.
./target/release/cipherpost receipts --from <z32_b>
# Expect table with share_ref prefix of the URI + purpose "phase3 receipt test" + B's fingerprint.

# Audit-detail view for the specific share:
./target/release/cipherpost receipts --from <z32_b> --share-ref <full-share_ref-hex>
# Expect 10-row audit detail with sender_pubkey, recipient_pubkey, ciphertext_hash, cleartext_hash, nonce, etc.

# Machine-readable:
./target/release/cipherpost receipts --from <z32_b> --json
# Expect pretty-printed JSON array with at least 1 object containing 10 keys.
```

**Why human:** Requires real Mainline DHT connectivity, two coordinated terminals, and a real cross-identity z32 paste into the acceptance banner. The automated MockTransport integration tests (phase3_end_to_end_a_sends_b_receipt, phase3_coexistence_b_self_share_and_receipt, phase3_share_ref_filter, phase3_tamper_zero_receipts) cover every cryptographic and flow-ordering assertion; what remains human-only is (a) confirming the full real-DHT publish-then-resolve path works across two nodes, (b) the `cipherpost receipts` CLI output is human-readable on an 80-col terminal, and (c) the `Publishing receipt to DHT...` stderr trace appears at the right moment (between acceptance and exit).

### 2. Optional: coexistence of B's outgoing share + incoming receipt on the real DHT

expected: B first runs `cipherpost send --self` to establish a self-share under B's key. B then runs the Test 1 receive to accept A's share. A (or any third party with B's z32) then runs `pkarrctl resolve <z32_b>` (if installed) and observes BOTH the `_cipherpost` label AND the `_cprcpt-<ref>` label under B's key.
result: pending
notes: Optional — defer if not needed right now. Covered by automated `phase3_coexistence_b_self_share_and_receipt.rs` against MockTransport.

**How to run:**
```
# Shell B, before running Test 1:
printf 'b self note' | ./target/release/cipherpost send --self -p 'b self' --material-file -
# Note the URI; confirms B's key has a _cipherpost label.

# Now run Test 1 above.

# After B accepts, query B's z32 via a DHT tool:
pkarrctl resolve <z32_b>
# Expect at least 2 TXT records: _cipherpost.<z32_b> AND _cprcpt-<share_ref>.<z32_b>
```

**Why human:** DHT observation tooling varies per environment; confirming the two-label coexistence on real infrastructure cannot be automated without adding a DHT dep to the test harness.

## Summary

total: 2
passed: 0
issues: 0
pending: 2
skipped: 0
blocked: 0
