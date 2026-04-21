---
status: partial
phase: 02-send-receive-and-explicit-acceptance
source: [02-VERIFICATION.md]
started: 2026-04-21T00:00:00Z
updated: 2026-04-21T00:00:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Interactive TTY acceptance-screen happy path (RECV-04 + D-ACCEPT-01/02/03)

expected: On a real terminal, `cipherpost send --self` publishes a share to Mainline DHT and prints a `cipherpost://...` URI. In the same terminal (so stdin/stderr are TTYs), `cipherpost receive <URI>` renders the D-ACCEPT-02 bordered banner on stderr with all rows present (Purpose, Sender OpenSSH+z32, Share ref, Type, Size, TTL with UTC expiry). Pasting the sender's z-base-32 pubkey and pressing Enter writes the decrypted `secret bytes` to stdout and the process exits 0. A sentinel file appears at `$CIPHERPOST_HOME/.cipherpost/state/accepted/<share_ref>` mode 0600 and a JSONL ledger line is appended to `$CIPHERPOST_HOME/.cipherpost/state/accepted.jsonl`.
result: [pending]

**How to run:**
```
# Use a throwaway HOME to avoid touching your real ~/.cipherpost/
export HOME=$(mktemp -d)
export CIPHERPOST_PASSPHRASE=test

./target/release/cipherpost identity generate
# Note the z32 fingerprint printed on stderr.

# Publish a self-share with some material via process-substitution stdin.
URI=$(printf 'secret bytes' | ./target/release/cipherpost send --self -p 'acceptance screen test' --material-file -)
echo "Share URI: $URI"

# Receive in the same terminal (TTY on stdin and stderr required by D-ACCEPT-03).
./target/release/cipherpost receive "$URI"
# When prompted, paste the sender z32 (shown in the banner). Press Enter.
# Expect: 'secret bytes' on stdout, exit 0, no ANSI colors in the banner.

# Verify state-ledger side effects:
ls -l "$HOME/.cipherpost/state/accepted/"        # should list the share_ref (mode 0600)
cat "$HOME/.cipherpost/state/accepted.jsonl"     # one JSONL line with sha256s and accepted_at
```

**Why human:** The banner's visual rendering and the `dialoguer::Input` typed-confirmation cannot be driven by `assert_cmd` without a PTY library. `assert_cmd` pipes stdin/stderr which makes them non-TTYs, and the production build's TTY pre-check (D-ACCEPT-03) refuses to proceed without both stdin and stderr being real terminals. Automated tests cover the decline path (library-level `DeclinePrompter` → exit 7) and the pre-TtyPrompter CLI error paths (missing / malformed URI → exit 1); the library-level unit test `tty_prompter_rejects_non_tty_env` in `src/flow.rs` authoritatively verifies the D-ACCEPT-03 error message. What remains human-only is confirming the banner *looks right* on a real terminal and that the paste-z32-then-Enter flow behaves as specified.

### 2. Real-DHT round trip across two identities (optional)

expected: Two shells (or two distinct `CIPHERPOST_HOME` directories) simulate sender A and recipient B. A generates identity A (prints z32_a). B generates identity B (prints z32_b). A runs `cipherpost send --share <z32_b> -p 'recipient test' --material-file -` with a payload on stdin; Mainline DHT publish succeeds; the printed URI is handed to B out-of-band. B runs `cipherpost receive <URI>`, the acceptance banner shows A's fingerprint, B pastes A's z32 to accept, and B's stdout receives the payload bytes. Both halves touch real Mainline DHT (no MockTransport).
result: [pending]

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
URI=$(printf 'recipient payload' | ./target/release/cipherpost send --share <z32_b> -p 'recipient test' --material-file -)
echo "URI: $URI"

# In Shell B: receive with B's identity.
./target/release/cipherpost receive "$URI"
# Paste A's z32_a when prompted. Expect 'recipient payload' on stdout.
```

**Why human:** Requires DHT connectivity, two coordinated terminals, and real cross-identity z32 paste. Out of scope for CI. Optional — defer if not needed right now.

## Summary

total: 2
passed: 0
issues: 0
pending: 2
skipped: 0
blocked: 0

## Gaps
