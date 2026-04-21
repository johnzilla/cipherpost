---
status: partial
phase: 01-foundation-scaffold-vendored-primitives-and-transport-seam
source: [01-VERIFICATION.md]
started: 2026-04-20T00:00:00Z
updated: 2026-04-20T00:00:00Z
---

## Current Test

[awaiting human testing]

## Tests

### 1. Interactive TTY passphrase prompt (IDENT-01)

expected: On a real terminal with no `CIPHERPOST_PASSPHRASE` env var set, `./target/release/cipherpost identity generate` prompts for the passphrase twice (via `dialoguer::Password`), writes the identity file at `~/.cipherpost/secret_key` with mode `0600`, and prints both the OpenSSH-style (`ed25519:SHA256:<base64>`) and z-base-32 PKARR fingerprints on success.
result: [pending]

**How to run:**
```
# Use a throwaway home to avoid touching your real ~/.cipherpost/
export HOME=$(mktemp -d)
./target/release/cipherpost identity generate
# Enter a passphrase twice when prompted
ls -l "$HOME/.cipherpost/secret_key"     # should be -rw------- (mode 0600)
./target/release/cipherpost identity show  # re-enter the passphrase; expect both fingerprints
```

**Why human:** The binary's `resolve_passphrase` falls through to `dialoguer::Password::interact()` only when no other passphrase source is available. Piping stdin causes dialoguer to reject with `"TTY not available for passphrase prompt"` — this is the only IDENT-01 code path that could not be driven automatically. All other paths (env var, file, fd, argv rejection) were verified with the live binary.

## Summary

total: 1
passed: 0
issues: 0
pending: 1
skipped: 0
blocked: 0

## Gaps
