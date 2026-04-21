# Phase 2: Send, receive, and explicit acceptance - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-04-21
**Phase:** 02-send-receive-and-explicit-acceptance
**Areas discussed:** Payload size model, Share URI format, Payload wire format, Acceptance + re-receive state

---

## Area selection

| Option | Description | Selected |
|--------|-------------|----------|
| Payload size model | 64 KB PRD cap vs ~1000 byte PKARR wire budget; blocking | ✓ |
| Share URI format | What `send` prints and `receive` accepts | ✓ |
| Payload wire format | Envelope binding + Material serde shape | ✓ |
| Acceptance + re-receive state | Confirmation token, screen layout, RECV-06 state | ✓ |

**User's choice:** All four. Multi-select.

---

## Payload size model

### Cap strategy

| Option | Description | Selected |
|--------|-------------|----------|
| Honor 64 KB, fail at publish (Recommended) | Two-layer: plaintext 64 KB cap + distinct wire-budget error | ✓ |
| Lower cap to realistic wire budget | Single cap at ~512 bytes, rewrite PROJECT.md | |
| Compress before encrypt | zstd/brotli the envelope before age-encrypt | |
| Defer actual cap number to planning | Commit to two-layer; planner picks numbers | |

**User's choice:** Honor 64 KB, fail at publish.

### Over-budget behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Reject with sized error (Recommended) | Fail naming actual size and wire budget | ✓ |
| Reject and suggest chunking (v1.1+) | Same but name future `--chunk` flag | |
| Warn and publish anyway | pkarr rejects at its layer | |

**User's choice:** Reject with sized error.

### Size-cap test shape

| Option | Description | Selected |
|--------|-------------|----------|
| 65537 bytes plaintext rejected before encrypt (Recommended) | Per ROADMAP SC4; pure client-side check | ✓ |
| 65537 bytes + real wire-budget test in one | Two tests in the same file | |
| Just the 65537 case for skeleton | Skip wire-budget integration test in Phase 2 | |

**User's choice:** 65537 bytes plaintext rejected before encrypt.

**Notes:** Phase 1's `signed_packet_budget.rs` already covers SignedPacket size for a representative payload; Phase 2 extends with the 65537-byte plaintext pre-encrypt check and a separate targeted wire-budget-exceeded integration case (planner-scoped).

---

## Share URI format

### URI shape

| Option | Description | Selected |
|--------|-------------|----------|
| Scheme URI with share_ref (Recommended) | `cipherpost://<z32>/<share_ref_hex>`; ~99 chars; supports URI-vs-record integrity check | ✓ |
| Scheme URI, no share_ref | `cipherpost://<z32>`; ~64 chars; no republish-race defense | |
| Bare z32 pubkey | 52 chars; no protocol marker | |
| Scheme URI with share_ref as fragment | `cipherpost://<z32>#<share_ref_hex>`; RFC-fragment-semantics variant | |

**User's choice:** Scheme URI with share_ref.

### share_ref mismatch behavior

| Option | Description | Selected |
|--------|-------------|----------|
| Abort with distinct error (Recommended) | New `ShareRefMismatch` variant; exit 1; not sig-failure | ✓ |
| Warn and proceed | Print stderr warning, continue | |
| Silently use resolved record's share_ref | Ignore URI hint | |

**User's choice:** Abort with distinct error.

### Accept bare z32 input

| Option | Description | Selected |
|--------|-------------|----------|
| Require full URI (Recommended) | Strict: refuse bare z32 | ✓ |
| Accept both forms | Tolerate bare z32 as ergonomic shortcut | |
| Require URI; fallback to bare z32 with warning | Middle ground | |

**User's choice:** Require full URI.

---

## Payload wire format

### Envelope binding approach

| Option | Description | Selected |
|--------|-------------|----------|
| Implicit via age AEAD + outer sig over blob (Recommended) | OuterRecordSignable unchanged; rely on age Poly1305 + outer sig covering blob | ✓ |
| Add ciphertext_hash commitment | Redundant with outer-sig-over-blob but pre-decrypt handle for Receipt | |
| Add ciphertext_hash AND cleartext_hash | Sender pre-commits to both; minor metadata leakage concern | |
| Add a separate inner-inner Ed25519 sig over Envelope | Three-sig design; overkill per SEND-04 | |

**User's choice:** Implicit via age AEAD + outer sig over blob.

### Material enum serde tag style

| Option | Description | Selected |
|--------|-------------|----------|
| Internal tag with snake_case types (Recommended) | `{"type": "generic_secret", "bytes": "..."}` | ✓ |
| Adjacently tagged | `{"type": "generic_secret", "data": {"bytes": "..."}}` | |
| Externally tagged (serde default) | `{"generic_secret": {"bytes": "..."}}` | |

**User's choice:** Internal tag with snake_case types.

### GenericSecret.bytes encoding

| Option | Description | Selected |
|--------|-------------|----------|
| Base64 standard with padding (Recommended) | `base64::engine::general_purpose::STANDARD`; matches Phase 1 codec | ✓ |
| Base64 URL-safe no padding | `URL_SAFE_NO_PAD`; second codec in codebase | |
| Lowercase hex | 2x size | |
| Serde default (JSON array of u8) | `[97, 98, 99]`; bloats the budget | |

**User's choice:** Base64 standard with padding.

---

## Acceptance + re-receive state

### Confirmation token

| Option | Description | Selected |
|--------|-------------|----------|
| Type the sender's full z32 pubkey (Recommended) | Constant 52 chars; max anti-phishing | ✓ |
| Type the purpose string | PITFALLS echo-back recommendation; variable friction | |
| Type a fixed word `accept` | Weakest anti-phishing | |
| Type sender's z32 AND echo purpose | Two-stage; strongest but most annoying | |

**User's choice:** Type the sender's full z32 pubkey.

### Acceptance screen layout

| Option | Description | Selected |
|--------|-------------|----------|
| Bordered box with labeled rows (Recommended) | Stable delimiters + labels; stderr-only; purpose in explicit quotes | ✓ |
| Flat list, no borders | Less visual noise; weaker visual boundary | |
| JSON-ish pretty-print | Machine-friendly, human-odd | |

**User's choice:** Bordered box with labeled rows.

### Local state format

| Option | Description | Selected |
|--------|-------------|----------|
| JSONL ledger + fingerprint file (Recommended) | `accepted.jsonl` append log + `accepted/<share_ref>` empty sentinel | ✓ |
| JSONL only | Ledger alone; O(N) per receive | |
| Per-share files only | One file per accepted share; no audit view | |
| SQLite | Adds dep; overkill | |

**User's choice:** JSONL ledger + fingerprint file.

### TTY requirement

| Option | Description | Selected |
|--------|-------------|----------|
| TTY-required; abort on non-TTY (Recommended) | Consistent with passphrase policy; V2-OPS-02 | ✓ |
| TTY-required for prompt, allow --yes | Explicit Pitfall #6 violation | |
| Read confirmation from stdin if no TTY | Collides with stdout-payload path | |

**User's choice:** TTY-required; abort on non-TTY.

---

## Final sign-off

| Option | Description | Selected |
|--------|-------------|----------|
| I'm ready for context | Write CONTEXT.md with current decisions | ✓ |
| Explore more gray areas | Surface additional ambiguities (TTL parse, version format, etc.) | |

**User's choice:** I'm ready for context. Remaining small-ticket items (TTL parse format, version output format, stdout-to-TTY safety, exact --dht-timeout override, acceptance-screen TTL-remaining formatting) captured as Claude's Discretion in CONTEXT.md.

---

## Claude's Discretion (carried to CONTEXT.md)

- `--ttl` parse format (seconds-only vs humanized like `24h`/`2d`)
- `cipherpost version` exact output format (lines vs `--json`)
- Stdout-to-TTY safety check for decrypted payload
- `--dht-timeout` inheritance and per-command override
- Unknown-trailing-component behavior on URI parsing (forward-compat rule)
- Exact `Error::Config` text for TTY-required failures
- Acceptance-screen TTL-remaining rendering

## Deferred Ideas (carried to CONTEXT.md)

- Multi-packet chunking (`--chunk`, v1.1+)
- Compression before encrypt (zstd/brotli, post-skeleton)
- State ledger rotation / GC (reconsider after real-use telemetry)
- State-store encryption at rest (v1.0)
- Receipt publishing on acceptance (Phase 3)
- `cipherpost list` command (backlog)
- Sender-side publish-and-retry on DHT failure (v1.0)
- `cipherpost version --json`
- Encrypt-then-sign for inner layer (v2 protocol consideration)
