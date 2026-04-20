# Pitfalls Research

**Domain:** Self-sovereign cryptographic-material handoff (Rust CLI, Mainline DHT + PKARR + age + Ed25519)
**Researched:** 2026-04-20
**Confidence:** MEDIUM–HIGH (high on crypto/Rust practice; medium on DHT empirical characteristics — academic numbers are 2011–2014 vintage; PKARR-specific observations limited)

> **How to read this file.** Each pitfall lists a one-line **prevention test** in bold — something a phase verification step can actually check. Pitfalls are grouped by severity. The Pitfall-to-Phase Mapping at the bottom is the authoritative list for roadmap planning.

---

## Critical Pitfalls

These are the pitfalls where a mistake at the walking-skeleton stage permanently compromises trust. Get them right the first time; do not plan to "fix them in v1.0."

### Pitfall 1: Ed25519 → X25519 conversion done with raw scalar instead of the spec'd conversion

**What goes wrong:**
age needs an X25519 (Montgomery curve) keypair to encrypt to; the identity is Ed25519 (Edwards curve). A naive implementation reuses the Ed25519 secret scalar directly as an X25519 private key. This produces wrong (or worse, subtly valid-looking but non-matching) X25519 keys and silently breaks the `--share <pubkey>` round trip — or, in the bad case, produces keys that work but don't have the security properties users assume.

**Why it happens:**
Both curves "use 32-byte keys and are Curve25519-adjacent," so developers assume they're interchangeable. They aren't: Ed25519 secret keys are hashed (SHA-512, clamped) before use; the X25519 scalar is the clamped first half of that hash, not the raw secret seed. Public-key conversion is a map from Edwards (x,y) to Montgomery u, with a sign choice that matters.

**How to avoid:**
Use libsodium's `crypto_sign_ed25519_sk_to_curve25519` / `_pk_to_curve25519` semantics (or the equivalent in `ed25519-dalek` + `x25519-dalek` via the `curve25519-dalek` conversion helpers). Never do the math by hand. Write a round-trip unit test: generate Ed25519 identity → derive X25519 → age-encrypt a known plaintext to the derived recipient → age-decrypt with the derived identity → assert equality. Run the same test against a second independent implementation (cclink's existing code, or a Python pynacl script) and assert keys match byte-for-byte.

**Prevention test:** **A byte-for-byte cross-implementation test confirms our Ed25519 → X25519 conversion matches libsodium's reference output.**

**Warning signs:**
- Any code path computing X25519 keys from Ed25519 keys that doesn't go through a named `ed25519_*_to_curve25519` function.
- Tests that only check self-encryption round trip (passes even with wrong conversion, because both sides use the same wrong math).
- No cross-implementation fixture test.

**Phase to address:** **Skeleton** (self-mode round trip exercises the conversion; share-mode makes it load-bearing).

---

### Pitfall 2: Dual-signature verification in the wrong order — inner-signature check after decrypt

**What goes wrong:**
The protocol has two signatures: the PKARR SignedPacket's outer Ed25519 signature (over the DNS-encoded packet, verified by the DHT machinery) and an inner Ed25519 signature over the canonical-JSON payload before encryption. If the receiver verifies the outer signature, then decrypts, then verifies the inner signature against the cleartext, an attacker who can forge or replay an outer packet (or a compromised relay) can feed arbitrary ciphertext into the recipient's age library. Any parser bug, panic, or side-channel in age is now reachable by a forgery.

**Why it happens:**
"Verify signature" and "decrypt" feel like independent operations. The natural code shape is `fetch → verify_outer → decrypt → verify_inner → return`. That order is wrong whenever the inner signature is computable before encryption — which it is here.

**How to avoid:**
Sign-then-encrypt means the inner signature is over cleartext, so you must decrypt before you can verify it — that's unavoidable for the inner check. The fix is not order but discipline:
1. Inner signature verification MUST happen before any payload field (including `purpose`) is surfaced to the user or acted on.
2. Outer signature verification MUST happen before decryption is attempted.
3. If either check fails, zeroize the decrypted buffer immediately and return a single opaque error — no partial data, no "purpose was X but signature was bad" leakage.
4. Consider encrypt-then-sign for the inner layer in a future spec revision (sign the ciphertext, not the cleartext) so that inner verification can happen before decrypt. Flag this for SPEC.md discussion.

**Prevention test:** **A fuzzing test flips one bit in the ciphertext and asserts no payload fields (including `purpose`) are exposed to the caller before the inner signature check completes.**

**Warning signs:**
- `receive` function returns a `Payload` struct whose fields (purpose, sender, material) are populated before the final verify call.
- Error messages that distinguish "bad signature" from "bad ciphertext" (leaks which check failed).
- Any code path that logs `purpose` before inner verification.

**Phase to address:** **Skeleton** (share-mode implements dual-signature verification; this is the highest-impact bug class).

---

### Pitfall 3: Canonical JSON implemented with `serde_json` without canonicalization — signature bypass

**What goes wrong:**
Inner signature is over "canonical JSON." Naive implementations call `serde_json::to_string(&payload)` and sign the result. `serde_json` is not canonical: it preserves source map ordering (non-deterministic in general), emits non-minimal whitespace in some modes, does not sort keys, and — crucially — round-trips floats with platform-dependent precision and non-ASCII strings without NFC normalization. A signer and verifier using the same `serde_json` version on the same platform may agree; swap out the library, language, or platform, and signatures fail to verify. Worse, an attacker who can cause the verifier to parse-then-re-serialize (or use a different canonicalization) can produce a payload that matches the signature but has different semantic content in the recipient's view.

**Why it happens:**
"Canonical JSON" is one phrase that names three incompatible specs: RFC 8785 (JCS), OLPC Canonical JSON, and various ad-hoc TUF-style canonicalizations. Developers pick one without knowing the others exist, or use `serde_json` and call it canonical.

**How to avoid:**
1. Pick one canonicalization scheme explicitly in SPEC.md. **Recommendation: RFC 8785 (JCS)** — it's an RFC, it handles Unicode and floats explicitly, and has implementations across languages for future interop.
2. Use a dedicated crate: `serde_canonical_json` provides a `CanonicalFormatter` for serde_json that implements JCS lexical key ordering. Verify its test vectors match the RFC 8785 published fixtures.
3. Forbid floats entirely in the signed payload (integers only, or strings representing decimals). Floats under JCS are defined but their edge cases — `-0.0`, subnormals, large magnitudes — have bitten every implementation that tried.
4. Require the payload schema to be a closed shape (no untyped `extra` fields), so verifier and signer agree on field set.
5. Write test vectors: a fixed payload → fixed canonical bytes → fixed signature, checked into the repo. Any library update that changes the bytes is a breaking change that must be caught by CI.

**Prevention test:** **Committed test vectors assert that signing a fixed payload produces a fixed byte sequence across the full test matrix (debug/release, x86/ARM, Linux/macOS).**

**Warning signs:**
- `serde_json::to_string` or `to_vec` called on anything that will be signed.
- No floats-are-banned check in payload validation.
- SPEC.md doesn't name a canonicalization RFC.
- No cross-platform CI matrix for signature tests.

**Phase to address:** **Skeleton** (dual-signature is in skeleton scope; canonicalization must be decided before any signature is ever produced — a later change means every previously-issued share is unverifiable).

---

### Pitfall 4: HKDF info strings not domain-separated across protocol contexts

**What goes wrong:**
The PRD specifies HKDF-SHA256 "with domain separation." If the `info` parameter is reused (or empty) across contexts — at-rest key wrapping, inner-payload encryption, PKARR packet derivation, receipt signing — then a key derived for one context can be substituted for another. A concrete attack: an attacker who captures a wrapped at-rest key blob and can coax the receive path to use it as an inner-payload key produces a cross-protocol oracle.

**Why it happens:**
HKDF's `info` parameter is defined as optional in RFC 5869. Developers leave it empty or use a generic "cipherpost" string everywhere. The salt vs info confusion (salt is for entropy mixing, info is for domain separation) compounds this.

**How to avoid:**
1. Enumerate every HKDF call site in the code and SPEC.md with a unique, versioned info string. Suggested format: `b"cipherpost/v1/<context>/<subcontext>"`, e.g., `b"cipherpost/v1/at-rest-wrap"`, `b"cipherpost/v1/inner-payload"`, `b"cipherpost/v1/receipt-sign"`.
2. Include the protocol version in the info string so future revisions are automatically separated.
3. Salt should be fresh randomness where possible (at-rest), or a deterministic-but-context-unique value where it must be reproducible.
4. Add a lint or unit test that asserts the set of info strings used in the codebase matches an allowlist in a single constants file.

**Prevention test:** **A unit test enumerates every HKDF call and asserts each uses a distinct, versioned info string from a central constants module.**

**Warning signs:**
- `Hkdf::new(None, &ikm)` or `info: b""` in any call.
- Any HKDF call not going through a named constant.
- SPEC.md doesn't enumerate the info-string namespace.

**Phase to address:** **Skeleton** (at-rest key wrapping and inner-payload key derivation are in skeleton scope).

---

### Pitfall 5: Signed receipt produced before full verification — confused-deputy attestation

**What goes wrong:**
The signed receipt is the cipherpost delta — its integrity is what differentiates this tool from cclink. If the recipient signs the receipt before (a) verifying both signatures, (b) decrypting the payload, (c) verifying the purpose matches what the user accepted, then the receipt attests to "I received something" rather than "I received this specific material for this specific purpose." An attacker can now harvest receipts for shares that aren't what they claim to be, degrading the receipt to a ping.

**Why it happens:**
Receipts feel like an acknowledgement ("I got your packet") and that language suggests a transport-level ack, not a cryptographic attestation. The temptation is to sign-and-publish immediately on pickup so the sender gets fast feedback.

**How to avoid:**
The receipt's signed body MUST include, at minimum: the hash of the received ciphertext, the hash of the canonical-JSON cleartext, the purpose string, the sender pubkey, the receipt timestamp, a protocol version, and the recipient's pubkey. The receipt MUST be produced only after (in strict order): outer-sig verified → decrypt → inner-sig verified → purpose shown to user → user confirms acceptance → receipt signed → receipt published. Nothing between "decrypt" and "receipt signed" may short-circuit.

Also: the receipt should be over a *canonical* encoding of those fields — same canonicalization pitfall as pitfall 3 applies.

**Prevention test:** **An integration test asserts that tampering with the ciphertext after pickup but before acceptance results in zero receipts published to the DHT.**

**Warning signs:**
- Receipt body is just a timestamp + share ID.
- Receipt sign-and-publish is in the same code path as pickup with no acceptance gate between.
- No test for "bad signature → no receipt."

**Phase to address:** **Skeleton** (signed receipt is explicitly in skeleton scope; it's the whole point of cipherpost).

---

### Pitfall 6: Acceptance step reduced to "press Y" — prompt fatigue / phishing-via-purpose

**What goes wrong:**
The acceptance step is supposed to be a real decision point. If the UX is `"Accept this share? [Y/n]"` with no sender fingerprint verification, no purpose salience, and no friction, users hit Y reflexively. An attacker who can get a recipient to initiate `cipherpost receive` with *any* share ID (phishing link, mistyped pubkey, accident) now has a reliable channel to get a signed receipt for attacker-controlled material with attacker-controlled `purpose` text.

This is the MFA-fatigue attack class applied to key handoff: high-profile breaches (Uber, Cisco, Rockstar) exploited exactly this shape of UX.

**Why it happens:**
CLI prompts default to short. Purpose strings are free-text and look like metadata. The acceptance step feels like confirmation, not authentication.

**How to avoid:**
1. Acceptance must show the **full sender pubkey fingerprint** in a format the user can compare to an out-of-band value (e.g., PGP-word-list or Base32 groups), not just a truncated hex prefix.
2. The purpose string must be **displayed prominently** and **echoed back** by the user (copy-paste or typed confirmation) before acceptance, not just a Y/N.
3. No default to "yes" on empty input; require an explicit affirmative action.
4. Rate-limit acceptance attempts with exponential backoff per sender pubkey (mitigates prompt-bombing).
5. Include number-matching style friction for high-value share types (v1.0, when typed payloads land).

**Prevention test:** **A manual UX test confirms the acceptance screen shows the sender's full fingerprint and requires more than a single keystroke to accept.**

**Warning signs:**
- Acceptance prompt fits on one line.
- Sender identifier displayed is a short hex prefix.
- No CI test for "user accidentally hits Enter."
- Purpose field rendered without delimiters or framing, letting an attacker include control characters or lookalike content.

**Phase to address:** **Skeleton** (acceptance step is in skeleton scope) — lightweight version in skeleton; full hardening in v1.0.

---

### Pitfall 7: Secrets leak via `Debug`, `Display`, or implicit `Clone`

**What goes wrong:**
Rust's type system is stronger than C's, but it does not prevent accidental secret exposure. Common failure modes: deriving `Debug` on a key-holding struct, printing it in a panic or log; stashing a `Vec<u8>` private key in a field that's later passed through `format!("{:?}")`; an implicit `.clone()` making a second copy that lives past the scope where zeroize runs; a passphrase buffer that Rust grows and reallocates, leaving the old buffer in freed memory unwiped.

**Why it happens:**
`#[derive(Debug)]` is the default reflex in every Rust tutorial. Error types often auto-derive Debug. The borrow checker makes `.clone()` feel like a cheap escape hatch from lifetime issues.

**How to avoid:**
1. Wrap every secret in `secrecy::SecretBox<T>` or `secrecy::SecretString`. Both implement `Debug` as `[[REDACTED]]` and zero on drop.
2. Implement `Zeroize` + `ZeroizeOnDrop` on any struct holding raw key bytes (`zeroize` crate). Never derive `Debug` on such structs directly — use `DebugSecret` for a redacted impl if debug is needed.
3. Ban `.clone()` on secret types; use `CloneableSecret` only in the one place it's unavoidable. Review every `.clone()` on key material as part of code review.
4. For passphrases, use `rpassword::prompt_password` (TTY-only, no echo) and feed directly into a fixed-size zeroized buffer. Do NOT accept passphrases from command-line args — they leak to `/proc/<pid>/cmdline` and shell history.
5. Run `cargo-careful` or Valgrind on key paths to catch use-after-free of secret memory.
6. Forbid `println!`, `dbg!`, and `format!` on any type implementing a secret trait (custom clippy lint or convention enforced in review).

**Prevention test:** **A unit test attempts `format!("{:?}", secret)` on every secret type and asserts the output does not contain the underlying bytes.**

**Warning signs:**
- `#[derive(Debug)]` on any struct with a field named `key`, `seed`, `passphrase`, `secret`, `private`.
- Secret values passed as function arguments by value without being wrapped in `SecretBox`.
- `cargo expand` showing derived `Debug` on identity structs.
- Passphrases as CLI flags (`--passphrase=...`) rather than prompted.

**Phase to address:** **Skeleton** (identity generation and unlock are both in skeleton scope — the first secret handled is also the first leak opportunity).

---

## Moderate Pitfalls

These matter but don't permanently burn credibility if caught in v1.0.

### Pitfall 8: Argon2id parameters too weak for 2026 hardware

**What goes wrong:**
The PRD locks Argon2id at **64 MB memory, 3 iterations**. OWASP's current baseline (as of the 2026 Password Storage Cheat Sheet revision) lists two *equivalent minima*: `m=47104 KiB (≈46 MiB), t=1, p=1` or `m=19456 KiB (≈19 MiB), t=2, p=1`. The PRD's 64 MiB / 3 iter is stronger than both OWASP minima — on paper, this is fine. The pitfall is committing the parameters so early that they can't scale up as hardware improves.

**Why it happens:**
Crypto parameters feel like protocol constants, so they get hardcoded. Five years later they're too weak and migrating is a breaking change.

**How to avoid:**
1. Store KDF parameters (m, t, p, salt, version) **inside** the wrapped-identity file header, not as code constants. This is standard PHC string format; `argon2` crate does it automatically via `PasswordHash::to_string()`.
2. On unlock, read parameters from the file. On write (new identity or passphrase change), use the current recommended values from a single `const` block in code.
3. Document a parameter-upgrade path in SPEC.md: if on-disk `m < MIN_M`, offer to rewrap at unlock time.
4. Current recommendation (reconfirm at v1.0): `m=65536 KiB, t=3, p=1` is defensible; drop to OWASP minimums only if 64 MiB causes usability problems on low-RAM devices.

**Prevention test:** **Unit test round-trips an identity with `m=19456, t=2, p=1` (lower than current default) and asserts unlock still succeeds using parameters from the file header, not from code constants.**

**Warning signs:**
- `Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(M, T, P, None).unwrap())` with hardcoded M/T/P in the unlock path.
- No params field in the on-disk identity format.

**Phase to address:** **Skeleton** (identity storage format is established in skeleton; changing it later is a breaking change).

---

### Pitfall 9: age nonce/stream misuse — treating age as a stream cipher

**What goes wrong:**
age uses ChaCha20-Poly1305 under the hood, in its own STREAM construction (chunked AEAD). Nonces are derived per-chunk within a single encryption operation; cross-encryption nonce reuse is prevented by the file key being fresh per-file. Developers who reach past the `age` crate API to `chacha20poly1305` directly — e.g., to encrypt chunks separately for a multi-part protocol — risk reusing nonces across chunks and catastrophically breaking both confidentiality and integrity.

**Why it happens:**
"I need to encrypt this 1KB and that 1KB with the same key" → reach for `ChaCha20Poly1305::encrypt(&nonce, &data)` → reuse `nonce`. With age's STREAM abstraction, this mistake isn't possible. Without it, it's trivial.

**How to avoid:**
1. **Never** call `chacha20poly1305` directly. Always go through the `age` crate's `Encryptor` / `Decryptor` APIs.
2. If a chunked or incremental API is needed, use age's `STREAM` construction (`age::stream`). Do not roll your own.
3. For any non-age AEAD use (if introduced later), use XChaCha20-Poly1305 (24-byte random nonces — random-nonce collision probability is negligible) rather than ChaCha20-Poly1305 (12-byte nonces — random-nonce collision is a real concern at scale).
4. Review every `encrypt`/`decrypt` call site in PR review and confirm the key is fresh-per-file.

**Prevention test:** **A grep-based CI check asserts no direct imports of `chacha20poly1305` or `aes_gcm` outside an allowlisted crypto module.**

**Warning signs:**
- `chacha20poly1305` in `Cargo.toml` dependencies.
- Any call to `.encrypt(nonce, ...)` outside the `age` crate.
- A custom chunking/framing layer around AEAD primitives.

**Phase to address:** **Skeleton** (self-mode encryption uses age; rule applies from day one).

---

### Pitfall 10: DHT unreliability treated as "mostly works" instead of budgeted as first-class

**What goes wrong:**
The PRD calls out DHT unreliability as a risk. The real numbers make it worse than "risk" suggests: median lookup latency on Mainline DHT is historically around **~1 minute** (2011 measurements, the most recent systematic study; modern numbers may be better but likely still tens of seconds), 90th percentile is significantly worse, and NAT/firewall nodes are a persistent connectivity drag. Records expire within hours, not days. A skeleton that assumes "publish, then recipient can fetch any time in the next 4 hours" will routinely fail in real use.

**Why it happens:**
Developers test on LAN or a low-latency local DHT. Real-world success rates from arbitrary hosts look different, especially on mobile/NATed networks. The PRD's "4-hour default TTL" further compresses the window.

**How to avoid:**
1. Implement **republish-on-read-failure** from sender side if still available, not just a one-shot publish.
2. Document the expected failure rate honestly in user-facing error messages: "DHT lookup failed after N tries — ask sender to republish."
3. Use multiple relays (pkarr's relay fallback) with clear documentation that relays are best-effort, not authoritative.
4. Budget retries: recipient should retry lookup with exponential backoff and multiple relay paths before reporting failure.
5. For the skeleton, set `--ttl` default to **24 hours**, not 4 hours. Tighten to 4 hours only after empirical success-rate data from real use is collected. The PRD's "4 hours for keyshare vs. 24 for cclink" is aspirational security hygiene that collides with DHT reality.
6. Instrument the CLI to log (locally only) lookup attempts, latency, and success, so future tuning is data-driven.

**Prevention test:** **A test over a real mainline DHT measures end-to-end publish → fetch round-trip latency distribution over 20+ trials and asserts p50 < 30s, p95 < 120s, failure rate < 10%.**

**Warning signs:**
- Single-shot publish with no retry or republish logic.
- Recipient lookup gives up after one attempt.
- Error messages that don't distinguish "not found yet" from "truly expired."
- TTL enforcement is purely client-side (DHT doesn't enforce expiry — a stale record can persist past intended TTL).

**Phase to address:** **Skeleton** (DHT transport is exercised end-to-end in skeleton) → refined in v1.0 based on skeleton data.

---

### Pitfall 11: PKARR SignedPacket replay — stale packets fetched as "fresh"

**What goes wrong:**
The DHT is content-addressed per-pubkey but not per-timestamp. A SignedPacket with a given pubkey and sequence number can persist on DHT nodes (or be re-seeded by adversaries) after the sender has moved on. A recipient fetching "the current record for pubkey X" may get an older version of the record that the sender intended to supersede. For cipherpost, this means an old share that was supposed to be one-shot (`--burn`) could be re-served.

**Why it happens:**
PKARR's BEP44 layer uses a sequence number (seq), and well-behaved DHT nodes prefer higher seq. But an attacker running DHT nodes can hold old, lower-seq packets and serve them to recipients whose routing table intersects the attacker's nodes. Content-addressed storage + lazy propagation = old versions are reachable.

**How to avoid:**
1. Each share SignedPacket MUST embed an absolute timestamp (monotonic, signed) inside the inner canonical JSON. Recipients reject any packet whose inner timestamp is older than `now - MAX_ACCEPTABLE_AGE` (e.g., 12 hours).
2. Each share MUST have a single-use nonce/share-ID; recipients maintain a local cache of share-IDs they've processed in the last TTL window and reject duplicates.
3. TTL is enforced **inside the inner signed payload**, not from outer metadata — because outer metadata may be stripped/reset by the DHT layer.
4. For `--burn` (v1.0, not skeleton): the receipt IS the burn confirmation; any subsequent pickup attempt that sees an existing receipt MUST fail closed.
5. Document replay/freshness assumptions clearly in THREAT-MODEL.md.

**Prevention test:** **An integration test publishes a share with timestamp `now - 13h`, attempts fetch, and asserts rejection before decryption.**

**Warning signs:**
- No timestamp field in the inner canonical JSON.
- TTL relied on from DHT layer / PKARR packet TTL rather than inner signed timestamp.
- No recipient-side replay cache.

**Phase to address:** **Skeleton** (inner-payload schema is defined in skeleton; timestamp + share-ID must be there from the start).

---

### Pitfall 12: Purpose binding trusted without attestation framing

**What goes wrong:**
Purpose is sender-supplied free text. A sender can claim any purpose — there is no "certified purpose" concept. If the UI or downstream compliance audit treats `purpose` as an authenticated claim from an authority, it's trivially spoofable: the sender just writes "Authorized rotation per Jira TICKET-1234" on an unauthorized share.

**Why it happens:**
The word "binding" in "purpose binding" suggests a cryptographic commitment that's more than it is. Users may assume purpose is verified.

**How to avoid:**
1. Document purpose explicitly in SPEC.md as "sender-attested, not independently verified." It's signed by the sender so it can't be tampered-with in transit, but it's not evidence the claim is true.
2. In the UI, frame purpose as "sender says:" rather than "purpose:" — makes the trust model legible.
3. Receipts bind recipient to "I accepted a share whose sender claimed purpose X" — that's the attestation layer. Third-party verification of X's truth is out of scope.
4. Consider (v1.1+) allowing purpose to include a reference to an externally-anchored attestation (git commit hash, ticket URL) — but don't promise to verify those either.

**Prevention test:** **THREAT-MODEL.md includes a section explicitly stating purpose is sender-attested and giving an example attack where purpose is false.**

**Warning signs:**
- SPEC.md describes purpose without naming its trust model.
- Receipt format includes purpose but no "sender-attested" qualifier.
- UI renders purpose as if authoritative.

**Phase to address:** **Skeleton** (THREAT-MODEL.md draft is in skeleton scope).

---

### Pitfall 13: Supply chain — unaudited dependencies, no reproducible build, no signed releases

**What goes wrong:**
A security tool that ships unsigned binaries or whose dependency tree contains unaudited crates is a contradiction. Users can't verify they're running what the author shipped; a compromised dependency (typosquat, account takeover on crates.io) is shipped to all users at the next release. The 2024 xz backdoor made this concrete even for security-nerd audiences.

**Why it happens:**
Rust culture is "just run cargo install." Few projects wire up cargo-audit / cargo-deny / cargo-vet / sigstore at start.

**How to avoid:**
1. **`cargo-audit`** in CI on every PR and nightly (flags RUSTSEC advisories). Fast, low-friction.
2. **`cargo-deny`** in CI with policy: no duplicate deps, allowlist of licenses, banned crates list, confirmed sources. Slightly more setup.
3. **`cargo-vet`** with Mozilla's + Google's audit imports. High initial setup but the payoff is meaningful on a security tool — "safe-to-deploy" on the whole tree.
4. Commit `Cargo.lock` (already standard for binaries; non-negotiable here).
5. Pin versions conservatively; review every bump of a crypto/transport dep in PR.
6. **Sigstore/cosign** on release artifacts: sign the binaries and the source tarball with cosign keyless + Fulcio, publish the bundle. Since Cosign v3 the bundle format is standardized.
7. **Reproducible builds**: pin toolchain via `rust-toolchain.toml`, document the exact `rustc --version` and build flags. Aim for byte-reproducibility so third parties can independently verify release artifacts match source.

**Prevention test:** **CI pipeline includes `cargo audit`, `cargo deny check`, and `cargo vet` as required-passing jobs on every PR.**

**Warning signs:**
- No `deny.toml` in repo.
- No `supply-chain/audits.toml` (cargo-vet) in repo.
- Release tags without a detached signature file.
- `Cargo.lock` in `.gitignore`.

**Phase to address:** **Skeleton** (set up in skeleton; cost of retrofit grows with dep count) for cargo-audit + cargo-deny; **v1.0** for cargo-vet and sigstore release signing (more setup, lower urgency than audit/deny).

---

## Minor Pitfalls

### Pitfall 14: Passphrases accepted via CLI flag

**What goes wrong:**
`cipherpost unlock --passphrase=hunter2` leaks the passphrase to `/proc/<pid>/cmdline`, shell history, `ps aux` output, and any audit log that captures commands. Even on personal machines this is embarrassing; on shared/CI systems it's a disclosure.

**How to avoid:**
Reject passphrase-on-argv with a clear error. Accept only via: (a) TTY prompt (via `rpassword`), (b) `CIPHERPOST_PASSPHRASE` env var with explicit opt-in and a warning printed to stderr, (c) `--passphrase-file` pointing to a file with 0600 permissions.

**Prevention test:** **CLI help text documents three passphrase input methods, none of which is direct CLI arg; a test asserts `--passphrase=X` is rejected.**

**Phase to address:** **Skeleton**.

---

### Pitfall 15: Identity file permissions not enforced / platform-portable

**What goes wrong:**
On-disk identity file is passphrase-wrapped but still worth protecting from curious processes. If permissions aren't set to 0600 (Unix) or ACL-restricted (Windows), a non-root local process can copy the ciphertext and crack the passphrase offline at leisure.

**How to avoid:**
On creation and every open, check and enforce `0600` (Unix) / user-only ACL (Windows). Refuse to proceed if permissions are weaker; print how to fix.

**Prevention test:** **Integration test creates an identity, `chmod 0644` on the file, and asserts subsequent unlock fails with a clear permissions error.**

**Phase to address:** **Skeleton**.

---

### Pitfall 16: Error messages distinguish failure modes → enumeration oracle

**What goes wrong:**
`"bad passphrase"` vs `"bad HKDF"` vs `"corrupt file"` — three distinct errors on unlock let an attacker with file access distinguish "passphrase wrong" from "file corrupt." Minor, but a good habit.

**How to avoid:**
Return a single opaque `"unlock failed"` error at the user-facing layer, regardless of which internal step failed. Log the specific cause only to a local debug log (behind a flag).

**Prevention test:** **Unit test confirms that three different kinds of corruption (wrong passphrase, tampered ciphertext, tampered KDF params) all produce the same user-visible error string.**

**Phase to address:** **v1.0** (nice-to-have, not critical for skeleton).

---

### Pitfall 17: No MSRV pinning / nightly Rust creep

**What goes wrong:**
Security-sensitive crates sometimes require nightly features or raise MSRV without warning. Users building from source on a stable system get mysterious breakage. Worse, a nightly-only build path gets different codegen than the release binary.

**How to avoid:**
Set `rust-version` in `Cargo.toml` explicitly. Pin via `rust-toolchain.toml` with a stable channel. Ban `#![feature(...)]` in non-test code. CI builds on the MSRV and on stable.

**Prevention test:** **CI has a job that builds on the declared MSRV and fails if it breaks.**

**Phase to address:** **v1.0**.

---

### Pitfall 18: "Works on my machine" — no cross-platform CI for signatures

**What goes wrong:**
Canonical JSON, time zones, locale handling, path separators — any of these can sneak into signatures or identity paths and make them non-portable. A share produced on Linux fails verification on macOS, or vice versa.

**How to avoid:**
CI matrix: Linux × macOS × Windows × (x86_64, arm64). Signature test vectors run on all.

**Prevention test:** **CI matrix exists and passes on all target platforms for the signature fixture tests.**

**Phase to address:** **v1.0**.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Use `serde_json::to_string` for signing "for now" | Ship skeleton faster | Every share ever issued becomes unverifiable when canonicalization is fixed | **Never** — inner signature must be canonical from day one |
| Hardcode Argon2id params in code instead of identity header | One fewer struct field | Breaking change to storage format to upgrade | **Never** — params in header from day one |
| Skip cargo-audit / cargo-deny in CI, add later | Less CI setup | One RUSTSEC advisory away from shipping a known-vulnerable binary | **Never** for a security tool |
| Use short pubkey prefix (8 chars) in acceptance UI | Shorter prompt | Collision-rate nontrivial; phishing surface | Only with a separate full-fingerprint verification mode also available |
| Single-shot DHT publish, no republish | Simpler code | Recipient fails reliably in real use | Acceptable in skeleton if documented as a skeleton limitation |
| `#[derive(Debug)]` on identity struct | Easier local debugging | One `println!("{:?}")` leaks the key | **Never** — use `SecretBox` or `DebugSecret` |
| Accept passphrases via `--passphrase=` for scripting | Trivial automation | Disclosure via `/proc`, shell history | **Never** — use stdin or env var instead |
| Skip sigstore signing on skeleton releases | One fewer thing to set up | Pre-release binaries can't be distinguished from tampered ones | Acceptable if skeleton releases are explicitly marked "source-only, not for distribution" |
| Use TTL from DHT packet instead of inner signed timestamp | Reuse PKARR machinery | TTL is DHT-layer metadata, trivially stripped/spoofed | **Never** — inner timestamp in signed payload from day one |

---

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Mainline DHT (via PKARR) | Treat as reliable transport with TTL guarantees | Best-effort; build republish and retry; inner signed timestamp for freshness |
| age crate | Reach past its API to raw `chacha20poly1305` | Always use `age::Encryptor`/`Decryptor` / `STREAM` |
| ed25519-dalek ↔ x25519-dalek | Convert secret by copying scalar | Use `curve25519-dalek` documented conversion, round-trip test vs libsodium |
| argon2 crate | Hardcode params, discard PHC string | Persist full PHC string in identity file header |
| serde_json | Use default serialization for signing | Use `serde_canonical_json` (JCS); ban floats in signed payloads |
| rpassword | Fall back to stdin if no TTY | Refuse and exit — TTY-only for passphrase input (stdin mode is a separate, documented path) |
| cosign / sigstore | Sign with long-lived keys | Keyless with Fulcio + short-lived certs; publish bundle |
| zeroize | Assume derive-macro covers all fields | Manually verify every field zeroizes; test with explicit drop and memory inspection |

---

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| Argon2id parameters tuned on dev machine | Unlock takes 30s on user laptop | Measure on typical hardware, target ~500ms–1s unlock | At first non-developer user |
| DHT publish retries with no backoff | Network flood, DHT node bans sender | Exponential backoff with jitter | Any adversarial or congested network |
| Synchronous DHT fetch in CLI | CLI blocks for 60s+ on lookup | Async with progress output, user-cancellable | p95 of real-world lookups |
| Replay cache unbounded | Cache grows until disk full | Bound to last N shares or TTL window, whichever larger | After weeks of use |
| Receipt-publish on every pickup, no dedup | DHT churn, wasted reads | Publish once, verify-cached | After signed-receipt feature is used heavily |

These are not "scale at 10K users" issues — cipherpost is per-user, roughly 1–100 shares per user per week. The traps above are latency and usability traps, not throughput traps.

---

## Security Mistakes

Domain-specific; these are the security issues beyond general CLI-app hygiene that are easy to miss.

| Mistake | Risk | Prevention |
|---------|------|------------|
| Emit panic backtraces in release builds | Panic messages may contain secrets copied to stack | Set `panic = "abort"` in release profile; catch-unwind at CLI boundary; scrub any displayed error |
| Log `purpose` or sender pubkey before signature verify | Attacker-controlled text in logs/terminal before authentication | Never display pre-verification payload fields |
| Accept share whose recipient pubkey doesn't match our identity | Someone else's share is decrypted and receipt-signed by wrong party | Verify recipient pubkey matches local identity before decrypt; fail closed |
| Trust outer PKARR packet timestamp | DHT layer can lie; stale packet served | Inner signed timestamp is authoritative; outer is informational only |
| Reuse ephemeral X25519 across multiple recipients (if multi-recipient ever lands) | Cross-recipient key recovery | Fresh ephemeral per recipient (age handles this correctly if used via the API) |
| Canonical JSON with fields including secret data | Secret may end up in logs of canonicalization library | Secrets are encrypted; signed payload contains only metadata and commitment hashes, never secret bytes |
| Skip small-subgroup check on X25519 | Malleable ciphertext, decryption by wrong recipient | age (via rage) now enforces this — do NOT use an older age library version that doesn't |
| Use `age` CLI's passphrase mode by shelling out | Passphrase leaks to process args | Use age as a Rust library, not a CLI, from inside cipherpost |

---

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Fingerprint shown as 8-char hex | Users copy-paste wrong keys, accept wrong sender | Full Base32 fingerprint grouped for readability, or BIP39-word-list mapping |
| "[Y/n]" default-yes on acceptance | Reflex acceptance | No default; require explicit typed confirmation |
| Purpose text rendered inline in terminal | Control chars / lookalike unicode / homoglyph attack | Render purpose inside explicit delimiters, strip control chars, warn on non-ASCII |
| Error "share not found" when actually expired | User waits and retries needlessly | Distinguish "never existed" from "expired" from "DHT lookup failed" in user-visible errors |
| Silent receipt publish | User doesn't know attestation happened | Print "Signed receipt published: \<hash\>" prominently on success |
| No way to inspect payload metadata before accept | Users can't tell if this is the share they were expecting | Show sender pubkey + purpose + timestamp + share-ID before acceptance; allow `--dry-run` that stops before decrypt |
| Passphrase prompt without confirmation on initial generation | Typo locks user out of their own identity forever | Double-prompt on create; offer recovery phrase export (v1.0) |

---

## "Looks Done But Isn't" Checklist

Things that appear complete but are missing critical pieces. Use during phase verification.

- [ ] **Self-mode round trip:** Often missing cross-implementation test — verify encryption/decryption works against cclink's fixture data, not just against itself.
- [ ] **Share-mode round trip:** Often missing recipient-mismatch test — verify a share encrypted to pubkey B cannot be decrypted by pubkey C (even if C is provided the ciphertext).
- [ ] **Dual-signature verification:** Often missing order test — verify a valid-outer-but-invalid-inner share fails *after* outer check, and no payload data is surfaced.
- [ ] **Canonical JSON:** Often missing test vectors — verify a committed fixture bytes-match on Linux, macOS, ARM, x86; verify `serde_json` alone is not used.
- [ ] **HKDF domain separation:** Often missing info-string allowlist test — verify every HKDF call in the codebase pulls from a named constants module.
- [ ] **Identity at-rest:** Often missing params-in-header test — verify old identities with weaker params still unlock.
- [ ] **Signed receipt:** Often missing bad-ciphertext test — verify no receipt is published when inner verify fails.
- [ ] **Acceptance step:** Often missing fingerprint-display test — verify full fingerprint renders, not just prefix.
- [ ] **Purpose binding:** Often missing threat-model documentation — verify THREAT-MODEL.md explicitly calls purpose "sender-attested."
- [ ] **TTL enforcement:** Often missing inner-timestamp check — verify stale shares rejected even if DHT still serves them.
- [ ] **Passphrase input:** Often missing argv-rejection test — verify `--passphrase=X` returns an error.
- [ ] **Secrets in memory:** Often missing `Debug` leak test — verify `format!("{:?}", identity)` does not contain key bytes.
- [ ] **File permissions:** Often missing enforcement test — verify identity file at 0644 refuses to unlock.
- [ ] **Supply chain:** Often missing `cargo deny` / `cargo audit` CI job — verify both run on every PR.
- [ ] **DHT reliability:** Often missing empirical latency test — verify p50 and p95 measured against real DHT, not mocked.
- [ ] **Release signing (v1.0):** Often missing cosign bundle — verify release tarball is signed and bundle committed.

---

## Recovery Strategies

When pitfalls occur despite prevention, how to recover.

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Canonical JSON bug shipped | HIGH | Bump protocol version in SPEC.md; new shares use v2 canonicalization; old shares unverifiable — document as breaking change; notify users |
| Ed25519→X25519 conversion bug | HIGH | All existing identities must regenerate and re-publish to DHT; coordinate migration; publish signed advisory |
| HKDF info collision discovered | HIGH | Similar to canonical-JSON: bump protocol version, regenerate keys; full migration |
| Weak Argon2 params shipped | MEDIUM | Users auto-rewrap on next unlock (thanks to params-in-header); no coordination needed if recovered early |
| Dependency RUSTSEC advisory | LOW | `cargo update` or bump, release patch version, sign it, users upgrade normally |
| DHT reliability worse than projected | MEDIUM | Extend default TTL, add republish loop, document user expectations; possibly introduce optional relay (commercial tier only per principles) |
| Secret leaked via Debug | MEDIUM | Code fix is easy; but users whose logs were shared publicly have compromised material — must advise key rotation |
| Phishing via purpose-binding reported in the wild | MEDIUM | UX hardening release; acceptance UI upgrade; user education post |
| Receipt produced before verification | HIGH | Breaks the core value prop — receipts issued this way are worthless; revoke and re-issue with correct flow; THREAT-MODEL advisory |
| Packaged binary tampered pre-sigstore adoption | HIGH | Until sigstore lands, users can't distinguish — recommend source-only installs and publish git tag signatures; accelerate sigstore adoption |

---

## "Keybase Problem" — Project Abandonment as a Pitfall

The PRD explicitly cites Keybase → Zoom → neglect as a motivator. A project in this space *must* plan for its own potential abandonment, because the trust model depends on the protocol outliving the author's attention.

**Signals users should look for (and that we should work to avoid):**
- No commits in 6+ months.
- Open issues with no maintainer response.
- CI permanently red.
- Published releases stop being signed.
- Dependencies with known RUSTSEC advisories not bumped.
- SECURITY.md disclosure contact bounces.
- Domain expires / website goes down.

**Defensive design for abandonment:**
- Protocol documented completely enough in SPEC.md that someone else can reimplement. **This is why SPEC.md cannot be an afterthought.**
- No server dependencies means "abandoned" doesn't mean "broken" — existing shares keep working. This is a principled advantage over Keybase.
- MIT license + publish to crates.io under a name the author does not block transfer of.
- Reproducible builds + signed releases means even an abandoned binary can be independently verified long after.
- Document a succession plan in README or CONTRIBUTING: if maintainer goes silent, how does the community fork cleanly?

**Phase to address:** **Skeleton** establishes SPEC.md discipline; **v1.0** adds succession-plan text and reproducible-build process.

---

## Pitfall-to-Phase Mapping

**Authoritative roadmap input.** Each pitfall maps to the earliest phase that must prevent it.

| # | Pitfall | Prevention Phase | Verification |
|---|---------|------------------|--------------|
| 1 | Ed25519→X25519 conversion bug | **Skeleton** | Cross-implementation byte-match test vs libsodium fixture |
| 2 | Dual-sig verification order | **Skeleton** | Fuzz test: bit-flip ciphertext, assert no payload fields surface |
| 3 | Non-canonical JSON | **Skeleton** | Cross-platform CI: fixture payload → fixed signature bytes |
| 4 | HKDF domain separation | **Skeleton** | Unit test: all HKDF info strings from central constants, all distinct |
| 5 | Receipt-before-verify | **Skeleton** | Integration test: tampered share → zero receipts published |
| 6 | Acceptance prompt fatigue | **Skeleton** (light) → **v1.0** (full) | UX test: full fingerprint shown, multi-keystroke acceptance |
| 7 | Secrets in memory (Debug/Clone leaks) | **Skeleton** | Unit test: `format!("{:?}", secret)` contains no key bytes |
| 8 | Weak/unupgradeable Argon2 params | **Skeleton** | Round-trip test: weak-param identity unlocks via header params |
| 9 | age stream / nonce misuse | **Skeleton** | CI grep: no direct `chacha20poly1305` imports outside allowlist |
| 10 | DHT unreliability unbudgeted | **Skeleton** (measure) → **v1.0** (tune) | Real-DHT latency measurement: p50 < 30s, p95 < 120s, failure < 10% |
| 11 | PKARR replay / stale packet | **Skeleton** | Integration: 13h-old share rejected before decrypt |
| 12 | Purpose binding trust model unclear | **Skeleton** | THREAT-MODEL.md section on purpose trust |
| 13 | Supply chain (audit/deny/sigstore) | **Skeleton** (audit + deny) → **v1.0** (vet + sigstore) | CI: cargo-audit + cargo-deny passing; v1.0: signed release bundle |
| 14 | Passphrase via CLI arg | **Skeleton** | Test: `--passphrase=X` rejected |
| 15 | Identity file permissions | **Skeleton** | Test: 0644 identity refuses to unlock |
| 16 | Error messages leak oracle | **v1.0** | Test: 3 corruption modes → same error string |
| 17 | MSRV / nightly creep | **v1.0** | CI job on declared MSRV |
| 18 | Cross-platform signatures | **v1.0** | CI matrix: 3 OS × 2 arch, signature fixtures match |
| — | Project-abandonment resilience | **Skeleton** (SPEC.md) → **v1.0** (succession plan) | SPEC.md alone enables reimplementation; succession plan documented |

**Skeleton must address pitfalls 1–15** (1–7 critical; 8–15 moderate-but-foundational). **v1.0 adds pitfalls 16–18 and hardens 6, 10, 13.** Ongoing vigilance: dependency updates, DHT empirical monitoring, disclosure response.

---

## Sources

**Crypto:**
- [Ed25519 ↔ X25519 conversion — libsodium documentation](https://libsodium.gitbook.io/doc/advanced/ed25519-curve25519)
- [Ed25519 / X25519 key reuse pitfalls — Bill Buchanan](https://billatnapier.medium.com/the-confusing-thing-about-x25519-and-ed25519-10310df41f81)
- [OpenSSL Ed25519→X25519 conversion PR discussion (cross-protocol key reuse concerns)](https://github.com/openssl/openssl/pull/24621)
- [OWASP Password Storage Cheat Sheet (Argon2id recommended parameters)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [Password hashing in 2026 — comparison](https://guptadeepak.com/the-complete-guide-to-password-hashing-argon2-vs-bcrypt-vs-scrypt-vs-pbkdf2-2026/)
- [Evaluating Argon2 adoption in real-world software (arxiv)](https://arxiv.org/html/2504.17121v1)
- [age crate (rage) changelog — X25519 small-order-point rejection fix](https://github.com/str4d/rage/blob/main/age/CHANGELOG.md)
- [RFC 5869 — HKDF](https://www.rfc-editor.org/rfc/rfc5869.html)
- [Understanding HKDF — Soatok](https://soatok.blog/2021/11/17/understanding-hkdf/)
- [Key Derivation Functions Without a Grain of Salt (2025 paper)](https://eprint.iacr.org/2025/657.pdf)

**Canonical JSON:**
- [RFC 8785 — JSON Canonicalization Scheme (JCS)](https://www.rfc-editor.org/rfc/rfc8785)
- [serde_canonical_json crate docs](https://docs.rs/serde_canonical_json/latest/serde_canonical_json/)
- [JSON canonicalization reference implementations](https://github.com/cyberphone/json-canonicalization)

**DHT / PKARR:**
- [Mainline DHT reliability measurements (2011)](https://philipp-andelfinger.net/pdfs/juenemann2011basic.pdf)
- [Sub-second Kademlia lookups research](https://www.diva-portal.org/smash/get/diva2:436670/FULLTEXT01.pdf)
- [BitTorrent's Mainline DHT Security Assessment](https://inria.hal.science/inria-00577043/file/BitTorrent_DHT_security_assessment_ntms11.pdf)
- [Real-world Sybil attacks in BitTorrent Mainline DHT](https://nymity.ch/sybilhunting/pdf/Wang2012a.pdf)
- [Active Sybil Attack and Defense in IPFS DHT (2025)](https://arxiv.org/html/2505.01139)
- [PKARR — Nuhvi / Pubky](https://github.com/pubky/pkarr)
- [PKARR Rust crate](https://crates.io/crates/pkarr)
- [cclink repository (source of inherited primitives)](https://github.com/johnzilla/cclink)

**Rust secrets / supply chain:**
- [secrecy crate](https://docs.rs/secrecy/latest/secrecy/)
- [zeroize crate](https://docs.rs/zeroize/latest/zeroize/index.html)
- [rpassword crate](https://docs.rs/rpassword/)
- [cargo-audit](https://crates.io/crates/cargo-audit)
- [cargo-deny](https://crates.io/crates/cargo-deny)
- [cargo-vet](https://mozilla.github.io/cargo-vet/)
- [Comparing Rust supply chain safety tools (LogRocket)](https://blog.logrocket.com/comparing-rust-supply-chain-safety-tools/)
- [Rust supply chain security 2026 (GeekWala)](https://www.geekwala.com/blog/securing-rust-dependencies-2026)
- [sigstore-rs](https://github.com/sigstore/sigstore-rs)
- [cosign v3 release notes](https://github.com/sigstore/cosign/releases)

**UX / abandonment:**
- [MFA fatigue attack analyses (Okta, BeyondTrust)](https://www.okta.com/blog/2022/09/mfa-fatigue-growing-security-concern/)
- [MFA prompt spam — Uber / Cisco / Rockstar breaches (BeyondTrust)](https://www.beyondtrust.com/resources/glossary/mfa-fatigue-attack)
- [Keybase post-Zoom status discussion](https://github.com/keybase/client/issues/24105)

---

*Pitfalls research for: self-sovereign cryptographic-material handoff (Cipherpost)*
*Researched: 2026-04-20*
