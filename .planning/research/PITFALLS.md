# Domain Pitfalls — v1.1 Addendum

**Domain:** Adding typed Material variants, pin/burn modes, non-interactive passphrase flags, and real-DHT validation to cipherpost/v1.
**Researched:** 2026-04-23
**Scope:** Integration hazards when ADDING v1.1 features to the shipped v1.0 walking skeleton. Does NOT repeat v1.0 pitfalls (1–18) already addressed in this file's predecessor section. Those lock-ins are load-bearing and pre-verified.

> **How to read this file.** Each pitfall carries:
> - **Category** — one of: `jcs`, `crypto`, `dht`, `cli`, `state`, `test`
> - **Warning signal** — what the bug looks like in practice before you have a name for it
> - **Prevention** — a named test, assertion, or code pattern (not "be careful")
> - **Phase** — which v1.1 phase owns the prevention

---

## Critical Pitfalls

### Pitfall 19: X.509 PEM vs. DER ambiguity breaks `share_ref` determinism

**Category:** `jcs`

**What goes wrong:** `Material::X509Cert` accepts a PEM-encoded certificate as input. PEM is
DER bytes wrapped in base64 with `-----BEGIN CERTIFICATE-----` headers, optional `Comment:`
headers, and varying line-width conventions (64-char standard, or arbitrary). If cipherpost
stores the PEM string verbatim and that string becomes a `bytes` field in JCS, two byte-identical
DER certificates submitted as PEM with different line wrapping or whitespace produce different
`share_ref` values, break re-send idempotency, and (if the PEM variation is produced by the
same user on two different openssl versions) produce different inner-signature bytes over what
appears to be "the same certificate."

Worse: legacy ASN.1 BER indefinite-length encoding appears in older CA-signed certificates.
If you accept DER-encoded bytes directly, some inputs will contain valid BER that is not
canonical DER (DER forbids indefinite-length). Two encodings of the same logical certificate
yield different bytes and therefore different `share_ref`s and different inner signatures.

**Why it happens:** The natural implementation is to accept whatever the user passes in (PEM
or DER), stash it in the `bytes` field (base64-encoded), and sign. This feels symmetric with
`GenericSecret { bytes }`. The difference is that `GenericSecret` has exactly one canonical
representation: the raw byte sequence the user provided. X.509 has at least three
representations for the same certificate (PEM with headers, PEM without headers, DER, BER).

**Consequences:**
- `share_ref` varies across re-sends of the "same" certificate
- Committed JCS fixture (`outer_record_signable.bin`) cannot lock in the `X509Cert` variant
  without first defining the canonical storage format
- Re-implementations cannot reproduce inner signatures without knowing the normalization rule
- PITFALL #3 (canonical JSON) is re-opened for the new variant

**Prevention:**
1. Define `Material::X509Cert` as storing normalized DER only. Accept PEM at the CLI surface
   (strip headers, base64-decode to DER), reject BER by running the DER bytes through
   `der::Document::from_der()` or equivalent (the parse itself validates canonical DER encoding).
2. The `ingest` function for X509Cert: PEM in → strip armor → base64-decode → DER parse (validates
   DER canonicity) → store normalized DER bytes → base64-STANDARD-encode for the `bytes` field.
3. Add a **property test**: `Material::X509Cert` field must be JCS-stable under round-trip
   encode-then-parse (parse the JSON back out, re-encode, assert byte-identical JCS output).
4. Add a **fixture test**: commit `tests/fixtures/x509_material_signable.bin` (smallest valid
   self-signed cert, normalized DER) and assert the JCS bytes match on every CI run.
5. Document in SPEC.md §3.2 that `x509_cert.bytes` carries normalized DER (not PEM) regardless
   of input format; PEM is a CLI input convenience only.

**Warning signal:** Tests that pass when the same PEM is round-tripped but fail when the cert
is re-pasted from a tool that reformats line width. Or `share_ref` values that change on
`send --share` re-runs of the same cert file.

**Phase:** Phase 6 (X509Cert implementation). Prevention items must be present before Phase 6
ships; the fixture file must be committed by Phase 6 plan 01.

---

### Pitfall 20: OpenPGP armored headers are non-deterministic — store binary packet stream, not armor

**Category:** `jcs`

**What goes wrong:** `Material::PgpKey` accepts an OpenPGP key as input. The natural form from
`gpg --export --armor` is ASCII armor with a `Version:` header line and optionally a `Comment:`
header line. The `Version:` content varies by gpg version and locale. The `Comment:` line is
configurable. Armor checksum (the `=XXXX` trailer) is deterministic given the binary packet
content, but the headers are not. Two exports of byte-identical key material yield different
armor strings and therefore different JCS bytes in `Material::PgpKey.bytes`, breaking `share_ref`
determinism identically to Pitfall 19 but for PGP.

A second hazard specific to PGP: a secret key exported with `gpg --export-secret-keys --armor`
includes the secret components. Cipherpost must distinguish "PGP public key" from "PGP secret
key" — accepting a secret key would mean the sender is inadvertently transmitting secret key
material wrapped in cipherpost's own secret-key wrapper. This is confusing but not a security
vulnerability (cipherpost encrypts it end-to-end), but it is a semantic footgun the acceptance
screen cannot easily flag without OpenPGP packet parsing.

**Why it happens:** OpenPGP armor is the human-visible format. `PgpKey = single public key`
suggests you grab it from a keyserver or `gpg --export --armor`. Storing armor verbatim seems
natural.

**Consequences:**
- `share_ref` non-determinism (see Pitfall 19)
- Any re-send of a key that was re-exported after a gpg version upgrade produces a different
  `share_ref`
- Secret-key acceptance happens silently (no error at send time, confusing semantics)

**Prevention:**
1. Store the canonical OpenPGP **binary packet stream** (the raw bytes of the Transferable Public
   Key packet sequence per RFC 4880 §11.1). Strip armor at ingest: `base64-decode the body
   (ignoring headers and checksum) → validate that the packet tags indicate a public key
   packet → store the binary`.
2. Reject armored secret keys at ingest (`gpg` packet tag 5 = secret key, tag 7 = secret subkey):
   return `Error::InvalidMaterial` with message "PgpKey material must be a public key, not a
   secret key". Exit code 1 (invalid input, not crypto failure).
3. Add a **property test**: `Material::PgpKey` JCS-stable under round-trip.
4. Add a **fixture test**: commit `tests/fixtures/pgp_material_signable.bin` (smallest minimal
   PGP public key, binary packet stream). Do not use a real key; generate a deterministic test
   key with `sequoia` or an inline byte vector.
5. Document in SPEC.md §3.2 that `pgp_key.bytes` carries the raw OpenPGP packet stream (RFC
   4880 binary, not ASCII armor). Armor is a CLI input convenience.

**Warning signal:** Two sends of the "same" public key produce different `share_ref`s.
`gpg --version` output changes between send and re-send and breaks re-send idempotency.

**Phase:** Phase 7 (PgpKey implementation). Prevention items must be present before Phase 7 ships.

---

### Pitfall 21: OpenSSH private key optional padding makes `SshKey` non-canonical without normalization

**Category:** `jcs`

**What goes wrong:** The OpenSSH private key format (RFC draft `draft-miller-ssh-agent`) stores
private key blobs padded to a cipher block boundary. Even for `none`-cipher (unencrypted private
key export), the padding bytes are present and their values may vary by implementation. Ed25519
private keys in OpenSSH format have a fixed-size payload, so padding is deterministic for that
key type — but other key types (RSA, ECDSA) have variable-length encodings, and the padding
is filled with implementation-specific bytes (OpenSSH fills with `0x01, 0x02, 0x03, ...`; some
other implementations fill with `0x00`).

More subtle: OpenSSH public key files (`.pub`) contain a base64-encoded wire blob followed by
a comment field. The comment field is arbitrary, changes between `ssh-keygen` invocations, and
is included in the file but NOT in the wire format. If cipherpost ingest parses the `.pub` file
format and includes the comment in `bytes`, two exports of the same key with different comments
(or hostname changes) produce different JCS bytes.

**Why it happens:** `ssh-keygen -y -f id_ed25519 > id_ed25519.pub` produces a pubkey file with
a comment. Developers paste the file contents into the CLI. The comment is part of the file,
so it ends up in bytes unless explicitly stripped.

**Consequences:**
- `share_ref` non-determinism for keys with different comment fields or padding
- Two users who both hold the same SSH keypair's public key but obtained it from different
  sources (one from `ssh-keygen -y`, one from `authorized_keys`) produce different `share_ref`s

**Prevention:**
1. For `Material::SshKey`, define the stored format as the **raw SSH wire blob** only (the
   base64-decoded body of the pubkey file, with no comment). For private keys, define storage
   as the raw OpenSSH private key blob bytes (stripped of the `-----BEGIN OPENSSH PRIVATE KEY-----`
   armor), with no trailing padding variation allowed — reject inputs where the `none`-cipher
   private key has non-standard padding by parsing with `ssh-key` crate.
2. At ingest: if input looks like `.pub` file format (starts with `ssh-ed25519 ` or similar
   algorithm prefix), split on whitespace, take only the base64 blob (column 2), base64-decode,
   store result in `bytes`. Discard comment column.
3. Add a **property test**: `Material::SshKey` JCS-stable under round-trip.
4. Add a **fixture test**: commit `tests/fixtures/ssh_material_signable.bin` (a known-bytes
   Ed25519 public key wire blob).
5. Document in SPEC.md §3.2 that `ssh_key.bytes` carries the SSH wire blob bytes (the
   base64-decoded body of the `.pub` file, no comment). Comment stripping happens at ingest.

**Warning signal:** Two sends of the same SSH key produce different `share_ref`s when the key
was obtained from a machine with a different default comment (e.g., different hostnames in
`id_ed25519.pub` generated by different machines).

**Phase:** Phase 7 (SshKey implementation). Prevention items must be present before Phase 7 ships.

---

### Pitfall 22: Per-variant plaintext size must be bounded and checked BEFORE encryption — not after

**Category:** `cli`

**What goes wrong:** The 64 KB plaintext cap (PAYL-03, D-PS-01) is checked for `GenericSecret`
before encryption. New variants must have the same pre-encrypt check. The hazard:

- PGP keys with multi-subkey rings and long UID packets can exceed 64 KB (a 4096-bit RSA key
  with 3 subkeys and 2 UIDs is roughly 8–12 KB; a keyring with many certifications and subkeys
  can grow to 100+ KB). The SCOPE note in PROJECT.md limits PgpKey to "single key, not keyring",
  which keeps typical size around 300 bytes (Ed25519 pubkey) to 3 KB (RSA-4096 pubkey). But
  "single key" must be enforced at parse time, not just described.
- X.509 certificates with large SAN (SubjectAlternativeName) extensions, embedded SCT
  (Signed Certificate Timestamp) lists, long certificate chains embedded as a leaf+issuer
  bundle, or embedded CRL distribution points can be 4–20 KB for a single cert. Still within
  the 64 KB cap, but the error message must clearly distinguish "payload too large (plaintext
  exceeds 64 KB)" from "PKARR wire budget exceeded" (BEP44 ~1000 bytes), because for some
  X.509 certs the wire budget is the binding constraint, not the 64 KB cap.
- SSH keys are small (Ed25519 pubkey ≈ 68 bytes wire; RSA-4096 pubkey ≈ 800 bytes). Not a
  realistic size concern, but the check must be present for consistency.

The PKARR wire budget (~1000 bytes total SignedPacket) is almost certainly the binding
constraint for all typed variants, not the 64 KB plaintext cap — but both checks must fire
in the right order.

**Why it happens:** Developers add a new Material variant, copy the serialize path from
GenericSecret, and forget to replicate the pre-encrypt size check because "the PKARR publish
will fail anyway." The PKARR publish failure produces `Error::WireBudgetExceeded` with
`plaintext: 0`, which is a poor user experience ("I tried to send a cert and got a wire
budget error with no suggestion").

**Consequences:**
- User gets a confusing late-stage error instead of a clear early-stage rejection with a
  suggested action (e.g., "trim SAN extensions" or "export public key only, not chain")
- A payload between 1000 bytes and 64 KB succeeds at the plaintext cap check but fails at
  publish — still a poor UX
- The test coverage gap means a size regression in a variant would not be caught early

**Prevention:**
1. Add a `material_plaintext_size(&self) -> usize` method to the `Material` enum. Each
   variant returns `bytes.len()` (for the raw bytes field before base64 encoding). Enforce
   `<= 65536` before serializing to JCS and entering the age-encrypt path — same as `GenericSecret`.
2. Test: for each new variant, add a test that creates a `Material` with `bytes.len() == 65537`
   and asserts `cipherpost send` returns `Error::PayloadTooLarge` with exit code 1 (not
   `Error::WireBudgetExceeded`).
3. For X.509 specifically: add a test with a real multi-SCT cert (or a synthesized cert with
   large SAN) to confirm the wire budget is the binding constraint and the error message clearly
   states "PKARR wire budget exceeded; consider stripping non-essential certificate extensions."
4. Emit a stderr warning when the plaintext is > 500 bytes: "Note: large payload may exceed
   PKARR wire budget and fail at publish; 64 KB plaintext cap is not the binding constraint."

**Warning signal:** A user attempts to send an X.509 cert and gets `Error::WireBudgetExceeded`
with `plaintext: 0` and no guidance. Support requests that say "it failed on my cert but not
on my colleague's cert" when the colleague has a smaller cert.

**Phase:** Phase 6 (establish per-variant size pattern). Phase 7 applies the same pattern.

---

### Pitfall 23: PIN mode creates a distinguishable oracle at the `age` decryption layer

**Category:** `crypto`

**What goes wrong:** PIN mode (from `--pin`) wraps the age-encrypted payload with a second
age passphrase recipient that uses the PIN as the passphrase. `age` decryption with multiple
recipients works by trying each identity in sequence until one succeeds. The `age::Decryptor`
returns an error that distinguishes "no matching recipient found" from "recipient matched but
decryption failed." If PIN decryption is attempted alongside the X25519 identity decryption:

- A wrong PIN may produce a detectable error ("tried passphrase recipient, failed") while the
  X25519 identity attempt might fail for a different reason.
- An attacker who can observe decryption-error distinctions (timing, error code, error message)
  can confirm: "the PIN recipient is present in this age file" — confirming PIN mode was used.
- Exit code leaks: if `--pin` produces exit code 4 (wrong PIN) instead of exit code 3 (sig
  failure) for a tampered payload, the attacker learns which verification layer failed.

This is a new form of Pitfall #16 (distinguishable oracle). The error-oracle hygiene invariant
from v1.0 must be extended to cover PIN mode.

**Why it happens:** `age` error types naturally distinguish `NoMatchingKeys` (no recipient
matched) from other failures. The developer adds PIN mode by adding a second passphrase
recipient, maps `NoMatchingKeys` to "wrong PIN", and adds a new error variant `PinIncorrect`
to the `thiserror` enum. Now `PinIncorrect` and `SignatureOuter` have different Display strings
and different exit codes.

**Consequences:**
- Attacker distinguishes "this is a PIN-protected share" from "this is a key-protected share"
  by observing the error returned on a wrong-identity decrypt attempt
- Error-oracle invariant tested in v1.0 (`signature_failure_variants_share_display` test)
  no longer covers all failure paths once PIN mode is added

**Prevention:**
1. Define the PIN-wrong user-visible path carefully: a wrong PIN at decrypt time MUST surface
   the same user-facing message and exit code as any other decrypt failure. Do NOT add a
   `PinIncorrect` variant with a distinct Display. Instead, map the age `NoMatchingKeys` result
   (when in PIN-expected mode) to `Error::DecryptFailed` (or an appropriate existing variant)
   with exit code 3.
2. Extend the `signature_failure_variants_share_display` enumeration test in v1.1 to enumerate
   all error variants that can arise on a `receive` call, including any new PIN-related variants,
   and assert all user-facing Display strings are identical.
3. Never expose in stderr output whether the share was PIN-mode or key-mode — that distinction
   is ciphertext metadata and is not in `OuterRecord` (which is visible to all DHT observers).
4. Define a protocol flag in `OuterRecord` for "pin mode required" if the recipient needs to
   know to prompt for a PIN — but do NOT place it in a non-encrypted field. The pin-mode bit
   must be inside the `Envelope` (encrypted), not in `OuterRecord` (visible). If the recipient
   always tries PIN prompt when PIN mode might be active, they prompt unnecessarily for
   non-PIN shares; document this UX trade-off explicitly.

**Warning signal:** Adding a new error variant with a distinct `Display` for PIN failure.
`--pin` mode producing exit code 4 for a wrong PIN (4 is "passphrase incorrect" in the v1.0
taxonomy — reusing it is semantically wrong; not-reusing it breaks the oracle invariant).

**Phase:** Phase 8 (pin/burn modes). The extension to the enumeration test must be in Phase 8
plan 01 before any PIN error path is added.

---

### Pitfall 24: PIN entropy is insufficient for offline brute force without a cryptographic rate limit

**Category:** `crypto`

**What goes wrong:** A 4–6 digit numeric PIN (10,000–1,000,000 values) is brute-forceable at
the rate of age's passphrase KDF. age uses scrypt (N=32768, r=8, p=1 by default) for
passphrase-based recipients, giving roughly 0.1–0.3 seconds per guess on commodity hardware.
Brute-forcing a 6-digit PIN at 0.3s/guess takes at most 300,000 seconds ≈ 3.5 days. A 4-digit
PIN takes 50 minutes. If the attacker exfiltrates the ciphertext (trivially from DHT, which is
public), they can run the brute force offline with no rate limiting.

cipherpost has no server to rate-limit guesses. The `--burn` mode could provide an implicit
limit (the share burns after one successful decrypt, but the attacker is brute-forcing locally
against the exfiltrated ciphertext, not against the DHT). There is no cryptographic mechanism
in the protocol that prevents offline brute force.

**Why it happens:** PIN feels like a "simpler passphrase for the recipient." age passphrase
recipients use scrypt, which is memory-hard, but scrypt at age's default parameters is
too-fast against a short numeric keyspace.

**Consequences:**
- All PIN-protected shares are offline-brute-forceable by anyone who can exfiltrate the
  ciphertext (which is publicly available on DHT)
- "PIN mode" implies to users that the share is protected by the PIN alone, but the actual
  security is "security of the age X25519 recipient key + PIN"; if the PIN is the only
  protection (no X25519 recipient), offline brute force recovers the plaintext

**Prevention:**
1. In SPEC.md and `cipherpost send --pin` help text: document explicitly that PIN mode adds
   a second layer for the RECIPIENT to type; it does NOT provide post-exfiltration security
   against offline brute force of short PINs. Recommend minimum 8-character PINs with mixed
   character classes.
2. Consider requiring PIN length >= 8 and character-class diversity (reject pure-numeric PINs
   < 12 digits) — surface as a `--pin` validation step with clear error.
3. Document in THREAT-MODEL.md: "PIN-protected shares are offline-brute-forceable by DHT
   observers against short PINs; PIN mode provides friction for an honest recipient who is
   not the intended age X25519 recipient, and provides non-repudiation (the recipient had
   to know the PIN); it does NOT provide post-exfiltration confidentiality against a determined
   adversary who has the ciphertext."
4. Add a test that asserts the CLI rejects `--pin` values shorter than 8 characters with
   `Error::InvalidInput` and a message explaining the entropy requirement.

**Warning signal:** The `--pin` flag description says "enter a PIN for the recipient" with no
entropy guidance. Short numeric-only PINs accepted at send time. No test for PIN length rejection.

**Phase:** Phase 8. Entropy guidance must be in Phase 8 plan 01 before the flag is implemented.

---

### Pitfall 25: `--burn` is local-state-only — second receiver on a fresh machine still decrypts

**Category:** `state`

**What goes wrong:** `--burn` marks the share as "consumed" in the SENDER's or RECIPIENT's
local state ledger. The ciphertext remains on Mainline DHT until TTL expires. A second machine
with a fresh `~/.cipherpost/state/` directory resolves the same DHT packet, passes all
verification (signatures are valid, TTL is not expired), and decrypts successfully. From the
protocol's perspective, the second machine has never seen this `share_ref` before. Burn is
LOCAL-state-only, not a cryptographic destruction event.

This is a known architectural limitation (cipherpost has no server; one-time delivery is not
cryptographically enforceable on a public DHT). The hazard is that users will EXPECT burn to
mean "only one person can ever decrypt this." Documenting "burn is local only" in a man page
is insufficient — the acceptance screen must make this explicit at the moment of decision.

**Why it happens:** The receipt mechanism in v1.0 provides a cryptographic proof of acceptance,
but not a cryptographic proof of uniqueness. There is no way to make a DHT packet self-destruct
on first retrieval — the DHT is read-only for observers. The "burn" semantic is therefore
enforced only by (a) the recipient's local ledger rejecting re-receive (idempotency, already
in v1.0), and (b) the implicit assumption that only one machine holds the recipient's private key.

**Consequences:**
- A backup restore, a second device, or an attacker who exfiltrated the identity file (and
  passphrase) before the share TTL expired can decrypt a "burned" share
- Users who believe "burned" means cryptographically destroyed are misled about the security
  guarantee
- If the sender uses burn as proof that the recipient is the only holder, the proof is false

**Prevention:**
1. Add `burn` mode to THREAT-MODEL.md as a first-class section: "Burn is not cryptographic
   destruction. The share remains on DHT until TTL expires. A recipient with a fresh state
   ledger (different machine, backup restore, key exfiltration) can still decrypt."
2. At send time with `--burn`: print a prominent stderr warning "BURN MODE: This share will
   be accepted at most once per recipient device. It does NOT prevent decryption by an
   attacker who holds the recipient's identity file and exfiltrates the DHT packet before TTL
   expires. For single-recipient confidentiality, use the default TTL carefully and confirm
   receipt via `cipherpost receipts --from <z32>`."
3. At receive time when the resolved `OuterRecord` has `burn_mode: true` (if burn is signaled
   in the encrypted envelope): print on the acceptance screen "BURN MODE: Your acceptance will
   be recorded in your local state ledger. A second receive attempt on this device will be
   rejected. Note: decryption may succeed on a fresh device."
4. The Envelope field for burn must be inside the encrypted blob (not in OuterRecord plaintext),
   consistent with Pitfall 23's rule that mode flags must not leak to DHT observers.
5. Add a test: `run_receive` on a share where the recipient's state ledger has a prior sentinel
   for the same `share_ref` — assert exit 0 with "already accepted" (idempotency, existing
   behavior); this is the only enforceable burn guarantee.

**Warning signal:** burn-mode documentation that says "prevents re-decryption" without the
caveat "on this device, from this state ledger." Any code that deletes the DHT record on burn
(impossible — the DHT is not writable by the sender post-publish; if someone attempts a
publish of an empty packet to "overwrite" the share, a subsequent resolve-most-recent on the
pkarr client will still find the old signed packet on other nodes if seq numbers race).

**Phase:** Phase 8. THREAT-MODEL.md section and acceptance-screen warning must be in Phase 8 plan 01.

---

### Pitfall 26: Atomic ordering of burn vs. emit in `run_receive` — failure modes differ from v1.0

> **SUPERSEDED 2026-04-25 by D-P8-12 (emit-before-mark for burn).** This pitfall
> predates Phase 8 BURN-03 lock-in. The original analysis (preserved below)
> recommended `mark-then-emit` as the canonical write order for burn mode.
> Phase 8's resolution: BURN-03 + D-P8-12 require `emit-then-mark` for burn
> shares specifically — a crash between emit and ledger-write leaves the share
> re-receivable on next invocation, which is the safer failure mode (the user
> keeps access to their data) compared to mark-then-emit (the user loses their
> data to a half-completed state write).
>
> The original "delete-the-sentinel-after-emit" footgun this pitfall warned
> against is still rejected — Plan 04 NEVER deletes the sentinel or removes
> the ledger row. The supersession only flips the *order* of (emit, mark);
> sentinel and ledger row are append-only and never removed.
>
> v1.0's accepted-flow ordering is UNCHANGED: mark-then-emit there preserves
> the idempotent-success contract (re-receive returns the same data without
> re-decrypting). The two flows have OPPOSITE atomicity contracts because
> `burned` represents a one-shot consume (where data-loss-on-crash is the
> worst outcome) while `accepted` represents idempotent persistence (where
> re-emit on crash is fine).
>
> See: `src/flow.rs::run_receive` STEP 11/12; `src/flow.rs::append_ledger_entry_with_state`;
> D-P8-12 in `.planning/phases/08-pin-and-burn-encryption-modes/08-CONTEXT.md`;
> SPEC.md §3.7 Burn Semantics; Plan 04 ship-gate
> `tests/burn_roundtrip.rs::burn_share_first_receive_succeeds_second_returns_exit_7`.

> **AMENDED 2026-04-27 by Quick 260427-axn (per-share_ref receive lock).** Both
> the v1.0 mark-then-emit accepted-flow and Phase 8's emit-then-mark burn-flow
> rely on `check_already_consumed` to gate re-receives. Sequential-receive
> correctness was load-bearing through v1.1; CONCURRENT receives of the same
> `share_ref` opened a TOCTOU window between STEP 1's `check_already_consumed`
> (src/flow.rs:560) and STEP 12's `create_sentinel` (src/flow.rs:799) where
> two processes could both pass the check, both decrypt + emit, and both
> append ledger rows.
>
> Quick 260427-axn closes the window with a per-`share_ref_hex` advisory file
> lock at `{state_dir}/locks/<share_ref>.lock`, acquired before STEP 1 and
> released after STEP 12 (`run_receive`'s `_share_lock` guard). STEP 13
> `publish_receipt` runs OUTSIDE the lock — receipt publication is best-effort
> and has its own CAS-retry contract (Pitfall #28, tests/cas_racer.rs).
>
> **Burn emit-before-mark ordering (D-P8-12) is UNCHANGED.** The lock serializes
> the resolve→sentinel→ledger window; the ordering invariant (emit then mark for
> burn, mark then emit for accepted) is observed identically inside the lock by
> exactly one receive at a time per `share_ref`.
>
> **Error-oracle hygiene (Pitfall #16) is preserved.** Lock-acquisition or
> -release I/O failures collapse into the existing `Error::Io` variant — no
> `Error::LockFailed` or similar new variant. Exit code 1 (default arm).
>
> **Async runtime constraint preserved.** The lock uses blocking
> `fs2::FileExt::lock_exclusive`. No tokio import at the cipherpost layer.
>
> Choice rationale (option (A) vs option (B)): moving `create_sentinel` to
> immediately after `transport.resolve()` (option B) would invert burn's
> emit-before-mark contract for that variant specifically, requiring two
> per-flow concurrency stories instead of one. Option (A) — the lock — closes
> the window uniformly across both flows without disturbing the load-bearing
> ordering invariant. Cost: one direct dep (`fs2` ~5 KB; MIT/Apache-2.0,
> within deny.toml allowlist; libc-only transitives).
>
> See: `src/flow.rs::acquire_share_lock`, `src/flow.rs::locks_dir`,
> `tests/state_ledger_concurrency.rs`, `Cargo.toml [dependencies] fs2`.

**Category:** `state`

**What goes wrong:** v1.0's `run_receive` marks the ledger sentinel BEFORE emitting the
plaintext to stdout. This is the correct order for idempotency: if stdout emit fails (pipe
broken, process killed), the sentinel is already written, and a re-run returns "already accepted"
rather than double-decrypting. This "mark-before-emit" is safe in v1.0 because a re-run is
idempotent (sentinel is present → early exit 0, no re-decrypt, no re-receipt).

`--burn` mode changes the failure analysis. The correct invariant for burn is:
"the user's process receives the plaintext, or they get an error; there is no state where
plaintext is emitted but no sentinel recorded." Under the v1.0 "mark-before-emit" ordering,
this is already correct. But if any v1.1 implementation of burn adds a delete-or-invalidate
step AFTER emit, there is a window where:
1. Sentinel written (burned)
2. Stdout emit fails (pipe broken)
3. Delete/invalidate step runs
4. User's process never received the plaintext; the share is now locally burned and they cannot recover it

For burn, the correct implementation is: `mark-then-emit` (same as v1.0) — and ensure that
a failure at emit does NOT remove the sentinel, because the sentinel is also the idempotency
guard. The plaintext is still on DHT (see Pitfall 25); the user can `receive` from a fresh
machine to recover.

**Why it happens:** "Burn means destroy after use" triggers the impulse to DELETE the sentinel
or the ledger entry after successful emit — so the share "looks available" again to the local
ledger. This is the opposite of the correct invariant.

**Consequences:**
- If sentinel is deleted after emit-failure, the share can be re-received locally, defeating
  the local-burn guarantee
- If sentinel is deleted after emit-success, re-receive attempts return "not yet accepted"
  instead of "already accepted", causing confusion
- If the delete step is non-atomic with the emit step, a process kill between emit and delete
  leaves an inconsistent local state

**Prevention:**
1. Keep `mark-then-emit` ordering from v1.0 for burn mode.
2. After burn-mode accept, the sentinel must NEVER be deleted from the local ledger. The
   sentinel IS the burn record. Write a `burn_mode: true` field into the ledger entry rather
   than relying on presence/absence of the sentinel to mean "burned."
3. Add a test: `run_receive` in burn mode with a simulated stdout-failure after decrypt but
   before stdout emit (inject a Write error via a mock writer) — assert the sentinel is still
   present and the ledger entry shows `burn_mode: true`.
4. A re-receive attempt on a burned share (sentinel present, `burn_mode: true`) should return
   a message distinguishing "already accepted normally" vs "already accepted in burn mode; will
   not re-decrypt."

**Warning signal:** Any code path in burn mode that calls `std::fs::remove_file` on the sentinel,
or that overwrites the ledger entry with `accepted: false` after emit.

**Phase:** Phase 8. The test must be written BEFORE the burn-mode emit path.

---

### Pitfall 27: Receipt semantics for burn mode must be defined before implementation, not after

**Category:** `state`

**What goes wrong:** In v1.0, a receipt is always published after successful acceptance. In
burn mode, there are two defensible choices, each with distinct threat-model implications:

**Option A: Receipt is published in burn mode (same as normal mode).** The receipt signals to
the sender that the share was accepted and burned. A second observer who sees the receipt knows
the share was consumed. The receipt is the burn confirmation. Implication: if the sender wants
to know "was my burned share received exactly once?", they check for a receipt.

**Option B: No receipt is published in burn mode.** Burn mode suppresses the receipt to avoid
leaving a public record of the acceptance event. Implication: the sender has no out-of-band
confirmation that the burned share was actually received; they must rely on the recipient
telling them out-of-band. The receipt's public-verifiability is lost.

If this is not decided before Phase 8 implementation starts, the developer will pick one
implicitly and the threat-model will be wrong.

**Why it happens:** Receipts and burn seem like independent features and get combined late.

**Consequences:**
- If Option A is implemented but not documented: users assume burn = no trace; the receipt
  IS a trace.
- If Option B is implemented but not documented: senders lose the receipt guarantee on all
  burn shares; this erodes cipherpost's core value proposition.
- If the decision is deferred mid-implementation, the result is inconsistent behavior.

**Prevention:**
1. Make the decision in Phase 8 plan 01 (before implementation) and record it in PROJECT.md
   Key Decisions table.
2. Recommendation (derived from threat model): **Option A — publish receipt in burn mode.**
   Rationale: the receipt is the sender's proof of delivery; suppressing it trades attestation
   for perceived anonymity that doesn't hold (the DHT observers saw the packet regardless).
   Document in THREAT-MODEL.md: "In burn mode, a receipt is still published after acceptance.
   The receipt is the sender's confirmation that the share was consumed."
3. Add to the acceptance screen for burn-mode shares: "A signed receipt will be published
   under your PKARR key confirming this acceptance."

**Warning signal:** Phase 8 implementation that conditionally skips `publish_receipt` without
an explicit decision in PROJECT.md. Any commit that gates `publish_receipt` on `!burn_mode`
without a cited decision.

**Phase:** Phase 8 plan 01 (decision must precede implementation; not an implementation detail).

---

### Pitfall 28: PKARR concurrent-racer test is a new hazard class — not covered by existing `serial_test` pattern

**Category:** `test`

**What goes wrong:** Phase 9 adds an explicit concurrent-racer test for the `cas`
(compare-and-swap) merge-republish path in `DhtTransport::publish_receipt`. The existing
`#[serial]` pattern on env-mutating tests prevents PROCESS-level races on `CIPHERPOST_HOME`.
It does NOT prevent a test that spawns two threads or two async tasks that both call
`publish_receipt` with real DHT, racing the same PKARR key's SignedPacket. This is a new
hazard class: concurrent publish to the SAME DHT KEY from the SAME process.

The specific failure mode: both tasks resolve the same current SignedPacket (seq=N), both
build a new SignedPacket (seq=N+1), the second publish wins and the first is dropped silently.
The `cas` parameter in the PKARR client should prevent the first publish from succeeding if
the server has already seen seq=N+1 — but this behavior needs to be empirically validated,
not assumed.

**Why it happens:** The concurrent-racer test was deferred from v1.0 (documented in
MILESTONES.md "Known deferred items"). Writing a correct concurrent-racer test is harder than
a sequential integration test; the developer may write a sequential simulation instead of a
true concurrent test.

**Consequences:**
- A sequential simulation of "two receipts back-to-back" does NOT exercise the race condition
  (the second publish happens after the first has already updated the DHT; there is no
  concurrent resolve)
- The actual bug (lost receipt under concurrent publish) only manifests when two `publish_receipt`
  calls race the resolve step
- CI may be green on the sequential test but the race bug exists in production

**Prevention:**
1. Write a true concurrent test: spawn two threads, each calling `publish_receipt` with a
   different `Receipt` on the same identity's PKARR key. Use a `Barrier` to synchronize both
   threads past the "resolve current packet" step BEFORE either calls publish. Assert that after
   both threads complete, BOTH receipts are present in the resolved SignedPacket (or assert
   exactly one is present and the test documents "known lost-update; tracking for retry in v1.2").
2. Under `MockTransport`, implement a `publish_receipt` that atomically checks the cas
   parameter against an in-memory sequence number and rejects stale publishes with a distinct
   error. Then the concurrent-racer test can be run under MockTransport without real DHT.
3. For Phase 9's real-DHT cross-identity test: use two separate identities (Alice and Bob),
   not two concurrent receipt publishes from the same identity. The concurrent-publish race
   is a SEPARATE test from the cross-identity round trip.
4. Mark the concurrent-publish test with `#[serial]` to prevent it from racing with other
   DHT-touching tests, but the test itself must use a real `Barrier` or `sync::Mutex` to
   create the race condition internally.

**Warning signal:** The "concurrent-racer test" is implemented as `publish_receipt` called
twice sequentially with `sleep(Duration::from_millis(0))` between them. No `Barrier`. No
concurrent threads or tasks.

**Phase:** Phase 9. MockTransport implementation of `cas` semantics should be in Phase 9 plan 01.

---

## Moderate Pitfalls

### Pitfall 29: Real-DHT tests are CI-hostile without a graceful skip mechanism

**Category:** `test`

**What goes wrong:** Phase 9 adds real-DHT E2E tests. GitHub Actions runners do NOT reliably
allow outbound UDP traffic on DHT ports (typically 6881–6889 for BitTorrent/Mainline DHT).
Firewall rules vary by runner flavor and change without notice. A real-DHT test that blocks
on network connectivity without a timeout will either hang until the CI job timeout fires, or
fail non-deterministically based on runner network policy.

Additionally: PKARR p50 lookup latency is approximately 1 minute (empirically; see v1.0
PITFALLS.md Pitfall #10). A CI job that sets a 5-minute per-test timeout may flake at p95.
Two concurrent real-DHT tests on the same CI worker compound the problem.

**Why it happens:** The developer runs the test locally on a development machine with full
outbound UDP access. It passes. The test is added to the standard test suite. CI fails
intermittently.

**Consequences:**
- CI flake degrades confidence in the test suite
- The real-DHT test provides no signal if the CI runner blocks UDP — it's not testing what
  you think it's testing
- A stuck CI job consumes runner minutes

**Prevention:**
1. Gate real-DHT tests behind a cargo feature flag `real-dht-e2e` (separate from `mock`).
   CI does NOT run `--features real-dht-e2e` in the standard PR check. A separate "nightly"
   or "pre-release" CI job runs with `--features real-dht-e2e` and a 10-minute timeout per test.
2. Inside each real-DHT test: add a pre-flight UDP reachability check (attempt to connect to
   a known Mainline DHT bootstrap node; if it fails within 5 seconds, `test::skip()` with a
   logged reason: "DHT unreachable on this runner; test skipped"). This prevents false failures
   on network-restricted environments.
3. Configure a per-test timeout of 120 seconds (not 5 minutes) — if DHT lookup hasn't
   returned in 120 seconds, it's a flake, not a slow success.
4. Do not run more than one real-DHT test per CI job; the combined latency will exceed the
   job timeout.
5. Mark real-DHT tests with `#[serial]` (same as env-mutating tests) to prevent concurrent
   DHT tests from racing the same bootstrap nodes.

**Warning signal:** Real-DHT test in the default `cargo test` or `cargo test --features mock`
path. No pre-flight connectivity check. No UDP-skip mechanism. Tests labeled `#[ignore]`
instead of feature-gated (ignore is less explicit than a feature flag).

**Phase:** Phase 9. Feature flag and pre-flight check must be in Phase 9 plan 01.

---

### Pitfall 30: Passphrase-file newline stripping must be exact — greedy strip breaks passphrases with trailing whitespace

**Category:** `cli`

**What goes wrong:** `--passphrase-file` reads a passphrase from a file. Scripts that generate
passphrase files commonly use `echo $PW > pw.txt`, which appends exactly one `\n` (LF on
Unix, `\r\n` on some contexts). The correct behavior: strip exactly ONE trailing LF (or one
trailing CRLF), no more. If the implementation uses `.trim()`, `.trim_end()`, or
`.trim_end_matches('\n')` without specificity, it strips ALL trailing whitespace including
space characters — a passphrase intentionally ending with a space character is silently modified.

This matters because passphrases for HSMs, PKCS#12 files, or GPG secret keys sometimes contain
non-trivial trailing whitespace (unusual but valid). Stripping aggressively corrupts them
silently — the user gets "wrong passphrase" when their passphrase was correct.

**Why it happens:** Rust's `str::trim()` strips all leading and trailing ASCII whitespace.
The developer calls `content.trim()` for "convenience" on the passphrase-file content.

**Consequences:**
- A passphrase ending in a space fails unlock with "passphrase failed" (exit 4) — the user
  has no indication the file was modified before use
- A passphrase file that was generated with `printf '%s\r\n' $PW` on Windows (CRLF line ending)
  has `\r` retained if only `\n` is stripped, causing "passphrase failed" on Unix

**Prevention:**
1. Implement passphrase-file reading as: read bytes → check for trailing `\r\n` (strip if
   present, ONE occurrence only) → check for trailing `\n` (strip if present, ONE occurrence
   only, and ONLY if `\r\n` was not already stripped) → use the resulting bytes as passphrase.
2. Write a unit test: passphrase file containing `"mysecret \n"` (passphrase ends in a space)
   → assert parsed passphrase is `"mysecret "` (space preserved, newline stripped).
3. Write a unit test: passphrase file containing `"mysecret\r\n"` → assert parsed passphrase
   is `"mysecret"` (CRLF stripped).
4. Write a unit test: passphrase file containing `"mysecret\n\n"` (two newlines, e.g., editor
   added a blank line) → assert parsed passphrase is `"mysecret\n"` (only ONE trailing newline
   stripped, the inner newline is part of the passphrase — unusual but this is the correct
   behavior for a content-preserving read).
5. Document in SPEC.md §7 (Passphrase Contract) and in `--passphrase-file` help text: "Exactly
   one trailing LF (or CRLF) is stripped; no other whitespace is modified."

**Warning signal:** `passphrase_content.trim()` or `passphrase_content.trim_end()` in the
passphrase-file reading path. No unit test for a passphrase ending in a space.

**Phase:** Phase 5 (non-interactive passphrase flags). Prevention must be in Phase 5 plan 01.

---

### Pitfall 31: `--passphrase-fd` double-close hazard in Rust on Unix

**Category:** `cli`

**What goes wrong:** `--passphrase-fd <N>` reads the passphrase from file descriptor N. In
Rust on Unix, `std::os::unix::io::FromRawFd::from_raw_fd(N)` creates a `File` that owns the
FD and will close it when dropped. If the caller (a shell script, a Python subprocess) also
closes FD N after `cipherpost` exits, the FD is closed twice — this is a double-close, which
is a use-after-free at the OS level and can, in rare cases, close a different FD that the
OS re-allocated to the same number.

The secondary hazard: `BorrowedFd` (available since Rust 1.63) allows reading from an FD
without taking ownership — the FD is NOT closed when the `BorrowedFd` is dropped. This is
the correct API to use for `--passphrase-fd`. Using `FromRawFd` (owning) is incorrect here.

**Why it happens:** `std::fs::File::from_raw_fd(N)` is the obvious way to read from an FD
number. The developer does not know about `BorrowedFd` or does not recognize the ownership
semantics.

**Consequences:**
- Double-close of FD N causes the OS to close whatever FD happens to have the same number
  in a concurrent context (unlikely but possible in multi-threaded code)
- If the caller is a shell script, the double-close has no effect (shells close all FDs on
  subprocess exit anyway) — but it IS a Rust unsafe-code correctness issue

**Prevention:**
1. Use `std::os::unix::io::BorrowedFd` (or `std::io::Read` from a `ManuallyDrop<File>`) to
   read from the passphrase FD without taking ownership. The FD must remain open until the
   read is complete; the caller is responsible for closing it.
2. Write a unit test: open a pipe, write a passphrase to the write end, pass the read end's
   FD number as `--passphrase-fd N`, assert the passphrase is read correctly AND the FD is
   not closed after use (check via `fcntl(fd, F_GETFD)` — if EBADF, the FD was closed).
3. Add a brief note in SPEC.md §7: "The caller is responsible for closing the FD after
   `cipherpost` exits; cipherpost reads from the FD without closing it."
4. Subprocess documentation (for Python, Node, shell): include a correct `pass_fds` or `stdio`
   setup example in SPEC.md §7 or in an examples directory.

**Warning signal:** `unsafe { std::fs::File::from_raw_fd(fd_number) }` in the passphrase-fd
reading path without a `ManuallyDrop` wrapper. Any code that explicitly calls `.close()` or
drops the `File` before exiting.

**Phase:** Phase 5. The `BorrowedFd` usage must be the default implementation; do not let a
`FromRawFd` implementation ship and "fix it later."

---

### Pitfall 32: Traceability-table drift fix must not silently break external tooling

**Category:** `cli`

**What goes wrong:** Phase 5 eliminates the traceability-table drift that produced 29 "Pending"
rows in the v1.0 archived REQUIREMENTS.md. Two candidate approaches each have hazards:

**Approach A: Script generates traceability table from body checkboxes.**
A bug in the generation script becomes silent data corruption: the table says "Pending" for
a requirement that is implemented (script fails to parse the checkbox), or "Done" for a
requirement that is not (script emits wrong status). The script must be tested, and the CI
check must fail LOUDLY (not silently skip) if the generated table diverges from the body.

**Approach B: Drop the table, keep only checkboxes.**
Any external tooling (Linear import script, a PM dashboard, a GitHub Action that parses the
REQUIREMENTS.md table for status reporting) breaks. Since no such tooling is confirmed to
exist for cipherpost, this is LOW risk — but check before dropping.

**Why it happens:** REQUIREMENTS.md is a planning artifact, not source code; it doesn't get
the same "change must be tested" discipline as `src/`.

**Prevention:**
1. Before choosing an approach, confirm whether any external tooling parses the traceability
   table (search for scripts that reference REQUIREMENTS.md format in the repository and any
   CI steps that parse it).
2. If approach A (script-generated table): the CI check must `diff` the script-generated table
   against the committed table and fail with a non-zero exit code and a clear message if they
   diverge. The check must not silently succeed on parse errors.
3. If approach B (drop the table): update any CI steps or templates that reference the table
   format; document the format change in a commit message. Add a `# Deprecated: traceability
   table dropped in v1.1` note at the top of any archived REQUIREMENTS.md that still has the
   table.
4. Whatever approach is chosen, the decision and its rationale must be recorded in PROJECT.md
   Key Decisions.

**Warning signal:** A CI check that `exit 0` on script parse errors. A script-generated table
that is committed but the CI check is not yet added. A "drop the table" approach chosen
without checking for external parsers.

**Phase:** Phase 5. Decision must be in Phase 5 plan 01; the CI check (if approach A) must
be in Phase 5 plan 02.

---

### Pitfall 33: DHT label audit — renaming labels is a protocol break; audit must confirm, not change

**Category:** `dht`

**What goes wrong:** Phase 5 includes a DHT label audit of `_cipherpost` and `_cprcpt-<share_ref>`.
The purpose of an "audit" is to confirm the labels match SPEC.md — NOT to rename them. If the
audit concludes "we should rename `_cipherpost` to `_cp` for brevity," every v1.0 wire snapshot
(any share published by any user running the walking skeleton) becomes unresolvable by v1.1
clients. The label is part of the DNS TXT record name in the PKARR SignedPacket; changing it
is a wire-format break requiring a protocol version bump.

**Why it happens:** An audit triggers the impulse to "improve" what's found. Label names look
like internal implementation details; their wire-stability is not obvious.

**Consequences:**
- v1.0 shares become permanently unresolvable by v1.1 clients
- There is no migration path (the sender would have to re-publish, but cipherpost has no
  "re-publish" command in v1.0/v1.1)
- SPEC.md §3.3 documents the label; changing it is a spec change, not a code change

**Prevention:**
1. The Phase 5 audit deliverable is: a CI test that asserts the label strings used in code
   (`src/transport.rs` or equivalent) match the strings documented in SPEC.md. Nothing more.
2. If the audit discovers a genuine discrepancy (code says one label, SPEC says another),
   the SPEC wins; update code to match SPEC, not the reverse.
3. If a label change is ever desired: it requires a protocol version bump (`protocol_version: 2`
   in `OuterRecord`), a migration guide in SPEC.md, and a v2 compatibility shim in the resolver
   path. Do not do this in v1.1.
4. Add a unit test: assert that the constant for the DHT label (`DNS_LABEL_SHARE` or equivalent)
   byte-matches the string `"_cipherpost"` and the receipt label constant matches `"_cprcpt-"`.
   Run on CI.

**Warning signal:** Phase 5 plan that includes renaming DHT labels as a scope item. Any commit
that changes the label string constants without a protocol version bump. An audit report that
recommends renaming.

**Phase:** Phase 5. The assertion test must be added; the audit scope must be explicitly limited
to "confirm, not change."

---

### Pitfall 34: Pin-version blessing — do not hard-pin crate versions in SPEC.md prose text

**Category:** `cli`

**What goes wrong:** Phase 5 "blesses" the shipped pin versions (`serde_canonical_json 1.0.0`,
`pkarr 5.0.4`, 550-byte wire budget) in SPEC.md. The hazard: if a RUSTSEC advisory surfaces
against `pkarr 5.0.4` after it is documented as "the current version" in SPEC.md, the spec
document falsely implies that version is recommended. Users who read SPEC.md as a deployment
guide will pin to a vulnerable version.

**Why it happens:** Version numbers in specs look authoritative. "Bless the shipped reality"
is correct in the sense of removing the "planned vs. shipped" discrepancy — but the form of
the blessing matters.

**Prevention:**
1. SPEC.md should state crate names and minimum acceptable API versions (e.g., "serde_canonical_json
   >= 1.0.0, implementing RFC 8785 JCS") not exact versions.
2. For operationally-significant constraints (the exact `ed25519-dalek =3.0.0-pre.5` pin is
   load-bearing because no stable 3.x exists), add a note: "See `Cargo.toml` for the exact
   version pin in effect; this constraint is a build artifact, not a protocol guarantee."
3. Version prose in SPEC.md should read: "as of the 2026-04 baseline; see `Cargo.toml` and
   `cargo audit` policy in `deny.toml` for the current constraint envelope."
4. Never embed a specific crate version in SPEC.md in a way that implies that version is the
   recommended one; only Cargo.toml and deny.toml carry that authority.

**Warning signal:** SPEC.md prose that says "cipherpost uses pkarr 5.0.4" instead of "cipherpost
uses pkarr (>= 5.0.3); see Cargo.toml." Any SPEC.md diff in Phase 5 that adds exact version
numbers in prose.

**Phase:** Phase 5. The phrasing must be reviewed in Phase 5 plan before the SPEC.md edit lands.

---

## Minor Pitfalls

### Pitfall 35: `CIPHERPOST_PASSPHRASE` visible in `ps auxe` — document the FD preference

**Category:** `cli`

**What goes wrong:** `CIPHERPOST_PASSPHRASE` env var is a supported passphrase input method.
On Linux, environment variables of running processes are readable from `/proc/<pid>/environ`
by any process with the same UID. `ps auxe` shows environment on some platforms. A passphrase
in an environment variable is therefore visible to co-resident processes under the same UID.

The v1.0 SPEC.md §7 documents this as an opt-in mechanism. The v1.1 non-interactive passphrase
work (Phase 5) makes env-var use more common. The hazard is not new, but it needs to be
re-surfaced in the context of scripted use (e.g., CI pipelines where `CIPHERPOST_PASSPHRASE`
is set in a shell environment variable rather than a secret manager).

**Prevention:**
1. SPEC.md §7 must include a preference ordering: FD (`--passphrase-fd`) > file (`--passphrase-file`)
   > env (`CIPHERPOST_PASSPHRASE`) > TTY prompt. Document WHY: FD and file avoid process-table
   exposure; env var is visible to co-resident processes.
2. When `CIPHERPOST_PASSPHRASE` is used, print a one-line warning to stderr: "Warning: passphrase
   read from environment variable; visible in process table. Prefer --passphrase-fd or
   --passphrase-file in production contexts."
3. Add a test that asserts the warning is emitted when `CIPHERPOST_PASSPHRASE` is set and used.
4. In the examples added to SPEC.md §7 for scripted use, show the FD approach as the FIRST
   example, not the env approach.

**Warning signal:** Documentation examples that lead with `CIPHERPOST_PASSPHRASE` for CI use.
No warning emitted when env var is used. SPEC.md §7 that does not have a preference ordering.

**Phase:** Phase 5.

---

### Pitfall 36: New Material variants need HKDF info-string enumeration test extension

**Category:** `crypto`

**What goes wrong:** The v1.0 enumeration test (`tests/hkdf_info_enumeration.rs` or equivalent)
walks every HKDF call site and asserts the prefix is `cipherpost/v1/`. When Phases 6 and 7
add new Material variants, if those variants introduce any HKDF-derived keys (unlikely for
typed Material variants that are just stored bytes, but possible if a future material type
has a per-variant key-derivation step), the new call sites must be in the enumeration.

More concretely: if `Material::X509Cert` adds a "material hash for attestation" derived via
HKDF, that call site is new and might not carry the correct info string if the developer copies
from a non-HKDF context.

**Prevention:**
1. After each new Material variant lands, re-run the HKDF enumeration test and confirm no new
   uncovered call sites appeared. The test should fail if a new HKDF call site uses an info
   string NOT in the allowlist — this is already the design of the test.
2. If any Material variant introduces a new HKDF call site, add the new info string to the
   allowlist in the constants module BEFORE adding the call site. Do not add the call site
   first and the allowlist entry second (the test will fail between commits, which is acceptable,
   but the allowlist entry must be in the same commit as the call site, not a later patch).

**Warning signal:** New HKDF call site added without a corresponding allowlist entry. HKDF
enumeration test disabled or bypassed in Phase 6 or 7.

**Phase:** Phase 6 (establish the pattern); Phase 7 (apply it to PgpKey and SshKey).

---

### Pitfall 37: `--pin` passphrase surface must go through `resolve_passphrase` — not a new flag with raw argv value

**Category:** `cli`

**What goes wrong:** The v1.0 passphrase contract (argv-inline rejected; env/file/fd allowed)
is enforced by `resolve_passphrase()`. If `--pin` introduces a new raw argv flag that bypasses
`resolve_passphrase`, the pin value ends up in `/proc/<pid>/cmdline`, shell history, and CI
logs — exactly the attack surface that `resolve_passphrase` was designed to prevent.

**Why it happens:** The developer adds `--pin <value>` as a separate flag, reasoning that "it's
a PIN, not a passphrase." The same argv-exposure attack applies to any secret passed via argv.

**Prevention:**
1. `--pin` must accept values through `resolve_passphrase` (same env/file/fd priority chain),
   or through a dedicated TTY prompt (for interactive use). It must NOT accept the PIN value
   as a direct argument to `--pin <value>`.
2. Use a distinct env var name (`CIPHERPOST_PIN`) and distinct file/fd flags (`--pin-file`,
   `--pin-fd`) so that pin and passphrase are not conflated — but both go through equivalent
   argv-rejection logic.
3. A test asserting `cipherpost send --pin 123456 <uri>` exits with `Error::Config` and a
   message directing the user to `CIPHERPOST_PIN` or `--pin-file`.

**Warning signal:** `--pin <value>` flag that accepts raw string input and does not emit
an "argv-inline rejected" error. No `CIPHERPOST_PIN` env var documented.

**Phase:** Phase 8. The PIN input contract must be in Phase 8 plan 01 SPEC.md update before
any PIN flag implementation.

---

## Phase-Specific Warnings Summary

| Phase | Topic | Pitfall # | Category | Key Mitigation |
|-------|-------|-----------|----------|----------------|
| 5 | Passphrase-file newline strip | 30 | cli | Exact one-LF strip; test space-ending passphrase |
| 5 | Passphrase-fd double-close | 31 | cli | `BorrowedFd`, not `FromRawFd`; test FD lifecycle |
| 5 | Traceability-table drift fix | 32 | cli | CI check must fail loudly; confirm no external parsers |
| 5 | DHT label audit scope | 33 | dht | Audit is confirm-not-change; assert label constants in CI |
| 5 | Pin-version blessing in SPEC | 34 | cli | State API version ranges, not exact versions; defer to Cargo.toml |
| 5 | `CIPHERPOST_PASSPHRASE` visibility | 35 | cli | FD > file > env preference; warn when env used |
| 6 | X.509 PEM/BER/DER normalization | 19 | jcs | Store normalized DER only; reject BER; commit fixture |
| 6 | X.509 plaintext size check | 22 | cli | Pre-encrypt size check; per-variant `material_plaintext_size()` |
| 6 | HKDF enumeration test extension | 36 | crypto | Extend allowlist before adding new call sites |
| 7 | PGP armor non-determinism | 20 | jcs | Store binary packet stream; reject secret keys at ingest |
| 7 | SSH comment stripping | 21 | jcs | Strip comment column; store wire blob only; commit fixture |
| 7 | PgpKey/SshKey plaintext size check | 22 | cli | Apply same pattern established in Phase 6 |
| 7 | HKDF enumeration extension for new variants | 36 | crypto | Apply Phase 6 pattern |
| 8 | PIN distinguishable oracle | 23 | crypto | Unify PIN error Display; extend sig-failure enumeration test |
| 8 | PIN offline brute force | 24 | crypto | Minimum 8-char PIN; document in THREAT-MODEL; reject short PINs |
| 8 | burn is local-state-only | 25 | state | THREAT-MODEL section; acceptance screen warning |
| 8 | burn atomic ordering (mark-then-emit) | 26 | state | Keep v1.0 ordering; sentinel is never deleted; test emit-failure |
| Quick (260427-axn) | per-share_ref receive lock (TOCTOU close) | 26 (amended) | state | Per-share_ref advisory file lock; emit-before-mark ordering unchanged; lock failures → Error::Io (no new variant) |
| 8 | burn + receipt semantics | 27 | state | Decide Option A or B in plan 01; record in PROJECT.md |
| 8 | `--pin` argv surface | 37 | cli | Must go through `resolve_passphrase` equivalent; test argv rejection |
| 9 | Concurrent-racer test correctness | 28 | test | Use `Barrier`; true concurrent threads; MockTransport `cas` semantics |
| 9 | Real-DHT tests CI-hostile | 29 | test | Feature-flag `real-dht-e2e`; pre-flight UDP check; 120s timeout |

---

## Protocol-Version Impact Summary

Breaking any of the following in v1.1 requires a `protocol_version` bump and a SPEC.md migration section:

| Change | Protocol Break? | Notes |
|--------|----------------|-------|
| Rename DHT label `_cipherpost` or `_cprcpt-*` | YES | Wire break; v1.0 shares unresolvable |
| Add new `Material` variant with new `bytes` encoding | NO (new variant, new tag) | v1.0 clients return `Error::NotImplemented`; v1.1 clients handle it |
| Change `share_ref` derivation formula | YES | All existing share URIs become invalid |
| Change `Envelope` field names or types | YES | Inner signature breaks |
| Add `burn_mode` field to `Envelope` | NO (inside encrypted blob; additive) | v1.0 clients ignore unknown fields if serde allows it; verify with `#[serde(deny_unknown_fields)]` setting |
| Add `burn_mode` flag to `OuterRecord` (outer, unencrypted) | YES — and violates design | Mode flags must NOT be in outer unencrypted record; see Pitfall 23 |
| Change passphrase file strip behavior | NO (CLI contract only) | Not a wire format |
| Change DHT label TTL value | NO (advisory to DHT nodes; not protocol-enforced) | SPEC.md update only |

---

## Sources

- v1.0 PITFALLS.md (pitfalls 1–18 — predecessor document, load-bearing lock-ins)
- SPEC.md §3 (wire format, Material variants, OuterRecord, Receipt)
- THREAT-MODEL.md (adversary analysis, error-oracle hygiene, receipt semantics)
- PROJECT.md (v1.1 phase descriptions, Constraints, Key Decisions)
- MILESTONES.md (v1.0 deferred items — concurrent-racer, real-DHT, traceability-table)
- RETROSPECTIVE.md (What Was Inefficient — traceability drift, crate-pin drift)
- CLAUDE.md (load-bearing lock-ins — ed25519-dalek exact pin, serial_test pattern, dual-sig ordering)
- RFC 4880 (OpenPGP Message Format — packet tags for public vs. secret keys)
- RFC 8785 (JCS — canonical JSON rules for new Material variants)
- OpenSSH wire format (draft-miller-ssh-agent — padding and comment field behavior)
- age crate: passphrase recipient scrypt parameters, multi-recipient identity-try ordering
- Rust std::os::unix::io (BorrowedFd vs FromRawFd — FD ownership semantics)
