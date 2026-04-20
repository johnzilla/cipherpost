# Feature Research — Cipherpost

**Domain:** Self-sovereign CLI tool for cryptographic-material handoff (keys, certs, credentials, passphrases)
**Researched:** 2026-04-20
**Confidence:** MEDIUM-HIGH (landscape well-mapped; CLI conventions HIGH; user-acceptance expectations MEDIUM — based on competitor docs, not direct user research)

## Method

Benchmarked Cipherpost's anchor competitors (per PRD Competitive Positioning table) against the PRD's MVP Scope. For each competitor, enumerated the feature set a real user relies on, then classified for Cipherpost as **Table Stakes** (must have), **Differentiators** (our competitive wedge), **Anti-Features** (deliberately excluded), and **Skeleton-Scope** (required for the walking-skeleton milestone to feel like a real tool, not a toy).

CLI ergonomics benchmarked against `age`/`rage` (closest lineage — same cryptographic primitives, same UNIX-composability philosophy), with supporting references to `gpg`, `ssh-keygen`, and `cosign`.

---

## Competitor Feature Inventory

What users of each tool rely on in practice. This is the "floor" — the features that are so assumed users don't even mention them, but notice immediately when missing.

### Bitwarden Send
- End-to-end encryption (AES-256), client-side
- Text up to 1,000 chars or files up to 500 MB (100 MB on mobile)
- Expiration (max 31 days), custom timestamp, max access count
- Optional password protection (separate from encryption — authentication only)
- Recipient needs no account
- Sender can track when file accessed (basic audit)

### 1Password Item Sharing ("Psst!")
- Link expiration: 1h / 1d / 7d / 14d / 30d / single-view
- Restrict to specific email addresses OR anyone-with-link
- Email verification via one-time code when recipient-restricted
- Password history stripped from shared copy (leakage reduction)
- Admin policy controls (business tier): max duration, enforce email verification, require single-view
- Client-side encryption, server in Frankfurt (disclosed)

### SendSafely
- OpenPGP + AES-256, browser-side decryption
- Email verification code (required by default)
- Optional SMS 2FA for recipient
- Detailed audit log: when, how, from what IP recipient touched the data
- Audit Log API for SIEM integration
- Post-expiry archival: payload deleted, transfer record retained
- Package forwarding, recipient management

### Tresorit Send
- Zero-knowledge, client-side encryption
- Default 7-day expiration; 14-day post-expiry metadata deletion
- Password protection, expiry, open-count & download limits
- Email verification
- Watermarking (enterprise)
- Access logs: email, open date, IP, platform

### crypt.fyi
- Open source, zero-knowledge, browser-side
- Burn-after-read (with bot-burn protections)
- Password protection, customizable expiration
- ML-KEM post-quantum encryption
- Rate limits for brute-force mitigation

### FileKey
- Fully offline, zero-knowledge, passkey-based (WebAuthn + PRF extension)
- AES-256, no servers at all (local only)
- Share Key is public; recipient identified by Share Key
- No accounts, no tracking
- Requires compatible passkey-capable password manager / hardware key
- Browser + OS must support WebAuthn PRF (a hard compatibility gate)

### Keybase (historical)
- Identity proofs: linked Twitter/GitHub/Reddit/HN/websites to keys — publicly verifiable
- KBFS: per-user encrypted filesystem (`/public/`, `/private/`, `/team/`)
- All files signed by client; private files encrypted end-to-end
- 250 GB free storage
- Team filesystems for group handoff
- Chat layer with identity integration
- (Cautionary tale: Zoom acquisition → neglect; operator risk realized)

### PGP over email (status-quo default)
- Totally serverless in the hand-off moment (email is the carrier)
- Accountless (key is identity)
- Fingerprints for manual verification
- Detached signatures, armor (PEM) encoding for pastability
- Severe usability burden: keyring management, WoT, no receipt, no expiration, no purpose binding
- Used by FIRST, MSRC, PSIRT teams today because nothing better is ubiquitous
- **This is the real competitor.** Not Bitwarden Send. If Cipherpost can't peel security engineers off `gpg`, it fails regardless of what Bitwarden does.

---

## Feature Landscape

### Table Stakes (Users Expect These)

Features a CLI-based secure-handoff tool MUST have or power users will reject it. Missing any of these = product feels unfinished.

| # | Feature | Why Expected | Complexity | PRD Coverage | Milestone |
|---|---------|--------------|------------|--------------|-----------|
| T1 | Clear error on expired/invalid share ("this share expired at 14:32 UTC, 2h ago") | Users waste hours debugging silent failures | LOW | Implicit in TTL design (line 47) — **not specified as UX requirement** | Skeleton |
| T2 | Visible sender fingerprint at pickup time (truncated + full form) | Recipient must be able to out-of-band verify sender | LOW | Implicit in Ed25519 identity — **not specified as UX element** ⚠ GAP | Skeleton |
| T3 | Deterministic recipient identification (pubkey on every invocation, not randomised) | Senders need a stable target; any shuffling breaks trust | LOW | Covered — `--share <pubkey>` is the addressing model | Skeleton |
| T4 | Stdin/stdout support with `-` convention (age/gpg/rage-compatible) | UNIX composability; `cat secret \| cipherpost send --share <pk>` must work | LOW | **Not specified** ⚠ GAP | Skeleton |
| T5 | `--output` / `-o` flag writing to file or `-` for stdout | Match age/gpg conventions; avoid secrets leaking to terminal scrollback | LOW | **Not specified** ⚠ GAP | Skeleton |
| T6 | Passphrase prompt on TTY, reject silently-piped passphrase unless `--passphrase-fd` or env | ssh-keygen / age behavior; prevents accidental shell-history leaks | LOW-MED | Covered via Argon2id design; prompt UX **not specified** ⚠ GAP | Skeleton |
| T7 | Non-interactive mode (`--yes`, `--batch`) for scripting in CI / automation | Security engineers script everything; interactive-only = adoption blocker | LOW | **Not specified** ⚠ GAP | v1.0 |
| T8 | Exit codes distinguish: success / expired / signature-failed / decrypt-failed / not-found / network | Scripts must differentiate; a single nonzero is useless for ops | LOW | **Not specified** ⚠ GAP | Skeleton |
| T9 | `--help` with examples, not just flag enumerations | Crypto CLIs with bad `--help` get abandoned — see anyone's first encounter with `gpg` | LOW | **Not specified** | Skeleton |
| T10 | Progress / status on DHT publish & lookup ("publishing to N nodes...") | DHT is slow (seconds) and opaque; silent hang = perceived breakage | LOW-MED | **Not specified** ⚠ GAP | Skeleton |
| T11 | Idempotent re-pickup: `receive` can be run twice, second time says "already accepted on <date>" | Users re-run commands; second run must not appear broken or cause double-receipt | MED | **Not specified** ⚠ GAP — receipt design implies single acceptance | v1.0 |
| T12 | Sender identity proof / fingerprint displayed with every `list` / `receive` output | Every crypto tool shows the key it's operating on — users check fingerprints constantly | LOW | Implicit | Skeleton |
| T13 | Expiration display in local time AND absolute UTC | Timezone ambiguity = expired-before-you-thought = lost secrets | LOW | Implicit in TTL handling | Skeleton |
| T14 | Max-access-count semantics (default: 1, the pickup retires the share) | Every competitor has it; burn-after-read is the normal mental model for one-off handoff | MED | `--burn` mode deferred per PROJECT.md L61 — but basic single-pickup semantics are table stakes even without `--burn` | Skeleton |
| T15 | Clipboard-safe output option (`--clip` or recommend `pbcopy`/`wl-copy` in docs) | Security engineers paste secrets; tool should guide safe handling | LOW | **Not specified** ⚠ GAP (docs-level) | v1.0 |
| T16 | Human-readable fingerprint format consistent with ecosystem (`ed25519:SHA256:base64` or similar) | Matches `ssh-keygen -l` / OpenSSH expectation | LOW | **Not specified** ⚠ GAP | Skeleton |
| T17 | Accept-step display of ALL binding metadata (purpose, sender fp, TTL remaining, payload type) *before* decryption | This is the whole point of the acceptance step — must be complete | LOW | Covered (PROJECT.md L39) — but "all metadata" specificity **not specified** | Skeleton |
| T18 | Signature verification failure is *fatal* and visible, never skipped | Dual signatures (PROJECT.md L34) are useless if the verifier can be bypassed | LOW | Covered (L34) — "signature verification is required before any decryption" | Skeleton |
| T19 | `version` subcommand showing build hash + crypto primitives in use | Security review requires reproducible "what code ran" | LOW | **Not specified** ⚠ GAP | Skeleton |
| T20 | Shell completion (`cipherpost completion bash/zsh/fish`) | Standard modern-CLI expectation (clap_complete makes it trivial) | LOW | **Not specified** ⚠ GAP | v1.0 |

### Differentiators (Where Cipherpost Wins)

Features Cipherpost can credibly claim that competitors cannot. These are the *why-pick-us* column. Each is already in the PRD; flagged here for emphasis.

| # | Feature | Value Proposition | Who Can't Match It | PRD Ref |
|---|---------|-------------------|--------------------|---------| 
| D1 | **No operator** — Mainline DHT only | "We can't be subpoenaed because we don't exist as an operator" — compliance / nation-state-concern language | Bitwarden/1P/SendSafely/Tresorit/crypt.fyi (all have servers) | PRD Principles #1 |
| D2 | **Accountless** — Ed25519 keypair is identity | No email verification, no account lifecycle, no password reset | Bitwarden/1P/SendSafely/Tresorit; Keybase had accounts too | PRD Principles #2 |
| D3 | **Signed receipt published to DHT** | Cryptographic non-repudiation: "X received this at T, signed by their pubkey" — auditable without a server | None. This is the cipherpost delta over cclink and over everything else | PROJECT.md L42-44; PRD line 69 |
| D4 | **Purpose binding** (free-text, signed into payload) | Sender-controlled context appears on acceptance screen — legal/operational scope limit baked into the handoff | 1Password has notes, but they aren't signed into a cryptographic binding; nobody else | PROJECT.md L38; PRD L68 |
| D5 | **Explicit acceptance step** before material is revealed | Creates a human-in-loop inflection point where recipient reviews terms — matches legal "affirmative consent" and e-discovery patterns | None of the share-link tools — they reveal on click | PROJECT.md L39; PRD L69 |
| D6 | **Ciphertext-only on the wire** (metadata + payload both encrypted) | DHT observers see opaque blobs only; even traffic analysis is constrained to PKARR-level patterns | Bitwarden/1P store *encrypted* items but server sees metadata (recipient email, timestamps). SendSafely sees even more | PRD Principles #3; PROJECT.md L48 |
| D7 | **Purpose-built for keys, not files** — typed payload schema | X.509 / PGP / SSH / generic-secret envelopes with shape the recipient can validate before accept | Everyone else is a generic file share; user has to enforce "this is a PGP key" socially | PRD L64; PROJECT.md L37 (reserved for v1.0) |
| D8 | **Dual signatures** (PKARR packet + inner canonical JSON) | Defense in depth — compromising one signing context doesn't forge the other | None | PROJECT.md L34 |
| D9 | **Open protocol, open source, MIT** | Auditable, forkable, self-hostable (well, it's serverless — "self-running") | 1P (closed), SendSafely (closed), Tresorit (closed); Bitwarden partial; crypt.fyi/FileKey yes | PRD Principles #5 |
| D10 | **Short default TTL (4h)** for keyshare | Default-safe for the domain — most keyshare use cases are time-bounded (outage response, onboarding) | Competitors default 7d-31d; Cipherpost's posture is "if you need longer, you need a vault, not a handoff" | PROJECT.md L47; PRD L66 |

**The combination** — no-server + accountless + attestation primitives + typed-crypto-material payloads — is the defensible intersection. No single competitor hits all four. (PRD Competitive Positioning table, lines 123-132.)

### Anti-Features (Deliberately NOT Building)

Features users will ask for that Cipherpost must reject. Each rejection has an alternative to direct the user toward.

| # | Anti-Feature | Why Users Ask | Why We Refuse | Redirect To | PRD Ref |
|---|--------------|---------------|---------------|-------------|---------|
| A1 | Long-term secret storage ("keep this safe for me") | Natural extension — "I already put it in Cipherpost…" | That's a vault; different threat model, different retention, different UX | Bitwarden, 1Password, HashiCorp Vault | PRD Non-users |
| A2 | Key rotation / lifecycle management | Keys expire; "rotate this to X" seems obvious | That's a KMS; out of scope — we hand off, we don't manage | AWS KMS, GCP KMS, HashiCorp Vault | PRD Non-users |
| A3 | Signing / crypto operations on user's behalf | "I have the key, can you just sign this for me?" | Different trust model; HSM territory | cosign, ssh-agent, Sigstore | PRD Non-users |
| A4 | General file transfer (large binaries, photos, tarballs) | 64KB limit feels small; "why can't I send this CSV?" | Different domain (throughput, not attestation); contaminates the schema | Magic Wormhole, croc, Tresorit Send | PRD Non-users; 64KB ceiling PROJECT.md L48 |
| A5 | Web UI in v1.x | "My colleague won't use a CLI" | CLI + TUI is the adoption model; web UI implies hosted service = operator = violates Principle #1 | Wait for v2+, or use the TUI | PROJECT.md L79 |
| A6 | Central directory / key discovery ("find users by email") | Comes up whenever anyone demos it | That's an account system; "no accounts" means no directory. Out-of-band pubkey exchange is the point | Keyoxide, PKARR-level discovery (different product) | PRD Principles #2 |
| A7 | Optional relay server / "if DHT is slow, use our relay" | DHT latency/unreliability frustration | Any relay = operator = subpoena target = defeats the thesis. Relay-assist is a *possible commercial tier later*, never v1.x core | Sender republishes; recipient retries | PROJECT.md L77, L94 |
| A8 | SSO / IdP federation, SAML, OIDC | Enterprise ask | "Key is identity" is the point; federation inverts the trust model | Commercial tier later (if ever) | PROJECT.md L78 |
| A9 | SIEM export, centralised audit | Enterprise ask | Contradicts "no operator"; receipts are already locally exportable and DHT-attested | Local audit log (v1.0), user scripts export to their own SIEM | PROJECT.md L78 |
| A10 | In-tool chat / messaging | Keybase shadow — "while I'm here, can we also talk?" | Scope expansion disease. Signal / Session / Keybase's successor exist for chat | Use Signal | (Implicit) |
| A11 | Browser extension / "share directly from GitHub" | Workflow integration request | Requires hosted bridge or relay; violates Principle #1 | User pipes: `gh api ... \| cipherpost send --share $PK` | (Implicit) |
| A12 | Notification on pickup (push / email / webhook) | "Tell me when they received it" | Receipt-on-DHT already does this attestably; push-notification infrastructure = operator | `cipherpost receipts --watch` polls the DHT | (Implicit — receipt model covers this, just not the delivery mechanism) |
| A13 | Auto-renew / extend TTL | "It expired before they got to it" | Each share is immutable + signed; "extension" = new share. That's a feature, not a bug | Sender re-sends with new TTL | (Implicit from immutable-payload design) |
| A14 | Multi-recipient broadcast in v1.0 | "Send to three maintainers at once" | Explicitly deferred to v1.2; acceptance + receipt semantics are fundamentally pair-wise and get messy with N>1 | Send N times (scripted) | PROJECT.md L69; PRD L79 |
| A15 | Destruction attestation in v1.0 | "Prove they deleted it" | Deferred to v1.1; requires recipient-side attestation infrastructure that doesn't exist yet | Wait for v1.1 | PROJECT.md L68 |

### Skeleton-Scope Subset

Of the Table Stakes above, these are required to ship a walking skeleton that a security engineer will use *twice*. Shipping without any of these risks the first-use impression: "this is a demo, not a tool."

**Must ship in the walking skeleton** (a subset of Table Stakes):

- **T1** Clear error on expired/invalid share
- **T2** Visible sender fingerprint at pickup — the *entire point* of accepting is knowing who you're accepting from
- **T3** Deterministic recipient identification (pubkey)
- **T4** Stdin/stdout `-` convention (without this, `cipherpost` doesn't compose with shell pipelines and everyone writes a wrapper)
- **T5** `--output`/`-o` flag (without this, output goes to terminal and leaks to scrollback)
- **T6** TTY passphrase prompt (never echo, never accept from shell history without an explicit flag)
- **T8** Meaningful exit codes (expired / sigfail / decryptfail / notfound / network)
- **T9** `--help` with one concrete example per subcommand
- **T10** DHT publish/lookup progress output (stderr, so it doesn't contaminate stdout)
- **T12** Fingerprint display on every relevant command
- **T13** Expiration display in local + UTC
- **T14** Single-pickup semantics (without `--burn` mode, but the default share retires on pickup)
- **T16** Fingerprint format consistent with ecosystem
- **T17** Accept-step shows all binding metadata before decryption
- **T18** Signature verification fatal on failure (covered by PROJECT.md L34, but verify in tests)
- **T19** `version` subcommand with crypto-primitive disclosure

**Deferrable from skeleton to v1.0**:

- T7 Non-interactive batch mode — useful but skeleton is for interactive validation
- T11 Idempotent re-pickup — nice-to-have, not foundational
- T15 Clipboard guidance — docs-level, not code-level
- T20 Shell completion — stock `clap_complete` add-on, ship when convenient

---

## CLI Ergonomics — Conventions to Match

Cipherpost should inherit the ergonomics of `age` specifically (same cryptographic primitives, same UNIX-composability ethos), with supporting patterns from `ssh-keygen`, `gpg`, and `cosign`. These are conventions power users already know.

### Flag conventions (match age/rage exactly where possible)

| Convention | Source | Cipherpost should... |
|------------|--------|----------------------|
| `-r, --recipient <pubkey>` for encryption target (repeatable) | age, rage | Match as-is; `cipherpost send --share` aliased to `-r` |
| `-R, --recipients-file <path>` for batch recipients | age, rage | Match if we ever support multi-recipient (v1.2); reserve the flag now |
| `-i, --identity <path>` for private-key file | age, rage | Match as-is for identity override |
| `-p, --passphrase` encrypt-with-passphrase (not recipient) | age, rage | Match for `--pin` mode when it lands (deferred per PROJECT.md L61) |
| `-o, --output <path>` writes to file or stdout if omitted | age, rage, gpg | Match as-is |
| `-d, --decrypt` | age, rage, gpg | Not directly applicable — Cipherpost has `send`/`receive` subcommands, not a single command with mode flags. Prefer subcommand style (closer to cosign) |
| `-a, --armor` PEM-armored ASCII output | age, rage, gpg | Match for any payload-export operation (e.g., `cipherpost identity export --armor`) |
| `-` as filename = stdin/stdout | age, rage, gpg, cosign | **Mandatory**. `cipherpost send --share <pk> -` reads secret from stdin |
| `-N '<passphrase>'` for non-interactive passphrase | ssh-keygen | Prefer `--passphrase-file` or `CIPHERPOST_PASSPHRASE` env over inline flag (shell-history hazard). Document explicitly. |

Sources: [age(1) Arch manpage](https://man.archlinux.org/man/extra/age/age.1.en), [age GitHub](https://github.com/FiloSottile/age), [rage GitHub](https://github.com/str4d/rage), [ssh-keygen(1)](https://www.man7.org/linux/man-pages/man1/ssh-keygen.1.html).

### Subcommand structure (match cosign's verb-noun style)

Cipherpost has more verbs than `age` does — it's closer to `cosign` or `gh` than to a single-purpose encrypt/decrypt tool. Recommended verb-first structure:

```
cipherpost <verb> [<noun>] [flags]

cipherpost identity generate
cipherpost identity show
cipherpost identity export [--armor]

cipherpost send --share <pubkey> [--purpose "<text>"] [--ttl 4h] [--payload-type generic-secret] [-o receipt.json] [file | -]
cipherpost send --self [flags] [file | -]

cipherpost receive [--id <share-id>] [--accept] [-o -]
cipherpost list                 # pending shares targeting this identity
cipherpost receipts             # receipts published for shares I sent
cipherpost receipts --watch     # poll DHT

cipherpost version
cipherpost completion {bash|zsh|fish}
```

Rationale:
- **Verbs are workflow stages** (`send`, `receive`, `list`, `receipts`) — matches how users think about the task
- **Nouns are objects** (`identity`) — pairs with conventional verbs (`generate`, `show`, `export`)
- **No single god-command with a dozen flags** — cosign learned this; `cosign sign-blob` vs `cosign sign` is the right direction
- Sources: [cosign CLI](https://docs.sigstore.dev/quickstart/quickstart-cosign/), [Sigstore Cosign repo](https://github.com/sigstore/cosign)

### Passphrase prompting

- **Default**: prompt on controlling TTY, no echo, matches `ssh-keygen` / `age` / `gpg` behavior
- **Non-interactive**: accept `CIPHERPOST_PASSPHRASE` env var, `--passphrase-file <path>`, and `--passphrase-fd <n>` (for keyed-fd passing in CI)
- **Never** accept `--passphrase <string>` inline — shell-history leak, appears in `ps`, violates basic hygiene. `ssh-keygen -N` is the exception, and it's widely regarded as a mistake even within OpenSSH.
- **On non-TTY stdin**: refuse passphrase operations unless an explicit env-var / file / fd is provided. `age` does this; users expect it.
- Reference: [age issue #603 on stdin passphrase](https://github.com/FiloSottile/age/issues/603).

### Output hygiene

- **Secrets go to stdout only when `-o -` is explicit**, never to TTY without a confirmation flag (age does this: refuses to output binary to a TTY without `-o -`)
- **Status / progress goes to stderr**, always. So pipelines work: `cipherpost receive -o - | gpg --import`.
- **JSON output mode** (`--json` global flag) for scripting — receipts, share metadata, identity info all exportable as JSON. Matches `gh`, `kubectl`, `cosign`.
- Reference: [age UX discussion #35](https://github.com/FiloSottile/age/issues/35).

### Shell completion

- Ship `cipherpost completion {bash,zsh,fish}` — standard `clap_complete` output
- Pubkeys and share-IDs should emit `ValueHints` so completion can fill them intelligently (pending shares, known identities on disk)
- Reference: [clap_complete docs](https://docs.rs/clap_complete/), [Rain's Rust CLI recommendations](https://rust-cli-recommendations.sunshowers.io/handling-arguments.html)

### Error messages

Model after `age`'s helpful pattern: when a flag is used in the wrong mode, say so *and suggest the right one*:
- `age` example: `"-i/--identity can't be used in encryption mode. Did you forget to specify -d/--decrypt?"`
- Cipherpost equivalents: "`--share` and `--self` are mutually exclusive. Use `--self` to send to yourself, `--share <pubkey>` to send to another identity."
- Reference: [age UX discussion #35](https://github.com/FiloSottile/age/issues/35).

### CLI Guidelines (general)

Follow [clig.dev](https://clig.dev/) (the *Command Line Interface Guidelines* canon), particularly:
- Output for humans by default, machines on `--json`
- Exit codes distinguish failure modes
- Respect `NO_COLOR` env var
- No dotfile config for v1.0 (`age`'s "no config options" philosophy is correct for this tool class)

---

## Feature Dependencies

```
Identity (generate, passphrase-wrapped)
    └── required by → send (self)
    └── required by → send (share)
    └── required by → receive
    └── required by → receipts

send (self)  ←── simpler: validates crypto + DHT publish path, no recipient
    └── feeds into → send (share) [same code path with different recipient resolution]

send (share)
    ├── requires → payload schema (generic-secret for skeleton)
    ├── requires → purpose binding (free-text field in schema)
    └── enables → receive-side acceptance flow

receive
    ├── requires → signature verification (dual — PKARR + inner JSON)
    ├── requires → acceptance display (purpose, sender fp, TTL, type)
    └── feeds into → receipt publication

receipt publication
    ├── requires → receive (acceptance step completed)
    └── enables → receipts subcommand (sender-side verification)

TTY passphrase prompt
    └── required by → any command that unlocks identity

Shell completion ──enhances──> every subcommand (but not strictly required)

--burn mode  ──conflicts──> default single-pickup semantics
    (Not a real conflict — "burn" is stronger single-pickup with destruction attestation;
     default skeleton single-pickup is a weaker version. Ensure the naming doesn't collide.)
```

### Dependency Notes

- **Identity → everything**: the very first thing to implement, and the only feature that unlocks the rest. Skeleton Phase 1 content.
- **Self-mode before share-mode**: same code path, fewer moving parts (no recipient pubkey resolution). Ship self-mode first to validate the crypto + DHT plumbing, then share-mode piggybacks.
- **Signature verification gates acceptance**: never let acceptance UI display decrypted content — the verify step must complete and pass first, or the tool surfaces a fatal error and aborts.
- **Receipt is the cipherpost delta**: without it, this is just cclink with a rebrand. Skeleton is not complete without receipt publication + `cipherpost receipts` readback.
- **TTY passphrase**: required infrastructure for every unlock; build once, use everywhere. Third thing to implement after identity gen/load.

---

## MVP / Milestone Mapping

### Walking Skeleton (this milestone)

Per PROJECT.md L21-54, the walking skeleton scope is:
- Identity generate + unlock (passphrase-wrapped)
- `send --self` round trip (DHT publish + DHT retrieve + decrypt)
- `send --share <pubkey>` round trip (dual-signed, age-encrypted, acceptance required)
- Signed receipt published on accepted pickup + `cipherpost receipts` readback
- Generic-secret payload type only (cert/PGP/SSH reserved in schema)
- Purpose binding + explicit acceptance step
- TTL (4h default, `--ttl` override), 64KB payload cap
- Draft SPEC.md / THREAT-MODEL.md / SECURITY.md

**Features to layer in from this research** (Table Stakes subset from above):
- T1, T2, T3, T4, T5, T6, T8, T9, T10, T12, T13, T14, T16, T17, T18, T19
- Subcommand structure: `identity {generate,show,export}`, `send {--self | --share}`, `receive`, `list`, `receipts`
- Flag conventions: `-r/--share`, `-i/--identity`, `-o/--output`, `-` for stdin/stdout
- Passphrase hygiene: TTY prompt default, env-var / fd alternatives for automation
- Output hygiene: stdout = data, stderr = status, `--json` reserved but implementation can be thin

### v1.0 (after skeleton validates)

Adds from PROJECT.md L60-64 + this research:
- `--pin` and `--burn` encryption modes
- Additional payload types: X.509, PGP, SSH
- TUI wizard
- Exportable audit log (local file; no SIEM)
- Shell completion (T20)
- Clipboard guidance docs (T15)
- Non-interactive batch mode (T7)
- Idempotent re-pickup semantics (T11)
- Three-real-user launch criterion + independent public review

### v1.1+ (deferred beyond v1.0)

Per PROJECT.md L66-69:
- Destruction attestation workflow (v1.1)
- Multi-recipient broadcast (v1.2)
- HSM integration (v1.3)

### Never (per PRD non-goals, PROJECT.md L71-79)

- Full key lifecycle / KMS features
- Long-term storage / vault features
- Signing/crypto on user's behalf
- General file transfer
- Any server / relay / operator in v1.x core
- SSO / SAML / OIDC federation
- SIEM export
- Web UI in any v1.x

---

## Gaps ⚠ — Things the PRD Should Address That It Currently Doesn't

Surfaced by the competitor benchmark. These are CLI-UX gaps; the cryptographic and protocol scope in the PRD is comprehensive.

| Gap | Impact | Suggested Fix |
|-----|--------|---------------|
| ⚠ G1: PRD doesn't specify fingerprint display format | Recipients can't out-of-band-verify without a canonical format; two implementations could disagree | SPEC.md should canonicalize: e.g., `ed25519:SHA256:<base64>` (OpenSSH-compatible) |
| ⚠ G2: No exit-code taxonomy | Scripting is impossible without it | SPEC.md or a `docs/exit-codes.md`: enumerate {0=ok, 1=generic, 2=expired, 3=sigfail, 4=decryptfail, 5=notfound, 6=network, 7=user-declined} |
| ⚠ G3: No stdin/stdout composability requirement | A crypto CLI that can't pipe fails in CI; everyone writes wrappers | Add to PROJECT.md Active requirements: "All payload I/O supports `-` for stdin/stdout; status on stderr" |
| ⚠ G4: Passphrase non-interactive contract unspecified | Automation users can't tell what's safe to script | SPEC.md: accept `CIPHERPOST_PASSPHRASE`, `--passphrase-file`, `--passphrase-fd`; reject inline `--passphrase <s>`; explicit TTY-required default |
| ⚠ G5: DHT publish/lookup progress/timeout UX unspecified | DHT is the weakest user-perceived link; silent hangs kill trust | SPEC.md: specify visible progress to stderr, overall timeout (e.g., 30s default with `--dht-timeout`), clear error on timeout |
| ⚠ G6: No version/build-info requirement | Security review needs reproducibility | Add `cipherpost version` to skeleton requirements; include git hash + crypto-primitive list |
| ⚠ G7: No spec for what the acceptance-step screen shows | The acceptance step is the user-visible differentiator; ambiguous spec = inconsistent implementations | SPEC.md: exact content — `{purpose, sender_fingerprint, sender_identity_context_if_any, ttl_remaining, payload_type, payload_size_bytes}` + "accept? [y/N]" |
| ⚠ G8: No shell-completion commitment | Minor, but every modern CLI has it and users notice its absence | Add to v1.0 scope |
| ⚠ G9: No clipboard guidance | Users will `cipherpost receive` and paste-into-chat anyway; should tell them the hygienic way | Docs-level: README section "Handling secrets safely after receive" |
| ⚠ G10: No idempotency semantics defined | `cipherpost receive` run twice — does it double-receipt? error? | Needs an explicit answer in SPEC.md. Recommendation: second receive on already-accepted share reports the prior acceptance timestamp and does **not** republish the receipt |

None of these change the **protocol** — they're all at the CLI / UX / spec-precision layer. But they're what makes the difference between "tool a security engineer will actually use" and "interesting prototype."

---

## Feature Prioritization Matrix (Skeleton Phase)

| Feature | User Value | Impl Cost | Priority | Notes |
|---------|------------|-----------|----------|-------|
| Identity generate/unlock | HIGH | MEDIUM | P1 | Prerequisite for everything; vendor from cclink |
| Self-mode round trip | HIGH | MEDIUM | P1 | Validates DHT + crypto plumbing |
| Share-mode round trip | HIGH | MEDIUM | P1 | Core skeleton value |
| Acceptance step w/ purpose display | HIGH | LOW | P1 | Differentiator D5; cheap to implement, high signal |
| Signed receipt publish + read | HIGH | MEDIUM | P1 | Differentiator D3; the cipherpost delta |
| Dual signature verify (fatal on fail) | HIGH | LOW | P1 | Already in PROJECT.md L34; verify with tests |
| TTY passphrase prompt | HIGH | LOW | P1 | Table stake; trivial with rpassword/dialoguer |
| Stdin/stdout `-` support | HIGH | LOW | P1 | Table stake; blocks CI adoption without it |
| `-o/--output` flag | HIGH | LOW | P1 | Table stake |
| Fingerprint display (canonical format) | HIGH | LOW | P1 | Table stake; pick format once |
| Meaningful exit codes | MEDIUM | LOW | P1 | Table stake; just a matter of discipline |
| Clear expired/invalid errors | HIGH | LOW | P1 | Table stake |
| DHT progress to stderr | MEDIUM | LOW | P1 | Prevents perceived-hang UX failure |
| `version` subcommand | MEDIUM | LOW | P1 | Table stake; trivial |
| `--help` with examples | MEDIUM | LOW | P1 | Discipline, not code |
| Single-pickup retire (no --burn) | HIGH | MEDIUM | P1 | Table stake — and foundation for --burn later |
| Shell completion | LOW | LOW | P2 | Ship when convenient; clap_complete is a freebie |
| `--json` output | MEDIUM | MEDIUM | P2 | Reserve the flag, implement fully in v1.0 |
| Non-interactive batch mode | MEDIUM | LOW | P2 | v1.0 |
| Idempotent re-receive | LOW | MEDIUM | P2 | Clarify semantics now, implement in v1.0 |
| Clipboard guidance (docs only) | LOW | LOW | P2 | v1.0 docs pass |
| TUI wizard | MEDIUM | HIGH | P3 | v1.0, explicitly out of skeleton |
| `--pin` / `--burn` modes | HIGH | MEDIUM | P2 | v1.0 — but the default skeleton single-pickup retire approximates `--burn` |
| X.509/PGP/SSH payload parsing | MEDIUM | HIGH | P3 | v1.0; skeleton validates protocol shape with generic-secret only |

---

## Competitor Feature Analysis — Side by Side

| Feature | Bitwarden Send | 1Password Sharing | SendSafely | Tresorit Send | crypt.fyi | FileKey | Keybase (hist.) | PGP/email | **Cipherpost (planned)** |
|---|---|---|---|---|---|---|---|---|---|
| No operator | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (local only) | ✗ | ✓ | **✓ (DHT only)** |
| Accountless | ✓ | ✗ | ✗ | ✗ | ✓ | ✓ | ✗ | ✓ | **✓** |
| E2E encryption | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | **✓ (age)** |
| Metadata also encrypted | partial | partial | ✗ | partial | partial | ✓ | partial | ✗ | **✓** |
| Expiration | ✓ (31d max) | ✓ (30d max) | ✓ | ✓ (7d default) | ✓ | n/a | n/a | ✗ | **✓ (4h default)** |
| Access count limit | ✓ | ✓ (single-view) | ✓ | ✓ | ✓ | n/a | n/a | ✗ | **✓ (default 1)** |
| Password protection (extra auth) | ✓ | ✗ | ✓ | ✓ | ✓ | n/a | n/a | ✗ | **Planned (`--pin`)** |
| Recipient email verification | ✗ | ✓ | ✓ | ✓ | ✗ | n/a (passkey) | ✗ | ✗ | **N/A (pubkey IS identity)** |
| Audit log / access tracking | basic | basic | ✓ (detailed) | ✓ | ✗ | n/a | ✗ | ✗ | **Local log (v1.0)** |
| Signed receipt from recipient | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | manual | **✓ (DHT-published)** |
| Purpose binding (cryptographic) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| Explicit acceptance step | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓** |
| Typed payload schema | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | **✓ (cert/PGP/SSH/generic)** |
| Open source | partial | ✗ | ✗ | ✗ | ✓ | ✓ | mostly | ✓ | **✓ (MIT)** |
| CLI-first UX | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ | ✓ | **✓** |
| Shell-compositional (stdin/stdout) | ✗ | ✗ | ✗ | ✗ | ✗ | ✗ | ✓ (kb fs) | ✓ | **✓ (planned)** |
| File size ceiling | 500 MB | (files) | large | large | small | large | large | ~email limit | **64 KB** |

The intersection of ✓s in the "Cipherpost (planned)" column that are ✗ elsewhere is **the product**:
- No operator + accountless + signed receipt + purpose binding + acceptance step + typed payload + CLI-first.

No other tool in the benchmark set hits more than 3 of those simultaneously.

---

## Open Questions Surfaced by This Research

Not for Cipherpost-the-product, but for the skeleton/spec work:

1. **Fingerprint canonical format** — OpenSSH-style (`SHA256:<base64>`), raw hex, base58, or PKARR-native z-base-32? Pick one for SPEC.md. Recommendation: SHA256:<base64> matching SSH, since users are trained on it.
2. **Accept-prompt exact wording** — needs a SPEC.md spec so that CLI and TUI render it identically.
3. **Idempotent re-receive semantics** — see gap G10 above. Design decision, not investigation.
4. **`cipherpost list` scope** — lists all pending-for-me shares? Needs a "have I accepted this?" state store locally. Where? `$XDG_STATE_HOME/cipherpost/`?
5. **How does `cipherpost receipts --watch` interact with DHT?** — polling interval? Notification on receipt-arrived? Graceful Ctrl-C?
6. **Identity storage path** — match `age`: `$XDG_CONFIG_HOME/cipherpost/identity.age`? Or `~/.cipherpost/`? Be explicit; users will back this file up.

None of these are blockers for *starting* the skeleton, but they should all be resolved before the skeleton's SPEC.md is considered draft-complete.

---

## Sources

### Competitors (MEDIUM — vendor-authored landing pages, but consistent across sources)

- [Bitwarden Send — product page](https://bitwarden.com/products/send/)
- [Bitwarden Send — How it works](https://bitwarden.com/blog/bitwarden-send-how-it-works/)
- [1Password Item Sharing docs](https://support.1password.com/share-items/)
- [1Password Security of shared links](https://support.1password.com/share-items-security/)
- [SendSafely features](https://explore.sendsafely.com/features/)
- [SendSafely recipient authentication](https://support.sendsafely.com/hc/en-us/articles/204583645-Options-for-Authenticating-File-Recipients)
- [Tresorit Send FAQ](https://support.tresorit.com/hc/en-us/articles/360012183493-Tresorit-Send-FAQ)
- [Tresorit zero-knowledge page](https://tresorit.com/features/zero-knowledge-encryption)
- [crypt.fyi landing](https://www.crypt.fyi/)
- [crypt.fyi GitHub](https://github.com/osbytes/crypt.fyi)
- [FileKey GitHub](https://github.com/RockwellShah/filekey)
- [Keybase filesystem docs](https://book.keybase.io/docs/files)
- [Keybase Wikipedia](https://en.wikipedia.org/wiki/Keybase)
- [FIRST PGP policy](https://www.first.org/pgp/) — evidence that PGP/email is still the default in PSIRT/incident-response work

### CLI ergonomics (HIGH — primary sources, man pages, canonical repos)

- [age GitHub](https://github.com/FiloSottile/age)
- [age(1) Arch manpage](https://man.archlinux.org/man/extra/age/age.1.en)
- [age UX discussion #35](https://github.com/FiloSottile/age/issues/35)
- [age stdin passphrase discussion #685](https://github.com/FiloSottile/age/discussions/685)
- [rage (Rust age) GitHub](https://github.com/str4d/rage)
- [rage i18n strings (source of flag help text)](https://github.com/str4d/rage/blob/main/rage/i18n/en-US/rage.ftl)
- [ssh-keygen(1) manpage](https://www.man7.org/linux/man-pages/man1/ssh-keygen.1.html)
- [GnuPG operational commands](https://www.gnupg.org/documentation/manuals/gnupg/Operational-GPG-Commands.html)
- [cosign Sigstore quickstart](https://docs.sigstore.dev/quickstart/quickstart-cosign/)
- [cosign GitHub](https://github.com/sigstore/cosign)
- [Rain's Rust CLI recommendations](https://rust-cli-recommendations.sunshowers.io/handling-arguments.html)
- [clap_complete docs](https://docs.rs/clap_complete/)
- [clig.dev — Command Line Interface Guidelines](https://clig.dev/)

### Supporting (MEDIUM)

- [OneTimeSecret — comparable zero-knowledge tool](https://onetimesecret.com/en/)
- [Cipher Projects — one-time secret sharing guide 2025](https://cipherprojects.com/blog/posts/complete-guide-one-time-secret-sharing-tools-2025/)
- [OWASP Secrets Management Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html)
- [SSH host key fingerprint practices](https://richardforesyth.wordpress.com/2025/08/01/how-ssh-site-key-fingerprints-keep-you-safe-and-how-to-share-them-securely/)
- [Public key fingerprint (Wikipedia)](https://en.wikipedia.org/wiki/Public_key_fingerprint)

---

*Feature research for: Cipherpost (self-sovereign cryptographic handoff CLI)*
*Researched: 2026-04-20*
