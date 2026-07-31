# Design: Derived-key packet addressing (lift the one-record-per-key ceiling)

> **Status: DESIGN / pre-implementation — FEASIBILITY SPIKE PASSED + COMMITTED.**
> Not shipped. The spike (§14) is committed as two `#[ignore]`'d tests in
> `tests/derived_key_spike.rs` (reproducible via `cargo test --test
> derived_key_spike -- --ignored`), carrying **byte-exact golden vectors**. Its
> crypto deps (`ed25519-dalek` `hazmat`+`digest`, `curve25519-dalek`, `bytes`)
> are **test-only dev-deps**, so the shipped binary stays hazmat-free until Phase 1
> wires derivation into `src/`. Nothing lands in production until the schema (§8)
> is signed off and Phase 1 begins. Touches signed bytes and key derivation.

## 1. Problem

PKARR gives each key **one** ~1000-byte SignedPacket, shared by every record
under it. Real cipherpost records are large (share ≈ 650 B, receipt ≈ 530 B),
so **any two exceed the budget** — a key holds effectively one record. This
produces two standing limitations (documented; see the packet-budget memory and
`SPEC.md`):

- **One outstanding share per sender** — all shares publish to the sender's
  single `_cipherpost` label; a new send overwrites the previous.
- **One outstanding receipt per identity** — a recipient's key can hold one
  `_cprcpt-*` receipt; a second received share's receipt is budget-degraded, and
  a self-share's receipt is skipped entirely to avoid colliding with the sender's
  own outgoing share.

**Labels alone do not lift this.** A pkarr SignedPacket is per-key and
indivisible; extra labels live in the *same* ~1000-byte packet. The ceiling only
lifts if each share/receipt gets **its own key** → its own packet.

## 2. Goals / non-goals

**Goals**
- Each share and each receipt addressed under its **own derived key** → its own
  packet → the single-slot ceiling disappears.
- **No discovery index.** The counterparty derives the key from *public* data it
  already holds (parent pubkey + `share_ref`), so nothing new is published to
  find records.
- No new servers, no new operator (PRD constraint #1 preserved).
- Keep the URI shape (`<parent_z32>:<share_ref>`) unchanged.

**Non-goals**
- HD key *trees* / multi-level derivation. We derive **one hop** from a public
  parent (see §4); chains are out of scope and bring the BIP32-Ed25519 pitfalls.
- Encrypting to derived keys. Payloads stay age-encrypted to the recipient's
  **real** identity X25519; only *addressing + packet signing* use derived keys.

## 3. Current addressing (what changes)

| Record | Today (v1.1) | Under this design |
|--------|--------------|-------------------|
| Share | `_cipherpost` label on **sender's** key | `_cipherpost` (single label) on **`derive(sender_pub, share_ref)`** |
| Receipt | `_cprcpt-<ref>` on **recipient's** key | `_cprcpt` (single label) on **`derive(recipient_pub, share_ref)`** |

The counterparty always knows both derivation inputs: the recipient of a share
has `sender_pub` + `share_ref` from the URI; the sender fetching a receipt has
`recipient_pub` (they chose it) + `share_ref` (they created it). No index needed.

## 4. Derivation scheme — single-hop stealth blinding

Monero-subaddress shape, one hop from a public parent. **Not** BIP32-Ed25519
(that construction's chain-code / 28-bit-clamped-addend machinery exists to make
*multi-level* derivation safe and carries documented Ed25519-HD footguns; we
derive one hop and need none of it).

Given parent public key `A` (an Ed25519 point, = `a·G` where `a` is the parent's
clamped scalar) and a 128-bit `share_ref`:

```
t   = reduce_mod_ℓ( SHA-512( DOMAIN ‖ A_bytes ‖ share_ref ) )      // public tweak (Scalar::from_bytes_mod_order_wide)
A'  = A + t·G                                                       // derived pubkey (public derivation)
a'  = a + t   (mod ℓ)                                               // derived scalar (secret side only)
```

- `DOMAIN` = a fixed domain-separation string, e.g. `b"cipherpost/v2/derive-addr"`.
- `t` is derived by hashing **public** inputs → anyone can compute `A'`
  (the no-index property). `t` is public.
- `a'` is computable only by the parent-secret holder (needs `a`, which comes
  from the master seed). `a'` is **never** revealed; only signatures are.
- **Signing nonce prefix** for the derived key is derived from a **secret**:
  `prefix' = SHA-512( DOMAIN_PREFIX ‖ master_hash_prefix ‖ share_ref )[..32]`,
  so per-key nonces stay unpredictable. (`master_hash_prefix` is the second half
  of `SHA-512(seed)`, available via `ExpandedSecretKey::from(&signing_key)`.)

Signing under `A'` uses `ed25519_dalek::hazmat::raw_sign::<Sha512>(&esk, msg, &A')`
with `esk = ExpandedSecretKey { scalar: a', hash_prefix: prefix' }`.

## 5. Security analysis

- **Signature validity with an unclamped scalar.** `a'` is *not* clamped (not a
  multiple of the cofactor). This is fine: Ed25519 verification checks
  `S·G = R + H(R,A',M)·A'`, which holds for `A' = a'·G` regardless of clamping.
  `A' = a'·G` is always in the **prime-order** subgroup (any scalar times the
  prime-order basepoint), so it is canonical and passes `verify_strict` — no
  small-subgroup / cofactor exposure via the public key.
- **No secret leak.** `t` and `A'` are public; `a = a' − t` would require knowing
  `a'`, which is never published. Standard additive-blinding / stealth-address
  security; safe for a single hop with a hashed, per-record tweak.
- **⚠️ ed25519-unsafe-libs footgun (raw_sign).** `raw_sign` leaks the scalar if
  the `verifying_key` passed does not match `scalar·G`. Mitigation is mandatory:
  compute `A'` as `a'·G` and (defense-in-depth) **self-verify every signature
  before use** (`A'.verify_strict(msg, &sig)`), plus golden vectors (§11).
- **Unlinkability (privacy win, ref finding #4).** `A' = A + H(DOMAIN‖A‖ref)·G`.
  A passive DHT observer who does **not** know `share_ref` cannot link `A'` back
  to `A` — a recipient's receipt keys are no longer enumerable from their public
  identity. Only a party holding `share_ref` (the counterparty, or anyone with
  the URI) can derive `A'`. This shrinks the finding-#4 residual: the receipt
  graph stops being publicly enumerable, though a party who *finds* a receipt
  still reads whatever the schema leaves in cleartext (see §8).

## 6. The pkarr signing seam (feasibility, verified)

pkarr cannot sign under a blinded key through its normal API — `Keypair` is
seed-only and there is no public raw-scalar / from-parts constructor. The usable
seam, all verified against `pkarr-5.0.3`:

1. Build the DNS packet (single TXT record), names normalized to the **derived**
   origin z32; encode with the same compressed encoder pkarr uses
   (`Packet::build_bytes_vec_compressed`, via re-exported `pkarr::dns`).
2. Compute the BEP44 signable bytes — pkarr's private helper, replicated exactly:
   `signable(ts, v) = b"3:seqi{ts}e1:v{v.len()}:" ‖ v`.
3. `sig = hazmat::raw_sign::<Sha512>(&esk, &signable, &A')`, self-verify.
4. Assemble `payload = sig(64) ‖ ts_be(8) ‖ encoded_packet` and construct via
   the **public** `SignedPacket::from_relay_payload(&A'_pubkey, &payload)`.

`from_relay_payload` → `from_bytes` runs `public_key.verify(&signable(ts, v), &sig)`,
so **pkarr itself verifies our hand-signed packet** — successful assembly is a
built-in correctness gate. Resolution by any node re-checks the BEP44 signature
under `A'`, so a byte-correct `signable` replication is required (guarded by a
test that verifies a *pkarr-built* packet's own signature against *our* recomputed
signable — if that passes, our encoder matches pkarr byte-for-byte).

**Deps:** enable `ed25519-dalek/hazmat` (zero-cost feature on the pinned
`=3.0.0-pre.5`); add `curve25519-dalek` as a direct dep (already in the tree at
`5.0.0-pre.5`) for point/scalar arithmetic. `SigningKey::to_scalar()` yields the
parent clamped scalar `a`.

## 7. Verification path (both sides)

- **Publish (secret holder):** derive `A'`, `a'`, `prefix'`; hand-sign; publish
  under `A'`.
- **Fetch (counterparty, public derivation):** derive `A'` from parent pubkey +
  `share_ref` (no secret); resolve the packet at `A'`; verify the BEP44 signature
  under `A'`; then the existing dual-signature discipline over the record body.
  Because `A'` is a deterministic function of `(parent_pub, share_ref)`, a valid
  packet at `A'` cryptographically binds the record to that parent and that
  `share_ref`.

## 8. Receipt schema — analysis + proposal (decide before touching signed bytes)

Under derived addressing, several receipt fields become redundant because the
**location** (`derive(recipient_pub, share_ref)`) plus the packet signature
already prove "the holder of `recipient_pub`'s secret attested, bound to
`share_ref`."

| Field | Keep? | Rationale |
|-------|-------|-----------|
| `accepted_at` | **keep** | The attestation's timestamp; not otherwise recoverable. |
| `ciphertext_hash` | **keep** | Binds the receipt to the exact blob (D-RS-04). |
| `cleartext_hash` | **keep** | Binds to the exact envelope incl. purpose (already the purpose-binding since #3). |
| `share_ref` | **keep** | Cheap self-description; already the derivation input. |
| `protocol_version` | **keep** | Versioning. |
| `nonce` | **DROP** | Its stated job is anti-synthesis (not replay). A receipt is now under a per-`share_ref` key only the recipient's secret can sign; synthesis is impossible without that secret, and replay is the ledger's job. The 42 bytes no longer earn their place. |
| `recipient_pubkey` | **DROP (from signed bytes)** | Redundant: it *is* the derivation input the verifier already holds, and it's the field that made the receipt a cleartext handoff-graph entry. `verify_receipt` takes it as context instead of reading it from the wire. |
| `sender_pubkey` | **DROP — needs sign-off** | The strongest privacy/size win but the field carrying the recipient's *claim* of who they received from (D-RS-07 provenance). Under derived addressing the fetching sender already knows it's their share (they derived with their own `share_ref`), so it's redundant for their own verification. Dropping it removes the last cleartext graph edge from the receipt body. **Open decision** — the alternative is keep it for third-party-auditable provenance. |

**Proposed minimal signed receipt:**
`{ accepted_at, ciphertext_hash, cleartext_hash, protocol_version, share_ref }`
plus the outer packet signature; `recipient_pub` supplied to `verify_receipt` as
context. This is the point to settle **before** the redesign touches signed
bytes (regenerating `receipt_signable.bin` + the SPEC §8 vector once, not twice).

## 9. Mock fidelity (must land day one)

Both prior blind spots (share clobber, merged budget) were mock-fidelity gaps;
this redesign is precisely where mock drift re-opens that class.

- `MockTransport` keys its store by **derived z32**, not parent z32 — the mock
  must model that publish/resolve target the derived key, and that the sender
  derives the same key to fetch.
- Model the `from_relay_payload` assembly path (single record per derived key),
  and keep the real per-packet budget check already added (each derived packet
  is independently ≤ 1000 B).
- Add a mock-vs-real parity test: the derived z32 the mock computes must equal
  the one the real derivation module computes (shared code path, not a re-impl).

## 10. Golden vectors (the pubky_auth treatment)

Commit fixtures + a byte-for-byte test for:
1. **Derivation — BYTE-EXACT hex vectors, not just properties.** A property
   assertion (`A' == A + t·G`) does not catch an upstream behavioral drift in the
   pre-release curve/hash stack that produces a *different-but-self-consistent*
   derived key. Pin the concrete outputs as hex literals for fixed inputs. The
   committed spike already carries the first vector — `seed=[7;32]`,
   `share_ref=[0x11;16]`, `DOMAIN="cipherpost/v2/derive-addr"`:
   `t = 2185bc56…230b9005`, `A' = 5af3abc0…d72155f5`,
   z32 `mm34zoy8y4cc7sh148ys5j61ag6hz4xkmq9h7874gmkpui3bkz4o`.
   Phase 1 expands this into the `derive` module's fixture set (multiple
   seeds/refs) and asserts public and secret derivation agree.
2. **signable replication:** a pkarr-built packet's own signature verifies
   against our recomputed `signable(ts, v)` (proves byte-exact replication).
3. **End-to-end:** hand-signed derived-key packet → `from_relay_payload` → Ok
   (pkarr verifies) → resolve round-trip → BEP44 sig verifies under `A'`.

## 11. Migration & protocol version

This changes **addressing** — v1.1 and v2 records live at different keys and do
not interop. It is a clean break, **PROTOCOL_VERSION bump to 2**. Consequences:
outer-record + receipt fixtures regenerate; the "v1.0 byte-compat" lock-in is
explicitly retired for v2 (call it out in CLAUDE.md and SPEC). No in-place
migration; ephemeral records (TTL hours) age out. Recommend gating v2 addressing
behind a feature/flag during rollout so v1.1 stays buildable for comparison.

## 12. Risks / open questions

- **R1 — signable replication drift.** If pkarr changes its BEP44 encoding, our
  hand-signing breaks. Mitigation: the pkarr-verifies-our-signable test (§10.2)
  fails loudly on any drift; pin pkarr.
- **R2 — hazmat on a pre-release curve stack.** `raw_sign` + `curve25519-dalek
  5.0.0-pre.5`. Mitigation: exact pins, golden vectors, self-verify-after-sign.
- **R3 — from_relay_payload is the only seam.** If a future pkarr removes it,
  we'd need a hand-rolled BEP44 publish. Low near-term risk; note it.
- **Q1 — drop `sender_pubkey`?** (§8) The one schema decision left open.
- **Q2 — inner receipt signature.** The outer BEP44 sig now authenticates the
  packet; is the inner Ed25519 receipt signature still worth keeping for
  standalone (relay-independent) receipt verifiability? Default: **keep** (cheap,
  preserves portability); revisit if size-critical.

## 13. Phased plan (each phase self-contained, tests green)

0. **Feasibility spike (throwaway)** — §14. Gate for everything below.
1. **`derive` module + golden vectors** — pure key math, no transport. Public and
   secret derivation, self-verify, fixtures (§10.1).
2. **Transport: publish/resolve under derived keys** — the `from_relay_payload` +
   hazmat signing path behind the trait; `signable` replication test (§10.2);
   **mock updated in the same phase** (§9).
3. **Flow wiring** — shares publish under `derive(sender_pub, share_ref)`;
   receipts under `derive(recipient_pub, share_ref)`; lift the one-per-key limits
   (re-enable self-receipts, multi-receipt). PROTOCOL_VERSION → 2.
4. **Receipt schema** — apply §8 once; regenerate fixtures + SPEC §8 vector.
5. **Docs + real-DHT validation** — SPEC/THREAT-MODEL/README/CLAUDE.md; extend the
   manual `real_dht_e2e` harness with a derived-key round trip.

## 14. Feasibility spike spec (do first)

A single `#[ignore]` test (mock, no network) that proves the seam end-to-end:

1. Master `SigningKey` from a fixed seed; `A = verifying_key`, `a = to_scalar`.
2. `share_ref = [fixed 16 bytes]`; compute `t`, `A'`, `a'`, `prefix'` (§4).
3. Assert public derivation (`A + t·G`) == secret derivation (`a'·G`) == `A'`.
4. Build a one-TXT DNS packet at origin `A'.to_z32()`; encode; `signable`;
   `raw_sign::<Sha512>`; **self-verify**; `from_relay_payload(&A', &payload)` → Ok.
5. Round-trip the SignedPacket bytes back through pkarr parse+verify → the TXT
   resolves and the BEP44 signature verifies under `A'`.
6. Separately: build a normal packet with a random pkarr `Keypair`; verify *its*
   signature against *our* recomputed `signable` (proves byte-exact replication).

Green spike ⇒ the approach is real and Phase 1 begins. Red ⇒ reassess (hand-rolled
BEP44 publish, or push pkarr for a raw-scalar signing API upstream).

### 14.1 Spike result — PASSED (committed)

Committed as two `#[ignore]`'d offline tests in `tests/derived_key_spike.rs`
(dev-dep crypto, shipped binary unaffected), both green: 

- **`signable_replication_matches_pkarr`** — built a normal packet with a random
  pkarr `Keypair`; pkarr's *own* signature verified against *our* recomputed
  `signable(ts, v)` → byte-exact replication (R1 guarded).
- **`derived_key_publish_resolve_verify`** — fixed seed `[7;32]`, `share_ref
  [0x11;16]`: public derivation `A + t·G` equalled secret `a'·G`; `raw_sign::<Sha512>`
  under `{scalar: a', hash_prefix: prefix'}` self-verified under `A'`;
  `SignedPacket::from_relay_payload(&A', payload)` returned Ok (pkarr verified our
  hand-signed packet); resolve + serialize→deserialize re-verified the BEP44
  signature under `A'`. Derived packet `v = 114 bytes` (budget 1000).

Implementation notes for Phase 1 (learned in the spike):
- Enable **both** `hazmat` *and* `digest` on `ed25519-dalek` (`digest` gates the
  re-exported `ed25519_dalek::Sha512`, whose `digest` version — sha2 0.11-rc —
  is the one `raw_sign`'s `CtxDigest` bound requires; sha2 0.10 does **not**
  satisfy it). Our own byte-hashing can stay on the workspace `sha2 0.10` (same
  algorithm → identical bytes; only the `raw_sign` type param is version-sensitive).
- `pkarr::PublicKey::from(VerifyingKey)` converts the derived key directly.
- `from_relay_payload` wants `&bytes::Bytes`; `bytes = sig(64) ‖ ts_be(8) ‖ v`.
- Minor doc correction: the tweak `t` is `reduce_mod_ℓ(SHA-512(...))` via
  `Scalar::from_bytes_mod_order_wide` — a reduction, not a clamp (clamping is only
  for the master scalar). §4 says "clamp_scalar"; read as "reduce mod ℓ".
