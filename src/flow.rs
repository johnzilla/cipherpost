//! src/flow.rs — Phase 2 orchestration.
//!
//! `run_send` and `run_receive` compose Phase 1 primitives + Plan-01 payload schema
//! into the full round-trip. D-RECV-01 order is enforced here. NO payload field
//! is printed before the acceptance-prompt step; tests assert this.
//!
//! Pitfalls addressed:
//!   #2  — verify-before-decrypt-before-accept (`Transport::resolve` already verifies
//!         outer + inner; `run_receive` verifies URI/share_ref match + TTL + age-decrypt
//!         + envelope-JCS-parse BEFORE presenting any payload field)
//!   #5  — only `[u8; 32]` bytes cross the age/pkarr crate boundary (no direct
//!         low-level curve-crate imports here)
//!   #6  — typed z32 confirmation via `Prompter`; no default, no `--yes`
//!   #7  — secret-holding types use manual Debug redaction in their defining
//!         modules; this file holds no types that derive the std Debug trait
//!   #11 — TTL is inner-signed `created_at + ttl_seconds` (not DHT packet TTL)
//!   #12 — purpose stripped of control chars at send-time

use crate::cli::MaterialVariant;
use crate::crypto;
use crate::error::Error;
use crate::identity::Identity;
use crate::payload::{self, Envelope, Material};
use crate::preview;
use crate::record::{self, OuterRecord, OuterRecordSignable};
use crate::transport::Transport;
use crate::{ShareUri, DHT_LABEL_OUTER, PROTOCOL_VERSION};

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroizing;

// ---- Constants --------------------------------------------------------------

/// Wire budget: maximum encoded SignedPacket size the real DHT accepts (D-PS-01).
/// Empirically measured in `tests/signed_packet_budget.rs` as 1000 bytes for the
/// DNS packet portion of `pkarr::SignedPacket`.
pub const WIRE_BUDGET_BYTES: usize = 1000;

/// Default share TTL in seconds: 24h per PROJECT.md Key Decisions (revised from
/// PRD's 4h after Mainline DHT latency research).
pub const DEFAULT_TTL_SECONDS: u64 = 86400;

/// Number of attempts `run_send` makes to fit a payload in the wire budget.
///
/// Rationale: age intentionally adds a random-length "grease" stanza on every
/// encryption (`age-core::format::grease_the_joint` — a 0..=265-byte random
/// stanza) to thwart ciphertext-size fingerprinting. For payloads near the
/// 1000-byte PKARR budget, an unlucky grease draw can push the encoded
/// SignedPacket over the limit even when the plaintext would fit comfortably
/// with a different draw. Retrying re-samples the grease. At ~50% fit
/// probability per attempt, 20 attempts reduces the false-reject probability
/// to ~1e-6. The check in step 2 still guarantees we are in the serviceable
/// plaintext range; retries only paper over grease-size variance.
pub const WIRE_BUDGET_RETRY_ATTEMPTS: usize = 20;

// ---- SendMode ---------------------------------------------------------------

/// Send target: encrypt to self OR encrypt to a recipient's PKARR pubkey (z-base-32).
pub enum SendMode {
    SelfMode,
    Share { recipient_z32: String },
}

// ---- Prompter trait ---------------------------------------------------------

/// Acceptance-screen renderer + typed-z32 confirmation reader.
///
/// Plan 02's production `Prompter` is not wired in this plan because the real TTY
/// banner + `dialoguer::Input` integration lands in Plan 03 alongside the CLI
/// dispatch wiring. Plan 02 tests inject an `AutoConfirmPrompter` or
/// `DeclinePrompter` (see [`test_helpers`]) to exercise the accept / decline paths.
///
/// The trait method is given the pre-verified envelope fields and the expected
/// sender z32; it returns `Ok(())` if the user confirms, `Err(Error::Declined)` if
/// the user typed the wrong value.
///
/// `material_type` is `&str` (not `&'static str`) so the caller may pass either a
/// compile-time string literal or a runtime-derived label.
pub trait Prompter {
    #[allow(clippy::too_many_arguments)]
    fn render_and_confirm(
        &self,
        purpose: &str,
        sender_openssh_fp: &str,
        sender_z32: &str,
        share_ref_hex: &str,
        material_type: &str,
        size_bytes: usize,
        preview_subblock: Option<&str>,
        ttl_remaining_seconds: u64,
        expires_unix_seconds: i64,
    ) -> Result<(), Error>;
}

// ---- state_dir --------------------------------------------------------------

/// Cipherpost state directory: `{key_dir}/state`, `CIPHERPOST_HOME`-overridable
/// (D-STATE-04). Mirrors `identity::key_dir()` exactly.
pub fn state_dir() -> PathBuf {
    crate::identity::key_dir().join("state")
}

fn accepted_dir() -> PathBuf {
    state_dir().join("accepted")
}

fn sentinel_path(share_ref_hex: &str) -> PathBuf {
    accepted_dir().join(share_ref_hex)
}

fn ledger_path() -> PathBuf {
    state_dir().join("accepted.jsonl")
}

// ---- check_already_accepted -------------------------------------------------

/// RECV-06 step 1: if the sentinel file exists, return `Some(accepted_at_string)`
/// by scanning the ledger for the matching share_ref. At skeleton traffic (1-100
/// shares/week per D-STATE-03) a linear scan is cheapest; rotation is deferred.
///
/// Returns `None` if not yet accepted. If the sentinel exists but no matching
/// ledger entry is found, returns `Some("<unknown; ...>")` so callers still
/// short-circuit — the sentinel alone is authoritative for "don't re-decrypt".
pub fn check_already_accepted(share_ref_hex: &str) -> Option<String> {
    if !sentinel_path(share_ref_hex).exists() {
        return None;
    }
    // Scan accepted.jsonl for the matching share_ref.
    if let Ok(data) = fs::read_to_string(ledger_path()) {
        for line in data.lines() {
            if !line.contains(share_ref_hex) {
                continue;
            }
            // Parse to be exact (avoid false matches in purpose text).
            if let Ok(v) = serde_json::from_str::<serde_json::Value>(line) {
                if v.get("share_ref").and_then(|s| s.as_str()) == Some(share_ref_hex) {
                    if let Some(s) = v.get("accepted_at").and_then(|s| s.as_str()) {
                        return Some(s.to_string());
                    }
                }
            }
        }
    }
    // Sentinel present but no ledger line → sentinel still wins.
    Some("<unknown; sentinel exists but ledger missing>".to_string())
}

// ---- MaterialSource / OutputSink -------------------------------------------

/// Source of the plaintext to be sent.
pub enum MaterialSource {
    /// Read from process stdin (CLI `-` convention; CLI-01 library-level).
    Stdin,
    /// Read the entire file at this path.
    File(PathBuf),
    /// Test-only helper: synthetic bytes passed directly from a unit or
    /// integration test.
    Bytes(Vec<u8>),
}

/// Destination for the decrypted material written by `run_receive`.
pub enum OutputSink {
    /// Write to process stdout (CLI default).
    Stdout,
    /// Write to the given filesystem path (CLI `-o <path>`).
    File(PathBuf),
    /// Test-only sink: the decrypted bytes are appended to this `Vec` so the
    /// test can assert on them without touching the filesystem.
    InMemory(Vec<u8>),
}

fn read_material(src: MaterialSource) -> Result<Zeroizing<Vec<u8>>, Error> {
    match src {
        MaterialSource::Stdin => {
            let mut buf = Vec::new();
            std::io::stdin().read_to_end(&mut buf).map_err(Error::Io)?;
            Ok(Zeroizing::new(buf))
        }
        MaterialSource::File(p) => Ok(Zeroizing::new(fs::read(p).map_err(Error::Io)?)),
        MaterialSource::Bytes(v) => Ok(Zeroizing::new(v)),
    }
}

// ---- run_send ---------------------------------------------------------------

/// Orchestrate the full send pipeline (SEND-01..05, PAYL-01..05 composition).
///
/// Returns the share URI on success. Publishes via `&dyn Transport` so tests can
/// inject `MockTransport`.
///
/// Steps (mapped to the acceptance criteria):
///  1. read material source (`-` = stdin; path = file; `Bytes` for tests) into a
///     `Zeroizing` buffer
///  2. `enforce_plaintext_cap` (D-PS-01 plaintext path)
///  3. `strip_control_chars` on purpose (D-WIRE-05)
///  4. build `Envelope`, JCS-serialize
///  5. derive recipient X25519 (self → own Ed25519 pubkey → X25519 pubkey;
///     share → recipient z32 → Ed25519 pubkey → X25519 pubkey)
///  6. `age_encrypt(jcs_bytes, recipient)` → ciphertext
///  7. `share_ref = record::share_ref_from_bytes(ciphertext_bytes, created_at)`
///     — hashes RAW ciphertext bytes, matching PAYL-05's spec text
///     `sha256(ciphertext || created_at)[..16]`. The Phase-1
///     `mock_transport_roundtrip.rs` test passed `blob.as_bytes()` (bytes of the
///     base64 string) which happens to work because `share_ref_from_bytes`
///     accepts any `&[u8]`, but the semantically correct argument for the real
///     flow is raw ciphertext — and is what PAYL-05 says. Decision is documented
///     in SUMMARY.
///  8. `blob = base64-STANDARD-encode(ciphertext)` (D-WIRE-04)
///  9. build `OuterRecordSignable` { blob, created_at, protocol_version,
///     pubkey=sender z32, recipient (None for self, Some(target_z32) for share),
///     share_ref, ttl_seconds }
/// 10. `signature = record::sign_record(&signable, &keypair)`
/// 11. assemble `OuterRecord` { ...signable fields, signature }
/// 12. wire-budget pre-check: build a real `SignedPacket`, compare
///     `encoded_packet().len()` against `WIRE_BUDGET_BYTES`; if over → return
///     `Error::WireBudgetExceeded { encoded, budget, plaintext }`
/// 13. `transport.publish(&keypair, &record)`
/// 14. return `ShareUri::format(sender_z32, &share_ref)`
#[allow(clippy::too_many_arguments)]
pub fn run_send(
    identity: &Identity,
    transport: &dyn Transport,
    keypair: &pkarr::Keypair,
    mode: SendMode,
    purpose: &str,
    material_source: MaterialSource,
    material_variant: MaterialVariant,
    ttl_seconds: u64,
) -> Result<String, Error> {
    // 1. read material bytes (unchanged)
    let plaintext_bytes: Zeroizing<Vec<u8>> = read_material(material_source)?;

    // 2. ingest: normalize raw bytes into a typed Material. The DECODED size
    // (e.g. PEM→DER) is what gets capped in step 3 — a 1 MB PEM that decodes
    // to 100 KB DER fails the cap on the decoded size, not the input size.
    // D-P6-01 + D-P6-18.
    let material = match material_variant {
        MaterialVariant::GenericSecret => {
            payload::ingest::generic_secret(plaintext_bytes.to_vec())?
        }
        MaterialVariant::X509Cert => payload::ingest::x509_cert(&plaintext_bytes)?,
        // Phase 7 Plan 01: PgpKey dispatch is now live — calls payload::ingest::pgp_key
        // (strict armor reject + multi-primary reject + trailing-bytes check).
        MaterialVariant::PgpKey => payload::ingest::pgp_key(&plaintext_bytes)?,
        // Phase 7 Plan 05: SshKey dispatch is now live — calls payload::ingest::ssh_key
        // (strict OpenSSH-v1 sniff + canonical re-encode + trailing-bytes check).
        MaterialVariant::SshKey => payload::ingest::ssh_key(&plaintext_bytes)?,
    };

    // 3. plaintext cap (pre-encrypt; D-PS-01 / D-P6-16). Uses the typed
    // Material's `plaintext_size()` so the DECODED DER length is capped, not
    // the raw PEM-input length.
    payload::enforce_plaintext_cap(material.plaintext_size())?;

    // 4. strip purpose control chars (D-WIRE-05)
    let stripped_purpose = payload::strip_control_chars(purpose);

    // 5. build Envelope + JCS-serialize
    let created_at = now_unix_seconds()?;
    let envelope = Envelope {
        created_at,
        material,
        protocol_version: PROTOCOL_VERSION,
        purpose: stripped_purpose,
    };
    let jcs_bytes = envelope.to_jcs_bytes()?;

    // 5. derive recipient X25519
    let (recipient_z32_option, recipient) = match mode {
        SendMode::SelfMode => {
            let ed_pub = identity.public_key_bytes();
            let x25519_pub = crypto::ed25519_to_x25519_public(&ed_pub)?;
            let rcpt = crypto::recipient_from_x25519_bytes(&x25519_pub)?;
            (None, rcpt)
        }
        SendMode::Share { ref recipient_z32 } => {
            let pk = pkarr::PublicKey::try_from(recipient_z32.as_str()).map_err(|_| {
                Error::Config(format!("invalid recipient pubkey: {}", recipient_z32))
            })?;
            let ed_pub: [u8; 32] = *pk.as_bytes();
            let x25519_pub = crypto::ed25519_to_x25519_public(&ed_pub)?;
            let rcpt = crypto::recipient_from_x25519_bytes(&x25519_pub)?;
            (Some(recipient_z32.clone()), rcpt)
        }
    };

    // Steps 6-12 are retried up to WIRE_BUDGET_RETRY_ATTEMPTS times. The age
    // format intentionally adds a random-length "grease" stanza on every
    // encryption (age-core `grease_the_joint` — a 0..=265-byte random stanza)
    // to prevent ciphertext-size fingerprinting. For payloads near the
    // 1000-byte PKARR wire budget, a single unlucky grease draw can push the
    // encoded SignedPacket over the limit even though a slightly different
    // draw would fit. Retrying re-samples the grease; the plaintext bound
    // check in step 2 already guarantees we're in the serviceable range.
    //
    // If we still fail after N attempts we emit a single WireBudgetExceeded
    // with the last-seen encoded size, so the caller sees a concrete number
    // and can decide whether to split the payload.
    let mut last_err: Option<(usize, usize)> = None;
    for _attempt in 0..WIRE_BUDGET_RETRY_ATTEMPTS {
        // 6. age_encrypt (grease stanza re-sampled each call)
        let ciphertext = crypto::age_encrypt(&jcs_bytes, &recipient)?;

        // 7. share_ref — hash raw ciphertext bytes per PAYL-05.
        let share_ref = record::share_ref_from_bytes(&ciphertext, created_at);

        // 8. blob (base64 STANDARD)
        use base64::Engine;
        let blob = base64::engine::general_purpose::STANDARD.encode(&ciphertext);

        // 9 + 10 + 11. signable → sign → record
        let signable = OuterRecordSignable {
            blob: blob.clone(),
            created_at,
            protocol_version: PROTOCOL_VERSION,
            pubkey: identity.z32_pubkey(),
            recipient: recipient_z32_option.clone(),
            share_ref: share_ref.clone(),
            ttl_seconds,
        };
        let signature = record::sign_record(&signable, keypair)?;
        let record = OuterRecord {
            blob,
            created_at,
            protocol_version: PROTOCOL_VERSION,
            pubkey: identity.z32_pubkey(),
            recipient: recipient_z32_option.clone(),
            share_ref: share_ref.clone(),
            signature,
            ttl_seconds,
        };

        // 12. wire-budget pre-check (REAL SignedPacket build, NOT mock's
        // rdata.len()).
        match check_wire_budget(&record, keypair, jcs_bytes.len()) {
            Ok(()) => {
                // 13. publish
                transport.publish(keypair, &record)?;
                // 14. return URI
                return Ok(ShareUri::format(&identity.z32_pubkey(), &share_ref));
            }
            Err(Error::WireBudgetExceeded { encoded, .. }) => {
                last_err = Some((encoded, jcs_bytes.len()));
                continue;
            }
            Err(other) => return Err(other),
        }
    }

    // Exhausted retries — surface the last-seen encoded size.
    let (encoded, plaintext) = last_err.unwrap_or((WIRE_BUDGET_BYTES + 1, jcs_bytes.len()));
    Err(Error::WireBudgetExceeded {
        encoded,
        budget: WIRE_BUDGET_BYTES,
        plaintext,
    })
}

/// Wire-budget pre-flight: build the actual `SignedPacket` and measure its
/// encoded DNS packet length. Matches `tests/signed_packet_budget.rs`'s
/// measurement path so real `DhtTransport::publish` succeeds if this check
/// passes.
///
/// `plaintext_len` is the jcs-serialized envelope length (i.e. what was fed to
/// `age_encrypt`); reported verbatim in `Error::WireBudgetExceeded.plaintext`
/// so users see the exact size that caused the overrun.
fn check_wire_budget(
    record: &OuterRecord,
    keypair: &pkarr::Keypair,
    plaintext_len: usize,
) -> Result<(), Error> {
    let rdata = serde_json::to_string(record).map_err(|e| Error::Transport(Box::new(e)))?;
    let name: pkarr::dns::Name<'_> = DHT_LABEL_OUTER
        .try_into()
        .map_err(|_| Error::Config("dns name encode".into()))?;
    let txt: pkarr::dns::rdata::TXT<'_> = rdata
        .as_str()
        .try_into()
        .map_err(|_| Error::Config("txt encode".into()))?;
    // pkarr::SignedPacketBuilder::sign returns Err(PacketTooLarge(len)) when
    // encoded_packet.len() > 1000 (pkarr-5.0.4 signed_packet.rs:276). We
    // translate that to Error::WireBudgetExceeded so the cipherpost-layer
    // error is taxonomically correct (Error::Transport would mask a
    // deterministic pre-flight failure as a generic network-ish error).
    let packet = match pkarr::SignedPacket::builder()
        .txt(name, txt, 300)
        .sign(keypair)
    {
        Ok(p) => p,
        Err(pkarr::errors::SignedPacketBuildError::PacketTooLarge(encoded)) => {
            return Err(Error::WireBudgetExceeded {
                encoded,
                budget: WIRE_BUDGET_BYTES,
                plaintext: plaintext_len,
            });
        }
        Err(other) => return Err(Error::Transport(Box::new(other))),
    };
    let encoded = packet.encoded_packet().len();
    if encoded > WIRE_BUDGET_BYTES {
        return Err(Error::WireBudgetExceeded {
            encoded,
            budget: WIRE_BUDGET_BYTES,
            plaintext: plaintext_len,
        });
    }
    Ok(())
}

// ---- run_receive ------------------------------------------------------------

/// Orchestrate the full receive pipeline (RECV-01..06 composition). Enforces the
/// strict D-RECV-01 order. Returns `Ok(())` on successful acceptance + write.
///
/// Invariant: no payload field is surfaced between step 2 and step 8. The in-body
/// `STEP N` comments document the exact order; any change there must preserve the
/// no-surface-before-accept guarantee.
#[allow(clippy::too_many_arguments)]
pub fn run_receive(
    identity: &Identity,
    transport: &dyn Transport,
    keypair: &pkarr::Keypair,
    uri: &ShareUri,
    output: &mut OutputSink,
    prompter: &dyn Prompter,
    armor: bool,
) -> Result<(), Error> {
    // STEP 1: sentinel-check (no network, no passphrase)
    if let Some(accepted_at) = check_already_accepted(&uri.share_ref_hex) {
        // NOTE: purpose/material intentionally NOT included — D-RECV-01
        // invariant: no envelope field surfaced before acceptance.
        eprintln!("already accepted at {}; not re-decrypting", accepted_at);
        return Ok(());
    }

    // STEP 2 + 3: transport.resolve() does outer PKARR sig check (pkarr
    // internals) + inner Ed25519 sig check (record::verify_record called inside
    // resolve). Any sig failure → Error::Signature* with unified Display
    // (exit 3).
    let record = transport.resolve(&uri.sender_z32)?;

    // STEP 4: URI/record share_ref match (D-URI-02)
    if record.share_ref != uri.share_ref_hex {
        return Err(Error::ShareRefMismatch);
    }

    // STEP 5: TTL (RECV-02) — inner-signed created_at + ttl_seconds (Pitfall #11)
    let now = now_unix_seconds()?;
    let expires_at = record.created_at.saturating_add(record.ttl_seconds as i64);
    if now >= expires_at {
        return Err(Error::Expired);
    }

    // STEP 6: age-decrypt into Zeroizing (wrong recipient → DecryptFailed exit 4)
    use base64::Engine;
    // D-16 oracle-hygiene: base64 decode failure maps to a Signature* variant so
    // the user-facing message is the unified "signature verification failed"
    // string. Rationale: the inner sig (verified in step 2-3) covers the base64
    // *string* in record.blob, not the decoded bytes, so a malformed blob
    // reaching here was either introduced by a (valid-signing) sender or by
    // tampering between resolve() and this point. Either path must not leak a
    // distinguishable error class vs. a true signature failure. No test
    // discriminates base64-decode from sig-canonical-mismatch (both funnel
    // through Display → D-16 unified string).
    let ciphertext = base64::engine::general_purpose::STANDARD
        .decode(&record.blob)
        .map_err(|_| Error::SignatureCanonicalMismatch)?;
    let seed = identity.signing_seed();
    let x25519_secret = crypto::ed25519_to_x25519_secret(&seed);
    let age_id = crypto::identity_from_x25519_bytes(&x25519_secret)?;
    let jcs_plain: Zeroizing<Vec<u8>> = crypto::age_decrypt(&ciphertext, &age_id)?;

    // STEP 7: parse decrypted bytes as JCS → Envelope (parse fail =
    // sig-canonical-mismatch, exit 3 per D-RECV-01 step 7)
    let envelope = Envelope::from_jcs_bytes(&jcs_plain)?;

    // STEP 8: acceptance prompt — BEFORE this point, NO payload field has been
    // printed. The Prompter sees the full fields and renders the screen + reads
    // confirmation.
    let (sender_openssh_fp, _z32_again) = sender_openssh_fingerprint_and_z32(&record.pubkey)?;

    // D-P6-09 / AD-1: match on envelope.material to select the correct accessor
    // AND (for typed variants) pre-render a preview subblock for the Prompter.
    // --armor rejection also happens here: it requires a typed material variant
    // (X509Cert in Phase 6; Phase 7 extends to PGP/SSH).
    let (material_bytes, preview_subblock): (&[u8], Option<String>) = match &envelope.material {
        Material::GenericSecret { .. } => {
            if armor {
                return Err(Error::Config(
                    "--armor requires --material x509-cert or pgp-key".into(),
                ));
            }
            (envelope.material.as_generic_secret_bytes()?, None)
        }
        Material::X509Cert { .. } => {
            let bytes = envelope.material.as_x509_cert_bytes()?;
            let sub = preview::render_x509_preview(bytes)?;
            (bytes, Some(sub))
        }
        Material::PgpKey { .. } => {
            // Phase 7 Plan 03: live PGP preview + armor-permitted variant.
            // bytes are the verbatim binary packet stream stored by Plan 01's
            // ingest. preview::render_pgp_preview pre-renders the SECRET-key
            // warning + Fingerprint / Primary UID / Key / Subkeys / Created
            // subblock per D-P7-07 (warning is the FIRST line of the returned
            // String); the subblock is threaded through the unchanged
            // Phase 6 Prompter trait via Option<&str>.
            let bytes = envelope.material.as_pgp_key_bytes()?;
            let sub = preview::render_pgp_preview(bytes)?;
            (bytes, Some(sub))
        }
        Material::SshKey { .. } => {
            // Phase 7 Plan 07: live SSH preview + armor reject per D-P7-13.
            // OpenSSH v1 is already PEM-armored by the format itself
            // (`-----BEGIN OPENSSH PRIVATE KEY-----`) — wrapping again would
            // produce nonsense. Reject `--armor` BEFORE rendering the preview
            // (cost-on-error: don't parse + render then reject; surfaces the
            // error before any preview lines hit stderr). bytes are the
            // canonical re-encoded OpenSSH v1 blob stored by Plan 05's ingest.
            // preview::render_ssh_preview pre-renders the Key (algo+bits+
            // [DEPRECATED] tag for DSA/RSA<2048) / Fingerprint (SHA-256) /
            // Comment ([sender-attested]) subblock per D-P7-14/15; the
            // subblock is threaded through the unchanged Phase 6 Prompter
            // trait via Option<&str>. D-P7-16 invariant: ssh-key crate
            // imports stay confined to src/preview.rs + src/payload/ingest.rs
            // — referenced here only via preview::render_ssh_preview.
            if armor {
                return Err(Error::Config(
                    "--armor not applicable to ssh-key — OpenSSH v1 is self-armored".into(),
                ));
            }
            let bytes = envelope.material.as_ssh_key_bytes()?;
            let sub = preview::render_ssh_preview(bytes)?;
            (bytes, Some(sub))
        }
    };

    let ttl_remaining = (expires_at - now).max(0) as u64;
    prompter.render_and_confirm(
        &envelope.purpose,
        &sender_openssh_fp,
        &record.pubkey,
        &record.share_ref,
        material_type_string(&envelope.material),
        material_bytes.len(),
        preview_subblock.as_deref(),
        ttl_remaining,
        expires_at,
    )?; // Err(Error::Declined) on mismatch → exit 7

    // STEPS 9-10 are encapsulated inside Prompter.

    // STEP 11: write material to output sink. D-P6-05 / X509-05 / PGP-05: if
    // --armor, dispatch to the per-variant armor helper (X.509 hand-rolled
    // PEM, PGP via rpgp's to_armored_bytes). Phase 7 Plan 07 finalized the
    // armor matrix: GenericSecret + SshKey BOTH reject `armor=true` at the
    // material match arm above (GenericSecret with the
    // `"--armor requires --material x509-cert or pgp-key"` literal; SshKey
    // with the variant-specific
    // `"--armor not applicable to ssh-key — OpenSSH v1 is self-armored"`
    // literal per D-P7-13). The unreachable! arm is a belt-and-suspenders
    // assertion — the architectural argument above the dispatch ensures
    // the panic never fires in any code path.
    let output_bytes: Vec<u8> = if armor {
        match &envelope.material {
            Material::X509Cert { .. } => pem_armor_certificate(material_bytes),
            Material::PgpKey { .. } => preview::pgp_armor(material_bytes)?,
            // GenericSecret + SshKey both reject `armor=true` at the material
            // match arm above — they never reach this dispatch.
            _ => unreachable!(
                "armor matrix validated above — only X509Cert + PgpKey reach here"
            ),
        }
    } else {
        material_bytes.to_vec()
    };
    write_output(output, &output_bytes)?;

    // STEP 12: sentinel FIRST, ledger SECOND (crash-safe; see fn-doc rationale).
    create_sentinel(&record.share_ref)?;
    append_ledger_entry(
        &record.share_ref,
        &record.pubkey,
        &envelope.purpose,
        &ciphertext,
        &jcs_plain,
    )?;

    // STEP 13: publish_receipt — best-effort, warn+degrade on failure (D-SEQ-01, D-SEQ-02).
    //
    // Pitfall #4 note: we recompute sha256(ciphertext) and sha256(jcs_plain) here.
    // Sha256 is deterministic over the same input bytes, so the Receipt's hash fields
    // are byte-identical to the row step 12 wrote. Both sources commit to the same
    // byte slices (ciphertext = the age-encrypted blob; jcs_plain = the JCS-canonical
    // Envelope bytes decrypted at step 6).
    //
    // Step 13 does NOT skip on self-mode (D-SEQ-06: sender_pubkey == recipient_pubkey
    // is a valid Receipt state — personal audit log).
    //
    // Step 13 is wrapped in a closure so EVERY Result-returning op inside
    // honors D-SEQ-02 warn+degrade: if any pre-publish op fails
    // (now_unix_seconds, sign_receipt's JCS serialize, serde_json::to_string)
    // OR the publish itself OR the D-SEQ-05 ledger update, we warn to stderr
    // and return Ok(()) from run_receive — the material was already delivered
    // (step 11) and locally recorded (step 12), so core-value delivery is
    // complete. Only the final warn is user-visible; the specific failure
    // class is still surfaced via user_message(&e).
    let publish_outcome: Result<(), Error> = (|| {
        use sha2::{Digest, Sha256};
        let ciphertext_hash = format!("{:x}", Sha256::digest(&ciphertext));
        let cleartext_hash = format!("{:x}", Sha256::digest(&jcs_plain));
        let accepted_at_unix = now_unix_seconds()?;
        let recipient_z32 = keypair.public_key().to_z32();

        let signable = crate::receipt::ReceiptSignable {
            accepted_at: accepted_at_unix,
            ciphertext_hash: ciphertext_hash.clone(),
            cleartext_hash: cleartext_hash.clone(),
            nonce: crate::receipt::nonce_hex(),
            protocol_version: crate::PROTOCOL_VERSION,
            purpose: envelope.purpose.clone(),
            recipient_pubkey: recipient_z32.clone(),
            sender_pubkey: record.pubkey.clone(),
            share_ref: record.share_ref.clone(),
        };
        let signature = crate::receipt::sign_receipt(&signable, keypair)?;
        let receipt = crate::receipt::Receipt {
            accepted_at: signable.accepted_at,
            ciphertext_hash: signable.ciphertext_hash.clone(),
            cleartext_hash: signable.cleartext_hash.clone(),
            nonce: signable.nonce.clone(),
            protocol_version: signable.protocol_version,
            purpose: signable.purpose.clone(),
            recipient_pubkey: signable.recipient_pubkey.clone(),
            sender_pubkey: signable.sender_pubkey.clone(),
            share_ref: signable.share_ref.clone(),
            signature,
        };
        let receipt_json = serde_json::to_string(&receipt)
            .map_err(|e| Error::Config(format!("receipt encode: {}", e)))?;

        transport.publish_receipt(keypair, &record.share_ref, &receipt_json)?;

        // D-SEQ-05: append a second ledger row with receipt_published_at: Some(iso).
        // check_already_accepted linear-scan handles 2-rows-per-share (last-wins).
        // The receipt is already on the DHT — a ledger failure here is still
        // non-fatal, and falls under the same warn+degrade path.
        let iso = iso8601_utc_now()?;
        append_ledger_entry_with_receipt(
            &record.share_ref,
            &record.pubkey,
            &envelope.purpose,
            &ciphertext_hash,
            &cleartext_hash,
            &iso,
        )?;
        Ok(())
    })();

    if let Err(e) = publish_outcome {
        // D-SEQ-02: warn + degrade; exit 0.
        eprintln!("receipt publish failed: {}", crate::error::user_message(&e));
    }

    Ok(())
}

// ---- run_receipts -----------------------------------------------------------

/// Fetch, verify, filter, and render signed receipts from a recipient's PKARR key.
///
/// D-OUT-04: no Identity required — receipts listing is passphrase-free.
///
/// D-OUT-03 exit-code taxonomy applied via returned Error variants:
///
/// - valid.len() >= 1                              → Ok (exit 0)
/// - valid empty, invalid_sig > 0                 → Err(Error::SignatureInner) (exit 3)
/// - valid empty, malformed > 0, invalid_sig == 0  → Err(Error::Config(..)) (exit 1)
/// - valid empty, all zero (or filter stripped)    → Err(Error::NotFound) (exit 5)
///
/// D-OUT-02: --share-ref filter is applied AFTER verify (Pitfall #6).
pub fn run_receipts(
    transport: &dyn Transport,
    from_z32: &str,
    share_ref_filter: Option<&str>,
    json_mode: bool,
) -> Result<(), Error> {
    // Fetch all _cprcpt-* TXT bodies. NotFound if no packet OR no matching label.
    let candidate_jsons = transport.resolve_all_cprcpt(from_z32)?;
    // resolve_all_cprcpt already returns Err(NotFound) on empty; so candidate_jsons is non-empty here.

    let mut valid: Vec<crate::receipt::Receipt> = Vec::new();
    let mut malformed = 0usize;
    let mut invalid_sig = 0usize;
    for raw in &candidate_jsons {
        let parsed: crate::receipt::Receipt = match serde_json::from_str(raw) {
            Ok(r) => r,
            Err(_) => {
                malformed += 1;
                continue;
            }
        };
        if crate::receipt::verify_receipt(&parsed).is_err() {
            invalid_sig += 1;
            continue;
        }
        valid.push(parsed);
    }

    // Summary on stderr (CLI-01).
    let mut summary = format!(
        "fetched {} receipt(s); {} valid",
        candidate_jsons.len(),
        valid.len()
    );
    if malformed > 0 {
        summary.push_str(&format!(", {} malformed", malformed));
    }
    if invalid_sig > 0 {
        summary.push_str(&format!(", {} invalid-signature", invalid_sig));
    }
    eprintln!("{}", summary);

    // D-OUT-02: filter after verify.
    if let Some(filter) = share_ref_filter {
        valid.retain(|r| r.share_ref == filter);
    }

    // Exit-code taxonomy.
    if valid.is_empty() {
        if invalid_sig > 0 {
            return Err(Error::SignatureInner);
        }
        if malformed > 0 {
            return Err(Error::Config("all receipts malformed".into()));
        }
        return Err(Error::NotFound);
    }

    // Render.
    if json_mode {
        // RESEARCH §"Open Questions" #4: pretty-print for UX (output is display-only,
        // not signed). JCS stays on the signature path inside verify_receipt.
        let out = serde_json::to_string_pretty(&valid)
            .map_err(|e| Error::Config(format!("json encode: {}", e)))?;
        println!("{}", out);
    } else {
        let audit_detail = share_ref_filter.is_some() && valid.len() == 1;
        render_receipts_table(&valid, audit_detail)?;
    }
    Ok(())
}

/// D-OUT-01 multi-row table OR D-OUT-02 single-row audit-detail view.
fn render_receipts_table(
    receipts: &[crate::receipt::Receipt],
    audit_detail: bool,
) -> Result<(), Error> {
    if audit_detail {
        let r = &receipts[0];
        println!("share_ref:          {}", r.share_ref);
        println!("sender_pubkey:      {}", r.sender_pubkey);
        println!("recipient_pubkey:   {}", r.recipient_pubkey);
        // format_unix_as_iso_utc already appends " UTC"; no extra suffix needed.
        println!(
            "accepted_at:        {} ({} local)",
            format_unix_as_iso_utc(r.accepted_at),
            format_unix_as_iso_local(r.accepted_at),
        );
        let safe_purpose: String = r.purpose.chars().filter(|c| !c.is_control()).collect();
        println!("purpose:            \"{}\"", safe_purpose);
        println!("ciphertext_hash:    {}", r.ciphertext_hash);
        println!("cleartext_hash:     {}", r.cleartext_hash);
        println!("nonce:              {}", r.nonce);
        println!("protocol_version:   {}", r.protocol_version);
        println!("signature:          {}", r.signature);
        return Ok(());
    }

    // Multi-row table (D-OUT-01 columns).
    println!(
        "{:<16}  {:<20}  {:<40}  recipient_fp",
        "share_ref", "accepted_at (UTC)", "purpose"
    );
    for r in receipts {
        let (fp, _) = sender_openssh_fingerprint_and_z32(&r.recipient_pubkey)?;
        let purpose_display = truncate_purpose(&r.purpose, 40);
        let utc = format_unix_as_iso_utc(r.accepted_at);
        let share_ref_short: String = r.share_ref.chars().take(16).collect();
        println!(
            "{:<16}  {:<20}  {:<40}  {}",
            share_ref_short, utc, purpose_display, fp,
        );
    }
    Ok(())
}

/// Strip ASCII control chars (defense-in-depth over send-time strip per PAYL-04 /
/// D-WIRE-05); truncate to `max` display chars, appending `…` if truncation applies.
fn truncate_purpose(p: &str, max: usize) -> String {
    let stripped: String = p.chars().filter(|c| !c.is_control()).collect();
    if stripped.chars().count() <= max {
        stripped
    } else {
        // Truncate by chars (not bytes) to avoid splitting a UTF-8 codepoint.
        let prefix: String = stripped.chars().take(max.saturating_sub(1)).collect();
        format!("{}…", prefix)
    }
}

fn material_type_string(m: &Material) -> &'static str {
    match m {
        Material::GenericSecret { .. } => "generic_secret",
        Material::X509Cert { .. } => "x509_cert",
        Material::PgpKey { .. } => "pgp_key",
        Material::SshKey { .. } => "ssh_key",
    }
}

fn write_output(sink: &mut OutputSink, bytes: &[u8]) -> Result<(), Error> {
    match sink {
        OutputSink::Stdout => {
            use std::io::Write as IoWrite;
            std::io::stdout().write_all(bytes).map_err(Error::Io)
        }
        OutputSink::File(p) => fs::write(p, bytes).map_err(Error::Io),
        OutputSink::InMemory(buf) => {
            buf.extend_from_slice(bytes);
            Ok(())
        }
    }
}

/// Wrap canonical DER cert bytes in a PEM armor envelope. X509-05.
/// Hand-rolled (no new dep): `-----BEGIN CERTIFICATE-----\n` + 64-char-wrapped
/// base64-STANDARD + `\n-----END CERTIFICATE-----\n`.
fn pem_armor_certificate(der: &[u8]) -> Vec<u8> {
    use base64::Engine;
    let encoded = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = String::with_capacity(encoded.len() + 80);
    out.push_str("-----BEGIN CERTIFICATE-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 output is ASCII"));
        out.push('\n');
    }
    out.push_str("-----END CERTIFICATE-----\n");
    out.into_bytes()
}

// ---- State: sentinel + ledger ---------------------------------------------

fn ensure_state_dirs() -> Result<(), Error> {
    let sd = state_dir();
    fs::create_dir_all(&sd).map_err(Error::Io)?;
    fs::set_permissions(&sd, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
    let ad = accepted_dir();
    fs::create_dir_all(&ad).map_err(Error::Io)?;
    fs::set_permissions(&ad, fs::Permissions::from_mode(0o700)).map_err(Error::Io)?;
    Ok(())
}

fn create_sentinel(share_ref_hex: &str) -> Result<(), Error> {
    ensure_state_dirs()?;
    let path = sentinel_path(share_ref_hex);
    match fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
    {
        Ok(_) => Ok(()),
        // benign race (D-STATE-01 create_new semantics) — sentinel already
        // exists, RECV-06 short-circuit should have caught this upstream
        Err(e) if e.kind() == ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(Error::Io(e)),
    }
}

#[derive(serde::Serialize)]
struct LedgerEntry<'a> {
    accepted_at: &'a str,
    ciphertext_hash: String,
    cleartext_hash: String,
    purpose: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    receipt_published_at: Option<&'a str>,
    sender: &'a str,
    share_ref: &'a str,
}

fn append_ledger_entry(
    share_ref: &str,
    sender_z32: &str,
    purpose: &str,
    ciphertext: &[u8],
    jcs_plain: &[u8],
) -> Result<(), Error> {
    ensure_state_dirs()?;
    use sha2::{Digest, Sha256};
    let ch = format!("{:x}", Sha256::digest(ciphertext));
    let ph = format!("{:x}", Sha256::digest(jcs_plain));
    let accepted_at = iso8601_utc_now()?;
    let entry = LedgerEntry {
        accepted_at: &accepted_at,
        ciphertext_hash: ch,
        cleartext_hash: ph,
        purpose,
        receipt_published_at: None, // step 12 writes null; step 13 appends a success row
        sender: sender_z32,
        share_ref,
    };
    // JCS guarantees alphabetical key order (mirrors on-wire convention
    // elsewhere). Append a newline for jsonl framing.
    let mut line = crypto::jcs_serialize(&entry)?;
    line.push(b'\n');
    let path = ledger_path();
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .map_err(Error::Io)?;
    f.write_all(&line).map_err(Error::Io)?;
    // Re-apply perms (defensive vs umask on first creation).
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
    Ok(())
}

/// D-SEQ-05: append a second ledger row with `receipt_published_at: Some(iso)`
/// after a successful Plan-03 step-13 publish_receipt. Append-only; the earlier
/// row (from step 12, with receipt_published_at: None) stays in the file.
/// `check_already_accepted` linear-scan already returns last-match-wins.
///
/// Pitfall #4: ciphertext_hash / cleartext_hash are passed IN (pre-computed at
/// step 12) rather than recomputed here — two hashing call-sites = two sources
/// of truth; the receipt field values must match what step 12 wrote.
fn append_ledger_entry_with_receipt(
    share_ref: &str,
    sender_z32: &str,
    purpose: &str,
    ciphertext_hash: &str,
    cleartext_hash: &str,
    receipt_published_at_iso: &str,
) -> Result<(), Error> {
    ensure_state_dirs()?;
    let accepted_at = iso8601_utc_now()?;
    let entry = LedgerEntry {
        accepted_at: &accepted_at,
        ciphertext_hash: ciphertext_hash.to_string(),
        cleartext_hash: cleartext_hash.to_string(),
        purpose,
        receipt_published_at: Some(receipt_published_at_iso),
        sender: sender_z32,
        share_ref,
    };
    let mut line = crypto::jcs_serialize(&entry)?;
    line.push(b'\n');
    let path = ledger_path();
    let mut f = fs::OpenOptions::new()
        .append(true)
        .create(true)
        .mode(0o600)
        .open(&path)
        .map_err(Error::Io)?;
    f.write_all(&line).map_err(Error::Io)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).map_err(Error::Io)?;
    Ok(())
}

// ---- Helpers ---------------------------------------------------------------

fn now_unix_seconds() -> Result<i64, Error> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Error::Config("system clock before epoch".into()))
        .map(|d| d.as_secs() as i64)
}

fn iso8601_utc_now() -> Result<String, Error> {
    // Minimal ISO-8601 UTC formatter — no chrono dep in Plan 02; Plan 03 can
    // migrate if chrono is added for the acceptance-screen time rendering.
    // Format: YYYY-MM-DDTHH:MM:SSZ
    let secs = now_unix_seconds()?;
    let days = secs.div_euclid(86400);
    let rem = secs.rem_euclid(86400);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    let second = rem % 60;
    let (y, m, d) = civil_from_days(days);
    Ok(format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y, m, d, hour, minute, second
    ))
}

/// Howard Hinnant's civil-from-days algorithm, epoch 1970-01-01. Returns
/// `(year, month, day_of_month)`.
fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y_out = if m <= 2 { y + 1 } else { y };
    (y_out as i32, m, d)
}

fn sender_openssh_fingerprint_and_z32(z32: &str) -> Result<(String, String), Error> {
    let pk = pkarr::PublicKey::try_from(z32).map_err(|_| Error::SignatureInner)?;
    let pk_bytes: [u8; 32] = *pk.as_bytes();
    let algo = b"ssh-ed25519";
    let mut encoded = Vec::with_capacity(4 + algo.len() + 4 + 32);
    encoded.extend_from_slice(&(algo.len() as u32).to_be_bytes());
    encoded.extend_from_slice(algo);
    encoded.extend_from_slice(&32u32.to_be_bytes());
    encoded.extend_from_slice(&pk_bytes);
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(&encoded);
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest);
    Ok((format!("ed25519:SHA256:{}", b64), z32.to_string()))
}

// ---- Test helpers (cfg-gated) ----------------------------------------------

#[cfg(any(test, feature = "mock"))]
pub mod test_helpers {
    use super::*;

    /// Auto-confirm `Prompter`: renders nothing, accepts always. Used in Plan
    /// 02 round-trip tests. Plan 03 will provide a real TTY `Prompter` for the
    /// CLI.
    pub struct AutoConfirmPrompter;

    impl Prompter for AutoConfirmPrompter {
        fn render_and_confirm(
            &self,
            _purpose: &str,
            _sender_openssh_fp: &str,
            _sender_z32: &str,
            _share_ref_hex: &str,
            _material_type: &str,
            _size_bytes: usize,
            _preview_subblock: Option<&str>,
            _ttl_remaining_seconds: u64,
            _expires_unix_seconds: i64,
        ) -> Result<(), Error> {
            Ok(())
        }
    }

    /// Always-decline `Prompter`. Used in decline / declined-exit-code tests.
    pub struct DeclinePrompter;

    impl Prompter for DeclinePrompter {
        fn render_and_confirm(
            &self,
            _purpose: &str,
            _sender_openssh_fp: &str,
            _sender_z32: &str,
            _share_ref_hex: &str,
            _material_type: &str,
            _size_bytes: usize,
            _preview_subblock: Option<&str>,
            _ttl_remaining_seconds: u64,
            _expires_unix_seconds: i64,
        ) -> Result<(), Error> {
            Err(Error::Declined)
        }
    }
}

// ============================================================================
// TtyPrompter — production Prompter used by main.rs::dispatch.
//
// Renders the D-ACCEPT-02 bordered banner to stderr, reads typed z32 via
// dialoguer::Input, byte-compares to the sender's z32 (after trim()).
// Pre-check: stdin AND stderr MUST both be TTYs. The cfg-gated
// CIPHERPOST_SKIP_TTY_CHECK env var allows the assert_cmd subprocess tests to
// drive stdin via a pipe — production builds (no `mock` feature and no test
// cfg) cannot honor the override.
// ============================================================================

/// Production Prompter backed by a real TTY.
///
/// Renders the D-ACCEPT-02 bordered banner to stderr and reads the sender's
/// z-base-32 pubkey via `dialoguer::Input` (or a plain stdin line-read in test
/// mode). Returns `Err(Error::Declined)` on any mismatch (D-ACCEPT-01).
///
/// The TTY pre-check (D-ACCEPT-03) requires BOTH stdin AND stderr to be TTYs.
/// Production builds cannot bypass it; only builds compiled with `cfg(test)`
/// or `--features mock` honor the `CIPHERPOST_SKIP_TTY_CHECK` env var.
pub struct TtyPrompter;

impl TtyPrompter {
    pub fn new() -> Self {
        TtyPrompter
    }
}

impl Default for TtyPrompter {
    fn default() -> Self {
        Self::new()
    }
}

/// Returns `true` iff the process is running under `cfg(test)` or the `mock`
/// feature AND `CIPHERPOST_SKIP_TTY_CHECK` is set. Always `false` in production
/// builds so the TTY pre-check cannot be bypassed.
fn tty_check_skipped() -> bool {
    #[cfg(any(test, feature = "mock"))]
    {
        std::env::var("CIPHERPOST_SKIP_TTY_CHECK").is_ok()
    }
    #[cfg(not(any(test, feature = "mock")))]
    {
        false
    }
}

/// Format `<Xh YYm>` for TTL remaining. Hand-rolled — no chrono dep.
fn format_ttl_remaining(seconds: u64) -> String {
    let h = seconds / 3600;
    let m = (seconds % 3600) / 60;
    format!("{}h {:02}m", h, m)
}

/// Format a unix-seconds timestamp as `YYYY-MM-DD HH:MM UTC`. Reuses the
/// civil-from-days helper already in this file (Plan 02).
///
/// Phase 6 Plan 02: visibility bumped from private to `pub(crate)` so
/// `src/preview.rs::render_x509_preview` can reuse it for NotBefore/NotAfter
/// rendering (D-P6-12). Callers MUST NOT append a second `" UTC"` suffix —
/// the returned string already ends in ` UTC` (see `format_unix_as_iso_utc_epoch`
/// pinned test in this file for the UAT-2 2026-04-21 double-UTC bug).
pub(crate) fn format_unix_as_iso_utc(unix: i64) -> String {
    let days = unix.div_euclid(86400);
    let rem = unix.rem_euclid(86400);
    let (y, m, d) = civil_from_days(days);
    let hour = rem / 3600;
    let minute = (rem % 3600) / 60;
    format!("{:04}-{:02}-{:02} {:02}:{:02} UTC", y, m, d, hour, minute)
}

/// Format a unix-seconds timestamp in the user's local timezone as
/// `YYYY-MM-DD HH:MM` (D-ACCEPT-02 / RECV-04). chrono reads the system
/// timezone at call time; if lookup fails we fall back to "?" rather than
/// surfacing the error through the acceptance path.
fn format_unix_as_iso_local(unix: i64) -> String {
    use chrono::{Local, TimeZone};
    match Local.timestamp_opt(unix, 0).single() {
        Some(dt) => dt.format("%Y-%m-%d %H:%M").to_string(),
        None => "?".to_string(),
    }
}

impl Prompter for TtyPrompter {
    fn render_and_confirm(
        &self,
        purpose: &str,
        sender_openssh_fp: &str,
        sender_z32: &str,
        share_ref_hex: &str,
        material_type: &str,
        size_bytes: usize,
        preview_subblock: Option<&str>,
        ttl_remaining_seconds: u64,
        expires_unix_seconds: i64,
    ) -> Result<(), Error> {
        // D-ACCEPT-03: TTY required on stdin AND stderr (unless skipped under
        // cfg(test) / feature=mock). Production builds cannot honor the skip.
        if !tty_check_skipped()
            && (!std::io::stderr().is_terminal() || !std::io::stdin().is_terminal())
        {
            return Err(Error::Config(
                "acceptance requires a TTY; non-interactive receive is deferred".into(),
            ));
        }

        // D-ACCEPT-02: render the bordered banner to stderr. No ANSI colors.
        // Purpose is defensively re-stripped of control chars at render time
        // (sender should have stripped at send time, but belt-and-suspenders).
        let safe_purpose: String = purpose.chars().filter(|c| !c.is_control()).collect();
        let expires_utc = format_unix_as_iso_utc(expires_unix_seconds);
        let expires_local = format_unix_as_iso_local(expires_unix_seconds);
        let ttl_str = format_ttl_remaining(ttl_remaining_seconds);

        eprintln!("=== CIPHERPOST ACCEPTANCE ===============================");
        eprintln!("Purpose:     \"{}\"", safe_purpose);
        eprintln!("Sender:      {}", sender_openssh_fp);
        eprintln!("             {}", sender_z32);
        eprintln!("Share ref:   {}", share_ref_hex);
        eprintln!("Type:        {}", material_type);
        eprintln!("Size:        {} bytes", size_bytes);
        // D-P6-09: typed-variant subblock between Size and TTL.
        // Caller (run_receive) pre-renders the multi-line string; this arm
        // is agnostic to the variant.
        if let Some(sub) = preview_subblock {
            eprintln!("{}", sub);
        }
        eprintln!(
            "TTL:         {} remaining (expires {} / {} local)",
            ttl_str, expires_utc, expires_local
        );
        eprintln!("=========================================================");
        eprintln!("To accept, paste the sender's z32 pubkey and press Enter:");

        // D-ACCEPT-01: read the typed z32 from the user. In test-mode with
        // the TTY check skipped, dialoguer::Input cannot prompt on a pipe;
        // fall back to a direct stdin line-read so assert_cmd tests can drive
        // this path via a piped stdin.
        let typed: String = if tty_check_skipped() {
            let mut s = String::new();
            std::io::stdin()
                .read_line(&mut s)
                .map_err(|_| Error::Config("stdin read failed".into()))?;
            s
        } else {
            dialoguer::Input::<String>::new()
                .with_prompt(">")
                .interact_text()
                .map_err(|_| Error::Config("TTY not available for acceptance prompt".into()))?
        };

        if typed.trim() == sender_z32 {
            Ok(())
        } else {
            Err(Error::Declined)
        }
    }
}

// ---- std::io::IsTerminal: required by TtyPrompter (Rust 1.70+; MSRV 1.85) --
use std::io::IsTerminal;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_dir_respects_cipherpost_home() {
        let saved = std::env::var("CIPHERPOST_HOME").ok();
        std::env::set_var("CIPHERPOST_HOME", "/tmp/cp-test-state-dir");
        assert_eq!(
            state_dir(),
            PathBuf::from("/tmp/cp-test-state-dir").join("state")
        );
        match saved {
            Some(v) => std::env::set_var("CIPHERPOST_HOME", v),
            None => std::env::remove_var("CIPHERPOST_HOME"),
        }
    }

    #[test]
    fn civil_from_days_epoch() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(59), (1970, 3, 1)); // Feb has 28 in 1970
    }

    #[test]
    fn iso_format_epoch_is_1970_01_01() {
        // Direct call with controlled input; skip now()-dependent path.
        let epoch_ts = 0_i64;
        let days = epoch_ts.div_euclid(86400);
        let (y, m, d) = civil_from_days(days);
        assert_eq!((y, m, d), (1970, 1, 1));
    }

    #[test]
    fn format_unix_as_iso_utc_epoch() {
        // Pins the suffix: callers must NOT append another " UTC" after
        // `format_unix_as_iso_utc(...)` — see UAT-2 2026-04-21 double-UTC bug.
        assert_eq!(format_unix_as_iso_utc(0), "1970-01-01 00:00 UTC");
    }

    #[test]
    fn format_unix_as_iso_local_renders_tz_aware_string() {
        // D-ACCEPT-02 / RECV-04: local time must render alongside UTC in the
        // acceptance banner. This test does NOT assert a specific timezone
        // offset (it's machine-dependent) — it asserts the formatter returns
        // a parseable `YYYY-MM-DD HH:MM` shape, not the "?" fallback, for a
        // valid unix timestamp. Any TZ that chrono can resolve produces this.
        let s = format_unix_as_iso_local(0);
        assert_ne!(s, "?", "chrono should resolve local TZ on a healthy host");
        assert_eq!(
            s.len(),
            16,
            "expected `YYYY-MM-DD HH:MM` (16 chars), got {:?}",
            s
        );
        assert_eq!(&s[4..5], "-");
        assert_eq!(&s[7..8], "-");
        assert_eq!(&s[10..11], " ");
        assert_eq!(&s[13..14], ":");
    }

    #[test]
    fn tty_prompter_rejects_non_tty_env() {
        // D-ACCEPT-03: when stdin or stderr is not a TTY AND CIPHERPOST_SKIP_TTY_CHECK
        // is unset, TtyPrompter::render_and_confirm must return
        // Error::Config("acceptance requires a TTY; non-interactive receive is deferred")
        // WITHOUT reading any bytes from stdin and without rendering the banner.
        //
        // Under `cargo test` the harness redirects stdin/stderr to pipes, so the
        // IsTerminal check naturally fails. We defensively ensure the override is
        // absent.
        let saved = std::env::var("CIPHERPOST_SKIP_TTY_CHECK").ok();
        std::env::remove_var("CIPHERPOST_SKIP_TTY_CHECK");

        let result = TtyPrompter::new().render_and_confirm(
            "test purpose",     // purpose
            "SHA256:dummy",     // sender_openssh_fp
            "sender_z32_dummy", // sender_z32
            "deadbeef",         // share_ref_hex
            "generic_blob",     // material_type
            42,                 // size_bytes
            None,               // preview_subblock
            3600,               // ttl_remaining_seconds
            0,                  // expires_unix_seconds
        );

        // Restore env before asserting so a panic does not leak state.
        if let Some(v) = saved {
            std::env::set_var("CIPHERPOST_SKIP_TTY_CHECK", v);
        }

        match result {
            Err(Error::Config(msg)) => {
                assert_eq!(
                    msg, "acceptance requires a TTY; non-interactive receive is deferred",
                    "D-ACCEPT-03 error message must be exact"
                );
            }
            Err(other) => panic!("expected Error::Config, got {:?}", other),
            Ok(()) => panic!("expected TTY pre-check to refuse in non-TTY cargo-test env"),
        }
    }
}
