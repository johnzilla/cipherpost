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

use crate::crypto;
use crate::error::Error;
use crate::identity::Identity;
use crate::payload::{self, Envelope, Material};
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
pub fn run_send(
    identity: &Identity,
    transport: &dyn Transport,
    keypair: &pkarr::Keypair,
    mode: SendMode,
    purpose: &str,
    material_source: MaterialSource,
    ttl_seconds: u64,
) -> Result<String, Error> {
    // 1. read material
    let plaintext_bytes: Zeroizing<Vec<u8>> = read_material(material_source)?;

    // 2. plaintext cap (pre-encrypt; D-PS-01)
    payload::enforce_plaintext_cap(plaintext_bytes.len())?;

    // 3. strip purpose control chars (D-WIRE-05)
    let stripped_purpose = payload::strip_control_chars(purpose);

    // 4. build Envelope + JCS-serialize
    let created_at = now_unix_seconds()?;
    let envelope = Envelope {
        created_at,
        material: Material::generic_secret(plaintext_bytes.to_vec()),
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

    // 6. age_encrypt
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
        recipient: recipient_z32_option,
        share_ref: share_ref.clone(),
        signature,
        ttl_seconds,
    };

    // 12. wire-budget pre-check (REAL SignedPacket build, NOT mock's rdata.len())
    check_wire_budget(&record, keypair, jcs_bytes.len())?;

    // 13. publish
    transport.publish(keypair, &record)?;

    // 14. return URI
    Ok(ShareUri::format(&identity.z32_pubkey(), &share_ref))
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
    let packet = pkarr::SignedPacket::builder()
        .txt(name, txt, 300)
        .sign(keypair)
        .map_err(|e| Error::Transport(Box::new(e)))?;
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
pub fn run_receive(
    identity: &Identity,
    transport: &dyn Transport,
    uri: &ShareUri,
    output: &mut OutputSink,
    prompter: &dyn Prompter,
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
    // Non-generic material variants return NotImplemented (exit 1).
    let material_bytes = envelope.material.as_generic_secret_bytes()?;
    let ttl_remaining = (expires_at - now).max(0) as u64;
    prompter.render_and_confirm(
        &envelope.purpose,
        &sender_openssh_fp,
        &record.pubkey,
        &record.share_ref,
        material_type_string(&envelope.material),
        material_bytes.len(),
        ttl_remaining,
        expires_at,
    )?; // Err(Error::Declined) on mismatch → exit 7

    // STEPS 9-10 are encapsulated inside Prompter.

    // STEP 11: write material to output sink
    write_output(output, material_bytes)?;

    // STEP 12: sentinel FIRST, ledger SECOND (crash-safe; see fn-doc rationale).
    create_sentinel(&record.share_ref)?;
    append_ledger_entry(
        &record.share_ref,
        &record.pubkey,
        &envelope.purpose,
        &ciphertext,
        &jcs_plain,
    )?;

    Ok(())
}

fn material_type_string(m: &Material) -> &'static str {
    match m {
        Material::GenericSecret { .. } => "generic_secret",
        Material::X509Cert => "x509_cert",
        Material::PgpKey => "pgp_key",
        Material::SshKey => "ssh_key",
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
            _ttl_remaining_seconds: u64,
            _expires_unix_seconds: i64,
        ) -> Result<(), Error> {
            Err(Error::Declined)
        }
    }
}

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
}
