//! SC2: tampering any byte of the OuterRecord signature aborts with exit 3
//! (SignatureInner or SignatureCanonicalMismatch — both share the unified
//! "signature verification failed" Display per D-16) BEFORE any age-decrypt.
//! No envelope field (purpose, material bytes) appears in any captured output
//! before the sig check passes.

use cipherpost::cli::MaterialVariant;
use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::{MockTransport, Transport};
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn tampered_signature_aborts_before_decrypt_and_does_not_leak_purpose() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let transport = MockTransport::new();

    // Unique-enough sentinels for the no-leak assertion. Keep short to fit
    // the 1000-byte wire budget (self-mode, post-age-overhead).
    let secret_purpose = "SPX42";
    let plaintext = b"SMXYZ".to_vec();

    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        secret_purpose,
        MaterialSource::Bytes(plaintext.clone()),
        MaterialVariant::GenericSecret,
        DEFAULT_TTL_SECONDS,
        None,  // Phase 8 Plan 01: pin=None — CLI --pin lands in Plan 02.
        false, // Phase 8 Plan 01: burn=false — CLI --burn lands in Plan 03.
    )
    .unwrap();
    let uri = ShareUri::parse(&uri_str).unwrap();

    // Tamper: resolve, flip a byte in the signature, re-publish via
    // MockTransport::publish (which does NOT verify — only resolve does, per
    // src/transport.rs). The bad record lands in the store; the next
    // run_receive's transport.resolve() call will fail inner-sig verify.
    let good = transport.resolve(&uri.sender_z32).expect("good resolve");
    let mut bad = good.clone();
    // Flip last base64 char of signature so it still base64-decodes but verify
    // fails (or Canonical re-serialize fails — either way: unified Display).
    let mut sig_chars: Vec<char> = bad.signature.chars().collect();
    let last = sig_chars.last_mut().unwrap();
    *last = if *last == 'A' { 'B' } else { 'A' };
    bad.signature = sig_chars.into_iter().collect();

    transport.publish(&kp, &bad).expect("publish corrupt");

    // Now run_receive; the corrupt signature must fail verify inside resolve()
    let mut sink = OutputSink::InMemory(Vec::new());
    let err = run_receive(
        &id,
        &transport,
        &kp,
        &uri,
        &mut sink,
        &AutoConfirmPrompter,
        false,
    )
    .unwrap_err();
    assert!(
        matches!(
            err,
            cipherpost::Error::SignatureInner | cipherpost::Error::SignatureCanonicalMismatch
        ),
        "expected SignatureInner / SignatureCanonicalMismatch, got {:?}",
        err
    );

    // D-16: user-facing message is unified "signature verification failed"
    let msg = cipherpost::error::user_message(&err);
    assert_eq!(msg, "signature verification failed");

    // Critical invariant: no payload field was surfaced. The sink must be empty,
    // and the secret_purpose string must NOT appear anywhere we can introspect.
    match sink {
        OutputSink::InMemory(buf) => {
            assert!(buf.is_empty(), "no material bytes should have been written");
            let as_str = String::from_utf8_lossy(&buf);
            assert!(
                !as_str.contains(secret_purpose),
                "purpose must not leak to output sink on sig failure"
            );
        }
        _ => panic!(),
    }
}
