//! RECV-06: second receive on the same accepted share_ref must short-circuit
//! (no network, no re-decrypt, no second ledger line).

use cipherpost::flow::test_helpers::AutoConfirmPrompter;
use cipherpost::flow::{
    run_receive, run_send, MaterialSource, OutputSink, SendMode, DEFAULT_TTL_SECONDS,
};
use cipherpost::transport::MockTransport;
use cipherpost::ShareUri;
use secrecy::SecretBox;
use serial_test::serial;
use tempfile::TempDir;

#[test]
#[serial]
fn second_receive_on_same_share_ref_short_circuits() {
    let dir = TempDir::new().unwrap();
    std::env::set_var("CIPHERPOST_HOME", dir.path());
    let pw = SecretBox::new(Box::new("pass".to_string()));
    let id = cipherpost::identity::generate(&pw).unwrap();
    let seed: [u8; 32] = *id.signing_seed();
    let kp = pkarr::Keypair::from_secret_key(&seed);
    let transport = MockTransport::new();

    // Keep plaintext + purpose short to fit the 1000-byte wire budget.
    let plaintext = b"p42".to_vec();
    let uri_str = run_send(
        &id,
        &transport,
        &kp,
        SendMode::SelfMode,
        "i",
        MaterialSource::Bytes(plaintext.clone()),
        DEFAULT_TTL_SECONDS,
    )
    .unwrap();
    let uri = ShareUri::parse(&uri_str).unwrap();

    // First receive — should succeed and write material + ledger + sentinel.
    let mut sink1 = OutputSink::InMemory(Vec::new());
    run_receive(&id, &transport, &kp, &uri, &mut sink1, &AutoConfirmPrompter).unwrap();
    match sink1 {
        OutputSink::InMemory(buf) => assert_eq!(buf, plaintext),
        _ => panic!(),
    }

    // Ledger must have 1 or 2 lines after first receive:
    //   - step 12 always writes 1 row (receipt_published_at: null)
    //   - step 13 appends a second row on successful publish_receipt (D-SEQ-05)
    // MockTransport publish_receipt succeeds, so we expect 2 rows.
    let ledger_path = dir.path().join("state").join("accepted.jsonl");
    let ledger_after_first = std::fs::read_to_string(&ledger_path).unwrap();
    let lines_after_first = ledger_after_first.lines().count();
    assert!(
        lines_after_first >= 1 && lines_after_first <= 2,
        "ledger must have 1–2 lines after first receive (step 12 null + optional step 13 with receipt_published_at), got {}",
        lines_after_first
    );

    // Second receive — must short-circuit: returns Ok, no ledger line added,
    // no material written.
    let mut sink2 = OutputSink::InMemory(Vec::new());
    run_receive(&id, &transport, &kp, &uri, &mut sink2, &AutoConfirmPrompter).unwrap();
    match sink2 {
        OutputSink::InMemory(buf) => {
            assert!(buf.is_empty(), "second receive must not write material")
        }
        _ => panic!(),
    }

    // Ledger unchanged after idempotent second receive.
    let ledger_after_second = std::fs::read_to_string(&ledger_path).unwrap();
    assert_eq!(
        ledger_after_second.lines().count(),
        lines_after_first,
        "ledger must not grow on idempotent re-receive"
    );
}
