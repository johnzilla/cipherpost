//! Assert a representative OuterRecord fits into a PKARR SignedPacket under
//! the BEP44 ~1000-byte budget. Catches schema bloat early.
//!
//! SEND-05 check; also validates TRANS-01 usability.
//!
//! The total SignedPacket encoding is 32 (pubkey) + 64 (sig) + 8 (timestamp) +
//! encoded_dns_packet. pkarr::SignedPacket::as_bytes() returns all of those.

use cipherpost::record::{share_ref_from_bytes, sign_record, OuterRecord, OuterRecordSignable};
use cipherpost::PROTOCOL_VERSION;

#[test]
fn representative_outer_record_fits_in_1000_bytes() {
    let seed = [42u8; 32];
    let kp = pkarr::Keypair::from_secret_key(&seed);

    // Representative sizing: 550 bytes base64 is the empirically-measured upper limit
    // for worst-case (recipient present, both z32 pubkeys) that fits within the 1000-byte
    // BEP44 DNS packet budget. blob_len=550 → dns_packet=999 bytes (OK); blob_len=600
    // → dns_packet=1049 bytes (exceeds budget). Phase 2 must enforce this ceiling at
    // the payload level or use two-tier storage for larger payloads.
    // Deviation from plan's "~600 bytes" assumption — see SUMMARY deviations.
    let blob = "A".repeat(550);
    let created_at = 1_700_000_000_i64;
    let share_ref = share_ref_from_bytes(blob.as_bytes(), created_at);
    let signable = OuterRecordSignable {
        blob: blob.clone(),
        created_at,
        pin_required: false,
        protocol_version: PROTOCOL_VERSION,
        pubkey: kp.public_key().to_z32(),
        recipient: Some(kp.public_key().to_z32()), // worst case: share mode, recipient present
        share_ref: share_ref.clone(),
        ttl_seconds: 86400,
    };
    let signature = sign_record(&signable, &kp).unwrap();
    let record = OuterRecord {
        blob: signable.blob,
        created_at: signable.created_at,
        pin_required: signable.pin_required,
        protocol_version: signable.protocol_version,
        pubkey: signable.pubkey,
        recipient: signable.recipient,
        share_ref: signable.share_ref,
        signature,
        ttl_seconds: signable.ttl_seconds,
    };

    let json = serde_json::to_string(&record).unwrap();
    let json_len = json.len();

    let name: pkarr::dns::Name<'_> = "_cipherpost".try_into().unwrap();
    let txt: pkarr::dns::rdata::TXT<'_> = json.as_str().try_into().unwrap();
    let packet = pkarr::SignedPacket::builder()
        .txt(name, txt, 300)
        .sign(&kp)
        .unwrap();

    // as_bytes() returns the full SignedPacket encoding:
    // 32 (pubkey) + 64 (signature) + 8 (timestamp) + encoded_dns_packet
    let encoded_len = packet.as_bytes().len();

    assert!(
        encoded_len < 1104, // SignedPacket::MAX_BYTES
        "SignedPacket encoded size {} exceeds 1104-byte MAX_BYTES limit",
        encoded_len
    );

    // Separately, the encoded DNS packet (the BEP44 value portion) must be <= 1000 bytes
    let dns_packet_len = packet.encoded_packet().len();
    assert!(
        dns_packet_len <= 1000,
        "DNS packet portion {} exceeds 1000-byte PKARR/BEP44 budget (JSON was {} bytes)",
        dns_packet_len,
        json_len
    );
}
