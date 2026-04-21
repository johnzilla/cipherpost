//! D-URI-01/02/03: strict share URI parser.

use cipherpost::{ShareUri, SHARE_URI_SCHEME};

const VALID_Z32: &str = "yhigci4xwmadibrmj8wzmf45f3i8xg8mht9abnprq3r5cfxihj8y"; // 52 chars
const VALID_HEX: &str = "0123456789abcdef0123456789abcdef"; // 32 chars lowercase

fn valid_uri() -> String {
    format!("{}{}/{}", SHARE_URI_SCHEME, VALID_Z32, VALID_HEX)
}

#[test]
fn parse_accepts_canonical_uri() {
    let parsed = ShareUri::parse(&valid_uri()).expect("canonical URI must parse");
    assert_eq!(parsed.sender_z32, VALID_Z32);
    assert_eq!(parsed.share_ref_hex, VALID_HEX);
}

#[test]
fn parse_rejects_bare_z32_with_hint_message() {
    let err = ShareUri::parse(VALID_Z32).unwrap_err();
    match err {
        cipherpost::Error::InvalidShareUri(reason) => {
            assert!(
                reason.contains("cipherpost://") || reason.contains("bare pubkey"),
                "bare-z32 rejection should include a hint, got: {}",
                reason
            );
        }
        other => panic!("expected InvalidShareUri, got {:?}", other),
    }
}

#[test]
fn parse_rejects_wrong_length_z32() {
    let too_short = format!("cipherpost://{}/{}", "short", VALID_HEX);
    assert!(matches!(
        ShareUri::parse(&too_short).unwrap_err(),
        cipherpost::Error::InvalidShareUri(_)
    ));
}

#[test]
fn parse_rejects_wrong_length_hex() {
    let too_short = format!("cipherpost://{}/deadbeef", VALID_Z32);
    assert!(matches!(
        ShareUri::parse(&too_short).unwrap_err(),
        cipherpost::Error::InvalidShareUri(_)
    ));
}

#[test]
fn parse_rejects_uppercase_hex() {
    let upper = format!(
        "cipherpost://{}/{}",
        VALID_Z32, "0123456789ABCDEF0123456789ABCDEF"
    );
    assert!(matches!(
        ShareUri::parse(&upper).unwrap_err(),
        cipherpost::Error::InvalidShareUri(_)
    ));
}

#[test]
fn parse_rejects_missing_slash_separator() {
    let bad = format!("cipherpost://{}{}", VALID_Z32, VALID_HEX);
    assert!(matches!(
        ShareUri::parse(&bad).unwrap_err(),
        cipherpost::Error::InvalidShareUri(_)
    ));
}

#[test]
fn parse_rejects_trailing_query() {
    let bad = format!("cipherpost://{}/{}?foo=bar", VALID_Z32, VALID_HEX);
    assert!(matches!(
        ShareUri::parse(&bad).unwrap_err(),
        cipherpost::Error::InvalidShareUri(_)
    ));
}

#[test]
fn parse_rejects_empty() {
    assert!(matches!(
        ShareUri::parse("").unwrap_err(),
        cipherpost::Error::InvalidShareUri(_)
    ));
}

#[test]
fn format_round_trip_matches_parse() {
    let s = ShareUri::format(VALID_Z32, VALID_HEX);
    let parsed = ShareUri::parse(&s).unwrap();
    assert_eq!(parsed.sender_z32, VALID_Z32);
    assert_eq!(parsed.share_ref_hex, VALID_HEX);
}
