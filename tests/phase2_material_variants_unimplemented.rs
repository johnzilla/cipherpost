//! PAYL-02: Material::X509Cert / PgpKey / SshKey variants serialize their type tag
//! but any attempt to access their material bytes returns Error::NotImplemented.

use cipherpost::payload::Material;

#[test]
fn x509_cert_generic_secret_accessor_returns_not_implemented_phase_2() {
    // Phase 6: X509Cert is a struct variant carrying bytes. Its native accessor
    // is `as_x509_cert_bytes()` (Plan 01). The *cross*-accessor path
    // `as_generic_secret_bytes()` still returns NotImplemented{phase:2} via the
    // wildcard arm — exercise that here.
    let m = Material::X509Cert {
        bytes: vec![0x30, 0x82],
    };
    let err = m.as_generic_secret_bytes().unwrap_err();
    assert!(
        matches!(err, cipherpost::Error::NotImplemented { phase: 2 }),
        "expected NotImplemented{{phase:2}}, got {:?}",
        err
    );
}

#[test]
fn pgp_key_bytes_access_returns_not_implemented_phase_2() {
    let err = Material::PgpKey.as_generic_secret_bytes().unwrap_err();
    assert!(matches!(
        err,
        cipherpost::Error::NotImplemented { phase: 2 }
    ));
}

#[test]
fn ssh_key_bytes_access_returns_not_implemented_phase_2() {
    let err = Material::SshKey.as_generic_secret_bytes().unwrap_err();
    assert!(matches!(
        err,
        cipherpost::Error::NotImplemented { phase: 2 }
    ));
}

#[test]
fn non_generic_variants_serialize_their_type_tag() {
    // Phase 6: X509Cert carries bytes, so its serialization is tested in
    // payload::tests::material_x509_cert_serde_round_trip. PgpKey and SshKey
    // remain unit variants with the bare-tag form until Phase 7.
    let s = serde_json::to_string(&Material::PgpKey).unwrap();
    assert_eq!(s, "{\"type\":\"pgp_key\"}");
    let s = serde_json::to_string(&Material::SshKey).unwrap();
    assert_eq!(s, "{\"type\":\"ssh_key\"}");
}
