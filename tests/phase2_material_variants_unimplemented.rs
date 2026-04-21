//! PAYL-02: Material::X509Cert / PgpKey / SshKey variants serialize their type tag
//! but any attempt to access their material bytes returns Error::NotImplemented.

use cipherpost::payload::Material;

#[test]
fn x509_cert_bytes_access_returns_not_implemented_phase_2() {
    let err = Material::X509Cert.as_generic_secret_bytes().unwrap_err();
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
    // Reserved variants still round-trip as JSON shapes — just their material bytes are inaccessible.
    let s = serde_json::to_string(&Material::X509Cert).unwrap();
    assert_eq!(s, "{\"type\":\"x509_cert\"}");
    let s = serde_json::to_string(&Material::PgpKey).unwrap();
    assert_eq!(s, "{\"type\":\"pgp_key\"}");
    let s = serde_json::to_string(&Material::SshKey).unwrap();
    assert_eq!(s, "{\"type\":\"ssh_key\"}");
}
