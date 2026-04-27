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
        "expected NotImplemented{{phase:2}}, got {err:?}"
    );
}

#[test]
fn pgp_key_bytes_access_returns_not_implemented_phase_2() {
    // Phase 7 Plan 01: PgpKey is a struct variant carrying bytes. Its native
    // accessor is `as_pgp_key_bytes()`. The cross-accessor path
    // `as_generic_secret_bytes()` still returns NotImplemented{phase:2} via
    // the wildcard arm — exercise that here.
    let err = Material::PgpKey {
        bytes: vec![0x99, 0x0d],
    }
    .as_generic_secret_bytes()
    .unwrap_err();
    assert!(matches!(
        err,
        cipherpost::Error::NotImplemented { phase: 2 }
    ));
}

#[test]
fn ssh_key_generic_secret_accessor_returns_not_implemented_phase_2() {
    // Phase 7 Plan 05: SshKey is a struct variant. Its native accessor is
    // as_ssh_key_bytes(). The cross-accessor as_generic_secret_bytes() still
    // returns NotImplemented{phase:2} via the wildcard arm — exercise that here.
    let m = Material::SshKey {
        bytes: vec![0x6f, 0x70, 0x65, 0x6e],
    };
    let err = m.as_generic_secret_bytes().unwrap_err();
    assert!(
        matches!(err, cipherpost::Error::NotImplemented { phase: 2 }),
        "expected NotImplemented{{phase:2}}, got {err:?}"
    );
}
