//! BlobStore — the v2 large-payload storage seam. Mirrors the
//! `Transport`/`MockTransport` pattern (src/transport.rs): a trait with a
//! production impl (`HomeserverBlobStore`, a later step) and an in-memory
//! `MockBlobStore` (cfg-gated) so integration tests never touch a live homeserver.
//!
//! Feature-gated behind `large-payload` so the DEFAULT build's dependency tree
//! (and every supply-chain guard test) is unchanged.
//!
//! Design invariant: the bytes a BlobStore stores are ALREADY age-ciphertext.
//! The store is a dumb mirror — it never sees plaintext, and cannot forge
//! content because the recipient verifies a hash carried in the signed manifest.

use crate::error::Error;

/// Storage seam for large (off-DHT) payloads.
///
/// The caller stores opaque (already-encrypted) bytes under a logical path
/// within its own space and gets back a `location` string. That location is
/// embedded in the dual-signed, age-encrypted manifest published to the DHT;
/// the recipient later hands the same string to `get`.
pub trait BlobStore {
    /// Store `bytes` at the logical `path` within the caller's own space.
    /// Returns the `location` string to embed in the manifest.
    fn put(&self, path: &str, bytes: &[u8]) -> Result<String, Error>;

    /// Fetch the bytes previously stored at `location` (as returned by `put`).
    /// Returns `Error::NotFound` if the location holds nothing.
    fn get(&self, location: &str) -> Result<Vec<u8>, Error>;
}

// ---- HomeserverBlobStore (production) --------------------------------------

use crate::pubky_auth;
use std::cell::RefCell;
use ureq::tls::{TlsConfig, TlsProvider};
use ureq::Agent;
use zeroize::Zeroizing;

/// Defensive cap on a single blob download. The homeserver enforces a 100 MB
/// per-request ceiling on writes; this guards the read side independently.
const MAX_DOWNLOAD_BYTES: u64 = 128 * 1024 * 1024;

/// Boxed transport-detail error. Collapses to the generic "transport error"
/// Display (oracle hygiene — detail only reachable via `source()`), mirroring
/// `transport.rs::CasConflictFinal`.
#[derive(Debug)]
struct BlobHttpError(String);
impl std::fmt::Display for BlobHttpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}
impl std::error::Error for BlobHttpError {}

fn transport(msg: impl Into<String>) -> Error {
    Error::Transport(Box::new(BlobHttpError(msg.into())))
}
fn transport_box(e: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Transport(Box::new(e))
}

/// Production `BlobStore` backed by a pubky homeserver over blocking HTTPS
/// (`ureq` + OS-native TLS). Holds the cipherpost identity keypair to mint pubky
/// `AuthToken`s, and caches the resulting session cookie for its lifetime.
///
/// No `#[derive(Debug)]` — this struct owns a secret keypair AND the session
/// cookie (a bearer credential, held in a `Zeroizing` buffer so it is wiped on drop).
pub struct HomeserverBlobStore {
    agent: Agent,
    base_url: String,
    keypair: pkarr::Keypair,
    z32: String,
    session_cookie: RefCell<Option<Zeroizing<String>>>,
}

impl HomeserverBlobStore {
    /// Target `base_url` (e.g. "https://hs.trustedgelabs.com"), authenticating as
    /// `keypair`. The native-TLS provider is selected EXPLICITLY: ureq defaults to
    /// rustls, which we do not compile (no ring/aws-lc), so the default would
    /// fail at runtime.
    ///
    /// Rejects a non-`https` `base_url` (the AuthToken and session cookie are
    /// bearer credentials — they must never traverse cleartext HTTP). `http://`
    /// is allowed only for loopback hosts, for a local `pubky-testnet`.
    pub fn new(base_url: impl Into<String>, keypair: pkarr::Keypair) -> Result<Self, Error> {
        let base_url = base_url.into().trim_end_matches('/').to_string();
        let is_https = base_url.starts_with("https://");
        let is_loopback_http = base_url.starts_with("http://127.0.0.1")
            || base_url.starts_with("http://localhost")
            || base_url.starts_with("http://[::1]");
        if !is_https && !is_loopback_http {
            return Err(Error::Config(format!(
                "CIPHERPOST_HS must be an https:// URL (http:// is allowed only for \
                 localhost); refusing to send credentials in cleartext to: {base_url}"
            )));
        }
        let tls = TlsConfig::builder()
            .provider(TlsProvider::NativeTls)
            .build();
        let config = Agent::config_builder()
            .tls_config(tls)
            .http_status_as_error(false) // inspect 4xx/5xx ourselves
            .build();
        let z32 = keypair.public_key().to_z32();
        Ok(Self {
            agent: config.into(),
            base_url,
            keypair,
            z32,
            session_cookie: RefCell::new(None),
        })
    }

    /// POST a fresh `AuthToken` to `/signup` or `/signin`. Returns `Some(cookie)`
    /// on 2xx, `None` on 409 (user already exists → caller retries the other
    /// endpoint), `Err` otherwise. A fresh token (new timestamp) is minted each
    /// call so the homeserver's replay guard never rejects the fallback.
    fn auth_request(&self, endpoint: &str) -> Result<Option<Zeroizing<String>>, Error> {
        let token = pubky_auth::build_auth_token(
            &self.keypair,
            pubky_auth::CAP_BLOB,
            pubky_auth::now_micros()?,
        );
        let url = format!("{}/{}", self.base_url, endpoint);
        let resp = self
            .agent
            .post(&url)
            .send(&token[..])
            .map_err(transport_box)?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            // The homeserver names our session cookie after our own z32 pubkey:
            // `<z32>=<session_secret>; Path=/; …`. We SELECT that pair (not
            // authenticate it — the cookie is an opaque bearer credential we only
            // ever send back to this same homeserver), bounding its size and
            // rejecting control chars defensively.
            for hv in resp.headers().get_all("set-cookie") {
                if let Ok(s) = hv.to_str() {
                    let pair = s.split(';').next().unwrap_or("").trim();
                    if pair.starts_with(&self.z32)
                        && pair.contains('=')
                        && pair.len() <= 4096
                        && !pair.chars().any(|c| c.is_control())
                    {
                        return Ok(Some(Zeroizing::new(pair.to_string())));
                    }
                }
            }
            Err(transport(format!(
                "{endpoint}: 2xx but no usable session cookie"
            )))
        } else if status == 409 {
            Ok(None)
        } else {
            Err(transport(format!("auth {endpoint}: HTTP {status}")))
        }
    }

    /// Establish (once) a session cookie: try `signup`, fall back to `signin` if
    /// the account already exists. NOTE: signup/signin outcome is entirely
    /// server-attested — a 409 (→ fall back to /session) carries no client-side
    /// guarantee about account state; see THREAT-MODEL §10.
    fn ensure_session(&self) -> Result<(), Error> {
        if self.session_cookie.borrow().is_some() {
            return Ok(());
        }
        // The signin handler is mounted at POST /session (NOT /signin); /signup
        // creates the user. Try signup first; on 409 (exists) fall back to /session.
        let cookie = match self.auth_request("signup")? {
            Some(c) => c,
            None => self
                .auth_request("session")?
                .ok_or_else(|| transport("signin returned no session cookie"))?,
        };
        *self.session_cookie.borrow_mut() = Some(cookie);
        Ok(())
    }

    fn cookie(&self) -> Result<Zeroizing<String>, Error> {
        self.session_cookie
            .borrow()
            .clone()
            .ok_or_else(|| transport("no session cookie"))
    }
}

impl BlobStore for HomeserverBlobStore {
    fn put(&self, path: &str, bytes: &[u8]) -> Result<String, Error> {
        self.ensure_session()?;
        let rel = path.trim_start_matches('/').to_string();
        let url = format!("{}/{}", self.base_url, rel);
        let cookie = self.cookie()?;
        let resp = self
            .agent
            .put(&url)
            .header("pubky-host", &self.z32)
            .header("Cookie", cookie.as_str())
            .send(bytes)
            .map_err(transport_box)?;
        let status = resp.status().as_u16();
        if (200..300).contains(&status) {
            // Return the relative path (location), not the full URL — the
            // receiver prepends its own homeserver base. Keeps the manifest small.
            Ok(rel)
        } else {
            Err(transport(format!("PUT {url}: HTTP {status}")))
        }
    }

    fn get(&self, location: &str) -> Result<Vec<u8>, Error> {
        // Reads under /pub/ are ANONYMOUS on the homeserver (authz.rs allows
        // GET /pub/* with no session) — only the tenant `pubky-host` header is
        // needed. No signup/signin, so a fresh receiver process never touches
        // the auth path just to download.
        let url = format!("{}/{}", self.base_url, location.trim_start_matches('/'));
        let mut resp = self
            .agent
            .get(&url)
            .header("pubky-host", &self.z32)
            .call()
            .map_err(transport_box)?;
        match resp.status().as_u16() {
            200 => resp
                .body_mut()
                .with_config()
                .limit(MAX_DOWNLOAD_BYTES)
                .read_to_vec()
                .map_err(transport_box),
            404 => Err(Error::NotFound),
            s => Err(transport(format!("GET {location}: HTTP {s}"))),
        }
    }
}

// ---- MockBlobStore (cfg-gated) ---------------------------------------------

#[cfg(any(test, feature = "mock"))]
pub use mock::MockBlobStore;

#[cfg(any(test, feature = "mock"))]
mod mock {
    use super::*;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    /// In-memory `BlobStore` for tests. Like `MockTransport`, it is `Clone` and
    /// shares ONE backing map across clones, so a "sender" instance and a
    /// "receiver" instance round-trip through the same storage.
    #[derive(Clone, Default)]
    pub struct MockBlobStore {
        store: Arc<Mutex<HashMap<String, Vec<u8>>>>,
    }

    impl MockBlobStore {
        pub fn new() -> Self {
            Self::default()
        }

        /// Number of distinct blobs stored (test introspection).
        pub fn len(&self) -> usize {
            self.store.lock().unwrap().len()
        }

        pub fn is_empty(&self) -> bool {
            self.store.lock().unwrap().is_empty()
        }

        /// Test-only: overwrite every stored blob with `new_bytes`, simulating a
        /// homeserver that serves corrupted/wrong bytes (drives the hash-mismatch path).
        pub fn corrupt_all_for_test(&self, new_bytes: &[u8]) {
            let mut store = self.store.lock().unwrap();
            for v in store.values_mut() {
                *v = new_bytes.to_vec();
            }
        }
    }

    impl BlobStore for MockBlobStore {
        fn put(&self, path: &str, bytes: &[u8]) -> Result<String, Error> {
            // Key by the normalized relative path so a `get` of the same
            // content-addressed path round-trips (mirrors HomeserverBlobStore).
            let key = path.trim_start_matches('/').to_string();
            self.store
                .lock()
                .unwrap()
                .insert(key.clone(), bytes.to_vec());
            Ok(key)
        }

        fn get(&self, location: &str) -> Result<Vec<u8>, Error> {
            self.store
                .lock()
                .unwrap()
                .get(location.trim_start_matches('/'))
                .cloned()
                .ok_or(Error::NotFound)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_rejects_cleartext_http_allows_https_and_loopback() {
        let kp = || pkarr::Keypair::from_secret_key(&[3u8; 32]);
        assert!(
            HomeserverBlobStore::new("http://evil.example.com", kp()).is_err(),
            "non-loopback http:// must be refused (cleartext credentials)"
        );
        assert!(HomeserverBlobStore::new("https://hs.example.com", kp()).is_ok());
        // loopback http allowed for a local pubky-testnet
        assert!(HomeserverBlobStore::new("http://127.0.0.1:6286", kp()).is_ok());
        assert!(HomeserverBlobStore::new("http://localhost:6286", kp()).is_ok());
    }

    #[test]
    fn mock_put_get_round_trip() {
        let s = MockBlobStore::new();
        let loc = s.put("cipherpost/abc123", b"age-ciphertext-bytes").unwrap();
        assert_eq!(s.get(&loc).unwrap(), b"age-ciphertext-bytes");
    }

    #[test]
    fn mock_get_missing_is_not_found() {
        let s = MockBlobStore::new();
        assert!(matches!(
            s.get("mock:///nope").unwrap_err(),
            Error::NotFound
        ));
    }

    #[test]
    fn mock_clone_shares_backing_store() {
        // Mirrors the send→receive split: a sender stores, a (cloned) receiver fetches.
        let sender = MockBlobStore::new();
        let receiver = sender.clone();
        let loc = sender.put("cipherpost/deadbeef", b"data").unwrap();
        assert_eq!(receiver.get(&loc).unwrap(), b"data");
        assert_eq!(sender.len(), 1);
    }
}
