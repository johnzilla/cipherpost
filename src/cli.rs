//! Full clap command tree (D-11: ships complete in Phase 1).
//! send/receive/receipts handlers are stubs in Phase 1 — their clap wiring is
//! final here and Phase 2/3 only replaces the bodies in src/main.rs.
//!
//! IdentityCmd::Generate and IdentityCmd::Show carry the full passphrase-input
//! field set from Phase 1 Plan 01 onward. The `--passphrase` inline flag is
//! marked hidden and is rejected at runtime by identity::resolve_passphrase
//! (Plan 02) — it exists in the surface ONLY so clap parses it and the runtime
//! rejection path returns exit 4 with a clear error (IDENT-04 / Pitfall #14).

use clap::{Parser, Subcommand};

/// Typed Material variant selector for `cipherpost send --material` (D-P6-01).
///
/// Clap renders kebab-case values (`generic-secret`, `x509-cert`, `pgp-key`, `ssh-key`)
/// for the CLI surface; the wire shape (`generic_secret`, `x509_cert`, ...) is owned by
/// `payload.rs`'s `#[serde(tag = "type", rename_all = "snake_case")]` — no coupling.
///
/// `PgpKey` / `SshKey` parse at clap level for UX polish but dispatch returns
/// `Error::NotImplemented { phase: 7 }`. Accepting them here lets the runtime error
/// be a clean typed message rather than clap's "unknown value for --material".
#[derive(clap::ValueEnum, Debug, Clone, Copy, PartialEq, Eq, Default)]
#[clap(rename_all = "kebab-case")]
pub enum MaterialVariant {
    #[default]
    GenericSecret,
    X509Cert,
    PgpKey,
    SshKey,
}

#[derive(Parser, Debug)]
#[command(
    name = "cipherpost",
    version,
    about = "Self-sovereign, serverless, accountless cryptographic-material handoff.",
    long_about = "Cipherpost transports keys, certs, credentials, and secrets end-to-end \
                  encrypted over Mainline DHT via PKARR. No servers, no accounts."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand, Debug)]
pub enum Command {
    /// Identity management
    Identity {
        #[command(subcommand)]
        cmd: IdentityCmd,
    },

    /// Send a cryptographic-material payload (phase 2)
    #[command(long_about = "Send a payload.\n\nEXAMPLES:\n  \
              cipherpost send --self -p 'backup signing key' --material-file ./key.age\n  \
              cipherpost send --share <z32-pubkey> -p 'onboarding token' -\n  \
              cipherpost send --self -p 'onboarding leaf cert' --material x509-cert --material-file ./leaf.pem\n  \
              CIPHERPOST_PASSPHRASE=hunter2 cipherpost send --self -p 'x' -\n  \
              cipherpost send --self -p 'x' --passphrase-file ./pw.txt -\n  \
              cipherpost send --self -p 'x' --passphrase-fd 3 - 3</tmp/pw")]
    Send {
        /// Encrypt to self (recipient = own identity)
        #[arg(long, conflicts_with = "share")]
        self_: bool,

        /// Encrypt to a recipient's PKARR pubkey (z-base-32 or OpenSSH format)
        #[arg(long, conflicts_with = "self_")]
        share: Option<String>,

        /// Purpose string (signed, sender-attested)
        #[arg(short, long)]
        purpose: Option<String>,

        /// Read payload from PATH or `-` for stdin
        #[arg(long)]
        material_file: Option<String>,

        /// TTL in seconds (default 86400 = 24h)
        #[arg(long)]
        ttl: Option<u64>,

        /// Typed material variant. Default `generic-secret` preserves every Phase 5 script.
        #[arg(long, value_enum, default_value_t = MaterialVariant::GenericSecret)]
        material: MaterialVariant,

        /// Read passphrase from the given file (newline-terminated, file must be mode 0600 or 0400)
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<std::path::PathBuf>,
        /// Read passphrase from the given file descriptor (for scripting)
        #[arg(long, value_name = "N")]
        passphrase_fd: Option<i32>,
        /// REJECTED — inline passphrases leak via argv / /proc/<pid>/cmdline / ps.
        /// Use CIPHERPOST_PASSPHRASE env, --passphrase-file, or --passphrase-fd instead.
        /// This flag exists only so the runtime rejection path returns a clear error (exit 4).
        #[arg(long, value_name = "VALUE", hide = true)]
        passphrase: Option<String>,
        /// Positional `-` means "read payload from stdin" (shorthand for --material-file -).
        /// Any value other than `-` is rejected at dispatch.
        #[arg(value_name = "STDIN")]
        material_stdin: Option<String>,

        /// Require a PIN as a second factor on receive (PIN-01).
        ///
        /// PIN is read from TTY at send time with double-entry confirmation;
        /// receiver is prompted at receive time. PIN-protected shares require
        /// BOTH the receiver's identity passphrase AND the PIN to decrypt.
        ///
        /// Non-interactive PIN sources (--pin-file, --pin-fd, CIPHERPOST_PIN
        /// env) are deferred to v1.2 — v1.1 keeps PIN as an intentionally
        /// human-in-the-loop second factor. Argv-inline `--pin <value>` is
        /// rejected by clap (bool flag).
        #[arg(long)]
        pin: bool,
    },

    /// Receive and decrypt a share (phase 2)
    #[command(long_about = "Receive a share.\n\nEXAMPLES:\n  \
              cipherpost receive <share-uri>\n  \
              cipherpost receive <share-uri> -o ./recovered.key\n  \
              cipherpost receive <share-uri> --armor -o ./leaf.pem\n  \
              CIPHERPOST_PASSPHRASE=hunter2 cipherpost receive <share-uri>\n  \
              cipherpost receive <share-uri> --passphrase-file ./pw.txt\n  \
              cipherpost receive <share-uri> --passphrase-fd 3 3</tmp/pw")]
    Receive {
        /// Share URI or sender z-base-32 pubkey
        share: Option<String>,

        /// Write payload to PATH or `-` for stdout
        #[arg(short, long)]
        output: Option<String>,

        /// Override default DHT resolve timeout (seconds)
        #[arg(long)]
        dht_timeout: Option<u64>,

        /// Emit PEM-armored certificate output (`-----BEGIN CERTIFICATE-----` envelope).
        /// Only valid when the share's Material is `x509_cert`; rejected otherwise.
        #[arg(long)]
        armor: bool,

        /// Read passphrase from the given file (newline-terminated, file must be mode 0600 or 0400)
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<std::path::PathBuf>,
        /// Read passphrase from the given file descriptor (for scripting)
        #[arg(long, value_name = "N")]
        passphrase_fd: Option<i32>,
        /// REJECTED — inline passphrases leak via argv / /proc/<pid>/cmdline / ps.
        /// Use CIPHERPOST_PASSPHRASE env, --passphrase-file, or --passphrase-fd instead.
        /// This flag exists only so the runtime rejection path returns a clear error (exit 4).
        #[arg(long, value_name = "VALUE", hide = true)]
        passphrase: Option<String>,
    },

    /// Fetch signed receipts for shares you sent (phase 3)
    #[command(long_about = "List and verify signed receipts.\n\nEXAMPLES:\n  \
              cipherpost receipts --from <recipient-z32>\n  \
              cipherpost receipts --from <recipient-z32> --share-ref <32-hex>\n  \
              cipherpost receipts --from <recipient-z32> --json")]
    Receipts {
        /// Recipient pubkey (z-base-32) to query
        #[arg(long)]
        from: String,

        /// Filter by share_ref (32-char hex)
        #[arg(long)]
        share_ref: Option<String>,

        /// Emit machine-readable JSON to stdout (status stays on stderr).
        #[arg(long)]
        json: bool,
    },

    /// Print crate version, git commit, and crypto primitives
    #[command(long_about = "Print version and build info.\n\nEXAMPLES:\n  \
              cipherpost version")]
    Version,
}

#[derive(Subcommand, Debug)]
pub enum IdentityCmd {
    /// Generate a new Ed25519/PKARR identity at ~/.cipherpost/secret_key
    #[command(long_about = "Generate identity.\n\nEXAMPLES:\n  \
              cipherpost identity generate\n  \
              CIPHERPOST_PASSPHRASE=hunter2 cipherpost identity generate\n  \
              cipherpost identity generate --passphrase-file ./pw.txt\n  \
              cipherpost identity generate --passphrase-fd 3 3</tmp/pw")]
    Generate {
        /// Read passphrase from the given file (newline-terminated, file must be mode 0600 or 0400)
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<std::path::PathBuf>,
        /// Read passphrase from the given file descriptor (for scripting)
        #[arg(long, value_name = "N")]
        passphrase_fd: Option<i32>,
        /// REJECTED — inline passphrases leak via argv / /proc/<pid>/cmdline / ps.
        /// Use CIPHERPOST_PASSPHRASE env, --passphrase-file, or --passphrase-fd instead.
        /// This flag exists only so the runtime rejection path returns a clear error (exit 4).
        #[arg(long, value_name = "VALUE", hide = true)]
        passphrase: Option<String>,
    },

    /// Show fingerprints (OpenSSH + z-base-32) for the current identity
    #[command(long_about = "Show identity fingerprints.\n\nEXAMPLES:\n  \
              cipherpost identity show\n  \
              CIPHERPOST_PASSPHRASE=hunter2 cipherpost identity show")]
    Show {
        /// Read passphrase from the given file (newline-terminated, file must be mode 0600 or 0400)
        #[arg(long, value_name = "PATH")]
        passphrase_file: Option<std::path::PathBuf>,
        /// Read passphrase from the given file descriptor (for scripting)
        #[arg(long, value_name = "N")]
        passphrase_fd: Option<i32>,
        /// REJECTED — see `identity generate --help` for rationale.
        #[arg(long, value_name = "VALUE", hide = true)]
        passphrase: Option<String>,
    },
}
