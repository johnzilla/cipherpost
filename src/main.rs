//! cipherpost — CLI entry point. Plain fn main per SCAF-05 (no async runtime attribute).
//! D-17: anyhow in binary; thiserror in library. Explicit match-to-exit-code
//! dispatcher prevents D-15 source-chain leakage.

use anyhow::Result;
use cipherpost::cli::{Cli, Command, IdentityCmd};
use cipherpost::error::{exit_code, user_message, Error};
use clap::Parser;

fn main() {
    let code = run();
    std::process::exit(code);
}

fn run() -> i32 {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => 0,
        Err(e) => {
            // D-15: print only top-level message. No `{:?}`, no source() walking.
            // Downcast to library Error for exact exit-code taxonomy.
            let code = if let Some(ce) = e.downcast_ref::<Error>() {
                eprintln!("{}", user_message(ce));
                exit_code(ce)
            } else {
                eprintln!("{}", e);
                1
            };
            code
        }
    }
}

fn dispatch(cli: Cli) -> Result<()> {
    match cli.command {
        Command::Identity { cmd } => match cmd {
            IdentityCmd::Generate {
                passphrase_file,
                passphrase_fd,
                passphrase,
            } => {
                // Reject argv-inline passphrase (IDENT-04 / Pitfall #14). The `passphrase`
                // field is `hide = true` in src/cli.rs — exists only so this rejection fires.
                let pw = cipherpost::identity::resolve_passphrase(
                    passphrase.as_deref(),
                    Some("CIPHERPOST_PASSPHRASE"),
                    passphrase_file.as_deref(),
                    passphrase_fd,
                )?;
                let id = cipherpost::identity::generate(pw.as_secret())?;
                let (openssh, z32) = cipherpost::identity::show_fingerprints(&id);
                eprintln!("Generated identity:");
                eprintln!("  {}", openssh);
                eprintln!("  {}", z32);
                Ok(())
            }
            IdentityCmd::Show {
                passphrase_file,
                passphrase_fd,
                passphrase,
            } => {
                let pw = cipherpost::identity::resolve_passphrase(
                    passphrase.as_deref(),
                    Some("CIPHERPOST_PASSPHRASE"),
                    passphrase_file.as_deref(),
                    passphrase_fd,
                )?;
                let id = cipherpost::identity::load(pw.as_secret())?;
                let (openssh, z32) = cipherpost::identity::show_fingerprints(&id);
                println!("{}", openssh);
                println!("{}", z32);
                Ok(())
            }
        },
        Command::Send {
            self_,
            share,
            purpose,
            material_file,
            ttl,
        } => {
            // Phase 2 does not add passphrase flags to Send — pulls from env / TTY only.
            // (cli.rs is locked per Phase 1 D-11; a future plan may add --passphrase-file / --fd.)
            let pw = cipherpost::identity::resolve_passphrase(
                None,
                Some("CIPHERPOST_PASSPHRASE"),
                None,
                None,
            )?;
            let id = cipherpost::identity::load(pw.as_secret())?;

            // Reconstruct the pkarr::Keypair from the identity's signing seed so we can
            // sign the OuterRecord and build the SignedPacket.
            let seed = id.signing_seed();
            let seed_bytes: [u8; 32] = *seed;
            let kp = pkarr::Keypair::from_secret_key(&seed_bytes);

            // Resolve send mode from mutually-exclusive flags.
            let mode = match (self_, share) {
                (true, None) => cipherpost::flow::SendMode::SelfMode,
                (false, Some(z32)) => cipherpost::flow::SendMode::Share { recipient_z32: z32 },
                (true, Some(_)) => {
                    return Err(cipherpost::Error::Config(
                        "--self and --share are mutually exclusive".into(),
                    )
                    .into())
                }
                (false, None) => {
                    return Err(cipherpost::Error::Config(
                        "Send requires either --self or --share <pubkey>".into(),
                    )
                    .into())
                }
            };

            // Material source: --material-file value ('-' = stdin; path = file; absent = error).
            let material_source = match material_file.as_deref() {
                None => {
                    return Err(cipherpost::Error::Config(
                        "--material-file <path> or - required (Phase 2: stdin only, no prompt)"
                            .into(),
                    )
                    .into())
                }
                Some("-") => cipherpost::flow::MaterialSource::Stdin,
                Some(p) => cipherpost::flow::MaterialSource::File(std::path::PathBuf::from(p)),
            };

            let ttl_seconds = ttl.unwrap_or(cipherpost::flow::DEFAULT_TTL_SECONDS);
            let purpose_str = purpose.as_deref().unwrap_or("");

            // Production transport is DhtTransport. Under `--features mock`, the
            // CIPHERPOST_USE_MOCK_TRANSPORT env var switches to the in-process
            // MockTransport so CLI tests can publish and receive without touching
            // the real DHT. Cross-process sharing is NOT supported (MockTransport's
            // HashMap is per-process); see Plan 02-03 SUMMARY for details.
            let transport: Box<dyn cipherpost::transport::Transport> = {
                #[cfg(feature = "mock")]
                {
                    if std::env::var("CIPHERPOST_USE_MOCK_TRANSPORT").is_ok() {
                        Box::new(cipherpost::transport::MockTransport::new())
                    } else {
                        Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
                    }
                }
                #[cfg(not(feature = "mock"))]
                {
                    Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
                }
            };

            let uri = cipherpost::flow::run_send(
                &id,
                transport.as_ref(),
                &kp,
                mode,
                purpose_str,
                material_source,
                ttl_seconds,
            )?;

            println!("{}", uri);
            Ok(())
        }
        Command::Receive {
            share,
            output,
            dht_timeout: _,
        } => {
            // Parse the URI first (cheap, no I/O) so invalid input fails before
            // we ask the user for a passphrase.
            let share_str =
                share.ok_or_else(|| cipherpost::Error::Config("share URI required".into()))?;
            let uri = cipherpost::ShareUri::parse(&share_str)?;

            // D-RECV-02: sentinel-first — BEFORE passphrase resolution.
            if let Some(accepted_at) = cipherpost::flow::check_already_accepted(&uri.share_ref_hex)
            {
                eprintln!("already accepted at {}; not re-decrypting", accepted_at);
                return Ok(());
            }

            let pw = cipherpost::identity::resolve_passphrase(
                None,
                Some("CIPHERPOST_PASSPHRASE"),
                None,
                None,
            )?;
            let id = cipherpost::identity::load(pw.as_secret())?;

            // Reconstruct the pkarr::Keypair from the identity's signing seed so we can
            // sign the Receipt in run_receive step 13 and publish it under this key (D-SEQ-07).
            let seed = id.signing_seed();
            let seed_bytes: [u8; 32] = *seed;
            let kp = pkarr::Keypair::from_secret_key(&seed_bytes);

            let mut sink = match output.as_deref() {
                None | Some("-") => cipherpost::flow::OutputSink::Stdout,
                Some(p) => cipherpost::flow::OutputSink::File(std::path::PathBuf::from(p)),
            };

            let prompter = cipherpost::flow::TtyPrompter::new();

            let transport: Box<dyn cipherpost::transport::Transport> = {
                #[cfg(feature = "mock")]
                {
                    if std::env::var("CIPHERPOST_USE_MOCK_TRANSPORT").is_ok() {
                        Box::new(cipherpost::transport::MockTransport::new())
                    } else {
                        Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
                    }
                }
                #[cfg(not(feature = "mock"))]
                {
                    Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
                }
            };

            cipherpost::flow::run_receive(
                &id,
                transport.as_ref(),
                &kp,
                &uri,
                &mut sink,
                &prompter,
            )?;
            Ok(())
        }
        Command::Receipts {
            from,
            share_ref,
            json,
        } => {
            // D-OUT-04: no passphrase prompt, no Identity load. Receipts listing
            // requires only a public PKARR key for the DHT resolve and the
            // Receipt's own recipient_pubkey for verify.
            let transport: Box<dyn cipherpost::transport::Transport> = {
                #[cfg(feature = "mock")]
                {
                    if std::env::var("CIPHERPOST_USE_MOCK_TRANSPORT").is_ok() {
                        Box::new(cipherpost::transport::MockTransport::new())
                    } else {
                        Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
                    }
                }
                #[cfg(not(feature = "mock"))]
                {
                    Box::new(cipherpost::transport::DhtTransport::with_default_timeout()?)
                }
            };
            cipherpost::flow::run_receipts(transport.as_ref(), &from, share_ref.as_deref(), json)?;
            Ok(())
        }
        Command::Version => {
            // Plan 02 replaces with real version printer per D-13
            println!(
                "cipherpost {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("CIPHERPOST_GIT_SHA").unwrap_or("unknown")
            );
            println!("crypto: age, Ed25519, Argon2id, HKDF-SHA256, JCS");
            Ok(())
        }
    }
}
