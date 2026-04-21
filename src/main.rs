//! cipherpost — CLI entry point. Plain fn main per SCAF-05 (no async runtime attribute).
//! D-17: anyhow in binary; thiserror in library. Explicit match-to-exit-code
//! dispatcher prevents D-15 source-chain leakage.

use anyhow::Result;
use clap::Parser;
use cipherpost::cli::{Cli, Command, IdentityCmd};
use cipherpost::error::{exit_code, user_message, Error};

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
            IdentityCmd::Generate { passphrase_file, passphrase_fd, passphrase } => {
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
            IdentityCmd::Show { passphrase_file, passphrase_fd, passphrase } => {
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
        Command::Send { .. } => {
            eprintln!("not implemented yet (phase 2)");
            std::process::exit(1);
        }
        Command::Receive { .. } => {
            eprintln!("not implemented yet (phase 2)");
            std::process::exit(1);
        }
        Command::Receipts { .. } => {
            eprintln!("not implemented yet (phase 3)");
            std::process::exit(1);
        }
        Command::Version => {
            // Plan 02 replaces with real version printer per D-13
            println!("cipherpost {} ({})",
                env!("CARGO_PKG_VERSION"),
                option_env!("CIPHERPOST_GIT_SHA").unwrap_or("unknown"));
            println!("crypto: age, Ed25519, Argon2id, HKDF-SHA256, JCS");
            Ok(())
        }
    }
}
