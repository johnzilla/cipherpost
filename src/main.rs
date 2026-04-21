//! cipherpost — CLI entry point (plain fn main per SCAF-05, no #[tokio::main]).
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
            IdentityCmd::Generate { passphrase_file: _, passphrase_fd: _, passphrase: _ } => {
                // Plan 02 Task 2 replaces this body with identity::resolve_passphrase +
                // identity::generate. The clap fields are destructured here (even though
                // unused in Phase 1) so the pattern-match compiles against the final
                // variant shape.
                Err(Error::NotImplemented { phase: 1 }.into())
            }
            IdentityCmd::Show { passphrase_file: _, passphrase_fd: _, passphrase: _ } => {
                // Plan 02 Task 2 replaces this body with identity::resolve_passphrase +
                // identity::load + identity::show_fingerprints.
                Err(Error::NotImplemented { phase: 1 }.into())
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
