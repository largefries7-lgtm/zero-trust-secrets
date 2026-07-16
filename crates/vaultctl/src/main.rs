//! `vaultctl` — a thin, STATELESS CLI over `vaultcore`.
//!
//! Design invariant (differs from the plan's original session-token idea): this
//! CLI never persists the DEK, or any unwrapping of it, to disk. Every command
//! that needs the DEK obtains it fresh (TPM unseal for hardware-bound vaults, or
//! the recovery passphrase otherwise) and drops it — zeroized — before exit.
//! There is no on-disk session, so `lock` is a no-op for symmetry.

mod clip;
mod prompt;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use vaultcore::secret::SecretString;
use vaultcore::vault::{LockedVault, Vault};
use vaultcore::Error;

#[cfg(windows)]
use vaultcore::keyprovider::CngPcpProvider;

#[derive(Parser)]
#[command(
    name = "vaultctl",
    about = "Zero-Trust Secrets Manager CLI (stateless; never persists the DEK)"
)]
struct Cli {
    /// Path to the vault file.
    #[arg(long, global = true, default_value = "vault.ztsv")]
    vault: PathBuf,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create a new vault (refuses to clobber an existing file).
    Init {
        /// Skip TPM hardware binding; protect the vault by the passphrase only.
        #[arg(long)]
        allow_no_tpm: bool,
        /// Unlock passphrase: the second factor (combined with the TPM), or the
        /// sole factor with --allow-no-tpm. Prompted (no echo) if omitted.
        #[arg(long)]
        passphrase: Option<String>,
        /// Also create a single-factor recovery escrow. Survives TPM loss, but
        /// reduces a STOLEN vault's security to the recovery passphrase's strength.
        #[arg(long)]
        recovery: bool,
        /// Recovery passphrase (requires --recovery). Prompted if omitted.
        #[arg(long, requires = "recovery")]
        recovery_passphrase: Option<String>,
    },
    /// Stateless credential smoke-check: derive the DEK, verify the MAC, drop it.
    Unlock {
        /// Unlock passphrase. Prompted if omitted.
        #[arg(long)]
        passphrase: Option<String>,
        /// Unlock via the recovery escrow (single factor) instead of TPM+passphrase.
        #[arg(long)]
        recovery: bool,
        #[arg(long, requires = "recovery")]
        recovery_passphrase: Option<String>,
    },
    /// No-op (nothing is persisted); prints `locked` for CLI symmetry.
    Lock,
    /// Add a secret record (fails if the name exists; use --force to replace).
    Add {
        /// Record name.
        name: String,
        /// Secret value. Prompted (no echo) if omitted.
        #[arg(long)]
        value: Option<String>,
        /// Replace the value in place if the name already exists (rotation),
        /// instead of failing. Without it, adding an existing name is refused so
        /// a secret is never silently shadowed.
        #[arg(long)]
        force: bool,
        /// Unlock passphrase. Prompted if omitted.
        #[arg(long)]
        passphrase: Option<String>,
        /// Unlock via the recovery escrow instead of TPM+passphrase.
        #[arg(long)]
        recovery: bool,
        #[arg(long, requires = "recovery")]
        recovery_passphrase: Option<String>,
    },
    /// Remove a secret record.
    Rm {
        /// Record name to remove.
        name: String,
        /// Unlock passphrase. Prompted if omitted.
        #[arg(long)]
        passphrase: Option<String>,
        /// Unlock via the recovery escrow instead of TPM+passphrase.
        #[arg(long)]
        recovery: bool,
        #[arg(long, requires = "recovery")]
        recovery_passphrase: Option<String>,
    },
    /// Retrieve a secret; prints to stdout, or copies to the clipboard with --clip.
    Get {
        name: String,
        /// Copy to clipboard (auto-clears in 15s) instead of printing.
        #[arg(long)]
        clip: bool,
        /// Unlock passphrase. Prompted if omitted.
        #[arg(long)]
        passphrase: Option<String>,
        /// Unlock via the recovery escrow instead of TPM+passphrase.
        #[arg(long)]
        recovery: bool,
        #[arg(long, requires = "recovery")]
        recovery_passphrase: Option<String>,
    },
    /// List record names (no DEK needed).
    List,
    /// Generate a random password (standalone; no vault).
    Gen {
        /// Password length.
        #[arg(long, default_value_t = 20)]
        len: usize,
        /// Include symbols in the character set.
        #[arg(long)]
        symbols: bool,
    },
    /// Report hardware-binding status of the vault (no DEK needed).
    SealStatus,
    /// Delete the persisted TPM wrapping key (DESTRUCTIVE — see confirmation).
    Deprovision {
        /// Skip the interactive confirmation prompt.
        #[arg(long)]
        yes: bool,
    },

    // --- Verification-harness-only subcommands (feature-gated) ---------------
    // These are compiled ONLY under `--features leaktest`; a normal production
    // build does not contain them. Each freezes the process in a precise state,
    // prints `READY` to stdout, and blocks reading stdin so the memory-scraping
    // harness (verify/dumper) can dump the process deterministically.
    /// [leaktest] Load the still-locked vault (no DEK), print READY, then block.
    #[cfg(feature = "leaktest")]
    #[command(name = "__hold-locked")]
    HoldLocked,
    /// [leaktest] Get a secret, copy it to the clipboard, drop+zeroize it, then
    /// (only after zeroization) print READY and block. Models "just after copy".
    #[cfg(feature = "leaktest")]
    #[command(name = "__hold-postclip")]
    HoldPostclip {
        /// Record name to fetch and copy.
        name: String,
        #[arg(long)]
        passphrase: String,
    },
    /// [leaktest] Positive control: keep `<canary>` in a plain, never-zeroized
    /// String alive across the dump, print READY, then block. Proves the
    /// scanner actually finds the canary when it IS present.
    #[cfg(feature = "leaktest")]
    #[command(name = "__leak")]
    Leak {
        /// Canary string to hold in plaintext.
        canary: String,
    },
}

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            // Errors go to stderr; vaultcore errors carry no secret material.
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let path = cli.vault.as_path();

    match cli.cmd {
        Cmd::Init { allow_no_tpm, passphrase, recovery, recovery_passphrase } => {
            let pass = resolve_new_passphrase("unlock passphrase", passphrase)?;
            let recovery_pw = if recovery {
                Some(resolve_new_passphrase("recovery passphrase", recovery_passphrase)?)
            } else {
                None
            };
            cmd_init(path, allow_no_tpm, pass, recovery_pw)?;
        }
        Cmd::Unlock { passphrase, recovery, recovery_passphrase } => {
            let locked = LockedVault::load(path)?;
            // unlock_* verify the header MAC and fail closed.
            let _vault = unlock_vault(locked, passphrase, recovery, recovery_passphrase)?;
            println!("unlock OK");
        }
        Cmd::Lock => {
            // Stateless: there is no on-disk session to clear.
            println!("locked");
        }
        Cmd::Add { name, value, force, passphrase, recovery, recovery_passphrase } => {
            let locked = LockedVault::load(path)?;
            let mut vault = unlock_vault(locked, passphrase, recovery, recovery_passphrase)?;
            let value = match value {
                Some(v) => {
                    eprintln!("warning: passing --value on the command line exposes it via the process list; prefer interactive entry");
                    v
                }
                None => prompt::read_secret_noecho("value: ")?,
            };
            let secret = SecretString::from_string(value);
            if force {
                vault.upsert(&name, secret)?;
            } else {
                // Fails closed with Error::Duplicate if the name exists, so a
                // second `add` can never silently shadow an existing secret.
                vault.add(&name, secret)?;
            }
            vault.save(path)?;
            println!("{} {name}", if force { "set" } else { "added" });
        }
        Cmd::Rm { name, passphrase, recovery, recovery_passphrase } => {
            let locked = LockedVault::load(path)?;
            let mut vault = unlock_vault(locked, passphrase, recovery, recovery_passphrase)?;
            if vault.remove(&name) {
                vault.save(path)?;
                println!("removed {name}");
            } else {
                return Err(Box::new(Error::NotFound(name)));
            }
        }
        Cmd::Get { name, clip, passphrase, recovery, recovery_passphrase } => {
            let locked = LockedVault::load(path)?;
            let vault = unlock_vault(locked, passphrase, recovery, recovery_passphrase)?;
            let secret = vault.get(&name)?;
            if clip {
                clip::copy_with_autoclear(secret.expose_str(), 15)?;
                eprintln!("copied to clipboard (clears in 15s)");
            } else {
                println!("{}", secret.expose_str());
            }
            // secret drops (zeroized) at scope end.
        }
        Cmd::List => {
            let locked = LockedVault::load(path)?;
            for name in locked.record_names() {
                println!("{name}");
            }
            // `list` reads names without the DEK, so the header MAC cannot be
            // checked here: the names shown are unauthenticated until an unlock
            // (get/unlock) verifies the MAC. Flag that on stderr so stdout stays
            // pipe-clean but the trust boundary is never silently elided.
            eprintln!(
                "note: names are unauthenticated metadata read without unlocking; \
                 tampering is detected only at unlock (get/unlock)"
            );
        }
        Cmd::Gen { len, symbols } => {
            let (secret, charset_size) = vaultcore::passgen::generate_password(len, symbols);
            let bits = (len as f64) * (charset_size as f64).log2();
            println!("{}", secret.expose_str());
            eprintln!("~{bits:.0} bits of entropy");
        }
        Cmd::Deprovision { yes } => {
            cmd_deprovision(yes)?;
        }
        Cmd::SealStatus => {
            let locked = LockedVault::load(path)?;
            let header = locked.header();
            println!("format_version: {}", header.format_version);
            println!("hardware_bound: {}", header.hardware_bound);
            println!(
                "factors: {}",
                if header.hardware_bound {
                    "TPM + passphrase (two-factor)"
                } else {
                    "passphrase only"
                }
            );
            println!("recovery_escrow: {}", header.recovery_wrap.is_some());
            println!("provider: {}", vaultcore::flow::describe_provider(header));
            println!("pcr_selection: {:?}", header.pcr_selection);
            if !header.hardware_bound {
                println!(
                    "warning: hardware binding is OFF; vault is protected by the passphrase only"
                );
            }
            if header.recovery_wrap.is_some() {
                println!(
                    "warning: recovery escrow is enabled; a stolen vault is only as strong as the recovery passphrase"
                );
            }
            // These fields are read straight from the header without the DEK, so
            // the header MAC is not verified here: on a tampered file they can be
            // misleading. Any real unlock still fails closed on tamper.
            eprintln!(
                "note: the fields above are read without unlocking and are not \
                 authenticated until unlock; a real unlock still fails closed on tamper"
            );
        }

        // --- Verification-harness-only subcommands (feature-gated) -----------
        #[cfg(feature = "leaktest")]
        Cmd::HoldLocked => {
            // Locked state: parse the header + (still-encrypted) records only.
            // No DEK is obtained, so no plaintext secret exists in this heap;
            // only ciphertext does. The canary MUST NOT be findable.
            let _locked = LockedVault::load(path)?;
            hold_until_stdin_eof()?;
            // _locked drops here (after the dump), carrying only ciphertext.
        }
        #[cfg(feature = "leaktest")]
        Cmd::HoldPostclip { name, passphrase } => {
            // Perform the whole unlock+get+clip inside an inner scope so the
            // `SecretString`, the DEK, the passphrase, and the TPM secret all run
            // their zeroizing `Drop` BEFORE we print READY. After this block the
            // process heap must be clean: the plaintext lives on only in the OS
            // clipboard (a separate process, out of scope for this assertion).
            {
                let locked = LockedVault::load(path)?;
                let vault = unlock_vault(locked, Some(passphrase), false, None)?;
                let secret = vault.get(&name)?;
                clip::copy_with_autoclear(secret.expose_str(), 15)?;
            }
            hold_until_stdin_eof()?;
        }
        #[cfg(feature = "leaktest")]
        Cmd::Leak { canary } => {
            // Positive control: keep the canary in a plain String that is NEVER
            // zeroized and stays alive across the dump. black_box prevents the
            // optimizer from eliding the live buffer. This MUST be findable.
            let held = std::hint::black_box(canary);
            hold_until_stdin_eof()?;
            // Force `held` to remain live across the blocking dump window.
            std::hint::black_box(&held);
        }
    }
    Ok(())
}

/// Verification-harness helper: signal readiness on stdout (so the dumper knows
/// the process is in the target state), then block until the harness closes our
/// stdin (EOF) to let the process exit. Not present in production builds.
#[cfg(feature = "leaktest")]
fn hold_until_stdin_eof() -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(b"READY\n")?;
    out.flush()?;
    // Blocks until a line arrives or stdin reaches EOF (harness drops the pipe).
    let mut line = String::new();
    let _ = std::io::stdin().read_line(&mut line)?;
    Ok(())
}

/// Create a new v2 (two-factor) vault. Refuses to overwrite an existing file.
///
/// Default: DEK wrapped under `HKDF(tpm_secret ‖ Argon2id(passphrase))` — both
/// the TPM and the passphrase are required to unlock. `--allow-no-tpm` drops the
/// TPM factor (passphrase-only). `recovery = Some` adds an optional single-factor
/// escrow that survives TPM loss but weakens theft resistance.
fn cmd_init(
    path: &std::path::Path,
    allow_no_tpm: bool,
    passphrase: String,
    recovery: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    use vaultcore::flow::{create_vault, CreateOptions, TpmBinding};

    let outcome = create_vault(
        path,
        CreateOptions {
            allow_no_tpm,
            passphrase: SecretString::from_string(passphrase),
            recovery_passphrase: recovery.map(SecretString::from_string),
        },
    )?;

    match &outcome.tpm {
        TpmBinding::Unavailable(msg) => {
            eprintln!("warning: TPM unavailable ({msg}); using passphrase-only protection")
        }
        TpmBinding::SealFailed(msg) => {
            eprintln!("warning: TPM seal failed ({msg}); using passphrase-only protection")
        }
        TpmBinding::Bound | TpmBinding::OptedOut => {}
    }

    if !outcome.hardware_bound {
        eprintln!("******************************************************************");
        eprintln!("** WARNING: HARDWARE BINDING IS OFF                             **");
        eprintln!("** This vault is protected by the PASSPHRASE ONLY (single       **");
        eprintln!("** factor). Anyone with the file and the passphrase can decrypt **");
        eprintln!("** it on any machine.                                           **");
        eprintln!("******************************************************************");
    } else if !outcome.has_recovery {
        eprintln!("NOTE: two-factor (TPM + passphrase), no recovery escrow. If the TPM is");
        eprintln!("reset/lost (or you run `deprovision`), this vault CANNOT be recovered.");
        eprintln!("Re-init with --recovery to add a passphrase-only escrow (weaker vs. theft).");
    }
    if outcome.has_recovery {
        eprintln!("WARNING: recovery escrow enabled. A STOLEN vault is only as strong as the");
        eprintln!("recovery passphrase (it bypasses the TPM second factor by design).");
    }

    let factors = if outcome.hardware_bound {
        "TPM + passphrase"
    } else {
        "passphrase only"
    };
    println!("initialized vault at {} (factors: {factors})", path.display());
    Ok(())
}

/// Delete the persisted TPM wrapping key. Destructive: requires typed
/// confirmation (or `--yes`), because it renders every TPM-bound vault on this
/// machine undecryptable via the TPM (a vault's recovery passphrase still works).
fn cmd_deprovision(yes: bool) -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(windows)]
    {
        if !yes {
            eprintln!("WARNING: this deletes the machine's TPM wrapping key.");
            eprintln!("Every TPM-bound vault becomes undecryptable via the TPM afterward");
            eprintln!("(a vault's recovery passphrase, if set, still works).");
            eprint!("Type DELETE to confirm: ");
            std::io::stderr().flush()?;
            let mut line = String::new();
            std::io::stdin().read_line(&mut line)?;
            if line.trim() != "DELETE" {
                println!("aborted");
                return Ok(());
            }
        }
        match CngPcpProvider::deprovision()? {
            true => println!("TPM wrapping key deleted"),
            false => println!("no TPM wrapping key present (nothing to delete)"),
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        let _ = yes;
        println!("no TPM provider on this platform (nothing to deprovision)");
        Ok(())
    }
}

/// Obtain the DEK without persisting it. TPM unseal for hardware-bound vaults,
/// otherwise unwrap via the recovery passphrase. Returns an owned, page-locked,
/// zeroize-on-drop `SecretBytes`.
/// Unlock a loaded vault. Default path is two-factor: for a hardware-bound vault
/// the TPM secret is unsealed (silently) AND the unlock passphrase is required;
/// for a `--allow-no-tpm` vault the passphrase is the sole factor. With
/// `recovery`, the single-factor recovery escrow is used instead. All paths
/// verify the header MAC and fail closed.
///
/// Passphrases are moved straight into zeroize-on-drop `SecretString`s (scrubbing
/// the clap-owned copies); the TPM secret is a page-locked `SecretBytes` that
/// drops before this returns.
fn unlock_vault(
    locked: LockedVault,
    passphrase: Option<String>,
    recovery: bool,
    recovery_passphrase: Option<String>,
) -> Result<Vault, Box<dyn std::error::Error>> {
    if recovery {
        let pw = resolve_unlock_pw("recovery passphrase", recovery_passphrase)?;
        return Ok(locked.unlock_recovery(&pw)?);
    }
    // Acquire the TPM factor FIRST so a hardware-bound vault with an
    // unavailable TPM fails fast, before ever prompting for a passphrase
    // that would never be used.
    let tpm_secret = vaultcore::flow::obtain_tpm_secret(&locked)?;
    let pw = resolve_unlock_pw("unlock passphrase", passphrase)?;
    Ok(locked.unlock_two_factor(&pw, tpm_secret.as_ref())?)
}

/// Resolve a NEW passphrase for `init` (labelled "unlock passphrase" or
/// "recovery passphrase"). If supplied on argv, warn and use it; otherwise
/// prompt twice (no echo) and require the entries to match. Rejects empty.
fn resolve_new_passphrase(
    label: &str,
    provided: Option<String>,
) -> Result<String, Box<dyn std::error::Error>> {
    if let Some(v) = provided {
        eprintln!("warning: passing a passphrase on the command line exposes it via the process list; prefer the interactive prompt");
        if v.is_empty() {
            return Err(format!("{label} must not be empty").into());
        }
        return Ok(v);
    }
    let pw = prompt::read_secret_noecho(&format!("new {label}: "))?;
    if pw.is_empty() {
        return Err(format!("{label} must not be empty").into());
    }
    let confirm = prompt::read_secret_noecho(&format!("confirm {label}: "))?;
    if pw != confirm {
        return Err("passphrases did not match".into());
    }
    Ok(pw)
}

/// Resolve an existing passphrase for an unlock-path command. If supplied on
/// argv, warn and use it; otherwise prompt once without echo. The result moves
/// into a zeroize-on-drop `SecretString`.
fn resolve_unlock_pw(label: &str, provided: Option<String>) -> std::io::Result<SecretString> {
    if let Some(v) = provided {
        eprintln!("warning: passing a passphrase on the command line exposes it via the process list; prefer interactive entry");
        return Ok(SecretString::from_string(v));
    }
    let pw = prompt::read_secret_noecho(&format!("{label}: "))?;
    Ok(SecretString::from_string(pw))
}
