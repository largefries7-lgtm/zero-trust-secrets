//! `vaultctl` — a thin, STATELESS CLI over `vaultcore`.
//!
//! Design invariant (differs from the plan's original session-token idea): this
//! CLI never persists the DEK, or any unwrapping of it, to disk. Every command
//! that needs the DEK obtains it fresh (TPM unseal for hardware-bound vaults, or
//! the recovery passphrase otherwise) and drops it — zeroized — before exit.
//! There is no on-disk session, so `lock` is a no-op for symmetry.

mod clip;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use vaultcore::crypto::Argon2Params;
use vaultcore::keyprovider::{KeyProvider, RecoveryProvider, SealedBlob};
use vaultcore::secret::{SecretBytes, SecretString};
use vaultcore::vault::{LockedVault, Vault, VaultHeader};
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
        /// Skip TPM hardware binding; protect the vault by recovery passphrase only.
        #[arg(long)]
        allow_no_tpm: bool,
        /// Recovery passphrase used to escrow the DEK (Argon2id).
        #[arg(long)]
        recovery_passphrase: String,
    },
    /// Stateless credential smoke-check: obtain the DEK, verify the MAC, drop it.
    Unlock {
        #[arg(long)]
        recovery_passphrase: Option<String>,
    },
    /// No-op (nothing is persisted); prints `locked` for CLI symmetry.
    Lock,
    /// Add or append a secret record.
    Add {
        /// Record name.
        name: String,
        /// Secret value. If omitted, read from stdin (see notes).
        #[arg(long)]
        value: Option<String>,
        #[arg(long)]
        recovery_passphrase: Option<String>,
    },
    /// Retrieve a secret; prints to stdout, or copies to the clipboard with --clip.
    Get {
        name: String,
        /// Copy to clipboard (auto-clears in 15s) instead of printing.
        #[arg(long)]
        clip: bool,
        #[arg(long)]
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
        recovery_passphrase: String,
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
        Cmd::Init { allow_no_tpm, recovery_passphrase } => {
            cmd_init(path, allow_no_tpm, recovery_passphrase)?;
        }
        Cmd::Unlock { recovery_passphrase } => {
            let locked = LockedVault::load(path)?;
            let dek = obtain_dek(
                locked.header(),
                recovery_passphrase.map(SecretString::from_string),
            )?;
            // unlock_with_dek verifies the header MAC and fails closed.
            let _vault = locked.unlock_with_dek(dek)?;
            println!("unlock OK");
        }
        Cmd::Lock => {
            // Stateless: there is no on-disk session to clear.
            println!("locked");
        }
        Cmd::Add { name, value, recovery_passphrase } => {
            let locked = LockedVault::load(path)?;
            let dek = obtain_dek(
                locked.header(),
                recovery_passphrase.map(SecretString::from_string),
            )?;
            let mut vault = locked.unlock_with_dek(dek)?;
            let value = match value {
                Some(v) => v,
                None => read_secret_line("value: ")?,
            };
            vault.add(&name, SecretString::from_string(value))?;
            vault.save(path)?;
            println!("added {name}");
        }
        Cmd::Get { name, clip, recovery_passphrase } => {
            let locked = LockedVault::load(path)?;
            let dek = obtain_dek(
                locked.header(),
                recovery_passphrase.map(SecretString::from_string),
            )?;
            let vault = locked.unlock_with_dek(dek)?;
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
        }
        Cmd::Gen { len, symbols } => {
            let (password, charset_size) = gen_password(len, symbols);
            let bits = (len as f64) * (charset_size as f64).log2();
            // Wrap so the buffer zeroizes; print via expose_str().
            let secret = SecretString::from_string(password);
            println!("{}", secret.expose_str());
            eprintln!("~{bits:.0} bits of entropy");
        }
        Cmd::SealStatus => {
            let locked = LockedVault::load(path)?;
            let header = locked.header();
            println!("hardware_bound: {}", header.hardware_bound);
            println!("provider: {}", active_provider_describe(header));
            println!("pcr_selection: {:?}", header.pcr_selection);
            if !header.hardware_bound {
                println!(
                    "warning: hardware binding is OFF; vault is protected by the recovery passphrase only"
                );
            }
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
        Cmd::HoldPostclip { name, recovery_passphrase } => {
            // Perform the whole get+clip inside an inner scope so the
            // `SecretString` and the DEK (inside `Vault`) run their zeroizing
            // `Drop` BEFORE we print READY. After this block the process heap
            // must be clean: the plaintext lives on only in the OS clipboard
            // (a separate process, out of scope for this assertion).
            {
                let locked = LockedVault::load(path)?;
                let dek = obtain_dek(
                    locked.header(),
                    Some(SecretString::from_string(recovery_passphrase)),
                )?;
                let vault = locked.unlock_with_dek(dek)?;
                let secret = vault.get(&name)?;
                clip::copy_with_autoclear(secret.expose_str(), 15)?;
                // secret (SecretString) and vault (owning the DEK SecretBytes)
                // both drop here -> zeroized -> heap clean before READY.
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

/// Create a new vault. Refuses to overwrite an existing file.
fn cmd_init(
    path: &std::path::Path,
    allow_no_tpm: bool,
    recovery_passphrase: String,
) -> Result<(), Box<dyn std::error::Error>> {
    if path.exists() {
        return Err(Box::new(Error::Provider(format!(
            "vault already exists at {}; refusing to overwrite",
            path.display()
        ))));
    }

    let dek = SecretBytes::generate(32);
    let params = Argon2Params::default_tuned();

    // Recovery escrow (always present).
    let recovery_wrap = RecoveryProvider::new(
        SecretString::from_string(recovery_passphrase),
        params,
    )
    .seal(&dek, &[])?
    .0;

    // TPM hardware binding (best effort unless opted out).
    let mut tpm_wrap: Option<Vec<u8>> = None;
    let mut hardware_bound = false;
    if !allow_no_tpm {
        #[cfg(windows)]
        {
            match CngPcpProvider::open() {
                Ok(provider) => match provider.seal(&dek, &[]) {
                    Ok(blob) => {
                        tpm_wrap = Some(blob.0);
                        hardware_bound = true;
                    }
                    Err(e) => {
                        eprintln!("warning: TPM seal failed ({e}); using recovery-only protection");
                    }
                },
                Err(e) => {
                    eprintln!("warning: TPM unavailable ({e}); using recovery-only protection");
                }
            }
        }
        #[cfg(not(windows))]
        {
            eprintln!(
                "warning: TPM binding unavailable on this platform; using recovery-only protection"
            );
        }
    }

    let header = VaultHeader {
        magic: *b"ZTSV",
        format_version: 1,
        hardware_bound,
        aead_id: 1,
        kdf: params,
        pcr_selection: vec![],
        tpm_wrap,
        recovery_wrap,
        header_mac: [0u8; 32],
    };

    // Zero records; save() computes and writes the header MAC, then the DEK drops.
    let vault = Vault::new_unlocked(dek, header);
    vault.save(path)?;

    if !hardware_bound {
        eprintln!("******************************************************************");
        eprintln!("** WARNING: HARDWARE BINDING IS OFF                             **");
        eprintln!("** This vault is NOT bound to the TPM. It is protected ONLY by  **");
        eprintln!("** the recovery passphrase. Anyone with the vault file and the  **");
        eprintln!("** passphrase can decrypt it on any machine.                    **");
        eprintln!("******************************************************************");
    }

    println!("initialized vault at {}", path.display());
    Ok(())
}

/// Obtain the DEK without persisting it. TPM unseal for hardware-bound vaults,
/// otherwise unwrap via the recovery passphrase. Returns an owned, page-locked,
/// zeroize-on-drop `SecretBytes`.
///
/// The passphrase is taken as an owned `SecretString` (zeroize-on-drop) rather
/// than a `&str` borrow of a clap-owned `String`: the caller moves the parsed
/// argument straight into a `SecretString`, which scrubs the original heap
/// buffer, so the passphrase does not linger un-zeroized in process memory.
/// (Its presence in argv is a separate, documented exposure.)
fn obtain_dek(
    header: &VaultHeader,
    recovery_pw: Option<SecretString>,
) -> vaultcore::Result<SecretBytes> {
    if header.hardware_bound {
        #[cfg(windows)]
        {
            let provider = CngPcpProvider::open()?;
            let wrap = header
                .tpm_wrap
                .clone()
                .ok_or_else(|| Error::Provider("hardware_bound vault has no tpm_wrap".into()))?;
            return provider.unseal(&SealedBlob(wrap));
        }
        #[cfg(not(windows))]
        {
            return Err(Error::Provider(
                "TPM path unavailable on this platform".into(),
            ));
        }
    }
    let pw = recovery_pw.ok_or_else(|| {
        Error::Provider("--recovery-passphrase required (vault is not hardware-bound)".into())
    })?;
    let provider = RecoveryProvider::new(pw, header.kdf);
    provider.unseal(&SealedBlob(header.recovery_wrap.clone()))
}

/// Describe the active key provider for `seal-status` (no DEK needed).
///
/// This must never claim TPM/hardware protection for a vault that isn't
/// actually hardware-bound: only consult (and name) the CNG/TPM provider
/// when `header.hardware_bound` is true. Otherwise the recovery passphrase
/// (Argon2id escrow) is what actually protects the vault, so describe that
/// instead -- without opening or naming the CNG provider at all.
fn active_provider_describe(header: &VaultHeader) -> String {
    if header.hardware_bound {
        #[cfg(windows)]
        {
            if let Ok(provider) = CngPcpProvider::open() {
                return provider.describe();
            }
            return "TPM-backed (hardware_bound is set, but the CNG provider could not be opened)"
                .to_string();
        }
        #[cfg(not(windows))]
        {
            return "TPM-backed (hardware_bound is set, but this platform has no CNG provider)"
                .to_string();
        }
    }
    // Not hardware-bound: describe the recovery provider only. Passphrase is
    // not used by describe(); construct with an empty one.
    let recovery = RecoveryProvider::new(SecretString::from_string(String::new()), header.kdf).describe();
    format!("{recovery} — NO hardware binding")
}

/// Prompt on stderr and read a line from stdin. No-echo is not available without
/// a new dependency, so this is a plain read for slice 1 (the primary path used
/// by tests and scripts is `--value`).
fn read_secret_line(prompt: &str) -> std::io::Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// Generate a password from a CSPRNG (via `SecretBytes::generate`, OsRng-backed).
/// Uses rejection sampling so each character is uniform over the charset, keeping
/// the reported entropy honest. Returns the password and the charset size.
fn gen_password(len: usize, symbols: bool) -> (String, usize) {
    const LOWER: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
    const UPPER: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const DIGITS: &[u8] = b"0123456789";
    const SYMBOLS: &[u8] = b"!@#$%^&*()-_=+[]{};:,.<>?";

    let mut charset: Vec<u8> = Vec::new();
    charset.extend_from_slice(LOWER);
    charset.extend_from_slice(UPPER);
    charset.extend_from_slice(DIGITS);
    if symbols {
        charset.extend_from_slice(SYMBOLS);
    }
    let n = charset.len();

    // Largest multiple of n that is <= 256; bytes at/above this are rejected to
    // avoid modulo bias.
    let threshold = (256 / n) * n;

    let mut out = String::with_capacity(len);
    while out.len() < len {
        let need = len - out.len();
        // Over-provision to reduce the number of CSPRNG draws.
        let batch = SecretBytes::generate(need.saturating_mul(2).max(16));
        for &b in batch.expose() {
            if out.len() == len {
                break;
            }
            let b = b as usize;
            if b < threshold {
                out.push(charset[b % n] as char);
            }
        }
        // batch (SecretBytes) drops here -> zeroized.
    }
    (out, n)
}
