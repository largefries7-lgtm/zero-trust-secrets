//! Feature-gated scripted "hold-mode" for the GUI verification harness
//! (`verify/dumper`). Mirrors `vaultctl`'s `__hold-locked`/`__hold-postclip`/
//! `__leak` CLI pattern (see `crates/vaultctl/src/main.rs`): freeze this GUI
//! process in one precise state, print `READY` to stdout, then block reading
//! stdin until EOF so the harness can `OpenProcess` + `MiniDumpWriteDump` this
//! process deterministically and scan the dump for the canary/sentinel.
//!
//! Compiled ONLY under `--features leaktest`; a normal shipping build does not
//! contain this module (see the `#[cfg(feature = "leaktest")] mod leaktest;`
//! in `main.rs`). This is a BIN-only module (not in `lib.rs`) because it needs
//! the generated `App` type, which lives in the binary crate root via
//! `slint::include_modules!()`.
//!
//! Three scenarios:
//!   * `gui-locked`        — vault loaded but never unlocked. No DEK is ever
//!                           obtained, so this heap holds only ciphertext (the
//!                           record NAME/sentinel may appear as authenticated-
//!                           but-not-yet-verified plaintext metadata; the
//!                           secret VALUE/canary must be absent).
//!   * `gui-post-autolock` — unlock, reveal a secret into the REAL `App`'s
//!                           `revealed_value` property (materializing exactly
//!                           the Slint `SharedString` residual under test),
//!                           let vaultcore's own buffers (DEK, `SecretString`)
//!                           zeroize on drop, THEN scrub the UI fields exactly
//!                           as `do_lock` does in `main.rs`. Models "the state
//!                           some time after auto-lock fired".
//!   * `gui-leak`          — positive control: hold the canary in a plain,
//!                           never-zeroized `String` across the dump. Proves
//!                           the scanner finds a canary when one IS present.
//!
//! Errors printed here never interpolate the canary/passphrase; the one
//! exception is `gui-leak`, which HOLDS the canary in memory (the whole point
//! of the control) but never prints it.

use std::io::Write;
use std::path::{Path, PathBuf};

use vaultcore::flow::{self, UnlockFactors};
use vaultcore::vault::LockedVault;

const USAGE: &str = "\
usage: vaultgui --leaktest <scenario> [--vault <path>] [--passphrase <pw>] [--name <record-name>] [--canary <value>]

scenarios:
  gui-locked          Load the still-locked vault (no DEK), print READY, then
                      block. The canary (secret value) must be ABSENT.
  gui-post-autolock   Unlock <vault> with <passphrase>, reveal <name> into the
                      real App's revealed_value property, drop the unlocked
                      vault/secret (vaultcore buffers zeroize), scrub the UI as
                      do_lock does, print READY, then block. Requires --vault,
                      --passphrase, --name.
  gui-leak            Positive control: hold <canary> in a plain,
                      never-zeroized String across the dump, print READY, then
                      block. Requires --canary.";

/// Parse everything AFTER the literal `--leaktest` token (the scenario name,
/// then `--flag value` pairs) and dispatch. Returns an error (usage already
/// printed to stderr) on a missing/unknown scenario or a missing required
/// flag; never leaks secret material in any error message.
pub fn run_from_args(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let scenario = match args.first() {
        Some(s) => s.clone(),
        None => {
            eprintln!("{USAGE}");
            return Err("missing <scenario>".into());
        }
    };

    let mut vault: Option<PathBuf> = None;
    let mut passphrase: Option<String> = None;
    let mut name: Option<String> = None;
    let mut canary: Option<String> = None;

    let mut it = args[1..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vault" => {
                vault = Some(PathBuf::from(it.next().ok_or("--vault requires a path argument")?))
            }
            "--passphrase" => {
                passphrase = Some(it.next().ok_or("--passphrase requires a value")?.clone())
            }
            "--name" => name = Some(it.next().ok_or("--name requires a value")?.clone()),
            "--canary" => canary = Some(it.next().ok_or("--canary requires a value")?.clone()),
            other => {
                eprintln!("{USAGE}");
                return Err(format!("unknown argument: {other}").into());
            }
        }
    }

    // Mirrors vaultctl's CLI default so a bare `--vault` omission still points
    // somewhere sensible; the harness always passes an explicit --vault.
    let vault_path = vault.unwrap_or_else(|| PathBuf::from("vault.ztsv"));

    run(&scenario, &vault_path, passphrase.as_deref(), name.as_deref(), canary.as_deref())
}

/// Run one hold-mode scenario. See the module docs for the state each freezes.
fn run(
    scenario: &str,
    vault_path: &Path,
    passphrase: Option<&str>,
    name: Option<&str>,
    canary: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    match scenario {
        "gui-locked" => {
            // Locked state: header + (still-encrypted) record framing only. No
            // DEK is ever obtained, so no plaintext secret exists in this
            // heap; only ciphertext does.
            let _locked = LockedVault::load(vault_path)?;
            ready_and_block()?;
            // _locked drops here (after the dump), carrying only ciphertext.
        }
        "gui-post-autolock" => {
            let passphrase = passphrase.ok_or("gui-post-autolock requires --passphrase")?;
            let name = name.ok_or("gui-post-autolock requires --name")?;

            // Build the REAL Slint App. No event loop is run (App::new() does
            // not create the native window -- see main.rs's anti-capture
            // comment -- so this is safe to call headlessly); the toolkit's
            // own SharedString property storage is exactly what's under test.
            let app = crate::App::new()?;

            {
                // Perform the whole unlock+get+reveal inside an inner scope so
                // the passphrase SecretString, the TPM secret, the DEK, and
                // the fetched secret all run their zeroizing Drop BEFORE the
                // UI scrub below. Whatever survives past this block is
                // Slint's own retained SharedString buffer -- un-zeroizable by
                // us, and exactly what "after auto-lock" is meant to measure.
                let mut pass_buf = passphrase.to_string();
                let pass = vaultgui::input::drain_to_secret(&mut pass_buf);
                let locked = LockedVault::load(vault_path)?;
                let vault = flow::unlock(locked, UnlockFactors::TwoFactor { passphrase: &pass })?;
                let secret = vault.get(name)?;
                app.set_revealed_value(secret.expose_str().into());
                // `secret` and `vault` (hence the DEK) drop here, zeroized.
            }

            // Scrub the UI exactly as `do_lock` does in main.rs.
            app.set_revealed_value("".into());
            app.set_generated_value("".into());

            ready_and_block()?;
        }
        "gui-leak" => {
            // Positive control: keep the canary in a plain String that is
            // NEVER zeroized and stays alive across the dump. black_box
            // prevents the optimizer from eliding the live buffer. This MUST
            // be findable, or the whole harness is meaningless.
            let canary = canary.ok_or("gui-leak requires --canary")?;
            let held = std::hint::black_box(canary.to_string());
            ready_and_block()?;
            // Force `held` to remain live across the blocking dump window.
            std::hint::black_box(&held);
        }
        other => {
            eprintln!("{USAGE}");
            return Err(format!("unknown leaktest scenario: {other}").into());
        }
    }
    Ok(())
}

/// Verification-harness helper: signal readiness on stdout (so the dumper
/// knows the process is in the target state), then block until the harness
/// closes our stdin (EOF) to let the process exit. Not present in production
/// builds.
fn ready_and_block() -> std::io::Result<()> {
    let mut out = std::io::stdout();
    out.write_all(b"READY\n")?;
    out.flush()?;
    // Blocks until a line arrives or stdin reaches EOF (harness drops the pipe).
    let _ = std::io::stdin().read_line(&mut String::new())?;
    Ok(())
}
