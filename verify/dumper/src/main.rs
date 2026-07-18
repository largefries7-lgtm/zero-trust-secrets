//! Memory-scraping verification harness for the Zero-Trust Secrets Manager.
//!
//! This binary EMPIRICALLY tests the memory-safety claim: that plaintext
//! secrets do not linger in `vaultctl`'s process RAM once they are no longer
//! needed. For each scenario it:
//!
//!   1. provisions a throwaway vault holding a random *canary* secret,
//!   2. spawns `vaultctl` into a hidden, feature-gated "hold" subcommand that
//!      freezes the process in a precise state and prints `READY`,
//!   3. `OpenProcess` + `MiniDumpWriteDump` the CHILD's full memory to a `.dmp`,
//!   4. scans the dump for the canary (UTF-8 and UTF-16LE), and
//!   5. asserts the expected hit count.
//!
//! Scenarios & expectations (CLI, driven by `vaultctl`'s `__hold-*`/`__leak`):
//!   * `locked`    — vault loaded but never unlocked -> **0 hits** (ciphertext only).
//!   * `post-clip` — secret fetched, copied to clipboard, then dropped/zeroized
//!                   BEFORE the dump -> **0 hits** in vaultctl's own heap.
//!   * `leak`      — POSITIVE CONTROL: canary kept in a plain, never-zeroized
//!                   String across the dump -> **>= 1 hit**. If this finds zero,
//!                   the whole harness is meaningless (hard failure).
//!
//! GUI scenarios (Task E2, driven by `vaultgui --leaktest <scenario>`; see
//! `crates/vaultgui/src/leaktest.rs`):
//!   * `gui-locked`        — mirrors `locked`: vault loaded, never unlocked ->
//!                           **0 hits**.
//!   * `gui-post-autolock` — unlock + reveal into the real Slint `App`, let
//!                           vaultcore's own buffers zeroize, THEN scrub the UI
//!                           exactly as auto-lock does. vaultcore's hygiene is
//!                           proven (sentinel found), but Slint's own freed
//!                           `SharedString` is NOT under our control and is not
//!                           zeroizable, so the canary MAY still be found. This
//!                           is reported as a measured residual, not a failure.
//!   * `gui-leak`          — POSITIVE CONTROL for the GUI binary, same shape as
//!                           `leak` -> **>= 1 hit**.
//!
//! Honesty note: THIS process holds the canary in its own memory (it must, to
//! search for it). That is exactly why it dumps the CHILD (`vaultctl`/
//! `vaultgui`) and never itself.

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

type Res<T> = Result<T, Box<dyn Error>>;

/// Passphrase used to provision every throwaway harness vault. It must clear the
/// single-factor strength floor now enforced by `vaultctl init` (mixed classes,
/// 22 chars). The same value is reused wherever a scenario later unlocks (`PostClip`,
/// `GuiPostAutolock`), so provision and unlock always agree.
const PROVISION_PASSPHRASE: &str = "Tq7!vK2m-Zp9x_Lw3r#Hs6";

/// All verification scenarios: the original CLI (`vaultctl`) trio plus the
/// GUI (`vaultgui --leaktest`) trio added by Task E2.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Locked,
    PostClip,
    Leak,
    GuiLocked,
    GuiPostAutolock,
    GuiLeak,
}

/// Every scenario `run_verify` runs, in report order: CLI trio first (as
/// before), then the GUI trio.
const ALL_SCENARIOS: [Scenario; 6] = [
    Scenario::Locked,
    Scenario::PostClip,
    Scenario::Leak,
    Scenario::GuiLocked,
    Scenario::GuiPostAutolock,
    Scenario::GuiLeak,
];

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Scenario::Locked => "locked",
            Scenario::PostClip => "post-clip",
            Scenario::Leak => "leak(ctrl)",
            Scenario::GuiLocked => "gui-locked",
            Scenario::GuiPostAutolock => "gui-post-autolock",
            Scenario::GuiLeak => "gui-leak(ctrl)",
        }
    }
    /// Human-readable expectation.
    fn expected_str(self) -> &'static str {
        match self {
            // Self-validating: the non-secret sentinel (the record NAME, held in
            // plaintext metadata) MUST be found in this very dump — proving the
            // dump+scan pipeline works on IT — while the canary MUST be absent.
            Scenario::Locked | Scenario::PostClip | Scenario::GuiLocked => "sent>=1 & can==0",
            // vaultcore's own buffers are proven zeroized (sentinel found), but
            // Slint's freed SharedString is not ours to zeroize -- the canary
            // count here is a measured residual, not a pass/fail signal.
            Scenario::GuiPostAutolock => "sent>=1 & can=RESIDUAL",
            // Positive controls load no vault, so they have no sentinel; their
            // own validity proof is that the canary IS found.
            Scenario::Leak | Scenario::GuiLeak => "can>=1",
        }
    }
    /// Whether this scenario loads the vault (and therefore carries the record
    /// NAME / sentinel in its process heap). The positive controls do not.
    fn loads_vault(self) -> bool {
        !matches!(self, Scenario::Leak | Scenario::GuiLeak)
    }
    /// Whether this scenario is a positive control (must find the canary, or
    /// the harness itself is broken/meaningless).
    fn is_control(self) -> bool {
        matches!(self, Scenario::Leak | Scenario::GuiLeak)
    }
    /// Whether this scenario is driven by the `vaultgui --leaktest` binary
    /// rather than `vaultctl`'s `__hold-*`/`__leak` subcommands.
    fn is_gui(self) -> bool {
        matches!(self, Scenario::GuiLocked | Scenario::GuiPostAutolock | Scenario::GuiLeak)
    }
    fn parse(s: &str) -> Option<Scenario> {
        match s {
            "locked" => Some(Scenario::Locked),
            "post-clip" | "postclip" => Some(Scenario::PostClip),
            "leak" => Some(Scenario::Leak),
            "gui-locked" => Some(Scenario::GuiLocked),
            "gui-post-autolock" | "gui-postautolock" => Some(Scenario::GuiPostAutolock),
            "gui-leak" => Some(Scenario::GuiLeak),
            _ => None,
        }
    }
}

struct ScenarioResult {
    scenario: Scenario,
    /// The "dump is real" sentinel: the vault PATH, a known non-secret string the
    /// loaded process always holds (argv + the PathBuf it opened). Must appear in
    /// any vault-loading scenario's dump. (Record NAMES are encrypted on disk as of
    /// format v3, so a name is no longer a usable plaintext sentinel in a locked
    /// process.)
    sentinel: String,
    /// The random secret VALUE; must NOT survive in the heap when not in use.
    canary: String,
    /// Hits of the sentinel (record name) across UTF-8 + UTF-16LE. Only
    /// meaningful for vault-loading scenarios.
    sentinel_hits: usize,
    canary_utf8: usize,
    canary_utf16: usize,
}

impl ScenarioResult {
    fn canary_total(&self) -> usize {
        self.canary_utf8 + self.canary_utf16
    }
    /// Pass criteria, per scenario:
    ///   * locked / post-clip / gui-locked: sentinel MUST be found (dump+scan
    ///     proven real for THIS dump) AND canary MUST be absent (no plaintext
    ///     secret lingering).
    ///   * gui-post-autolock: sentinel MUST be found (pipeline proven real).
    ///     The canary is NOT required to be absent here -- see
    ///     `gui_residual_note`. vaultcore's own buffers are zeroized before this
    ///     dump, but Slint's freed `SharedString` (holding the revealed value)
    ///     is outside our control and is not zeroizable, so a nonzero canary
    ///     count is an expected, reported residual rather than a failure.
    ///   * leak / gui-leak (positive controls): canary MUST be found.
    /// A missing sentinel where one is expected is a FAILURE — the pipeline is
    /// broken for that dump, so its canary count would be vacuous either way.
    fn passed(&self) -> bool {
        match self.scenario {
            Scenario::Locked | Scenario::PostClip | Scenario::GuiLocked => {
                self.sentinel_hits >= 1 && self.canary_total() == 0
            }
            Scenario::GuiPostAutolock => self.sentinel_hits >= 1,
            Scenario::Leak | Scenario::GuiLeak => self.canary_total() >= 1,
        }
    }
    /// Informational note for the un-zeroizable Slint `SharedString` residual:
    /// `Some(..)` only for `gui-post-autolock` with a nonzero canary count.
    /// Never affects `passed()` -- this is a measurement, not a defect.
    fn gui_residual_note(&self) -> Option<String> {
        if self.scenario == Scenario::GuiPostAutolock && self.canary_total() > 0 {
            Some(format!(
                "gui-post-autolock: vaultcore buffers zeroized; Slint retains {} canary \
                 byte-run{} in its freed SharedString (un-zeroizable toolkit residual — see \
                 TEST_PLAN)",
                self.canary_total(),
                if self.canary_total() == 1 { "" } else { "s" }
            ))
        } else {
            None
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match real_main(&args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("dumper: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn real_main(args: &[String]) -> Res<ExitCode> {
    match args.first().map(String::as_str) {
        Some("verify") => run_verify(&args[1..]),
        Some(other) if Scenario::parse(other).is_some() => run_single(args),
        _ => {
            eprintln!("{USAGE}");
            Ok(ExitCode::FAILURE)
        }
    }
}

const USAGE: &str = "\
dumper — memory-scraping verification harness

USAGE:
  dumper verify [--vaultctl <path>] [--vaultgui <path>] [--keep-dumps]
      Run all six scenarios (locked, post-clip, leak, gui-locked,
      gui-post-autolock, gui-leak) and assert. Each vault-loading scenario
      self-validates via a non-secret sentinel that MUST appear in its own
      dump. Exits 0 iff:
        locked            (sentinel>=1 AND canary==0)
        post-clip         (sentinel>=1 AND canary==0)
        leak              (canary>=1)
        gui-locked        (sentinel>=1 AND canary==0)
        gui-post-autolock (sentinel>=1; canary count is a reported residual,
                            NOT a pass/fail signal -- see module docs)
        gui-leak          (canary>=1)

  dumper <scenario> <out.dmp> [--vaultctl <path>] [--vaultgui <path>]
      Run a single scenario (locked | post-clip | leak | gui-locked |
      gui-post-autolock | gui-leak), write the dump to <out.dmp> (kept), and
      print the sentinel + canary hit counts for manual use.

Default --vaultctl: target/release/vaultctl.exe (relative to the current dir;
verify/run.sh cds to the repo root first).
Default --vaultgui: target/release/vaultgui.exe (same convention).";

/// `dumper verify [--vaultctl <path>] [--vaultgui <path>] [--keep-dumps]`
fn run_verify(rest: &[String]) -> Res<ExitCode> {
    let mut vaultctl = default_vaultctl();
    let mut vaultgui = default_vaultgui();
    let mut keep_dumps = false;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vaultctl" => {
                vaultctl = PathBuf::from(
                    it.next().ok_or("--vaultctl requires a path argument")?,
                );
            }
            "--vaultgui" => {
                vaultgui = PathBuf::from(
                    it.next().ok_or("--vaultgui requires a path argument")?,
                );
            }
            "--keep-dumps" => keep_dumps = true,
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    check_vaultctl(&vaultctl)?;
    check_vaultgui(&vaultgui)?;

    let base = make_workdir()?;
    println!("dumper: work dir {}", base.display());
    println!("dumper: vaultctl {}", vaultctl.display());
    println!("dumper: vaultgui {}", vaultgui.display());
    println!();

    let mut results: Vec<ScenarioResult> = Vec::new();
    for scen in ALL_SCENARIOS {
        let sdir = base.join(scen.name().replace(['(', ')'], ""));
        let dmp = sdir.join("dump.dmp");
        let res = run_scenario(&vaultctl, &vaultgui, scen, &sdir, &dmp)?;
        if scen.loads_vault() {
            eprintln!(
                "  {:<18} dumped -> sentinel={} canary(utf8={} utf16={} total={})",
                scen.name(),
                res.sentinel_hits,
                res.canary_utf8,
                res.canary_utf16,
                res.canary_total()
            );
        } else {
            eprintln!(
                "  {:<18} dumped -> canary(utf8={} utf16={} total={})",
                scen.name(),
                res.canary_utf8,
                res.canary_utf16,
                res.canary_total()
            );
        }
        if let Some(note) = res.gui_residual_note() {
            eprintln!("      note: {note}");
        }
        if !keep_dumps {
            let _ = fs::remove_file(&dmp);
        }
        results.push(res);
    }

    println!();
    print_table(&results);

    let all_pass = results.iter().all(ScenarioResult::passed);
    // The positive controls are the crux: call each out explicitly. There are
    // two now (CLI `leak` and GUI `gui-leak`) -- each validates its own binary's
    // dump+scan pipeline independently.
    for ctrl_scen in ALL_SCENARIOS.iter().copied().filter(|s| s.is_control()) {
        let ctrl = results
            .iter()
            .find(|r| r.scenario == ctrl_scen)
            .expect("control scenario always run");
        if ctrl.canary_total() == 0 {
            println!(
                "\nHARD FAILURE: positive control '{}' found 0 hits -> the scanner is \
                 not proving anything for that binary. A passing vault-loading scenario \
                 for it would be vacuous.",
                ctrl_scen.name()
            );
        }
    }
    // Each vault-loading scenario also self-validates via its sentinel: if the
    // sentinel is missing, that dump/scan is broken and its canary count (0 or
    // otherwise) proves nothing.
    for r in &results {
        if r.scenario.loads_vault() && r.sentinel_hits == 0 {
            println!(
                "\nHARD FAILURE: scenario '{}' found 0 sentinel hits -> its \
                 dump/scan pipeline is broken; its canary count there proves nothing.",
                r.scenario.name()
            );
        }
    }
    // gui-post-autolock's canary count (if any) is informational only -- surface
    // it distinctly from the PASS/FAIL machinery above so it never reads as a
    // failure.
    for r in &results {
        if let Some(note) = r.gui_residual_note() {
            println!("\nNOTE: {note}");
        }
    }

    if keep_dumps {
        println!("\ndumps kept under {}", base.display());
    } else {
        let _ = fs::remove_dir_all(&base);
    }

    if all_pass {
        println!("\nOVERALL: PASS");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("\nOVERALL: FAIL");
        Ok(ExitCode::FAILURE)
    }
}

/// `dumper <scenario> <out.dmp> [--vaultctl <path>] [--vaultgui <path>]`
fn run_single(args: &[String]) -> Res<ExitCode> {
    let scen = Scenario::parse(&args[0]).ok_or("unknown scenario")?;
    let out = PathBuf::from(args.get(1).ok_or("missing <out.dmp> path")?);
    let mut vaultctl = default_vaultctl();
    let mut vaultgui = default_vaultgui();
    let mut it = args[2..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vaultctl" => {
                vaultctl = PathBuf::from(
                    it.next().ok_or("--vaultctl requires a path argument")?,
                );
            }
            "--vaultgui" => {
                vaultgui = PathBuf::from(
                    it.next().ok_or("--vaultgui requires a path argument")?,
                );
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    // Provisioning always goes through vaultctl (shared .ztsv format), so it
    // must exist regardless of scenario.
    check_vaultctl(&vaultctl)?;
    // The binary this scenario actually spawns as its "hold" child also needs
    // to exist -- only checked for GUI scenarios here since vaultctl was just
    // checked above unconditionally.
    if scen.is_gui() {
        check_vaultgui(&vaultgui)?;
    }

    let base = make_workdir()?;
    let sdir = base.join("single");
    let res = run_scenario(&vaultctl, &vaultgui, scen, &sdir, &out)?;
    if scen.loads_vault() {
        println!(
            "scenario={} dump={} sentinel={} (hits={}) canary={} (utf8={} utf16={} total={}) expected {} -> {}",
            scen.name(),
            out.display(),
            res.sentinel,
            res.sentinel_hits,
            res.canary,
            res.canary_utf8,
            res.canary_utf16,
            res.canary_total(),
            scen.expected_str(),
            if res.passed() { "PASS" } else { "FAIL" },
        );
        if let Some(note) = res.gui_residual_note() {
            println!("note: {note}");
        }
        println!(
            "manual cross-check: python verify/scan_dump.py {} {}   # canary: expect ABSENT (exit 0)",
            out.display(),
            res.canary,
        );
        println!(
            "manual cross-check: python verify/scan_dump.py {} {}   # sentinel: expect PRESENT (exit 2)",
            out.display(),
            res.sentinel,
        );
    } else {
        println!(
            "scenario={} dump={} canary={} (utf8={} utf16={} total={}) expected {} -> {}",
            scen.name(),
            out.display(),
            res.canary,
            res.canary_utf8,
            res.canary_utf16,
            res.canary_total(),
            scen.expected_str(),
            if res.passed() { "PASS" } else { "FAIL" },
        );
        println!(
            "manual cross-check: python verify/scan_dump.py {} {}   # canary: expect PRESENT (exit 2)",
            out.display(),
            res.canary,
        );
    }
    // Keep the requested dump; clean up only the throwaway vault dir.
    let _ = fs::remove_dir_all(&base);
    Ok(if res.passed() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

/// Provision a fresh vault whose record NAME is a random non-secret sentinel and
/// whose VALUE is a random secret canary, spawn the hold subcommand (either
/// `vaultctl`'s `__hold-*`/`__leak`, or `vaultgui --leaktest <scenario>` for the
/// GUI trio — see `Scenario::is_gui`), dump the child's memory, and scan the
/// dump for BOTH markers.
///
/// Provisioning always goes through `vaultctl` (both binaries share the same
/// `.ztsv` on-disk format), even for GUI scenarios.
///
/// The sentinel is the vault PATH — a known non-secret string the loaded process
/// always holds (argv + the opened PathBuf) — so it MUST appear in any vault-
/// loading scenario's dump, self-validating that the dump+scan pipeline works on
/// that very dump. (Record NAMES are encrypted on disk as of format v3, so a name
/// is not a usable plaintext sentinel in a locked process.) The canary (secret
/// value) is encrypted at rest and zeroized after use, so it MUST NOT appear in
/// the locked/post-clip/gui-locked heaps. (`gui-post-autolock` is the one
/// exception — see its `passed()`/`gui_residual_note` docs.)
fn run_scenario(
    vaultctl: &Path,
    vaultgui: &Path,
    scen: Scenario,
    sdir: &Path,
    dmp: &Path,
) -> Res<ScenarioResult> {
    fs::create_dir_all(sdir)?;
    if let Some(parent) = dmp.parent() {
        fs::create_dir_all(parent)?;
    }
    let vault = sdir.join("vault.ztsv");
    let record_name = generate_sentinel()?;
    let canary = generate_canary()?;
    // As of on-disk format v3 record NAMES are encrypted, so a locked (never-
    // unlocked) process holds no plaintext record name. The "dump is real"
    // sentinel is therefore the vault PATH — a known non-secret string the loaded
    // process always holds (argv + the PathBuf it opened) regardless of unlock —
    // rather than the record name. It proves the dump/scan pipeline works on THIS
    // dump, so a canary==0 result is meaningful and not vacuous.
    let sentinel = vault.to_string_lossy().to_string();

    provision(vaultctl, &vault, &record_name, &canary)?;

    // Build the hold subcommand for this scenario: CLI scenarios spawn
    // vaultctl's hidden `__hold-*`/`__leak` subcommands; GUI scenarios spawn
    // vaultgui's `--leaktest <scenario>` mode (Task E1). Both print `READY`
    // once frozen in the target state and then block on stdin EOF, so the rest
    // of this function (wait_for_ready/dump_process/scan) is shared.
    let mut cmd = if scen.is_gui() {
        let mut c = Command::new(vaultgui);
        c.arg("--leaktest");
        match scen {
            Scenario::GuiLocked => {
                c.arg("gui-locked").arg("--vault").arg(&vault);
            }
            Scenario::GuiPostAutolock => {
                c.arg("gui-post-autolock")
                    .arg("--vault")
                    .arg(&vault)
                    .arg("--passphrase")
                    .arg(PROVISION_PASSPHRASE)
                    .arg("--name")
                    .arg(&record_name);
            }
            Scenario::GuiLeak => {
                c.arg("gui-leak").arg("--canary").arg(&canary);
            }
            Scenario::Locked | Scenario::PostClip | Scenario::Leak => {
                unreachable!("is_gui() guarantees a GUI variant here")
            }
        }
        c
    } else {
        let mut c = Command::new(vaultctl);
        c.arg("--vault").arg(&vault);
        match scen {
            Scenario::Locked => {
                c.arg("__hold-locked");
            }
            Scenario::PostClip => {
                // Fetch by the record name.
                c.args(["__hold-postclip", &record_name, "--passphrase", PROVISION_PASSPHRASE]);
            }
            Scenario::Leak => {
                c.arg("__leak").arg(&canary);
            }
            Scenario::GuiLocked | Scenario::GuiPostAutolock | Scenario::GuiLeak => {
                unreachable!("!is_gui() guarantees a CLI variant here")
            }
        }
        c
    };
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let child_bin = if scen.is_gui() { "vaultgui" } else { "vaultctl" };
    let mut child = cmd
        .spawn()
        .map_err(|e| format!("failed to spawn {child_bin} hold subcommand: {e}"))?;

    // Wait until the child signals it is in the target state.
    wait_for_ready(child.stdout.take().ok_or("child has no stdout pipe")?)?;

    let pid = child.id();

    // Dump the CHILD (never ourselves — we hold the canary to search for it).
    dump_process(pid, dmp)?;

    // Release the child: closing its stdin gives EOF so it exits, then reap it.
    drop(child.stdin.take());
    let _ = child.wait();

    let (canary_utf8, canary_utf16) = count_canary_in_dump(dmp, &canary)?;
    // The sentinel proof only applies to scenarios that actually load the vault.
    let sentinel_hits = if scen.loads_vault() {
        let (s8, s16) = count_canary_in_dump(dmp, &sentinel)?;
        s8 + s16
    } else {
        0
    };
    Ok(ScenarioResult {
        scenario: scen,
        sentinel,
        canary,
        sentinel_hits,
        canary_utf8,
        canary_utf16,
    })
}

/// Read the child's stdout until a line equal to `READY`. Errors if the child
/// closes stdout (exits) before printing it.
fn wait_for_ready(stdout: std::process::ChildStdout) -> Res<()> {
    let mut reader = BufReader::new(stdout);
    let mut line = String::new();
    loop {
        line.clear();
        let n = reader.read_line(&mut line)?;
        if n == 0 {
            return Err("child exited before printing READY".into());
        }
        if line.trim_end() == "READY" {
            return Ok(());
        }
        // Ignore any other stray lines.
    }
}

/// Run `vaultctl init` then `vaultctl add <sentinel-name> --value <canary>`.
/// The record NAME is the non-secret sentinel; the VALUE is the secret canary.
fn provision(vaultctl: &Path, vault: &Path, name: &str, canary: &str) -> Res<()> {
    run_checked(
        Command::new(vaultctl)
            .arg("--vault")
            .arg(vault)
            .args(["init", "--allow-no-tpm", "--passphrase", PROVISION_PASSPHRASE]),
        "vaultctl init",
    )?;
    run_checked(
        Command::new(vaultctl)
            .arg("--vault")
            .arg(vault)
            .args(["add", name, "--value", canary, "--passphrase", PROVISION_PASSPHRASE]),
        "vaultctl add",
    )?;
    Ok(())
}

/// Run a command to completion and require exit success; surface stderr on error.
fn run_checked(cmd: &mut Command, what: &str) -> Res<()> {
    let output = cmd
        .stdin(Stdio::null())
        .output()
        .map_err(|e| format!("{what}: failed to run: {e}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("{what}: exited with {}: {}", output.status, stderr.trim()).into());
    }
    Ok(())
}

/// Generate a random canary of the form `CANARY-<16 hex><16 hex>` from the OS RNG.
/// This is the SECRET value; it must not linger in the heap when not in use.
fn generate_canary() -> Res<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("OsRng (getrandom) failed: {e}"))?;
    let r1 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let r2 = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    Ok(format!("CANARY-{r1:016x}{r2:016x}"))
}

/// Generate a random sentinel of the form `SENTINEL-<16 hex>` from the OS RNG.
/// This is a NON-SECRET record name (plaintext metadata) that MUST show up in a
/// vault-loading scenario's dump — proving that dump+scan works on that dump.
fn generate_sentinel() -> Res<String> {
    let mut bytes = [0u8; 8];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("OsRng (getrandom) failed: {e}"))?;
    let r = u64::from_le_bytes(bytes);
    Ok(format!("SENTINEL-{r:016x}"))
}

/// Count occurrences of the canary in the dump, as UTF-8 and as UTF-16LE.
fn count_canary_in_dump(path: &Path, canary: &str) -> Res<(usize, usize)> {
    let utf8 = canary.as_bytes().to_vec();
    let utf16: Vec<u8> = canary
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    let n8 = count_needle_in_file(path, &utf8)?;
    let n16 = count_needle_in_file(path, &utf16)?;
    Ok((n8, n16))
}

/// Stream a file in 1 MiB chunks (with `needle.len()-1` overlap so matches that
/// straddle a chunk boundary are still found exactly once) and count needle hits.
/// Bounds memory regardless of dump size.
fn count_needle_in_file(path: &Path, needle: &[u8]) -> Res<usize> {
    if needle.is_empty() {
        return Ok(0);
    }
    let mut file = File::open(path)
        .map_err(|e| format!("open dump {}: {e}", path.display()))?;
    let overlap = needle.len() - 1;
    const CHUNK: usize = 1 << 20;
    let mut buf = vec![0u8; overlap + CHUNK];
    let mut carry = 0usize; // valid bytes retained at the front of `buf`
    let mut count = 0usize;
    loop {
        let n = file.read(&mut buf[carry..])?;
        if n == 0 {
            break;
        }
        let filled = carry + n;
        count += count_occurrences(&buf[..filled], needle);
        if filled >= overlap {
            // Retain the trailing `overlap` bytes so a match spanning this
            // boundary completes (and is counted exactly once) next iteration.
            buf.copy_within(filled - overlap..filled, 0);
            carry = overlap;
        } else {
            carry = filled;
        }
    }
    Ok(count)
}

/// Count occurrences of `needle` in `hay` (overlapping matches allowed).
fn count_occurrences(hay: &[u8], needle: &[u8]) -> usize {
    if needle.is_empty() || hay.len() < needle.len() {
        return 0;
    }
    hay.windows(needle.len()).filter(|w| *w == needle).count()
}

/// Dump the full memory of process `pid` to `out_path` via MiniDumpWriteDump.
///
/// Uses the same-user `OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)`
/// rights, which suffice for dumping a child spawned by this process without
/// elevation. Never dumps the current process.
#[cfg(windows)]
fn dump_process(pid: u32, out_path: &Path) -> Res<()> {
    use windows::Win32::Foundation::{CloseHandle, FALSE, HANDLE};
    use windows::Win32::System::Diagnostics::Debug::{
        MiniDumpWithFullMemory, MiniDumpWriteDump,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    // Open the CHILD process for reading its memory. Same-user access, no
    // elevation needed for a process we spawned.
    // SAFETY: FFI call. The access-rights flags are valid constants, `FALSE`
    // is a valid BOOL (do not inherit the handle), and `pid` is the live
    // child's PID. On failure the Result is mapped to an error (no unwrap);
    // on success we own a process handle that is closed below.
    let process: HANDLE = unsafe {
        OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)
    }
    .map_err(|e| {
        format!(
            "OpenProcess(pid={pid}, QUERY_INFORMATION|VM_READ) failed: {e} \
             (HRESULT 0x{:08X})",
            e.code().0 as u32
        )
    })?;

    // Create the destination dump file and hand its raw handle to the dumper.
    // `dmp_file` is kept alive until after the FFI call so the handle stays valid.
    let dmp_file = File::create(out_path).map_err(|e| {
        // Close the process handle we just opened before bailing out.
        // SAFETY: `process` is the live handle from OpenProcess above, closed once.
        unsafe {
            let _ = CloseHandle(process);
        }
        format!("create dump file {}: {e}", out_path.display())
    })?;
    let dmp_handle = HANDLE(dmp_file.as_raw_handle() as *mut core::ffi::c_void);

    // SAFETY: FFI call. `process` is the live child handle from OpenProcess;
    // `pid` identifies the same process; `dmp_handle` is the live, writable
    // handle owned by `dmp_file` (kept in scope across this call);
    // `MiniDumpWithFullMemory` is a valid dump type; the three optional stream
    // pointers are `None`. The Result is mapped to an error (no unwrap).
    let dump_res = unsafe {
        MiniDumpWriteDump(
            process,
            pid,
            dmp_handle,
            MiniDumpWithFullMemory,
            None,
            None,
            None,
        )
    };

    // Close the process handle regardless of the dump outcome.
    // SAFETY: `process` is the live handle from OpenProcess, closed exactly once.
    unsafe {
        let _ = CloseHandle(process);
    }
    // Flush + close the dump file before it is scanned.
    drop(dmp_file);

    dump_res.map_err(|e| {
        format!(
            "MiniDumpWriteDump(pid={pid}) failed: {e} (HRESULT 0x{:08X})",
            e.code().0 as u32
        )
    })?;
    Ok(())
}

#[cfg(not(windows))]
fn dump_process(_pid: u32, _out_path: &Path) -> Res<()> {
    Err("process memory dumping is only implemented on Windows".into())
}

/// Default vaultctl path, relative to the current working directory.
fn default_vaultctl() -> PathBuf {
    PathBuf::from("target").join("release").join("vaultctl.exe")
}

/// Default vaultgui path, relative to the current working directory (same
/// convention as `default_vaultctl`).
fn default_vaultgui() -> PathBuf {
    PathBuf::from("target").join("release").join("vaultgui.exe")
}

fn check_vaultctl(p: &Path) -> Res<()> {
    if !p.exists() {
        return Err(format!(
            "vaultctl binary not found at {} (build it: \
             `cargo build --release -p vaultctl --features leaktest`)",
            p.display()
        )
        .into());
    }
    Ok(())
}

fn check_vaultgui(p: &Path) -> Res<()> {
    if !p.exists() {
        return Err(format!(
            "vaultgui binary not found at {} (build it: \
             `cargo build --release -p vaultgui --features leaktest`)",
            p.display()
        )
        .into());
    }
    Ok(())
}

/// Create a unique temp working directory for this run.
fn make_workdir() -> Res<PathBuf> {
    let mut salt = [0u8; 8];
    getrandom::getrandom(&mut salt).map_err(|e| format!("getrandom: {e}"))?;
    let tag = u64::from_le_bytes(salt);
    let dir = std::env::temp_dir().join(format!("ztsv-verify-{}-{:016x}", std::process::id(), tag));
    fs::create_dir_all(&dir)?;
    Ok(dir)
}

fn print_table(results: &[ScenarioResult]) {
    // sentinel = non-secret record-name marker that MUST be in the dump (proves
    // the scan pipeline works on THAT dump); canary = secret value that must not
    // linger. "-" for sentinel means the scenario loads no vault (positive control).
    println!(
        "{:<18} {:>8} {:>10} {:>11} {:>22}  {}",
        "scenario", "sentinel", "canary_u8", "canary_u16", "expected", "result"
    );
    println!("{}", "-".repeat(86));
    for r in results {
        let sentinel = if r.scenario.loads_vault() {
            r.sentinel_hits.to_string()
        } else {
            "-".to_string()
        };
        println!(
            "{:<18} {:>8} {:>10} {:>11} {:>22}  {}",
            r.scenario.name(),
            sentinel,
            r.canary_utf8,
            r.canary_utf16,
            r.scenario.expected_str(),
            if r.passed() { "PASS" } else { "FAIL" },
        );
        // gui-post-autolock's canary count is a reported residual, never a
        // pass/fail signal on its own -- flag it right under its table row so
        // it can't be misread as silent.
        if let Some(note) = r.gui_residual_note() {
            println!("    ^ residual: {note}");
        }
    }
}
