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
//! Scenarios & expectations:
//!   * `locked`    — vault loaded but never unlocked -> **0 hits** (ciphertext only).
//!   * `post-clip` — secret fetched, copied to clipboard, then dropped/zeroized
//!                   BEFORE the dump -> **0 hits** in vaultctl's own heap.
//!   * `leak`      — POSITIVE CONTROL: canary kept in a plain, never-zeroized
//!                   String across the dump -> **>= 1 hit**. If this finds zero,
//!                   the whole harness is meaningless (hard failure).
//!
//! Honesty note: THIS process holds the canary in its own memory (it must, to
//! search for it). That is exactly why it dumps the CHILD (`vaultctl`) and never
//! itself.

use std::error::Error;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

type Res<T> = Result<T, Box<dyn Error>>;

/// The three verification scenarios.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Scenario {
    Locked,
    PostClip,
    Leak,
}

impl Scenario {
    fn name(self) -> &'static str {
        match self {
            Scenario::Locked => "locked",
            Scenario::PostClip => "post-clip",
            Scenario::Leak => "leak(ctrl)",
        }
    }
    /// Human-readable expectation.
    fn expected_str(self) -> &'static str {
        match self {
            Scenario::Leak => ">= 1",
            _ => "== 0",
        }
    }
    /// Does `hits` satisfy this scenario's expectation?
    fn passes(self, hits: usize) -> bool {
        match self {
            Scenario::Leak => hits >= 1,
            _ => hits == 0,
        }
    }
    fn parse(s: &str) -> Option<Scenario> {
        match s {
            "locked" => Some(Scenario::Locked),
            "post-clip" | "postclip" => Some(Scenario::PostClip),
            "leak" => Some(Scenario::Leak),
            _ => None,
        }
    }
}

struct ScenarioResult {
    scenario: Scenario,
    canary: String,
    utf8: usize,
    utf16: usize,
}

impl ScenarioResult {
    fn total(&self) -> usize {
        self.utf8 + self.utf16
    }
    fn passed(&self) -> bool {
        self.scenario.passes(self.total())
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
  dumper verify [--vaultctl <path>] [--keep-dumps]
      Run all three scenarios (locked, post-clip, leak) and assert.
      Exits 0 iff locked==0 AND post-clip==0 AND leak>=1.

  dumper <scenario> <out.dmp> [--vaultctl <path>]
      Run a single scenario (locked | post-clip | leak), write the dump to
      <out.dmp> (kept), and print the canary + hit counts for manual use.

Default --vaultctl: target/release/vaultctl.exe (relative to the current dir;
verify/run.sh cds to the repo root first).";

/// `dumper verify [--vaultctl <path>] [--keep-dumps]`
fn run_verify(rest: &[String]) -> Res<ExitCode> {
    let mut vaultctl = default_vaultctl();
    let mut keep_dumps = false;
    let mut it = rest.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vaultctl" => {
                vaultctl = PathBuf::from(
                    it.next().ok_or("--vaultctl requires a path argument")?,
                );
            }
            "--keep-dumps" => keep_dumps = true,
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    check_vaultctl(&vaultctl)?;

    let base = make_workdir()?;
    println!("dumper: work dir {}", base.display());
    println!("dumper: vaultctl {}", vaultctl.display());
    println!();

    let scenarios = [Scenario::Locked, Scenario::PostClip, Scenario::Leak];
    let mut results: Vec<ScenarioResult> = Vec::new();
    for scen in scenarios {
        let sdir = base.join(scen.name().replace(['(', ')'], ""));
        let dmp = sdir.join("dump.dmp");
        let res = run_scenario(&vaultctl, scen, &sdir, &dmp)?;
        eprintln!(
            "  {:<11} dumped -> utf8={} utf16={} total={}",
            scen.name(),
            res.utf8,
            res.utf16,
            res.total()
        );
        if !keep_dumps {
            let _ = fs::remove_file(&dmp);
        }
        results.push(res);
    }

    println!();
    print_table(&results);

    let all_pass = results.iter().all(ScenarioResult::passed);
    // The positive control is the crux: call it out explicitly.
    let ctrl = results
        .iter()
        .find(|r| r.scenario == Scenario::Leak)
        .expect("leak scenario always run");
    if ctrl.total() == 0 {
        println!(
            "\nHARD FAILURE: positive control found 0 hits -> the scanner is \
             not proving anything. A passing 'locked'/'post-clip' would be vacuous."
        );
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

/// `dumper <scenario> <out.dmp> [--vaultctl <path>]`
fn run_single(args: &[String]) -> Res<ExitCode> {
    let scen = Scenario::parse(&args[0]).ok_or("unknown scenario")?;
    let out = PathBuf::from(args.get(1).ok_or("missing <out.dmp> path")?);
    let mut vaultctl = default_vaultctl();
    let mut it = args[2..].iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--vaultctl" => {
                vaultctl = PathBuf::from(
                    it.next().ok_or("--vaultctl requires a path argument")?,
                );
            }
            other => return Err(format!("unknown argument: {other}").into()),
        }
    }
    check_vaultctl(&vaultctl)?;

    let base = make_workdir()?;
    let sdir = base.join("single");
    let res = run_scenario(&vaultctl, scen, &sdir, &out)?;
    println!(
        "scenario={} dump={} canary={} utf8={} utf16={} total={} expected {} -> {}",
        scen.name(),
        out.display(),
        res.canary,
        res.utf8,
        res.utf16,
        res.total(),
        scen.expected_str(),
        if res.passed() { "PASS" } else { "FAIL" },
    );
    println!(
        "manual cross-check: python verify/scan_dump.py {} {}",
        out.display(),
        res.canary,
    );
    // Keep the requested dump; clean up only the throwaway vault dir.
    let _ = fs::remove_dir_all(&base);
    Ok(if res.passed() { ExitCode::SUCCESS } else { ExitCode::FAILURE })
}

/// Provision a fresh vault with a random canary, spawn the hold subcommand,
/// dump the child's memory, and scan the dump for the canary.
fn run_scenario(
    vaultctl: &Path,
    scen: Scenario,
    sdir: &Path,
    dmp: &Path,
) -> Res<ScenarioResult> {
    fs::create_dir_all(sdir)?;
    if let Some(parent) = dmp.parent() {
        fs::create_dir_all(parent)?;
    }
    let vault = sdir.join("vault.ztsv");
    let canary = generate_canary()?;

    provision(vaultctl, &vault, &canary)?;

    // Build the hold subcommand for this scenario.
    let mut cmd = Command::new(vaultctl);
    cmd.arg("--vault").arg(&vault);
    match scen {
        Scenario::Locked => {
            cmd.arg("__hold-locked");
        }
        Scenario::PostClip => {
            cmd.args(["__hold-postclip", "secret", "--recovery-passphrase", "pw"]);
        }
        Scenario::Leak => {
            cmd.arg("__leak").arg(&canary);
        }
    }
    cmd.stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = cmd.spawn().map_err(|e| {
        format!("failed to spawn vaultctl hold subcommand: {e}")
    })?;

    // Wait until the child signals it is in the target state.
    wait_for_ready(child.stdout.take().ok_or("child has no stdout pipe")?)?;

    let pid = child.id();

    // Dump the CHILD (never ourselves — we hold the canary to search for it).
    dump_process(pid, dmp)?;

    // Release the child: closing its stdin gives EOF so it exits, then reap it.
    drop(child.stdin.take());
    let _ = child.wait();

    let (utf8, utf16) = count_canary_in_dump(dmp, &canary)?;
    Ok(ScenarioResult { scenario: scen, canary, utf8, utf16 })
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

/// Run `vaultctl init` then `vaultctl add secret --value <canary>`.
fn provision(vaultctl: &Path, vault: &Path, canary: &str) -> Res<()> {
    run_checked(
        Command::new(vaultctl)
            .arg("--vault")
            .arg(vault)
            .args(["init", "--allow-no-tpm", "--recovery-passphrase", "pw"]),
        "vaultctl init",
    )?;
    run_checked(
        Command::new(vaultctl)
            .arg("--vault")
            .arg(vault)
            .args(["add", "secret", "--value", canary, "--recovery-passphrase", "pw"]),
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
fn generate_canary() -> Res<String> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes).map_err(|e| format!("OsRng (getrandom) failed: {e}"))?;
    let r1 = u64::from_le_bytes(bytes[..8].try_into().unwrap());
    let r2 = u64::from_le_bytes(bytes[8..].try_into().unwrap());
    Ok(format!("CANARY-{r1:016x}{r2:016x}"))
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
    println!("{:<12} {:>5} {:>6} {:>6} {:>9}  {}", "scenario", "utf8", "utf16", "total", "expected", "result");
    println!("{}", "-".repeat(56));
    for r in results {
        println!(
            "{:<12} {:>5} {:>6} {:>6} {:>9}  {}",
            r.scenario.name(),
            r.utf8,
            r.utf16,
            r.total(),
            r.scenario.expected_str(),
            if r.passed() { "PASS" } else { "FAIL" },
        );
    }
}
