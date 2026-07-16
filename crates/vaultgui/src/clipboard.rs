//! Clipboard copy with a live countdown and verify-before-clear.
//!
//! Invariants (spec #5): the secret is fed to `clip.exe` via STDIN, never argv;
//! the delayed clear runs detached and only overwrites the clipboard if it STILL
//! holds our value (so we don't nuke something the user copied since); both the
//! set and the verify feed the value via stdin; executables are launched by
//! ABSOLUTE System32 path so no earlier-in-PATH lookalike can receive the secret.

use std::path::PathBuf;

/// UI-facing countdown; one tick == one second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Countdown {
    pub total_secs: u64,
    pub remaining_secs: u64,
}

impl Countdown {
    pub fn new(total_secs: u64) -> Self {
        Countdown { total_secs, remaining_secs: total_secs }
    }
    /// Decrement by one second (saturating). Returns true once fully elapsed.
    pub fn tick(&mut self) -> bool {
        self.remaining_secs = self.remaining_secs.saturating_sub(1);
        self.remaining_secs == 0
    }
}

/// Absolute path to a System32 executable, e.g. `system32("clip.exe")`.
pub fn system32(exe: &str) -> PathBuf {
    let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
    PathBuf::from(root).join("System32").join(exe)
}

/// PowerShell that reads the expected clipboard value from stdin, waits `secs`,
/// and clears the clipboard ONLY if it still equals that value.
pub fn clear_script(secs: u64) -> String {
    format!(
        "$exp = [Console]::In.ReadToEnd(); \
         Start-Sleep -Seconds {secs}; \
         if ((Get-Clipboard -Raw) -eq $exp) {{ Set-Clipboard -Value ' ' }}"
    )
}

/// Copy `secret` to the clipboard (via clip.exe stdin) and schedule a detached,
/// verify-before-clear after `secs` seconds.
#[cfg(windows)]
pub fn copy_with_autoclear(secret: &str, secs: u64) -> std::io::Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let clip = system32("clip.exe");
    let mut child = Command::new(&clip).stdin(Stdio::piped()).spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(secret.as_bytes())?;
    }
    child.wait()?;

    let ps = system32("WindowsPowerShell\\v1.0\\powershell.exe");
    let mut clearer = Command::new(&ps)
        .args(["-NoProfile", "-NonInteractive", "-Command", &clear_script(secs)])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    if let Some(mut stdin) = clearer.stdin.take() {
        stdin.write_all(secret.as_bytes())?;
    }
    // Detached: do not wait.
    Ok(())
}

/// Copy `secret` to the clipboard (via clip.exe stdin) and schedule a detached,
/// verify-before-clear after `secs` seconds. Non-Windows stub returning Ok(()).
#[cfg(not(windows))]
pub fn copy_with_autoclear(_secret: &str, _secs: u64) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn countdown_reaches_zero_and_reports_elapsed() {
        let mut c = Countdown::new(3);
        assert_eq!(c.remaining_secs, 3);
        assert!(!c.tick()); // 2
        assert!(!c.tick()); // 1
        assert!(c.tick()); // 0 -> elapsed
        assert_eq!(c.remaining_secs, 0);
        assert!(c.tick()); // saturates at 0
    }

    // `is_absolute()` follows the HOST's path semantics: a `C:\...` path is only
    // "absolute" on Windows, so this assertion is Windows-gated. The `ends_with`
    // component check below is host-independent and stays unconditional.
    #[cfg(windows)]
    #[test]
    fn system32_path_is_absolute_under_system_root() {
        let p = system32("clip.exe");
        assert!(p.is_absolute());
    }

    #[test]
    fn system32_path_ends_in_system32_exe() {
        let p = system32("clip.exe");
        assert!(p.ends_with("System32\\clip.exe") || p.ends_with("System32/clip.exe"));
    }

    #[test]
    fn clear_script_verifies_before_clearing_and_keeps_secret_off_argv() {
        let s = clear_script(15);
        assert!(s.contains("Start-Sleep -Seconds 15"));
        assert!(s.contains("[Console]::In.ReadToEnd()")); // value arrives via stdin
        assert!(s.contains("-eq $exp")); // verify-before-clear
        // The secret itself must never be embedded in the script text (argv).
        assert!(!s.contains("hunter2"));
    }
}
