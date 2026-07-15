//! Clipboard copy with auto-clear.
//!
//! Invariant: the secret is fed to `clip.exe` via STDIN, never as a
//! command-line argument, so it never appears in any process's argv (which is
//! world-readable on the machine). The follow-up clear runs in a detached
//! process and only ever passes a single space on its own argv.

use std::io::Write;
use std::process::{Command, Stdio};

/// Copy `text` to the Windows clipboard via `clip.exe` stdin (NOT as a
/// command-line argument, so the secret never appears in any process's argv),
/// then spawn a detached process that clears the clipboard after `secs`.
pub fn copy_with_autoclear(text: &str, secs: u64) -> std::io::Result<()> {
    // set: pipe the secret through clip.exe stdin.
    let mut child = Command::new("cmd")
        .args(["/C", "clip"])
        .stdin(Stdio::piped())
        .spawn()?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(text.as_bytes())?;
        // stdin drops here -> EOF, so clip.exe finishes reading.
    }
    child.wait()?;

    // clear after `secs`: detached powershell; only a space is ever on argv.
    Command::new("powershell")
        .args([
            "-NoProfile",
            "-Command",
            &format!("Start-Sleep -Seconds {secs}; Set-Clipboard -Value ' '"),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;
    Ok(())
}
