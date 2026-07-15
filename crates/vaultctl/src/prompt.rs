//! Interactive secret entry without echoing to the terminal.
//!
//! Passing secrets on argv exposes them to every process on the machine (the
//! process command line is world-readable) and to shell history. Interactive
//! entry avoids argv entirely; disabling echo additionally keeps the secret out
//! of the terminal's visible scrollback. If stdin is not a console (piped
//! input, e.g. scripts/tests), there is no echo to suppress and we read plainly.

use std::io::{self, BufRead, Write};

/// Read a line from stdin with terminal echo disabled. The trailing newline is
/// stripped. Echo is restored before returning, even on error paths (RAII).
pub fn read_secret_noecho(prompt: &str) -> io::Result<String> {
    eprint!("{prompt}");
    io::stderr().flush()?;

    let guard = EchoGuard::disable(); // no-op if stdin is not a console
    let mut line = String::new();
    let read = io::stdin().lock().read_line(&mut line);
    drop(guard); // restore echo before we do anything else
    read?;

    // The user's Enter was not echoed while echo was off; advance the cursor.
    eprintln!();

    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

#[cfg(windows)]
struct EchoGuard {
    handle: windows::Win32::Foundation::HANDLE,
    prev_mode: u32,
    active: bool,
}

#[cfg(windows)]
impl EchoGuard {
    fn disable() -> Self {
        use windows::Win32::System::Console::{
            GetConsoleMode, GetStdHandle, SetConsoleMode, CONSOLE_MODE, ENABLE_ECHO_INPUT,
            STD_INPUT_HANDLE,
        };
        // SAFETY: FFI. STD_INPUT_HANDLE is a valid predefined handle id; the
        // out-pointer and handle passed below are valid. On any failure we return
        // an inactive guard and leave the console mode untouched.
        unsafe {
            let handle = match GetStdHandle(STD_INPUT_HANDLE) {
                Ok(h) => h,
                Err(_) => return Self::inactive(),
            };
            let mut mode = CONSOLE_MODE(0);
            if GetConsoleMode(handle, &mut mode).is_err() {
                // Not a console (piped/redirected stdin): nothing to disable.
                return Self::inactive();
            }
            let new_mode = CONSOLE_MODE(mode.0 & !ENABLE_ECHO_INPUT.0);
            if SetConsoleMode(handle, new_mode).is_err() {
                return Self::inactive();
            }
            EchoGuard { handle, prev_mode: mode.0, active: true }
        }
    }

    fn inactive() -> Self {
        EchoGuard {
            handle: windows::Win32::Foundation::HANDLE(core::ptr::null_mut()),
            prev_mode: 0,
            active: false,
        }
    }
}

#[cfg(windows)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        if self.active {
            use windows::Win32::System::Console::{SetConsoleMode, CONSOLE_MODE};
            // SAFETY: restore the exact mode we saved, on the same handle.
            unsafe {
                let _ = SetConsoleMode(self.handle, CONSOLE_MODE(self.prev_mode));
            }
        }
    }
}

// Non-Windows: no console echo control available here; read plainly.
#[cfg(not(windows))]
struct EchoGuard;
#[cfg(not(windows))]
impl EchoGuard {
    fn disable() -> Self {
        EchoGuard
    }
}
