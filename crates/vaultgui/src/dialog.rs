//! Native "choose vault file" dialog.
//!
//! Returns the path the user picked, or `None` if they cancelled or the dialog
//! isn't available. Windows uses the common Open dialog (`GetOpenFileNameW`,
//! filtered to `*.ztsv`); every other platform returns `None`. No secret
//! material is involved — only a filesystem path.
//!
//! `owner` is the top-level window's `HWND` (as an `isize`; `0` = no owner).
//! Passing the real owner makes the dialog MODAL — Windows disables the owner
//! window while the picker's nested message loop runs, so the unlock screen
//! behind it can't accept reentrant input (e.g. an Unlock click) mid-dialog.

use std::path::PathBuf;

#[cfg(windows)]
pub fn choose_vault_file(owner: isize) -> Option<PathBuf> {
    use windows::core::{PCWSTR, PWSTR};
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::Controls::Dialogs::{
        GetOpenFileNameW, OFN_FILEMUSTEXIST, OFN_NOCHANGEDIR, OFN_PATHMUSTEXIST, OPENFILENAMEW,
    };

    // A double-NUL-terminated filter: "<label>\0<pattern>\0...\0\0".
    let filter: Vec<u16> = "Vault files (*.ztsv)\0*.ztsv\0All files (*.*)\0*.*\0\0"
        .encode_utf16()
        .collect();
    // Receives the chosen path (wide, NUL-terminated). Sized generously so a
    // legitimately long selection doesn't fail as FNERR_BUFFERTOOSMALL (which
    // is indistinguishable from a cancel at this call site).
    let mut file_buf = vec![0u16; 4096];

    let mut ofn = OPENFILENAMEW {
        lStructSize: core::mem::size_of::<OPENFILENAMEW>() as u32,
        // SAFETY of the cast: `owner` is either 0 (no owner) or a live top-level
        // HWND obtained from the running window; the dialog only uses it as the
        // owner to make itself modal.
        hwndOwner: HWND(owner as *mut core::ffi::c_void),
        lpstrFilter: PCWSTR(filter.as_ptr()),
        lpstrFile: PWSTR(file_buf.as_mut_ptr()),
        nMaxFile: file_buf.len() as u32,
        // NOCHANGEDIR: don't let navigating the dialog change the process CWD.
        Flags: OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_NOCHANGEDIR,
        ..Default::default()
    };

    // SAFETY: FFI. `ofn` is fully initialized; `filter` (NUL-terminated) and
    // `file_buf` (an `nMaxFile`-long writable buffer) both outlive the call.
    // GetOpenFileNameW only reads the filter and writes into `file_buf`.
    let ok = unsafe { GetOpenFileNameW(&mut ofn) };
    if !ok.as_bool() {
        return None; // cancelled (or a dialog error — treated the same as cancel)
    }

    let end = file_buf.iter().position(|&c| c == 0).unwrap_or(file_buf.len());
    let s = String::from_utf16_lossy(&file_buf[..end]);
    if s.is_empty() {
        None
    } else {
        Some(PathBuf::from(s))
    }
}

#[cfg(not(windows))]
pub fn choose_vault_file(_owner: isize) -> Option<PathBuf> {
    None
}
