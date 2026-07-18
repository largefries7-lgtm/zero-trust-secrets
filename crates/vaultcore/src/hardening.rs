//! Process-level hardening (Windows): exploit-mitigation policies, crash-report
//! suppression, and in-RAM secret encryption via `CryptProtectMemory`.
//!
//! All of this lives strictly below the userspace ceiling stated in `SECURITY.md`:
//! it raises the bar against same-user attackers (DLL-injection, passive memory
//! scraping) but cannot stop a compromised kernel or code already executing inside
//! this process. Every call is best-effort — a failure on an older Windows build
//! degrades to the prior behavior rather than aborting.

/// CryptProtectMemory operates on buffers whose length is a multiple of this many
/// bytes (`CRYPTPROTECTMEMORY_BLOCK_SIZE`).
pub const BLOCK: usize = 16;

#[cfg(windows)]
mod imp {
    use super::BLOCK;
    use core::ffi::c_void;
    use windows::Win32::Security::Cryptography::{
        CryptProtectMemory, CryptUnprotectMemory, CRYPTPROTECTMEMORY_SAME_PROCESS,
    };
    use windows::Win32::System::Diagnostics::Debug::{
        SetErrorMode, SEM_FAILCRITICALERRORS, SEM_NOGPFAULTERRORBOX,
    };
    use windows::Win32::System::Threading::{
        SetProcessMitigationPolicy, ProcessExtensionPointDisablePolicy, ProcessImageLoadPolicy,
        PROCESS_MITIGATION_POLICY,
    };

    /// Apply the safe, high-value process-mitigation subset and suppress the WER
    /// crash UI. Returns the names of the mitigations that applied.
    ///
    /// Deliberately NOT enabled: `ProcessDynamicCodePolicy` (ACG) and
    /// `ProcessSignaturePolicy` (Microsoft/Store-signed-only). Both can break the
    /// GUI's third-party GPU-driver DLL loads under Slint, so they are left off
    /// rather than risk bricking rendering — an honest tradeoff, not an oversight.
    pub fn harden_process() -> Vec<&'static str> {
        let mut applied = Vec::new();

        // Block legacy AppInit_DLLs / SetWindowsHookEx extension-point injection.
        if set_policy(ProcessExtensionPointDisablePolicy, 0x1) {
            applied.push("extension-point-disable");
        }
        // Refuse loading DLLs from remote (UNC) paths (bit 0) or low-integrity
        // locations (bit 1). PreferSystem32 (bit 2) is left off to avoid surprising
        // load-order changes for the rendering stack.
        if set_policy(ProcessImageLoadPolicy, 0x1 | 0x2) {
            applied.push("image-load-restrict");
        }

        // Suppress the crash dialog / critical-error box so a fault dies quietly
        // rather than popping WER UI. (Full local-dump suppression is a machine
        // registry setting outside a userspace process's reach — see SECURITY.md.)
        // SAFETY: FFI; the flags are valid constants.
        unsafe {
            let _ = SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX);
        }
        applied.push("no-crash-ui");

        applied
    }

    /// These mitigation policies are DWORD bitfields, so a 4-byte `u32` buffer with
    /// the right bits set is the correct shape for `SetProcessMitigationPolicy`.
    fn set_policy(policy: PROCESS_MITIGATION_POLICY, flags: u32) -> bool {
        // SAFETY: FFI. `flags` is a live 4-byte value passed by const pointer with
        // length 4, matching the DWORD-bitfield layout these policies expect.
        // Best-effort: failure (older Windows, or already applied) returns false.
        unsafe {
            SetProcessMitigationPolicy(policy, &flags as *const u32 as *const c_void, 4).is_ok()
        }
    }

    /// Encrypt `buf` in place with a process-bound key (`CRYPTPROTECTMEMORY_SAME_PROCESS`).
    /// Returns false (leaving `buf` untouched) if the length is not a multiple of
    /// `BLOCK` or the OS call fails.
    pub fn protect_in_place(buf: &mut [u8]) -> bool {
        if buf.is_empty() || !buf.len().is_multiple_of(BLOCK) {
            return false;
        }
        // SAFETY: FFI; `buf` is a live writable slice whose length is a multiple of
        // the block size. SAME_PROCESS binds the wrapping key to this process.
        unsafe {
            CryptProtectMemory(
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            )
            .is_ok()
        }
    }

    /// Inverse of [`protect_in_place`].
    pub fn unprotect_in_place(buf: &mut [u8]) -> bool {
        if buf.is_empty() || !buf.len().is_multiple_of(BLOCK) {
            return false;
        }
        // SAFETY: as `protect_in_place`, on a buffer previously protected in this
        // same process.
        unsafe {
            CryptUnprotectMemory(
                buf.as_mut_ptr() as *mut c_void,
                buf.len() as u32,
                CRYPTPROTECTMEMORY_SAME_PROCESS,
            )
            .is_ok()
        }
    }
}

#[cfg(not(windows))]
mod imp {
    /// No OS mitigation policies on non-Windows targets (stub).
    pub fn harden_process() -> Vec<&'static str> {
        Vec::new()
    }
    /// No OS in-RAM memory encryption available; callers fall back to holding the
    /// secret in a page-locked, zeroize-on-drop buffer (still scrubbed on drop).
    pub fn protect_in_place(_buf: &mut [u8]) -> bool {
        false
    }
    pub fn unprotect_in_place(_buf: &mut [u8]) -> bool {
        false
    }
}

pub use imp::{harden_process, protect_in_place, unprotect_in_place};

#[cfg(all(windows, test))]
mod tests {
    use super::*;

    #[test]
    fn protect_unprotect_round_trips() {
        let original = [7u8; 32];
        let mut buf = original;
        // If CryptProtectMemory is available, the buffer must differ once protected
        // and match again once unprotected. If unavailable (false), it's untouched.
        if protect_in_place(&mut buf) {
            assert_ne!(buf, original, "protected buffer should not be plaintext");
            assert!(unprotect_in_place(&mut buf));
            assert_eq!(buf, original, "unprotect must recover the plaintext");
        }
    }

    #[test]
    fn rejects_non_block_multiple_length() {
        let mut buf = [0u8; 20]; // not a multiple of 16
        assert!(!protect_in_place(&mut buf));
    }
}
