//! Page-locking so secret buffers cannot be written to the pagefile.
//! Degrades to a no-op (returns false) if the privilege is unavailable.

#[cfg(windows)]
pub fn lock(ptr: *mut u8, len: usize) -> bool {
    use windows::Win32::System::Memory::VirtualLock;
    if len == 0 { return true; }
    // SAFETY: caller guarantees ptr..ptr+len is an owned, live allocation.
    unsafe { VirtualLock(ptr as _, len).is_ok() }
}

#[cfg(windows)]
pub fn unlock(ptr: *mut u8, len: usize) {
    use windows::Win32::System::Memory::VirtualUnlock;
    if len == 0 { return; }
    // SAFETY: same allocation previously passed to lock().
    let _ = unsafe { VirtualUnlock(ptr as _, len) };
}

#[cfg(not(windows))]
pub fn lock(_ptr: *mut u8, _len: usize) -> bool { false }
#[cfg(not(windows))]
pub fn unlock(_ptr: *mut u8, _len: usize) {}
