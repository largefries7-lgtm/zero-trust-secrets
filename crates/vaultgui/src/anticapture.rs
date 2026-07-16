//! Exclude the window from screen capture/screen-share (renders blank in captures).
//! Covers screen capture, NOT a camera pointed at the display (documented limit).

#[cfg(windows)]
pub fn exclude_from_capture_hwnd(hwnd: isize) -> bool {
    use windows::Win32::Foundation::HWND;
    use windows::Win32::UI::WindowsAndMessaging::{
        SetWindowDisplayAffinity, WDA_EXCLUDEFROMCAPTURE,
    };
    // SAFETY: FFI. `hwnd` is the live top-level window handle owned by the Slint
    // window for the lifetime of the app; the affinity flag is a valid constant.
    unsafe { SetWindowDisplayAffinity(HWND(hwnd as *mut core::ffi::c_void), WDA_EXCLUDEFROMCAPTURE).is_ok() }
}

#[cfg(not(windows))]
pub fn exclude_from_capture_hwnd(_hwnd: isize) -> bool {
    false
}
