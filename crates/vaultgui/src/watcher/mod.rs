//! OS event SOURCE for auto-lock. Owns a message-only window (WM_WTSSESSION_CHANGE,
//! WM_POWERBROADCAST) and polls GetLastInputInfo for SYSTEM-WIDE idle. On a lock
//! trigger it calls `on_lock(reason)`; it never touches the DEK or any secret.

use crate::autolock::{self, AutoLockInput, Decision, LockReason};
use std::time::Duration;

/// System-wide idle time (now - last input) via GetLastInputInfo.
#[cfg(windows)]
pub fn idle_duration() -> Duration {
    use windows::Win32::System::SystemInformation::GetTickCount;
    use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};
    let mut lii = LASTINPUTINFO {
        cbSize: core::mem::size_of::<LASTINPUTINFO>() as u32,
        dwTime: 0,
    };
    // SAFETY: FFI; `lii` is a correctly-sized out param.
    let ok = unsafe { GetLastInputInfo(&mut lii).as_bool() };
    if !ok {
        return Duration::ZERO;
    }
    let now = unsafe { GetTickCount() };
    Duration::from_millis(now.wrapping_sub(lii.dwTime) as u64)
}

#[cfg(not(windows))]
pub fn idle_duration() -> Duration {
    Duration::ZERO
}

/// Pure helper: given the current snapshot, should we fire a lock? (Wraps the
/// autolock reducer so the watcher loop stays a thin adapter around tested logic.)
pub fn evaluate(
    idle: Duration,
    timeout: Option<Duration>,
    workstation_locked: bool,
    suspending: bool,
) -> Option<LockReason> {
    match autolock::decide(&AutoLockInput {
        idle,
        timeout,
        workstation_locked,
        suspending,
        manual: false,
    }) {
        Decision::Lock(reason) => Some(reason),
        Decision::Stay => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evaluate_maps_reducer_output() {
        assert_eq!(evaluate(Duration::from_secs(10), Some(Duration::from_secs(5)), false, false), Some(LockReason::Idle));
        assert_eq!(evaluate(Duration::ZERO, Some(Duration::from_secs(5)), false, false), None);
        assert_eq!(evaluate(Duration::ZERO, None, false, true), Some(LockReason::Suspend));
        assert_eq!(evaluate(Duration::ZERO, None, true, false), Some(LockReason::WorkstationLock));
    }
}

/// Windows implementation: a dedicated thread owns a message-only window that
/// receives WM_WTSSESSION_CHANGE / WM_POWERBROADCAST and polls idle via a 1s
/// WM_TIMER. Everything that touches the HWND (creation, class registration,
/// GWLP_USERDATA, message pump, teardown) stays on that one thread; only a plain
/// `isize` copy of the handle crosses back to the caller, so nothing here needs
/// `unsafe impl Send` -- the boxed `on_lock` closure and the shared flags never
/// leave the thread that owns the window.
#[cfg(windows)]
mod win {
    use super::{evaluate, idle_duration};
    use crate::autolock::LockReason;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;
    use windows::core::PCWSTR;
    use windows::Win32::Foundation::{
        GetLastError, ERROR_CLASS_ALREADY_EXISTS, HINSTANCE, HWND, LPARAM, LRESULT, WPARAM,
    };
    use windows::Win32::System::LibraryLoader::GetModuleHandleW;
    use windows::Win32::System::RemoteDesktop::{
        WTSRegisterSessionNotification, WTSUnRegisterSessionNotification, NOTIFY_FOR_THIS_SESSION,
    };
    use windows::Win32::UI::WindowsAndMessaging::{
        CreateWindowExW, DefWindowProcW, DestroyWindow, DispatchMessageW, GetMessageW,
        GetWindowLongPtrW, KillTimer, PostMessageW, PostQuitMessage, RegisterClassW, SetTimer,
        SetWindowLongPtrW, TranslateMessage, GWLP_USERDATA, HWND_MESSAGE, MSG, PBT_APMSUSPEND,
        WINDOW_EX_STYLE, WINDOW_STYLE, WM_CLOSE, WM_DESTROY, WM_POWERBROADCAST, WM_TIMER,
        WM_WTSSESSION_CHANGE, WNDCLASSW, WTS_SESSION_LOCK,
    };

    /// Shared state stashed in GWLP_USERDATA; owned by the watcher thread for the
    /// lifetime of the window (created in `run`, reclaimed in `run`'s cleanup).
    struct WatcherState {
        timeout: Option<Duration>,
        on_lock: Box<dyn Fn(LockReason)>,
        fired: Arc<AtomicBool>,
    }

    extern "system" fn wndproc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) -> LRESULT {
        // SAFETY: reads the pointer this same thread stashed via SetWindowLongPtrW
        // right after CreateWindowExW; null for any message delivered before that
        // setup runs (e.g. messages sent during CreateWindowExW itself).
        let ptr = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *const WatcherState;
        if ptr.is_null() {
            // SAFETY: FFI passthrough; hwnd/msg/wparam/lparam are exactly what
            // Windows handed this callback.
            return unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) };
        }
        // SAFETY: `ptr` was produced by `Box::into_raw` in `run`, on this same
        // thread, and is only reclaimed by that thread's post-loop cleanup -- which
        // runs after this window can no longer receive messages (see the WM_CLOSE
        // case below). Valid for every message this proc can still process.
        let state = unsafe { &*ptr };

        if msg == WM_WTSSESSION_CHANGE && wparam.0 as u32 == WTS_SESSION_LOCK {
            (state.on_lock)(LockReason::WorkstationLock);
            return LRESULT(0);
        }
        if msg == WM_POWERBROADCAST && wparam.0 as u32 == PBT_APMSUSPEND {
            (state.on_lock)(LockReason::Suspend);
            return LRESULT(1);
        }
        if msg == WM_TIMER {
            match evaluate(idle_duration(), state.timeout, false, false) {
                Some(LockReason::Idle) => {
                    if !state.fired.swap(true, Ordering::Relaxed) {
                        (state.on_lock)(LockReason::Idle);
                    }
                }
                _ => {
                    // Not idle-to-threshold right now: clear the latch so the
                    // NEXT idle period (after this activity) can fire again.
                    // Without this, the guard stays latched forever after the
                    // first idle-lock and a later session never idle-locks.
                    state.fired.store(false, Ordering::Relaxed);
                }
            }
            return LRESULT(0);
        }
        if msg == WM_CLOSE {
            // Deliberately NOT delegating to DefWindowProcW: its default WM_CLOSE
            // handling calls DestroyWindow itself, which would tear the window
            // (and GWLP_USERDATA) down synchronously, before `run`'s post-loop
            // cleanup gets a chance to reclaim the WatcherState box or unregister
            // the timer/WTS notification -- leaking the box and running those APIs
            // against an already-dead hwnd. Posting quit directly instead keeps the
            // window alive until `run` destroys it explicitly, in the order its
            // cleanup actually needs.
            //
            // SAFETY: FFI; posts WM_QUIT to this thread's queue.
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        if msg == WM_DESTROY {
            // SAFETY: FFI; belt-and-suspenders so the loop still unwinds if the
            // window is ever destroyed by a path other than the WM_CLOSE case above.
            unsafe { PostQuitMessage(0) };
            return LRESULT(0);
        }
        // SAFETY: FFI passthrough for anything we don't special-case.
        unsafe { DefWindowProcW(hwnd, msg, wparam, lparam) }
    }

    /// Runs entirely on the watcher thread: registers the window class, creates the
    /// message-only window, hands its hwnd back through `tx`, pumps messages, and
    /// tears everything down before returning.
    fn run(
        timeout: Option<Duration>,
        on_lock: impl Fn(LockReason) + Send + 'static,
        fired: Arc<AtomicBool>,
        tx: mpsc::Sender<isize>,
    ) {
        // Manual UTF-16 class-name buffer: simpler than fighting the `w!` macro on
        // this windows-rs version. Must outlive RegisterClassW/CreateWindowExW (it
        // does -- it's a local that lives for the rest of this function, and the
        // class name isn't needed again after CreateWindowExW returns).
        let class_name: Vec<u16> = "ZtsvVaultWatcher\0".encode_utf16().collect();
        let class_name_pcwstr = PCWSTR(class_name.as_ptr());

        // SAFETY: FFI; `None` resolves to the current module's HMODULE, which is
        // infallible for the calling process's own module.
        let hinstance: HINSTANCE = unsafe { GetModuleHandleW(None) }
            .expect("GetModuleHandleW(None) failed for the current module")
            .into();

        let wc = WNDCLASSW {
            lpfnWndProc: Some(wndproc),
            hInstance: hinstance,
            lpszClassName: class_name_pcwstr,
            ..Default::default()
        };
        // SAFETY: FFI; `wc` is fully initialized, `lpfnWndProc` points at a valid
        // `extern "system"` function, and `class_name` outlives this call.
        let atom = unsafe { RegisterClassW(&wc) };
        if atom == 0 {
            // SAFETY: FFI; reads this thread's last-error code, set by
            // RegisterClassW immediately above.
            let err = unsafe { GetLastError() };
            assert_eq!(
                err, ERROR_CLASS_ALREADY_EXISTS,
                "RegisterClassW failed for a reason other than the class already existing"
            );
        }

        // SAFETY: FFI; message-only window (HWND_MESSAGE parent, never shown),
        // using the class just registered; `class_name_pcwstr` is still alive.
        let hwnd = unsafe {
            CreateWindowExW(
                WINDOW_EX_STYLE(0),
                class_name_pcwstr,
                PCWSTR::null(),
                WINDOW_STYLE(0),
                0,
                0,
                0,
                0,
                HWND_MESSAGE,
                None,
                hinstance,
                None,
            )
        }
        .expect("CreateWindowExW(HWND_MESSAGE) failed for the watcher's message-only window");

        let state = Box::new(WatcherState {
            timeout,
            on_lock: Box::new(on_lock),
            fired,
        });
        // SAFETY: FFI; stashes ownership of `state` in this window's user-data slot
        // so `wndproc` (which only ever runs on this thread) can read it back.
        // Reclaimed and dropped in the cleanup below.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, Box::into_raw(state) as isize) };

        // SAFETY: FFI; registers `hwnd` for WM_WTSSESSION_CHANGE, scoped to this
        // session.
        unsafe { WTSRegisterSessionNotification(hwnd, NOTIFY_FOR_THIS_SESSION) }
            .expect("WTSRegisterSessionNotification failed for a freshly created hwnd");

        // SAFETY: FFI; arms a ~1s repeating timer (id 1) that drives the idle poll
        // in wndproc's WM_TIMER case.
        let timer_id = unsafe { SetTimer(hwnd, 1, 1000, None) };
        assert_ne!(timer_id, 0, "SetTimer failed to arm the idle-poll timer");

        // Hand the hwnd back to `spawn` now that setup is complete. Only a plain
        // `isize` crosses the thread boundary -- HWND itself never needs to be
        // Send, since every other Win32 call against it happens right here.
        let _ = tx.send(hwnd.0 as isize);

        let mut msg = MSG::default();
        // SAFETY: FFI; standard message-only pump. `msg` is a valid out-param for
        // every call, and this only ever runs on the watcher's own thread.
        while unsafe { GetMessageW(&mut msg, HWND::default(), 0, 0) }.0 > 0 {
            // SAFETY: FFI passthrough of the message this thread just retrieved.
            unsafe {
                let _ = TranslateMessage(&msg);
                DispatchMessageW(&msg);
            }
        }

        // SAFETY: FFI; matches the SetTimer call above. Errors ignored -- we're
        // shutting down regardless.
        let _ = unsafe { KillTimer(hwnd, 1) };
        // SAFETY: FFI; matches WTSRegisterSessionNotification above.
        let _ = unsafe { WTSUnRegisterSessionNotification(hwnd) };

        // SAFETY: reclaims the WatcherState box; the slot is cleared first so
        // wndproc's null-check protects any message that might still arrive while
        // DestroyWindow below unwinds the window (e.g. WM_NCDESTROY).
        let raw = unsafe { GetWindowLongPtrW(hwnd, GWLP_USERDATA) } as *mut WatcherState;
        // SAFETY: FFI; hwnd is still a valid window here -- wndproc's WM_CLOSE case
        // deliberately keeps DefWindowProcW from destroying it early (see the
        // comment there), so this slot is still readable/writable.
        unsafe { SetWindowLongPtrW(hwnd, GWLP_USERDATA, 0) };
        if !raw.is_null() {
            // SAFETY: `raw` came from `Box::into_raw` above, on this same thread,
            // and has not been reclaimed since; this is the one and only drop.
            drop(unsafe { Box::from_raw(raw) });
        }

        // SAFETY: FFI; final teardown of the still-live message-only window.
        let _ = unsafe { DestroyWindow(hwnd) };
    }

    /// Handle to the running watcher thread. `stop()` unregisters and joins;
    /// dropping the handle without calling `stop()` leaves the thread (and its
    /// message-only window) running for the remainder of the process.
    pub struct WatcherHandle {
        hwnd: isize,
        join: Option<JoinHandle<()>>,
        fired: Arc<AtomicBool>,
    }

    impl WatcherHandle {
        /// Clears the "already fired" idle latch so a fresh idle period (e.g.
        /// after the UI unlocks) can trigger another `LockReason::Idle` event.
        pub fn rearm(&self) {
            self.fired.store(false, Ordering::Relaxed);
        }

        /// Posts WM_CLOSE to the watcher's window and joins its thread.
        pub fn stop(mut self) {
            let hwnd = HWND(self.hwnd as *mut core::ffi::c_void);
            // SAFETY: FFI; `hwnd` is the watcher thread's own window, still alive
            // until that thread processes this message and tears itself down (see
            // wndproc's WM_CLOSE case and `run`'s post-loop cleanup).
            let _ = unsafe { PostMessageW(hwnd, WM_CLOSE, WPARAM(0), LPARAM(0)) };
            if let Some(join) = self.join.take() {
                let _ = join.join();
            }
        }
    }

    pub fn spawn<F>(timeout: Option<Duration>, on_lock: F) -> WatcherHandle
    where
        F: Fn(LockReason) + Send + 'static,
    {
        let fired = Arc::new(AtomicBool::new(false));
        let fired_for_thread = Arc::clone(&fired);
        let (tx, rx) = mpsc::channel::<isize>();

        let join = thread::spawn(move || run(timeout, on_lock, fired_for_thread, tx));

        let hwnd = rx
            .recv()
            .expect("watcher thread exited before it could hand back its hwnd");

        WatcherHandle {
            hwnd,
            join: Some(join),
            fired,
        }
    }
}

#[cfg(windows)]
pub use win::{spawn, WatcherHandle};

#[cfg(not(windows))]
pub struct WatcherHandle;

#[cfg(not(windows))]
impl WatcherHandle {
    pub fn rearm(&self) {}
    pub fn stop(self) {}
}

#[cfg(not(windows))]
pub fn spawn<F>(_timeout: Option<Duration>, _on_lock: F) -> WatcherHandle
where
    F: Fn(LockReason) + Send + 'static,
{
    WatcherHandle
}
