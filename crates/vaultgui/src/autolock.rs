//! Pure auto-lock decision. Takes an immutable snapshot of inputs and returns a
//! decision — NO clock or OS calls inside, so every branch is deterministically
//! unit-testable. The watcher (src/watcher) supplies the snapshot; the UI thread
//! acts on the decision.

use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockReason {
    Idle,
    WorkstationLock,
    Suspend,
    Manual,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Stay,
    Lock(LockReason),
}

/// Snapshot of everything the decision depends on.
#[derive(Debug, Clone, Copy)]
pub struct AutoLockInput {
    /// System-wide idle time (now - last input), from GetLastInputInfo.
    pub idle: Duration,
    /// Idle timeout; `None` disables idle-based locking (OS events still lock).
    pub timeout: Option<Duration>,
    pub workstation_locked: bool,
    pub suspending: bool,
    pub manual: bool,
}

/// Priority: an explicit request and hard OS signals win over the idle timer.
pub fn decide(i: &AutoLockInput) -> Decision {
    if i.manual {
        return Decision::Lock(LockReason::Manual);
    }
    if i.suspending {
        return Decision::Lock(LockReason::Suspend);
    }
    if i.workstation_locked {
        return Decision::Lock(LockReason::WorkstationLock);
    }
    if let Some(t) = i.timeout {
        if i.idle >= t {
            return Decision::Lock(LockReason::Idle);
        }
    }
    Decision::Stay
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> AutoLockInput {
        AutoLockInput {
            idle: Duration::ZERO,
            timeout: Some(Duration::from_secs(300)),
            workstation_locked: false,
            suspending: false,
            manual: false,
        }
    }

    #[test]
    fn stays_below_timeout() {
        let i = AutoLockInput { idle: Duration::from_secs(299), ..base() };
        assert_eq!(decide(&i), Decision::Stay);
    }

    #[test]
    fn locks_at_timeout_boundary() {
        let i = AutoLockInput { idle: Duration::from_secs(300), ..base() };
        assert_eq!(decide(&i), Decision::Lock(LockReason::Idle));
    }

    #[test]
    fn disabled_timeout_never_idle_locks() {
        let i = AutoLockInput { idle: Duration::from_secs(99999), timeout: None, ..base() };
        assert_eq!(decide(&i), Decision::Stay);
    }

    #[test]
    fn workstation_lock_is_immediate() {
        let i = AutoLockInput { workstation_locked: true, idle: Duration::ZERO, ..base() };
        assert_eq!(decide(&i), Decision::Lock(LockReason::WorkstationLock));
    }

    #[test]
    fn suspend_beats_workstation_and_idle() {
        let i = AutoLockInput { suspending: true, workstation_locked: true, ..base() };
        assert_eq!(decide(&i), Decision::Lock(LockReason::Suspend));
    }

    #[test]
    fn manual_beats_everything() {
        let i = AutoLockInput { manual: true, suspending: true, ..base() };
        assert_eq!(decide(&i), Decision::Lock(LockReason::Manual));
    }
}
