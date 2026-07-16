//! vaultgui engine: window-free, unit-testable modules (auto-lock, session,
//! input marshalling, prefs, clipboard, OS watcher, anti-capture, Hello). The
//! Slint UI wiring lives in the binary (`main.rs`); these modules are the
//! library's public API so they are testable in isolation and never dead code.
pub mod anticapture;
pub mod autolock;
pub mod clipboard;
pub mod input;
pub mod prefs;
pub mod session;
pub mod watcher;
