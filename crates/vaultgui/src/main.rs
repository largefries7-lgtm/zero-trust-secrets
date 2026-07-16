//! GUI entry point: builds the Slint `App`, loads non-secret prefs, populates
//! startup UI state, and wires every `App` callback. D3a-1 wired the
//! NON-SECRET layer (lock, theme, idle-timeout, record selection/mask,
//! navigation); D3a-2 (this pass) wires the SECRET-FLOW layer (`unlock`,
//! `create_vault`, `reveal`, `copy`, `copy_generated`, `add_secret`, `rotate`,
//! `remove`, `generate`, `search`, `deprovision`) plus `pick_vault` (an
//! intentional no-op — a native file-picker dialog is deferred).
//!
//! D3b-1 (this pass) applies anti-capture (`WDA_EXCLUDEFROMCAPTURE`) to the
//! top-level window so screenshots/screen-share render it blank. Still
//! deferred to D3b-2: the OS watcher / auto-lock-on-idle wiring, and the
//! ticking clipboard-countdown timer (the `clip_remaining` property is set on
//! copy but does not yet count down on its own).
slint::include_modules!();

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use slint::{ComponentHandle, SharedString, VecModel};
use vaultcore::flow::{self, describe_provider, CreateOptions, UnlockFactors};
use vaultcore::vault::{LockedVault, Vault};
use vaultgui::prefs::{Prefs, Theme};
use vaultgui::session::{AppState, Session};
use vaultgui::{clipboard, input};

/// `%APPDATA%\ZeroTrustSecrets\` (falls back to the current dir if `APPDATA`
/// is unset, e.g. under a stripped-down test environment).
fn base_dir() -> PathBuf {
    let base = std::env::var("APPDATA").unwrap_or_else(|_| ".".to_string());
    PathBuf::from(base).join("ZeroTrustSecrets")
}

/// Best-effort prefs write. Prefs hold no secret material (see prefs.rs), so a
/// failed write is not security-relevant; it just means the next launch falls
/// back to defaults/last-known values. Kept quiet rather than surfaced via the
/// error banner to avoid nagging the user over something this low-stakes.
fn persist_prefs(prefs: &Prefs, path: &Path) {
    let _ = std::fs::write(path, prefs.to_serialized());
}

/// Build a `[string]` model from an owned `Vec` (record-name list, filtered
/// search results, etc.) for `App::set_record_names`.
fn names_model(v: Vec<SharedString>) -> slint::ModelRc<SharedString> {
    Rc::new(VecModel::from(v)).into()
}

/// An empty `[string]` model, for scrubbing `record_names` on lock.
fn empty_names_model() -> slint::ModelRc<SharedString> {
    names_model(vec![])
}

/// Renders the authenticated unlock-factor posture, once an unlock/create has
/// actually verified it (never shown pre-auth -- see `posture_authenticated`).
fn posture_string(hardware_bound: bool, has_recovery: bool) -> &'static str {
    match (hardware_bound, has_recovery) {
        (true, false) => "TWO-FACTOR · TPM + PASSPHRASE",
        (true, true) => "TWO-FACTOR · TPM + PASSPHRASE · RECOVERY ESCROW",
        (false, _) => "PASSPHRASE ONLY",
    }
}

/// After a vault mutation (add/rotate/remove), recompute the full record-name
/// list from the vault itself and push it both into `full_names` (the
/// unfiltered source `search` filters against) and `record_names` (what's
/// currently on screen). Called with an active search filter still in effect
/// will transiently show the unfiltered list until the next keystroke -- an
/// acceptable tradeoff since D3a-2 does not re-run the last filter here.
fn refresh_names(app: &App, full_names: &Rc<RefCell<Vec<SharedString>>>, vault: &Vault) {
    let names: Vec<SharedString> = vault.list().iter().map(|s| SharedString::from(*s)).collect();
    *full_names.borrow_mut() = names.clone();
    app.set_record_names(names_model(names));
}

/// Transition to locked and scrub every bit of UI state that could otherwise
/// linger on-screen or in a model after the `Session` (and its DEK) is
/// dropped. Shared by the `lock_now` callback (here) and the future OS-watcher
/// auto-lock path (D3b).
fn do_lock(app: &App, state: &Rc<RefCell<AppState>>, full_names: &Rc<RefCell<Vec<SharedString>>>) {
    state.borrow_mut().lock();
    app.set_revealed_value("".into());
    app.set_generated_value("".into());
    app.set_record_names(empty_names_model());
    app.set_selected("".into());
    app.set_clip_remaining(0);
    app.set_posture_authenticated(false);
    app.set_screen("unlock".into());
    full_names.borrow_mut().clear();
}

fn main() -> Result<(), slint::PlatformError> {
    let app = App::new()?;

    let dir = base_dir();
    let _ = std::fs::create_dir_all(&dir);
    let prefs_path = dir.join("prefs.txt");
    let loaded_prefs = std::fs::read_to_string(&prefs_path)
        .map(|s| Prefs::from_serialized(&s))
        .unwrap_or_default();
    let vault_path = match &loaded_prefs.last_vault_path {
        Some(p) => PathBuf::from(p),
        None => dir.join("vault.ztsv"),
    };

    // UI-thread state. Nothing here is unlocked yet -- that's D3a-2's job.
    let state = Rc::new(RefCell::new(AppState::Locked));
    let full_names: Rc<RefCell<Vec<SharedString>>> = Rc::new(RefCell::new(Vec::new()));
    let prefs = Rc::new(RefCell::new(loaded_prefs));

    // ---- Startup property population ---------------------------------
    // `dark` is aliased straight through to the Theme global (`in-out
    // property <bool> dark <=> Theme.dark;` in app.slint), so setting it here
    // is enough -- no separate `app.global::<Theme>()` call needed. `System`
    // has no OS dark-mode query wired up yet, so it's treated as dark for now.
    app.set_dark(matches!(prefs.borrow().theme, Theme::Dark | Theme::System));
    app.set_idle_timeout_secs(prefs.borrow().idle_timeout_secs.unwrap_or(0) as i32);
    app.set_hello_available(vaultgui::hello::available());
    app.set_vault_path(vault_path.display().to_string().into());

    if vault_path.exists() {
        app.set_screen("unlock".into());
        match LockedVault::load(&vault_path) {
            Ok(locked) => {
                let header = locked.header();
                app.set_hardware_bound(header.hardware_bound);
                app.set_has_recovery(header.recovery_wrap.is_some());
                app.set_provider_desc(describe_provider(header).into());
                app.set_posture(
                    if header.hardware_bound { "TPM-bound" } else { "Passphrase only" }.into(),
                );
            }
            Err(_) => {
                // File exists but couldn't be parsed (corrupt/foreign file) --
                // still let the user land on the unlock screen with a generic
                // posture rather than bouncing them to "create".
                app.set_hardware_bound(false);
                app.set_has_recovery(false);
                app.set_provider_desc("".into());
                app.set_posture("Unknown".into());
            }
        }
        // Pre-unlock posture is read from an unauthenticated header -- never
        // display it as verified until a real unlock succeeds (D3a-2).
        app.set_posture_authenticated(false);
    } else {
        app.set_screen("create".into());
    }

    // ---- Non-secret callbacks ------------------------------------------
    {
        let w = app.as_weak();
        let state = state.clone();
        let full_names = full_names.clone();
        app.on_lock_now(move || {
            let app = w.unwrap();
            do_lock(&app, &state, &full_names);
        });
    }

    {
        let w = app.as_weak();
        let prefs = prefs.clone();
        let prefs_path = prefs_path.clone();
        app.on_set_dark(move |value| {
            let app = w.unwrap();
            app.set_dark(value);
            let mut p = prefs.borrow_mut();
            p.theme = if value { Theme::Dark } else { Theme::Light };
            persist_prefs(&p, &prefs_path);
        });
    }

    {
        let w = app.as_weak();
        let prefs = prefs.clone();
        let prefs_path = prefs_path.clone();
        app.on_set_timeout(move |secs| {
            let app = w.unwrap();
            let mut p = prefs.borrow_mut();
            let normalized = if secs <= 0 { 0 } else { secs };
            p.idle_timeout_secs = if secs <= 0 { None } else { Some(secs as u64) };
            persist_prefs(&p, &prefs_path);
            drop(p);
            app.set_idle_timeout_secs(normalized);
        });
    }

    {
        let w = app.as_weak();
        app.on_select(move |name| {
            let app = w.unwrap();
            app.set_selected(name);
            app.set_revealed_value("".into());
        });
    }

    {
        let w = app.as_weak();
        app.on_mask(move || {
            let app = w.unwrap();
            app.set_revealed_value("".into());
        });
    }

    // ---- Secret-flow callbacks (D3a-2) ---------------------------------
    // Every typed secret is drained into a `SecretString` via
    // `input::drain_to_secret` immediately on entry to its callback -- no
    // secret is held as a plain `String`/`SharedString` past that point. The
    // sole documented exception is `revealed_value`/`generated_value`
    // (transient plaintext for on-screen display; scrubbed by `mask`/
    // `do_lock`). No `set_error` string below ever interpolates secret
    // material -- vaultcore's `Error` messages carry only names/paths/reasons.

    {
        let w = app.as_weak();
        let state = state.clone();
        let full_names = full_names.clone();
        let vault_path = vault_path.clone();
        app.on_unlock(move |passphrase, recovery| {
            let app = w.unwrap();
            let pass = input::drain_to_secret(&mut passphrase.to_string());
            match LockedVault::load(&vault_path) {
                Ok(locked) => {
                    let outcome = if recovery {
                        flow::unlock(locked, UnlockFactors::Recovery { recovery_passphrase: &pass })
                    } else {
                        flow::unlock(locked, UnlockFactors::TwoFactor { passphrase: &pass })
                    };
                    match outcome {
                        Ok(vault) => {
                            // Read header-derived posture + the record list off
                            // `vault` BEFORE it's moved into the Session below.
                            let names: Vec<SharedString> =
                                vault.list().iter().map(|s| SharedString::from(*s)).collect();
                            let hardware_bound = vault.header().hardware_bound;
                            let has_recovery = vault.header().recovery_wrap.is_some();
                            let provider_desc = describe_provider(vault.header());

                            *state.borrow_mut() = AppState::Unlocked(Session::new(vault));
                            *full_names.borrow_mut() = names.clone();
                            app.set_record_names(names_model(names));
                            app.set_hardware_bound(hardware_bound);
                            app.set_has_recovery(has_recovery);
                            app.set_provider_desc(provider_desc.into());
                            app.set_posture(posture_string(hardware_bound, has_recovery).into());
                            app.set_posture_authenticated(true);
                            app.set_error("".into());
                            app.set_screen("vault".into());
                        }
                        Err(_) => app.set_error(
                            "Unlock failed — wrong passphrase, or the vault/TPM is unavailable."
                                .into(),
                        ),
                    }
                }
                Err(e) => app.set_error(format!("Could not open vault: {e}").into()),
            }
        });
    }

    {
        let w = app.as_weak();
        let vault_path = vault_path.clone();
        app.on_create_vault(move |passphrase, confirm, allow_no_tpm, use_recovery, recovery_passphrase| {
            let app = w.unwrap();
            if passphrase != confirm {
                app.set_error("Passphrases do not match.".into());
                return;
            }
            let pass = input::drain_to_secret(&mut passphrase.to_string());
            let rec = if use_recovery {
                Some(input::drain_to_secret(&mut recovery_passphrase.to_string()))
            } else {
                None
            };
            match flow::create_vault(
                &vault_path,
                CreateOptions { allow_no_tpm, passphrase: pass, recovery_passphrase: rec },
            ) {
                Ok(outcome) => {
                    app.set_error("".into());
                    app.set_hardware_bound(outcome.hardware_bound);
                    app.set_has_recovery(outcome.has_recovery);
                    app.set_posture(
                        posture_string(outcome.hardware_bound, outcome.has_recovery).into(),
                    );
                    app.set_posture_authenticated(false);
                    app.set_screen("unlock".into());
                }
                Err(e) => app.set_error(format!("Could not create vault: {e}").into()),
            }
        });
    }

    {
        let w = app.as_weak();
        let state = state.clone();
        app.on_reveal(move |name| {
            let app = w.unwrap();
            let st = state.borrow();
            if let AppState::Unlocked(s) = &*st {
                match s.vault().get(&name) {
                    Ok(v) => app.set_revealed_value(v.expose_str().into()),
                    Err(e) => app.set_error(format!("Could not read secret: {e}").into()),
                }
            }
        });
    }

    {
        let w = app.as_weak();
        let state = state.clone();
        app.on_copy(move |name| {
            let app = w.unwrap();
            let st = state.borrow();
            if let AppState::Unlocked(s) = &*st {
                if let Ok(v) = s.vault().get(&name) {
                    let _ = clipboard::copy_with_autoclear(v.expose_str(), 15);
                    app.set_clip_remaining(15);
                }
            }
        });
    }

    {
        let w = app.as_weak();
        app.on_copy_generated(move || {
            let app = w.unwrap();
            let g = app.get_generated_value();
            if !g.is_empty() {
                let _ = clipboard::copy_with_autoclear(&g, 15);
                app.set_clip_remaining(15);
            }
        });
    }

    {
        let w = app.as_weak();
        let state = state.clone();
        let full_names = full_names.clone();
        let vault_path = vault_path.clone();
        app.on_add_secret(move |name, value| {
            let app = w.unwrap();
            let secret = input::drain_to_secret(&mut value.to_string());
            let mut st = state.borrow_mut();
            if let AppState::Unlocked(s) = &mut *st {
                match s.vault_mut().add(&name, secret) {
                    Ok(()) => {
                        let save_result = s.vault_mut().save(&vault_path);
                        refresh_names(&app, &full_names, s.vault());
                        match save_result {
                            Ok(()) => app.set_error("".into()),
                            Err(e) => app.set_error(
                                format!(
                                    "Change applied in memory but NOT saved to disk: {e}. Try the action again."
                                )
                                .into(),
                            ),
                        }
                    }
                    Err(vaultcore::Error::Duplicate(_)) => {
                        app.set_error(format!("A secret named \"{name}\" already exists.").into());
                    }
                    Err(e) => app.set_error(format!("{e}").into()),
                }
            }
        });
    }

    {
        let w = app.as_weak();
        let state = state.clone();
        let full_names = full_names.clone();
        let vault_path = vault_path.clone();
        app.on_rotate(move |name, value| {
            let app = w.unwrap();
            let secret = input::drain_to_secret(&mut value.to_string());
            let mut st = state.borrow_mut();
            if let AppState::Unlocked(s) = &mut *st {
                match s.vault_mut().upsert(&name, secret) {
                    Ok(()) => {
                        let save_result = s.vault_mut().save(&vault_path);
                        refresh_names(&app, &full_names, s.vault());
                        match save_result {
                            Ok(()) => app.set_error("".into()),
                            Err(e) => app.set_error(
                                format!(
                                    "Change applied in memory but NOT saved to disk: {e}. Try the action again."
                                )
                                .into(),
                            ),
                        }
                    }
                    Err(e) => app.set_error(format!("{e}").into()),
                }
            }
        });
    }

    {
        let w = app.as_weak();
        let state = state.clone();
        let full_names = full_names.clone();
        let vault_path = vault_path.clone();
        app.on_remove(move |name| {
            let app = w.unwrap();
            let mut st = state.borrow_mut();
            if let AppState::Unlocked(s) = &mut *st {
                s.vault_mut().remove(&name);
                let save_result = s.vault_mut().save(&vault_path);
                refresh_names(&app, &full_names, s.vault());
                match save_result {
                    Ok(()) => app.set_error("".into()),
                    Err(e) => app.set_error(
                        format!(
                            "Change applied in memory but NOT saved to disk: {e}. Try the action again."
                        )
                        .into(),
                    ),
                }
            }
            drop(st);
            app.set_selected("".into());
            app.set_revealed_value("".into());
        });
    }

    {
        let w = app.as_weak();
        app.on_generate(move |length, symbols| {
            let app = w.unwrap();
            let (pw, _bits_n) = vaultcore::passgen::generate_password(length.max(1) as usize, symbols);
            app.set_generated_value(pw.expose_str().into());
        });
    }

    {
        let w = app.as_weak();
        let full_names = full_names.clone();
        app.on_search(move |query| {
            let app = w.unwrap();
            let q = query.to_lowercase();
            let filtered: Vec<SharedString> = full_names
                .borrow()
                .iter()
                .filter(|n| n.to_lowercase().contains(q.as_str()))
                .cloned()
                .collect();
            app.set_record_names(names_model(filtered));
        });
    }

    {
        let w = app.as_weak();
        app.on_deprovision(move || {
            let app = w.unwrap();
            #[cfg(windows)]
            {
                match vaultcore::keyprovider::CngPcpProvider::deprovision() {
                    Ok(true) => app.set_error("TPM wrapping key deleted.".into()),
                    Ok(false) => app.set_error("No TPM wrapping key to delete.".into()),
                    Err(e) => app.set_error(format!("Deprovision failed: {e}").into()),
                }
            }
            #[cfg(not(windows))]
            {
                app.set_error("TPM deprovisioning is not available on this platform.".into());
            }
        });
    }

    // A native file-picker dialog is deferred (post-D3). Registered as an
    // explicit no-op rather than left unregistered, so the deferral is
    // documented intent rather than an accidental gap.
    app.on_pick_vault(move || {});

    // ---- Anti-capture (D3b-1) ------------------------------------------
    // The native HWND does not exist yet at this point: Slint's winit backend
    // creates the OS window lazily once the event loop actually starts
    // running (`WinitWindowAdapter::ensure_window`, called from winit's
    // `resumed()` callback), not synchronously during `App::new()`/`show()`.
    // Reading the raw window handle right here would find no window and
    // silently no-op. Scheduling a `Duration::ZERO` single-shot timer BEFORE
    // `app.run()` sidesteps that: timers only fire once the event loop is
    // pumping, by which point `resumed()` has already created the window, so
    // this fires on/near the very first iteration with a valid HWND in hand.
    #[cfg(windows)]
    {
        let w = app.as_weak();
        slint::Timer::single_shot(std::time::Duration::ZERO, move || {
            if let Some(app) = w.upgrade() {
                apply_anticapture(&app);
            }
        });
    }

    app.run()
}

/// Exclude the top-level window from screen capture (see
/// `vaultgui::anticapture`). Pulls the live Win32 `HWND` out of Slint via its
/// `raw-window-handle` 0.6 integration (the `raw-window-handle-06` Slint
/// feature); a failure to resolve a `Win32` handle (wrong backend, or called
/// before the window exists) is a silent no-op -- there is no user-facing
/// error to surface for "screenshots aren't blanked."
#[cfg(windows)]
fn apply_anticapture(app: &App) {
    use raw_window_handle::HasWindowHandle;

    if let Ok(h) = app.window().window_handle().window_handle() {
        if let raw_window_handle::RawWindowHandle::Win32(w) = h.as_raw() {
            let _ = vaultgui::anticapture::exclude_from_capture_hwnd(w.hwnd.get());
        }
    }
}
