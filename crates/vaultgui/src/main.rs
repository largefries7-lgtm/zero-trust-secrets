//! GUI entry point: builds the Slint `App`, loads non-secret prefs, populates
//! startup UI state, and wires the NON-SECRET callback layer (lock, theme,
//! idle-timeout, record selection/mask, navigation). No secret material is
//! touched here: the secret-flow callbacks (`unlock`, `create_vault`,
//! `reveal`, `copy`, `add_secret`, `rotate`, `remove`, `generate`,
//! `deprovision`) and the OS watcher / anti-capture wiring are deferred to
//! later tasks (D3a-2, D3b) and are simply left unregistered for now (an
//! unregistered Slint callback is an inert no-op).
slint::include_modules!();

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use slint::{ComponentHandle, SharedString, VecModel};
use vaultcore::flow::describe_provider;
use vaultcore::vault::LockedVault;
use vaultgui::prefs::{Prefs, Theme};
use vaultgui::session::AppState;

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

/// An empty `[string]` model, for scrubbing `record_names` on lock.
fn empty_names_model() -> slint::ModelRc<SharedString> {
    Rc::new(VecModel::<SharedString>::from(vec![])).into()
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
        let prefs = prefs.clone();
        let prefs_path = prefs_path.clone();
        app.on_set_timeout(move |secs| {
            let mut p = prefs.borrow_mut();
            p.idle_timeout_secs = if secs <= 0 { None } else { Some(secs as u64) };
            persist_prefs(&p, &prefs_path);
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

    app.run()
}
