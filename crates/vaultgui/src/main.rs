//! GUI entry point: builds the Slint `App`, loads non-secret prefs, populates
//! startup UI state, and wires every `App` callback. D3a-1 wired the
//! NON-SECRET layer (lock, theme, idle-timeout, record selection/mask,
//! navigation); D3a-2 (this pass) wires the SECRET-FLOW layer (`unlock`,
//! `create_vault`, `reveal`, `copy`, `copy_generated`, `add_secret`, `rotate`,
//! `remove`, `generate`, `search`, `deprovision`) plus `pick_vault` (an
//! intentional no-op — a native file-picker dialog is deferred).
//!
//! D3b-1 applied anti-capture (`WDA_EXCLUDEFROMCAPTURE`) to the top-level
//! window so screenshots/screen-share render it blank. D3b-2 (this pass)
//! spawns the OS watcher (`vaultgui::watcher`) so idle/lock/suspend events
//! post an `invoke_lock_now()` onto the UI thread, and adds a repeating 1s
//! timer that ticks `clip_remaining` down and refreshes `idle_remaining`
//! while unlocked.
slint::include_modules!();

// Scripted hold-mode for the memory-scraping verification harness
// (verify/dumper). A BIN module (not lib.rs) because it needs the `App` type
// generated above by `include_modules!()`. Compiled ONLY under
// `--features leaktest`; absent from a normal build.
#[cfg(feature = "leaktest")]
mod leaktest;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use slint::{ComponentHandle, SharedString, VecModel};
use vaultcore::flow::{self, describe_provider, CreateOptions, KdfStrategy, UnlockFactors};
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

/// Populate the pre-unlock posture props from a vault file's (unauthenticated)
/// header. Used at startup and after the user picks a different vault. Always
/// leaves `posture_authenticated = false` — this data is read from an
/// unauthenticated header and must never display as verified until a real unlock.
fn apply_locked_header(app: &App, path: &Path) {
    match LockedVault::load(path) {
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
            // File exists but couldn't be parsed (corrupt/foreign) -- still land
            // on unlock with a generic posture rather than bouncing to "create".
            app.set_hardware_bound(false);
            app.set_has_recovery(false);
            app.set_provider_desc("".into());
            app.set_posture("Unknown".into());
        }
    }
    app.set_posture_authenticated(false);
}

/// Transition to locked and scrub every bit of UI state that could otherwise
/// linger on-screen or in a model after the `Session` (and its DEK) is dropped.
/// Shared by the `lock_now` callback and the OS-watcher auto-lock path. Returns
/// to the "create" screen (not "unlock") if the vault file no longer exists, so
/// a first-run user who steps away mid-create isn't stranded on an unlock screen
/// for a vault that was never written.
fn do_lock(
    app: &App,
    state: &Rc<RefCell<AppState>>,
    full_names: &Rc<RefCell<Vec<SharedString>>>,
    vault_path: &Rc<RefCell<PathBuf>>,
) {
    state.borrow_mut().lock();
    app.set_revealed_value("".into());
    app.set_generated_value("".into());
    app.set_record_names(empty_names_model());
    app.set_selected("".into());
    app.set_clip_remaining(0);
    app.set_posture_authenticated(false);
    app.set_screen(if vault_path.borrow().exists() { "unlock" } else { "create" }.into());
    full_names.borrow_mut().clear();
}

fn main() -> Result<(), slint::PlatformError> {
    // Best-effort process hardening, applied as early as possible: Windows
    // exploit-mitigation policies (block extension-point / remote / low-integrity
    // DLL injection into this long-lived, DEK-holding process) and suppress the
    // crash UI. No-op on other platforms. See vaultcore::hardening.
    let _ = vaultcore::hardening::harden_process();

    // Verification-harness-only entry point (see leaktest.rs). Checked FIRST,
    // before any normal UI is built, so the harness can drive this process
    // into a precise state without ever running the real event loop. Not
    // present in a normal build (feature-gated).
    #[cfg(feature = "leaktest")]
    {
        let args: Vec<String> = std::env::args().collect();
        if let Some(pos) = args.iter().position(|a| a == "--leaktest") {
            if let Err(e) = leaktest::run_from_args(&args[pos + 1..]) {
                // vaultcore::Error/leaktest usage messages never carry secret
                // material, so this is safe to print verbatim.
                eprintln!("leaktest error: {e}");
                std::process::exit(1);
            }
            return Ok(());
        }
    }

    let app = App::new()?;

    let dir = base_dir();
    let _ = std::fs::create_dir_all(&dir);
    let prefs_path = dir.join("prefs.txt");
    let loaded_prefs = std::fs::read_to_string(&prefs_path)
        .map(|s| Prefs::from_serialized(&s))
        .unwrap_or_default();
    // Held in an `Rc<RefCell<_>>` so the "Choose…" picker can change which vault
    // the unlock/create/save paths target at runtime.
    let vault_path = Rc::new(RefCell::new(match &loaded_prefs.last_vault_path {
        Some(p) => PathBuf::from(p),
        None => dir.join("vault.ztsv"),
    }));

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
    app.set_hello_enabled(prefs.borrow().hello_enabled);
    app.set_vault_path(vault_path.borrow().display().to_string().into());

    if vault_path.borrow().exists() {
        app.set_screen("unlock".into());
        apply_locked_header(&app, vault_path.borrow().as_path());
    } else {
        app.set_screen("create".into());
    }

    // ---- Non-secret callbacks ------------------------------------------
    {
        let w = app.as_weak();
        let state = state.clone();
        let full_names = full_names.clone();
        let vault_path = vault_path.clone();
        app.on_lock_now(move || {
            let app = w.unwrap();
            do_lock(&app, &state, &full_names, &vault_path);
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
        let prefs = prefs.clone();
        let prefs_path = prefs_path.clone();
        app.on_set_hello(move |value| {
            let app = w.unwrap();
            let mut p = prefs.borrow_mut();
            p.hello_enabled = value;
            persist_prefs(&p, &prefs_path);
            drop(p);
            app.set_hello_enabled(value);
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
            match LockedVault::load(vault_path.borrow().as_path()) {
                Ok(locked) => {
                    let outcome = if recovery {
                        // Recovery input is a generated CODE: normalize (case /
                        // dashes / spacing tolerant) inside the shared helper.
                        flow::unlock_with_recovery_code(locked, pass.expose_str())
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
        app.on_create_vault(move |passphrase, confirm, allow_no_tpm, use_recovery| {
            let app = w.unwrap();
            if passphrase != confirm {
                app.set_error("Passphrases do not match.".into());
                return;
            }
            let pass = input::drain_to_secret(&mut passphrase.to_string());
            match flow::create_vault(
                vault_path.borrow().as_path(),
                CreateOptions {
                    allow_no_tpm,
                    passphrase: pass,
                    recovery: use_recovery,
                    kdf: KdfStrategy::Calibrate,
                },
            ) {
                Ok(outcome) => {
                    app.set_error("".into());
                    app.set_hardware_bound(outcome.hardware_bound);
                    app.set_has_recovery(outcome.has_recovery);
                    app.set_posture(
                        posture_string(outcome.hardware_bound, outcome.has_recovery).into(),
                    );
                    app.set_posture_authenticated(false);
                    // If an escrow was requested, reveal the generated code ONCE
                    // before moving on to unlock; otherwise go straight to unlock.
                    match outcome.recovery_code {
                        Some(code) => {
                            app.set_recovery_code(code.into());
                            app.set_screen("recovery-code".into());
                        }
                        None => app.set_screen("unlock".into()),
                    }
                }
                Err(e) => app.set_error(format!("Could not create vault: {e}").into()),
            }
        });
    }

    // Live passphrase-strength scoring for the create screen. Reads a transient
    // &str view of the typed passphrase (no owned secret copy is retained) and
    // drives the meter + submit gate. The floor depends on the factor choice.
    {
        let w = app.as_weak();
        app.on_check_strength(move |passphrase, allow_no_tpm| {
            let app = w.unwrap();
            let policy = if allow_no_tpm {
                vaultcore::strength::Policy::single_factor()
            } else {
                vaultcore::strength::Policy::two_factor()
            };
            match vaultcore::strength::check(passphrase.as_str(), &policy) {
                Ok(()) => {
                    let bits = vaultcore::strength::estimate(passphrase.as_str()).bits;
                    app.set_strength_ok(true);
                    app.set_strength_hint(format!("Strong enough (~{bits:.0} bits)").into());
                }
                Err(weakness) => {
                    app.set_strength_ok(false);
                    app.set_strength_hint(format!("Too weak — {weakness}").into());
                }
            }
        });
    }

    // Copy the one-time recovery code to the clipboard (30s auto-clear; longer
    // than a secret value's 15s because the code is longer to transcribe).
    {
        let w = app.as_weak();
        app.on_copy_recovery_code(move || {
            let app = w.unwrap();
            let code = app.get_recovery_code();
            if !code.is_empty() {
                let _ = clipboard::copy_with_autoclear(&code, 30);
                app.set_clip_remaining(30);
            }
        });
    }

    {
        let w = app.as_weak();
        let state = state.clone();
        app.on_reveal(move |name| {
            let app = w.unwrap();
            // Opt-in Windows Hello reveal gate (Settings). Gated on BOTH the
            // user's preference AND live availability -- if Hello was
            // enabled but the device later loses it (driver issue, disabled
            // in Windows), the gate is not enforced rather than permanently
            // locking reveal out. This never touches the KEK/passphrase
            // factor; it only stands in front of the on-screen reveal.
            if app.get_hello_enabled() && vaultgui::hello::available() {
                if !vaultgui::hello::verify("Reveal a secret in Zero-Trust Secrets") {
                    app.set_error(
                        "Windows Hello verification was declined — secret not revealed.".into(),
                    );
                    return;
                }
            }
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
                        let save_result = s.vault_mut().save(vault_path.borrow().as_path());
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
                        let save_result = s.vault_mut().save(vault_path.borrow().as_path());
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
                let save_result = s.vault_mut().save(vault_path.borrow().as_path());
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

    // Native "choose vault file" dialog. On selection we retarget every
    // path-consuming flow (unlock/create/save) at the chosen file, remember it
    // as `last_vault_path`, and refresh the pre-unlock posture from its header.
    {
        let w = app.as_weak();
        let vault_path = vault_path.clone();
        let prefs = prefs.clone();
        let prefs_path = prefs_path.clone();
        app.on_pick_vault(move || {
            let app = w.unwrap();
            // Pass the owner HWND so the picker is modal (disables this window
            // while it's open — no reentrant input on the screen behind it).
            if let Some(chosen) = vaultgui::dialog::choose_vault_file(main_hwnd(&app)) {
                app.set_vault_path(chosen.display().to_string().into());
                {
                    let mut p = prefs.borrow_mut();
                    p.last_vault_path = Some(chosen.display().to_string());
                    persist_prefs(&p, &prefs_path);
                }
                apply_locked_header(&app, &chosen);
                app.set_screen("unlock".into());
                app.set_error("".into());
                *vault_path.borrow_mut() = chosen;
            }
        });
    }

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

    // ---- Auto-lock watcher (D3b-2) --------------------------------------
    // `watcher::spawn` owns a background thread on Windows (message-only
    // window polling GetLastInputInfo + WTS/power notifications) and is a
    // no-op handle on other platforms. Its `on_lock` closure runs on THAT
    // thread, never the UI thread, so it must not touch `state`/`Rc` secrets
    // directly -- it only posts an `invoke_lock_now()` onto the UI thread via
    // `slint::invoke_from_event_loop`, which runs the callback wired above
    // (the one holding the `Rc<RefCell<AppState>>` and calling `do_lock`).
    // `slint::Weak<App>` is `Send`, so it's the only thing that crosses the
    // thread boundary here.
    //
    // The timeout is read ONCE here at startup. If the user changes the
    // auto-lock timeout in Settings mid-session, the already-running watcher
    // keeps using the startup value; the new value takes effect on the NEXT
    // launch. Accepted slice-2 limitation (see D3b-2 report).
    let timeout = prefs.borrow().idle_timeout_secs.map(std::time::Duration::from_secs);
    let watcher = {
        let w = app.as_weak();
        vaultgui::watcher::spawn(timeout, move |_reason| {
            let w = w.clone();
            let _ = slint::invoke_from_event_loop(move || {
                if let Some(app) = w.upgrade() {
                    app.invoke_lock_now();
                }
            });
        })
    };

    // ---- Countdown timer (D3b-2) -----------------------------------------
    // One repeating 1s Slint timer drives both on-screen countdowns:
    //   - `clip_remaining`: ticked down here for display only. The actual
    //     clipboard CLEAR is performed independently by the detached
    //     PowerShell helper spawned in `clipboard::copy_with_autoclear` (B5);
    //     this timer never touches the clipboard itself.
    //   - `idle_remaining`: recomputed from the live OS idle time (while
    //     unlocked) so the on-screen "locks in Ns" reflects what the watcher
    //     thread above is about to act on.
    // Bound to `_countdown` (not `_`) so the Timer stays alive across
    // `app.run()` -- a dropped `slint::Timer` stops firing.
    let _countdown = slint::Timer::default();
    {
        let w = app.as_weak();
        let idle_timeout = prefs.borrow().idle_timeout_secs;
        _countdown.start(
            slint::TimerMode::Repeated,
            std::time::Duration::from_secs(1),
            move || {
                if let Some(app) = w.upgrade() {
                    let c = app.get_clip_remaining();
                    if c > 0 {
                        app.set_clip_remaining(c - 1);
                    }
                    if app.get_posture_authenticated() {
                        if let Some(t) = idle_timeout {
                            let idle = vaultgui::watcher::idle_duration().as_secs();
                            app.set_idle_remaining(t.saturating_sub(idle) as i32);
                        }
                    }
                }
            },
        );
    }

    app.run()?;

    // Clean thread join for the watcher's background window/thread. Errors
    // from `app.run()` above already propagated via `?`; this only runs on
    // the normal shutdown path.
    watcher.stop();

    Ok(())
}

/// The top-level window's Win32 `HWND` (as an `isize`), pulled out of Slint via
/// its `raw-window-handle` 0.6 integration (the `raw-window-handle-06` Slint
/// feature). Returns `0` if it can't be resolved (wrong backend, or called
/// before the window exists). `0` is a safe sentinel for both consumers:
/// anti-capture skips, and the file dialog treats it as "no owner".
#[cfg(windows)]
fn main_hwnd(app: &App) -> isize {
    use raw_window_handle::HasWindowHandle;

    if let Ok(h) = app.window().window_handle().window_handle() {
        if let raw_window_handle::RawWindowHandle::Win32(w) = h.as_raw() {
            return w.hwnd.get();
        }
    }
    0
}

#[cfg(not(windows))]
fn main_hwnd(_app: &App) -> isize {
    0
}

/// Exclude the top-level window from screen capture (see
/// `vaultgui::anticapture`). A missing HWND (`0`) is a silent no-op -- there is
/// no user-facing error to surface for "screenshots aren't blanked."
#[cfg(windows)]
fn apply_anticapture(app: &App) {
    let hwnd = main_hwnd(app);
    if hwnd != 0 {
        let _ = vaultgui::anticapture::exclude_from_capture_hwnd(hwnd);
    }
}
