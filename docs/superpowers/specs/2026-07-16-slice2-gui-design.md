# Zero-Trust Local Secrets Manager — Slice 2: Desktop GUI Design

- **Date:** 2026-07-16
- **Status:** Draft for review
- **Author:** Riley (with Claude Code)
- **Scope:** Slice 2 of N — a desktop GUI (`vaultgui`) on top of the existing
  `vaultcore` library, becoming the primary user surface. The `vaultctl` CLI stays
  in the repo as a testing/automation tool. No changes to vaultcore's crypto.

> Read alongside the slice-1 design + as-built threat model:
> [`2026-07-14-zero-trust-secrets-core-design.md`](2026-07-14-zero-trust-secrets-core-design.md)
> (§16 is the authoritative two-factor model this slice builds on).

---

## 1. Purpose & the central architectural shift

Slice 1 delivered a headless security core whose two load-bearing, *empirically
verified* claims are (a) hardware-bound two-factor key protection and (b) plaintext
secrets provably never linger in process RAM once unneeded. Slice 2 puts a modern,
clean desktop GUI on that core **without weakening either claim**.

The single biggest new risk surface is a deliberate inversion of the CLI's model:

- **`vaultctl` is stateless** — it obtains the DEK fresh per command and zeroizes it
  before exit, so the DEK never sits in RAM at rest.
- **`vaultgui` is the long-lived in-RAM DEK holder** the slice-1 design named as
  slice 2's job (§15). While unlocked, the DEK and decrypted values live in process
  RAM for the duration of the session.

Everything security-relevant in this slice flows from managing that window: hold the
DEK in exactly one place, for the minimum time, and destroy it aggressively
(auto-lock) on every signal that the user has stepped away.

### Non-negotiable invariants (acceptance criteria, rank ABOVE any visual goal)

1. Reuse `vaultcore` unchanged for all crypto/format/key-provider logic. New needs
   are added to vaultcore **with tests**, never inlined in the UI.
2. All plaintext (passphrases, secret values, generated passwords, revealed values)
   lives only in `SecretString`/`SecretBytes`. Never in `String`, `format!`, logs,
   error messages, telemetry, or window titles.
3. No secrets on argv, ever.
4. Input-field hygiene is a known hard problem, confronted honestly (§5): pull text
   into a `SecretString` as early as possible, clear the field, and **document the
   residual copies the toolkit/OS retain**. Do not claim the input path is clean.
5. Clipboard: stdin-fed copy, auto-clear ~15s, verify-before-clear, live countdown.
6. Anti-capture: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`; masked by
   default, reveal only on explicit action, re-mask on blur/lock.
7. Fail closed and honestly: mirror the CLI's trust boundaries; unauthenticated
   pre-unlock reads (names, seal-status) are labelled as such in the UI.
8. No network. Zero network I/O, zero auto-update, zero crash reporting.

---

## 2. Environment & decisions (2026-07-16)

| Fact | Value | Consequence |
|------|-------|-------------|
| OS | Windows 11 IoT Enterprise LTSC 2024 (26100) | Windows-first, consistent with slice 1 |
| Rust / Cargo | 1.96.0 | Build stack ready |
| GUI toolkit | **Slint** (pure-Rust, retained/declarative) | Named in slice-1 §1; best theming for a premium/trustworthy look; single-process (no separate renderer holding plaintext); real Win32 `HWND` for anti-capture |

**Decisions taken during brainstorming:**

- **Toolkit = Slint.** Rejected: a webview stack (Tauri) — plaintext would live in a
  separate WebView2/Edge process we cannot dump or scrub, and it adds a network/update
  surface (violates invariant #8). egui/Iced were viable pure-Rust alternatives;
  Slint chosen for theming/aesthetic fit and alignment with the slice-1 doc.
- **In scope this slice:** the full baseline lifecycle (below) **plus** OS-event
  auto-lock (session lock + suspend, not only idle) **plus** Windows Hello as an
  optional user-presence gate.
- **Deferred to a later slice:** system tray / minimize-to-tray, entropy visualizer
  (the honest numeric entropy estimate is kept), encrypted metadata names, PCR-policy
  sealing. (See §9.)
- **Session architecture = "Option C":** the `Vault`/DEK is owned solely on the UI
  thread; a lightweight watcher thread is a pure OS-event source that posts lock
  *events* and never touches secrets (§4).

### Baseline lifecycle (must-have)

create-vault (two-factor / `--allow-no-tpm` / optional recovery escrow) → unlock
(two-factor or recovery) → main vault view (filter names, add / rotate / remove) →
click-to-reveal → copy-to-clipboard with countdown → generate password (honest
entropy) → settings/status (binding, factors, escrow state, provider, auto-lock
timeout, deprovision) → lock (idle auto-lock + explicit "Lock now").

---

## 3. Architecture & crate layout

New workspace member `crates/vaultgui`. Module boundaries are chosen so every
non-UI unit is testable **without a window**:

```
crates/vaultgui/
  build.rs            # slint-build compiles the .slint UI
  ui/*.slint          # declarative UI: theme + create/unlock/vault/settings screens
  src/
    main.rs           # wiring only: build window, apply anti-capture, spawn watcher, run loop
    session.rs        # AppState { Locked, Unlocked(Session) }; Session owns the one Vault
    autolock.rs       # PURE reducer: inputs -> Lock | Stay   [heavily unit-tested]
    watcher/          # OS event SOURCE only (never holds secrets):
      mod.rs          #   message-only Win32 window: WM_WTSSESSION_CHANGE, WM_POWERBROADCAST
                      #   + GetLastInputInfo idle poll; posts Lock via invoke_from_event_loop
    clipboard.rs      # stdin-fed copy + verify-before-clear + countdown model  [timing tested]
    hello.rs          # Windows Hello UserConsentVerifier gate (app/reveal presence)
    anticapture.rs    # SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE) on the HWND
    input.rs          # field-text -> SecretString marshalling + field-clear helpers
    prefs.rs          # non-secret prefs only (auto-lock timeout, theme override, last vault path)
  tests/              # session/autolock/clipboard-timing/input-marshalling unit tests
```

### `vaultcore` additions (small, tested — so no flow is reimplemented in the UI)

Two security-relevant flows currently live **inside the CLI's `main.rs`**, not the
library. The GUI must not copy-paste them; instead they move into vaultcore:

1. **`vaultcore::passgen`** — lift the rejection-sampling generator from
   `vaultctl/src/main.rs` (`gen_password`) into vaultcore with its tests. Reused by
   both CLI and GUI (invariant #1: "reuse the generator").
2. **`vaultcore::flow`** — lift the create orchestration (`cmd_init`:
   TPM open→seal→`envelope::wrap_dek`→`VaultHeader::new_v2`→`save`) and the unlock
   orchestration (`unlock_vault`: TPM unseal→`unlock_two_factor` / `unlock_recovery`)
   into tested library functions. The GUI calls these rather than re-orchestrating
   TPM + envelope calls itself.
3. **Provider-describe helper** — lift `active_provider_describe` so the GUI status
   screen and CLI emit identical, honest provider strings.

The CLI **may** be migrated onto these helpers to dedupe, but only as a clean lift;
the CLI's behavior and role as automation tool are unchanged. No crypto changes to
the audited core — only extraction of existing flows into reusable, tested functions.
The stale `vaultctl migrate` comment in `vault.rs:29-31` is fixed in this pass (no
such command exists; v1 vaults must be recreated).

---

## 4. Session & auto-lock state machine (the core new risk surface)

```
        unlock success (MAC verified, fail-closed)
Locked ───────────────────────────────────────────▶ Unlocked(Session{ vault: Vault })
   ▲                                                        │
   │   Lock trigger: Vault::lock() (zeroize DEK)            │
   │   + drop Session + scrub UI-visible secret state       │
   └────────────────────────────────────────────────────────┘
```

- **Single ownership.** The `Vault` (hence the DEK) exists only inside
  `AppState::Unlocked(Session)`, owned on the UI thread. It is never cloned, never
  serialized, never sent across a thread boundary.
- **Lock triggers** (any one → immediate lock):
  - **Idle timeout** — default **5 min**, configurable; measured with
    `GetLastInputInfo` (system-wide idle, so "walked away" counts even if the app has
    focus).
  - **Workstation lock** — `WM_WTSSESSION_CHANGE` / `WTS_SESSION_LOCK` (via
    `WTSRegisterSessionNotification`).
  - **Sleep/suspend** — `WM_POWERBROADCAST` / `PBT_APMSUSPEND`.
  - **Explicit "Lock now"** — always one click / keyboard shortcut away.
  - (Minimize-to-tray trigger deferred with the tray feature.)
- **Pure reducer (`autolock.rs`).** `decide(now, last_input, timeout, os_events,
  manual) -> Lock | Stay`. No clock/OS calls inside; time and events are injected, so
  unit tests cover the idle boundary, os-event immediacy, timeout-disabled, and
  manual-lock cases deterministically.
- **Watcher thread.** Owns a **message-only** Win32 window that receives the OS
  notifications, and polls idle. On any trigger it calls
  `slint::invoke_from_event_loop` to post a `Lock` event to the UI thread. It holds
  **no** secret material — it is purely an event source.
- **On lock, scrub both layers.** vaultcore zeroizes the DEK (Session drop →
  `Vault::lock()`); **additionally** the UI explicitly clears every Slint model/string
  that held a revealed value (revealed fields set back to masked/empty; any generated
  password buffer dropped). Record *names* remain (non-secret authenticated metadata).
  The residual Slint retains after this scrub is measured and reported by the harness
  (§7) and documented (§5), not hidden.

---

## 5. Security surfaces & honest residuals

### 5.1 Input-field hygiene (invariant #4 — the hard problem)

**What we do:** passphrase/value fields are password-mode (no echo of the secret).
On submit — or on each change, as early as possible — `input.rs` copies the field
text into a `SecretString` and immediately sets the field's text to empty.

**Residual we CANNOT scrub, stated plainly:** Slint's `LineEdit` stores the edited
text in an internal `SharedString`. Editing can reallocate that buffer, leaving prior
un-zeroized heap copies; clearing the field drops the *current* buffer but does not
zeroize past copies, and Slint owns the glyph/layout caches. The OS text stack (IME
composition, edit undo) may retain copies outside our address space entirely. We
minimize exposure (early extraction, field clear, password mode) but **do not claim
the input path is clean.** This is an honest improvement over the CLI's `prompt.rs`
(which read into a growing `String`), not a perfection claim. The `gui-post-autolock`
harness scenario (§7) measures what actually survives.

### 5.2 Clipboard (invariant #5)

Reuse the CLI's pattern (`clip.rs`): the secret is fed to the clipboard via **stdin**
(never argv), and a detached helper clears it after ~15s. Improvements this slice:

- **Verify-before-clear.** The clear step confirms the clipboard still holds our value
  before overwriting it, so a value the user copied in the meantime is not destroyed.
  The expected value reaches the helper via stdin (never argv), matching the no-argv rule.
- **Absolute `System32` paths** for `clip`/`powershell` (fixes the PATH-lookalike
  finding from the slice-1 CLI review — no earlier-in-`PATH` binary can receive the secret).
- **Live countdown** surfaced in the UI (a model value ticked on the UI thread).

The OS clipboard is a separate process's memory and remains out of scope for the heap
assertion, exactly as documented for the CLI.

### 5.3 Anti-capture (invariant #6)

After window creation, obtain the `HWND` (via `raw-window-handle`) and call
`SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)` so screenshots and
screen-share render the window blank. Secret values are masked by default; reveal is
explicit (click-to-reveal), transient, and re-masks on blur and on lock. **Documented
limits:** this defeats screen capture, not a camera pointed at the display; and
accessibility APIs (screen readers) can read a revealed field's contents — so reveal
stays user-initiated and short-lived, and the a11y/anti-capture tradeoff is stated in
the docs rather than silently resolved either way.

### 5.4 Windows Hello (optional, in scope)

An optional gate using WinRT `UserConsentVerifier::RequestVerificationAsync`.
**Precise framing (non-negotiable):** Hello gates *access to the app* (and, if
enabled, re-challenges before a reveal). It **does not** contribute to the KEK — the
`Argon2id(passphrase)` factor is unchanged, and the vault file is exactly as strong
with or without Hello. If Hello is unavailable or the user declines, the app still
unlocks via the passphrase (the real factor). We never weaken the crypto to add a
biometric convenience. This framing is surfaced in the UI and the threat-model docs.

---

## 6. Screens & visual direction

All screens are backed by existing vaultcore operations via the §3 helpers.

- **Locked / unlock.** Vault-path picker (remembers last path in prefs); masked
  passphrase; "Unlock" (two-factor: TPM auto-unseal + passphrase) with a "Use recovery
  passphrase" alternate path. The security-posture badge (2FA / passphrase-only /
  recovery-enabled), read from the header, is shown but **labelled unauthenticated
  until unlock** (invariant #7).
- **First-run / create.** Choose two-factor (default) vs `--allow-no-tpm`
  passphrase-only, with the **same loud honesty the CLI uses** about what each choice
  defends against; optional recovery escrow with its explicit theft-vs-survivability
  warning; passphrase + confirm.
- **Main vault view (unlocked).** Searchable/filterable list of record **names**
  (fuzzy filter); header shows posture + prominent **Lock now** + idle countdown;
  per-record: reveal (masked default), copy (countdown), rotate (`upsert`), remove
  (confirm). Add-secret affordance. Names are authenticated here (unlock verified the MAC).
- **Generator.** Length + symbols; honest entropy bits; generates into a locked
  buffer; copy or insert as a record value.
- **Settings / status.** Hardware-binding status, factors, recovery-escrow state,
  honest provider description, auto-lock timeout, Hello toggle, and **deprovision**
  (destructive; typed-`DELETE` confirmation mirroring the CLI).

**Visual language.** Calm, dense-but-uncluttered; strong typographic hierarchy;
generous whitespace; keyboard-first (every action has a shortcut; focus rings always
visible). OS-following light/dark with a manual override. Locked vs unlocked is
visually distinct (restrained/monochrome when locked; an active accent when unlocked),
and the security posture is always visible, never buried. Motion is limited to
functional state transitions and the clipboard countdown — no decorative flourish that
would undercut a security tool's need to read as trustworthy. Accessibility: sufficient
contrast, focus rings, screen-reader labels — reconciled with §5.3 (reveal is the only
moment a value is exposed to a11y APIs, and that tradeoff is documented). The concrete
visual system (palette, type scale, spacing) is produced via the frontend-design skill
at build time.

---

## 7. Memory-scraping harness extension

Extends `verify/` with the same methodology: **positive control** + **per-dump
sentinel** (a non-secret record name that MUST appear in a vault-loading dump, proving
the dump+scan pipeline is live for that dump), scanning for the canary in UTF-8 and
UTF-16LE via the existing `OpenProcess` + `MiniDumpWriteDump` pipeline.

**Driving a GUI headlessly.** A `leaktest` cargo feature adds a scripted hold-mode
(analogous to the CLI's `__hold-*`) that drives the app **programmatically** — no user
input — using a feature-gated test hook: load a throwaway vault, unlock with a known
passphrase, and (per scenario) reveal or reveal-then-auto-lock, then print `READY` and
block on stdin so the dumper can capture the process. The app runs its real Slint event
loop (software renderer; hidden/minimized window) so the dump reflects real widget state.

**New scenarios (CLI scenarios retained):**

| Scenario | State at dump | Expectation |
|----------|---------------|-------------|
| `gui-locked` | window built, vault loaded, **not** unlocked | canary **0**; sentinel ≥ 1 |
| `gui-post-autolock` | unlock → reveal → **auto-lock** → dump | canary in vaultcore buffers **0**; Slint widget residual **reported honestly** (see below); sentinel ≥ 1 |
| `gui-leak` (control) | canary kept in a plain never-zeroized `String` across the dump | canary ≥ 1 |

**Honest reporting.** For `gui-post-autolock` we first try to reach zero by explicitly
clearing Slint models/strings on lock (§4). If Slint retains a shaped-glyph/`SharedString`
copy of the revealed value that survives that scrub, the harness **reports that non-zero
number** rather than hiding the scenario, and the docs record it. The pass criterion for
the *vaultcore-owned* buffers is zero; the Slint-owned residual is a measured, documented
number, consistent with the mission's "report honestly rather than hide."

`verify/run.sh` and the dumper gain the GUI scenarios; `verify/TEST_PLAN.md` is updated
with the new table and the honest-residual note.

---

## 8. Testing strategy (TDD where testable)

- **Unit (no window):** `autolock` reducer (idle boundary, OS-event immediacy,
  disabled timeout, manual lock); clipboard timing/verify-before-clear logic;
  `input.rs` field→`SecretString` marshalling; `prefs` load/save of non-secret values;
  `vaultcore::passgen` (moved with its tests) and `vaultcore::flow` (create/unlock
  round-trips, wrong-passphrase fails closed, `--allow-no-tpm` path).
- **Integration:** full lifecycle against a real throwaway vault via the flow helpers;
  recovery-path unlock; wrong passphrase fails closed; TPM path exercised on hardware
  that has one.
- **Verification:** the §7 harness scenarios, with the positive control still firing.
- **CI:** a new **windows-latest** job builds + tests the whole workspace including
  `vaultgui` (compile gate for the Win32/Slint/WinRT code, which the existing
  ubuntu-only job never compiles). The memory harness stays a documented manual step.

Test-first cadence matches the repo's existing git history.

---

## 9. Threat model deltas (to be finalized as-built)

### Newly defended / improved
- **Aggressive auto-lock** shrinks the unlocked window: idle, workstation lock, and
  suspend each zeroize the DEK immediately; explicit Lock now is always available.
- **Anti-capture** blanks the window to screenshots/screen-share.
- **Clipboard verify-before-clear** + absolute paths close two slice-1 CLI findings.
- **Optional Hello** adds a user-presence gate without touching the crypto.

### New surfaces NOT fully defended (stated honestly)
- **Long-lived DEK in RAM while unlocked.** By construction the GUI holds the DEK for
  the session; a debugger/injection on the live unlocked process can read it. This is
  the same userspace ceiling as slice 1, now with a longer window (mitigated, not
  closed, by auto-lock).
- **Input-field residual (§5.1).** Slint/OS retain un-zeroizable copies of typed text.
- **Revealed-value widget residual (§5.2/§7).** Whatever Slint keeps after our on-lock
  scrub — measured and reported, not assumed zero.
- **Hello is an app gate, not a KEK factor** — it does not harden the vault file.
- **Anti-capture covers screen capture, not a camera; a11y APIs can read revealed values.**

### Unchanged ceiling (from slice-1 §16)
Kernel compromise, debugger on the live unlocked process, cold-boot on an unlocked
machine — cannot be closed from userspace; not pretended otherwise.

### Consciously deferred (with reason)
- **System tray / minimize-to-tray** — convenience; not security-load-bearing.
- **Entropy visualizer** — the honest numeric estimate already meets the requirement.
- **Encrypted metadata names, PCR-policy sealing, KEK/recovery rotation** — carried
  forward from slice 1; none is a currently-exploitable hole.

---

## 10. Documentation deliverables

- **This spec** + an as-built "Slice 2" section appended after implementation (repo
  convention from slice-1 §15–17): what changed, defended, NOT defended, deferred.
- **README** — GUI build/run, new surfaces, updated layout.
- **SECURITY.md** — threat model extended for the long-lived-DEK and input-field
  surfaces; empirical-verification section updated to include the GUI scenarios and
  their honest numbers.
- **Fix** the stale `vaultctl migrate` comment in `vaultcore/src/vault.rs`.

---

## 11. Definition of done

- `cargo build` / `cargo test` green across the workspace; new logic has tests.
- The GUI performs the full lifecycle (create → unlock → add/rotate/remove → get →
  copy → lock) against a real vault, TPM path included on hardware that has one.
- The extended memory harness runs and reports honest numbers for the `gui-locked` and
  `gui-post-autolock` states, with the positive control still firing.
- Threat-model docs updated truthfully. No claim in the UI or docs outruns what the
  code and harness actually demonstrate.

## 12. Explicitly out of scope

Cloud sync, browser extensions, mobile, multi-user/sharing, autofill; any change that
moves crypto out of vaultcore or weakens the two-factor KEK; defeating the stated
ceiling (kernel, live-process debugger, cold-boot).

---

## 13. As-built notes — Slice 2 (2026-07-17)

The GUI was built, wired to vaultcore through the lifted `flow`/`passgen` helpers, and
unit-tested at the engine layer. This section is the as-built delta over §§1–12,
following the slice-1 convention (see the slice-1 spec §§15–17): what changed, what's
defended, what honestly is not, and what's deliberately deferred. Where this section
differs from the design body above, this section is authoritative.

### What changed
- New crate `crates/vaultgui` (lib + bin, Slint 1.17.1). **Engine** (window-free,
  unit-tested): a pure `autolock` reducer; `session` (single-owner
  `AppState::Unlocked(Session)` holding the Vault/DEK); `input::drain_to_secret`;
  `prefs` (non-secret, hand-rolled codec, zero new deps); `clipboard` (countdown +
  verify-before-clear + absolute `System32` paths + `CREATE_NO_WINDOW`). **Windows
  FFI:** `anticapture` (`SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`); `watcher`
  (message-only window: WTS session-lock + suspend + `GetLastInputInfo` idle → posts a
  lock to the UI thread); `hello` (Windows Hello `UserConsentVerifier` — app/reveal
  gate only). **UI:** `theme` (light/dark tokens), four screens (create/unlock/vault/
  settings), full engine↔UI wiring.
- `vaultcore` additions (tested, no crypto change): `passgen` + `flow`
  (create/unlock/describe) lifted out of the CLI, per §3; the CLI now shares those
  flows instead of duplicating them.
- The session model realizes the design's "Option C" (§4) as specified: the GUI is
  the long-lived in-RAM DEK holder; the DEK lives **only** on the UI thread; the
  watcher is a pure event source — only a `Weak<App>` crosses the thread boundary, no
  secret material. Auto-lock triggers: idle (`GetLastInputInfo`, default 5 min,
  configurable), workstation lock, sleep/suspend, and an always-available "Lock now".
  On lock, the `Session` drops (DEK zeroized) **and** the revealed/generated Slint
  properties are explicitly cleared (§4).

### Defended (as-built)
- **Aggressive auto-lock** shrinks the unlocked window: idle, workstation lock, and
  suspend each zeroize the DEK immediately, alongside an always-available manual
  "Lock now".
- **Anti-capture** blanks the window to screenshots and screen-share
  (`WDA_EXCLUDEFROMCAPTURE`).
- **Clipboard verify-before-clear + absolute `System32` paths** close two findings
  from the slice-1 CLI review: the clear step no longer stomps a value the user
  copied in the meantime, and no earlier-in-`PATH` binary can intercept the secret.
- **Optional Windows Hello** adds a user-presence gate on app entry/reveal without
  touching the crypto.

### NOT defended (honest ceiling)
- **Long-lived DEK in RAM while unlocked.** By construction the GUI holds the DEK for
  the whole session; a debugger or code injection on the live unlocked process can
  read it. This is the same userspace ceiling as slice 1 (its CLI held the DEK only
  per-command) — slice 2 trades a much longer exposure window for usability, and
  auto-lock **mitigates**, but does not **close**, that window.
- **Input-field residual.** Slint's `LineEdit` `SharedString` storage and the OS
  IME/undo stacks retain copies of typed text we cannot zeroize (design invariant
  #4). We minimize exposure — drain to a `SecretString` on submit, then clear the
  field — but do not claim the input path is clean.
- **Revealed-value widget residual.** After `do_lock` clears the Slint property, the
  freed `SharedString` buffer can still hold the revealed plaintext until the
  allocator reuses it. This is **measured** by the `gui-post-autolock` harness
  scenario and **reported honestly** — not asserted zero. See `verify/TEST_PLAN.md`.
- **Hello is an app/reveal presence gate, not a KEK factor.** It does not harden the
  vault file; the `Argon2id(passphrase)` factor is exactly as strong with or without
  Hello enabled.
- **Anti-capture covers screen capture, not a camera pointed at the display; and
  accessibility APIs can read a revealed value while it is shown** (reveal remains
  user-initiated and transient, per §5.3).

### Unchanged ceiling (from slice-1 §16)
Kernel compromise, a debugger attached to the live unlocked process, and cold-boot on
an already-unlocked machine carry forward unchanged — none of these is closable from
userspace, and slice 2 does not pretend otherwise.

### Consciously deferred (with reason)
- **System tray / minimize-to-tray** — convenience, not security-load-bearing.
- **Entropy visualizer** — the honest numeric entropy estimate already meets the
  requirement.
- **Encrypted metadata names** — carried forward from slice 1; not a currently
  exploitable hole.
- **PCR-policy sealing** — still a CNG limitation (slice-1 §15); needs a `tss-esapi`
  backend.
- **Dynamic auto-lock timeout** — a Settings change to the idle timeout takes effect
  on next launch, not live mid-session.
- **Native file-open dialog for the vault-path picker** — `pick_vault` is a stub; the
  vault path defaults to `%APPDATA%\ZeroTrustSecrets\vault.ztsv`.
- **Scrubbing Slint's own retained-render residual** — not achievable without owning
  the toolkit's internals; measured and disclosed instead (see above and §7).

### Verification honesty
The GUI is compile-verified and structurally code-reviewed. The live lifecycle, the
visual pass, and the memory harness (`gui-locked` / `gui-post-autolock` / `gui-leak`)
require real hardware (a display, a TPM for the two-factor/Hello paths, and
`MiniDumpWriteDump`) and are run there — see `verify/TEST_PLAN.md` for the harness
design, the pass criteria, and the recorded result (including whether the GUI
scenarios have been executed yet in a given environment). No claim in this section
outruns what the code and the harness actually demonstrate.
