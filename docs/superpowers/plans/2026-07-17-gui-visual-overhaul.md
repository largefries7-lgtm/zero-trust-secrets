# "Command Vault" GUI Visual Overhaul — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Re-skin the `vaultgui` Slint GUI into a premium dark "command vault" HUD — cyan+amber duotone, dark glass panels, a glowing radial vault dial (reused as the live auto-lock gauge), and refined motion — with **zero changes to security behavior, crypto, or app flows**.

**Architecture:** Purely presentational. Rewrite `theme.slint` (tokens) and `widgets.slint` (shared kit + a new `Dial`), then recompose the four screens + `app.slint` to use them. `main.rs`/`vaultcore` are untouched except binding the dial to *existing* auto-lock properties. Every task ends compiling with zero warnings.

**Tech Stack:** Slint 1.17 (declarative UI, `Path`/rotation/animation), system fonts (Segoe UI + Consolas). No new dependencies.

## Global Constraints

- **No security/crypto/flow change.** DEK single-ownership, `SecretString` marshalling, fail-closed unlock, `SetWindowDisplayAffinity` anti-capture, clipboard verify-before-clear, Hello reveal-gate, `do_lock` scrubbing — all unchanged. No secret in any new place; record NAMES stay non-secret metadata; secret VALUES stay masked-by-default / click-to-reveal.
- **No new dependencies. System fonts only** (`Segoe UI`, `Consolas`). No image/font assets.
- **App-level property/callback contract in `app.slint` is unchanged** — same 18 properties + 15 callbacks; screens keep their existing `in`/`callback` signatures so `main.rs` bindings still resolve.
- **Every task must compile with ZERO warnings** (`cargo build -p vaultgui --locked`) and keep the **20 vaultgui lib tests passing** (`cargo test -p vaultgui --lib --locked`).
- **Verification model:** UI markup is not unit-testable. Per task = compile clean + lib tests pass + commit. **Visual correctness is Riley's hardware pass** (this environment has no display) — noted once here, not repeated per task.
- **All colors/sizes/radii/motion route through `Theme` tokens** — no hardcoded colors in screen files.
- Branch: `feat/gui-visual-overhaul` (already created). Commit trailer: `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>`.

---

## File Structure

```
crates/vaultgui/ui/theme.slint     # REWRITE: command-vault tokens (dark identity + restrained light)
crates/vaultgui/ui/widgets.slint   # REWRITE: glass kit + new Dial; keep exported names screens use
crates/vaultgui/ui/unlock.slint    # RECOMPOSE: glass card, hero Dial (dormant), chips
crates/vaultgui/ui/vault.slint     # RECOMPOSE: header Dial-as-countdown-gauge, glowing rows, glass detail
crates/vaultgui/ui/settings.slint  # RECOMPOSE: glass-carded sections, chips, red deprovision card
crates/vaultgui/ui/create.slint    # RECOMPOSE: glass card, cyan/amber choice cards
crates/vaultgui/ui/app.slint       # screen cross-fade + error toast; bind header dial fraction
```

`main.rs`, `vaultcore`, and the harness are **not** touched (the dial reads `idle_remaining`/`idle_timeout_secs`, which already exist as App properties bound in `app.slint`/`main.rs`).

---

### Task 1: Theme tokens — the command-vault palette

**Files:** Rewrite `crates/vaultgui/ui/theme.slint`

**Interfaces — Produces (token names the kit + screens rely on; keep these exact so existing screens compile):** `Theme.{bg-base, bg-elevated, bg-raised, bg-inset, line, text-primary, text-secondary, text-faint, accent, accent-dim, on-accent, caution, danger, on-danger, cyan, cyan-bright, cyan-glow, cyan-soft, amber, amber-glow, glass-fill, glass-border, glass-highlight, grad-accent, shadow, shadow-blur, font-ui, font-mono, text-hero, weight-hero, text-display, weight-display, text-title, weight-title, text-body, weight-body, text-small, text-label, weight-label, text-mono, weight-mono, text-mono-lg, weight-mono-lg, label-letterspacing, space-1..space-12, radius-panel, radius-field, radius-pill}`. `accent` aliases `cyan` and `caution` aliases `amber` so screens that still say `Theme.accent`/`Theme.caution` become cyan/amber automatically.

- [ ] **Step 1: Replace the whole file** with:

```slint
// Command-vault design tokens. Dark is the identity; a restrained light variant
// keeps the light/dark toggle working (glows collapse to soft shadows).
export global Theme {
    in property <bool> dark: true;

    // Neutrals + glass
    out property <brush> bg-base: dark ? #0A0D11 : #EAEEF3;
    out property <brush> bg-elevated: dark ? #111821 : #F3F6FA;
    out property <brush> bg-raised: dark ? #131A22 : #FFFFFF;
    out property <brush> bg-inset: dark ? #080B0F : #FFFFFF;
    out property <brush> line: dark ? #1C2530 : #D3DCE5;
    out property <brush> glass-fill: dark
        ? @linear-gradient(180deg, #FFFFFF0D, #FFFFFF05)
        : @linear-gradient(180deg, #FFFFFF, #F5F8FC);
    out property <brush> glass-border: dark ? #FFFFFF17 : #D3DCE5;
    out property <brush> glass-highlight: dark ? #FFFFFF10 : #FFFFFF;
    out property <brush> text-primary: dark ? #E7EEF4 : #10202D;
    out property <brush> text-secondary: dark ? #8493A1 : #47586A;
    out property <brush> text-faint: dark ? #54626E : #7C8B99;

    // Cyan identity + amber secondary/caution
    out property <brush> cyan: dark ? #2FE0D0 : #0E9E8E;
    out property <brush> cyan-bright: dark ? #48ECDB : #12A392;
    out property <color> cyan-glow: dark ? #2FE0D08c : #0E9E8E33;
    out property <brush> cyan-soft: dark ? #2FE0D017 : #DCF1EE;
    out property <brush> amber: dark ? #F5A623 : #B9791A;
    out property <color> amber-glow: dark ? #F5A62380 : #B9791A33;

    // Semantic aliases so existing screens keep compiling with retinted colors.
    out property <brush> accent: root.cyan;
    out property <brush> accent-dim: dark ? #46585F : #7E948F;
    out property <brush> on-accent: dark ? #04120F : #FFFFFF;
    out property <brush> caution: root.amber;
    out property <brush> danger: dark ? #FF6B6B : #C0392B;
    out property <brush> on-danger: dark ? #180909 : #FFFFFF;

    // Button/panel gradients + depth
    out property <brush> grad-accent: dark
        ? @linear-gradient(180deg, #48ECDB, #22C6B5)
        : @linear-gradient(180deg, #17A392, #0C8072);
    out property <color> shadow: dark ? #00000073 : #1a2a3a2e;
    out property <length> shadow-blur: 26px;

    // Typography (system fonts only)
    out property <string> font-ui: "Segoe UI";
    out property <string> font-mono: "Consolas";
    out property <length> text-hero: 32px;
    out property <int> weight-hero: 250;
    out property <length> text-display: 22px;
    out property <int> weight-display: 300;
    out property <length> text-title: 18px;
    out property <int> weight-title: 600;
    out property <length> text-body: 14px;
    out property <int> weight-body: 400;
    out property <length> text-small: 12px;
    out property <length> text-label: 11px;
    out property <int> weight-label: 700;
    out property <length> text-mono: 14px;
    out property <int> weight-mono: 400;
    out property <length> text-mono-lg: 22px;
    out property <int> weight-mono-lg: 500;
    out property <length> label-letterspacing: 1.4px;

    // Spacing / shape
    out property <length> space-1: 4px;
    out property <length> space-2: 8px;
    out property <length> space-3: 12px;
    out property <length> space-4: 16px;
    out property <length> space-5: 20px;
    out property <length> space-6: 24px;
    out property <length> space-8: 32px;
    out property <length> space-10: 40px;
    out property <length> space-12: 48px;
    out property <length> radius-panel: 18px;
    out property <length> radius-field: 9px;
    out property <length> radius-pill: 20px;
}
```

- [ ] **Step 2: Build** — `cargo build -p vaultgui --locked`. Expected: compiles, **zero warnings**. (Screens still reference `accent`/`caution`/etc., which now resolve to cyan/amber — the app is already re-tinted.)
- [ ] **Step 3: Tests** — `cargo test -p vaultgui --lib --locked`. Expected: 20 passed.
- [ ] **Step 4: Commit**

```bash
git add crates/vaultgui/ui/theme.slint
git commit -m "feat(vaultgui): command-vault design tokens (cyan+amber, glass, dark identity + light)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Widget kit — glass components + the radial Dial

**Files:** Rewrite `crates/vaultgui/ui/widgets.slint`

**Interfaces — Produces (exported components; keep the existing names `Card`, `PrimaryButton`, `GhostButton`, `Field`, `Checkbox`, `SectionLabel`, `Divider` with their current prop/callback shapes so unmodified screens compile, and ADD `Dial`, `StatusChip`):**
- `Dial { in size: length; in engaged: bool; in caution: bool; in fraction: float (0..1 lit); in center-glyph: string; in center-label: string }`
- `Card` (glass panel, inherits Rectangle), `StatusChip { in text; in tone: string ("cyan"|"amber"|"danger") }`
- `PrimaryButton { in text }` (now glass-glow), `GhostButton { in text; in active: bool; in danger: bool }`, `Field { in placeholder; in masked: bool; in field-enabled: bool; in-out text; callback accepted; callback edited(string) }`, `Checkbox { in text; in checked: bool }`, `SectionLabel` (Text), `Divider` (Rectangle).

- [ ] **Step 1: Replace the whole file** with:

```slint
import { Theme } from "theme.slint";

// ---- The radial vault dial (signature) --------------------------------------
// A segmented tick-ring gauge (robust in Slint: rotated ticks, no SVG-arc trig)
// + a glass hub. `fraction` (0..1) lights that share of the ring; lit ticks glow
// cyan, or amber when `caution` or the fraction is low. `engaged=false` = dormant
// (all ticks dim). Reused as the auto-lock countdown gauge (fraction = remaining).
export component Dial {
    in property <length> size: 150px;
    in property <bool> engaged: false;
    in property <bool> caution: false;
    in property <float> fraction: 1.0;
    in property <string> center-glyph: "\u{1F512}";
    in property <string> center-label: "LOCKED";
    property <int> segs: 44;
    property <bool> warm: root.caution || root.fraction < 0.2;
    width: root.size;
    height: root.size;

    for i in root.segs : Rectangle {
        property <float> t: i / root.segs;
        property <bool> lit: root.engaged && root.fraction >= t;
        width: 2px;
        height: root.size * 0.09;
        // place the tick's top at the ring radius, centered horizontally, then
        // rotate the whole tick about the dial centre.
        x: root.size / 2 - self.width / 2;
        y: root.size * 0.03;
        border-radius: 1px;
        background: root.lit ? (root.warm ? Theme.amber : Theme.cyan) : Theme.line;
        drop-shadow-blur: root.lit ? 6px : 0px;
        drop-shadow-color: root.warm ? Theme.amber-glow : Theme.cyan-glow;
        rotation-angle: (i * 360deg) / root.segs;
        rotation-origin-x: root.size / 2 - self.x;
        rotation-origin-y: root.size / 2 - self.y;
    }

    // glass hub
    Rectangle {
        width: root.size * 0.52;
        height: root.size * 0.52;
        x: (root.size - self.width) / 2;
        y: (root.size - self.height) / 2;
        border-radius: self.width / 2;
        background: Theme.bg-inset;
        border-width: 1px;
        border-color: root.engaged ? (root.warm ? Theme.amber : Theme.cyan) : Theme.line;
        drop-shadow-blur: root.engaged ? 14px : 0px;
        drop-shadow-color: root.warm ? Theme.amber-glow : Theme.cyan-glow;

        VerticalLayout {
            alignment: center;
            Text {
                text: root.center-glyph;
                font-size: root.size * 0.16;
                horizontal-alignment: center;
            }
            Text {
                text: root.center-label;
                color: Theme.text-secondary;
                font-family: Theme.font-mono;
                font-size: root.size * 0.075;
                letter-spacing: 1.5px;
                horizontal-alignment: center;
            }
        }
    }
}

// ---- Glass panel ------------------------------------------------------------
export component Card inherits Rectangle {
    background: Theme.glass-fill;
    border-radius: Theme.radius-panel;
    border-width: 1px;
    border-color: Theme.glass-border;
    drop-shadow-blur: Theme.shadow-blur;
    drop-shadow-color: Theme.shadow;
    drop-shadow-offset-y: 12px;
}

export component SectionLabel inherits Text {
    color: Theme.text-faint;
    font-family: Theme.font-ui;
    font-size: Theme.text-label;
    font-weight: Theme.weight-label;
    letter-spacing: Theme.label-letterspacing;
}

export component Divider inherits Rectangle {
    height: 1px;
    background: Theme.line;
}

export component StatusChip {
    in property <string> text;
    in property <string> tone: "cyan"; // "cyan" | "amber" | "danger"
    property <brush> col: root.tone == "amber" ? Theme.amber : (root.tone == "danger" ? Theme.danger : Theme.cyan);
    property <color> glo: root.tone == "amber" ? Theme.amber-glow : Theme.cyan-glow;
    height: 22px;
    Rectangle {
        border-radius: Theme.radius-pill;
        background: Theme.bg-inset;
        border-width: 1px;
        border-color: root.col;
        drop-shadow-blur: 6px;
        drop-shadow-color: root.glo;
        HorizontalLayout {
            padding-left: Theme.space-2;
            padding-right: Theme.space-2;
            Text {
                text: root.text;
                color: root.col;
                font-family: Theme.font-ui;
                font-size: 9.5px;
                font-weight: 700;
                letter-spacing: 1px;
                vertical-alignment: center;
            }
        }
    }
}

export component PrimaryButton inherits TouchArea {
    in property <string> text;
    height: 42px;
    Rectangle {
        width: 100%;
        height: 100%;
        border-radius: Theme.radius-field;
        background: root.enabled ? Theme.grad-accent : Theme.accent-dim;
        drop-shadow-blur: root.enabled ? 18px : 0px;
        drop-shadow-color: root.enabled ? Theme.cyan-glow : #00000000;
        drop-shadow-offset-y: 3px;
        Rectangle {
            width: 100%;
            height: 100%;
            border-radius: parent.border-radius;
            background: root.pressed && root.enabled ? #00000024 : (root.has-hover && root.enabled ? #FFFFFF24 : transparent);
        }
        Text {
            text: root.text;
            color: Theme.on-accent;
            font-family: Theme.font-ui;
            font-size: Theme.text-body;
            font-weight: 700;
            letter-spacing: 1px;
            horizontal-alignment: center;
            vertical-alignment: center;
            width: 100%;
            height: 100%;
        }
    }
}

export component GhostButton inherits TouchArea {
    in property <string> text;
    in property <bool> active: false;
    in property <bool> danger: false;
    height: 38px;
    Rectangle {
        width: 100%;
        height: 100%;
        border-radius: Theme.radius-field;
        border-width: root.active ? 1.5px : 1px;
        border-color: root.danger ? Theme.danger : (root.active ? Theme.cyan : Theme.glass-border);
        background: root.active ? Theme.cyan-soft : (root.has-hover && root.enabled ? Theme.bg-raised : transparent);
        drop-shadow-blur: root.active ? 8px : 0px;
        drop-shadow-color: Theme.cyan-glow;
        opacity: root.enabled ? 1.0 : 0.45;
        Text {
            text: root.text;
            color: root.danger ? Theme.danger : (root.active ? Theme.cyan : Theme.text-secondary);
            font-family: Theme.font-ui;
            font-size: Theme.text-body;
            horizontal-alignment: center;
            vertical-alignment: center;
            width: 100%;
            height: 100%;
        }
    }
}

export component Field inherits Rectangle {
    in property <string> placeholder;
    in property <bool> masked: false;
    in property <bool> field-enabled: true;
    in-out property <string> text <=> input.text;
    callback accepted();
    callback edited(text: string);
    height: 42px;
    background: Theme.bg-inset;
    border-radius: Theme.radius-field;
    border-width: 1px;
    border-color: input.has-focus ? Theme.cyan : Theme.glass-border;
    drop-shadow-blur: input.has-focus ? 10px : 0px;
    drop-shadow-color: Theme.cyan-glow;
    opacity: root.field-enabled ? 1.0 : 0.5;
    input := TextInput {
        x: Theme.space-3;
        width: parent.width - 2 * Theme.space-3;
        height: 100%;
        vertical-alignment: center;
        input-type: root.masked ? InputType.password : InputType.text;
        enabled: root.field-enabled;
        color: Theme.text-primary;
        font-family: Theme.font-ui;
        font-size: Theme.text-body;
        accepted => { root.accepted(); }
        edited => { root.edited(self.text); }
    }
    if input.text == "" && !input.has-focus: Text {
        x: Theme.space-3;
        width: parent.width - 2 * Theme.space-3;
        height: 100%;
        vertical-alignment: center;
        text: root.placeholder;
        color: Theme.text-faint;
        font-family: Theme.font-ui;
        font-size: Theme.text-body;
    }
}

export component Checkbox inherits TouchArea {
    in property <string> text;
    in property <bool> checked: false;
    height: 24px;
    opacity: root.enabled ? 1.0 : 0.4;
    HorizontalLayout {
        spacing: Theme.space-2;
        alignment: start;
        Rectangle {
            width: 18px;
            height: 18px;
            y: (parent.height - self.height) / 2;
            border-radius: 4px;
            border-width: 1px;
            border-color: root.checked ? Theme.cyan : Theme.glass-border;
            background: root.checked ? Theme.cyan : Theme.bg-inset;
            drop-shadow-blur: root.checked ? 8px : 0px;
            drop-shadow-color: Theme.cyan-glow;
            Text {
                visible: root.checked;
                text: "\u{2713}";
                color: Theme.on-accent;
                font-size: 13px;
                font-weight: 700;
                horizontal-alignment: center;
                vertical-alignment: center;
                width: 100%;
                height: 100%;
            }
        }
        Text {
            text: root.text;
            color: Theme.text-primary;
            font-family: Theme.font-ui;
            font-size: Theme.text-body;
            vertical-alignment: center;
        }
    }
}
```

- [ ] **Step 2: Verify the `Dial` renders** — the tick rotation math (`rotation-origin-x/y = size/2 - self.x`) is the one Slint-specific risk. Build: `cargo build -p vaultgui --locked`. If it compiles but you cannot confirm rotation visually here, that's expected (Riley's pass). If the rotation origin doesn't compile or is clearly wrong, use the fallback: position each tick at `x: size/2 + (size*0.44)*sin(i*360deg/segs) - width/2; y: size/2 - (size*0.44)*cos(i*360deg/segs) - height/2; rotation-angle: i*360deg/segs; rotation-origin-x: width/2; rotation-origin-y: height/2;` (Slint has `sin`/`cos` on `angle`). Note in the commit which form you used.
- [ ] **Step 3: Build + tests** — `cargo build -p vaultgui --locked` (zero warnings) and `cargo test -p vaultgui --lib --locked` (20 passed). The screens still import `Card`/`PrimaryButton`/`GhostButton`/`Field`/`Checkbox`/`SectionLabel`/`Divider` (all still exported, now glass/glow) — they compile and immediately look premium. `Seal` is still referenced by unlock/vault; keep a temporary `Seal` shim so they compile: add `export component Seal inherits Dial { size: 28px; }` at the end of the file.
- [ ] **Step 4: Commit**

```bash
git add crates/vaultgui/ui/widgets.slint
git commit -m "feat(vaultgui): glass widget kit + radial vault Dial (cyan+amber, glow)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Unlock screen — hero dial + glass card

**Files:** Recompose `crates/vaultgui/ui/unlock.slint`

**Interfaces — Consumes:** `Dial`, `Card`, `Field`, `PrimaryButton`, `GhostButton`, `SectionLabel`, `StatusChip` from `widgets.slint`. Keeps its existing `in` props (`vault_path`, `posture`, `posture_authenticated`) and callbacks (`pick_vault`, `unlock(passphrase, recovery)`) unchanged.

- [ ] **Step 1: Recompose.** Keep the component's props/callbacks/`use-recovery` local state exactly as they are now. Replace the centered content with: a `Card { width: 400px; }` on a `Theme.bg-base` background, containing a `VerticalLayout { padding: Theme.space-8; spacing: Theme.space-5; }` with, in order:
  1. A centered `Dial { size: 96px; engaged: false; center-glyph: "\u{1F512}"; center-label: "LOCKED"; }` (dormant hero).
  2. A centered `HorizontalLayout { spacing: Theme.space-2; }` of `StatusChip { text: root.posture == "" ? "NO VAULT" : root.posture; tone: "cyan"; }` and, `if !root.posture_authenticated`, `StatusChip { text: "UNVERIFIED"; tone: "amber"; }`.
  3. `Text { text: "UNLOCK VAULT"; font-size: Theme.text-display; font-weight: Theme.weight-display; color: Theme.text-primary; horizontal-alignment: center; letter-spacing: 2px; }`.
  4. A `VerticalLayout { spacing: Theme.space-2; }`: `SectionLabel { text: "VAULT FILE"; }` then a `HorizontalLayout { spacing: Theme.space-2; }` of a bg-inset `Rectangle` (height 38, radius `Theme.radius-field`, border `Theme.glass-border`) holding a mono elided `Text` (`root.vault_path == "" ? "No vault selected" : root.vault_path`, color `Theme.text-secondary`/`Theme.text-faint`, `Theme.font-mono`, `Theme.text-small`) plus a `GhostButton { text: "Choose\u{2026}"; width: 96px; clicked => { root.pick_vault(); } }`.
  5. `pw := Field { placeholder: root.use-recovery ? "Recovery passphrase" : "Passphrase"; masked: true; accepted => { root.unlock(self.text, root.use-recovery); } }`.
  6. `PrimaryButton { text: "UNLOCK"; clicked => { root.unlock(pw.text, root.use-recovery); } }`.
  7. A centered `GhostButton { text: root.use-recovery ? "Use regular passphrase" : "Use recovery key"; width: 240px; clicked => { root.use-recovery = !root.use-recovery; } }`.
- [ ] **Step 2: Build + tests** — `cargo build -p vaultgui --locked` (zero warnings), `cargo test -p vaultgui --lib --locked` (20 passed).
- [ ] **Step 3: Commit** — `feat(vaultgui): recompose unlock screen (hero dial + glass card)` with the trailer.

---

### Task 4: Vault screen — header countdown dial + glowing rows + glass detail

**Files:** Recompose `crates/vaultgui/ui/vault.slint`

**Interfaces — Consumes:** `Dial`, `Card`, `Field`, `PrimaryButton`, `GhostButton`, `SectionLabel`, `Divider`, `StatusChip`. Keeps all existing `in` props, the `filter` two-way binding, all callbacks (`select`/`reveal`/`mask`/`copy`/`add_secret`/`rotate`/`remove`/`lock_now`/`search`/`open_settings`), the local `adding`/`rotating`/`confirm-remove`/backing-text state, and the **`changed selected` reset handler** — all unchanged (they carry security-relevant behavior).

- [ ] **Step 1: Header.** A `Rectangle { height: 60px; background: Theme.bg-raised; }` with a bottom 1px `Theme.line`, containing a `HorizontalLayout`: on the left `Dial { size: 40px; engaged: true; caution: root.weak-posture; fraction: root.idle_timeout_secs > 0 ? root.idle_remaining / root.idle_timeout_secs : 1.0; center-glyph: ""; center-label: root.idle_remaining > 0 ? (floor(root.idle_remaining/60) + ":" + (mod(root.idle_remaining,60) < 10 ? "0" : "") + mod(root.idle_remaining,60)) : "\u{221E}"; }` next to a `StatusChip { text: root.posture; tone: root.weak-posture ? "amber" : "cyan"; }`; a stretch spacer; then `GhostButton { text: "Settings"; width: 96px; clicked => { root.open_settings(); } }` and `GhostButton { text: "Lock now"; width: 104px; clicked => { root.lock_now(); } }`. (`weak-posture` = the existing local `property <bool> weak-posture: !root.hardware_bound || root.has_recovery;`.)
- [ ] **Step 2: Body.** Keep the two-pane split. Left = a `Theme.bg-raised` panel (width 264) with a right 1px `Theme.line`, holding the search `Field { placeholder: "Search secrets"; text <=> root.filter; edited(text) => { root.search(text); } }`, a `SectionLabel` count (`root.record_names.length == 1 ? "1 SECRET" : root.record_names.length + " SECRETS"`), a `Flickable` list of rows (each: `Rectangle`, height 38, radius `Theme.radius-field`, `background: name == root.selected ? Theme.cyan-soft : (touch.has-hover ? Theme.bg-raised : transparent)`, a `if name == root.selected` cyan left-bar `Rectangle` (width 3, glowing via `drop-shadow-color: Theme.cyan-glow; drop-shadow-blur: 6px`), a name `Text`, and a covering `touch := TouchArea { clicked => { root.select(name); } }`), the add panel (`if root.adding`, name/value `Field`s + a `PrimaryButton { text: "Save secret"; ... }` — keep the existing save + reset logic verbatim), and a `GhostButton { text: root.adding ? "Cancel" : "+ Add secret"; clicked => { root.adding = !root.adding; } }`.
- [ ] **Step 3: Detail (right pane).** `if root.selected == ""`: a centered empty state — `Dial { size: 56px; engaged: false; center-glyph: "\u{1F512}"; center-label: ""; }` + `Text "Select a secret"` (title) + `Text "Pick one from the list, or add a new secret."` (faint). `if root.selected != ""`: a vertically+horizontally centered `Card { width: 560px; }` with the record title (`Theme.text-display`), a `SectionLabel "SECRET VALUE"`, the value in a bg-inset glass field (glowing cyan border when revealed: `border-color: root.revealed_value == "" ? Theme.glass-border : Theme.cyan; drop-shadow-blur: root.revealed_value == "" ? 0 : 12px; drop-shadow-color: Theme.cyan-glow`) showing `root.revealed_value == "" ? "\u{2022}".repeated... ` (use a literal dots string `"\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}"`) else `root.revealed_value`, mono-lg; a row `PrimaryButton { text: root.revealed_value == "" ? "Reveal" : "Hide"; clicked => { if root.revealed_value == "" { root.reveal(root.selected); } else { root.mask(); } } }` + `GhostButton { text: root.clip_remaining > 0 ? "Copied \u{00B7} " + root.clip_remaining + "s" : "Copy"; active: root.clip_remaining > 0; clicked => { root.copy(root.selected); } }`; a `Divider`; then `GhostButton` Rotate + danger `GhostButton` Remove (**keep the existing `confirm-remove` two-click logic verbatim**); and the `if root.rotating` inline field + Save (keep verbatim).
- [ ] **Step 4: Build + tests** — zero warnings, 20 passed. (If `floor`/`mod` on the countdown label don't compile in Slint, fall back to `center-label: root.idle_remaining + "s"`.)
- [ ] **Step 5: Commit** — `feat(vaultgui): recompose vault screen (header countdown dial, glowing rows, glass detail)`.

---

### Task 5: Settings screen — glass-carded sections

**Files:** Recompose `crates/vaultgui/ui/settings.slint`

**Interfaces — Consumes:** `Card`, `Field`, `PrimaryButton`, `GhostButton`, `Checkbox`, `SectionLabel`, `StatusChip`. Keeps all `in` props, callbacks, and the local `gen-length`/`gen-symbols` state unchanged. Keeps the `Flickable` scroll wrapper (so it never clips) and the header with a `Back to vault` `GhostButton`.

- [ ] **Step 1: Recompose** each section as a glass `Card` (padding `Theme.space-5`), preserving every callback/binding:
  1. **SECURITY POSTURE** — `SectionLabel` + readout rows (engraved label + mono value); use `StatusChip`s for `HARDWARE BINDING` (`tone: root.hardware_bound ? "cyan" : "amber"`) and `RECOVERY ESCROW` (`tone: root.has_recovery ? "amber" : "cyan"`); `PROVIDER` as a wrapped mono `Text`.
  2. **Windows Hello** — the `Checkbox { text: "Require Windows Hello before revealing a secret"; checked: root.hello_enabled; enabled: root.hello_available; clicked => { root.set_hello(!root.hello_enabled); } }` + the existing honest note text (verbatim).
  3. **AUTO-LOCK** — the four preset `GhostButton`s (`active` on the matching `idle_timeout_secs`, `clicked => root.set_timeout(...)`) + the existing "applies next launch" note.
  4. **APPEARANCE** — Light/Dark `GhostButton`s (`active`/`set_dark`).
  5. **PASSWORD GENERATOR** — the ± length control, `Checkbox` Symbols, `PrimaryButton "Generate"`, and (`if root.generated_value != ""`) the glowing mono output field + a `GhostButton "Copy"` → `copy_generated()` (keep the auto-clear path).
  6. **DEPROVISION** — a `Card { border-color: Theme.danger; }` with a red `SectionLabel`, the warning text, a `Field "Type DELETE to confirm"`, and a danger button (reuse the existing local `DangerButton` or a `GhostButton { danger: true }`) enabled only when the field equals `"DELETE"` → `deprovision()`.
- [ ] **Step 2: Build + tests** — zero warnings, 20 passed.
- [ ] **Step 3: Commit** — `feat(vaultgui): recompose settings (glass-carded sections, chips, red deprovision card)`.

---

### Task 6: Create screen — glass card + choice cards

**Files:** Recompose `crates/vaultgui/ui/create.slint`

**Interfaces — Consumes:** `Card`, `Field`, `PrimaryButton`, `Checkbox`, `SectionLabel`. Keeps the `create_vault(...)` callback, the local `allow-no-tpm`/`use-recovery` state, and the `Flickable` scroll wrapper unchanged.

- [ ] **Step 1: Recompose** — a centered glass `Card { width: 460px; }` (inside the existing `Flickable`) with: a small `Dial { size: 34px; }` + `Text "Create a vault"` header; `SectionLabel "SECOND FACTOR"`; two selectable choice cards (a local `Choice` component styled as an inset card with a radio dot — keep the current `Choice` component but restyle its colors to `Theme.cyan-soft`/`Theme.cyan` when selected; **keep the tradeoff-color logic: two-factor is cyan/neutral, passphrase-only is unconditionally `Theme.amber`**); a recovery `Checkbox` + its `Theme.amber` warning; the passphrase/confirm/recovery masked `Field`s (recovery `field-enabled: root.use-recovery`); and a `PrimaryButton "Create vault"` calling `create_vault(pw.text, confirm.text, root.allow-no-tpm, root.use-recovery, recovery.text)`.
- [ ] **Step 2: Build + tests** — zero warnings, 20 passed.
- [ ] **Step 3: Commit** — `feat(vaultgui): recompose create screen (glass card + choice cards)`.

---

### Task 7: App root — transitions, error toast, and cleanup

**Files:** Modify `crates/vaultgui/ui/app.slint`; touch `crates/vaultgui/ui/widgets.slint` (remove the temporary `Seal` shim if now unused).

- [ ] **Step 1: Screen transition.** Wrap each `if root.screen == "..."` screen so it fades in: give each screen instance `opacity: 1;` with `animate opacity { duration: 200ms; easing: ease-out; }`. (Slint animates the opacity of the newly-instantiated screen; keep it simple — no layout animation.)
- [ ] **Step 2: Error toast.** Restyle the existing `if root.error != ""` banner as a glass toast: a `Rectangle` with `background: Theme.danger`, `border-radius: Theme.radius-field`, a small margin from the top, a drop-shadow, the message in `Theme.on-danger`, and the existing `\u{00D7}` dismiss `TouchArea { clicked => { root.error = ""; } }`. Keep it top-most.
- [ ] **Step 3: Cleanup** — grep the screens for `Seal` usage (`rg "\bSeal\b" crates/vaultgui/ui`). If none remain (Tasks 3–4 replaced them with `Dial`), delete the temporary `export component Seal ...` shim from `widgets.slint`. Confirm no other now-dead tokens/components remain.
- [ ] **Step 4: Full verification** — `cargo build -p vaultgui --locked` (zero warnings), `cargo build --release -p vaultgui --locked` (release, zero warnings), `cargo test -p vaultgui --lib --locked` (20 passed). Confirm the App-level property/callback contract in `app.slint` is unchanged (18 props + 15 callbacks; `git diff` should show only styling/transition edits, no renamed members).
- [ ] **Step 5: Commit** — `feat(vaultgui): screen cross-fade + error toast; drop the Seal shim`.

---

## Self-Review

**Spec coverage (spec §→task):**
- §3 tokens (dark+light, cyan+amber, glass, type, motion) → Task 1. ✓
- §4 radial dial (states, auto-lock gauge reuse, Slint draw, motion) → Task 2 (component) + Task 4 (header gauge) + Task 3 (dormant hero). ✓
- §5 component kit (Card/GlowButton/GhostButton/Field/StatusChip/Toggle/SectionLabel/Divider/Row) → Task 2 (+ Row realized inline in Task 4's list). ✓
- §6 per-screen (unlock/create/vault/settings/app root) → Tasks 3,6,4,5,7. ✓
- §7 motion (transitions, hover/press glow, focus glow, dial pulse, caret) → glow/hover built into Task 2 components; screen cross-fade Task 7. (Ambient dial glow-pulse: optional refinement, folded into Task 2's Dial or Task 7; reduced-motion residual documented in spec §7.) ✓
- §8 feasibility (Path/segment dial, no conic-gradient, faux-glass, glow, animation) → Task 2 uses the robust segmented-tick dial with a documented fallback. ✓
- §9 scope (files) / §2 invariants (no security/logic change) → the App contract + all security-relevant screen logic (`changed selected`, confirm-remove, save-error handling, secret marshalling in main.rs) are explicitly kept verbatim; Task 7 verifies the contract is unchanged. ✓
- §10 acceptance (zero warnings, 20 tests, tokens-only colors, dial appears both places, invariants intact, Riley visual pass) → per-task build/test gates + Task 7 full verification. ✓

**Placeholder scan:** token values, the full `theme.slint` and `widgets.slint` (incl. the Dial), and concrete per-screen composition are all specified. The two genuine Slint uncertainties (dial tick rotation-origin; `floor`/`mod` in the countdown label) carry concrete fallbacks, not TODOs.

**Type/name consistency:** `Theme.*` token names are stable across tasks (Task 1 defines, all later tasks consume; `accent`=cyan/`caution`=amber aliases keep unmodified refs valid). Widget names (`Card`, `PrimaryButton`, `GhostButton`, `Field`, `Checkbox`, `SectionLabel`, `Divider`, `Dial`, `StatusChip`) are consistent between Task 2 (produces) and Tasks 3–7 (consume). The App-level property/callback names are never changed.

## Notes for the implementer

- **The Dial is the one real risk.** Build it first (Task 2), and if the tick-ring math doesn't render right, use the documented `sin`/`cos` fallback. Everything else is straightforward glass/glow styling of an already-working screen.
- **Never change** the App-level property/callback contract, the `changed selected` reset, the confirm-remove two-click, the save-error banners, or any `main.rs` secret handling. This is a re-skin — if a task tempts you to touch logic, stop.
- **Visual truth is Riley's.** Compile-clean + 20 tests passing is the automated gate here; the look is confirmed on hardware.
