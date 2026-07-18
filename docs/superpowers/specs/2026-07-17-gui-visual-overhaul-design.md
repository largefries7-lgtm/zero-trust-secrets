# vaultgui Visual Overhaul — "Command Vault" (premium glass HUD)

- **Date:** 2026-07-17
- **Status:** Draft for review
- **Author:** Riley (with Claude Code)
- **Scope:** A visual re-skin of the `vaultgui` desktop GUI (Slint). Establishes a
  premium dark "command console / vault" identity — cyan + amber duotone, dark
  glass panels, a glowing radial vault dial, and refined (quiet) motion. **No
  changes to security behavior, crypto, vault format, or app flows.**

> Direction set from a user reference image (dark glassmorphic HUD dashboard with
> cyan + amber glowing radial gauges) and two decisions: **duotone cyan+amber
> glass HUD** (not retro-terminal, not single-accent) and **"Refined only"
> motion** (smooth polish + a live gauge, no cinematic showpiece).

---

## 1. Purpose

The current look (flat teal-on-graphite, thin outlines) reads as generic. The
owner wants the app to *feel* secure and powerful. This overhaul commits to a
distinctive identity — a **machined command-vault HUD**: near-black glass panels
with a cyan identity glow, amber as a warm secondary/caution accent, and a
**glowing radial dial** as the signature element (the vault seal, reused as the
live auto-lock countdown gauge). Motion is refined and quiet — trust over
theatrics.

This is presentation only. It re-skins the theme, the shared widget kit, and the
four screens; it does not touch `vaultcore`, the security invariants, or the
Rust callback logic (beyond binding the dial to *existing* auto-lock properties).

## 2. Non-goals & invariants (unchanged)

- **No security change.** DEK single-ownership, secret marshalling into
  `SecretString`, fail-closed unlock, `SetWindowDisplayAffinity` anti-capture,
  clipboard verify-before-clear, Windows Hello reveal-gate, `do_lock` scrubbing —
  all unchanged. No secret is exposed in any new place. Record **names** remain
  non-secret authenticated metadata (already displayed); secret **values** stay
  masked-by-default / click-to-reveal.
- **No new dependencies.** System fonts only (Segoe UI + Consolas). No image
  assets, no font files, no new crates.
- **No flow/logic change.** Same screens, same App-level property/callback
  contract, same navigation. The only Rust-adjacent work is binding the dial to
  the already-existing `idle_remaining` / `idle_timeout_secs` properties.
- **No new plaintext surface.** The redesign adds glow/glass/animation, not data.

## 3. Design tokens

Defined in `theme.slint`. **Dark is the identity/default;** a restrained,
low-glow **light** variant is retained so the existing light/dark toggle keeps
working (light dials glows down to soft shadows and uses deeper accents for
contrast).

### Color — dark (primary identity)
| token | value | role |
|-------|-------|------|
| bg-base | `#0A0D11` | app background (with a subtle radial vignette to `#111821` at top-center) |
| bg-elevated | `#111821` | vignette center / raised base |
| glass-fill | `linear-gradient(rgba(255,255,255,.05), rgba(255,255,255,.02))` | glass panels |
| glass-border | `rgba(255,255,255,.09)` | panel hairline |
| glass-highlight | `rgba(255,255,255,.06)` | inset top edge |
| inset | `rgba(0,0,0,.35)` | recessed fields/wells |
| line | `#1C2530` | dividers |
| text-primary | `#E7EEF4` | |
| text-secondary | `#8493A1` | |
| text-faint | `#54626E` | labels/captions |
| **cyan** | `#2FE0D0` | **identity / active / primary action / focus / secure / posture-strong** |
| cyan-bright | `#48ECDB` | button gradient top / hero |
| cyan-glow | `rgba(47,224,208,.55)` | glow color |
| cyan-soft | `rgba(47,224,208,.09)` | selected-row / tint fills |
| **amber** | `#F5A623` | **secondary highlight + caution** (hardware-off, recovery escrow, unverified, low countdown) |
| amber-glow | `rgba(245,166,35,.5)` | |
| danger | `#FF6B6B` | destructive (remove, deprovision) |
| on-accent | `#04120F` | text on cyan fills |

### Color — light (restrained variant)
bg `#EDF1F5`; cards solid white with a soft (non-glowing) shadow + `#D3DCE5`
border; cyan `#0E9E8E`, amber `#B9791A`, danger `#C0392B`, text `#10202D` /
`#47586A`. Glows collapse to subtle shadows; the dial arcs stay but without the
glow filter.

### Typography (system-only)
- UI: **Segoe UI**. Data/secret/path/readout/dial numbers: **Consolas** (mono).
- Scale: hero 32/light · display 22/light · title 18/600 · body 14/400 ·
  small 12 · label 11/700 UPPERCASE + `1.4px` letter-spacing · mono 14 ·
  mono-lg 22/500.
- Engraved uppercase letter-spaced labels and status chips carry the "console"
  read; secret/technical values are always mono.

### Shape / depth
- Radius: panel 18 · card 14 · field 9 · pill/chip 20 (full) · button 9.
- Glass panels: `glass-fill` + `1px glass-border` + inset top highlight +
  `drop-shadow(blur 24, color rgba(0,0,0,.55), y 10)`.
- Glow = `drop-shadow-color` = the accent's `*-glow` token, blur 12–22.
- Space scale: 4·8·12·16·20·24·32·40·48.

### Motion durations
- fast 120ms · base 200ms · slow 350ms · ambient pulse 3s.
- Easing: ease-out for enters, ease-in-out for pulses.

## 4. Signature — the radial vault dial

The one bold element. A concentric gauge drawn in Slint with vector `Path`s
(Slint has **no** CSS conic-gradient): an outer **arc** (cyan primary segment +
an amber accent segment), a **tick ring** (a `for` loop of short marks, or a
dashed `Path`), and a **glass hub** center holding a glyph + a short mono label.

States (driven by props the screens already have):
- **Dormant / locked** (unlock screen): dim cyan ring, no fill, 🔒 + `LOCKED`.
  Low glow.
- **Engaged** (unlocked + `posture_authenticated`): bright cyan arc + amber
  segment, full glow, open glyph + `SEALED`.
- **Caution** (weaker posture: `!hardware_bound || has_recovery`): the accent
  segment shifts to amber-dominant.

**Reuse as the auto-lock gauge:** the same component, shrunk (~40px), sits in the
vault header. Its arc represents remaining idle time —
`arc_fraction = idle_remaining / idle_timeout_secs` (both already App
properties) — and the center shows the mono countdown (`4:58`). The arc/label
tint to **amber** when the remaining fraction is low (e.g. < 20%). This binds the
signature motif to real function with **no new Rust** (the props exist; the dial
just reads them).

Refined motion for the dial: the countdown arc animates smoothly as
`idle_remaining` changes; a gentle `ambient` glow pulse (~3s); on unlock the arc
fills dormant→engaged over `slow` (350ms) — a quiet transition, **not** a
spin-up showpiece (per the "Refined only" decision).

## 5. Component kit (`widgets.slint`, rewritten)

Each is a small, reusable component; screens compose them.

- **Dial** — the signature above (`size`, `engaged`, `caution`, `arc_fraction`,
  `center_text` props).
- **Card** — glass panel (fill + border + highlight + shadow/glow).
- **GlowButton** (primary) — cyan gradient fill, `on-accent` text, outer cyan
  glow; hover brightens + grows the glow, press dims; disabled → flat dim.
- **GhostButton** — outline; hover fills to a faint glass tint; `active` →
  cyan border/text + `cyan-soft` fill; `danger` → red border/text.
- **Field** — dark inset, mono/UI text, placeholder; focus → cyan border + a
  soft cyan focus-ring glow; optional masked; `accepted` + `edited` callbacks.
- **StatusChip** — pill with `tone` (cyan/amber/danger): tinted text + border +
  faint glow (e.g. `TPM DETECTED`, `UNVERIFIED`, `RECOVERY ESCROW`).
- **Toggle / Checkbox** — glowing cyan when on; dim/disabled when unavailable.
- **SectionLabel** — engraved uppercase letter-spaced faint text.
- **Divider** — 1px `line`.
- **Row** (record list) — selected = `cyan-soft` fill + cyan left-bar + faint
  glow + primary text; hover = faint glass tint.

## 6. Per-screen application

- **Unlock** — radial vignette bg; a centered glass **Card**: brand + posture
  **StatusChips** (cyan `TPM DETECTED` / amber `UNVERIFIED`), the **dormant hero
  Dial**, `UNLOCK VAULT` (hero weight), mono vault-path readout with a
  `Choose…` GhostButton, a masked **Field** (cyan focus), a **GlowButton**
  `Unlock`, and a `Use recovery key` ghost link.
- **Create** — scrollable centered glass **Card**: small dial + `Create a vault`;
  two selectable choice cards (two-factor = cyan-selected glow; passphrase-only =
  amber-caution wording, always cautioned); recovery toggle + warning; masked
  passphrase/confirm/recovery **Fields**; `Create vault` GlowButton.
- **Vault** — a header strip: the **engaged Dial as the live auto-lock gauge** +
  a posture StatusChip + `Settings` + `Lock now`; a thin cyan idle progress line.
  Left: a glass list panel with a search **Field**, a `N SECRETS` label, glowing
  selectable **Rows**, and an `+ Add secret` affordance (inline name/value on
  add). Right: a glass detail **Card** — record title, `SECRET VALUE` label, the
  value in a glowing mono field (masked dots by default; revealed in cyan),
  `Reveal/Hide` GlowButton + `Copy · Ns` GhostButton, then `Rotate` + danger
  `Remove` (fresh confirm per record). Empty state: a dormant-dial watermark +
  `Select a secret` invitation.
- **Settings** — scrollable stack of glass **Cards**: SECURITY POSTURE (readout
  rows + StatusChips), Windows Hello reveal-gate toggle + honest note, AUTO-LOCK
  pills, APPEARANCE (light/dark), PASSWORD GENERATOR (length ±, symbols, Generate
  GlowButton, glowing mono output + Copy), and DEPROVISION in a **red-bordered
  glass Card** with a typed-`DELETE` confirm.
- **App root** — screen changes cross-fade (`base` 200ms); the dismissable error
  banner becomes a red glass toast.

## 7. Motion inventory (Refined)

- Screen cross-fade on `screen` change (~200ms).
- Hover: button/card glow-up (increase `drop-shadow-blur`) + ~1% scale; press:
  dim + ~1% shrink.
- Field focus: cyan border + focus-ring glow fade-in.
- Dial: continuous smooth arc animation tracking `idle_remaining`; ~3s ambient
  glow pulse; dormant→engaged arc fill on unlock (~350ms).
- Blinking caret in focused fields; numeric clipboard + idle countdowns (already
  wired).
- **Reduced motion:** disable the ambient glow pulse and any looping motion when
  the platform signals reduced motion. Slint's exposure of the OS reduced-motion
  setting is limited; if it isn't directly queryable, ambient motion is kept
  minimal and the setting-driven gate is documented as a residual (honest, per
  repo convention).

## 8. Slint feasibility & approximations

- **Radial dial** — drawn with `Path` arc commands (cyan + amber segments) and a
  tick ring; animated by binding arc end-angle / a fraction property. This is the
  signature build effort. Verified pattern: Slint `Path` supports stroked arcs.
- **No conic-gradient** in Slint → arcs are `Path`s, not CSS gradients.
- **Glass blur** — Slint has no backdrop blur; "glass" is approximated with a
  translucent gradient fill + hairline highlight + soft shadow/glow, which reads
  the same over a dark background. Stated honestly; not pixel-identical to the
  reference render.
- **Glow** — `drop-shadow-blur` + `drop-shadow-color` (accent glow tokens).
- **Gradients** — linear/radial supported (button fill, background vignette).
- **Animation** — Slint `animate <prop> { duration; easing; }` for transitions;
  looping ambient via an animated property. Compiles headless; visual pass is on
  hardware.

## 9. Scope — files touched

- `crates/vaultgui/ui/theme.slint` — rewrite token set (dark + restrained light).
- `crates/vaultgui/ui/widgets.slint` — rewrite the kit; add the `Dial` component.
- `crates/vaultgui/ui/unlock.slint`, `create.slint`, `vault.slint`,
  `settings.slint` — re-skin using the new kit + compositions above.
- `crates/vaultgui/ui/app.slint` — screen cross-fade + error toast styling; bind
  the header dial's `arc_fraction` from existing props.
- `crates/vaultgui/src/main.rs` — **no logic change.** At most a trivial computed
  binding if the dial fraction is easier to feed from Rust than from the `.slint`
  (both `idle_remaining` and `idle_timeout_secs` already exist as properties).

**Out of scope:** any `vaultcore` change; the memory harness; the file-dialog /
scroll / CI fixes already on `feat/slice2-gui-polish` (this overhaul builds on
top of them and keeps them); new screens or features; a system tray; the entropy
visualizer.

## 10. Acceptance criteria

- `cargo build -p vaultgui` compiles with **zero warnings**; the 20 vaultgui lib
  tests still pass; no `vaultcore`/`vaultctl`/harness changes.
- Every color/size/radius/motion value routes through `theme.slint` tokens (no
  hardcoded colors in screens).
- The four screens render the compositions in §6; the dial appears as the unlock
  hero (dormant) and the vault-header auto-lock gauge (engaged, counting down).
- Security invariants demonstrably unchanged (no secret in new places; values
  masked-by-default; anti-capture intact). Verified by re-reading the wiring, not
  re-derived.
- Riley confirms the live look on hardware (this environment has no display).
