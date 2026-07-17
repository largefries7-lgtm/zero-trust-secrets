# Security

## Threat model

The authoritative threat model for the security core — what is and isn't defended,
and why — lives in the slice-1 design spec:
[`docs/superpowers/specs/2026-07-14-zero-trust-secrets-core-design.md`](docs/superpowers/specs/2026-07-14-zero-trust-secrets-core-design.md)
(§3 threat model, §15–17 as-built deltas). The GUI's as-built threat-model delta —
what slice 2 newly defends and, just as importantly, what it newly does **not**
defend — lives in the slice-2 spec:
[`docs/superpowers/specs/2026-07-16-slice2-gui-design.md`](docs/superpowers/specs/2026-07-16-slice2-gui-design.md)
(§13). Read both before relying on this tool.

**One-line ceiling:** this is a userspace application on a general-purpose OS. It
cannot defend against a compromised kernel, a debugger attached to the live
*unlocked* process at the moment of decryption, or a cold-boot attack on an
already-unlocked machine. It aims to be as strong as is *actually achievable*
below that ceiling, and to state honestly where the ceiling is.

### New surfaces introduced by the GUI (slice 2)

`vaultgui` inverts the CLI's stateless model on purpose: it is the long-lived
in-RAM holder of the decryption key (DEK) for the duration of an unlocked session,
rather than obtaining it fresh per command. This is a deliberate, disclosed
tradeoff, not an oversight — two new surfaces follow from it:

- **Long-lived DEK in RAM while unlocked.** A debugger or code injection attached
  to the live unlocked `vaultgui` process can read the DEK for as long as the
  session stays unlocked. This is the same userspace ceiling described above, now
  with a materially longer exposure window than the CLI's per-command one.
  Aggressive auto-lock (idle, workstation-lock, suspend, manual "Lock now")
  shrinks this window but does not close it.
- **Input-field and revealed-value residuals.** The Slint UI toolkit's own
  `LineEdit`/`SharedString` storage (and the OS IME/undo stacks) retain copies of
  typed passphrases/values, and a revealed secret's freed display buffer can
  outlive the property that displayed it, until the allocator reuses that memory.
  `vaultcore`'s own buffers are still zeroized on drop as designed; the residual
  above is Slint/OS-owned memory `vaultcore` never controlled to begin with.

Neither surface is hidden or minimized — see §13 of the slice-2 spec for the full
defended / not-defended / deferred breakdown, including why Windows Hello (an
optional feature of this slice) is a presence gate on the app and not a
contribution to the cryptographic key.

## Empirical verification

The memory-safety claim is not asserted, it is demonstrated:

```sh
bash verify/run.sh
```

This dumps a running `vaultctl` process and proves no plaintext secret survives in
its heap when locked or just after a clipboard copy, with a positive control
proving the scanner works. It also dumps a running `vaultgui` process across three
scenarios: `gui-locked` (clean at rest, same guarantee as the CLI's `locked`),
`gui-post-autolock` (asserts `vaultcore`'s own DEK/`SecretString` buffers are
zeroized after auto-lock, and separately **measures and reports** — rather than
hides — whatever residual Slint's own retained `SharedString` storage still holds
after the UI-side scrub), and `gui-leak` (a positive control for the GUI binary,
mirroring the CLI's). The GUI scenarios require a real interactive Windows session
(a display, and a TPM for the Hello-gated paths exercised elsewhere in the app) to
run. See [`verify/TEST_PLAN.md`](verify/TEST_PLAN.md) for the full scenario table,
pass criteria, and the current recorded result — including whether the GUI
scenarios have been executed yet in a given environment; no number is invented
here or there.

## Dependency trust

The security core deliberately uses a **small, widely-audited** dependency set —
the standard RustCrypto ecosystem — rather than bespoke cryptography:

| Crate | Role | Why trusted |
|-------|------|-------------|
| `chacha20poly1305` | XChaCha20-Poly1305 AEAD | RustCrypto AEAD, audited, ubiquitous |
| `argon2` | Argon2id password KDF | RustCrypto password-hashes |
| `hkdf`, `sha2`, `hmac` | HKDF / HMAC-SHA256 | RustCrypto core hashes |
| `subtle` | constant-time comparison | RustCrypto, purpose-built for CT |
| `zeroize` | scrub secrets on drop | RustCrypto, the standard for this |
| `getrandom` / `rand_core` | OS CSPRNG | the standard entropy source |
| `windows` | TPM (CNG), VirtualLock, MiniDump, Console | Microsoft's official Win32 bindings |
| `clap` | CLI parsing | ubiquitous, no crypto surface |

No custom cryptographic primitive is implemented; only standard constructions are
composed (envelope encryption, encrypt-then-MAC header authentication, HKDF domain
separation).

**Reproducibility / pinning:** exact versions are pinned by the committed
`Cargo.lock`. `windows`-crate features are minimized per crate (only the Win32
sub-APIs actually used are enabled).

**Auditing:** [`deny.toml`](deny.toml) defines the supply-chain policy
(advisories = deny, wildcards = deny, permissive-license allow-list, crates.io
only). [`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `cargo deny
check` — the sole supply-chain gate, performing the advisory audit against that
target-scoped, justified-ignore policy — on every push and pull request, gating
every dependency change.

### Dependency-surface tradeoff of the GUI (slice 2) — honest disclosure

`vaultcore`'s crypto dependency set above is unchanged by the GUI: no crypto crate
was added, swapped, or touched. But `vaultgui` itself pulls in **Slint** and, through
it, Slint's transitive image/SVG/font rendering stack (needed to draw the UI at
all) — this **materially expands the overall dependency surface** of the repo
beyond the minimal, widely-audited crypto core described above. That is a real,
deliberate cost of adopting a full GUI toolkit, not something to gloss over:

- Three transitive crates reached only via Slint's image/SVG decoding —
  `paste`, `rustybuzz`, and `ttf-parser` — are unmaintained upstream (their
  maintainers have said so; no safe upgrade exists) and are listed in
  [`deny.toml`](deny.toml)'s `[advisories].ignore` with a comment explaining the
  path each is reached by. These are **maintenance-status** advisories (the
  project is no longer maintained), **not** known exploitable vulnerabilities,
  and `vaultgui`/`vaultcore` never call into any of the three directly.
- `deny.toml`'s `[graph].targets` is scoped to `x86_64-pc-windows-msvc` (the only
  target this project ships), which prunes Linux/macOS/Android/wasm-only
  transitive subtrees that winit's cross-platform backend selection pulls into
  `Cargo.lock` (`objc2-*`, `wayland-*`, `x11rb`, `ndk`, …) but that never actually
  compile into our Windows binary, out of the analyzed graph — rather than
  papering over advisories that don't apply to what we actually build.

Net effect: the security core's dependency footprint stays small and audited as
before; the GUI's footprint is larger because a real rendering stack is now in the
tree. State this plainly rather than let the aggregate dependency count imply the
crypto core grew — it didn't.

## Reporting

This is a personal/reference project. If you are reviewing it and find a flaw,
open an issue describing the impact and a reproduction.
