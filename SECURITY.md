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

### Passphrase-factor hardening (hardening program, phase 1)

The most realistic attack on a local vault is offline brute force of a *stolen
file*. Three measures raise that floor, none of which change the on-disk format or
add a dependency:

- **Auto-calibrated Argon2id.** At vault creation the passphrase KDF cost is
  benchmarked on the machine and set to the largest memory (256 MiB floor, 1 GiB
  cap) that keeps unlock near ~0.75 s — typically 512 MiB–1 GiB on modern hardware,
  up from a fixed 64 MiB. The floor wins over the latency target on a slow machine,
  so a weak machine cannot silently mint a weak vault. Parameters live in the
  authenticated header, bounded by the parser's DoS ceiling.
- **Creation-time strength gate.** A passphrase below a length + character-class
  entropy floor, or on an embedded common-password blocklist, is refused. The floor
  is context-aware: stricter for a passphrase-only (`--allow-no-tpm`) vault, where
  the passphrase is the sole factor, than for a two-factor vault. This is a *floor,
  not a strength promise* — it catches weak passphrases, it does not certify strong
  ones (the honest tradeoff for not adding a zxcvbn-grade dependency).
- **Generated recovery code.** The optional escrow (still off by default) no longer
  takes a human passphrase — the weakest link when enabled. It generates a 128-bit
  code (Crockford base32, shown once, stored offline), so a stolen vault with the
  escrow is still protected by 128 bits, not by whatever a human chose. The code
  wraps the DEK through the same envelope construction; no new cryptography.

### Process & RAM hardening (hardening program, phase 2)

Windows-specific measures that raise the bar against same-user attackers, all
strictly below the userspace ceiling (a compromised kernel or code injected into
the *unlocked* process still wins — stated plainly):

- **Build-time exploit mitigations.** The shipped binaries are compiled with
  Control Flow Guard (`-Ccontrol-flow-guard`) and marked CET-compatible
  (`/CETCOMPAT`) for a hardware shadow stack; ASLR, high-entropy VA and DEP/NX are
  MSVC defaults. Verified present in the release image (`DllCharacteristics`
  includes `GUARD_CF | DYNAMIC_BASE | HIGH_ENTROPY_VA | NX_COMPAT`). The release
  profile also enables `overflow-checks` (traps integer overflow in the untrusted-
  header parser), LTO, and symbol stripping. Panic strategy stays **unwind** on
  purpose, so `ZeroizeOnDrop` still scrubs secrets even on a panic.
- **Runtime mitigation policies.** At startup both binaries call
  `SetProcessMitigationPolicy` to disable extension points (legacy AppInit /
  `SetWindowsHookEx` DLL injection) and to refuse loading DLLs from remote or
  low-integrity locations, and `SetErrorMode` to suppress the crash UI. ACG
  (dynamic-code prohibition) and signature-only image loading are deliberately
  **not** enabled — they can break the GUI's third-party GPU-driver DLL loads; that
  tradeoff is stated rather than risked silently.
- **DEK encrypted at rest in RAM.** `vaultgui` holds the DEK for a whole unlocked
  session — the GUI's headline new surface. The DEK is now kept
  `CryptProtectMemory`-encrypted (`SAME_PROCESS`) between operations and decrypted
  only transiently, for the microseconds of a single crypto op, into a page-locked
  buffer that is zeroized immediately after. This shrinks the cold-boot / passive-
  scrape window: between operations there is no plaintext DEK in memory. It does
  **not** stop code executing inside the process (it can call `CryptUnprotectMemory`
  too) — the same ceiling, narrowed in time.

### TPM PCR sealing (hardening program, phase 4) — status

Binding the DEK to a **boot state** (PCR policy) and a **TPM PIN** (hardware
dictionary-attack lockout) would be the deepest hardware hardening, but on the
Windows CNG path it is **not available**, and the alternatives cannot be delivered
safely in the current environment:

- **CNG cannot express PCR-policy sealing** (documented limitation); the DEK stays
  bound to the TPM's non-exportable *platform key* — device-bound, not boot-state
  bound.
- **`tss-esapi`** (the usual Rust TSS binding) targets the Linux `tpm2-tss` C
  libraries and **fails to build on this Windows-first target**, so it cannot be
  adopted without breaking the build and the supply-chain gate.
- The only Windows-viable route is hand-built TPM2 commands over **TBS**, which
  **must be validated against real TPM hardware** (with data-loss tests) before
  shipping — an unverified implementation could permanently lock a vault.

Rather than ship unverified TPM code, this remains **specified and deferred** (see
the phase-4 section of the design spec for the concrete TBS/TPM2 plan). What ships
now is honesty: `vaultctl seal-status` states the ceiling explicitly
(`pcr_policy: none — device-bound …, NOT sealed to a PCR/boot state`) so it is never
implied to be stronger than it is.

### Metadata encryption — format v3 (hardening program, phase 3)

Previously a stolen `.ztsv` leaked its record **names** (authenticated, but stored
in plaintext), the exact size of every name and value, and the record count.
Format v3 closes all three:

- **Encrypted names.** Each record's name is encrypted under its own per-record
  HKDF subkey (distinct from the value's), so the file no longer reveals what
  accounts it holds. Listing names now requires unlocking — and the names shown are
  therefore *authenticated*, eliminating the old "unauthenticated metadata" caveat.
- **Padded sizes.** Names and values are padded to fixed size buckets before
  encryption, so a record's on-disk length reveals only a coarse bucket, not the
  real length.
- **Padded count.** The record set is padded with indistinguishable *tombstone*
  records up to a count bucket (minimum 8, so even an empty vault looks like 8
  records), and real vs tombstone positions are shuffled on every save. The count
  is revealed only to a coarse bucket. Tombstones are inside the authenticated
  set and filtered out at unlock.

The DEK envelope and AEAD/MAC constructions are unchanged; no new primitive. An
existing **v2** vault is read and **auto-migrated to v3 on the next save**: it is
authenticated under the legacy MAC, its values are re-encrypted into the v3 layout,
and (for a legacy escrow) a human recovery passphrase is still accepted — so the
upgrade is lossless and transparent. Only a **v1** vault (single-factor, genuinely
weaker crypto) stays unreadable and must be recreated. Verified empirically: a
distinctive record name and value do not appear anywhere in a v3 file, the on-disk
record count is padded, and a v2 vault round-trips through migration to v3.

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
opt-in feature of this slice, toggled in Settings) is a reveal gate — not
app-entry, and never a contribution to the cryptographic key.

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

## Reporting a vulnerability

**Please report privately, not in a public issue.**

### Primary channel: GitHub Private Vulnerability Reporting

Open a private report here:

> https://github.com/largefries7-lgtm/zero-trust-secrets/security/advisories/new

This creates a private advisory visible only to you and the maintainers. It
supports threaded discussion, private draft patches, and — once a fix is ready —
coordinated publication. Nothing you write there is public until the advisory is
published.

If that link returns a 404, Private Vulnerability Reporting has not been enabled
on the repository yet; see [`CONTRIBUTING.md`](CONTRIBUTING.md) for the enabling
steps, and in the meantime email the address in the repository owner's GitHub
profile rather than filing a public issue.

### What to include

- The impact, stated concretely: what an attacker gains, and what access they
  need to start with. This project already concedes a broad class of attacker
  (see **Threat model** above) — a report that assumes kernel compromise or an
  attacker already executing inside the process is describing a documented
  limitation, not a vulnerability.
- A reproduction: exact steps, the build/commit, and your Windows version.
  A failing test or a `.ztsv` fixture is ideal.
- Whether you intend to publish, and on what timeline.

### What happens next

This is a personal project, not a funded product, so these are honest targets
rather than a contractual SLA:

| Stage | Target |
|---|---|
| Acknowledgement | 5 business days |
| Initial assessment (valid / not / need more) | 14 days |
| Fix or documented mitigation for a confirmed issue | 90 days, sooner when the severity warrants |

If a report is going to take longer than that, you will be told why rather than
left waiting.

### CVE assignment

**Confirmed vulnerabilities get a CVE.** GitHub is a CVE Numbering Authority,
and this project requests a CVE through the GitHub Security Advisory once a
report is validated — regardless of whether the reporter asks for one. The
advisory is published together with the fix, crediting the reporter unless they
ask otherwise.

We do not silently patch security bugs. A vulnerability that is real enough to
fix is real enough to disclose.

### Scope

**In scope** — anything that breaks a claim this document makes: recovering
plaintext from a `.ztsv` without the passphrase, a parser flaw reachable from a
hostile vault file, secrets surviving in memory where **Empirical verification**
says they do not, the vault failing open instead of closed, or a supply-chain
weakness in the release pipeline (see [`VERIFICATION.md`](VERIFICATION.md)).

**Out of scope** — the limitations this document already concedes, principally:
a compromised kernel, an attacker with code execution in the vault process, and
the absence of PCR-policy binding (see **TPM PCR sealing — status**). These are
documented ceilings, not bugs. If you believe one is understated, that argument
is itself in scope and worth making.

### Safe harbor

Good-faith research against your own installation is welcome and will not draw a
legal complaint. Do not test against other people's data or systems.
