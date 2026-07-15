# Zero-Trust Local Secrets Manager — Slice 1: Security Core Design

- **Date:** 2026-07-14
- **Status:** Draft for review
- **Author:** Riley (with Claude Code)
- **Scope:** Slice 1 of N — headless security core + verification harness. No GUI.

---

## 1. Purpose & scope

Build the security-critical core of a local-first, air-gapped secrets manager as a
headless Rust library (`vaultcore`) plus a thin CLI (`vaultctl`) and a mandatory
memory-scraping verification harness (`verify/`).

This slice deliberately excludes the GUI. The GUI (Slint, pure Rust) is **slice 2**
and gets its own spec. The reason for headless-first: the load-bearing, *provable*
claims of this product are (a) hardware-bound key protection and (b) plaintext memory
hygiene. Those can be built and tested end-to-end in a headless core. The GUI is
mostly presentation and is where the hardest *honesty* problems live, so it is
sequenced second on a proven foundation.

### In scope (slice 1)
- 256-bit Data Encryption Key (DEK), never persisted in plaintext.
- Envelope encryption with dual key-wrapping: TPM-seal + Argon2id recovery escrow.
- Encrypted, authenticated, versioned vault file format.
- Zeroizing secret types (`Zeroize` + `ZeroizeOnDrop`) with anti-reallocation discipline
  and page-locking (`VirtualLock`).
- `KeyProvider` hardware-abstraction trait with a working Windows implementation
  (CNG Platform Crypto Provider) and compiled stubs for macOS/Linux.
- `vaultctl` CLI: `init`, `unlock`, `lock`, `add`, `get`, `list`, `gen`, `seal-status`,
  clipboard copy with auto-clear.
- Memory-scraping verification harness with a **positive control**, plus a written test plan.

### Explicitly out of scope (slice 1) — deferred to later slices
- Slint GUI, dark-mode UX, fuzzy search UI, entropy visualizer, biometric unlock UI. *(Slice 2)*
- Anti-screenshot window flags (`SetWindowDisplayAffinity`, `NSWindowSharingNone`). *(Slice 2, needs a window)*
- macOS Secure Enclave / `LocalAuthentication` implementation. *(Later; not testable on this machine)*
- Linux Wayland/X11 surface protections and a `tss-esapi` TPM provider. *(Later)*
- Windows Hello / TouchID biometric gating. *(Slice 2)*

---

## 2. Environment findings (2026-07-14, this machine)

| Fact | Value | Consequence |
|------|-------|-------------|
| OS | Windows 11 IoT Enterprise LTSC 2024 (26100) | Windows-first; macOS untestable here |
| Rust / Cargo | 1.96.0 | Build stack ready |
| Node | 26.3.0 | Only relevant to slice 2 (not used here) |
| Project dir | empty | Greenfield |
| TPM WMI query | **Access denied** (non-admin) | Cannot assume elevated TPM ops; `VirtualLock` privilege may also be denied — must degrade gracefully |

**Implication:** the core must run and be testable **without** elevation or a guaranteed
usable TPM. The recovery-escrow path doubles as the testable software path. Any operation
that needs privileges it cannot obtain must degrade with a loud, recorded warning rather
than crash.

---

## 3. Threat model (honest boundaries)

### Defended
- **Drive theft / offline attack.** A stolen vault file is cryptographically inaccessible
  without either (a) the original TPM in the original PCR state, or (b) the recovery
  passphrase. No plaintext key material is at rest.
- **Process RAM scraping while locked.** With the vault locked, a full-memory dump of the
  `vaultctl` process contains no plaintext secrets and no plaintext DEK.
- **Minimized plaintext lifetime while unlocked.** The DEK and any decrypted secret exist
  in RAM only for the minimum window, in page-locked buffers that zero on drop.

### NOT defended (stated plainly, in code docs and README)
- A **debugger or code-injection attached to the live, unlocked process** at decryption
  time can read the DEK. No userspace program can prevent this against a privileged local
  attacker.
- **Kernel or hook-based keyloggers.** A GUI slice can reduce surface but cannot defeat them.
- **Cold-boot / DMA against an already-unlocked machine.** `VirtualLock` prevents swap, not
  physical RAM remanence.
- **Compromised OS / malicious firmware.** Hardware binding assumes an honest TPM+OS.
- **The OS clipboard is not process memory.** When a secret is copied, the OS clipboard
  buffer holds plaintext for any process to read until auto-cleared. This is a documented,
  inherent property of "copy to clipboard," not a bug, and the verification harness asserts
  only that the *vaultctl process's own heap* is clean — not the clipboard.

---

## 4. Architecture

Cargo workspace:

```
zero-trust-secrets/
├─ Cargo.toml                # workspace
├─ crates/
│  ├─ vaultcore/            # lib: no I/O side effects beyond the vault file
│  │  ├─ secret.rs          # Secret<T>, SecretBytes, SecretString, guards
│  │  ├─ crypto.rs          # AEAD, HKDF, Argon2id wrap/unwrap
│  │  ├─ vault.rs           # file format, records, open/save, lock/unlock state machine
│  │  ├─ keyprovider/
│  │  │  ├─ mod.rs          # trait KeyProvider, ProviderStatus, SealedBlob
│  │  │  ├─ cng_pcp.rs      # Windows CNG Platform Crypto Provider (TPM-backed)
│  │  │  ├─ recovery.rs     # Argon2id KEK escrow (always available)
│  │  │  ├─ macos_stub.rs   # Secure Enclave stub -> Unsupported
│  │  │  └─ linux_stub.rs   # tss-esapi stub -> Unsupported
│  │  └─ lib.rs
│  └─ vaultctl/             # bin: clap CLI over vaultcore
├─ verify/
│  ├─ dumper/               # Rust: MiniDumpWriteDump driver + scenario runner
│  ├─ scan_dump.py          # "Volatility-style" canary scanner
│  └─ TEST_PLAN.md          # step-by-step verification procedure
└─ docs/
```

Each crate has one clear purpose and a narrow public interface. `vaultcore` performs no
network I/O ever (air-gapped by construction) and touches only the single vault file it is
given.

---

## 5. Key model — envelope encryption, dual-wrapped (Approach A)

```
                     ┌─────────────────────────────┐
   random 256-bit →  │           DEK               │  encrypts every record (XChaCha20-Poly1305)
                     └──────────────┬──────────────┘
                                    │ wrapped two independent ways, both stored in header:
             ┌──────────────────────┴───────────────────────┐
             ▼                                               ▼
   ┌──────────────────┐                          ┌──────────────────────┐
   │  TPM-sealed blob │  unlock path A           │ recovery-wrapped DEK │  unlock path B
   │  (CNG PCP, PCR-  │  (silent, device-bound)  │  AEAD under KEK =     │  (passphrase)
   │   bound key)     │                          │  Argon2id(recovery pw)│
   └──────────────────┘                          └──────────────────────┘
```

- The DEK is generated once from the OS CSPRNG at `init`.
- **Path A (TPM):** the DEK is sealed/wrapped by a non-exportable, TPM-resident key created
  in the CNG Platform Crypto Provider, bound to device + PCR policy. Unwrapping requires the
  same TPM in an acceptable PCR state.
- **Path B (recovery):** the DEK is encrypted with a KEK derived from a user recovery
  passphrase via Argon2id. This is the escrow that survives PCR changes (BIOS/OS updates),
  motherboard replacement, or TPM loss.
- Rotating the recovery passphrase, or re-sealing after a legitimate PCR change, rewraps only
  the DEK — record ciphertext is untouched.
- **Rejected alternatives:** (B) sealing a passphrase-derived key directly — messy recovery,
  couples records to the TPM; (C) TPM-as-HMAC-oracle deriving the DEK fresh each unlock —
  elegant and arguably strongest, but materially harder to get right and complicates escrow.
  Revisit (C) in a hardening pass.

### `--allow-no-tpm`
If no usable TPM is present at `init`, the vault can still be created with an explicit
`--allow-no-tpm` flag. The header records `hardware_bound = false`, `seal-status` reports it
prominently, and every unlock prints a warning. This keeps the tool usable and testable on
this locked-down box **without silently weakening the security claim**.

---

## 6. Vault file format

A single file, versioned and fully authenticated. Conceptual layout:

```
Header (authenticated):
  magic            "ZTSV"
  format_version   u16
  hardware_bound   bool
  aead_id          u8            # XChaCha20-Poly1305
  kdf_params       { mem_kib, time, parallelism, salt[16] }   # Argon2id
  pcr_selection    [u32]         # PCRs the TPM seal is bound to (empty if !hardware_bound)
  tpm_wrap         Option<bytes> # TPM-sealed DEK (path A)
  recovery_wrap    bytes         # AEAD(KEK, DEK) + nonce (path B)
  header_mac        # HKDF-derived MAC over all the above (fail-closed on tamper)
Body:
  records[]        # each: AEAD(DEK-derived subkey, plaintext) with AAD = record_id||version
```

- Header integrity via an HKDF-SHA256-derived MAC key; any tamper (including downgrade of
  `hardware_bound` or PCR selection) fails the open.
- Per-record subkeys via `HKDF(DEK, "record" || record_id)` for domain separation.
- Random 24-byte XChaCha20 nonce per record; nonces stored alongside ciphertext.
- Serialization is hand-shaped (not `#[derive(Serialize)]` on any secret-bearing type) so
  plaintext never flows through a serializer buffer.

---

## 7. Cryptographic primitives & crates

| Concern | Choice | Crate |
|---------|--------|-------|
| Record & DEK-wrap AEAD | XChaCha20-Poly1305 | `chacha20poly1305` |
| Recovery KDF | Argon2id (benchmarked params) | `argon2` |
| Subkey / MAC key derivation | HKDF-SHA256 | `hkdf`, `sha2` |
| Constant-time compare | — | `subtle` |
| CSPRNG | OS entropy only | `getrandom` / `rand_core::OsRng` |
| Zeroization | `Zeroize`, `ZeroizeOnDrop` | `zeroize` |
| Windows TPM + `VirtualLock` + minidump | CNG / Win32 | `windows` |
| CLI | — | `clap` |
| Property tests | — | `proptest` |

- **AEAD rationale:** XChaCha20-Poly1305's 192-bit nonce makes random-nonce collisions a
  non-issue; no nonce counter state to manage. (AES-256-GCM considered; rejected to avoid
  nonce-management footguns, despite AES-NI speed — throughput is not the bottleneck here.)
- **Argon2id params** are chosen by a one-time calibration targeting ~64 MiB / t=3 / p=1
  (tuned so a derive takes a few hundred ms), stored per-vault so the vault is portable.

---

## 8. KeyProvider HAL

```rust
pub trait KeyProvider {
    fn status(&self) -> ProviderStatus;                        // Available | Unsupported | Degraded{reason}
    fn seal(&self, dek: &SecretBytes, pcrs: &[u32]) -> Result<SealedBlob>;
    fn unseal(&self, blob: &SealedBlob) -> Result<SecretBytes>;
    fn describe(&self) -> String;                              // for `seal-status`
}
```

- **`CngPcpProvider` (Windows, real):** `NCryptOpenStorageProvider(MS_PLATFORM_CRYPTO_PROVIDER)`,
  create/open a persisted non-exportable TPM key, and wrap the DEK with it. PCR binding via the
  provider's platform key attributes. No native `tpm2-tss` build required. Degrades to
  `Unsupported` (not a crash) if the platform provider is absent.
- **`RecoveryProvider` (all platforms, real):** Argon2id KEK + AEAD wrap of the DEK. Always
  available; the escrow path and the test path.
- **`macos_stub` / `linux_stub`:** compile, return `Unsupported`. Keep the seam honest; real
  Secure Enclave and `tss-esapi` implementations land in later slices.

`tss-esapi` is intentionally **not** a slice-1 dependency: on Windows it drags in a heavy,
finicky `tpm2-tss` native build. It is documented as the future Linux backend.

---

## 9. Memory safety model

- **`Secret<T>` family:** `SecretBytes` (wraps `Vec<u8>`) and `SecretString`, both
  `Zeroize + ZeroizeOnDrop`. `Debug`/`Display` redact to `Secret(***)`. No derived `Clone` or
  `Serialize`; explicit `expose()` returns a borrow with a documented, minimized lifetime.
- **Anti-reallocation discipline:** secrets are constructed in **exact-capacity** buffers and
  never grown. Rationale: `Vec` growth allocates a new buffer, copies, and frees the old one
  *without zeroizing* — leaving a stale plaintext copy on the heap. The verification harness's
  positive control specifically exercises this failure mode.
- **Page locking:** DEK and decrypted-record buffers are `VirtualLock`ed to keep them out of
  the pagefile; if the privilege is denied, downgrade with a recorded warning (do not fail).
- **Lifecycle:** DEK is materialized only between `unseal` and `lock`. `lock` zeroizes the DEK
  and drops all cached plaintext. Decrypted values are returned as `SecretString`, printed or
  copied, then dropped immediately.
- **No leaks through the back door:** no secret is ever passed to `format!`, `println!` of a
  non-redacted value, logging, or an error message. Clipboard copy spawns an auto-clear timer
  (default 15 s) and zeroizes its own source buffer.

---

## 10. Verification harness (mandatory) + positive control

Deliverables under `verify/`:

1. **`dumper/`** — a Rust program that: plants a unique canary secret `CANARY-<uuid>`, drives
   `vaultctl` into a defined state, and captures a full-memory minidump of the target process
   via `MiniDumpWriteDump` (`MiniDumpWithFullMemory`). A Linux path via `/proc/<pid>/mem` is
   noted for later.
2. **`scan_dump.py`** — a simulated Volatility-style scanner that memory-maps the raw dump and
   reports every offset where the canary (and a set of derived encodings: UTF-8, UTF-16LE) is
   found.
3. **`TEST_PLAN.md`** — the step-by-step procedure and expected results.

### Scenarios asserted
- **S1 — Locked vault:** unlock, then `lock`, then dump. **Expected: 0 canary hits** and no
  plaintext DEK.
- **S2 — Post-clipboard:** `get` a secret with clipboard copy, wait past the copy, dump the
  `vaultctl` process. **Expected: 0 canary hits in the process heap.** (The OS clipboard is out
  of scope and separately documented.)
- **S3 — Positive control (must FAIL to be clean):** a build/test-only leaky path holds the
  canary in a plain `String`; dump and scan. **Expected: canary IS found.** This proves the
  scanner and dumper actually work — without it, S1/S2 passing is meaningless.

A run passes iff S1 = 0 hits, S2 = 0 hits, **and** S3 > 0 hits.

---

## 11. CLI surface (`vaultctl`)

```
vaultctl init [--allow-no-tpm]         # create vault, generate DEK, set recovery passphrase, seal
vaultctl unlock                        # TPM unseal (path A) or --recovery (path B)
vaultctl lock                          # zeroize DEK + cached plaintext
vaultctl add <name>                    # add secret (value read without echo, into a Secret buffer)
vaultctl get <name> [--clip]           # print (redacted by default) or copy to clipboard w/ auto-clear
vaultctl list                          # names + metadata only, never values
vaultctl gen [--len N] [--symbols]     # CSPRNG password generator, reports entropy bits
vaultctl seal-status                    # provider, hardware_bound, PCR selection, warnings
```

---

## 12. Testing strategy (TDD)

- **Unit:** secret zeroization (controlled-allocation pointer peek after drop), AEAD round-trip
  + tamper rejection, Argon2id wrap/unwrap, HKDF known-answer vectors, constant-time compare,
  password-generator entropy accounting.
- **Integration:** `init → seal → lock → unseal → read`; recovery-passphrase unlock; wrong
  passphrase fails closed; tampered header/PCR/`hardware_bound` fails closed; `--allow-no-tpm`
  path stamps and warns.
- **Property (`proptest`):** vault serialize/deserialize round-trip; arbitrary record
  contents survive encrypt/decrypt.
- **Verification:** S1/S2/S3 above, wired as a CI-runnable script.

Every feature is written test-first per the TDD skill.

---

## 13. Open risks

- **CNG PCP PCR binding depth.** CNG exposes TPM-backed keys but is less granular about PCR
  policy than raw TPM2. If fine-grained PCR sealing proves infeasible via CNG, slice 1 binds
  to the device/platform key (still defeats drive theft) and records the exact binding in
  `seal-status`; full PCR-policy sealing may require the `tss-esapi` backend in a later slice.
  This is called out so it is not discovered as a surprise.
- **`VirtualLock` privilege** may be denied on this box (TPM WMI already was) — handled by the
  documented degrade-with-warning path.
- **Minidump size/permissions.** `MiniDumpWriteDump` on self or a child requires appropriate
  access; the harness runs the target as a child of the dumper to guarantee the handle.

---

## 14. Milestones (for the implementation plan)

1. Workspace + `Secret<T>` types + zeroization/anti-realloc unit tests + positive-control scaffold.
2. Crypto core (AEAD, HKDF, Argon2id wrap) + tests.
3. Vault file format + open/save/lock state machine + tamper tests.
4. `KeyProvider` trait + `RecoveryProvider` (real) + platform stubs.
5. `CngPcpProvider` (Windows TPM) + `seal-status`.
6. `vaultctl` CLI incl. clipboard auto-clear.
7. `verify/` dumper + scanner + `TEST_PLAN.md`; wire S1/S2/S3.

Slice 2 (separate spec): Slint GUI, anti-capture window flags, Windows Hello, fuzzy search,
entropy visualizer, native secret-reveal surface.

---

## 15. As-built notes & slice-1 deltas (added post-implementation, 2026-07-14)

The core was built and verified. The following decisions/deltas emerged during implementation
and supersede or refine the design above:

- **Record-set authentication added (strengthens §6).** Review found the header MAC authenticated
  only the header, leaving record framing (count/order/plaintext `name`) unauthenticated. Hardened:
  each record's ciphertext is bound to its `name` via the AEAD AAD (`id‖version‖name`), and the
  header MAC (HMAC-SHA256, HKDF-keyed) now covers the full record set (`count` + per record
  `id‖len(name)‖name‖len(ct)‖ct`). Relabel, delete, reorder, and inject now fail closed at unlock.
- **TPM backend = CNG Platform Crypto Provider; device-bound, NOT PCR-policy-bound (realizes §13).**
  `CngPcpProvider` wraps the DEK with a persisted, non-exportable RSA-2048 TPM key via NCrypt.
  This defeats drive theft (the wrap is inaccessible off the original TPM) but CNG does not expose
  PCR-policy sealing at this granularity. `status()` reports `Degraded("PCR-policy sealing not
  available via CNG…")` — honest, not overstated. **The TPM path was exercised for real on this
  machine** (create → seal → unseal → equality). Full PCR-bound sealing remains a `tss-esapi`
  hardening slice. A persisted key `ZeroTrustSecretsDEKWrap` now exists per-user; a future
  `deprovision` command should `NCryptDeleteKey` it.
- **`vaultctl` is STATELESS (supersedes §11's session concept).** The plan's persisted "session
  token" would have cached the DEK (or an unwrapping of it) at rest during the unlocked window,
  violating the core "plaintext never persists at rest" requirement. Instead every command obtains
  the DEK fresh (TPM unseal, or `--recovery-passphrase`) and zeroizes it before exit; only wrapped
  key material and encrypted records touch disk. The long-running in-RAM DEK holder is the future
  GUI/agent (slice 2).
- **Threat-model addition (extends §3):** the `--recovery-passphrase` and `--value` CLI inputs
  travel on the process command line (argv), which is world-readable in process listings. This is a
  property of the stateless *CLI* used for testing/harnessing, not of the vault at rest; the GUI
  slice avoids argv entirely.
- **Verification harness self-validates (strengthens §10).** Beyond the S3 positive control, each
  clean scenario (S1 locked, S2 post-clip) plants a non-secret `SENTINEL-<hex>` record name that
  MUST be found in that scenario's own dump — proving the dump+scan pipeline is live for that dump
  while the canary is absent. Empirical result: **S1 = 0, S2 = 0, S3 ≥ 1 → PASS**, via real
  `OpenProcess`+`MiniDumpWriteDump` without elevation.
- **Known slice-1 limitations (carried forward):** record *names* are stored as plaintext-but-
  authenticated metadata (values encrypted; names not) — a "encrypt metadata" hardening is future
  work; `VirtualLock` is page-granular/non-nesting; the `add` stdin prompt echoes (a no-echo input
  is a GUI-slice concern); `save` is non-atomic (temp-then-rename is future hardening).

---

## 16. Hardening pass — two-factor + red-team fixes (2026-07-15)

A dedicated hardening branch (`harden/security-ceiling`) pushed the core toward the achievable
ceiling. This section is the **authoritative, as-built threat model** — it supersedes the
defended/not-defended lists in §3 where they differ.

### What changed
- **Two-factor by default (format v2).** The DEK is wrapped under
  `KEK = HKDF(tpm_secret ‖ Argon2id(unlock_passphrase))`. A hardware-bound vault now requires
  **both** the TPM *and* the passphrase to unlock; the TPM seals a random secret, never the DEK.
  `--allow-no-tpm` = passphrase-only (single factor). Verified on real hardware: `get` with a
  wrong passphrase fails **even though the TPM is present**.
- **Recovery escrow is opt-in and off by default** (`init --recovery`), with a loud warning that
  it reduces a stolen vault to the recovery passphrase's strength. Default vaults have no escrow:
  losing the TPM = losing the vault (strongest).
- **Secret input hardened:** no-echo interactive entry; `--value`/`--recovery-passphrase`/
  `--passphrase` on argv now warn (argv is world-readable and cannot be scrubbed from the PEB).
- **Memory hygiene:** recovery/unlock passphrases move into zeroize-on-drop `SecretString`s
  (clap copies scrubbed); `get` wraps the decrypted buffer in place (no `to_vec` transient).
- **Parser:** DoS-safe (no pre-allocation from untrusted counts); property-fuzzed (~768 cases, no
  panics); removed MAC-bypassing `header_mut`/`set_records`.
- **`deprovision`** deletes the TPM wrapping key (typed confirmation). Supply-chain: `deny.toml`
  policy + documented dependency trust ([`SECURITY.md`](../../../SECURITY.md)).

### Defended (as-built)
- **Drive theft / offline attack** — cold vault is inaccessible without the original TPM *and*
  passphrase (default), or the recovery passphrase (if escrow was enabled).
- **Smash-and-grab same-user malware** — a process running briefly as the user that copies the
  vault file and drives the TPM **no longer gets the DEK**: it also needs the passphrase, which it
  can only obtain by additionally keylogging/persisting. This is the key gain of two-factor over v1.
- **Process RAM scraping while locked / post-operation** — empirically verified (no plaintext
  canary in a full memory dump; positive control confirms the scanner works).
- **Tamper** — header, record set (count/order/names/ciphertext), format version, and KDF params
  are all authenticated; any modification fails closed at unlock.

### NOT defended (honest ceiling — unchanged truths)
- **A keylogger or debugger present while you unlock.** Two-factor raises the bar against
  smash-and-grab, but an attacker with persistent user-level code execution can capture the
  passphrase as you type it and read the DEK from the live unlocked process. **This is the ceiling
  for a userspace app on a general-purpose OS and cannot be closed from userspace.**
- **Compromised kernel / malicious OS / cold-boot on an unlocked machine.**
- **argv exposure** of `--passphrase`/`--value` when passed on the command line (mitigated by
  no-echo prompts + warnings; the GUI slice avoids argv entirely).
- **Weak passphrases** — offline brute-force of the passphrase factor (or a recovery passphrase)
  is bounded only by Argon2id cost + passphrase entropy. Two-factor means an offline attacker also
  needs the TPM, but a recovery-enabled vault is brute-forceable to recovery-passphrase strength.
- **Record *names*** remain plaintext-but-authenticated metadata.
- **TPM binding is device-bound, not PCR-policy-bound** (CNG limitation) — does not defend against
  evil-maid boot tampering; would require a `tss-esapi` backend.

### Consciously deferred (with reason)
- **v1→v2 migration:** not built — there are no persistent v1 vaults, and a v1 reader would
  resurrect legacy single-factor crypto (more attack surface). v1 files must be recreated.
- **PCR-policy sealing, encrypted metadata names, clipboard history/cloud-sync exclusion, key
  rotation, Argon2id auto-calibration, `save` orphan-temp reaper** — real improvements, tracked as
  future work; none is a currently-exploitable hole.
