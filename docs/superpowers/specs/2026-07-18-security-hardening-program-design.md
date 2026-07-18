# Security Hardening Program — Design

**Date:** 2026-07-18
**Status:** approved (user authorized autonomous execution of all phases)
**Scope:** make `vaultcore` / `vaultctl` / `vaultgui` "as secure as physically achievable"
below the userspace ceiling stated in `SECURITY.md`, closing the documented gaps
between the current design and that ceiling.

This program is decomposed into four independent phases. Each keeps the project's
ethos: **no new cryptographic primitives** (only standard constructions composed),
honest defended/not-defended docs updated per phase, and — where a new runtime
claim is made — the `verify/` memory-dump harness extended to *prove* it.

| Phase | Front | On-disk format | Effort |
|------:|-------|----------------|--------|
| 1 | Passphrase-factor hardening (KDF calibration, strength gate, recovery code) | no change | S |
| 2 | Process & RAM hardening (build mitigations, runtime mitigation policies, in-RAM DEK protection, crash-dump opt-out) | no change | M |
| 3 | Metadata encryption (encrypt+pad record names, pad sizes) | **v3** | M |
| 4 | TPM PCR sealing + PIN (`tss-esapi` backend) | header fields | L |

**Cross-cutting:** Phases 3 and 4 both touch the on-disk header. They are designed
so existing vaults are not broken twice — Phase 3 introduces format v3 with a clean
additive layout that Phase 4's PCR fields slot into. Dependency-surface tension is
flagged where it arises (Phase 4's `tss-esapi`), consistent with front F's
"shrink the surface" goal; Phase 1 adds **no** dependency.

---

## Phase 1 — Passphrase-factor hardening

**Status: implemented (2026-07-18).** As-built: `crypto::Argon2Params::calibrate`
(release-measured 512 MiB / ~695 ms unlock on the dev machine), `strength` module
(estimator + blocklist + context-aware `Policy`), `recovery::RecoveryCode`
(Crockford base32 128-bit), `flow::{KdfStrategy, unlock_with_recovery_code}` +
`Error::WeakPassphrase`; CLI `--recovery-code`; GUI live strength meter + one-time
recovery-code screen. vaultcore 59 lib tests (+16), CLI 11 (+1). Calibration only
selects meaningfully in a release build (debug Argon2 is ~10–50× slower and floors
at 256 MiB — safe, just slow).

**Goal:** maximize resistance of a *stolen vault file* to offline attack, which is
the most realistic threat against a local vault. Three parts, all in `vaultcore`
plus the CLI/GUI flows. **No on-disk format change** — Argon2 parameters already
live in the (authenticated) header, so stronger values are fully compatible.

### 1A. Argon2id auto-calibration

- New `Argon2Params::calibrate(target, max_trial)` in `crypto.rs`. At vault
  creation it climbs `mem_kib` geometrically from a **256 MiB floor**, holding
  `time = 3`, `parallelism = 1` (the RustCrypto `argon2` crate computes lanes
  serially, so memory is the honest cost knob), choosing the **largest** memory
  whose measured single-derive stays **≤ ~0.75 s**, clamped to a **1 GiB cap**
  (== `vault::MAX_ARGON2_MEM_KIB`, so headers always parse). The floor wins over
  the time target on a weak machine; a per-trial `max_trial` (~3 s) bounds init.
- `default_tuned()` is retained for tests. Production `create_vault` uses
  calibration, but calibration is **injectable** via `CreateOptions.kdf` so the
  test suite stays fast and calibration logic is unit-testable in isolation.

### 1B. Passphrase strength gate

- New pure module `vaultcore::strength`: `estimate(&str) -> Estimate` and
  `check(&str, &Policy) -> Result<(), Weakness>`. Entropy is the honest
  length × log2(effective character-pool) estimate, **plus an embedded
  common-password blocklist** (a few hundred of the most common choices +
  trivial patterns) that hard-rejects known-weak passphrases regardless of the
  computed bits. Documented as a *floor, not a strength promise* (the tradeoff for
  declining a zxcvbn dependency).
- **Context-aware policy:** two-factor (TPM-bound) floor ≈ 50 bits; single-factor
  (no-TPM) floor ≈ 70 bits; a hard minimum length regardless. New
  `Error::WeakPassphrase(reason)`. Enforced authoritatively inside
  `create_vault` (covers the CLI too) and surfaced live in the GUI create screen.

### 1C. Generated recovery code

- The opt-in recovery escrow stops taking a *human passphrase*. `create_vault`
  generates **128 bits** from `OsRng`, encoded as **Crockford base32** grouped in
  4-char blocks (case-insensitive, ambiguity-free, no wordlist dependency), wraps
  the DEK under it via the *existing* `wrap_dek_recovery` (no new crypto), and
  returns the code **once** in `CreateOutcome.recovery_code`. It is never stored.
- A single canonical `normalize()` (strip separators, upcase, Crockford aliases)
  is applied on both generation and unlock input, so formatting never matters.
- `CreateOptions.recovery_passphrase: Option<SecretString>` → `recovery: bool`.
  CLI: `init --recovery` prints the code with a loud "shown once" warning; recovery
  unlock flag becomes `--recovery-code`. GUI: shows the code once with copy + an
  explicit "I saved it" confirmation.
- **No in-place migration** of any pre-existing passphrase-based recovery vault —
  a vault must be recreated to adopt the code path (matches the existing v1→v2
  "recreate to upgrade crypto" stance). Recovery stays **off by default**.

### Verification (Phase 1)
Unit tests: calibration stays within [floor, cap] and respects the target/floor;
estimator accepts strong / rejects short+common; context floors; recovery-code
generate → wrap → normalize(display) → normalize(input) → unwrap round-trips and a
wrong code fails closed. CLI integration tests updated for the new recovery flag.
Docs (README / SECURITY / slice-1 as-built) updated in the honest voice; the
one-time recovery-code on-screen display is called out as sharing the existing
Slint display-residual caveat. No `verify/` change (no new secret residency).

---

## Phase 2 — Process & RAM hardening (Windows)

- **Build mitigations:** add `.cargo/config.toml` RUSTFLAGS enabling Control Flow
  Guard (`/guard:cf`), CET shadow stack (`/CETCOMPAT`), high-entropy ASLR; add a
  release profile (`panic = "abort"`, `overflow-checks = true`, `lto`, `strip`).
- **Runtime `SetProcessMitigationPolicy`** (new `vaultgui` startup + optional for
  `vaultctl`): block dynamic code, remote/low-integrity image loads, and
  extension-point DLLs; enable CET. Signature-only policy is left off by default
  because it can break vendor GPU-driver loads under Slint (documented).
- **In-RAM DEK protection:** wrap the at-rest DEK with `CryptProtectMemory`
  (`SameProcess`) in the `vaultgui` `Session`, decrypting only for the moment of a
  crypto op, shrinking the cold-boot / scrape window between operations.
- **Crash-dump opt-out:** `panic = "abort"` + `WerAddExcludedApplication` /
  disable WER for the process so a crash cannot spill secrets to a `.dmp`.
- Verify: extend the dump harness with a `gui-idle-protected` scenario asserting
  the DEK is not plaintext-findable *between* operations.

## Phase 3 — Metadata encryption (format v3)

- Encrypt record **names** (currently authenticated plaintext) under a per-vault
  HKDF name-subkey, and **pad** names + record ciphertext to size buckets so a
  stolen file leaks neither what accounts exist nor their sizes; pad the record
  **count** to a bucket too. Bump `FORMAT_VERSION` to 3 with a clean additive
  header layout that Phase 4 extends. Provide a v2→v3 upgrade on next save.

## Phase 4 — TPM PCR sealing + PIN

- Add a `tss-esapi` backend behind the existing `KeyProvider` trait that seals the
  TPM secret under a **PCR policy** (boot-state binding) and an optional **TPM
  PIN** (hardware anti-hammering), populating the already-present but unused
  `pcr_selection` header field. `tss-esapi` is a **new dependency** — the surface
  cost is disclosed. CNG path retained as the default/fallback.

---

## Out of scope (whole program)
New crypto primitives; a dual-cipher cascade; duress/decoy vaults; non-Windows
TPM/mitigation parity (stubs stay stubs). Front F items beyond the build-hardening
already folded into Phase 2 (cargo-vet, Authenticode signing, reproducible builds)
are noted as follow-ups, not implemented here.
