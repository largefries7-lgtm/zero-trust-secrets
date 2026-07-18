# Zero-Trust Local Secrets Manager

A local-first, air-gapped secrets manager whose master key is **bound to this
machine's TPM** and whose plaintext secrets **provably never linger in process
RAM** longer than the design admits. The security core is a Rust library
(`vaultcore`); `vaultgui` (Slint desktop app) is the primary user surface as of
slice 2; `vaultctl` (CLI) remains for automation/testing; `verify/` is the
memory-scraping verification harness for both.

> Windows-first. The TPM path uses the CNG Platform Crypto Provider and has been
> exercised on real hardware. macOS/Linux providers are compiled stubs for now.

## Requirements

- Rust 1.96+ (`cargo`)
- Windows 11 with a usable TPM 2.0 (for the hardware-bound path). Without a TPM,
  use `--allow-no-tpm` to fall back to a recovery-passphrase-only vault (it prints
  a loud warning that hardware binding is off).
- Python 3 is optional — only for the standalone `verify/scan_dump.py` cross-check.

## Build

```sh
cargo build --release -p vaultctl
# binary: target/release/vaultctl.exe
```

## Desktop GUI (`vaultgui`) — the primary user surface

```sh
cargo build --release -p vaultgui
# binary: target/release/vaultgui.exe
cargo run --release -p vaultgui        # or run the built exe directly
```

`vaultgui` is a Slint desktop app and is the primary way to use the vault day to
day: create/unlock, browse and search records, reveal/copy with an auto-clearing
clipboard, generate passwords, and manage settings (auto-lock timeout, Hello
toggle, deprovision). It is Windows-first, like the rest of this project. The
`vaultctl` CLI documented below is retained in the repo as an automation/testing
tool, not replaced.

**GUI security surfaces.** Unlike the stateless CLI (which obtains the DEK fresh
per command), `vaultgui` holds the decryption key in RAM for the whole unlocked
session, aggressively auto-locking on idle, workstation-lock, suspend, or manual
"Lock now". It also blanks itself to screen capture/screen-share and offers an
optional Windows Hello gate on secret reveal (opt-in in Settings) that does not
touch the crypto. These are real new surfaces with honest, stated limits (a
long-lived in-RAM key while unlocked, and un-zeroizable input-field/revealed-value
residuals in the UI toolkit) — see the as-built section of the slice-2 design spec
for the full defended/not-defended breakdown:
[`docs/superpowers/specs/2026-07-16-slice2-gui-design.md`](docs/superpowers/specs/2026-07-16-slice2-gui-design.md)
(§13).

## Quickstart

```sh
BIN=target/release/vaultctl.exe

# Create a TPM-bound, two-factor vault. You are prompted (no echo) for an
# UNLOCK passphrase; every unlock then needs the TPM *and* that passphrase.
$BIN --vault my.ztsv init

# Optional: also create a single-factor recovery escrow (survives TPM loss). A
# 128-bit recovery CODE is generated and printed ONCE — store it offline:
#   $BIN --vault my.ztsv init --recovery

$BIN --vault my.ztsv seal-status
#  hardware_bound: true
#  factors: TPM + passphrase (two-factor)
#  provider: Windows CNG Platform Crypto Provider (TPM-backed, non-exportable ...)

# Add + read secrets (each command prompts for the unlock passphrase; the TPM
# factor is unsealed automatically):
$BIN --vault my.ztsv add github                 # prompts for the value (no echo)
$BIN --vault my.ztsv add github --force         # rotate an existing name in place
$BIN --vault my.ztsv get github                 # prints the value
$BIN --vault my.ztsv get github --clip          # clipboard copy, auto-clears in 15s
$BIN --vault my.ztsv list                       # names only
$BIN --vault my.ztsv rm github                  # delete a record

# If the vault has a recovery escrow (init --recovery), unlock via the code:
$BIN --vault my.ztsv get github --recovery --recovery-code "XXXX-XXXX-..."

# Standalone password generator (OS CSPRNG, reports entropy):
$BIN gen --len 24 --symbols
```

Note: a plain `add <name>` refuses to overwrite an existing name (so a secret is
never silently shadowed); use `--force` to rotate it in place.

No-TPM machine (e.g. a VM/CI): add `--allow-no-tpm` to `init`. The unlock
passphrase becomes the sole factor; pass `--passphrase` (prompted if omitted) to
`add`/`get`/`rm` — there is no TPM to auto-unseal.

## Commands

| Command | Purpose |
|---------|---------|
| `init [--allow-no-tpm] [--passphrase <pw>] [--recovery]` | Create a vault; wrap the DEK under TPM + passphrase (two-factor), optionally add a single-factor recovery escrow (prints a generated 128-bit code once). Refuses a weak passphrase. |
| `unlock [--passphrase <pw>] [--recovery --recovery-code <code>]` | Credential smoke-check (verifies you can obtain the DEK) |
| `lock` | No-op by design — the CLI is stateless, nothing is cached to clear |
| `add <name> [--value <v>] [--force] [--passphrase <pw>]` | Add a secret; refuses an existing name unless `--force` (rotate in place) |
| `rm <name> [--passphrase <pw>]` | Remove a secret record |
| `get <name> [--clip] [--passphrase <pw>]` | Read a secret (stdout, or clipboard with auto-clear) |
| `list` | List secret names (metadata only) |
| `gen [--len N] [--symbols]` | Generate a password and report entropy |
| `seal-status` | Show `hardware_bound`, factors, the active key provider, and warnings |
| `deprovision [--yes]` | Delete the persisted TPM wrapping key (destructive) |

`--recovery-code` (on `unlock`/`get`/`add`/`rm`) requires `--recovery`; passing it
alone is rejected rather than silently ignored. `init --recovery` takes no code
argument — the code is generated and shown once.

`--vault <path>` is global (default `vault.ztsv`).

## How it protects your secrets

- **Hardware-bound, two-factor key.** A random 256-bit DEK encrypts every secret
  (XChaCha20-Poly1305). On a hardware-bound vault the DEK is wrapped under
  `KEK = HKDF(tpm_secret ‖ Argon2id(passphrase))`, so unlocking requires **both**
  the original TPM **and** the passphrase — a stolen vault file, or same-user
  malware that can drive the TPM, is useless without also capturing the passphrase.
  An optional, off-by-default recovery escrow (`init --recovery`) additionally wraps
  the DEK under a **generated 128-bit recovery code** (shown once, stored offline) —
  as strong as the DEK itself — trading theft-resistance for survivability if the
  TPM is lost.
- **Calibrated KDF + strength floor.** The Argon2id passphrase cost is
  auto-calibrated at vault creation to the largest memory (256 MiB floor, up to a
  1 GiB cap) that keeps unlock near ~0.75 s on the creating machine — materially
  harder against offline attack than a fixed default (was 64 MiB). Creation also
  refuses weak passphrases: a length + character-class entropy floor plus a
  common-password blocklist, stricter for a passphrase-only vault than a two-factor
  one.
- **Tamper-evident.** The vault header and the whole record set (count, order,
  names, ciphertext) are authenticated by an HKDF-keyed HMAC; each secret is also
  bound to its name via AEAD AAD. Relabel / delete / reorder / inject all fail
  closed at unlock. `save` is atomic and durable (temp file, `fsync`, then rename).
- **Memory hygiene.** All secret material lives in `ZeroizeOnDrop`, page-locked
  (`VirtualLock`), exact-capacity buffers and is zeroized the moment it's dropped.
  The CLI is **stateless**: the DEK is never written to disk.

## Verify the memory-safety claim yourself

```sh
bash verify/run.sh
```

This builds `vaultctl` with a hidden `leaktest` feature, spawns it into defined
states, dumps its full process memory (`MiniDumpWriteDump`), and scans the dump:

```
scenario     sentinel  canary_u8  canary_u16         expected  result
locked              2          0           0 sent>=1 & can==0  PASS
post-clip           9          0           0 sent>=1 & can==0  PASS
leak(ctrl)          -          5           2           can>=1  PASS
OVERALL: PASS
```

(Exact hit counts vary per run with heap layout — what matters is `canary == 0`
for `locked`/`post-clip` and `canary >= 1` for the control.) `locked` and
`post-clip` find **zero** plaintext canary in RAM; the `leak`
positive control proves the scanner actually works; each clean scenario also finds
a non-secret sentinel, proving its own dump is real (not vacuously empty). See
[`verify/TEST_PLAN.md`](verify/TEST_PLAN.md).

`verify/run.sh` also builds and dumps `vaultgui` (`gui-locked` / `gui-post-autolock`
/ `gui-leak`), including the honestly-reported Slint widget residual for
`gui-post-autolock`. Those scenarios need a real interactive Windows session (a
display, and a TPM for the Hello-gated paths) — see `verify/TEST_PLAN.md` for the
current recorded result in this environment.

## Honest limitations (slice 1)

- TPM binding is **device-bound, not PCR-policy-bound** (a CNG limitation); real
  PCR sealing needs a `tss-esapi` backend in a later slice.
- `--value` / `--recovery-code` travel on the command line (visible in
  process listings). This is a property of the test/automation CLI; the GUI slice
  avoids argv. The `--clip` path routes the secret via stdin, not argv.
- Record **names** are authenticated but stored as plaintext metadata (values are
  encrypted).
- **Not defended:** a debugger attached to the live *unlocked* process at
  decryption time, kernel keyloggers, or a compromised OS.

Full design, threat model, and as-built notes:
[`docs/superpowers/specs/2026-07-14-zero-trust-secrets-core-design.md`](docs/superpowers/specs/2026-07-14-zero-trust-secrets-core-design.md).

## Layout

```
crates/vaultcore/   library: secret types, crypto, vault format, KeyProvider HAL
crates/vaultctl/    the CLI
crates/vaultgui/    the Slint desktop GUI (slice 2)
verify/             memory-scraping harness (dumper + scan_dump.py + TEST_PLAN)
docs/               design spec + implementation plan
```

## Test

```sh
cargo test --workspace   # vaultcore 59 (lib) + codec-fuzz 3 + proptest 1, vaultctl CLI 11, vaultgui 20
bash verify/run.sh       # empirical memory-dump proof (CLI + GUI scenarios)
```

`vaultgui` is a workspace member but not a `default-member` (see `Cargo.toml`), so
plain `cargo test` skips its 19 tests — pass `--workspace` to include them. Counts
above are current as of this doc; they will drift as tests are added, so treat
`cargo test --workspace` itself as the source of truth.
