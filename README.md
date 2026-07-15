# Zero-Trust Local Secrets Manager — Security Core (Slice 1)

A local-first, air-gapped secrets manager whose master key is **bound to this
machine's TPM** and whose plaintext secrets **provably never linger in process
RAM**. This slice is the headless security core: a Rust library (`vaultcore`), a
CLI (`vaultctl`), and a memory-scraping verification harness (`verify/`). The GUI
is a separate later slice.

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

## Quickstart

```sh
BIN=target/release/vaultctl.exe

# Create a TPM-bound vault (recovery passphrase is the escrow if the TPM is ever lost)
$BIN --vault my.ztsv init --recovery-passphrase "correct-horse-battery-staple"

$BIN --vault my.ztsv seal-status
#  hardware_bound: true
#  provider: Windows CNG Platform Crypto Provider (TPM-backed, non-exportable ...)

# Add + read secrets. On a hardware-bound vault the DEK is unsealed from the TPM
# automatically — no passphrase needed for day-to-day use.
$BIN --vault my.ztsv add github --value "ghp_..."
$BIN --vault my.ztsv get github            # prints the value
$BIN --vault my.ztsv get github --clip     # copies to clipboard, auto-clears in 15s
$BIN --vault my.ztsv list                  # names only

# The recovery passphrase always works too (survives TPM loss / PCR change):
$BIN --vault my.ztsv get github --recovery-passphrase "correct-horse-battery-staple"

# Standalone password generator (OS CSPRNG, reports entropy):
$BIN gen --len 24 --symbols
```

No-TPM machine (e.g. a VM/CI): add `--allow-no-tpm` to `init`, and pass
`--recovery-passphrase` to `add`/`get` (there is no TPM to auto-unseal).

## Commands

| Command | Purpose |
|---------|---------|
| `init [--allow-no-tpm] --recovery-passphrase <pw>` | Create a vault; seal the DEK to the TPM and escrow it under the passphrase |
| `unlock [--recovery-passphrase <pw>]` | Credential smoke-check (verifies you can obtain the DEK) |
| `lock` | No-op by design — the CLI is stateless, nothing is cached to clear |
| `add <name> [--value <v>] [--recovery-passphrase <pw>]` | Add a secret |
| `get <name> [--clip] [--recovery-passphrase <pw>]` | Read a secret (stdout, or clipboard with auto-clear) |
| `list` | List secret names (metadata only) |
| `gen [--len N] [--symbols]` | Generate a password and report entropy |
| `seal-status` | Show `hardware_bound`, the active key provider, and warnings |

`--vault <path>` is global (default `vault.ztsv`).

## How it protects your secrets

- **Hardware-bound key.** A random 256-bit DEK encrypts every secret
  (XChaCha20-Poly1305). The DEK is **dual-wrapped**: (1) sealed by a non-exportable
  TPM key, and (2) escrowed under an Argon2id key derived from your recovery
  passphrase. A stolen vault file is useless without the original TPM **or** the
  passphrase.
- **Tamper-evident.** The vault header and the whole record set (count, order,
  names, ciphertext) are authenticated by an HKDF-keyed HMAC; each secret is also
  bound to its name via AEAD AAD. Relabel / delete / reorder / inject all fail
  closed at unlock. `save` is atomic (temp-then-rename).
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

## Honest limitations (slice 1)

- TPM binding is **device-bound, not PCR-policy-bound** (a CNG limitation); real
  PCR sealing needs a `tss-esapi` backend in a later slice.
- `--value` / `--recovery-passphrase` travel on the command line (visible in
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
verify/             memory-scraping harness (dumper + scan_dump.py + TEST_PLAN)
docs/               design spec + implementation plan
```

## Test

```sh
cargo test           # vaultcore 22 + proptest 1 + vaultctl CLI 5
bash verify/run.sh   # empirical memory-dump proof
```
