# Memory-Scraping Verification Harness — Test Plan

**Goal.** Prove *empirically* that plaintext secrets do not linger in the
`vaultctl` process's RAM once they are no longer needed — and prove the proof is
meaningful by showing, via a positive control, that the scanner **can** find a
canary when it genuinely is present.

This is not a unit test of zeroization logic; it dumps the **actual process
memory** of a running `vaultctl` and searches the raw bytes.

---

## Components

| File | Role |
|------|------|
| `crates/vaultctl` (feature `leaktest`) | Adds hidden `__hold-locked`, `__hold-postclip`, `__leak` subcommands that freeze the process in a precise state, print `READY`, and block on stdin. **Not present in a production build.** |
| `verify/dumper` | Spawns `vaultctl` into a scenario, `OpenProcess` + `MiniDumpWriteDump` the **child's** full memory, scans the dump for the canary (UTF‑8 and UTF‑16LE), and asserts. |
| `verify/scan_dump.py` | Standalone Volatility-style scanner for **manual** cross-verification (mmaps a dump, searches both encodings, prints hit offsets). Requires Python 3. |
| `verify/run.sh` | One-command runner (Git Bash): builds both binaries with the right features and runs the harness. |

---

## How to run

### One command (recommended)

```bash
verify/run.sh
```

This runs, from the repo root:

```bash
cargo build --release -p vaultctl --features leaktest
cargo build --release -p dumper
./target/release/dumper verify --vaultctl target/release/vaultctl.exe
```

### Keep the dumps for manual inspection

```bash
verify/run.sh --keep-dumps        # dumps left under a temp dir (path printed)
```

### Single scenario + manual Python scan

```bash
# Writes the dump to leak.dmp (kept) and prints the random canary it planted:
./target/release/dumper leak leak.dmp --vaultctl target/release/vaultctl.exe
# Cross-check with the standalone scraper (exit 2 == canary found):
python verify/scan_dump.py leak.dmp CANARY-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

`scan_dump.py` exit codes: `0` = canary absent (clean), `2` = canary present, `1` = usage/IO error.

---

## Scenarios and what each proves

Each scenario provisions a **throwaway** vault (`init --allow-no-tpm` +
`add secret --value <canary>`) with a fresh random canary of the form
`CANARY-<32 hex digits>` drawn from the OS CSPRNG.

| # | Scenario | vaultctl state at dump time | Expectation | Proves |
|---|----------|-----------------------------|-------------|--------|
| S1 | `locked` | `LockedVault::load` only — no DEK obtained, records still encrypted | **0 hits** | The at-rest/locked process holds only ciphertext; the plaintext canary never enters memory. |
| S2 | `post-clip` | Secret fetched, copied to clipboard, then `SecretString` + DEK dropped/zeroized **inside an inner scope before** `READY` | **0 hits** | Immediately after a real "copy password to clipboard" operation, `vaultctl`'s own heap is clean — zeroization already ran. |
| S3 | `leak` (**positive control**) | Canary kept in a plain, never-zeroized `String`, held live across the dump (via `std::hint::black_box`) | **>= 1 hit** | The dumper + scanner actually work. If this is 0, S1/S2 are vacuous. |

**Pass criteria (overall):** `S1 == 0` **AND** `S2 == 0` **AND** `S3 >= 1`.
The dumper exits `0` iff all three hold, non-zero otherwise.

---

## Recorded result (this environment)

Windows 11 IoT Enterprise LTSC 2024 (10.0.26100), `cargo 1.96.0`, `windows` crate 0.58.
`OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ)` on a same-user child +
`MiniDumpWriteDump(MiniDumpWithFullMemory)` — no elevation required. Full-memory
dump ~22 MB per run.

```
scenario      utf8  utf16  total  expected  result
--------------------------------------------------------
locked           0      0      0      == 0  PASS
post-clip        0      0      0      == 0  PASS
leak(ctrl)       5      2      7      >= 1  PASS

OVERALL: PASS
```

The positive control fired: the canary was found **5 times as UTF‑8 and 2 times
as UTF‑16LE** in the leak dump, while both the locked and post-clip dumps
contained **zero** occurrences in either encoding. The result is deterministic
across repeated runs.

---

## Honest scope notes (what this does and does NOT prove)

1. **S2 asserts only `vaultctl`'s own process heap.** The OS clipboard buffer
   separately holds the plaintext until the auto-clear fires (~15 s later, in a
   detached helper process). That is inherent to "copy to clipboard" and is a
   *different process's* memory — out of scope for this assertion. The harness
   dumps `vaultctl`, not the clipboard owner.

2. **CLI argv is world-readable.** `--recovery-passphrase` and `--value` are
   passed on the command line, so they travel in a process's argument vector,
   which is visible to `ps`-style tooling and appears in that process's
   full-memory dump. This is a property of the **stateless test CLI**, not of the
   vault at rest. Concretely: the throwaway canary is placed on the argv of the
   separate `add` provisioning process — which has already **exited** before we
   dump — so it is *not* in the `__hold-postclip` dump (S2 confirms 0 hits). The
   `__hold-postclip` process's own argv contains the passphrase `pw` and the
   record name `secret`, but never the decrypted canary value. (The clipboard
   path deliberately feeds the secret via `clip.exe` **stdin**, never argv; the
   planned GUI slice avoids argv entirely.) The canary search targets the
   *decrypted secret value* — which is what S1/S2 prove absent from the heap.

3. **Threat model boundary.** This proves plaintext-secret hygiene in the process
   heap for the *locked* and *post-operation* states. It does **not** defend
   against a live debugger attached at the exact instant of decryption (while the
   `SecretString` is legitimately alive in `get`), which is explicitly outside
   the spec's threat model.

4. **The dumper holds the canary too.** By necessity, the dumper process keeps
   the canary in its own memory in order to search for it. That is precisely why
   it dumps the **child** (`vaultctl`) and never itself.
