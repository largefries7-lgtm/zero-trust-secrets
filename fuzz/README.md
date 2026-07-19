# Coverage-guided fuzzing (`cargo-fuzz` / libFuzzer)

Continuous, coverage-guided fuzzing of `vaultcore`'s untrusted-input surfaces.
This supplements — it does not replace — the property tests in
`crates/vaultcore/tests/codec_fuzz.rs`, which still run on every `cargo test`.

## Platform

**libFuzzer targets run on Linux (or macOS), not Windows.** `cargo-fuzz` requires
a nightly toolchain and does not officially support `x86_64-pc-windows-msvc`.
Since the parser surfaces fuzzed here are all platform-independent — the
`#[cfg(windows)]` FFI is not reachable from any of these targets — running them
on the Ubuntu CI runner loses no coverage. Windows developers can use WSL.

## Targets

| Target | Surface | Oracle |
|---|---|---|
| `vault_header_parse` | `VaultHeader::from_bytes` | no panic + serialization is idempotent |
| `locked_vault_load` | `LockedVault::load_from_bytes` | no panic, no memory amplification |
| `v2_to_v3_migration` | `LockedVault::unlock_with_dek` on a v2 vault | full value round-trip after migration |

### Why `v2_to_v3_migration` uses a builder

The migration path is gated by the v2 header MAC and then a per-record AEAD
open. A byte-oriented fuzzer cannot forge either, so feeding it arbitrary
v2-framed bytes would only ever prove "the MAC rejects garbage" and would never
reach a line of migration logic.

Instead the fuzzer chooses record *content*, and
`vaultcore::vault::fuzz_support::build_v2_image` (behind the non-default
`fuzzing` feature) seals it correctly under a fixed DEK. Arbitrary semantics,
valid cryptography.

That builder is itself load-bearing: if it ever stopped emitting a MAC-valid v2
image, every fuzz case would bail early and the target would report "no crashes"
while testing nothing. `crates/vaultcore/tests/fuzz_support_oracle.rs` guards
against exactly that and runs on stable in normal CI.

## Running locally

```bash
# One-time setup (Linux/macOS/WSL)
rustup toolchain install nightly --profile minimal
cargo install cargo-fuzz --locked

# Compile every target without running (fast sanity check)
cargo +nightly fuzz build

# Run one target until you stop it (Ctrl-C)
cargo +nightly fuzz run vault_header_parse

# Bounded run, as CI does it
cargo +nightly fuzz run vault_header_parse -- -max_total_time=60 -timeout=10 -rss_limit_mb=2048
cargo +nightly fuzz run locked_vault_load  -- -max_total_time=60 -timeout=10 -rss_limit_mb=2048
cargo +nightly fuzz run v2_to_v3_migration -- -max_total_time=60 -timeout=10 -rss_limit_mb=2048
```

`-rss_limit_mb` is not incidental: the parser's central DoS defense is that it
refuses to pre-allocate from an unvalidated length prefix. A regression there
shows up as an RSS blowup, so the limit is the assertion.

### Reproducing and triaging a crash

```bash
# libFuzzer writes the offending input here
cargo +nightly fuzz run <target> fuzz/artifacts/<target>/crash-<hash>

# Shrink it to a minimal reproducer
cargo +nightly fuzz tmin <target> fuzz/artifacts/<target>/crash-<hash>
```

Any crash found here should be turned into a permanent regression test in
`crates/vaultcore/tests/` before the fix lands.

### Coverage

```bash
cargo +nightly fuzz coverage <target>
```

## Open question flagged by this work

`build_v2_image` will happily emit a v2 image with **duplicate record names**.
The `v2_to_v3_migration` target currently skips those inputs, because the
round-trip property is undefined for them: after migration, `Vault::get(name)`
resolves by name and would return an arbitrary one of the duplicates. A real v2
file could contain duplicates. Whether migration should reject them, dedupe
them, or rename them is a product decision that has not been made — it is not
currently a crash, but it is unspecified behavior on an untrusted-input path.
