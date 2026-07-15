# Security

## Threat model

The authoritative threat model — what is and isn't defended, and why — lives in the
design spec:
[`docs/superpowers/specs/2026-07-14-zero-trust-secrets-core-design.md`](docs/superpowers/specs/2026-07-14-zero-trust-secrets-core-design.md)
(§3 threat model, §15 as-built deltas). Read it before relying on this tool.

**One-line ceiling:** this is a userspace application on a general-purpose OS. It
cannot defend against a compromised kernel, a debugger attached to the live
*unlocked* process at the moment of decryption, or a cold-boot attack on an
already-unlocked machine. It aims to be as strong as is *actually achievable*
below that ceiling, and to state honestly where the ceiling is.

## Empirical verification

The memory-safety claim is not asserted, it is demonstrated:

```sh
bash verify/run.sh
```

dumps a running `vaultctl` process and proves no plaintext secret survives in its
heap when locked or just after a clipboard copy, with a positive control proving
the scanner works. See [`verify/TEST_PLAN.md`](verify/TEST_PLAN.md).

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
check` and `cargo audit` on every push and pull request, gating every dependency
change.

## Reporting

This is a personal/reference project. If you are reviewing it and find a flaw,
open an issue describing the impact and a reproduction.
