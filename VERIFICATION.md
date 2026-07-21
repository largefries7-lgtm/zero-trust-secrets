# Verifying a `zero-trust-secrets` release

Every release publishes two independent pieces of evidence alongside the
binaries. This document explains how to check them — and, just as importantly,
what each one does **not** prove.

Repository: `github.com/largefries7-lgtm/zero-trust-secrets`

| File | What it is |
|---|---|
| `vaultctl.exe`, `vaultgui.exe` | the binaries |
| `multiple.intoto.jsonl` | SLSA build provenance covering both binaries |
| `vaultctl.exe.bundle`, `vaultgui.exe.bundle` | Sigstore signature bundles |

---

## 1. Verify the SLSA build provenance

Provenance answers: *which source commit, built by which workflow, produced
exactly these bytes?*

Install [`slsa-verifier`](https://github.com/slsa-framework/slsa-verifier)
(v2.7.1 or later), then:

```bash
slsa-verifier verify-artifact \
  --provenance-path multiple.intoto.jsonl \
  --source-uri github.com/largefries7-lgtm/zero-trust-secrets \
  --source-tag v0.1.0 \
  vaultctl.exe vaultgui.exe
```

Expected output ends with `PASSED: SLSA verification passed`.

`--source-tag` is not optional in practice: without it, verification passes for
provenance generated from *any* tag in this repository, so an attacker who could
publish a release from an old or unreviewed tag would still verify. Pin it to
the version you intend to run.

## 2. Verify the Sigstore signature

The signature answers a different question: *was this artifact published by this
repository's release workflow?*

Install [cosign](https://github.com/sigstore/cosign) v2 or later:

```bash
cosign verify-blob \
  --bundle vaultctl.exe.bundle \
  --certificate-identity-regexp '^https://github\.com/largefries7-lgtm/zero-trust-secrets/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  vaultctl.exe
```

Expected output: `Verified OK`.

Both `--certificate-identity-regexp` and `--certificate-oidc-issuer` are
mandatory. **`cosign verify-blob` without an identity constraint verifies that
*somebody* signed the file, not that *we* did** — it is close to meaningless.
The regexp above pins the signer to this repository's `release.yml`, running on
a version tag.

Signing is **keyless**: the workflow exchanges its GitHub OIDC token for a
~10-minute Fulcio certificate, and the signature is logged in the Rekor
transparency log. There is no long-lived private key to steal or rotate. The
tradeoff is that verification trusts the Sigstore public-good instance rather
than a key you have pinned yourself.

---

## 3. What this does and does not prove

Read this section before relying on any of the above.

**Verified provenance + signature together establish:**

- The binary was produced by this repository's `release.yml`, from the commit
  named in the provenance, with the dependency versions in the committed
  `Cargo.lock` (the build uses `--locked`).
- The bytes have not been altered since that build.

**They do NOT establish:**

- **That the source code is correct or secure.** Provenance is a supply-chain
  control, not a code-quality one. A vulnerability committed to `master` gets
  faithfully built, validly signed, and correctly attested.

- **SLSA Build Level 3 in the strictest reading.** We use
  `slsa-github-generator`'s *generic* generator. Provenance signing happens
  inside a reusable workflow our own job cannot influence, so the provenance is
  non-forgeable — that is L3's central property. But the binaries are compiled
  in our `build` job, not inside the trusted builder. Anyone able to modify this
  repository's workflows could therefore obtain valid provenance for a malicious
  binary. We claim non-forgeable provenance; we do not claim an isolated build
  environment, and an audit should treat the distinction as real.

- **That the release was intended.** Provenance proves origin, not authorization.
  Branch protection and required review on `master` are what constrain *what*
  gets released; see the OpenSSF Baseline checklist in `CONTRIBUTING.md`.

- **Anything about the TPM/CNG behavior on your machine.** See `SECURITY.md` for
  the userspace ceiling this project operates under.

---

## 4. Verifying the source, not just the binary

The repository carries its own evidence, all of it reproducible locally.

### Tests and supply-chain policy

```bash
cargo test --workspace --locked
cargo deny check            # advisories, licenses, bans, source restrictions
```

### Coverage-guided fuzzing

Three libFuzzer targets cover the untrusted-input surfaces (header parsing,
whole-file framing, and the v2 -> v3 migration). **Linux or macOS only** —
`cargo-fuzz` requires nightly and does not support `windows-msvc`. See
`fuzz/README.md`.

```bash
cargo +nightly fuzz build
cargo +nightly fuzz run vault_header_parse -- -max_total_time=60
```

### Formal proofs (Kani)

```bash
cargo kani -p vaultcore
```

**Scope, stated plainly:** these proofs cover the codec's size arithmetic and
bounds checks — `padded_len`, `Cursor::take`, the name/value plaintext decoders,
and the `ProtectedDek` block padding. They are exhaustive over the stated input
domains, which is strictly more than testing gives you.

They say **nothing** about the `unsafe` FFI. Kani has no semantics for
`extern "system"` calls and cannot model them; stubbing the CNG entry points
would only verify the stubs. Kani also does not run on Windows, so on the Linux
host it requires, every `#[cfg(windows)]` block compiles to its non-Windows
no-op stub. Any claim that "the FFI is formally verified" would be false.

They also say **nothing about zeroization**. `zeroize`'s optimization barrier is
`core::arch::asm!`, and Kani cannot model inline assembly — any proof that drops
a `ZeroizeOnDrop` value fails with
`TerminatorKind::InlineAsm is not currently supported`. The one harness that
returns a `SecretBytes` therefore leaks it deliberately (`mem::forget`) so the
barrier stays unreachable and the proof covers the bounds arithmetic it is
actually about. Zeroization is evidenced empirically instead — `verify/run.sh`
dumps a live process and looks for surviving plaintext (see `SECURITY.md`,
*Empirical verification*). Formal proof and memory-dump evidence cover different
halves of this problem, and neither substitutes for the other.

Because Kani cannot run on this project's primary development platform, each
proof is mirrored by a `kani_mirror_*` proptest that runs on stable everywhere
(`cargo test -p vaultcore kani_mirror`). The mirrors sample; the proofs are
exhaustive. If they ever disagree, the mirror is describing the shipped binary.

### The `unsafe` FFI

FFI soundness is addressed by dynamic analysis on Windows, where the code
actually compiles. These are **manual procedures, not CI gates** — the same
stance `SECURITY.md` takes toward `verify/run.sh`, and for the same reason: they
need a real TPM and, in one case, administrator rights.

**AddressSanitizer** (catches out-of-bounds and use-after-free across the FFI
boundary):

```powershell
rustup toolchain install nightly
$env:RUSTFLAGS = "-Zsanitizer=address"
cargo +nightly test -p vaultcore --target x86_64-pc-windows-msvc
Remove-Item Env:\RUSTFLAGS
```

**Application Verifier** (catches heap corruption and handle misuse in the
NCrypt calls; requires an elevated prompt):

```powershell
appverif.exe -enable Heaps Handles Locks -for vaultctl.exe
# exercise the TPM paths, e.g.: vaultctl init / add / get
appverif.exe -disable * -for vaultctl.exe
```

Wiring either of these into CI is **not yet done** — neither has been validated
on a GitHub-hosted runner, and a Windows runner has no TPM, so the CNG paths
skip. Treat this section as the current honest state, not an aspiration.

---

## 5. Reproducing the build

The release profile is deterministic by construction (`lto = true`,
`codegen-units = 1`, `strip = true`), and the build is `--locked`.

```bash
git checkout v0.1.0
cargo build --release --locked -p vaultctl -p vaultgui
sha256sum target/release/vaultctl.exe target/release/vaultgui.exe
```

Compare against the digests in the provenance. Note that **bit-identical
reproduction across machines is not currently guaranteed** — absolute paths can
be embedded in the binary, and no `--remap-path-prefix` is configured. Matching
digests are strong evidence; differing digests are not by themselves evidence of
tampering. Making the build fully reproducible is tracked as future work.
