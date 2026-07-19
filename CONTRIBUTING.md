# Contributing

Thanks for looking at this project. It is a local-first, TPM-bound secrets
manager, and it is being prepared for independent security review — so the bar
for changes in the cryptographic core is deliberately high, while the bar for
reporting problems is deliberately low.

## Reporting a security vulnerability

**Do not open a public issue.** See [`SECURITY.md`](SECURITY.md) — report
privately at
<https://github.com/largefries7-lgtm/zero-trust-secrets/security/advisories/new>.

## Reporting a non-security defect

Open a [GitHub issue](https://github.com/largefries7-lgtm/zero-trust-secrets/issues/new)
and include:

- What you expected, and what happened instead.
- The commit or release you are running, and your Windows version.
- Exact reproduction steps. A failing test is the fastest possible bug report.
- Relevant output. **Never paste a real passphrase, vault file, or secret
  value** — reproduce with throwaway data instead.

If you are unsure whether something is a security issue, treat it as one and
report it privately. It is easy to move a report to a public issue; it is
impossible to un-publish one.

## Proposing a change

1. **Open an issue first** for anything beyond a typo or a comment fix,
   especially in `vaultcore`. Discussing the approach before writing code avoids
   work that cannot be merged.
2. **Fork and branch.** `master` is protected; changes land through pull
   requests, never direct commits.
3. **Write tests before the fix.** This repository has property tests, fuzz
   targets, and proof harnesses because the failure modes here are silent — a
   crypto bug does not throw, it just quietly produces something an attacker can
   read.
4. **Open a pull request** describing what changed and why, and what you did to
   convince yourself it is correct.

### Before you push

```bash
cargo test --workspace --locked
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo deny check
```

CI runs the same checks plus the Kani proofs and a bounded fuzzing pass. See
[`VERIFICATION.md`](VERIFICATION.md) for the full verification surface and
`fuzz/README.md` for fuzzing specifically.

### Changes to the cryptographic core

Changes to `crates/vaultcore/src/{crypto,envelope,vault,secret}.rs` get extra
scrutiny, and some are effectively off the table without a very strong argument:

- **Do not change the on-disk format** without a version bump and a migration
  path. Bricking someone's vault is worse than any feature is good — see
  commit `b4f645d` for what that mistake looked like and how it was repaired.
- **Do not weaken `ZeroizeOnDrop` coverage**, and do not switch the release
  profile to `panic = "abort"`. Unwinding is what runs the destructors that
  scrub secrets from RAM; that is the project's central claim, and
  `verify/run.sh` empirically demonstrates it.
- **Do not add a dependency to `vaultcore`** without justification in the PR.
  The crypto core's small, widely-audited dependency set is a deliberate
  security property, documented in `SECURITY.md` under **Dependency trust**.
- **Do not weaken a documented limitation into a claim.** This project's
  credibility rests on stating its ceiling honestly. If a change makes a
  guarantee stronger, say exactly how; if it does not, do not imply it does.

## Repository security settings

These are maintainer-only actions, recorded here because the OpenSSF Baseline
assessment in [`docs/OPENSSF_BASELINE.md`](docs/OPENSSF_BASELINE.md) depends on
them and because they are easy to forget.

### Enable Private Vulnerability Reporting

Required for the reporting flow in `SECURITY.md` to work at all — until it is
on, the "report a vulnerability" link 404s for researchers.

1. Go to
   <https://github.com/largefries7-lgtm/zero-trust-secrets/settings/security_analysis>
2. Under **Private vulnerability reporting**, click **Enable**.

(The `/security/policy` URL is where `SECURITY.md` is *displayed* to visitors —
it is not where the feature is turned on.)

### Protect the primary branch

Required by OSPS-AC-03.01 and OSPS-AC-03.02.

1. Go to
   <https://github.com/largefries7-lgtm/zero-trust-secrets/settings/branches>
2. Add a branch protection rule (or ruleset) for `master`:
   - **Require a pull request before merging**
   - **Require status checks to pass** — select the CI jobs
   - **Do not allow bypassing the above settings**
   - Leave branch deletion disallowed (the default under a protection rule)

On a single-maintainer project, requiring a *review* would deadlock you; the
Baseline requires that direct commits be blocked, not that a second person
approve. Requiring a PR plus green status checks satisfies the control and
still gets you the CI gate.

## License

> **This repository currently has no license file.** Until one is added, the
> code is "all rights reserved" by default and cannot be legally reused or
> redistributed — and contributions cannot be accepted on clear terms. This is
> tracked as the top action item in
> [`docs/OPENSSF_BASELINE.md`](docs/OPENSSF_BASELINE.md).

Once a license is added, contributing implies your contributions are licensed
under it.
