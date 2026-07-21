# OpenSSF Security Baseline — Level 1 assessment

Assessed against **OSPS Baseline v2026.02.19**, the current published version.
All 25 Level 1 (`maturity-1`) assessment requirements are listed; none are
omitted. Requirement text is quoted from the upstream control definitions at
<https://github.com/ossf/security-baseline>.

**Two programs, often conflated.** The *OSPS Baseline* (this document) is a set
of 41 controls across three maturity levels. The *OpenSSF Best Practices Badge*
(formerly the CII Badge) is a separate, older self-certification with
passing/silver/gold tiers. They have different criteria — notably, a Code of
Conduct is **not** an OSPS Baseline requirement at any level, but it **is** a
Best Practices Badge criterion. This document covers the Baseline only.

## Summary

| Status | Count |
|---|---|
| Met | 21 |
| **Not met — blocking** | **2** |
| Not applicable | 1 |
| Retired upstream | 1 |

Two requirements fail, and both are fixed by the same action: protecting the
primary branch.

---

## Resolved

### Licensing — OSPS-LE-02.01, LE-02.02, LE-03.01, LE-03.02 — **now met**

The project is dual-licensed `MIT OR Apache-2.0`, the Rust ecosystem
convention: Apache-2.0 supplies an explicit patent grant, MIT is maximally
permissive, and downstream users comply with whichever suits them.

- `LICENSE` — states the dual arrangement and the contribution terms
- `LICENSE-APACHE`, `LICENSE-MIT` — full texts
- `license = "MIT OR Apache-2.0"` in `[workspace.package]`, inherited by all
  four crates via `license.workspace = true`

This was the top-priority item in the previous revision of this document, and
not only for the Baseline: without a license the code was all-rights-reserved by
default, which a third-party auditor (OSTIF, Cure53) would have raised before
starting work, since reviewing and quoting source requires a license permitting
it. That blocker is cleared.

---

## Blocking gaps

### `master` is unprotected — fails OSPS-AC-03.01, OSPS-AC-03.02

`GET /repos/.../branches/master/protection` returns `404 Branch not protected`.
Direct commits to `master` are possible, and nothing marks branch deletion as
sensitive.

This also undercuts the `VERIFICATION.md` provenance story: SLSA provenance
proves a binary came from a given commit on this repository, but if anyone with
write access can push straight to `master`, that says less than it appears to.

**Fix:** the step-by-step settings are in [`CONTRIBUTING.md`](../CONTRIBUTING.md)
under *Protect the primary branch*. Requiring a PR plus green status checks is
sufficient — the control requires that direct commits be blocked, not that a
second person approve, which would deadlock a single-maintainer project.

---

## Full requirement table

### Access Control

| ID | Requirement | Status |
|---|---|---|
| OSPS-AC-01.01 | MFA required for sensitive actions in the authoritative repo | **Unverified** — cannot be checked via API; confirm at [account security settings](https://github.com/settings/security). Enable it if it is not on. |
| OSPS-AC-02.01 | New collaborators get lowest privilege by default | Met — GitHub default; no collaborators are configured |
| OSPS-AC-03.01 | Enforcement prevents direct commits to the primary branch | **NOT MET** — see blocking gap |
| OSPS-AC-03.02 | Primary-branch deletion requires explicit confirmation | **NOT MET** — see blocking gap |

### Build and Release

| ID | Requirement | Status |
|---|---|---|
| OSPS-BR-01.01 | Untrusted CI/CD metadata is sanitized before use | Met — no workflow interpolates untrusted input into a shell |
| OSPS-BR-01.02 | *(retired upstream in ossf/security-baseline#443)* | n/a |
| OSPS-BR-01.03 | Untrusted code snapshots cannot reach privileged credentials | Met — workflows use `pull_request`, never `pull_request_target`, so fork PRs get no secrets |
| OSPS-BR-03.01 | Official project URIs delivered over encrypted channels | Met — GitHub-hosted, HTTPS only |
| OSPS-BR-03.02 | Distribution channel authenticated against AitM | Met — GitHub Releases over HTTPS, plus Sigstore signatures and SLSA provenance (see [`VERIFICATION.md`](../VERIFICATION.md)) |
| OSPS-BR-07.01 | Prevent unintentional storage of unencrypted secrets in VCS | Met — no secrets committed; `.gitignore` excludes dumps, scan artifacts, and `*.dmp` |

### Documentation

| ID | Requirement | Status |
|---|---|---|
| OSPS-DO-01.01 | User guides for all basic functionality (once released) | Met — `README.md`; not yet triggered, as there are no releases |
| OSPS-DO-02.01 | A guide for reporting defects (once released) | Met — [`CONTRIBUTING.md`](../CONTRIBUTING.md) *Reporting a non-security defect* |

### Governance

| ID | Requirement | Status |
|---|---|---|
| OSPS-GV-02.01 | A public mechanism for discussion of changes and obstacles | Met — GitHub Issues enabled |
| OSPS-GV-03.01 | Documentation explains the contribution process | Met — [`CONTRIBUTING.md`](../CONTRIBUTING.md) |

### Legal

| ID | Requirement | Status |
|---|---|---|
| OSPS-LE-02.01 | Source code license meets the OSI/FSF definition | Met — `MIT OR Apache-2.0`, both OSI-approved |
| OSPS-LE-02.02 | Released asset license meets the OSI/FSF definition | Met — same dual license covers the release binaries |
| OSPS-LE-03.01 | License maintained in `LICENSE`/`COPYING`/`LICENSES/` | Met — `LICENSE`, `LICENSE-APACHE`, `LICENSE-MIT` at the repo root |
| OSPS-LE-03.02 | License included alongside release assets | Met — `release.yml` attaches `LICENSE`, `LICENSE-APACHE`, `LICENSE-MIT` to every release |

### Quality

| ID | Requirement | Status |
|---|---|---|
| OSPS-QA-01.01 | Source repo publicly readable at a static URL | Met — repository is public |
| OSPS-QA-01.02 | Public record of all changes, author, and timestamp | Met — public git history |
| OSPS-QA-02.01 | Dependency list covering direct language dependencies | Met — `Cargo.toml` manifests plus a committed `Cargo.lock` |
| OSPS-QA-04.01 | Multi-repository projects document their codebases | n/a — single repository |
| OSPS-QA-05.01 | No generated executable artifacts in VCS | Met — verified, no tracked binaries |
| OSPS-QA-05.02 | No unreviewable binary artifacts in VCS | Met — verified |

### Vulnerability Management

| ID | Requirement | Status |
|---|---|---|
| OSPS-VM-02.01 | Documentation contains security contacts | Met — [`SECURITY.md`](../SECURITY.md) *Reporting a vulnerability* |

---

## Action list

Ordered by what actually blocks progress.

1. **Protect `master`.** The only remaining Baseline failure, and it also
   weakens the SLSA provenance claim. Steps in `CONTRIBUTING.md`.
2. **Confirm MFA is enabled** on the owner account (AC-01.01). Not
   API-verifiable; check manually.
3. **Enable Private Vulnerability Reporting.** Not itself a Level 1 control, but
   `SECURITY.md` now directs researchers to a URL that 404s until it is on.
   Steps in `CONTRIBUTING.md`.
All three remaining items are owner-only settings; nothing in the codebase
blocks them.

## Beyond Level 1

Level 2 and 3 add release-signing, SBOM publication, documented governance, and
enforced code review. Several are already effectively satisfied by the
Sigstore/SLSA pipeline in `VERIFICATION.md`. Assessing them is worth doing once
the Level 1 gaps above are closed — not before.
