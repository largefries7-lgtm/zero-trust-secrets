#!/usr/bin/env bash
# One-command runner for the memory-scraping verification harness (Git Bash).
#
# Builds the leaktest-enabled vaultctl, the leaktest-enabled vaultgui, and the
# dumper, then runs all six scenarios and asserts. Exits 0 iff locked==0,
# post-clip==0, gui-locked==0, leak>=1, and gui-leak>=1. It ALSO proves the
# GUI process's own heap: gui-locked proves the locked GUI holds no plaintext
# secret, and gui-post-autolock proves vaultcore's DEK/SecretString buffers
# are zeroized after auto-lock (the reported canary count there is an
# informational residual from Slint's own retained buffers, not a pass/fail
# signal -- see verify/TEST_PLAN.md).
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# vaultctl MUST be built with --features leaktest so the __hold-* / __leak
# subcommands exist. A plain production build deliberately omits them.
cargo build --release -p vaultctl --features leaktest
# vaultgui MUST be built with --features leaktest so --leaktest <scenario>
# exists. A plain production build deliberately omits it.
cargo build --release -p vaultgui --features leaktest
cargo build --release -p dumper

./target/release/dumper verify --vaultctl target/release/vaultctl.exe --vaultgui target/release/vaultgui.exe "$@"
