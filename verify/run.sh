#!/usr/bin/env bash
# One-command runner for the memory-scraping verification harness (Git Bash).
#
# Builds the leaktest-enabled vaultctl and the dumper, then runs all three
# scenarios and asserts. Exits 0 iff locked==0, post-clip==0, and the positive
# control (leak) >= 1.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# vaultctl MUST be built with --features leaktest so the __hold-* / __leak
# subcommands exist. A plain production build deliberately omits them.
cargo build --release -p vaultctl --features leaktest
cargo build --release -p dumper

./target/release/dumper verify --vaultctl target/release/vaultctl.exe "$@"
