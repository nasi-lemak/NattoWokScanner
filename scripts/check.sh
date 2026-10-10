#!/bin/sh
# Runs the same checks CI would: formatting, lints, tests. Run before pushing.
set -e
cd "$(dirname "$0")/.."
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
