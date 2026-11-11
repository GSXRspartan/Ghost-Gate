#!/usr/bin/env bash
# M8 build script: compile bridge, gg-test-signer, and telegram bot binaries.
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_DIR"

echo "=== Building ghost-gate-bridge and gg-test-signer ==="
cargo build -p ghost-gate-walletd --bin ghost-gate-bridge --bin gg-test-signer 2>&1
echo "=== Building ghost-gate-telegram ==="
cargo build -p ghost-gate-telegram 2>&1
echo "=== Build complete ==="
ls -lh target/debug/ghost-gate-bridge target/debug/gg-test-signer target/debug/ghost-gate-telegram
