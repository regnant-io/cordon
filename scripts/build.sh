#!/usr/bin/env bash
# Cordon build and test script
# Usage: ./scripts/build.sh [--release] [--test] [--check-only]
set -euo pipefail

RELEASE=""
RUN_TESTS=""
CHECK_ONLY=""
VERBOSE=""

for arg in "$@"; do
    case $arg in
        --release) RELEASE="--release" ;;
        --test) RUN_TESTS="yes" ;;
        --check-only) CHECK_ONLY="yes" ;;
        --verbose) VERBOSE="--verbose" ;;
        *) echo "Unknown argument: $arg"; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$PROJECT_ROOT"

echo "═══════════════════════════════════════════════"
echo "  Cordon v2.0 Build"
echo "  Mode: ${RELEASE:-debug}"
echo "═══════════════════════════════════════════════"

# Check Rust toolchain
if ! command -v cargo &>/dev/null; then
    echo "ERROR: cargo not found. Install Rust: https://rustup.rs"
    exit 1
fi

RUST_VERSION=$(rustc --version)
echo "Rust: $RUST_VERSION"
echo ""

# Security audit (if cargo-audit is available)
if command -v cargo-audit &>/dev/null; then
    echo "Running security audit..."
    cargo audit || echo "Warning: security audit found issues"
    echo ""
fi

# Check only (no build artifacts)
if [ -n "$CHECK_ONLY" ]; then
    echo "Checking code..."
    cargo check --workspace $VERBOSE 2>&1
    echo ""
    echo "Running clippy..."
    cargo clippy --workspace -- -D warnings 2>&1 || true
    echo ""
    echo "Check complete."
    exit 0
fi

# Build
echo "Building workspace..."
cargo build --workspace $RELEASE $VERBOSE 2>&1
echo ""

# Run tests
if [ -n "$RUN_TESTS" ]; then
    echo "Running unit tests..."
    cargo test --workspace $RELEASE $VERBOSE 2>&1
    echo ""
    echo "Running integration tests..."
    cargo test --test integration_tests $RELEASE $VERBOSE 2>&1
    echo ""
fi

# Build binaries summary
if [ -n "$RELEASE" ]; then
    TARGET_DIR="target/release"
else
    TARGET_DIR="target/debug"
fi

echo "Build artifacts:"
for bin in cordon cordon-keygen cordon-verify-log cordon-provision; do
    if [ -f "$TARGET_DIR/$bin" ]; then
        SIZE=$(du -sh "$TARGET_DIR/$bin" | cut -f1)
        echo "  ✓ $TARGET_DIR/$bin ($SIZE)"
    fi
done

echo ""
echo "Build complete."
