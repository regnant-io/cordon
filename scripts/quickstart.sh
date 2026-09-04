#!/usr/bin/env bash
# Cordon quick-start: builds and launches a local Light-mode node
# Usage: ./scripts/quickstart.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

DATA_DIR="${CORDON_DATA_DIR:-/tmp/cordon-dev}"
BIND="${CORDON_BIND:-127.0.0.1:8443}"

echo "╔══════════════════════════════════════════════╗"
echo "║   Cordon v2.0 — Quick Start (Light Mode)    ║"
echo "║                                              ║"
echo "║   ⚠  Light mode: no TEE, no hardware         ║"
echo "║      protection. Dev/testing only.           ║"
echo "╚══════════════════════════════════════════════╝"
echo ""

# Build if needed
if [ ! -f "target/debug/cordon" ]; then
    echo "Building Cordon..."
    cargo build --bin cordon 2>&1
    echo ""
fi

# Create data directories
mkdir -p "$DATA_DIR"/{audit,bundles,tls}

echo "Starting Cordon node..."
echo "  Bind:     $BIND"
echo "  Data dir: $DATA_DIR"
echo "  Mode:     light"
echo ""
echo "API endpoints:"
echo "  GET  http://$BIND/v1/health"
echo "  GET  http://$BIND/v1/health/detailed"
echo "  POST http://$BIND/v1/inference"
echo "  GET  http://$BIND/v1/attestation"
echo "  GET  http://$BIND/v1/audit/tail"
echo "  GET  http://$BIND/metrics"
echo ""
echo "Press Ctrl+C to stop."
echo ""

RUST_LOG=info ./target/debug/cordon serve \
    --bind "$BIND" \
    --data-dir "$DATA_DIR" \
    --no-tls
