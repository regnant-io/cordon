#!/usr/bin/env bash
# Cordon key ceremony helper
# Generates CMK and all derived keys for a new deployment.
# 
# In production: Run this on an air-gapped machine with an HSM attached.
# The CMK must be imported into the HSM and the key file DELETED.
#
# Usage: ./scripts/keygen.sh --deployment-id <id> --client-id <id> [--output <dir>]
set -euo pipefail

DEPLOYMENT_ID=""
CLIENT_ID=""
BUNDLE_ID=""
OUTPUT_DIR="./cordon-keys-$(date +%Y%m%d-%H%M%S)"

for arg in "$@"; do
    case $arg in
        --deployment-id=*) DEPLOYMENT_ID="${arg#*=}" ;;
        --client-id=*) CLIENT_ID="${arg#*=}" ;;
        --bundle-id=*) BUNDLE_ID="${arg#*=}" ;;
        --output=*) OUTPUT_DIR="${arg#*=}" ;;
        --deployment-id) shift; DEPLOYMENT_ID="$1" ;;
        --client-id) shift; CLIENT_ID="$1" ;;
        --bundle-id) shift; BUNDLE_ID="$1" ;;
        --output) shift; OUTPUT_DIR="$1" ;;
    esac
done

if [ -z "$DEPLOYMENT_ID" ] || [ -z "$CLIENT_ID" ]; then
    echo "Usage: $0 --deployment-id <id> --client-id <id> [--bundle-id <id>] [--output <dir>]"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
KEYGEN="$PROJECT_ROOT/target/release/cordon-keygen"

if [ ! -f "$KEYGEN" ]; then
    KEYGEN="$PROJECT_ROOT/target/debug/cordon-keygen"
fi

if [ ! -f "$KEYGEN" ]; then
    echo "Building cordon-keygen..."
    cd "$PROJECT_ROOT"
    cargo build --bin cordon-keygen
    KEYGEN="$PROJECT_ROOT/target/debug/cordon-keygen"
fi

echo "╔══════════════════════════════════════════════╗"
echo "║   Cordon Key Ceremony                       ║"
echo "╚══════════════════════════════════════════════╝"
echo ""
echo "  ⚠  WARNING: The CMK is the root of ALL security."
echo "  ⚠  In production:"
echo "      1. Run this on an air-gapped HSM workstation"
echo "      2. Import CMK into FIPS 140-2 Level 3+ HSM"
echo "      3. Shred the cmk.hex file immediately after import"
echo ""
echo "Deployment ID: $DEPLOYMENT_ID"
echo "Client ID:     $CLIENT_ID"
echo "Output:        $OUTPUT_DIR"
echo ""

BUNDLE_ARGS=""
if [ -n "$BUNDLE_ID" ]; then
    BUNDLE_ARGS="--bundle-id $BUNDLE_ID"
fi

"$KEYGEN" generate \
    --output "$OUTPUT_DIR" \
    --deployment-id "$DEPLOYMENT_ID" \
    --client-id "$CLIENT_ID" \
    $BUNDLE_ARGS

echo ""
echo "Key ceremony complete."
echo ""
echo "Files created in $OUTPUT_DIR:"
ls -la "$OUTPUT_DIR/" 2>/dev/null || true
echo ""
echo "CRITICAL NEXT STEPS:"
echo "  1. Import cmk.hex into your HSM"
echo "  2. Verify the import succeeded: the HSM should report the key"
echo "  3. SHRED cmk.hex: shred -u $OUTPUT_DIR/cmk.hex"
echo "  4. Provision log_verifying_key.hex to the Cordon node"
echo "  5. Provision admin_verifying_key.hex to the Cordon node"
