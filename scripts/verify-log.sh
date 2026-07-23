#!/usr/bin/env bash
# Cordon audit log verifier
# Verifies a Cordon audit log without connecting to the node.
# Requires only the exported log and the K_log verifying key.
#
# Usage: ./scripts/verify-log.sh --log <path> --key <hex> --deployment-id <id>
set -euo pipefail

LOG_PATH=""
KEY_HEX=""
DEPLOYMENT_ID=""
FORMAT="text"
SUMMARY=""

for arg in "$@"; do
    case $arg in
        --log=*) LOG_PATH="${arg#*=}" ;;
        --key=*) KEY_HEX="${arg#*=}" ;;
        --deployment-id=*) DEPLOYMENT_ID="${arg#*=}" ;;
        --format=*) FORMAT="${arg#*=}" ;;
        --summary) SUMMARY="--summary" ;;
        --log) shift; LOG_PATH="$1" ;;
        --key) shift; KEY_HEX="$1" ;;
        --deployment-id) shift; DEPLOYMENT_ID="$1" ;;
    esac
done

if [ -z "$LOG_PATH" ] || [ -z "$KEY_HEX" ] || [ -z "$DEPLOYMENT_ID" ]; then
    echo "Usage: $0 --log <path> --key <hex> --deployment-id <id> [--format text|json] [--summary]"
    echo ""
    echo "  --log            Path to audit log file or directory"
    echo "  --key            K_log verifying key (hex, 64 chars)"
    echo "  --deployment-id  Deployment ID (used to verify genesis entry)"
    echo "  --format         Output format: text (default) or json"
    echo "  --summary        Show event type statistics"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
VERIFIER="$PROJECT_ROOT/target/release/cordon-verify-log"

if [ ! -f "$VERIFIER" ]; then
    VERIFIER="$PROJECT_ROOT/target/debug/cordon-verify-log"
fi

if [ ! -f "$VERIFIER" ]; then
    echo "Building cordon-verify-log..."
    cd "$PROJECT_ROOT"
    cargo build --bin cordon-verify-log
    VERIFIER="$PROJECT_ROOT/target/debug/cordon-verify-log"
fi

"$VERIFIER" \
    --log "$LOG_PATH" \
    --key "$KEY_HEX" \
    --deployment-id "$DEPLOYMENT_ID" \
    --format "$FORMAT" \
    $SUMMARY

EXIT_CODE=$?
if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "✓ Log verification PASSED"
elif [ $EXIT_CODE -eq 1 ]; then
    echo ""
    echo "✗ Log verification FAILED — log has been tampered"
else
    echo ""
    echo "✗ Verification error"
fi
exit $EXIT_CODE
