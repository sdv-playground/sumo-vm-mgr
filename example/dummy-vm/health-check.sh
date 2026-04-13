#!/bin/bash
# health-check.sh — poll vm-service health endpoint for a running VM.
#
# Usage:
#   ./example/linux-vm/health-check.sh                  # default: linux1
#   ./example/linux-vm/health-check.sh vm1               # specific VM name
#   ./example/linux-vm/health-check.sh linux1 2          # poll every 2 seconds
#
# Requires run-vm.sh to be running in another terminal.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CONFIG="$SCRIPT_DIR/vm-service.yaml"
VM_NAME="${1:-linux1}"
INTERVAL="${2:-3}"

SOCKET=$(grep '^socket:' "$CONFIG" | awk '{print $2}')

if [[ ! -S "$SOCKET" ]]; then
    echo "[health] ERROR: socket not found: $SOCKET"
    echo "[health] Is vm-service running? Start it with: ./example/linux-vm/run-vm.sh"
    exit 1
fi

cleanup() {
    echo ""
    echo "[health] stopped."
}
trap cleanup EXIT INT TERM

echo "[health] polling $VM_NAME every ${INTERVAL}s (socket: $SOCKET)"
echo "[health] press Ctrl-C to stop"
echo ""

while true; do
    TIMESTAMP=$(date '+%H:%M:%S')

    # Health endpoint
    HEALTH=$(curl -sf --unix-socket "$SOCKET" \
        "http://localhost/vms/$VM_NAME/health" 2>&1) && {
        STATUS=$(echo "$HEALTH" | python3 -c "import sys,json; print(json.load(sys.stdin).get('status','?'))" 2>/dev/null || echo "$HEALTH")
        echo "[$TIMESTAMP] $VM_NAME: $STATUS"
    } || {
        echo "[$TIMESTAMP] $VM_NAME: ERROR (service unreachable)"
    }

    sleep "$INTERVAL"
done
