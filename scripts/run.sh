#!/bin/bash
# vm-mgr boot loop — simulated bootloader
#
# Builds the workspace, optionally factory-inits the NV store, starts the
# SOVD server, and optionally runs the boot loop.
# The SOVD REST API defaults to http://0.0.0.0:4000 (SOVD Explorer default).
#
# Usage:
#   ./scripts/run.sh                        # factory-init + SOVD server only
#   ./scripts/run.sh --profile <p> --images <dir>  # full boot loop + SOVD
#
# Examples:
#   # SOVD API for SOVD Explorer testing:
#   Terminal 1: ./scripts/run.sh
#   Terminal 2: open SOVD Explorer -> connect to http://localhost:4000
#
#   # Full boot loop:
#   Terminal 1: ./scripts/run.sh --profile profiles/os1-minimal.toml --images /path/to/output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIRMWARE_DIR="$ROOT_DIR/firmware"
NV_PATH="${VM_MGR_NV:-/tmp/vm-mgr-nv.bin}"

# Defaults — port 4000 matches SOVD Explorer
SOVD_ADDR="${VM_MGR_SOVD_ADDR:-0.0.0.0:4000}"
PROFILE=""
NO_INIT=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-init)
            NO_INIT=true
            shift
            ;;
        --profile)
            PROFILE="$2"
            EXTRA_ARGS+=("$1" "$2")
            shift 2
            ;;
        --nv)
            NV_PATH="$2"
            shift 2
            ;;
        --addr)
            SOVD_ADDR="$2"
            shift 2
            ;;
        --firmware-dir)
            FIRMWARE_DIR="$2"
            shift 2
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

echo "[vm-mgr] building..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --quiet

RUNNER="$ROOT_DIR/target/debug/vm-runner"
DIAGSERVER="$ROOT_DIR/target/debug/vm-diagserver"
SOVD="$ROOT_DIR/target/debug/vm-sovd"

# Factory init (unless --no-init or NV already exists with data)
if [ "$NO_INIT" = false ]; then
    echo "[vm-mgr] factory init from $FIRMWARE_DIR"
    "$DIAGSERVER" "$NV_PATH" factory-init "$FIRMWARE_DIR" --runner-path "$RUNNER"
    echo ""
fi

echo "[vm-mgr] NV store: $NV_PATH"
echo "[vm-mgr] SOVD:     http://${SOVD_ADDR/0.0.0.0/localhost}"
echo ""
echo "[vm-mgr] Quick test:"
echo "  curl http://${SOVD_ADDR/0.0.0.0/localhost}/vehicle/v1/components"
echo "  curl http://${SOVD_ADDR/0.0.0.0/localhost}/vehicle/v1/components/os1/data"
echo "  curl http://${SOVD_ADDR/0.0.0.0/localhost}/vehicle/v1/components/os1/flash/activation"
echo ""

if [ -z "$PROFILE" ]; then
    # SOVD-only mode (no boot loop)
    exec "$SOVD" "$NV_PATH" "$SOVD_ADDR"
else
    # Start SOVD server in background, run boot loop
    "$SOVD" "$NV_PATH" "$SOVD_ADDR" &
    SOVD_PID=$!

    cleanup() {
        kill "$SOVD_PID" 2>/dev/null
        wait "$SOVD_PID" 2>/dev/null
    }
    trap cleanup EXIT

    "$RUNNER" "${EXTRA_ARGS[@]}" --nv "$NV_PATH" --init
fi
