#!/bin/bash
# vm-mgr boot loop — simulated bootloader
#
# Syncs sumo-rs dependencies, generates SUIT signing keys and demo firmware,
# factory-inits the NV store, and starts the SOVD server with the trust anchor.
#
# The SOVD REST API defaults to http://0.0.0.0:4000 (SOVD Explorer default).
#
# Usage:
#   ./example/run.sh                        # factory-init + SOVD server only
#   ./example/run.sh --profile <p> --images <dir>  # full boot loop + SOVD
#
# Examples:
#   # SOVD API for SOVD Explorer testing:
#   Terminal 1: ./example/run.sh
#   Terminal 2: open SOVD Explorer -> connect to http://localhost:4000
#
#   # Full boot loop:
#   Terminal 1: ./example/run.sh --profile example/profiles/os1-minimal.toml --images /path/to/output

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIRMWARE_DIR="$ROOT_DIR/example/factory"
NV_PATH="${VM_MGR_NV:-/tmp/vm-mgr-nv.bin}"
KEYS_DIR="$ROOT_DIR/example/keys"
TRUST_ANCHOR="$KEYS_DIR/signing.pub"

# Defaults — port 4000 matches SOVD Explorer
SOVD_ADDR="${VM_MGR_SOVD_ADDR:-0.0.0.0:4000}"
PROFILE=""
NO_INIT=false
FRESH=false
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --no-init)
            NO_INIT=true
            shift
            ;;
        --fresh)
            FRESH=true
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

# Fresh start — remove NV store
if [ "$FRESH" = true ] && [ -f "$NV_PATH" ]; then
    echo "[vm-mgr] removing old NV store: $NV_PATH"
    rm -f "$NV_PATH"
fi

# 1. Sync sumo-rs dependencies
echo "[vm-mgr] syncing sumo-rs dependencies..."
cargo update --manifest-path "$ROOT_DIR/Cargo.toml" \
    -p sumo-onboard -p sumo-crypto -p sumo-codec --quiet 2>/dev/null || true

# 2. Build workspace + examples
echo "[vm-mgr] building workspace..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --quiet

# 3. Generate SUIT keys and demo firmware (if keys don't exist)
if [ ! -f "$TRUST_ANCHOR" ]; then
    echo "[vm-mgr] generating SUIT signing keys and demo firmware..."
    cargo run --manifest-path "$ROOT_DIR/Cargo.toml" --example build --quiet
else
    echo "[vm-mgr] using existing keys in $KEYS_DIR"
fi

RUNNER="$ROOT_DIR/target/debug/vm-runner"
DIAGSERVER="$ROOT_DIR/target/debug/vm-diagserver"
SOVD="$ROOT_DIR/target/debug/vm-sovd"

# 4. Factory init (unless --no-init or NV already exists with data)
if [ "$NO_INIT" = false ]; then
    echo "[vm-mgr] factory init from $FIRMWARE_DIR"
    "$DIAGSERVER" "$NV_PATH" factory-init "$FIRMWARE_DIR" --runner-path "$RUNNER"
    echo ""
fi

echo "[vm-mgr] NV store:      $NV_PATH"
echo "[vm-mgr] Trust anchor:  $TRUST_ANCHOR"
echo "[vm-mgr] SOVD:          http://${SOVD_ADDR/0.0.0.0/localhost}"
echo ""
echo "[vm-mgr] Quick test:"
echo "  curl http://${SOVD_ADDR/0.0.0.0/localhost}/vehicle/v1/components"
echo "  curl http://${SOVD_ADDR/0.0.0.0/localhost}/vehicle/v1/components/os1/data"
echo "  curl http://${SOVD_ADDR/0.0.0.0/localhost}/vehicle/v1/components/os1/flash/activation"
echo ""
echo "[vm-mgr] Flash demo firmware (SUIT envelope):"
echo "  curl -X POST http://${SOVD_ADDR/0.0.0.0/localhost}/vehicle/v1/components/os1/files \\"
echo "    -H 'Content-Type: application/octet-stream' \\"
echo "    --data-binary @example/output/os1.suit"
echo ""

if [ -z "$PROFILE" ]; then
    # SOVD-only mode (no boot loop)
    exec "$SOVD" "$NV_PATH" "$TRUST_ANCHOR" "$SOVD_ADDR"
else
    # Start SOVD server in background, run boot loop
    "$SOVD" "$NV_PATH" "$TRUST_ANCHOR" "$SOVD_ADDR" &
    SOVD_PID=$!

    cleanup() {
        kill "$SOVD_PID" 2>/dev/null
        wait "$SOVD_PID" 2>/dev/null
    }
    trap cleanup EXIT

    "$RUNNER" "${EXTRA_ARGS[@]}" --nv "$NV_PATH" --init
fi
