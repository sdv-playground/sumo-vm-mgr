#!/bin/bash
# vm-mgr boot loop — simulated bootloader
#
# Syncs sumo-rs dependencies, generates SUIT signing keys and demo firmware,
# factory-inits the NV store, starts the security helper and SOVD server.
#
# The SOVD REST API defaults to http://0.0.0.0:4000 (SOVD Explorer default).
# The security helper runs on port 9100 (SOVD Explorer default).
#
# Usage:
#   ./example/run.sh                        # factory-init + SOVD server only
#   ./example/run.sh --fresh                # wipe NV store first
#   ./example/run.sh --profile <p> --images <dir>  # full boot loop + SOVD
#
# Examples:
#   Terminal 1: ./example/run.sh
#   Terminal 2: open SOVD Explorer -> connect to http://localhost:4000
#              Settings: helper URL = http://localhost:9100, token = dev-secret-123

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FIRMWARE_DIR="$ROOT_DIR/example/factory"
SECRETS_CONFIG="$ROOT_DIR/example/config/secrets.toml"
NV_PATH="${VM_MGR_NV:-/tmp/vm-mgr-nv.bin}"
KEYS_DIR="$ROOT_DIR/example/keys"
TRUST_ANCHOR="$KEYS_DIR/signing.pub"

# Defaults
SOVD_ADDR="${VM_MGR_SOVD_ADDR:-0.0.0.0:4000}"
HELPER_PORT="${VM_MGR_HELPER_PORT:-9100}"
HELPER_TOKEN="dev-secret-123"
HELPER_REPO="https://github.com/skarlsson/SOVD-security-helper"
HELPER_TOOLS_DIR="$ROOT_DIR/target/tools"
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

# 4. Install security helper (if not available)
HELPER_BIN=""
if [ -x "$ROOT_DIR/../SOVD-security-helper/target/debug/sovd-security-helper" ]; then
    HELPER_BIN="$ROOT_DIR/../SOVD-security-helper/target/debug/sovd-security-helper"
    echo "[vm-mgr] using local security helper: $HELPER_BIN"
elif [ -x "$HELPER_TOOLS_DIR/bin/sovd-security-helper" ]; then
    HELPER_BIN="$HELPER_TOOLS_DIR/bin/sovd-security-helper"
    echo "[vm-mgr] using installed security helper"
else
    echo "[vm-mgr] installing security helper from $HELPER_REPO..."
    if cargo install --git "$HELPER_REPO" --root "$HELPER_TOOLS_DIR" 2>&1 | tail -1; then
        HELPER_BIN="$HELPER_TOOLS_DIR/bin/sovd-security-helper"
    else
        echo "[vm-mgr] WARNING: failed to install security helper — security unlock won't work"
    fi
fi

RUNNER="$ROOT_DIR/target/debug/vm-runner"
DIAGSERVER="$ROOT_DIR/target/debug/vm-diagserver"
SOVD="$ROOT_DIR/target/debug/vm-sovd"

# 5. Factory init (unless --no-init or NV already exists with data)
if [ "$NO_INIT" = false ]; then
    echo "[vm-mgr] factory init from $FIRMWARE_DIR"
    "$DIAGSERVER" "$NV_PATH" factory-init "$FIRMWARE_DIR" --runner-path "$RUNNER"
    echo ""
fi

# 6. Cleanup handler
HELPER_PID=""
SOVD_PID=""
cleanup() {
    [ -n "$HELPER_PID" ] && kill "$HELPER_PID" 2>/dev/null && wait "$HELPER_PID" 2>/dev/null
    [ -n "$SOVD_PID" ] && kill "$SOVD_PID" 2>/dev/null && wait "$SOVD_PID" 2>/dev/null
}
trap cleanup EXIT

# 7. Start security helper
if [ -n "$HELPER_BIN" ]; then
    echo "[vm-mgr] starting security helper on port $HELPER_PORT..."
    "$HELPER_BIN" \
        --port "$HELPER_PORT" \
        --config "$SECRETS_CONFIG" \
        --token "$HELPER_TOKEN" \
        > /tmp/vm-mgr-helper.log 2>&1 &
    HELPER_PID=$!
    sleep 0.5
fi

echo ""
echo "[vm-mgr] NV store:         $NV_PATH"
echo "[vm-mgr] Trust anchor:     $TRUST_ANCHOR"
echo "[vm-mgr] SOVD:             http://${SOVD_ADDR/0.0.0.0/localhost}"
if [ -n "$HELPER_BIN" ]; then
echo "[vm-mgr] Security helper:  http://localhost:$HELPER_PORT (token: $HELPER_TOKEN)"
fi
echo ""
echo "[vm-mgr] SOVD Explorer settings:"
echo "  Server URL:   http://${SOVD_ADDR/0.0.0.0/localhost}"
echo "  Helper URL:   http://localhost:$HELPER_PORT"
echo "  Helper token: $HELPER_TOKEN"
echo ""
echo "[vm-mgr] Flash flow: session → programming → security unlock → upload → commit"
echo ""

# 8. Start SOVD server
if [ -z "$PROFILE" ]; then
    exec "$SOVD" "$NV_PATH" "$TRUST_ANCHOR" "$SOVD_ADDR"
else
    "$SOVD" "$NV_PATH" "$TRUST_ANCHOR" "$SOVD_ADDR" &
    SOVD_PID=$!
    "$RUNNER" "${EXTRA_ARGS[@]}" --nv "$NV_PATH" --init
fi
