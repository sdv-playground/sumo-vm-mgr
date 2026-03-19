#!/bin/bash
# vm-mgr boot loop — simulated bootloader
#
# Builds the workspace, initializes NV store, and runs the boot loop.
# Use vm-diagserver from another terminal to send OTA/diag commands.
#
# Usage: ./scripts/run.sh --profile <profile.toml> --images <dir> [--sim-dir <dir>]
#
# Example:
#   Terminal 1: ./scripts/run.sh --profile profiles/os1-minimal.toml --images /path/to/output
#   Terminal 2: ./target/debug/vm-diagserver /tmp/vm-mgr-nv.bin status os1
#               ./target/debug/vm-diagserver /tmp/vm-mgr-nv.bin install os1 image.bin v2.0 1

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
NV_PATH="${VM_MGR_NV:-/tmp/vm-mgr-nv.bin}"

# Pass through all args, we'll extract what we need
PROFILE=""
EXTRA_ARGS=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --profile)
            PROFILE="$2"
            EXTRA_ARGS+=("$1" "$2")
            shift 2
            ;;
        --nv)
            NV_PATH="$2"
            shift 2
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

if [ -z "$PROFILE" ]; then
    echo "Usage: $0 --profile <profile.toml> --images <dir> [--sim-dir <dir>]"
    echo ""
    echo "Options:"
    echo "  --profile <path>    VM profile TOML file (required)"
    echo "  --images <dir>      Directory with bank images (required)"
    echo "  --sim-dir <dir>     Directory with simulator binaries"
    echo "  --nv <path>         NV store path (default: /tmp/vm-mgr-nv.bin)"
    echo ""
    echo "Environment:"
    echo "  VM_MGR_NV           Alternative to --nv (default: /tmp/vm-mgr-nv.bin)"
    exit 1
fi

echo "[vm-mgr] building..."
cargo build --manifest-path "$ROOT_DIR/Cargo.toml" --quiet

RUNNER="$ROOT_DIR/target/debug/vm-runner"
DIAGSERVER="$ROOT_DIR/target/debug/vm-diagserver"

echo "[vm-mgr] NV store: $NV_PATH"
echo "[vm-mgr] profile:  $PROFILE"
echo ""
echo "[vm-mgr] From another terminal, use the diagserver:"
echo "  $DIAGSERVER $NV_PATH status os1"
echo "  $DIAGSERVER $NV_PATH install os1 <image> <version> <secver>"
echo "  $DIAGSERVER $NV_PATH commit os1"
echo "  $DIAGSERVER $NV_PATH rollback os1"
echo ""

exec "$RUNNER" "${EXTRA_ARGS[@]}" --nv "$NV_PATH" --init
