#!/bin/bash
# Create a VMFB firmware bundle from a manifest + image.
#
# Usage: ./scripts/mkbundle.sh <manifest.yaml> <image> <output.vmfb>

set -euo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 <manifest.yaml> <image> <output.vmfb>"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DIAGSERVER="$ROOT_DIR/target/debug/vm-diagserver"

if [ ! -f "$DIAGSERVER" ]; then
    echo "[mkbundle] building..."
    cargo build --manifest-path "$ROOT_DIR/Cargo.toml" -p vm-diagserver --quiet
fi

"$DIAGSERVER" _ pack "$1" "$2" "$3"
