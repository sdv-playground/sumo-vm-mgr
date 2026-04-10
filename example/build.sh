#!/bin/bash
# =============================================================================
# Generate demo SUIT artifacts demonstrating firmware/manifest separation.
#
# Firmware binaries are content-addressable (stored by SHA-256 hash).
# Manifests are signed policy documents referencing firmware by digest.
# The same firmware can be re-signed with different security_version.
#
# Output:
#   example/keys/          signing + device key pairs (COSE_Key CBOR)
#   example/output/        signed SUIT envelopes
#   example/output/firmware/   content-addressable firmware binaries
#
# Usage:
#   ./example/build.sh
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
WORKSPACE="$(cd "$ROOT_DIR/../.." && pwd)"
SUMO_RS_DIR="$WORKSPACE/components/sumo-rs"
TMPL_DIR="$SCRIPT_DIR/templates"

export KEYS_DIR="$SCRIPT_DIR/keys"
OUTPUT_DIR="$SCRIPT_DIR/output"
FW_DIR="$OUTPUT_DIR/firmware"

FIRMWARE_SIZE=1048576  # 1MB

# Build sumo-tool
echo "[build] building sumo-tool..."
(cd "$SUMO_RS_DIR" && cargo build --release --quiet -p sumo-tools)
SUMO_TOOL="$SUMO_RS_DIR/target/release/sumo-tool"

mkdir -p "$KEYS_DIR" "$OUTPUT_DIR" "$FW_DIR"

# ---------------------------------------------------------------
# 1. Generate signing key + device key
# ---------------------------------------------------------------
echo "[build] generating keys..."
"$SUMO_TOOL" keygen --output "$KEYS_DIR/signing.key" --public "$KEYS_DIR/signing.pub"
"$SUMO_TOOL" keygen --device --output "$KEYS_DIR/device.key" --public "$KEYS_DIR/device.pub"
echo "[build] wrote keys to $KEYS_DIR/"

# ---------------------------------------------------------------
# 2. Build firmware binaries (content-addressable by SHA-256)
# ---------------------------------------------------------------
echo ""
echo "[build] === Firmware binaries ==="

# Stores: fw_digests[component-version]=hex_hash, fw_paths[component-version]=path, fw_sizes[component-version]=size
declare -A fw_digests fw_paths fw_sizes

build_fw() {
    local component="$1" version="$2"
    local key="${component}-${version}"

    # 1MB random firmware
    local tmp_path="$FW_DIR/tmp_${key}.bin"
    dd if=/dev/urandom bs=$FIRMWARE_SIZE count=1 of="$tmp_path" 2>/dev/null

    local digest
    digest=$(sha256sum "$tmp_path" | cut -d' ' -f1)
    local fw_path="$FW_DIR/${digest}.bin"
    mv "$tmp_path" "$fw_path"

    fw_digests[$key]="$digest"
    fw_paths[$key]="$fw_path"
    fw_sizes[$key]="$FIRMWARE_SIZE"

    echo "[build] $component v$version -> $(basename "$fw_path") ($FIRMWARE_SIZE bytes, hash: ${digest:0:16}...)"
}

# OS1: upgrade path 1.0.0 -> 1.1.0 -> 1.2.0 -> 1.3.0
for ver in "1.0.0" "1.1.0" "1.2.0" "1.3.0"; do
    build_fw "os1" "$ver"
done

# HSM: single-bank firmware
build_fw "hsm" "1.1.0"

# QTD: A/B banked firmware
build_fw "qtd" "1.1.0"

# ---------------------------------------------------------------
# 3. OS1 manifests — all versions get security_version=1
# ---------------------------------------------------------------
echo ""
echo "[build] === OS1 manifests (secver=1, integrated) ==="

seq_num=0
for ver in "1.0.0" "1.1.0" "1.2.0" "1.3.0"; do
    seq_num=$((seq_num + 1))
    filename="os1-v${ver}.suit"

    export COMPONENT="os1" VERSION="$ver" SEQ="$seq_num" SECVER=1
    export FW_PATH="${fw_paths[os1-${ver}]}"
    export MANIFEST_PATH="$OUTPUT_DIR/$filename"
    export MODEL_NAME="OS1-Linux"
    export MODEL_INFO="OS1-SW-$(printf '%03d' "$seq_num")"
    export DESCRIPTION="OS1-SP-${ver//.}"

    envsubst < "$TMPL_DIR/l2-encrypted.yaml.tmpl" | "$SUMO_TOOL" build --manifest -
    echo "[build] $filename ($(stat -c%s "$OUTPUT_DIR/$filename") bytes, secver=1)"
done

# ---------------------------------------------------------------
# 4. HSM + QTD manifests
# ---------------------------------------------------------------
echo ""
echo "[build] === HSM manifest (secver=1, integrated) ==="

export COMPONENT="hsm" VERSION="1.1.0" SEQ=1 SECVER=1
export FW_PATH="${fw_paths[hsm-1.1.0]}"
export MANIFEST_PATH="$OUTPUT_DIR/hsm-v1.1.0.suit"
export MODEL_NAME="HSM-Firmware" MODEL_INFO="HSM-SW-001" DESCRIPTION="HSM-SP-110"
envsubst < "$TMPL_DIR/l2-encrypted.yaml.tmpl" | "$SUMO_TOOL" build --manifest -
echo "[build] hsm-v1.1.0.suit ($(stat -c%s "$OUTPUT_DIR/hsm-v1.1.0.suit") bytes, secver=1)"

echo ""
echo "[build] === QTD manifest (secver=1, integrated) ==="

export COMPONENT="qtd" VERSION="1.1.0" SEQ=1 SECVER=1
export FW_PATH="${fw_paths[qtd-1.1.0]}"
export MANIFEST_PATH="$OUTPUT_DIR/qtd-v1.1.0.suit"
export MODEL_NAME="QTD-QNX" MODEL_INFO="QTD-SW-001" DESCRIPTION="QTD-SP-110"
envsubst < "$TMPL_DIR/l2-encrypted.yaml.tmpl" | "$SUMO_TOOL" build --manifest -
echo "[build] qtd-v1.1.0.suit ($(stat -c%s "$OUTPUT_DIR/qtd-v1.1.0.suit") bytes, secver=1)"

# ---------------------------------------------------------------
# 5. Security incident — re-sign OS1 1.2.0 and 1.3.0 with secver=2
# ---------------------------------------------------------------
echo ""
echo "[build] === Re-signed OS1 manifests after security incident (secver=2) ==="

seq_num=2  # 1.2.0 was seq=3, 1.3.0 was seq=4
for ver in "1.2.0" "1.3.0"; do
    seq_num=$((seq_num + 1))

    # Reference-only (no payload, for content-addressable workflow)
    filename="os1-v${ver}-secver2.suit"
    export COMPONENT="os1" VERSION="$ver" SEQ="$seq_num" SECVER=2
    export FW_DIGEST="${fw_digests[os1-${ver}]}" FW_SIZE="${fw_sizes[os1-${ver}]}"
    export MANIFEST_PATH="$OUTPUT_DIR/$filename"
    export MODEL_NAME="OS1-Linux"
    export MODEL_INFO="OS1-SW-$(printf '%03d' "$seq_num")"
    export DESCRIPTION="OS1-SP-${ver//.}"
    envsubst < "$TMPL_DIR/l2-reference.yaml.tmpl" | "$SUMO_TOOL" build --manifest -
    echo "[build] $filename ($(stat -c%s "$OUTPUT_DIR/$filename") bytes, secver=2, reference)"

    # Integrated (with payload, for direct upload)
    filename="os1-v${ver}-secver2-full.suit"
    export FW_PATH="${fw_paths[os1-${ver}]}"
    export MANIFEST_PATH="$OUTPUT_DIR/$filename"
    envsubst < "$TMPL_DIR/l2-encrypted.yaml.tmpl" | "$SUMO_TOOL" build --manifest -
    echo "[build] $filename ($(stat -c%s "$OUTPUT_DIR/$filename") bytes, secver=2, integrated)"
done

# ---------------------------------------------------------------
# 6. CRL manifest — raises floor to 2, blocking 1.0.0 and 1.1.0
# ---------------------------------------------------------------
echo ""
echo "[build] === CRL manifest ==="

export COMPONENT="os1" SEQ=100 SECVER=2
export MANIFEST_PATH="$OUTPUT_DIR/os1-crl-secver2.suit"
envsubst < "$TMPL_DIR/crl.yaml.tmpl" | "$SUMO_TOOL" build --manifest -
echo "[build] os1-crl-secver2.suit ($(stat -c%s "$OUTPUT_DIR/os1-crl-secver2.suit") bytes)"

# ---------------------------------------------------------------
# 7. Usage
# ---------------------------------------------------------------
echo ""
echo "=== Components ==="
echo ""
echo "  os1  — OS1 Linux VM (A/B banked, rollbackable)"
echo "  os2  — OS2 Linux VM (A/B banked, rollbackable)"
echo "  hsm  — Hardware Security Module (single-bank, non-rollbackable)"
echo "  qtd  — QNX Target Partition (A/B banked, rollbackable)"
echo "  hyp  — Hypervisor (A/B banked, rollbackable)"
echo ""
echo "=== Test scenarios ==="
echo ""
echo "Upgrade path (os1):"
echo "  Flash 1.1.0 -> commit -> flash 1.2.0 -> commit -> flash 1.3.0 -> commit"
echo ""
echo "A/B testing:"
echo "  Flash 1.3.0 -> rollback (stay on 1.2.0) -> flash 1.3.0 -> commit"
echo ""
echo "Security incident response:"
echo "  Flash os1-crl-secver2.suit -> raises floor to 2"
echo "  Flash 1.0.0 -> REJECTED (secver 1 < floor 2)"
echo "  Flash os1-v1.2.0-secver2.suit -> works (re-signed, secver=2)"
echo ""
echo "HSM (single-bank):"
echo "  Flash hsm-v1.1.0.suit -> immediate commit, no rollback available"
echo ""
echo "Content-addressable workflow:"
echo "  Re-signed manifests are ~500 bytes (no firmware payload)"
echo "  Firmware binaries are in example/output/firmware/ (by SHA-256)"
echo ""
echo "SOVD Explorer -> connect to http://localhost:4000"
