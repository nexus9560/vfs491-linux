#!/usr/bin/env bash
# Open client capture runner for VFS491
# - Handshake + send capture command + read image on EP 0x82
# - Self-logs to <script>_log.txt in LOG_DIR (default: /tmp/opencode)
set -euo pipefail

SCRIPT="$(basename "$0")"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/tmp/opencode}"
LOG="${LOG_DIR}/${SCRIPT%.sh}_log.txt"
mkdir -p "${LOG_DIR}"

# Rotate log if large
if [[ -f "${LOG}" && $(stat -c%s "${LOG}" 2>/dev/null || echo 0) -gt 2000000 ]]; then
  mv "${LOG}" "${LOG}.prev" 2>/dev/null || true
fi

# Vendor artifacts (from extract_hp_artifacts.py / hp_extract + capture)
VNDIR="${VNDIR:-/tmp/opencode/vendor}"
P1="${P1:-${VNDIR}/patch1.bin}"
P2="${P2:-${VNDIR}/patch2.bin}"
PK="${PK:-${VNDIR}/cert_key.bin}"
CKE="${CKE:-${VNDIR}/cke_key.bin}"
CV="${CV:-${VNDIR}/slot0d_plain.bin}"

# Default capture command (vendor-derived minimal; works, though vendor uses 2331B register table)
# From our working run: 02 20 01 ff 03 15 00 08 00 00 00 00 00 20 28 00 00
CMD="${CMD:-02 20 01 ff 03 15 00 08 00 00 00 00 00 20 28 00 00}"

# Image output
IMG="${IMG:-/tmp/opencode/image.bin}"

# Client
CLIENT="${CLIENT:-/home/mpryzlwyn/source/repos/fingerprint-sensor/build/vfs491_ssl}"

exec > >(tee -a "${LOG}") 2>&1

echo "=================================================="
date
echo "Script: ${SCRIPT}"
echo "CWD: $(pwd)"
echo "LOG: ${LOG}"
echo "VNDIR: ${VNDIR}"
echo "P1=${P1} P2=${P2} PK=${PK} CKE=${CKE} CV=${CV}"
echo "CMD: ${CMD}"
echo "IMG: ${IMG}"
echo "CLIENT: ${CLIENT}"
echo "=================================================="

need=("${P1}" "${P2}" "${PK}" "${CKE}" "${CV}")
for f in "${need[@]}"; do
  if [[ ! -f "${f}" ]]; then
    echo "ERROR: missing ${f}" >&2
    echo "Run regen_vendor_artifacts.sh or extract_hp_artifacts.py from an HP capture." >&2
    echo "Alternatively place required .bin files in ${VNDIR}/" >&2
    exit 1
  fi
done

if [[ ! -x "${CLIENT}" ]]; then
  echo "ERROR: client not built: ${CLIENT}" >&2
  echo "Build: cd /home/mpryzlwyn/source/repos/fingerprint-sensor && make" >&2
  exit 1
fi

echo "Tip: swipe slowly across the sensor while capturing (~2s), then lift."
echo "Running open client (modle default, correct CV key)..."
sudo "${CLIENT}" "${P1}" "${P2}" \
  --pubkey "${PK}" \
  --cke-key "${CKE}" \
  --cv-key "${CV}" \
  --no-spi \
  --cmd "${CMD}" \
  --image \
  --image-out "${IMG}"
echo "Done. Image saved to: ${IMG}"
echo "Log: ${LOG}"
