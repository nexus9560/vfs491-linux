#!/usr/bin/env bash
# Regenerate vendor artifacts
# - Downloads sp84530 if needed
# - Unpacks RPM to HP_ROOT
# - Extracts patch blobs
# - Extracts keys/artifacts from an HP init capture (requires running validity-sensor -doinit under usblog)
set -euo pipefail

LOG_DIR="${LOG_DIR:-/tmp/opencode}"
LOG="${LOG_DIR}/$(basename "$0" .sh)_log.txt"
mkdir -p "${LOG_DIR}"
exec > >(tee -a "${LOG}") 2>&1

HP_ROOT="${HP_ROOT:-/tmp/opencode/hp/root}"
VNDIR="${VNDIR:-/tmp/opencode/vendor}"
OUT_PATCHES="${OUT_PATCHES:-/tmp/opencode/hp-patches}"
REPO=/home/mpryzlwyn/source/repos/fingerprint-sensor

echo "=== regen_vendor_artifacts ==="
date
echo "HP_ROOT=${HP_ROOT} VNDIR=${VNDIR} OUT_PATCHES=${OUT_PATCHES}"

mkdir -p /tmp/opencode/hp "${VNDIR}" "${OUT_PATCHES}"

# Download if needed
SP_TAR=/tmp/opencode/hp/sp84530.tar
if [[ ! -f "${SP_TAR}" ]]; then
  echo "Downloading sp84530.tar..."
  curl -L -o "${SP_TAR}" https://ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar
fi

RPM=/tmp/opencode/hp/SP84530/Validity-Sensor-Setup-4.5-136.0.x86_64.rpm
if [[ ! -f "${RPM}" ]]; then
  echo "Unpacking tar..."
  (cd /tmp/opencode/hp && tar xf sp84530.tar)
fi

if [[ ! -x "${HP_ROOT}/usr/sbin/validity-sensor" ]]; then
  echo "Extracting RPM to ${HP_ROOT}..."
  mkdir -p "${HP_ROOT}"
  (cd "${HP_ROOT}" && rpm2cpio "${RPM}" | cpio -idm 2>/dev/null)
fi

# Extract patch blobs
echo "Extracting patch blobs with hp_extract.py..."
python3 "${REPO}/tools/hp_extract.py" "${HP_ROOT}/usr/sbin/validity-sensor" -o "${OUT_PATCHES}"
cp -p "${OUT_PATCHES}"/patch1.bin "${VNDIR}/" 2>/dev/null || true
cp -p "${OUT_PATCHES}"/patch2.bin "${VNDIR}/" 2>/dev/null || true

echo "---"
echo "Patches: $(ls -lh ${VNDIR}/patch* 2>/dev/null | awk '{print $9"("$5")"}')"
echo "---"
echo "NEXT: you need a usbmon/init capture (e.g. hp_init_capture.sh getstartinfo -doinit)"
echo "Then run: python3 capture/extract_hp_artifacts.py /tmp/opencode/vfslog_init.txt --outdir /tmp/opencode/patches --sensor-bin ${HP_ROOT}/usr/sbin/validity-sensor"
echo "And copy keys: cp /tmp/opencode/patches/{cert_key.bin,cke_key.bin,sensor_pubkey.bin,slot0d_plain.bin} ${VNDIR}/ 2>/dev/null || true"
