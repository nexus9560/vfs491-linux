#!/usr/bin/env bash
# Vendor gdb capture runner
# - Runs gate-patched validity-sensor under gdb with breakpoints at scsSend (0x4f7bd0) and scsSSLAppDataWrite (0x514d10)
# - Dumps 8192 bytes from the command buffer at each hit (vendor's style widened capture)
# - Self-logs to <script>_log.txt in LOG_DIR (default: /tmp/opencode)
set -euo pipefail

SCRIPT="$(basename "$0")"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${LOG_DIR:-/tmp/opencode}"
LOG="${LOG_DIR}/${SCRIPT%.sh}_log.txt"
mkdir -p "${LOG_DIR}"

if [[ -f "${LOG}" && $(stat -c%s "${LOG}" 2>/dev/null || echo 0) -gt 2000000 ]]; then
  mv "${LOG}" "${LOG}.prev" 2>/dev/null || true
fi

# Paths (vendor artifacts live in tmpfs)
HP_ROOT="${HP_ROOT:-/tmp/opencode/hp/root}"
VNDIR="${VNDIR:-/tmp/opencode/vendor}"
TOOL="${TOOL:-/tmp/opencode/validity-sensor-unlocked}"
USBLOG="${USBLOG:-/tmp/opencode/usblog.so}"
OUTDUMP="${OUTDUMP:-/tmp/opencode/gdb_capture.log}"

# Capture command to run (default getprintwait -doinit)
CMD="${CMD:-getprintwait -doinit}"

exec > >(tee -a "${LOG}") 2>&1

echo "=================================================="
date
echo "Script: ${SCRIPT}"
echo "LOG: ${LOG}"
echo "HP_ROOT: ${HP_ROOT}"
echo "TOOL: ${TOOL}"
echo "USBLOG: ${USBLOG}"
echo "OUTDUMP: ${OUTDUMP}"
echo "CMD: ${CMD}"
echo "=================================================="

SRC="${HP_ROOT}/usr/sbin/validity-sensor"
[[ -x "${SRC}" ]] || { echo "ERROR: ${SRC} not found. See docs/hp-artifacts.md (sp84530 unpack)." >&2; exit 1; }

# 1) Gate patch
if [[ ! -x "${TOOL}" ]]; then
  echo "Gate-patching: ${SRC} -> ${TOOL}"
  python3 - "${SRC}" "${TOOL}" <<'PY'
import struct, sys
d = bytearray(open(sys.argv[1],'rb').read())
off = 0x44122d - 0x400000
assert d[off:off+4] == bytes.fromhex("488b7b08"), "unexpected binary (not sp84530 4.5-136.0?)"
d[off:off+5] = b"\xe9" + struct.pack("<i", 0x4412b4 - (0x44122d + 5))
open(sys.argv[2],'wb').write(bytes(d))
PY
  chmod +x "${TOOL}"
fi

# 2) usblog.so
if [[ ! -f "${USBLOG}" ]]; then
  REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")"/../.. && pwd)"
  # fallback
  if [[ ! -d "${REPO}/reference/nixos-validity-VFS491/research" ]]; then
    REPO=/home/mpryzlwyn/source/repos/fingerprint-sensor
  fi
  echo "Building usblog.so from ${REPO}/reference/nixos-validity-VFS491/research/usblog.c"
  cc -shared -fPIC -O2 -o "${USBLOG}" "${REPO}/reference/nixos-validity-VFS491/research/usblog.c" -ldl
fi

# 3) gdb script: break at scsSend(0x4f7bd0) and scsSSLAppDataWrite(0x514d10) and dump 8192B from rsi/arg
cat > /tmp/opencode/vfs_gdb.dump <<'GDB'
set pagination off
set history save off
set confirm off
break *0x4f7bd0
break *0x514d10
commands 1
  silent
  printf "=== scsSend len=%ld flags=%ld (rdi=r15 context?) ===\n", $rsi, $rdx
  x/1024xb $rdi
  cont
end
commands 2
  silent
  printf "=== APP-DATA (pre-encrypt) len=%d ===\n", *(int*)($rdi+0xc)
  x/1024xb $rdi
  cont
end
run
quit
GDB

RUNDIR="${LOG_DIR}/run_gdb_$$"
mkdir -p "${RUNDIR}"
cd "${RUNDIR}"
: > "${OUTDUMP}"
echo "running: gdb -batch -x /tmp/opencode/vfs_gdb.dump --args ${TOOL} ${CMD} (VFSLOG=${OUTDUMP})"
# LD_PRELOAD logged via usblog? use env similar to original
LD_PRELOAD="${USBLOG}" VFSLOG="${OUTDUMP}" gdb -batch -x /tmp/opencode/vfs_gdb.dump --args "${TOOL}" ${CMD}
echo "Dump: ${OUTDUMP}"
