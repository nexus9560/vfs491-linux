#!/usr/bin/env bash
# Research-only: capture the *init* traffic HP's `validity-sensor` sends to the
# VFS491, so we can learn the exact unlock sequence (RAM patches) and the SSL
# session, and replay it with our own open client.
#
# This drives HP's proprietary tool (SoftPaq sp84530). It is a measurement
# instrument only: nothing it produces is committed, and we never ship its code.
# See docs/hp-artifacts.md.
#
# The tool calls usb_reset() during init, which makes the sensor re-enumerate
# (new /dev/bus/usb/NNN/NNN). The device node therefore needs an ACL or root;
# run this with `sudo` if the tool cannot open the device.
#
# Usage:
#   capture/hp_init_capture.sh [HP_ROOT] [--] <tool command> [args...]
#
# Examples:
#   sudo capture/hp_init_capture.sh /tmp/opencode/hp/root getstartinfo -doinit
#   sudo capture/hp_init_capture.sh /tmp/opencode/hp/root getprintwait -doinit
#
# HP_ROOT is the directory holding `usr/sbin/validity-sensor` (unpacked from
# sp84530's RPM). Output goes to $OUTDIR (default /tmp/opencode). Never commit it.
set -euo pipefail

HP_ROOT=${HP_ROOT:-${1:-/tmp/opencode/hp/root}}
if [[ ${1:-} && -d ${1:-} ]]; then shift; fi
[[ ${1:-} == "--" ]] && shift
OUTDIR=${OUTDIR:-/tmp/opencode}
LOG=${LOG:-$OUTDIR/vfslog_init.txt}

SRC=$HP_ROOT/usr/sbin/validity-sensor
[[ -x $SRC ]] || { echo "no $SRC (unpack sp84530 first; see docs/hp-artifacts.md)" >&2; exit 1; }

mkdir -p "$OUTDIR"
TOOL=$OUTDIR/validity-sensor-unlocked
USBLOG=$OUTDIR/usblog.so

# 1. Gate patch: HP disabled the diagnostic commands in main(); jump over the
#    gate at VA 0x44122d (file offset 0x4122d): 48 8b 7b 08 -> e9 <rel32>.
if [[ ! -x $TOOL ]]; then
  python3 - "$SRC" "$TOOL" <<'PY'
import struct, sys
d = bytearray(open(sys.argv[1], "rb").read())
off = 0x44122d - 0x400000
assert d[off:off+4] == bytes.fromhex("488b7b08"), "unexpected binary (not sp84530 4.5-136.0?)"
d[off:off+5] = b"\xe9" + struct.pack("<i", 0x4412b4 - (0x44122d + 5))
open(sys.argv[2], "wb").write(bytes(d))
PY
  chmod +x "$TOOL"
  echo "gate-patched tool -> $TOOL"
fi

# 2. LD_PRELOAD logger for all libusb-0.1 traffic.
if [[ ! -f $USBLOG ]]; then
  here=$(dirname "$(readlink -f "$0")")
  cc=${CC:-cc}
  "$cc" -shared -fPIC -O2 -o "$USBLOG" "$here/../reference/nixos-validity-VFS491/research/usblog.c" -ldl
  echo "built -> $USBLOG"
fi

# 3. Run from a directory WITHOUT the HPUsbVFS*.img files, so DeviceInit's
#    EFI/flash branch cannot pick them up. Read-only commands only.
RUNDIR=${RUNDIR:-$OUTDIR/run}
mkdir -p "$RUNDIR"; cd "$RUNDIR"
: > "$LOG"
echo "running: $TOOL $*   (VFSLOG=$LOG)"
LD_PRELOAD=$USBLOG VFSLOG=$LOG "$TOOL" "$@"

# 4. Tidy transfer summary + OUT-command histogram.
echo
echo "=== transfers (dir ep first-bytes) ==="
awk '$2=="OUT"||$2=="IN"{d="";if(match($0,/data=/))d=substr($0,RSTART+5);printf "  %-4s %-6s %s\n",$2,$3,substr(d,1,72)}' "$LOG"
echo
echo "=== OUT commands by first byte ==="
grep -oE 'OUT ep=01 len=[0-9]+ ret=[0-9]+ data=[0-9a-f]{2}' "$LOG" \
  | sed -E 's/.*data=//' | sort | uniq -c
echo "full log: $LOG"
