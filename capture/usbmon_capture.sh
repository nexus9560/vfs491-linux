#!/usr/bin/env bash
#
# Capture USB traffic for the VFS491 (138a:003d).
#
# usbmon is built into this kernel (CONFIG_USB_MON=y) and /dev/usbmon* exist,
# but the capture interfaces are root-only, so this script needs root.
#
# Two output paths:
#   * tshark (package wireshark-cli) if installed -> captures/<label>.pcap,
#     openable in Wireshark, full USB + (for later) TLS decoding.
#   * otherwise the kernel's usbmon *text* API -> captures/<label>.txt,
#     no extra packages needed; parse it with capture/usbmon_parse.py
#
# Usage:
#   sudo bash capture/usbmon_capture.sh [--label NAME] [--seconds N] [--bus N] [--text]
#
# Examples:
#   sudo bash capture/usbmon_capture.sh --label probe --seconds 10
#   python3 capture/usbmon_parse.py --devnum 3 captures/probe.txt

set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	echo "usbmon is root-only; re-executing with sudo..." >&2
	exec sudo -- bash "$0" "$@"
fi

label="capture"
seconds=30
bus=""
force_text=0

while [[ $# -gt 0 ]]; do
	case "$1" in
	--label)   label="$2"; shift 2 ;;
	--seconds) seconds="$2"; shift 2 ;;
	--bus)     bus="$2"; shift 2 ;;
	--text)    force_text=1; shift ;;
	-h|--help) sed -n '2,20p' "$0"; exit 0 ;;
	*) echo "unknown argument: $1" >&2; exit 2 ;;
	esac
done

# --- locate the sensor -------------------------------------------------------
sysfs=""
for d in /sys/bus/usb/devices/*/; do
	[[ -r "${d}idVendor" ]] || continue
	if [[ "$(cat "${d}idVendor")" == "138a" && "$(cat "${d}idProduct")" == "003d" ]]; then
		sysfs="$d"
		break
	fi
done

if [[ -z "$sysfs" ]]; then
	echo "VFS491 (138a:003d) not found on USB" >&2
	exit 1
fi

devbus=$(cat "${sysfs}busnum")
devnum=$(cat "${sysfs}devnum")
bus="${bus:-$devbus}"
mkdir -p captures

echo "sensor: bus ${devbus} device ${devnum} (${sysfs%/})"

# --- capture -----------------------------------------------------------------
if [[ $force_text -eq 0 ]] && command -v tshark >/dev/null 2>&1; then
	out="captures/${label}.pcap"
	echo "capturing bus ${bus} with tshark for ${seconds}s -> ${out}"
	echo "in Wireshark, filter with: usb.device_address == ${devnum}"
	tshark -i "usbmon${bus}" -a duration:"${seconds}" -w "${out}"
else
	out="captures/${label}.txt"
	echo "capturing bus ${bus} via the usbmon text API for ${seconds}s -> ${out}"
	echo "NOTE: the text API caps captured data at 32 bytes per transfer"
	echo "      (DATA_MAX in drivers/usb/mon/mon_text.c).  Good for command"
	echo "      framing; NOT good for payloads -- install wireshark-cli for a pcap."
	# The 'u' file is the 1u text format: it includes the bus number, unlike
	# the legacy 't' (1t) format.  Endpoint numbers there are decimal without
	# the direction bit -- usbmon_parse.py normalises them.
	timeout "${seconds}" cat "/sys/kernel/debug/usb/usbmon/${bus}u" >"${out}" || true
fi

# captures are written as root; hand them back to the invoking user
if [[ -n "${SUDO_UID:-}" && -n "${SUDO_GID:-}" ]]; then
	chown "${SUDO_UID}:${SUDO_GID}" "${out}" 2>/dev/null || true
fi

echo
echo "wrote ${out}"
echo "parse: python3 capture/usbmon_parse.py --devnum ${devnum} ${out}"
