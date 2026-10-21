#!/usr/bin/env bash
#
# cleanup-proprietary.sh
#
# Removes every trace of the HP/Validity *proprietary* VFS491 stack that was
# installed on this machine between 2026-10-09 and 2026-10-14, and restores
# libfprint to the stock Fedora package.
#
# Every path touched here was verified with `rpm -qf` to be owned by *no* RPM,
# except libfprint itself, which is restored with `dnf reinstall`.
#
# Usage (as root):
#     sudo bash cleanup-proprietary.sh
#
# Idempotent: safe to run more than once.

set -euo pipefail

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "must run as root: sudo bash $0" >&2
  exit 1
fi

say() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. Stop everything that holds the USB device or talks to the vendor daemon
# ---------------------------------------------------------------------------
say "stopping services / daemon"
systemctl disable --now vcsFPService.service 2>/dev/null || true
systemctl stop fprintd.service 2>/dev/null || true
pkill -x vcsFPService 2>/dev/null || true
sleep 1

# ---------------------------------------------------------------------------
# 2. HP vendor stack and stray artifacts
# ---------------------------------------------------------------------------
say "removing the HP vendor stack"
note "the vcsFPService daemon, its wrapper, the HPUsbVFS491 firmware and the"
note "fw-path/guards preload shims all live under /usr/lib64/vfs491"
rm -rf  /usr/lib64/vfs491
rm -f   /usr/bin/HPUsbVFS491.img          # stray copy of the firmware image
rm -f   /usr/local/bin/vfs491_test        # helper built against the HP wrapper
rm -f   /etc/ValidityPersistentData       # empty vendor data file

say "removing IPC / runtime leftovers"
rm -f /run/ValidityService.pid /var/run/ValidityService.pid
rm -f /tmp/vfs491-daemon-used
rm -f /tmp/vcsSemKey_*

# ---------------------------------------------------------------------------
# 3. Units, drop-in and udev rules added by the proprietary installer
# ---------------------------------------------------------------------------
say "removing systemd units and the fprintd drop-in"
rm -f /etc/systemd/system/vcsFPService.service
rm -f /etc/systemd/system/fprintd.service.d/10-vfs491.conf
rmdir --ignore-fail-on-non-empty /etc/systemd/system/fprintd.service.d 2>/dev/null || true

say "removing custom udev rules"
# /etc/udev/rules.d/60-vfs491.rules           : access + keep-awake rules
# /usr/lib/udev/rules.d/60-fprint-autosuspend.rules : unowned replacement that
#   labelled 138a:003d "Validity Sensors (proprietary driver)" and forced
#   power/control=auto, which resets this sensor mid-scan.
rm -f /etc/udev/rules.d/60-vfs491.rules
rm -f /usr/lib/udev/rules.d/60-fprint-autosuspend.rules

# ---------------------------------------------------------------------------
# 4. Restore the stock Fedora libfprint
#    (the installed .so was replaced with a build containing the vfs491
#     vendor-stack driver; the original was kept as .so.2.0.0.dist)
# ---------------------------------------------------------------------------
say "restoring stock libfprint"
if dnf reinstall -y libfprint; then
  note "reinstalled from the Fedora repo"
  rm -f /usr/lib64/libfprint-2.so.2.0.0.dist
else
  note "dnf reinstall failed (offline?); falling back to the saved stock copy"
  ln -sfn libfprint-2.so.2.0.0 /usr/lib64/libfprint-2.so.2
  if [[ -f /usr/lib64/libfprint-2.so.2.0.0.dist ]]; then
    mv -f /usr/lib64/libfprint-2.so.2.0.0.dist /usr/lib64/libfprint-2.so.2.0.0
  fi
fi

# ---------------------------------------------------------------------------
# 5. Reload
# ---------------------------------------------------------------------------
say "reloading systemd / udev / ldconfig"
systemctl daemon-reload
udevadm control --reload
udevadm trigger --subsystem-match=usb
ldconfig

# ---------------------------------------------------------------------------
# 6. Verification
# ---------------------------------------------------------------------------
say "verification"
echo "-- rpm -V libfprint (no output below = package is pristine):"
rpm -V libfprint || true

echo "-- SONAME symlink:"
readlink /usr/lib64/libfprint-2.so.2

echo "-- vendor-stack driver still present in libfprint? (want 0):"
strings /usr/lib64/libfprint-2.so.2.0.0 2>/dev/null | grep -c vfs491 || true

echo "-- leftover paths (want: all 'No such file'):"
ls -d /usr/lib64/vfs491 \
      /etc/udev/rules.d/60-vfs491.rules \
      /usr/lib/udev/rules.d/60-fprint-autosuspend.rules \
      /etc/systemd/system/vcsFPService.service \
      /usr/local/bin/vfs491_test 2>&1 || true

echo "-- ld cache entries for vfs (want: none):"
ldconfig -p | grep -i vfs || echo "    none"

echo "-- systemd unit (want: not-found):"
systemctl is-enabled vcsFPService.service 2>&1 || true

echo "-- USB device is still enumerated:"
lsusb -d 138a:003d 2>&1 || printf '    %s\n' "(lsusb not installed)"

echo "-- fprintd device list (clean baseline: 'No devices available'):"
fprintd-list "${SUDO_USER:-$(logname 2>/dev/null || echo root)}" 2>&1 | head -5 || true

say "done"
