#!/usr/bin/env bash
#
# cleanup-proprietary.sh
#
# Removes the HP/Validity *proprietary* VFS491 stack (the vendor daemon,
# firmware and preload shims) and restores the distro's stock libfprint.
#
# The paths below are the ones the vendor/RPM stack installs on Fedora; on
# another distro some will simply not exist and are removed as no-ops. The
# libfprint restore uses whichever package manager is present.
#
# Usage (as root):
#     sudo bash cleanup-proprietary.sh
#
# Idempotent: safe to run more than once.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=proprietary/vfs491-lib.sh
. "$REPO/proprietary/vfs491-lib.sh"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "must run as root: sudo bash $0" >&2
  exit 1
fi

say() { printf '==> %s\n' "$*"; }
note() { printf '    %s\n' "$*"; }

# libfprint's shared object lives in a multiarch dir on Debian, lib64 elsewhere.
lf_dir() {
  local d
  for d in /usr/lib64 /usr/lib/*/ /usr/lib; do
    [ -e "${d%/}/libfprint-2.so.2" ] && { printf '%s\n' "${d%/}"; return; }
  done
  printf '/usr/lib64\n'
}
LF_DIR="$(lf_dir)"

# ---------------------------------------------------------------------------
# 1. Stop everything that holds the USB device or talks to the vendor daemon
# ---------------------------------------------------------------------------
say "stopping services / daemon"
systemctl disable --now vcsFPService.service 2>/dev/null || true
systemctl disable --now vfs491-bridge.service 2>/dev/null || true
systemctl stop fprintd.service 2>/dev/null || true
pkill -x vcsFPService 2>/dev/null || true
sleep 1

# ---------------------------------------------------------------------------
# 2. This project's own working path (setup.sh + enable-auth.sh)
#    Separate from the old vendor stack below: setup.sh installs to /usr/libexec
#    and installs units/drop-ins, none of which the vendor paths cover.
# ---------------------------------------------------------------------------
say "removing this project's installed working path"
note "tool + scripts: ${LIBEXEC:-/usr/libexec/vfs491}"
rm -rf "${LIBEXEC:-/usr/libexec/vfs491}"
rm -f /etc/systemd/system/vfs491-bridge.service
rm -f /etc/systemd/system/fprintd.service.d/virtual-image.conf
rmdir --ignore-fail-on-non-empty /etc/systemd/system/fprintd.service.d 2>/dev/null || true

note "greeter ordering drop-ins"
for g in gdm sddm lightdm plasmalogin lxdm greetd ly xdm; do
  rm -f "/etc/systemd/system/${g}.service.d/vfs491.conf"
  rmdir --ignore-fail-on-non-empty "/etc/systemd/system/${g}.service.d" 2>/dev/null || true
done

note "run-time state"
rm -rf /run/vfs491-fprint /run/fprint

# Undo the PAM wiring this repo added (authselect feature or direct edits).
if [ -x "$REPO/proprietary/enable-auth.sh" ]; then
  say "reversing the PAM fingerprint wiring"
  "$REPO/proprietary/enable-auth.sh" --undo || true
fi

# ---------------------------------------------------------------------------
# 3. HP vendor stack and stray artifacts
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
# 4. Units, drop-in and udev rules added by the proprietary installer
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
# 5. Restore the distro's stock libfprint
#    (the installed .so may have been replaced with a build containing the
#     vfs491 vendor-stack driver; the original is kept as .so.2.0.0.dist)
# ---------------------------------------------------------------------------
say "restoring stock libfprint"
# Try the native package manager for whatever distro this is.
restore_ok=no
if command -v dnf >/dev/null 2>&1 && dnf reinstall -y libfprint; then
  note "reinstalled via dnf"; restore_ok=yes
elif command -v apt-get >/dev/null 2>&1 && apt-get install --reinstall -y libfprint-2-2; then
  note "reinstalled via apt"; restore_ok=yes
elif command -v pacman >/dev/null 2>&1 && pacman -S --noconfirm libfprint; then
  note "reinstalled via pacman"; restore_ok=yes
elif command -v zypper >/dev/null 2>&1 && zypper --non-interactive install --force libfprint-2-2; then
  note "reinstalled via zypper"; restore_ok=yes
fi

if [ "$restore_ok" = no ]; then
  note "package reinstall unavailable; falling back to the saved stock copy"
  ln -sfn "libfprint-2.so.2.0.0" "$LF_DIR/libfprint-2.so.2"
  if [[ -f "$LF_DIR/libfprint-2.so.2.0.0.dist" ]]; then
    mv -f "$LF_DIR/libfprint-2.so.2.0.0.dist" "$LF_DIR/libfprint-2.so.2.0.0"
    note "restored $LF_DIR/libfprint-2.so.2.0.0 from .dist"
  else
    note "no saved copy found; nothing to restore automatically"
  fi
fi

# ---------------------------------------------------------------------------
# 6. Reload
# ---------------------------------------------------------------------------
say "reloading systemd / udev / ldconfig"
command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
command -v udevadm   >/dev/null 2>&1 && udevadm control --reload || true
command -v udevadm   >/dev/null 2>&1 && udevadm trigger --subsystem-match=usb || true
command -v ldconfig  >/dev/null 2>&1 && ldconfig || true

# ---------------------------------------------------------------------------
# 7. Verification
# ---------------------------------------------------------------------------
say "verification"
if command -v rpm >/dev/null 2>&1; then
  echo "-- rpm -V libfprint (no output below = package is pristine):"
  rpm -V libfprint || true
else
  echo "-- (no rpm on this distro; skipping package verify)"
fi

echo "-- SONAME symlink:"
readlink "$LF_DIR/libfprint-2.so.2" || true

echo "-- vendor-stack driver still present in libfprint? (want 0):"
strings "$LF_DIR/libfprint-2.so.2.0.0" 2>/dev/null | grep -c vfs491 || true

echo "-- leftover paths (want: all 'No such file'):"
ls -d "${LIBEXEC:-/usr/libexec/vfs491}" \
      /usr/lib64/vfs491 \
      /etc/systemd/system/vfs491-bridge.service \
      /etc/systemd/system/fprintd.service.d/virtual-image.conf \
      /etc/systemd/system/*.service.d/vfs491.conf \
      /etc/udev/rules.d/60-vfs491.rules \
      /usr/lib/udev/rules.d/60-fprint-autosuspend.rules \
      /etc/systemd/system/vcsFPService.service \
      /usr/local/bin/vfs491_test 2>&1 || true

echo "-- ld cache entries for vfs (want: none):"
ldconfig -p | grep -i vfs || echo "    none"

echo "-- systemd unit (want: not-found):"
systemctl is-enabled vcsFPService.service 2>&1 || true

echo "-- USB device is still enumerated:"
if command -v lsusb >/dev/null 2>&1; then
  lsusb -d "${VFS491_VID}:${VFS491_PID}" 2>&1 || true
else
  printf '    %s\n' "(lsusb not installed)"
fi

echo "-- fprintd device list (clean baseline: 'No devices available'):"
fprintd-list "$(vfs_auth_user)" 2>&1 | head -5 || true

say "done"
