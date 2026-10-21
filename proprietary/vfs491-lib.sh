#!/usr/bin/env bash
# vfs491-lib.sh -- shared, distro-neutral helpers for the VFS491 scripts.
#
# Source this, do not run it:   . "$(dirname "$0")/vfs491-lib.sh"
#
# Everything here avoids assuming a distribution, an init system beyond systemd
# (checked at use sites), a username, or a fixed USB topology.

# --- pretty printing ---------------------------------------------------------
vfs_say()  { printf '\033[1m==> %s\033[0m\n' "$*"; }
vfs_warn() { printf '\033[1;33m!!! %s\033[0m\n' "$*" >&2; }
vfs_err()  { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; }
vfs_die()  { vfs_err "$*"; exit 1; }

# --- the account the fingerprint belongs to ----------------------------------
# Under `sudo`, $USER is usually root, which is NOT the account whose finger we
# want to enroll or verify. Prefer SUDO_USER (or DOAS_USER for doas), then the
# owner of the current tty, then the login session user.
vfs_auth_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ]; then
    printf '%s\n' "$SUDO_USER"; return
  fi
  if [ -n "${DOAS_USER:-}" ] && [ "$DOAS_USER" != root ]; then
    printf '%s\n' "$DOAS_USER"; return
  fi
  local u
  u="$(logname 2>/dev/null || true)"
  [ -n "$u" ] && [ "$u" != root ] && { printf '%s\n' "$u"; return; }
  u="$(id -un 2>/dev/null || true)"
  printf '%s\n' "${u:-root}"
}

# --- run as root, without assuming sudo exists -------------------------------
# Prefer sudo; fall back to doas; fall back to plain execution if already root.
vfs_sudo() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  elif command -v doas >/dev/null 2>&1; then
    doas "$@"
  else
    vfs_die "need root: neither sudo nor doas is installed, and you are not root"
  fi
}

# --- locate the sensor by VID:PID, never by bus-port -------------------------
# The sysfs node (e.g. 3-1.1) is topology-specific and differs between
# machines, docks, and reboots. Match the USB IDs instead.
VFS491_VID="${VFS491_VID:-138a}"
VFS491_PID="${VFS491_PID:-003d}"

vfs_sensor_sysfs() {
  local d
  for d in /sys/bus/usb/devices/*/; do
    [ -r "${d}idVendor" ] || continue
    if [ "$(cat "${d}idVendor" 2>/dev/null)" = "$VFS491_VID" ] &&
       [ "$(cat "${d}idProduct" 2>/dev/null)" = "$VFS491_PID" ]; then
      printf '%s\n' "${d%/}"
      return 0
    fi
  done
  return 1
}

# Re-enumerate the device to clear a wedged sensor, without a reboot.
# Usage: vfs_reenumerate
vfs_reenumerate() {
  local dev
  dev="$(vfs_sensor_sysfs)" || {
    vfs_err "sensor ${VFS491_VID}:${VFS491_PID} not found on the USB bus"
    return 1
  }
  vfs_say "re-enumerating ${dev##*/} (no reboot needed)"
  vfs_sudo sh -c "echo 0 > '$dev/authorized'; sleep 2; echo 1 > '$dev/authorized'"
}

# --- PAM module directory ----------------------------------------------------
# Multiarch: /usr/lib/<triplet>/security on Debian, /usr/lib64/security on
# Fedora/SUSE, /usr/lib/security elsewhere. Ask pam itself first (most reliable),
# then fall back to the common locations.
vfs_pam_secdir() {
  local d
  if command -v pkg-config >/dev/null 2>&1; then
    d="$(pkg-config --variable=libdir pam 2>/dev/null || true)"
    [ -n "$d" ] && [ -d "$d/security" ] && { printf '%s\n' "$d/security"; return; }
  fi
  for d in /usr/lib64/security /usr/lib/security /usr/lib/*/security /lib/security; do
    [ -d "$d" ] && { printf '%s\n' "$d"; return; }
  done
  return 1
}

vfs_pam_module() {
  local secdir
  secdir="$(vfs_pam_secdir)" || return 1
  printf '%s\n' "$secdir/pam_fprintd.${VFS_PAM_MODSUF:-so}"
}

# --- init system -------------------------------------------------------------
vfs_have_systemd() { command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; }

# --- the display manager / greeter that actually exists ----------------------
# Returns the first greeter unit present, so cold-boot ordering targets reality
# instead of assuming Plasma's greeter.
#
# Note: `systemctl list-unit-files <name>` exits 0 even with no match on systemd
# older than v246, so confirm the name appears in the output rather than trusting
# the exit status.
vfs_greeter_unit() {
  local u out
  for u in gdm sddm lightdm plasmalogin lxdm greetd ly xdm; do
    if command -v systemctl >/dev/null 2>&1; then
      out="$(systemctl list-unit-files --no-legend "${u}.service" 2>/dev/null || true)"
      if printf '%s\n' "$out" | grep -q "^${u}\.service"; then
        printf '%s\n' "${u}.service"; return 0
      fi
    fi
    # Filesystem fallback, works regardless of systemd version.
    if [ -e "/usr/lib/systemd/system/${u}.service" ] ||
       [ -e "/etc/systemd/system/${u}.service" ] ||
       [ -e "/lib/systemd/system/${u}.service" ]; then
      printf '%s\n' "${u}.service"; return 0
    fi
  done
  return 1
}
