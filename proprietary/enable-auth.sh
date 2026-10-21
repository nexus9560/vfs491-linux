#!/usr/bin/env bash
# Wire the VFS491 fingerprint reader into authentication.
#
#   ./enable-auth.sh              # enable fingerprint for sudo/polkit/login/lock
#   ./enable-auth.sh --status     # show what is currently wired
#   ./enable-auth.sh --undo       # remove the fingerprint wiring
#
# Works across distributions:
#   * Fedora/RHEL: uses `authselect`, so the change is tracked and reversible.
#   * Debian/Arch/everything else: adds `pam_fprintd.so` to the PAM service
#     files directly, keeping a .vfs491-bak copy of each file it touches.
#
# pam_fprintd is `sufficient`: a good swipe authenticates, and anything else
# falls through to the password prompt, which is always kept.
#
# Nothing here is destructive without a backup, and --undo reverses it.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=proprietary/vfs491-lib.sh
. "$REPO/proprietary/vfs491-lib.sh"

PAMDIR=/etc/pam.d
MARK="# vfs491-fingerprint"
FP_LINE="auth        sufficient    pam_fprintd.so"

# PAM service files we wire, and why:
#   system-auth / password-auth  Fedora stacks used by everything below
#   sudo, su, login              direct
#   polkit-1                     GUI privilege prompts (created if absent)
#   kde / kde-fingerprint / kscreensaver / kcheckpass   KDE greeter + lock
#   gdm-fingerprint / gdm-password                       GNOME greeter
#   sddm, lightdm, lxdm, greetd, ly                     other greeters
SERVICES="sudo su login polkit-1 kde kde-fingerprint gdm-fingerprint gdm-password sddm lightdm lxdm greetd ly kscreensaver kcheckpass"

# ---------------------------------------------------------------------------
# --status
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--status" ]; then
  vfs_say "PAM module"
  if mod="$(vfs_pam_module)" && [ -e "$mod" ]; then
    echo "  present: $mod"
  else
    echo "  MISSING: install fprintd-pam (Fedora) / fprintd provides it on"
    echo "           Debian and Arch; check your package name"
  fi
  echo
  vfs_say "fprintd service"
  systemctl is-enabled fprintd >/dev/null 2>&1 && echo "  enabled" || echo "  not enabled"
  systemctl is-active  fprintd >/dev/null 2>&1 && echo "  running" || echo "  not running"
  echo
  vfs_say "wired PAM services"
  if command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1; then
    echo "  authselect profile: $(authselect current 2>/dev/null | head -1)"
    grep -rl pam_fprintd /etc/authselect/ 2>/dev/null | sed 's/^/  /' || echo "  (feature not enabled)"
  fi
  found=0
  for s in $SERVICES; do
    f="$PAMDIR/$s"
    [ -f "$f" ] || continue
    if grep -q pam_fprintd "$f" 2>/dev/null; then
      echo "  $f"; found=1
    fi
  done
  [ "$found" = 1 ] || echo "  (no pam_fprintd in $PAMDIR)"
  exit 0
fi

# ---------------------------------------------------------------------------
# helper: is pam_fprintd present?
# ---------------------------------------------------------------------------
ensure_pam_module() {
  local mod
  if mod="$(vfs_pam_module)" && [ -e "$mod" ]; then
    return 0
  fi
  vfs_err "pam_fprintd.so not found in $(vfs_pam_secdir 2>/dev/null || echo 'any PAM dir')"
  cat >&2 <<'EOF'

Install the PAM module first:
  Fedora/RHEL   sudo dnf install fprintd-pam
  Debian/Ubuntu sudo apt install libpam-fprintd
  Arch          sudo pacman -S fprintd   (ships pam_fprintd.so)
  openSUSE      sudo zypper install fprintd-pam

Then re-run this script.
EOF
  exit 1
}

# ---------------------------------------------------------------------------
# --undo
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--undo" ]; then
  if command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1; then
    vfs_say "disabling the authselect with-fingerprint feature"
    vfs_sudo authselect disable-feature with-fingerprint || true
  fi
  vfs_say "restoring PAM files from backups"
  for s in $SERVICES; do
    f="$PAMDIR/$s"
    if [ -f "$f.vfs491-bak" ]; then
      vfs_sudo cp -L --remove-destination "$f.vfs491-bak" "$f"
      vfs_sudo rm -f "$f.vfs491-bak"
      echo "  restored $f"
    elif grep -q "$MARK" "$f" 2>/dev/null; then
      vfs_say "removing our line from $f (no backup found)"
      vfs_sudo sed -i "/$MARK/d" "$f"
    fi
  done
  # Remove the greeter-ordering drop-in we may have installed.
  if vfs_have_systemd; then
    for g in gdm sddm lightdm plasmalogin lxdm greetd ly xdm; do
      if [ -f "/etc/systemd/system/${g}.service.d/vfs491.conf" ]; then
        vfs_say "removing ${g} ordering drop-in"
        vfs_sudo rm -f "/etc/systemd/system/${g}.service.d/vfs491.conf"
        vfs_sudo rmdir --ignore-fail-on-non-empty "/etc/systemd/system/${g}.service.d" 2>/dev/null || true
      fi
    done
    vfs_sudo systemctl daemon-reload 2>/dev/null || true
  fi
  # If we invented /etc/pam.d/polkit-1, delete it instead of "restoring" our own file.
  if [ -f "$PAMDIR/.polkit-1.vfs491-created" ]; then
    vfs_say "removing $PAMDIR/polkit-1 (this script created it)"
    vfs_sudo rm -f "$PAMDIR/polkit-1" "$PAMDIR/.polkit-1.vfs491-created"
  fi
  vfs_say "done"
  exit 0
fi

# ---------------------------------------------------------------------------
# --reenumerate : clear a wedged sensor without a reboot
# ---------------------------------------------------------------------------
if [ "${1:-}" = "--reenumerate" ]; then
  vfs_reenumerate
  exit 0
fi

# Reject unknown flags rather than silently falling through to "enable".
case "${1:-}" in
  ""|--status|--undo|--reenumerate) : ;;
  -h|--help)
    cat <<EOF
usage: enable-auth.sh [--status | --undo | --reenumerate]

  (no flag)       wire fingerprint into PAM (sudo, polkit, greeter, lock)
  --status        show the PAM module, fprintd and wiring state
  --undo          reverse the wiring and restore PAM backups
  --reenumerate   USB re-enumerate the sensor (recover a wedged reader)

README: ../proprietary/README.md
EOF
    exit 0 ;;
  *) vfs_die "unknown option: $1 (try --help)" ;;
esac

# ---------------------------------------------------------------------------
# enable
# ---------------------------------------------------------------------------
vfs_say "checking the PAM module"
ensure_pam_module

vfs_say "checking the fprintd service"
if ! systemctl is-enabled fprintd >/dev/null 2>&1; then
  vfs_warn "fprintd is not enabled; enabling it"
  vfs_sudo systemctl enable --now fprintd || true
fi

# --- Fedora/RHEL path: authselect is tracked and reversible -------------------
use_authselect=no
if command -v authselect >/dev/null 2>&1 && authselect current >/dev/null 2>&1; then
  profile="$(authselect current 2>/dev/null | awk -F': ' '/Profile ID/{print $2}')"
  if authselect list-features "$profile" 2>/dev/null | grep -q with-fingerprint; then
    vfs_say "authselect detected: enabling with-fingerprint (tracked + reversible)"
    vfs_sudo authselect enable-feature with-fingerprint
    vfs_say "enabled"
    use_authselect=yes
  else
    vfs_warn "profile '$profile' has no 'with-fingerprint' feature; using direct PAM edits"
  fi
fi

# --- generic path: edit PAM service files directly ---------------------------
# Runs on Debian/Arch, and as a fallback on Fedora profiles without the feature.
if [ "$use_authselect" = no ]; then
  vfs_say "wiring PAM service files directly (backups kept as *.vfs491-bak)"

  # polkit-1 may not have a file; create one from the distro default if needed.
  # Mark it so --undo removes it rather than restoring our own creation.
  if [ ! -f "$PAMDIR/polkit-1" ]; then
    vfs_say "creating $PAMDIR/polkit-1 (was absent; polkit used a built-in default)"
    vfs_sudo install -m 0644 /dev/stdin "$PAMDIR/polkit-1" <<'POLKIT'
#%PAM-1.0
auth       include      system-auth
account    include      system-auth
password   include      system-auth
session    include      system-auth
POLKIT
    vfs_sudo install -m 0644 /dev/null "$PAMDIR/.polkit-1.vfs491-created"
  fi

  touched=0
  for s in $SERVICES; do
    f="$PAMDIR/$s"
    [ -f "$f" ] || continue
    if grep -q pam_fprintd "$f" 2>/dev/null; then
      echo "  already wired: $f"
      continue
    fi
    # A symlinked PAM file (e.g. Fedora's authselect-managed ones) points at a
    # shared target that other services also use. Editing through the link would
    # modify that shared file with no symmetric backup, so refuse and say why.
    if [ -L "$f" ]; then
      real="$(vfs_sudo readlink -f "$f" 2>/dev/null || true)"
      vfs_warn "$f is a symlink${real:+ -> $real}; not editing through it"
      vfs_warn "  enable it at the source instead, e.g.:"
      vfs_warn "    sudo authselect enable-feature with-fingerprint"
      continue
    fi
    # back up once (regular file at this point)
    [ -f "$f.vfs491-bak" ] || vfs_sudo cp "$f" "$f.vfs491-bak"
    # Insert our auth line after the first 'auth' line (usually pam_unix/include).
    vfs_sudo python3 - "$f" "$FP_LINE" "$MARK" <<'PY'
import sys, re
path, line, mark = sys.argv[1], sys.argv[2], sys.argv[3]
src = open(path).read().splitlines()
out, inserted = [], False
for ln in src:
    out.append(ln)
    if not inserted and re.match(r'\s*auth\b', ln):
        out.append(line + "    " + mark)
        inserted = True
if not inserted:                      # no auth line: prepend one
    out.insert(0, line + "    " + mark)
open(path, "w").write("\n".join(out) + "\n")
PY
    echo "  wired: $f"
    touched=$((touched + 1))
  done
  [ "$touched" -gt 0 ] && vfs_say "wired $touched PAM service file(s)"
fi

# --- cold-boot ordering: make the greeter wait for the bridge ----------------
if vfs_have_systemd; then
  if greeter="$(vfs_greeter_unit)"; then
    vfs_say "ordering ${greeter} after vfs491-bridge"
    vfs_sudo install -d -m 0755 "/etc/systemd/system/${greeter}.d"
    vfs_sudo install -m 0644 /dev/stdin "/etc/systemd/system/${greeter}.d/vfs491.conf" <<'DROP'
[Unit]
After=vfs491-bridge.service
Wants=vfs491-bridge.service
DROP
    vfs_sudo systemctl daemon-reload
  fi
fi

# --- report ------------------------------------------------------------------
# Show the greeter we found, so the coverage claim matches this machine.
greeter_name="(none detected)"
if vfs_have_systemd; then
  g="$(vfs_greeter_unit 2>/dev/null || true)"; [ -n "$g" ] && greeter_name="$g"
fi

cat <<EOF

Done. Fingerprint is now offered for:
  * sudo, su, login               (${PAMDIR})
  * polkit privilege prompts      (${PAMDIR}/polkit-1)
  * your display manager:         ${greeter_name}
The password prompt is always still available.

Test, easiest first (swipe when the sensor is armed; 'SWIPE NOW' in the bridge log):
  sudo true
  pkexec true                   # a GUI privilege prompt
  # then lock the screen and try there

Undo:
  ./enable-auth.sh --undo       # (or: sudo authselect disable-feature with-fingerprint)

Notes:
  * The first swipe of a session can fail; just swipe again.
  * If the sensor stops opening, re-enumerate it (no reboot):
      $REPO/proprietary/enable-auth.sh --reenumerate
EOF
