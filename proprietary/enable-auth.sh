#!/usr/bin/env bash
# Wire the VFS491 fingerprint reader into authentication, on Fedora.
#
#   ./enable-auth.sh              # enable fingerprint for sudo/polkit/login/lock
#   ./enable-auth.sh --status     # show what is currently wired
#
# This uses authselect so the change is tracked and reversible:
#   sudo authselect disable-feature with-fingerprint     # to undo
#
# What it touches, and why:
#   system-auth  -> sudo, su, login, kscreensaver, kcheckpass (all include it)
#   password-auth + fingerprint-auth -> Plasma's `kde` / `kde-fingerprint`
#   polkit-1     -> falls back to system-auth, so desktop privilege prompts work
#
# Password fallback is always kept. pam_fprintd is `sufficient`: a good swipe
# authenticates, anything else falls through to the password prompt.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

if [[ "${1:-}" == "--status" ]]; then
  say "authselect profile"
  authselect current || true
  echo
  say "pam_fprintd module"
  ls -la /usr/lib64/security/pam_fprintd.so 2>/dev/null || echo "  MISSING (install fprintd-pam)"
  echo
  say "pam_fprintd wiring"
  grep -rl pam_fprintd /etc/authselect/ 2>/dev/null || echo "  (not enabled anywhere)"
  echo
  for f in /etc/authselect/system-auth /etc/authselect/password-auth /etc/authselect/fingerprint-auth; do
    [ -f "$f" ] || continue
    echo "--- $f"
    grep -nE 'fprintd|pam_unix' "$f" || echo "  (no fprintd)"
  done
  exit 0
fi

say "current state"
authselect current

# pam_fprintd.so lives in fprintd-pam; without it, enabling with-fingerprint
# would point PAM at a missing module.
if ! [ -e /usr/lib64/security/pam_fprintd.so ]; then
  say "installing fprintd-pam (provides /usr/lib64/security/pam_fprintd.so)"
  sudo dnf install -y fprintd-pam
fi
[ -e /usr/lib64/security/pam_fprintd.so ] || { echo "ERROR: pam_fprintd.so still missing" >&2; exit 1; }

say "enabling the with-fingerprint feature (covers sudo, su, login, KDE, lock)"
sudo authselect enable-feature with-fingerprint

say "result"
for f in system-auth password-auth fingerprint-auth; do
  echo "--- /etc/authselect/$f"
  grep -nE 'fprintd' "/etc/authselect/$f" || echo "  (no fprintd here)"
done

cat <<'EOF'

Done. Fingerprint is now offered wherever `system-auth` / `password-auth` /
`fingerprint-auth` is used: sudo, su, login, the KDE lock screen, and polkit
prompts. The password prompt is always still available.

Test, easiest first (swipe when the sensor is armed, ~2 s in):
  sudo true
  pkexec true                          # a GUI privilege prompt
  # then log out / lock the screen and try the greeter

Undo:
  sudo authselect disable-feature with-fingerprint

Notes:
- The first swipe of a session can fail; just swipe again. Some fingers scan
  better than others (see ../README.md).
- If the sensor stops opening, re-enumerate it (no reboot):
    sudo sh -c 'echo 0 > /sys/bus/usb/devices/3-1.1/authorized; \
                sleep 2; echo 1 > /sys/bus/usb/devices/3-1.1/authorized'
EOF
