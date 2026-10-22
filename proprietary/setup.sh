#!/usr/bin/env bash
# Set up the proprietary-capture path for the VFS491 (distro-neutral).
#
#   ./proprietary/setup.sh            # fetch + unpack + gate-patch + install
#
# What it does (all under $STAGE unless noted; nothing from HP goes in the repo):
#   1. Download SoftPaq sp84530 (Validity Sensor Setup 4.5-136.0) from HP.
#   2. Unpack the RPM (rpm2cpio+cpio, bsdtar, or a built-in Python reader) and
#      gate-patch validity-sensor -> validity-sensor-unlocked.
#   3. Install the tool + the harvest/capture/bridge scripts into /usr/libexec/vfs491/.
#   4. Install the systemd units for the bridge and the fprintd virtual_image drop-in.
#
# It does not call a package manager. It checks for what it needs and tells you
# exactly what to install if something is missing, so it works on any distro.
#
# HP's tool is proprietary and is fetched from HP at run time, never redistributed.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=proprietary/vfs491-lib.sh
. "$REPO/proprietary/vfs491-lib.sh"

STAGE="${STAGE:-/tmp/opencode/hp}"
LIBEXEC="${LIBEXEC:-/usr/libexec/vfs491}"
SP_URL="https://ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar"
SP_SHA256="dc9128f965532dd0140d9bcf662ef7a4180ba5fd182c5f8056119c0e967c0364"

say() { vfs_say "$@"; }

# ---- 0. preflight ----------------------------------------------------------
# Fail early, with an actionable message, rather than mid-way through.
need() {
  command -v "$1" >/dev/null 2>&1 || vfs_die "missing required tool: $1"
}
need curl
need sha256sum
need tar
need python3
need install

# Unpacking HP's RPM: prefer whatever this distro has.
rpm_unpacker() {
  if command -v rpm2cpio >/dev/null 2>&1 && command -v cpio >/dev/null 2>&1; then
    echo rpm2cpio
  elif command -v bsdtar >/dev/null 2>&1; then
    echo bsdtar
  elif command -v 7z >/dev/null 2>&1; then
    echo 7z
  elif command -v python3 >/dev/null 2>&1; then
    echo python
  else
    echo none
  fi
}

mkdir -p "$STAGE"

# If a gate-patched binary is already installed, reuse it instead of fetching
# HP's SoftPaq again. This makes re-running setup.sh (e.g. to install a fix)
# work offline, and $STAGE normally lives in /tmp, which a reboot wipes.
INSTALLED_TOOL="$LIBEXEC/validity-sensor-unlocked"
REUSE_INSTALLED=no
if [[ ! -x "$STAGE/validity-sensor-unlocked" && -x "$INSTALLED_TOOL" ]]; then
  REUSE_INSTALLED=yes
  say "reusing the already-installed tool ($INSTALLED_TOOL); no download needed"
fi

# ---- 1. download ----------------------------------------------------------
if [[ "$REUSE_INSTALLED" == no ]]; then
  if [[ ! -f "$STAGE/sp84530.tar" ]]; then
    say "downloading sp84530.tar"
    curl -fL -o "$STAGE/sp84530.tar" "$SP_URL"
  fi
  got="$(sha256sum "$STAGE/sp84530.tar" | awk '{print $1}')"
  [[ "$got" == "$SP_SHA256" ]] || { echo "ERROR: sp84530 hash mismatch ($got)" >&2; exit 1; }
fi

# ---- 2. unpack + gate-patch ----------------------------------------------
if [[ ! -x "$STAGE/validity-sensor-unlocked" ]]; then
  say "unpacking RPM"
  rm -rf "$STAGE/root"
  mkdir -p "$STAGE/root"
  ( cd "$STAGE" && tar xf sp84530.tar )

  # HP's tarball contains an SP* directory holding the RPM; don't assume its
  # exact name, just find the one RPM inside.
  rpm="$(find "$STAGE" -maxdepth 2 -name '*.rpm' -print -quit)"
  [ -n "$rpm" ] || vfs_die "no .rpm found inside sp84530.tar"

  case "$(rpm_unpacker)" in
    rpm2cpio) ( cd "$STAGE/root" && rpm2cpio "$rpm" | cpio -idm --quiet ) ;;
    bsdtar)   bsdtar -xf "$rpm" -C "$STAGE/root" ;;
    7z)       ( cd "$STAGE/root" && 7z x -y "$rpm" >/dev/null
                for c in *.cpio; do
                  [ -e "$c" ] || continue
                  7z x -y "$c" >/dev/null || vfs_die "7z failed to unpack $c"
                done ) ;;
    python)   say "unpacking with the built-in Python reader"
              python3 "$REPO/tools/rpm_unpack.py" "$rpm" "$STAGE/root" ;;
    *)        vfs_die "cannot unpack RPM: install one of
                       - rpm2cpio + cpio  (rpm, cpio)
                       - bsdtar           (libarchive / libarchive-tools)
                       - 7z               (p7zip)
                       Python 3 is also enough (no extra packages)" ;;
  esac

  vendorbin="$STAGE/root/usr/sbin/validity-sensor"
  [ -f "$vendorbin" ] || vfs_die "expected $vendorbin after unpacking; HP may have repackaged"

  say "gate-patching validity-sensor"
  python3 - "$STAGE/root/usr/sbin/validity-sensor" "$STAGE/validity-sensor-unlocked" <<'PY'
import struct, sys
d = bytearray(open(sys.argv[1], "rb").read())
off = 0x44122d - 0x400000
assert d[off:off+4] == bytes.fromhex("488b7b08"), "unexpected binary (not sp84530 4.5-136.0?)"
d[off:off+5] = b"\xe9" + struct.pack("<i", 0x4412b4 - (0x44122d + 5))
open(sys.argv[2], "wb").write(bytes(d))
print("  patched: main() gate skipped at VA 0x44122d")
PY
  chmod +x "$STAGE/validity-sensor-unlocked"
fi

# ---- 3. install -----------------------------------------------------------
say "installing to $LIBEXEC (needs root)"
vfs_sudo install -d -m 0755 "$LIBEXEC"
if [[ "$REUSE_INSTALLED" == yes ]]; then
  echo "  (keeping the installed tool as-is)"
else
  vfs_sudo install -m 0755 "$STAGE/validity-sensor-unlocked" "$LIBEXEC/validity-sensor-unlocked"
fi
vfs_sudo install -m 0644 "$REPO/proprietary/harvest.py" "$LIBEXEC/harvest.py"
vfs_sudo install -m 0755 "$REPO/proprietary/capture.py" "$LIBEXEC/capture.py"
vfs_sudo install -m 0755 "$REPO/proprietary/bridge.py"  "$LIBEXEC/bridge.py"
vfs_sudo install -m 0755 "$REPO/proprietary/vfs491-recover" "$LIBEXEC/vfs491-recover"
# The lib is sourced by the recovery script, so it has to be next to it.
vfs_sudo install -m 0644 "$REPO/proprietary/vfs491-lib.sh" "$LIBEXEC/vfs491-lib.sh"

say "installing the udev rule (keeps the sensor out of USB autosuspend)"
vfs_sudo install -d -m 0755 /etc/udev/rules.d
vfs_sudo install -m 0644 "$REPO/proprietary/60-vfs491.rules" /etc/udev/rules.d/60-vfs491.rules
command -v udevadm >/dev/null 2>&1 && {
  vfs_sudo udevadm control --reload || true
  vfs_sudo udevadm trigger --subsystem-match=usb --action=change || true
}

say "installing vfs491-capture wrapper"
vfs_sudo install -m 0755 /dev/stdin "$LIBEXEC/vfs491-capture" <<SH
#!/usr/bin/env bash
# One swipe -> PGM, via HP's tool under gdb. Root.
export VFS491_TOOL=${LIBEXEC}/validity-sensor-unlocked
export VFS491_HARVEST=${LIBEXEC}/harvest.py
exec python3 ${LIBEXEC}/capture.py "\$@"
SH

# ---- 4. systemd units -----------------------------------------------------
if ! vfs_have_systemd; then
  vfs_warn "systemd not detected; skipping unit installation"
  vfs_warn "you will need to run the bridge some other way:"
  vfs_warn "  FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock python3 $LIBEXEC/bridge.py"
  cat <<EOF

Installed the tool and scripts to $LIBEXEC.
Skipped systemd units (no systemd).

Test one capture first (root, swipe when it says 'SWIPE NOW'):
  $LIBEXEC/vfs491-capture /tmp/fp.pgm
EOF
  exit 0
fi

PYTHON="$(command -v python3 || vfs_die 'python3 not found')"

say "checking libfprint provides the virtual_image driver"
# The whole path depends on libfprint honouring FP_VIRTUAL_IMAGE. Verify rather
# than assume, so a wrong libfprint fails loudly here instead of silently later.
# Search multiarch dirs too (Debian uses /usr/lib/<triplet>/).
if ! grep -rqs 'FP_VIRTUAL_IMAGE' /usr/lib*/libfprint-2.so* /usr/lib/*/libfprint-2.so* 2>/dev/null; then
  vfs_warn "this libfprint does not look like it supports FP_VIRTUAL_IMAGE"
  vfs_warn "the bridge will not be able to hand images to fprintd."
  vfs_warn "libfprint >= 1.94.100 with the virtual_image driver is required."
  vfs_warn "continuing anyway; install a suitable libfprint if swipes fail."
fi

say "installing systemd units"
vfs_sudo install -d -m 0755 /etc/systemd/system/fprintd.service.d
vfs_sudo install -m 0644 /dev/stdin /etc/systemd/system/fprintd.service.d/virtual-image.conf <<'CONF'
[Service]
# Point fprintd at libfprint's virtual_image driver instead of a USB driver.
Environment=FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock
# Log the NBIS match score for every swipe (grep score).
Environment=G_MESSAGES_DEBUG=libfprint-print
RuntimeDirectory=fprint
CONF

vfs_sudo install -m 0644 /dev/stdin /etc/systemd/system/vfs491-bridge.service <<UNIT
[Unit]
Description=VFS491 fingerprint capture bridge (feeds fprintd's virtual_image)
# Start as soon as the basic system is up so the sensor is ready before any
# login greeter asks for a finger; stop only at shutdown.
After=basic.target
Before=multi-user.target

[Service]
Type=simple
Environment=FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock
Environment=VFS491_CAPTURE=${LIBEXEC}/capture.py
Environment=VFS491_TOOL=${LIBEXEC}/validity-sensor-unlocked
Environment=VFS491_HARVEST=${LIBEXEC}/harvest.py
Environment=VFS491_RECOVER=${LIBEXEC}/vfs491-recover
# Put the sensor in a known-good state before we serve any request. After a
# cold boot it can be left deauthorized or USB-autosuspended, which truncates
# swipes and eventually wedges the device.
#
# --reset       always re-enumerate the USB device, so every boot starts from a
#               known-clean state (this is what used to be a manual chore).
# --if-present  if the sensor is not plugged in, carry on rather than fail the
#               unit; the bridge will still be ready for it when it appears.
ExecStartPre=${LIBEXEC}/vfs491-recover --reset --if-present
ExecStart=${PYTHON} ${LIBEXEC}/bridge.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

# Make the login greeter wait for the bridge, so a tearless cold-boot login can
# offer a finger. Detect which greeter is actually installed rather than
# assuming Plasma; extend it with a drop-in rather than editing it.
if greeter="$(vfs_greeter_unit)"; then
  say "ordering ${greeter} after vfs491-bridge"
  vfs_sudo install -d -m 0755 "/etc/systemd/system/${greeter}.d"
  vfs_sudo install -m 0644 /dev/stdin "/etc/systemd/system/${greeter}.d/vfs491.conf" <<'DROP'
[Unit]
After=vfs491-bridge.service
Wants=vfs491-bridge.service
DROP
else
  vfs_warn "no known display manager found; cold-boot fingerprint login may race"
  vfs_warn "the bridge will still work once you are logged in"
fi

say "reloading systemd"
vfs_sudo systemctl daemon-reload

cat <<EOF

Done. Next:
  1. If you installed the open native driver, make sure it is NOT grabbing the
     USB device, so HP's tool gets exclusive access: blacklist the module or
     remove the udev rule it installed. (The working path does not need the
     native driver at all -- skip this if you never built it.)
  2. systemctl enable --now vfs491-bridge.service
  3. systemctl restart fprintd
  4. Test one capture first (as root):
        $LIBEXEC/vfs491-capture /tmp/fp.pgm
     (it prints 'SWIPE NOW' when armed ~2 s in; swipe then, slowly and evenly)
  5. Then:  fprintd-enroll "$(vfs_auth_user)"  and  fprintd-verify "$(vfs_auth_user)"
EOF
