#!/usr/bin/env bash
# Set up the proprietary-capture path for the VFS491 on Fedora.
#
#   ./proprietary/setup.sh            # fetch + unpack + gate-patch + install
#
# What it does (all under $STAGE unless noted; nothing from HP goes in the repo):
#   1. Download SoftPaq sp84530 (Validity Sensor Setup 4.5-136.0) from HP.
#   2. Unpack the RPM and gate-patch validity-sensor -> validity-sensor-unlocked.
#   3. Install the tool + the harvest/capture/bridge scripts into /usr/libexec/vfs491/.
#   4. Install the systemd units for the bridge and the fprintd virtual_image drop-in.
#
# HP's tool is proprietary and is fetched from HP at run time, never redistributed.
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAGE="${STAGE:-/tmp/opencode/hp}"
LIBEXEC="/usr/libexec/vfs491"
SP_URL="https://ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar"
SP_SHA256="dc9128f965532dd0140d9bcf662ef7a4180ba5fd182c5f8056119c0e967c0364"

say() { printf '\033[1m==> %s\033[0m\n' "$*"; }

mkdir -p "$STAGE"

# ---- 1. download ----------------------------------------------------------
if [[ ! -f "$STAGE/sp84530.tar" ]]; then
  say "downloading sp84530.tar"
  curl -fL -o "$STAGE/sp84530.tar" "$SP_URL"
fi
got="$(sha256sum "$STAGE/sp84530.tar" | awk '{print $1}')"
[[ "$got" == "$SP_SHA256" ]] || { echo "ERROR: sp84530 hash mismatch ($got)" >&2; exit 1; }

# ---- 2. unpack + gate-patch ----------------------------------------------
if [[ ! -x "$STAGE/validity-sensor-unlocked" ]]; then
  say "unpacking RPM"
  mkdir -p "$STAGE/root"
  ( cd "$STAGE" && tar xf sp84530.tar )
  ( cd "$STAGE/root" && rpm2cpio "$STAGE"/SP84530/*.rpm | cpio -idm 2>/dev/null )

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
sudo install -d -m 0755 "$LIBEXEC"
sudo install -m 0755 "$STAGE/validity-sensor-unlocked" "$LIBEXEC/validity-sensor-unlocked"
sudo install -m 0644 "$REPO/proprietary/harvest.py" "$LIBEXEC/harvest.py"
sudo install -m 0755 "$REPO/proprietary/capture.py" "$LIBEXEC/capture.py"
sudo install -m 0755 "$REPO/proprietary/bridge.py"  "$LIBEXEC/bridge.py"

say "installing vfs491-capture wrapper"
sudo install -m 0755 /dev/stdin "$LIBEXEC/vfs491-capture" <<'SH'
#!/usr/bin/env bash
# One swipe -> PGM, via HP's tool under gdb. Root.
export VFS491_TOOL=/usr/libexec/vfs491/validity-sensor-unlocked
export VFS491_HARVEST=/usr/libexec/vfs491/harvest.py
export PATH=/usr/bin:/bin
exec python3 /usr/libexec/vfs491/capture.py "$@"
SH

# ---- 4. systemd units -----------------------------------------------------
say "installing systemd units"
sudo install -d -m 0755 /etc/systemd/system/fprintd.service.d
sudo install -m 0644 /dev/stdin /etc/systemd/system/fprintd.service.d/virtual-image.conf <<'CONF'
[Service]
# Point fprintd at libfprint's virtual_image driver instead of a USB driver.
Environment=FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock
# Log the NBIS match score for every swipe (grep score).
Environment=G_MESSAGES_DEBUG=libfprint-print
RuntimeDirectory=fprint
CONF

sudo install -m 0644 /dev/stdin /etc/systemd/system/vfs491-bridge.service <<'UNIT'
[Unit]
Description=VFS491 fingerprint capture bridge (feeds fprintd's virtual_image)
# Start as soon as the basic system is up so the sensor is ready before any
# login greeter asks for a finger; stop only at shutdown.
After=basic.target
Before=multi-user.target

[Service]
Type=simple
Environment=FP_VIRTUAL_IMAGE=/run/fprint/virtimg_sock
Environment=VFS491_CAPTURE=/usr/libexec/vfs491/capture.py
Environment=VFS491_TOOL=/usr/libexec/vfs491/validity-sensor-unlocked
Environment=VFS491_HARVEST=/usr/libexec/vfs491/harvest.py
ExecStart=/usr/bin/python3 /usr/libexec/vfs491/bridge.py
Restart=always
RestartSec=2

[Install]
WantedBy=multi-user.target
UNIT

# Make the login greeter wait for the bridge, so a tearless cold-boot login can
# offer a finger. plasmalogin is SDDM-derived; extend it rather than edit it.
if systemctl list-unit-files plasmalogin.service >/dev/null 2>&1; then
  say "ordering plasmalogin after vfs491-bridge"
  sudo install -d -m 0755 /etc/systemd/system/plasmalogin.service.d
  sudo install -m 0644 /dev/stdin /etc/systemd/system/plasmalogin.service.d/vfs491.conf <<'DROP'
[Unit]
After=vfs491-bridge.service
Wants=vfs491-bridge.service
DROP
fi

say "reloading systemd"
sudo systemctl daemon-reload

cat <<EOF

Done. Next:
  1. Make the native vfs491 driver NOT grab the USB device (comment out the udev
     rule / blacklist it) so HP's tool gets exclusive access. See docs/capture.md.
  2. sudo systemctl enable --now vfs491-bridge.service
  3. sudo systemctl restart fprintd
  4. Test one capture first:
        sudo /usr/libexec/vfs491/vfs491-capture /tmp/fp.pgm
     (it prints when it is ready ~2 s in; swipe then, slowly and evenly)
  5. Then:  sudo fprintd-enroll    and    sudo fprintd-verify
EOF
