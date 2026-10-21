"""One swipe on the VFS491 -> PGM (200x300, match quality).

Drives HP's validity-sensor under gdb, which holds the sensor's secure session and
reconstructs the swipe; harvest.py pulls the assembled image out of its memory.
Usage (root): vfs491-capture OUT.pgm      env: VFS_TIMEOUT (s, default 75)
Exit: 0 = image written, 10 = no usable swipe.

Key behaviour: the sensor only starts listening 2-3 s after the tool launches
(patch upload + SSL session + calibration), so swipe AFTER the delay, slowly.
Adapted from saifulmd0/vfs495-linux and mbtech-nl/nixos-validity-VFS491 (MIT).
"""
import os
import struct
import shutil
import subprocess
import sys
import tempfile
import time

TOOL = os.environ.get("VFS491_TOOL")        # gate-patched validity-sensor
HARVEST = os.environ.get("VFS491_HARVEST")  # harvest.py


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: vfs491-capture OUT.pgm")
    for var, val in (("VFS491_TOOL", TOOL), ("VFS491_HARVEST", HARVEST)):
        if not val:
            sys.exit(f"vfs491-capture: {var} is not set "
                     f"(see /usr/libexec/vfs491/vfs491-capture)")
    if not shutil.which("gdb"):
        sys.exit("vfs491-capture: gdb not found. Install it:\n"
                 "  Fedora/RHEL  sudo dnf install gdb\n"
                 "  Debian       sudo apt install gdb\n"
                 "  Arch         sudo pacman -S gdb\n"
                 "  openSUSE     sudo zypper install gdb")
    fd, asm = tempfile.mkstemp(suffix=".bin")
    os.close(fd)
    armed = os.environ.get("VFS_ARMED")
    if armed:
        try:
            os.unlink(armed)
        except OSError:
            pass
    # -nx -batch: skip init files and be non-interactive. debuginfod would
    # otherwise try to fetch debuginfo over the network before running.
    cmd = ["gdb", "-q", "-nx", "-batch",
           "-ex", "set debuginfod enabled off",
           "-x", HARVEST, "--args", TOOL]
    t0 = time.monotonic()
    try:
        subprocess.run(cmd, env={**os.environ, "VFS_ASM_OUT": asm},
                       timeout=int(os.environ.get("VFS_TIMEOUT", "75")),
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except subprocess.TimeoutExpired:
        # pkill is not present everywhere; a missing binary must not mask the
        # real error (the timeout we are handling).
        if shutil.which("pkill"):
            try:
                subprocess.run(["pkill", "-9", "-f", "validity-sensor-unlocked"],
                               stderr=subprocess.DEVNULL)
            except OSError:
                pass
    try:
        d = open(asm, "rb").read()
    finally:
        os.unlink(asm)
    if len(d) < 16:
        print(f"no finger captured (after {time.monotonic()-t0:.1f}s)", file=sys.stderr)
        return 10
    w, h = struct.unpack("<II", d[:8])
    with open(sys.argv[1], "wb") as f:
        f.write(f"P5\n{w} {h}\n255\n".encode() + d[8:8 + w * h])
    print(f"captured {w}x{h} -> {sys.argv[1]} (after {time.monotonic()-t0:.1f}s)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
