#!/usr/bin/env python3
"""VFS491 bridge (event-driven): stays completely idle until fprintd's device
reports finger-needed=true (a verify or enroll is waiting for a swipe), then runs
ONE capture on the real sensor and delivers the image to libfprint's virtual_image
socket. When fprintd stops needing a finger (timeout, cancel, done) a still-running
capture is cancelled, so the sensor is never held longer than an authentication
actually lasts.

Environment:
  FP_VIRTUAL_IMAGE  socket libfprint listens on (default /run/fprint/virtimg_sock)
  VFS491_CAPTURE    path to capture.py
  VFS_TIMEOUT       optional gdb/harvest timeout in seconds (default 70)
Adapted from saifulmd0/vfs495-linux and mbtech-nl/nixos-validity-VFS491 (MIT).
"""
import os
import shutil
import signal
import socket
import struct
import subprocess
import sys
import threading
import time

# Check our dependencies with a clear message. This runs as a systemd service
# with Restart=always, so a bare ImportError would crash-loop forever with a
# traceback buried in the journal; say exactly what is missing instead.
_missing = []
for _mod, _pkg in (("dbus", "python3-dbus"),
                   ("gi", "python3-gobject")):
    try:
        __import__(_mod)
    except ImportError:
        _missing.append((_mod, _pkg))
if _missing:
    sys.stderr.write(
        "vfs491-bridge: missing Python module(s): "
        + ", ".join(m for m, _ in _missing) + "\n"
        + "Install them, e.g.:\n"
        + "  Fedora/RHEL  sudo dnf install python3-dbus python3-gobject\n"
        + "  Debian       sudo apt install python3-dbus python3-gi\n"
        + "  Arch         sudo pacman -S python-dbus python-gobject\n"
        + "  openSUSE     sudo zypper install python3-dbus-python python3-gobject\n"
    )
    sys.exit(1)

import dbus
import dbus.mainloop.glib
from gi.repository import GLib

SOCK = os.environ.get("FP_VIRTUAL_IMAGE", "/run/fprint/virtimg_sock")
CAPTURE = os.environ.get("VFS491_CAPTURE")
if not CAPTURE:
    sys.stderr.write("vfs491-bridge: VFS491_CAPTURE is not set "
                     "(path to capture.py); see the systemd unit\n")
    sys.exit(1)
MIN_ROWS = 80                                # a real swipe assembles to ~200x300; tiny = no usable print
RUN = "/run/vfs491-fprint"                   # tmpfs, root only; last.pgm = most recent capture (debugging)
BUS_NAME, DEV_IFACE = "net.reactivated.Fprint", "net.reactivated.Fprint.Device"
PROPS = "org.freedesktop.DBus.Properties"
lock = threading.Lock()
state = {"proc": None, "capturing": False, "wanted": False, "gen": 0}


def log(m):
    print("[vfs491-bridge] " + m, file=sys.stderr, flush=True)


def read_pgm(p):
    with open(p, "rb") as f:
        assert f.readline().strip() == b"P5"
        w, h = map(int, f.readline().split())
        f.readline()
        return w, h, f.read(w * h)


def deliver(w, h, data):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect(SOCK)
    s.sendall(struct.pack("<ii", w, h) + data)
    s.close()


def recover_sensor():
    """Re-enumerate the sensor (USB 138a:003d) to clear a wedged/suspended state.

    Returns True if the sensor came back. We look the device up by USB ID, not
    by bus port, so this works on any machine and after any replug.
    """
    script = os.environ.get("VFS491_RECOVER")
    if not script:
        here = os.path.dirname(os.path.abspath(__file__))
        script = os.path.join(here, "vfs491-recover")
    if not os.path.exists(script):
        log(f"recovery script not found at {script}; cannot re-enumerate")
        return False
    try:
        r = subprocess.run([script, "--reset"], timeout=60)
    except subprocess.TimeoutExpired:
        log("recovery timed out")
        return False
    except OSError as e:
        log(f"recovery failed to run: {e}")
        return False
    return r.returncode == 0


def run_capture(out):
    """One capture attempt. Returns True if an image was written to `out`."""
    armed = RUN + "/armed"
    try:
        os.unlink(armed)
    except OSError:
        pass
    # Keep the capture's own output out of the journal on success (gdb is noisy)
    # but retain it in a file so a failure is diagnosable rather than silent.
    cap_log = RUN + "/capture.log"
    try:
        lf = open(cap_log, "wb")
    except OSError:
        lf = subprocess.DEVNULL
    p = subprocess.Popen([sys.executable, CAPTURE, out],
                         env={**os.environ, "VFS_TIMEOUT": "70", "VFS_ARMED": armed},
                         stdout=lf, stderr=lf,
                         start_new_session=True)
    if lf != subprocess.DEVNULL:
        lf.close()
    with lock:
        state["proc"] = p
    # Watch for the armed marker and tell the user exactly when to swipe.
    def watch():
        while p.poll() is None:
            if os.path.exists(armed):
                log("sensor armed -> SWIPE NOW (slowly, full length)")
                return
            time.sleep(0.05)
    threading.Thread(target=watch, daemon=True).start()
    rc = p.wait()
    with lock:
        state["proc"] = None
    return rc == 0


def kill_capture():
    with lock:
        p = state["proc"]
    if p and p.poll() is None:
        try:
            os.killpg(p.pid, signal.SIGTERM)
        except OSError:
            pass
        # Belt-and-braces: sweep any stray tool. pkill is not universal, so a
        # missing binary must not raise here.
        if shutil.which("pkill"):
            try:
                subprocess.run(["pkill", "-9", "-f", "validity-sensor-unlocked"],
                               stderr=subprocess.DEVNULL)
            except OSError:
                pass


def capture_and_deliver(gen):
    os.makedirs(RUN, mode=0o700, exist_ok=True)
    out, last = RUN + "/cap.pgm", RUN + "/last.pgm"
    t0 = time.monotonic()
    try:
        # A single attempt by default. A *blind* retry doubles the wait and
        # hammers the sensor's USB open/close path -- the known cause of its
        # "Open Sensor failed" wedge. But a retry that follows a USB
        # re-enumeration is different: it resets the device state instead of
        # grinding it, so we are allowed exactly one of those.
        ok = run_capture(out)
        if state["gen"] != gen or not state["wanted"]:
            log("capture cancelled (fprintd no longer waiting)")
            return

        if not ok:
            log("capture failed; re-enumerating the sensor and trying once more")
            if not recover_sensor():
                log("recovery failed; swipe again when prompted")
                return
            ok = run_capture(out)
            if state["gen"] != gen or not state["wanted"]:
                log("capture cancelled (fprintd no longer waiting)")
                return
            if not ok:
                log("no usable finger scan (swipe again when prompted)")
                return

        try:
            img = read_pgm(out)
            os.replace(out, last)
        except Exception as e:          # noqa: BLE001 - a malformed image must not kill the service
            log(f"could not read captured image: {e}")
            return
        if img[1] < MIN_ROWS:
            # A truncated image means the sensor was suspended or wedged
            # mid-capture. Re-enumerate and try once; if the swipe itself was
            # just short, the retry will produce a short image again and we
            # report that honestly.
            log(f"sensor returned a tiny scan ({img[0]}x{img[1]}): re-enumerating and retrying once")
            if recover_sensor():
                ok = run_capture(out)
                if ok and state["gen"] == gen and state["wanted"]:
                    try:
                        img = read_pgm(out)
                        os.replace(out, last)
                    except Exception as e:      # noqa: BLE001 - never crash the service
                        log(f"could not read retry image: {e}")
                        img = None
                else:
                    img = None
                if img is None or img[1] < MIN_ROWS:
                    log("still no usable scan: swipe slowly, full length, and try again")
                    return
            else:
                log("recovery failed; swipe again when prompted")
                return

        try:
            deliver(*img)
            log(f"delivered scan {img[0]}x{img[1]} after {time.monotonic()-t0:.1f}s")
        except OSError as e:
            log(f"deliver failed: {e}")
    finally:
        try:
            os.unlink(out)
        except OSError:
            pass
        state["capturing"] = False


def on_needed(reason):
    state["wanted"] = True
    if state["capturing"]:
        return
    state["capturing"] = True
    state["gen"] += 1
    log(f"finger needed ({reason}) -> capturing; swipe now")
    threading.Thread(target=capture_and_deliver, args=(state["gen"],), daemon=True).start()


def on_not_needed():
    if not state["wanted"]:
        return
    state["wanted"] = False
    if state["capturing"]:
        state["gen"] += 1
        kill_capture()


def on_props_changed(iface, changed, invalidated, path=None):
    if iface != DEV_IFACE or "finger-needed" not in changed:
        return
    if bool(changed["finger-needed"]):
        on_needed("finger-needed")
    else:
        on_not_needed()


def on_verify_selected(*args, path=None):
    on_needed("verify started")


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()
    bus.add_signal_receiver(on_props_changed, signal_name="PropertiesChanged",
                            dbus_interface=PROPS, bus_name=BUS_NAME, path_keyword="path")
    bus.add_signal_receiver(on_verify_selected, signal_name="VerifyFingerSelected",
                            dbus_interface=DEV_IFACE, bus_name=BUS_NAME, path_keyword="path")

    def check_initial():                                # a scan already pending at startup?
        try:
            mgr = dbus.Interface(bus.get_object(BUS_NAME, "/net/reactivated/Fprint/Manager"),
                                 "net.reactivated.Fprint.Manager")
            for dev in mgr.GetDevices():
                p = dbus.Interface(bus.get_object(BUS_NAME, dev), PROPS)
                if bool(p.Get(DEV_IFACE, "finger-needed")):
                    on_needed("pending at startup")
        except dbus.DBusException:
            pass
        return False

    GLib.timeout_add(1500, check_initial)
    log("idle; waiting for fprintd to need a finger")
    GLib.MainLoop().run()


if __name__ == "__main__":
    main()
