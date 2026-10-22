#!/usr/bin/env python3
"""Self-test for the delivery half of proprietary/bridge.py.

No hardware, no root, no fprintd needed.

libfprint's virtual_image driver is picky about how images arrive, and it is
not documented anywhere outside the source:

  * libfprint/drivers/virtual-image.c, recv_image()
        reads an 8-byte header (two little-endian int32: width, height)
  * recv_image_hdr_recv_cb()
        then reads width*height bytes of pixels, and calls recv_image()
        again -- i.e. it expects the *next* image on the same stream
  * libfprint/drivers/virtual-device-listener.c, on_stream_read_cb()
        a header read that hits EOF is turned into
        G_IO_ERROR_INVALID_DATA "Got empty data"

So a bridge that connects, sends one image and closes the socket works, but
makes libfprint log "Error receiving header for image data: Got empty data"
on every single swipe. This test pins the behaviour we want:

  1. two images sent in a row arrive as two images;
  2. the listener never sees a premature EOF (no "Got empty data");
  3. the connection is reused, not re-opened per image;
  4. a stale connection (peer went away) is detected and replaced.

    python3 proprietary/selftest.py
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import tempfile
import threading
import types

HERE = os.path.dirname(os.path.abspath(__file__))
BRIDGE = os.path.join(HERE, "bridge.py")


class FakeListener:
    """Mimics libfprint's virtual_image listener.

    Accepts one client, then reads header+pixels repeatedly on that same
    connection, exactly like recv_image() does. Records every image and
    every EOF it sees.
    """

    def __init__(self, path):
        self.path = path
        self.images = []
        self.eof_seen = False
        self.connections = 0
        self._srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._srv.bind(path)
        self._srv.listen(4)
        self._srv.settimeout(10)
        self._stop = False
        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self._srv.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.connections += 1
            threading.Thread(target=self._session, args=(conn,),
                             daemon=True).start()

    def _session(self, conn):
        try:
            while True:
                hdr = b""
                while len(hdr) < 8:
                    chunk = conn.recv(8 - len(hdr))
                    if not chunk:
                        # EOF: libfprint would report "Got empty data" here.
                        self.eof_seen = True
                        return
                    hdr += chunk
                w, h = struct.unpack("<ii", hdr)
                want = w * h
                data = b""
                while len(data) < want:
                    chunk = conn.recv(min(65536, want - len(data)))
                    if not chunk:
                        self.eof_seen = True
                        return
                    data += chunk
                self.images.append((w, h, data))
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def stop(self):
        self._stop = True
        try:
            self._srv.close()
        except OSError:
            pass


def load_bridge(sock_path):
    """Import bridge.py with the D-Bus bits stubbed out.

    We only exercise deliver(), which does not touch D-Bus, but the module
    imports dbus/gi at the top level.
    """
    class Fake:
        def __getattr__(self, n):
            return Fake()

        def __call__(self, *a, **k):
            return Fake()

    dbus = types.ModuleType("dbus")
    mainloop = types.ModuleType("dbus.mainloop")
    glib = types.ModuleType("dbus.mainloop.glib")
    gi = types.ModuleType("gi")
    gi.__path__ = []
    repository = types.ModuleType("gi.repository")
    repository.GLib = Fake()
    gi.repository = repository
    sys.modules.update({"dbus": dbus, "dbus.mainloop": mainloop,
                        "dbus.mainloop.glib": glib, "gi": gi,
                        "gi.repository": repository})

    os.environ["FP_VIRTUAL_IMAGE"] = sock_path
    os.environ["VFS491_CAPTURE"] = "/nonexistent/capture.py"

    src = open(BRIDGE).read()
    ns = {"__name__": "bridge_under_test"}
    exec(compile(src, BRIDGE, "exec"), ns)
    return ns


def main():
    failures = []

    def check(name, ok, detail=""):
        print("%-4s %s%s" % ("PASS" if ok else "FAIL", name,
                             "" if ok else "  <- " + str(detail)))
        if not ok:
            failures.append(name)

    tmp = tempfile.mkdtemp(prefix="vfs491-selftest-")
    sock_path = os.path.join(tmp, "virtimg_sock")
    ns = load_bridge(sock_path)
    deliver = ns["deliver"]

    # --- 1. two images in a row -------------------------------------------
    listener = FakeListener(sock_path)
    deliver(200, 300, b"\x01" * (200 * 300))
    deliver(200, 300, b"\x02" * (200 * 300))
    listener._thread.join(timeout=5)
    # give the listener a moment to notice EOF if the bridge closed early
    import time
    time.sleep(0.3)

    check("two images arrive as two images", len(listener.images) == 2,
          "got %d" % len(listener.images))
    check("image 1 pixels intact",
          bool(listener.images) and listener.images[0][2][:1] == b"\x01")
    check("image 2 pixels intact",
          len(listener.images) > 1 and listener.images[1][2][:1] == b"\x02")
    check("dimensions are 200x300",
          all(i[0] == 200 and i[1] == 300 for i in listener.images))
    check("no premature EOF (no 'Got empty data')", not listener.eof_seen,
          "listener saw EOF")
    check("connection is reused, not reopened", listener.connections == 1,
          "connections=%d" % listener.connections)

    # --- 2. a stale connection is replaced --------------------------------
    # The peer goes away; the next delivery must reconnect rather than
    # silently write into a dead socket.
    ns["_drop_conn"]()
    old = ns["_conn"]
    check("connection was dropped", old is None)

    deliver(200, 300, b"\x03" * (200 * 300))
    time.sleep(0.3)
    check("delivery after reconnect reaches the listener",
          len(listener.images) == 3, "got %d" % len(listener.images))
    check("reconnect used a new connection", listener.connections == 2,
          "connections=%d" % listener.connections)

    # --- 3. a dead peer is detected, not written to ----------------------
    ns["_drop_conn"]()
    ns["SOCK"] = os.path.join(tmp, "nobody_home")
    ok = True
    try:
        deliver(200, 300, b"\x04" * 10)
    except OSError:
        ok = False
    check("delivery to a dead socket raises OSError", not ok)

    # --- 4. the old behaviour really did cause the warning ---------------
    # Connect, send, close -- what the bridge used to do. libfprint's next
    # header read then hits EOF, which is exactly the "Got empty data"
    # warning we saw on every swipe.
    sock_path2 = os.path.join(tmp, "virtimg_sock2")
    listener3 = FakeListener(sock_path2)
    for payload in (b"\x05" * (200 * 300), b"\x06" * (200 * 300)):
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(sock_path2)
        s.sendall(struct.pack("<ii", 200, 300) + payload)
        s.close()
    time.sleep(0.5)
    check("old connect/send/close behaviour DID cause the EOF",
          listener3.eof_seen, "expected the old code to trip this")
    listener3.stop()

    # --- 5. a fprintd restart drops the connection ------------------------
    # Point the bridge back at a live listener first.
    ns["SOCK"] = sock_path
    ns["_drop_conn"]()
    deliver(200, 300, b"\x07" * (200 * 300))
    time.sleep(0.2)
    check("connection is established again", ns["_conn"] is not None)
    ns["on_name_owner_changed"](ns["BUS_NAME"], ":1.42", "")
    check("fprintd restart drops the stale connection", ns["_conn"] is None)

    listener.stop()

    print()
    if failures:
        print("%d check(s) failed: %s" % (len(failures), ", ".join(failures)))
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
