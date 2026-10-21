#!/usr/bin/env python3
"""Self-test for capture/usbmon_parse.py -- no hardware, no root needed.

Builds a synthetic usbmon text capture that mirrors the real thing (see
captures/getver.txt from the first live capture): grouped 4-byte data words,
a control setup line, a GET_VERSION exchange, and a reply truncated to 32
bytes the way the kernel does it.  Then runs the parser over it and checks
the decoded output and the reconstructed PGM.

    python3 capture/selftest.py
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PARSER = HERE / "usbmon_parse.py"

GETVER_REPLY = bytes.fromhex(
    "00 00 1a ef 52 4d 68 00 00 00 04 3c 01 03 00 01 0b 00 "
    "00 20 52 04 14 91 01 30 00 00 00 00 01 81 05 fa 00 00 00 12"
)

# the iSerial string descriptor read back in the live capture
STRING_DESC = bytes.fromhex(
    "1a033000 30003200 30003500 32003000 34003100 34003900 3100"
)


def words(data: bytes) -> str:
    """The kernel prints data as groups of up to 4 bytes, space-separated."""
    return " ".join(data[i : i + 4].hex() for i in range(0, len(data), 4))


def frame(line_no: int, first: bool = False) -> bytes:
    flags = b"\x06\x06\x08\x00" if first else b"\x06\x06\x18\x00"
    pixels = bytes((line_no * 100 + i) % 256 for i in range(264))
    return b"\x01\xfe" + line_no.to_bytes(2, "little") + flags + pixels


def build_capture() -> str:
    # Endpoint numbers are DECIMAL and bare; the i/o letter gives the
    # direction.  So 0x01 OUT, 0x81 IN and 0x82 IN are "1", "1" and "2".
    return "\n".join(
        [
            # libusb descriptor reads: setup packet, then a short completion
            "ffff8d18446250c0 30598108 S Ci:2:003:0 s 80 06 0300 0000 0004 4 <",
            "ffff8d18446250c0 30598373 C Ci:2:003:0 0 4 = 04030904",
            "ffff8d18446250c0 30599834 S Ci:2:003:0 s 80 06 0301 0409 00ff 255 <",
            f"ffff8d18446250c0 30599982 C Ci:2:003:0 0 26 = {words(STRING_DESC)}",
            # our probe: GET_VERSION out on 0x01, reply in on 0x81
            "ffff8d18446250c0 30600030 S Bo:2:003:1 -115 1 = 01",
            "ffff8d18446250c0 30600096 C Bo:2:003:1 0 1 >",
            "ffff8d18446250c0 30600113 S Bi:2:003:1 -115 38 <",
            # the kernel caps data at 32 bytes: claim 38, deliver 32
            f"ffff8d18446250c0 30600492 C Bi:2:003:1 0 38 = {words(GETVER_REPLY[:32])}",
            # scan-line frames on 0x82 (full length here so the extractor works;
            # a real text capture would truncate these to 32 bytes as well)
            f"ffff8b0c1d2e3f42 30601000 C Bi:2:003:2 0:272 272 = {words(frame(0, True))}",
            f"ffff8b0c1d2e3f43 30602000 C Bi:2:003:2 0:272 272 = {words(frame(1))}",
            # legacy 1t format line (no bus) for the same device
            "ffff8b0c1d2e3f45 30603000 C Bi:003:1 0:1 1 = 00",
            # noise from another device on the same bus: must be filtered out
            "ffff8b0c1d2e3f44 30604000 S Bo:2:009:2 -115 64 = aa bb cc",
            "",
        ]
    )


def run(capture: Path, *extra: str) -> str:
    proc = subprocess.run(
        [sys.executable, str(PARSER), *extra, str(capture)],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(proc.stdout)
        print(proc.stderr, file=sys.stderr)
        raise SystemExit(f"parser exited {proc.returncode}")
    return proc.stdout


def main() -> int:
    failures = 0

    with tempfile.TemporaryDirectory() as tmp:
        tmpdir = Path(tmp)
        capture = tmpdir / "sample.txt"
        capture.write_text(build_capture())

        out = run(capture, "--devnum", "3")
        checks = [
            ("GET_VERSION reply decoded", "command replies in" in out),
            ("grouped 4-byte words decoded", "data[32]: 00 00 1a ef 52 4d" in out),
            ("status word shown", "st=0 n=38" in out),
            ("OUT command shown", "commands out" in out),
            ("scan-line data shown", "image/scanline in" in out),
            ("32-byte cap detected", "TRUNCATED: 32 of 38 bytes" in out),
            ("control setup decoded", "GET_DESCRIPTOR STRING index=1" in out),
            ("legacy 1t line parsed (no bus)", "???:003:81" in out),
            ("bus noise filtered out", ":009:" not in out),
            ("untruncated transfer not flagged", "TRUNCATED: 26" not in out),
        ]
        for name, ok in checks:
            print(f"{'ok  ' if ok else 'FAIL'}  {name}")
            failures += not ok

        pgm = tmpdir / "out.pgm"
        run(capture, "--devnum", "3", "--scanlines", str(pgm))
        blob = pgm.read_bytes()
        header = b"P5\n264 2\n255\n"
        checks = [
            ("PGM header", blob.startswith(header)),
            ("PGM pixel count", len(blob) == len(header) + 264 * 2),
            ("line 0 pixels", blob[len(header) : len(header) + 3] == bytes([0, 1, 2])),
            ("line 1 pixels", blob[len(header) + 264 : len(header) + 264 + 3] == bytes([100, 101, 102])),
        ]
        for name, ok in checks:
            print(f"{'ok  ' if ok else 'FAIL'}  {name}")
            failures += not ok

    print(f"\n{'all checks passed' if not failures else f'{failures} check(s) failed'}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
