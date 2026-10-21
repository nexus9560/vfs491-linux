#!/usr/bin/env python3
"""Parse a kernel usbmon *text* capture and make it readable.

Companion to capture/usbmon_capture.sh (the no-extra-packages path).
Standard library only -- no pyusb, no wireshark.

One line per URB event, per Documentation/usb/usbmon.rst:

    <tag> <timestamp> <event> <addr> <status...> <len> [<|=. data]

  event    S = submit, C = callback (complete), E = submission error
  addr     <type><dir>:<bus>:<dev>:<ep>   (\"1u\" format, from .../<bus>u)
           <type><dir>:<dev>:<ep>         (\"1t\" format, from .../<bus>t)
           type  B=bulk C=control I=interrupt Z=isochronous, dir i=IN o=OUT
           bus, dev and ep are *decimal*; ep is the bare endpoint number,
           the direction comes from the i/o letter
  '<'      control setup packet follows (8 bytes)
  '='      transfer data follows

Endpoints are normalised internally to the full USB address (0x01, 0x81,
0x82, ...) so they can be matched against EP_NOTE and the sensor's known map.

Two kernel quirks this tool knows about (drivers/usb/mon/mon_text.c):

  * Data words are a byte stream split into groups of up to 4 bytes, e.g.
    \"00001aef 524d6800 0000\" -- not one byte per word.
  * Data is capped at DATA_MAX = 32 bytes per URB:

        \"No, we do not want arbitrarily long data strings.
         Use the binary interface if you want to capture bulk data!\"

    So a text capture is good for framing and small commands, but payloads
    (the sensor's 272-byte scan-line frames, the 38-byte GET_VERSION reply)
    are cut short -- transfers where that happened are marked TRUNCATED.

Data for OUT transfers appears on the S line, data for IN transfers on the
C line; this tool prints whichever carries bytes.

Examples
--------
    python3 capture/usbmon_parse.py captures/probe.txt                 # everything
    python3 capture/usbmon_parse.py --devnum 3 captures/probe.txt       # sensor only
    python3 capture/usbmon_parse.py --devnum 3 --ep 0x81 --hexdump cap.txt
    python3 capture/usbmon_parse.py --devnum 3 --scanlines out.pgm cap.txt

--scanlines reassembles the sensor's *plaintext* scan-line frames (see
docs/protocol.md) from bulk IN data on EP 0x82 into a PGM image.  It needs
full-length frames, so it cannot work from a truncated text capture; it is
useful once data comes from the binary API or from our own client.
"""

from __future__ import annotations

import argparse
import re
import sys

XACT = {"B": "bulk", "C": "control", "I": "interrupt", "Z": "isoch"}

EP_NOTE = {
    0x01: "commands out",
    0x81: "command replies in",
    0x82: "image/scanline in",
    0x83: "interrupt in",
}

STD_REQUEST = {
    0: "GET_STATUS",
    1: "CLEAR_FEATURE",
    3: "SET_FEATURE",
    5: "SET_ADDRESS",
    6: "GET_DESCRIPTOR",
    7: "SET_DESCRIPTOR",
    8: "GET_CONFIGURATION",
    9: "SET_CONFIGURATION",
    10: "GET_INTERFACE",
    11: "SET_INTERFACE",
    12: "SYNCH_FRAME",
}
DESC_TYPE = {1: "DEVICE", 2: "CONFIG", 3: "STRING", 4: "INTERFACE", 5: "ENDPOINT"}

ADDR_1U = re.compile(r"^([BCIZ])([io]):(\d+):(\d+):(\d+)$")
ADDR_1T = re.compile(r"^([BCIZ])([io]):(\d+):(\d+)$")
HEXWORD = re.compile(r"^[0-9a-fA-F]+$")
NUMWORD = re.compile(r"^-?\d+$")
COLONWORD = re.compile(r"^-?\d+(?::-?\d+)+$")

FRAME_LEN = 272  # 1fe marker(2) + line u16(2) + flags(4) + 264 pixels
PIXELS = 264


def hexwords_to_bytes(words):
    """Decode the kernel's grouped data words ('00001aef 42') into bytes."""
    out = bytearray()
    for w in words:
        if len(w) % 2 or not HEXWORD.match(w):
            return None
        out.extend(bytes.fromhex(w))
    return bytes(out)


def decode_setup(words):
    """The setup packet is printed as 5 words: %02x %02x %04x %04x %04x.

    The 16-bit words are little-endian numbers, so rebuild wire order.
    """
    if len(words) < 5:
        return None
    try:
        bm, br = int(words[0], 16), int(words[1], 16)
        wv, wi, wl = int(words[2], 16), int(words[3], 16), int(words[4], 16)
    except ValueError:
        return None
    return bytes(
        [
            bm & 0xFF,
            br & 0xFF,
            wv & 0xFF,
            (wv >> 8) & 0xFF,
            wi & 0xFF,
            (wi >> 8) & 0xFF,
            wl & 0xFF,
            (wl >> 8) & 0xFF,
        ]
    )


def describe_setup(s: bytes) -> str:
    if len(s) < 8 or (s[0] & 0x60) != 0:  # not a standard request
        return ""
    name = STD_REQUEST.get(s[1])
    if not name:
        return ""
    wv = s[2] | (s[3] << 8)
    if s[1] == 6:  # GET_DESCRIPTOR
        return f"{name} {DESC_TYPE.get(wv >> 8, wv >> 8)} index={wv & 0xFF}"
    return name


def parse_line(line: str):
    toks = line.split()
    if len(toks) < 5:
        return None
    tag, _ts, event = toks[0], toks[1], toks[2]
    if event not in ("S", "C", "E"):
        return None

    m = ADDR_1U.match(toks[3])
    if m:
        xfer, direction = m.group(1), m.group(2)
        bus, dev, epnum = int(m.group(3)), int(m.group(4)), int(m.group(5))
    else:
        m = ADDR_1T.match(toks[3])
        if not m:
            return None
        xfer, direction = m.group(1), m.group(2)
        bus, dev, epnum = None, int(m.group(3)), int(m.group(4))

    # bare endpoint number + direction letter -> full USB address
    ep = epnum | (0x80 if direction == "i" else 0)

    rest = toks[4:]

    data = b""
    if "=" in rest:
        i = rest.index("=")
        data = hexwords_to_bytes(rest[i + 1 :]) or b""
        rest = rest[:i]

    setup = b""
    has_setup = False
    if "s" in rest:
        i = rest.index("s")
        setup = decode_setup(rest[i + 1 : i + 6]) or b""
        has_setup = bool(setup)
        if has_setup:
            rest = rest[:i] + rest[i + 6 :]
    elif "__" in rest:
        has_setup = True  # setup present but not captured

    status = None
    nums: list[int] = []
    for t in rest:
        if COLONWORD.match(t):  # interrupt/iso: status:interval[:...]
            parts = [int(x) for x in t.split(":")]
            if status is None:
                status = parts[0]
            continue
        if NUMWORD.match(t):
            nums.append(int(t))

    if not has_setup and status is None and nums:
        status = nums[0]
    length = nums[-1] if nums else None

    return {
        "tag": tag,
        "event": event,
        "xfer": XACT.get(xfer, xfer),
        "dir": direction,
        "bus": bus,
        "dev": dev,
        "ep": ep,
        "epnum": epnum,
        "status": status,
        "len": length,
        "setup": setup,
        "data": data,
    }


def hexdump(data: bytes, prefix: str = "        ") -> str:
    out = []
    for i in range(0, len(data), 16):
        chunk = data[i : i + 16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in chunk)
        out.append(f"{prefix}{i:04x}  {hexs:<47}  |{text}|")
    return "\n".join(out)


def scanlines(blob: bytes, out_path: str) -> None:
    """Reassemble plaintext 272-byte scan-line frames into a PGM (P5)."""
    lines: dict[int, bytes] = {}
    i = 0
    while i + FRAME_LEN <= len(blob):
        if blob[i] == 0x01 and blob[i + 1] == 0xFE:
            line_no = blob[i + 2] | (blob[i + 3] << 8)
            pixels = blob[i + 8 : i + 8 + PIXELS]
            lines[line_no] = pixels
            i += FRAME_LEN
        else:
            i += 1

    if not lines:
        print("scanlines: no plaintext frames found (swipe data is encrypted?)")
        return

    height = max(lines) + 1
    img = bytearray(PIXELS * height)
    for line_no, pixels in lines.items():
        start = line_no * PIXELS
        img[start : start + PIXELS] = pixels

    with open(out_path, "wb") as fh:
        fh.write(b"P5\n%d %d\n255\n" % (PIXELS, height))
        fh.write(bytes(img))

    print(
        f"scanlines: {len(lines)} frame(s), lines {min(lines)}..{max(lines)} "
        f"-> {out_path} ({PIXELS}x{height})"
    )


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("capture", help="usbmon text capture file ('-' for stdin)")
    ap.add_argument("--devnum", type=int, help="only this USB device number")
    ap.add_argument("--bus", type=int, help="only this USB bus (needs the '1u' format)")
    ap.add_argument("--ep", type=lambda s: int(s, 0), action="append", help="only this endpoint (0x81, or 1 for the same endpoint)")
    ap.add_argument("--dir", choices=["i", "o"], help="only IN or OUT")
    ap.add_argument("--hexdump", action="store_true", help="full hexdump of every transfer with data")
    ap.add_argument("--max", type=int, default=64, help="bytes of data to show per transfer (default 64)")
    ap.add_argument("--all", action="store_true", help="show transfers without data too")
    ap.add_argument("--scanlines", metavar="OUT.pgm", help="reassemble plaintext scan lines into a PGM")
    args = ap.parse_args()

    if args.capture == "-":
        stream = sys.stdin
    else:
        stream = open(args.capture, "r", errors="replace")

    shown = 0
    truncated = 0
    blob = bytearray()

    for line in stream:
        rec = parse_line(line)
        if rec is None:
            continue
        if args.devnum is not None and rec["dev"] != args.devnum:
            continue
        if args.bus is not None and rec["bus"] != args.bus:
            continue
        if args.ep and rec["ep"] not in args.ep and rec["epnum"] not in args.ep:
            continue
        if args.dir and rec["dir"] != args.dir:
            continue

        data = rec["data"]
        if rec["ep"] == 0x82 and rec["dir"] == "i" and data:
            blob.extend(data)

        if not data and not rec["setup"] and not args.all:
            continue

        shown += 1
        name = EP_NOTE.get(rec["ep"], "")
        bus_s = f"{rec['bus']:03d}" if rec["bus"] is not None else "???"
        head = (
            f"{rec['event']} {rec['xfer']:<9} {rec['dir']} "
            f"{bus_s}:{rec['dev']:03d}:{rec['ep']:02x} "
            f"st={rec['status']} n={rec['len']} {name}"
        ).rstrip()
        if rec["setup"]:
            note = describe_setup(rec["setup"])
            head += f" setup=[{rec['setup'].hex(' ')}]"
            if note:
                head += f" {note}"
        if rec["len"] is not None and data and rec["len"] > len(data):
            head += f"   TRUNCATED: {len(data)} of {rec['len']} bytes captured"
            truncated += 1
        print(head)

        if data:
            if args.hexdump:
                print(hexdump(data))
            else:
                shown_bytes = data[: args.max]
                suffix = " ..." if len(data) > len(shown_bytes) else ""
                ascii_ = "".join(chr(b) if 0x20 <= b < 0x7F else "." for b in shown_bytes)
                print(f"        data[{len(data)}]: {shown_bytes.hex(' ')}{suffix}")
                print(f"        ascii:        {ascii_}")

    if args.capture != "-":
        stream.close()

    summary = f"{shown} transfer(s) shown"
    if truncated:
        summary += f", {truncated} truncated by the text API (32-byte cap -- use the binary API for payloads)"
    print(f"\n{summary}", file=sys.stderr)

    if args.scanlines:
        scanlines(bytes(blob), args.scanlines)

    return 0


if __name__ == "__main__":
    sys.exit(main())
