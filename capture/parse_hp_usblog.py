#!/usr/bin/env python3
"""
parse_hp_usblog.py -- turn a `usblog.so` transfer log into a readable trace.

`usblog.so` (built from reference/nixos-validity-VFS491/research/usblog.c) wraps
libusb and logs every bulk transfer the HP `validity-sensor` binary makes:

    <ts> OUT ep=01 len=693 ret=693 data=0602000001374fc980...
    <ts> IN  ep=01 req=38  ret=38  data=00001aef524d68...
    <ts> IN  ep=02 req=4096 ret=4096 data=45415422...

This tool decodes the VCSFW command layer (see docs/protocol.md) and, for the
0x11 SSL tunnel, the nested SSLv3 records and handshake messages, so a capture
can be read without eyeballing hex.

It embeds no vendor bytes and writes nothing: it is pure analysis, so it is
safe to keep in the repo.  Vendor artefacts never enter the tree.

Usage:
    parse_hp_usblog.py LOG [--hex N] [--full]

    --hex N   show the first N bytes of each undecoded payload (default 24)
    --full    also dump every ep=02 (image/flash) transfer in full length
"""

import argparse
import re
import sys

LINE_RE = re.compile(
    r"\S+\s+(OUT|IN)\s+ep=([0-9a-fA-F]+)\s+(?:len|req)=(\d+)\s+ret=(-?\d+)\s+data=(\S*)"
)

CMDS = {
    0x01: "GET_VERSION",
    0x02: "CAPTURE",           # refused unless an SSL session is active
    0x06: "DOWNLOAD_PATCH",
    0x11: "SSL_TUNNEL",
    0x15: "GET_FP/CFG",
    0x17: "SSL_APPDATA",
    0x19: "GET_START_INFO",
    0x1F: "SPI_READ",
}

# Once the session is up, records travel raw (not wrapped in 0x11), so a
# payload that looks like `14/15/16/17 03 00 <len>` is a TLS record, not a
# VCSFW command whose id happens to collide.
TLS_MAGIC = (0x14, 0x15, 0x16, 0x17)


def looks_like_tls(data):
    return len(data) >= 3 and data[0] in TLS_MAGIC and data[1:3] == b"\x03\x00"

# SSL content types
CT = {0x14: "CCS", 0x15: "Alert", 0x16: "Handshake", 0x17: "AppData"}

# SSLv3/TLS handshake message types
HS = {
    0x00: "HelloRequest", 0x01: "ClientHello", 0x02: "ServerHello",
    0x0B: "Certificate", 0x0C: "ServerKeyExchange", 0x0D: "CertificateRequest",
    0x0E: "ServerHelloDone", 0x0F: "CertificateVerify",
    0x10: "ClientKeyExchange", 0x11: "CertificateVerify?", 0x14: "Finished",
}


def unhex(s):
    s = s.strip()
    if len(s) % 2:
        s = s[:-1]
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def parse_records(blob, indent):
    """Print the SSL records (and their handshake messages) in `blob`."""
    p, out = 0, []
    while p + 5 <= len(blob):
        ct = blob[p]
        ver = blob[p + 1:p + 3].hex()
        rl = int.from_bytes(blob[p + 3:p + 5], "big")
        body = blob[p + 5:p + 5 + rl]
        out.append(f"{indent}record {CT.get(ct, hex(ct))} ver={ver} len={rl}")
        if ct == 0x15 and len(body) == 2:
            out.append(f"{indent}  ALERT level={body[0]} desc=0x{body[1]:02x}")
        if ct == 0x16:
            q = 0
            while q + 4 <= len(body):
                ht = body[q]
                ln = int.from_bytes(body[q + 1:q + 4], "big")
                hb = body[q + 4:q + 4 + ln]
                out.append(f"{indent}  hs {HS.get(ht, hex(ht))} len={ln}"
                           f"  {hb[:12].hex()}")
                q += 4 + ln
        p += 5 + rl
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--hex", type=int, default=24)
    ap.add_argument("--full", action="store_true")
    args = ap.parse_args()

    rows = []
    with open(args.log, "r", errors="replace") as fh:
        for line in fh:
            m = LINE_RE.match(line)
            if not m:
                continue
            rows.append((m.group(1), m.group(2), int(m.group(3)),
                         int(m.group(4)), unhex(m.group(5))))

    n_out = n_in = 0
    summary = {}
    for direction, ep, n, ret, data in rows:
        if direction == "OUT":
            n_out += 1
        else:
            n_in += 1
        if not data:
            print(f"{direction} ep{ep} ({n} bytes)")
            continue
        if ep != "01":
            head = data[:args.hex].hex()
            tail = f"  {head}{'…' if len(data) > args.hex else ''}"
            print(f"{direction} ep{ep} ({ret} bytes){tail}")
            continue

        cmd = data[0]
        if looks_like_tls(data):
            name = f"TLS {CT.get(cmd, hex(cmd))}"
        else:
            name = CMDS.get(cmd, f"0x{cmd:02x}")
        summary[name] = summary.get(name, 0) + 1
        print(f"{direction} {name} ({len(data)} bytes)")

        if cmd == 0x06 and len(data) > 4:
            print(f"    payload {len(data) - 1} bytes: {data[1:1 + args.hex].hex()}…")
        elif cmd == 0x11 and len(data) >= 3:
            tl = int.from_bytes(data[1:3], "little")
            print(f"    tunnel declares {tl} record bytes")
            for ln in parse_records(data[3:3 + tl], "    "):
                print(ln)
        elif looks_like_tls(data):
            for ln in parse_records(data, "    "):
                print(ln)
        elif len(data) > 1:
            print(f"    {data[1:1 + args.hex].hex()}"
                  f"{'…' if len(data) - 1 > args.hex else ''}")

    print(f"\nsummary: {n_out} OUT, {n_in} IN")
    for k in sorted(summary, key=lambda k: -summary[k]):
        print(f"  {summary[k]:3d}  {k}")


if __name__ == "__main__":
    sys.exit(main())
