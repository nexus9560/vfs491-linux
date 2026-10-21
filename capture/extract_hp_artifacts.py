#!/usr/bin/env python3
"""
extract_hp_artifacts.py -- regenerate the client's research inputs from a
`usblog.so` trace of HP's `validity-sensor` (research-only measurement run).

`parse_hp_usblog.py` only *prints* a trace; this tool writes the handful of
files `tools/vfs491_ssl.c` and `tools/vfs491_session.c` consume.  They live
outside the repo (`/tmp/opencode/patches`, wiped on reboot because /tmp is
tmpfs); this makes them reproducible from a capture.

It embeds **no vendor bytes**: you point it at a log you produced locally, and
the files it writes are HP's, so they must never enter git.

What it writes to --outdir:

    patch1.bin                 first  0x06 DOWNLOAD_PATCH payload (692 B)
    patch2.bin                 second 0x06 DOWNLOAD_PATCH payload (1300 B)
    cap_spi1.bin               first  EP 0x82 read (the 128-byte one)
    flash_11_4096.bin          second EP 0x82 read (the 4096-byte region)
    sensor_pubkey.bin          flash_11_4096.bin[0x5b6:0x6b6] (RSA-2048 modulus)
    vendor_clienthello_rec.bin the 0x11 tunneled ClientHello *record*
    vendor_clientflight.bin    the 0x11 tunneled client flight (Cert..Finished)
    vendor_serverflight_full.bin the ServerHello flight record
    vendor_server_final.bin    the server's CCS+Finished(+AppData) reply
    vendor_cert_hs.bin         handshake 0x0b Certificate      (with 4-B hdr)
    vendor_cke_hs.bin          handshake 0x10 ClientKeyExchange (with 4-B hdr)
    vendor_cv_hs.bin           handshake 0x0f CertificateVerify (with 4-B hdr)
    cert_key.bin               flash_11_4096.bin[0x5b6:0x6b6] (client cert modulus)
    cke_key.bin                flash_11_4096.bin[0x6b6:0x7b6] (server CKE modulus)
    slot0d_ct.bin              flash_11_4096.bin[0x100:0x100+1184] (encrypted client key)
    slot0d_plain.bin           slot 0x0d decrypted (needs --sensor-bin, see below)

`slot0d_plain.bin` requires `--sensor-bin PATH` (your copy of the vendor
`validity-sensor`): its storage blob is AES-256-CBC under a 32-byte constant
that the binary assembles at the top of `scsDecryptWithGSKGlobal`.  This tool
recovers that constant from the binary and decrypts the blob; the constant is
never written into the repo.

Usage:
    extract_hp_artifacts.py LOG --outdir /tmp/opencode/patches
    extract_hp_artifacts.py LOG --outdir /tmp/opencode/patches --sensor-bin validity-sensor
"""

import argparse
import hashlib
import os
import re
import sys
import zlib

LINE_RE = re.compile(
    r"\S+\s+(OUT|IN)\s+ep=([0-9a-fA-F]+)\s+(?:len|req)=(\d+)\s+ret=(-?\d+)\s+data=(\S*)"
)

# The sensor's RSA-2048 modulus sits here in the 4096-byte 0x1f read.
PUBKEY_OFF = 0x5B6
PUBKEY_LEN = 256

# Storage-table entries inside the 4096-byte 0x1f read (offset = flash - 0x1000).
CERT_OFF, CERT_LEN = 0x5B6, 256          # DataID 0x0c: client cert modulus
CKE_OFF, CKE_LEN = 0x6B6, 256            # DataID 0x0a: server CKE modulus
SLOT0D_OFF, SLOT0D_LEN = 0x100, 1206     # DataID 0x0d: client private-key blob
SLOT0D_HDR = 22                          # version(1) + 0(1) + CRC32(4) + IV(16)

HS = {0x01: "clienthello", 0x02: "serverhello", 0x0B: "cert",
      0x0C: "serverkeyexchange", 0x0D: "certreq", 0x0E: "serverhellodone",
      0x0F: "cv", 0x10: "cke", 0x14: "finished"}


def unhex(s):
    s = s.strip()
    if len(s) % 2:
        s = s[:-1]
    try:
        return bytes.fromhex(s)
    except ValueError:
        return b""


def records(blob):
    """Yield (content_type, body) for each TLS record in `blob`."""
    p = 0
    while p + 5 <= len(blob):
        ct = blob[p]
        rl = int.from_bytes(blob[p + 3:p + 5], "big")
        yield ct, blob[p + 5:p + 5 + rl]
        p += 5 + rl


def handshakes(body):
    """Yield (type, full_message_with_4B_header) for a handshake record body."""
    q = 0
    while q + 4 <= len(body):
        ht = body[q]
        ln = int.from_bytes(body[q + 1:q + 4], "big")
        msg = body[q:q + 4 + ln]
        yield ht, msg
        q += 4 + ln


def extract_gsk_key(binpath):
    """Recover the 32-byte GSKGlobal constant from a vendor `validity-sensor`.

    `scsDecryptWithGSKGlobal` builds it as 32 consecutive
        c6 44 24 <disp> <imm>        ; movb $imm, <disp>(%rsp)
    with <disp> counting up by one.  Returns the 32 bytes, or None."""
    b = open(binpath, "rb").read()
    i = 0
    while True:
        j = b.find(b"\xc6\x44\x24", i)
        if j < 0:
            return None
        d0 = b[j + 3]
        run, k, ok = [], j, True
        for n in range(32):
            if (k + 5 > len(b) or b[k:k + 3] != b"\xc6\x44\x24"
                    or b[k + 3] != (d0 + n) & 0xFF):
                ok = False
                break
            run.append(b[k + 4])
            k += 5
        if ok:
            return bytes(run)
        i = j + 1


def decrypt_slot0d(blob, gsk):
    """Decrypt a storage-slot blob with the GSKGlobal key via `openssl enc`.

    Layout: [0]=version [1]=0 [2..5]=CRC32(zlib) of (IV||ct) [6..21]=IV [22..]=ct.
    Returns the plaintext bytes, or None."""
    import struct
    import subprocess
    import tempfile

    ver = blob[0]
    crc = struct.unpack("<I", blob[2:6])[0]
    iv, ct = blob[6:22], blob[22:]
    if ver < 2:
        print(f"  !! slot0x0d: unexpected version {ver}", file=sys.stderr)
    if zlib.crc32(iv + ct) & 0xFFFFFFFF != crc:
        print("  !! slot0x0d: CRC32 mismatch (key/blob wrong)", file=sys.stderr)
    with tempfile.NamedTemporaryFile(delete=False) as fc:
        fc.write(ct)
        ctp = fc.name
    try:
        out = subprocess.run(
            ["openssl", "enc", "-aes-256-cbc", "-d", "-nopad",
             "-K", gsk.hex(), "-iv", iv.hex(), "-in", ctp],
            capture_output=True, check=True)
        return out.stdout
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"  !! slot0x0d: openssl decrypt failed ({e})", file=sys.stderr)
        return None
    finally:
        os.unlink(ctp)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("log")
    ap.add_argument("-o", "--outdir", default="/tmp/opencode/patches")
    ap.add_argument("--sensor-bin", metavar="PATH", default=None,
                    help="your copy of the vendor validity-sensor binary; lets "
                         "this tool recover the GSKGlobal key and decrypt the "
                         "DataID 0x0d client private-key blob")
    args = ap.parse_args()

    rows = []
    with open(args.log, "r", errors="replace") as fh:
        for line in fh:
            m = LINE_RE.match(line)
            if not m:
                continue
            rows.append((m.group(1), m.group(2), int(m.group(3)),
                         int(m.group(4)), unhex(m.group(5))))

    os.makedirs(args.outdir, exist_ok=True)
    written = []

    def save(name, blob):
        if not blob:
            print(f"  !! {name}: empty, skipped", file=sys.stderr)
            return None
        path = os.path.join(args.outdir, name)
        with open(path, "wb") as fh:
            fh.write(blob)
        written.append((name, len(blob), hashlib.sha256(blob).hexdigest()))
        return blob

    # --- command-layer artefacts ------------------------------------------
    patches = [d[1:] for (dr, ep, n, ret, d) in rows
               if dr == "OUT" and ep == "01" and d[:1] == b"\x06"]
    # patch #1 is 692 B, patch #2 is 1300 B (see docs/hp-artifacts.md)
    p1 = next((b for b in patches if len(b) == 692), patches[0] if patches else b"")
    p2 = next((b for b in patches if len(b) == 1300),
              patches[1] if len(patches) > 1 else b"")
    save("patch1.bin", p1)
    save("patch2.bin", p2)

    # 0x1f flash reads come back on EP 0x82: 128 B then 4096 B
    ep2 = [d for (dr, ep, n, ret, d) in rows if dr == "IN" and ep == "02" and d]
    small = next((b for b in ep2 if len(b) == 128), None)
    big = next((b for b in ep2 if len(b) == 4096), None)
    if small:
        save("cap_spi1.bin", small)
    if big:
        save("flash_11_4096.bin", big)
        if len(big) >= PUBKEY_OFF + PUBKEY_LEN:
            save("sensor_pubkey.bin", big[PUBKEY_OFF:PUBKEY_OFF + PUBKEY_LEN])
        else:
            print(f"  !! 4096 read too short for pubkey at 0x{PUBKEY_OFF:x}",
                  file=sys.stderr)
        # DataID 0x0c (client cert) and 0x0a (server CKE) moduli
        if len(big) >= CKE_OFF + CKE_LEN:
            save("cert_key.bin", big[CERT_OFF:CERT_OFF + CERT_LEN])
            save("cke_key.bin", big[CKE_OFF:CKE_OFF + CKE_LEN])
        # DataID 0x0d: encrypted client private key
        if len(big) >= SLOT0D_OFF + SLOT0D_LEN:
            blob = big[SLOT0D_OFF:SLOT0D_OFF + SLOT0D_LEN]
            save("slot0d_ct.bin", blob[SLOT0D_HDR:])
            if args.sensor_bin:
                gsk = extract_gsk_key(args.sensor_bin)
                if not gsk:
                    print("  !! could not recover the GSKGlobal key from "
                          f"{args.sensor_bin}", file=sys.stderr)
                else:
                    plain = decrypt_slot0d(blob, gsk)
                    if plain:
                        save("slot0d_plain.bin", plain)
                        print(f"  slot0x0d: decrypted {len(plain)} B "
                              "(client RSA-2048 private key)")
            else:
                print("  (pass --sensor-bin to decrypt slot0d_plain.bin)")
    else:
        print("  !! no 4096-byte EP 0x82 read found; pubkey NOT written",
              file=sys.stderr)

    # --- 0x11 SSL tunnels -------------------------------------------------
    tunnels = [d for (dr, ep, n, ret, d) in rows
               if dr == "OUT" and ep == "01" and d[:1] == b"\x11"]
    for t in tunnels:
        if len(t) < 3:
            continue
        tl = int.from_bytes(t[1:3], "little")
        blob = t[3:3 + tl]
        recs = list(records(blob))
        # ClientHello flight: a single handshake record starting 0x01
        if len(recs) == 1 and recs[0][0] == 0x16 and recs[0][1][:1] == b"\x01":
            save("vendor_clienthello_rec.bin", blob)
            print("  clienthello record:", len(blob), "bytes")
        # client flight: has a CCS (0x14) after the handshake record
        elif any(ct == 0x14 for ct, _ in recs):
            save("vendor_clientflight.bin", blob)
            print("  client flight:", len(blob), "bytes,",
                  "records:", [hex(ct) for ct, _ in recs])
            for ct, body in recs:
                if ct != 0x16:
                    continue
                for ht, msg in handshakes(body):
                    nm = HS.get(ht)
                    if nm:
                        save(f"vendor_{nm}_hs.bin", msg)

    # --- server flight (IN on 0x01 that is a raw TLS handshake record) -----
    for dr, ep, n, ret, d in rows:
        if dr != "IN" or ep != "01" or not d:
            continue
        if d[0] == 0x16 and d[1:3] == b"\x03\x00":
            recs = list(records(d))
            if any(body[:1] == b"\x02" for ct, body in recs if ct == 0x16):
                save("vendor_serverflight_full.bin", d)
                print("  server flight:", len(d), "bytes")
                for ct, body in recs:
                    if ct != 0x16:
                        continue
                    for ht, msg in handshakes(body):
                        nm = HS.get(ht)
                        if nm:
                            save(f"vendor_{nm}_hs.bin", msg)
            elif any(ct in (0x14, 0x17) for ct, _ in recs):
                save("vendor_server_final.bin", d)
                print("  server final (CCS/Finished/AppData):", len(d), "bytes")

    # Cross-check the offset: the Certificate echoed in the flight carries the
    # same modulus at body offset 18 (4-byte handshake header + 14-byte key
    # header).  If these disagree, PUBKEY_OFF is wrong for this firmware.
    pk = os.path.join(args.outdir, "sensor_pubkey.bin")
    ce = os.path.join(args.outdir, "vendor_cert_hs.bin")
    if os.path.exists(pk) and os.path.exists(ce):
        pub = open(pk, "rb").read()
        cert = open(ce, "rb").read()
        if len(cert) >= 18 + PUBKEY_LEN:
            print("\npubkey check:",
                  "OK (matches the flight Certificate)"
                  if cert[18:18 + PUBKEY_LEN] == pub else
                  "MISMATCH vs flight Certificate -- check PUBKEY_OFF!")

    print(f"\nwrote {len(written)} files to {args.outdir}")
    for name, n, h in written:
        print(f"  {name:28s} {n:6d} B  sha256 {h[:16]}…")


if __name__ == "__main__":
    sys.exit(main())
