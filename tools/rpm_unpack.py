#!/usr/bin/env python3
"""Minimal, dependency-free RPM payload unpacker.

Used by proprietary/setup.sh as a fallback when neither `rpm2cpio`+`cpio` nor
`bsdtar` is available, so the vendor path unpacks identically on any distro
(Debian, Arch, ...) with nothing but Python 3.

Scope: it extracts the cpio archive carried in the RPM payload. That is all we
need -- we only want `usr/sbin/validity-sensor` out of HP's RPM. It does NOT
verify signatures, resolve dependencies, or run scriptlets, and it is not a
general replacement for `rpm`. Verify the tarball by SHA-256 upstream instead
(setup.sh does).

Usage: rpm_unpack.py <file.rpm> <destdir>

RPM layout (all big-endian):
    lead        96 bytes, magic ed ab ee db
    signature   header, then padding to an 8-byte boundary
    header      header, then padding to an 8-byte boundary
    payload     compressed cpio (gzip, xz, zstd, or bzip2)

A "header" is: magic 8e ad e8, version, 4 reserved, nindex (u32),
hsize (u32, size of the data store), then nindex 16-byte index entries.
"""

import bz2
import gzip
import io
import lzma
import os
import struct
import sys

HEADER_MAGIC = b"\x8e\xad\xe8"
LEAD_MAGIC = b"\xed\xab\xee\xdb"


class RpmError(Exception):
    pass


def _read_header(buf, off):
    """Return (data_store: bytes, offset_after_padding)."""
    if buf[off:off + 3] != HEADER_MAGIC:
        raise RpmError(f"no RPM header at offset {off}")
    # magic(3) version(1) reserved(4) nindex(4) hsize(4)
    nindex, hsize = struct.unpack(">II", buf[off + 8:off + 16])
    data_start = off + 16 + nindex * 16
    data_end = data_start + hsize
    store = buf[data_start:data_end]
    # headers are padded to an 8-byte boundary
    after = data_end + (-(data_end) % 8)
    return store, after


def _looks_like_magic(b):
    return (b[:2] in (b"\x1f\x8b", b"\xfd7")
            or b[:3] == b"BZh"
            or b[:4] == b"\x28\xb5\x2f\xfd"
            or b[:6] in (b"070701", b"070702")
            or b[:1] == b"\x5d")


def _skip_alignment(payload, limit=16):
    """RPM pads the payload to an 8-byte boundary with 0xff/0x00 filler.

    The alignment is measured from the start of the *file*, so skip any leading
    filler until a recognisable compression magic appears. Bound the scan so a
    truncated/garbage payload can't loop forever.
    """
    for _ in range(limit):
        if _looks_like_magic(payload):
            return payload
        payload = payload[1:]
    return payload



def _try_raw_lzma(payload):
    """Decode containerless LZMA1, trying successive start offsets.

    HP's SoftPaq payload is LZMA1 with no properties byte, and is preceded by
    filler that is not purely 8-byte header padding (observed: 0xff*8 then an
    8-byte value). So rather than guess the exact offset, try decoding from a
    few candidate offsets and accept the first result that is a cpio archive.
    """
    candidates = []
    for lc, lp, pb in ((3, 0, 2), (0, 0, 0), (2, 0, 2), (1, 0, 0)):
        for ds in (1 << 23, 1 << 26, 1 << 22, 1 << 24, 1 << 20):
            candidates.append({"id": lzma.FILTER_LZMA1, "dict_size": ds,
                               "lc": lc, "lp": lp, "pb": pb})
    for start in range(0, min(len(payload), 32)):
        body = payload[start:]
        for filt in candidates:
            try:
                dec = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=[filt])
                out = dec.decompress(body)
            except Exception:
                continue
            if out[:6] in (b"070701", b"070702"):
                return out
    return None


def _decompress(payload):
    """Sniff the compression and decompress."""
    original = payload
    payload = _skip_alignment(payload)
    if payload[:2] == b"\x1f\x8b":
        return gzip.decompress(payload)
    if payload[:6] == b"\xfd7zXZ\x00":
        return lzma.decompress(payload)
    if payload[:3] == b"BZh":
        return bz2.decompress(payload)
    if payload[:4] == b"\x28\xb5\x2f\xfd":       # zstd
        try:
            import zstandard  # optional
        except ImportError:
            raise RpmError(
                "payload is zstd-compressed and the 'zstandard' module is not "
                "installed; use bsdtar or 7z instead"
            )
        return zstandard.ZstdDecompressor().decompress(payload)
    if payload[:6] in (b"070701", b"070702"):
        return payload                          # already cpio (rare)
    if payload[:1] == b"\x5d":                  # raw LZMA with props byte
        try:
            return lzma.decompress(payload, format=lzma.FORMAT_ALONE)
        except lzma.LZMAError:
            pass
    # Last resort: containerless LZMA1 (this is what HP's SoftPaq uses). Try
    # from the original, unskipped payload so our own alignment heuristic can't
    # throw away the real start.
    out = _try_raw_lzma(original)
    if out is not None:
        return out
    raise RpmError(
        "unrecognised payload compression; use bsdtar or 7z to unpack this RPM"
    )


def _parse_cpio(data, destdir):
    """Extract a 'newc' (SVR4) cpio archive. Returns list of written paths."""
    written = []
    off = 0
    n = len(data)
    # newc header: 6-byte magic + 13 x 8-byte hex fields = 110 bytes.
    # fields: ino, mode, uid, gid, nlink, mtime, filesize, devmajor, devminor,
    #         rdevmajor, rdevminor, namesize, check
    HDR = struct.Struct(">6s" + "8s" * 13)
    HDR_LEN = HDR.size
    while off + HDR_LEN <= n:
        magic = data[off:off + 6]
        if magic not in (b"070701", b"070702"):
            break  # trailer / padding
        fields = HDR.unpack(data[off:off + HDR_LEN])
        # fields[0]=magic [1]=ino [2]=mode [3]=uid [4]=gid [5]=nlink
        # [6]=mtime [7]=filesize [8]=devmajor [9]=devminor [10]=rdevmajor
        # [11]=rdevminor [12]=namesize
        mode = int(fields[2], 16)
        filesize = int(fields[7], 16)
        namesize = int(fields[12], 16)
        off += 110
        name = data[off:off + namesize - 1].decode("utf-8", "surrogateescape")
        off += namesize
        off += -off % 4                            # name padded to 4 bytes

        filedata = data[off:off + filesize]
        off += filesize
        off += -off % 4                            # data padded to 4 bytes

        if name == "TRAILER!!!":
            break

        # Sanitise into a path that is guaranteed to stay under destdir.
        # Use realpath/commonpath rather than a string prefix test, which a
        # sibling like "<destdir>_evil/" would otherwise pass.
        dest = os.path.normpath(destdir)
        rel = name.lstrip("/")
        target = os.path.normpath(os.path.join(dest, rel))
        if target != dest and not target.startswith(dest + os.sep):
            raise RpmError(f"refusing path outside destination: {name}")

        # Check symlinks BEFORE regular files: S_IFLNK (0o120000) also has the
        # S_IFREG bit (0o100000) set, so the file branch would swallow them.
        if mode & 0o170000 == 0o040000:            # directory
            os.makedirs(target, exist_ok=True)
        elif mode & 0o170000 == 0o120000:          # symlink
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if os.path.lexists(target):
                os.remove(target)
            os.symlink(filedata.decode("utf-8", "surrogateescape"), target)
        elif mode & 0o170000 == 0o100000:          # regular file
            os.makedirs(os.path.dirname(target), exist_ok=True)
            with open(target, "wb") as f:
                f.write(filedata)
            os.chmod(target, mode & 0o7777)
            written.append(target)
    return written


def unpack(rpm_path, destdir):
    with open(rpm_path, "rb") as f:
        buf = f.read()

    if buf[:4] != LEAD_MAGIC:
        raise RpmError("not an RPM file (bad lead magic)")

    off = 96                                       # skip the lead
    _store, off = _read_header(buf, off)           # signature header
    _store, off = _read_header(buf, off)           # main header

    payload = _decompress(buf[off:])
    return _parse_cpio(payload, destdir)

def main(argv):
    if len(argv) != 3:
        print(__doc__.strip().splitlines()[-1], file=sys.stderr)
        print("usage: rpm_unpack.py <file.rpm> <destdir>", file=sys.stderr)
        return 2
    rpm_path, destdir = argv[1], argv[2]
    os.makedirs(destdir, exist_ok=True)
    try:
        written = unpack(rpm_path, destdir)
    except RpmError as e:
        print(f"rpm_unpack: {e}", file=sys.stderr)
        return 1
    print(f"rpm_unpack: extracted {len(written)} file(s) to {destdir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
