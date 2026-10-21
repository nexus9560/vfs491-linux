#!/usr/bin/env python3
"""Extract the Falcon sensor patch blobs from HP's `validity-sensor` binary.

The VFS491 (and VFS495) sensor boots from ROM and needs firmware "patches"
uploaded into its RAM before it will open a secure session.  HP's Linux tool
sends those blobs as VCSFW command 0x06 (`0x06 || patchbytes`); the blobs are
plain C arrays embedded in the tool binary, which ships *with symbols and DWARF*
in SoftPaq sp84530 (`usr/sbin/validity-sensor`).

This script reads that binary and writes the blobs out, plus a manifest
(load address, size, sha256).  It embeds **no vendor bytes** -- you point it at
the binary you have locally, and nothing it writes belongs in git.

Usage:
    tools/hp_extract.py usr/sbin/validity-sensor -o /tmp/opencode/hp-patches

Why this is safe: it only *reads* a file.  It never talks to the sensor, and
nothing it does can write sensor flash or OTP.

Provenance of the binary this was developed against (SoftPaq sp84530):
    tar sha256  dc9128f965532dd0140d9bcf662ef7a4180ba5fd182c5f8056119c0e967c0364
    validity-sensor is ELF x86-64, "with debug_info, not stripped"
"""

import argparse
import hashlib
import json
import os
import struct
import sys


# --- minimal ELF64 reader (no pyelftools needed) -----------------------------

class Elf:
    def __init__(self, data):
        if data[:4] != b"\x7fELF" or data[4] != 2:
            raise ValueError("not an ELF64 file")
        (self.e_shoff,) = struct.unpack_from("<Q", data, 0x28)
        (self.e_shentsize,) = struct.unpack_from("<H", data, 0x3A)
        (self.e_shnum,) = struct.unpack_from("<H", data, 0x3C)
        (self.e_shstrndx,) = struct.unpack_from("<H", data, 0x3E)
        self.data = data
        self.sections = []
        for i in range(self.e_shnum):
            o = self.e_shoff + i * self.e_shentsize
            name, stype, flags, addr, off, size, link, info, align, entsize = \
                struct.unpack_from("<IIQQQQIIQQ", data, o)
            self.sections.append(dict(name_off=name, type=stype, addr=addr,
                                      off=off, size=size, link=link,
                                      entsize=entsize, index=i))
        shstr = self.sections[self.e_shstrndx]
        for s in self.sections:
            s["name"] = self._cstr(shstr["off"] + s["name_off"])

    def _cstr(self, off):
        end = self.data.index(b"\0", off)
        return self.data[off:end].decode("latin1")

    def vaddr_to_off(self, v):
        for s in self.sections:
            if s["addr"] <= v < s["addr"] + s["size"] and s["type"] != 8:
                return s["off"] + (v - s["addr"])
        return None

    def read(self, v, n):
        o = self.vaddr_to_off(v)
        if o is None:
            return None
        return self.data[o:o + n]

    def symbols(self):
        symtab = next((s for s in self.sections if s["name"] == ".symtab"), None)
        strtab = next((s for s in self.sections if s["name"] == ".strtab"), None)
        if not symtab or not strtab:
            return {}
        out = {}
        n = symtab["size"] // 24
        for i in range(n):
            o = symtab["off"] + i * 24
            name, info, other, shndx, value, size = \
                struct.unpack_from("<IBBHQQ", self.data, o)
            if name == 0:
                continue
            nm = self._cstr(strtab["off"] + name)
            out.setdefault(value, (nm, size, shndx))
        return out


# --- patch-list walking ------------------------------------------------------

# Each entry in a `*PatchConfigList` is a pointer to a descriptor struct whose
# u32 size lives at +0x44 and whose data pointer lives at +0x48.  The symbol
# name of the descriptor encodes the sensor load address (e.g. flcn_patch2a1e00
# -> 0x2a1e00).  Both offsets were verified against a live disassembly
# (scsSensorSendDownloadPatch_V4) and cross-checked against the symbol sizes.

DESC_SIZE_OFF = 0x44
DESC_DATA_OFF = 0x48

LISTS = [
    "secMgmtFalconPatchList",   # security-management set (uploaded at init)
    "falconPatchConfigList",    # full firmware patch set
    "falconPrintConfigList",    # capture (get-print) patches
    "falconCalConfigList",      # calibration patches
    "falconTestPatchConfigList",
]


def walk_list(elf, by_name, list_name, outdir, manifest):
    entry = by_name.get(list_name)
    if entry is None:
        return 0
    list_addr, list_size, _ = entry
    base_off = elf.vaddr_to_off(list_addr)
    if base_off is None:
        return 0
    # follow up to the list's byte size worth of 8-byte pointers
    count = list_size // 8 if list_size else 4096
    written = 0
    for i in range(count):
        (ptr,) = struct.unpack_from("<Q", elf.data, base_off + i * 8)
        if ptr == 0:
            break
        desc = elf.read(ptr, 0x60)
        if desc is None or len(desc) < 0x58:
            break
        blob_size = struct.unpack_from("<I", desc, DESC_SIZE_OFF)[0]
        data_ptr = struct.unpack_from("<Q", desc, DESC_DATA_OFF)[0]
        dsym = syms_by_value.get(ptr, ("?@%#x" % ptr, 0, 0))[0]
        blob = elf.read(data_ptr, blob_size)
        if blob is None or len(blob) != blob_size:
            print(f"  !! {dsym}: could not read {blob_size} bytes "
                  f"from {data_ptr:#x}", file=sys.stderr)
            continue
        # A descriptor is "verified" when its data pointer resolves to a symbol
        # whose recorded size matches the descriptor's size field.  The two
        # patch lists pass this test for every entry; the cal/print lists use a
        # different descriptor layout and largely fail it.
        tent = syms_by_value.get(data_ptr)
        verified = bool(tent and tent[1] == blob_size)
        load = 0
        if dsym.startswith("flcn_patch"):
            try:
                load = int(dsym[len("flcn_patch"):], 16)
            except ValueError:
                pass
        d = os.path.join(outdir, list_name)
        os.makedirs(d, exist_ok=True)
        path = os.path.join(d, dsym + ".bin")
        with open(path, "wb") as fh:
            fh.write(blob)
        manifest.append(dict(list=list_name, symbol=dsym, load_addr=load,
                             load_addr_hex="%#x" % load, size=blob_size,
                             verified=verified,
                             sha256=hashlib.sha256(blob).hexdigest(),
                             file=os.path.relpath(path, outdir)))
        written += 1
    return written


syms_by_value = {}


def main():
    global syms_by_value
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("binary", help="path to HP's usr/sbin/validity-sensor")
    ap.add_argument("-o", "--outdir", default="/tmp/opencode/hp-patches")
    args = ap.parse_args()

    data = open(args.binary, "rb").read()
    elf = Elf(data)
    raw_syms = elf.symbols()
    syms_by_value = raw_syms
    by_name = {nm: (v, sz, sh) for v, (nm, sz, sh) in raw_syms.items()}

    print(f"binary : {args.binary}")
    print(f"sha256 : {hashlib.sha256(data).hexdigest()}")
    print(f"symbols: {len(raw_syms)}")
    print(f"outdir : {args.outdir}\n")

    manifest = []
    total = 0
    for lst in LISTS:
        if lst not in by_name:
            continue
        n = walk_list(elf, by_name, lst, args.outdir, manifest)
        entries = [m for m in manifest if m["list"] == lst]
        sz = sum(m["size"] for m in entries)
        v = sum(1 for m in entries if m["verified"])
        total += sz
        print(f"{lst:28s} {n:3d} blobs, {sz:7d} bytes, {v}/{n} verified")

    mpath = os.path.join(args.outdir, "manifest.json")
    os.makedirs(args.outdir, exist_ok=True)
    with open(mpath, "w") as fh:
        json.dump(dict(binary_sha256=hashlib.sha256(data).hexdigest(),
                       blobs=manifest), fh, indent=2)
    print(f"\ntotal {len(manifest)} blobs, {total} bytes")
    print(f"manifest: {mpath}")
    print("\nNOTE: these blobs are HP's proprietary firmware.  Do not commit "
          "them; the repo .gitignore keeps /tmp and captures/ out of git.")


if __name__ == "__main__":
    main()
