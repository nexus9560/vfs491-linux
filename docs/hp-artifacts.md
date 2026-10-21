# HP/Synaptics reference artifacts (research-only, never shipped)

We use HP's own binaries as **measurement instruments** to learn the wire
protocol. Nothing in this file (and nothing the tools emit) is redistributed or
linked into the driver. All artifacts live outside the repo
(`/tmp/opencode/...`, and the pre-existing `~/INF/...`); the repo only contains
our own tools and notes.

## 1. What we have

| Artifact | Where | Notes |
| --- | --- | --- |
| HP SoftPaq **sp84530** (Validity Sensor Setup 4.5-136.0, SLED 11) | fetched to `/tmp/opencode/hp` | `ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar` |
| `usr/sbin/validity-sensor` | inside sp84530 | **ELF x86-64, `with debug_info, not stripped`** |
| `usr/sbin/HPUsbVFS491.img` (315392 B) | inside sp84530 | our sensor's firmware image |
| `usr/sbin/HPUsbVFS495.img` | inside sp84530 | VFS495 equivalent |
| `usr/bin/vcsFPService`, `usr/lib64/libvfsFprintWrapper.so` | inside sp84530 | the proprietary daemon/wrapper (not used) |
| Synaptics/Validity **Windows** driver 4.5.341.0 (x86 + x64) | already on the box at `~/INF/` | includes `wbf_vfs_003d_adv.dll` (our chip!) and `vcsAPIFORWBF.dll` |

### Provenance / hashes

```
sp84530.tar                     dc9128f965532dd0140d9bcf662ef7a4180ba5fd182c5f8056119c0e967c0364
  (matches the hash pinned by mbtech-nl/nixos-validity-VFS491:
   sha256-3JEo+WVTLdAUDZvPZi73pBgLpf0YLF+AVhGcDpZ8A2Q=)
usr/sbin/validity-sensor        089322826391fad7735407c28c986cf016ce5817637589235273ab7bde20d353
usr/sbin/HPUsbVFS491.img        956e15393789e74be459226505044325 (md5)
usr/sbin/HPUsbVFS495.img        cf1eecff82aa690481bdd9a59f4eddef (md5)
```

The `.img` files are **encrypted/compressed** (entropy ~7.997, no strings beyond
a 32-byte `_VEHHPUsbVFS49x.VALIDITY` header) and are not usable directly. The
Windows EFI resource DLL (`ValEFIResDll.dll`) carries larger variants of the
same two images as PE resources (`BIN` resources #200 = 495, #202 = 491); they
are encrypted too.

## 2. The important find: the tool is symbolized

Because `validity-sensor` is not stripped we can read the whole pipeline off the
symbol table instead of reverse-engineering it. The functions that matter:

```
scsFalconDeviceInit              -> the init state machine (calls scsSSLEstablishSession)
scsSSLEstablishSession, scsSSL*  -> the proprietary SSLv3 session (same code as vfs495-linux)
scsSensorSendDownloadPatch_V4    -> builds the 0x06 command
LoadPreSecurityManagementPatch / LoadSecurityManagementPatch
scsSensorLoadPatch / ...LoadPatchEx / scsDownloadRunPatch
scsSensorGetStartInfo            -> the 0x19 command
```

## 3. The 0x06 framing (confirmed from HP's own code)

Disassembly of `scsSensorSendDownloadPatch_V4` shows exactly:

```
movb $0x6,(%rbx)        ; buf[0] = 0x06
memcpy(buf+1, patch, patchlen)     ; patchlen from the chunk descriptor (u16 at +0x22)
scsSend(dev, buf, patchlen+1, 0x22, ...)
```

So: **`0x06 || patchbytes`**, no extra header. (If the sensor were *secured*,
the body is first passed through `scsCreateSignedPatch`; ours is unsecured, so
the raw bytes go on the wire — consistent with the `0x0426` "patch not loaded"
gate we measured on the 0x11 tunnel.)

## 4. The Falcon patch inventory

The blobs are plain C arrays in `.rodata`, indexed by config lists in
`.data.rel.ro`. `tools/hp_extract.py` walks the lists and writes the blobs plus
a manifest (load address, size, sha256). Current output:

```
secMgmtFalconPatchList         8 blobs,   15016 bytes, 8/8 verified
falconPatchConfigList         51 blobs,   99180 bytes, 51/51 verified
falconPrintConfigList         44 blobs,   97296 bytes, 44/44 verified
falconTestPatchConfigList     13 blobs,   22940 bytes, 13/13 verified
falconCalConfigList           36 blobs,    5184 bytes, 0/36 verified   <- different struct layout, ignored
```

"verified" = the descriptor's `data` pointer resolves to a symbol whose size
equals the descriptor's `size` field. The two lists we care about
(`secMgmtFalconPatchList`, `falconPatchConfigList`) are 100% verified, and their
totals match the independent sum of the `flcn_patch*` symbol sizes exactly.

| Descriptor field | Offset |
| --- | --- |
| size (u32) | `+0x44` |
| data pointer (u64) | `+0x48` |
| load address | encoded in the descriptor symbol name, e.g. `flcn_patch2a1e00` -> 0x2a1e00 |

`LoadPreSecurityManagementPatch` and `LoadSecurityManagementPatch` both push the
**security-management set** (`secMgmtFalconPatchList`, load addresses
0x306960..0x3071a0); the full `falconPatchConfigList` is the rest of the
firmware patch set.

## 4b. Ground-truth init + SSL capture (2026-10-16)

We ran HP's (gate-patched) tool against the VFS491 with the `usblog.so`
LD_PRELOAD logger (`capture/hp_init_capture.sh`). `getver` alone is minimal, but
**`getstartinfo -doinit`** and **`getprintwait -doinit`** run the real
`scsFalconDeviceInit` and the whole secure path. The full trace
(`capture/parse_hp_usblog.py /tmp/opencode/vfslog_init.txt`) is:

```
OUT 01                 GET_VERSION                -> IN 38 B
OUT 19                 GET_START_INFO             -> IN 68 B
OUT 06 <692 B>         DOWNLOAD_PATCH  #1         -> IN 0000
OUT 01                 GET_VERSION                -> IN 38 B
OUT 1f <116 B>         SPI/flash read             -> IN 0000 + EP82 128 B
OUT 1f <120 B>         SPI/flash read             -> IN 0000 + EP82 4096 B
OUT 06 <1300 B>        DOWNLOAD_PATCH  #2         -> IN 0000
OUT 01                 GET_VERSION                -> IN 38 B
OUT 11 <60 B record>   SSL ClientHello            -> IN 66 B raw TLS
                                                     (ServerHello + CertificateRequest
                                                      + ServerHelloDone)
OUT 11 <874 B record>  Certificate + ClientKeyExchange + CertificateVerify
                       + CCS + Finished           -> IN 144 B raw TLS (CCS + Finished + AppData)
...                    42 AppData records (capture command + config) ...
                       scan lines / image on EP 0x82
OUT 15                 alert (teardown)           -> IN 15 alert
```

Findings:

* **Patch #1** is **byte-identical to `flcn_patch302810`** (692 B,
  `falconPatchConfigList`) — one blob in the tool's `.rodata`, validating both
  the extractor and the offset mapping.
* **Patch #2** (1300 B) is **not** in the binary and **not** the 8-blob
  security-management set; it is built at runtime (it lands *after* the two `1f`
  reads), so it is sensor-state dependent. We have its bytes from the capture.
* The `0x1f` reads return the sensor's persistent region; the 4096-byte read
  contains the sensor's **RSA-2048 public key at offset `0x5b6`**, which the
  vendor echoes in the handshake `Certificate` message (byte-identical).
* The tunnel opens after patch #2; the handshake completes with **no `0x2f`
  alert** and a fingerprint is captured. See `docs/ssl-notes.md`.

`scsFalconDeviceInit` still has to be traced function-by-function for the exact
meaning of each step, but the wire behaviour above is the ground truth.

Note: the tool calls `usb_reset()` during init, so the sensor **re-enumerates**
(new `/dev/bus/usb/NNN/NNN`, same serial, and the fresh node may not carry the
logind ACL). It is unharmed.

## 5. Safety

HP's tool is a full sensor manager and `scsFalconDeviceInit` contains
`EraseFlash` / `LoadEFIToFlash` / `xvfsStorageOpen` paths. **We do not run it
against the sensor**: those code paths can write the sensor's flash, and the
project's rule is read-only probing. `tools/hp_extract.py` only reads a file.
Never send the permanent commands listed in `docs/protocol.md`.

## 6. Reproduce

```bash
# 1. fetch and unpack HP's tool (never committed)
mkdir -p /tmp/opencode/hp && cd /tmp/opencode/hp
curl -L -O https://ftp.hp.com/pub/softpaq/sp84501-85000/sp84530.tar
tar xf sp84530.tar
mkdir -p root && cd root
rpm2cpio ../SP84530/Validity-Sensor-Setup-4.5-136.0.x86_64.rpm | cpio -idm

# 2. extract the patch blobs (our tool; reads the vendor binary)
#    run from the repo root
python3 tools/hp_extract.py /tmp/opencode/hp/root/usr/sbin/validity-sensor \
        -o /tmp/opencode/hp-patches

# 3. capture the real init sequence off the sensor (research-only; see the
#    script header).  Needs device access, and the tool resets the sensor.
sudo capture/hp_init_capture.sh /tmp/opencode/hp/root getstartinfo -doinit
```

## 7. What this unlocked

The capture closed the two questions that drove it:

1. **Does the tunnel open on the VFS491?** Yes — after both patches (~`0x0426`
   before). The `0x1f` parameters and ordering are now known from the trace.
2. **Does the `0x2f` gate fire here?** No — HP's client completes a full
   mutually-authenticated SSLv3 handshake, and a fingerprint is captured. The
   `0x2f` the open VFS495 client hit is a client omission, not a sensor policy:
   the vendor's flight has a `Certificate` + `0x0f` answering the sensor's
   `CertificateRequest`.
3. **Where does the sensor's RSA public key come from?** From the sensor, over
   the wire: the `0x1f` read returns the persistent region and the key sits at
   offset `0x5b6`; the vendor echoes it in the `Certificate`.

Still open before an open client can be proven end-to-end:

* whether the sensor **verifies** the client `0x0f`/CertificateVerify or merely
  requires the message (the blob does not validate as a signature under the
  sensor key — test with a dummy), and
* where **patch #2** (1300 B) comes from, since it is not in the binary.

Next: build **our own** client (`tools/`) that replays the init (uploading the
patches from user-supplied files), reads the sensor pubkey from the `0x1f`
region, and sends `Certificate + CKE + 0x0f + CCS + Finished` — the decisive
test.
