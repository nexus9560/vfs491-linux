# VFS491 protocol notes

Living document. Everything under **Known** is either measured on this machine,
read out of the USB descriptor, or taken from prior art that is cited inline.
Everything under **Unknown** is what still blocks a native driver.

## Safety

The sensor has a command set that includes permanent, irreversible operations.
**Never send** `provision`, `write_otp`, `spiflashwrite`, `setowner`,
`resetowner`, `makeprod`, `serialize`, `set_prod_opts`. They write to OTP
memory / flash / ownership state. Patches sent with the download-patch command
only land in sensor RAM and are gone after a power cycle, so experimenting with
those is safe.

## Device facts (measured here, 2026-10-16)

From the USB descriptor (`/sys/bus/usb/devices/2-1.1/descriptors`):

| Field | Value |
| --- | --- |
| idVendor:idProduct | `138a:003d` |
| bcdUSB | `0x0110` |
| bcdDevice | `0x0104` |
| bDeviceClass / SubClass / Protocol | `0xff` / `0x11` / `0xff` (vendor specific) |
| bMaxPacketSize0 | 8 |
| iSerial (index 1) | `002052041491` |
| iManufacturer / iProduct | 0 / 0 (no strings) |
| Configurations | 1 (value 1, bmAttributes `0xa0`, 100 mA) |
| Interfaces | 1 (number 0, class `0xff`, subclass `0x00`, protocol `0x00`, 4 endpoints) |

Endpoint map:

| Endpoint | Type | Direction | Max packet | Role |
| --- | --- | --- | --- | --- |
| `0x01` | bulk | OUT | 64 | commands, host -> sensor |
| `0x81` | bulk | IN | 64 | command replies |
| `0x82` | bulk | IN | 64 | image / scan-line data |
| `0x83` | interrupt | IN | 8 | finger / status events |

Sensor identity, read with GET_VERSION (see below) and confirmed on this
machine: firmware 4.60 build 104, "Falcon ROM", product 3 `Falconusb`,
siliconrev 0, formalrel 1, platform `0x0b`, build time `0x4d52ef1a`. Matches the
documented VFS495 (`138a:003f`) values.

## Command layer

Model: a command is one bulk transfer to EP `0x01`; the reply arrives on EP
`0x81` (commands) or EP `0x82` (bulk data such as images). Replies start with a
16-bit little-endian status; `0x0000` means success.

### `0x01` GET_VERSION

Host sends one byte `01`. Reply is up to 38 bytes on EP `0x81`. Layout
(from `vfs495-linux` / `nixos-validity-VFS491` `research/vcsfw_getver.py`):

| Offset | Size | Meaning |
| --- | --- | --- |
| 0 | 2 | status, u16 LE |
| 2 | 4 | build time, u32 LE |
| 6 | 4 | build number, u32 LE |
| 10 | 1 | version major |
| 11 | 1 | version minor |
| 12 | 1 | target (1 ROM, 2 FPGA, 3 RTLSIM, 4 ISS, 5 FPGADBG) |
| 13 | 1 | product (1 Falcon, 2 Raptor, 3 Falconusb, 4 Falconspi, 5 Raptorusb, 6 Raptorspi) |
| 14 | 1 | silicon revision |
| 15 | 1 | formal release |
| 16 | 1 | platform id |
| 17 | 1 | patch flag |
| 18 | 6 | device serial, raw bytes -- equals the iSerial string (`002052041491` -> `00 20 52 04 14 91`) |
| 24 | 2 | security bytes (VFS491 `01 30`, VFS495 `01 7d`) |
| 26 | 4 | patch signature, u32 LE |
| 30 | 1 | interface id |
| 31 | 7 | trailing bytes -- **unknown** (the reply is 38 bytes; prior-art parsers read only 31) |

Implement in `tools/vfs491_probe.c` (`make run`). Measured on this machine,
2026-10-16 (status `0x0000`, 38 bytes on `0x81`):

```
0000  00 00 1a ef 52 4d 68 00  00 00 04 3c 01 03 00 01  |....RMh....<....|
0010  0b 00 00 20 52 04 14 91  01 30 00 00 00 00 01 81  |... R....0......|
0020  05 fa 00 00 00 12                                 |......|
```

* version 4.60, build 104, build time `0x4d52ef1a`
* target 1 (ROM), product 3 (Falconusb)
* siliconrev 0, formalrel 1, platform `0x0b`
* bytes 18-23 = `00 20 52 04 14 91` = the serial (`iSerial` is `002052041491`)
* security bytes `01 30`, matching the documented VFS491 value
* patch signature `0x00000000` and patch flag 0 -> no patch loaded at power-on
* **measured (ground-truth capture):** the patch flag at offset 17 and the patch
  signature at offsets 26-29 are a clean progress indicator -- `0x00`/`0x00000000`
  before any patch, still `0x00` after patch #1 (692 B), then **`0x07`/`0x11`**
  once patch #2 (1300 B) lands. The tunnel opens on that transition.
* trailing bytes 31-37 = `81 05 fa 00 00 00 12` -> **unknown**, worth decoding
* framing confirmed independently in an usbmon capture of our own probe
  (`captures/getver.txt`, see `docs/capture.md`)

### Command overview

| Command | Direction | State | Notes |
| --- | --- | --- | --- |
| `0x01` GET_VERSION | out | measured | see above |
| `0x19` GET_START_INFO | out | measured | 68-byte reply, see below |
| `0x11` SSL tunnel | out | measured | refused until the RAM patches are loaded, see below |
| `0x06` DOWNLOAD_PATCH | out | prior art | two uploads, 693 B then a 1301 B "security management" patch; sensor RAM only |
| `0x1f` (SPI/flash read) | out | measured | reads the sensor's persistent region; the reply comes on EP `0x82` (128 B, then a 4096-byte read that contains the sensor RSA-2048 public key at offset `0x5b6`) |
| `0x02` GET_CONFIGURATION | out | prior art | plaintext is refused with status `0x0404` on the VFS495 -- the capture path must be inside the session |
| `0x04`/`0x05`/`0x07`/`0x08`/`0x0b`/`0x0c`/`0x0d`/`0x13`/`0x15`/`0x17`/`0x1a`-`0x1e`/`0x24`/`0x26`/`0x27`/`0x29` | out | prior art | full VCSFW list in `reference/vfs495-linux/docs/FINDINGS.md` |

### `0x19` GET_START_INFO (measured 2026-10-16)

Reply is 68 bytes, status `0x0000`. Stable reply (identical over repeated calls):

```
0000  00 00 00 03 04 00 40 0c  00 00 00 00 00 00 00 00  |......@.........|
0010  00 00 00 00 6d de 34 f5  00 00 00 00 00 00 00 00  |....m.4.........|
0020  00 00 00 00 b7 41 87 d8  00 00 00 00 00 00 00 00  |.....A..........|
0030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
0040  a8 a7 4b 21                                       |..K!|
```

* bytes 0-1 = status `0x0000`; `03` at offset 3 is the boot/reset **type**
  (prior art: their vendor-tool sessions read type 2 = WOE / 0 = POWERON, and a
  mismatch here is a known wire-visible difference between tool and open client;
  ours reads type 3).
* fixed-looking fields: `6d de 34 f5` (0x14), `b7 41 87 d8` (0x24),
  `a8 a7 4b 21` (0x40) -- per-boot identifiers or signatures.
* **Not fully deterministic.** The *first* call after the sensor had been idle
  (our very first `0x19` ever) returned non-zero data through 0x10-0x3f, e.g.
  `... 6d de 34 f5 f2 f0 f8 be f7 59 96 17 9d cc fd 99 b7 41 87 d8 ba 30 ff cc ...`;
  every later call zeroes those positions. The fields at 0x14, 0x24 and 0x40
  were identical in both. So part of this reply is state/RAM residue rather than
  fixed data -- worth a clean re-plug baseline before drawing conclusions.
* This may feed the session's pairing check, so it is worth characterising.

### `0x11` SSL tunnel (measured 2026-10-16)

Framing is `11 <u16 LE record length> <TLS record>`, exactly as the VFS495 spec.
Sending a correct, self-built ClientHello gets a **2-byte reply `26 04` = status
`0x0426`** and no TLS record.

`tools/vfs491_session.c gate` sends four different `0x11` payloads (none, zero
length, a truncated record, garbage) and gets **the same `0x0426` every time**,
so the sensor refuses at the command layer and never parses the record: it is a
**state gate**, not a content check.

**Confirmed by ground-truth capture (`docs/ssl-notes.md`):** with HP's two RAM
patches loaded, that same tunnel opens -- status `0x0000` -- and the sensor
answers a tunnelled ClientHello with a **raw, un-tunnelled TLS record** on EP
`0x81` (`ServerHello + CertificateRequest + ServerHelloDone`). The `0x0426` was
purely "patches not loaded":

```
01 GET_VERSION -> 19 GET_START_INFO -> 06 DOWNLOAD_PATCH(692 B = flcn_patch302810)
 -> 01 -> 1f (116 B) -> 1f (120 B) -> 06 DOWNLOAD_PATCH(1300 B, runtime-built)
 -> 01 (patch bits set) -> 0x11 tunnel -> SSLv3 handshake
```

The tunnel only opens once those two patches are in sensor RAM, and they come
from HP's proprietary tool. See `docs/ssl-notes.md`.

## Scan-line frame format (plaintext)

Seen in calibration data and in plaintext image dumps. 272 bytes per frame:

| Bytes | Content |
| --- | --- |
| 0-1 | `01 fe` marker |
| 2-3 | line number, u16 LE |
| 4-7 | `06 06 18 00` (first line: `06 06 08 00`) |
| 8-271 | 264 pixels, 1 byte each |

`capture/usbmon_parse.py --scanlines out.pgm` reassembles these from EP `0x82`
data. A real finger swipe arrives **encrypted**, so it will not parse into an
image until the session layer is understood.

## Session / encryption layer

The sensor runs an **SSLv3** session wrapped in command `0x11`. Cipher suites
`0x42`-`0x44` are AES-128/192/256-CBC-SHA1. Swipe data (~1.08 MB on EP `0x82`)
is encrypted under the session keys; calibration data beforehand is plaintext.
The full reversed spec (records, KDF, RSA, Finished, and the quirks) is distilled
in [`docs/ssl-notes.md`](ssl-notes.md).

What we measured here (2026-10-16):

* the tunnel command `0x11` exists and is framed exactly as the VFS495 spec says
  (`11 <u16 LE len> <record>`), but
* it is **refused with a constant status `0x0426`** in our un-patched state,
  whatever we send (`tools/vfs491_session.c gate`) -- a state gate at the command
  layer, so the TLS layer is never reached.

**Both blockers now have measurements (2026-10-16):**

1. **Getting into the tunnel.** The init needs two `0x06` DOWNLOAD_PATCH uploads
   (692 B and 1300 B), interleaved with two `0x1f` reads. They come from HP's
   proprietary tool. Ground-truth capture confirms the tunnel opens after
   patch #2 (`0x0426` before).
2. **The `0x2f` pairing gate.** `vfs495-linux` reimplemented the whole handshake,
   validated every primitive byte-exact, and their VFS495 sensor still rejected
   the assembled flight with a firmware alert `0x2f`. But the **VFS491 does not
   fire it for HP's own client** -- the captured vendor session completes the
   handshake and captures a fingerprint. The vendor flight carries a
   `Certificate` + a `0x0f` message answering the sensor's `CertificateRequest`,
   which the open spec's flight (`CKE + CCS + Finished`) omitted. That omission
   is the leading explanation for `0x2f`. See `docs/ssl-notes.md`.

## Reconstruction (after decryption)

Turning decrypted scan lines into an image is HP's `IR*` pipeline: motion
estimation between lines plus analog reconstruction. Reference symbol names
(from the VFS495/VFS491 work):

`irDliRTFalconData`, `IRprocessScanline`, `IR_addScanlinesToPool`,
`IRcorrelate*`, `IRreconstructImage`, `IRanalogReconScanline`,
`IRhandleInvertAndFlip`, `IRConstrastEnhanceImage{Rows,Cols}`,
`IRqualityDetermination`, `irDliGetImage`.

`vfs495-linux` has a Python `reconstruct.py` that is the starting point for our
own implementation.

## Unknowns / open questions

- [ ] exact `0x06`/`0x1f` reply semantics; the meaning of the `0x19` state bytes
- [x] does the sensor open the `0x11` tunnel without HP's RAM patches? -- no (`0x0426`); **yes** with both patches loaded (capture, 2026-10-16)
- [x] does the sensor accept a host-built SSLv3 session (the `0x2f` gate)? -- the vendor's session completes with **no** `0x2f`; the `0x0f` message is the open client's missing piece (see `docs/ssl-notes.md`)
- [ ] does the sensor *verify* the client `0x0f`/CertificateVerify, or only require the message to exist? -- decidable with our own client
- [ ] where patch #2 (1300 B) comes from -- runtime-assembled; origin unknown
- [ ] what do the security bytes `01 30` encode, and does the sensor check them?
- [ ] what exactly does the sensor send after decryption (line batching, ordering)?
- [x] do bytes 18-23 of the GET_VERSION reply matter? -- no, they are the serial
- [ ] what are the trailing bytes 31-37 (`81 05 fa 00 00 00 12`)?
- [ ] interrupt EP `0x83`: what events does it carry, and when?

## Experiment plan (ordered, cheapest first)

1. **Reach the SSL session.** *Done (knowledge).* The command layer is byte
   compatible and the full vendor session is captured: unlock sequence, both
   patches, ServerHello flight (with CertificateRequest), and the client flight
   (Certificate + CKE + `0x0f` + CCS + Finished). **Next:** build our own client
   that replays the init and sends that flight, and check whether the sensor
   accepts a dummy `0x0f` (no `0x2f`) -- this is the decisive test.
2. **Take the session keys from a reference implementation once**, to learn what
   the decrypted stream looks like. (Requires running vendor software as a
   measuring instrument; a decision to make deliberately, see README.)
3. **Open reconstruction**: port `reconstruct.py` / reimplement the `IR*` steps.
4. **Reverse the handshake check** statically if (1) fails.

## Log

| Date | What | Result |
| --- | --- | --- |
| 2026-10-16 | proprietary HP stack removed, stock libfprint restored | clean baseline, `fprintd-list` = "No devices available" |
| 2026-10-16 | `tools/vfs491_probe.c` written (GET_VERSION only) | builds clean, no warnings |
| 2026-10-16 | GET_VERSION on the real sensor (no sudo needed) | status 0, 38 bytes; version 4.60 build 104; security `01 30`; bytes 18-23 = serial; bytes 31-37 unknown |
| 2026-10-16 | first usbmon capture of our own probe (`captures/getver.txt`) | framing confirmed: 1-byte OUT `01` on `0x01`, 38-byte IN on `0x81` status 0, first 32 bytes identical to the probe; text API caps data at 32 B (`DATA_MAX`) |
| 2026-10-16 | descriptor dump (see above) | endpoints match prior art |
| 2026-10-16 | `tools/vfs491_session.c`: GET_VERSION + GET_START_INFO + self-built SSLv3 ClientHello | `0x19` works (68 B, status 0); tunnel `0x11` refused |
| 2026-10-16 | characterised the `0x11` refusal with four payloads (`... gate`) | constant status `0x0426` -- state gate, the record is never parsed |
| 2026-10-16 | compared with `vfs495-linux` / `nixos-validity-VFS491` | command layer byte-compatible; tunnel needs HP's RAM patches; VFS495's validated host session is blocked by firmware alert `0x2f` |
| 2026-10-16 | repeated `0x19` calls | stable, but the first (cold) call differed at 0x10-0x3f -> part of the reply is RAM/state residue; re-plug baseline still to do |
| 2026-10-16 | obtained HP SoftPaq sp84530; read HP's symbolized `validity-sensor` | `0x06` framing is `0x06 || patchbytes`; init uploads secMgmt patch set (8 blobs) + full patch set (51 blobs); see `docs/hp-artifacts.md` |
| 2026-10-16 | **full vendor init captured** (`getprintwait -doinit` under `usblog.so`) | tunnel opens after patch #2; handshake completes with **no `0x2f`**; server flight has CertificateRequest; client flight adds Certificate + `0x0f`; fingerprint captured on EP `0x82`. See `docs/ssl-notes.md` |
| 2026-10-16 | decoded the capture (`capture/parse_hp_usblog.py`) | patch #1 = `flcn_patch302810` (692 B); patch #2 (1300 B) runtime-built; sensor RSA-2048 pubkey readable from the `0x1f` region at `0x5b6` and echoed in the client Certificate; the `0x0f` blob is **not** a valid RSA signature under that key |

## References

* `saifulmd0/vfs495-linux` (MIT) -- protocol docs, SSL PoC, `reconstruct.py`,
  scaffolded libfprint driver. The deepest prior work.
* `mbtech-nl/nixos-validity-VFS491` (MIT) -- VFS491-specific facts, comparison
  table, research tooling. Both are cloned under `reference/`.
* `nmikhailov/Validity90`, `uunicorn/python-validity` -- 138a:0090/0094/0097
  family, *different* protocol generation; useful only as background.
* Upstream libfprint: no driver for `138a:003d`; the in-flight Validity/Synaptics
  work (MR 626) covers `138a:0090/0097/009d/00ab` and `06cb:*`, not this chip.
