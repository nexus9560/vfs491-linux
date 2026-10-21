# fingerprint-sensor

Open-source support for the **Validity VFS491** fingerprint sensor
(USB **`138a:003d`**), developed on an HP EliteBook 8770w running Fedora 44 but
written to be distro-neutral: nothing in the shipped path assumes a particular
distribution, package manager, username, or desktop. The driver is open source
and contains no vendor code; HP's RAM patches are loaded at runtime from files
the user supplies and are never committed here.

> **Attribution:** This project was directed by **Nex**. The majority of the implementation, refactoring, debugging, and hardening was performed by an AI agent, with direction and testing done by Nex. See [`Agent.md`](Agent.md) for a breakdown of the approach taken.

Status: **working on hardware.** Two paths are documented here.

* **Working path (in use):** HP's proprietary tool handles the sensor's secure
  session + capture + reconstruction, and an open, event-driven bridge feeds the
  finished image to stock libfprint's `virtual_image` driver. `fprintd-enroll`
  completes and `fprintd-verify` returns **`verify-match`** (scores 175/40 and
  55/40 against a threshold of 40). See [`proprietary/`](proprietary/README.md).

* **Open driver (protocol proven):** the native libfprint driver in
  `driver/vfs491.c` opens the sensor, uploads HP's RAM patches, completes the
  SSLv3 session, and arms/reads capture. It is kept as the research path toward
  a fully open driver; an audit showed the EP `0x82` swipe stream is
  AES-encrypted and needs HP's `IR*` reconstruction, which is why the working
  path delegates capture to the vendor tool.

The vendor patch blobs are **not** part of this repo: they are loaded at
runtime from `/usr/libexec/vfs491/` (override with `FP_VFS491_DIR`). See
`docs/protocol.md` and `docs/ssl-notes.md`.

## Get it working (working path)

On this machine the sensor already works end to end. Clone the repo anywhere
and run everything below from its root:

```bash
./proprietary/setup.sh                              # fetch + patch + install (needs root)
sudo systemctl enable --now vfs491-bridge.service
sudo systemctl restart fprintd

sudo fprintd-enroll "${SUDO_USER:-$USER}"            # swipe when the sensor is armed (~2 s)
sudo fprintd-verify "${SUDO_USER:-$USER}"            # -> verify-match
journalctl -u fprintd | grep score                  # e.g. "score 175/40" (>=40 = match)
journalctl -u vfs491-bridge -f                      # prints "SWIPE NOW" when armed
```

Works on any distro: `setup.sh` does not call a package manager, checks for the
tools it needs, and unpacks HP's RPM with whichever of `rpm2cpio`+`cpio`,
`bsdtar`, `7z`, or a built-in Python reader is available. The only hard
requirement is Python 3 and systemd.

See [`proprietary/README.md`](proprietary/README.md) for the architecture,
timing, and recovery from a wedged sensor.

## Use it for authentication (sudo, polkit, login, lock screen)

```bash
./proprietary/enable-auth.sh              # wire fingerprint into PAM
./proprietary/enable-auth.sh --status     # show what is wired
./proprietary/enable-auth.sh --undo       # reverse it
```

Cross-distro: on Fedora/RHEL it uses `authselect` (tracked and reversible); on
Debian, Arch and everywhere else it edits the PAM service files directly,
keeping a `*.vfs491-bak` backup of each file it touches. It detects your actual
display manager (gdm, sddm, lightdm, plasmalogin, ...) for cold-boot ordering
instead of assuming one, and prints the package name of the PAM module if it is
missing.

Fingerprint is offered for `sudo`, `su`, `login`, the greeter, the lock screen,
and polkit prompts. `pam_fprintd` is `sufficient`, so the password prompt always
remains as a fallback. Details in [`proprietary/README.md`](proprietary/README.md).

## Why it has to be written from scratch

The only libfprint integrations that support `138a:003d`
(`rindeal/libfprint-vfs_proprietary-driver`, `ludwhe/libfprint`,
`eekpie/libfprint`, `rmackinnon/libfprint_vfs4xx_support`) all wrap HP's
proprietary `vcsFPService`. `uunicorn/python-validity` does not support it, and
upstream libfprint's new Validity/Synaptics work (MR 626) covers
`138a:0090/0097/009d/00ab` and `06cb:*`, not this chip. So this is a
reverse-engineering project with a clear, documented starting point.

## Layout

```
build/                   local build state: libfprint tarball/source + meson build (not committed)
build-libfprint.sh       build libfprint 1.94.100 with integrated vfs491 driver
cleanup-proprietary.sh   removes old proprietary stack (done 2026-10-16)
driver/vfs491.c          libfprint driver for Validity VFS491 (open-source)
driver/vfs491_descramble.inc  column descramble table for VFS491
libfprint-1.94.100-vfs491.patch  full patch to integrate into libfprint 1.94.100
Makefile                 builds the USB tools below
tools/vfs491_probe.c     libusb probe: descriptors + GET_VERSION (read-only)
tools/vfs491_session.c   command set + SSLv3 ClientHello and unlock
tools/vfs491_ssl.c       full open SSLv3 client: handshake completion
tools/hp_extract.py      extract Falcon patch blobs from HP's symbolized tool
tools/standalone/        offline harnesses for testing driver logic
capture/usbmon_capture.sh  usbmon capture (text API or tshark pcap)
capture/usbmon_parse.py    stdlib parser + scan-line PGM extractor
capture/selftest.py        hardware-free self-test for the parser
capture/hp_init_capture.sh research-only: run HP tool under usblog
capture/parse_hp_usblog.py decode a usblog trace (VCSFW command + SSL layers)
docs/protocol.md         wire protocol details
docs/ssl-notes.md        SSLv3 session layer (handshake, CV, keys)
docs/hp-artifacts.md     HP/Synaptics reference binaries
docs/capture.md          capture methodology
proprietary/             WORKING PATH: HP capture + open bridge (see its README)
reference/               prior art, cloned on demand (not committed)
captures/                capture output (not committed)
```

## Build

> **A fresh clone cannot run this yet.** `build/libfprint.tgz` is git-ignored
> (it is a 1 MB upstream tarball, not our code), so you have to supply it once
> yourself before `./build-libfprint.sh` will work:
>
> ```bash
> mkdir -p build
> curl -fL -o build/libfprint.tgz \
>   https://gitlab.freedesktop.org/libfprint/libfprint/-/archive/v1.94.100/libfprint-v1.94.100.tar.gz
> # (or point at any 1.94.100 source tarball you already have)
> ```
>
> This only affects the **research path** below. The working capture path in
> [`proprietary/`](proprietary/README.md) does not need libfprint built, and
> needs nothing from `build/`.

Everything else lives under this repository. The first run unpacks the tarball
into `build/libfprint-v1.94.100/`, applies `libfprint-1.94.100-vfs491.patch`,
and configures `build/lfp-full-build/`:

```bash
./build-libfprint.sh
# -> build/lfp-full-build/libfprint/libfprint-2.so.2.0.0
```

The library keeps the stock SONAME/version (`libfprint-2.so.2.0.0`,
libfprint 1.94.100), so it can replace Fedora's copy and work with the stock
`fprintd`:

```bash
# run as root yourself
install -m 755 build/lfp-full-build/libfprint/libfprint-2.so.2.0.0 \
        /usr/lib64/libfprint-2.so.2.0.0
ldconfig
```

Set `BUILD_DIR=...` to use a different build directory, or `DRIVERS=...` to
change the driver set (default: `default,vfs491`).

Original machine baseline (before the driver): stock Fedora `libfprint`
1.94.100 and `fprintd` 1.94.5, both pristine per `rpm -V`; no
`/usr/lib64/vfs491`; `fprintd-list` said *No devices available* because no
open driver claimed the sensor.

## Try what exists today

```bash
make run
```

`vfs491_probe` needs no sudo here (systemd-logind grants your user an ACL on the
device node). It prints the descriptors and sends the one read-only command we
know, `GET_VERSION`, then decodes the reply. Verified on this machine: ROM
4.60 build 104, product `Falconusb`, security bytes `01 30`, status `0x0000`.

There is also a second, still read-only tool that reaches further into the
protocol:

```bash
make run-session          # GET_VERSION, GET_START_INFO, and an SSL ClientHello
make run-session ARGS=info # or: info | hello | gate | all
```

`GET_START_INFO` (`0x19`) works and returns 68 bytes. The SSL tunnel (`0x11`)
**does not**: it answers a constant status `0x0426` to any payload, because the
sensor gates the tunnel until HP's RAM patches are loaded. Details in
`docs/protocol.md` and `docs/ssl-notes.md`.

The session tool can also **reproduce HP's unlock with our own code** and then
open the tunnel. The two patches are HP firmware, so you point it at files you
supply (see `docs/ssl-notes.md`); the patch bytes never enter this repo:

```bash
# needs write access to the sensor node (run as root or add a udev rule)
sudo ./build/vfs491_session unlock \
        /tmp/opencode/patches/patch1.bin /tmp/opencode/patches/patch2.bin
```

It uploads patch #1, does the two `0x1f` reads, uploads patch #2, then sends our
ClientHello. Expected if the patches take: the reply is a raw TLS ServerHello
(`16 03 00 ...`) instead of `26 04` (`0x0426`).

`tools/vfs491_ssl.c` goes all the way: after the same unlock it answers the
sensor's `CertificateRequest` and completes the handshake (client `Finished`),
then decrypts and **verifies the sensor's `Finished`** to prove the keys agree.
It needs the sensor's RSA-2048 public key, which is per-device and is read from
the `0x1f` flash region (the same bytes the vendor echoes in its `Certificate`;
see `docs/ssl-notes.md`). No vendor bytes are compiled in:

```bash
sudo ./build/vfs491_ssl \
        /tmp/opencode/patches/patch1.bin /tmp/opencode/patches/patch2.bin \
        --pubkey /tmp/opencode/patches/sensor_pubkey.bin
```

It tries both modulus byte orders in one run (`--modle` / `--modbe` to pin one)
and prints whether the handshake completed. `--cv FILE` overrides the
`CertificateVerify`(`0x0f`) body (default: zeros). `--app` then sends an encrypted
`GET_VERSION` to exercise the tunnel.

The `0x0f` is a real RSA signature over the handshake transcript
(`MD5‖SHA1`), signed by a client key HP keeps in SPI-flash slot 13 -- *not* the
id-10 key, and not recoverable from the `0x1f` reads (see `docs/ssl-notes.md`).
Device experiments that settle whether the sensor checks it:

* `--no-cv` omit the signature; `--cv-rsa` send a well-formed arbitrary block.
* `--own-key` present a fresh client key and sign with it (if the sensor trusts
  the certificate, this completes with no vendor key).
* `--cv-rev` byte-reverse the signed body.

Offline crypto self-tests: `./build/vfs491_ssl --selftest`, `--rsatest MOD.bin`,
and `--cvselftest` (exercises the `--own-key` signing path).

Capture the exchange to confirm the framing (`docs/capture.md`):

```bash
sudo bash capture/usbmon_capture.sh --label getver --seconds 8   # terminal 1
make run                                                          # terminal 2
python3 capture/usbmon_parse.py --devnum "$(cat /sys/bus/usb/devices/2-1.1/devnum)" \
        captures/getver.txt
```

This was done on 2026-10-16 and confirmed the framing (1-byte OUT `01` on
`0x01`, 38-byte IN on `0x81` status 0). One caveat: the text API caps captured
data at 32 bytes per transfer, so payloads need `wireshark-cli` or our own
client -- see `docs/capture.md`.

Get the prior art locally, then install the optional capture tooling:

```bash
mkdir -p reference
git clone --depth 1 https://github.com/saifulmd0/vfs495-linux        reference/vfs495-linux
git clone --depth 1 https://github.com/mbtech-nl/nixos-validity-VFS491 reference/nixos-validity-VFS491
sudo dnf install -y wireshark-cli        # optional: pcap instead of text API
                                         # (Debian: apt install tshark; Arch: pacman -S wireshark-cli)
```

## Next steps

1. ~~Confirm GET_VERSION framing from a capture of our own probe~~ -- done
   2026-10-16, `captures/getver.txt`; log filled in `docs/protocol.md`.
2. **SSL session -- captured end to end.** The command layer is byte-compatible
   with the VFS495's, and using HP's binaries as a **research-only measurement
   instrument** (agreed 2026-10-16) we captured the whole vendor session:
   the unlock sequence (two `0x06` patches + two `0x1f` reads), the ServerHello
   flight (which includes a **CertificateRequest**), and the client flight
   (`Certificate + ClientKeyExchange + CertificateVerify + CCS + Finished`).
   The sensor completes the handshake with **no `0x2f` alert** and a fingerprint
   is captured, so `0x2f` is not a sensor gate. The open VFS495 client's flight
   omitted the `Certificate`/`0x0f` messages -- the leading fix. The sensor's
   RSA-2048 public key is readable from the `0x1f` region (offset `0x5b6`).
   Details in `docs/ssl-notes.md` and `docs/hp-artifacts.md`.

   Next: build our own client that replays the init, reads the pubkey, and sends
   the full flight; test whether a dummy `0x0f` is accepted.
3. ~~Only after the session works: image decryption + reconstruction, then a
   libfprint driver (`vfs491.c`) built on the in-tree driver API.~~ -- done:
   see `driver/vfs491.c` and `build-libfprint.sh`.
4. ~~A full enroll/verify run under `fprintd`.~~ -- **WORKING** (2026-10-21) via
   the vendor-capture path: `fprintd-enroll` completes and `fprintd-verify`
   returns `verify-match` (175/40, 55/40). An audit of the open capture path
   showed the EP `0x82` swipe stream is AES-encrypted and the image needs HP's
   `IR*` reconstruction, so capture is delegated to the vendor tool while the
   bridge and matching stay open — see [`proprietary/`](proprietary/README.md).
   Remaining research: replace that delegation with an open decrypt +
   reconstruct, and drop the native `driver/vfs491.c` capture path.

## Rules for this effort

* Read-only unless the write is known to be safe. Patch uploads land in sensor
  RAM and vanish on power-off; **OTP / flash / ownership commands are
  forbidden** (`docs/protocol.md` lists them).
* No vendor code in the shipped path. Using HP's tool once, offline, purely to
  obtain reference traces is a research decision, not part of the solution.
* Never commit captures -- they contain fingerprint images and session keys.

## License

Two licenses, both permissive of derivative works — see [`LICENSE`](LICENSE):

* **MIT** — the tooling, bridge, capture/harvest scripts, build scripts and
  documentation (everything except the driver). Some of these files are
  *adapted from* the MIT prior art `vfs495-linux` and `nixos-validity-VFS491`,
  whose terms are preserved.
* **LGPL-2.1-or-later** — `driver/vfs491.c`, its `.inc`, and the libfprint
  patch. A libfprint driver has to be LGPL so it can link with libfprint; each
  file says so in its header.

HP's Validity software is proprietary, is not included, and is not covered by
either license — you fetch it from HP yourself at setup time.
