# Capturing USB traffic

usbmon is compiled into this kernel (`CONFIG_USB_MON=y`), and `/dev/usbmon0..6`
plus `/sys/kernel/debug/usb/usbmon/` exist. The capture interfaces are root-only,
so capture commands need `sudo`; the sensor itself is reachable without sudo
(logind grants your user an ACL on the device node).

## Quick captures

Everything with data, sensor only:

```bash
sudo bash capture/usbmon_capture.sh --label probe --seconds 10
```

The script finds the sensor, picks its bus, and writes `captures/probe.txt`
(text API) or `captures/probe.pcap` (if `tshark` is installed). It prints the
exact parse command at the end.

Better output (optional, one-time install; needs root for usbmon either way):

```bash
sudo dnf install -y wireshark-cli          # Fedora
sudo apt install -y tshark                 # Debian/Ubuntu
sudo pacman -S wireshark-cli               # Arch
```

## The 32-byte limit of the text API

The text API is convenient but it truncates. The kernel keeps at most
`DATA_MAX = 32` bytes of each transfer, and says so in the source
(`drivers/usb/mon/mon_text.c`):

    "No, we do not want arbitrarily long data strings.
     Use the binary interface if you want to capture bulk data!"

So in `captures/*.txt`:

* small commands are complete (the 26-byte string-descriptor read is fine),
* the 38-byte GET_VERSION reply is cut to its first 32 bytes,
* the sensor's 272-byte scan-line frames would be cut to 32 bytes each.

`usbmon_parse.py` flags every transfer this happened to, e.g.

    C bulk i 002:003:81 st=0 n=38 command replies in   TRUNCATED: 32 of 38 bytes captured

For payload work, install `wireshark-cli` (tshark uses the binary API and
captures full data), or read payloads straight from the device with our own
client -- the probe already gets all 38 bytes without usbmon.

## Capturing our own probe traffic

Terminal 1:

```bash
sudo bash capture/usbmon_capture.sh --label getver --seconds 8
```

Terminal 2 (repeat a few times so the capture has more than one exchange):

```bash
make run
```

Then look at what we sent and what came back:

```bash
python3 capture/usbmon_parse.py --devnum "$(cat /sys/bus/usb/devices/2-1.1/devnum)" \
    captures/getver.txt
python3 capture/usbmon_parse.py --devnum 3 --ep 0x01 --ep 0x81 --hexdump captures/getver.txt
```

Done on 2026-10-16 (`captures/getver.txt`), and it confirms the framing in
`docs/protocol.md`:

* the probe's descriptor reads appear as `GET_DESCRIPTOR STRING index=0..3`,
  and index 1 reads back `002052041491` -- the same serial the probe prints,
* our command is a 1-byte bulk OUT `01` on `0x01` (`S Bo:2:003:1 ... = 01`),
* the reply is a 38-byte bulk IN on `0x81` with status 0, and its first 32
  bytes match the probe's dump byte for byte; the last 6 are lost to the
  32-byte text-API cap described above.

## Capturing a swipe

Not possible yet, and this is the honest blocker: after cleanup there is no
host-side implementation that can put the sensor into a state where it waits for
a finger. The old proprietary stack could, but it is removed. If you ever decide
to use HP's tool strictly as a *measuring instrument* to obtain reference traces,
re-fetch the SoftPaq (nothing is shipped in the repo) -- that is a research
decision, not part of the working solution.

Until then, swipe traffic can only be captured once our own host implementation
gets through the command sequence + session setup. Order of work is in
`docs/protocol.md` ("Experiment plan").

## What to do with a pcap

If you installed `wireshark-cli`/Wireshark:

* filter to the sensor: `usb.device_address == <devnum>`
* `usb.transfer_type == 0x02` for bulk traffic
* the pre-TLS command phase is plaintext and decodes fine; the SSLv3 phase does
  not (Wireshark cannot decrypt TLS over USB without a custom dissector)

Once the session layer is understood, the plan is the same trick the Goodix
reverse engineering used: proxy the byte stream over a local TCP socket so
Wireshark can decrypt it with a known key.

## Testing the parser without hardware

`capture/selftest.py` builds a synthetic capture in the real on-disk shape --
4-byte-grouped data words, a control setup line, a GET_VERSION exchange with a
32-byte-truncated reply, full scan-line frames, a legacy 1t-format line and
unrelated bus noise -- runs the parser over it, and checks the decoded output
and the reconstructed PGM (14 checks):

```bash
python3 capture/selftest.py
```

No root, no hardware, no packages.

## Making sure HP's tool can open the sensor

The working path runs HP's `validity-sensor` under gdb, and that tool needs
**exclusive** access to `138a:003d`. If something else already owns the device,
you get `Open Sensor failed` / `Sensor isn't detected` and no capture.

Only one of these is usually true for you:

* **You never built the open driver.** Then there is nothing to do — the stock
  system has no vfs491 driver, and the sensor is free. This is the normal case.
* **You built and installed the open driver** (`build-libfprint.sh`) on this
  machine. Its udev/autosuspend entries can claim the device. Undo that before
  using the proprietary path:
  * if you installed a modified libfprint, restore the stock one:
    `sudo dnf reinstall libfprint` (or `apt install --reinstall libfprint-2-2`)
  * remove any driver udev rule you added under `/etc/udev/rules.d/`
  * reload: `sudo udevadm control --reload && sudo udevadm trigger --subsystem-match=usb`

The two paths are alternatives: the native driver is research, the vendor
capture path is what works. Run one or the other, not both.

If the sensor is wedged after many rapid captures, re-enumerate it (no reboot) —
`proprietary/enable-auth.sh --reenumerate`, or see `proprietary/README.md`.

## Do not publish

Captures and memory dumps contain fingerprint images and session keys. Keep
`captures/` local (it is in `.gitignore`).
