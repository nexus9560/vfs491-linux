# Working path: HP capture + open bridge

This is the path that **works on hardware** (Fedora 44, HP EliteBook 8770w,
`138a:003d`). `fprintd-enroll` completes and `fprintd-verify` returns
`verify-match` (observed scores **175/40** and **55/40**; match threshold is 40).

## Why not a purely open driver

The native driver in `../driver/vfs491.c` proves the protocol end of the problem
(open SSLv3 session, patch upload, arm, read). But an audit of a full,
undecoded swipe stream from the sensor's EP `0x82` showed the pixels have
optical-signal statistics yet **no fingerprint ridge structure** — while the
vendor's reconstructed image (this path) does. The sibling-sensor research
(`reference/vfs495-linux`, `reference/nixos-validity-VFS491`) confirms the
reason: the swipe data is **AES-encrypted end to end** and the image is produced
by HP's proprietary motion-compensated reconstruction (`IR*`). Both live only in
HP's binary, so the community-proven split is used here too:

```
sudo/fprintd ── libfprint virtual_image (stock Fedora, FP_VIRTUAL_IMAGE socket)
             ◀── vfs491-bridge.service (root): waits for finger-needed
                    └── capture.py: gdb + harvest.py
                          └── HP validity-sensor 4.5-136 (gate-patched)
                              → SSL session + capture + reconstruction
                              → gdb stops at IRqualityDetermination, lifts 200x300 image
             → NBIS minutiae + bozorth3 match
```

Only **SSL + capture** are delegated to the vendor tool; the driver
scaffolding, the bridge, and the matching (libfprint's normal NBIS matcher) are
ours / upstream.

## Install

```bash
cd ~/source/repos/fingerprint-sensor
./proprietary/setup.sh          # fetch sp84530, gate-patch, install units (asks for sudo)
sudo systemctl enable --now vfs491-bridge.service
sudo systemctl restart fprintd
```

`setup.sh` verifies the SoftPaq SHA-256, unpacks the RPM, gate-patches the
tool's `main()` guard, installs `validity-sensor-unlocked` + these scripts into
`/usr/libexec/vfs491/`, and installs:

* `/etc/systemd/system/fprintd.service.d/virtual-image.conf` — sets
  `FP_VIRTUAL_IMAGE` so stock libfprint uses its `virtual_image` driver.
* `/etc/systemd/system/vfs491-bridge.service` — the event-driven bridge.

HP's tool is proprietary and is **downloaded from HP at setup time, never
committed**.

## Use

```bash
# one-off capture test (root); swipe ~3 s after it starts, slowly and evenly
sudo /usr/libexec/vfs491/vfs491-capture /tmp/fp.pgm

sudo fprintd-enroll mpryzlwyn
sudo fprintd-verify mpryzlwyn
journalctl -u fprintd | grep score      # e.g. "score 175/40"; >=40 is a match
```

## Files

| File | Purpose |
|---|---|
| `harvest.py` | gdb script: breakpoint at `IRqualityDetermination` (`0x4689b0`), copies the assembled image out |
| `capture.py` | one swipe → PGM, via gdb + `harvest.py` |
| `bridge.py` | event-driven: one capture per `finger-needed`, delivers to the `virtual_image` socket |
| `setup.sh` | fetch + verify + unpack + gate-patch + install units |

Adapted from [saifulmd0/vfs495-linux](https://github.com/saifulmd0/vfs495-linux)
and [mbtech-nl/nixos-validity-VFS491](https://github.com/mbtech-nl/nixos-validity-VFS491)
(both MIT).

## Swiping tips (from the reference project's results)

* The sensor only listens ~2–3 s after the tool starts (patch upload + SSL +
  calibration). Swipe **after** the delay, **slowly and evenly**, the whole
  length of the sensor. Rushed swipes are the most common cause of failure.
* How well a finger scans varies a lot between fingers. The reference measured
  one index finger at median bozorth3 21 and another at 87; if one finger
  verifies poorly, enroll a different one.
* Occasional tiny scan (`200x33`) means the wake-on-finger didn't re-arm; the
  bridge retries once. If it persists, power the machine **off** fully (a
  reboot is not enough).
