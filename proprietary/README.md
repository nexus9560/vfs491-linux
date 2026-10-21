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

## Using it for authentication

`./enable-auth.sh` installs `fprintd-pam` (provides `pam_fprintd.so`, which
`fprintd` alone does not ship) and enables the authselect `with-fingerprint`
feature. `pam_fprintd` is `sufficient`, so a swipe can authenticate but the
password prompt is always still there.

| Target | PAM stack | Covered |
|---|---|---|
| `sudo`, `su`, `login` | `system-auth` | ✅ |
| KDE lock screen | `kscreensaver`, `kcheckpass` → `system-auth` | ✅ |
| KDE login greeter | `kde` / `kde-fingerprint` | ✅ |
| polkit (GUI prompts) | falls back to `system-auth` | ✅ |

```bash
./enable-auth.sh            # install pam module + enable the feature
./enable-auth.sh --status   # show what is wired
sudo authselect disable-feature with-fingerprint   # to undo
```

Test easiest first (`sudo true`, then `pkexec true`, then the lock screen).
Cold-boot login works because `setup.sh` orders `plasmalogin` after
`vfs491-bridge` (see its `plasmalogin.service.d/vfs491.conf` drop-in).

## Use

```bash
# one-off capture test (root); swipe when it says the sensor is armed (~2 s)
sudo /usr/libexec/vfs491/vfs491-capture /tmp/fp.pgm

sudo fprintd-enroll mpryzlwyn
sudo fprintd-verify mpryzlwyn
journalctl -u fprintd | grep score      # e.g. "score 175/40"; >=40 is a match
```

## Timing and responsiveness

Measured on this machine (one capture, from tool start to image):

| Phase | Cost | Notes |
|---|---|---|
| gdb start + load the 2.8 MB tool | ~0.7 s | unavoidable with gdb |
| **sensor init** (patch upload + SSL + calibration, ~25 USB writes) | **~1.4 s** | HP's code; the dominant cost |
| armed → waiting for the finger | — | the sensor is listening from ~2.0 s |
| capture + reconstruct | **~0.14 s** | the sensor itself is fast |

So a capture is ~4–5 s wall-clock, but **~2.1 s is fixed overhead** and the rest is
the swipe itself. The **armed signal** (`SensorGetPrintWait` at `0x43eb20`, entered
once init finishes) fires at ~2.0 s and is what the bridge uses to print
`SWIPE NOW`, instead of guessing — swipe at that point and the first try lands.

Init is redone on every capture (the sensor does not cache it), so a repeated
capture is not faster. The path is deliberately **one attempt per prompt**: a blind
retry doubles the wait and hammers the sensor's USB open/close path, which is what
pushes it into the "Open Sensor failed" wedge.

## Recovering a wedged sensor

After many rapid captures the sensor can stop opening (`Sensor isn't detected`).
A **USB re-enumeration** recovers it without a reboot:

```bash
sudo sh -c 'echo 0 > /sys/bus/usb/devices/3-1.1/authorized; \
            sleep 2; echo 1 > /sys/bus/usb/devices/3-1.1/authorized'
lsusb | grep 138a
sudo /usr/libexec/vfs491/vfs491-capture /tmp/fp.pgm     # should work again
```

(Adjust the `3-1.1` path to the sensor's sysfs node if it differs.)

## Files

| File | Purpose |
|---|---|
| `harvest.py` | gdb script: breakpoint at `IRqualityDetermination` (`0x4689b0`), copies the assembled image out; touches `$VFS_ARMED` when `SensorGetPrintWait` is entered |
| `capture.py` | one swipe → PGM, via gdb + `harvest.py` |
| `bridge.py` | event-driven: one capture per `finger-needed`, delivers to the `virtual_image` socket; logs `SWIPE NOW` on the armed signal |
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
