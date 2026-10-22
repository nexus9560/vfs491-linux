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

## Requirements

Nothing here is distro-specific. The install path needs:

| Need | Why | Notes |
|---|---|---|
| Python 3 | the bridge, capture and harvest scripts | ≥3.6 |
| `gdb` | drives HP's tool to grab the reconstructed image | required |
| systemd | the bridge runs as a service | optional; you can run it by hand |
| one RPM unpacker | to open HP's SoftPaq | `rpm2cpio`+`cpio`, `bsdtar`, `7z`, **or just Python 3** |
| `python3-dbus`, `python3-gobject` | the bridge listens on fprintd's D-Bus signal | required for auth |
| `fprintd` + a libfprint with `virtual_image` | matching is done by stock libfprint | `setup.sh` warns if absent |

Package names, if `setup.sh` or the bridge says something is missing:

| Tool | Fedora/RHEL | Debian/Ubuntu | Arch | openSUSE |
|---|---|---|---|---|
| gdb | `gdb` | `gdb` | `gdb` | `gdb` |
| dbus bindings | `python3-dbus` | `python3-dbus` | `python-dbus` | `python3-dbus-python` |
| gobject bindings | `python3-gobject` | `python3-gi` | `python-gobject` | `python3-gobject` |
| RPM unpacking | `rpm` + `cpio` | `rpm2cpio` + `cpio` | `libarchive` | `rpm` + `cpio` |
| PAM module | `fprintd-pam` | `libpam-fprintd` | `fprintd` | `fprintd-pam` |

None of these are installed automatically; the scripts tell you what is missing
and stop, rather than calling a package manager behind your back.

## Install

```bash
./proprietary/setup.sh          # fetch sp84530, gate-patch, install units (needs root)
sudo systemctl enable --now vfs491-bridge.service
sudo systemctl restart fprintd
```

`setup.sh` verifies the SoftPaq SHA-256, unpacks the RPM with whichever tool you
have, gate-patches the tool's `main()` guard, installs `validity-sensor-unlocked`
+ these scripts into `/usr/libexec/vfs491/`, and installs:

* `/etc/systemd/system/fprintd.service.d/virtual-image.conf` — sets
  `FP_VIRTUAL_IMAGE` so stock libfprint uses its `virtual_image` driver.
* `/etc/systemd/system/vfs491-bridge.service` — the event-driven bridge.

HP's tool is proprietary and is **downloaded from HP at setup time, never
committed**.

## Using it for authentication

`./enable-auth.sh` installs `fprintd-pam` (provides `pam_fprintd.so`, which
`fprintd` alone does not ship) and wires `pam_fprintd` into PAM. `pam_fprintd`
is `sufficient`, so a swipe can authenticate but the password prompt is always
still there.

How it wires depends on the distro, and it reports what it did:

| Distro | Mechanism |
|---|---|
| Fedora / RHEL | `authselect enable-feature with-fingerprint` (tracked, reversible) |
| Debian / Arch / other | edits the PAM service files directly, keeping `*.vfs491-bak` backups |

PAM files that are *symlinks* into a shared target (Fedora's authselect-managed
`system-auth` and friends) are skipped with a warning rather than edited through
the link, since that would change a file other services share without a matching
backup. Use `authselect` for those.

| Target | PAM service(s) |
|---|---|
| `sudo`, `su`, `login` | `sudo`, `su`, `login` (and `system-auth` on Fedora) |
| greeter / lock screen | `kde`, `kde-fingerprint`, `gdm-fingerprint`, `gdm-password`, `sddm`, `lightdm`, `lxdm`, `greetd`, `ly`, `kscreensaver`, `kcheckpass` |
| polkit (GUI prompts) | `polkit-1` (created if your distro has no such file) |

```bash
./enable-auth.sh            # wire fingerprint into PAM
./enable-auth.sh --status   # show what is wired
./enable-auth.sh --undo     # reverse it
```

If `pam_fprintd.so` is missing, the script tells you the package name for your
distro (`fprintd-pam` on Fedora/`libpam-fprintd` on Debian, `fprintd` on Arch).
It does not install packages for you.

Test easiest first (`sudo true`, then `pkexec true`, then the lock screen).
For cold-boot login, both `setup.sh` and `enable-auth.sh` detect your actual
display manager and order it after `vfs491-bridge` via a drop-in, so this is
not tied to any one desktop.

## Use

```bash
# one-off capture test (root); swipe when it says the sensor is armed (~2 s)
sudo /usr/libexec/vfs491/vfs491-capture /tmp/fp.pgm

sudo fprintd-enroll "${SUDO_USER:-$USER}"
sudo fprintd-verify "${SUDO_USER:-$USER}"
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

This is handled automatically now, but the manual path is still there.

**What causes it.** The kernel's default USB autosuspend delay is 2 seconds,
and the VFS491's endpoints do not survive a suspend/resume cycle. A capture
that spans one comes back truncated — a 200×86 or 200×58 strip instead of a
200×300 print — and repeated suspend/resume cycles eventually leave the device
wedged so it stops opening at all (`Sensor isn't detected`). A cold boot is the
worst case, because the sensor sits idle and suspended from the moment it
enumerates until you touch it.

**What we do about it**, in three layers:

1. `60-vfs491.rules` (installed to `/etc/udev/rules.d/`) sets
   `power/control=on` for `138a:003d`, so the sensor is never autosuspended.
2. The bridge unit runs `vfs491-recover --if-present` as an `ExecStartPre`, so
   every boot starts with the sensor re-enumerated and awake.
3. The bridge itself self-heals mid-session: if a capture fails or comes back
   truncated, it re-enumerates the sensor and retries **once**. (A blind retry
   is not allowed — that is what drives the device into the wedge in the first
   place. A retry that follows a re-enumeration resets the device instead of
   grinding it.)

**Manual recovery**, if you ever need it:

```bash
sudo /usr/libexec/vfs491/vfs491-recover            # wake it; reset only if unhealthy
sudo /usr/libexec/vfs491/vfs491-recover --reset    # always re-enumerate
./enable-auth.sh --reenumerate                     # same thing, convenience alias
```

The script finds the sensor by its USB IDs, so there is no port path to adjust.
The sysfs node (`3-1.1`, `1-1.4`, ...) is specific to your USB topology and
differs between machines, docks and reboots, which is why we match on
`138a:003d` instead of hard-coding it.

> Note: `sudo` here will itself offer a fingerprint first (that is the point of
> this project), so it can pause for a swipe before the command runs. Use
> `sudo -n` if you want it to fail fast instead.

## Cold-boot ordering

The bridge is ordered `After=basic.target` / `Before=multi-user.target`, and
`setup.sh` installs a drop-in making your display manager
(`gdm`, `sddm`, `lightdm`, `plasmalogin`, ...) wait for
`vfs491-bridge.service`. Without that, the greeter can ask for a finger before
the bridge is listening and the first login attempt times out.

## Files

| File | Purpose |
|---|---|
| `harvest.py` | gdb script: breakpoint at `IRqualityDetermination` (`0x4689b0`), copies the assembled image out; touches `$VFS_ARMED` when `SensorGetPrintWait` is entered |
| `capture.py` | one swipe → PGM, via gdb + `harvest.py` |
| `bridge.py` | event-driven: one capture per `finger-needed`, delivers to the `virtual_image` socket; logs `SWIPE NOW` on the armed signal; re-enumerates and retries once on a failed or truncated capture |
| `vfs491-recover` | puts the sensor in a known-good state: finds it by USB ID, re-enumerates it, and keeps it out of autosuspend |
| `60-vfs491.rules` | udev rule: `power/control=on` for `138a:003d`, so the sensor is never autosuspended mid-capture |
| `vfs491-lib.sh` | shared helpers: sensor discovery by USB ID, PAM dir/greeter detection, auth-user resolution |
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
