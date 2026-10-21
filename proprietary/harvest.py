# gdb python: run HP's validity-sensor (4.5-136) for one swipe and harvest the
# motion-compensated assembled image at IRqualityDetermination (0x4689b0), where
# rdi = IR context, [ctx+0xa8] = image, dims at image-0x44 / image-0x48.
# Writes <u32 dim1><u32 dim2><pixels> to $VFS_ASM_OUT. Same layout on VFS491 and VFS495.
#
# Why this exists: the EP 0x82 swipe stream is AES-encrypted end to end, and the
# reconstruction (motion estimation + analog recon) is HP's IR* pipeline. Both are
# only available inside the vendor binary, so we let it do them and lift the finished
# 200x300 image out of its memory. See docs/hp-artifacts.md and README.md.
#
# Adapted from saifulmd0/vfs495-linux and mbtech-nl/nixos-validity-VFS491 (both MIT),
# plus a guard against the short/fast-swipe case where the breakpoint fires with
# bad dimensions.
#
# Env:
#   VFS_ASM_OUT   where to write the harvested image (required)
#   VFS_LED_LOG   if set, also log a timeline of pipeline breakpoints (diagnostics)
#   VFS_ARMED     if set, touched the first time the sensor is armed and idle
#                 (init traffic has stopped, so a swipe will now register)
import gdb, os, struct, time

OUT = os.environ["VFS_ASM_OUT"]
LED_LOG = os.environ.get("VFS_LED_LOG")
ARMED = os.environ.get("VFS_ARMED")
hits = {"n": 0}
T0 = time.monotonic()
# Init (patch upload + SSL + calibration) is a burst of scsSSLAppDataWrite calls
# that then goes quiet: that quiet point is when the sensor is listening. We only
# care about the first quiet gap, and only during the pre-swipe phase.
_last_write = [0.0]
_armed = [False]


def _touch_armed():
    if _armed[0]:
        return
    _armed[0] = True
    if ARMED:
        try:
            open(ARMED, "w").close()
        except OSError:
            pass

if LED_LOG:
    _log = open(LED_LOG, "w", buffering=1)

    def mark(msg):
        _log.write("%7.3f  %s\n" % (time.monotonic() - T0, msg))

    # vcsSensorLEDReadyForSwipe is the "sensor is armed, swipe now" signal. The
    # others bound the swipe: Accepted/Rejected mark the outcome.
    for name, addr in {
        "vcsSensorLEDReadyForSwipe": 0x454880,
        "vcsSensorLEDSwipeAccepted": 0x4547c0,
        "IRqualityDetermination": 0x4689b0,
        "scsSSLAppDataWrite": 0x514d10,
    }.items():
        class _M(gdb.Breakpoint):
            def __init__(self, n, a):
                super().__init__("*0x%x" % a, internal=True)
                self.n = n

            def stop(self):
                mark(self.n)
                return False

        try:
            _M(name, addr)
        except Exception as e:
            mark("SETFAIL %s: %s" % (name, e))
    mark("bps set")


# SensorGetPrintWait (0x43eb20) is entered exactly when the sensor has finished
# init and is now listening for a finger. That is the "swipe now" moment.
class AtArmed(gdb.Breakpoint):
    def stop(self):
        if LED_LOG:
            mark("ARMED (sensor listening)")
        _touch_armed()
        return False


AtArmed("*0x43eb20", internal=True)


class AtQuality(gdb.Breakpoint):
    def stop(self):
        inf = gdb.selected_inferior()
        ctx = int(gdb.selected_frame().read_register("rdi")) & 0xffffffffffffffff
        try:
            img = int.from_bytes(inf.read_memory(ctx + 0xa8, 8), "little")
            if not img:
                print("ASM_SKIP image pointer is NULL")
                return False
            a = int.from_bytes(inf.read_memory(img - 0x44, 4), "little")
            b = int.from_bytes(inf.read_memory(img - 0x48, 4), "little")
            if not (0 < a <= 5000 and 0 < b <= 20000 and a * b <= 4_000_000):
                print(f"ASM_SKIP bad dims {a}x{b}")
                return False
            px = bytes(inf.read_memory(img, a * b))
            with open(OUT, "wb") as fh:
                fh.write(struct.pack("<II", a, b) + px)
            hits["n"] += 1
        except gdb.MemoryError as e:
            print(f"ASM_SKIP {e}")
        return False


AtQuality("*0x4689b0", internal=True)
gdb.execute("run getprintwait -doinit")
print("ASM_HITS", hits["n"])
if LED_LOG:
    mark("tool exited")
gdb.execute("quit")
