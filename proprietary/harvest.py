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
import gdb, os, struct

OUT = os.environ["VFS_ASM_OUT"]
hits = {"n": 0}


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
gdb.execute("quit")
