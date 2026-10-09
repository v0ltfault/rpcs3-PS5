#!/usr/bin/env python3
"""Small PS5 runtime fixes for RPCS3 found on a retail PS5 (FW 7.40).

1. sys_ss_random_number_generator: the title's sandbox cannot open /dev/urandom, so the first
   PS3 thread that asks for random bytes (the XMB's ScePafJob) ended the emulation with
   "Failed to generate pseudo-random numbers". On the PS5 build, fall back to a xoshiro256**
   generator seeded from the TSC, the monotonic clock and an address. The PS3 uses these bytes
   for nonces and IDs; cryptographic quality is not needed to emulate it.

Usage: patch-rpcs3-ps5-misc.py <src/rpcs3>
"""
import os, sys

root = sys.argv[1]
path = os.path.join(root, "rpcs3/Emu/Cell/lv2/sys_ss.cpp")
s = open(path, encoding="utf-8").read()

old = (
    "#else\n"
    "\tfs::file rnd{\"/dev/urandom\"};\n"
    "\n"
    "\tif (!rnd || rnd.read(temp.get(), size) != size)\n"
    "\t{\n"
    "\t\tfmt::throw_exception(\"sys_ss_random_number_generator(): Failed to generate pseudo-random numbers\");\n"
    "\t}\n"
    "#endif\n"
)
assert s.count(old) == 1, "sys_ss anchor"

new = (
    "#else\n"
    "\tfs::file rnd{\"/dev/urandom\"};\n"
    "\n"
    "\tif (!rnd || rnd.read(temp.get(), size) != size)\n"
    "\t{\n"
    "#ifdef __PROSPERO__\n"
    "\t\t// PS5: the sandbox has no /dev/urandom. xoshiro256** seeded once per process.\n"
    "\t\tstatic std::mutex s_rng_mutex;\n"
    "\t\tstatic u64 s_rng[4]{};\n"
    "\t\tstd::lock_guard lock(s_rng_mutex);\n"
    "\t\tif (!(s_rng[0] | s_rng[1] | s_rng[2] | s_rng[3]))\n"
    "\t\t{\n"
    "\t\t\tu64 seed = __builtin_ia32_rdtsc() ^ static_cast<u64>(std::chrono::steady_clock::now().time_since_epoch().count()) ^ reinterpret_cast<u64>(&s_rng);\n"
    "\t\t\tfor (u64& v : s_rng)\n"
    "\t\t\t{\n"
    "\t\t\t\tseed += 0x9E3779B97F4A7C15ull;\n"
    "\t\t\t\tu64 z = seed;\n"
    "\t\t\t\tz = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;\n"
    "\t\t\t\tz = (z ^ (z >> 27)) * 0x94D049BB133111EBull;\n"
    "\t\t\t\tv = z ^ (z >> 31);\n"
    "\t\t\t}\n"
    "\t\t}\n"
    "\t\tconst auto rotl = [](u64 x, int k) { return (x << k) | (x >> (64 - k)); };\n"
    "\t\tfor (u64 i = 0; i < size; i += 8)\n"
    "\t\t{\n"
    "\t\t\tconst u64 out = rotl(s_rng[1] * 5, 7) * 9;\n"
    "\t\t\tconst u64 t = s_rng[1] << 17;\n"
    "\t\t\ts_rng[2] ^= s_rng[0]; s_rng[3] ^= s_rng[1]; s_rng[1] ^= s_rng[2]; s_rng[0] ^= s_rng[3];\n"
    "\t\t\ts_rng[2] ^= t; s_rng[3] = rotl(s_rng[3], 45);\n"
    "\t\t\tstd::memcpy(temp.get() + i, &out, std::min<u64>(8, size - i));\n"
    "\t\t}\n"
    "#else\n"
    "\t\tfmt::throw_exception(\"sys_ss_random_number_generator(): Failed to generate pseudo-random numbers\");\n"
    "#endif\n"
    "\t}\n"
    "#endif\n"
)
s = s.replace(old, new, 1)
for inc in ("#include <mutex>\n", "#include <chrono>\n", "#include <algorithm>\n"):
    if inc not in s:
        s = inc + s
open(path, "w", encoding="utf-8", newline="\n").write(s)
print("patched", path)
