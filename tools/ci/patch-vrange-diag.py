#!/usr/bin/env python3
"""Diagnostic patch for the payload SDK's platform layer (platform/src/shm.c).

On PS5 firmware 7.40 (un-jailbroken app) RPCS3's PPU compiler workers die with
ps5_vrange_commit(..., prot=7) -> 0x8002000d (EACCES) after a few dozen successful
executable commits. This patch records which kernel call fails, the counters at that
moment, free direct memory, and whether a read-execute retry would have been accepted,
to /data/rpcs3/vrange_diag.log. Behaviour is unchanged: the commit still fails.

Usage: patch-vrange-diag.py <path to platform/src/shm.c>
"""
import sys

path = sys.argv[1]
s = open(path, encoding="utf-8").read()

def replace(old, new):
    global s
    assert s.count(old) == 1, old
    s = s.replace(old, new, 1)

# 1. helpers after the counters
replace(
    "static atomic_uint_fast64_t objects, object_bytes, views, view_bytes, ranges, range_bytes,\n"
    "   committed_bytes;\n",
    "static atomic_uint_fast64_t objects, object_bytes, views, view_bytes, ranges, range_bytes,\n"
    "   committed_bytes;\n"
    "\n"
    "/* --- fw740 diagnostic (see tools/ci/patch-vrange-diag.py in rpcs3-PS5) --- */\n"
    "#include \"ps5platform/memory.h\"\n"
    "#include <fcntl.h>\n"
    "#include <stdio.h>\n"
    "#include <unistd.h>\n"
    "#include <time.h>\n"
    "static double probe_now(void)\n"
    "{\n"
    "   struct timespec ts;\n"
    "   clock_gettime(CLOCK_MONOTONIC, &ts);\n"
    "   return (double)ts.tv_sec + (double)ts.tv_nsec / 1e9;\n"
    "}\n"
    "static double probe_t0;\n"
    "static atomic_uint_fast64_t diag_calls, diag_exec_calls;\n"
    "static void\n"
    "vrange_diag(const char *step, uintptr_t at, size_t bytes, int wanted, int32_t rc, uintptr_t unit_at,\n"
    "            int32_t retry_rc)\n"
    "{\n"
    "   struct ps5_memory_stats st;\n"
    "   unsigned long free_b = 0, largest = 0, flex = 0;\n"
    "   if (rc != 0 && ps5_memory_query(&st)) {\n"
    "      free_b = (unsigned long)st.free_bytes;\n"
    "      largest = (unsigned long)st.largest_bytes;\n"
    "      flex = (unsigned long)st.flexible_bytes;\n"
    "   }\n"
    "   char line[320];\n"
    "   const int n = snprintf(line, sizeof line,\n"
    "      \"t=%.3f commit step=%s at=%lx bytes=%zx prot=%d rc=%x unit=%lx retry_rx_rc=%x calls=%lu exec_calls=%lu \"\n"
    "      \"committed=%lu free=%lu largest=%lu flexible=%lu\\n\",\n"
    "      probe_now() - probe_t0, step, (unsigned long)at, bytes, wanted, (unsigned)rc, (unsigned long)unit_at, (unsigned)retry_rc,\n"
    "      (unsigned long)atomic_load(&diag_calls), (unsigned long)atomic_load(&diag_exec_calls),\n"
    "      (unsigned long)atomic_load(&committed_bytes), free_b, largest, flex);\n"
    "   if (n <= 0)\n"
    "      return;\n"
    "   const int fd = open(\"/data/rpcs3/vrange_diag.log\", O_WRONLY | O_CREAT | O_APPEND, 0644);\n"
    "   if (fd < 0)\n"
    "      return;\n"
    "   (void)!write(fd, line, (size_t)n);\n"
    "   close(fd);\n"
    "}\n"
    "#ifndef FW740_PROBES\n"
    "static void probe3_check(unsigned long call, int commit_failed) { (void)call; (void)commit_failed; }\n"
    "#else\n"
    "static void probe3_check(unsigned long call, int commit_failed);\n"
    "#endif\n"
    "/* --- end diagnostic helpers --- */\n",
)

# 2. count calls at the top of ps5_vrange_commit
replace(
    "   const int wanted = kernel_protection(protection);\n"
    "   const int at_map = PS5_KERNEL_PROT_CPU_READ | PS5_KERNEL_PROT_CPU_WRITE;\n"
    "   int32_t result = 0;\n"
    "   pthread_mutex_lock(&units_lock);\n",
    "   const int wanted = kernel_protection(protection);\n"
    "   const int at_map = PS5_KERNEL_PROT_CPU_READ | PS5_KERNEL_PROT_CPU_WRITE;\n"
    "   int32_t result = 0;\n"
    "   atomic_fetch_add(&diag_calls, 1);\n"
    "   if (wanted & PS5_KERNEL_PROT_CPU_EXEC)\n"
    "      atomic_fetch_add(&diag_exec_calls, 1);\n"
    "   uintptr_t diag_unit = 0;\n"
    "   const char *diag_step = \"none\";\n"
    "   pthread_mutex_lock(&units_lock);\n",
)

# 3. alloc failure
replace(
    "      result = sceKernelAllocateDirectMemory(0, sceKernelGetDirectMemorySize(), PS5P_DIRECT_UNIT,\n"
    "                                             PS5P_DIRECT_UNIT, PS5_KERNEL_DIRECT_TYPE_CPU, &start);\n"
    "      if (result != 0)\n"
    "         break;\n",
    "      result = sceKernelAllocateDirectMemory(0, sceKernelGetDirectMemorySize(), PS5P_DIRECT_UNIT,\n"
    "                                             PS5P_DIRECT_UNIT, PS5_KERNEL_DIRECT_TYPE_CPU, &start);\n"
    "      if (result != 0) {\n"
    "         diag_step = \"alloc\";\n"
    "         diag_unit = at;\n"
    "         break;\n"
    "      }\n",
)

# 4. map failure
replace(
    "      if (result != 0) {\n"
    "         sceKernelReleaseDirectMemory(start, PS5P_DIRECT_UNIT);\n"
    "         break;\n"
    "      }\n",
    "      if (result != 0) {\n"
    "         diag_step = \"map\";\n"
    "         diag_unit = at;\n"
    "         sceKernelReleaseDirectMemory(start, PS5P_DIRECT_UNIT);\n"
    "         break;\n"
    "      }\n",
)

# 5. edge protections + final protection, with the read-execute retry experiment
replace(
    "      if (at < page_low)\n"
    "         result = sceKernelMprotect(mapped, page_low - at, 0);\n"
    "      if (result == 0 && at + PS5P_DIRECT_UNIT > page_high)\n"
    "         result = sceKernelMprotect((void *)page_high, at + PS5P_DIRECT_UNIT - page_high, 0);\n"
    "   }\n"
    "   if (result == 0)\n"
    "      result = sceKernelMprotect((void *)page_low, page_high - page_low, wanted);\n"
    "   pthread_mutex_unlock(&units_lock);\n"
    "   return result;\n",
    "      if (at < page_low)\n"
    "         result = sceKernelMprotect(mapped, page_low - at, 0);\n"
    "      if (result == 0 && at + PS5P_DIRECT_UNIT > page_high)\n"
    "         result = sceKernelMprotect((void *)page_high, at + PS5P_DIRECT_UNIT - page_high, 0);\n"
    "      if (result != 0) {\n"
    "         diag_step = \"mprotect_edge\";\n"
    "         diag_unit = at;\n"
    "      }\n"
    "   }\n"
    "   int32_t retry_rc = 0;\n"
    "   if (result == 0) {\n"
    "      result = sceKernelMprotect((void *)page_low, page_high - page_low, wanted);\n"
    "      if (result != 0) {\n"
    "         diag_step = \"mprotect_final\";\n"
    "         diag_unit = page_low;\n"
    "         if (wanted & PS5_KERNEL_PROT_CPU_EXEC) {\n"
    "            /* Experiment: would read-execute (no write) have been accepted? Restore read-write after. */\n"
    "            retry_rc = sceKernelMprotect((void *)page_low, page_high - page_low,\n"
    "                                         PS5_KERNEL_PROT_CPU_READ | PS5_KERNEL_PROT_CPU_EXEC);\n"
    "            (void)sceKernelMprotect((void *)page_low, page_high - page_low, at_map);\n"
    "         }\n"
    "      }\n"
    "   }\n"
    "   if (wanted & PS5_KERNEL_PROT_CPU_EXEC)\n"
    "      probe3_check((unsigned long)atomic_load(&diag_exec_calls), result != 0);\n"
    "   if (result != 0 || (wanted & PS5_KERNEL_PROT_CPU_EXEC))\n"
    "      vrange_diag(result != 0 ? diag_step : \"ok\", begin, bytes, wanted, result, diag_unit, retry_rc);\n"
    "   pthread_mutex_unlock(&units_lock);\n"
    "   return result;\n",
)

open(path, "w", encoding="utf-8", newline="\n").write(s)
print("patched", path)
