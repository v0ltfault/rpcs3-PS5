#!/usr/bin/env python3
"""Executable-memory probe for PS5 firmware 7.40, added to the payload SDK's platform layer
(platform/src/shm.c) after patch-vrange-diag.py. Runs once, at the first ps5_vrange_commit
call (so /data is reachable), and appends its findings to /data/rpcs3/exec_probe.log:

  P1  direct memory mapped RW then sceKernelMprotect(RX), 64 times: how many succeed
  P2  anonymous mmap RW then mprotect(RX)
  P3  a second (alias) mapping of direct memory mapped R, then RX; and mapped RW, then RX
  P4  execute asked for at map time (RX, RWX)
  P5  JIT shared memory (sceKernelJitCreateSharedMemory): RWX mapping, write view + execute alias
  P6  toggling protections on a mapping that already has execute; retrying a refused one
  P7  after freeing everything: does the budget come back
  P8  one 16 MiB region after exhaustion

Diagnostic only; it uses up some of the budget, so the application fails earlier afterwards.
Usage: patch-exec-probe.py <path to platform/src/shm.c>
"""
import sys

path = sys.argv[1]
s = open(path, encoding="utf-8").read()

def replace(old, new):
    global s
    assert s.count(old) == 1, old
    s = s.replace(old, new, 1)

PROBE = r'''
/* --- fw740 executable-memory probe (tools/ci/patch-exec-probe.py in rpcs3-PS5) --- */
#ifdef __PROSPERO__
#include <errno.h>
#include <stdarg.h>
#include <sys/mman.h>
#define PR_RW (PS5_KERNEL_PROT_CPU_READ | PS5_KERNEL_PROT_CPU_WRITE)
#define PR_RX (PS5_KERNEL_PROT_CPU_READ | PS5_KERNEL_PROT_CPU_EXEC)
#define PR_RWX (PR_RW | PS5_KERNEL_PROT_CPU_EXEC)
static void
probe_log(const char *fmt, ...)
{
   char line[512];
   va_list ap;
   va_start(ap, fmt);
   int n = vsnprintf(line, sizeof line - 1, fmt, ap);
   va_end(ap);
   if (n <= 0)
      return;
   if (n > (int)sizeof line - 2)
      n = (int)sizeof line - 2;
   line[n++] = '\n';
   const int fd = open("/data/rpcs3/exec_probe.log", O_WRONLY | O_CREAT | O_APPEND, 0644);
   if (fd < 0)
      return;
   (void)!write(fd, line, (size_t)n);
   close(fd);
}
static int32_t
probe_chunk(int64_t *start, void **at, int map_prot)
{
   *start = -1;
   *at = NULL;
   int32_t rc = sceKernelAllocateDirectMemory(0, sceKernelGetDirectMemorySize(), PS5P_DIRECT_UNIT,
                                              PS5P_DIRECT_UNIT, PS5_KERNEL_DIRECT_TYPE_CPU, start);
   if (rc != 0)
      return rc;
   rc = sceKernelMapDirectMemory(at, PS5P_DIRECT_UNIT, map_prot, 0, *start, PS5P_DIRECT_UNIT);
   if (rc != 0) {
      sceKernelReleaseDirectMemory(*start, PS5P_DIRECT_UNIT);
      *at = NULL;
   }
   return rc;
}
static void
probe_release(int64_t start, void *at)
{
   if (at)
      sceKernelMunmap(at, PS5P_DIRECT_UNIT);
   if (start >= 0)
      sceKernelReleaseDirectMemory(start, PS5P_DIRECT_UNIT);
}
static void
exec_probe(void)
{
   static atomic_int done;
   if (atomic_exchange(&done, 1))
      return;
   probe_log("probe start pid-local unit=%zx", (size_t)PS5P_DIRECT_UNIT);
   enum { MAX = 64 };
   int64_t starts[MAX];
   void *ats[MAX];
   int n = 0, first_fail = -1, ok_after_fail = 0;
   int32_t fail_rc = 0;
   /* P1 */
   for (int i = 0; i < MAX; i++) {
      int32_t rc = probe_chunk(&starts[n], &ats[n], PR_RW);
      if (rc != 0) {
         probe_log("P1 i=%d alloc/map rc=%x", i, (unsigned)rc);
         break;
      }
      n++;
      rc = sceKernelMprotect(ats[n - 1], PS5P_DIRECT_UNIT, PR_RX);
      if (rc != 0) {
         if (first_fail < 0) {
            first_fail = i;
            fail_rc = rc;
         }
      } else if (first_fail >= 0) {
         ok_after_fail++;
      }
   }
   probe_log("P1 direct RW->RX x%d: first_fail=%d rc=%x ok_after_fail=%d", n, first_fail,
             (unsigned)fail_rc, ok_after_fail);
   /* P2 */
   {
      void *anon = mmap(NULL, PS5P_DIRECT_UNIT, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
      if (anon == MAP_FAILED) {
         probe_log("P2 anon mmap failed errno=%d", errno);
      } else {
         const int r = mprotect(anon, PS5P_DIRECT_UNIT, PROT_READ | PROT_EXEC);
         probe_log("P2 anon RW->RX: rc=%d errno=%d", r, r ? errno : 0);
         munmap(anon, PS5P_DIRECT_UNIT);
      }
   }
   /* P3 */
   if (n > 0) {
      const int32_t e = sceKernelEnableDmemAliasing();
      void *alias = NULL;
      int32_t rc = sceKernelMapDirectMemory(&alias, PS5P_DIRECT_UNIT, PS5_KERNEL_PROT_CPU_READ, 0,
                                            starts[0], PS5P_DIRECT_UNIT);
      const int32_t rc2 = rc == 0 ? sceKernelMprotect(alias, PS5P_DIRECT_UNIT, PR_RX) : -1;
      probe_log("P3 alias R->RX: enable=%x map=%x mprotect=%x", (unsigned)e, (unsigned)rc, (unsigned)rc2);
      if (rc == 0)
         sceKernelMunmap(alias, PS5P_DIRECT_UNIT);
      void *alias2 = NULL;
      rc = sceKernelMapDirectMemory(&alias2, PS5P_DIRECT_UNIT, PR_RW, 0, starts[0], PS5P_DIRECT_UNIT);
      const int32_t rc3 = rc == 0 ? sceKernelMprotect(alias2, PS5P_DIRECT_UNIT, PR_RX) : -1;
      const int32_t rc4 = rc == 0 ? sceKernelMprotect(alias2, PS5P_DIRECT_UNIT, PR_RWX) : -1;
      probe_log("P3b alias RW->RX->RWX: map=%x rx=%x rwx=%x", (unsigned)rc, (unsigned)rc3, (unsigned)rc4);
      if (rc == 0)
         sceKernelMunmap(alias2, PS5P_DIRECT_UNIT);
   }
   /* P4 */
   {
      int64_t st;
      void *at;
      int32_t rc = probe_chunk(&st, &at, PR_RX);
      probe_log("P4 map-time RX: rc=%x", (unsigned)rc);
      probe_release(st, at);
      rc = probe_chunk(&st, &at, PR_RWX);
      probe_log("P4 map-time RWX: rc=%x", (unsigned)rc);
      probe_release(st, at);
   }
   /* P5 */
   {
      int fd = -1;
      int32_t rc = sceKernelJitCreateSharedMemory("rpcs3probe", PS5P_DIRECT_UNIT, PR_RWX, &fd);
      probe_log("P5 jitshm create(RWX): rc=%x fd=%d", (unsigned)rc, fd);
      if (rc == 0 && fd >= 0) {
         void *m = NULL;
         const int32_t rcm = sceKernelJitMapSharedMemory(fd, PR_RWX, &m);
         probe_log("P5 JitMapSharedMemory RWX: rc=%x at=%p", (unsigned)rcm, m);
         if (rcm == 0 && m)
            sceKernelMunmap(m, PS5P_DIRECT_UNIT);
         void *a = mmap(NULL, PS5P_DIRECT_UNIT, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_SHARED, fd, 0);
         probe_log("P5 mmap(fd) RWX: %s errno=%d", a == MAP_FAILED ? "FAIL" : "ok", a == MAP_FAILED ? errno : 0);
         if (a != MAP_FAILED)
            munmap(a, PS5P_DIRECT_UNIT);
         void *w = mmap(NULL, PS5P_DIRECT_UNIT, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
         int afd = -1;
         const int32_t rca = sceKernelJitCreateAliasOfSharedMemory(fd, PR_RX, &afd);
         void *x = rca == 0 ? mmap(NULL, PS5P_DIRECT_UNIT, PROT_READ | PROT_EXEC, MAP_SHARED, afd, 0) : MAP_FAILED;
         probe_log("P5 write view %s, alias rc=%x afd=%d, exec view %s errno=%d", w == MAP_FAILED ? "FAIL" : "ok",
                   (unsigned)rca, afd, x == MAP_FAILED ? "FAIL" : "ok", x == MAP_FAILED ? errno : 0);
         if (w != MAP_FAILED && x != MAP_FAILED) {
            /* write through w, read back through x: same pages? */
            ((volatile unsigned char *)w)[0] = 0xC3;
            probe_log("P5 alias readback: %s", ((volatile unsigned char *)x)[0] == 0xC3 ? "same pages" : "DIFFERENT");
         }
         if (w != MAP_FAILED)
            munmap(w, PS5P_DIRECT_UNIT);
         if (x != MAP_FAILED)
            munmap(x, PS5P_DIRECT_UNIT);
         if (afd >= 0)
            close(afd);
         close(fd);
      }
      fd = -1;
      rc = sceKernelJitCreateSharedMemory("rpcs3probe2", PS5P_DIRECT_UNIT, PR_RX, &fd);
      probe_log("P5 jitshm create(RX): rc=%x fd=%d", (unsigned)rc, fd);
      if (rc == 0 && fd >= 0)
         close(fd);
   }
   /* P6 */
   if (n > 0 && first_fail != 0) {
      const int32_t a = sceKernelMprotect(ats[0], PS5P_DIRECT_UNIT, PR_RW);
      const int32_t b = sceKernelMprotect(ats[0], PS5P_DIRECT_UNIT, PR_RX);
      const int32_t c = sceKernelMprotect(ats[0], PS5P_DIRECT_UNIT, PR_RWX);
      const int32_t d = sceKernelMprotect(ats[0], PS5P_DIRECT_UNIT, PR_RX);
      probe_log("P6 toggle on exec chunk: ->RW=%x ->RX=%x ->RWX=%x ->RX=%x", (unsigned)a, (unsigned)b, (unsigned)c, (unsigned)d);
   }
   if (first_fail >= 0 && first_fail < n) {
      const int32_t r = sceKernelMprotect(ats[first_fail], PS5P_DIRECT_UNIT, PR_RX);
      probe_log("P6b retry on a refused chunk: %x", (unsigned)r);
   }
   /* P7 */
   for (int i = 0; i < n; i++)
      probe_release(starts[i], ats[i]);
   n = 0;
   for (int i = 0; i < 3; i++) {
      int64_t st;
      void *at;
      int32_t rc = probe_chunk(&st, &at, PR_RW);
      const int32_t rc2 = rc == 0 ? sceKernelMprotect(at, PS5P_DIRECT_UNIT, PR_RX) : -1;
      probe_log("P7 after freeing all: i=%d map=%x rx=%x", i, (unsigned)rc, (unsigned)rc2);
      probe_release(st, at);
   }
   /* P8 */
   {
      const size_t big = (size_t)16 << 20;
      int64_t st = -1;
      void *at = NULL;
      int32_t rc = sceKernelAllocateDirectMemory(0, sceKernelGetDirectMemorySize(), big, PS5P_DIRECT_UNIT,
                                                 PS5_KERNEL_DIRECT_TYPE_CPU, &st);
      if (rc == 0)
         rc = sceKernelMapDirectMemory(&at, big, PR_RW, 0, st, PS5P_DIRECT_UNIT);
      const int32_t rc2 = rc == 0 ? sceKernelMprotect(at, big, PR_RX) : -1;
      probe_log("P8 16MiB after exhaustion: map=%x rx=%x", (unsigned)rc, (unsigned)rc2);
      if (at)
         sceKernelMunmap(at, big);
      if (st >= 0)
         sceKernelReleaseDirectMemory(st, big);
   }
   probe_log("probe done");
}
#else
static void exec_probe(void) {}
#endif
/* --- end probe --- */
'''

# 1. probe after the diagnostic helpers
replace("/* --- end diagnostic helpers --- */\n", "/* --- end diagnostic helpers --- */\n" + PROBE)

# 2. run it at the first commit
replace(
    "   atomic_fetch_add(&diag_calls, 1);\n",
    "   exec_probe();\n"
    "   atomic_fetch_add(&diag_calls, 1);\n",
)

open(path, "w", encoding="utf-8", newline="\n").write(s)
print("probe patched", path)
