#!/usr/bin/env python3
"""PS5 firmware 7.40: executable memory must be set up before the game boots.

Measured on a retail PS5 on 7.40 (tools/ci/patch-exec-probe.py): early in a game boot the
process loses, permanently, the ability to make any mapping executable (sceKernelMprotect with
EXEC returns 0x8002000d for new mappings, aliases, anonymous memory, and even for a mapping that
was executable before). Mappings that are already executable keep working as long as their
protection is never changed. PS5X360 (Xenia) is unaffected because its code cache is created
and made executable once at startup.

This patch gives RPCS3 the same shape:
  1. util/vm_native.cpp (PS5): JIT reservations (memory_reserve with can_be_jit) are served from
     one pool of direct memory, mapped and made RWX once at first use (startup); commit, decommit,
     protect, reset and release inside the pool make no kernel calls.
  2. Utilities/JITLLVM.cpp (PS5): the linking JIT uses MemoryManager2, whose sections come from
     jit_runtime's shared region (inside the pool), instead of MemoryManager1's 768 MiB region per
     module (hundreds of them, each needing new executable commits).

Pool size: RPCS3_PS5_EXEC_POOL_MB (default 2112: jit_runtime's 2 GiB plus its 16 MiB runtime and
slack). Usage: patch-rpcs3-execpool.py <src/rpcs3>
"""
import os, sys

root = sys.argv[1]

def patch(path, pairs):
    s = open(path, encoding="utf-8").read()
    for old, new in pairs:
        assert s.count(old) == 1, (path, old[:60])
        s = s.replace(old, new, 1)
    open(path, "w", encoding="utf-8", newline="\n").write(s)
    print("patched", path)

vm = os.path.join(root, "rpcs3/util/vm_native.cpp")
POOL = r'''
#ifdef __PROSPERO__
// PS5 firmware 7.40: one executable pool, granted at startup, never re-protected (see
// tools/ci/patch-rpcs3-execpool.py in rpcs3-PS5).
namespace
{
	struct ps5_exec_pool
	{
		u8* base = nullptr;
		usz size = 0;
		usz used = 0;
		bool tried = false;
		shared_mutex mutex;

		bool contains(const void* p) const
		{
			const u8* q = static_cast<const u8*>(p);
			return base && q >= base && q < base + size;
		}

		void create()
		{
			tried = true;
			usz mb = 2112;
			if (const char* env = std::getenv("RPCS3_PS5_EXEC_POOL_MB"))
			{
				if (const auto v = std::strtoull(env, nullptr, 10); v >= 64 && v <= 8192) mb = v;
			}
			const usz bytes = mb << 20;
			s64 start = -1;
			if (const int rc = ::sceKernelAllocateDirectMemory(0, ::sceKernelGetDirectMemorySize(), bytes, 0x200000, PS5_KERNEL_DIRECT_TYPE_CPU, &start); rc != 0)
			{
				std::fprintf(stderr, "ps5 exec pool: direct memory (%zu MiB) failed: 0x%x\n", mb, static_cast<u32>(rc));
				return;
			}
			void* at = nullptr;
			if (const int rc = ::ps5_vrange_reserve(bytes, reinterpret_cast<void*>(0x30'0000'0000ull), 0x200000, &at); rc != 0)
			{
				std::fprintf(stderr, "ps5 exec pool: reserve failed: 0x%x\n", static_cast<u32>(rc));
				::sceKernelReleaseDirectMemory(start, bytes);
				return;
			}
			void* mapped = at;
			if (const int rc = ::sceKernelMapDirectMemory(&mapped, bytes, PS5_KERNEL_PROT_CPU_READ | PS5_KERNEL_PROT_CPU_WRITE, PS5_KERNEL_MAP_FIXED, start, 0x200000); rc != 0 || mapped != at)
			{
				std::fprintf(stderr, "ps5 exec pool: map failed: 0x%x\n", static_cast<u32>(rc));
				if (rc == 0) ::sceKernelMunmap(mapped, bytes);
				::ps5_vrange_release(at, bytes);
				::sceKernelReleaseDirectMemory(start, bytes);
				return;
			}
			std::memset(mapped, 0, bytes);
			if (const int rc = ::sceKernelMprotect(mapped, bytes, PS5_KERNEL_PROT_CPU_READ | PS5_KERNEL_PROT_CPU_WRITE | PS5_KERNEL_PROT_CPU_EXEC); rc != 0)
			{
				std::fprintf(stderr, "ps5 exec pool: RWX protect failed: 0x%x\n", static_cast<u32>(rc));
				::sceKernelMunmap(mapped, bytes);
				::ps5_vrange_release(at, bytes);
				::sceKernelReleaseDirectMemory(start, bytes);
				return;
			}
			base = static_cast<u8*>(mapped);
			size = bytes;
			std::fprintf(stderr, "ps5 exec pool: %zu MiB RWX at %p\n", mb, mapped);
		}

		void* take(usz bytes)
		{
			std::lock_guard lock(mutex);
			if (!tried) create();
			if (!base) return nullptr;
			const usz aligned = utils::align(used, 0x10000);
			if (aligned + bytes > size)
			{
				std::fprintf(stderr, "ps5 exec pool: out of pool (%zu MiB asked, %zu used of %zu)\n", bytes >> 20, used >> 20, size >> 20);
				return nullptr;
			}
			used = aligned + bytes;
			return base + aligned;
		}
	};

	ps5_exec_pool g_ps5_exec_pool;
}
#endif
'''

patch(vm, [
    # the pool, right after the PS5 includes
    ("#ifdef __PROSPERO__\n#include <ps5platform/kernel.h>\n#include <ps5platform/shm.h>\n",
     "#ifdef __PROSPERO__\n#include <ps5platform/kernel.h>\n#include <ps5platform/shm.h>\n#include <cstdlib>\n#include <cstring>\n" + POOL),
    # memory_reserve: JIT reservations come from the pool
    ("		// budget: reserve address space with the platform layer (never inside the GPU window).\n		// Committed memory is direct memory, see memory_commit.\n		if (use_addr && reinterpret_cast<uptr>(use_addr) % 0x10000)\n",
     "		// budget: reserve address space with the platform layer (never inside the GPU window).\n		// Committed memory is direct memory, see memory_commit.\n		if (can_be_jit && !use_addr)\n		{\n			if (void* slice = g_ps5_exec_pool.take(utils::align(size, 0x10000)))\n			{\n				return slice;\n			}\n		}\n		if (use_addr && reinterpret_cast<uptr>(use_addr) % 0x10000)\n"),
    # memory_commit
    ("#elif defined(__PROSPERO__)\n		if (const int rc = ps5_vrange_commit(pointer, size, +prot); rc != 0)\n		{\n			fmt::throw_exception(\"ps5_vrange_commit(%p, 0x%x, %d) failed: 0x%x\", pointer, size, +prot, static_cast<u32>(rc));\n		}\n#else\n		const u64 ptr64 = reinterpret_cast<u64>(pointer);\n		ensure(::mprotect(reinterpret_cast<void*>(ptr64 & -get_page_size()), size + (ptr64 & (get_page_size() - 1)), +prot) != -1);\n",
     "#elif defined(__PROSPERO__)\n		if (g_ps5_exec_pool.contains(pointer)) return; // already RWX and backed\n		if (const int rc = ps5_vrange_commit(pointer, size, +prot); rc != 0)\n		{\n			fmt::throw_exception(\"ps5_vrange_commit(%p, 0x%x, %d) failed: 0x%x\", pointer, size, +prot, static_cast<u32>(rc));\n		}\n#else\n		const u64 ptr64 = reinterpret_cast<u64>(pointer);\n		ensure(::mprotect(reinterpret_cast<void*>(ptr64 & -get_page_size()), size + (ptr64 & (get_page_size() - 1)), +prot) != -1);\n"),
    # memory_decommit
    ("#elif defined(__PROSPERO__)\n		ensure(ps5_vrange_decommit(pointer, size) == 0, \"ps5_vrange_decommit failed\");\n#else\n		const u64 ptr64 = reinterpret_cast<u64>(pointer);\n#if defined(__APPLE__) && defined(ARCH_ARM64)\n		// Hack: on macOS, Apple explicitly fails mmap if you combine MAP_FIXED and MAP_JIT.\n",
     "#elif defined(__PROSPERO__)\n		if (g_ps5_exec_pool.contains(pointer)) return; // pool memory stays mapped\n		ensure(ps5_vrange_decommit(pointer, size) == 0, \"ps5_vrange_decommit failed\");\n#else\n		const u64 ptr64 = reinterpret_cast<u64>(pointer);\n#if defined(__APPLE__) && defined(ARCH_ARM64)\n		// Hack: on macOS, Apple explicitly fails mmap if you combine MAP_FIXED and MAP_JIT.\n"),
    # memory_reset
    ("#elif defined(__PROSPERO__)\n		ensure(ps5_vrange_decommit(pointer, size) == 0, \"ps5_vrange_decommit failed\");\n		if (const int rc = ps5_vrange_commit(pointer, size, +prot); rc != 0)\n",
     "#elif defined(__PROSPERO__)\n		if (g_ps5_exec_pool.contains(pointer)) { std::memset(pointer, 0, size); return; }\n		ensure(ps5_vrange_decommit(pointer, size) == 0, \"ps5_vrange_decommit failed\");\n		if (const int rc = ps5_vrange_commit(pointer, size, +prot); rc != 0)\n"),
    # memory_release
    ("#elif defined(__PROSPERO__)\n		ensure(ps5_vrange_release(pointer, size) == 0, \"ps5_vrange_release failed\");\n",
     "#elif defined(__PROSPERO__)\n		if (g_ps5_exec_pool.contains(pointer)) return; // the pool is never released\n		ensure(ps5_vrange_release(pointer, size) == 0, \"ps5_vrange_release failed\");\n"),
    # memory_protect
    ("#ifdef __PROSPERO__\n		{\n			const u64 addr64 = reinterpret_cast<u64>(pointer);\n			const u64 page = PS5_KERNEL_PAGE_SIZE;\n",
     "#ifdef __PROSPERO__\n		{\n			if (g_ps5_exec_pool.contains(pointer)) return; // stays RWX: a protection change would be refused\n			const u64 addr64 = reinterpret_cast<u64>(pointer);\n			const u64 page = PS5_KERNEL_PAGE_SIZE;\n"),
])

jit = os.path.join(root, "Utilities/JITLLVM.cpp")
patch(jit, [
    ("	else\n	{\n		mem = std::make_unique<MemoryManager1>(std::move(symbols_cement));\n	}\n",
     "	else\n	{\n#ifdef __PROSPERO__\n		// PS5 7.40: code must come from the executable pool jit_runtime lives in (see\n		// tools/ci/patch-rpcs3-execpool.py in rpcs3-PS5), not a fresh region per module.\n		mem = std::make_unique<MemoryManager2>(std::move(symbols_cement));\n		null_mod->setTargetTriple(llvm::Triple(jit_compiler::triple2()));\n#else\n		mem = std::make_unique<MemoryManager1>(std::move(symbols_cement));\n#endif\n	}\n"),
])
print("exec pool patch applied")
