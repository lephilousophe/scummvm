/* ScummVM - Graphic Adventure Engine
 *
 * ScummVM is the legal property of its developers, whose names
 * are too numerous to list here. Please refer to the COPYRIGHT
 * file distributed with this source distribution.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#define FORBIDDEN_SYMBOL_ALLOW_ALL
#include "common/scummsys.h"

#if defined(DYNAMIC_MODULES) && defined(RISCOS)

#include "backends/plugins/riscos/riscos-provider.h"
#include "backends/plugins/elf/arm-loader.h"

#include "common/debug.h"

#include <kernel.h>
#include <swis.h>

// By declaring this variable we force libunixlib to always use dynamic areas for data allocations
// This frees up space for plugins and allows to have plenty of space for data
const char *const __dynamic_da_name = "ScummVM Heap";

// HACK: These two function are part of private API in libunixlib
// They let allocate and free data in the application space where the stack is placed below 64MB
// When using malloc with big chunks we end up in memory mapped areas above 64MB
extern "C" {
extern void *__stackalloc (size_t __size);
extern void __stackfree (void *__ptr);
}

// HACK: This is needed so that standard library functions that are only
// used in plugins can be found in the main executable.
void pluginHack() {
	volatile float f = 0.0f;
	volatile double d = 0.0;
	volatile int i = 0;

	byte *b = new (std::nothrow) byte[100];

	f = tanhf(f);
	f = logf(f);
	f = log10f(f);
	f = lroundf(f);
	f = expf(f);
	f = frexpf(f, NULL);
	f = ldexpf(f, 1);
	f = fmaxf(f, f);
	f = fminf(f, f);
	f = truncf(f);

	d = nearbyint(d);

	i = strcoll("dummyA", "dummyB");

	rename("dummyA", "dummyB");

	delete[] b;
}

class RiscOSDLObject : public ARMDLObject {
protected:
	void flushDataCache(void *ptr, uint32 len) const override {
		_kernel_swi_regs regs;

		regs.r[0] = 1;
		regs.r[1] = (int)ptr;
		regs.r[2] = (int)ptr + len;

		_kernel_swi(OS_SynchroniseCodeAreas, &regs, &regs);
	}

};

/**
 * On 26-bit RISC OS, plugins need to be allocated in the first 64 MB
 * of RAM so that it can be executed. This may not be the case when using
 * the default allocators, which use dynamic areas for large allocations.
 * We first try to allocate in Application Space which is now unused
 * because we use dynamic areas.
 * If it fails because AS is full, we fallback on the RMA space shared by
 * all applications. This is not great but it's the only space left.
 * TODO: Make more of an effort to free the memory in the event of a crash.
 */
class RiscOSDLObject_26bits : public RiscOSDLObject {
protected:
	/* We know that our pointer will be under 26-bit mark but our ptr is 32-bits
	 * Use the high-order bit to store that we used the RMA
	 */
	STATIC_ASSERT(sizeof(uintptr) == 4, uintptr_must_be_32_bits);
	static const uintptr RMA_FLAG = 0x80000000;

	uintptr doAllocate(uint32 size) {
		uintptr p = (uintptr)__stackalloc(size);
		if (!p) {
			// No more space in Application Space: let's take memory in RMA
			_kernel_swi_regs regs;
			_kernel_oserror *error;

			regs.r[0] = 6;
			regs.r[3] = size;

			if ((error = _kernel_swi(OS_Module, &regs, &regs)) == NULL) {
				p = regs.r[2];
				if (p) {
					p |= RMA_FLAG;
				}
			} else {
				debug(8, "OS_Module failed %d (%s)", error->errnum, error->errmess);
				p = 0;
			}
		}
		return p;
	}

	void doFree(uintptr ptr) {
		if (ptr & RMA_FLAG) {
			ptr &= ~RMA_FLAG;

			_kernel_swi_regs regs;

			regs.r[0] = 7;
			regs.r[2] = ptr;

			_kernel_swi(OS_Module, &regs, &regs);
		} else {
			__stackfree((void *)ptr);
		}

	}

	void *allocateMemory(uint32 align, uint32 size) override {
		if (align < sizeof(uintptr)) {
			// Make sure we are also aligned to store the uintptr in header
			align = sizeof(uintptr);
		}

		// Allocate with worst case alignment
		size += sizeof(uintptr) + align - 1;

		uintptr p = doAllocate(size);
		if (!p) {
			// We can't allocate: fail gracefully
			return nullptr;
		}

		uintptr np = (p + sizeof(uintptr) + align - 1) & ~(align -1);
		// Clear high-order bit which stores whether we are in RMA or not
		np &= ~RMA_FLAG;

		*((uintptr *)np - 1) = p;

		debug(8, "Allocated 0x%08x while alignment was %d: using %p", p, align, (void *)np);

		return (void *)np;
	}

	void deallocateMemory(void *ptr, uint32 size) override {
		uintptr p = *((uintptr *)ptr - 1);

		debug(8, "Freeing %p which was allocated at 0x%08x", ptr, p);
		doFree(p);
	}
};

RiscOSPluginProvider::RiscOSPluginProvider() : _is32bit(false) {
	__asm__ volatile (
		"SUBS	%[is32bit], r0, r0\n\t" /* Set at least one status flag and set is32bits to 0 */
		"TEQ	pc, pc\n\t"				/* First operand never contains flags while second one contains them in 26-bits only */
		"MOVEQ	%[is32bit], #1\n\t"		/* Set to 1 only if EQ flag is set */
		: [is32bit] "=r" (_is32bit)
		: /* no inputs */
		: "cc");
}

Plugin *RiscOSPluginProvider::createPlugin(const Common::FSNode &node) const {
	if (_is32bit) {
		return new TemplatedELFPlugin<RiscOSDLObject>(node.getPath());
	} else {
		return new TemplatedELFPlugin<RiscOSDLObject_26bits>(node.getPath());
	}
}

#endif // defined(DYNAMIC_MODULES) && defined(RISCOS)
