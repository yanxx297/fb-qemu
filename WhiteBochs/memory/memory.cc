/////////////////////////////////////////////////////////////////////////
// $Id: memory.cc,v 1.82 2009/12/04 16:53:12 sshwarts Exp $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2009  The Bochs Project
//
//  This library is free software; you can redistribute it and/or
//  modify it under the terms of the GNU Lesser General Public
//  License as published by the Free Software Foundation; either
//  version 2 of the License, or (at your option) any later version.
//
//  This library is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
//  Lesser General Public License for more details.
//
//  You should have received a copy of the GNU Lesser General Public
//  License along with this library; if not, write to the Free Software
//  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301 USA
//
/////////////////////////////////////////////////////////////////////////

#include "bochs.h"
#include "memory.h"
#include <whitebochs.h>
#include <sys/mman.h>

#define BX_MEM_VECTOR_ALIGN 4096

/* STRALIGN returns the number of bytes to add to a pointer to make it
 * point to a (unsigned long)-aligned piece of memory */
#define STRALIGN(x) ((((uintptr_t)x+sizeof(long)-1)&(-sizeof(long)))-(uintptr_t)x)
#define UNALIGNED(x,y) (((unsigned long)x & (sizeof (unsigned long)-1)) ^ ((unsigned long)y & (sizeof (unsigned long)-1)))

BX_MEM_C::BX_MEM_C() {
  actual_vector = vector = NULL;
  len    = 0;
}


Bit8u* BX_MEM_C::alloc_vector_aligned(Bit32u bytes, Bit32u alignment) {
#if 0
  Bit64u test_mask = alignment - 1;

  BX_MEM_THIS actual_vector = new Bit8u [(Bit32u)(bytes + test_mask)];
  if (BX_MEM_THIS actual_vector == 0) {
    BX_PANIC(("alloc_vector_aligned: unable to allocate host RAM !"));
    return 0;
  }
  // round address forward to nearest multiple of alignment.  Alignment
  // MUST BE a power of two for this to work.
  Bit64u masked = ((Bit64u)(BX_MEM_THIS actual_vector + test_mask)) & ~test_mask;
  Bit8u *vector = (Bit8u *) masked;
  // sanity check: no lost bits during pointer conversion
  assert(sizeof(masked) >= sizeof(vector));
  // sanity check: after realignment, everything fits in allocated space
  assert(vector+bytes <= BX_MEM_THIS actual_vector+bytes+test_mask);
#else
  void *physmem_base = (void*) 0x70000000;
  assert(bytes % 4096 == 0);
  vector = (Bit8u *) mmap(physmem_base, bytes, PROT_WRITE | PROT_READ, 
			  MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
  
  assert(vector == physmem_base);
#endif

  actual_vector = vector;

  return vector;
}


BX_MEM_C::~BX_MEM_C() {
  ;
}

void BX_MEM_C::init_memory(Bit64u guest) {
  BX_MEM_THIS vector = BX_MEM_THIS alloc_vector_aligned(guest + 4096, BX_MEM_VECTOR_ALIGN);
  BX_MEM_THIS len = guest;
}

Bit8u* BX_MEM_C::getHostMemAddr(bx_cpu_c* cpu, bx_phy_address addr, 
				unsigned int rw) {
  assert(addr < BX_MEM_THIS len);
  return BX_MEM_THIS vector + addr;
}

inline void dump_mem(unsigned char *data, unsigned len) {
  for (unsigned i = 0; i < len; i++) {
    debug(" %.2x", data[i]);
  }
}

// A modified version of memcpy from diet libc (https://www.fefe.de/dietlibc/)
void *memcpy_diet (void *dst, const void *src, size_t n)
{
    void           *res = dst;
    unsigned char  *c1, *c2;
    int             tmp;
    unsigned long  *lx1 = NULL;
    const unsigned long *lx2 = NULL;

    if ((tmp = STRALIGN(dst))) {
      c1 = (unsigned char *) dst;
      c2 = (unsigned char *) src;
      while (tmp-- && n--)
	*c1++ = *c2++;
      if (n == (size_t) - 1)
	return (res);
      dst = c1;
      src = c2;
    }

    lx1 = (unsigned long *) dst;
    lx2 = (unsigned long *) src;

    for (; n >= sizeof(unsigned long); n -= sizeof(unsigned long))
      *lx1++ = *lx2++;

    if (n) {
        c1 = (unsigned char *) (lx1?lx1:dst);
        c2 = (unsigned char *) (lx1?lx2:src);
        while (n--)
            *c1++ = *c2++;
    }

    return (res);
}


void BX_MEM_C::writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
				 unsigned len, void *data) {
  memcpy_diet(BX_MEM_THIS vector + addr, data, len);
}

void BX_MEM_C::readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr, 
				unsigned len, void *data) {
  memcpy_diet(data, BX_MEM_THIS vector + addr, len);

}

void BX_MEM_C::dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr, unsigned len, 
			     void *data) {
  memcpy_diet(data, BX_MEM_THIS vector + addr, len);
}
