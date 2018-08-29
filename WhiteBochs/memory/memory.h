/////////////////////////////////////////////////////////////////////////
// $Id: memory.h,v 1.68 2010/03/07 09:16:24 sshwarts Exp $
/////////////////////////////////////////////////////////////////////////
//
//  Copyright (C) 2001-2009  The Bochs Project
//
//  I/O memory handlers API Copyright (C) 2003 by Frank Cornelis
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

#ifndef BX_MEM_H
#  define BX_MEM_H 1

// if static member functions on, then there is only one memory
#define BX_MEM_SMF  static
#define BX_MEM_THIS BX_MEM(0)->

class BX_CPU_C;

class BOCHSAPI BX_MEM_C {
private:
  Bit8u   *vector;   // aligned correctly
  Bit64u  len;
  Bit64u  allocated;  
  Bit8u   *actual_vector;

  Bit8u* alloc_vector_aligned(Bit32u bytes, Bit32u alignment);

public:
  BX_MEM_C();
 ~BX_MEM_C();

  BX_MEM_SMF void    init_memory(Bit64u host);
  BX_MEM_SMF void    readPhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
                                      unsigned len, void *data);
  BX_MEM_SMF void    dbg_fetch_mem(BX_CPU_C *cpu, bx_phy_address addr,
				   unsigned len, void *data);
  BX_MEM_SMF void    writePhysicalPage(BX_CPU_C *cpu, bx_phy_address addr,
                                       unsigned len, void *data);
  BX_MEM_SMF Bit8u* getHostMemAddr(BX_CPU_C *cpu, bx_phy_address addr, 
				   unsigned rw);
  BX_MEM_SMF Bit64u get_memory_len(void);
};

BOCHSAPI extern BX_MEM_C bx_mem;

// must be power of two
#define BX_MEM_BLOCK_LEN (1024*1024) /* 1M blocks */

BX_CPP_INLINE Bit64u BX_MEM_C::get_memory_len(void)
{
  return (BX_MEM_THIS len);
}

#endif
