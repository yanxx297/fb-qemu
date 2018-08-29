#ifndef __WHITEBOCHS_H__
#define __WHITEBOCHS_H__

#ifndef NEED_CPU_REG_SHORTCUTS
#define NEED_CPU_REG_SHORTCUTS
#endif
#include <cpu/cpu.h>
#include <debug.h>
#include <symbolic.h>
#include <stdlib.h>

extern BX_CPU_C bx_cpu;
extern BX_MEM_C bx_mem;
extern Bit8u bx_cpu_count;

extern char symbolic_execution;

#define CR0 (bx_cpu.cr0)
#define CR2 (bx_cpu.cr2)
#define CR3 (bx_cpu.cr3)
#if BX_CPU_LEVEL >= 4
#define CR4 (bx_cpu.cr4)
#endif
#if BX_CPU_LEVEL >= 3
#define DR0 (bx_cpu.dr[0])
#define DR1 (bx_cpu.dr[1])
#define DR2 (bx_cpu.dr[2])
#define DR3 (bx_cpu.dr[3])
#define DR6 (bx_cpu.dr6)
#define DR7 (bx_cpu.dr7)
#endif

// *****************************************************************************
// Debugging stuff
// *****************************************************************************
#define __bx_error__(...) {						\
    fprintf(__DEBUG_FILE__, "BOCHS ERROR (%s:%d): ", __FILE__, __LINE__); \
    fprintf(__DEBUG_FILE__, __VA_ARGS__);				\
    fprintf(__DEBUG_FILE__, "\n");					\
    fflush(__DEBUG_FILE__);						\
  }

#ifndef SILENT
#undef BX_ERROR
#define BX_ERROR(x)   __bx_error__ x
#endif

#define __bx_debug__(...) {						\
    fprintf(__DEBUG_FILE__, "BOCHS DEBUG (%s:%d): ", __FILE__, __LINE__); \
    fprintf(__DEBUG_FILE__, __VA_ARGS__);				\
    fprintf(__DEBUG_FILE__, "\n");					\
    fflush(__DEBUG_FILE__);						\
  }

#ifndef SILENT
#undef BX_DEBUG
#define BX_DEBUG(x)   __bx_debug__ x
#endif

#define __bx_panic__(...) {						\
    fprintf(__DEBUG_FILE__, "BOCHS PANIC (%s:%d): ", __FILE__, __LINE__); \
    fprintf(__DEBUG_FILE__, __VA_ARGS__);				\
    fprintf(__DEBUG_FILE__, "\n");					\
    fflush(__DEBUG_FILE__);						\
    abort();								\
  }

#ifndef SILENT
#undef BX_PANIC
#define BX_PANIC(x)   __bx_panic__ x
#endif

#define __bx_assert__(x) { \
    fprintf(__DEBUG_FILE__, "BOCHS ASSERT `%s' (%s:%d) failed\n", # x, \
	    __FILE__,							\
	    __LINE__);							\
    fflush(__DEBUG_FILE__);						\
    abort();								\
  }

#ifndef SILENT
#undef BX_ASSERT
#define BX_ASSERT(x) {				\
    if (!(x))					\
      __bx_assert__(x);				\
  }
#endif


#define __bx_info__(...) {			\
    fprintf(__DEBUG_FILE__, __VA_ARGS__);	\
    fprintf(__DEBUG_FILE__, "\n");		\
    fflush(__DEBUG_FILE__);			\
}

#ifndef SILENT
#undef BX_INFO
#define BX_INFO(x)     \
  if (DEBUG_LEVEL) \
    __bx_info__ x
#endif

#ifndef SILENT
#undef BX_DEBUG
#define BX_DEBUG(x)	   \
  debug2 x \
  debug2("\n");
#endif

// *****************************************************************************
// Translate a linear address to a physical address
// *****************************************************************************
static inline bx_phy_address translate_lin_to_phy(bx_address addr) {
  bx_phy_address paddr;
  bool r;

  r = bx_cpu.dbg_xlate_linear2phy(addr, &paddr);
  assert(r);

  return paddr;
}

static inline void *translate_guest_to_host(bx_phy_address paddr) {
  return bx_mem.getHostMemAddr(&bx_cpu, paddr, 0);
}

static inline bx_phy_address translate_host_to_guest(void *paddr) {
  return (bx_phy_address) (((Bit8u *) paddr) - ((Bit8u *) bx_mem.getHostMemAddr(&bx_cpu, 0, 0)));
}

static inline void *translate_lin_to_host(bx_address addr) {
  return translate_guest_to_host(translate_lin_to_phy(addr));
}

#define g2h(x) translate_guest_to_host(x)
#define h2g(x) translate_host_to_guest((void *) x)
#define l2h(x) translate_lin_to_host(x)
#define l2p(x) translate_lin_to_phy(x)

static inline void refresh_seg_selectors() {
  bx_segment_reg_t *seg;
  Bit16u raw_selector;

  for (unsigned i = 0; i < sizeof(bx_cpu.sregs) / sizeof(*bx_cpu.sregs); i++) {
    seg = &(bx_cpu.sregs[i]);
    raw_selector = seg->selector.value;
    seg->selector.index = raw_selector >> 3;
    seg->selector.ti    = (raw_selector >> 2) & 0x01;
    seg->selector.rpl   = raw_selector & 0x03;
  }

  seg = &(bx_cpu.tr);
  raw_selector = seg->selector.value;
  seg->selector.index = raw_selector >> 3;
  seg->selector.ti    = (raw_selector >> 2) & 0x01;
  seg->selector.rpl   = raw_selector & 0x03;

  seg = &(bx_cpu.ldtr);
  raw_selector = seg->selector.value;
  seg->selector.index = raw_selector >> 3;
  seg->selector.ti    = (raw_selector >> 2) & 0x01;
  seg->selector.rpl   = raw_selector & 0x03;

  bx_cpu.updateFetchModeMask();
}

static inline void refresh_seg_descriptors() {
  Bit32u dword1, dword2;
  bx_segment_reg_t *seg;

  // Update the hidden part of segment registers currently pointing to the
  // modified descriptor if needed (note that multiple segment registers can
  // point to the same segment)
  for (unsigned idx = 1; idx < bx_cpu.gdtr.limit / 8; idx++) { 
    for (unsigned i = 0; i < sizeof(bx_cpu.sregs) / sizeof(*bx_cpu.sregs); i++) {
      seg = &(bx_cpu.sregs[i]);
      if ((seg->selector.value >> 3) == idx) {
	bx_cpu.fetch_raw_descriptor(&seg->selector, &dword1, &dword2, 0xFFFF);
	parse_descriptor(dword1, dword2, &seg->cache);
      }
    }

    if (bx_cpu.tr.selector.value == idx) {
      seg = &(bx_cpu.tr);
      bx_cpu.fetch_raw_descriptor(&seg->selector, &dword1, &dword2, 0xFFFF);
      parse_descriptor(dword1, dword2, &seg->cache);
    }

#if 0
    if ((bx_cpu.ldtr.selector.value >> 3) == idx) {
      seg = &(bx_cpu.ldtr);
      bx_cpu.fetch_raw_descriptor(&seg->selector, &dword1, &dword2, 0xFFFF);
      parse_descriptor(dword1, dword2, &seg->cache);
    }
#endif
  }
}

// *****************************************************************************
// Concrete execution
// *****************************************************************************
#ifndef SYMBOLIC_EXECUTION

#define MAKE_REG_SYMBOLIC(x)
#define MAKE_SREG_SYMBOLIC(x)
#define MAKE_CREG_SYMBOLIC(x)
#define MAKE_DREG_SYMBOLIC(x)
#define MAKE_PHYS_MEM_SYMBOLIC(x, y)
#define MAKE_VIRT_MEM_SYMBOLIC(x, y)
#define MAKE_SEGMENT_SYMBOLIC(x)
#define MAKE_GDT_SYMBOLIC()
#define MAKE_REG_CONCRETE(x)
#define MAKE_SREG_CONCRETE(x)
#define MAKE_CREG_CONCRETE(x)
#define MAKE_DREG_CONCRETE(x)
#define MAKE_MEM_CONCRETE(x, y)
#define MAKE_SEGMENT_CONCRETE(x)
#define MAKE_PDE_SYMBOLIC(x)
#define MAKE_PTE_SYMBOLIC(x)
#define MAKE_PAGE_SYMBOLIC(x)
#define MAKE_PAGE_TABLE_SYMBOLIC(x)
#define MAKE_INTDESC_SYMBOLIC(x)
#define MAKE_IDT_SYMBOLIC()

#else // SYMBOLIC_EXECUTION

#define masked_assume(x, y, z) \
  ASSUME((y & z) == (y & z))

// *****************************************************************************
// Make the CPU state symbolic
// *****************************************************************************
template<typename V>
static inline void __make_symbolic(V *v, const char *n) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  V v_;
  
  debug3("__make_symbolic: %.8x-%.8x (%.8d) %s\n", v, 
	 ((size_t) v) + sizeof(V) - 1, sizeof(v_), n);

  MAKE_SYMBOLIC(v, &v_, sizeof(V), n);
  memcpy(v, &v_, sizeof(V));
}

static inline void __make_symbolic(void *v, size_t s, const char *n = NULL) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  void *v_;
  char tmp[64];
  
  sprintf(tmp, "%.8x%s%s", h2g(v), n && n[0] ? " " : "", n ? n : "");
  debug3("__make_symbolic: %.8x-%.8x (%.8d) %s\n", v, 
	 ((size_t) v) + s - 1, s, tmp);

  v_ = malloc(s);
  assert(v_);
  MAKE_SYMBOLIC(v, v_, s, tmp);
  memcpy(v, v_, s);
  free(v_);
}

// Segment selector (note: index is kept concrete)
static inline void __make_sreg_symbolic(bx_selector_t *sel, const char *n) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  // assert(IS_CONCRETE(sel->value));

  Bit16u concrete_value = sel->value;

  __make_symbolic(&(sel->value), n); 
  ASSUME_EQ_masked(sel->value, concrete_value, BX_SELECTOR_RPL_MASK);
  parse_selector(sel->value, sel);
}

// Control register 
static inline void __make_creg_symbolic(bx_cr0_t *cr0, const char *n) {
  ;
}

#if BX_CPU_LEVEL >= 4
static inline void __make_creg_symbolic(bx_cr4_t *cr4, const char *n) {
  ;
}
#endif

// Segment descriptor (note: base & limit are kept concrete)
static inline void __make_seg_symbolic(Bit16u idx) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  assert(bx_cpu.cpu_mode == BX_MODE_IA32_PROTECTED && "Unsupported CPU mode");
  // assert(IS_CONCRETE(bx_cpu.gdtr.base) && "GDT base must be concrete");

  bx_address gdt = bx_cpu.gdtr.base;
  Bit8u *gdt_entry = (Bit8u *) translate_lin_to_host(gdt + idx * 8);
  Bit8u gdt_entry_concrete[8];
  char tmp[64];

  // Skip if not symbolic ??
  if (!(gdt_entry[5] & 0x80)) {
    return;
  }

  // Backup the original content of the gdt 
  memcpy(&gdt_entry_concrete, gdt_entry, sizeof(gdt_entry_concrete));

  sprintf(tmp, "mem_%.8x GDT[%.4x]", gdt + idx * 8, idx);
  __make_symbolic(gdt_entry, 8, tmp);

  // Keep the base & limit concrete 
  // |---------------------------------------------|
  // |             Segment Descriptor              |
  // |---------------------------------------------|
  // |33222222|2|2|2|2| 11 11 |1|11|1|11  |        |
  // |10987654|3|2|1|0| 98 76 |5|43|2|1098|76543210|
  // |--------|-|-|-|-|-------|-|--|-|----|--------|
  // |Base    |G|D|L|A|Limit  |P|D |S|Type|Base    |
  // |[31-24] | |/| |V|[19-16]| |P | |    |[23-16] |
  // |        | |B| |L|       | |L | |    |        |
  // |------------------------|--------------------|
  // |       Base [15-0]      |    Limit [15-0]    |
  // |------------------------|--------------------|
  // base 
  ASSUME_EQ(gdt_entry[2], gdt_entry_concrete[2]);
  ASSUME_EQ(gdt_entry[3], gdt_entry_concrete[3]);
  ASSUME_EQ(gdt_entry[4], gdt_entry_concrete[4]);
  ASSUME_EQ(gdt_entry[7], gdt_entry_concrete[7]);
  // limit
  ASSUME_EQ(gdt_entry[0], gdt_entry_concrete[0]);
  ASSUME_EQ(gdt_entry[1], gdt_entry_concrete[1]);
  // limit & g
  ASSUME_EQ_masked(gdt_entry[6], gdt_entry_concrete[6], 0xf | 0x80);
  // s
  ASSUME_EQ_masked(gdt_entry[5], gdt_entry_concrete[5], 0x10);
}

#define BX_CR3_PAGING_MASK    (BX_CONST64(0x000ffffffffff000))

#define shift(a, n) \
  (((a) >> (n*8)) & 0xff)
#define add(a, n) \
  (*(((unsigned char *) (&(a))) + n))

#define assume_eq_dword_masked(a, b, m) {			\
    ASSUME_EQ_masked(add(a, 0), shift(a, 0), shift(m, 0));	\
    ASSUME_EQ_masked(add(a, 1), shift(a, 1), shift(m, 1));	\
    ASSUME_EQ_masked(add(a, 2), shift(a, 2), shift(m, 2));	\
    ASSUME_EQ_masked(add(a, 3), shift(a, 3), shift(m, 3));	\
  }

static inline void __make_pte_symbolic(bx_phy_address pte) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  assert(bx_cpu.cpu_mode == BX_MODE_IA32_PROTECTED && "Unsupported CPU mode");
  assert(bx_cpu.cr0.get_PG() && "Paging not enabled");
#if BX_CPU_LEVEL >= 6
  assert(bx_cpu.cr4.get_PAE() && "PAE not supported");
#endif

  bx_phy_address *pte_host = (bx_phy_address *) g2h(pte);
  bx_phy_address pte_concrete;
  char tmp[64];

  // Backup the original content of the pte
  pte_concrete = *pte_host;

  if (!(pte_concrete & 0x1)) {
    // Entry not present, skip it
    return;
  }

  sprintf(tmp, "mem_%.8x PTE", (size_t) -1);
  __make_symbolic(pte_host, sizeof(pte_concrete), tmp);

  // Format of a 32-Bit Page-Table Entry that Maps a 4-KByte Page
  // -----------------------------------------------------------
  // 00    | Present (P)
  // 01    | R/W
  // 02    | U/S
  // 03    | Page-Level Write-Through (PWT)
  // 04    | Page-Level Cache-Disable (PCD)
  // 05    | Accessed (A)
  // 06    | Dirty (D)
  // 07    | PAT (if PAT is supported, reserved otherwise)
  // 08    | Global (G) (if CR4.PGE=1, ignored otherwise)
  // 11-09 | (ignored)
  // 31-12 | Physical address of the 4-KByte page
  // -----------------------------------------------------------
  // Concretize the physical address [31-12]
#define pte_host ((unsigned char *) pte_host)
#define pte_concrete ((unsigned char *) &pte_concrete)

  // ASSUME_EQ(pte_host[0], pte_concrete[0]);
  ASSUME_EQ(pte_host[1], pte_concrete[1]);
  ASSUME_EQ(pte_host[2], pte_concrete[2]);
  ASSUME_EQ(pte_host[3], pte_concrete[3]);

#undef pte_host
#undef pte_concrete
}

static inline void __make_pde_symbolic(bx_phy_address pde, bool rec = false) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  assert(bx_cpu.cpu_mode == BX_MODE_IA32_PROTECTED && "Unsupported CPU mode");
  assert(bx_cpu.cr0.get_PG() && "Paging not enabled");
#if BX_CPU_LEVEL >= 6
  assert(bx_cpu.cr4.get_PAE() && "PAE not supported");
#endif

  bx_phy_address *pde_host = (bx_phy_address *) g2h(pde);
  bx_phy_address pde_concrete;
  char tmp[32];

  // Backup the original content of the pde
  pde_concrete = *pde_host;

  if (!(pde_concrete & 0x1)) {
    // Entry not present, skip it
    return;
  }

  // Make entries of the page table as symbolic as well
  if (rec) {
    for (int i = 0; i < (1 << 10); i++) {
      bx_phy_address *pte = ((bx_phy_address *) g2h(pde_concrete & BX_CR3_PAGING_MASK)) + i;
      // Make symbolic only pages that are effectively present
      if (*pte & 0x1) {
	__make_pte_symbolic(h2g(pte));
      }
    }
  }

  sprintf(tmp, "mem_%.8x PDE", (size_t) -1);
  __make_symbolic(pde_host, sizeof(pde_concrete), tmp);

  // Format of a 32-Bit Page-Directory Entry that References a Page Table
  // -----------------------------------------------------------
  // 00    | Present (P)
  // 01    | R/W
  // 02    | U/S
  // 03    | Page-Level Write-Through (PWT)
  // 04    | Page-Level Cache-Disable (PCD)
  // 05    | Accessed (A)
  // 06    | (ignored)
  // 07    | Page size (If CR4.PSE = 1, must be 0 (otherwise, this entry maps a
  //       |  4-MByte page); otherwise, ignored
  // 11-08 | (ignored)
  // 31-12 | Physical address of the 4-KByte page
  // -----------------------------------------------------------
  // Concretize the physical address [31-12], the page size [7], and the
  // presence bit [0]
#define pde_host ((unsigned char *) pde_host)
#define pde_concrete ((unsigned char *) &pde_concrete)

  // ASSUME_EQ(pde_host[0], pde_concrete[0]);
  ASSUME_EQ(pde_host[1], pde_concrete[1]);
  ASSUME_EQ(pde_host[2], pde_concrete[2]);
  ASSUME_EQ(pde_host[3], pde_concrete[3]);

#undef pde_host
#undef pde_concrete
}

static inline void __make_page_symbolic(bx_address page) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  ;
}

// Walk the page table and set each PDE/PTE as symbolic
static inline void __make_page_table_symbolic(bx_phy_address pagtab) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  assert(bx_cpu.cpu_mode == BX_MODE_IA32_PROTECTED && "Unsupported CPU mode");
  assert(bx_cpu.cr0.get_PG() && "Paging not enabled");
#if BX_CPU_LEVEL >= 6
  assert(bx_cpu.cr4.get_PAE() && "PAE not supported");
#endif

  debug("CR3: %.8x\n", pagtab);

  // 32-bit protected mode, no PAE
  for (int i = 0; i < (1 << 10); i++) {
    bx_phy_address *pde = ((bx_phy_address *) g2h(pagtab & BX_CR3_PAGING_MASK)) + i;
    // Make symbolic only pages that are effectively present
    if (*pde & 0x1) {
      debug("PDE %d %.8x\n", i, *pde);
      __make_pde_symbolic(h2g(pde), true);
    }
  }
}

#undef shift
#undef add
#undef assume_eq_dword_masked

// Interrupt descriptor
static inline void __make_intdesc_symbolic(Bit16u idx) {
#if defined(FUZZBALL)
  if (!FUZZBALL_DRYRUN)
    return;
#endif

  // assert(IS_CONCRETE(bx_cpu.idtr.base) && "IDT base must be concrete");
  bx_address idt = bx_cpu.idtr.base;
  Bit8u *idt_entry = (Bit8u *) translate_lin_to_host(idt + idx * 8);
  Bit8u idt_entry_concrete[8];
  char tmp[64];

  // Backup the original content of the idt 
  memcpy(&idt_entry_concrete, idt_entry, sizeof(idt_entry_concrete));

  sprintf(tmp, "mem_%.8x IDT[%.4x]", idt + idx * 8, idx);
  __make_symbolic(idt_entry, 8, tmp);

  // Offset 
  ASSUME_EQ(idt_entry[0], idt_entry_concrete[0]);
  ASSUME_EQ(idt_entry[1], idt_entry_concrete[1]);
  ASSUME_EQ(idt_entry[6], idt_entry_concrete[6]);
  ASSUME_EQ(idt_entry[7], idt_entry_concrete[7]);
  // Selector
  ASSUME_EQ(idt_entry[2], idt_entry_concrete[2]);
  ASSUME_EQ(idt_entry[3], idt_entry_concrete[3]);
  // D (16 or 32 bit)
  ASSUME_EQ_masked(idt_entry[5], idt_entry_concrete[5], 0x8);
#undef mask  
}

#define MAKE_REG_SYMBOLIC(x) \
  __make_symbolic(&(x), "reg_" #x)

#define MAKE_SREG_SYMBOLIC(x)						\
  __make_sreg_symbolic(&(bx_cpu.sregs[BX_SEG_REG_##x].selector), "sreg_" #x)
  
#define MAKE_CREG_SYMBOLIC(x) \
  __make_creg_symbolic(&(x), "creg_" #x);

#define MAKE_DREG_SYMBOLIC(x) 

#define MAKE_PHYS_MEM_SYMBOLIC(x, y)	{				\
    assert((LPFOf(x) == LPFOf(x + y)) &&				\
	   "Symbolic buffer crosses page boundary");			\
    char tmp[64];							\
    sprintf(tmp, "mem_%.8x %s", (size_t) -1, #x);				\
    __make_symbolic(g2h(x), (y), tmp);					\
  }
  
#define MAKE_VIRT_MEM_SYMBOLIC(x, y)   {				\
    assert((LPFOf(x) == LPFOf(x + y)) &&				\
	   "Symbolic buffer crosses page boundary");			\
    char tmp[64];							\
    sprintf(tmp, "%.8x %s", x, #x);					\
    __make_symbolic(translate_lin_to_host(x), (y), tmp);		\
  }

#define MAKE_SEGMENT_SYMBOLIC(x) \
  __make_seg_symbolic(x);

#define MAKE_GDT_SYMBOLIC() {					  \
    for (unsigned idx = 0; idx < bx_cpu.gdtr.limit / 8; idx++) {  \
      MAKE_SEGMENT_SYMBOLIC(idx);				  \
    }								  \
  }

#define MAKE_PDE_SYMBOLIC(x) \
  __make_pde_symbolic(x)

#define MAKE_PTE_SYMBOLIC(x) \
  __make_pte_symbolic(x)
  
#define MAKE_PAGE_SYMBOLIC(x) \
  __make_page_symbolic(x)

#define MAKE_PAGE_TABLE_SYMBOLIC(x) \
  __make_page_table_symbolic(x)

#define MAKE_INTDESC_SYMBOLIC(x) \
  __make_intdesc_symbolic(x);

#define MAKE_IDT_SYMBOLIC() {					  \
    for (unsigned idx = 0; idx < bx_cpu.idtr.limit / 8; idx++) {  \
      MAKE_INTDESC_SYMBOLIC(idx);				  \
    }								  \
  }

#define MAKE_REG_CONCRETE(x)			\
  x = __concretize(x);
 
#define MAKE_SREG_CONCRETE(x, y)				      \
  parse_selector(__concretize(bx_cpu.sregs[BX_SEG_REG_##x].selector), \
		 &(bx_cpu.sregs[BX_SEG_REG_##x].selector))    
    
#define MAKE_CREG_CONCRETE(x)			\
  x = __concretize(x);
 
#define MAKE_DREG_CONCRETE(x)			\
  x = __concretize(x);
 
#define MAKE_MEM_CONCRETE(x, y) \
  __concretize((void*) x, y);

#define MAKE_SEGMENT_CONCRETE(x) 

#ifdef KLEE
void at_exit();

#undef longjmp
#define longjmp(x, j)			       \
  fprintf(__DEBUG_FILE__, "longjmp %s\n", #x); \
  exit(0);
#endif

#endif

#endif // !__WHITEBOCHS_H__
