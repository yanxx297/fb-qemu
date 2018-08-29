#define XGLUE(x, y) x ## y
#define GLUE(x, y) XGLUE(x, y)

#if defined(SAVING)

#define OP        save
#define SEG(x, y) save_segment(x, y)
#define TAB(x, y) save_table(x, y)
#define MSR(x)    save_msr(x)
#define REG(x, y) (x = y)

#elif defined(LOADING)

#define OP        load
#define SEG(x, y) load_segment(x, y)
#define TAB(x, y) load_table(x, y)
#define MSR(x)    load_msr(x)
#define REG(x, y) (y = x)

#else

#error "Invalid argument"

#endif

#if 0
static Bit8u pack_FPU_TW(Bit16u twd) {
  Bit8u tag_byte = 0;

  if((twd & 0x0003) != 0x0003) tag_byte |= 0x01;
  if((twd & 0x000c) != 0x000c) tag_byte |= 0x02;
  if((twd & 0x0030) != 0x0030) tag_byte |= 0x04;
  if((twd & 0x00c0) != 0x00c0) tag_byte |= 0x08;
  if((twd & 0x0300) != 0x0300) tag_byte |= 0x10;
  if((twd & 0x0c00) != 0x0c00) tag_byte |= 0x20;
  if((twd & 0x3000) != 0x3000) tag_byte |= 0x40;
  if((twd & 0xc000) != 0xc000) tag_byte |= 0x80;

  return tag_byte;
}

static void write_dqword(bx_address addr, Bit8u *data) {
  memcpy((void *) addr, data, sizeof(Bit64u) * 2);
}

static void fxsave(fpu_state_t *pfpu) {
#if BX_SUPPORT_FPU
  unsigned index;
  bx_address addr = (bx_address) pfpu;
  BxPackedXmmRegister xmm;

  xmm.xmm16u(0) = bx_cpu.the_i387.get_control_word();
  xmm.xmm16u(1) = bx_cpu.the_i387.get_status_word();
  xmm.xmm16u(2) = pack_FPU_TW(bx_cpu.the_i387.get_tag_word());

  /* x87 FPU Opcode (16 bits) */
  /* The lower 11 bits contain the FPU opcode, upper 5 bits are reserved */
  xmm.xmm16u(3) = bx_cpu.the_i387.foo;

  /*
   * x87 FPU IP Offset (32/64 bits)
   * The contents of this field differ depending on the current
   * addressing mode (16/32/64 bit) when the FXSAVE instruction was executed:
   *   + 64-bit mode - 64-bit IP offset
   *   + 32-bit mode - 32-bit IP offset
   *   + 16-bit mode - low 16 bits are IP offset; high 16 bits are reserved.
   * x87 CS FPU IP Selector
   *   + 16 bit, in 16/32 bit mode only
   */
  xmm.xmm32u(2) = (Bit32u)(bx_cpu.the_i387.fip) & 0xffffffff;
  xmm.xmm32u(3) =         (bx_cpu.the_i387.fcs);

  write_dqword(addr, (Bit8u *) &xmm);
  addr += sizeof(Bit64u) * 2;

  /*
   * x87 FPU Instruction Operand (Data) Pointer Offset (32/64 bits)
   * The contents of this field differ depending on the current
   * addressing mode (16/32 bit) when the FXSAVE instruction was executed:
   *   + 64-bit mode - 64-bit offset
   *   + 32-bit mode - 32-bit offset
   *   + 16-bit mode - low 16 bits are offset; high 16 bits are reserved.
   * x87 DS FPU Instruction Operand (Data) Pointer Selector
   *   + 16 bit, in 16/32 bit mode only
   */
  xmm.xmm32u(0) = (Bit32u)(bx_cpu.the_i387.fdp) & 0xffffffff;
  xmm.xmm32u(1) =         (bx_cpu.the_i387.fds);

  xmm.xmm32u(2) = BX_MXCSR_REGISTER;
  xmm.xmm32u(3) = MXCSR_MASK;

  write_dqword(addr, (Bit8u *) &xmm);
  addr += sizeof(Bit64u) * 2;
  
  /* store i387 register file */
  for(index=0; index < 8; index++) {
    const floatx80 &fp = BX_FPU_REG(index);

    xmm.xmm64u(0) = fp.fraction;
    xmm.xmm64u(1) = 0;
    xmm.xmm16u(4) = fp.exp;

    write_dqword(addr, (Bit8u *) &xmm);
    addr += sizeof(Bit64u) * 2;
  }

  /* store XMM register file */
  for(index=0; index < BX_XMM_REGISTERS; index++) {
    // save XMM8-XMM15 only in 64-bit mode
    if (index < 8 || Is64BitMode()) {
      write_dqword(addr, (Bit8u *) &(bx_cpu.xmm[index]));
      addr += sizeof(Bit64u) * 2;
    }
  }
#endif
}
#endif

// Load & save segment a segment register
static inline void GLUE(OP,_segment)(segment_reg_t &snap, 
				     bx_segment_reg_t &bochs) {
  REG(snap.selector, bochs.selector.value);
#ifdef SAVING
  REG(snap.unusable, 0);
#else
  // Update hidden part of the segment register
  Bit32u dword1, dword2;
  parse_selector(bochs.selector.value, &(bochs.selector));
  bx_cpu.fetch_raw_descriptor(&(bochs.selector), &dword1, &dword2, 0);
  parse_descriptor(dword1, dword2, &(bochs.cache));
#endif
}

// Load & save idt & gdt
static inline void GLUE(OP,_table)(dtable_reg_t &snap, 
				   bx_global_segment_reg_t &bochs) {
  REG(snap.base, bochs.base);
  REG(snap.limit, bochs.limit);
}

// Load & save MSR registers
static inline void GLUE(OP,_msr) (msr_reg_t &reg) {
#if BX_CPU_LEVEL >= 5
#ifdef SAVING
  bx_cpu.rdmsr(reg.idx, &(reg.val));
#else
  bx_cpu.wrmsr(reg.idx, reg.val);
#endif
#endif
}

static int GLUE(OP,_snapshot) (const char *f_, header_t *hdr = NULL) {
  header_t h;
  cpu_state_t s;
  char tempfile[PATH_MAX];
  file f;
  int r, i;

#ifdef SAVING
  // Initialization
  memset(&s, 0, sizeof(s));

  // Get output file name
  strncpy(tempfile, "/tmp/kemufuzzer-XXXXXX", PATH_MAX - 1);
  mkstemp(tempfile);
  f = fopen(tempfile, "w");
#else
  f = fopen(f_, "r");
#endif

  assert(f);

#ifdef SAVING
  // Fill header
  REG(h.magic, 0xefef);
  REG(h.version, 0x0001);
  REG(h.emulator, EMULATOR_BOCHS);
  REG(h.mem_size, bx_mem.get_memory_len());
  REG(h.cpusno, 1);

  // Dump header to disk
  r = fwrite(f, &h, sizeof(h));
  assert(r == sizeof(h));
#else
  // Read header from disk
  r = fread(f, &h, sizeof(h));
  assert(r == sizeof(h));

  assert(h.magic == 0xefef);
  assert(h.version == 0x0001);
  assert(h.cpusno == 1);
  assert((h.mem_size % 1024*1204) == 0);

  bx_mem.init_memory(h.mem_size);

  if (hdr)
    memcpy(hdr, &h, sizeof(h));
#endif

#ifdef LOADING
  r = fread(f, &s, sizeof(s));
  assert(r == sizeof(s));
#endif

  // General purpose registers
#if BX_SUPPORT_X86_64
#error "Todo"
#else
  REG(s.regs_state.rax, EAX);
  REG(s.regs_state.rbx, EBX);
  REG(s.regs_state.rcx, ECX);
  REG(s.regs_state.rdx, EDX);
  REG(s.regs_state.rsi, ESI);
  REG(s.regs_state.rdi, EDI);
  REG(s.regs_state.rsp, ESP);
  REG(s.regs_state.rbp, EBP);
#endif

  // RFlags
  REG(s.regs_state.rflags, bx_cpu.eflags);

  // Rip
  REG(s.regs_state.rip, bx_cpu.prev_rip);
  REG(s.regs_state.rip, EIP);

  // System registers
  REG(s.sregs_state.cr0, bx_cpu.cr0.val32);
  REG(s.sregs_state.cr2, bx_cpu.cr2);
  REG(s.sregs_state.cr3, bx_cpu.cr3);
#if BX_CPU_LEVEL >= 4
  REG(s.sregs_state.cr4, bx_cpu.cr4.val32);
#endif

  // Debug registers
  REG(s.sregs_state.dr0, bx_cpu.dr[0]);
  REG(s.sregs_state.dr1, bx_cpu.dr[1]);
  REG(s.sregs_state.dr2, bx_cpu.dr[2]);
  REG(s.sregs_state.dr3, bx_cpu.dr[3]);
  REG(s.sregs_state.dr6, bx_cpu.dr6);
  REG(s.sregs_state.dr7, bx_cpu.dr7);

#if 0  
  // The DR7 register should have been pushed on the top of the stack -- verify
  // this assumption
  Bit32u saved_dr7;
  peek_memory(RSP+BX_CPU_THIS_PTR sregs[BX_SEG_REG_SS].cache.u.segment.base, 
	      sizeof(BX_CPU_THIS_PTR dr7), (uint8_t*) &saved_dr7);
  assert(BX_CPU_THIS_PTR dr7 == saved_dr7);
#endif

  // Load/save mem state
#ifdef SAVING
  r = fwrite(f, bx_mem.getHostMemAddr(&bx_cpu, 0, 0), h.mem_size);
#else
  r = fread(f, bx_mem.getHostMemAddr(&bx_cpu, 0, 0), h.mem_size);
#endif
  assert(r == h.mem_size);

#ifdef LOADING
  // Set the CPU in the proper mode and flush everything that needs to be
  // flushed
  bx_cpu.handleCpuModeChange();
  bx_cpu.TLB_flush();
  bx_cpu.lf_flags_status = 0;
#undef LOAD_SEG

  // Tables
  TAB(s.sregs_state.idtr, bx_cpu.idtr);
  TAB(s.sregs_state.gdtr, bx_cpu.gdtr);

  // Segments
  SEG(s.sregs_state.cs, bx_cpu.sregs[BX_SEG_REG_CS]);
  SEG(s.sregs_state.ds, bx_cpu.sregs[BX_SEG_REG_DS]);
  SEG(s.sregs_state.es, bx_cpu.sregs[BX_SEG_REG_ES]);
  SEG(s.sregs_state.fs, bx_cpu.sregs[BX_SEG_REG_FS]);
  SEG(s.sregs_state.gs, bx_cpu.sregs[BX_SEG_REG_GS]);
  SEG(s.sregs_state.ss, bx_cpu.sregs[BX_SEG_REG_SS]);
  SEG(s.sregs_state.tr, bx_cpu.tr);
  SEG(s.sregs_state.ldt, bx_cpu.ldtr);

#if BX_SUPPORT_X86_64
  REG(s.sregs_state.efer, bx_cpu.efer.val32);
#endif

  // Exception
  // s.exception_state.vector = exception_number;
  // s.exception_state.error_code = 0;

#if 0
  // Save FPU state
  kemufuzzer_fxsave(&s.fpu_state);
#endif

#ifdef SAVING
  // Dump MSR registers
  s.msrs_state.n = sizeof(MSRs_to_save)/sizeof(int);
  assert(s.msrs_state.n < MAX_MSRS);
#endif

  for (i = 0; i < s.msrs_state.n; i++) {
    MSR(s.msrs_state.msr_regs[i]);
  }

  // Dump cpu state
#ifdef SAVING
  r = fwrite(f, &s, sizeof(s));
  assert(r == sizeof(s));
#endif

  fclose(f);

#ifdef SAVING
  rename(tempfile, f_);
#endif

#endif
}

#undef OP
#undef REG
#undef SEG
#undef TAB
#undef MSR

#undef LOADING
#undef SAVING

#undef GLUE
#undef XGLUE
