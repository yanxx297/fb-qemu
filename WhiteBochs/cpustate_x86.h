// This file is part of KEmuFuzzer.
// 
// KEmuFuzzer is free software: you can redistribute it and/or modify it under
// the terms of the GNU General Public License as published by the Free
// Software Foundation, either version 3 of the License, or (at your option)
// any later version.
// 
// KEmuFuzzer is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
// 
// You should have received a copy of the GNU General Public License along with
// KEmuFuzzer.  If not, see <http://www.gnu.org/licenses/>.

#ifndef CPUSTATE_H
#define CPUSTATE_H

#include <stdint.h>

#ifdef __LP64__
#define ADDR(x) ((uint64_t) (x))
#define PTR(x) ((uint64_t *) (x))
#define CPU_64_BIT
#define CPU_BITS 64
#else
#define ADDR(x) ((uint32_t) (x))
#define PTR(x) ((uint32_t *) (x))
#define CPU_32_BIT
#define CPU_BITS 32
#endif

#define PAD64(x) ((uint64_t) (x))

/* trap/fault mnemonics */
#define EXCEPTION_DIVIDE_ERROR      0
#define EXCEPTION_DEBUG             1
#define EXCEPTION_NMI               2
#define EXCEPTION_INT3              3
#define EXCEPTION_OVERFLOW          4
#define EXCEPTION_BOUNDS            5
#define EXCEPTION_INVALID_OP        6
#define EXCEPTION_NO_DEVICE         7
#define EXCEPTION_DOUBLE_FAULT      8
#define EXCEPTION_COPRO_SEG         9
#define EXCEPTION_INVALID_TSS      10
#define EXCEPTION_NO_SEGMENT       11
#define EXCEPTION_STACK_ERROR      12
#define EXCEPTION_GP_FAULT         13
#define EXCEPTION_PAGE_FAULT       14
#define EXCEPTION_SPURIOUS_INT     15
#define EXCEPTION_COPRO_ERROR      16
#define EXCEPTION_ALIGNMENT_CHECK  17
#define EXCEPTION_MACHINE_CHECK    18
#define EXCEPTION_SIMD_ERROR       19
#define EXCEPTION_DEFERRED_NMI     31
#define EXCEPTION_NONE             0xFFFF

/* cr0 bits */
#define CR0_PE         (1u << 0)
#define CR0_MP         (1u << 1)
#define CR0_EM         (1u << 2)
#define CR0_TS         (1u << 3)
#define CR0_ET         (1u << 4)
#define CR0_NE         (1u << 5)
#define CR0_WP         (1u << 16)
#define CR0_AM         (1u << 18)
#define CR0_NW         (1u << 29)
#define CR0_CD         (1u << 30)
#define CR0_PG         (1u << 31)

#define CR4_PAE        (1u << 5)

/* rflags */
#define RFLAGS_RESERVED_MASK    2

#define RFLAGS_TRAP    (1u << 8)

#define EFER_LME       (1u << 8)

#define PAGE_4K_MASK 0xfffff000
#define PAGE_4K_SIZE 0x1000

/* MSRs */
#define X86_MSR_IA32_SYSENTER_CS            0x174
#define X86_MSR_IA32_SYSENTER_ESP           0x175
#define X86_MSR_IA32_SYSENTER_EIP           0x176
#define X86_MSR_IA32_APICBASE               0x1b
#define X86_MSR_EFER                        0xc0000080
#define X86_MSR_STAR                        0xc0000081
#define X86_MSR_PAT                         0x277
#define X86_MSR_VM_HSAVE_PA                 0xc0010117
#define X86_MSR_IA32_PERF_STATUS            0x198




#define KEMUFUZZER_HYPERCALL_START_TESTCASE  0x23
#define KEMUFUZZER_HYPERCALL_STOP_TESTCASE   0x45

#define EXPECTED_MAGIC    0xEFEF
#define EXPECTED_VERSION  0x0001

#define CPU_STATE_MAGIC          0xEFEF
#define CPU_STATE_VERSION        0x0001
#define MAX_MSRS                   0x20
#define HYPERCALL_LEN               0x2	// length of a "hypercall" instruction (in bytes)

static int MSRs_to_save[] = {
  X86_MSR_IA32_SYSENTER_CS,
  X86_MSR_IA32_SYSENTER_ESP,
  X86_MSR_IA32_SYSENTER_EIP,
  X86_MSR_IA32_APICBASE,
  X86_MSR_EFER,
  X86_MSR_STAR,
  X86_MSR_PAT,
  X86_MSR_VM_HSAVE_PA,
  X86_MSR_IA32_PERF_STATUS,  
};

typedef uint64_t reg64_t;
typedef uint32_t reg32_t;
typedef uint16_t reg16_t;

typedef struct __attribute__((__packed__)) {
  uint64_t mantissa;
  uint16_t expsign;
  uint8_t  reserved[6];
} fpust_t;

typedef struct __attribute__((__packed__)) {
  uint8_t data[16];
} fpuxmm_t;

typedef struct __attribute__((__packed__)) {
  uint16_t fcw;
  uint16_t fsw;
  uint8_t  ftw;
  uint8_t  unused;
  uint16_t fop;
  uint32_t fpuip;
  uint16_t cs;
  uint16_t reserved0;
  uint32_t fpudp;
  uint16_t ds;
  uint16_t reserved1;
  uint32_t mxcsr;
  uint32_t mxcsr_mask;

  fpust_t st[8];                // STx/MMx
  fpuxmm_t xmm[8];
  fpuxmm_t xmm_reserved[14];
} fpu_state_t;

typedef enum {
  EMULATOR_QEMU = 0,
  EMULATOR_BOCHS,
  EMULATOR_VIRTUALBOX,
  EMULATOR_VMWARE,
  EMULATOR_KVM
} emulator_t;

typedef enum {
  PRE_TESTCASE = 0,
  POST_TESTCASE = 1,
  CRASH_TESTCASE = 0x10,
  TIMEOUT_TESTCASE = 0x20,
  IO_TESTCASE = 0x40
} type_t;

typedef struct __attribute__ ((__packed__)) {
  uint16_t    magic;
  uint16_t    version;
  emulator_t  emulator;
  char        kernel_version[16];
  char        kernel_checksum[64];
  char        testcase_checksum[64];
  type_t      type;
  uint8_t     cpusno;
  uint32_t    mem_size;
  uint8_t     ioports[2];
} header_t;

typedef struct __attribute__ ((__packed__)) {
  reg64_t rax, rbx, rcx, rdx, rsi, rdi, rsp, rbp, r8, r9, r10;
  reg64_t r11, r12, r13, r14, r15, rip, rflags;
} regs_state_t;

typedef struct __attribute__ ((__packed__)) {
  uint64_t base;
  uint32_t limit;
  uint16_t selector;
  uint8_t type;
  uint8_t present, dpl, db, s, l, g, avl;
  uint8_t unusable;
} segment_reg_t;

typedef struct __attribute__ ((__packed__)) {
  uint64_t base;
  uint16_t limit;
} dtable_reg_t;

typedef struct __attribute__ ((__packed__)) {
  segment_reg_t cs, ds, es, fs, gs, ss;
  segment_reg_t tr, ldt;
  dtable_reg_t idtr, gdtr;
  uint64_t cr0, cr1, cr2, cr3, cr4, cr8;
  uint64_t dr0, dr1, dr2, dr3, dr6, dr7;
  uint64_t efer;
} sregs_state_t;

typedef struct __attribute__ ((__packed__)) {
  uint32_t idx;
  uint64_t val;
} msr_reg_t;

typedef struct __attribute__ ((__packed__)) {
  uint32_t n;
  msr_reg_t msr_regs[MAX_MSRS];
} msrs_state_t;

typedef struct __attribute__ ((__packed__)) {
  uint32_t vector;
  uint32_t error_code;
} exception_state_t;

typedef struct __attribute__ ((__packed__)) {
  // FPU state
  fpu_state_t fpu_state;

  // General purpose registers state
  regs_state_t regs_state;

  // Special registers state
  sregs_state_t sregs_state;

  // Exception state
  exception_state_t exception_state;

  // MSR registers state
  msrs_state_t msrs_state;
} cpu_state_t;

// HEADER + CPU[0] + CPU[1] + .... + MEM

#ifndef DONT_GZIP_STATE
#include <zlib.h>
#define file   gzFile
#define fwrite(a,b,c) gzwrite(a,b,c)
#define fread(a,b,c) gzread(a,b,c)
#define fclose(a) gzclose(a)
#define fopen(a,b) gzopen(a,b)
#else
#define file   FILE *
#define fwrite(a,b,c) (fwrite(b,c,1,a) * c)
#define fread(a,b,c)  (fread(b,c,1,a) * c)
#endif

#endif
