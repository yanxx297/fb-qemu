#include "bochs.h"
#define NEED_CPU_REG_SHORTCUTS
#include "cpu/cpu.h"
#include "disasm/disasm.h"
#include "whitebochs.h"
#include <assert.h>

int DEBUG_LEVEL = 1;
FILE *DEBUG_FILE = stdout;

// ****************************************************************************
// Helper functions for dealing with symbolic variables
// ****************************************************************************
#include "symbolic.h"

#define DONT_GZIP_STATE
#include "cpustate_x86.h"
typedef header_t snapshot_header_t;

// ****************************************************************************
// CPU & physical memory
// ****************************************************************************
BX_CPU_C bx_cpu;
BX_MEM_C bx_mem;
Bit8u bx_cpu_count = 1;
Bit32s EXCEPTION = -1;
void *PAGE_ZERO;
void *PAGE_ONE;
bxInstruction_c i, popf;

#define SCRATCHPAD_SIZE 0x2000
static Bit8u scratchpad[SCRATCHPAD_SIZE];

// ****************************************************************************
// Templetized functions for loading and saving snapshots
// ****************************************************************************
#define LOADING
#include "snapshot.h"

#define POKE(x, y) \
  bx_mem.writePhysicalPage(&bx_cpu, x, sizeof(y), (uint8_t *) y);

#define PEEK(x, y) \
  bx_mem.readPhysicalPage(&bx_cpu, x, sizeof(y), (uint8_t *) y);

// *****************************************************************************
// Dump the content of the physical memory
// *****************************************************************************
static void dump_phys_mem(bx_phy_address physaddr, size_t len)  {
  FILE *f = stderr;
  fprintf(f, "-------------------------------------- MEMORY ---------------------------------\n");
  for (size_t i = 0; i < len; i++) {
    if (i % 16 == 0) {
      fprintf(f, "%s%.16lx", i ? "\n" : "", PAD64(physaddr + i));
    }
    fprintf(f, "%s%.2x", i % 2 == 0 ? " " : "",
	    *(bx_mem.getHostMemAddr(&bx_cpu, physaddr + i, 0)));
  }
  fprintf(f, "\n");
  fprintf(f, "-------------------------------------------------------------------------------\n");
}

// *****************************************************************************
// Parse & install a shellcode
// *****************************************************************************
static size_t load_shellcode(bx_address addr, char *shellcode) {
  char *tok;
  unsigned char hex;
  size_t i = 0, len = 0;
  bx_address eip;
  bx_phy_address phy_eip;

  shellcode = strdup(shellcode);

  bx_phy_address start_eip = translate_lin_to_phy(addr);
  while (tok = strtok(!i ? shellcode : NULL, "\\x")) {
    hex = strtoul(tok, NULL, 16);
    eip = addr + i++;
    phy_eip = translate_lin_to_phy(eip);
    bx_mem.writePhysicalPage(&bx_cpu, phy_eip, sizeof(hex), (uint8_t *) &hex);
    len++;
  }

  free(shellcode);
  dump_phys_mem(start_eip, 8);
  return len;
}

// *****************************************************************************
// Dump the state of the CPU
// *****************************************************************************
static void dump_cpu_state() {
  (bx_cpu.debug)(EIP + bx_cpu.sregs[BX_SEG_REG_CS].cache.u.segment.base);
}

// *****************************************************************************
// Fetch and decode an instruction
// *****************************************************************************
static void fetch_and_decode(bx_address rip, bxInstruction_c *i) {
  int ret;

  ret = bx_cpu.fetchDecode32((Bit8u *) bx_mem.getHostMemAddr(&bx_cpu, rip, 0), 
			     i, (rip & 0x1000) + 0xfff - rip);
  if (ret < 0) {
    // Fetching instruction on segment/page boundary
    bx_cpu.boundaryFetch((Bit8u *) bx_mem.getHostMemAddr(&bx_cpu, rip, 0), 
			 (rip & 0x1000) + 0xfff - rip, i);
  }
}

// *****************************************************************************
// Execute an instruction
// *****************************************************************************
static void execute(bxInstruction_c &i) {
  bx_cpu.prev_rip = EIP;
  EIP += i.ilen();
  debug("Executing %s...\n", get_bx_opcode_name(i.getIaOpcode()) + 6);
  BX_CPU_CALL_METHOD(i.execute, (&i)); 
  bx_cpu.prev_rip = EIP;
  debug("Execution completed\n");
}

// *****************************************************************************
// 
// *****************************************************************************
int main(int argc, char *argv[]) {
  bx_address eip_concrete;
  size_t shellcode_len = 0;
  snapshot_header_t snapshot, sym_snapshot; 

  if (getenv("WHITEBOCHS_DEBUG")) {
    DEBUG_LEVEL = atoi(getenv("WHITEBOCHS_DEBUG"));
  }

  if (argc != 2 && argc != 3) {
    fprintf(stderr, "usage: %s snapshot [shellcode]\n", argv[0]);
    exit(1);
  }

  // Initialize the CPU state
  load_snapshot(argv[1], &snapshot);
  eip_concrete = EIP;

  PAGE_ZERO = g2h(0);
  PAGE_ONE = g2h(0x1000);

  if (argc == 3)
    // Load the instruction to execute
    shellcode_len = load_shellcode(EIP + bx_cpu.sregs[BX_SEG_REG_CS].cache.u.segment.base, argv[2]);

  // Decode the current instruction
  fetch_and_decode(EIP + bx_cpu.sregs[BX_SEG_REG_CS].cache.u.segment.base, &i);

#ifndef SYMBOLIC_EXECUTION
  dump_cpu_state();
#endif


#ifdef FUZZBALL
  INIT_SYMBOLIC_EXECUTION();

#define FUZZBALL_REG(r)				\
  printf("FUZZBALL_REG\treg_%s\t%d\t%p\n", #r, sizeof(r), &(r))
#define FUZZBALL_SREG(r)				\
  printf("FUZZBALL_REG\tsreg_%s\t%d\t%p\n", #r, sizeof(bx_cpu.sregs[BX_SEG_REG_##r].selector), &(bx_cpu.sregs[BX_SEG_REG_##r].selector))
#define FUZZBALL_CREG(r)				\
  printf("FUZZBALL_REG\tcreg_%s\t%d\t%p\n", #r, sizeof(r), &(r))
#define FUZZBALL_DREG(r)						\
  printf("FUZZBALL_REG\tdreg_%s\t%d\t%p\n", #r, sizeof(r), &(r))
#define FUZZBALL_DESC(r)						\
  printf("FUZZBALL_DESC\tdesc_%s\t%d\t%p\t%d\n", #r, sizeof(bx_cpu.sregs[BX_SEG_REG_##r].cache), &(bx_cpu.sregs[BX_SEG_REG_##r].cache), bx_cpu.sregs[BX_SEG_REG_##r].selector.index)

  if (fuzzball_dryrun) {
    printf("FUZZBALL_EMULATOR\tBOCHS\n");

    FUZZBALL_REG(EAX);
    FUZZBALL_REG(EBX);
    FUZZBALL_REG(ECX);
    FUZZBALL_REG(EDX);
    FUZZBALL_REG(ESP);
    FUZZBALL_REG(EBP);
    FUZZBALL_REG(ESI);
    FUZZBALL_REG(EDI);

    FUZZBALL_REG(EIP);
    FUZZBALL_REG(EFLAGS);

    FUZZBALL_SREG(CS);
    FUZZBALL_SREG(DS);
    FUZZBALL_SREG(ES);
    FUZZBALL_SREG(FS);
    FUZZBALL_SREG(GS);
    FUZZBALL_SREG(SS);

    FUZZBALL_DESC(CS);
    FUZZBALL_DESC(DS);
    FUZZBALL_DESC(ES);
    FUZZBALL_DESC(FS);
    FUZZBALL_DESC(GS);
    FUZZBALL_DESC(SS);

    printf("FUZZBALL_GDTR\t%d\t%p\t%d\t%p\n", sizeof(bx_cpu.gdtr.base), &(bx_cpu.gdtr.base), sizeof(bx_cpu.gdtr.limit), &(bx_cpu.gdtr.limit));
    printf("FUZZBALL_IDTR\t%d\t%p\t%d\t%p\n", sizeof(bx_cpu.idtr.base), &(bx_cpu.idtr.base), sizeof(bx_cpu.idtr.limit), &(bx_cpu.idtr.limit));
    printf("FUZZBALL_TR\t%d\t%p\n", sizeof(bx_cpu.tr.selector.value), &(bx_cpu.tr.selector.value));
    printf("FUZZBALL_DESC\tdesc_TR\t%d\t%p\t%d\n", sizeof(bx_cpu.tr.cache), &(bx_cpu.tr.cache), bx_cpu.tr.selector.value);
    printf("FUZZBALL_LDTR\t%d\t%p\n", sizeof(bx_cpu.ldtr.selector.value), &(bx_cpu.ldtr.selector.value));

    FUZZBALL_CREG(CR0);
    FUZZBALL_CREG(CR2);
    FUZZBALL_CREG(CR3);
#if BX_CPU_LEVEL >= 4
    FUZZBALL_CREG(CR4);
#endif
#if BX_CPU_LEVEL >= 3
    FUZZBALL_DREG(DR0);
    FUZZBALL_DREG(DR1);
    FUZZBALL_DREG(DR2);
    FUZZBALL_DREG(DR3);
    FUZZBALL_DREG(DR6);
    FUZZBALL_DREG(DR7);
#endif

#if BX_SUPPORT_FPU
    printf("FUZZBALL_FPU\t%p\t%u\n", &bx_cpu.the_i387, sizeof(bx_cpu.the_i387));
#endif 
    printf("FUZZBALL_GET_TLS\t%p\n", tls);
    printf("FUZZBALL_MEM\t%p\t%u\n", g2h(0), bx_mem.get_memory_len());
    printf("FUZZBALL_SCRATCHPAD\t%p\t%u\n", scratchpad, SCRATCHPAD_SIZE);
    printf("FUZZBALL_SNAPSHOT\t%s\n", argv[1]);
    // Dummy variable used to store the current exception
    printf("FUZZBALL_EXCEPTION\t%p\n", &EXCEPTION);
    // Address of the function used to handle the exception
    printf("FUZZBALL_EXCEPTION_HANDLER\t%p\t1\n", bx_cpu.exception);

    // Address of functions used to write to the virtual mem
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t2\n", bx_cpu.write_virtual_byte_32);
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t2\n", bx_cpu.write_virtual_word_32);
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t2\n", bx_cpu.write_virtual_dword_32);
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t2\n", bx_cpu.write_virtual_qword_32);
#if BX_CPU_LEVEL >= 6
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t2\n", bx_cpu.write_virtual_dqword_32);
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t2\n", bx_cpu.write_virtual_dqword_aligned_32);
#endif

    // Address of functions used to read from the virtual mem
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_virtual_byte_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_virtual_word_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_virtual_dword_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_RMW_virtual_byte_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_RMW_virtual_word_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_RMW_virtual_dword_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_RMW_virtual_dword_32);
#if BX_CPU_LEVEL >= 6
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_virtual_dqword_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_virtual_dqword_aligned_32);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t2\n", bx_cpu.read_RMW_virtual_dword_32);
#endif

#if BX_SUPPORT_X86_64
    printf("FUZZBALL_REG\tefer\t%p\n%u\n", &(bx_cpu.efer.value), 
	   sizeof(bx_cpu.efer.value));
#endif
    printf("FUZZBALL_MSRS\t%p\t%u\n", bx_cpu.msrs, sizeof(bx_cpu.msrs));

#if 0
    // Address of functions used to read from the virtual mem
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t1\n", bx_cpu.system_read_byte);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t1\n", bx_cpu.system_read_word);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t1\n", bx_cpu.system_read_dword);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t1\n", bx_cpu.system_read_qword);
    printf("FUZZBALL_READ_VIRTUAL_MEM\t%p\t1\n", bx_cpu.v2h_read_byte);

    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t1\n", bx_cpu.system_write_byte);
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t1\n", bx_cpu.system_write_word);
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t1\n", bx_cpu.system_write_dword);
    printf("FUZZBALL_WRITE_VIRTUAL_MEM\t%p\t1\n", bx_cpu.v2h_write_byte);
#endif

    printf("FUZZBALL_METAINFO1\t%p\t%d\t\\x%.2x\n", &(i.metaInfo.metaInfo1), sizeof(i.metaInfo.metaInfo1), i.metaInfo.metaInfo1);
    printf("FUZZBALL_METADATA\t%p\t%d\t", &(i.metaData), sizeof(i.metaData));
    for (int k = 0; k < sizeof(i.metaData); k++) {
      printf("\\x%.2x", i.metaData[k]);
    }
    printf("\n");

    printf("FUZZBALL_IGNORE_CALL\tfprintf\t%p\t0\n", fprintf);
    if (argc == 3)
      printf("FUZZBALL_SHELLCODE\t%s\n", argv[2]);
  }

  START_SYMBOLIC_EXECUTION(ADDRESS_HERE());

  // #define DESCRIPTOR_HACK

#ifndef DESCRIPTOR_HACK
  // refresh_seg_descriptors();
  refresh_seg_selectors();

  EXCEPTION = -1;

  IGNORE_PATHCOND_TILL_HERE();
#else
  printf("FUZZBALL_DESCRIPTOR\t%s\t%p\t%u\n", "CS", &(bx_cpu.sregs[BX_SEG_REG_CS].cache), sizeof(bx_cpu.sregs[BX_SEG_REG_CS].cache));
#endif

#endif // FUZZBALL

  // Start tracing from this point
  START_TRACING();

  // Stop here if this is a dry run
  FINI_SYMBOLIC_EXECTUION();

#ifdef DESCRIPTOR_HACK
  bx_segment_reg_t *seg = &(bx_cpu.sregs[BX_SEG_REG_CS]);
  Bit32u dword1, dword2;
  bx_cpu.fetch_raw_descriptor(&seg->selector, &dword1, &dword2, 0xFFFF);
  parse_descriptor(dword1, dword2, &seg->cache);  
  exit(0);
#endif


  // Execute the current instruction
  execute(i);

  // Force update of eflags
  // bx_cpu.force_flags();

#ifndef SYMBOLIC_EXECUTION
  dump_cpu_state();
#endif

  return 0;
}
