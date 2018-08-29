#include "bochs.h"
#define NEED_CPU_REG_SHORTCUTS
#include "cpu/cpu.h"
#include "disasm/disasm.h"
#include "whitebochs.h"
#include "symbolic.h"
#include "debug.h"
#include <assert.h>

int DEBUG_LEVEL = 1;
FILE *DEBUG_FILE = stdout;

BX_CPU_C bx_cpu;
BX_MEM_C bx_mem;
Bit8u bx_cpu_count = 1;

#define CODE_SIZE 128
Bit8u code[CODE_SIZE];
disassembler disasm;

void load_shellcode(char *shellcode) {
  char *tok;
  unsigned char hex;
  size_t i = 0;

  shellcode = strdup(shellcode);
  assert(shellcode);

  while (tok = strtok(!i ? shellcode : NULL, "\\x")) {
    hex = strtoul(tok, NULL, 16);
    assert(i < CODE_SIZE);
    code[i++] = hex;
  }

  free(shellcode);
}

int disasm_one(void) {
  bxInstruction_c i;
  int r;
  unsigned int isize;
  char istr[512];
#ifdef SYMBOLIC_EXECUTION
#else
  int j;
#endif

  START_SYMBOLIC_EXECUTION(ADDRESS_HERE());

  r = bx_cpu.fetchDecode32(code, &i, CODE_SIZE);

#ifdef SYMBOLIC_EXECUTION
  printf("SYMBOLIC_EXECUTION turned on\n");
  IGNORE((r == 0) && (i.getIaOpcode() != BX_IA_ERROR));
#else
  if (r != 0 || i.getIaOpcode() == BX_IA_ERROR)
    return 1;

  isize = disasm.disasm(bx_cpu.sregs[BX_SEG_REG_CS].cache.u.segment.d_b, bx_cpu.cpu_mode == BX_MODE_LONG_64, bx_cpu.get_segment_base(BX_SEG_REG_CS), 0, code, istr);
  for (j = 0; j < i.ilen(); j++) {
    printf("\\x%.2x", code[j]);
  }

  printf("\t%d\t%s\t%s\t%x\n", isize, istr, get_bx_opcode_name(i.getIaOpcode()) + 6, i.repUsedL() | i.seg() | (i.modC0() << 4));
#endif

  return 0;
}

int main(int argc, char *argv[]) {
#ifdef SYMBOLIC_EXECUTION
  int symbolic_code_size = 3;
#else
#endif

  bx_mem.init_memory(1*1024*1024);

  if (getenv("WHITEDISASM_DEBUG")) {
    DEBUG_LEVEL = atoi(getenv("WHITEDISASM_DEBUG"));
  }

  BX_CPU_THIS_PTR sregs[BX_SEG_REG_CS].cache.u.segment.d_b = 1;

  INIT_SYMBOLIC_EXECUTION();

#if defined(KLEE) || defined(FUZZBALL)
  /* E.g., fuzzball-whitedisasm */
  assert(argc == 1 || argc == 2);
  if (argc == 2) {
    symbolic_code_size = atoi(argv[1]);
    assert(symbolic_code_size > 0 && symbolic_code_size <= 15);
  }
  MAKE_SYMBOLIC((void *) code, (void *) code, (size_t) symbolic_code_size, 
		"SHELLCODE");
#elif defined(DISASM_MANY)
  /* I.e., whitedisasm-many */
  {
    char linebuf[CODE_SIZE * 5 + 1];
    char *res;
    while ((res = fgets(linebuf, sizeof(linebuf), stdin))) {
      load_shellcode(linebuf);
      disasm_one();
    }
  }
#else
  /* I.e., concrete-whitedisasm */
  assert(argc == 2);
  load_shellcode(argv[1]);
#endif

  return disasm_one();
}
