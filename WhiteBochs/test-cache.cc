#include "bochs.h"
#define NEED_CPU_REG_SHORTCUTS
#include "cpu/cpu.h"
#include "disasm/disasm.h"
#include "whitebochs.h"
#include <assert.h>

// ****************************************************************************
// CPU & physical memory
// ****************************************************************************
BX_CPU_C bx_cpu;
BX_MEM_C bx_mem;
Bit8u bx_cpu_count = 1;

FILE *DEBUG_FILE = stderr;
int DEBUG_LEVEL = 1;

int main(int argc, char *argv[]) {
  bx_segment_reg_t *seg = &(bx_cpu.sregs[BX_SEG_REG_CS]);
  Bit32u dword1, dword2;
  Bit8u *buf = (Bit8u *) &(seg->cache);

  dword1 = strtoul(argv[1], NULL, 16);
  dword2 = strtoul(argv[2], NULL, 16);

  parse_descriptor(dword1, dword2, &seg->cache);  

  for (int i = 0; i < sizeof(bx_cpu.sregs[BX_SEG_REG_CS]); i++) {
    printf("out_desc_____40_%d=%.2x\n", i, buf[i]); 
  }

  return 0;
}
