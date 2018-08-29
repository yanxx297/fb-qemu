#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>

void main(int argc, char **argv) {
  int n;
  /* xor eax, eax; inc eax; xor ebx, ebx; int 0x80 */
  uint8_t do_exit[] = "\x31\xc0\x40\x31\xdb\xcd\x80";
  uint8_t *buf = NULL;

  buf = mmap(0, 4096, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | 
	     MAP_PRIVATE, 0, 0);
  assert(buf);

  n = read(0, buf, 4096 - sizeof(do_exit) - 1);
  memcpy(buf+n, do_exit, sizeof(do_exit));

  ((void (*) ()) buf)();
}
