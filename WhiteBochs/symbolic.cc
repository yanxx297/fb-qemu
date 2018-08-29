char symbolic_execution = 0;
char fuzzball_dryrun = 0;

#define GETPC() ((void *)((unsigned long)__builtin_return_address(0) - 1))
void *ADDRESS_HERE() {
  return GETPC();
}
