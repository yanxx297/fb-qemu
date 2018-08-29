OBJs = memory.o

all: libmemory.a libmemory.bc

include ../Makefile.common

libmemory.a: $(OBJs)
	$(AR) r $@ $+

libmemory.bc: $(LLVM_OBJs)
	$(LLVM_LINK) -o $(@:%.bc=%.sh) -b $@ $+ $(LLVM_LDFLAGS)

clean:
	rm -rf $(OBJs) $(LLVM_OBJs) *.d libmemory.a libmemory.bc libmemory.sh

.PHONY: clean
