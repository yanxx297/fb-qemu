OBJs =  dis_decode.o \
	dis_groups.o \
	resolve.o    \
	syntax.o

all: libdisasm.a libdisasm.bc

include ../Makefile.common

libdisasm.a: $(OBJs)
	$(AR) r $@ $+

libdisasm.bc: $(LLVM_OBJs)
	$(LLVM_LINK) -o $(@:%.bc=%.sh) -b $@ $+ $(LLVM_LDFLAGS)

clean:
	rm -rf *.d $(OBJs) $(LLVM_OBJs) libdisasm.a libdisasm.bc libdisasm.sh

.PHONY: clean 
