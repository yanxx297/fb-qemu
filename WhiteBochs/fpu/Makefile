OBJs = f2xm1.o ferr.o fpatan.o fprem.o fpu_arith.o fpu.o fpu_compare.o fpu_const.o fpu_load_store.o fpu_misc.o fpu_tags.o fpu_trans.o fsincos.o fyl2x.o poly.o softfloat.o softfloat-round-pack.o softfloat-specialize.o softfloatx80.o

all: libfpu.a libfpu.bc

include ../Makefile.common

libfpu.a: $(OBJs)
	$(AR) r $@ $+

libfpu.bc: $(LLVM_OBJs)
	$(LLVM_LINK) -o $(@:%.bc=%.sh) -b $@ $+ $(LLVM_LDFLAGS)

clean:
	rm -rf $(OBJs) $(LLVM_OBJs) *.d libfpu.a libcpu.bc libcpu.sh

.PHONY: clean
