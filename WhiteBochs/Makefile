OBJs = symbolic.o \
       concrete-whitebochs.o \
       concrete-whitedisasm.o \
       whitedisasm-many.o \
       fuzzball-whitebochs.o \
       fuzzball-whitedisasm.o

EXEs = concrete-whitebochs fuzzball-whitebochs \
	concrete-whitedisasm whitedisasm-many fuzzball-whitedisasm \
	run-on-cpu test-cache # klee-whitebochs klee-whitedisasm

all: $(EXEs)

include Makefile.common

memory/libmemory.a::
	$(MAKE) -C memory libmemory.a

memory/libmemory.bc::
	$(MAKE) -C memory libmemory.bc

cpu/libcpu.a::
	$(MAKE) -C cpu libcpu.a

cpu/libcpu.bc::
	$(MAKE) -C cpu libcpu.bc

fpu/libfpu.a::
	$(MAKE) -C fpu libfpu.a

disasm/libdisasm.a::
	$(MAKE) -C disasm libdisasm.a

disasm/libdisasm.bc::
	$(MAKE) -C disasm libdisasm.bc

whitebochs: concrete-whitebochs klee-whitebochs fuzzball-whitebochs

whitedisasm: concrete-whitedisasm whitedisasm-many \
             klee-whitedisasm fuzzball-whitedisasm

concrete-%.o: %.cc snapshot.h config.h whitebochs.h 
	$(CXX) -c -o $@ $(CXXFLAGS) $<

fuzzball-%.o: %.cc snapshot.h config.h whitebochs.h symbolic.h
	$(CXX) -c -o $@ $(CXXFLAGS) $(FUZZBALL_CFLAGS) $<

whitedisasm-many.o: whitedisasm.cc snapshot.h config.h whitebochs.h
	$(CXX) -c -o $@ $(CXXFLAGS) -DDISASM_MANY whitedisasm.cc

concrete-whitebochs: concrete-whitebochs.o symbolic.o \
	memory/libmemory.a cpu/libcpu.a \
	disasm/libdisasm.a fpu/libfpu.a
	${LINK} ${CXXFLAGS} -o $@ $+ ${LDFLAGS} 

# fix deps
klee-whitebochs: whitebochs.bc symbolic.bc memory/libmemory.bc cpu/libcpu.bc \
	disasm/libdisasm.bc
	${LLVM_LINK} -o $@.sh -b $@ $+ ${LLVM_LDFLAGS} && \
	rm -f $@.sh

fuzzball-whitebochs: fuzzball-whitebochs.o symbolic.o \
	memory/libmemory.a cpu/libcpu.a \
	disasm/libdisasm.a fpu/libfpu.a
	${LINK} ${CXXFLAGS} -o $@ $+ ${LDFLAGS}

concrete-whitedisasm: concrete-whitedisasm.o symbolic.o \
	memory/libmemory.a cpu/libcpu.a \
	disasm/libdisasm.a fpu/libfpu.a
	${LINK} ${CXXFLAGS} -o $@ $+ ${LDFLAGS} 

whitedisasm-many: whitedisasm-many.o symbolic.o \
	memory/libmemory.a cpu/libcpu.a \
	disasm/libdisasm.a fpu/libfpu.a
	${LINK} ${CXXFLAGS} -o $@ $+ ${LDFLAGS}

# fix deps
klee-whitedisasm: whitedisasm.bc symbolic.bc memory/libmemory.bc cpu/libcpu.bc \
	disasm/libdisasm.bc
	${LLVM_LINK} -o $@.sh -b $@ $+ ${LLVM_LDFLAGS} && \
	rm -f $@.sh

fuzzball-whitedisasm: fuzzball-whitedisasm.o symbolic.o \
	memory/libmemory.a cpu/libcpu.a \
	disasm/libdisasm.a fpu/libfpu.a
	${LINK} ${CXXFLAGS} -o $@ $+ ${LDFLAGS} 

run-on-cpu: run-on-cpu.c
	$(CC) -Wall -g -m32 -o $@ $^

test-cache: test-cache.cc  \
	memory/libmemory.a cpu/libcpu.a \
	disasm/libdisasm.a fpu/libfpu.a
	${LINK} ${CXXFLAGS} -o $@ $+ ${LDFLAGS}

clean:
	rm -f $(OBJs) $(LLVM_OBJs) *.d *.pyc
	rm -f klee-whitedisasm.sh klee-whitebochs.sh
	$(MAKE) -C cpu clean
	$(MAKE) -C disasm clean
	$(MAKE) -C memory clean

clean-all: clean
	rm -f $(EXEs)

.PHONY: clean clean-all whitebochs whitedisasm
