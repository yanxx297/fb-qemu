OBJs =	init.o \
	cpu.o \
	icache.o \
	resolver.o \
	fetchdecode.o \
	access.o \
	access32.o \
	shift16.o \
	logical16.o \
	ctrl_xfer32.o \
	ctrl_xfer16.o \
	mmx.o \
	3dnow.o \
	fpu_emu.o \
	sse.o \
	sse_move.o \
	sse_pfp.o \
	sse_rcp.o \
	sse_string.o \
	xsave.o \
	aes.o \
	vmx.o \
	vmexit.o \
	soft_int.o \
	apic.o \
	bcd.o \
	mult16.o \
	tasking.o \
	shift32.o \
	shift8.o \
	arith8.o \
	stack16.o \
	protect_ctrl.o \
	mult8.o \
	load32.o \
	data_xfer8.o \
	vm8086.o \
	logical8.o \
	logical32.o \
	arith16.o \
	segment_ctrl.o \
	data_xfer16.o \
	data_xfer32.o \
	exception.o \
	cpuid.o \
	proc_ctrl.o \
	crregs.o \
	msr.o \
	smm.o \
	lazy_flags.o \
	flag_ctrl_pro.o \
	stack32.o \
	debugstuff.o \
	flag_ctrl.o \
	mult32.o \
	arith32.o \
	jmp_far.o \
	call_far.o \
	ret_far.o \
	iret.o \
	ctrl_xfer_pro.o \
	segment_ctrl_pro.o \
	io.o \
	crc32.o \
	bit.o \
	bit16.o \
	bit32.o \
	string.o \
	paging.o

# Objects which are only used for x86-64 code
OBJs64 = access64.o \
	arith64.o \
	ctrl_xfer64.o \
	data_xfer64.o \
	fetchdecode64.o \
	logical64.o \
	mult64.o \
	shift64.o \
	bit64.o \
	stack64.o

all: libcpu.a libcpu.bc

include ../Makefile.common

libcpu.a: $(OBJs)
	$(AR) r $@ $+

libcpu.bc: $(LLVM_OBJs)
	$(LLVM_LINK) -o $(@:%.bc=%.sh) -b $@ $+ $(LLVM_LDFLAGS)

clean:
	rm -rf $(OBJs) $(LLVM_OBJs) *.d libcpu.a libcpu.bc libcpu.sh

.PHONY: clean
