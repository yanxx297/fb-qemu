#!/usr/bin/python

import os, sys, subprocess, base64, time, re
from cpustate_x86 import *
from common import *
from memoizable import memoizable_disk as memoizable
from macpath import join

t0 = time.time()

os.environ["COLUMNS"] = os.getenv("COLUMNS", "80")

HOME = os.getenv("HOME")
HERE = os.path.abspath(os.path.dirname(__file__))
DEBUG = os.getenv("FUZZBALL_DEBUG", True)
if not DEBUG:
    FUZZBALL = os.path.join(HERE, "../fuzzball/exec_utils/fuzzball")
else:
    os.environ["OCAMLRUNPARAM"] = "b"
    FUZZBALL = os.path.join(HERE, "../fuzzball/exec_utils/fuzzball")

#GDB = os.path.join(HERE, "gdb")
GDB = "gdb"
OUTDIR = sys.argv[1]
print OUTDIR
FUZZBALL_ENV_ARGS = os.getenv("FUZZBALL_ARGS", "")
FUZZBALL_MAX_ITERS = os.getenv("FUZZBALL_MAX_ITERATIONS", "4096")
FUZZBALL_ARGS = "-solver smtlib -solver-path ../../lib/z3/build/z3 -arch x64 \
        -load-base 0x60000000 -linux-syscalls -trace-iterations -zero-memory \
        -trace-basic -table-limit 8 -no-sym-regions %s -total-timeout 7200" % \
    (FUZZBALL_ENV_ARGS)
KERNEL = os.getenv("KERNEL_MODE", False)
EXTRA_DESC_COND = os.path.join(HERE, "extra-desc-conds.txt")
SNAPSHOT = "../base.snap"


usrcmdline = sys.argv[2:]

# To disable use of GDB core file generation, set the "corefile" variable
# to empty, as in the second line
# corefile = Tempfile(suffix = ".core")
corefile = ""

symbolic_regs = True
symbolic_sregs = True
symbolic_cregs = True
symbolic_dregs = False
symbolic_gdt = True
symbolic_idt = os.getenv("FUZZBALL_SYMBOLIC_IDT", False)
symbolic_pt = True
stop_at_exceptions = True
ignored_functions = []#["fprintf"] #[] 
symbolic_mem_regions = [(0x1000, 16, "PAGEONE"), (0x2000, 16, "PAGETWO")]
symbolic_metadata = False

start_address = None
start_tracing_address = None
coredump_address = None
stop_addresses = []
ignore_paths = []

emulator = None
cpu_regs = []
descrs = []
gdtr = None
idtr = None
tr = None
ldtr = None
phys_mem = None
exception = None
exception_handlers = []
read_virt_mem_handlers = []
write_virt_mem_handlers = []
fpu = None
shellcode = None
snapshot = None
snapshot_file = None
snapshot_md5 = None
ignored_calls = []
get_tls = None
tls_base = None
ignore_pathcond_till = None
scratchpad = None
msrs = None
eip = None
metainfo1 = None
metadata = None

cmdline = []

symbolic_bytes = []
concrete_bytes = []
tempfiles = []

dump_region = False
preferred_value = False
cpustate_addr = 0x622dd2a0
phys_mem = (0x544d3000, 16777216)
start_address = 0x6004ae15
end_address = 0x6004ae20 #0x6004ae1d
fuzzball_reg = {
        0 : "reg_EAX",
        1 : "reg_ECX",
        2 : "reg_EDX",
        3 : "reg_EBX",
        4 : "reg_ESP",
        5 : "reg_EBP",
        6 : "reg_ESI",
        7 : "reg_EDI"
        }
fuzzball_sreg = {
        0 : "sreg_ES",
        1 : "sreg_CS",
        2 : "sreg_SS",
        3 : "sreg_DS",
        4 : "sreg_FS",
        5 : "sreg_GS",
        }

if KERNEL:
    buf = open(SNAPSHOT).read()
    snapshot = X86Dump(buf)
    snapshot_file = SNAPSHOT
    snapshot_md5 = md5(buf)

def extra_cond_eq(n, v, m = 0xff):
    if m == 0xff:
        return ["-extra-condition", "(%s == %u:reg8_t)" % (n, v)]
    elif m != 0:
        return ["-extra-condition", 
                "((%s & %u:reg8_t) == %u:reg8_t)" % (n, m, v & m)]
    else:
        return []


def vine_for_mem(a, b = 32):
    return "mem[0x%.8x:reg32_t]:reg%d_t" % (a, b)


def vine_for_stack(s):
    return "mem[R_ESP:reg32_t + %d:reg32_t]:reg32_t" % (s * 4)


def addr_for_symbolic_bit():
    global scratchpad
    a, s, u = scratchpad
    assert u < s
    scratchpad = (a, s, u + 1)
    return a + s - u


# ===-----------------------------------------------------------------------===
# Build cmdline arguments for making a memory location symbolic (bits set in
# the mask are asserted to make them concrete)
# ===-----------------------------------------------------------------------===
def __make_mem_symbolic(haddr, gaddr, sym, value = 0, mask = 0, mindist = False):
    global symbolic_bytes, concrete_bytes

    cmdline = []
    name = "in_mem_%.8x_%s_1_0" % (gaddr, encode(sym))

    if mask < 0xff:
        cmdline = ["-symbolic-byte", "0x%.8x=%s" % (haddr, name)]
        symbolic_bytes += [haddr]

        if mask > 0:
            cmdline += ["-extra-condition", "(%s & %u:reg8_t) == %u:reg8_t" % \
                            (name, mask, value & mask)]

        if mindist and preferred_value:
            cmdline += ["-preferred-value", "%s:0x%.2x" % (name, value)]
            
    else:
         concrete_bytes += [haddr]

    return cmdline


# ===-----------------------------------------------------------------------===
# Build cmdline arguments for making a memory location symbolic (bits set in
# the mask are asserted to make them concrete)
# ===-----------------------------------------------------------------------===
def make_mem_symbolic(haddr, gaddr, sym, values, masks, mindist = False):
    global symbolic_bytes, concrete_bytes

    cmdline = []

    assert len(values) == len(masks)

    for i in range(len(values)):
        cmdline += __make_mem_symbolic(haddr + i, gaddr + i, sym + "_%d" % i, 
                                       ord(values[i]), masks[i], mindist)

    return cmdline

# ===-----------------------------------------------------------------------===
# Mark a memory region as concrete
# ===-----------------------------------------------------------------------===
def make_mem_concrete(haddr, size):
    global symbolic_bytes, concrete_bytes

    cmdline = []

    for i in range(size):
        concrete_bytes += [haddr + i]

    return cmdline

# ===-----------------------------------------------------------------------===
# Build cmdline arguments for making a memory hardcoding the state of the
# descriptor cache
# ===-----------------------------------------------------------------------===
def make_extra_cond_desc(desc, sym, values, desc_cache):
    global tempfiles
    name, addr, size, idx = desc_cache

    cmdline = []
    extracond = ""

    print EXTRA_DESC_COND
    assert os.path.isfile(EXTRA_DESC_COND)

    for l in open(EXTRA_DESC_COND).readlines():
        if l.startswith("out_desc_"):
            l = l.split(" = ")
            out = l[0].split("_")[:-2]
            out = addr + int(out[-1])
            cond = " = ".join(l[1:])
            for i in range(8):
                # if the current byte of the descriptor is concrete replace the
                # input variable with the value
                if (phys_mem[0] + desc + i) in concrete_bytes:
                    cond = re.sub("in_desc_%d_\d+:reg8_t" % i, \
                                      "0x%x:reg8_t" % (ord(values[i])), 
                                  cond)
                else:
                    cond = re.sub("in_desc_%d_\d+:reg8_t" % i, \
                                      "in_mem_%.08x_%s_1_0:reg8_t" % \
                                      (desc + i, encode(sym + "_%d" % i)), cond)
            cond = cond.replace("pathcond_", "tmp_pathcond_")
            cond = cond.replace("out_", "tmp_out_")
            cond = cond.replace("\n", "")
#             print cond
            tmp = Tempfile(data = cond)
            #print ["0x%.8x" % out]
            #print str(tmp)
            cmdline += ["-symbolic-byte-expr-from-file", 
                        "0x%.8x=%s" % (out, str(tmp))]
#             cmdline += ["-symbolic-byte-expr", 
#                         "0x%.8x=%s" % (out, cond)]

            # Hold temporary files till the end of the execution
            tempfiles += [tmp]

    return cmdline

# ===-----------------------------------------------------------------------===
# Build cmdline arguments for making a register symbolic (bits set in the mask
# are asserted to make them concrete)
# ===-----------------------------------------------------------------------===
def make_reg_symbolic(haddr, name, size, value = 0, mask = 0, mindist = False):
    global symbolic_bytes, concrete_bytes

    cmdline = []
    value = chunk(value, size)[0]
    mask = chunk(mask, size)[0]

    for i in range(size):
        n = "in_%s__%d_%d" % (name, size, i)
        m, v = mask[i], value[i]
        if m < 0xff:
            cmdline += ["-symbolic-byte", "0x%.8x=%s" % (haddr + i, n)]
            symbolic_bytes += [haddr + i]
            if m > 0:
                cmdline += ["-extra-condition", 
                            "((%s & %u:reg8_t) == %u:reg8_t)" % (n, m, v & m)]
            if mindist and preferred_value:
                cmdline += ["-preferred-value", "%s:0x%.2x" % (n, v)]
        else:
            concrete_bytes += [haddr + i]
    
    return cmdline

# ===-----------------------------------------------------------------------===
# Build cmdline arguments for making a buffer symbolic (bits set in the mask
# are asserted to make them concrete)
# ===-----------------------------------------------------------------------===
def make_buf_symbolic(haddr, name, values, masks, extraname = ""):
    global symbolic_bytes, concrete_bytes

    cmdline = []

    for i in range(len(values)):
        name = "%s_%s_%d_%d" % (name, encode(extraname), len(values), i)
        mask = masks[i]
        value = ord(values[i])
        if mask < 0xff:
            cmdline = ["-symbolic-byte", "0x%.8x=%s" % (haddr, name)]
            symbolic_bytes += [haddr]
            if mask > 0:
                cmdline += ["-extra-condition", 
                            "(%s & %u:reg8_t) == %u:reg8_t" % \
                            (name, mask, value & mask)]
        else:
            concrete_bytes += [haddr]

    return cmdline

# ===-----------------------------------------------------------------------===
# Computer a set of regions in the physical memory which are neither concrete
# not symbolic (with on-disk caching)
# ===-----------------------------------------------------------------------===
@memoizable
def compute_missing_locs(ph, s, c):
    ph = uncluster([(ph[0], ph[0] + ph[1] - 1)])
    rem = set(ph) - set(s) - set(c)
    return cluster(rem)



os.environ["COLUMNS"] = str(columns())
title = "%s" % " ".join(usrcmdline)
pad = "#"*((columns() - len(title)) / 2 - 1)
print pad + " " + title + " " + pad

# ===-----------------------------------------------------------------------===
# Calculate information based on CPUX86State starting address
# ===-----------------------------------------------------------------------===
offset = 0
# General registers
for i in range(8):
    r, s, a = fuzzball_reg[i], 4, int(cpustate_addr+offset)
    cpu_regs += [(r, s, a)]
    offset += 4

# EIP
r, s, a = "reg_EIP", 4, int(cpustate_addr+offset)
eip = a
cpu_regs += [(r, s, a)]
offset += 4

# EFLAGS
r, s, a = "reg_EFLAGS", 4, int(cpustate_addr+offset)
cpu_regs += [(r, s, a)]
offset += 4

# Segment registers
offset += 28
for i in range(6):
    r, s, a = fuzzball_sreg[i], 4, int(cpustate_addr+offset)
    cpu_regs += [(r, s, a)]
    offset += 16

# LDTR
s, a = 4, int(cpustate_addr+offset)
ldtr = (s, a)
offset += 16

# TR
s, a = 4, int(cpustate_addr+offset)
tr = (s, a)
offset += 16

# GDTR
s0, a0, s1, a1 = 4, int(cpustate_addr+offset), 2, int(cpustate_addr+offset+4)
gdtr = (s0, a0, s1, a1)
offset += 16

# IDTR
s0, a0, s1, a1 = 4, int(cpustate_addr+offset), 2, int(cpustate_addr+offset+4)
idtr = (s0, a0, s1, a1)
offset += 16

# Control registers
for i in range(5):
    if i != 4:
        r, s, a = "creg_CR%d" % i, 4, int(cpustate_addr+offset)
        cpu_regs += [(r, s, a)]
    offset += 4

# Debug registers
offset += 548
for i in range(8):
    if i != 4 and i != 5:
        r, s, a = "dreg_DR%d" % i, 4, int(cpustate_addr+offset)
        cpu_regs += [(r, s, a)]
    offset += 4
# Exception index
offset += 34132
exception = int(cpustate_addr+offset)

# ===-----------------------------------------------------------------------===
# generate a coredump
#da ===-----------------------------------------------------------------------===
if corefile:
    t1 = time.time()
    print "Generating core dump...",
    sys.stdout.flush()

    # Generate a coredump using gdb and get the address of the TLS by calling a
    # function in the binary
    gdbout = Tempfile()
    cmd = "break *0x%x\nrun\nset logging file %s\nset logging on\n" \
        "print/x 0x%x()\nset logging off\ngenerate-core-file %s" % \
        (coredump_address, str(gdbout), get_tls, str(corefile))

    tmp = Tempfile(data = cmd)
    print cmd
    print str(usrcmdline)
    print str(tmp)
    print GDB
    p = subprocess.check_call([GDB, "-q", "-batch", "-x", str(tmp), "-args"] + \
                                    usrcmdline, stdout = NULL, stderr = NULL)#, shell = True)
    assert p == 0
    print "done (%.3fs)" % (time.time() - t1)
    
    assert corefile.read(7) == "\x7f\x45\x4c\x46\x01\x01\x01"

    # Prase the output of gdb to get the base of the TLS
    gdbout = gdbout.read()
    assert gdbout.startswith("$1 = ")
    tls_base = int(gdbout.split(" = ")[1], 16)


# ===-----------------------------------------------------------------------===
# Registers
# ===-----------------------------------------------------------------------===
for r, s, a in cpu_regs:
    if r.startswith("reg_") and symbolic_regs and not r in ["reg_EIP"]:
        cmdline +=make_reg_symbolic(a, r, s)
        if dump_region:
            cmdline += ["-dump-region", "0x%.8x:%d=out_%s__%d" % (a, s, r, s)]

    if r.startswith("sreg_") and symbolic_sregs:
        if KERNEL:
            v = getattr(snapshot.cpus[0].sregs_state,
                    r.strip("sreg_").lower()).selector
        else:
            v = 0
        cmdline += make_reg_symbolic(a, r, 2, v, 0xfffc)
        if dump_region:
            cmdline += ["-dump-region", "0x%.8x:%d=out_%s__%d" % (a, 2, r, s)]

    if r.startswith("creg_") and symbolic_cregs:
        v, m, z = 0, 0, False
        if r == "creg_CR3":
            if KERNEL:
                v = snapshot.cpus[0].sregs_state.cr3
            m = CR3_PAGING_MASK
            z = True
        elif r == "creg_CR0":
            if KERNEL:
                v = snapshot.cpus[0].sregs_state.cr0
            m = (1<<31) | 1
            z = True
        elif r == "creg_CR4":
            if KERNEL:
                v = snapshot.cpus[0].sregs_state.cr4
            m = (1 << 4) | (1 << 5)
            z = True
            
        cmdline += make_reg_symbolic(a, r, s, v, m, z)
        if dump_region:
            cmdline += ["-dump-region", "0x%.8x:%d=out_%s__%d" % (a, s, r, s)]

    if r.startswith("dreg_") and symbolic_dregs:
        cmdline += make_reg_symbolic(a, r, s)
        if dump_region:
            cmdline += ["-dump-region", "0x%.8x:%d=out_%s__%d" % (a, s, r, s)]


# ===-----------------------------------------------------------------------===
# GDT
#
# |---------------------------------------------|
# |             Segment Descriptor              |
# |---------------------------------------------|
# |33222222|2|2|2|2| 11 11 |1|11|1|11  |        |
# |10987654|3|2|1|0| 98 76 |5|43|2|1098|76543210|
# |--------|-|-|-|-|-------|-|--|-|----|--------|
# |Base    |G|D|L|A|Limit  |P|D |S|Type|Base    |
# |[31-24] | |/| |V|[19-16]| |P | |    |[23-16] |
# |        | |B| |L|       | |L | |    |        |
# |------------------------|--------------------|
# |       Base [15-0]      |    Limit [15-0]    |
# |------------------------|--------------------|
# ===-----------------------------------------------------------------------===
if KERNEL:
    gdt_base = snapshot.cpus[0].sregs_state.gdtr.base
    gdt_limit = snapshot.cpus[0].sregs_state.gdtr.limit
    gdt_data = snapshot.mem.data[gdt_base:gdt_base+gdt_limit]
    # keep limit, base, s, and g concrete
    # masks = [0xff, 0xff, 0xff, 0xff, 0xff, 0x10, 0xf|0x80, 0xff]
    # keep base, s, type, and g concrete
    mask = [0x0, 0x0, 0xff, 0xff, 0xff, 0x0, 0x40, 0xff]
    print "gdt_limit: %d" % gdt_limit
    for i in range(1, gdt_limit / 8):
        data = gdt_data[i*8:(i+1)*8]
        ga = gdt_base + i*8
        ha = ga + phys_mem[0]
        sym = "GDT_%d_8" % i
        if symbolic_gdt:
            cmdline += make_mem_symbolic(ha, ga, sym, data, mask, True)
            for desc in descrs:
                if desc[3] == i:
                    cmdline += make_extra_cond_desc(ga, sym, data, desc)

        else:
            cmdline += make_mem_concrete(ha, len(data))
        
# ===-----------------------------------------------------------------------===
# IDT
# ===-----------------------------------------------------------------------===
if KERNEL:
    idt_base = snapshot.cpus[0].sregs_state.idtr.base
    idt_limit = snapshot.cpus[0].sregs_state.idtr.limit
    idt_data = snapshot.mem.data[idt_base:idt_base+idt_limit]
    masks = [0xff, 0xff, 0xff, 0xff, 0x0, 0x0, 0xff, 0xff]
    for i in range(1, idt_limit / 8):
        data = idt_data[i*8:(i+1)*8]
        ga = idt_base + i*8
        ha = ga + phys_mem[0]
        sym = "IDT_%d_8" % i
        if symbolic_idt:
            cmdline += make_mem_symbolic(ha, ga, sym, data, mask, True)
        else:
            cmdline += make_mem_concrete(ha, len(data))


# ===-----------------------------------------------------------------------===
# PAGE TABLE
# XXX: currently supports 32-bit non PAE
#
# Format of a 32-Bit Page-Directory Entry that References a Page Table
# -----------------------------------------------------------
# 00    | Present (P)
# 01    | R/W
# 02    | U/S
# 03    | Page-Level Write-Through (PWT)
# 04    | Page-Level Cache-Disable (PCD)
# 05    | Accessed (A)
# 06    | (ignored)
# 07    | Page size (If CR4.PSE = 1, must be 0 (otherwise, this entry maps a
#       |  4-MByte page); otherwise, ignored
# 11-08 | (ignored)
# 31-12 | Physical address of the 4-KByte page
# -----------------------------------------------------------
#
# Format of a 32-Bit Page-Table Entry that Maps a 4-KByte Page
# -----------------------------------------------------------
# 00    | Present (P)
# 01    | R/W
# 02    | U/S
# 03    | Page-Level Write-Through (PWT)
# 04    | Page-Level Cache-Disable (PCD)
# 05    | Accessed (A)
# 06    | Dirty (D)
# 07    | PAT (if PAT is supported, reserved otherwise)
# 08    | Global (G) (if CR4.PGE=1, ignored otherwise)
# 11-09 | (ignored)
# 31-12 | Physical address of the 4-KByte page
# -----------------------------------------------------------
# ===-----------------------------------------------------------------------===
if KERNEL:
    cr0 = snapshot.cpus[0].sregs_state.cr0
    cr4 = snapshot.cpus[0].sregs_state.cr4
    cr3 = snapshot.cpus[0].sregs_state.cr3 & CR3_PAGING_MASK
    assert (cr0 & CR0_PG) and not (cr4 & CR4_PAE)

    deref4 = lambda x: deref(snapshot.mem.data, x, 4)
    chunk4 = lambda x: chunk(x)[0]
    pde_mask = pte_mask = [0x00, 0xff, 0xff, 0xff]
    ptes_done = set()
    for i in range(bit(10)):
        pde = cr3 + i*4
        pde_data = snapshot.mem.data[pde:pde+4]
        pde_ha = pde + phys_mem[0]
        if deref4(pde) & 1:
            sym = "PDE_%d_4" % i
            if symbolic_pt:
                cmdline += make_mem_symbolic(pde_ha, pde, sym, pde_data, pde_mask)
            else:
                cmdline += make_mem_concrete(pde_ha, len(pde_data))

            if (deref4(pde) & CR3_PAGING_MASK) in ptes_done:
                # Skip PTE if already seen
                continue

            for j in range(bit(10)):
                pte = (deref4(pde) & CR3_PAGING_MASK) + j*4
                pte_data = snapshot.mem.data[pte:pte+4]
                pte_ha = pte + phys_mem[0]
                if deref4(pte) & 1:
                    sym = "PTE_%d_4" % i
                    if symbolic_pt:
                        cmdline += make_mem_symbolic(pte_ha, pte, sym, pte_data,
                                                     pte_mask, True)
                    else:
                        cmdline += make_mem_concrete(pte_ha, len(pte_data))

                else:
                    cmdline += make_mem_concrete(pte_ha, len(pte_data))

            # Mark the PTE as processed in case multiple PDEs point to the same PTE
            ptes_done.add(deref4(pde) & CR3_PAGING_MASK)

        else:
            cmdline += make_mem_concrete(pde_ha, len(pde_data))


# ===-----------------------------------------------------------------------===
# Additional symbolic regions
# ===-----------------------------------------------------------------------===
# for a, l, n in symbolic_mem_regions:
#    cmdline += make_mem_symbolic(a + phys_mem[0], a, n, "\x00"*l, 
#                                 [0 for _ in range(l)])

if symbolic_metadata:
    print "METADATA", metadata
    print "METAINFO", metainfo1
    mask = 0x0 # nnn
    cmdline += make_buf_symbolic(metadata[0] + 2, "in_metadata2", 
                                 metadata[2][2], [mask & 0xff])
    mask = ~(1 << 2) # mod == c0
    cmdline += make_buf_symbolic(metainfo1[0], "in_metainfo1", metainfo1[2],
                                 [mask & 0xff])


# ===-----------------------------------------------------------------------===
# Make the remaining of the physical memory as symbolic (lazily)
# ===-----------------------------------------------------------------------===
symbytes_no = len(symbolic_bytes)

remaining_bytes = compute_missing_locs(phys_mem, symbolic_bytes, concrete_bytes)
for first, last in remaining_bytes:
    # print "Lazy symbolic bytes: %.8x-%.8x" % (first, last)
    cmdline += ["-symbolic-region", "0x%.8x+%u" % \
                    (first, last - first + 1)]
    # symbytes_no = symbytes_no + (last - first + 1)

# print "***", symbytes_no
# exit(0)

# ===-----------------------------------------------------------------------===
# Monitor the final state of the memory/fpu/exception
# ===-----------------------------------------------------------------------===
if dump_region:
    cmdline += ["-dump-region", "0x%.8x:%u=out_mem___1" % phys_mem]
    #cmdline += ["-dump-region", "0x%.8x:%u=out_fpu___%u" % (fpu[0], fpu[1], fpu[1])]
    #cmdline += ["-dump-region", "0x%.8x:4=out_exception___4" % exception]
    #cmdline += ["-dump-region", "0x%.8x:%u=out_msrs___%u" % (msrs[0], msrs[1], msrs[0])]
# TODO: port -exit-status-exp from emuFuzzBALL for better debugging
#cmdline += ["-exit-status-exp", "exception#" + vine_for_mem(exception)]
#cmdline += ["-exit-status-exp", "eip#" + vine_for_mem(eip)]

cmdline += ["-fuzz-start-addr", "0x%.8x" % start_address]
cmdline += ["-fuzz-end-addr", "0x%.8x" % end_address]
#cmdline += ["-trace-insns"]
for a in ignore_paths:
    cmdline += ["-ignore-path", "0x%.8x" % a]
for a in stop_addresses:
    cmdline += ["-symulate-exit", "0x%.8x" % a]
if ignore_pathcond_till:
    cmdline += ["-ignore-pc-till", "0x%.8x" % ignore_pathcond_till]
if start_tracing_address:
    cmdline += ["-trace-from", "0x%.8x" % start_tracing_address]

# Record the exception occurred
for a, s in exception_handlers:
    cmdline += ["-concretize-expr", "0x%.8x#%s#%s" % 
                (a, vine_for_mem(exception), vine_for_stack(s))]
    if stop_at_exceptions:
        cmdline += ["-simulate-exit", "0x%.8x" % a]

# Concretize virtual addresses
for a, s in read_virt_mem_handlers + write_virt_mem_handlers:
    cmdline += ["-concretize-expr", "0x%.8x#%s#" % 
                (a, vine_for_stack(s))]   
 
# for a, s in write_virt_mem_handlers:
#     cmdline += ["-concretize-expr", "0x%.8x#%s#" % 
#                 (a, vine_for_stack(s))]

for a, r, n in ignored_calls:
    if n in ignored_functions:
        cmdline += ["-skip-func-ret", "0x%.8x=%u" % (a, r)]

try:
    os.mkdir(OUTDIR)
except OSError:
    pass

if corefile:
    cmdline += ["-core", str(corefile)]
    cmdline += ["-tls-base", "0x%.8x" % tls_base]


cmdline = FUZZBALL.split() + FUZZBALL_ARGS.split() + cmdline + \
    [usrcmdline[0], "--"] + usrcmdline

cmdline_ = " ".join(cmdline)
if len(cmdline_) >= columns()*3:
    cmdline_ = cmdline_[:columns()*3 - 8] + "..."

print "Starting FuzzBall:", cmdline_
print "#"*columns()
print

open("/tmp/fuzzball.cmd", "w").write(" ".join(["\"%s\"" % c for c in cmdline]))

if KERNEL:
    open("%s/snapshot" % OUTDIR, "w").write(snapshot_md5)
open("%s/cmdline" % OUTDIR, "w").write("\x00".join(usrcmdline))
open("%s/exe" % OUTDIR, "w").write(md5(open(usrcmdline[0])))
#open("%s/shellcode" % OUTDIR, "w").write(shellcode)

r = subprocess.call(cmdline)

open("%s/exitstatus" % OUTDIR, "w").write(str(r))
open("%s/time" % OUTDIR, "w").write("%f" % (time.time() - t0))

try:
    os.rmdir("./fuzzball-tmp-1")
except OSError:
    pass

print "Run completed in %.3fs" % (time.time() - t0)
