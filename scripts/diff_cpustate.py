#!/usr/bin/python

# This file is part of KEmuFuzzer.
# 
# KEmuFuzzer is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
# 
# KEmuFuzzer is distributed in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License along with
# KEmuFuzzer.  If not, see <http://www.gnu.org/licenses/>.


import sys, gzip, copy
from cpustate_x86 import *
from os.path import isfile, isdir, dirname, basename, abspath, join as joinpath

ROOT = abspath(joinpath(dirname(abspath(__file__)), ".."))
KERNEL = joinpath(ROOT, "Kernel/kernel")


# ===-----------------------------------------------------------------------===
# Create a dummy segement descriptor
# ===-----------------------------------------------------------------------===
def null_segment_descriptor():
    s = segment_reg_t()
    s.base     = 0
    s.limit    = 0
    s.selector = 0
    s.present  = 0
    s.type     = 0
    s.dpl      = 0
    s.db       = 0
    s.s        = 0
    s.l        = 0
    s.g        = 0
    s.avl      = 0
    s.unusable = 0

    return s


# ===-----------------------------------------------------------------------===
# Return the name of the emulator
# ===-----------------------------------------------------------------------===
def emulator_name(d):
    if is_valid_type(d.hdr.type):
        s = "%16s" % EMULATORS[d.hdr.emulator][:16]
    else:
        s = colorize("%16s" % EMULATORS[d.hdr.emulator][:16])
    return s


# ===-----------------------------------------------------------------------===
# Recurse trough the various fields of the CPU state and parse them
# ===-----------------------------------------------------------------------===
def parse_state_recurse(d, p, h = None):
    fields = getattr(d, "_fields_", None)

    if h is None:
        h = {}

    if p in ["hdr.kernel_version", "hdr.kernel_checksum", 
             "hdr.testcase_checksum"]:
        h[p] = d
    # dirty hack to detect ctypes array
    elif getattr(d, "__getslice__", None):
        # Index MSR registers by their idx
        if "msrs_state.msr_regs" in p:
            for e in range(h[p.replace(".msr_regs", ".n")]):
                h["%s[%.8x]" % (p, d[e].idx)] = d[e].val
        else:
            for e in range(len(d)):
                parse_state_recurse(d[e], "%s[%d]" % (p, e), h)
    elif not fields:
        h[p] = d
    else:
        for n,t in fields:
            parse_state_recurse(getattr(d, n), "%s.%s" % (p, n), h)


# ===-----------------------------------------------------------------------===
# Parse the CPU state and return a dict
# ===-----------------------------------------------------------------------===
def parse_state(d):
    h = {}
    parse_state_recurse(d.hdr, "hdr", h)

    for i in range(h["hdr.cpusno"]):
        parse_state_recurse(d.cpus[i], "cpu[%d]" % i, h)

    h["mem"] = d.mem.data

    return h


# ===-----------------------------------------------------------------------===
# Add colors to strings
# ===-----------------------------------------------------------------------===
RED    = 31
GREEN  = 32
YELLOW = 33
BLUE   = 34
GREY   = 37

def colorize(s, color = RED):
    return (chr(0x1B) + "[0;%dm" % color + str(s) + chr(0x1B) + "[0m")


# ===-----------------------------------------------------------------------===
# Return a colorized diff
# ===-----------------------------------------------------------------------===
def pretty_diff(dd):
    assert not diff([len(d) for d in dd])

    ddc = ["" for i in range(len(dd))]

    for i in range(len(dd[0])):
        di = [d[i] for d in dd]
        for j in range(len(di)):
            d = di[j]
            if d != " " and diff(di):
                if (len(filter(lambda a: a == d, di)) / float(len(di))) > \
                        2/float(3):
                    color = GREEN
                elif (len(filter(lambda a: a == d, di)) / float(len(di))) > \
                        1/float(3):
                    color = YELLOW
                else:
                    color = RED
                ddc[j] += colorize(d, color)
            else:
                ddc[j] += d

    return ddc


# ===-----------------------------------------------------------------------===
# Return true if a difference is found
# ===-----------------------------------------------------------------------===
def diff(dd):
    return len(set(dd)) > 1


# ===-----------------------------------------------------------------------===
# Compute differences between CPU states
# ===-----------------------------------------------------------------------===
def diff_dumps(files, kernel_dir = None, update_guest = False,
               pretty_print = False, strict_check = True, normalize = True):
    crashed = 0

    dumps = []
    for f in files:
        try:
            d = gzip.open(f).read()
        except IOError:
            d = open(f).read()

        d = X86Dump(d, kernel_dir)

        dumps += [d]

    kernel_versions = [d.hdr.kernel_version for d in dumps]
    kernel_checksums = [d.hdr.kernel_checksum for d in dumps]
    testcase_checksums = [d.hdr.testcase_checksum for d in dumps]

    if strict_check:
        if diff(kernel_versions):
            print "[W] Mismatching kernel version: %s" % \
                (" ".join(kernel_versions))

        assert not diff(kernel_checksums), \
            "[!] Mismatching kernel checksum: %s" % \
        (" ".join(kernel_checksums))

        assert not diff(testcase_checksums), \
            "[!] Mismatching testcase checksum: %s" % \
            (" ".join(testcase_checksums))

    mem_sizes = []
    for d in dumps:
        if is_valid_type(d.hdr.type):
            mem_sizes.append(d.hdr.mem_size)

    assert not diff(mem_sizes), \
        "[!] Mismatching guest memory sizes: %s" % (" ".join(mem_sizes))

    for d in dumps:
        if d.hdr.type & IO_TESTCASE:
            return (IO_TESTCASE, [])

    tmp = None
    for d in dumps:
        if is_valid_type(d.hdr.type):
            tmp = d
            break

    if tmp is not None:
        # Fix CPU and memory states for invalid dumps
        for d in dumps:
            if not is_valid_type(d.hdr.type):
                d.hdr.mem_size = tmp.hdr.mem_size
                d.hdr.cpusno = 1
                d.cpus.append(tmp.cpus[0])
                d.mem = X86DumpMemory("?"*tmp.hdr.mem_size)
                crashed = CRASH_TESTCASE

    if normalize:
        normalize_states(dumps)

    if update_guest:
        for d in dumps:
            if is_valid_type(d.hdr.type):
                for i in range(len(d.cpus)):
                    d.guess_guest_ctx(i)

    states = [parse_state(d) for d in dumps]
    keys = states[0].keys()
    keys.sort()

    # Header
    if not diff(kernel_versions) and dumps[0].kernel:
        print "%41s" % "(RED = invalid dump)" + \
            " ".join([emulator_name(d) for d in dumps]) \
            + " %32s" % " Section/Symbol"
        print "="*(41+(len(dumps)-1)+(16*len(dumps))+33)
    else:
        print "%41s" % "(RED = invalid dump)" + \
            " ".join([emulator_name(d) for d in dumps]) 
        print "="*(41+(len(dumps)-1)+(16*len(dumps)))

    dd = []

    

    for k in keys:
        # Fields to be ignored
        if k in ["hdr.emulator"]:
            continue

        if not strict_check:
            if k in ["hdr.testcase_checksum", "hdr.kernel_version", 
                     "hdr.kernel_checksum"]:
                continue

        if k == "mem":
            # Skip the first MB where all devices are mapped
            for j in range(1024*1024, len(states[0][k]), 4096):
                # Quick check (if the content of the pages is the same it is
                # useless to perform a more fine grained comparison)
                ss = [s[k][j:j+4096] for s in states]
                if not diff(ss):
                    continue

                tmp = set(ss)
                if len(tmp) == 2 and '?'*4096 in tmp:
                    # There is only a difference on an invalid state
                    continue

                for i in range(j, j + 4096, 4):
                    if i in [0x20cfd8, 0x20cfdc, 0x20cfe0]:
                        continue
                    ss = [s[k][i:i+4] for s in states]

                    tmp = set(ss)
                    dummy_diff = (len(tmp) == 2 and '????' in tmp)
                    
                    if diff(ss) and not dummy_diff:
                        ww = []
                        for s in ss:
                            if s[:4] == '????':
                                data = '????'
                            else:
                                data = "%.2x%.2x%.2x%.2x" % (ord(s[0]), ord(s[1]), 
                                                             ord(s[2]), ord(s[3]))
                            w = "%16s" % data
                            ww.append(w)

                        if pretty_print:
                            ww = pretty_diff(ww)

                        # resolve symbols
                        sec = ""
                        if not diff(kernel_versions) and dumps[0].kernel:
                            if dumps[0].kernel.findSection(i):
                                sec = dumps[0].kernel.findSection(i)
                                sec = "%s (%x)" % (sec.getName(), sec.getLowAddr())
                            for sym in dumps[0].kernel.getSymbol():
                                if sym.getAddress() <= i and \
                                        sym.getAddress() + sym.getSize() >= i:
                                    if sym.getName() in ["gdt", "idt"]:
                                        sec = "%s[%d]" % (sym.getName(), 
                                                          (i - sym.getAddress()) / 8)
                                    elif sym.getName().startswith("tss"):
                                        sec = "%s[%d]" % (sym.getName(), 
                                                          (i - sym.getAddress()))
                                    else:
                                        sec = "%s (%x)" % (sym.getName(), 
                                                           sym.getAddress())
                                    break

                        # Record this difference
                        data = []
                        for s in states:
                            m = s[k][i:i+4]
                            e = s['hdr.emulator']
                            t = s['hdr.type']
                            data.append((m,e,t))
                        dd.append((k, i, data))

                        print "%-40s %s %32s" % ("%s[%.16x]" % (k, i), 
                                                 " ".join(ww), sec)

                    elif diff(ss):
                        data = []
                        for s in states:
                            m = s[k][i:i+4]
                            e = s['hdr.emulator']
                            t = s['hdr.type']
                            data.append((m,e,t))
                        dd.append((k, i, data))

        else:
            skip = False
            for s in states:
                if not k in s:
                    skip = True
                    break

            if skip:
                continue

            ss = []
            for s in states:
                if not is_valid_type(s["hdr.type"]):
                    v = "????"
                else:
                    v = s[k]
                ss.append(v)

            tmp = set(ss)
            dummy_diff = len(tmp) == 2 and "????" in tmp

            if diff(ss) and not dummy_diff:
                if k in ["hdr.kernel_version", "hdr.kernel_checksum", 
                         "hdr.testcase_checksum"]:
                    ww = ["%16s" % s[:16] for s in ss]
                    if pretty_print:
                        ww = [colorize(w) for w in ww]
                else:
                    ww = []
                    for s in ss:
                        if s == "????":
                            ww.append("%16s" % s)
                        else:
                            ww.append("%16x" % s)

                    if pretty_print:
                        ww = pretty_diff(ww)


                # Record this difference
                data = []
                for s in states:
                    v = s[k]
                    e = s['hdr.emulator']
                    t = s['hdr.type']
                    data.append((v,e,t))
                dd.append((k, None, data))

                print "%-40s %s" % (k, " ".join(ww))

            elif diff(ss):
                # Record this difference
                data = []
                for s in states:
                    v = s[k]
                    e = s['hdr.emulator']
                    t = s['hdr.type']
                    data.append((v,e,t))
                dd.append((k, None, data))
                
#            elif k == "cpu[0].regs_state.rip":
#                eips = ""
#                for s in states:
#                    if eips: eips += " "
#                    eips += colorize("%16x" % s[k], GREEN)
#                print "%-40s %s" % (k, eips)

    
    return (crashed, dd)
             
       
# ===-----------------------------------------------------------------------===
# Normalize cpu states to remove spurios differences
# ===-----------------------------------------------------------------------===
def normalize_states(dumps):
    # These normalizations are used to ignore state fields that are not updated
    # by the emulator drivers
    emulators = [d.hdr.emulator for d in dumps]

    # Consider only the first 32 bits of general purpose registers
    for d in dumps:
        for c in d.cpus:
            r = c.regs_state
            r.rip &= 0xffffffff
            r.rflags &= 0xffffffff
            r.rax &= 0xffffffff
            r.rbx &= 0xffffffff
            r.rcx &= 0xffffffff
            r.rdx &= 0xffffffff
            r.rsi &= 0xffffffff
            r.rdi &= 0xffffffff
            r.rsp &= 0xffffffff
            r.rbp &= 0xffffffff

            if EMULATOR_QEMU in emulators:
                c.sregs_state.cr0 |= 0xe0000000

            for st in c.fpu_state.st:
                # Ignore FPU reserved bits
                st.reserved[5] = 0
                # Ignore other FPU stuff
                st.expsign = 0
                st.mantissa = 0

            # Ignore other FPU stuff
            c.fpu_state.mxcsr = 0
            c.fpu_state.mxcsr_mask = 0
            c.fpu_state.ftw = 0
            c.fpu_state.fpuip = 0 # Not kept by QEMU
            c.fpu_state.fpudp = 0 # Not kept by QEMU
            for xmm in c.fpu_state.xmm:
                for i in range(len(xmm.data)):
                    xmm.data[i] = 0

            if d.hdr.emulator == EMULATOR_KVM:
                c.regs_state.rflags &= ~0x10000

            # ignore ZF, SF, PF, AF, ...
#            c.regs_state.rflags &= ~(1 | 1 << 2 | 1 << 4 | 1 << 6 | 1 << 7 | 1 << 11)

        # Ignore accessed bit in PDEs and PTEs (because BOCHS does not set it)
        if EMULATOR_BOCHS in emulators and dumps[0].kernel:
            pd = dumps[0].kernel.getSymbol("pd")
            pt = dumps[0].kernel.getSymbol("pt")
            assert pd and pt

            pd_data = ""
            for i in range(pd.getAddress(), pd.getAddress() + pd.getSize(), 4):
                pd_data += chr(ord(d.mem.data[i]) & ~0x20) + d.mem.data[i+1:i+4]
            d.mem.data = d.mem.data[:pd.getAddress()] + pd_data + \
                d.mem.data[pd.getAddress() + pd.getSize():]
            assert len(d.mem.data) == d.hdr.mem_size

            pt_data = ""
            for i in range(pt.getAddress(), pt.getAddress() + pt.getSize(), 4):
                pt_data += chr(ord(d.mem.data[i]) & ~0x20) + d.mem.data[i+1:i+4]
            d.mem.data = d.mem.data[:pt.getAddress()] + pt_data + \
                d.mem.data[pt.getAddress() + pt.getSize():]
            assert len(d.mem.data) == d.hdr.mem_size

    # Ignore the eflags field in the tss of Exception#5
    for d in dumps:
        tss = dumps[0].kernel.getSymbol("tssEXCP05")
        assert tss

        tss_data = ""
        for i in range(tss.getAddress(), tss.getAddress() + tss.getSize(), 105):
            tss_data += d.mem.data[i: i+35] + chr(ord(d.mem.data[i+36]) & ~0xff) + \
                    chr(ord(d.mem.data[i+37]) & ~0xff) + d.mem.data[i+38: i+105]
        d.mem.data = d.mem.data[:tss.getAddress()] + tss_data + d.mem.data[tss.getAddress() + tss.getSize():]
        assert len(d.mem.data) == d.hdr.mem_size

    # Ignore the eflags field in the tss of Exception#32
    for d in dumps:
        tss = dumps[0].kernel.getSymbol("tssEXCP32")
        assert tss

        tss_data = ""
        for i in range(tss.getAddress(), tss.getAddress() + tss.getSize(), 105):
            tss_data += d.mem.data[i: i+35] + chr(ord(d.mem.data[i+36]) & ~0xff) + \
                    chr(ord(d.mem.data[i+37]) & ~0xff) + d.mem.data[i+38: i+105]
        d.mem.data = d.mem.data[:tss.getAddress()] + tss_data + d.mem.data[tss.getAddress() + tss.getSize():]
        assert len(d.mem.data) == d.hdr.mem_size

    # Ignore dr{0,1,2,3,6} because not virtualized, also ignore dr7
    for d in dumps:
        for c in d.cpus:
            c.sregs_state.dr0 = 0
            c.sregs_state.dr1 = 0
            c.sregs_state.dr2 = 0
            c.sregs_state.dr3 = 0
            c.sregs_state.dr6 = 0
            c.sregs_state.dr7 = 0

    # Keep only meaningful MSRs
    MSR_REGS = [X86_MSR_IA32_SYSENTER_CS, X86_MSR_IA32_SYSENTER_ESP, 
                X86_MSR_IA32_SYSENTER_EIP]
    for d in dumps:
        for c in d.cpus:
            c.msrs_state.n = len(MSR_REGS)         
            for r in c.msrs_state.msr_regs:
                if not r.idx in MSR_REGS:
                    r.idx = 0
                    r.val = 0            

    # Ignore segment descriptors cache
    # for d in dumps:
    #     if not is_valid_type(d.hdr.type):
    #         continue
    #     i = 0
    #     for c in d.cpus:
    #         for seg in [c.sregs_state.cs, c.sregs_state.ds, c.sregs_state.es, 
    #                     c.sregs_state.fs, c.sregs_state.gs, c.sregs_state.ss]:
    #             seg = d.parse_seg(i, seg.selector)
    #         i += 1


def main():
    args = {
        "update_guest" : os.getenv("KEMUFUZZER_UPDATE_GUEST", False),
        "pretty_print" : os.getenv("KEMUFUZZER_PRETTY_PRINT", False),
        "strict_check" : os.getenv("KEMUFUZZER_STRICT_CHECK", True),
        "kernel_dir" : os.getenv("KEMUFUZZER_KERNEL_DIR", None),
        "normalize" : os.getenv("KEMUFUZZER_NORMALIZE_DUMP", True),
        }

    dumps = []

    for i in sys.argv[1:]:
        try:
            a, v = i.split(":")
            args[a] = v
        except Exception:
            dumps += [i]
        
    assert len(dumps) >= 1

    if len(dumps) >= 2:
        update_guest = bool(args["update_guest"])
        kernel_dir = args["kernel_dir"]
        pretty_print = bool(args["pretty_print"])
        strict_check = bool(args["strict_check"])
        normalize = bool(args["normalize"])

        # diff
        status, found_diffs = diff_dumps(dumps, update_guest = update_guest, 
                                         kernel_dir = kernel_dir,
                                         pretty_print = pretty_print,
                                         strict_check = strict_check,
                                         normalize = normalize)

        if len(found_diffs) == 0 or status == IO_TESTCASE:
            sys.exit(0)

        if status == CRASH_TESTCASE:
            sys.exit(1)

        # len(found_diffs) > 2 or status == TIMEOUT_TESTCASE:
        sys.exit(2)
    else:
        # read a single dump file from stdin
        try:
            data = gzip.open(dumps[0]).read()
        except IOError:
            data = open(dumps[0]).read()

        d = X86Dump(data, kernel_dir = args["kernel_dir"])
        if is_valid_type(d.hdr.type):
            if args["update_guest"]:
                for i in range(len(d.cpus)):
                    d.guess_guest_ctx(i)

        print d

if __name__ == "__main__":
    main()

