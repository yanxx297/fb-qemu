import os, sys, subprocess, struct, base64, re, stat, hashlib, gzip, pickle
import tempfile as tempfile_
import lockfile
from memoizable import memoizable_disk as memoizable

NULL = open("/dev/null", "w")

# ===-----------------------------------------------------------------------===
# Temporary auto-deleting file
# ===-----------------------------------------------------------------------===
class Tempfile:
    def __init__(self, delete = True, data = None, mod = 0600, **kwargs):
        tempfd, self.temp = tempfile_.mkstemp(**kwargs)
        os.close(tempfd)
        self.delete = delete
        if data is not None:
            open(self.temp, "w").write(data)
        os.chmod(self.temp, mod)

    def __del__(self):
        if self.delete and os.path.isfile(self.temp):
            os.unlink(self.temp)

    def __str__(self):
        return self.temp

    def read(self, n = None):
        if n is not None:
            return open(self.temp).read(n)
        else:
            return open(self.temp).read()

    def write(self, data):
        open(self.temp, "w").write(data)


def md5(obj):
    if isinstance(obj, file):
        obj = obj.read()
    return hashlib.md5(obj).hexdigest()

# ===-----------------------------------------------------------------------===
# Add colors to strings
# ===-----------------------------------------------------------------------===
RED    = 31
GREEN  = 32
YELLOW = 33
BLUE   = 34

def colorize(s, color = RED):
    return (chr(0x1B) + "[0;%dm" % color + str(s) + chr(0x1B) + "[0m")

red = lambda s: colorize(s, RED)
green = lambda s: colorize(s, GREEN)
blue = lambda s: colorize(s, BLUE)
YELLOW = lambda s: colorize(s, YELLOW)

def mkdir(d):
    try:
        os.mkdir(d)
    except OSError:
        pass

# ===-----------------------------------------------------------------------===
# Disassemble a buffer
# ===-----------------------------------------------------------------------===
# def disasm(buf, n = 1):
#     tmp = Tempfile(data = buf)
#     cmdline = "objdump -m i386 -b binary --wide --no-show-raw-insn -D %s" % \
#         (str(tmp))
#     p = subprocess.Popen(cmdline.split(), stdout = subprocess.PIPE)
#     out = []
#     for l in p.communicate()[0].split("\n"):
#         m = re.match("[ \t]*[0123456789abcedfABCDEF]+:[ \t]*(.*)", l)
#         if m:
#             out += [re.sub(" +", " ", m.group(1))]
#     if n == 1:
#         if out:
#             return out[0]
#         else:
#             return "?????"
#     else:
#         return out[:min(n, len(out))]
def disasm(s, base = 0):
    try:
        p = subprocess.Popen(["ndisasm", "-u", "-", "-o", "0x%x" % base], 
                             stdin=subprocess.PIPE, 
                             stdout=subprocess.PIPE)
        out = p.communicate(s)[0]
    except OSError:
        return ["?????????????"]

    insts = []
    for l in out.split("\n"):
        l = l.strip(" \t\r\n")
        if len(l) == 0:
            continue
        l = l.split()
        insts.append(" ".join(l[2:]))

    return insts


# ===-----------------------------------------------------------------------===
# Return the list of rets in a given function (very dirty!!!)
# ===-----------------------------------------------------------------------===
def retaddrs(prog, entry):
    cachefile = "/tmp/retaddrs.cache"

    if os.path.isfile(cachefile) and \
            mtime(cachefile) > mtime(prog):
        cache = pickle.load(open(cachefile))
    else:
        cache = {}

    if entry in cache:
        return cache[entry]

    p = subprocess.Popen(["objdump", "-d", prog], stdout = subprocess.PIPE)
    out = p.communicate()[0]
    found_entry = False
    rets = []
    for l in out.split("\n"):
        l = l.replace("\t", " ")
        m = re.match("([0123456789abcdef]+) <.*>:", l)
        if m:
            if int(m.group(1), 16) == entry:
                found_entry = True
            elif found_entry:
                break
            else:
                continue

        if found_entry:
            m = re.match(" *([0123456789abcdef]+):.{23}ret", l)
            if m:
                rets += [int(m.group(1), 16)]

    cache[entry] = rets
    pickle.dump(cache, open(cachefile, "w"))

    return rets


def cluster(ii):
    ii = list(ii)
    ii.sort()
   
    oo = []
    last = None

    for i in ii:
        if last is not None and i == last + 1:
            oo[-1] = (oo[-1][0], i)
        else:
            oo += [(i, i)]

        last = i

    return oo

def uncluster(c):
    r = []

    for f, l in c:
        r += range(f, l+1)

    return r

def cluster_sub2(c0, c1):
    c0 = set(c0)

    stable = False
    while not stable:

        for f0, l0 in c0:

            stable = True
            for f1, l1 in c1:

                if f1 >= f0 and l1 <= l0:
                    # f0----f1====l1---l0
                    stable = False
                    c0.remove((f0, l0))
                    if f1 > f0:
                        c0.add((f0, f1 - 1))
                    if l1 < l0:
                        c0.add((l1 + 1, l0))

                elif f1 < f0 and l1 >= f0 and l1 <= l0:
                    # f1====f0===l1----l0
                    stable = False
                    c0.remove((f0, f1))
                    if l1 < l0:
                        c0.add((l1 + 1, l0))

                elif f1 >= f0 and f1 <= l0 and l1 > l0:
                    # f0----f1====l0===l1
                    stable = False
                    c0.remove((f0, f1))
                    if f1 > f0:
                        c0.add((f0, f1 - 1))

                if not stable:
                    break

            if not stable:
                break

    c0 = list(c0)
    c0.sort(lambda x, y: cmp(x[0], y[0]))

    return c0

def encode(s):
    s = base64.b32encode(s)
    # We replace the default padding base32 padding '=' with 'z' because '=' is
    # not allowed by Vine in a variable name
    return s.replace("=", "z")


def decode(s):
    s = s.replace("z", "=")
    return base64.b32decode(s)
    

def hexstr(h):
    return "".join(["\\x%.2x" % ord(b) for b in h])


def terminal_size():
    import fcntl, termios, struct

    in_ = struct.pack('HHHH', 0, 0, 0, 0)
    out = fcntl.ioctl(0, termios.TIOCGWINSZ, in_)
    h, w, hp, wp = struct.unpack('HHHH', out)
    return w, h


def columns(): 
    return int(os.getenv("COLUMNS", 80)) #terminal_size()[0]


def to_bin_str(s):
    assert len(s) % 4 == 0
    r = ""
    for i in range(0, len(s), 4):
        assert s[i:i+2] == "\\x"
        r += chr(int(s[i+2:i+4], 16))
    return r

     
def to_c_str(s):
    assert len(s) % 2 == 0
    r = ""
    for i in range(0, len(s), 2):
        r += "\\x" + s[i:i+2]
    return r


def mtime(f):
    return os.stat(f)[stat.ST_MTIME]

              
def chunk(l, n = 4):
    
    if isinstance(l, int) or isinstance(l, long):
        pack = {1 : "B", 2 : "H", 4 : "I"}
        l = struct.pack(pack[n], l)
        l = list(l)
        l = "".join(l)

    assert len(l) % n == 0
    r = []
    for i in range(0, len(l), n):
        r += [[ord(b) for b in l[i:i+n]]]
    return r


def deref(buf, off, size = 4):
    data = buf[off : off + size]
    pack = {1 : "B", 2 : "H", 4 : "I"}
    return struct.unpack(pack[size], data)[0]
    

def lock(f, timeout = 30):
    l = lockfile.FileLock(f)
    l.acquire(timeout = timeout)
    return l


def unlock(l):
    l.release()


version_no=3


class KTestError(Exception):
    pass


class KTest:
    @staticmethod
    def fromfile(path):
        if not os.path.exists(path):
            print "ERROR: file %s not found" % (path)
            sys.exit(1)
            
        f = open(path,'rb')
        hdr = f.read(5)
        if len(hdr)!=5 or (hdr!='KTEST' and hdr != "BOUT\n"):
            raise KTestError,'unrecognized file'
        version, = struct.unpack('>i', f.read(4))
        if version > version_no:
            raise KTestError,'unrecognized version'
        numArgs, = struct.unpack('>i', f.read(4))
        args = []
        for i in range(numArgs):
            size, = struct.unpack('>i', f.read(4))
            args.append(f.read(size))
            
        if version >= 2:
            symArgvs, = struct.unpack('>i', f.read(4))
            symArgvLen, = struct.unpack('>i', f.read(4))
        else:
            symArgvs = 0
            symArgvLen = 0

        numObjects, = struct.unpack('>i', f.read(4))
        objects = []
        for i in range(numObjects):
            size, = struct.unpack('>i', f.read(4))
            name = f.read(size)
            size, = struct.unpack('>i', f.read(4))
            bytes = f.read(size)
            objects.append( (name,bytes) )

        # Create an instance
        b = KTest(version, args, symArgvs, symArgvLen, objects)
        # Augment with extra filename field
        b.filename = path
        return b
    
    def __init__(self, version, args, symArgvs, symArgvLen, objects):
        self.version = version
        self.symArgvs = symArgvs
        self.symArgvLen = symArgvLen
        self.args = args
        self.objects = objects

        # add a field that represents the name of the program used to
        # generate this .ktest file:
        program_full_path = self.args[0]
        program_name = os.path.basename(program_full_path)
        # sometimes program names end in .bc, so strip them
        if program_name.endswith('.bc'):
          program_name = program_name[:-3]
        self.programName = program_name


def load_klee_tc(f, full = False):
    return KTest.from_file(f)


# Currently assumes the following format:
#
#       in_type_name_info_size_elem
#
# where 'info' is a base32 encoded data (used to track extra information about
# the variable), 'size' is the orignal size of the variable (now split in
# bytes), and 'elem' denotes the current byte of the variable
def load_fuzzball_tc(f, full = False):
    inputs = {}
    vars_info = {}

    try:
        f = gzip.open(f)
    except IOError:
        f = open(f)

    for l in f.read().split("\n"):
        l = l.strip()
        if not l.startswith("in_"): 
            continue

        var, val = l.split("=")
        var = var.split("_")
        print var
        _, t, n, d, s, i = var

        var = (t, n)
        if not var in inputs:
            inputs[var] = [None for j in range(int(s))]
            assert not var in vars_info
            vars_info[var] = decode(d)

        assert vars_info[var] == decode(d)
        inputs[var][int(i)] = chr(int(val, 16))

    for var, vals in inputs.iteritems():
        if full:
            inputs[var] = (vals, vars_info[var])

    return inputs

