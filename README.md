# QEMU testing with FuzzBALL

### Compile QEMU and FuzzBALL

###### QEMU
```bash
./configure --disable-werror --disable-fdt --target-list=i386-linux-user
```

###### FuzzBALL
```bash
./configure --with-vex=/home/yanxx297/Project/common/vex-r2737
# May also need to set binutil location
```

### Explore QEMU with FuzzBALL

```bash
./run-qemu-fuzzball.py /tmp/out ../qemu/i386-linux-user/qemu-i386 -R 16777216 \
../small-32bit-progs/hw32-bare
# /tmp/out: output directory
# The rest of the command is the command line to run QEMU
```
To use different solvers, replace `-solver` and `-solver-path` in FUZZBALL_ARGS.
For example, if you want to use Z3 instead of STP, `-solver` should be `smtlib`, and `-solver-path`should be the path to z3 binary.

FuzzBALL currently only work on qemu 1.5.3.
Switch to branch `stable-1.5` before you compile qemu.
