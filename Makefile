# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang
CC= gcc
CFLAGS=-g
OBJ= libbpf.o bpf_load.o vm.o hmap.o
LINK= -lelf -lopenvswitch -lpthread -lrt
BPFOBJ=sockex1_kern.o two_ebpf.o http_filter.o

all: $(OBJ) $(BPFOBJ) verify_target_bpf
	$(CC) $(CFLAGS) $(OBJ) $(LINK) -o sockex1 sockex1_user.c -lelf

libbpf.o: libbpf.c
	$(CC) $(CFLAGS) -c libbpf.c 

bpf_load.o: bpf_load.c
	$(CC) $(CFLAGS) -c bpf_load.c

vm.o: vm.c
	$(CC) $(CFLAGS) -c vm.c

hmap.o: hmap.c
	$(CC) $(CFLAGS) -c hmap.c

# Verify LLVM compiler tools are available and bpf target is supported by llc
.PHONY: verify_cmds verify_target_bpf $(CLANG) $(LLC)

verify_cmds: $(CLANG) $(LLC)
	@for TOOL in $^ ; do \
		if ! (which -- "$${TOOL}" > /dev/null 2>&1); then \
			echo "*** ERROR: Cannot find LLVM tool $${TOOL}" ;\
			exit 1; \
		else \
			echo "pass verify_cmds:" \
			true; fi; \
	done

verify_target_bpf: verify_cmds
	@if ! (${LLC} -march=bpf -mattr=help > /dev/null 2>&1); then \
		echo "*** ERROR: LLVM (${LLC}) does not support 'bpf' target" ;\
		echo "   NOTICE: LLVM version >= 3.7.1 required" ;\
		exit 2; \
	else \
		echo "pass verify_target_bpf:" \
		true; fi

# BPF program
sockex1_kern.o: sockex1_kern.c
	$(CLANG) $(LINUXINCLUDE) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-O2 -emit-llvm -g -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
clean:
	@rm -f *.o


# LINUXSOURCE
# LINUXINCLUDE=-nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/5/include -I./arch/x86/include \
-I./arch/x86/include/generated/uapi -I./arch/x86/include/generated \
-I./include -I./arch/x86/include/uapi \
-I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h

