# Allows pointing LLC/CLANG to a LLVM backend with bpf support, redefine on cmdline:
#  make samples/bpf/ LLC=~/git/llvm/build/bin/llc CLANG=~/git/llvm/build/bin/clang
LLC ?= llc
CLANG ?= clang
CC= gcc
CFLAGS=-g
OBJ= libbpf.o bpf_load.o vm.o map.o
LINK= -lelf -lopenvswitch -lpthread -lrt
BPFOBJ=sockex1_kern.o

# LINUXSOURCE
# LINUXINCLUDE=-nostdinc -isystem /usr/lib/gcc/x86_64-linux-gnu/5/include -I./arch/x86/include \
-I./arch/x86/include/generated/uapi -I./arch/x86/include/generated \
-I./include -I./arch/x86/include/uapi \
-I./include/uapi -I./include/generated/uapi -include ./include/linux/kconfig.h

all: $(OBJ) $(BPFOBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LINK) -o sockex1 sockex1_user.c -lelf

libbpf.o: libbpf.c
	$(CC) $(CFLAGS) -c libbpf.c 

bpf_load.o: bpf_load.c
	$(CC) $(CFLAGS) -c bpf_load.c

vm.o: vm.c
	$(CC) $(CFLAGS) -c vm.c

hmap.o: hmap.c
	$(CC) $(CFLAGS) -c map.c

sockex1_kern.o: sockex1_kern.c
	$(CLANG) $(LINUXINCLUDE) \
		-D__KERNEL__ -D__ASM_SYSREG_H -Wno-unused-value -Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member -Wno-tautological-compare \
		-O2 -emit-llvm -g -c $< -o -| $(LLC) -march=bpf -filetype=obj -o $@
clean:
	@rm -f *.o


