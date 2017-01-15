# userspace BPF virtual machine

This project is a GPL-licensed lib for executing eBPF program in userspace.

## About 
Most of the codes are ported from linux kernel, in particular in
linux/kernel/bpf/
linux/samples/bpf/

## Build and run

You will need clang 3.7 and llvm with BPF target
$ make
$ ./sockex1

BPF bytecode:
  sockex1_kern.o

## Source code
vm.c: main BPF interpreter, copy from Linux kernel

sockex1_user.c, sockex1_kern.c: use to test BPF
	sockex1_kern.o contains BPF bytecode

hmap.c: BPF hash map

libbpf.c, bpf_load.c: BPF loader, copy from linux/samples/bpf/
	instead of calling into kernel, intercept and call in userspace


## TODO list
- BPF map support
- userspace map support
- more test cases
