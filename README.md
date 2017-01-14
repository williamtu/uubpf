# userspace BPF runtime

vm.c: main BPF interpreter, copy from Linux kernel

sockex1_user.c, sockex1_kern.c: use to test BPF
	sockex1_kern.o contains BPF bytecode

hmap.c: BPF hash map

libbpf.c, bpf_load.c: BPF loader, copy from linux/samples/bpf/
	instead of calling into kernel, intercept and call in userspace

# How to run
$ make
$ ./sockex1

