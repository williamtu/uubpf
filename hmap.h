#ifndef __UBPF_HMAP
#define __UBPF_HMAP

int ubpf_insert_map(union bpf_attr *attr);
void *ubpf_lookup_map(union bpf_attr *attr);
int ubpf_create_map(union bpf_attr *attr);

#endif
