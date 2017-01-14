#ifndef __UBPF_H
#define __UBPF_H

/* userspace bpf */
unsigned int __bpf_prog_run(void *ctx, const struct bpf_insn *insn);
struct usk_buff {
    void *data;
    void *data_end;
};

typedef signed char s8; 
typedef unsigned char u8; 
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

#define cpu_to_be16 htons
#define cpu_to_be32 htonl
#define cpu_to_be64 htobe64
#define cpu_to_le16
#define cpu_to_le32
#define cpu_to_le64

#define uload_byte(skb, off) (*(u8  *)(skb->data + off))
#define uload_half(skb, off) (*(u16 *)(skb->data + off))
#define uload_word(skb, off) (*(u32 *)(skb->data + off))

#endif
