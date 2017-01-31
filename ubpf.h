#ifndef __UBPF_H
#define __UBPF_H
#include <arpa/inet.h>

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

/*
 * casts are necessary for constants, because we never know how for sure
 * how U/UL/ULL map to __u16, __u32, __u64. At least not in a portable way.
 */
#define ___constant_swab16(x) ((__u16)(             \
    (((__u16)(x) & (__u16)0x00ffU) << 8) |          \
    (((__u16)(x) & (__u16)0xff00U) >> 8)))

#define ___constant_swab32(x) ((__u32)(             \
    (((__u32)(x) & (__u32)0x000000ffUL) << 24) |        \
    (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |        \
    (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |        \
    (((__u32)(x) & (__u32)0xff000000UL) >> 24)))

#define ___constant_swab64(x) ((__u64)(             \
    (((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |   \
    (((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |   \
    (((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |   \
    (((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |   \
    (((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |   \
    (((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |   \
    (((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |   \
    (((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))

#define __constant_htonl(x) (___constant_swab32((x)))
#define __constant_ntohl(x) (___constant_swab32(x))
#define __constant_htons(x) (___constant_swab16((x)))
#define __constant_ntohs(x) ___constant_swab16((x))

#define cpu_to_be16 htons
#define cpu_to_be32 htonl
#define cpu_to_be64 htobe64
#define cpu_to_le16
#define cpu_to_le32
#define cpu_to_le64

#define uload_byte(skb, off) (*(u8  *)(skb->data + off))
#define uload_half(skb, off) __constant_ntohs(*(u16 *)(skb->data + off))
#define uload_word(skb, off) __constant_ntohl(*(u32 *)(skb->data + off))

#define DEBUG 1
#if DEBUG
#define printk(fmt, ...)    \
({  char ___fmt[] = fmt;    \
    bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);\
})
#else
#define printk(fmt, ...)    do {} while(0)
#endif

# define offsetof(typ, memb)     ((unsigned long)((char *)&(((typ *)0)->memb)))
struct iphdr {
    u8    ihl:4,
        version:4;
    u8    tos;
    u16  tot_len;
    u16  id; 
    u16  frag_off;
    u8    ttl;
    u8    protocol;
    u16 check;
    u32  saddr;
    u32  daddr;
    /*The options start here. */
};


#endif
