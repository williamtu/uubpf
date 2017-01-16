/*
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
*/
#include <linux/bpf.h>

#define ETH_P_IP    0x0800      /* Internet Protocol packet */
#define ETH_P_ARP   0x0806      /* Address Resolution packet    */
/*
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define IPPROTO_ICMP 1
*/
#include "bpf_helpers.h"
#include "ubpf.h"
#define printk(fmt, ...)    \
({  char ___fmt[] = fmt;    \
    bpf_trace_printk(___fmt, sizeof(___fmt), ##__VA_ARGS__);\
})

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(u32),
	.value_size = sizeof(u32),
	.max_entries = 256,
};

static __always_inline void parse_ipv4(struct usk_buff *skb)
{
	u32 ip_proto;

	ip_proto = uload_byte(skb, 14 + offsetof(struct iphdr, protocol));
	switch (ip_proto) {
	case IPPROTO_TCP:
		printk("receve TCP\n");
		break;
	case IPPROTO_UDP:
		printk("receve UDP\n");
		break;
	case IPPROTO_ICMP:
		printk("receve ICMP\n");
		break;
	default:
		printk("IP protocol %x not support\n", ip_proto);
		break;
	}
	return;
}

SEC("socket1")
int bpf_prog1(struct usk_buff *skb)
{
	// basic parsing
	u16 val;
	
	// test write packet
	// *(u16 *) (skb->data + 12) = __constant_htons(ETH_P_ARP);

	u16 proto = uload_half(skb, 12);

	if (proto == ETH_P_IP) {
		printk("IP packet");
		parse_ipv4(skb);	
	}
	else if (proto == ETH_P_ARP) {
		printk("ARP packet");
	}
	else
		printk("proto %x not supoprt\n", proto);

	return 0;

}

SEC("socket2") // test ALU
int bpf_prog2(struct usk_buff *skb)
{
    int a = 1, b = 2, c = 3;
	int d;
    d = ((a + b) * c) / 2;
    return d;
}

SEC("socket3") // test MAP
int bpf_prog3(struct usk_buff *skb)
{
	int index = 0;
	int value = 0, *ret;

	value = uload_half(skb, 12);
	bpf_map_update_elem(&my_map, &index, &value, BPF_ANY);

	
	ret = bpf_map_lookup_elem(&my_map, &index);
	printk("ret proto = 0x%x\n", *ret);
    return 0;
}


#if 0
SEC("socket2")
//int bpf_prog1(struct __sk_buff *skb)
int bpf_prog2(struct usk_buff *skb)
{
/* work
    int a = 1, b = 2, c = 3;
    c = a + b;
    return c;
*/
	int index;
	u64 *ret;
	u64 value = 0xdeaddeadbeefbeef;
    char fmt[] = "socket: %llx\n";

	index = uload_byte(skb, 10);
	bpf_map_update_elem(&my_map, &index, &value, BPF_ANY);
	//index = uload_half(skb, 10);
	ret = bpf_map_lookup_elem(&my_map, &index);

    bpf_trace_printk(fmt, sizeof(fmt), *ret);
	return *ret;

	//index = uload_word(skb, 10);
//    return index;

/* work
    char fmt[] = "socket: %d\n";
	int index = uload_byte(skb, 10);
    bpf_trace_printk(fmt, sizeof(fmt), index);
*/

/*
    long *value;
    int index = 0;
	value = bpf_map_lookup_elem(&my_map, &index);
    if (!value)
        return 1;
*/
/*
long *value;

	if (skb->pkt_type != PACKET_OUTGOING)
		return 0;

	value = bpf_map_lookup_elem(&my_map, &index);
	if (value)
		__sync_fetch_and_add(value, skb->len);
*/
	return 0;
}
#endif

char _license[] SEC("license") = "GPL";
