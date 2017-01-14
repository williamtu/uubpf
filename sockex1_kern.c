/*
#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
*/
#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "ubpf.h"

struct bpf_map_def SEC("maps") my_map = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(unsigned int),
	.value_size = sizeof(long),
	.max_entries = 256,
};

SEC("socket1")
//int bpf_prog1(struct __sk_buff *skb)
int bpf_prog1(struct usk_buff *skb)
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
char _license[] SEC("license") = "GPL";
