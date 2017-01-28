/* 
copy from bcc
https://github.com/iovisor/bcc/blob/master/examples/networking/http_filter/http-parse-simple.c
*/
/*
#include <uapi/linux/ptrace.h>
#include <net/sock.h>
#include <bcc/proto.h>
*/
#include <linux/bpf.h>
#include "ubpf.h"
#include "bpf_helpers.h"

#define IP_TCP 	6   
#define ETH_HLEN 14
struct ethernet_t {
    char dstAddr[6]; /* bit<48> */
    char srcAddr[6]; /* bit<48> */
    u16 type; /* bit<16> */
};
struct ip_t {
    u8 hlen:4; /* bit<4> */
    u8 version:4; /* bit<4> */
    u8 diffserv; /* bit<8> */
    u16 tlen; /* bit<16> */
    u16 identification; /* bit<16> */
    u16 flags:3; /* bit<3> */
    u16 fragOffset:13; /* bit<13> */
    u8 ttl; /* bit<8> */
    u8 nextp; /* bit<8> */
    u16 hdrChecksum; /* bit<16> */
    u32 srcAddr; /* bit<32> */
    u32 dstAddr; /* bit<32> */
}; 
struct tcp_t {
    u16 srcPort; /* bit<16> */
    u16 dstPort; /* bit<16> */
    u32 seqNo; /* bit<32> */
    u32 ackNo; /* bit<32> */
    u8 res:4; /* bit<4> */
    u8 offset:4; /* bit<4> */
    u8 flags; /* bit<8> */
    u16 window; /* bit<16> */
    u16 checksum; /* bit<16> */
    u16 urgentPtr; /* bit<16> */
};
struct icmp_t {
    u16 typeCode; /* bit<16> */
    u16 hdrChecksum; /* bit<16> */
};

/*eBPF program.
  Filter IP and TCP packets, having payload not empty
  and containing "HTTP", "GET", "POST" ... as first bytes of payload
  if the program is loaded as PROG_TYPE_SOCKET_FILTER
  and attached to a socket
  return  0 -> DROP the packet
  return -1 -> KEEP the packet and return it to user space (userspace can read it from the socket_fd )
*/
//int http_filter(struct __sk_buff *skb) {
SEC("socket1")
int bpf_prog1(struct usk_buff *skb) {

	//struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
	struct ethernet_t *ethernet = (struct ethernet_t *)(skb->data);
	//filter IP packets (ethernet type = 0x0800)
	if (!(__constant_ntohs(ethernet->type) == 0x0800)) {
		goto DROP;	
	}
	else
		printk("IP");

	//struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
	struct ip_t *ip = (struct ip_t *)(skb->data + sizeof(*ethernet));
	//filter TCP packets (ip next protocol = 0x06)
	if (ip->nextp != IP_TCP) {
		goto DROP;
	}
	else
		printk("TCP\n");

	u32  tcp_header_length = 0;
	u32  ip_header_length = 0;
	u32  payload_offset = 0;
	u32  payload_length = 0;

	//struct tcp_t *tcp = cursor_advance(cursor, sizeof(*tcp));
	struct tcp_t *tcp = (struct tcp_t *)(skb->data + sizeof(*ip) + sizeof(*ethernet));

	//calculate ip header length
	//value to multiply * 4
	//e.g. ip->hlen = 5 ; IP Header Length = 5 x 4 byte = 20 byte
	ip_header_length = ip->hlen << 2;    //SHL 2 -> *4 multiply
		
	printk("ip_header_len %x\n", ip_header_length);
	//calculate tcp header length
	//value to multiply *4
	//e.g. tcp->offset = 5 ; TCP Header Length = 5 x 4 byte = 20 byte
	tcp_header_length = tcp->offset << 2; //SHL 2 -> *4 multiply

	printk("tcp_header_len %x\n", tcp_header_length);
	//calculate patload offset and length
	payload_offset = ETH_HLEN + ip_header_length + tcp_header_length; 
	payload_length = ip->tlen - ip_header_length - tcp_header_length;
		  
	//http://stackoverflow.com/questions/25047905/http-request-minimum-size-in-bytes
	//minimum length of http request is always geater than 7 bytes
	//avoid invalid access memory
	//include empty payload
	if(payload_length < 7) {
		printk("http payload too small");
		goto DROP;
	}

	//load first 7 byte of payload into p (payload_array)
	//direct access to skb not allowed
	char p[7];
	int i = 0;
	int j = 0;
	for (i = payload_offset ; i < (payload_offset + 7) ; i++) {
		//p[j] = uload_byte(skb , i);
		p[j] = *(u8 *)(skb->data + i);
		j++;
	}
	//printk("ip hlen %d payload offset %d\n", ip_header_length, payload_offset);
	printk("start parsing HTTP message");
	
	//find a match with an HTTP message
	//HTTP
	if ((p[0] == 'H') && (p[1] == 'T') && (p[2] == 'T') && (p[3] == 'P')) {
		printk("HTTP");
		goto KEEP;
	}
	//GET
	if ((p[0] == 'G') && (p[1] == 'E') && (p[2] == 'T')) {
		printk("GET");
		goto KEEP;
	}
	//POST
	if ((p[0] == 'P') && (p[1] == 'O') && (p[2] == 'S') && (p[3] == 'T')) {
		printk("POST");
		goto KEEP;
	}
	//PUT
	if ((p[0] == 'P') && (p[1] == 'U') && (p[2] == 'T')) {
		printk("PUT");
		goto KEEP;
	}
	//DELETE
	if ((p[0] == 'D') && (p[1] == 'E') && (p[2] == 'L') && (p[3] == 'E') && (p[4] == 'T') && (p[5] == 'E')) {
		printk("DELETE");
		goto KEEP;
	}
	//HEAD
	if ((p[0] == 'H') && (p[1] == 'E') && (p[2] == 'A') && (p[3] == 'D')) {
		printk("HEAD");
		goto KEEP;
	}
	//no HTTP match
	goto DROP;

	//keep the packet and send it to userspace retruning -1
	KEEP:
	return -1;

	//drop the packet returning 0
	DROP:
	return 0;

}
