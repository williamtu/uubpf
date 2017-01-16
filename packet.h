#ifndef __UBPF_PACKET
#define __UBPF_PACKET

#include <stdlib.h>
#include <stdio.h>

char packet0[] = "010203aa55aa55000000";
char packet1[] = "aa55aa550000001b213cab6408004500007e79464000402fba550101025c0101025820000800000001c8fe71d883724fbeb6f4e1494a080045000054ba200000400184861e0000011e00000200004227e75400030af3195500000000f265010000000000101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f3031323334353637";

// TCP packet
char packet[] = "50540000000950540000000a080045000028fc2a4000400628a10a0101020a01010100020001396bb55d8cadbf895011000a5ec20000";

/* caller must free */
void *build_packet(void)
{
	int i;
	unsigned char *pkt, *_pkt;

	pkt = malloc(sizeof(packet)/2);
	if (!pkt)
		return NULL;

	_pkt = pkt;
	for (i = 0; i < sizeof(packet); i+=2) {
		unsigned char value;
		char tmp[3];
		tmp[0] = packet[i];
		tmp[1] = packet[i+1];
		tmp[2] = '\0'; 
		
		value = (unsigned char) strtol(tmp, NULL, 16);
		//printf("%s value %d\n", tmp, value);
		*_pkt++ = value;
	}

	return pkt;
}
#endif
/*
int main()
{
	
	char *pkt = build_packet();
	printf("packet = %d\n", pkt[0]);
	printf("packet = %d\n", pkt[1]);
	printf("packet = %d\n", pkt[2]);


}
*/
//#endif
