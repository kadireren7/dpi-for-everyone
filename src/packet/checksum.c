#include "packet.h"

#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

uint32_t	checksum_accumulate(const void *data, size_t len, uint32_t seed)
{
	const uint8_t	*p;
	uint32_t		sum;

	p = data;
	sum = seed;

	while (len > 1)
	{
		sum += ((uint32_t)p[0] << 8) | p[1];
		p += 2;
		len -= 2;
	}

	if (len == 1)
		sum += (uint32_t)p[0] << 8;

	return (sum);
}

uint16_t	checksum_finalize(uint32_t sum)
{
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ((uint16_t)~sum);
}

uint16_t	checksum_ipv4_header(const t_ipv4_header *hdr, uint8_t ihl_bytes)
{
	const uint8_t	*bytes;
	uint32_t		sum;

	bytes = (const uint8_t *)hdr;
	sum = checksum_accumulate(bytes, 10, 0);
	sum = checksum_accumulate(bytes + 12, (size_t)ihl_bytes - 12, sum);

	return (checksum_finalize(sum));
}

/* TCP checksum field sits at byte offset 16, length 2, inside the
 * 20-byte fixed TCP header; it must contribute zero to the sum. */
uint16_t	checksum_tcp_v4(const t_ipv4_header *ip, const uint8_t *tcp_seg,
	size_t tcp_seg_len)
{
	uint32_t	sum;
	uint8_t		pseudo[4];
	uint16_t	tcp_len_be;

	if (tcp_seg_len < 18)
		return (0);

	pseudo[0] = 0;
	pseudo[1] = 6;
	tcp_len_be = htons((uint16_t)tcp_seg_len);
	memcpy(pseudo + 2, &tcp_len_be, 2);

	sum = checksum_accumulate(&ip->src, 4, 0);
	sum = checksum_accumulate(&ip->dst, 4, sum);
	sum = checksum_accumulate(pseudo, 4, sum);
	sum = checksum_accumulate(tcp_seg, 16, sum);
	sum = checksum_accumulate(tcp_seg + 18, tcp_seg_len - 18, sum);

	return (checksum_finalize(sum));
}

uint16_t	checksum_tcp_v6(const t_ipv6_header *ip, const uint8_t *tcp_seg,
	size_t tcp_seg_len)
{
	uint32_t	sum;
	uint8_t		pseudo[8];
	uint32_t	len_be;

	if (tcp_seg_len < 18)
		return (0);

	memset(pseudo, 0, sizeof(pseudo));
	len_be = htonl((uint32_t)tcp_seg_len);
	memcpy(pseudo, &len_be, 4);
	pseudo[7] = 6;

	sum = checksum_accumulate(ip->src, 16, 0);
	sum = checksum_accumulate(ip->dst, 16, sum);
	sum = checksum_accumulate(pseudo, 8, sum);
	sum = checksum_accumulate(tcp_seg, 16, sum);
	sum = checksum_accumulate(tcp_seg + 18, tcp_seg_len - 18, sum);

	return (checksum_finalize(sum));
}
