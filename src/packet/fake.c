#include "packet.h"

#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

int	packet_make_fake_tcp_v4(const uint8_t *in, size_t in_len,
	uint8_t ttl, uint8_t *out, size_t *out_len)
{
	t_ipv4_view		ip;
	t_tcp_view		tcp;
	int				status;
	t_ipv4_header	*out_ip;
	uint8_t			*out_tcp_bytes;
	uint16_t		*checksum_field;

	status = packet_parse_ipv4(in, in_len, &ip);
	if (status != PACKET_OK)
		return (status);
	if (ip.protocol != 6)
		return (PACKET_ERR_UNSUPPORTED);
	status = packet_parse_tcp(ip.payload, ip.payload_len, &tcp);
	if (status != PACKET_OK)
		return (status);
	if (tcp.payload_len == 0)
		return (PACKET_ERR_MALFORMED);

	memcpy(out, in, in_len);
	*out_len = in_len;

	out_ip = (t_ipv4_header *)out;
	out_ip->ttl = ttl;
	out_ip->checksum = 0;
	out_ip->checksum = htons(checksum_ipv4_header(out_ip, ip.ihl_bytes));

	/* Deliberately invalid TCP checksum: bitwise complement of
	 * whatever the (correct, since `in` is a real captured packet)
	 * checksum currently is. checksum == ~checksum has no 16-bit
	 * solution, so this is always a genuinely different — and thus
	 * invalid — value, regardless of byte-order interpretation. */
	out_tcp_bytes = out + ip.ihl_bytes;
	checksum_field = (uint16_t *)(out_tcp_bytes + 16);
	*checksum_field = (uint16_t)~(*checksum_field);

	return (PACKET_OK);
}
