#include "packet.h"

#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

int	packet_split_tcp_v4(const uint8_t *in, size_t in_len, size_t split_offset,
	uint8_t *out1, size_t *out1_len, uint8_t *out2, size_t *out2_len)
{
	t_ipv4_view		ip;
	t_tcp_view		tcp;
	int				status;
	size_t			hdrs_len;
	t_ipv4_header	*out_ip;
	uint8_t			*out_tcp_bytes;

	status = packet_parse_ipv4(in, in_len, &ip);
	if (status != PACKET_OK)
		return (status);

	if (ip.protocol != 6)
		return (PACKET_ERR_UNSUPPORTED);

	status = packet_parse_tcp(ip.payload, ip.payload_len, &tcp);
	if (status != PACKET_OK)
		return (status);

	if (split_offset == 0 || split_offset >= tcp.payload_len)
		return (PACKET_ERR_MALFORMED);

	hdrs_len = (size_t)ip.ihl_bytes + tcp.offset_bytes;

	memcpy(out1, in, hdrs_len);
	memcpy(out1 + hdrs_len, tcp.payload, split_offset);
	*out1_len = hdrs_len + split_offset;
	out_ip = (t_ipv4_header *)out1;
	out_ip->total_len = htons((uint16_t)*out1_len);
	out_ip->checksum = 0;
	out_ip->checksum = htons(checksum_ipv4_header(out_ip, ip.ihl_bytes));
	out_tcp_bytes = out1 + ip.ihl_bytes;
	((t_tcp_header *)out_tcp_bytes)->checksum = 0;
	((t_tcp_header *)out_tcp_bytes)->checksum = htons(checksum_tcp_v4(
			out_ip, out_tcp_bytes, tcp.offset_bytes + split_offset));

	memcpy(out2, in, hdrs_len);
	memcpy(out2 + hdrs_len, tcp.payload + split_offset,
		tcp.payload_len - split_offset);
	*out2_len = hdrs_len + (tcp.payload_len - split_offset);
	out_ip = (t_ipv4_header *)out2;
	out_ip->total_len = htons((uint16_t)*out2_len);
	out_ip->checksum = 0;
	out_tcp_bytes = out2 + ip.ihl_bytes;
	((t_tcp_header *)out_tcp_bytes)->seq = htonl(tcp.seq
			+ (uint32_t)split_offset);
	((t_tcp_header *)out_tcp_bytes)->checksum = 0;
	out_ip->checksum = htons(checksum_ipv4_header(out_ip, ip.ihl_bytes));
	((t_tcp_header *)out_tcp_bytes)->checksum = htons(checksum_tcp_v4(
			out_ip, out_tcp_bytes,
			tcp.offset_bytes + (tcp.payload_len - split_offset)));

	return (PACKET_OK);
}

int	packet_split_tcp_v6(const uint8_t *in, size_t in_len, size_t split_offset,
	uint8_t *out1, size_t *out1_len, uint8_t *out2, size_t *out2_len)
{
	t_ipv6_view		ip;
	t_tcp_view		tcp;
	int				status;
	size_t			hdrs_len;
	t_ipv6_header	*out_ip;
	uint8_t			*out_tcp_bytes;
	uint16_t		upper_len;

	status = packet_parse_ipv6(in, in_len, &ip);
	if (status != PACKET_OK)
		return (status);

	status = packet_parse_tcp(ip.payload, ip.payload_len, &tcp);
	if (status != PACKET_OK)
		return (status);

	if (split_offset == 0 || split_offset >= tcp.payload_len)
		return (PACKET_ERR_MALFORMED);

	hdrs_len = sizeof(t_ipv6_header) + tcp.offset_bytes;

	memcpy(out1, in, hdrs_len);
	memcpy(out1 + hdrs_len, tcp.payload, split_offset);
	*out1_len = hdrs_len + split_offset;
	out_ip = (t_ipv6_header *)out1;
	upper_len = (uint16_t)(tcp.offset_bytes + split_offset);
	out_ip->payload_len = htons(upper_len);
	out_tcp_bytes = out1 + sizeof(t_ipv6_header);
	((t_tcp_header *)out_tcp_bytes)->checksum = 0;
	((t_tcp_header *)out_tcp_bytes)->checksum = htons(checksum_tcp_v6(
			out_ip, out_tcp_bytes, upper_len));

	memcpy(out2, in, hdrs_len);
	memcpy(out2 + hdrs_len, tcp.payload + split_offset,
		tcp.payload_len - split_offset);
	*out2_len = hdrs_len + (tcp.payload_len - split_offset);
	out_ip = (t_ipv6_header *)out2;
	upper_len = (uint16_t)(tcp.offset_bytes
			+ (tcp.payload_len - split_offset));
	out_ip->payload_len = htons(upper_len);
	out_tcp_bytes = out2 + sizeof(t_ipv6_header);
	((t_tcp_header *)out_tcp_bytes)->seq = htonl(tcp.seq
			+ (uint32_t)split_offset);
	((t_tcp_header *)out_tcp_bytes)->checksum = 0;
	((t_tcp_header *)out_tcp_bytes)->checksum = htons(checksum_tcp_v6(
			out_ip, out_tcp_bytes, upper_len));

	return (PACKET_OK);
}
