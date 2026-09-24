#include "packet.h"

#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

int	packet_fragment_ipv4(const uint8_t *in, size_t in_len,
	size_t tcp_payload_split_offset,
	uint8_t *out1, size_t *out1_len, uint8_t *out2, size_t *out2_len)
{
	t_ipv4_view		ip;
	t_tcp_view		tcp;
	int				status;
	size_t			raw_offset;
	size_t			frag_offset;
	t_ipv4_header	*out_ip;
	uint16_t		flags_frag;

	status = packet_parse_ipv4(in, in_len, &ip);
	if (status != PACKET_OK)
		return (status);
	if (ip.protocol != 6)
		return (PACKET_ERR_UNSUPPORTED);
	status = packet_parse_tcp(ip.payload, ip.payload_len, &tcp);
	if (status != PACKET_OK)
		return (status);

	/* Fragment boundary is IP-payload-relative and must land at or
	 * after the end of the TCP header (fragment 1 always keeps a
	 * complete TCP header) and be a multiple of IP_FRAG_UNIT, per
	 * RFC 791's fragment-offset field. */
	raw_offset = (size_t)tcp.offset_bytes + tcp_payload_split_offset;
	if (tcp_payload_split_offset == 0
		|| tcp_payload_split_offset >= tcp.payload_len)
		return (PACKET_ERR_MALFORMED);
	frag_offset = ((raw_offset + IP_FRAG_UNIT - 1) / IP_FRAG_UNIT)
		* IP_FRAG_UNIT;
	if (frag_offset < (size_t)tcp.offset_bytes
		|| frag_offset >= ip.payload_len)
		return (PACKET_ERR_MALFORMED);

	/* Fragment 1: offset field 0, MF set, DF cleared (contradicting
	 * DF+MF on a datagram we're deliberately fragmenting would be
	 * invalid). */
	memcpy(out1, in, (size_t)ip.ihl_bytes);
	memcpy(out1 + ip.ihl_bytes, ip.payload, frag_offset);
	*out1_len = (size_t)ip.ihl_bytes + frag_offset;
	out_ip = (t_ipv4_header *)out1;
	out_ip->total_len = htons((uint16_t)*out1_len);
	flags_frag = (uint16_t)(ntohs(out_ip->flags_frag) & IP_FLAG_DF);
	flags_frag = (uint16_t)((flags_frag & ~IP_FLAG_DF) | IP_FLAG_MF);
	out_ip->flags_frag = htons(flags_frag);
	out_ip->checksum = 0;
	out_ip->checksum = htons(checksum_ipv4_header(out_ip, ip.ihl_bytes));

	/* Fragment 2: offset field = frag_offset / 8, MF clear (last
	 * fragment), no TCP header at all — a raw continuation of the IP
	 * payload. TCP checksum is never touched anywhere in this
	 * function: the original datagram's TCP checksum already covers
	 * the complete, unmodified payload, and reassembly at the
	 * destination reconstructs those exact bytes. */
	memcpy(out2, in, (size_t)ip.ihl_bytes);
	memcpy(out2 + ip.ihl_bytes, ip.payload + frag_offset,
		ip.payload_len - frag_offset);
	*out2_len = (size_t)ip.ihl_bytes + (ip.payload_len - frag_offset);
	out_ip = (t_ipv4_header *)out2;
	out_ip->total_len = htons((uint16_t)*out2_len);
	out_ip->flags_frag = htons((uint16_t)(frag_offset / IP_FRAG_UNIT));
	out_ip->checksum = 0;
	out_ip->checksum = htons(checksum_ipv4_header(out_ip, ip.ihl_bytes));

	return (PACKET_OK);
}
