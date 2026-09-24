#include "packet.h"

#include <string.h>

# ifdef _WIN32
#  include <winsock2.h>
# else
#  include <arpa/inet.h>
# endif

int	packet_parse_ipv4(const uint8_t *data, size_t len, t_ipv4_view *out)
{
	const t_ipv4_header	*hdr;
	uint8_t					version;
	uint8_t					ihl_bytes;
	uint16_t				total_len;

	if (data == NULL || out == NULL)
		return (PACKET_ERR_MALFORMED);

	if (len < sizeof(t_ipv4_header))
		return (PACKET_ERR_TRUNCATED);

	hdr = (const t_ipv4_header *)data;
	version = hdr->ver_ihl >> 4;

	if (version != 4)
		return (PACKET_ERR_MALFORMED);

	ihl_bytes = (uint8_t)((hdr->ver_ihl & 0x0F) * 4);

	if (ihl_bytes < sizeof(t_ipv4_header) || ihl_bytes > len)
		return (PACKET_ERR_TRUNCATED);

	total_len = ntohs(hdr->total_len);

	if (total_len < ihl_bytes || total_len > len)
		return (PACKET_ERR_TRUNCATED);

	/* A fragment (offset != 0) has no transport header at all — its
	 * bytes are a raw continuation of the original payload, not a
	 * TCP header. Parsing that as TCP would read garbage ports/seq/
	 * flags. The first fragment (offset == 0, MF set) does have a
	 * real TCP header, but its payload is incomplete and this
	 * project doesn't implement IP-level reassembly, so it's
	 * rejected too rather than handled half-right. */
	if ((ntohs(hdr->flags_frag) & 0x3FFF) != 0)
		return (PACKET_ERR_UNSUPPORTED);

	out->header = hdr;
	out->ihl_bytes = ihl_bytes;
	out->total_len = total_len;
	out->protocol = hdr->protocol;
	out->payload = data + ihl_bytes;
	out->payload_len = (size_t)(total_len - ihl_bytes);

	return (PACKET_OK);
}

int	packet_parse_ipv6(const uint8_t *data, size_t len, t_ipv6_view *out)
{
	const t_ipv6_header	*hdr;
	uint8_t					version;
	uint16_t				payload_len;

	if (data == NULL || out == NULL)
		return (PACKET_ERR_MALFORMED);

	if (len < sizeof(t_ipv6_header))
		return (PACKET_ERR_TRUNCATED);

	hdr = (const t_ipv6_header *)data;
	version = (uint8_t)(ntohl(hdr->ver_class_flow) >> 28);

	if (version != 6)
		return (PACKET_ERR_MALFORMED);

	payload_len = ntohs(hdr->payload_len);

	if ((size_t)payload_len + sizeof(t_ipv6_header) > len)
		return (PACKET_ERR_TRUNCATED);

	/* Extension headers (hop-by-hop, routing, fragment, ...) are not
	 * walked: safer to report unsupported and let the caller PASS
	 * than to misparse a header chain we don't fully implement. */
	if (hdr->next_header != 6)
		return (PACKET_ERR_UNSUPPORTED);

	out->header = hdr;
	out->next_header = hdr->next_header;
	out->payload = data + sizeof(t_ipv6_header);
	out->payload_len = payload_len;

	return (PACKET_OK);
}
