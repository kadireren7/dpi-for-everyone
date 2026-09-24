#include "packet.h"

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

int	packet_parse_tcp(const uint8_t *data, size_t len, t_tcp_view *out)
{
	const t_tcp_header	*hdr;
	uint8_t				offset_bytes;

	if (data == NULL || out == NULL)
		return (PACKET_ERR_MALFORMED);

	if (len < sizeof(t_tcp_header))
		return (PACKET_ERR_TRUNCATED);

	hdr = (const t_tcp_header *)data;
	offset_bytes = (uint8_t)((hdr->offset_reserved >> 4) * 4);

	if (offset_bytes < sizeof(t_tcp_header) || offset_bytes > len)
		return (PACKET_ERR_TRUNCATED);

	out->header = hdr;
	out->offset_bytes = offset_bytes;
	out->seq = ntohl(hdr->seq);
	out->ack = ntohl(hdr->ack);
	out->flags = hdr->flags;
	out->payload = data + offset_bytes;
	out->payload_len = len - offset_bytes;

	return (PACKET_OK);
}
