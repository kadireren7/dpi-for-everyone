#include "tls_sni.h"

#include <string.h>

static uint16_t	read_u16(const uint8_t *p)
{
	return ((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

int	tls_parse_client_hello_sni(const uint8_t *data, size_t len,
	char *host_out, size_t host_out_size)
{
	size_t		pos;
	size_t		end;
	size_t		session_len;
	size_t		cipher_len;
	size_t		compression_len;
	size_t		extensions_len;
	size_t		extension_len;
	size_t		name_len;
	uint32_t	handshake_len;
	uint16_t	extension_type;

	if (data == NULL || host_out == NULL || host_out_size == 0)
		return (PACKET_ERR_MALFORMED);

	if (len > TLS_CLIENTHELLO_CAP)
		return (PACKET_ERR_MALFORMED);

	if (len < 5)
		return (PACKET_ERR_TRUNCATED);

	if (data[0] != 0x16)
		return (PACKET_ERR_UNSUPPORTED);

	pos = 5;
	if (pos + 4 > len)
		return (PACKET_ERR_TRUNCATED);

	if (data[pos] != 0x01)
		return (PACKET_ERR_UNSUPPORTED);

	handshake_len = ((uint32_t)data[pos + 1] << 16)
		| ((uint32_t)data[pos + 2] << 8) | data[pos + 3];
	if (handshake_len > TLS_CLIENTHELLO_CAP)
		return (PACKET_ERR_MALFORMED);
	pos += 4;

	if (pos + 34 > len)
		return (PACKET_ERR_TRUNCATED);
	pos += 34;

	if (pos + 1 > len)
		return (PACKET_ERR_TRUNCATED);
	session_len = data[pos];
	pos += 1;
	if (pos + session_len > len)
		return (PACKET_ERR_TRUNCATED);
	pos += session_len;

	if (pos + 2 > len)
		return (PACKET_ERR_TRUNCATED);
	cipher_len = read_u16(data + pos);
	pos += 2;
	if (pos + cipher_len > len)
		return (PACKET_ERR_TRUNCATED);
	pos += cipher_len;

	if (pos + 1 > len)
		return (PACKET_ERR_TRUNCATED);
	compression_len = data[pos];
	pos += 1;
	if (pos + compression_len > len)
		return (PACKET_ERR_TRUNCATED);
	pos += compression_len;

	if (pos + 2 > len)
		return (PACKET_ERR_TRUNCATED);
	extensions_len = read_u16(data + pos);
	pos += 2;
	if (extensions_len > TLS_CLIENTHELLO_CAP)
		return (PACKET_ERR_MALFORMED);
	if (pos + extensions_len > len)
		return (PACKET_ERR_TRUNCATED);

	end = pos + extensions_len;
	while (pos + 4 <= end)
	{
		extension_type = read_u16(data + pos);
		extension_len = read_u16(data + pos + 2);
		pos += 4;

		if (pos + extension_len > end)
			return (PACKET_ERR_MALFORMED);

		if (extension_type == 0x0000)
		{
			if (extension_len < 5)
				return (PACKET_ERR_MALFORMED);
			if (data[pos + 2] != 0x00)
				return (PACKET_ERR_MALFORMED);
			name_len = read_u16(data + pos + 3);
			if (5 + name_len > extension_len)
				return (PACKET_ERR_MALFORMED);
			if (name_len == 0 || name_len >= host_out_size)
				return (PACKET_ERR_MALFORMED);
			memcpy(host_out, data + pos + 5, name_len);
			host_out[name_len] = '\0';
			return (PACKET_OK);
		}

		pos += extension_len;
	}

	return (PACKET_ERR_UNSUPPORTED);
}

/* Handshake bytes spread over several back-to-back handshake records
 * (a client — or another DPI tool in front of us — that already
 * fragmented its ClientHello) are gathered into one record, so the
 * single-record parser above and the TLSREC re-framing see the real
 * hostname instead of a record header in the middle of it. A trailing
 * record that has only partly arrived counts with its declared
 * length: the rest of its body simply continues after our output.
 * Anything after the handshake records is copied unchanged. */
ssize_t	tls_coalesce_handshake_records(const uint8_t *in, size_t len,
	uint8_t *out, size_t out_size)
{
	size_t	pos;
	size_t	body;
	size_t	declared;
	size_t	records;
	size_t	rlen;
	size_t	avail;

	if (in == NULL || out == NULL || len < 5 || in[0] != 0x16)
		return (-1);
	pos = 0;
	body = 5;
	declared = 0;
	records = 0;
	while (pos + 5 <= len && in[pos] == 0x16)
	{
		rlen = read_u16(in + pos + 3);
		avail = len - pos - 5;
		if (avail > rlen)
			avail = rlen;
		if (body + avail > out_size)
			return (-1);
		memcpy(out + body, in + pos + 5, avail);
		body += avail;
		declared += rlen;
		records++;
		pos += 5 + avail;
		if (avail < rlen)
			break ;
	}
	/* one record: nothing to do; over 2^14: can't be one record */
	if (records < 2 || declared > 16384 || body + (len - pos) > out_size)
		return (-1);
	out[0] = 0x16;
	out[1] = in[1];
	out[2] = in[2];
	out[3] = (uint8_t)(declared >> 8);
	out[4] = (uint8_t)(declared & 0xff);
	memcpy(out + body, in + pos, len - pos);
	return ((ssize_t)(body + len - pos));
}
