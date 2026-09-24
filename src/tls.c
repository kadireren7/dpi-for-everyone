#include "tls.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static uint16_t	read_u16(const unsigned char *p)
{
	return ((uint16_t)p[0] << 8 | (uint16_t)p[1]);
}

ssize_t	tls_find_sni_split(const unsigned char *data, size_t length)
{
	size_t	pos;
	size_t	end;
	size_t	session_len;
	size_t	cipher_len;
	size_t	compression_len;
	size_t	extensions_len;
	size_t	extension_len;
	size_t	name_len;
	uint16_t	extension_type;

	if (length < 5)
		return (-1);

	if (data[0] != 0x16)
		return (-1);

	pos = 5;

	if (pos + 4 > length)
		return (-1);

	if (data[pos] != 0x01)
		return (-1);

	pos += 4;

	if (pos + 34 > length)
		return (-1);

	pos += 34;

	if (pos + 1 > length)
		return (-1);

	session_len = data[pos];
	pos += 1;

	if (pos + session_len > length)
		return (-1);

	pos += session_len;

	if (pos + 2 > length)
		return (-1);

	cipher_len = read_u16(data + pos);
	pos += 2;

	if (pos + cipher_len > length)
		return (-1);

	pos += cipher_len;

	if (pos + 1 > length)
		return (-1);

	compression_len = data[pos];
	pos += 1;

	if (pos + compression_len > length)
		return (-1);

	pos += compression_len;

	if (pos + 2 > length)
		return (-1);

	extensions_len = read_u16(data + pos);
	pos += 2;

	if (pos + extensions_len > length)
		return (-1);

	end = pos + extensions_len;

	while (pos + 4 <= end)
	{
		extension_type = read_u16(data + pos);
		extension_len = read_u16(data + pos + 2);
		pos += 4;

		if (pos + extension_len > end)
			return (-1);

		if (extension_type == 0x0000)
		{
			if (extension_len < 5)
				return (-1);

			if (data[pos + 2] != 0x00)
				return (-1);

			name_len = read_u16(data + pos + 3);

			if (5 + name_len > extension_len)
				return (-1);

			if (name_len < 2)
				return (-1);

			return ((ssize_t)(pos + 5 + (name_len / 2)));
		}

		pos += extension_len;
	}

	return (-1);
}

/* TLS record fragmentation: rewrites the first record in `data` (a
 * handshake record, i.e. a ClientHello) as two back-to-back records
 * carrying the same handshake bytes, split at handshake-body offset
 * `at`. Receivers must reassemble handshake messages across records
 * (RFC 8446 5.1 / RFC 5246 6.2.1), but a DPI box that parses only the
 * first record never sees a complete ClientHello/SNI.
 *
 * `data` may hold only the start of the record (len < 5 + record_len)
 * — only the two headers change, so whatever of the record arrives
 * later just continues as the second record's body. Needs
 * 1 <= at < min(record_len, len - 5). Writes len + 5 bytes to `out`
 * and returns that length, or -1 if `data` isn't a handshake record,
 * `at` is out of range, or out_size is too small. */
ssize_t	tls_fragment_first_record(const unsigned char *data, size_t len,
	size_t at, unsigned char *out, size_t out_size)
{
	size_t	record_len;

	if (len < 6 || data[0] != 0x16 || data[1] != 0x03)
		return (-1);
	record_len = ((size_t)data[3] << 8) | data[4];
	if (at < 1 || at >= record_len || at >= len - 5 || out_size < len + 5)
		return (-1);
	memcpy(out, data, 3);
	out[3] = (unsigned char)(at >> 8);
	out[4] = (unsigned char)at;
	memcpy(out + 5, data + 5, at);
	memcpy(out + 5 + at, data, 3);
	out[5 + at + 3] = (unsigned char)((record_len - at) >> 8);
	out[5 + at + 4] = (unsigned char)(record_len - at);
	memcpy(out + 10 + at, data + 5 + at, len - 5 - at);
	return ((ssize_t)(len + 5));
}

/* Where to fragment: mid-hostname when the SNI is in `data` (same
 * point tls_find_sni_split picks, translated to a body offset), else
 * right after the first body byte — both verified live against an
 * SNI-matching DPI that ignores plain TCP segmentation. */
size_t	tls_record_split_point(const unsigned char *data, size_t len)
{
	ssize_t	split;

	split = tls_find_sni_split(data, len);
	if (split > 5)
		return ((size_t)split - 5);
	return (1);
}
