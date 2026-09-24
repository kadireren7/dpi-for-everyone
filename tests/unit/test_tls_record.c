#define _GNU_SOURCE
#include "tls.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Minimal ClientHello: record header, handshake header, version,
 * random, empty session id, one cipher, null compression, and one SNI
 * extension for `host`. */
/* memmem() is a GNU extension; the tests also build for Windows */
static const void	*find_bytes(const void *hay, size_t hay_len,
	const void *needle, size_t needle_len)
{
	const unsigned char	*h;
	size_t				i;

	h = hay;
	i = 0;
	while (needle_len <= hay_len && i + needle_len <= hay_len)
	{
		if (memcmp(h + i, needle, needle_len) == 0)
			return (h + i);
		i++;
	}
	return (NULL);
}

static size_t	build_client_hello(unsigned char *buf, const char *host)
{
	size_t	pos;
	size_t	name_len;
	size_t	body_len;

	name_len = strlen(host);
	pos = 0;
	buf[pos++] = 0x16;
	buf[pos++] = 0x03;
	buf[pos++] = 0x01;
	pos += 2; /* record length, filled below */
	buf[pos++] = 0x01;
	pos += 3; /* handshake length, filled below */
	buf[pos++] = 0x03;
	buf[pos++] = 0x03;
	memset(buf + pos, 0xAB, 32);
	pos += 32;
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = 0x02;
	buf[pos++] = 0x13;
	buf[pos++] = 0x01;
	buf[pos++] = 0x01;
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)(4 + 5 + name_len);
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)(5 + name_len);
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)(3 + name_len);
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)name_len;
	memcpy(buf + pos, host, name_len);
	pos += name_len;
	body_len = pos - 5;
	buf[3] = (unsigned char)(body_len >> 8);
	buf[4] = (unsigned char)body_len;
	buf[6] = 0;
	buf[7] = (unsigned char)((body_len - 4) >> 8);
	buf[8] = (unsigned char)(body_len - 4);
	return (pos);
}

/* Both output records must carry the original handshake bytes, in
 * order, with correct headers — i.e. a TLS receiver reassembles
 * exactly the original ClientHello. */
static void	assert_reassembles(const unsigned char *orig, size_t orig_len,
	const unsigned char *out, size_t out_len, size_t at)
{
	size_t	first_len;
	size_t	second_len;

	assert(out_len == orig_len + 5);
	first_len = ((size_t)out[3] << 8) | out[4];
	assert(first_len == at);
	assert(memcmp(out, orig, 3) == 0);
	assert(memcmp(out + 5 + at, orig, 3) == 0);
	second_len = ((size_t)out[5 + at + 3] << 8) | out[5 + at + 4];
	assert(first_len + second_len == (((size_t)orig[3] << 8) | orig[4]));
	assert(memcmp(out + 5, orig + 5, at) == 0);
	assert(memcmp(out + 10 + at, orig + 5 + at, orig_len - 5 - at) == 0);
}

static void	test_fragment_splits_mid_hostname(void)
{
	unsigned char	ch[512];
	unsigned char	out[512];
	size_t			len;
	size_t			at;
	ssize_t			out_len;
	const char		*host;

	len = build_client_hello(ch, "discord.com");
	at = tls_record_split_point(ch, len);
	host = (const char *)memchr(ch, 'd', len);
	assert(host != NULL);
	/* split point is inside "discord.com", so neither record holds the
	 * whole hostname */
	assert(at + 5 > (size_t)((const unsigned char *)host - ch));
	assert(at + 5 < (size_t)((const unsigned char *)host - ch) + 11);
	out_len = tls_fragment_first_record(ch, len, at, out, sizeof(out));
	assert(out_len > 0);
	assert_reassembles(ch, len, out, (size_t)out_len, at);
	assert(find_bytes(out, (size_t)out_len, "discord.com", 11) == NULL);
}

/* Only the start of a record arrived in the first read: the headers
 * are still rewritten correctly and the rest of the stream continues
 * as the second record's body. */
static void	test_fragment_partial_record(void)
{
	unsigned char	ch[512];
	unsigned char	out[512];
	size_t			len;
	ssize_t			out_len;

	len = build_client_hello(ch, "discord.com");
	out_len = tls_fragment_first_record(ch, 20, 1, out, sizeof(out));
	assert(out_len == 25);
	assert(out[3] == 0 && out[4] == 1);
	assert((((size_t)out[9] << 8) | out[10]) == len - 5 - 1);
	assert(memcmp(out + 11, ch + 6, 14) == 0);
}

static void	test_fragment_rejects_bad_input(void)
{
	unsigned char	ch[512];
	unsigned char	out[512];
	size_t			len;

	len = build_client_hello(ch, "discord.com");
	assert(tls_fragment_first_record(ch, len, 0, out, sizeof(out)) == -1);
	assert(tls_fragment_first_record(ch, len, len - 5, out,
			sizeof(out)) == -1);
	assert(tls_fragment_first_record(ch, len, 10, out, len + 4) == -1);
	assert(tls_fragment_first_record((const unsigned char *)"GET / HTTP/1.1",
			14, 3, out, sizeof(out)) == -1);
	/* no SNI in the buffer yet → fall back to splitting after byte 1 */
	assert(tls_record_split_point(ch, 20) == 1);
}

int	main(void)
{
	test_fragment_splits_mid_hostname();
	test_fragment_partial_record();
	test_fragment_rejects_bad_input();
	printf("test_tls_record: OK\n");
	return (0);
}
