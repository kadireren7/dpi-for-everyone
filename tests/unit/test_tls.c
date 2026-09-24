#include "tls_sni.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void	put_u16(uint8_t *buf, size_t *pos, uint16_t v)
{
	buf[*pos] = (uint8_t)(v >> 8);
	buf[*pos + 1] = (uint8_t)v;
	*pos += 2;
}

/* Builds a minimal-but-structurally-real ClientHello: record header,
 * handshake header, version+random+session+ciphers+compression, and
 * an extensions block containing exactly one SNI (server_name)
 * extension for `hostname`. */
static size_t	build_client_hello(uint8_t *buf, const char *hostname)
{
	size_t	pos;
	size_t	name_len;
	size_t	sni_ext_len;
	size_t	ext_block_len_pos;
	size_t	handshake_len_pos;
	size_t	i;

	name_len = strlen(hostname);
	sni_ext_len = 2 + 1 + 2 + name_len;

	pos = 0;
	buf[pos++] = 0x16;
	put_u16(buf, &pos, 0x0301);
	put_u16(buf, &pos, 0);

	buf[pos++] = 0x01;
	handshake_len_pos = pos;
	buf[pos++] = 0;
	buf[pos++] = 0;
	buf[pos++] = 0;

	put_u16(buf, &pos, 0x0303);
	for (i = 0; i < 32; i++)
		buf[pos++] = (uint8_t)i;

	buf[pos++] = 0;

	put_u16(buf, &pos, 2);
	put_u16(buf, &pos, 0x1301);

	buf[pos++] = 1;
	buf[pos++] = 0;

	ext_block_len_pos = pos;
	put_u16(buf, &pos, 0);

	put_u16(buf, &pos, 0x0000);
	put_u16(buf, &pos, (uint16_t)sni_ext_len);
	put_u16(buf, &pos, (uint16_t)(1 + 2 + name_len));
	buf[pos++] = 0x00;
	put_u16(buf, &pos, (uint16_t)name_len);
	memcpy(buf + pos, hostname, name_len);
	pos += name_len;

	buf[ext_block_len_pos] = (uint8_t)((pos - ext_block_len_pos - 2) >> 8);
	buf[ext_block_len_pos + 1] = (uint8_t)(pos - ext_block_len_pos - 2);

	buf[handshake_len_pos] = (uint8_t)((pos - handshake_len_pos - 3) >> 16);
	buf[handshake_len_pos + 1] = (uint8_t)((pos - handshake_len_pos - 3) >> 8);
	buf[handshake_len_pos + 2] = (uint8_t)(pos - handshake_len_pos - 3);

	buf[3] = (uint8_t)((pos - 5) >> 8);
	buf[4] = (uint8_t)(pos - 5);

	return (pos);
}

static void	test_full_hello_extracts_sni(void)
{
	uint8_t	buf[512];
	size_t	len;
	char	host[256];

	len = build_client_hello(buf, "example.com");
	assert(tls_parse_client_hello_sni(buf, len, host, sizeof(host))
		== PACKET_OK);
	assert(strcmp(host, "example.com") == 0);
}

static void	test_bounded_reassembly(void)
{
	uint8_t	buf[512];
	size_t	len;
	char	host[256];
	size_t	cut;

	len = build_client_hello(buf, "discord.com");

	for (cut = 1; cut < len; cut++)
	{
		int	status;

		status = tls_parse_client_hello_sni(buf, cut, host, sizeof(host));
		assert(status == PACKET_ERR_TRUNCATED
			|| status == PACKET_ERR_MALFORMED);
	}

	assert(tls_parse_client_hello_sni(buf, len, host, sizeof(host))
		== PACKET_OK);
	assert(strcmp(host, "discord.com") == 0);
}

static void	test_not_tls_is_unsupported(void)
{
	uint8_t	buf[16] = { 0x17, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11 };
	char	host[256];

	assert(tls_parse_client_hello_sni(buf, sizeof(buf), host, sizeof(host))
		== PACKET_ERR_UNSUPPORTED);
}

static void	test_oversized_is_malformed(void)
{
	/* Need pos+4<=len (9 bytes) so the parser actually reads the
	 * 3-byte handshake length at buf[6..8] instead of correctly
	 * reporting TRUNCATED first for want of those bytes. */
	uint8_t	buf[9];
	char	host[256];

	buf[0] = 0x16;
	buf[1] = 3;
	buf[2] = 1;
	buf[3] = 0xFF;
	buf[4] = 0xFF;
	buf[5] = 0x01;
	buf[6] = 0xFF;
	buf[7] = 0xFF;
	buf[8] = 0xFF;

	assert(tls_parse_client_hello_sni(buf, sizeof(buf), host, sizeof(host))
		== PACKET_ERR_MALFORMED);
}

static void	test_no_sni_is_unsupported(void)
{
	uint8_t	buf[512];
	uint8_t	*p;
	size_t	pos;
	char	host[256];

	/* Same shape as build_client_hello but with an empty extensions
	 * block (no SNI present). */
	p = buf;
	pos = 0;
	p[pos++] = 0x16;
	put_u16(p, &pos, 0x0301);
	put_u16(p, &pos, 0);

	p[pos++] = 0x01;
	p[pos++] = 0;
	p[pos++] = 0;
	p[pos++] = 0;

	put_u16(p, &pos, 0x0303);
	memset(p + pos, 0, 32);
	pos += 32;
	p[pos++] = 0;
	put_u16(p, &pos, 2);
	put_u16(p, &pos, 0x1301);
	p[pos++] = 1;
	p[pos++] = 0;
	put_u16(p, &pos, 0);

	p[3] = (uint8_t)((pos - 3 - 2) >> 8);
	p[4] = (uint8_t)(pos - 3 - 2);
	p[6] = (uint8_t)((pos - 9) >> 16);
	p[7] = (uint8_t)((pos - 9) >> 8);
	p[8] = (uint8_t)(pos - 9);

	assert(tls_parse_client_hello_sni(buf, pos, host, sizeof(host))
		== PACKET_ERR_UNSUPPORTED);
}

/* A ClientHello that arrives already split into TLS records (another
 * DPI tool in front of us did it): parsed raw, the SNI would include
 * a record header ("collector.\x16\x03\x01..githu" was seen live);
 * merged, it is the original hello again. */
static void	test_coalesce_split_records(void)
{
	uint8_t	hello[512];
	uint8_t	split[600];
	uint8_t	merged[600];
	char	host[TLS_SNI_HOST_MAX];
	size_t	len;
	size_t	cut;
	size_t	body;
	ssize_t	n;

	len = build_client_hello(hello, "collector.github.com");
	body = len - 5;
	cut = 60;
	memcpy(split, hello, 5 + cut);
	split[3] = (uint8_t)(cut >> 8);
	split[4] = (uint8_t)cut;
	split[5 + cut] = 0x16;
	split[6 + cut] = hello[1];
	split[7 + cut] = hello[2];
	split[8 + cut] = (uint8_t)((body - cut) >> 8);
	split[9 + cut] = (uint8_t)(body - cut);
	memcpy(split + 10 + cut, hello + 5 + cut, body - cut);
	n = tls_coalesce_handshake_records(split, len + 5, merged, sizeof(merged));
	assert(n == (ssize_t)len && memcmp(merged, hello, len) == 0);
	assert(tls_parse_client_hello_sni(merged, (size_t)n, host, sizeof(host))
		== PACKET_OK && strcmp(host, "collector.github.com") == 0);
	/* the second record only partly here: declared length kept, the
	 * rest continues the merged body later */
	n = tls_coalesce_handshake_records(split, len - 10, merged,
			sizeof(merged));
	assert(n == (ssize_t)(len - 15));
	assert(merged[3] == hello[3] && merged[4] == hello[4]);
	/* trailing non-handshake bytes are kept as they are */
	memcpy(split + len + 5, "\x14\x03\x03\x00\x01\x01", 6);
	n = tls_coalesce_handshake_records(split, len + 11, merged,
			sizeof(merged));
	assert(n == (ssize_t)len + 6
		&& memcmp(merged + len, "\x14\x03\x03\x00\x01\x01", 6) == 0);
	/* one record, not TLS, output too small: -1 (use input as is) */
	assert(tls_coalesce_handshake_records(hello, len, merged,
			sizeof(merged)) == -1);
	assert(tls_coalesce_handshake_records((const uint8_t *)"GET / HTTP",
			10, merged, sizeof(merged)) == -1);
	assert(tls_coalesce_handshake_records(split, len + 5, merged, 64) == -1);
}

int	main(void)
{
	test_full_hello_extracts_sni();
	test_bounded_reassembly();
	test_not_tls_is_unsupported();
	test_oversized_is_malformed();
	test_no_sni_is_unsupported();
	test_coalesce_split_records();
	printf("test_tls: OK\n");
	return (0);
}
