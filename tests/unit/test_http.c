#include "http_parse.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void	test_valid_host(void)
{
	const char	*req = "GET / HTTP/1.1\r\nHost: example.org\r\n"
		"User-Agent: curl\r\n\r\n";
	char		host[256];

	assert(http_parse_host((const uint8_t *)req, strlen(req),
			host, sizeof(host)) == PACKET_OK);
	assert(strcmp(host, "example.org") == 0);
}

static void	test_case_insensitive_and_extra_spaces(void)
{
	const char	*req = "GET / HTTP/1.1\r\nhOsT:    weird.example\r\n\r\n";
	char		host[256];

	assert(http_parse_host((const uint8_t *)req, strlen(req),
			host, sizeof(host)) == PACKET_OK);
	assert(strcmp(host, "weird.example") == 0);
}

static void	test_truncated_before_headers_end(void)
{
	const char	*req = "GET / HTTP/1.1\r\nHost: example.org\r\n";
	char		host[256];

	assert(http_parse_host((const uint8_t *)req, strlen(req),
			host, sizeof(host)) == PACKET_ERR_TRUNCATED);
}

static void	test_not_http_is_unsupported(void)
{
	const uint8_t	garbage[] = { 0x16, 0x03, 0x01, 0x00, 0x05, 1, 2, 3 };
	char			host[256];

	assert(http_parse_host(garbage, sizeof(garbage), host, sizeof(host))
		== PACKET_ERR_UNSUPPORTED);
}

static void	test_no_host_header_is_unsupported(void)
{
	const char	*req = "GET / HTTP/1.0\r\nConnection: close\r\n\r\n";
	char		host[256];

	assert(http_parse_host((const uint8_t *)req, strlen(req),
			host, sizeof(host)) == PACKET_ERR_UNSUPPORTED);
}

static void	test_oversized_headers_are_malformed(void)
{
	static char	req[HTTP_SCAN_CAP + 100];
	size_t		i;

	memcpy(req, "GET / HTTP/1.1\r\n", 16);
	for (i = 16; i < sizeof(req) - 1; i++)
		req[i] = 'a';
	req[sizeof(req) - 1] = '\0';

	char	host[256];

	assert(http_parse_host((const uint8_t *)req, strlen(req),
			host, sizeof(host)) == PACKET_ERR_MALFORMED);
}

static void	test_small_output_buffer_is_malformed(void)
{
	const char	*req = "GET / HTTP/1.1\r\nHost: example.org\r\n\r\n";
	char		host[4];

	assert(http_parse_host((const uint8_t *)req, strlen(req),
			host, sizeof(host)) == PACKET_ERR_MALFORMED);
}

int	main(void)
{
	test_valid_host();
	test_case_insensitive_and_extra_spaces();
	test_truncated_before_headers_end();
	test_not_http_is_unsupported();
	test_no_host_header_is_unsupported();
	test_oversized_headers_are_malformed();
	test_small_output_buffer_is_malformed();
	printf("test_http: OK\n");
	return (0);
}
