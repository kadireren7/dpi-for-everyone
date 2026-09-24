#include "http_parse.h"

#include <string.h>

static int	looks_like_request_line(const uint8_t *data, size_t len)
{
	static const char	*methods[] = {
		"GET ", "POST ", "HEAD ", "PUT ", "DELETE ",
		"OPTIONS ", "CONNECT ", "PATCH ", "TRACE ", NULL
	};
	size_t				i;
	size_t				method_len;

	i = 0;
	while (methods[i] != NULL)
	{
		method_len = strlen(methods[i]);
		if (len >= method_len && memcmp(data, methods[i], method_len) == 0)
			return (1);
		i++;
	}
	return (0);
}

static size_t	find_header_end(const uint8_t *data, size_t scan_len,
	int *found)
{
	size_t	i;

	*found = 0;
	if (scan_len < 4)
		return (0);
	i = 0;
	while (i + 4 <= scan_len)
	{
		if (data[i] == '\r' && data[i + 1] == '\n'
			&& data[i + 2] == '\r' && data[i + 3] == '\n')
		{
			*found = 1;
			return (i);
		}
		i++;
	}
	return (0);
}

static int	starts_with_host_header(const uint8_t *line, size_t line_len)
{
	static const char	prefix[] = "host:";
	size_t				i;

	if (line_len < 5)
		return (0);
	i = 0;
	while (i < 5)
	{
		if ((line[i] | 0x20) != prefix[i])
			return (0);
		i++;
	}
	return (1);
}

static int	extract_host_line(const uint8_t *headers, size_t headers_len,
	char *host_out, size_t host_out_size)
{
	size_t	line_start;
	size_t	i;
	size_t	value_start;
	size_t	value_len;

	line_start = 0;
	i = 0;
	while (i + 1 < headers_len)
	{
		if (headers[i] == '\r' && headers[i + 1] == '\n')
		{
			if (starts_with_host_header(headers + line_start,
					i - line_start))
			{
				value_start = line_start + 5;
				while (value_start < i && headers[value_start] == ' ')
					value_start++;
				value_len = i - value_start;
				if (value_len == 0 || value_len >= host_out_size)
					return (PACKET_ERR_MALFORMED);
				memcpy(host_out, headers + value_start, value_len);
				host_out[value_len] = '\0';
				return (PACKET_OK);
			}
			line_start = i + 2;
			i = line_start;
			continue ;
		}
		i++;
	}
	return (PACKET_ERR_UNSUPPORTED);
}

int	http_parse_host(const uint8_t *data, size_t len,
	char *host_out, size_t host_out_size)
{
	size_t	scan_len;
	size_t	header_end;
	int		found;

	if (data == NULL || host_out == NULL || host_out_size == 0)
		return (PACKET_ERR_MALFORMED);

	if (len < 4)
		return (PACKET_ERR_TRUNCATED);

	if (!looks_like_request_line(data, len))
		return (PACKET_ERR_UNSUPPORTED);

	scan_len = len;
	if (scan_len > HTTP_SCAN_CAP)
		scan_len = HTTP_SCAN_CAP;

	header_end = find_header_end(data, scan_len, &found);

	if (!found)
	{
		if (len >= HTTP_SCAN_CAP)
			return (PACKET_ERR_MALFORMED);
		return (PACKET_ERR_TRUNCATED);
	}

	/* find_header_end returns the offset of the blank line's own
	 * "\r\n\r\n"; +2 includes the *last real header's* trailing
	 * "\r\n" so extract_host_line's line-splitter (which requires
	 * every line to end in "\r\n") actually sees that last line. */
	return (extract_host_line(data, header_end + 2, host_out,
			host_out_size));
}
