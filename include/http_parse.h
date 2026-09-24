#ifndef HTTP_PARSE_H
# define HTTP_PARSE_H

# include "packet.h"
# include <stddef.h>
# include <stdint.h>

# define HTTP_HOST_MAX 256
/* Bound how many header bytes we'll ever buffer/scan looking for the
 * end of the header block, so a client that never sends "\r\n\r\n"
 * can't make us grow an unbounded buffer. */
# define HTTP_SCAN_CAP 8192

/* Returns PACKET_OK (host_out filled), PACKET_ERR_TRUNCATED (valid so
 * far, need more bytes), PACKET_ERR_MALFORMED, or PACKET_ERR_UNSUPPORTED
 * (not an HTTP request, or no recognizable Host header — either way,
 * caller should PASS). */
int	http_parse_host(const uint8_t *data, size_t len,
		char *host_out, size_t host_out_size);

#endif
