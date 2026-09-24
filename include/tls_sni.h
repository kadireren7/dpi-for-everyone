#ifndef TLS_SNI_H
# define TLS_SNI_H

# include "packet.h"
# include <stddef.h>
# include <stdint.h>
# include <sys/types.h>

# define TLS_SNI_HOST_MAX 256
/* Bound how many ClientHello bytes we'll ever buffer across packets
 * before giving up, so a malformed/oversized handshake can't make
 * flow reassembly grow without limit. */
# define TLS_CLIENTHELLO_CAP 16384

/* Returns PACKET_OK (host_out filled), PACKET_ERR_TRUNCATED (valid so
 * far, caller should buffer more bytes from later packets and retry),
 * PACKET_ERR_MALFORMED (structurally invalid or over TLS_CLIENTHELLO_CAP
 * — give up, don't retry), or PACKET_ERR_UNSUPPORTED (not a TLS
 * ClientHello, or one with no SNI extension). Either way but OK,
 * caller should PASS the flow through unmodified. */
int	tls_parse_client_hello_sni(const uint8_t *data, size_t len,
		char *host_out, size_t host_out_size);

/* Rewrites a ClientHello that arrives as two or more handshake
 * records into one record with the same handshake bytes (trailing
 * non-handshake bytes kept as-is). Returns the new length, or -1 if
 * `in` isn't a multi-record handshake (use it unchanged) or `out` is
 * too small. `in` and `out` must not overlap. */
ssize_t	tls_coalesce_handshake_records(const uint8_t *in, size_t len,
		uint8_t *out, size_t out_size);

#endif
