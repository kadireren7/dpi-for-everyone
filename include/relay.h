#ifndef RELAY_H
# define RELAY_H

# include "platform.h"
# include "strategy.h"
# include <stddef.h>

/* The stream-processing core shared by SOCKS mode (src/socks.c) and
 * transparent mode (src/transparent/transparent.c): both hand the
 * client's first write (normally its TLS ClientHello) to
 * relay_send_first(), then copy bytes both ways with relay_pump(). */

/* `split_tls`: what to do with the client's first write. */
# define RELAY_SPLIT_NONE 0
# define RELAY_SPLIT_TCP 1
# define RELAY_SPLIT_TLS_RECORD 2
/* TLS_RECORD re-framing, all of it written at once except that the
 * first RELAY_TLSREC_TCP_CUT bytes go out as their own TCP segment */
# define RELAY_SPLIT_TLS_RECORD_TCP 3
# define RELAY_TLSREC_TCP_CUT 3

/* The split_tls mode that executes stream strategy `s` (TLSREC,
 * TLSREC_SPLIT); anything else is NONE. */
int	relay_split_for(t_strategy s);

typedef struct s_relay_stats
{
	unsigned long long	up_bytes;		/* client -> upstream, after first */
	unsigned long long	down_bytes;		/* upstream -> client */
	int					client_eof_first;	/* client finished sending
											 * before the server did */
	int					upstream_reset;	/* upstream errored (e.g. RST) */
}	t_relay_stats;

/* Blocking send of all `len` bytes; 0 or -1. */
int	relay_send_all(socket_t fd, const unsigned char *buf, size_t len);

/* Sends the client's first write upstream: unchanged (NONE), split
 * mid-SNI into two TCP segments (TCP), or re-framed as two TLS records
 * (TLS_RECORD). Anything that isn't a ClientHello is sent unchanged.
 * `len` must be at most BUFFER_SIZE. */
int	relay_send_first(socket_t upstream_fd, const unsigned char *buf,
		size_t len, int split_tls);

/* Copies both directions until both are finished, propagating
 * half-closes (EOF on one side -> shutdown(SHUT_WR) on the other). An
 * upstream error ends the relay and resets the client connection, so
 * the application sees the failure instead of a clean close. `stats`
 * may be NULL. */
int	relay_pump(socket_t client_fd, socket_t upstream_fd,
		t_relay_stats *stats);
/* Same, but gives up (-1) after `idle_timeout_ms` with no data in
 * either direction; -1 = wait forever (relay_pump). */
int	relay_pump_timeout(socket_t client_fd, socket_t upstream_fd,
		t_relay_stats *stats, int idle_timeout_ms);

/* SOCKS mode: reads the client's first write, relay_send_first()s it,
 * then relay_pump()s. */
int	relay_connection(socket_t client_fd, socket_t upstream_fd, int split_tls);

#endif
