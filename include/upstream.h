#ifndef UPSTREAM_H
# define UPSTREAM_H

# include "platform.h"

socket_t	connect_upstream(const char *host, int port);

# ifdef __linux__
/* Transparent mode only (Linux: SOCK_CLOEXEC, SO_MARK).
 * Connects to an already-resolved address with a bounded wait
 * (`timeout_ms`), TCP_NODELAY set (so a split first write stays
 * split), and SO_MARK `mark` if non-zero (needs CAP_NET_ADMIN; used by
 * transparent mode so its own connections are never intercepted
 * again). Returns a blocking socket, or SOCKET_INVALID. */
socket_t	connect_upstream_addr(const struct sockaddr *addr,
				socklen_t addr_len, int timeout_ms, int mark);
# endif

#endif
