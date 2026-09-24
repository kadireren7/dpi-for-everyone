#ifndef SOCKS_H
# define SOCKS_H

/* `host` may be NULL for the default 127.0.0.1 (loopback only). */
int	run_socks_server(const char *host, int port);

/* 1 (default) prints "request: host:port" per connection; set to 0
 * before calling run_socks_server() for --log-level error. */
extern int	g_socks_verbose;

#endif
