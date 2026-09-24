#include "relay.h"
#include "common.h"
#include "tls.h"

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
# include <poll.h>
#endif

int	relay_send_all(socket_t fd, const unsigned char *buffer, size_t length)
{
	size_t	total;
	ssize_t	sent;

	total = 0;
	while (total < length)
	{
		sent = send(fd, (const char *)(buffer + total),
				length - total, MSG_NOSIGNAL);
		if (sent < 0 && socket_error_is_interrupted(socket_last_error()))
			continue ;
		if (sent <= 0)
			return (-1);
		total += (size_t)sent;
	}
	return (0);
}

static void	split_delay(void)
{
#ifdef _WIN32
	Sleep(1);
#else
	usleep(1000);
#endif
}

static int	send_first_tls(socket_t upstream_fd,
	const unsigned char *buffer, size_t bytes)
{
	ssize_t	split;

	split = tls_find_sni_split(buffer, bytes);

	if (split <= 0 || (size_t)split >= bytes)
		return (relay_send_all(upstream_fd, buffer, bytes));

	/* Send the ClientHello in two writes, splitting mid-SNI-hostname,
	 * so a DPI box matching the hostname against a single packet
	 * doesn't see it whole. TCP_NODELAY (set on the upstream socket)
	 * plus this delay keep the OS from coalescing the two writes back
	 * into one segment. */
	if (relay_send_all(upstream_fd, buffer, (size_t)split) < 0)
		return (-1);

	split_delay();

	return (relay_send_all(upstream_fd, buffer + split,
			bytes - (size_t)split));
}

/* TLS record fragmentation: the ClientHello is re-framed as two TLS
 * records (tls_fragment_first_record), and the first record goes out
 * in its own TCP segment. Unlike send_first_tls's plain TCP split —
 * which a reassembling DPI sees straight through — this changes what
 * the DPI has to parse, not just how the bytes are packetized. Falls
 * back to sending `buffer` unchanged if it isn't a ClientHello. */
static int	send_first_tls_record(socket_t upstream_fd,
	const unsigned char *buffer, size_t bytes)
{
	unsigned char	out[BUFFER_SIZE + 5];
	ssize_t			out_len;
	size_t			at;

	at = tls_record_split_point(buffer, bytes);
	out_len = tls_fragment_first_record(buffer, bytes, at,
			out, sizeof(out));
	if (out_len < 0)
		return (relay_send_all(upstream_fd, buffer, bytes));
	if (relay_send_all(upstream_fd, out, 5 + at) < 0)
		return (-1);
	split_delay();
	return (relay_send_all(upstream_fd, out + 5 + at,
			(size_t)out_len - (5 + at)));
}

/* Same re-framing as send_first_tls_record, but the TCP cut is not at
 * the record boundary: a few header bytes alone, then everything else
 * (both records) in one write. */
static int	send_first_tls_record_tcp(socket_t upstream_fd,
	const unsigned char *buffer, size_t bytes)
{
	unsigned char	out[BUFFER_SIZE + 5];
	ssize_t			out_len;
	size_t			at;

	at = tls_record_split_point(buffer, bytes);
	out_len = tls_fragment_first_record(buffer, bytes, at,
			out, sizeof(out));
	if (out_len <= RELAY_TLSREC_TCP_CUT)
		return (relay_send_all(upstream_fd, buffer, bytes));
	if (relay_send_all(upstream_fd, out, RELAY_TLSREC_TCP_CUT) < 0)
		return (-1);
	split_delay();
	return (relay_send_all(upstream_fd, out + RELAY_TLSREC_TCP_CUT,
			(size_t)out_len - RELAY_TLSREC_TCP_CUT));
}

int	relay_split_for(t_strategy s)
{
	if (s == STRATEGY_TLSREC)
		return (RELAY_SPLIT_TLS_RECORD);
	if (s == STRATEGY_TLSREC_SPLIT)
		return (RELAY_SPLIT_TLS_RECORD_TCP);
	return (RELAY_SPLIT_NONE);
}

int	relay_send_first(socket_t upstream_fd, const unsigned char *buf,
	size_t len, int split_tls)
{
	if (split_tls == RELAY_SPLIT_TLS_RECORD)
		return (send_first_tls_record(upstream_fd, buf, len));
	if (split_tls == RELAY_SPLIT_TLS_RECORD_TCP)
		return (send_first_tls_record_tcp(upstream_fd, buf, len));
	if (split_tls == RELAY_SPLIT_TCP)
		return (send_first_tls(upstream_fd, buf, len));
	return (relay_send_all(upstream_fd, buf, len));
}

/* One read from `from`, written to `to`. Returns 1 if data was moved,
 * 0 on EOF, -1 on a read error, -2 on a write error. */
static int	forward_once(socket_t from, socket_t to,
	unsigned long long *counter)
{
	unsigned char	buffer[BUFFER_SIZE];
	ssize_t			bytes;

	bytes = recv(from, (char *)buffer, sizeof(buffer), 0);
	if (bytes == 0)
		return (0);
	if (bytes < 0)
	{
		if (socket_error_is_interrupted(socket_last_error()))
			return (1);
		return (-1);
	}
	if (relay_send_all(to, buffer, (size_t)bytes) < 0)
		return (-2);
	if (counter != NULL)
		*counter += (unsigned long long)bytes;
	return (1);
}

static void	reset_connection(socket_t fd)
{
	struct linger	lg;

	lg.l_onoff = 1;
	lg.l_linger = 0;
	setsockopt(fd, SOL_SOCKET, SO_LINGER, (const char *)&lg, sizeof(lg));
}

#ifndef _WIN32
# define SHUT_WRITE SHUT_WR
#else
# define SHUT_WRITE SD_SEND
#endif

/* Waits until client and/or upstream is readable, among the
 * directions still open. Returns <0 on error. */
static int	wait_readable(socket_t client_fd, socket_t upstream_fd,
	int up_open, int down_open, int *client_ready, int *upstream_ready,
	int timeout_ms)
{
#ifndef _WIN32
	struct pollfd	pfd[2];
	int				ready;

	pfd[0].fd = up_open ? client_fd : -1;
	pfd[0].events = POLLIN;
	pfd[0].revents = 0;
	pfd[1].fd = down_open ? upstream_fd : -1;
	pfd[1].events = POLLIN;
	pfd[1].revents = 0;
	ready = poll(pfd, 2, timeout_ms);
	if (ready < 0)
		return (ready);
	*client_ready = (pfd[0].revents != 0);
	*upstream_ready = (pfd[1].revents != 0);
	return (ready);
#else
	fd_set			read_set;
	int				ready;
	int				max_fd;
	struct timeval	tv;

	FD_ZERO(&read_set);
	if (up_open)
		FD_SET(client_fd, &read_set);
	if (down_open)
		FD_SET(upstream_fd, &read_set);
	max_fd = (int)(client_fd > upstream_fd ? client_fd : upstream_fd);
	tv.tv_sec = timeout_ms / 1000;
	tv.tv_usec = (timeout_ms % 1000) * 1000;
	ready = select(max_fd + 1, &read_set, NULL, NULL,
			timeout_ms < 0 ? NULL : &tv);
	if (ready < 0)
		return (ready);
	*client_ready = up_open && FD_ISSET(client_fd, &read_set);
	*upstream_ready = down_open && FD_ISSET(upstream_fd, &read_set);
	return (ready);
#endif
}

int	relay_pump(socket_t client_fd, socket_t upstream_fd,
	t_relay_stats *stats)
{
	return (relay_pump_timeout(client_fd, upstream_fd, stats, -1));
}

int	relay_pump_timeout(socket_t client_fd, socket_t upstream_fd,
	t_relay_stats *stats, int idle_timeout_ms)
{
	int				ready;
	t_relay_stats	local;
	int				up_open;
	int				down_open;
	int				client_ready;
	int				upstream_ready;
	int				status;

	if (stats == NULL)
		stats = &local;
	memset(stats, 0, sizeof(*stats));
	up_open = 1;
	down_open = 1;
	while (up_open || down_open)
	{
		ready = wait_readable(client_fd, upstream_fd, up_open, down_open,
				&client_ready, &upstream_ready, idle_timeout_ms);
		if (ready < 0)
		{
			if (socket_error_is_interrupted(socket_last_error()))
				continue ;
			return (-1);
		}
		if (ready == 0)
			return (-1);
		if (client_ready)
		{
			status = forward_once(client_fd, upstream_fd, &stats->up_bytes);
			if (status == 0)
			{
				up_open = 0;
				if (down_open)
					stats->client_eof_first = 1;
				shutdown(upstream_fd, SHUT_WRITE);
			}
			else if (status < 0)
				return (0);
		}
		if (upstream_ready)
		{
			status = forward_once(upstream_fd, client_fd, &stats->down_bytes);
			if (status == 0)
			{
				down_open = 0;
				shutdown(client_fd, SHUT_WRITE);
			}
			else if (status == -1)
			{
				stats->upstream_reset = 1;
				reset_connection(client_fd);
				return (0);
			}
			else if (status < 0)
				return (0);
		}
	}
	return (0);
}

int	relay_connection(socket_t client_fd, socket_t upstream_fd, int split_tls)
{
	unsigned char	buffer[BUFFER_SIZE];
	ssize_t			bytes;
	int				client_ready;
	int				upstream_ready;

	/* The split only applies if the client talks first (TLS); a
	 * server-speaks-first protocol (SSH, SMTP, ...) is just pumped. */
	if (split_tls == RELAY_SPLIT_NONE)
		return (relay_pump(client_fd, upstream_fd, NULL));
	while (wait_readable(client_fd, upstream_fd, 1, 1, &client_ready,
			&upstream_ready, -1) < 0)
	{
		if (!socket_error_is_interrupted(socket_last_error()))
			return (-1);
	}
	if (!client_ready)
		return (relay_pump(client_fd, upstream_fd, NULL));
	do
		bytes = recv(client_fd, (char *)buffer, sizeof(buffer), 0);
	while (bytes < 0 && socket_error_is_interrupted(socket_last_error()));
	if (bytes <= 0)
		return (0);
	if (relay_send_first(upstream_fd, buffer, (size_t)bytes, split_tls) < 0)
		return (-1);
	return (relay_pump(client_fd, upstream_fd, NULL));
}
