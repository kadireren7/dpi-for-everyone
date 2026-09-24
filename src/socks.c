#include "socks.h"
#include "platform.h"
#include "relay.h"
#include "upstream.h"

#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Set from main.c per --log-level before run_socks_server() is
 * called; 1 (default) prints the per-connection "request: host:port"
 * line, 0 (--log-level error) suppresses it. */
int	g_socks_verbose = 1;

static ssize_t	recv_exact(socket_t fd, void *buffer, size_t length)
{
	unsigned char	*p;
	size_t			total;
	ssize_t			n;

	p = buffer;
	total = 0;

	while (total < length)
	{
		n = recv(fd, (char *)(p + total), length - total, 0);

		if (n == 0)
			return (0);

		if (n < 0)
		{
			if (socket_error_is_interrupted(socket_last_error()))
				continue ;
			return (-1);
		}

		total += (size_t)n;
	}

	return ((ssize_t)total);
}

static int	socks_negotiate(socket_t fd)
{
	unsigned char	header[2];
	unsigned char	methods[255];
	unsigned char	reply[2];

	if (recv_exact(fd, header, 2) != 2)
		return (-1);

	if (header[0] != 0x05)
		return (-1);

	if (header[1] == 0)
		return (-1);

	if (recv_exact(fd, methods, header[1]) != header[1])
		return (-1);

	reply[0] = 0x05;
	reply[1] = 0x00;

	if (send(fd, (const char *)reply, 2, MSG_NOSIGNAL) != 2)
		return (-1);

	return (0);
}

static int	send_result(socket_t fd, int success);

static int	read_target(socket_t fd, char *host,
	size_t host_size, int *port)
{
	unsigned char	header[4];
	unsigned char	length;
	unsigned char	port_buf[2];

	if (recv_exact(fd, header, 4) != 4)
		return (-1);

	if (header[0] != 0x05 || header[1] != 0x01)
		return (-1);

	unsigned char atyp = header[3];

	if (atyp == 0x03)
	{
		/* DOMAIN */
		if (recv_exact(fd, &length, 1) != 1)
			return (-1);

		if (length == 0 || (size_t)length >= host_size)
			return (-1);

		if (recv_exact(fd, host, length) != length)
			return (-1);

		host[length] = '\0';

		if (recv_exact(fd, port_buf, 2) != 2)
			return (-1);

		*port = ((int)port_buf[0] << 8) | port_buf[1];
		return (0);
	}
	else if (atyp == 0x01)
	{
		/* IPv4 */
		unsigned char addr4[4];

		if (recv_exact(fd, addr4, 4) != 4)
			return (-1);

		if (inet_ntop(AF_INET, addr4, host, host_size) == NULL)
			return (-1);

		if (recv_exact(fd, port_buf, 2) != 2)
			return (-1);

		*port = ((int)port_buf[0] << 8) | port_buf[1];
		return (0);
	}
	else if (atyp == 0x04)
	{
		/* IPv6 */
		unsigned char addr6[16];

		if (recv_exact(fd, addr6, 16) != 16)
			return (-1);

		if (inet_ntop(AF_INET6, addr6, host, host_size) == NULL)
			return (-1);

		if (recv_exact(fd, port_buf, 2) != 2)
			return (-1);

		*port = ((int)port_buf[0] << 8) | port_buf[1];
		return (0);
	}
	else
	{
		/* unsupported ATYP: reply failure to client then abort */
		send_result(fd, 0);
		return (-1);
	}
}

static int	send_result(socket_t fd, int success)
{
	unsigned char	reply[10];

	memset(reply, 0, sizeof(reply));

	reply[0] = 0x05;
	reply[1] = success ? 0x00 : 0x01;
	reply[2] = 0x00;
	reply[3] = 0x01;

	return (send(fd, (const char *)reply, sizeof(reply),
			MSG_NOSIGNAL) == (ssize_t)sizeof(reply) ? 0 : -1);
}

static void	handle_client(socket_t client_fd)
{
	char		host[256];
	int			port;
	socket_t	upstream_fd;
	int			split_tls;

	if (socks_negotiate(client_fd) < 0)
		return ;

	if (read_target(client_fd,
			host, sizeof(host), &port) < 0)
		return ;

	if (g_socks_verbose)
		printf("request: %s:%d\n", host, port);

	upstream_fd = connect_upstream(host, port);

	if (upstream_fd == SOCKET_INVALID)
	{
		send_result(client_fd, 0);
		return ;
	}

	if (send_result(client_fd, 1) < 0)
	{
		socket_close(upstream_fd);
		return ;
	}

	/* ClientHello splitting is OFF by default: in testing it reliably
	 * broke the handshake against at least Cloudflare-fronted hosts
	 * (upstream closed the connection right after the split write),
	 * while leaving unaffected hosts untouched. Opt in per-run with
	 * DPI_PROXY_SPLIT_TLS=1 (plain TCP split) or
	 * DPI_PROXY_SPLIT_TLS=record (TLS record fragmentation, see
	 * send_first_tls_record) and verify it actually helps *and*
	 * doesn't break the sites you care about before relying on it. */
	split_tls = RELAY_SPLIT_NONE;

	{
		const char	*env;

		env = getenv("DPI_PROXY_SPLIT_TLS");

		if (env != NULL && strcmp(env, "1") == 0)
			split_tls = RELAY_SPLIT_TCP;
		else if (env != NULL && strcmp(env, "record") == 0)
			split_tls = RELAY_SPLIT_TLS_RECORD;
	}

	relay_connection(client_fd, upstream_fd, split_tls);

	socket_close(upstream_fd);
}

static void	*client_thread(void *arg)
{
	socket_t	client_fd;

	client_fd = *(socket_t *)arg;
	free(arg);

	handle_client(client_fd);

	socket_close(client_fd);

	return (NULL);
}

int	run_socks_server(const char *host, int port)
{
	struct sockaddr_in	addr;
	socket_t			server_fd;
	socket_t			client_fd;
	socket_t			*client_arg;
	int					reuse;
	pthread_t			tid;

#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif

	server_fd = socket(AF_INET, SOCK_STREAM, 0);

	if (server_fd == SOCKET_INVALID)
	{
		perror("socket");
		return (-1);
	}

	reuse = 1;

	setsockopt(server_fd, SOL_SOCKET,
		SO_REUSEADDR, (const char *)&reuse, sizeof(reuse));

	memset(&addr, 0, sizeof(addr));

	addr.sin_family = AF_INET;

	if (host == NULL)
		addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	else if (inet_pton(AF_INET, host, &addr.sin_addr) != 1)
	{
		fprintf(stderr, "invalid --listen address: %s "
			"(only IPv4 dotted-decimal is supported)\n", host);
		socket_close(server_fd);
		return (-1);
	}

	addr.sin_port = htons((uint16_t)port);

	if (bind(server_fd,
			(struct sockaddr *)&addr,
			sizeof(addr)) < 0)
	{
		perror("bind");
		if (host != NULL && strcmp(host, "127.0.0.1") != 0)
			fprintf(stderr, "note: binding to %s (not loopback) exposes "
				"this proxy to whatever can reach that address\n", host);
		socket_close(server_fd);
		return (-1);
	}

	if (listen(server_fd, 64) < 0)
	{
		perror("listen");
		socket_close(server_fd);
		return (-1);
	}

	printf("dpi-proxy listening on %s:%d\n",
		host != NULL ? host : "127.0.0.1", port);

	while (1)
	{
		client_fd = accept(server_fd, NULL, NULL);

		if (client_fd == SOCKET_INVALID)
		{
			if (socket_error_is_interrupted(socket_last_error()))
				continue ;
			perror("accept");
			break ;
		}

		client_arg = malloc(sizeof(*client_arg));

		if (client_arg == NULL)
		{
			socket_close(client_fd);
			continue ;
		}

		*client_arg = client_fd;

		if (pthread_create(&tid, NULL, client_thread, client_arg) != 0)
		{
			perror("pthread_create");
			socket_close(client_fd);
			free(client_arg);
			continue ;
		}

		pthread_detach(tid);
	}

	socket_close(server_fd);
	return (-1);
}
