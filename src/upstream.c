#include "upstream.h"

#include <stdio.h>
#include <string.h>

socket_t	connect_upstream(const char *host, int port)
{
	struct addrinfo	hints;
	struct addrinfo	*result;
	struct addrinfo	*current;
	char			port_str[16];
	socket_t		fd;
	int				status;

	snprintf(port_str, sizeof(port_str), "%d", port);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	status = getaddrinfo(host, port_str, &hints, &result);
	if (status != 0)
	{
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
		return (SOCKET_INVALID);
	}

	fd = SOCKET_INVALID;
	current = result;
	while (current != NULL)
	{
		fd = socket(current->ai_family,
				current->ai_socktype,
				current->ai_protocol);
		if (fd != SOCKET_INVALID)
		{
			if (connect(fd, current->ai_addr,
					current->ai_addrlen) == 0)
			{
				int	one = 1;

				/* Nagle would happily coalesce a deliberately
				 * split first write back into one TCP segment,
				 * defeating the point of the split. */
				setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
					(const char *)&one, sizeof(one));
				break ;
			}
			socket_close(fd);
			fd = SOCKET_INVALID;
		}
		current = current->ai_next;
	}

	freeaddrinfo(result);
	return (fd);
}

#ifdef __linux__
# include <errno.h>
# include <fcntl.h>
# include <poll.h>

socket_t	connect_upstream_addr(const struct sockaddr *addr,
	socklen_t addr_len, int timeout_ms, int mark)
{
	socket_t		fd;
	int				flags;
	int				one;
	int				err;
	socklen_t		err_len;
	struct pollfd	pfd;

	fd = socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd == SOCKET_INVALID)
		return (SOCKET_INVALID);
	if (mark != 0 && setsockopt(fd, SOL_SOCKET, SO_MARK, &mark,
			sizeof(mark)) < 0)
	{
		/* an unmarked socket would be redirected straight back to us */
		close(fd);
		return (SOCKET_INVALID);
	}
	one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
	flags = fcntl(fd, F_GETFL, 0);
	fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (connect(fd, addr, addr_len) < 0 && errno != EINPROGRESS)
	{
		close(fd);
		return (SOCKET_INVALID);
	}
	pfd.fd = fd;
	pfd.events = POLLOUT;
	pfd.revents = 0;
	while (poll(&pfd, 1, timeout_ms) < 0 && errno == EINTR)
		;
	err = 0;
	err_len = sizeof(err);
	if (!(pfd.revents & POLLOUT)
		|| getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0
		|| err != 0)
	{
		close(fd);
		return (SOCKET_INVALID);
	}
	fcntl(fd, F_SETFL, flags);
	return (fd);
}
#endif
