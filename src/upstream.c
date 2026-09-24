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
