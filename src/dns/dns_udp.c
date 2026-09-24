#include "dns.h"
#include "compat.h"

#include <string.h>

#ifndef SO_MARK
# define SO_MARK 36
#endif

static t_dns_socket_hook	g_hook;

void	dns_set_socket_hook(t_dns_socket_hook hook)
{
	g_hook = hook;
}

int	dns_prepare_socket(int fd, int family, int so_mark)
{
	if (g_hook != NULL)
		return (g_hook(fd, family));
#ifdef __linux__
	if (so_mark != 0)
		setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark));
#else
	(void)so_mark;
#endif
	return (0);
}

static int	parse_one(const char *text, struct sockaddr_storage *ss,
	unsigned int *len)
{
	struct sockaddr_in	*v4;
	struct sockaddr_in6	*v6;

	memset(ss, 0, sizeof(*ss));
	v4 = (struct sockaddr_in *)ss;
	if (inet_pton(AF_INET, text, &v4->sin_addr) == 1)
	{
		v4->sin_family = AF_INET;
		v4->sin_port = htons(53);
		*len = sizeof(*v4);
		return (0);
	}
	v6 = (struct sockaddr_in6 *)ss;
	if (inet_pton(AF_INET6, text, &v6->sin6_addr) == 1)
	{
		v6->sin6_family = AF_INET6;
		v6->sin6_port = htons(53);
		*len = sizeof(*v6);
		return (0);
	}
	return (-1);
}

size_t	dns_udp_servers_parse(t_dns_udp_servers *s, const char *list,
	int so_mark)
{
	char	item[64];
	size_t	n;

	memset(s, 0, sizeof(*s));
	s->so_mark = so_mark;
	while (*list != '\0' && s->count < DNS_MAX_SERVERS)
	{
		n = 0;
		while (*list == ' ' || *list == ',')
			list++;
		while (*list != '\0' && *list != ',' && *list != ' '
			&& n < sizeof(item) - 1)
			item[n++] = *list++;
		item[n] = '\0';
		while (*list != '\0' && *list != ',')
			list++;
		if (n > 0 && parse_one(item,
				(struct sockaddr_storage *)s->addrs[s->count],
				&s->addr_lens[s->count]) == 0)
			s->count++;
	}
	return (s->count);
}

long	dns_udp_transport(size_t server_index, const uint8_t *query,
	size_t query_len, uint8_t *reply, size_t reply_size, int timeout_ms,
	void *userdata)
{
	t_dns_udp_servers		*s;
	struct sockaddr_storage	*ss;
	ssize_t					n;
	int						fd;

	s = userdata;
	if (server_index >= s->count)
		return (-1);
	ss = (struct sockaddr_storage *)s->addrs[server_index];
	fd = (int)socket(ss->ss_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);
	/* connect(): the kernel then drops datagrams from any other
	 * source, so only the queried server can answer. */
	if (dns_prepare_socket(fd, ss->ss_family, s->so_mark) != 0
		|| connect(fd, (struct sockaddr *)ss, s->addr_lens[server_index]) < 0
		|| compat_send(fd, query, query_len) != (ssize_t)query_len)
	{
		compat_close(fd);
		return (-1);
	}
	n = 0;
	if (compat_wait(fd, POLLIN, timeout_ms) == 1)
		n = compat_recv(fd, reply, reply_size);
	compat_close(fd);
	if (n < 0)
		return (-1);
	return ((long)n);
}
