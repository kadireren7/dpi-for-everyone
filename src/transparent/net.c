#define _GNU_SOURCE
#include "tpd.h"
#include "compat.h"
#include "tp_platform.h"

#include <string.h>

int	tpd_connect(const struct sockaddr *addr, socklen_t addr_len,
	int timeout_ms)
{
	int	fd;

	fd = (int)socket(addr->sa_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);
	/* an unprepared socket would be intercepted straight back to us */
	if (tpp_prepare_socket(fd, addr->sa_family) != 0)
	{
		compat_close(fd);
		return (-1);
	}
	compat_setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1);
	compat_set_nonblocking(fd, 1);
	if (connect(fd, addr, addr_len) < 0 && !compat_connect_pending())
	{
		compat_close(fd);
		return (-1);
	}
	if (compat_wait(fd, POLLOUT, timeout_ms) <= 0 || compat_so_error(fd) != 0)
	{
		compat_close(fd);
		return (-1);
	}
	compat_set_nonblocking(fd, 0);
	return (fd);
}
