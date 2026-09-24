#define _GNU_SOURCE
#include "compat.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#ifdef _WIN32
# include <windows.h>

int	compat_poll(t_pollfd *fds, size_t n, int timeout_ms)
{
	return (WSAPoll(fds, (ULONG)n, timeout_ms));
}

ssize_t	compat_recv(int fd, void *buf, size_t len)
{
	return (recv((SOCKET)fd, (char *)buf, (int)len, 0));
}

ssize_t	compat_send(int fd, const void *buf, size_t len)
{
	return (send((SOCKET)fd, (const char *)buf, (int)len, 0));
}

int	compat_close(int fd)
{
	return (closesocket((SOCKET)fd));
}

int	compat_set_nonblocking(int fd, int on)
{
	u_long	mode;

	mode = on ? 1 : 0;
	return (ioctlsocket((SOCKET)fd, FIONBIO, &mode) == 0 ? 0 : -1);
}

int	compat_connect_pending(void)
{
	int	e;

	e = WSAGetLastError();
	return (e == WSAEWOULDBLOCK || e == WSAEINPROGRESS);
}

int	compat_interrupted(void)
{
	return (WSAGetLastError() == WSAEINTR);
}

int	compat_addr_in_use(void)
{
	return (WSAGetLastError() == WSAEADDRINUSE);
}

int	compat_so_error(int fd)
{
	int	err;
	int	len;

	err = 0;
	len = sizeof(err);
	if (getsockopt((SOCKET)fd, SOL_SOCKET, SO_ERROR, (char *)&err, &len) != 0)
		return (-1);
	return (err);
}

int	compat_setsockopt_int(int fd, int level, int name, int value)
{
	return (setsockopt((SOCKET)fd, level, name, (const char *)&value,
			sizeof(value)));
}

void	compat_sleep_ms(int ms)
{
	Sleep((DWORD)ms);
}

int64_t	compat_now_ms(void)
{
	return ((int64_t)GetTickCount64());
}

int	compat_rename_replace(const char *tmp, const char *path)
{
	return (MoveFileExA(tmp, path, MOVEFILE_REPLACE_EXISTING) ? 0 : -1);
}

const char	*compat_sock_strerror(void)
{
	static __thread char	buf[160];
	int						err;
	DWORD					n;

	err = WSAGetLastError();
	n = FormatMessageA(FORMAT_MESSAGE_FROM_SYSTEM
			| FORMAT_MESSAGE_IGNORE_INSERTS, NULL, (DWORD)err, 0, buf,
			sizeof(buf), NULL);
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r'
			|| buf[n - 1] == '.'))
		buf[--n] = '\0';
	if (n == 0)
		snprintf(buf, sizeof(buf), "socket error %d", err);
	return (buf);
}

#else
# include <fcntl.h>
# include <unistd.h>

int	compat_poll(t_pollfd *fds, size_t n, int timeout_ms)
{
	return (poll(fds, (nfds_t)n, timeout_ms));
}

ssize_t	compat_recv(int fd, void *buf, size_t len)
{
	return (recv(fd, buf, len, 0));
}

ssize_t	compat_send(int fd, const void *buf, size_t len)
{
	return (send(fd, buf, len, MSG_NOSIGNAL));
}

int	compat_close(int fd)
{
	return (close(fd));
}

int	compat_set_nonblocking(int fd, int on)
{
	int	flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return (-1);
	flags = on ? (flags | O_NONBLOCK) : (flags & ~O_NONBLOCK);
	return (fcntl(fd, F_SETFL, flags));
}

int	compat_connect_pending(void)
{
	return (errno == EINPROGRESS);
}

int	compat_interrupted(void)
{
	return (errno == EINTR);
}

int	compat_addr_in_use(void)
{
	return (errno == EADDRINUSE || errno == EADDRNOTAVAIL);
}

int	compat_so_error(int fd)
{
	int			err;
	socklen_t	len;

	err = 0;
	len = sizeof(err);
	if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0)
		return (-1);
	return (err);
}

int	compat_setsockopt_int(int fd, int level, int name, int value)
{
	return (setsockopt(fd, level, name, &value, sizeof(value)));
}

void	compat_sleep_ms(int ms)
{
	struct timespec	ts;

	ts.tv_sec = ms / 1000;
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) < 0 && errno == EINTR)
		;
}

int64_t	compat_now_ms(void)
{
	struct timespec	ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ((int64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000);
}

int	compat_rename_replace(const char *tmp, const char *path)
{
	return (rename(tmp, path));
}

const char	*compat_sock_strerror(void)
{
	return (strerror(errno));
}

#endif

int	compat_wait(int fd, short events, int timeout_ms)
{
	t_pollfd	pfd;
	int			rc;

	pfd.fd = fd;
	pfd.events = events;
	pfd.revents = 0;
	do
		rc = compat_poll(&pfd, 1, timeout_ms);
	while (rc < 0 && compat_interrupted());
	return (rc);
}
