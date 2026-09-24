#include "platform.h"

#ifdef _WIN32

int	platform_init(void)
{
	WSADATA	wsa;

	return (WSAStartup(MAKEWORD(2, 2), &wsa) == 0 ? 0 : -1);
}

void	platform_cleanup(void)
{
	WSACleanup();
}

int	socket_close(socket_t fd)
{
	return (closesocket(fd));
}

int	socket_last_error(void)
{
	return (WSAGetLastError());
}

int	socket_error_is_interrupted(int err)
{
	(void)err;
	return (0);
}

#else

# include <errno.h>

int	platform_init(void)
{
	return (0);
}

void	platform_cleanup(void)
{
}

int	socket_close(socket_t fd)
{
	return (close(fd));
}

int	socket_last_error(void)
{
	return (errno);
}

int	socket_error_is_interrupted(int err)
{
	return (err == EINTR);
}

#endif
