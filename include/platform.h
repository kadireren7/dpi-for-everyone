#ifndef PLATFORM_H
# define PLATFORM_H

# ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>

typedef SOCKET	socket_t;

#  define SOCKET_INVALID INVALID_SOCKET
# else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <unistd.h>

typedef int	socket_t;

#  define SOCKET_INVALID (-1)
# endif

# ifndef MSG_NOSIGNAL
#  define MSG_NOSIGNAL 0
# endif

int		platform_init(void);
void	platform_cleanup(void);
int		socket_close(socket_t fd);
int		socket_last_error(void);
int		socket_error_is_interrupted(int err);

#endif
