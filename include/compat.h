#ifndef COMPAT_H
# define COMPAT_H

/* ============================================================
 * The few POSIX calls transparent mode and the DNS code use that
 * differ on Windows (Winsock). On Linux/macOS every function here is
 * the exact call it wraps. Sockets are kept in `int` variables on all
 * platforms (Winsock SOCKET values fit; this is the usual practice).
 * ============================================================ */

# include "platform.h"
# include <stddef.h>
# include <stdint.h>
# include <sys/types.h>

# ifdef _WIN32
#  include <winsock2.h>
typedef WSAPOLLFD	t_pollfd;
#  ifndef SOCK_CLOEXEC
#   define SOCK_CLOEXEC 0
#  endif
# else
#  include <poll.h>
typedef struct pollfd	t_pollfd;
# endif

int		compat_poll(t_pollfd *fds, size_t n, int timeout_ms);
/* poll() on one socket; >0 ready, 0 timeout, <0 error */
int		compat_wait(int fd, short events, int timeout_ms);
ssize_t	compat_recv(int fd, void *buf, size_t len);
ssize_t	compat_send(int fd, const void *buf, size_t len);
int		compat_close(int fd);
int		compat_set_nonblocking(int fd, int on);
/* After a non-blocking connect() returned -1: still in progress? */
int		compat_connect_pending(void);
/* The last socket call failed only because it was interrupted. */
int		compat_interrupted(void);
int		compat_so_error(int fd);
int		compat_setsockopt_int(int fd, int level, int name, int value);
void	compat_sleep_ms(int ms);
int64_t	compat_now_ms(void);	/* monotonic */
/* Text for the last failed socket call (errno, or WSAGetLastError). */
const char	*compat_sock_strerror(void);
/* Atomically replaces `path` with `tmp` (rename over an existing file). */
int		compat_rename_replace(const char *tmp, const char *path);

#endif
