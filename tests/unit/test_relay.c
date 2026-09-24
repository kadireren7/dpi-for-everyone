#define _GNU_SOURCE
#include "relay.h"

#include <assert.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/* The stream core shared by SOCKS and transparent mode, exercised over
 * socketpairs: "client" side cl[0] (app) <-> cl[1] (relay), "upstream"
 * side up[1] (relay) <-> up[0] (server). */

typedef struct s_pump_arg
{
	int				client;
	int				upstream;
	int				timeout_ms;
	int				rc;
	t_relay_stats	stats;
}	t_pump_arg;

static void	*pump_thread(void *p)
{
	t_pump_arg	*a;

	a = p;
	a->rc = relay_pump_timeout(a->client, a->upstream, &a->stats,
			a->timeout_ms);
	return (NULL);
}

static size_t	build_client_hello(unsigned char *buf, const char *host)
{
	size_t	pos;
	size_t	n;

	n = strlen(host);
	pos = 0;
	buf[pos++] = 0x16;
	buf[pos++] = 0x03;
	buf[pos++] = 0x01;
	pos += 2;
	buf[pos++] = 0x01;
	pos += 3;
	buf[pos++] = 0x03;
	buf[pos++] = 0x03;
	memset(buf + pos, 0xAB, 32);
	pos += 32;
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = 0x02;
	buf[pos++] = 0x13;
	buf[pos++] = 0x01;
	buf[pos++] = 0x01;
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)(4 + 5 + n);
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)(5 + n);
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)(3 + n);
	buf[pos++] = 0x00;
	buf[pos++] = 0x00;
	buf[pos++] = (unsigned char)n;
	memcpy(buf + pos, host, n);
	pos += n;
	buf[3] = (unsigned char)((pos - 5) >> 8);
	buf[4] = (unsigned char)(pos - 5);
	buf[6] = 0;
	buf[7] = (unsigned char)((pos - 9) >> 8);
	buf[8] = (unsigned char)(pos - 9);
	return (pos);
}

static size_t	read_all(int fd, unsigned char *buf, size_t size)
{
	size_t	total;
	ssize_t	n;

	total = 0;
	while (total < size)
	{
		n = recv(fd, buf + total, size - total, 0);
		if (n <= 0)
			break ;
		total += (size_t)n;
	}
	return (total);
}

static void	test_send_first_modes(void)
{
	int				sp[2];
	unsigned char	ch[512];
	unsigned char	got[1024];
	size_t			len;
	size_t			n;
	size_t			rec1;

	len = build_client_hello(ch, "discord.com");
	/* NONE: byte-identical */
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	assert(relay_send_first(sp[0], ch, len, RELAY_SPLIT_NONE) == 0);
	shutdown(sp[0], SHUT_WR);
	n = read_all(sp[1], got, sizeof(got));
	assert(n == len && memcmp(got, ch, len) == 0);
	close(sp[0]);
	close(sp[1]);
	/* TLS_RECORD: two records, same handshake bytes, SNI not whole in
	 * the first */
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	assert(relay_send_first(sp[0], ch, len, RELAY_SPLIT_TLS_RECORD) == 0);
	shutdown(sp[0], SHUT_WR);
	n = read_all(sp[1], got, sizeof(got));
	assert(n == len + 5);
	assert(got[0] == 0x16 && got[1] == 0x03);
	rec1 = ((size_t)got[3] << 8) | got[4];
	assert(rec1 >= 1 && rec1 < len - 5);
	assert(got[5 + rec1] == 0x16);
	assert((((size_t)got[5 + rec1 + 3] << 8) | got[5 + rec1 + 4])
		== len - 5 - rec1);
	assert(memcmp(got + 5, ch + 5, rec1) == 0);
	assert(memcmp(got + 10 + rec1, ch + 5 + rec1, len - 5 - rec1) == 0);
	assert(memmem(got, 5 + rec1, "discord.com", 11) == NULL);
	close(sp[0]);
	close(sp[1]);
	/* TLS_RECORD_TCP: the same re-framed bytes (only the TCP cut
	 * differs, which a socketpair can't show) */
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	assert(relay_send_first(sp[0], ch, len, RELAY_SPLIT_TLS_RECORD_TCP) == 0);
	shutdown(sp[0], SHUT_WR);
	{
		unsigned char	got2[1024];

		assert(read_all(sp[1], got2, sizeof(got2)) == n
			&& memcmp(got2, got, n) == 0);
	}
	close(sp[0]);
	close(sp[1]);
	assert(relay_split_for(STRATEGY_TLSREC) == RELAY_SPLIT_TLS_RECORD);
	assert(relay_split_for(STRATEGY_TLSREC_SPLIT)
		== RELAY_SPLIT_TLS_RECORD_TCP);
	assert(relay_split_for(STRATEGY_PASS) == RELAY_SPLIT_NONE);
	/* not a ClientHello: sent unchanged whatever the mode */
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
	assert(relay_send_first(sp[0], (const unsigned char *)"GET / HTTP/1.1",
			14, RELAY_SPLIT_TLS_RECORD) == 0);
	shutdown(sp[0], SHUT_WR);
	n = read_all(sp[1], got, sizeof(got));
	assert(n == 14 && memcmp(got, "GET / HTTP/1.1", 14) == 0);
	close(sp[0]);
	close(sp[1]);
}

/* Both directions flow; a client half-close is propagated while the
 * server can still answer; stats count bytes and who finished first. */
static void	test_pump_half_close(void)
{
	int			cl[2];
	int			up[2];
	pthread_t	tid;
	t_pump_arg	a;
	char		buf[64];
	size_t		n;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, up) == 0);
	memset(&a, 0, sizeof(a));
	a.client = cl[1];
	a.upstream = up[1];
	a.timeout_ms = 5000;
	assert(pthread_create(&tid, NULL, pump_thread, &a) == 0);
	assert(send(cl[0], "hello", 5, 0) == 5);
	assert(read_all(up[0], (unsigned char *)buf, 5) == 5);
	assert(memcmp(buf, "hello", 5) == 0);
	shutdown(cl[0], SHUT_WR);
	/* upstream sees EOF... */
	assert(recv(up[0], buf, sizeof(buf), 0) == 0);
	/* ...and can still send its answer back */
	assert(send(up[0], "world!", 6, 0) == 6);
	close(up[0]);
	n = read_all(cl[0], (unsigned char *)buf, sizeof(buf));
	assert(n == 6 && memcmp(buf, "world!", 6) == 0);
	pthread_join(tid, NULL);
	assert(a.rc == 0);
	assert(a.stats.up_bytes == 5);
	assert(a.stats.down_bytes == 6);
	assert(a.stats.client_eof_first == 1);
	assert(a.stats.upstream_reset == 0);
	close(cl[0]);
	close(cl[1]);
	close(up[1]);
}

static void	test_pump_idle_timeout(void)
{
	int			cl[2];
	int			up[2];
	t_pump_arg	a;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, cl) == 0);
	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, up) == 0);
	memset(&a, 0, sizeof(a));
	a.client = cl[1];
	a.upstream = up[1];
	a.timeout_ms = 50;
	pump_thread(&a);
	assert(a.rc == -1);
	close(cl[0]);
	close(cl[1]);
	close(up[0]);
	close(up[1]);
}

int	main(void)
{
	signal(SIGPIPE, SIG_IGN);
	test_send_first_modes();
	test_pump_half_close();
	test_pump_idle_timeout();
	printf("test_relay: OK\n");
	return (0);
}
