#define _GNU_SOURCE
#include "dns.h"
#include "dns_doh.h"
#include "compat.h"
#include "relay.h"
#include "tlsclient.h"

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ============================================================
 * DNS-over-HTTPS transport (RFC 8484, POST, HTTP/1.1 keep-alive).
 *
 * The servers are dialled by IP literal, so resolving them needs no
 * DNS. TLS goes through tlsclient.c, so the first flight (the
 * ClientHello, SNI e.g. "cloudflare-dns.com") goes out re-framed with
 * TLSREC, just like the connections we proxy — a DPI that matches DoH
 * SNIs sees no more than it does for them. The certificate is
 * verified against the system trust store and the provider's
 * hostname.
 *
 * Connections are pooled per server and reused; one that fails is
 * closed and the query retried once on a fresh connection.
 * ============================================================ */

#define DOH_POOL 4
#define DOH_IDLE_MAX_S 50
#define DOH_HTTP_MAX 4096

typedef struct s_doh_conn
{
	t_tlsc	*tls;
	int64_t	last_used;
}	t_doh_conn;

typedef struct s_doh_server
{
	struct sockaddr_storage	addr;
	socklen_t				addr_len;
	char					host[128];
	char					label[256];
	t_doh_conn				*idle[DOH_POOL];
	size_t					nidle;
}	t_doh_server;

struct s_dns_doh
{
	t_doh_server		srv[DNS_MAX_SERVERS];
	size_t				count;
	int					so_mark;
	int					split;
	void				*ctx;
	pthread_mutex_t		lock;
	t_dns_udp_servers	*fallback;
};

static int64_t	now_ms(void)
{
	return (compat_now_ms());
}

/* ---- setup ---- */

static int	parse_server(t_doh_server *s, const char *item)
{
	char				ip[64];
	const char			*slash;
	size_t				n;
	struct sockaddr_in	*v4;
	struct sockaddr_in6	*v6;

	slash = strchr(item, '/');
	if (slash == NULL || slash == item || slash[1] == '\0')
		return (-1);
	n = (size_t)(slash - item);
	if (n >= sizeof(ip) || strlen(slash + 1) >= sizeof(s->host))
		return (-1);
	memcpy(ip, item, n);
	ip[n] = '\0';
	memset(s, 0, sizeof(*s));
	snprintf(s->host, sizeof(s->host), "%s", slash + 1);
	snprintf(s->label, sizeof(s->label), "%s@%s", s->host, ip);
	v4 = (struct sockaddr_in *)&s->addr;
	v6 = (struct sockaddr_in6 *)&s->addr;
	if (inet_pton(AF_INET, ip, &v4->sin_addr) == 1)
	{
		v4->sin_family = AF_INET;
		v4->sin_port = htons(443);
		s->addr_len = sizeof(*v4);
		return (0);
	}
	if (inet_pton(AF_INET6, ip, &v6->sin6_addr) == 1)
	{
		v6->sin6_family = AF_INET6;
		v6->sin6_port = htons(443);
		s->addr_len = sizeof(*v6);
		return (0);
	}
	return (-1);
}

t_dns_doh	*dns_doh_new(const char *list, int so_mark,
	t_dns_udp_servers *fallback)
{
	t_dns_doh	*d;
	char		item[256];
	size_t		n;

	d = calloc(1, sizeof(*d));
	if (d == NULL)
		return (NULL);
	d->so_mark = so_mark;
	d->split = RELAY_SPLIT_TLS_RECORD;
	d->fallback = fallback;
	pthread_mutex_init(&d->lock, NULL);
	while (*list != '\0' && d->count < DNS_MAX_SERVERS)
	{
		while (*list == ' ' || *list == ',')
			list++;
		n = 0;
		while (*list != '\0' && *list != ',' && *list != ' '
			&& n < sizeof(item) - 1)
			item[n++] = *list++;
		item[n] = '\0';
		while (*list != '\0' && *list != ',')
			list++;
		if (n > 0 && parse_server(&d->srv[d->count], item) == 0)
			d->count++;
	}
	d->ctx = tlsc_ctx_new("http/1.1");
	if (d->count == 0 || d->ctx == NULL)
	{
		dns_doh_free(d);
		return (NULL);
	}
	return (d);
}

size_t	dns_doh_count(const t_dns_doh *d)
{
	return (d->count);
}

size_t	dns_doh_total(const t_dns_doh *d)
{
	return (d->count + (d->fallback ? d->fallback->count : 0));
}

const char	*dns_doh_label(const t_dns_doh *d, size_t i)
{
	if (i < d->count)
		return (d->srv[i].label);
	return ("udp");
}

static void	conn_free(t_doh_conn *c)
{
	if (c == NULL)
		return ;
	tlsc_free(c->tls);
	free(c);
}

void	dns_doh_free(t_dns_doh *d)
{
	size_t	i;

	if (d == NULL)
		return ;
	i = 0;
	while (i < d->count)
	{
		while (d->srv[i].nidle > 0)
			conn_free(d->srv[i].idle[--d->srv[i].nidle]);
		i++;
	}
	tlsc_ctx_free(d->ctx);
	pthread_mutex_destroy(&d->lock);
	free(d);
}

void	dns_doh_drop_idle(t_dns_doh *d)
{
	t_doh_conn	*drop[DNS_MAX_SERVERS * DOH_POOL];
	size_t		n;
	size_t		i;

	n = 0;
	pthread_mutex_lock(&d->lock);
	i = 0;
	while (i < d->count)
	{
		while (d->srv[i].nidle > 0)
			drop[n++] = d->srv[i].idle[--d->srv[i].nidle];
		i++;
	}
	pthread_mutex_unlock(&d->lock);
	while (n > 0)
		conn_free(drop[--n]);
}

/* ---- connections ---- */

static int	connect_fd(const t_dns_doh *d, const t_doh_server *s,
	int64_t deadline)
{
	int		fd;
	int		busy;
	int64_t	left;

	fd = (int)socket(s->addr.ss_family, SOCK_STREAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return (-1);
	if (dns_prepare_socket(fd, s->addr.ss_family, d->so_mark) != 0)
	{
		compat_close(fd);
		return (-1);
	}
	compat_setsockopt_int(fd, IPPROTO_TCP, TCP_NODELAY, 1);
	compat_set_nonblocking(fd, 1);
	if (connect(fd, (const struct sockaddr *)&s->addr, s->addr_len) < 0
		&& !compat_connect_pending())
	{
		busy = compat_addr_in_use();
		compat_close(fd);
		return (busy ? -2 : -1);
	}
	left = deadline - now_ms();
	if (left <= 0 || compat_wait(fd, POLLOUT, (int)left) <= 0
		|| compat_so_error(fd) != 0)
	{
		compat_close(fd);
		return (-1);
	}
	/* blocking from here on; every read is behind a poll deadline */
	compat_set_nonblocking(fd, 0);
	return (fd);
}

static t_doh_conn	*conn_open(t_dns_doh *d, t_doh_server *s, int64_t deadline)
{
	t_doh_conn		*c;
	int				fd;
	int				tries;
	t_tlsc_result	r;

	/* -2: local port in use (Windows: our port range): new socket */
	tries = 0;
	do
		fd = connect_fd(d, s, deadline);
	while (fd == -2 && ++tries < 8);
	if (fd < 0)
		return (NULL);
	c = calloc(1, sizeof(*c));
	if (c == NULL)
	{
		compat_close(fd);
		return (NULL);
	}
	c->tls = tlsc_handshake(d->ctx, fd, s->host, d->split, deadline, 1, &r);
	if (c->tls == NULL)
	{
		free(c);
		return (NULL);
	}
	return (c);
}

/* ---- HTTP ---- */

static long	header_value(const char *head, const char *name)
{
	const char	*p;
	size_t		n;

	n = strlen(name);
	p = head;
	while ((p = strchr(p, '\n')) != NULL)
	{
		p++;
		if (strncasecmp(p, name, n) == 0 && p[n] == ':')
			return (strtol(p + n + 1, NULL, 10));
	}
	return (-1);
}

/* One request/response on `c`. Returns the body length, 0 if the
 * server answered but not with a usable DNS message, -1 if the
 * connection is broken (caller retries on a fresh one). */
static long	doh_request(t_doh_conn *c, const t_doh_server *s,
	const uint8_t *query, size_t qlen, uint8_t *reply, size_t reply_size,
	int64_t deadline)
{
	char	head[DOH_HTTP_MAX + 1];
	size_t	have;
	char	*end;
	long	status;
	long	body_len;
	size_t	body_have;
	int		n;

	n = snprintf(head, sizeof(head),
			"POST /dns-query HTTP/1.1\r\nHost: %s\r\n"
			"Content-Type: application/dns-message\r\n"
			"Accept: application/dns-message\r\n"
			"Content-Length: %zu\r\n\r\n", s->host, qlen);
	if (n <= 0 || (size_t)n >= sizeof(head)
		|| tlsc_write(c->tls, head, (size_t)n, deadline) != 0
		|| tlsc_write(c->tls, query, qlen, deadline) != 0)
		return (-1);
	have = 0;
	end = NULL;
	while (end == NULL)
	{
		if (have >= DOH_HTTP_MAX)
			return (-1);
		n = tlsc_read(c->tls, head + have, DOH_HTTP_MAX - have, deadline);
		if (n <= 0)
			return (-1);
		have += (size_t)n;
		head[have] = '\0';
		end = strstr(head, "\r\n\r\n");
	}
	*end = '\0';
	status = (strncmp(head, "HTTP/1.", 7) == 0) ? strtol(head + 9, NULL, 10)
		: 0;
	body_len = header_value(head, "Content-Length");
	if (body_len < 0 || (size_t)body_len > reply_size)
		return (-1);
	body_have = have - (size_t)(end + 4 - head);
	if (body_have > (size_t)body_len)
		return (-1);
	memcpy(reply, end + 4, body_have);
	while (body_have < (size_t)body_len)
	{
		n = tlsc_read(c->tls, reply + body_have, (size_t)body_len - body_have,
				deadline);
		if (n <= 0)
			return (-1);
		body_have += (size_t)n;
	}
	if (status != 200 || body_len < 12)
		return (0);
	return (body_len);
}

static t_doh_conn	*pool_get(t_dns_doh *d, t_doh_server *s)
{
	t_doh_conn	*c;
	int64_t		now;

	now = now_ms();
	c = NULL;
	pthread_mutex_lock(&d->lock);
	while (c == NULL && s->nidle > 0)
	{
		c = s->idle[--s->nidle];
		if (now - c->last_used > DOH_IDLE_MAX_S * 1000)
		{
			pthread_mutex_unlock(&d->lock);
			conn_free(c);
			c = NULL;
			pthread_mutex_lock(&d->lock);
		}
	}
	pthread_mutex_unlock(&d->lock);
	return (c);
}

static void	pool_put(t_dns_doh *d, t_doh_server *s, t_doh_conn *c)
{
	c->last_used = now_ms();
	pthread_mutex_lock(&d->lock);
	if (s->nidle < DOH_POOL)
	{
		s->idle[s->nidle++] = c;
		c = NULL;
	}
	pthread_mutex_unlock(&d->lock);
	conn_free(c);
}

static long	doh_query(t_dns_doh *d, t_doh_server *s, const uint8_t *query,
	size_t qlen, uint8_t *reply, size_t reply_size, int timeout_ms)
{
	t_doh_conn	*c;
	int64_t		deadline;
	long		n;
	int			fresh;

	deadline = now_ms() + timeout_ms;
	c = pool_get(d, s);
	fresh = (c == NULL);
	while (1)
	{
		if (c == NULL)
			c = conn_open(d, s, deadline);
		if (c == NULL)
			return (0);
		n = doh_request(c, s, query, qlen, reply, reply_size, deadline);
		if (n >= 0)
		{
			pool_put(d, s, c);
			return (n > 0 ? n : -1);
		}
		conn_free(c);
		c = NULL;
		/* a pooled connection the server had already closed: once more
		 * on a new one */
		if (fresh || now_ms() >= deadline)
			return (0);
		fresh = 1;
	}
}

long	dns_doh_transport(size_t server_index, const uint8_t *query,
	size_t query_len, uint8_t *reply, size_t reply_size, int timeout_ms,
	void *userdata)
{
	t_dns_doh	*d;

	d = userdata;
	if (server_index < d->count)
		return (doh_query(d, &d->srv[server_index], query, query_len, reply,
				reply_size, timeout_ms));
	if (d->fallback == NULL)
		return (-1);
	return (dns_udp_transport(server_index - d->count, query, query_len,
			reply, reply_size, timeout_ms, d->fallback));
}
