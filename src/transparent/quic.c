#define _GNU_SOURCE
#include "tpd.h"
#include "tp_platform.h"

#include <pthread.h>
#include <string.h>

/* The QUIC-reject set (tp.h: quic_block4/quic_block6), fed from two
 * places: the DNS forwarder, for every address a known-blocked name
 * resolves to (before the application even sees the answer), and
 * conn.c, for any destination a bypass step just carried. Each nft
 * update forks `nft`, so a small in-memory table remembers what is
 * already in the set; an entry is refreshed in nft once it is past
 * half the set's element timeout. */

#define QUIC_SEEN_MAX 512

typedef struct s_quic_seen
{
	int		family;
	uint8_t	addr[16];
	int64_t	added_at;
}	t_quic_seen;

static t_quic_seen		g_seen[QUIC_SEEN_MAX];
static size_t			g_seen_count;
static pthread_mutex_t	g_seen_lock = PTHREAD_MUTEX_INITIALIZER;

/* 1 if the caller should (re)add the address to nft. */
static int	note(int family, const uint8_t *addr, int64_t now)
{
	size_t	len;
	size_t	i;
	size_t	oldest;

	len = (family == 6) ? 16 : 4;
	oldest = 0;
	i = 0;
	while (i < g_seen_count)
	{
		if (g_seen[i].family == family
			&& memcmp(g_seen[i].addr, addr, len) == 0)
		{
			if (now - g_seen[i].added_at < TP_QUIC_BLOCK_TIMEOUT_S / 2)
				return (0);
			g_seen[i].added_at = now;
			return (1);
		}
		if (g_seen[i].added_at < g_seen[oldest].added_at)
			oldest = i;
		i++;
	}
	if (g_seen_count < QUIC_SEEN_MAX)
		i = g_seen_count++;
	else
		i = oldest;
	memset(&g_seen[i], 0, sizeof(g_seen[i]));
	g_seen[i].family = family;
	memcpy(g_seen[i].addr, addr, len);
	g_seen[i].added_at = now;
	return (1);
}

/* The new addresses of `ans`, handed to the platform layer at once
 * (Linux: one `nft` run). */
void	tpd_quic_block_answer(const t_dns_answer *ans)
{
	t_dns_addr	fresh[DNS_MAX_ADDRS];
	size_t		n;
	size_t		i;
	int			add;

	n = 0;
	i = 0;
	while (i < ans->count && i < DNS_MAX_ADDRS)
	{
		pthread_mutex_lock(&g_seen_lock);
		add = note(ans->addrs[i].family, ans->addrs[i].addr, tpd_now());
		pthread_mutex_unlock(&g_seen_lock);
		if (add)
			fresh[n++] = ans->addrs[i];
		i++;
	}
	if (n == 0)
		return ;
	tpp_quic_block(fresh, n);
	tpd_debug("[quic] %zu address(es): UDP/443 rejected (falls back to TCP)",
		n);
}

void	tpd_quic_block(int family, const uint8_t *addr)
{
	t_dns_answer	one;

	memset(&one, 0, sizeof(one));
	one.count = 1;
	one.addrs[0].family = family;
	memcpy(one.addrs[0].addr, addr, family == 6 ? 16 : 4);
	tpd_quic_block_answer(&one);
}

void	tpd_quic_block_sockaddr(const struct sockaddr_storage *ss)
{
	if (ss->ss_family == AF_INET6)
		tpd_quic_block(6, (const uint8_t *)
			&((const struct sockaddr_in6 *)ss)->sin6_addr);
	else if (ss->ss_family == AF_INET)
		tpd_quic_block(4, (const uint8_t *)
			&((const struct sockaddr_in *)ss)->sin_addr);
}

void	tpd_quic_forget(void)
{
	pthread_mutex_lock(&g_seen_lock);
	g_seen_count = 0;
	pthread_mutex_unlock(&g_seen_lock);
}
