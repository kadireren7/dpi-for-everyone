#ifndef TPD_H
# define TPD_H

/* Internal to src/transparent/: state shared by the connection
 * handler (conn.c), the verifier (verify.c) and the main loop
 * (transparent.c). */

# include "dns.h"
# include "dns_doh.h"
# include "strategy.h"
# include "tp.h"
# include "tp_sys.h"

# include <netinet/in.h>
# include <pthread.h>
# include <stdint.h>
# include <sys/socket.h>

typedef struct s_tpd_stats
{
	unsigned long	flows_total;
	unsigned long	flows_active;
	unsigned long	passthrough;	/* no hostname / cooldown / manual pass */
	unsigned long	direct;			/* ladder: original address DIRECT */
	unsigned long	bypassed;		/* any non-direct step */
	unsigned long	failed;			/* every attempt failed */
	unsigned long	verified_ok;
	unsigned long	verified_bad;
	unsigned long	dns_queries;	/* through the local forwarder */
	unsigned long	dns_failures;	/* answered with SERVFAIL */
}	t_tpd_stats;

typedef struct s_tpd
{
	t_tp_options		opt;
	pthread_mutex_t		lock;		/* guards everything below */
	t_strategy_config	cfg;
	t_tp_decisions		dec;
	uint64_t			fp;
	/* last bypass step strategy that carried a connection on this
	 * network (reset on network change): listed hosts try it first */
	t_strategy			preferred;
	t_tpd_stats			stats;
	int64_t				started_at;
	int					ipv6;		/* [::1] listener is up */
	char				last_learned[STRATEGY_DOMAIN_MAX + 64];
	/* the resolver has its own locking (dns lock hooks) */
	t_dns_resolver		*dns;
	t_dns_udp_servers	dns_servers;
	t_dns_doh			*doh;		/* NULL: plain UDP only */
	int					dns_intercept;	/* forwarder up, DNS redirected */
	int					conflict;	/* another interceptor's table seen */
	pthread_mutex_t		dns_lock;
}	t_tpd;

extern t_tpd	g_tpd;

void	tpd_log(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
void	tpd_debug(const char *fmt, ...)
		__attribute__((format(printf, 1, 2)));
int64_t	tpd_now(void);
int64_t	tpd_now_ms(void);	/* monotonic */

/* dnsfwd.c: starts the UDP+TCP forwarder on 127.0.0.1:port and, if
 * *ipv6, [::1]:port (clears *ipv6 if that one fails). -1 if the IPv4
 * side can't start. */
int		tpd_dnsfwd_start(int port, int *ipv6);

/* conn.c: handles one accepted, redirected connection, then closes it. */
void	tpd_handle_connection(int client_fd, int family);

/* Puts an address into the QUIC-reject set (UDP/443 rejected, so the
 * application falls back to TCP, which we can bypass). Deduplicated
 * in memory: repeated calls for the same address cost nothing. */
void	tpd_quic_block(int family, const uint8_t *addr);
void	tpd_quic_block_answer(const t_dns_answer *ans);
void	tpd_quic_block_sockaddr(const struct sockaddr_storage *ss);
/* Network changed: the nft sets were flushed; forget the dedup too. */
void	tpd_quic_forget(void);

/* Printable form of an IPv4/IPv6 sockaddr (address only). */
void	tpd_addr_str(const struct sockaddr_storage *ss, char *out,
			size_t out_size);

/* verify.c ---- */

typedef enum e_tpd_verify_kind
{
	/* a connection DIRECT to the original address ended suspiciously:
	 * does that address present a valid certificate for the host? */
	TPD_VERIFY_DIRECT = 0,
	/* a non-direct step carried a connection: confirm it with an
	 * ordinary verified handshake before caching it */
	TPD_VERIFY_CONFIRM
}	t_tpd_verify_kind;

typedef struct s_tpd_verify_job
{
	t_tpd_verify_kind		kind;
	char					host[STRATEGY_DOMAIN_MAX];
	int						family;
	uint64_t				fp;
	t_tp_step				step;
	struct sockaddr_storage	addr;		/* where the step connects */
	socklen_t				addr_len;
	struct sockaddr_storage	original;	/* the application's address */
}	t_tpd_verify_job;

int		tpd_verify_start(void);
/* Queues a job unless the same (kind, host, family, step) ran
 * recently; never blocks. */
void	tpd_verify_submit(const t_tpd_verify_job *job);

#endif
