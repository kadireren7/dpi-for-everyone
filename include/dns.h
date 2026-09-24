#ifndef DNS_H
# define DNS_H

# include <stddef.h>
# include <stdint.h>

/* ============================================================
 * Trusted resolver (Phase A): resolves hostnames the engine itself
 * connects to through a fixed list of public resolvers instead of the
 * system/router resolver, which on some networks answers blocked
 * names with a block-page address (observed: discord.com ->
 * 195.175.254.2, an ISP interception host).
 *
 * Plain DNS over UDP to the listed servers, not DoH: this project
 * links no TLS library, and a poisoned answer can never turn into a
 * false "success" anyway — every success criterion downstream
 * requires a certificate that verifies for the hostname (see
 * probe_classify_openssl_output / the transparent-mode ladder).
 *
 * Everything in dns.c is pure (no sockets): the network round trip is
 * a caller-supplied t_dns_transport, so tests drive it with canned
 * packets. src/dns/dns_udp.c provides the real UDP transport.
 * ============================================================ */

# define DNS_NAME_MAX 254
# define DNS_MAX_ADDRS 8
# define DNS_MAX_SERVERS 12
# define DNS_CACHE_SIZE 256
# define DNS_QTYPE_A 1
# define DNS_QTYPE_AAAA 28

/* Clamp answer TTLs: never cache longer than an hour (network changes)
 * and never shorter than 30s (a TTL-0 answer would otherwise force a
 * lookup on every single connection). */
# define DNS_TTL_MIN 30
# define DNS_TTL_MAX 3600
/* Cache "no such name / no records" answers briefly too. */
# define DNS_NEGATIVE_TTL 30

/* A server that failed this many times in a row is skipped (tried
 * last, not dropped) until DNS_SERVER_BACKOFF_SECONDS have passed. */
# define DNS_SERVER_FAIL_LIMIT 3
# define DNS_SERVER_BACKOFF_SECONDS 60

typedef struct s_dns_addr
{
	int		family;		/* 4 or 6 */
	uint8_t	addr[16];	/* network byte order; first 4 bytes for v4 */
}	t_dns_addr;

typedef struct s_dns_answer
{
	t_dns_addr	addrs[DNS_MAX_ADDRS];
	size_t		count;
	uint32_t	ttl;		/* smallest TTL among the used records */
}	t_dns_answer;

typedef enum e_dns_status
{
	DNS_OK = 0,
	DNS_NODATA,			/* valid reply, name exists, no records of qtype */
	DNS_NXDOMAIN,
	DNS_ERR_TIMEOUT,
	DNS_ERR_MALFORMED,	/* unparseable, or doesn't match our query */
	DNS_ERR_SERVFAIL,
	DNS_ERR_ALL_FAILED
}	t_dns_status;

const char		*dns_status_name(t_dns_status s);

/* Builds a standard recursive query (RD=1, one question) for `name`
 * and `qtype`. Returns its length, or 0 if `name` is invalid (empty,
 * a label > 63 bytes, total > 253) or `out` is too small. */
size_t			dns_build_query(uint16_t id, const char *name,
					uint16_t qtype, uint8_t *out, size_t out_size);

/* Parses a response to the query built with the same id/name/qtype.
 * Rejects (DNS_ERR_MALFORMED) anything that isn't a response to that
 * exact question — mismatched id, name, qtype, or a truncated
 * packet — so a stray/spoofed packet can't be mistaken for the
 * answer. Follows the answer section's records of `qtype`, whatever
 * the CNAME chain in front of them; keeps up to DNS_MAX_ADDRS. */
t_dns_status	dns_parse_response(const uint8_t *pkt, size_t len,
					uint16_t id, const char *name, uint16_t qtype,
					t_dns_answer *out);

/* One network round trip: send `query` to server `server_index`, wait
 * at most `timeout_ms` for a reply, write it to `reply`. Returns the
 * reply length, 0 on timeout, -1 on a local error. */
typedef long	(*t_dns_transport)(size_t server_index, const uint8_t *query,
					size_t query_len, uint8_t *reply, size_t reply_size,
					int timeout_ms, void *userdata);

typedef struct s_dns_server_health
{
	unsigned int	consecutive_failures;
	int64_t			skip_until;
	unsigned long	queries;
	unsigned long	failures;
}	t_dns_server_health;

typedef struct s_dns_cache_entry
{
	char			name[DNS_NAME_MAX];
	uint16_t		qtype;
	t_dns_status	status;		/* DNS_OK, DNS_NODATA or DNS_NXDOMAIN */
	t_dns_answer	answer;
	int64_t			expires_at;
	int64_t			last_used;
}	t_dns_cache_entry;

/* Optional locking for multithreaded callers: called with lock=1/0
 * around every access to the cache and health state, and never held
 * across a network round trip, so one slow lookup doesn't stall the
 * others. NULL (the default) means single-threaded use. */
typedef void	(*t_dns_lock_fn)(void *ctx, int lock);

typedef struct s_dns_resolver
{
	size_t				server_count;
	t_dns_lock_fn		lock;
	void				*lock_ctx;
	t_dns_server_health	health[DNS_MAX_SERVERS];
	t_dns_cache_entry	cache[DNS_CACHE_SIZE];
	t_dns_transport		transport;
	void				*transport_data;
	int					timeout_ms;
	uint16_t			next_id;
	unsigned long		cache_hits;
	unsigned long		cache_misses;
}	t_dns_resolver;

void			dns_resolver_init(t_dns_resolver *r, size_t server_count,
					t_dns_transport transport, void *transport_data,
					int timeout_ms, uint16_t id_seed);

/* Cache first (by name+qtype, until the clamped TTL expires), then the
 * servers in a deterministic order: healthy servers in list order,
 * then backed-off ones in list order. SERVFAIL/timeout/malformed move
 * on to the next server; NXDOMAIN/NODATA/OK are authoritative answers
 * and stop the walk. Returns DNS_ERR_ALL_FAILED if no server gave a
 * usable reply. Names are case-insensitive. */
t_dns_status	dns_resolve(t_dns_resolver *r, const char *name,
					uint16_t qtype, int64_t now, t_dns_answer *out);

/* Drops every cached answer (e.g. the network changed). */
void			dns_cache_flush(t_dns_resolver *r);

/* True if at least one server is not currently backed off. */
int				dns_resolver_healthy(const t_dns_resolver *r, int64_t now);

/* ---- raw forwarding (the transparent daemon's DNS forwarder) ---- */

/* Reads a query's single question: `name` (dotted, lowercase),
 * `qtype`, and the client's EDNS UDP payload size (512 without an OPT
 * record). Returns -1 if `pkt` isn't a standard one-question query. */
int				dns_query_info(const uint8_t *pkt, size_t len, char *name,
					size_t name_size, uint16_t *qtype, uint16_t *udp_size);

/* Sends the client's own query, unchanged, to the servers in the same
 * order as dns_resolve (with the same health bookkeeping) until one
 * returns a reply to exactly that question (same id and question;
 * SERVFAIL/REFUSED count as failures). No caching — the system's stub
 * resolver in front of us does that. Returns the reply length, or -1
 * if no server answered. */
long			dns_exchange(t_dns_resolver *r, const uint8_t *query,
					size_t qlen, uint8_t *reply, size_t reply_size,
					int64_t now);

/* Header-and-question replies to `query`: TC set (retry over TCP),
 * or SERVFAIL. Return the length, 0 if `query` is malformed. */
size_t			dns_truncated_reply(const uint8_t *query, size_t qlen,
					uint8_t *out, size_t out_size);
size_t			dns_servfail_reply(const uint8_t *query, size_t qlen,
					uint8_t *out, size_t out_size);

/* ---- real UDP transport (src/dns/dns_udp.c) ---- */

# define DNS_DEFAULT_SERVERS "1.1.1.1,1.0.0.1,8.8.8.8,8.8.4.4,9.9.9.9"

typedef struct s_dns_udp_servers
{
	/* struct sockaddr_storage, kept opaque here so this header stays
	 * free of socket includes for the pure code and its tests */
	uint64_t		addrs[DNS_MAX_SERVERS][16];
	unsigned int	addr_lens[DNS_MAX_SERVERS];
	size_t			count;
	int				so_mark;	/* 0 = don't set SO_MARK */
}	t_dns_udp_servers;

/* Parses a comma-separated list of IPv4/IPv6 literals (port 53).
 * Invalid entries are skipped. Returns the number of servers parsed. */
size_t			dns_udp_servers_parse(t_dns_udp_servers *s, const char *list,
					int so_mark);

/* Called on every socket the UDP and DoH transports open, before
 * connect (transparent mode: tpp_prepare_socket, so the daemon's own
 * DNS traffic is never intercepted). Without a hook, a non-zero
 * so_mark is applied as SO_MARK (Linux). Returns 0, or -1 to abandon
 * the socket. */
typedef int		(*t_dns_socket_hook)(int fd, int family);
void			dns_set_socket_hook(t_dns_socket_hook hook);
int				dns_prepare_socket(int fd, int family, int so_mark);

/* t_dns_transport over a connected UDP socket per query; userdata is
 * a t_dns_udp_servers. */
long			dns_udp_transport(size_t server_index, const uint8_t *query,
					size_t query_len, uint8_t *reply, size_t reply_size,
					int timeout_ms, void *userdata);

#endif
