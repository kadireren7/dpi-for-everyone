#ifndef DNS_DOH_H
# define DNS_DOH_H

# include "dns.h"
# include <stddef.h>

/* ============================================================
 * DNS-over-HTTPS transport for t_dns_resolver (src/dns/dns_doh.c,
 * Linux, links OpenSSL). Server indexes 0..dns_doh_count()-1 are the
 * DoH servers; the indexes after them are the plain-UDP `fallback`
 * servers, so the resolver's in-order walk tries every DoH server
 * before any unencrypted one.
 * ============================================================ */

/* "IP/hostname" pairs: dialled by IP, certificate checked against
 * the hostname (also the SNI and Host header). HTTP/1.1 only, so no
 * Quad9: its DoH endpoint answers HTTP/1.1 with 505 (it requires
 * HTTP/2); it stays in the plain-DNS fallback list. */
# define DNS_DOH_DEFAULT_SERVERS \
	"1.1.1.1/cloudflare-dns.com,1.0.0.1/cloudflare-dns.com," \
	"8.8.8.8/dns.google,8.8.4.4/dns.google"

typedef struct s_dns_doh	t_dns_doh;

/* NULL if no entry parses or the TLS context can't be set up.
 * `fallback` (may be NULL) must outlive the transport. */
t_dns_doh	*dns_doh_new(const char *list, int so_mark,
				t_dns_udp_servers *fallback);
void		dns_doh_free(t_dns_doh *d);
size_t		dns_doh_count(const t_dns_doh *d);
/* DoH servers + fallback servers: the resolver's server_count. */
size_t		dns_doh_total(const t_dns_doh *d);
const char	*dns_doh_label(const t_dns_doh *d, size_t i);
/* Closes pooled connections (e.g. the network changed). */
void		dns_doh_drop_idle(t_dns_doh *d);

long		dns_doh_transport(size_t server_index, const uint8_t *query,
				size_t query_len, uint8_t *reply, size_t reply_size,
				int timeout_ms, void *userdata);

#endif
