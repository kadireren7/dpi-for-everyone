#ifndef TP_PLATFORM_H
# define TP_PLATFORM_H

# include "dns.h"
# include "platform.h"
# include <stddef.h>
# include <stdint.h>

/* ============================================================
 * Transparent mode's platform layer: everything that decides *how*
 * traffic reaches the daemon and how its own traffic is kept out of
 * the interception. The rest of transparent mode (conn.c, dnsfwd.c,
 * policy.c, verify.c, the DoH resolver) is shared by all platforms.
 *
 *   Linux    platform_linux.c    nftables REDIRECT + SO_ORIGINAL_DST,
 *                                own sockets excluded by SO_MARK
 *   Windows  platform_windows.c  WinDivert reflection, original
 *                                destination = the accepted peer, own
 *                                sockets excluded by a reserved local
 *                                port range
 *   macOS    platform_macos.c    PF anchor (route-to lo0 + rdr), the
 *                                original destination from PF's state
 *                                table (DIOCNATLOOK), own sockets
 *                                excluded by a reserved local port
 *                                range, a watchdog process for
 *                                fail-open
 * ============================================================ */

/* One-time setup (Winsock on Windows). */
int			tpp_init(void);

/* Start intercepting TCP/443 to `port` and (dns_port > 0) UDP+TCP/53
 * to `dns_port`; ipv6: the IPv6 listeners are up. Idempotent. */
int			tpp_install(int port, int ipv6, int dns_port);
/* Heartbeat, every TP_HEARTBEAT_S: keeps interception alive (Linux:
 * re-arms the fail-open timer; reinstalls if it vanished). */
int			tpp_refresh(void);
/* Stops intercepting; nothing of ours remains. Idempotent. */
void		tpp_remove(void);

/* QUIC (UDP/443) to these addresses is refused from now on, so the
 * applications fall back to TCP. */
void		tpp_quic_block(const t_dns_addr *addrs, size_t n);
/* The network changed: forget every QUIC block. */
void		tpp_quic_flush(void);

/* Listeners bind to loopback (0) or to the wildcard address (1:
 * Windows, where redirected packets arrive addressed to the host's
 * own interface address). */
int			tpp_listen_wildcard(void);
/* For an accepted TCP connection: where the application was really
 * going. -1 = this connection was not redirected by us (refuse it). */
int			tpp_original_dst(int client_fd, int family,
				struct sockaddr_storage *out, socklen_t *out_len);
/* For a DNS query that reached the forwarder from `peer`: was it
 * redirected by us? (Windows: the listener is reachable from the LAN;
 * only redirected queries are answered.) */
int			tpp_dns_peer_ok(const struct sockaddr *peer, socklen_t len,
				int tcp);
/* The DNS server a redirected query was really sent to (usually the
 * router). `fd`: the forwarder's UDP socket, or the accepted TCP
 * connection; `peer`: the querying application. -1 when the platform
 * can't tell (Linux, Windows): the forwarder then uses only the
 * trusted resolvers, as before. */
int			tpp_dns_original(int fd, const struct sockaddr *peer,
				socklen_t peer_len, int tcp, struct sockaddr_storage *out,
				socklen_t *out_len);
/* Called on every socket the daemon itself opens (upstream, DoH,
 * plain DNS), before connect/sendto, so it is never intercepted. */
int			tpp_prepare_socket(int fd, int family);

/* Network change notification: a descriptor to poll (readable =
 * something may have changed; then call tpp_netwatch_drain, which
 * returns 1 if what arrived can change the network profile), or -1
 * when the platform only supports the periodic check. */
int			tpp_netwatch_fd(void);
int			tpp_netwatch_drain(void);
/* Current network fingerprint (netfingerprint.h semantics). */
uint64_t	tpp_network_fingerprint(void);

/* Another transparent interceptor that would fight with us is active
 * (Linux: the dpi-bypass nftables table). Text for the warning, or
 * NULL. */
const char	*tpp_conflict(void);
/* "nftables", "WinDivert", "PF" — for logs and status. */
const char	*tpp_name(void);
/* Extra "key: value" lines for the status file describing the
 * interception's live state (macOS: PF enabled, anchor loaded,
 * watchdog); writes "" when there is nothing to add. */
void		tpp_status_extra(char *out, size_t out_size);

#endif
