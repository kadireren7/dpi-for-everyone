#define _WIN32_WINNT 0x0A00
#include "tp_platform.h"
#include "compat.h"
#include "netfingerprint.h"
#include "tp.h"

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>
#include <tlhelp32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "windivert.h"

/* ============================================================
 * Windows: WinDivert "reflection" (the technique of WinDivert's own
 * streamdump sample). An outbound packet of a new TCP/443 flow
 *     A:p -> D:443          (application to remote server)
 * is rewritten to
 *     D:p -> A:1091         and reinjected as INBOUND
 * so it reaches our listener (bound to the wildcard address) as if
 * the remote host had connected to us: the accepted peer (D, p) *is*
 * the original destination. Our listener's packets back
 *     A:1091 -> D:p   become   D:443 -> A:p   (inbound, to the app).
 * UDP/TCP 53 is reflected the same way to the DNS forwarder's port.
 *
 * - Only flows whose SYN (or, for UDP, first datagram) we saw are
 *   reflected; connections that existed before we started are left
 *   alone. The flow table is also what lets the listeners refuse
 *   anything that was not reflected by us (they listen on the
 *   wildcard address, so the LAN could otherwise reach them).
 * - The daemon's own sockets bind to local ports OWN_PORT_LO..HI,
 *   which the filter excludes: that is our SO_MARK.
 * - Fail-open: diversion belongs to our WinDivert handle. When the
 *   process exits or dies, the driver stops diverting at once.
 * - QUIC: only long-header (handshake) UDP/443 packets are captured
 *   at all (filter: first payload byte >= 0xC0); those to blocked
 *   addresses are dropped, so ordinary QUIC data never leaves the
 *   kernel.
 * ============================================================ */

#define OWN_PORT_LO 45000
#define OWN_PORT_HI 45999
#define WORKERS 4
#define FLOW_BUCKETS 4096
#define FLOW_TCP_IDLE_MS (2 * 3600 * 1000)
#define FLOW_TCP_CLOSING_MS (30 * 1000)
#define FLOW_UDP_IDLE_MS (60 * 1000)
#define QUIC_MAX 1024
#define PKT_MAX 0xFFFF

typedef struct s_flow
{
	struct s_flow	*next;
	int				proto;		/* IPPROTO_TCP / IPPROTO_UDP */
	int				family;		/* 4 / 6 */
	uint8_t			local[16];	/* A: the application's address */
	uint16_t		lport;		/* p: the application's port (net order) */
	uint8_t			remote[16];	/* D: where it was going */
	uint16_t		oport;		/* its original destination port (host) */
	int				closing;
	int64_t			last;
}	t_flow;

typedef struct s_quic
{
	int		family;
	uint8_t	addr[16];
	int64_t	until;
}	t_quic;

static HANDLE			g_div = INVALID_HANDLE_VALUE;
static HANDLE			g_threads[WORKERS];
static volatile LONG	g_running;
static int				g_port;
static int				g_dns_port;
static int				g_ipv6;
static t_flow			*g_flows[FLOW_BUCKETS];
static SRWLOCK			g_flow_lock = SRWLOCK_INIT;
static t_quic			g_quic[QUIC_MAX];
static size_t			g_nquic;
static SRWLOCK			g_quic_lock = SRWLOCK_INIT;
static volatile LONG	g_own_next;
static int				g_notify_rx = -1;
static int				g_notify_tx = -1;
static HANDLE			g_route_notify;

/* ---- flow table ---- */

static size_t	alen(int family)
{
	return (family == 6 ? 16 : 4);
}

/* keyed on what both directions and accept() know: proto, remote,
 * application port, original port — local address compared after */
static size_t	bucket(int proto, int family, const uint8_t *remote,
	uint16_t lport, uint16_t oport)
{
	uint32_t	h;
	size_t		i;

	h = 2166136261u ^ (uint32_t)proto ^ ((uint32_t)oport << 8);
	i = 0;
	while (i < alen(family))
		h = (h ^ remote[i++]) * 16777619u;
	h = (h ^ lport) * 16777619u;
	return (h % FLOW_BUCKETS);
}

static t_flow	*find(int proto, int family, const uint8_t *local,
	uint16_t lport, const uint8_t *remote, uint16_t oport)
{
	t_flow	*f;

	f = g_flows[bucket(proto, family, remote, lport, oport)];
	while (f != NULL)
	{
		if (f->proto == proto && f->family == family && f->lport == lport
			&& f->oport == oport
			&& memcmp(f->remote, remote, alen(family)) == 0
			&& (local == NULL || memcmp(f->local, local, alen(family)) == 0))
			return (f);
		f = f->next;
	}
	return (NULL);
}

static void	add_flow(int proto, int family, const uint8_t *local,
	uint16_t lport, const uint8_t *remote, uint16_t oport, int64_t now)
{
	t_flow	*f;
	size_t	b;

	f = find(proto, family, local, lport, remote, oport);
	if (f == NULL)
	{
		f = calloc(1, sizeof(*f));
		if (f == NULL)
			return ;
		b = bucket(proto, family, remote, lport, oport);
		f->next = g_flows[b];
		g_flows[b] = f;
	}
	f->proto = proto;
	f->family = family;
	memcpy(f->local, local, alen(family));
	f->lport = lport;
	memcpy(f->remote, remote, alen(family));
	f->oport = oport;
	f->closing = 0;
	f->last = now;
}

static void	sweep_flows(int64_t now)
{
	size_t	b;
	t_flow	**pp;
	t_flow	*f;
	int64_t	limit;

	AcquireSRWLockExclusive(&g_flow_lock);
	b = 0;
	while (b < FLOW_BUCKETS)
	{
		pp = &g_flows[b];
		while ((f = *pp) != NULL)
		{
			limit = f->proto == IPPROTO_UDP ? FLOW_UDP_IDLE_MS
				: (f->closing ? FLOW_TCP_CLOSING_MS : FLOW_TCP_IDLE_MS);
			if (now - f->last > limit)
			{
				*pp = f->next;
				free(f);
			}
			else
				pp = &f->next;
		}
		b++;
	}
	ReleaseSRWLockExclusive(&g_flow_lock);
}

static void	free_flows(void)
{
	size_t	b;
	t_flow	*f;

	AcquireSRWLockExclusive(&g_flow_lock);
	b = 0;
	while (b < FLOW_BUCKETS)
	{
		while ((f = g_flows[b]) != NULL)
		{
			g_flows[b] = f->next;
			free(f);
		}
		b++;
	}
	ReleaseSRWLockExclusive(&g_flow_lock);
}

/* ---- address classes ---- */

static int	private_v4(const uint8_t *a)
{
	return (a[0] == 0 || a[0] == 10 || a[0] == 127 || a[0] >= 224
		|| (a[0] == 100 && (a[1] & 0xC0) == 64)
		|| (a[0] == 169 && a[1] == 254)
		|| (a[0] == 172 && (a[1] & 0xF0) == 16)
		|| (a[0] == 192 && a[1] == 168));
}

static int	private_v6(const uint8_t *a)
{
	static const uint8_t	loop[16] = {0, 0, 0, 0, 0, 0, 0, 0,
		0, 0, 0, 0, 0, 0, 0, 1};

	return ((a[0] & 0xFE) == 0xFC || (a[0] == 0xFE && (a[1] & 0xC0) == 0x80)
		|| a[0] == 0xFF || memcmp(a, loop, 16) == 0);
}

static int	quic_blocked(int family, const uint8_t *addr, int64_t now)
{
	size_t	i;
	int		hit;

	hit = 0;
	AcquireSRWLockShared(&g_quic_lock);
	i = 0;
	while (!hit && i < g_nquic)
	{
		hit = (g_quic[i].family == family && g_quic[i].until > now
				&& memcmp(g_quic[i].addr, addr, alen(family)) == 0);
		i++;
	}
	ReleaseSRWLockShared(&g_quic_lock);
	return (hit);
}

/* ---- the packet path ---- */

typedef struct s_pkt
{
	int					family;
	uint8_t				*src;
	uint8_t				*dst;
	PWINDIVERT_TCPHDR	tcp;
	PWINDIVERT_UDPHDR	udp;
	uint8_t				*payload;
	UINT				payload_len;
}	t_pkt;

static int	parse(uint8_t *packet, UINT len, t_pkt *p)
{
	PWINDIVERT_IPHDR	ip;
	PWINDIVERT_IPV6HDR	ip6;
	PVOID				data;

	memset(p, 0, sizeof(*p));
	data = NULL;
	if (!WinDivertHelperParsePacket(packet, len, &ip, &ip6, NULL, NULL, NULL,
			&p->tcp, &p->udp, &data, &p->payload_len, NULL, NULL))
		return (-1);
	p->payload = data;
	if (ip != NULL)
	{
		p->family = 4;
		p->src = (uint8_t *)&ip->SrcAddr;
		p->dst = (uint8_t *)&ip->DstAddr;
	}
	else if (ip6 != NULL)
	{
		p->family = 6;
		p->src = (uint8_t *)ip6->SrcAddr;
		p->dst = (uint8_t *)ip6->DstAddr;
	}
	else
		return (-1);
	return ((p->tcp != NULL || p->udp != NULL) ? 0 : -1);
}

static void	swap_addrs(t_pkt *p)
{
	uint8_t	tmp[16];
	size_t	n;

	n = alen(p->family);
	memcpy(tmp, p->src, n);
	memcpy(p->src, p->dst, n);
	memcpy(p->dst, tmp, n);
}

static int	own_port(uint16_t port_net)
{
	int	port;

	port = ntohs(port_net);
	return (port >= OWN_PORT_LO && port <= OWN_PORT_HI);
}

/* Returns 1 to send the (possibly rewritten) packet, 0 to drop it. */
static int	handle(t_pkt *p, WINDIVERT_ADDRESS *addr, int64_t now)
{
	uint16_t	sport;
	uint16_t	dport;
	int			proto;
	int			svc;
	t_flow		*f;

	proto = p->tcp != NULL ? IPPROTO_TCP : IPPROTO_UDP;
	sport = p->tcp != NULL ? p->tcp->SrcPort : p->udp->SrcPort;
	dport = p->tcp != NULL ? p->tcp->DstPort : p->udp->DstPort;
	/* 1) our listener answering a reflected flow: back to the app */
	svc = 0;
	if (ntohs(sport) == g_port && proto == IPPROTO_TCP)
		svc = 443;
	else if (g_dns_port > 0 && ntohs(sport) == g_dns_port)
		svc = 53;
	if (svc != 0)
	{
		AcquireSRWLockExclusive(&g_flow_lock);
		f = find(proto, p->family, p->src, dport, p->dst, (uint16_t)svc);
		if (f != NULL)
		{
			f->last = now;
			if (p->tcp != NULL && (p->tcp->Fin || p->tcp->Rst))
				f->closing = 1;
		}
		ReleaseSRWLockExclusive(&g_flow_lock);
		if (f == NULL)
			return (1);
		swap_addrs(p);
		if (p->tcp != NULL)
			p->tcp->SrcPort = htons((uint16_t)svc);
		else
			p->udp->SrcPort = htons((uint16_t)svc);
		addr->Outbound = 0;
		return (1);
	}
	/* 2) QUIC handshake to a blocked address: refused */
	if (p->udp != NULL && ntohs(dport) == 443)
		return (!(p->payload_len > 0 && p->payload[0] >= 0xC0
				&& quic_blocked(p->family, p->dst, now)));
	/* 3) the application's traffic to 443 / 53 */
	if (own_port(sport))
		return (1);
	svc = ntohs(dport);
	if (svc == 443 && proto == IPPROTO_TCP)
	{
		if ((p->family == 4 && private_v4(p->dst))
			|| (p->family == 6 && private_v6(p->dst))
			|| (p->family == 6 && !g_ipv6))
			return (1);
	}
	else if (!(svc == 53 && g_dns_port > 0) || (p->family == 6 && !g_ipv6))
		return (1);
	AcquireSRWLockExclusive(&g_flow_lock);
	f = find(proto, p->family, p->src, sport, p->dst, (uint16_t)svc);
	if (f == NULL && (proto == IPPROTO_UDP
			|| (p->tcp->Syn && !p->tcp->Ack)))
	{
		add_flow(proto, p->family, p->src, sport, p->dst, (uint16_t)svc, now);
		f = find(proto, p->family, p->src, sport, p->dst, (uint16_t)svc);
	}
	if (f != NULL)
	{
		f->last = now;
		if (p->tcp != NULL && (p->tcp->Fin || p->tcp->Rst))
			f->closing = 1;
	}
	ReleaseSRWLockExclusive(&g_flow_lock);
	/* a connection that existed before we started: not ours */
	if (f == NULL)
		return (1);
	swap_addrs(p);
	if (p->tcp != NULL)
		p->tcp->DstPort = htons((uint16_t)(svc == 443 ? g_port : g_dns_port));
	else
		p->udp->DstPort = htons((uint16_t)g_dns_port);
	addr->Outbound = 0;
	return (1);
}

static DWORD WINAPI	worker(LPVOID arg)
{
	uint8_t				*packet;
	UINT				len;
	WINDIVERT_ADDRESS	addr;
	t_pkt				p;

	(void)arg;
	packet = malloc(PKT_MAX);
	if (packet == NULL)
		return (1);
	while (g_running)
	{
		if (!WinDivertRecv(g_div, packet, PKT_MAX, &len, &addr))
		{
			if (GetLastError() == ERROR_NO_DATA
				|| GetLastError() == ERROR_INVALID_HANDLE
				|| GetLastError() == ERROR_OPERATION_ABORTED)
				break ;
			continue ;
		}
		if (parse(packet, len, &p) == 0 && !handle(&p, &addr,
				compat_now_ms()))
			continue ;
		WinDivertHelperCalcChecksums(packet, len, &addr, 0);
		WinDivertSend(g_div, packet, len, NULL, &addr);
	}
	free(packet);
	return (0);
}

/* ---- interface ---- */

static void	notify_setup(void)
{
	struct sockaddr_in	a;
	int					len;

	g_notify_rx = (int)socket(AF_INET, SOCK_DGRAM, 0);
	g_notify_tx = (int)socket(AF_INET, SOCK_DGRAM, 0);
	memset(&a, 0, sizeof(a));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	len = sizeof(a);
	if (g_notify_rx < 0 || g_notify_tx < 0
		|| bind((SOCKET)g_notify_rx, (struct sockaddr *)&a, sizeof(a)) != 0
		|| getsockname((SOCKET)g_notify_rx, (struct sockaddr *)&a, &len) != 0
		|| connect((SOCKET)g_notify_tx, (struct sockaddr *)&a, sizeof(a)) != 0)
	{
		if (g_notify_rx >= 0)
			compat_close(g_notify_rx);
		if (g_notify_tx >= 0)
			compat_close(g_notify_tx);
		g_notify_rx = -1;
		g_notify_tx = -1;
		return ;
	}
	compat_set_nonblocking(g_notify_rx, 1);
}

static VOID WINAPI	on_route_change(PVOID ctx,
	PMIB_IPFORWARD_ROW2 row, MIB_NOTIFICATION_TYPE type)
{
	(void)ctx;
	(void)row;
	(void)type;
	if (g_notify_tx >= 0)
		send((SOCKET)g_notify_tx, "n", 1, 0);
}

int	tpp_init(void)
{
	/* a restarted service must not reuse the local ports (and so the
	 * 4-tuples, possibly still in TIME_WAIT) its predecessor just used */
	g_own_next = (LONG)((GetTickCount64() ^ ((uint64_t)GetCurrentProcessId()
					* 2654435761u)) % (OWN_PORT_HI - OWN_PORT_LO + 1));
	notify_setup();
	if (g_notify_tx >= 0)
		NotifyRouteChange2(AF_UNSPEC, on_route_change, NULL, FALSE,
			&g_route_notify);
	return (0);
}

static void	stop_workers(void)
{
	size_t	i;

	InterlockedExchange(&g_running, 0);
	if (g_div != INVALID_HANDLE_VALUE)
		WinDivertShutdown(g_div, WINDIVERT_SHUTDOWN_BOTH);
	i = 0;
	while (i < WORKERS)
	{
		if (g_threads[i] != NULL)
		{
			WaitForSingleObject(g_threads[i], 5000);
			CloseHandle(g_threads[i]);
			g_threads[i] = NULL;
		}
		i++;
	}
	if (g_div != INVALID_HANDLE_VALUE)
		WinDivertClose(g_div);
	g_div = INVALID_HANDLE_VALUE;
}

int	tpp_install(int port, int ipv6, int dns_port)
{
	char	filter[1024];
	size_t	i;

	tpp_remove();
	g_port = port;
	g_ipv6 = ipv6;
	g_dns_port = dns_port;
	/* outbound, not loopback, not our own injected packets; and then
	 * only what handle() may act on */
	if (dns_port > 0)
		snprintf(filter, sizeof(filter),
			"outbound and !loopback and !impostor and ("
			"(tcp and (tcp.DstPort == 443 or tcp.SrcPort == %d"
			" or tcp.DstPort == 53 or tcp.SrcPort == %d))"
			" or (udp and ((udp.DstPort == 443 and udp.Payload[0] >= 192)"
			" or udp.DstPort == 53 or udp.SrcPort == %d)))",
			port, dns_port, dns_port);
	else
		snprintf(filter, sizeof(filter),
			"outbound and !loopback and !impostor and ("
			"(tcp and (tcp.DstPort == 443 or tcp.SrcPort == %d))"
			" or (udp and udp.DstPort == 443 and udp.Payload[0] >= 192))",
			port);
	g_div = WinDivertOpen(filter, WINDIVERT_LAYER_NETWORK, 0, 0);
	if (g_div == INVALID_HANDLE_VALUE)
		return (-1);
	WinDivertSetParam(g_div, WINDIVERT_PARAM_QUEUE_LENGTH, 8192);
	WinDivertSetParam(g_div, WINDIVERT_PARAM_QUEUE_TIME, 2000);
	InterlockedExchange(&g_running, 1);
	i = 0;
	while (i < WORKERS)
	{
		g_threads[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
		i++;
	}
	return (g_threads[0] != NULL ? 0 : -1);
}

int	tpp_refresh(void)
{
	DWORD	code;

	sweep_flows(compat_now_ms());
	if (g_div != INVALID_HANDLE_VALUE && g_threads[0] != NULL
		&& GetExitCodeThread(g_threads[0], &code) && code == STILL_ACTIVE)
		return (0);
	if (tpp_install(g_port, g_ipv6, g_dns_port) == 0)
		return (1);
	return (-1);
}

void	tpp_remove(void)
{
	stop_workers();
	free_flows();
}

void	tpp_quic_block(const t_dns_addr *addrs, size_t n)
{
	size_t	i;
	size_t	j;
	size_t	k;
	int64_t	now;

	now = compat_now_ms();
	AcquireSRWLockExclusive(&g_quic_lock);
	i = 0;
	while (i < n)
	{
		j = 0;
		while (j < g_nquic && !(g_quic[j].family == addrs[i].family
				&& memcmp(g_quic[j].addr, addrs[i].addr,
					alen(addrs[i].family)) == 0))
			j++;
		if (j == g_nquic && g_nquic < QUIC_MAX)
			g_nquic++;
		else if (j == g_nquic)
		{
			/* full: reuse the entry that expires first */
			j = 0;
			k = 1;
			while (k < QUIC_MAX)
			{
				if (g_quic[k].until < g_quic[j].until)
					j = k;
				k++;
			}
		}
		memset(&g_quic[j], 0, sizeof(g_quic[j]));
		g_quic[j].family = addrs[i].family;
		memcpy(g_quic[j].addr, addrs[i].addr, alen(addrs[i].family));
		g_quic[j].until = now + (int64_t)TP_QUIC_BLOCK_TIMEOUT_S * 1000;
		i++;
	}
	ReleaseSRWLockExclusive(&g_quic_lock);
}

void	tpp_quic_flush(void)
{
	AcquireSRWLockExclusive(&g_quic_lock);
	g_nquic = 0;
	ReleaseSRWLockExclusive(&g_quic_lock);
}

int	tpp_listen_wildcard(void)
{
	return (1);
}

static void	sock_addr(const struct sockaddr_storage *ss, int *family,
	const uint8_t **addr, uint16_t *port)
{
	if (ss->ss_family == AF_INET6)
	{
		*family = 6;
		*addr = (const uint8_t *)&((const struct sockaddr_in6 *)ss)->sin6_addr;
		*port = ((const struct sockaddr_in6 *)ss)->sin6_port;
	}
	else
	{
		*family = 4;
		*addr = (const uint8_t *)&((const struct sockaddr_in *)ss)->sin_addr;
		*port = ((const struct sockaddr_in *)ss)->sin_port;
	}
}

int	tpp_original_dst(int client_fd, int family, struct sockaddr_storage *out,
	socklen_t *out_len)
{
	struct sockaddr_storage	peer;
	struct sockaddr_storage	self;
	int						len;
	int						fam;
	const uint8_t			*remote;
	const uint8_t			*local;
	uint16_t				port;
	uint16_t				lport;
	t_flow					*f;

	(void)family;
	len = sizeof(peer);
	if (getpeername((SOCKET)client_fd, (struct sockaddr *)&peer, &len) != 0)
		return (-1);
	len = sizeof(self);
	if (getsockname((SOCKET)client_fd, (struct sockaddr *)&self, &len) != 0)
		return (-1);
	sock_addr(&peer, &fam, &remote, &port);
	sock_addr(&self, &fam, &local, &lport);
	AcquireSRWLockShared(&g_flow_lock);
	f = find(IPPROTO_TCP, fam, local, port, remote, 443);
	ReleaseSRWLockShared(&g_flow_lock);
	/* not reflected by us (e.g. someone on the LAN connecting to the
	 * listener directly): refuse */
	if (f == NULL)
		return (-1);
	memset(out, 0, sizeof(*out));
	if (fam == 6)
	{
		((struct sockaddr_in6 *)out)->sin6_family = AF_INET6;
		memcpy(&((struct sockaddr_in6 *)out)->sin6_addr, remote, 16);
		((struct sockaddr_in6 *)out)->sin6_port = htons(443);
		*out_len = sizeof(struct sockaddr_in6);
	}
	else
	{
		((struct sockaddr_in *)out)->sin_family = AF_INET;
		memcpy(&((struct sockaddr_in *)out)->sin_addr, remote, 4);
		((struct sockaddr_in *)out)->sin_port = htons(443);
		*out_len = sizeof(struct sockaddr_in);
	}
	return (0);
}

int	tpp_dns_peer_ok(const struct sockaddr *peer, socklen_t len, int tcp)
{
	int				fam;
	const uint8_t	*remote;
	uint16_t		port;
	t_flow			*f;

	(void)len;
	sock_addr((const struct sockaddr_storage *)peer, &fam, &remote, &port);
	AcquireSRWLockShared(&g_flow_lock);
	f = find(tcp ? IPPROTO_TCP : IPPROTO_UDP, fam, NULL, port, remote, 53);
	ReleaseSRWLockShared(&g_flow_lock);
	return (f != NULL);
}

/* Our own sockets come from OWN_PORT_LO..HI, which the filter lets
 * pass untouched. */
int	tpp_prepare_socket(int fd, int family)
{
	struct sockaddr_storage	ss;
	int						tries;
	int						port;
	int						len;

	tries = 0;
	while (tries++ < 64)
	{
		port = OWN_PORT_LO + (int)((unsigned long)InterlockedIncrement(
					&g_own_next) % (OWN_PORT_HI - OWN_PORT_LO + 1));
		memset(&ss, 0, sizeof(ss));
		if (family == AF_INET6)
		{
			((struct sockaddr_in6 *)&ss)->sin6_family = AF_INET6;
			((struct sockaddr_in6 *)&ss)->sin6_port = htons((uint16_t)port);
			len = sizeof(struct sockaddr_in6);
		}
		else
		{
			((struct sockaddr_in *)&ss)->sin_family = AF_INET;
			((struct sockaddr_in *)&ss)->sin_port = htons((uint16_t)port);
			len = sizeof(struct sockaddr_in);
		}
		if (bind((SOCKET)fd, (struct sockaddr *)&ss, len) == 0)
			return (0);
	}
	return (-1);
}

int	tpp_netwatch_fd(void)
{
	return (g_notify_rx);
}

void	tpp_netwatch_drain(void)
{
	char	buf[64];

	if (g_notify_rx < 0)
		return ;
	while (recv((SOCKET)g_notify_rx, buf, sizeof(buf), 0) > 0)
		;
}

/* The default route's interface and gateway (and the gateway's MAC,
 * which tells apart two networks that both use 192.168.1.1). */
uint64_t	tpp_network_fingerprint(void)
{
	MIB_IPFORWARD_ROW2		route;
	SOCKADDR_INET			dest;
	SOCKADDR_INET			src;
	MIB_IPNET_ROW2			neigh;
	uint64_t				h;
	const uint8_t			*p;
	size_t					i;

	memset(&dest, 0, sizeof(dest));
	dest.Ipv4.sin_family = AF_INET;
	dest.Ipv4.sin_addr.s_addr = htonl(0x01010101);
	if (GetBestRoute2(NULL, 0, NULL, &dest, 0, &route, &src) != NO_ERROR)
		return (NETFP_UNKNOWN);
	h = 1469598103934665603ULL;
	p = (const uint8_t *)&route.InterfaceLuid;
	i = 0;
	while (i < sizeof(route.InterfaceLuid))
		h = (h ^ p[i++]) * 1099511628211ULL;
	p = (const uint8_t *)&route.NextHop.Ipv4.sin_addr;
	i = 0;
	while (i < 4)
		h = (h ^ p[i++]) * 1099511628211ULL;
	memset(&neigh, 0, sizeof(neigh));
	neigh.Address = route.NextHop;
	neigh.InterfaceLuid = route.InterfaceLuid;
	if (GetIpNetEntry2(&neigh) == NO_ERROR)
	{
		i = 0;
		while (i < neigh.PhysicalAddressLength)
			h = (h ^ neigh.PhysicalAddress[i++]) * 1099511628211ULL;
	}
	return (h == NETFP_UNKNOWN ? 1 : h);
}

/* Other WinDivert-based DPI tools divert the same packets. */
const char	*tpp_conflict(void)
{
	static const char	*names[] = {"goodbyedpi.exe", "winws.exe", NULL};
	HANDLE				snap;
	PROCESSENTRY32		pe;
	const char			*hit;
	size_t				i;

	snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return (NULL);
	hit = NULL;
	pe.dwSize = sizeof(pe);
	if (Process32First(snap, &pe))
	{
		do
		{
			i = 0;
			while (hit == NULL && names[i] != NULL)
			{
				if (_stricmp(pe.szExeFile, names[i]) == 0)
					hit = (i == 0) ? "GoodbyeDPI is running"
						: "zapret (winws) is running";
				i++;
			}
		}
		while (hit == NULL && Process32Next(snap, &pe));
	}
	CloseHandle(snap);
	return (hit);
}

const char	*tpp_name(void)
{
	return ("WinDivert");
}
