#include "tp.h"

#include <stdarg.h>
#include <stdio.h>

/* ============================================================
 * The macOS PF anchor (tp.h, tp_pf_ruleset). Pure text generation, so
 * it is unit tested on every platform; platform_macos.c loads it.
 *
 * PF's rdr only applies to packets arriving on an interface, and a
 * locally generated connection never arrives anywhere. The standard
 * way around that (also used by sshuttle and mitmproxy): a `pass out
 * route-to (lo0 ...)` rule sends the packet to the loopback interface,
 * where it arrives, and `rdr on lo0` redirects it to our listener.
 * The reply goes back through the rdr state, so the application sees
 * its server answering.
 * ============================================================ */

typedef struct s_out
{
	char	*buf;
	size_t	size;
	size_t	len;
	int		overflow;
}	t_out;

__attribute__((format(printf, 2, 3)))
static void	put(t_out *o, const char *fmt, ...)
{
	va_list	ap;
	int		n;

	if (o->overflow)
		return ;
	va_start(ap, fmt);
	n = vsnprintf(o->buf + o->len, o->size - o->len, fmt, ap);
	va_end(ap);
	if (n < 0 || (size_t)n >= o->size - o->len)
	{
		o->overflow = 1;
		return ;
	}
	o->len += (size_t)n;
}

size_t	tp_pf_ruleset(char *out, size_t out_size, int port, int ipv6,
	int dns_port)
{
	t_out		o;
	char		src[64];

	o.buf = out;
	o.size = out_size;
	o.len = 0;
	o.overflow = (out_size == 0);
	/* "every source port except ours" */
	snprintf(src, sizeof(src), "from any port %d <> %d",
		TP_PF_OWN_PORT_LO, TP_PF_OWN_PORT_HI);
	put(&o, "# dpi-proxy transparent mode (anchor %s). Generated and owned "
		"by dpi-proxy;\n# removed when it stops.\n", TP_PF_ANCHOR);
	put(&o, "table <dpi_local4> const { 0.0.0.0/8, 10.0.0.0/8, "
		"100.64.0.0/10, 127.0.0.0/8, 169.254.0.0/16, 172.16.0.0/12, "
		"192.168.0.0/16, 224.0.0.0/3 }\n");
	put(&o, "table <dpi_local6> const { ::/128, ::1/128, ::ffff:0:0/96, "
		"fc00::/7, fe80::/10, ff00::/8 }\n");
	/* the router is the resolver that lies: private DNS servers are
	 * intercepted too, but not loopback (local resolvers, whose own
	 * upstream queries are intercepted) nor IPv6 link-local/multicast
	 * (scoped addresses can't be moved to lo0) */
	put(&o, "table <dpi_nodns6> const { ::1/128, fe80::/10, ff00::/8 }\n");
	put(&o, "table <%s>\ntable <%s>\n", TP_PF_QUIC_TABLE4, TP_PF_QUIC_TABLE6);
	/* translation: whatever route-to delivered to lo0 */
	put(&o, "rdr pass on lo0 inet proto tcp %s to ! <dpi_local4> port 443 "
		"-> 127.0.0.1 port %d\n", src, port);
	if (ipv6)
		put(&o, "rdr pass on lo0 inet6 proto tcp %s to ! <dpi_local6> "
			"port 443 -> ::1 port %d\n", src, port);
	if (dns_port > 0)
	{
		put(&o, "rdr pass on lo0 inet proto { udp, tcp } %s to ! "
			"127.0.0.0/8 port 53 -> 127.0.0.1 port %d\n", src, dns_port);
		if (ipv6)
			put(&o, "rdr pass on lo0 inet6 proto { udp, tcp } %s to ! "
				"<dpi_nodns6> port 53 -> ::1 port %d\n", src, dns_port);
	}
	/* filtering */
	put(&o, "block return out quick inet proto udp from any to <%s> "
		"port 443\n", TP_PF_QUIC_TABLE4);
	put(&o, "block return out quick inet6 proto udp from any to <%s> "
		"port 443\n", TP_PF_QUIC_TABLE6);
	put(&o, "pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet proto "
		"tcp %s to ! <dpi_local4> port 443 flags S/SA keep state\n", src);
	if (ipv6)
		put(&o, "pass out quick on ! lo0 route-to (lo0 ::1) inet6 proto "
			"tcp %s to ! <dpi_local6> port 443 flags S/SA keep state\n",
			src);
	if (dns_port > 0)
	{
		put(&o, "pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet "
			"proto udp %s to ! 127.0.0.0/8 port 53 keep state\n", src);
		put(&o, "pass out quick on ! lo0 route-to (lo0 127.0.0.1) inet "
			"proto tcp %s to ! 127.0.0.0/8 port 53 flags S/SA keep state\n",
			src);
		if (ipv6)
		{
			put(&o, "pass out quick on ! lo0 route-to (lo0 ::1) inet6 "
				"proto udp %s to ! <dpi_nodns6> port 53 keep state\n", src);
			put(&o, "pass out quick on ! lo0 route-to (lo0 ::1) inet6 "
				"proto tcp %s to ! <dpi_nodns6> port 53 flags S/SA keep "
				"state\n", src);
		}
	}
	if (o.overflow)
		return (0);
	return (o.len);
}
