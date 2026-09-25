#ifndef NETFINGERPRINT_H
# define NETFINGERPRINT_H

# include <stddef.h>
# include <stdint.h>

/* Network fingerprint: a stable-but-opaque identifier for "the
 * network this machine is currently on", used only to scope the
 * discovery cache (src/discovery/cache.c) so a strategy learned on
 * one network is never silently reused on another. Callers only ever
 * see the resulting uint64_t; the signals it is computed from are
 * described by t_net_profile below.
 *
 * Linux-only (reads /proc/net/route and /proc/net/ipv6_route, same
 * privilege-free posture as capabilities_probe_linux()) — consistent
 * with this module only mattering to packet mode, which is
 * Linux-only itself. Never fabricated: if no default route can be
 * read, returns NETFP_UNKNOWN, which callers must treat as "always
 * reprobe", never as a stable value two calls could coincidentally
 * match on.
 *
 * NO TELEMETRY, NO EXTERNAL NETWORK CALLS: every signal below is read
 * from local kernel/OS state (/proc, /sys, ioctl on a local socket,
 * or a local NetworkManager query via `nmcli`) or is a value this
 * process already had. Nothing is ever sent anywhere to determine
 * any of it — deliberately, per this project's "everything remains
 * local" design constraint. In particular there is no "what's my
 * public IP" lookup against any third-party service, and no ASN/
 * country/GeoIP lookup (those would require either an external
 * service or a bundled offline database this project doesn't ship) —
 * `t_net_profile.local_addr` is this host's own interface address as
 * the kernel already knows it, not an internet-facing public address
 * behind NAT. */
# define NETFP_UNKNOWN 0

# define NETPROFILE_IFACE_MAX 64
# define NETPROFILE_SSID_MAX 64

typedef enum e_link_type
{
	LINK_UNKNOWN = 0,
	LINK_ETHERNET,
	LINK_WIFI,
	LINK_OTHER
}	t_link_type;

const char	*link_type_name(t_link_type t);

typedef struct s_net_profile
{
	char		iface[NETPROFILE_IFACE_MAX];
	t_link_type	link_type;
	/* Only populated when link_type == LINK_WIFI and a local `nmcli`
	 * query succeeded; empty otherwise — never fabricated. */
	char		ssid[NETPROFILE_SSID_MAX];
	int			has_ipv4_default;
	int			has_ipv6_default;
	/* This host's own address on `iface`, read locally via ioctl
	 * (SIOCGIFADDR) — see the file-level note above for why this is
	 * deliberately NOT a public/NAT-traversed address. Empty if it
	 * couldn't be read. */
	char		local_addr[NETPROFILE_IFACE_MAX];
}	t_net_profile;

/* Gathers every signal above, purely from local state (see the
 * file-level "NO TELEMETRY" note). Safe to call frequently — no
 * network I/O, no privilege required. Leaves fields at their
 * zero/empty defaults when a signal isn't available rather than
 * fabricating one. */
void		netprofile_gather(t_net_profile *out);

/* Human-readable one-line rendering for --status, e.g.
 * "iface=wlan0 link=wifi ssid=\"HomeNet\" ipv4=yes ipv6=yes
 * local_addr=192.168.1.42". */
void		netprofile_describe(const t_net_profile *profile, char *buf,
				size_t buf_size);

/* FNV-1a hash of every t_net_profile signal (iface, link type, SSID,
 * IPv4/IPv6 default-route availability) plus the default gateway
 * address and, when resolved, the gateway's MAC — so two networks
 * sharing the same private gateway IP (192.168.1.1 is extremely
 * common; so are phone-hotspot defaults) are told apart even when
 * SSID can't help (plain ethernet, or Wi-Fi without `nmcli`), the
 * same technique platform_windows.c (GetIpNetEntry2) and
 * platform_macos.c (gateway_mac(), RTF_LLINFO) already use. Returns
 * NETFP_UNKNOWN if no default route can be read at all. */
uint64_t	netfingerprint_current(void);

/* The pure combination step behind netfingerprint_current(): no I/O,
 * so tests can exercise the "same gateway IP, different MAC must not
 * collide" property with synthetic inputs instead of needing two real
 * physical networks. `gw_mac` is ignored unless `has_gw_mac` is set
 * (the gateway's ARP entry may not be resolved yet, e.g. right after
 * boot — that must still produce a valid, if less specific,
 * fingerprint, never NETFP_UNKNOWN and never a crash). */
uint64_t	netfingerprint_hash(const t_net_profile *profile,
				uint32_t gw_raw, const uint8_t *gw_mac, int has_gw_mac);

#endif
