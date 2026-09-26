#include "netfingerprint.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

/* Can't assert a specific value (depends on the machine this runs
 * on), but can assert determinism: two calls in the same process,
 * same network, must agree — otherwise the discovery cache would
 * spuriously invalidate itself on every lookup. */
static void	test_fingerprint_is_deterministic(void)
{
	uint64_t	a;
	uint64_t	b;

	a = netfingerprint_current();
	b = netfingerprint_current();
	assert(a == b);
}

/* Same determinism property for the richer profile gather — and, on
 * any machine with a default route (true in this project's own CI/
 * dev environments), the gathered iface must be non-empty and must
 * match what the fingerprint itself is scoped to. */
static void	test_profile_gather_is_deterministic_and_consistent(void)
{
	t_net_profile	a;
	t_net_profile	b;

	netprofile_gather(&a);
	netprofile_gather(&b);
	assert(strcmp(a.iface, b.iface) == 0);
	assert(a.link_type == b.link_type);
	assert(a.has_ipv4_default == b.has_ipv4_default);
	assert(a.has_ipv6_default == b.has_ipv6_default);

	if (netfingerprint_current() != NETFP_UNKNOWN)
		assert(a.iface[0] != '\0');
}

static void	test_describe_never_overflows_and_is_nul_terminated(void)
{
	t_net_profile	profile;
	char			buf[8]; /* deliberately tiny */

	netprofile_gather(&profile);
	netprofile_describe(&profile, buf, sizeof(buf));
	assert(strlen(buf) < sizeof(buf));
}

static void	test_link_type_name_covers_every_value(void)
{
	assert(strcmp(link_type_name(LINK_UNKNOWN), "unknown") == 0);
	assert(strcmp(link_type_name(LINK_ETHERNET), "ethernet") == 0);
	assert(strcmp(link_type_name(LINK_WIFI), "wifi") == 0);
	assert(strcmp(link_type_name(LINK_OTHER), "other") == 0);
}

/* Regression test for a real gap: two networks that hand out the same
 * private gateway IP (192.168.1.1 is extremely common — home routers,
 * some hotspots) must not collide into the same fingerprint when
 * there's no SSID to tell them apart (plain ethernet, or Wi-Fi
 * without `nmcli`), or a bypass decision learned on one network would
 * silently leak onto the other. Windows (GetIpNetEntry2) and macOS
 * (gateway_mac(), RTF_LLINFO) already fold the gateway's MAC in for
 * exactly this reason; this proves the Linux hash does too. */
static void	test_same_gateway_ip_different_mac_does_not_collide(void)
{
	t_net_profile	profile;
	uint8_t			mac_a[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
	uint8_t			mac_b[6] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
	uint32_t		gw_raw;
	uint64_t		h_a;
	uint64_t		h_b;
	uint64_t		h_no_mac;

	memset(&profile, 0, sizeof(profile));
	strcpy(profile.iface, "eth0");
	profile.link_type = LINK_ETHERNET; /* no SSID signal available */
	profile.has_ipv4_default = 1;
	gw_raw = 0x0101a8c0; /* same on both: this is the point of the test */

	h_a = netfingerprint_hash(&profile, gw_raw, mac_a, 1);
	h_b = netfingerprint_hash(&profile, gw_raw, mac_b, 1);
	assert(h_a != h_b);

	/* MAC not resolved yet (e.g. right after boot): still a valid,
	 * non-crashing fingerprint, just less specific — and it must
	 * actually differ from the resolved-MAC case, or the MAC input
	 * would be silently ignored. */
	h_no_mac = netfingerprint_hash(&profile, gw_raw, mac_a, 0);
	assert(h_no_mac != NETFP_UNKNOWN);
	assert(h_no_mac != h_a);
}

/* The property the discovery cache depends on: identical inputs must
 * hash identically, every time. */
static void	test_hash_is_deterministic_for_same_inputs(void)
{
	t_net_profile	profile;
	uint8_t			mac[6] = {1, 2, 3, 4, 5, 6};
	uint64_t		a;
	uint64_t		b;

	memset(&profile, 0, sizeof(profile));
	strcpy(profile.iface, "wlan0");
	profile.link_type = LINK_WIFI;
	strcpy(profile.ssid, "HomeNet");
	profile.has_ipv4_default = 1;
	profile.has_ipv6_default = 1;

	a = netfingerprint_hash(&profile, 0x0101a8c0, mac, 1);
	b = netfingerprint_hash(&profile, 0x0101a8c0, mac, 1);
	assert(a == b);
}

int	main(void)
{
	test_fingerprint_is_deterministic();
	test_profile_gather_is_deterministic_and_consistent();
	test_describe_never_overflows_and_is_nul_terminated();
	test_link_type_name_covers_every_value();
	test_same_gateway_ip_different_mac_does_not_collide();
	test_hash_is_deterministic_for_same_inputs();
	printf("test_netfingerprint: OK\n");
	return (0);
}
