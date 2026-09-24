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

int	main(void)
{
	test_fingerprint_is_deterministic();
	test_profile_gather_is_deterministic_and_consistent();
	test_describe_never_overflows_and_is_nul_terminated();
	test_link_type_name_covers_every_value();
	printf("test_netfingerprint: OK\n");
	return (0);
}
