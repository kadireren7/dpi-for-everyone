#include "nft_rules.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void	test_generate_contains_expected_pieces(void)
{
	char	buf[512];
	size_t	len;

	len = nft_rules_generate_create(buf, sizeof(buf), 7);
	assert(len > 0);
	assert(strstr(buf, "table inet " NFT_TABLE_NAME) != NULL);
	assert(strstr(buf, "chain " NFT_CHAIN_NAME) != NULL);
	assert(strstr(buf, "queue num 7 bypass") != NULL);
	assert(strstr(buf, "tcp dport { 80, 443 }") != NULL);
	/* Loop-prevention: self-injected (SPLIT-path) packets are
	 * SO_MARK-tagged and must be excluded here, or a re-injected
	 * segment would immediately re-enter this same queue. */
	assert(strstr(buf, "meta mark != 0x2a4b") != NULL);
	/* `counter` is required for `nft list table` to show packet/byte
	 * counts — the M4.1 "interception actually happened" evidence a
	 * live validation pass needs to point at. */
	assert(strstr(buf, "counter queue num 7 bypass") != NULL);
}

static void	test_generate_reports_too_small_buffer(void)
{
	char	buf[8];

	assert(nft_rules_generate_create(buf, sizeof(buf), 0) == 0);
}

/* Real (not mocked) calls: this process has no CAP_NET_ADMIN, so
 * nft_rules_apply must fail safely rather than pretend to succeed,
 * and nft_rules_remove (best-effort by contract) must still return 0
 * even though the underlying `nft` invocation itself fails. This is
 * the one thing about the privileged path this environment CAN
 * verify: that the failure mode is safe, not that the success path
 * works (that needs real root — see README/report). */
static void	test_unprivileged_behavior_is_safe(void)
{
	assert(nft_rules_remove() == 0);
	assert(nft_rules_apply(0) == -1);
}

int	main(void)
{
	test_generate_contains_expected_pieces();
	test_generate_reports_too_small_buffer();
	test_unprivileged_behavior_is_safe();
	printf("test_nft_rules: OK (note: only the unprivileged-failure "
		"path was exercised; success path needs real root — see "
		"report)\n");
	return (0);
}
