#ifndef NFT_RULES_H
# define NFT_RULES_H

# include <stddef.h>

# define NFT_TABLE_NAME "dpi_proxy"
# define NFT_CHAIN_NAME "output"
# define NFT_DEFAULT_QUEUE_NUM 0

/* Packets the engine self-injects (see nfqueue_engine.c's SPLIT
 * path) are SO_MARK-tagged with this value; the generated rule
 * excludes them so a re-injected split segment doesn't immediately
 * loop back into the same queue. Single source of truth for both
 * the rule text and the socket option that sets it. */
# define NFT_ANTILOOP_MARK 0x2a4b

/* Builds the nftables ruleset (as text fed to `nft -f -`) that owns a
 * single dedicated `inet dpi_proxy` table: nothing outside that table
 * is ever touched. `queue_num` selects the NFQUEUE number; the
 * `bypass` flag means traffic is ACCEPTed, not dropped, if no
 * userspace program is bound to the queue (daemon crash/not-running
 * fails open, never fails closed). Pure string building — no I/O, no
 * privilege required, fully unit-testable. Returns the number of
 * bytes written (excluding NUL), or 0 if `out_size` was too small. */
size_t	nft_rules_generate_create(char *out, size_t out_size,
			int queue_num);

/* Best-effort: `nft delete table inet dpi_proxy`. Safe to call even
 * if the table doesn't exist (idempotent cleanup) — always returns 0;
 * real failures are logged, not propagated, because cleanup must
 * never be what blocks shutdown. Requires CAP_NET_ADMIN/root; shells
 * out via fork+execvp with a fixed argv (never system()/popen with
 * interpolated strings). Live-tested on Linux with real nftables. */
int		nft_rules_remove(void);

/* Runs nft_rules_remove() first (idempotent), then applies the
 * ruleset from nft_rules_generate_create(). Returns 0 on success, -1
 * on failure. Live-tested along with nft_rules_remove(). */
int		nft_rules_apply(int queue_num);

#endif
