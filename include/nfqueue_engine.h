#ifndef NFQUEUE_ENGINE_H
# define NFQUEUE_ENGINE_H

/* Requires libnetfilter-queue-dev (not installed in the environment
 * this was written in — see README "Packet mode" section). Only
 * built by `make packet-mode`, never by the default `make`/`make re`,
 * so its absence never affects the legacy SOCKS5 build. */

/* Runs the NFQUEUE receive loop on `queue_num` until SIGINT/SIGTERM.
 * Installs nftables rules on entry, removes them on every exit path
 * (including signal-driven shutdown). Every packet's verdict is
 * NF_ACCEPT with the payload unmodified in this version — flows are
 * classified (HTTP/TLS host logged when found) for observability, but
 * no strategy is actually applied to the wire yet. Returns 0 on a
 * clean shutdown, -1 on setup failure. */
int	nfqueue_engine_run(int queue_num);

#endif
