#ifndef CAPABILITIES_H
# define CAPABILITIES_H

/* Short platform name for reporting: "linux", "macos", "windows", or
 * "unknown". Compile-time, never wrong. */
const char	*capabilities_platform(void);

/* Linux-only real probes, no lasting side effects: *out_raw_socket is
 * set by actually creating (and immediately closing) a SOCK_RAW
 * socket — the same operation the SPLIT path needs at runtime, so
 * this tells the truth about whether it would work right now. The
 * net_admin/net_raw capability bits are parsed from this process's
 * own /proc/self/status (CapEff), which is a read, not a mutation.
 * On non-Linux platforms, or if /proc can't be read, all outputs are
 * left as 0 (never fabricated as 1). */
void		capabilities_probe_linux(int *out_net_admin, int *out_net_raw,
				int *out_raw_socket);

/* 1 if an `nft` executable is found on PATH (existence/executability
 * check only, via access() — never actually invoked). 0 otherwise,
 * including on non-Linux platforms. */
int			capabilities_has_nft(void);

#endif
