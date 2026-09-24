#include "netfingerprint.h"

#include <arpa/inet.h>
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

const char	*link_type_name(t_link_type t)
{
	if (t == LINK_ETHERNET)
		return ("ethernet");
	if (t == LINK_WIFI)
		return ("wifi");
	if (t == LINK_OTHER)
		return ("other");
	return ("unknown");
}

/* FNV-1a, 64-bit. Not cryptographic — this only needs to be a stable,
 * well-distributed identifier for cache scoping, never a security
 * boundary. */
static uint64_t	fnv1a(uint64_t hash, const void *data, size_t len)
{
	const unsigned char	*p;
	size_t					i;

	p = data;
	i = 0;
	while (i < len)
	{
		hash ^= (uint64_t)p[i];
		hash *= 1099511628211ULL;
		i++;
	}
	return (hash);
}

/* /proc/net/route: one header line, then whitespace-separated fields
 * "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window
 * IRTT" per route, Destination/Gateway as 8 hex chars in the kernel's
 * raw in-memory byte order (the standard, well-known way every
 * `route`-like tool reads this file: parsed via strtoul base 16 and
 * used as a raw 32-bit value — never reinterpreted or byte-swapped
 * here, since this function only needs internal consistency, not a
 * human-readable address). Destination "00000000" is the default
 * route (0.0.0.0/0). Returns 1 and fills `iface`/`gw_raw` on success,
 * 0 if no default route line was found. */
static int	find_default_route_v4(char *iface, size_t iface_size,
	uint32_t *gw_raw)
{
	FILE	*f;
	char	line[256];
	char	iface_field[64];
	char	dest_field[32];
	char	gw_field[32];
	int		found;

	f = fopen("/proc/net/route", "r");
	if (f == NULL)
		return (0);

	found = 0;
	if (fgets(line, sizeof(line), f) == NULL)
	{
		fclose(f);
		return (0);
	}
	while (fgets(line, sizeof(line), f) != NULL)
	{
		if (sscanf(line, "%63s %31s %31s", iface_field, dest_field,
				gw_field) != 3)
			continue ;
		if (strcmp(dest_field, "00000000") != 0)
			continue ;
		if (iface_size > 0)
		{
			strncpy(iface, iface_field, iface_size - 1);
			iface[iface_size - 1] = '\0';
		}
		*gw_raw = (uint32_t)strtoul(gw_field, NULL, 16);
		found = 1;
		break ;
	}
	fclose(f);
	return (found);
}

/* /proc/net/ipv6_route: one line per route, whitespace-separated
 * fields, first field (32 hex chars) is the destination and second
 * (2 hex chars) is the prefix length — the default route is
 * "00000000000000000000000000000000 00 ...". No header line (unlike
 * the v4 file). Returns 1 if a default route exists, 0 otherwise
 * (including if the file can't be read — IPv6 just isn't assumed
 * available, never fabricated). */
static int	has_default_route_v6(void)
{
	FILE	*f;
	char	line[256];
	char	dest_field[64];
	char	prefixlen_field[8];

	f = fopen("/proc/net/ipv6_route", "r");
	if (f == NULL)
		return (0);
	while (fgets(line, sizeof(line), f) != NULL)
	{
		if (sscanf(line, "%63s %7s", dest_field, prefixlen_field) != 2)
			continue ;
		if (strcmp(prefixlen_field, "00") == 0
			&& strspn(dest_field, "0") == strlen(dest_field))
		{
			fclose(f);
			return (1);
		}
	}
	fclose(f);
	return (0);
}

/* A wireless interface has a /sys/class/net/<iface>/wireless entry —
 * the standard, long-stable Linux kernel signal for this, no
 * privilege required. */
static t_link_type	detect_link_type(const char *iface)
{
	char	path[128];

	if (iface[0] == '\0')
		return (LINK_UNKNOWN);
	snprintf(path, sizeof(path), "/sys/class/net/%s/wireless", iface);
	if (access(path, F_OK) == 0)
		return (LINK_WIFI);
	snprintf(path, sizeof(path), "/sys/class/net/%s", iface);
	if (access(path, F_OK) == 0)
		return (LINK_ETHERNET);
	return (LINK_OTHER);
}

/* Local-only NetworkManager query — `nmcli` talks to NetworkManager
 * over the local D-Bus, no network I/O of its own. fork+execvp with a
 * fixed argv (never system()/popen() with an interpolated string),
 * same discipline as nft_rules.c's `nft` invocation. Best-effort:
 * leaves `out` empty (not fabricated) if nmcli is missing, times out,
 * or reports nothing active. */
static void	get_active_ssid(char *out, size_t out_size)
{
	int		pipefd[2];
	pid_t	pid;
	char	buf[512];
	ssize_t	n;
	size_t	total;
	int		status;
	char	*line;
	char	*saveptr;

	out[0] = '\0';
	if (pipe(pipefd) < 0)
		return ;
	pid = fork();
	if (pid < 0)
	{
		close(pipefd[0]);
		close(pipefd[1]);
		return ;
	}
	if (pid == 0)
	{
		dup2(pipefd[1], STDOUT_FILENO);
		close(pipefd[0]);
		close(pipefd[1]);
		execlp("nmcli", "nmcli", "-t", "-f", "active,ssid", "dev", "wifi",
			(char *)NULL);
		_exit(127);
	}
	close(pipefd[1]);
	total = 0;
	while (total + 1 < sizeof(buf))
	{
		n = read(pipefd[0], buf + total, sizeof(buf) - 1 - total);
		if (n > 0)
			total += (size_t)n;
		else if (n == 0)
			break ;
		else if (errno != EINTR)
			break ;
	}
	buf[total] = '\0';
	close(pipefd[0]);
	waitpid(pid, &status, 0);

	/* Lines look like "yes:MySSID" or "no:OtherSSID". nmcli escapes a
	 * literal ':' inside an SSID as "\:" — good enough for a display/
	 * fingerprint signal without a full unescaper, so a colon-bearing
	 * SSID just yields a truncated-at-the-colon result rather than a
	 * parse error. */
	line = strtok_r(buf, "\n", &saveptr);
	while (line != NULL)
	{
		if (strncmp(line, "yes:", 4) == 0)
		{
			strncpy(out, line + 4, out_size - 1);
			out[out_size - 1] = '\0';
			return ;
		}
		line = strtok_r(NULL, "\n", &saveptr);
	}
}

/* This host's own address on `iface`, read via SIOCGIFADDR on a local
 * throwaway UDP socket — no packet is ever sent, this ioctl only
 * consults the kernel's own interface table. Deliberately not an
 * internet-facing/public address (see the header's "NO TELEMETRY"
 * note) — just whatever this interface's assigned address is. */
static void	get_iface_local_addr(const char *iface, char *out,
	size_t out_size)
{
	int					fd;
	struct ifreq		req;
	struct sockaddr_in	*addr;

	out[0] = '\0';
	if (iface[0] == '\0')
		return ;
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return ;
	memset(&req, 0, sizeof(req));
	strncpy(req.ifr_name, iface, sizeof(req.ifr_name) - 1);
	if (ioctl(fd, SIOCGIFADDR, &req) == 0)
	{
		addr = (struct sockaddr_in *)&req.ifr_addr;
		if (inet_ntop(AF_INET, &addr->sin_addr, out, (socklen_t)out_size)
			== NULL)
			out[0] = '\0';
	}
	close(fd);
}

void	netprofile_gather(t_net_profile *out)
{
	uint32_t	gw_raw;

	memset(out, 0, sizeof(*out));
	if (!find_default_route_v4(out->iface, sizeof(out->iface), &gw_raw))
		out->iface[0] = '\0';
	(void)gw_raw; /* only the gateway's presence (via iface) matters here */
	out->has_ipv4_default = (out->iface[0] != '\0');
	out->has_ipv6_default = has_default_route_v6();
	out->link_type = detect_link_type(out->iface);
	if (out->link_type == LINK_WIFI)
		get_active_ssid(out->ssid, sizeof(out->ssid));
	get_iface_local_addr(out->iface, out->local_addr,
		sizeof(out->local_addr));
}

void	netprofile_describe(const t_net_profile *profile, char *buf,
	size_t buf_size)
{
	snprintf(buf, buf_size,
		"iface=%s link=%s ssid=\"%s\" ipv4=%s ipv6=%s local_addr=%s",
		profile->iface[0] ? profile->iface : "(none)",
		link_type_name(profile->link_type), profile->ssid,
		profile->has_ipv4_default ? "yes" : "no",
		profile->has_ipv6_default ? "yes" : "no",
		profile->local_addr[0] ? profile->local_addr : "(none)");
}

uint64_t	netfingerprint_current(void)
{
	t_net_profile	profile;
	char			iface[NETPROFILE_IFACE_MAX];
	uint32_t		gw_raw;
	uint64_t		hash;

	if (!find_default_route_v4(iface, sizeof(iface), &gw_raw))
		return (NETFP_UNKNOWN);

	netprofile_gather(&profile);

	hash = 1469598103934665603ULL; /* FNV offset basis */
	hash = fnv1a(hash, iface, strlen(iface));
	hash = fnv1a(hash, &gw_raw, sizeof(gw_raw));
	hash = fnv1a(hash, &profile.link_type, sizeof(profile.link_type));
	hash = fnv1a(hash, profile.ssid, strlen(profile.ssid));
	hash = fnv1a(hash, &profile.has_ipv4_default,
			sizeof(profile.has_ipv4_default));
	hash = fnv1a(hash, &profile.has_ipv6_default,
			sizeof(profile.has_ipv6_default));

	/* NETFP_UNKNOWN (0) is reserved to mean "no fingerprint could be
	 * computed" — on the astronomically unlikely chance the hash
	 * itself lands on 0, perturb it so a real (if unusual) network is
	 * never mistaken for "unknown". */
	if (hash == NETFP_UNKNOWN)
		hash = 1;
	return (hash);
}
