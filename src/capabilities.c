#include "capabilities.h"

#include <stddef.h>
#include <stdlib.h>
#include <string.h>

const char	*capabilities_platform(void)
{
#if defined(_WIN32)
	return ("windows");
#elif defined(__APPLE__)
	return ("macos");
#elif defined(__linux__)
	return ("linux");
#else
	return ("unknown");
#endif
}

#ifdef __linux__

# include <stdio.h>
# include <sys/socket.h>
# include <sys/types.h>
# include <netinet/in.h>
# include <unistd.h>

# define CAP_NET_ADMIN_BIT 12
# define CAP_NET_RAW_BIT 13

static unsigned long long	read_cap_eff(void)
{
	FILE				*f;
	char				line[256];
	unsigned long long	value;

	f = fopen("/proc/self/status", "r");
	if (f == NULL)
		return (0);

	value = 0;
	while (fgets(line, sizeof(line), f) != NULL)
	{
		if (strncmp(line, "CapEff:", 7) == 0)
		{
			value = strtoull(line + 7, NULL, 16);
			break ;
		}
	}
	fclose(f);
	return (value);
}

void	capabilities_probe_linux(int *out_net_admin, int *out_net_raw,
	int *out_raw_socket)
{
	unsigned long long	cap_eff;
	int					fd;

	cap_eff = read_cap_eff();
	*out_net_admin = ((cap_eff >> CAP_NET_ADMIN_BIT) & 1ULL) != 0;
	*out_net_raw = ((cap_eff >> CAP_NET_RAW_BIT) & 1ULL) != 0;

	fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	*out_raw_socket = (fd >= 0);
	if (fd >= 0)
		close(fd);
}

int	capabilities_has_nft(void)
{
	if (access("/usr/sbin/nft", X_OK) == 0)
		return (1);
	if (access("/sbin/nft", X_OK) == 0)
		return (1);
	if (access("/usr/bin/nft", X_OK) == 0)
		return (1);
	return (0);
}

#else

void	capabilities_probe_linux(int *out_net_admin, int *out_net_raw,
	int *out_raw_socket)
{
	*out_net_admin = 0;
	*out_net_raw = 0;
	*out_raw_socket = 0;
}

int	capabilities_has_nft(void)
{
	return (0);
}

#endif
