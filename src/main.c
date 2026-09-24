#include "capabilities.h"
#include "common.h"
#include "platform.h"
#include "socks.h"
#ifdef __linux__
# include "tp_sys.h"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef DPI_PROXY_VERSION
# define DPI_PROXY_VERSION "0.0.0-dev"
#endif

static void	print_usage(const char *argv0)
{
	printf("Usage: %s [options]\n"
		"\n"
		"A general-purpose local SOCKS5 proxy. With no options, listens\n"
		"on 127.0.0.1:%d.\n"
		"\n"
		"Options:\n"
		"  --listen HOST:PORT   bind address (default 127.0.0.1:%d)\n"
		"  --mode proxy         SOCKS5 proxy (default)\n"
		"  --mode transparent   Linux, root/CAP_NET_ADMIN: intercept\n"
		"                       outgoing TCP/443 system-wide via nftables\n"
		"                       and bypass DPI automatically (normally run\n"
		"                       by the dpi-proxy-transparent service)\n"
		"                       — see docs/transparent-mode.md\n"
		"  --port PORT          transparent listener port (default %d)\n"
		"  --debug              transparent mode: log every connection\n"
		"  --log-level LEVEL    error|info (default: info) — \"error\"\n"
		"                       suppresses the per-connection \"request:\n"
		"                       host:port\" line\n"
		"  --capabilities       print a platform/capability report and exit\n"
		"  --version            print the version and exit\n"
		"  --help               print this message and exit\n"
		"\n"
		"Example:\n"
		"  %s --listen 127.0.0.1:1081\n",
		argv0, DPI_PROXY_PORT, DPI_PROXY_PORT, 1091, argv0);
}

static void	print_capabilities(void)
{
	int	net_admin;
	int	net_raw;
	int	raw_socket;

	capabilities_probe_linux(&net_admin, &net_raw, &raw_socket);
	printf("platform: %s\n", capabilities_platform());
	printf("proxy_mode: supported\n");
#ifdef __linux__
	printf("transparent_mode: supported (--mode transparent)\n");
#else
	printf("transparent_mode: not on this platform (Linux only)\n");
#endif
	printf("packet_mode: not built into this binary "
		"(see dpi-proxy-packet, Linux only)\n");
	printf("ipv4: yes\n");
	printf("ipv6: yes (SOCKS5 ATYP 0x04)\n");
	printf("tls_split: yes (DPI_PROXY_SPLIT_TLS=1 or =record in proxy mode; "
		"automatic in transparent mode)\n");
	if (strcmp(capabilities_platform(), "linux") == 0)
	{
		printf("raw_socket: %s (irrelevant to this binary; shown for "
			"reference)\n", raw_socket ? "yes" : "no");
	}
}

static int	parse_listen(const char *arg, char *host_out, size_t host_out_size,
	int *port_out)
{
	const char	*colon;
	size_t		host_len;

	colon = strrchr(arg, ':');
	if (colon == NULL || colon == arg)
		return (-1);

	host_len = (size_t)(colon - arg);
	if (host_len >= host_out_size)
		return (-1);

	memcpy(host_out, arg, host_len);
	host_out[host_len] = '\0';

	*port_out = atoi(colon + 1);
	if (*port_out <= 0 || *port_out > 65535)
		return (-1);

	return (0);
}

int	main(int argc, char **argv)
{
	int		i;
	int		rc;
	const char	*host;
	int			port;
	char		host_buf[256];
	int			transparent;
	int			tp_port;
	int			tp_debug;

	host = NULL;
	port = DPI_PROXY_PORT;
	transparent = 0;
	tp_port = 0;
	tp_debug = 0;

	i = 1;
	while (i < argc)
	{
		if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0)
		{
			print_usage(argv[0]);
			return (0);
		}
		else if (strcmp(argv[i], "--version") == 0)
		{
			printf("dpi-proxy %s\n", DPI_PROXY_VERSION);
			return (0);
		}
		else if (strcmp(argv[i], "--capabilities") == 0)
		{
			print_capabilities();
			return (0);
		}
		else if (strcmp(argv[i], "--listen") == 0 && i + 1 < argc)
		{
			i++;
			if (parse_listen(argv[i], host_buf, sizeof(host_buf), &port) < 0)
			{
				fprintf(stderr, "invalid --listen value \"%s\", expected "
					"HOST:PORT (e.g. 127.0.0.1:1081)\n", argv[i]);
				return (1);
			}
			host = host_buf;
		}
		else if (strcmp(argv[i], "--mode") == 0 && i + 1 < argc)
		{
			i++;
			if (strcmp(argv[i], "transparent") == 0)
				transparent = 1;
			else if (strcmp(argv[i], "proxy") != 0)
			{
				fprintf(stderr, "unknown --mode \"%s\" (proxy or "
					"transparent; for packet mode see dpi-proxy-packet)\n",
					argv[i]);
				return (1);
			}
		}
		else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc)
		{
			i++;
			tp_port = atoi(argv[i]);
			if (tp_port <= 0 || tp_port > 65535)
			{
				fprintf(stderr, "invalid --port \"%s\"\n", argv[i]);
				return (1);
			}
		}
		else if (strcmp(argv[i], "--debug") == 0)
			tp_debug = 1;
		else if (strcmp(argv[i], "--log-level") == 0 && i + 1 < argc)
		{
			i++;
			if (strcmp(argv[i], "error") == 0)
				g_socks_verbose = 0;
			else if (strcmp(argv[i], "info") != 0)
			{
				fprintf(stderr, "unknown --log-level \"%s\" (expected "
					"error or info)\n", argv[i]);
				return (1);
			}
		}
		else
		{
			fprintf(stderr, "unknown option: %s (see --help)\n", argv[i]);
			return (1);
		}
		i++;
	}

	if (platform_init() != 0)
	{
		fprintf(stderr, "platform init failed\n");
		return (1);
	}

	if (transparent)
	{
#ifdef __linux__
		t_tp_options	opt;

		tp_options_default(&opt);
		if (tp_port != 0)
			opt.port = tp_port;
		if (tp_debug)
			opt.debug = 1;
		setvbuf(stderr, NULL, _IOLBF, 0);
		rc = run_transparent_server(&opt);
		platform_cleanup();
		return (rc < 0 ? 1 : 0);
#else
		(void)tp_port;
		(void)tp_debug;
		fprintf(stderr, "--mode transparent is Linux-only; use the "
			"SOCKS5 proxy (the default mode) on this platform\n");
		return (1);
#endif
	}

	printf("dpi-proxy — general-purpose SOCKS5 proxy\n");

	rc = run_socks_server(host, port);
	if (rc < 0 && host != NULL)
		fprintf(stderr, "note: could not bind %s:%d — if the address is "
			"already in use, another process (or another dpi-proxy) is "
			"probably listening there already\n", host, port);

	platform_cleanup();

	return (rc < 0 ? 1 : 0);
}
