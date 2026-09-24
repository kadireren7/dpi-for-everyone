NAME = dpi-proxy

CC = cc

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0-dev)

CFLAGS = -Wall -Wextra -Werror -DDPI_PROXY_VERSION=\"$(VERSION)\"

# Header dependencies (.d files next to each .o): changing a header
# rebuilds every object that includes it, so a struct change can
# never link against stale objects.
DEPFLAGS = -MMD -MP

INCLUDES = -Iinclude

LDFLAGS = -lpthread

# e.g. `make test TEST_CFLAGS="-fsanitize=address,undefined -g"`
TEST_CFLAGS ?=

SRC = \
	src/main.c \
	src/socks.c \
	src/upstream.c \
	src/relay.c \
	src/tls.c \
	src/platform.c \
	src/capabilities.c

# Packet-mode building blocks (classifier, strategy engine, packet/
# checksum primitives, nft rule-management): plain portable C, no
# privilege or extra dev packages required to build or unit test.
# NOT part of the default SOCKS5 build (`all`/`re`) — see `make test`
# and `make packet-mode`.
PACKET_SRC = \
	src/packet/ip.c \
	src/packet/tcp.c \
	src/packet/checksum.c \
	src/packet/split.c \
	src/packet/fragment.c \
	src/packet/fake.c \
	src/http/http.c \
	src/tls/sni_extract.c \
	src/flow/flow.c \
	src/strategy/strategy.c \
	src/nfqueue/nft_rules.c \
	src/discovery/netfingerprint.c \
	src/discovery/ladder.c \
	src/discovery/cache.c \
	src/dns/dns.c \
	src/dns/dns_udp.c \
	src/transparent/policy.c

PACKET_OBJ = $(PACKET_SRC:.c=.o)

TEST_SRC = $(wildcard tests/unit/test_*.c)
TEST_BIN = $(TEST_SRC:.c=)

# Transparent mode (`dpi-proxy --mode transparent`): Linux-only, built
# into the same dpi-proxy binary on Linux. It reuses the SOCKS stream
# core (relay.c/upstream.c) plus these modules, and links OpenSSL
# (libssl-dev) for its DNS-over-HTTPS resolver; runtime also needs the
# nft and openssl binaries. Not part of the Windows build (WIN_OBJ uses
# $(SRC) only).
TP_SRC = \
	src/transparent/transparent.c \
	src/transparent/conn.c \
	src/transparent/verify.c \
	src/transparent/nft.c \
	src/transparent/policy.c \
	src/transparent/quic.c \
	src/transparent/dnsfwd.c \
	src/dns/dns.c \
	src/dns/dns_udp.c \
	src/dns/dns_doh.c \
	src/strategy/strategy.c \
	src/tls/sni_extract.c \
	src/discovery/netfingerprint.c \
	src/discovery/ladder.c

# Override both for a non-standard OpenSSL location, e.g.
# `make OPENSSL_CFLAGS=-I/opt/ssl/include OPENSSL_LIBS="-L/opt/ssl/lib
# -lssl -lcrypto"`.
OPENSSL_CFLAGS ?= $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS ?= $(shell pkg-config --libs openssl 2>/dev/null || echo -lssl -lcrypto)

ifeq ($(shell uname -s),Linux)
PROXY_SRC = $(SRC) $(TP_SRC)
LDFLAGS += $(OPENSSL_LIBS)
INCLUDES += $(OPENSSL_CFLAGS)
else
PROXY_SRC = $(SRC)
endif

OBJ = $(PROXY_SRC:.c=.o)

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) $(LDFLAGS) -o $(NAME)

%.o: %.c
	$(CC) $(CFLAGS) $(DEPFLAGS) $(TEST_CFLAGS) $(INCLUDES) -c $< -o $@

-include $(wildcard src/*.d src/*/*.d)

tests/unit/%: tests/unit/%.c $(PACKET_OBJ)
	$(CC) $(CFLAGS) $(TEST_CFLAGS) $(INCLUDES) $< $(PACKET_OBJ) -o $@

# src/tls.c is proxy-mode code (not in PACKET_OBJ), so this one test
# links it explicitly.
tests/unit/test_tls_record: tests/unit/test_tls_record.c $(PACKET_OBJ) src/tls.o
	$(CC) $(CFLAGS) $(TEST_CFLAGS) $(INCLUDES) $< $(PACKET_OBJ) src/tls.o -o $@

# The shared SOCKS/transparent stream core (proxy-mode code, not in
# PACKET_OBJ).
tests/unit/test_relay: tests/unit/test_relay.c $(PACKET_OBJ) src/relay.o \
		src/tls.o src/platform.o
	$(CC) $(CFLAGS) $(TEST_CFLAGS) $(INCLUDES) $< $(PACKET_OBJ) src/relay.o \
		src/tls.o src/platform.o -lpthread -o $@

test: $(TEST_BIN)
	@set -e; for t in $(TEST_BIN); do ./$$t; done

# Full unit suite under ASan+UBSan. Forces a clean rebuild first so
# stale non-instrumented .o files from a plain `make test` can't slip
# through uninstrumented.
sanitize:
	$(MAKE) clean
	$(MAKE) test TEST_CFLAGS="-fsanitize=address,undefined -g -fno-omit-frame-pointer"

# Requires libnetfilter-queue-dev + nftables, and CAP_NET_ADMIN/
# CAP_NET_RAW (or root) to actually run the resulting binary.
#
# Forces a clean rebuild first, same reasoning as `sanitize`: if a
# prior `make sanitize` left ASan/UBSan-instrumented .o files for
# $(PACKET_OBJ) lying around, make's mtime-based rule wouldn't know
# to recompile them plain, and this target would link mismatched
# object flavors — undefined __asan_*/__ubsan_* references at link
# time. Demonstrated for real 2026-09-21: `make sanitize && make
# packet-mode` in one tree failed exactly this way.
#
# src/tls.o is included explicitly: nfqueue_engine.c's live SPLIT
# path calls tls_find_sni_split() (src/tls.c), which is otherwise
# only part of the SOCKS5 build's $(SRC)/$(OBJ). Without it this
# target fails to link with "undefined reference to
# tls_find_sni_split" — demonstrated for real 2026-09-21; the
# packet-mode-compile CI job had never actually run against this
# (unpushed) code, which is why it went unnoticed.
packet-mode:
	$(MAKE) clean
	$(MAKE) $(PACKET_OBJ) src/capabilities.o src/tls.o
	@pkg-config --exists libnetfilter_queue || { \
		echo "Error: libnetfilter-queue-dev not installed." >&2; \
		echo "Run: sudo apt-get install -y libnetfilter-queue-dev nftables" >&2; \
		exit 1; \
	}
	$(CC) $(CFLAGS) -DHAVE_NFQUEUE_ENGINE $(INCLUDES) \
		-c src/nfqueue/nfqueue_engine.c -o src/nfqueue/nfqueue_engine.o
	$(CC) $(CFLAGS) -DHAVE_NFQUEUE_ENGINE $(INCLUDES) \
		-c src/discovery/probe_runner.c -o src/discovery/probe_runner.o
	$(CC) $(CFLAGS) -DHAVE_NFQUEUE_ENGINE $(INCLUDES) \
		-c src/main_packet.c -o src/main_packet.o
	$(CC) $(CFLAGS) $(PACKET_OBJ) src/capabilities.o src/tls.o \
		src/nfqueue/nfqueue_engine.o \
		src/discovery/probe_runner.o \
		src/main_packet.o $$(pkg-config --libs libnetfilter_queue) \
		-lpthread -o dpi-proxy-packet

clean:
	rm -f $(wildcard src/*.d src/*/*.d)
	rm -f $(OBJ) $(SRC:.c=.o) $(TP_SRC:.c=.o) $(WIN_OBJ) $(PACKET_OBJ) $(TEST_BIN) \
		src/nfqueue/nfqueue_engine.o src/main_packet.o \
		src/discovery/probe_runner.o

fclean: clean
	rm -f $(NAME) $(NAME).exe dpi-proxy-packet

re: fclean all

install: $(NAME)
	install -Dm755 $(NAME) $(HOME)/.local/bin/$(NAME)

uninstall:
	rm -f $(HOME)/.local/bin/$(NAME)

# Cross-compile for Windows via MinGW-w64. Requires the
# x86_64-w64-mingw32-gcc toolchain (e.g. `apt install mingw-w64`).
CC_WIN = x86_64-w64-mingw32-gcc
LDFLAGS_WIN = -lws2_32 -lpthread -static
WIN_OBJ = $(SRC:.c=.win.o)

%.win.o: %.c
	$(CC_WIN) $(CFLAGS) $(INCLUDES) -c $< -o $@

windows: $(WIN_OBJ)
	$(CC_WIN) $(CFLAGS) $(WIN_OBJ) $(LDFLAGS_WIN) -o $(NAME).exe

.PHONY: all clean fclean re install uninstall windows test sanitize packet-mode