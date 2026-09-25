#define _GNU_SOURCE
#include "tlsclient.h"
#include "compat.h"
#include "relay.h"

#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
# include <wincrypt.h>
#endif

struct s_tlsc
{
	int		fd;
	SSL		*ssl;
	BIO		*rbio;
	BIO		*wbio;
};

#ifdef _WIN32

/* OpenSSL on Windows has no default CA file: trust exactly what the
 * system trusts (the machine's ROOT store). */
static int	load_system_roots(SSL_CTX *ctx)
{
	HCERTSTORE		store;
	PCCERT_CONTEXT	cert;
	X509_STORE		*xs;
	X509			*x;
	const unsigned char	*p;
	int				n;

	store = CertOpenSystemStoreA(0, "ROOT");
	if (store == NULL)
		return (-1);
	xs = SSL_CTX_get_cert_store(ctx);
	n = 0;
	cert = NULL;
	while ((cert = CertEnumCertificatesInStore(store, cert)) != NULL)
	{
		p = cert->pbCertEncoded;
		x = d2i_X509(NULL, &p, (long)cert->cbCertEncoded);
		if (x != NULL)
		{
			if (X509_STORE_add_cert(xs, x) == 1)
				n++;
			X509_free(x);
		}
	}
	CertCloseStore(store, 0);
	ERR_clear_error();
	return (n > 0 ? 0 : -1);
}

#elif defined(__APPLE__)

/* The release build links its own OpenSSL, whose compiled-in default
 * directory may not exist on the user's Mac: use the bundle macOS
 * itself ships (and updates), then the defaults. */
static int	load_system_roots(SSL_CTX *ctx)
{
	if (SSL_CTX_load_verify_locations(ctx, "/etc/ssl/cert.pem", NULL) == 1)
		return (0);
	ERR_clear_error();
	return (SSL_CTX_set_default_verify_paths(ctx) == 1 ? 0 : -1);
}

#else

static int	load_system_roots(SSL_CTX *ctx)
{
	return (SSL_CTX_set_default_verify_paths(ctx) == 1 ? 0 : -1);
}

#endif

void	*tlsc_ctx_new(const char *alpn)
{
	SSL_CTX			*ctx;
	unsigned char	wire[64];
	size_t			n;

	ctx = SSL_CTX_new(TLS_client_method());
	if (ctx == NULL)
		return (NULL);
	if (load_system_roots(ctx) != 0)
	{
		SSL_CTX_free(ctx);
		return (NULL);
	}
	SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
	/* verification is checked after the handshake (tlsc_handshake), so
	 * a completed handshake with a bad certificate can be told apart
	 * from a connection that never got that far */
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
	if (alpn != NULL)
	{
		n = strlen(alpn);
		if (n > 0 && n < sizeof(wire) - 1)
		{
			wire[0] = (unsigned char)n;
			memcpy(wire + 1, alpn, n);
			SSL_CTX_set_alpn_protos(ctx, wire, (unsigned int)(n + 1));
		}
	}
	return (ctx);
}

void	tlsc_ctx_free(void *ctx)
{
	if (ctx != NULL)
		SSL_CTX_free((SSL_CTX *)ctx);
}

void	tlsc_free(t_tlsc *t)
{
	if (t == NULL)
		return ;
	if (t->ssl != NULL)
		SSL_free(t->ssl);
	if (t->fd >= 0)
		compat_close(t->fd);
	free(t);
}

/* Sends whatever OpenSSL produced; the first flight with `split`. */
static int	flush_out(t_tlsc *t, int split)
{
	unsigned char	buf[16384];
	int				n;

	while (BIO_ctrl_pending(t->wbio) > 0)
	{
		n = BIO_read(t->wbio, buf, sizeof(buf));
		if (n <= 0)
			return (-1);
		if (relay_send_first(t->fd, buf, (size_t)n, split) != 0)
			return (-1);
		split = RELAY_SPLIT_NONE;
	}
	return (0);
}

/* Feeds the next bytes from the socket to OpenSSL. */
static int	feed_in(t_tlsc *t, int64_t deadline)
{
	unsigned char	buf[16384];
	ssize_t			n;
	int64_t			left;

	left = deadline - compat_now_ms();
	if (left <= 0 || compat_wait(t->fd, POLLIN, (int)left) <= 0)
		return (-1);
	do
		n = compat_recv(t->fd, buf, sizeof(buf));
	while (n < 0 && compat_interrupted());
	if (n <= 0)
		return (-1);
	return (BIO_write(t->rbio, buf, (int)n) == (int)n ? 0 : -1);
}

t_tlsc	*tlsc_handshake(void *ctx, int fd, const char *host, int split,
	int64_t deadline_ms, int require_valid, t_tlsc_result *result)
{
	t_tlsc	*t;
	int		rc;
	int		first;

	*result = TLSC_FAILED;
	t = calloc(1, sizeof(*t));
	if (t == NULL)
	{
		compat_close(fd);
		return (NULL);
	}
	t->fd = fd;
	t->ssl = SSL_new((SSL_CTX *)ctx);
	t->rbio = BIO_new(BIO_s_mem());
	t->wbio = BIO_new(BIO_s_mem());
	if (t->ssl == NULL || t->rbio == NULL || t->wbio == NULL)
	{
		BIO_free(t->rbio);
		BIO_free(t->wbio);
		tlsc_free(t);
		return (NULL);
	}
	SSL_set_bio(t->ssl, t->rbio, t->wbio);
	SSL_set_tlsext_host_name(t->ssl, host);
	SSL_set1_host(t->ssl, host);
	SSL_set_connect_state(t->ssl);
	first = 1;
	while ((rc = SSL_do_handshake(t->ssl)) != 1)
	{
		if (SSL_get_error(t->ssl, rc) != SSL_ERROR_WANT_READ
			|| flush_out(t, first ? split : RELAY_SPLIT_NONE) != 0
			|| feed_in(t, deadline_ms) != 0)
		{
			ERR_clear_error();
			tlsc_free(t);
			return (NULL);
		}
		first = 0;
	}
	if (flush_out(t, RELAY_SPLIT_NONE) != 0)
	{
		tlsc_free(t);
		return (NULL);
	}
	*result = (SSL_get_verify_result(t->ssl) == X509_V_OK
			&& SSL_get0_peer_certificate(t->ssl) != NULL)
		? TLSC_OK : TLSC_BAD_CERT;
	if (require_valid && *result != TLSC_OK)
	{
		tlsc_free(t);
		return (NULL);
	}
	return (t);
}

int	tlsc_write(t_tlsc *t, const void *buf, size_t len, int64_t deadline_ms)
{
	int	rc;

	while (len > 0)
	{
		rc = SSL_write(t->ssl, buf, (int)len);
		if (rc <= 0)
		{
			if (SSL_get_error(t->ssl, rc) != SSL_ERROR_WANT_READ
				|| flush_out(t, RELAY_SPLIT_NONE) != 0
				|| feed_in(t, deadline_ms) != 0)
				return (-1);
			continue ;
		}
		buf = (const char *)buf + rc;
		len -= (size_t)rc;
	}
	return (flush_out(t, RELAY_SPLIT_NONE));
}

int	tlsc_read(t_tlsc *t, void *buf, size_t size, int64_t deadline_ms)
{
	int	rc;

	while (1)
	{
		rc = SSL_read(t->ssl, buf, (int)size);
		if (rc > 0)
			return (rc);
		if (SSL_get_error(t->ssl, rc) != SSL_ERROR_WANT_READ
			|| flush_out(t, RELAY_SPLIT_NONE) != 0
			|| feed_in(t, deadline_ms) != 0)
			return (-1);
	}
}

const char	*tlsc_result_name(t_tlsc_result r)
{
	if (r == TLSC_OK)
		return ("verified");
	if (r == TLSC_BAD_CERT)
		return ("certificate-invalid");
	return ("no-handshake");
}
