#ifndef TLSCLIENT_H
# define TLSCLIENT_H

# include <stddef.h>
# include <stdint.h>
# include <sys/types.h>

/* ============================================================
 * Minimal TLS client over an already-connected socket (OpenSSL,
 * memory BIOs). Every byte OpenSSL sends passes through here, so the
 * first flight (the ClientHello) can go out re-framed by the shared
 * relay core (relay_send_first, e.g. RELAY_SPLIT_TLS_RECORD) — the
 * same treatment the proxied connections get. Used by the DoH
 * resolver and by transparent mode's certificate verifier.
 *
 * Certificates are checked against the system trust store (on
 * Windows, the "ROOT" certificate store) and the given hostname.
 * ============================================================ */

typedef struct s_tlsc	t_tlsc;

typedef enum e_tlsc_result
{
	TLSC_OK = 0,		/* handshake done, certificate valid for host */
	TLSC_BAD_CERT,		/* handshake done, certificate NOT valid for host */
	TLSC_FAILED			/* no completed handshake (reset, timeout, ...) */
}	t_tlsc_result;

/* A client context (SSL_CTX *), shareable between threads. `alpn`
 * (e.g. "http/1.1") may be NULL. NULL on failure. */
void			*tlsc_ctx_new(const char *alpn);
void			tlsc_ctx_free(void *ctx);

/* Handshake for `host` on connected socket `fd` (which the returned
 * t_tlsc then owns and closes), first flight sent with relay split
 * mode `split`, everything bounded by `deadline_ms` (compat_now_ms
 * clock). *result says how it ended; with require_valid, anything but
 * TLSC_OK returns NULL (fd closed). Without it, a completed handshake
 * returns the session whatever the certificate check said. */
t_tlsc			*tlsc_handshake(void *ctx, int fd, const char *host,
					int split, int64_t deadline_ms, int require_valid,
					t_tlsc_result *result);
int				tlsc_write(t_tlsc *t, const void *buf, size_t len,
					int64_t deadline_ms);
/* Up to `size` bytes; -1 on error, EOF or deadline. */
int				tlsc_read(t_tlsc *t, void *buf, size_t size,
					int64_t deadline_ms);
void			tlsc_free(t_tlsc *t);

const char		*tlsc_result_name(t_tlsc_result r);

#endif
