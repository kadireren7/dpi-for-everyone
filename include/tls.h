#ifndef TLS_H
# define TLS_H

# include <stddef.h>
# include <sys/types.h>

ssize_t	tls_find_sni_split(const unsigned char *data, size_t length);
ssize_t	tls_fragment_first_record(const unsigned char *data, size_t len,
			size_t at, unsigned char *out, size_t out_size);
size_t	tls_record_split_point(const unsigned char *data, size_t len);

#endif