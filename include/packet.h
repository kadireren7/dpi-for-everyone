#ifndef PACKET_H
# define PACKET_H

# include <stddef.h>
# include <stdint.h>

/* Return codes shared by every parser in this module. Anything other
 * than PACKET_OK means "do not trust this packet's fields" — the
 * caller must fail open (PASS) rather than act on partial data. */
typedef enum e_packet_status
{
	PACKET_OK = 0,
	PACKET_ERR_TRUNCATED = -1,
	PACKET_ERR_MALFORMED = -2,
	PACKET_ERR_UNSUPPORTED = -3
}	t_packet_status;

# define TCP_FLAG_FIN 0x01
# define TCP_FLAG_SYN 0x02
# define TCP_FLAG_RST 0x04
# define TCP_FLAG_PSH 0x08
# define TCP_FLAG_ACK 0x10
# define TCP_FLAG_URG 0x20

#pragma pack(push, 1)
typedef struct s_ipv4_header
{
	uint8_t		ver_ihl;
	uint8_t		tos;
	uint16_t	total_len;
	uint16_t	id;
	uint16_t	flags_frag;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	checksum;
	uint32_t	src;
	uint32_t	dst;
}	t_ipv4_header;

typedef struct s_ipv6_header
{
	uint32_t	ver_class_flow;
	uint16_t	payload_len;
	uint8_t		next_header;
	uint8_t		hop_limit;
	uint8_t		src[16];
	uint8_t		dst[16];
}	t_ipv6_header;

typedef struct s_tcp_header
{
	uint16_t	src_port;
	uint16_t	dst_port;
	uint32_t	seq;
	uint32_t	ack;
	uint8_t		offset_reserved;
	uint8_t		flags;
	uint16_t	window;
	uint16_t	checksum;
	uint16_t	urgent_ptr;
}	t_tcp_header;
#pragma pack(pop)

/* Zero-copy views into a caller-owned buffer: no allocation, no
 * mutation of the input, always bounds-checked against `len`. */
typedef struct s_ipv4_view
{
	const t_ipv4_header	*header;
	uint8_t					ihl_bytes;
	uint16_t				total_len;
	uint8_t					protocol;
	const uint8_t			*payload;
	size_t					payload_len;
}	t_ipv4_view;

typedef struct s_ipv6_view
{
	const t_ipv6_header	*header;
	uint8_t					next_header;
	const uint8_t			*payload;
	size_t					payload_len;
}	t_ipv6_view;

typedef struct s_tcp_view
{
	const t_tcp_header	*header;
	uint8_t				offset_bytes;
	uint32_t			seq;
	uint32_t			ack;
	uint8_t				flags;
	const uint8_t		*payload;
	size_t				payload_len;
}	t_tcp_view;

int			packet_parse_ipv4(const uint8_t *data, size_t len,
				t_ipv4_view *out);
int			packet_parse_ipv6(const uint8_t *data, size_t len,
				t_ipv6_view *out);
int			packet_parse_tcp(const uint8_t *data, size_t len,
				t_tcp_view *out);

/* RFC 1071 one's-complement checksum, split into an accumulate step
 * (composable across several buffers — pseudo-header, then TCP
 * header, then payload — via `seed`) and a finalize step (fold +
 * complement). `checksum_finalize`'s result is host-order; callers
 * store it into a wire field with htons(). */
uint32_t	checksum_accumulate(const void *data, size_t len, uint32_t seed);
uint16_t	checksum_finalize(uint32_t sum);

uint16_t	checksum_ipv4_header(const t_ipv4_header *hdr, uint8_t ihl_bytes);
uint16_t	checksum_tcp_v4(const t_ipv4_header *ip, const uint8_t *tcp_seg,
				size_t tcp_seg_len);
uint16_t	checksum_tcp_v6(const t_ipv6_header *ip, const uint8_t *tcp_seg,
				size_t tcp_seg_len);

/* Re-segment a captured IPv4/TCP packet into two wire-valid packets,
 * splitting the TCP payload at `split_offset` bytes in. Both outputs
 * carry the original TCP header (incl. options) with seq/checksum/IP
 * total-length corrected. `out1`/`out2` must each be at least
 * `in_len` bytes; `*out1_len`/`*out2_len` receive the real sizes. */
int			packet_split_tcp_v4(const uint8_t *in, size_t in_len,
				size_t split_offset,
				uint8_t *out1, size_t *out1_len,
				uint8_t *out2, size_t *out2_len);
int			packet_split_tcp_v6(const uint8_t *in, size_t in_len,
				size_t split_offset,
				uint8_t *out1, size_t *out1_len,
				uint8_t *out2, size_t *out2_len);

/* IPv4 flags_frag field layout: top 3 bits are flags (reserved, DF,
 * MF), low 13 bits are the fragment offset in 8-byte units. */
# define IP_FLAG_DF 0x4000
# define IP_FLAG_MF 0x2000
# define IP_FRAG_OFFSET_MASK 0x1FFF
# define IP_FRAG_UNIT 8

/* True IP-layer fragmentation (RFC 791) of an already-complete,
 * already-checksummed IPv4/TCP datagram — NOT TCP segmentation (see
 * packet_split_tcp_v4 for that). `tcp_payload_split_offset` is
 * interpreted the same way packet_split_tcp_v4's split_offset is
 * (an offset into the TCP payload, e.g. from tls_find_sni_split),
 * but the actual fragmentation boundary is computed as the next
 * IP_FRAG_UNIT-aligned offset at or after the end of the TCP header
 * — fragment 1 always carries the complete TCP header plus however
 * much payload landed before that boundary; fragment 2 is a headerless
 * continuation of the same IP payload. Because the original datagram
 * is complete and correctly checksummed *before* being split, no TCP
 * seq/ack/checksum recomputation happens here at all — the
 * destination's IP reassembly reconstructs the identical original
 * payload byte-for-byte, so the original TCP checksum is still valid
 * after reassembly. Both fragments share the original IP
 * identification field. If the original packet had IP_FLAG_DF set,
 * it is cleared on both fragments (fragmenting a DF datagram at all
 * only happens because this function was explicitly asked to).
 * Returns PACKET_ERR_MALFORMED if no valid 8-byte-aligned split point
 * exists strictly between the end of the TCP header and the end of
 * the payload (caller should fall back to unmodified ACCEPT). */
int			packet_fragment_ipv4(const uint8_t *in, size_t in_len,
				size_t tcp_payload_split_offset,
				uint8_t *out1, size_t *out1_len,
				uint8_t *out2, size_t *out2_len);

/* Builds one synthetic decoy IPv4/TCP packet from a real captured
 * packet: same 5-tuple, same starting sequence number, same flags/ack
 * as the input, IP TTL set to `ttl`, and the TCP checksum deliberately
 * set to an invalid value (bitwise complement of the correct one —
 * always different, since checksum == ~checksum has no 16-bit
 * solution). The IP header checksum is left VALID, so ordinary IP
 * forwarding still carries the decoy to wherever a DPI box might be
 * inspecting it; the invalid TCP checksum is what makes a real
 * endpoint's TCP stack (or NIC RX checksum offload) silently drop it
 * before it ever reaches application/stream state — belt-and-
 * suspenders with the lowered TTL, which independently expires the
 * packet before most real origins if some path device doesn't
 * validate the TCP checksum. This never touches the real segment's
 * own sequence numbers or bytes; the caller sends the real data
 * separately and unmodified. Heuristic, not a guarantee — effectiveness
 * against any specific DPI depends on that DPI's own behavior. `out`
 * must be at least `in_len` bytes. */
int			packet_make_fake_tcp_v4(const uint8_t *in, size_t in_len,
				uint8_t ttl, uint8_t *out, size_t *out_len);

#endif
