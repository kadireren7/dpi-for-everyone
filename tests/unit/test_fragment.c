#include "packet.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

/* Self-contained (like the other tests/unit/test_*.c files, no
 * shared header beyond packet.h): builds one valid IPv4/TCP packet
 * with a real, correctly-computed TCP checksum, optionally with the
 * IP_FLAG_DF bit set, so the fragmentation tests below can verify
 * DF is cleared on the synthesized fragments. */
static void	fill_packet(uint8_t *buf, size_t *out_len,
	const uint8_t *payload, size_t payload_len, int set_df)
{
	t_ipv4_header	*ip;
	t_tcp_header	*tcp;
	size_t			total;

	total = sizeof(t_ipv4_header) + sizeof(t_tcp_header) + payload_len;
	memset(buf, 0, total);

	ip = (t_ipv4_header *)buf;
	ip->ver_ihl = (4 << 4) | 5;
	ip->total_len = htons((uint16_t)total);
	ip->id = htons(0xBEEF);
	if (set_df)
		ip->flags_frag = htons(IP_FLAG_DF);
	ip->ttl = 64;
	ip->protocol = 6;
	ip->src = htonl(0x0A000001u);
	ip->dst = htonl(0x0A000002u);

	tcp = (t_tcp_header *)(buf + sizeof(t_ipv4_header));
	tcp->src_port = htons(51000);
	tcp->dst_port = htons(443);
	tcp->seq = htonl(1000);
	tcp->ack = htonl(1);
	tcp->offset_reserved = (5 << 4);
	tcp->flags = TCP_FLAG_PSH | TCP_FLAG_ACK;
	tcp->window = htons(65535);

	memcpy(buf + sizeof(t_ipv4_header) + sizeof(t_tcp_header),
		payload, payload_len);

	ip->checksum = htons(checksum_ipv4_header(ip, sizeof(t_ipv4_header)));
	tcp->checksum = htons(checksum_tcp_v4(ip,
			buf + sizeof(t_ipv4_header),
			sizeof(t_tcp_header) + payload_len));

	*out_len = total;
}

static int	ipv4_header_checksum_is_valid(const t_ipv4_header *ip)
{
	uint32_t	sum;

	sum = checksum_accumulate(ip, sizeof(t_ipv4_header), 0);
	return (checksum_finalize(sum) == 0);
}

static void	make_payload(uint8_t *buf, size_t len)
{
	size_t	i;

	i = 0;
	while (i < len)
	{
		buf[i] = (uint8_t)('A' + (i % 26));
		i++;
	}
}

/* Core correctness: fragment a real packet, verify each fragment's
 * IP header is independently valid, verify the two fragments'
 * payload bytes concatenate back to exactly the original TCP
 * header+payload (byte-for-byte — this is what IP reassembly at the
 * destination would produce), and verify the ORIGINAL TCP checksum
 * (untouched by fragmentation, per design) is still valid against
 * that reassembled data. */
static void	test_fragment_basic_correctness(void)
{
	uint8_t			in[256];
	size_t			in_len;
	uint8_t			payload[64];
	uint8_t			out1[256];
	uint8_t			out2[256];
	size_t			out1_len;
	size_t			out2_len;
	t_ipv4_header	*ip1;
	t_ipv4_header	*ip2;
	uint8_t			reassembled[256];
	uint8_t			orig_l4[256];
	uint16_t		flags1;
	uint16_t		flags2;

	make_payload(payload, sizeof(payload));
	fill_packet(in, &in_len, payload, sizeof(payload), 0);

	assert(packet_fragment_ipv4(in, in_len, 10, out1, &out1_len,
			out2, &out2_len) == PACKET_OK);

	ip1 = (t_ipv4_header *)out1;
	ip2 = (t_ipv4_header *)out2;

	assert(ipv4_header_checksum_is_valid(ip1));
	assert(ipv4_header_checksum_is_valid(ip2));

	/* Same IP identification field on both, so the destination's IP
	 * stack knows they belong to the same original datagram. */
	assert(ip1->id == ip2->id);
	assert(ip1->id == ((t_ipv4_header *)in)->id);

	flags1 = ntohs(ip1->flags_frag);
	flags2 = ntohs(ip2->flags_frag);

	/* Fragment 1: offset 0, MF set, DF clear. */
	assert((flags1 & IP_FRAG_OFFSET_MASK) == 0);
	assert((flags1 & IP_FLAG_MF) != 0);
	assert((flags1 & IP_FLAG_DF) == 0);

	/* Fragment 2: MF clear (last fragment), nonzero offset, DF clear. */
	assert((flags2 & IP_FLAG_MF) == 0);
	assert((flags2 & IP_FRAG_OFFSET_MASK) != 0);
	assert((flags2 & IP_FLAG_DF) == 0);

	/* Fragment 2's offset field, in 8-byte units, must equal fragment
	 * 1's own payload length in bytes / 8 — that's the RFC 791
	 * contract that lets a real IP stack reassemble correctly. */
	assert((size_t)(flags2 & IP_FRAG_OFFSET_MASK) * IP_FRAG_UNIT
		== out1_len - sizeof(t_ipv4_header));

	/* Reassemble byte-for-byte and compare against the original
	 * TCP header + payload. */
	memcpy(reassembled, out1 + sizeof(t_ipv4_header),
		out1_len - sizeof(t_ipv4_header));
	memcpy(reassembled + (out1_len - sizeof(t_ipv4_header)),
		out2 + sizeof(t_ipv4_header), out2_len - sizeof(t_ipv4_header));
	memcpy(orig_l4, in + sizeof(t_ipv4_header), in_len - sizeof(t_ipv4_header));
	assert(memcmp(reassembled, orig_l4,
			in_len - sizeof(t_ipv4_header)) == 0);

	/* The original TCP checksum was never touched by fragmentation
	 * (see packet_fragment_ipv4's contract) — it must still validate
	 * against the reassembled bytes using the original pseudo-header. */
	{
		uint8_t		pseudo[4];
		uint16_t	tcp_len_be;
		uint32_t	sum;
		size_t		l4_len;

		l4_len = in_len - sizeof(t_ipv4_header);
		pseudo[0] = 0;
		pseudo[1] = 6;
		tcp_len_be = htons((uint16_t)l4_len);
		memcpy(pseudo + 2, &tcp_len_be, 2);
		sum = checksum_accumulate(&((t_ipv4_header *)in)->src, 4, 0);
		sum = checksum_accumulate(&((t_ipv4_header *)in)->dst, 4, sum);
		sum = checksum_accumulate(pseudo, 4, sum);
		sum = checksum_accumulate(reassembled, l4_len, sum);
		assert(checksum_finalize(sum) == 0);
	}
}

/* Fragment 1 must always carry the complete TCP header, regardless of
 * how small a split offset was requested — the boundary is rounded up
 * to at least the end of the TCP header. */
static void	test_fragment_boundary_covers_tcp_header(void)
{
	uint8_t	in[256];
	size_t	in_len;
	uint8_t	payload[64];
	uint8_t	out1[256];
	uint8_t	out2[256];
	size_t	out1_len;
	size_t	out2_len;

	make_payload(payload, sizeof(payload));
	fill_packet(in, &in_len, payload, sizeof(payload), 0);

	/* split_offset = 1 (as early as possible inside the TCP payload)
	 * must still round up to at least the 20-byte TCP header, i.e.
	 * fragment 1's IP-payload length must be >= 20 (and 8-aligned). */
	assert(packet_fragment_ipv4(in, in_len, 1, out1, &out1_len,
			out2, &out2_len) == PACKET_OK);
	assert(out1_len - sizeof(t_ipv4_header) >= sizeof(t_tcp_header));
	assert((out1_len - sizeof(t_ipv4_header)) % IP_FRAG_UNIT == 0);
}

static void	test_fragment_rejects_invalid_offsets(void)
{
	uint8_t	in[256];
	size_t	in_len;
	uint8_t	payload[64];
	uint8_t	out1[256];
	uint8_t	out2[256];
	size_t	out1_len;
	size_t	out2_len;

	make_payload(payload, sizeof(payload));
	fill_packet(in, &in_len, payload, sizeof(payload), 0);

	assert(packet_fragment_ipv4(in, in_len, 0, out1, &out1_len,
			out2, &out2_len) == PACKET_ERR_MALFORMED);
	assert(packet_fragment_ipv4(in, in_len, sizeof(payload), out1, &out1_len,
			out2, &out2_len) == PACKET_ERR_MALFORMED);
	assert(packet_fragment_ipv4(in, in_len, sizeof(payload) + 100,
			out1, &out1_len, out2, &out2_len) == PACKET_ERR_MALFORMED);
}

static void	test_fragment_rejects_non_tcp(void)
{
	uint8_t	in[256];
	size_t	in_len;
	uint8_t	payload[64];
	uint8_t	out1[256];
	uint8_t	out2[256];
	size_t	out1_len;
	size_t	out2_len;

	make_payload(payload, sizeof(payload));
	fill_packet(in, &in_len, payload, sizeof(payload), 0);
	((t_ipv4_header *)in)->protocol = 17;

	assert(packet_fragment_ipv4(in, in_len, 10, out1, &out1_len,
			out2, &out2_len) == PACKET_ERR_UNSUPPORTED);
}

static void	test_fragment_too_small_payload_for_useful_split(void)
{
	uint8_t	in[256];
	size_t	in_len;
	uint8_t	payload[4];
	uint8_t	out1[256];
	uint8_t	out2[256];
	size_t	out1_len;
	size_t	out2_len;
	int		status;

	make_payload(payload, sizeof(payload));
	fill_packet(in, &in_len, payload, sizeof(payload), 0);

	/* A 4-byte payload: any split offset inside it rounds up to
	 * beyond the whole IP payload once added to the 20-byte TCP
	 * header, so this must fail open rather than produce a bogus
	 * fragment 2 with nothing in it. */
	status = packet_fragment_ipv4(in, in_len, 2, out1, &out1_len,
			out2, &out2_len);
	assert(status == PACKET_ERR_MALFORMED);
}

int	main(void)
{
	test_fragment_basic_correctness();
	test_fragment_boundary_covers_tcp_header();
	test_fragment_rejects_invalid_offsets();
	test_fragment_rejects_non_tcp();
	test_fragment_too_small_payload_for_useful_split();
	printf("test_fragment: OK\n");
	return (0);
}
