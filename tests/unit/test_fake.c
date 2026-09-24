#include "packet.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

static void	fill_packet(uint8_t *buf, size_t *out_len,
	const uint8_t *payload, size_t payload_len, uint32_t seq)
{
	t_ipv4_header	*ip;
	t_tcp_header	*tcp;
	size_t			total;

	total = sizeof(t_ipv4_header) + sizeof(t_tcp_header) + payload_len;
	memset(buf, 0, total);

	ip = (t_ipv4_header *)buf;
	ip->ver_ihl = (4 << 4) | 5;
	ip->total_len = htons((uint16_t)total);
	ip->id = htons(4242);
	ip->ttl = 64;
	ip->protocol = 6;
	ip->src = htonl(0x0A000001u);
	ip->dst = htonl(0x0A000002u);

	tcp = (t_tcp_header *)(buf + sizeof(t_ipv4_header));
	tcp->src_port = htons(51000);
	tcp->dst_port = htons(443);
	tcp->seq = htonl(seq);
	tcp->ack = htonl(1);
	tcp->offset_reserved = (5 << 4);
	tcp->flags = TCP_FLAG_PSH | TCP_FLAG_ACK;
	tcp->window = htons(65535);

	if (payload_len > 0)
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

static int	tcp_checksum_v4_is_valid(const t_ipv4_header *ip,
	const uint8_t *tcp_seg, size_t tcp_seg_len)
{
	uint8_t		pseudo[4];
	uint16_t	tcp_len_be;
	uint32_t	sum;

	pseudo[0] = 0;
	pseudo[1] = 6;
	tcp_len_be = htons((uint16_t)tcp_seg_len);
	memcpy(pseudo + 2, &tcp_len_be, 2);

	sum = checksum_accumulate(&ip->src, 4, 0);
	sum = checksum_accumulate(&ip->dst, 4, sum);
	sum = checksum_accumulate(pseudo, 4, sum);
	sum = checksum_accumulate(tcp_seg, tcp_seg_len, sum);
	return (checksum_finalize(sum) == 0);
}

static void	make_payload(uint8_t *buf, size_t len)
{
	size_t	i;

	i = 0;
	while (i < len)
	{
		buf[i] = (uint8_t)('a' + (i % 26));
		i++;
	}
}

/* Core contract: the decoy keeps the real packet's identity (5-tuple,
 * sequence number, ack, flags) so it looks plausible in-flow, but its
 * IP header checksum stays VALID (so ordinary forwarding still
 * delivers it) while its TCP checksum is deliberately made INVALID —
 * this is the mechanism that makes a real endpoint's TCP stack drop
 * it before application/stream state is ever touched. TTL is set to
 * the requested value. */
static void	test_fake_contract(void)
{
	uint8_t			in[256];
	size_t			in_len;
	uint8_t			payload[32];
	uint8_t			out[256];
	size_t			out_len;
	t_ipv4_header	*out_ip;
	t_tcp_header	*out_tcp;
	t_ipv4_header	*in_ip;
	t_tcp_header	*in_tcp;

	make_payload(payload, sizeof(payload));
	fill_packet(in, &in_len, payload, sizeof(payload), 5000);

	assert(packet_make_fake_tcp_v4(in, in_len, 6, out, &out_len)
		== PACKET_OK);
	assert(out_len == in_len);

	out_ip = (t_ipv4_header *)out;
	out_tcp = (t_tcp_header *)(out + sizeof(t_ipv4_header));
	in_ip = (t_ipv4_header *)in;
	in_tcp = (t_tcp_header *)(in + sizeof(t_ipv4_header));

	assert(out_ip->ttl == 6);
	assert(ipv4_header_checksum_is_valid(out_ip));

	/* Deliberately invalid — this is the whole point. */
	assert(!tcp_checksum_v4_is_valid(out_ip,
			out + sizeof(t_ipv4_header),
			out_len - sizeof(t_ipv4_header)));
	assert(out_tcp->checksum != in_tcp->checksum);

	/* Everything else about the segment is preserved, so it looks
	 * like it belongs to the same flow/position. */
	assert(out_ip->src == in_ip->src);
	assert(out_ip->dst == in_ip->dst);
	assert(out_tcp->src_port == in_tcp->src_port);
	assert(out_tcp->dst_port == in_tcp->dst_port);
	assert(out_tcp->seq == in_tcp->seq);
	assert(out_tcp->ack == in_tcp->ack);
	assert(out_tcp->flags == in_tcp->flags);
	assert(memcmp(out + sizeof(t_ipv4_header) + sizeof(t_tcp_header),
			payload, sizeof(payload)) == 0);
}

/* checksum == ~checksum has no 16-bit solution, but verify it holds
 * across several different real (non-degenerate) checksum values
 * too, not just algebraically. */
static void	test_fake_checksum_always_changes(void)
{
	uint8_t		in[256];
	size_t		in_len;
	uint8_t		out[256];
	size_t		out_len;
	uint8_t		payload[16];
	size_t		i;
	uint16_t	before;
	uint16_t	after;

	i = 0;
	while (i < 20)
	{
		make_payload(payload, sizeof(payload));
		payload[0] = (uint8_t)i;
		fill_packet(in, &in_len, payload, sizeof(payload),
			(uint32_t)(1000 + i * 37));
		before = ((t_tcp_header *)(in + sizeof(t_ipv4_header)))->checksum;
		assert(packet_make_fake_tcp_v4(in, in_len, 8, out, &out_len)
			== PACKET_OK);
		after = ((t_tcp_header *)(out + sizeof(t_ipv4_header)))->checksum;
		assert(before != after);
		i++;
	}
}

static void	test_fake_rejects_non_tcp(void)
{
	uint8_t	in[256];
	size_t	in_len;
	uint8_t	out[256];
	size_t	out_len;
	uint8_t	payload[16];

	make_payload(payload, sizeof(payload));
	fill_packet(in, &in_len, payload, sizeof(payload), 100);
	((t_ipv4_header *)in)->protocol = 17;

	assert(packet_make_fake_tcp_v4(in, in_len, 8, out, &out_len)
		== PACKET_ERR_UNSUPPORTED);
}

static void	test_fake_rejects_empty_payload(void)
{
	uint8_t	in[256];
	size_t	in_len;
	uint8_t	out[256];
	size_t	out_len;

	fill_packet(in, &in_len, NULL, 0, 100);

	assert(packet_make_fake_tcp_v4(in, in_len, 8, out, &out_len)
		== PACKET_ERR_MALFORMED);
}

int	main(void)
{
	test_fake_contract();
	test_fake_checksum_always_changes();
	test_fake_rejects_non_tcp();
	test_fake_rejects_empty_payload();
	printf("test_fake: OK\n");
	return (0);
}
