#include "packet.h"

#include <assert.h>
#include <string.h>
#include <stdio.h>

#ifdef _WIN32
# include <winsock2.h>
#else
# include <arpa/inet.h>
#endif

/* Independent reference checksum (deliberately written differently
 * from src/packet/checksum.c's accumulate/finalize split) used as a
 * cross-check oracle, plus the standard "sum including the checksum
 * field itself must fold to zero" self-verification trick — together
 * these don't need a live network capture to catch a sign/order bug. */
static uint16_t	reference_checksum(const uint8_t *data, size_t len)
{
	uint32_t	sum;
	size_t		i;

	sum = 0;
	i = 0;
	while (i + 1 < len)
	{
		sum += ((uint32_t)data[i] << 8) | data[i + 1];
		i += 2;
	}
	if (i < len)
		sum += (uint32_t)data[i] << 8;
	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);
	return ((uint16_t)~sum);
}

static void	fill_ipv4_tcp_packet(uint8_t *buf, size_t *out_len,
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
	ip->id = htons(1234);
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

	memcpy(buf + sizeof(t_ipv4_header) + sizeof(t_tcp_header),
		payload, payload_len);

	ip->checksum = htons(checksum_ipv4_header(ip, sizeof(t_ipv4_header)));
	tcp->checksum = htons(checksum_tcp_v4(ip,
			buf + sizeof(t_ipv4_header),
			sizeof(t_tcp_header) + payload_len));

	*out_len = total;
}

/* The classic verification: summing a valid checksummed region
 * *including* the already-filled-in checksum field must fold to
 * exactly zero. */
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

static void	test_checksum_matches_reference(void)
{
	uint8_t	data[37];
	size_t	i;

	for (i = 0; i < sizeof(data); i++)
		data[i] = (uint8_t)(i * 7 + 3);

	assert(checksum_finalize(checksum_accumulate(data, sizeof(data), 0))
		== reference_checksum(data, sizeof(data)));
}

static void	test_ipv4_parse_roundtrip(void)
{
	uint8_t			buf[128];
	size_t			len;
	uint8_t			payload[] = "hello-world";
	t_ipv4_view		view;

	fill_ipv4_tcp_packet(buf, &len, payload, sizeof(payload) - 1, 1000);

	assert(ipv4_header_checksum_is_valid((const t_ipv4_header *)buf));
	assert(packet_parse_ipv4(buf, len, &view) == PACKET_OK);
	assert(view.protocol == 6);
	assert(view.ihl_bytes == sizeof(t_ipv4_header));
	assert(tcp_checksum_v4_is_valid(view.header, view.payload,
			view.payload_len));
}

static void	test_ipv4_fragment_is_unsupported(void)
{
	uint8_t			buf[128];
	size_t			len;
	uint8_t			payload[] = "fragment-me";
	t_ipv4_header	*ip;
	t_ipv4_view		view;

	/* Non-first fragment: offset != 0. Its bytes are a raw payload
	 * continuation, not a TCP header — must not be parsed as one. */
	fill_ipv4_tcp_packet(buf, &len, payload, sizeof(payload) - 1, 1);
	ip = (t_ipv4_header *)buf;
	ip->flags_frag = htons(5);
	assert(packet_parse_ipv4(buf, len, &view) == PACKET_ERR_UNSUPPORTED);

	/* First fragment: offset == 0 but MF (more fragments) is set. */
	ip->flags_frag = htons(1 << 13);
	assert(packet_parse_ipv4(buf, len, &view) == PACKET_ERR_UNSUPPORTED);

	/* Not fragmented at all: must parse normally. */
	ip->flags_frag = 0;
	assert(packet_parse_ipv4(buf, len, &view) == PACKET_OK);
}

static void	test_ipv4_truncated_and_malformed(void)
{
	uint8_t			buf[128];
	size_t			len;
	uint8_t			payload[] = "x";
	t_ipv4_view		view;

	fill_ipv4_tcp_packet(buf, &len, payload, 1, 1);

	assert(packet_parse_ipv4(buf, 5, &view) == PACKET_ERR_TRUNCATED);
	assert(packet_parse_ipv4(buf, len - 1, &view) == PACKET_ERR_TRUNCATED);

	buf[0] = (6 << 4) | 5;
	assert(packet_parse_ipv4(buf, len, &view) == PACKET_ERR_MALFORMED);
}

static void	test_split_preserves_payload_and_checksums(void)
{
	uint8_t			buf[512];
	uint8_t			out1[512];
	uint8_t			out2[512];
	size_t			len;
	size_t			out1_len;
	size_t			out2_len;
	uint8_t			payload[300];
	size_t			i;
	t_ipv4_view		v1;
	t_ipv4_view		v2;
	t_tcp_view		t1;
	t_tcp_view		t2;
	uint8_t			rejoined[300];

	for (i = 0; i < sizeof(payload); i++)
		payload[i] = (uint8_t)(i ^ 0x5A);

	fill_ipv4_tcp_packet(buf, &len, payload, sizeof(payload), 5000);

	assert(packet_split_tcp_v4(buf, len, 137,
			out1, &out1_len, out2, &out2_len) == PACKET_OK);

	assert(packet_parse_ipv4(out1, out1_len, &v1) == PACKET_OK);
	assert(packet_parse_ipv4(out2, out2_len, &v2) == PACKET_OK);
	assert(ipv4_header_checksum_is_valid(v1.header));
	assert(ipv4_header_checksum_is_valid(v2.header));

	assert(packet_parse_tcp(v1.payload, v1.payload_len, &t1) == PACKET_OK);
	assert(packet_parse_tcp(v2.payload, v2.payload_len, &t2) == PACKET_OK);
	assert(tcp_checksum_v4_is_valid(v1.header, v1.payload, v1.payload_len));
	assert(tcp_checksum_v4_is_valid(v2.header, v2.payload, v2.payload_len));

	assert(t1.seq == 5000);
	assert(t2.seq == 5000 + 137);
	assert(t1.payload_len == 137);
	assert(t2.payload_len == sizeof(payload) - 137);

	memcpy(rejoined, t1.payload, t1.payload_len);
	memcpy(rejoined + t1.payload_len, t2.payload, t2.payload_len);
	assert(memcmp(rejoined, payload, sizeof(payload)) == 0);
}

static void	test_split_rejects_bad_offset(void)
{
	uint8_t	buf[128];
	uint8_t	out1[128];
	uint8_t	out2[128];
	size_t	len;
	size_t	o1;
	size_t	o2;
	uint8_t	payload[] = "abcdef";

	fill_ipv4_tcp_packet(buf, &len, payload, sizeof(payload) - 1, 1);

	assert(packet_split_tcp_v4(buf, len, 0, out1, &o1, out2, &o2)
		== PACKET_ERR_MALFORMED);
	assert(packet_split_tcp_v4(buf, len, sizeof(payload) - 1,
			out1, &o1, out2, &o2) == PACKET_ERR_MALFORMED);
}

int	main(void)
{
	test_checksum_matches_reference();
	test_ipv4_parse_roundtrip();
	test_ipv4_fragment_is_unsupported();
	test_ipv4_truncated_and_malformed();
	test_split_preserves_payload_and_checksums();
	test_split_rejects_bad_offset();
	printf("test_packet: OK\n");
	return (0);
}
