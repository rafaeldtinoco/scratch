/*
 * conntracker - tracks flows into memory tables and dump results
 * Copyright (C) 2020 Rafael David Tinoco <rafaeldtinoco@ubuntu.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include "conntracker.h"

/* Sequences stored in memory */

GSequence *tcpv4flows;
GSequence *udpv4flows;
GSequence *icmpv4flows;

GSequence *tcpv6flows;
GSequence *udpv6flows;
GSequence *icmpv6flows;

/* compare bases */

#define cmpbase(type, arg1, arg2)						\
gint cmp_##type(struct type one, struct type two)				\
{										\
	if (one.arg1 < two.arg1)						\
		return LESS;							\
										\
	if (one.arg1 > two.arg1)						\
		return MORE;							\
										\
	if (one.arg1 == two.arg1)						\
	{									\
		if (one.arg2 < two.arg2)					\
			return LESS;						\
										\
		if (one.arg2 > two.arg2)					\
			return MORE;						\
	}									\
										\
	return EQUAL;								\
}

cmpbase(ipv4base, src.s_addr, dst.s_addr);
cmpbase(portbase, dst, src);
cmpbase(icmpbase, type, code);

int cmp_ipv6base(struct ipv6base one, struct ipv6base two)
{
	int res = 0;
	char one_src[INET6_ADDRSTRLEN], one_dst[INET6_ADDRSTRLEN];
	char two_src[INET6_ADDRSTRLEN], two_dst[INET6_ADDRSTRLEN];

	memset(&one_src, 0, INET6_ADDRSTRLEN);
	memset(&one_dst, 0, INET6_ADDRSTRLEN);
	memset(&two_src, 0, INET6_ADDRSTRLEN);
	memset(&two_dst, 0, INET6_ADDRSTRLEN);

	inet_ntop(AF_INET6, &one.src, one_src, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &two.src, two_src, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &one.dst, one_dst, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &two.dst, two_dst, INET6_ADDRSTRLEN);

	res = g_strcmp0(one_src, two_src);

	if (res < 0)
		return LESS;
	if (res > 0)
		return MORE;

	if (res == 0) {
		res = g_strcmp0(one_dst, two_dst);

		if (res < 0)
			return LESS;
		if (res > 0)
			return MORE;
	}

	return EQUAL;
}

/* compare flows */

#define cmpflow(type, arg1, arg2)						\
int cmp_##type(struct type *one, struct type *two)				\
{										\
	int res;								\
										\
	if ((res = cmp_##arg1(one->addrs, two->addrs)) != EQUAL)		\
		return res;							\
	if ((res = cmp_##arg2(one->base, two->base)) != EQUAL)			\
		return res;							\
										\
	if (one->reply < two->reply)						\
		return LESS;							\
	if (one->reply > two->reply)						\
		return MORE;							\
										\
	return EQUAL;								\
}

cmpflow(tcpv4flow, ipv4base, portbase);
cmpflow(udpv4flow, ipv4base, portbase);
cmpflow(icmpv4flow, ipv4base, icmpbase);
cmpflow(tcpv6flow, ipv6base, portbase);
cmpflow(udpv6flow, ipv6base, portbase);
cmpflow(icmpv6flow, ipv6base, icmpbase);

/* compare types: tcpv4, udpv4, icmpv4, tcpv6, udpv6 or icmpv6 */

#define cmpflows(type)								\
gint cmp_##type##s(gconstpointer ptr_one,					\
		   gconstpointer ptr_two,					\
		   gpointer data)						\
{										\
	struct type *one = (struct type *) ptr_one;				\
	struct type *two = (struct type *) ptr_two;				\
										\
	return cmp_##type(one, two);						\
}

cmpflows(tcpv4flow);
cmpflows(udpv4flow);
cmpflows(icmpv4flow);
cmpflows(tcpv6flow);
cmpflows(udpv6flow);
cmpflows(icmpv6flow);

/* add flows to in-memory binary-trees */

#define addflows(type)								\
gint add_##type##s(struct type *flow)						\
{										\
	gpointer gptr;								\
										\
	gptr = g_malloc0(sizeof(struct type));					\
	memcpy(gptr, flow, sizeof(struct type));				\
										\
	if (g_sequence_lookup(type##s, gptr, cmp_##type##s, NULL) == NULL)	\
		g_sequence_insert_sorted (type##s, gptr, cmp_##type##s, NULL);	\
										\
	return SUCCESS;								\
}

addflows(tcpv4flow);
addflows(udpv4flow);
addflows(icmpv4flow);
addflows(tcpv6flow);
addflows(udpv6flow);
addflows(icmpv6flow);

/* debug */

#define DEBUG

static void debug(char *string)
{
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s\n", string);
#endif
}

/* conntracker event callback */

static int event_cb(enum nf_conntrack_msg_type type,
		    struct nf_conntrack *ct,
		    void *data)
{
	short reply = 0;
	char *ip_src_str, *ip_dst_str;
	const uint8_t *family, *proto;
	const uint8_t *itype, *icode;
	const uint16_t *port_src, *port_dst;
	const uint32_t *constatus, *ipv4_src, *ipv4_dst;
	struct in_addr ipv4_src_in, ipv4_dst_in;
	struct in6_addr *ipv6_src, *ipv6_dst;
	char ipv4_src_str[INET_ADDRSTRLEN], ipv4_dst_str[INET_ADDRSTRLEN];
	char ipv6_src_str[INET6_ADDRSTRLEN], ipv6_dst_str[INET6_ADDRSTRLEN];

	/* check if flow ever got a reply from the peer */

	constatus = (uint32_t *) nfct_get_attr(ct, ATTR_STATUS);

	if(*constatus & IPS_SEEN_REPLY)
		reply = 1;

	/* skip address families other than IPv4 and IPv6 */

	family = (uint8_t *) nfct_get_attr(ct, ATTR_L3PROTO);

	switch (*family) {
	case AF_INET:
	case AF_INET6:
		break;
	default:
		debug("skipping non AF_INET/AF_INET6 traffic");
		return NFCT_CB_CONTINUE;
	}

	/* skip IP protocols other than TCP / UDP / ICMP / ICMPv6 */

	proto = (uint8_t *) nfct_get_attr(ct, ATTR_L4PROTO);

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		break;
	default:
		printf("%u\n", (unsigned short) *proto);
		debug("skipping non UDP/TCP/ICMP/ICMPv6 traffic");
		return NFCT_CB_CONTINUE;
	}

	/* netfilter: address family only attributes */

	switch (*family) {
	case AF_INET:
		ipv4_src = (in_addr_t*) nfct_get_attr(ct, ATTR_IPV4_SRC);
		ipv4_dst = (in_addr_t*) nfct_get_attr(ct, ATTR_IPV4_DST);
		ipv4_src_in.s_addr = (in_addr_t) *ipv4_src;
		ipv4_dst_in.s_addr = (in_addr_t) *ipv4_dst;
		inet_ntop(AF_INET, ipv4_src, ipv4_src_str, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, ipv4_dst, ipv4_dst_str, INET_ADDRSTRLEN);
		break;
	case AF_INET6:
		ipv6_src = (struct in6_addr*) nfct_get_attr(ct, ATTR_IPV6_SRC);
		ipv6_dst = (struct in6_addr*) nfct_get_attr(ct, ATTR_IPV6_DST);
		inet_ntop(AF_INET6, ipv6_src, ipv6_src_str, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, ipv6_dst, ipv6_dst_str, INET6_ADDRSTRLEN);
		break;
	}

	/* netfilter: protocol only attributes */

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		port_src = (uint16_t*) nfct_get_attr(ct, ATTR_PORT_SRC);
		port_dst = (uint16_t*) nfct_get_attr(ct, ATTR_PORT_DST);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		itype = (uint8_t*) nfct_get_attr(ct, ATTR_ICMP_TYPE);
		icode = (uint8_t*) nfct_get_attr(ct, ATTR_ICMP_CODE);
		break;
	}

	/* store the flows in memory for further processing */

	switch (*family) {
	case AF_INET:
		switch (*proto) {
		case IPPROTO_TCP:
		{
			struct tcpv4flow flow;
			memset(&flow, '0', sizeof(struct tcpv4flow));
			flow.addrs.src = ipv4_src_in;
			flow.addrs.dst = ipv4_dst_in;
			flow.base.src = *port_src;
			flow.base.dst = *port_dst;
			flow.reply = reply;
			add_tcpv4flows(&flow);
		}
		break;
		case IPPROTO_UDP:
		{
			struct udpv4flow flow;
			memset(&flow, '0', sizeof(struct udpv4flow));
			flow.addrs.src = ipv4_src_in;
			flow.addrs.dst = ipv4_dst_in;
			flow.base.src = *port_src;
			flow.base.dst = *port_dst;
			flow.reply = reply;
			add_udpv4flows(&flow);
		}
		break;
		case IPPROTO_ICMP:
		{
			struct icmpv4flow flow;
			memset(&flow, '0', sizeof(struct icmpv4flow));
			flow.addrs.src = ipv4_src_in;
			flow.addrs.dst = ipv4_dst_in;
			flow.base.type = *itype;
			flow.base.code = *icode;
			flow.reply = reply;
			add_icmpv4flows(&flow);
		}
		break;
		}
		break;
	case AF_INET6:
		switch (*proto) {
		case IPPROTO_TCP:
		{
			struct tcpv6flow flow;
			memset(&flow, '0', sizeof(struct tcpv6flow));
			flow.addrs.src = *ipv6_src;
			flow.addrs.dst = *ipv6_dst;
			flow.base.src = *port_src;
			flow.base.dst = *port_dst;
			flow.reply = reply;
			add_tcpv6flows(&flow);
		}
		break;
		case IPPROTO_UDP:
		{
			struct udpv6flow flow;
			memset(&flow, '0', sizeof(struct udpv6flow));
			flow.addrs.src = *ipv6_src;
			flow.addrs.dst = *ipv6_dst;
			flow.base.src = *port_src;
			flow.base.dst = *port_dst;
			flow.reply = reply;
			add_udpv6flows(&flow);
		}
		break;
		case IPPROTO_ICMPV6:
		{
			struct icmpv6flow flow;
			memset(&flow, '0', sizeof(struct icmpv6flow));
			flow.addrs.src = *ipv6_src;
			flow.addrs.dst = *ipv6_dst;
			flow.base.type = *itype;
			flow.base.code = *icode;
			flow.reply = reply;
			add_icmpv6flows(&flow);
		}
		break;
		}
		break;
	}

	return NFCT_CB_CONTINUE;
}

// display (temporary)

void printa_tcpv4flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	struct tcpv4flow *flow = data;

	const uint32_t *ipv4_src, *ipv4_dst;
	char ipv4_src_str[INET_ADDRSTRLEN], ipv4_dst_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(flow->addrs.src), ipv4_src_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(flow->addrs.dst), ipv4_dst_str, INET_ADDRSTRLEN);

	printf("[%d] TCPv4  src = %s (port=%u) to ", times++, ipv4_src_str, ntohs(flow->base.src));
	printf("dst = %s (port=%u)%s\n", ipv4_dst_str, (int) ntohs(flow->base.dst), flow->reply ? " (R)" : "");
}

void printa_udpv4flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	struct udpv4flow *flow = data;

	const uint32_t *ipv4_src, *ipv4_dst;
	char ipv4_src_str[INET_ADDRSTRLEN], ipv4_dst_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(flow->addrs.src), ipv4_src_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(flow->addrs.dst), ipv4_dst_str, INET_ADDRSTRLEN);

	printf("[%d] UDPv4  src = %s (port=%u) to ", times++, ipv4_src_str, ntohs(flow->base.src));
	printf("dst = %s (port=%u)\n", ipv4_dst_str, (int) ntohs(flow->base.dst));
}

void printa_icmpv4flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	struct icmpv4flow *flow = data;

	const uint32_t *ipv4_src, *ipv4_dst;
	char ipv4_src_str[INET_ADDRSTRLEN], ipv4_dst_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(flow->addrs.src), ipv4_src_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(flow->addrs.dst), ipv4_dst_str, INET_ADDRSTRLEN);

	printf("[%d] ICMPv4 src = %s to ", times++, ipv4_src_str);
	printf("dst = %s - (type=%u | code=%u)%s\n", ipv4_dst_str, (int) flow->base.type, (int) flow->base.code, flow->reply ? " (R)" : "");
}

void printa_tcpv6flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	struct tcpv6flow *flow = data;

	char ipv6_src_str[INET6_ADDRSTRLEN], ipv6_dst_str[INET6_ADDRSTRLEN];

	memset(&ipv6_src_str, 0, INET6_ADDRSTRLEN);
	memset(&ipv6_dst_str, 0, INET6_ADDRSTRLEN);

	inet_ntop(AF_INET6, &(flow->addrs.src), ipv6_src_str, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(flow->addrs.dst), ipv6_dst_str, INET6_ADDRSTRLEN);

	printf("[%d] TCPv6  src = %s (port=%u) to ", times++, ipv6_src_str, ntohs(flow->base.src));
	printf("dst = %s (port=%u)%s\n", ipv6_dst_str, (int) ntohs(flow->base.dst), flow->reply ? " (R)" : "");
}

void printa_udpv6flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	struct udpv6flow *flow = data;

	char ipv6_src_str[INET6_ADDRSTRLEN], ipv6_dst_str[INET6_ADDRSTRLEN];

	memset(&ipv6_src_str, 0, INET6_ADDRSTRLEN);
	memset(&ipv6_dst_str, 0, INET6_ADDRSTRLEN);

	inet_ntop(AF_INET6, &(flow->addrs.src), ipv6_src_str, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(flow->addrs.dst), ipv6_dst_str, INET6_ADDRSTRLEN);

	printf("[%d] UDPv6  src = %s (port=%u) to ", times++, ipv6_src_str, ntohs(flow->base.src));
	printf("dst = %s (port=%u)\n", ipv6_dst_str, (int) ntohs(flow->base.dst));
}

void printa_icmpv6flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	struct icmpv6flow *flow = data;

	char ipv6_src_str[INET6_ADDRSTRLEN], ipv6_dst_str[INET6_ADDRSTRLEN];

	memset(&ipv6_src_str, 0, INET6_ADDRSTRLEN);
	memset(&ipv6_dst_str, 0, INET6_ADDRSTRLEN);

	inet_ntop(AF_INET6, &(flow->addrs.src), ipv6_src_str, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &(flow->addrs.dst), ipv6_dst_str, INET6_ADDRSTRLEN);

	printf("[%d] ICMPv6 src = %s to ", times++, ipv6_src_str);
	printf("dst = %s - (type=%u | code=%u)%s\n", ipv6_dst_str, (int) flow->base.type, (int) flow->base.code, flow->reply ? " (R)" : "");
}

// cleanup

void cleanup(void)
{
	g_sequence_foreach(tcpv4flows, printa_tcpv4flows, NULL);
	g_sequence_foreach(udpv4flows, printa_udpv4flows, NULL);
	g_sequence_foreach(icmpv4flows, printa_icmpv4flows, NULL);

	g_sequence_foreach(tcpv6flows, printa_tcpv6flows, NULL);
	g_sequence_foreach(udpv6flows, printa_udpv6flows, NULL);
	g_sequence_foreach(icmpv6flows, printa_icmpv6flows, NULL);

	g_sequence_free(tcpv4flows);
	g_sequence_free(udpv4flows);
	g_sequence_free(icmpv4flows);

	g_sequence_free(tcpv6flows);
	g_sequence_free(udpv6flows);
	g_sequence_free(icmpv6flows);
}

void handler(int what)
{
	cleanup();

	exit(SUCCESS);
}

// main

int main(void)
{
	int ret = 0;
	struct nfct_handle *h;

	signal(SIGINT, handler);

	tcpv4flows = g_sequence_new(NULL); // TODO: create a destroy function to free items
	udpv4flows = g_sequence_new(NULL);
	icmpv4flows = g_sequence_new(NULL);

	tcpv6flows = g_sequence_new(NULL);
	udpv6flows = g_sequence_new(NULL);
	icmpv6flows = g_sequence_new(NULL);

	h = nfct_open(CONNTRACK, NF_NETLINK_CONNTRACK_NEW | NF_NETLINK_CONNTRACK_UPDATE);
	if (!h) {
		perror("nfct_open");
		ret = EXIT_FAILURE;
		goto endclean;
	}

	nfct_callback_register(h, NFCT_T_ALL, event_cb, NULL);

	ret |= nfct_catch(h);

	ret |= nfct_close(h);

endclean:

	cleanup();

	exit(ret);
}

