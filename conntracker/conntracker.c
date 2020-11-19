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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>

#include <gmodule.h>

#define SUCCESS 0
#define ERROR -1

#define LESS -1
#define EQUAL 0
#define MORE 1

struct ipv4base {
	struct in_addr src;
	struct in_addr dst;
};

struct ipv6base {
	struct in6_addr src;
	struct in6_addr dst;
};

struct portbase {
	uint16_t src;
	uint16_t dst;
};

struct icmpbase {
	uint8_t type;
	uint8_t code;
};

/* IPv4 netfilter flows */

struct tcpv4flow {
	struct ipv4base addrs;
	struct portbase ports;
	uint8_t reply;
};

struct udpv4flow {
	struct ipv4base addrs;
	struct portbase ports;
	uint8_t reply;
};

struct icmpv4flow {
	struct ipv4base addrs;
	struct icmpbase base;
	uint8_t reply;
};

/* IPv6 netfilter flows */

struct tcpv6flow {
	struct ipv6base addrs;
	struct portbase ports;
	uint8_t reply;
};

struct udpv6flow {
	struct ipv6base addrs;
	struct portbase ports;
	uint8_t reply;
};

struct icmpv6flow {
	struct ipv6base addrs;
	struct icmpbase base;
	uint8_t reply;
};

/* Sequences stored in memory */

GSequence *tcpv4flows;
GSequence *udpv4flows;
GSequence *icmpv4flows;

GSequence *tcpv6flows;
GSequence *udpv6flows;
GSequence *icmpv6flows;

/* Compare functions to keep binary trees balanced */

#define MORE_OR_LESS(one, two)			\
{						\
	if (one < two) { return LESS; }		\
	if (one > two) { return MORE; }		\
}

int cmp_ipv4base(struct ipv4base one, struct ipv4base two)
{
	/* source address sort, then dest address sort */

	MORE_OR_LESS(one.src.s_addr, two.src.s_addr);

	if (one.src.s_addr == two.src.s_addr)
		MORE_OR_LESS(one.dst.s_addr, two.dst.s_addr);

	return EQUAL;
}

int cmp_ipv6base(struct ipv6base one, struct ipv6base two)
{
	/* IPv6 is 128-bit, sort it as strings, first source then dest */

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

	MORE_OR_LESS(res, 0);

	if (res == 0) {
		res = g_strcmp0(one_dst, two_dst);
		MORE_OR_LESS(one_dst, two_dst);
	}

	return EQUAL;
}

int cmp_portbase(struct portbase one, struct portbase two)
{
	/* dest port sort, then src port sort */

	MORE_OR_LESS(one.dst, two.dst);

	if (one.dst == two.dst)
		MORE_OR_LESS(one.src, two.src);

	return EQUAL;
}

int cmp_icmpbase(struct icmpbase one, struct icmpbase two)
{
	/* icmp type sort, then icmp code sort */

	MORE_OR_LESS(one.type, two.type);

	if (one.type == two.type)
		MORE_OR_LESS(one.code, two.code);

	return EQUAL;
}

/* Compare functions using the base structures comparison */

	/* INET */

int cmp_tcpv4flow(struct tcpv4flow *one, struct tcpv4flow *two)
{
	int res;

	if ((res = cmp_ipv4base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->ports, two->ports)) != EQUAL)
		return res;

	MORE_OR_LESS(one->reply, two->reply);

	return EQUAL;
}

int cmp_udpv4flow(struct udpv4flow *one, struct udpv4flow *two)
{
	int res;

	if ((res = cmp_ipv4base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->ports, two->ports)) != EQUAL)
		return res;

	MORE_OR_LESS(one->reply, two->reply);

	return EQUAL;
}

int cmp_icmpv4flow(struct icmpv4flow *one, struct icmpv4flow *two)
{
	int res;

	if ((res = cmp_ipv4base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_icmpbase(one->base, two->base)) != EQUAL)
		return res;

	MORE_OR_LESS(one->reply, two->reply);

	return EQUAL;
}

int cmp_tcpv6flow(struct tcpv6flow *one, struct tcpv6flow *two)
{
	int res;

	if ((res = cmp_ipv6base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->ports, two->ports)) != EQUAL)
		return res;

	MORE_OR_LESS(one->reply, two->reply);

	return EQUAL;
}

int cmp_udpv6flow(struct udpv6flow *one, struct udpv6flow *two)
{
	int res;

	if ((res = cmp_ipv6base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->ports, two->ports)) != EQUAL)
		return res;

	MORE_OR_LESS(one->reply, two->reply);

	return EQUAL;
}

int cmp_icmpv6flow(struct icmpv6flow *one, struct icmpv6flow *two)
{
	int res;

	if ((res = cmp_ipv6base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_icmpbase(one->base, two->base)) != EQUAL)
		return res;

	MORE_OR_LESS(one->reply, two->reply);

	return EQUAL;
}

/* Compare functions: types are tcpv4, udpv4, icmpv4, tcpv6, udpv6 or icmpv6 */

#define cmpflows(type)					\
gint cmp_##type##s(gconstpointer ptr_one,		\
		   gconstpointer ptr_two,		\
		   gpointer data)			\
{							\
	struct type *one = (struct type *) ptr_one;	\
	struct type *two = (struct type *) ptr_two;	\
							\
	return cmp_##type(one, two);			\
}

cmpflows(tcpv4flow);
cmpflows(udpv4flow);
cmpflows(icmpv4flow);

cmpflows(tcpv6flow);
cmpflows(udpv6flow);
cmpflows(icmpv6flow);

/* balanced binary trees keeping the flows in memory */

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

/* Default debug */

#define DEBUG

static void debug(char *string)
{
#ifdef DEBUG
	fprintf(stderr, "DEBUG: %s\n", string);
#endif
}

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
			flow.ports.src = *port_src;
			flow.ports.dst = *port_dst;
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
			flow.ports.src = *port_src;
			flow.ports.dst = *port_dst;
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
			flow.ports.src = *port_src;
			flow.ports.dst = *port_dst;
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
			flow.ports.src = *port_src;
			flow.ports.dst = *port_dst;
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

	printf("[%d] TCPv4  src = %s (port=%u) to ", times++, ipv4_src_str, ntohs(flow->ports.src));
	printf("dst = %s (port=%u)%s\n", ipv4_dst_str, (int) ntohs(flow->ports.dst), flow->reply ? " (R)" : "");
}

void printa_udpv4flows(gpointer data, gpointer user_data)
{
	static int times = 0;
	struct udpv4flow *flow = data;

	const uint32_t *ipv4_src, *ipv4_dst;
	char ipv4_src_str[INET_ADDRSTRLEN], ipv4_dst_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(flow->addrs.src), ipv4_src_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(flow->addrs.dst), ipv4_dst_str, INET_ADDRSTRLEN);

	printf("[%d] UDPv4  src = %s (port=%u) to ", times++, ipv4_src_str, ntohs(flow->ports.src));
	printf("dst = %s (port=%u)\n", ipv4_dst_str, (int) ntohs(flow->ports.dst));
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

	printf("[%d] TCPv6  src = %s (port=%u) to ", times++, ipv6_src_str, ntohs(flow->ports.src));
	printf("dst = %s (port=%u)%s\n", ipv6_dst_str, (int) ntohs(flow->ports.dst), flow->reply ? " (R)" : "");
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

	printf("[%d] UDPv6  src = %s (port=%u) to ", times++, ipv6_src_str, ntohs(flow->ports.src));
	printf("dst = %s (port=%u)\n", ipv6_dst_str, (int) ntohs(flow->ports.dst));
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

