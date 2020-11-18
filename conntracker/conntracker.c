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
};

struct icmpv4flow {
	struct ipv4base addrs;
	struct icmpbase base;
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
};

struct icmpv6flow {
	struct ipv6base addrs;
	struct icmpbase base;
};

/* Sequences stored in memory */

GSequence *tcpv4flows;
GSequence *udpv4flows;
GSequence *icmpv4flows;

GSequence *tcpv6flows;
GSequence *udpv6flows;
GSequence *icmpv6flows;

/* Compare functions to keep binary trees balanced */

int cmp_ipv4base(struct ipv4base one, struct ipv4base two)
{
	/* source address sort, then dest address sort */

	if (one.src.s_addr < two.src.s_addr)
		return LESS;
	if (one.src.s_addr > two.src.s_addr)
		return MORE;

	if (one.src.s_addr == two.src.s_addr)
	{
		if (one.dst.s_addr < two.dst.s_addr)
			return LESS;
		if (one.dst.s_addr > two.dst.s_addr)
			return MORE;
	}

	return EQUAL;
}

int cmp_ipv6base(struct ipv6base one, struct ipv6base two)
{

}

int cmp_portbase(struct portbase one, struct portbase two)
{
	/* dest port sort, then src port sort */

	if (one.dst < two.dst)
		return LESS;
	if (one.dst > two.dst)
		return MORE;

	if (one.dst == two.dst)
	{
		if (one.src < two.src)
			return LESS;
		if (one.src > two.src)
			return MORE;
	}

	return EQUAL;
}

int cmp_icmpbase(struct icmpbase one, struct icmpbase two)
{

}

int cmp_tcpv4flow(struct tcpv4flow *one, struct tcpv4flow *two)
{
	int res;

	if ((res = cmp_ipv4base(one->addrs, two->addrs)) != EQUAL)
		return res;
	if ((res = cmp_portbase(one->ports, two->ports)) != EQUAL)
		return res;

	if (one->reply < two->reply)
		return LESS;
	if (one->reply > two->reply)
		return MORE;

	return EQUAL;
}

// int cmp_udpv4flow(struct udpv4flow one, struct udpv4flow two);
// int cmp_icmpv4flow(struct icmpv4flow one, struct icmpv4flow two);
//
// int cmp_tcpv6flow(struct tcpv6flow one, struct tcpv6flow two);
// int cmp_udpv6flow(struct udpv6flow one, struct udpv6flow two)
// int cmp_icmpv6flow(struct icmpv6flow one, struct icmpv6flow two);

/* Compare functions */

gint cmp_tcpv4flows(gconstpointer ptr_one, gconstpointer ptr_two, gpointer data)
{
	struct tcpv4flow *one = (struct tcpv4flow *) ptr_one;
	struct tcpv4flow *two = (struct tcpv4flow *) ptr_two;

	return cmp_tcpv4flow(one, two);
};

/* balanced binary trees keeping the flows in memory */

int add_tcpv4flows(struct tcpv4flow *flow)
{
	gpointer gptr;

	if (tcpv4flows == NULL)
		return ERROR;

	gptr = g_malloc0(sizeof(struct tcpv4flow));
	memcpy(gptr, flow, sizeof(struct tcpv4flow));

	if (g_sequence_lookup(tcpv4flows, gptr, cmp_tcpv4flows, NULL) == NULL)
		g_sequence_insert_sorted (tcpv4flows, gptr, cmp_tcpv4flows, NULL);

	return SUCCESS;
};

int add_udpv4flows(struct udpv4flow *flow)
{
	gpointer gptr;

	if (udpv4flows == NULL)
		return ERROR;

	gptr = g_malloc0(sizeof(struct udpv4flow));
	memcpy(gptr, flow, sizeof(struct udpv4flow));
	g_sequence_append(udpv4flows, gptr);

	return SUCCESS;
};

int add_icmpv4flows(struct icmpv4flow *flow)
{
	gpointer gptr;

	if (icmpv4flows == NULL)
		return ERROR;

	gptr = g_malloc0(sizeof(struct icmpv4flow));
	memcpy(gptr, flow, sizeof(struct icmpv4flow));
	g_sequence_append(icmpv4flows, gptr);

	return SUCCESS;
};

int add_tcpv6flows(struct tcpv6flow *flow)
{
	gpointer gptr;

	if (tcpv6flows == NULL)
		return ERROR;

	gptr = g_malloc0(sizeof(struct tcpv6flow));
	memcpy(gptr, flow, sizeof(struct tcpv6flow));
	g_sequence_append(tcpv6flows, gptr);

	return SUCCESS;
};

int add_udpv6flows(struct udpv6flow *flow)
{
	gpointer gptr;

	if (udpv6flows == NULL)
		return ERROR;

	gptr = g_malloc0(sizeof(struct udpv6flow));
	memcpy(gptr, flow, sizeof(struct udpv6flow));
	g_sequence_append(udpv6flows, gptr);

	return SUCCESS;
};

int add_icmpv6flows(struct icmpv6flow *flow)
{
	gpointer gptr;

	if (icmpv6flows == NULL)
		return ERROR;

	gptr = g_malloc0(sizeof(struct icmpv6flow));
	memcpy(gptr, flow, sizeof(struct icmpv6flow));
	g_sequence_append(icmpv6flows, gptr);

	return SUCCESS;
};

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
	const uint16_t *port_src, *port_dst;
	const uint32_t *constatus, *ipv4_src, *ipv4_dst;
	struct in_addr ipv4_src_in, ipv4_dst_in;
	struct in6_addr *ipv6_src, *ipv6_dst;
	char ipv4_src_str[INET_ADDRSTRLEN], ipv4_dst_str[INET_ADDRSTRLEN];
        char ipv6_src_str[INET6_ADDRSTRLEN], ipv6_dst_str[INET6_ADDRSTRLEN];

	// keep only new conntracks when replies were seen

	constatus = (uint32_t *) nfct_get_attr(ct, ATTR_STATUS);

	if(*constatus & IPS_SEEN_REPLY)
		reply = 1;

	// skip address families other than IPv4 and IPv6

	family = (uint8_t *) nfct_get_attr(ct, ATTR_L3PROTO);

	switch (*family) {
	case AF_INET:
	case AF_INET6:
		break;
	default:
		debug("skipping non AF_INET/AF_INET6 traffic");
		return NFCT_CB_CONTINUE;
	}

	// skip IP protocols other than TCP / UDP / ICMP / ICMPv6

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

	// netfilter: address family attributes

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

	// netfilter: protocol attributes

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		port_src = (uint16_t*) nfct_get_attr(ct, ATTR_PORT_SRC);
		port_dst = (uint16_t*) nfct_get_attr(ct, ATTR_PORT_DST);
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		break;
	}

	// store the flows

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
			add_udpv4flows(&flow);
		}
		break;
		case IPPROTO_ICMP:
		{
			struct icmpv4flow flow;
			memset(&flow, '0', sizeof(struct icmpv4flow));
			flow.addrs.src = ipv4_src_in;
			flow.addrs.dst = ipv4_dst_in;
			// missing type
			// missing code
			add_icmpv4flows(&flow);
		}
			break;
		}

		break;
	case AF_INET6:
		switch (*proto) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
		case IPPROTO_ICMP:
			break;
		}

		break;
	}

	// display

	switch (*family) {
	case AF_INET:
		ip_src_str = ipv4_src_str;
		ip_dst_str = ipv4_dst_str;
		break;
	case AF_INET6:
		ip_src_str = ipv6_src_str;
		ip_dst_str = ipv6_dst_str;
		break;
	}

	switch (*proto) {
	case IPPROTO_TCP:
		printf("TCP  (%d) src = %s to ", type, ip_src_str);
		printf("dst = %s (port=%u)%s\n", ip_dst_str, (int) ntohs(*port_dst), reply ? " (R)" : "");
		break;
	case IPPROTO_UDP:
		printf("UDP  (%d) src = %s to ", type, ip_src_str);
		printf("dst = %s (port=%u)%s\n", ip_dst_str, (int) ntohs(*port_dst), reply ? " (R)" : "");
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		printf("ICMP (%d) src = %s to ", type, ip_src_str);
		printf("dst = %s\n", ip_dst_str);
		break;
	}

	return NFCT_CB_CONTINUE;
}

void printa_tcpv4flows(gpointer data, gpointer user_data) {

	static int times = 0;
	struct tcpv4flow *flow = data;

	const uint32_t *ipv4_src, *ipv4_dst;
	char ipv4_src_str[INET_ADDRSTRLEN], ipv4_dst_str[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &(flow->addrs.src), ipv4_src_str, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, &(flow->addrs.dst), ipv4_dst_str, INET_ADDRSTRLEN);

	printf("(%d) TCPv4 src = %s to ", times++, ipv4_src_str);
	printf("dst = %s (port=%u)%s\n", ipv4_dst_str, (int) ntohs(flow->ports.dst), flow->reply ? " (R)" : "");

}

void cleanup(void)
{
	g_sequence_foreach(tcpv4flows, printa_tcpv4flows, NULL);

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

	h = nfct_open(CONNTRACK, NFCT_ALL_CT_GROUPS);
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

