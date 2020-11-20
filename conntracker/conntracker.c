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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA  02110-1301, USA.
 */

#include "conntracker.h"

/* helper functions */

gchar *ipv4_str(struct in_addr *addr)
{
	gchar temp[INET_ADDRSTRLEN];

	memset(temp, 0, INET_ADDRSTRLEN);
	inet_ntop(AF_INET, addr, temp, INET_ADDRSTRLEN);

	return g_strdup(temp);
}

gchar *ipv6_str(struct in6_addr *addr)
{
	gchar temp[INET6_ADDRSTRLEN];

	memset(temp, 0, INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, addr, temp, INET6_ADDRSTRLEN);

	return g_strdup(temp);
}

/* seqs stored in memory */

GSequence *tcpv4flows;
GSequence *udpv4flows;
GSequence *icmpv4flows;
GSequence *tcpv6flows;
GSequence *udpv6flows;
GSequence *icmpv6flows;

void cleanflow(gpointer data)
{
	g_free(data);
}

/* functions used to sort existing sequences based on its elements */

#define cmpbase(type, arg1, arg2)								\
gint cmp_##type(struct type one, struct type two)						\
{												\
	if (one.arg1 < two.arg1)								\
		return LESS;									\
												\
	if (one.arg1 > two.arg1)								\
		return MORE;									\
												\
	if (one.arg1 == two.arg1)								\
	{											\
		if (one.arg2 < two.arg2)							\
			return LESS;								\
												\
		if (one.arg2 > two.arg2)							\
			return MORE;								\
	}											\
												\
	return EQUAL;										\
}

cmpbase(ipv4base, src.s_addr, dst.s_addr);
cmpbase(portbase, dst, src);
cmpbase(icmpbase, type, code);

int cmp_ipv6base(struct ipv6base one, struct ipv6base two)
{
	/* ipv6 sorting done through its string as its easier */

	int res = 0;
	gchar *str1, *str2;

	str1 = ipv6_str(&one.src);
	str2 = ipv6_str(&two.src);

	res = g_strcmp0(str1, str2);

	g_free(str1);
	g_free(str2);

	if (res < 0)
		return LESS;
	if (res > 0)
		return MORE;

	if (res == 0) {

		str1 = ipv6_str(&one.dst);
		str2 = ipv6_str(&two.dst);

		res = g_strcmp0(str1, str2);

		g_free(str1);
		g_free(str2);

		if (res < 0)
			return LESS;
		if (res > 0)
			return MORE;
	}

	return EQUAL;
}

/* call proper comparison/sorting functions based on given type */

#define cmpflow(type, arg1, arg2)								\
int cmp_##type(struct type *one, struct type *two)						\
{												\
	int res;										\
												\
	if ((res = cmp_##arg1(one->addrs, two->addrs)) != EQUAL)				\
		return res;									\
	if ((res = cmp_##arg2(one->base, two->base)) != EQUAL)					\
		return res;									\
												\
	if (one->reply < two->reply)								\
		return LESS;									\
	if (one->reply > two->reply)								\
		return MORE;									\
												\
	return EQUAL;										\
}

cmpflow(tcpv4flow, ipv4base, portbase);
cmpflow(udpv4flow, ipv4base, portbase);
cmpflow(icmpv4flow, ipv4base, icmpbase);
cmpflow(tcpv6flow, ipv6base, portbase);
cmpflow(udpv6flow, ipv6base, portbase);
cmpflow(icmpv6flow, ipv6base, icmpbase);

/* compare two given flows (tcpv4, udpv4, icmpv4, tcpv6, udpv6 or icmpv6) */

#define cmpflows(type)										\
gint cmp_##type##s(gconstpointer ptr_one,							\
		   gconstpointer ptr_two,							\
		   gpointer data)								\
{												\
	struct type *one = (struct type *) ptr_one;						\
	struct type *two = (struct type *) ptr_two;						\
												\
	return cmp_##type(one, two);								\
}

cmpflows(tcpv4flow);
cmpflows(udpv4flow);
cmpflows(icmpv4flow);
cmpflows(tcpv6flow);
cmpflows(udpv6flow);
cmpflows(icmpv6flow);

/* add flows based on given type */

#define addflows(type)										\
gint add_##type##s(struct type *flow)								\
{												\
	struct type *temp;									\
	GSequenceIter *found, *found2;								\
												\
	temp = g_malloc0(sizeof(struct type));							\
	memcpy(temp, flow, sizeof(struct type));						\
												\
	found = g_sequence_lookup(type##s, temp, cmp_##type##s, NULL);				\
												\
	if (found == NULL) { 									\
		switch (temp->reply) {								\
		case 0:										\
			temp->reply = 1;							\
			found2 = g_sequence_lookup(type##s, temp, cmp_##type##s, NULL); 	\
			temp->reply = 0;							\
			if (found2 == NULL) {							\
				g_sequence_insert_sorted(type##s, temp, cmp_##type##s, NULL);	\
				goto inserted;							\
			}									\
			break;									\
		case 1:										\
			temp->reply = 0;							\
			found2 = g_sequence_lookup(type##s, temp, cmp_##type##s, NULL); 	\
			temp->reply = 1;							\
			if (found2 != NULL) {							\
				g_sequence_remove(found2);					\
				g_sequence_insert_sorted(type##s, temp, cmp_##type##s, NULL);	\
				goto inserted;							\
			}									\
			break;									\
		}										\
	}											\
												\
	g_free(temp); 										\
												\
inserted:											\
	return SUCCESS;										\
}

addflows(tcpv4flow);
addflows(udpv4flow);
addflows(icmpv4flow);
addflows(tcpv6flow);
addflows(udpv6flow);
addflows(icmpv6flow);

/* call addflows */

#define addflow(arg1, arg2, arg3, arg4)								\
gint add##arg1(struct arg2 s, struct arg2 d,							\
		uint16_t ps, uint16_t pd, uint8_t r)						\
{												\
	struct arg1 flow;									\
	memset(&flow, '0', sizeof(struct arg1));						\
												\
	flow.addrs.src = s;									\
	flow.addrs.dst = d;									\
	flow.base.arg3 = ps;									\
	flow.base.arg4 = pd;									\
	flow.reply = r;										\
												\
	add_##arg1##s(&flow);									\
												\
	return SUCCESS;										\
}

addflow(tcpv4flow, in_addr, src, dst);
addflow(udpv4flow, in_addr, src, dst);
addflow(icmpv4flow, in_addr, type, code);
addflow(tcpv6flow, in6_addr, src, dst);
addflow(udpv6flow, in6_addr, src, dst);
addflow(icmpv6flow, in6_addr, type, code);

/* display the flows */

#define printa(arg1, arg2, ...) \
void printa_##arg1##s(gpointer data, gpointer user_data)					\
{												\
	static int times = 0;									\
	gchar *src, *dst;									\
	struct arg1 *flow = data;								\
												\
	src = arg2##_str(&flow->addrs.src);							\
	dst = arg2##_str(&flow->addrs.dst);							\
												\
	printf(__VA_ARGS__);									\
												\
	g_free(src);										\
	g_free(dst);										\
}

printa(tcpv4flow, ipv4, " TCPv4 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++,
		src, ntohs(flow->base.src), dst, ntohs(flow->base.dst),
		flow->reply ? " (confirmed)" : "");

printa(udpv4flow, ipv4, " UDPv4 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++,
		src, ntohs(flow->base.src), dst, ntohs(flow->base.dst),
		flow->reply ? " (confirmed)" : "");

printa(icmpv4flow, ipv4, "ICMPv4 [%12d] src = %s to dst = %s (type=%u | code=%u)%s\n", times++,
		src, dst, (uint8_t) ntohs(flow->base.type), (uint8_t) ntohs(flow->base.code),
		flow->reply ? " (confirmed)" : "");

printa(tcpv6flow, ipv6, " TCPv6 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++,
		src, ntohs(flow->base.src), dst, ntohs(flow->base.dst),
		flow->reply ? " (confirmed)" : "");

printa(udpv6flow, ipv6, " UDPv6 [%12d] src = %s (port=%u) to dst = %s (port=%u)%s\n", times++,
		src, ntohs(flow->base.src), dst, ntohs(flow->base.dst),
		flow->reply ? " (confirmed)" : "");

printa(icmpv6flow, ipv6, "ICMPv6 [%12d] src = %s to dst = %s (type=%u | code=%u)%s\n", times++,
		src, dst, (uint8_t) ntohs(flow->base.type), (uint8_t) ntohs(flow->base.code),
		flow->reply ? " (confirmed)" : "");

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

	uint8_t *family = NULL, *proto = NULL;
	uint16_t *port_src = NULL, *port_dst = NULL;
	uint8_t *itype = NULL, *icode = NULL;
	uint32_t *constatus = NULL;
	struct in_addr ipv4_src_in, ipv4_dst_in;
	struct in6_addr *ipv6_src_in = NULL, *ipv6_dst_in = NULL;
	uint16_t privport = htons(1024);

	/* initialize to avoid compiler warnings */

	memset(&ipv4_src_in, 0, sizeof(struct in_addr));
	memset(&ipv4_dst_in, 0, sizeof(struct in_addr));

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
		debug("skipping non UDP/TCP/ICMP/ICMPv6 traffic");
		return NFCT_CB_CONTINUE;
	}

	/* netfilter: address family only attributes */

	switch (*family) {
	case AF_INET:
		ipv4_src_in.s_addr = *((in_addr_t *) nfct_get_attr(ct, ATTR_IPV4_SRC));
		ipv4_dst_in.s_addr = *((in_addr_t *) nfct_get_attr(ct, ATTR_IPV4_DST));
		break;
	case AF_INET6:
		ipv6_src_in = (struct in6_addr *) nfct_get_attr(ct, ATTR_IPV6_SRC);
		ipv6_dst_in = (struct in6_addr *) nfct_get_attr(ct, ATTR_IPV6_DST);
		break;
	}

	/* netfilter: protocol only attributes */

	switch (*proto) {
	case IPPROTO_TCP:
	case IPPROTO_UDP:
		port_src = (uint16_t *) nfct_get_attr(ct, ATTR_PORT_SRC);
		port_dst = (uint16_t *) nfct_get_attr(ct, ATTR_PORT_DST);
		/* all unprivileged source ports logged as 1024 */
		if ((int) ntohs(*port_src) > 1024)
			port_src = &privport;
		break;
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		itype = (uint8_t *) nfct_get_attr(ct, ATTR_ICMP_TYPE);
		icode = (uint8_t *) nfct_get_attr(ct, ATTR_ICMP_CODE);
		break;
	}

	/* store the flows in memory for further processing */

	switch (*family) {
	case AF_INET:
		switch (*proto) {
		case IPPROTO_TCP:
			addtcpv4flow(ipv4_src_in, ipv4_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_UDP:
			addudpv4flow(ipv4_src_in, ipv4_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_ICMP:
			addicmpv4flow(ipv4_src_in, ipv4_dst_in, *itype, *icode, reply);
			break;
		}
		break;
	case AF_INET6:
		switch (*proto) {
		case IPPROTO_TCP:
			addtcpv6flow(*ipv6_src_in, *ipv6_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_UDP:
			addudpv6flow(*ipv6_src_in, *ipv6_dst_in, *port_src, *port_dst, reply);
			break;
		case IPPROTO_ICMPV6:
			addicmpv6flow(*ipv6_src_in, *ipv6_dst_in, *itype, *icode, reply);
			break;
		}
		break;
	}

	return NFCT_CB_CONTINUE;
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

	tcpv4flows = g_sequence_new(cleanflow);
	udpv4flows = g_sequence_new(cleanflow);
	icmpv4flows = g_sequence_new(cleanflow);
	tcpv6flows = g_sequence_new(cleanflow);
	udpv6flows = g_sequence_new(cleanflow);
	icmpv6flows = g_sequence_new(cleanflow);

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

