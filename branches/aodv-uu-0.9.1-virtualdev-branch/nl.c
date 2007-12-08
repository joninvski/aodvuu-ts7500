/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University and Ericsson AB.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * Author: Erik Nordström, <erik.nordstrom@it.uu.se>
 * 
 *****************************************************************************/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/rtnetlink.h>

#include "defs.h"
#include "lnx/kaodv-netlink.h"
#include "debug.h"
#include "aodv_rreq.h"
#include "aodv_timeout.h"
#include "routing_table.h"
#include "aodv_hello.h"
#include "params.h"
#include "aodv_socket.h"
#include "aodv_rerr.h"

/* Implements a Netlink socket communication channel to the kernel. Route
 * information and refresh messages are passed. */

static int nlsock, rtnlsock;
static struct sockaddr_nl local;
static struct sockaddr_nl peer;

static void nl_callback(int sock);

extern int llfeedback, active_route_timeout, qual_threshold, internet_gw_mode,
    wait_on_reboot;
extern struct timer worb_timer;

#define BUFLEN 256

void nl_init(void)
{
	int status;

	nlsock = socket(PF_NETLINK, SOCK_RAW, NETLINK_AODV);
	
	if (nlsock < 0) {
		perror("Unable to create netlink socket");
		exit(-1);
	}
	
	rtnlsock = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	
	if (rtnlsock < 0) {
		perror("Unable to create netlink socket");
		exit(-1);
	}
	
	memset(&local, 0, sizeof(struct sockaddr_nl));
	local.nl_family = AF_NETLINK;
	local.nl_pid = getpid();
	local.nl_groups = AODVGRP_NOTIFY;

	memset(&peer, 0, sizeof(struct sockaddr_nl));
	peer.nl_family = AF_NETLINK;
	peer.nl_pid = 0;
	peer.nl_groups = 0;

	status = bind(nlsock, (struct sockaddr *)&local, sizeof(local));
	
	if (status == -1) {
		perror("Bind failed");
		exit(-1);
	}
	
	local.nl_groups = RTMGRP_NOTIFY | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
	
	status = bind(rtnlsock, (struct sockaddr *)&local, sizeof(local));
	
	if (status == -1) {
		perror("Bind failed");
		exit(-1);
	}

	if (attach_callback_func(nlsock, nl_callback) < 0) {
		alog(LOG_ERR, 0, __FUNCTION__, "Could not attach callback.");
	}

	if (attach_callback_func(rtnlsock, nl_callback) < 0) {
		alog(LOG_ERR, 0, __FUNCTION__, "Could not attach callback.");
	}
}

void nl_cleanup(void)
{
	close(nlsock);
}

static void nl_callback(int sock)
{
	int len, attrlen;
	socklen_t addrlen;
	struct nlmsghdr *nlm;
	struct nlmsgerr *nlmerr;
	char buf[BUFLEN];
	struct in_addr dest_addr, src_addr;	
	struct ifaddrmsg *ifm;
	struct rtattr *rta;
	kaodv_rt_msg_t *m;
	rt_table_t *rt, *fwd_rt, *rev_rt = NULL;
		
	addrlen = sizeof(peer);


	len = recvfrom(sock, buf, BUFLEN, 0, (struct sockaddr *)&peer, &addrlen);

	if (len <= 0)
		return;
	
	nlm = (struct nlmsghdr *)buf;

	switch (nlm->nlmsg_type) {
	case NLMSG_ERROR:
		nlmerr = NLMSG_DATA(nlm);
		if (nlmerr->error == 0) {
			DEBUG(LOG_DEBUG, 0, "NLMSG_ACK");
		} else
			DEBUG(LOG_DEBUG, 0, "NLMSG_ERROR, error=%d", 
			      nlmerr->error);
		break;
	case RTM_NEWLINK:
		DEBUG(LOG_DEBUG, 0, "RTM_NEWADDR");
		break;
	case RTM_NEWADDR:
		DEBUG(LOG_DEBUG, 0, "RTM_NEWADDR");

		ifm = NLMSG_DATA(nlm);

		rta = (struct rtattr *)((char *)ifm + sizeof(ifm));
		
		attrlen = nlm->nlmsg_len - 
			sizeof(struct nlmsghdr) - 
			sizeof(struct ifaddrmsg);
		
		for (; RTA_OK(rta, attrlen); rta = RTA_NEXT(rta, attrlen)) {

			if (rta->rta_type == IFA_ADDRESS) {
				struct in_addr ifaddr;
				
				memcpy(&ifaddr, RTA_DATA(rta), RTA_PAYLOAD(rta));
				
				DEBUG(LOG_DEBUG, 0, 
				      "Interface index %d changed address to %s", 
				      ifm->ifa_index, ip_to_str(ifaddr));
				
			}
		}
		break;
	case KAODVM_TIMEOUT:
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;

		DEBUG(LOG_DEBUG, 0,
		      "Got TIMEOUT msg from kernel for %s",
		      ip_to_str(dest_addr));

		rt = rt_table_find(dest_addr);

		if (rt && rt->state == VALID)
			route_expire_timeout(rt);
		else
			DEBUG(LOG_DEBUG, 0,
			      "Got rt timeoute event but there is no route");
		break;
	case KAODVM_NOROUTE:
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;

		DEBUG(LOG_DEBUG, 0,
		      "Got NOROUTE msg from kernel for %s",
		      ip_to_str(dest_addr));

		rreq_route_discovery(dest_addr, 0, NULL);
		break;
	case KAODVM_REPAIR:
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;
		src_addr.s_addr = m->src;

		DEBUG(LOG_DEBUG, 0, "Got REPAIR msg from kernel for %s",
		      ip_to_str(dest_addr));

		fwd_rt = rt_table_find(dest_addr);

		if (fwd_rt)
			rreq_local_repair(fwd_rt, src_addr, NULL);

		break;
	case KAODVM_ROUTE_UPDATE:
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;
		src_addr.s_addr = m->src;
	
		if (dest_addr.s_addr == AODV_BROADCAST ||
		    dest_addr.s_addr ==
		    DEV_IFINDEX(m->ifindex).broadcast.s_addr)
			return;

		fwd_rt = rt_table_find(dest_addr);
		rev_rt = rt_table_find(src_addr);

		rt_table_update_route_timeouts(fwd_rt, rev_rt);

		break;
	case KAODVM_SEND_RERR:
		m = NLMSG_DATA(nlm);
		dest_addr.s_addr = m->dst;
		src_addr.s_addr = m->src;

		if (dest_addr.s_addr == AODV_BROADCAST ||
		    dest_addr.s_addr ==
		    DEV_IFINDEX(m->ifindex).broadcast.s_addr)
			return;

		fwd_rt = rt_table_find(dest_addr);
		rev_rt = rt_table_find(src_addr);

		do {
			struct in_addr rerr_dest;
			RERR *rerr;

			DEBUG(LOG_DEBUG, 0,
			      "Sending RERR for unsolicited message from %s to dest %s",
			      ip_to_str(src_addr),
			      ip_to_str(dest_addr));

			if (fwd_rt) {
				rerr = rerr_create(0, fwd_rt->dest_addr,
						   fwd_rt->dest_seqno);

				rt_table_update_timeout(fwd_rt,
							DELETE_PERIOD);
			} else
				rerr = rerr_create(0, dest_addr, 0);

			/* Unicast the RERR to the source of the data transmission
			 * if possible, otherwise we broadcast it. */

			if (rev_rt && rev_rt->state == VALID)
				rerr_dest = rev_rt->next_hop;
			else
				rerr_dest.s_addr = AODV_BROADCAST;

			aodv_socket_send((AODV_msg *) rerr, rerr_dest,
					 RERR_CALC_SIZE(rerr), 1,
					 &DEV_IFINDEX(m->ifindex));

			if (wait_on_reboot) {
				DEBUG(LOG_DEBUG, 0,
				      "Wait on reboot timer reset.");
				timer_set_timeout(&worb_timer,
						  DELETE_PERIOD);
			}
		} while (0);
		break;
	default:
		DEBUG(LOG_DEBUG, 0, "Got mesg type=%d\n", nlm->nlmsg_type);
	}
} 


static int nl_create_and_send_msg(int sock, int type, void *data, int len)
{
	int status;
	char buf[BUFLEN];
	struct nlmsghdr *nlm;

	memset(buf, 0, BUFLEN);

	nlm = (struct nlmsghdr *)buf;

	nlm->nlmsg_len = NLMSG_LENGTH(len);
	nlm->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
	nlm->nlmsg_type = type;
	nlm->nlmsg_pid = local.nl_pid;

	memcpy(NLMSG_DATA(nlm), data, len);
	
	status = sendto(sock, nlm, nlm->nlmsg_len, 0,
			(struct sockaddr *)&peer, sizeof(peer));

	return status;
}

int nl_send_add_route_msg(struct in_addr dest, struct in_addr next_hop,
			   u_int32_t lifetime, int rt_flags)
{
	kaodv_rt_msg_t m;
	
	DEBUG(LOG_DEBUG, 0, "Send ADD/UPDATE ROUTE to kernel: %s:%s",
	      ip_to_str(dest), ip_to_str(next_hop));

	memset(&m, 0, sizeof(m));
	
	m.dst = dest.s_addr;
	m.nhop = next_hop.s_addr;
	m.time = lifetime;
	
	if (rt_flags & RT_INET_DEST)
		m.flags |= KAODV_RT_GW_ENCAP;

	if (rt_flags & RT_REPAIR)
		m.flags |= KAODV_RT_REPAIR;
	
	return nl_create_and_send_msg(nlsock, KAODVM_ADDROUTE, &m, sizeof(m));
}

int nl_send_no_route_found_msg(struct in_addr dest)
{
	DEBUG(LOG_DEBUG, 0, "Send NOROUTE_FOUND to kernel: %s",
	      ip_to_str(dest));
	
	return nl_create_and_send_msg(nlsock, KAODVM_NOROUTE_FOUND, &dest, sizeof(dest));
}

int nl_send_del_route_msg(struct in_addr dest)
{
	DEBUG(LOG_DEBUG, 0, "Send DELROUTE to kernel: %s", ip_to_str(dest));
	return nl_create_and_send_msg(nlsock, KAODVM_DELROUTE, &dest, sizeof(dest));
}

int nl_send_conf_msg(void)
{
	kaodv_conf_msg_t cm;

	memset(&cm, 0, sizeof(cm));
	
	cm.qual_th = qual_threshold;
	cm.active_route_timeout = active_route_timeout;
	cm.is_gateway = internet_gw_mode;
	
	return nl_create_and_send_msg(nlsock, KAODVM_CONFIG, &cm, sizeof(cm));
}

static int nl_add_attr(struct nlmsghdr *nlm, int buflen, char *data, int type, int datalen)
{
        struct rtattr *rta;

        if (NLMSG_ALIGN(nlm->nlmsg_len) + RTA_LENGTH(datalen) > buflen)
                return -1;
        
	rta = (struct rtattr *)(((char *)nlm) + NLMSG_ALIGN(nlm->nlmsg_len));
        rta->rta_type = type;
        rta->rta_len = RTA_LENGTH(datalen);

        memcpy(RTA_DATA(rta), data, datalen);

        nlm->nlmsg_len = NLMSG_ALIGN(nlm->nlmsg_len) + RTA_LENGTH(datalen);

        return 0;
}


int nl_set_ifaddr(struct in_addr ifaddr, struct in_addr bcaddr, int ifindex)
{
	struct {
		struct ifaddrmsg ifa;
		struct {
			struct rtattr rta;
			struct in_addr addr;
		} data[3];
	} m;

	memset(&m, 0, sizeof(m));

	m.ifa.ifa_family = AF_INET;
	
	if (IN_CLASSA(ifaddr.s_addr))
		m.ifa.ifa_prefixlen = IN_CLASSA_NSHIFT;
	else if (IN_CLASSB(ifaddr.s_addr))
		m.ifa.ifa_prefixlen = IN_CLASSB_NSHIFT;
	else if (IN_CLASSC(ifaddr.s_addr))
		m.ifa.ifa_prefixlen = IN_CLASSC_NSHIFT;
	else if (IN_CLASSD(ifaddr.s_addr))
		m.ifa.ifa_prefixlen = 0;

	m.ifa.ifa_prefixlen = 24;
	m.ifa.ifa_flags = 0; //IFA_F_PERMANENT;
	m.ifa.ifa_scope = RT_SCOPE_UNIVERSE;
	m.ifa.ifa_index = ifindex;
	
	m.data[0].rta.rta_len = RTA_LENGTH(sizeof(ifaddr));
	m.data[0].rta.rta_type = IFA_LOCAL;
	m.data[0].addr.s_addr = ifaddr.s_addr;
	
	m.data[1].rta.rta_len = RTA_LENGTH(sizeof(ifaddr));
	m.data[1].rta.rta_type = IFA_ADDRESS;
	m.data[1].addr.s_addr = ifaddr.s_addr;

	m.data[2].rta.rta_len = RTA_LENGTH(sizeof(ifaddr));
	m.data[2].rta.rta_type = IFA_BROADCAST;
	m.data[2].addr.s_addr = bcaddr.s_addr;

	
	DEBUG(LOG_DEBUG, 0, "Sending new ifaddr %s %s netlink message index=%d", 
	      ip_to_str(ifaddr),
	      ip_to_str(bcaddr),
	      ifindex);

	return nl_create_and_send_msg(rtnlsock, RTM_NEWADDR, &m, sizeof(m));
}
