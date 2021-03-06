/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University and Ericsson Telecom AB.
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
 * Authors: Erik Nordstr�m, <erno3431@student.uu.se>
 *          Henrik Lundgren, <henrikl@docs.uu.se>
 *
 *****************************************************************************/
#include <time.h>

#include "defs.h"
#include "aodv_timeout.h"
#include "aodv_socket.h"
#include "aodv_rreq.h"
#include "aodv_rerr.h"
#include "timer_queue.h"
#include "debug.h"
#include "params.h"
#include "routing_table.h"
#include "packet_input.h"
#include "k_route.h"
#include "seek_list.h"
#include "icmp.h"

/* These are timeout functions which are called when timers expire... */

extern int expanding_ring_search;

void route_delete_timeout(void *arg);

void route_discovery_timeout(void *arg)
{
    seek_list_t *seek_entry;
    int i;
    
    seek_entry = (seek_list_t *) arg;

    /* Sanity check... */
    if (seek_entry == NULL)
	return;

#ifdef DEBUG
    log(LOG_DEBUG, 0, "route_discovery_timeout: %s",
	ip_to_str(seek_entry->dest_addr));
#endif

    if (seek_entry->reqs < RREQ_RETRIES) {
	RREQ *rreq;

	if (expanding_ring_search) {

	    if (seek_entry->ttl < TTL_THRESHOLD)
		seek_entry->ttl += TTL_INCREMENT;
	    else {
		seek_entry->ttl = NET_DIAMETER;
		seek_entry->reqs++;
	    }
	    /* Set a new timer for seeking this destination */
	    timer_add_msec(&seek_entry->seek_timer,
			   2 * seek_entry->ttl * NODE_TRAVERSAL_TIME);
	} else {
	    seek_entry->reqs++;
	    timer_add_msec(&seek_entry->seek_timer, NET_TRAVERSAL_TIME);
	}
#ifdef DEBUG
	log(LOG_DEBUG, 0, "route_discovery_timeout: Sending RREQ, ttl=%d on all interfaces", seek_entry->ttl);
#endif
	for (i = 0; i < MAX_NR_INTERFACES; i++) {
	    if (!DEV_NR(i).enabled)
		continue;
	    rreq = rreq_create(seek_entry->flags, seek_entry->dest_addr,
			       seek_entry->dest_seqno, DEV_NR(i).ipaddr);

	    aodv_socket_send((AODV_msg *) rreq, AODV_BROADCAST, RREQ_SIZE,
			     seek_entry->ttl, &DEV_NR(i));
	}
	
    } else {
	packet_buff_drop(seek_entry->dest_addr);

#ifdef DEBUG
	log(LOG_DEBUG, 0, "route_discovery_timeout: NO ROUTE FOUND!");
#endif
	/* Send an ICMP Destination Host Unreachable to the application: */
	if (seek_entry->ipd)
	    icmp_send_host_unreachable(seek_entry->ipd->data,
				       seek_entry->ipd->len);

	seek_list_remove(seek_entry->dest_addr);

    }
}


void route_expire_timeout(void *arg)
{
    rt_table_t *rt_entry;
#ifdef DEBUG
    struct timeval now;

    gettimeofday(&now, NULL);
#endif

    rt_entry = (rt_table_t *) arg;

    if (rt_entry == NULL) {
	log(LOG_WARNING, 0,
	    "route_expire_timer: arg was NULL, ignoring timeout!");
	return;
    }
#ifdef DEBUG
    log(LOG_DEBUG, 0, "route_expire_timeout: %s timeout-now=%ld msecs",
	ip_to_str(rt_entry->dest_addr),
	timeval_diff(&rt_entry->rt_timer.timeout, &now) / 1000);
#endif

    /* If hopcount = 1, this is a direct neighbor and a link break has
       occured. Send a RERR with the incremented sequence number */
    if (rt_entry->hcnt == 1) {
	RERR *rerr;
	rt_table_t *u_entry;
	int i;
	
#ifdef DEBUG
	log(LOG_DEBUG, 0,
	    "route_expire_timeout: LINK FAILURE for %s, seqno=%d",
	    ip_to_str(rt_entry->dest_addr), rt_entry->dest_seqno);
#endif
	/* Create a route error msg */
	rerr = rerr_create(0, rt_entry->dest_addr, rt_entry->dest_seqno);

	/* Check the routing table for entries which have the unreachable
	   destination (dest) as next hop. These entries (destinations)
	   cannot be reached either since dest is down. They should
	   therefore also be included in the RERR. */
	for (i = 0; i < RT_TABLESIZE; i++) {
	    for (u_entry = routing_table[i]; u_entry != NULL;
		 u_entry = u_entry->next) {

		if ((u_entry->next_hop == rt_entry->dest_addr) &&
		    (u_entry->dest_addr != rt_entry->dest_addr)) {

		    if (u_entry->precursors != NULL) {

			rerr_add_udest(rerr, u_entry->dest_addr,
				       u_entry->dest_seqno);
#ifdef DEBUG
			log(LOG_DEBUG, 0, "route_expire_timeout: Added %s as unreachable, seqno=%d", ip_to_str(u_entry->dest_addr), u_entry->dest_seqno);
#endif
			rerr->dest_count++;
		    }
		    rt_table_invalidate(u_entry);
		}
	    }
	}
	/* FIXME: Check if we should unicast the RERR. This check does not
	   catch all cases when we could unicast (like when several
	   unreachable destinations have the same precursor). */
#ifdef DEBUG
	log(LOG_DEBUG, 0, "route_expire_timeout: RERR created, %d bytes.",
	    RERR_CALC_SIZE(rerr));
#endif
	
	if (rerr->dest_count == 1 &&
	    rt_entry->precursors != NULL
	    && rt_entry->precursors->next == NULL)
	    aodv_socket_send((AODV_msg *) rerr,
			     rt_entry->precursors->neighbor,
			     RERR_CALC_SIZE(rerr), 1, 
			     &DEV_IFINDEX(rt_entry->ifindex));

	else if (rerr->dest_count >= 1 && (rt_entry->precursors != NULL)) {
	    /* FIXME: Should only transmit RERR on those interfaces
	     * which have precursor nodes for the broken route */
	     for (i = 0; i < MAX_NR_INTERFACES; i++) {
		 if (!DEV_NR(i).enabled)
		     continue;
		 aodv_socket_send((AODV_msg *) rerr, AODV_BROADCAST,
				  RERR_CALC_SIZE(rerr), 1, &DEV_NR(i));
	     }
	}
#ifdef DEBUG
	else
	    log(LOG_DEBUG, 0, "route_expire_timeout: No precursors, dropping RERR");
#endif

    }
    /* Now also invalidate the entry of the link that broke... */
    rt_table_invalidate(rt_entry);
}

void route_delete_timeout(void *arg)
{
    rt_table_t *rt_entry;

    rt_entry = (rt_table_t *) arg;

    /* Sanity check: */
    if (rt_entry == NULL)
	return;

#ifdef DEBUG
    log(LOG_DEBUG, 0, "route_delete_timeout: %s",
	ip_to_str(rt_entry->dest_addr));
#endif
    /* The kernel route entry is already deleted, so we only delete the
       internal AODV routing entry... */
    rt_table_delete(rt_entry->dest_addr);
}

/* This is called when we stop receiveing hello messages from a
   node. For now this is basically the same as a route timeout. */
void hello_timeout(void *arg)
{
    rt_table_t *rt_entry;
    struct timeval now;
    
    rt_entry = (rt_table_t *) arg;

    gettimeofday(&now, NULL);
#ifdef DEBUG
    log(LOG_DEBUG, 0, "hello_timeout: %s last HELLO: %d", ip_to_str(rt_entry->dest_addr), timeval_diff(&now, &rt_entry->last_hello_time) / 1000);
#endif

    if (rt_entry != NULL &&
	rt_entry->hcnt != INFTY && !(rt_entry->flags & UNIDIR)) {
	timer_remove(&rt_entry->rt_timer);
	route_expire_timeout(rt_entry);
    }
}

void rreq_record_timeout(void *arg)
{
    struct rreq_record *rreq_pkt;

    rreq_pkt = (struct rreq_record *) arg;

#ifdef DEBUG
    log(LOG_DEBUG, 0, "rreq_record_timeout: %s rreq_id=%lu",
	ip_to_str(rreq_pkt->orig_addr), rreq_pkt->rreq_id);
#endif

    /* Remove buffered information for this rreq */
    rreq_record_remove(rreq_pkt->orig_addr, rreq_pkt->rreq_id);
}

void rreq_blacklist_timeout(void *arg)
{
    struct blacklist *bl_entry;
    bl_entry = (struct blacklist *) arg;
#ifdef DEBUG
    log(LOG_DEBUG, 0, "rreq_blacklist_timeout: %s",
	ip_to_str(bl_entry->dest_addr));
#endif
    rreq_blacklist_remove(bl_entry->dest_addr);
}

void rrep_ack_timeout(void *arg)
{
    rt_table_t *rt_entry;

    /* We must be really sure here, that this entry really exists at
       this point... (Though it should). */
    rt_entry = (rt_table_t *) arg;

    /* When a RREP transmission fails (i.e. lack of RREP-ACK), add to
       blacklist set... */
    rreq_blacklist_insert(rt_entry->dest_addr);

#ifdef DEBUG
    log(LOG_DEBUG, 0, "rrep_ack_timeout: %s",
	ip_to_str(rt_entry->dest_addr));
#endif
}

void wait_on_reboot_timeout(void *arg)
{
    *((int *) arg) = 0;
#ifdef DEBUG
    log(LOG_DEBUG, 0, "wait_on_reboot_timeout: Wait on reboot over!!");
#endif
}
