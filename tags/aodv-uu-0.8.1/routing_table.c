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
 * Authors: Erik Nordstr�m, <erik.nordstrom@it.uu.se>
 *
 *****************************************************************************/

#include <time.h>

#ifdef NS_PORT
#include "aodv-uu.h"
#else
#include "routing_table.h"
#include "aodv_timeout.h"
#include "packet_queue.h"
#include "aodv_rerr.h"
#include "aodv_hello.h"
#include "aodv_socket.h"
#include "k_route.h"
#include "timer_queue.h"
#include "defs.h"
#include "debug.h"
#include "params.h"
#include "seek_list.h"
#endif				/* NS_PORT */

static unsigned int hashing(struct in_addr *addr, hash_value *hash);

void NS_CLASS rt_table_init()
{
    int i;

    rt_tbl.num_entries = 0;
    rt_tbl.num_active = 0;

    /* We do a for loop here... NS does not like us to use memset() */
    for (i = 0; i < RT_TABLESIZE; i++) {
	INIT_LIST_HEAD(&rt_tbl.tbl[i]);
    }
}

void NS_CLASS rt_table_destroy()
{
    int i;
    list_t *tmp = NULL, *pos = NULL;

    for (i = 0; i < RT_TABLESIZE; i++) {
	list_foreach_safe(pos, tmp, &rt_tbl.tbl[i]) {
	    rt_table_t *rt = (rt_table_t *)pos;
	    
	    rt_table_delete(rt);
	}
    }
}

/* Calculate a hash value and table index given a key... */
unsigned int hashing(struct in_addr * addr, hash_value * hash)
{
    /*   *hash = (*addr & 0x7fffffff); */
    *hash = (hash_value)addr->s_addr;

    return (*hash & RT_TABLEMASK);
}

rt_table_t *NS_CLASS rt_table_insert(struct in_addr dest_addr, 
				     struct in_addr next,
				     u_int8_t hops, u_int32_t seqno,
				     u_int32_t life, u_int8_t state,
				     u_int16_t flags, unsigned int ifindex)
{
    hash_value hash;
    unsigned int index;
    list_t *pos;
    rt_table_t *rt;
    struct in_addr nm;
    nm.s_addr = 0;
    
    /* Calculate hash key */
    index = hashing(&dest_addr, &hash);

    /* Check if we already have an entry for dest_addr */
    list_foreach(pos, &rt_tbl.tbl[index]) {
	rt = (rt_table_t *)pos;
	if (memcmp(&rt->dest_addr, &dest_addr, sizeof(struct in_addr)) == 0) {
	    DEBUG(LOG_INFO, 0, "%s already exist in routing table!", 
		  ip_to_str(dest_addr));

	    return NULL;
	}
    }

    if ((rt = (rt_table_t *) malloc(sizeof(rt_table_t))) == NULL) {
	fprintf(stderr, "Malloc failed!\n");
	exit(-1);
    }
    
    memset(rt, 0, sizeof(rt_table_t));

    rt->dest_addr = dest_addr;
    rt->next_hop = next;
    rt->dest_seqno = seqno;
    rt->flags = flags;
    rt->hcnt = hops;
    rt->ifindex = ifindex;
    rt->hash = hash;
    rt->state = state;

    timer_init(&rt->rt_timer, &NS_CLASS route_expire_timeout, rt);

    timer_init(&rt->ack_timer, &NS_CLASS rrep_ack_timeout, rt);

    timer_init(&rt->hello_timer, &NS_CLASS hello_timeout, rt);

    rt->last_hello_time.tv_sec = 0;
    rt->last_hello_time.tv_usec = 0;
    rt->hello_cnt = 0;

    rt->nprec = 0;
    INIT_LIST_HEAD(&rt->precursors);

    /* Insert first in bucket... */
    
    rt_tbl.num_entries++;
    

    DEBUG(LOG_INFO, 0, "Inserting %s (bucket %d) next hop %s",
	  ip_to_str(dest_addr), index, ip_to_str(next));

    list_add(&rt_tbl.tbl[index], &rt->l);
    
    if (state == INVALID) {

	if (flags & RT_REPAIR) {
	    rt->rt_timer.handler = &NS_CLASS local_repair_timeout;
	    life = ACTIVE_ROUTE_TIMEOUT;
	} else {
	    rt->rt_timer.handler = &NS_CLASS route_delete_timeout;
	    life = DELETE_PERIOD;
	}

    } else {
	rt_tbl.num_active++;
#ifndef NS_PORT
	/* Add route to kernel routing table ... */
	if (k_add_rte(dest_addr, next, nm, hops, rt->ifindex) < 0)
	    alog(LOG_WARNING, errno, __FUNCTION__,
		"Could not add kernel route!");
#endif
    }

#ifdef CONFIG_GATEWAY_DISABLE
    if (rt->flags & RT_GATEWAY)
	rt_table_update_inet_rt(rt, life);
#endif

    DEBUG(LOG_INFO, 0, "New timer for %s, life=%d",
	  ip_to_str(rt->dest_addr), life);

    if (life != 0)
	timer_set_timeout(&rt->rt_timer, life);

    /* In case there are buffered packets for this destination, we
     * send them on the new route. */
    if (rt->state == VALID && seek_list_remove(seek_list_find(dest_addr))) {
	if (rt->flags & RT_INET_DEST)
            packet_queue_set_verdict(dest_addr, PQ_ENC_SEND);
        else
            packet_queue_set_verdict(dest_addr, PQ_SEND);
    }
    return rt;
}

rt_table_t *NS_CLASS rt_table_update(rt_table_t * rt, struct in_addr next,
				     u_int8_t hops, u_int32_t seqno,
				     u_int32_t lifetime, u_int8_t state,
				     u_int16_t flags)
{
    struct in_addr nm;
    nm.s_addr = 0;

    if (rt->state == INVALID && state == VALID) {

	/* If this previously was an expired route, but will now be
	   active again we must add it to the kernel routing
	   table... */
	rt_tbl.num_active++;
#ifndef NS_PORT
	if (k_add_rte(rt->dest_addr, next, nm, hops, rt->ifindex) < 0)
	    alog(LOG_WARNING, errno, __FUNCTION__,
		"Could not add kernel route!");
	else
	    DEBUG(LOG_INFO, 0, "Added kernel route for expired %s",
		  ip_to_str(rt->dest_addr));
#endif

    } else if (rt->next_hop.s_addr != 0 && 
	       rt->next_hop.s_addr != next.s_addr) {
	DEBUG(LOG_INFO, 0, "rt->next_hop=%s, new_next_hop=%s",
	      ip_to_str(rt->next_hop), ip_to_str(next));

#ifndef NS_PORT
	if (k_chg_rte(rt->dest_addr, next, nm, hops, rt->ifindex) < 0)
	    alog(LOG_WARNING, errno, __FUNCTION__,
		"Could not update kernel route!");
#endif
    }

    rt->dest_seqno = seqno;
    rt->flags = flags;
    rt->next_hop = next;

    if (hops > 1 && rt->hcnt == 1) {
	rt->last_hello_time.tv_sec = 0;
	rt->last_hello_time.tv_usec = 0;
	rt->hello_cnt = 0;
	timer_remove(&rt->hello_timer);
    }

    rt->hcnt = hops;
    /* Finally, mark as VALID */
    rt->state = state;
    
#ifdef CONFIG_GATEWAY_DISABLED
    if (rt->flags & RT_GATEWAY)
	rt_table_update_inet_rt(rt, lifetime);
#endif

    rt->rt_timer.handler = &NS_CLASS route_expire_timeout;

    rt_table_update_timeout(rt, lifetime);
    
    
    /* In case there are buffered packets for this destination, we send
     * them on the new route. */
    if (rt->state == VALID && seek_list_remove(seek_list_find(rt->dest_addr))) {
	if (rt->flags & RT_INET_DEST)
            packet_queue_set_verdict(rt->dest_addr, PQ_ENC_SEND);
        else
            packet_queue_set_verdict(rt->dest_addr, PQ_SEND);
    }
    return rt;
}

NS_INLINE rt_table_t *NS_CLASS rt_table_update_timeout(rt_table_t * rt,
						       u_int32_t lifetime)
{
    struct timeval new_timeout;

    if (!rt)
	return NULL;

    if (rt->state == VALID) {
	/* Check if the current valid timeout is larger than the new
	   one - in that case keep the old one. */
	gettimeofday(&new_timeout, NULL);
	timeval_add_msec(&new_timeout, lifetime);

	if (timeval_diff(&rt->rt_timer.timeout, &new_timeout) < 0)
	    timer_set_timeout(&rt->rt_timer, lifetime);
    } else
	timer_set_timeout(&rt->rt_timer, lifetime);

    return rt;
}

rt_table_t *NS_CLASS rt_table_find(struct in_addr dest_addr)
{
    hash_value hash;
    unsigned int index;
    list_t *pos;

    if (rt_tbl.num_entries == 0)
	return NULL;

    /* Calculate index */
    index = hashing(&dest_addr, &hash);

    /* Handle collisions: */
    list_foreach(pos, &rt_tbl.tbl[index]) {
	rt_table_t *rt = (rt_table_t *)pos;

	if (rt->hash != hash) 
	    continue;
	
	if (memcmp(&dest_addr, &rt->dest_addr, sizeof(struct in_addr)) == 0)
	    return rt;

    }
    return NULL;
}
rt_table_t *NS_CLASS rt_table_find_gateway()
{
    rt_table_t *gw = NULL;
    int i;

    for (i = 0; i < RT_TABLESIZE; i++) {
	list_t *pos;
	list_foreach(pos, &rt_tbl.tbl[i]) {
	    rt_table_t *rt = (rt_table_t *)pos;
	    
	    if (rt->flags & RT_GATEWAY && rt->state == VALID) {
		if (!gw || rt->hcnt < gw->hcnt)
		    gw = rt;
	    }
	}
    }
    return gw;
}
#ifdef CONFIG_GATEWAY_DISABLED
int NS_CLASS rt_table_update_inet_rt(rt_table_t *gw, u_int32_t life)
{
    int n = 0;
    int i;
    
    if (!gw)
	return -1;

    for (i = 0; i < RT_TABLESIZE; i++) {
	list_t *pos;
	list_foreach(pos, &rt_tbl.tbl[i]) {
	    rt_table_t *rt = (rt_table_t *)pos;
	    
	    if (rt->flags & RT_INET_DEST && rt->state == INVALID) {
		rt_table_update(rt, gw->dest_addr, gw->hcnt, 0, life,
				VALID, rt->flags);
		n++;
	    }
	}
    }
    return n;
}
#endif /* CONFIG_GATEWAY_DISABLED */

/* Route expiry and Deletion. */
int NS_CLASS rt_table_invalidate(rt_table_t * rt)
{
    struct timeval now;

    gettimeofday(&now, NULL);

    if (rt == NULL)
	return -1;

     /* If the route is already invalidated, do nothing... */
    if (rt->state == INVALID) {
	DEBUG(LOG_DEBUG, 0, "Route %s already invalidated!!!",
	      ip_to_str(rt->dest_addr));
	return -1;
    }
    
    if (rt->hello_timer.used) {
	DEBUG(LOG_DEBUG, 0, "last HELLO: %ld",
	      timeval_diff(&now, &rt->last_hello_time));
    }
   
    /* Remove any pending, but now obsolete timers. */
    timer_remove(&rt->rt_timer);
    timer_remove(&rt->hello_timer);
    timer_remove(&rt->ack_timer);

    /* Mark the route as invalid */
    rt->state = INVALID;
    rt_tbl.num_active--;

    rt->hello_cnt = 0;

    /* When the lifetime of a route entry expires, increase the sequence
       number for that entry. */
    seqno_incr(rt->dest_seqno);
    
    rt->last_hello_time.tv_sec = 0;
    rt->last_hello_time.tv_usec = 0;

#ifndef NS_PORT
    /* Delete kernel routing table entry. */
    if (k_del_rte(rt->dest_addr) < 0)
	alog(LOG_WARNING, errno, __FUNCTION__, "Could not delete kernel route!");
#endif

    
#ifdef CONFIG_GATEWAY
    /* If this was a gateway, check if any Internet destinations were using
     * it. In that case update them to use a backup gateway or invalide them
     * too. */
    if (rt->flags & RT_GATEWAY) {
	int i;
	
	rt_table_t *gw = rt_table_find_gateway();
	
	for (i = 0; i < RT_TABLESIZE; i++) {
	    list_t *pos;
	    list_foreach(pos, &rt_tbl.tbl[i]) {
		rt_table_t *rt2 = (rt_table_t *)pos;
		
		if (rt2->state == VALID && (rt2->flags & RT_INET_DEST) &&
		    (rt2->next_hop.s_addr == rt->dest_addr.s_addr)) {
		    if (0) {
			DEBUG(LOG_DEBUG, 0, "Invalidated GW %s but found new GW %s for %s",  ip_to_str(rt->dest_addr), ip_to_str(gw->dest_addr),  
			      ip_to_str(rt2->dest_addr));
			rt_table_update(rt2, gw->dest_addr, gw->hcnt, 0, 
					timeval_diff(&rt->rt_timer.timeout, 
						     &now), VALID, rt2->flags);
		    } else {
			rt_table_invalidate(rt2);
			precursor_list_destroy(rt2);
		    }
		}
	    }
	}
    }
#endif

    if (rt->flags & RT_REPAIR) {
	/* Set a timeout for the repair */

	rt->rt_timer.handler = &NS_CLASS local_repair_timeout;
	timer_set_timeout(&rt->rt_timer, ACTIVE_ROUTE_TIMEOUT);

	DEBUG(LOG_DEBUG, 0, "%s kept for repairs during %u msecs",
	      ip_to_str(rt->dest_addr), ACTIVE_ROUTE_TIMEOUT);
    } else {

	/* Schedule a deletion timer */
	rt->rt_timer.handler = &NS_CLASS route_delete_timeout;
	timer_set_timeout(&rt->rt_timer, DELETE_PERIOD);

	DEBUG(LOG_DEBUG, 0, "%s removed in %u msecs",
	      ip_to_str(rt->dest_addr), DELETE_PERIOD);
    }

    return 0;
}

void NS_CLASS rt_table_delete(rt_table_t *rt)
{
    if(!rt) {
	DEBUG(LOG_ERR, 0, "No route entry to delete");
	return;
    }
    
    list_detach(&rt->l);
    
    precursor_list_destroy(rt);
    
    if (rt->state == VALID) {
	
#ifndef NS_PORT
	if (k_del_rte(rt->dest_addr) < 0)
	    alog(LOG_WARNING, errno, __FUNCTION__,
		"Could not delete kernel route!");
	
#endif
	rt_tbl.num_active--;
    }
    /* Make sure timers are removed... */
    timer_remove(&rt->rt_timer);
    timer_remove(&rt->hello_timer);
    timer_remove(&rt->ack_timer);
    
    rt_tbl.num_entries--;
    
    free(rt);
    return;
}

/****************************************************************/

/* Add an neighbor to the active neighbor list. */

void NS_CLASS precursor_add(rt_table_t * rt, struct in_addr addr)
{
    precursor_t *pr;
    list_t *pos;

    /* Sanity check */
    if (!rt)
	return;

    /* Check if the node is already in the precursors list. */
    list_foreach(pos, &rt->precursors) {
	pr = (precursor_t *)pos;
	    
	if (pr->neighbor.s_addr == addr.s_addr)
	    return;
    }
    
    if ((pr = (precursor_t *) malloc(sizeof(precursor_t))) == NULL) {
	perror("Could not allocate memory for precursor node!!\n");
	exit(-1);
    }

    DEBUG(LOG_INFO, 0, "Adding precursor %s to rte %s",
	  ip_to_str(addr), ip_to_str(rt->dest_addr));
    
    pr->neighbor.s_addr = addr.s_addr;
    
    /* Insert in precursors list */
    
    list_add(&rt->precursors, &pr->l);
    rt->nprec++;

    return;
}

/****************************************************************/

/* Remove a neighbor from the active neighbor list. */

void NS_CLASS precursor_remove(rt_table_t * rt, struct in_addr addr)
{
    list_t *pos;

    /* Sanity check */
    if (!rt)
	return;

    list_foreach(pos, &rt->precursors) {
	precursor_t *pr = (precursor_t *)pos;
	if (pr->neighbor.s_addr == addr.s_addr) {
	    DEBUG(LOG_INFO, 0, "Removing precursor %s from rte %s",
		  ip_to_str(addr), ip_to_str(rt->dest_addr));

	    list_detach(pos);
	    rt->nprec--;
	    free(pr);
	    return;
	}
    }
}

/****************************************************************/

/* Delete all entries from the active neighbor list. */

void precursor_list_destroy(rt_table_t * rt)
{
    list_t *pos, *tmp;
    
    /* Sanity check */
    if (!rt)
	return;

    list_foreach_safe(pos, tmp, &rt->precursors) {
	precursor_t *pr = (precursor_t *)pos;
	list_detach(pos);
	rt->nprec--;
	free(pr);
    }
}
