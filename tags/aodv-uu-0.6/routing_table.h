/*****************************************************************************
 *
 * Copyright (C) 2001 Uppsala University & Ericsson AB.
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
 *
 *****************************************************************************/
#ifndef ROUTING_TABLE_H
#define ROUTING_TABLE_H

#ifndef NS_NO_GLOBALS
#include "defs.h"

typedef struct rt_table rt_table_t;

/* Neighbor struct for active routes in Route Table */
typedef struct precursor {
    u_int32_t neighbor;
    struct precursor *next;
} precursor_t;


typedef u_int32_t hash_value;	/* A hash value */

/* Route table entries */
struct rt_table {
    u_int32_t dest_addr;	/* IP address of the destination */
    u_int32_t dest_seqno;
    unsigned int ifindex;	/* Network interface index... */
    u_int32_t next_hop;		/* IP address of the next hop to the dest */
    u_int8_t hcnt;		/* Distance (in hops) to the destination */
    u_int16_t flags;		/* Routing flags */
    u_int8_t state;		/* The state of this entry */
    struct timer rt_timer;	/* The timer associated with this entry */
    struct timer ack_timer;	/* RREP_ack timer for this destination */
    struct timer hello_timer;
    struct timeval last_hello_time;
    u_int8_t hello_cnt;
    hash_value hash;
    precursor_t *precursors;	/* List of neighbors using the route */
    struct rt_table *next;	/* Pointer to next Route Table entry */
};


/* Route entry flags */
#define RT_UNIDIR        0x1
#define RT_REPAIR        0x2
#define RT_INV_SEQNO 0x4

/* Route entry states */
#define INVALID   0
#define VALID     1


#define RT_TABLESIZE 64		/* Must be a power of 2 */
#define RT_TABLEMASK (RT_TABLESIZE - 1)

struct routing_table {
    unsigned int num_entries;
    unsigned int num_active;
    rt_table_t *tbl[RT_TABLESIZE];
};

void precursor_list_destroy(rt_table_t * rt);
#endif				/* NS_NO_GLOBALS */

#ifndef NS_NO_DECLARATIONS

struct routing_table rt_tbl;

void rt_table_init();
void rt_table_destroy();
rt_table_t *rt_table_insert(u_int32_t dest, u_int32_t next, u_int8_t hops,
			    u_int32_t seqno, u_int32_t life,
			    u_int8_t state, u_int16_t flags,
			    unsigned int ifindex);
rt_table_t *rt_table_update(rt_table_t * rt, u_int32_t next,
			    u_int8_t hops, u_int32_t seqno,
			    u_int32_t lifetime, u_int8_t state,
			    u_int16_t flags);
NS_INLINE rt_table_t *rt_table_update_timeout(rt_table_t * rt,
					      u_int32_t lifetime);
rt_table_t *rt_table_find(u_int32_t dest);
int rt_table_invalidate(rt_table_t * rt);
void rt_table_delete(u_int32_t dest);
void precursor_add(rt_table_t * rt, u_int32_t addr);
void precursor_remove(rt_table_t * rt, u_int32_t addr);

#ifdef NS_PORT
void rt_table_remove_precursor(u_int32_t dest_addr);
#endif

#endif				/* NS_NO_DECLARATIONS */

#endif				/* ROUTING_TABLE_H */