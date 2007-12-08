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
 *****************************************************************************/
#ifndef DEFS_H
#define DEFS_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/signal.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <sys/ioctl.h>
#include <syslog.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>

#ifndef NS_PORT
#include "timer_queue.h"
#endif

#ifdef NS_PORT
#define NS_CLASS AODVUU::
#define NS_OUTSIDE_CLASS ::
#define NS_STATIC
/* NS_PORT: Using network device 0, with interface index 0. */
#define NS_DEV_NR 0
#define NS_IFINDEX NS_DEV_NR
#else
#define NS_CLASS
#define NS_OUTSIDE_CLASS
#define NS_STATIC static
#endif

#define AODV_UU_VERSION "0.5.1"

#ifdef NS_PORT
/* NS_PORT: Log filename split into prefix and suffix. */
#define AODV_LOG_PATH_PREFIX "aodv-uu_"
#define AODV_RT_LOG_PATH_PREFIX "aodv-uu_rt_"
#define AODV_LOG_PATH_SUFFIX ".log"
#define AODV_RT_LOG_PATH_SUFFIX AODV_LOG_PATH_SUFFIX
#else
#define AODV_LOG_PATH "/var/log/aodvd.log"
#define AODV_RT_LOG_PATH "/var/log/aodvd_rt.log"
#endif				/* NS_PORT */

#define INFTY 0xff
#define IS_INFTY(x) ((x & INFTY) == INFTY) ? 1 : 0
#define max(A,B) ( (A) > (B) ? (A):(B))

#define MINTTL 1		/* min TTL in the packets sent locally */

#define MAX_NR_INTERFACES 10
#define MAX_IFINDEX (MAX_NR_INTERFACES - 1)
#ifndef IFNAMSIZ
#define IFNAMSIZ 16
#endif

/* Data for a network device */
struct dev_info {
    int enabled;		/* 1 if struct is used, else 0 */
    int sock;			/* AODV socket associated with this device */
    unsigned int ifindex;
    char ifname[IFNAMSIZ];
    u_int32_t ipaddr;		/* The local IP address */
    u_int32_t netmask;		/* The netmask we use */
    u_int32_t broadcast;
};

struct host_info {
    u_int32_t seqno;		/* Sequence number */
    struct timeval bcast_time;	/* The time of the last broadcast msg sent */
    u_int32_t rreq_id;		/* RREQ id */
    int gateway_mode;
    int nif;			/* Number of interfaces to broadcast on */
    struct dev_info devs[MAX_NR_INTERFACES];
};


/*
  NS_PORT: TEMPORARY SOLUTION: Moved the two variables into the AODVUU class,
  and placed the function definition after the AODVUU class declaration.

  (Don't want to run lots of passes through defs.h...)

  TODO: Find some smarter way to accomplish this.
*/
#ifndef NS_PORT
/* This will point to a struct containing information about the host */
struct host_info this_host;

/* Array of interface indexes */
unsigned int dev_indices[MAX_NR_INTERFACES];

/* Given a network interface index, return the index into the
   devs array, Necessary because ifindex is not always 0, 1,
   2... */
static inline int ifindex2devindex(unsigned int ifindex)
{
    int i;

    for (i = 0; i < this_host.nif; i++)
	if (dev_indices[i] == ifindex)
	    return i;

    return -1;
}
#endif


/* Two macros to simplify retriving of a dev_info struct. Either using
   an ifindex or a device number (index into devs array). */
#define DEV_IFINDEX(ifindex) (this_host.devs[ifindex2devindex(ifindex)])
#define DEV_NR(n) (this_host.devs[n])

 /* Broadcast address according to draft (255.255.255.255) */
#define AODV_BROADCAST 0xFFFFFFFF

#define AODV_PORT 654

/* AODV Message types */
#define AODV_HELLO    0		/* Really never used as a separate type... */
#define AODV_RREQ     1
#define AODV_RREP     2
#define AODV_RERR     3
#define AODV_RREP_ACK 4

/* A generic AODV packet header struct... */
#ifdef NS_PORT
struct AODV_msg {
#else
typedef struct {
#endif
    u_int8_t type;

/* NS_PORT: Additions for the AODVUU packet type in ns-2 */
#ifdef NS_PORT
    static int offset_;		// Required by PacketHeaderManager

    inline static int &offset() {
	return offset_;
    } inline static AODV_msg *access(const Packet * p) {
	return (AODV_msg *) p->access(offset_);
    }

    int size();
};

typedef AODV_msg hdr_aodvuu;	// Name convention for headers
#define HDR_AODVUU(p) ((hdr_aodvuu *) hdr_aodvuu::access(p))
#else
} AODV_msg;
#endif

/* AODV Extension types */
#define RREQ_EXT 1
#define RREP_EXT 1
#define RREP_HELLO_INTERVAL_EXT 2
#define RREP_HELLO_NEIGHBOR_SET_EXT 3

/* An generic AODV extensions header */
typedef struct {
    u_int8_t type;
    u_int8_t length;
    /* Type specific data follows here */
} AODV_ext;

/* MACROS to access AODV extensions... */
#define AODV_EXT_HDR_SIZE sizeof(AODV_ext)
#define AODV_EXT_DATA(ext) ((AODV_ext *)((char *)ext + AODV_EXT_HDR_SIZE))
#define AODV_EXT_NEXT(ext) ((AODV_ext *)((char *)ext + AODV_EXT_HDR_SIZE + ext->length))
#define AODV_EXT_SIZE(ext) (AODV_EXT_HDR_SIZE + ext->length)

#ifndef NS_PORT
/* The callback function */
typedef void (*callback_func_t) (int);
extern int attach_callback_func(int fd, callback_func_t func);
#endif

#endif				/* DEFS_H */