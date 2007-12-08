/* Copyright (C) Uppsala University
 *
 * This file is distributed under the terms of the GNU general Public
 * License (GPL), see the file LICENSE
 *
 * Author: Erik Nordström, <erikn@it.uu.se>
 */
#include <linux/config.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/etherdevice.h>
#include <linux/init.h>
#include <linux/if_ether.h>
#include <net/ip.h>
#include <linux/random.h>
#include <linux/wireless.h>
#include <linux/udp.h>
#include <linux/if_arp.h>

#include "kaodv-expl.h"
#include "kaodv-netlink.h"
#include "kaodv-queue.h"
#include "kaodv-ipenc.h"

#define DEBUG_KERN

static int aprintk(char *format, ...);

#ifdef DEBUG_KERN
#define DEBUG(s, args...) aprintk(s, ## args)
#else
#define DEBUG(s, args...)
#endif

#define ACTIVE_ROUTE_TIMEOUT active_route_timeout
extern int active_route_timeout;

#define AODV_PORT 654

struct aodv_node {
	__u32 ifaddr;
	__u32 bcaddr;
	struct net_device *dev;
	struct net_device *slave_dev;
	struct in_device *slave_indev;
	struct net_device_stats stats;
};

/* AODV nodes... Need to make this a list of nodes to support more
 * network intrefaces */

/* aodv_node must be static on some older kernels, otherwise it segfaults on
 * module load */
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static struct aodv_node *aodv_node;
#else
struct aodv_node *aodv_node;
#endif

static int rp_filter = 0;
static int forwarding = 0;
extern int is_gateway;
extern int qual_th;

static inline char *print_eth(char *addr)
{
#define BUFLEN (18 * 4)
	static char buf[BUFLEN];
	static int index = 0;
	char *str;
	
	sprintf(&buf[index], "%02x:%02x:%02x:%02x:%02x:%02x",
		(unsigned char)addr[0], (unsigned char)addr[1],
		(unsigned char)addr[2], (unsigned char)addr[3],
		(unsigned char)addr[4], (unsigned char)addr[5]);
	
	str = &buf[index];
	index += 18;
	index %= BUFLEN;

	return str;
}


static int kaodv_dev_xmit(struct sk_buff *skb);

static int kaodv_ip_recv(struct sk_buff *skb, struct net_device *indev,
			struct packet_type *pt);

static struct packet_type aodv_packet_type = {
	.type = __constant_htons(ETH_P_IP),
	.func = kaodv_ip_recv,
};

static int kaodv_arp_recv(struct sk_buff *skb, struct net_device *indev,
			  struct packet_type *pt);

static struct packet_type arp_packet_type = {
	.type = __constant_htons(ETH_P_ARP),
	.func = kaodv_arp_recv,
};

static int kaodv_dev_start_xmit(struct sk_buff *skb, struct net_device *dev);
static struct net_device_stats *kaodv_dev_get_stats(struct net_device *dev);

int aprintk(char *format, ...)
{
/* 	static char printk_buf[1024]; */
	int plen = 0;
	va_list args;

	va_start(args, format);

	/* Emit the output into the temporary buffer */
	/* plen = vsnprintf(printk_buf, (printk_buf), fmt, args); */
	printk(format, args);

	va_end(args);

	return plen;
}

static void kaodv_update_route_timeouts(const struct net_device *dev,
					struct iphdr *iph)
{
	struct expl_entry e;
	/* struct netdev_info *netdi; */

/* 	netdi = netdev_info_from_ifindex(dev->ifindex); */

/* 	if (!netdi) */
/* 		return; */

	/* First update forward route and next hop */
	if (kaodv_expl_get(iph->daddr, &e)) {

		kaodv_expl_update(e.daddr, e.nhop, ACTIVE_ROUTE_TIMEOUT,
				  e.flags);

		if (e.nhop != e.daddr && kaodv_expl_get(e.nhop, &e))
			kaodv_expl_update(e.daddr, e.nhop,
					  ACTIVE_ROUTE_TIMEOUT, e.flags);
	}
	/* Update reverse route */
	if (kaodv_expl_get(iph->saddr, &e)) {

		kaodv_expl_update(e.daddr, e.nhop, ACTIVE_ROUTE_TIMEOUT,
				  e.flags);

		if (e.nhop != e.daddr && kaodv_expl_get(e.nhop, &e))
			kaodv_expl_update(e.daddr, e.nhop, ACTIVE_ROUTE_TIMEOUT,
					  e.flags);

	}
}
static int kaodv_dev_inetaddr_event(struct notifier_block *this,
				    unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = (struct in_ifaddr *)ptr;
	struct in_device *indev;
	struct aodv_node *anode;

	if (!ifa)
		return NOTIFY_DONE;

	indev = ifa->ifa_dev;

	if (!indev)
		return NOTIFY_DONE;

	anode = indev->dev->priv;

	switch (event) {
	case NETDEV_UP:
		DEBUG("Netdev UP\n");
		if (indev->dev == anode->dev) {

			anode->ifaddr = ifa->ifa_address;
			anode->bcaddr = ifa->ifa_broadcast;

			anode->slave_indev = in_dev_get(anode->slave_dev);

			/* Disable rp_filter and enable forwarding */
			if (anode->slave_indev) {
				rp_filter = anode->slave_indev->cnf.rp_filter;
				forwarding = anode->slave_indev->cnf.forwarding;
				anode->slave_indev->cnf.rp_filter = 0;
				anode->slave_indev->cnf.forwarding = 1;
			}
		}
		break;
	case NETDEV_DOWN:
		DEBUG("notifier down\n");
		break;
	case NETDEV_REGISTER:
	default:
		break;
	};
	return NOTIFY_DONE;
}

static int kaodv_dev_netdev_event(struct notifier_block *this,
				  unsigned long event, void *ptr)
{
	struct net_device *dev = (struct net_device *)ptr;
	struct aodv_node *anode = aodv_node;
	int slave_change = 0;

	if (!dev)
		return NOTIFY_DONE;

	switch (event) {
	case NETDEV_REGISTER:
		DEBUG("Netdev register %s\n", dev->name);

		if (anode->slave_dev == NULL && dev->get_wireless_stats) {
			anode->slave_dev = dev;
			dev_hold(anode->slave_dev);

			if (!aodv_packet_type.func) {
				aodv_packet_type.func = kaodv_ip_recv;
				aodv_packet_type.dev = anode->slave_dev;
				dev_add_pack(&aodv_packet_type);
			}
			slave_change = 1;
		}

		if (slave_change)
			DEBUG("New AODV slave interface %s\n", dev->name);
		break;
	case NETDEV_CHANGE:
		DEBUG("Netdev change\n");
		break;
	case NETDEV_UP:
		DEBUG("Netdev up %s\n", dev->name);
		break;
	case NETDEV_UNREGISTER:
		DEBUG("Netdev unregister %s\n", dev->name);
		if (dev == anode->slave_dev) {
			dev_put(anode->slave_dev);
			anode->slave_dev = NULL;
			dev_remove_pack(&aodv_packet_type);
			aodv_packet_type.func = NULL;
			slave_change = 1;
		}

		if (slave_change)
			DEBUG("AODV slave interface %s unregisterd\n",
			      dev->name);
		break;
	case NETDEV_DOWN:
		DEBUG("Netdev down %s\n", dev->name);
		if (dev == anode->dev && anode->slave_dev) {

			if (anode->slave_indev) {
				anode->slave_indev->cnf.rp_filter = rp_filter;
				anode->slave_indev->cnf.forwarding = forwarding;
				in_dev_put(anode->slave_indev);
				anode->slave_indev = NULL;
			}
		}
		break;
	default:
		break;
	};

	return NOTIFY_DONE;
}

static int kaodv_dev_set_address(struct net_device *dev, void *p)
{
	struct sockaddr *sa = p;

	if (!is_valid_ether_addr(sa->sa_data))
		return -EADDRNOTAVAIL;

	memcpy(dev->dev_addr, sa->sa_data, ETH_ALEN);
	return 0;
}

/* fake multicast ability */
static void set_multicast_list(struct net_device *dev)
{
}

#ifdef CONFIG_NET_FASTROUTE
static int kaodv_dev_accept_fastpath(struct net_device *dev,
				     struct dst_entry *dst)
{
	return -1;
}
#endif
static int kaodv_dev_open(struct net_device *dev)
{
	netif_start_queue(dev);
	return 0;
}

static int kaodv_dev_stop(struct net_device *dev)
{
	netif_stop_queue(dev);
	return 0;
}

static void kaodv_dev_uninit(struct net_device *dev)
{
	struct aodv_node *anode = dev->priv;

	DEBUG("Calling dev_put on interfaces anode->slave_dev=%u anode->dev=%u\n",
	      (unsigned int)anode->slave_dev, (unsigned int)anode->dev);

	if (anode->slave_dev)
		dev_put(anode->slave_dev);

	dev_put(anode->dev);
	aodv_node = NULL;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
static int kaodv_dev_setup(struct net_device *dev)
#else
static void kaodv_dev_setup(struct net_device *dev)
#endif
{
	struct aodv_node *anode = dev->priv;
	  
        /* Fill in device structure with ethernet-generic values. */
//	ether_setup(dev);
	/* Initialize the device structure. */
	dev->get_stats = kaodv_dev_get_stats;
	dev->uninit = kaodv_dev_uninit;
	dev->open = kaodv_dev_open;
	dev->stop = kaodv_dev_stop;

	dev->hard_start_xmit = kaodv_dev_start_xmit;
	dev->set_multicast_list = set_multicast_list;
	dev->set_mac_address = kaodv_dev_set_address;
#ifdef CONFIG_NET_FASTROUTE
	dev->accept_fastpath = kaodv_dev_accept_fastpath;
#endif
	
	dev->type = ARPHRD_TUNNEL;
	dev->tx_queue_len = 0;
//	dev->flags |= IFF_NOARP;
	dev->flags &= ~IFF_MULTICAST;
	dev->hard_header_len = anode->slave_dev->hard_header_len + AODV_ENC_SIZE;
	dev->mtu = anode->slave_dev->mtu - AODV_ENC_SIZE;
	dev->iflink = 0;
	SET_MODULE_OWNER(dev);
	dev->addr_len = AODV_ENC_SIZE;

	get_random_bytes(dev->dev_addr, 6);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	return 0;
#endif
}

/* static int kaodv_ip_recv(struct sk_buff *skb) */
/* { */

/* 	kfree_skb(skb); */
/* 	return 1; */
/* } */


static int kaodv_dev_deliver(struct sk_buff *skb)
{
	struct ethhdr *ethh;
/* 	int len; */

	if (!skb)
		return -1;

	/* Super ugly hack to fix record route options */

	/* Need to make hardware header visible again since we are going down a
	 * layer */
	skb->mac.raw = skb->data - aodv_node->dev->hard_header_len;
	skb->ip_summed = CHECKSUM_UNNECESSARY;

	ethh = (struct ethhdr *)skb->mac.raw;

	memcpy(ethh->h_dest, aodv_node->dev->dev_addr, ETH_ALEN);
	memset(ethh->h_source, 0, ETH_ALEN);
	ethh->h_proto = htons(ETH_P_IP);

	aodv_node->stats.rx_packets++;
	aodv_node->stats.rx_bytes += skb->len;

	netif_rx(skb);

	return 0;
}

static int kaodv_arp_recv(struct sk_buff *skb, struct net_device *indev,
			struct packet_type *pt)
{
	struct aodv_node *anode = indev->priv;
	struct ethhdr *ethh;
	struct arphdr *arph;
	__u32 ipaddr;

	ethh = (struct ethhdr *)skb->data;
	arph = (struct arphdr *)skb->data + sizeof(struct ethhdr);


	memcpy(&ipaddr, (char *)arph + sizeof(struct arphdr) + ETH_ALEN *2 + 4, 4);
	
	DEBUG("ARP packet recv ip=%s\n", print_ip(ipaddr));

	if (ntohs(arph->ar_op) == ARPOP_REPLY && 
	    memcmp(&anode->ifaddr, (char *)arph + 
		   sizeof(struct arphdr) + ETH_ALEN *2 + 4, 4)) {
		
		DEBUG("ARP REPLY for aodv\n");
		skb->dev = anode->dev;

		kaodv_dev_deliver(skb);
	} else
		kfree_skb(skb);

	return 0;
}

static int kaodv_ip_recv(struct sk_buff *skb, struct net_device *indev,
			struct packet_type *pt)
{
	struct iphdr *iph = skb->nh.iph;
	struct aodv_node *anode = indev->priv;
	struct expl_entry e;

/* 	if (skb->pkt_type == PACKET_OTHERHOST) */
/* 		kfree_skb(skb); */

	if (iph->daddr == INADDR_BROADCAST ||
	    IN_MULTICAST(ntohl(iph->daddr)) || iph->daddr == anode->bcaddr) {
		kfree_skb(skb);
		return 0;
	}

	if (iph && iph->protocol == IPPROTO_UDP) {
		struct udphdr *udph;

		udph = (struct udphdr *)((char *)iph + (iph->ihl << 2));

		if (ntohs(udph->dest) == AODV_PORT ||
		    ntohs(udph->source) == AODV_PORT) {

#ifdef CONFIG_QUAL_THRESHOLD
#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,0))
			qual = (int)(*skb)->__unused;
#elif (LINUX_VERSION_CODE >= KERNEL_VERSION(2,6,0))
			qual = (*skb)->iwq.qual;
#endif
			if (qual_th) {

				if (qual && qual < qual_th) {
					pkts_dropped++;
					return 0;
				}
			}
#endif				/* CONFIG_QUAL_THRESHOLD */

			kaodv_update_route_timeouts(indev, iph);
			DEBUG("Received AODV packet\n");
			return 0;
		}
	}
	return 0;

	kaodv_netlink_send_rt_update_msg(PKT_INBOUND, iph->saddr,
					 iph->daddr, indev->ifindex);

	kaodv_update_route_timeouts(indev, iph);

	/* If we are a gateway maybe we need to decapsulate? */
	if (is_gateway && iph->protocol == IPPROTO_MIPE &&
	    iph->daddr == anode->ifaddr) {
		ip_pkt_decapsulate(skb);
		iph = skb->nh.iph;
	}

	/* Check for unsolicited data packets */
	else if (!kaodv_expl_get(iph->daddr, &e)) {
		kaodv_netlink_send_rerr_msg(PKT_INBOUND, iph->saddr,
					    iph->daddr, indev->ifindex);
	}

	/* Check if we should repair the route */
	else if (e.flags & KAODV_RT_REPAIR) {

		kaodv_netlink_send_rt_msg(KAODVM_REPAIR, iph->saddr,
					  iph->daddr);
		kaodv_queue_enqueue_packet(skb, kaodv_dev_xmit);
	}

	return 0;
}

int kaodv_dev_xmit(struct sk_buff *skb)
{
	int res = 0;

	skb->dev = aodv_node->slave_dev;

	aodv_node->stats.tx_packets++;
	aodv_node->stats.tx_bytes += skb->len;

/* 	dst_release(skb->dst); */
	
/* 	nf_reset(skb); */

	res = dev_queue_xmit(skb);

	return res;
}

/* Main receive function for packets originated in user space */
static int kaodv_dev_start_xmit(struct sk_buff *skb, struct net_device *dev)
{
	/* struct aodv_node *anode = (struct aodv_node *)dev->priv; */
	struct ethhdr *ethh = (struct ethhdr *)skb->data;
	struct iphdr *iph = skb->nh.iph;
	struct expl_entry e;
	struct aodv_node *anode = dev->priv;
	struct arphdr *arph;

	switch (ntohs(ethh->h_proto)) {
	case ETH_P_IP:
		if (iph->daddr == INADDR_BROADCAST ||
		    IN_MULTICAST(ntohl(iph->daddr)) || 
		    iph->daddr == anode->bcaddr)
			goto xmit;

		if (iph->daddr == 0)
			return 0;

		DEBUG("IP packet\n");
		kaodv_netlink_send_rt_update_msg(PKT_OUTBOUND, iph->saddr,
						 iph->daddr, dev->ifindex);
		
		if (!kaodv_expl_get(iph->daddr, &e) ||
		    (e.flags & KAODV_RT_REPAIR)) {

			if (!kaodv_queue_find(iph->daddr))
				kaodv_netlink_send_rt_msg(KAODVM_NOROUTE,
							  iph->saddr,
							  iph->daddr);

			kaodv_queue_enqueue_packet(skb, kaodv_dev_xmit);

			return 0;

		} else if (e.flags & KAODV_RT_GW_ENCAP) {

			/* Make sure that also the virtual Internet dest entry is
			 * refreshed */
			kaodv_update_route_timeouts(dev, iph);

			if (!ip_pkt_encapsulate(skb, e.nhop))
				return -1;
		}

		/* Update route timeouts */
		kaodv_update_route_timeouts(skb->dev, skb->nh.iph);

		break;
	case ETH_P_ARP:
		arph = (struct arphdr *)(skb->data + sizeof(struct ethhdr));

		if (ntohs(arph->ar_op) == ARPOP_REQUEST) {
			DEBUG("ARP REQ\n");
			memcpy(ethh->h_source, anode->slave_dev->dev_addr, ETH_ALEN);
			
			memcpy((char *)arph + sizeof(struct arphdr), 
			       anode->slave_dev->dev_addr, ETH_ALEN);

		} else if (ntohs(arph->ar_op) == ARPOP_REPLY) {
			DEBUG("ARP REP\n");
		}
		
	/* 	DEBUG("ARP s:%s d:%s\n", */
/* 		      print_eth(ethh->h_source), */
/* 		      print_eth(ethh->h_dest)); */
			
		break;
	default:
		DEBUG("Unkown packet type\n");
	}

      xmit:
	kaodv_dev_xmit(skb);

	return 0;
}

static struct net_device_stats *kaodv_dev_get_stats(struct net_device *dev)
{
	return &(((struct aodv_node *)dev->priv)->stats);
}

static struct notifier_block netdev_notifier = {
      notifier_call:kaodv_dev_netdev_event,
};

/* Notifier for inetaddr addition/deletion events.  */
static struct notifier_block inetaddr_notifier = {
	.notifier_call = kaodv_dev_inetaddr_event,
};

int kaodv_dev_init(char *ifname)
{
	int res = 0;
	struct net_device *adev;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,5,0)
	adev = alloc_etherdev(sizeof(struct aodv_node));

	if (!adev)
		return -ENOMEM;

	dev_alloc_name(adev, "aodv%d");

	adev->init = &kaodv_dev_setup;
#else
	adev = alloc_netdev(sizeof(struct aodv_node), "aodv%d", kaodv_dev_setup);
	if (!aodv_node->dev)
		return -ENOMEM;
#endif
	aodv_node = (struct aodv_node *)adev->priv;

	printk("Interface is %s\n", ifname);

	if (ifname) {
		aodv_node->slave_dev = dev_get_by_name(ifname);

		if (!aodv_node->slave_dev) {
			DEBUG("device %s not found\n", ifname);
			res = -1;
			goto cleanup_netdev;
		}

		if (aodv_node->slave_dev == aodv_node->dev) {
			DEBUG("invalid slave device %s\n", ifname);
			res = -1;
			dev_put(aodv_node->slave_dev);
			goto cleanup_netdev;
		}
	} else {
		read_lock(&dev_base_lock);
		for (aodv_node->slave_dev = dev_base;
		     aodv_node->slave_dev != NULL;
		     aodv_node->slave_dev = aodv_node->slave_dev->next) {

			if (aodv_node->slave_dev->get_wireless_stats)
				break;
		}
		read_unlock(&dev_base_lock);

		if (aodv_node->slave_dev) {
			dev_hold(aodv_node->slave_dev);
			DEBUG("wireless interface is %s\n",
			      aodv_node->slave_dev->name);

		} else {
			DEBUG("No proper slave device found\n");
			res = -1;
			goto cleanup_netdev;
		}
	}

	/* DEBUG("Setting %s as slave interface\n", aodv_node->slave_dev->name); */
	arp_packet_type.dev = aodv_node->slave_dev;
	dev_add_pack(&arp_packet_type);

	aodv_packet_type.dev = aodv_node->slave_dev;
	dev_add_pack(&aodv_packet_type);

	res = register_netdev(adev);

	if (res < 0)
		goto cleanup_netdev;

	res = register_netdevice_notifier(&netdev_notifier);

	if (res < 0)
		goto cleanup_netdev_register;

	res = register_inetaddr_notifier(&inetaddr_notifier);

	if (res < 0)
		goto cleanup_netdevice_notifier;
	/* We must increment usage count since we hold a reference */
	dev_hold(adev);

	return 0;
      cleanup_netdevice_notifier:
	unregister_netdevice_notifier(&netdev_notifier);
      cleanup_netdev_register:
	unregister_netdev(adev);
      cleanup_netdev:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
	free_netdev(adev);
#else
	kfree(adev);
#endif
	return res;
}

void __exit kaodv_dev_fini(void)
{
	if (aodv_packet_type.func)
		dev_remove_pack(&aodv_packet_type);

	
	if (arp_packet_type.func)
		dev_remove_pack(&arp_packet_type);

	unregister_netdevice_notifier(&netdev_notifier);
	unregister_inetaddr_notifier(&inetaddr_notifier);
	unregister_netdev(aodv_node->dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2,5,0)
	free_netdev(aodv_node->dev);
#else
	kfree(aodv_node->dev);
#endif
}
