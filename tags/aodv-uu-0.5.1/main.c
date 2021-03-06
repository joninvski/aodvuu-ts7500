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
 * Author: Erik Nordstr�m, <erik.nordstrom@it.uu.se>
 *
 *****************************************************************************/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <linux/sockios.h>
#include <linux/wireless.h>
#include <getopt.h>
#include <ctype.h>

#include "defs.h"
#include "debug.h"
#include "timer_queue.h"
#include "params.h"
#include "aodv_socket.h"
#include "aodv_timeout.h"
#include "k_route.h"
#include "routing_table.h"
#include "aodv_hello.h"
#include "packet_input.h"
#include "packet_queue.h"

#ifdef USE_IW_SPY
#include "link_qual.h"
#endif

/* Global variables: */
int log_to_file = 0;
int rt_log_interval = 0;	/* msecs between routing table logging 0=off */
int unidir_hack = 0;
int rreq_gratuitous = 0;
int expanding_ring_search = 1;
int internet_gw_mode = 0;
int local_repair = 0;
int receive_n_hellos = 0;
int hello_jittering = 1;
char *progname;
char versionstring[100];
int wait_on_reboot = 1;
int hello_qual_threshold = 12;
char *spy_addrs = NULL;
struct timer worb_timer;	/* Wait on reboot timer */

static void cleanup();

struct option longopts[] = {
    {"interface", required_argument, NULL, 'i'},
    {"hello-jitter", no_argument, NULL, 'j'},
    {"log", no_argument, NULL, 'l'},
    {"n-hellos", required_argument, NULL, 'n'},
    {"daemon", no_argument, NULL, 'd'},
    {"force-gratuitous", no_argument, NULL, 'g'},
    {"quality-threshold", required_argument, NULL, 'q'},
    {"log-rt-table", required_argument, NULL, 'r'},
    {"add-spy", required_argument, NULL, 's'},
    {"unidir_hack", no_argument, NULL, 'u'},
    {"gateway-mode", no_argument, NULL, 'w'},
    {"help", no_argument, NULL, 'h'},
    {"no-expanding-ring", no_argument, NULL, 'x'},
    {"no-worb", no_argument, NULL, 'D'},
    {"version", no_argument, NULL, 'V'},
    {0}
};

void usage(int status)
{
    if (status != 0) {
	fprintf(stderr, "Try `%s --help' for more information.\n", progname);
	exit(status);
    }

    printf
	("\nUsage: %s [-dghjluwxDV] [-i if0,if1,..] [-r N] [-n N]\n\n"
	 "-d, --daemon            Daemon mode, i.e. detach from the console.\n"
	 "-g, --force-gratuitous  Force the gratuitous flag to be set on all RREQ's.\n"
	 "-h, --help              This information.\n"
	 "-i, --interface         Network interfaces to attach to. Defaults to first\n"
	 "                        wireless interface.\n"
	 "-j, --hello-jitter      Toggle hello jittering (default on).\n"
	 "-l, --log               Log debug output to %s.\n"
	 "-r, --log-rt-table      Log routing table to %s every N secs.\n"
	 "-n, --n-hellos          Receive N hellos from host before treating as neighbor.\n"
	 "-u, --unidir-hack       Detect and avoid unidirectional links (experimental).\n"
	 "-w, --gateway-mode      Enable experimental Internet gateway support.\n"
	 "-x, --no-expanding-ring Disable expanding ring search for RREQs.\n"
	 "-D, --no-worb           Disable 15 seconds wait on reboot delay.\n"
	 "-V, --version           Show version.\n\n"
	 "Author: Erik Nordstr�m, erik.nordstrom@it.uu.se\n\n",
	 progname, AODV_LOG_PATH, AODV_RT_LOG_PATH);

    exit(status);
}

int set_kernel_options()
{
    int i, fd = -1;
    char on = '1';
    char off = '0';
    char command[64];

    if ((fd = open("/proc/sys/net/ipv4/ip_forward", O_WRONLY)) < 0)
	return -1;
    if (write(fd, &on, sizeof(char)) < 0)
	return -1;
    close(fd);

    if ((fd = open("/proc/sys/net/ipv4/route/max_delay", O_WRONLY)) < 0)
	return -1;
    if (write(fd, &off, sizeof(char)) < 0)
	return -1;
    close(fd);

    if ((fd = open("/proc/sys/net/ipv4/route/min_delay", O_WRONLY)) < 0)
	return -1;
    if (write(fd, &off, sizeof(char)) < 0)
	return -1;
    close(fd);

    /* Disable ICMP redirects on all interfaces: */

    for (i = 0; i < MAX_NR_INTERFACES; i++) {
	if (!DEV_NR(i).enabled)
	    continue;

	memset(command, '\0', 64);
	sprintf(command, "/proc/sys/net/ipv4/conf/%s/send_redirects",
		DEV_NR(i).ifname);
	if ((fd = open(command, O_WRONLY)) < 0)
	    return -1;
	if (write(fd, &off, sizeof(char)) < 0)
	    return -1;
	close(fd);
	memset(command, '\0', 64);
	sprintf(command, "/proc/sys/net/ipv4/conf/%s/accept_redirects",
		DEV_NR(i).ifname);
	if ((fd = open(command, O_WRONLY)) < 0)
	    return -1;
	if (write(fd, &off, sizeof(char)) < 0)
	    return -1;
	close(fd);
    }
    memset(command, '\0', 64);
    sprintf(command, "/proc/sys/net/ipv4/conf/all/send_redirects");
    if ((fd = open(command, O_WRONLY)) < 0)
	return -1;
    if (write(fd, &off, sizeof(char)) < 0)
	return -1;
    close(fd);


    memset(command, '\0', 64);
    sprintf(command, "/proc/sys/net/ipv4/conf/all/accept_redirects");
    if ((fd = open(command, O_WRONLY)) < 0)
	return -1;
    if (write(fd, &off, sizeof(char)) < 0)
	return -1;
    close(fd);

    return 0;
}

int find_default_gw(void)
{
    FILE *route;
    char buf[100], *l;

    route = fopen("/proc/net/route", "r");

    if (route == NULL) {
	perror("open /proc/net/route");
	exit(-1);
    }

    while (fgets(buf, sizeof(buf), route)) {
	l = strtok(buf, " \t");
	l = strtok(NULL, " \t");
	if (l != NULL) {
	    if (strcmp("00000000", l) == 0) {
		l = strtok(NULL, " \t");
		l = strtok(NULL, " \t");
		if (strcmp("0003", l) == 0) {
		    fclose(route);
		    return 1;
		}
	    }
	}
    }
    fclose(route);
    return 0;
}

/*
 * Returns information on a network interface given its name...
 */
struct sockaddr_in *get_if_info(char *ifname, int type)
{
    int skfd;
    struct sockaddr_in *ina;
    struct ifreq ifr;

    /* Get address of interface... */
    skfd = socket(AF_INET, SOCK_DGRAM, 0);

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(skfd, type, &ifr) < 0) {
	log(LOG_ERR, errno, "Could not get address of %s ", ifname);
	close(skfd);
	return NULL;
    } else {
	ina = (struct sockaddr_in *) &ifr.ifr_addr;
	close(skfd);
	return ina;
    }
}

/* This will limit the number of handler functions we can have for
   sockets and file descriptors and so on... */
#define CALLBACK_FUNCS 4
static struct callback {
    int fd;
    callback_func_t func;
} callbacks[CALLBACK_FUNCS];

static int nr_callbacks = 0;

int attach_callback_func(int fd, callback_func_t func)
{
    if (nr_callbacks >= CALLBACK_FUNCS) {
	fprintf(stderr, "callback attach limit reached!!\n");
	exit(-1);
    }
    callbacks[nr_callbacks].fd = fd;
    callbacks[nr_callbacks].func = func;
    nr_callbacks++;
    return 0;
}

/* Here we find out how to load the kernel modules... If the modules
   are located in the current directory. use those. Otherwise fall
   back to modprobe. */

void load_modules(char *ifname)
{
    struct stat st;
    char buf[1024], *l = NULL;
    int found = 0;
    FILE *m;

    system("/sbin/modprobe iptable_filter &>/dev/null");

    memset(buf, '\0', 64);
    if (stat("./ip_queue.o", &st) < 0)
	sprintf(buf, "/sbin/modprobe ip_queue &>/dev/null");
    else
	sprintf(buf, "/sbin/insmod ip_queue.o &>/dev/null");
    system(buf);

    memset(buf, '\0', 64);
    if (stat("./kaodv.o", &st) < 0)
	sprintf(buf, "/sbin/modprobe kaodv ifname=%s &>/dev/null", ifname);
    else
	sprintf(buf, "/sbin/insmod kaodv.o ifname=%s &>/dev/null", ifname);
    system(buf);

    /* Check result */
    m = fopen("/proc/modules", "r");
    while (fgets(buf, sizeof(buf), m)) {
	l = strtok(buf, " \t");
	if (!strcmp(l, "kaodv"))
	    found++;
	if (!strcmp(l, "ip_queue"))
	    found++;
	if (!strcmp(l, "ipchains")) {
	    fprintf(stderr,
		    "ERROR: The ipchains kernel module is loaded and prevents AODV-UU from functioning properly.\n");
	    exit(-1);
	}
    }
    fclose(m);
    if (found != 2) {
	fprintf(stderr,
		"A kernel module could not be loaded, check your installation...\n");
	exit(-1);
    }
}

void remove_modules(void)
{
    system("/sbin/modprobe -r kaodv &>/dev/null");
    system("/sbin/modprobe -r ip_queue &>/dev/null");
    system("/sbin/modprobe -r iptable_filter &>/dev/null");
}

void host_init(char *ifname)
{
    struct sockaddr_in *ina;
    char buf[1024], tmp_ifname[IFNAMSIZ],
	ifnames[(IFNAMSIZ + 1) * MAX_NR_INTERFACES], *iface;
    struct ifconf ifc;
    struct ifreq ifreq, *ifr;
    int i, iw_sock, if_sock = 0;

    memset(&this_host, 0, sizeof(struct host_info));
    memset(dev_indices, 0, sizeof(unsigned int) * MAX_NR_INTERFACES);

    if (!ifname) {
	/* No interface was given... search for first wireless. */
	iw_sock = socket(PF_INET, SOCK_DGRAM, 0);
	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(iw_sock, SIOCGIFCONF, &ifc) < 0) {
	    fprintf(stderr, "Could not get wireless info\n");
	    exit(-1);
	}
	ifr = ifc.ifc_req;
	for (i = ifc.ifc_len / sizeof(struct ifreq); i >= 0; i--, ifr++) {
	    struct iwreq req;

	    strcpy(req.ifr_name, ifr->ifr_name);
	    if (ioctl(iw_sock, SIOCGIWNAME, &req) >= 0) {
		strcpy(tmp_ifname, ifr->ifr_name);
		break;
	    }
	}
	/* Did we find a wireless interface? */
	if (!strlen(tmp_ifname)) {
	    fprintf(stderr, "\nCould not find a wireless interface!\n");
	    fprintf(stderr, "Use -i <interface> to override...\n\n");
	    exit(-1);
	}
	strcpy(ifreq.ifr_name, tmp_ifname);
	if (ioctl(iw_sock, SIOCGIFINDEX, &ifreq) < 0) {
	    log(LOG_ERR, errno, "Could not get index of %s", tmp_ifname);
	    close(if_sock);
	    exit(-1);
	}
	close(iw_sock);

	ifname = tmp_ifname;

	log(LOG_NOTICE, 0,
	    "INIT: Attaching to %s, override with -i <if1,if2,...>.",
	    tmp_ifname);
    }

    strcpy(ifnames, ifname);

    /* Intitialize the local sequence number an rreq_id to zero */
    this_host.seqno = 0;
    this_host.rreq_id = 0;

    /* Zero interfaces enabled so far... */
    this_host.nif = 0;

    /* Find the indices of all interfaces to broadcast on... */
    if_sock = socket(AF_INET, SOCK_DGRAM, 0);

    iface = strtok(ifname, ",");

    /* OK, now lookup interface information, and store it... */
    do {
	strcpy(ifreq.ifr_name, iface);
	if (ioctl(if_sock, SIOCGIFINDEX, &ifreq) < 0) {
	    log(LOG_ERR, errno, "Could not get index of %s", iface);
	    close(if_sock);
	    exit(-1);
	}

	dev_indices[this_host.nif++] = ifreq.ifr_ifindex;

	strcpy(DEV_IFINDEX(ifreq.ifr_ifindex).ifname, iface);

	/* Get IP-address of interface... */
	ina = get_if_info(iface, SIOCGIFADDR);
	if (ina == NULL)
	    exit(-1);

	DEV_IFINDEX(ifreq.ifr_ifindex).ipaddr = ntohl(ina->sin_addr.s_addr);

	/* Get netmask of interface... */
	ina = get_if_info(iface, SIOCGIFNETMASK);
	if (ina == NULL)
	    exit(-1);

	DEV_IFINDEX(ifreq.ifr_ifindex).netmask = ntohl(ina->sin_addr.s_addr);

	ina = get_if_info(iface, SIOCGIFBRDADDR);
	if (ina == NULL)
	    exit(-1);

	DEV_IFINDEX(ifreq.ifr_ifindex).broadcast = ntohl(ina->sin_addr.s_addr);

	DEV_IFINDEX(ifreq.ifr_ifindex).enabled = 1;

	if (this_host.nif >= MAX_NR_INTERFACES)
	    break;

    } while ((iface = strtok(NULL, ",")));

    close(if_sock);

    /* Load kernel modules */
    load_modules(ifnames);

    /* Enable IP forwarding and set other kernel options... */
    if (set_kernel_options() < 0) {
	fprintf(stderr, "Could not set kernel options!\n");
	exit(-1);
    }
    if (internet_gw_mode) {
	if (find_default_gw()) {
	    log(LOG_NOTICE, 0, "INIT: Internet gateway mode enabled!");
	    this_host.gateway_mode = 1;
	} else {
	    this_host.gateway_mode = 0;
	    sprintf(buf, "/sbin/route add default gw 127.0.0.1 dev lo");
	    system(buf);
	}
    }
}

/* This signal handler ensures clean exits */
void signal_handler(int type)
{

    switch (type) {
    case SIGSEGV:
	log(LOG_ERR, 0, "SEGMENTATION FAULT!!!! Exiting!!! "
	    "To get a core dump, compile with DEBUG option.");
    case SIGINT:
    case SIGHUP:
    case SIGTERM:
    default:
	exit(0);
    }
}

int main(int argc, char **argv)
{
    static char *ifname = NULL;	/* Name of interface to attach to */
    fd_set rfds, readers;
    int n, nfds = 0, i;
    int daemonize = 0;
    struct timeval *timeout;

    /* Remember the name of the executable... */
    progname = strrchr(argv[0], '/');

    if (progname)
	progname++;
    else
	progname = argv[0];

    /* Use debug output as default */
    debug = 1;

    /* Parse command line: */

    while (1) {
	int opt;

	opt = getopt_long(argc, argv, "i:jln:dghq:r:s:uwxDV", longopts, 0);

	if (opt == EOF)
	    break;

	switch (opt) {
	case 0:
	    break;
	case 'd':
	    debug = 0;
	    daemonize = 1;
	    break;
	case 'g':
	    rreq_gratuitous = 1;
	    break;
	case 'i':
	    ifname = optarg;
	    break;
	case 'j':
	    hello_jittering = 0;
	    break;
	case 'l':
	    log_to_file = 1;
	    break;
	case 'n':
	    if (optarg && isdigit(*optarg)) {
		receive_n_hellos = atoi(optarg);
		if (receive_n_hellos < 2) {
		    fprintf(stderr, "-n should be at least 2!\n");
		    exit(-1);
		}
	    }
	    break;
	case 'q':
	    if (optarg && isdigit(*optarg))
		hello_qual_threshold = atoi(optarg);
	    break;
	case 'r':
	    if (optarg && isdigit(*optarg))
		rt_log_interval = atof(optarg) * 1000;
	    break;
	case 's':
	    if (optarg)
		spy_addrs = optarg;
	    break;
	case 'u':
	    unidir_hack = 1;
	    break;
	case 'w':
	    internet_gw_mode = 1;
	    break;
	case 'x':
	    expanding_ring_search = 0;
	    break;
	case 'D':
	    wait_on_reboot = 0;
	    break;
	case 'V':
	    printf
		("\nAODV-UU v%s, AODV draft v10 � Uppsala University & Ericsson AB.\nAuthor: Erik Nordstr�m, erik.nordstrom@it.uu.se\n\n",
		 AODV_UU_VERSION);
	    exit(0);
	    break;
	case '?':
	case ':':
	    exit(0);
	default:
	    usage(0);
	}
    }
    /* Check that we are running as root */
    if (geteuid() != 0) {
	fprintf(stderr, "aodvd: must be root\n");
	exit(1);
    }

    /* Detach from terminal */
    if (daemonize) {
	if (fork() != 0)
	    exit(0);
	/* Close stdin, stdout and stderr... */
	/*  close(0); */
	close(1);
	close(2);
	setsid();
    }
    /* Make sure we cleanup at exit... */
    atexit((void *) &cleanup);

    /* Initialize data structures and services... */
    log_init();
    host_init(ifname);
    timer_queue_init();
    rt_table_init();
    packet_queue_init();
    packet_input_init();
    aodv_socket_init();
#ifdef USE_IW_SPY
    if (spy_addrs)
	link_qual_init(spy_addrs);
#endif
    /* Make sure we run at high priority to make up for the user space
       packet processing... */
    /* nice(-5);  */

    /* Catch SIGHUP, SIGINT and SIGTERM type signals */
    signal(SIGHUP, signal_handler);
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    /* Only capture segmentation faults when we are not debugging... */
#ifndef DEBUG
    signal(SIGSEGV, signal_handler);
#endif
    /* Set sockets to watch... */
    FD_ZERO(&readers);
    for (i = 0; i < nr_callbacks; i++) {
	FD_SET(callbacks[i].fd, &readers);
	if (callbacks[i].fd >= nfds)
	    nfds = callbacks[i].fd + 1;
    }

    /* Set the wait on reboot timer... */
    if (wait_on_reboot) {
	worb_timer.handler = wait_on_reboot_timeout;
	worb_timer.data = &wait_on_reboot;
	worb_timer.used = 0;
	timer_add_msec(&worb_timer, DELETE_PERIOD);
	log(LOG_NOTICE, 0,
	    "INIT: In wait on reboot for %d milliseconds. Disable with \"-D\".",
	    DELETE_PERIOD);
    }

    /* Schedule the first Hello */
    hello_init();

    if (rt_log_interval)
	log_rt_table_init();

    while (1) {
	memcpy((char *) &rfds, (char *) &readers, sizeof(rfds));

	timeout = timer_age_queue();

	if ((n = select(nfds, &rfds, NULL, NULL, timeout)) < 0) {
	    if (errno != EINTR)
		log(LOG_WARNING, errno, "main.c: Failed select (main loop)");
	    continue;
	}

	if (n > 0) {
	    for (i = 0; i < nr_callbacks; i++) {
		if (FD_ISSET(callbacks[i].fd, &rfds)) {
		    /* We don't want any timer SIGALRM's while executing the
		       callback functions, therefore we block the timer... */
		    (*callbacks[i].func) (callbacks[i].fd);
		}
	    }
	}
    }				/* Main loop */
    return 0;
}

static void cleanup(void)
{
    DEBUG(LOG_DEBUG, 0, "CLEANING UP!");
    if (internet_gw_mode && !this_host.gateway_mode)
	system("/sbin/route del default");
    remove_modules();
    rt_table_destroy();
    packet_input_cleanup();
    aodv_socket_cleanup();
#ifdef USE_IW_SPY
    link_qual_cleanup();
#endif
    log_cleanup();
}
