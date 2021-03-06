/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Shane Alcock
 *         Brendon Jones
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * amplet2 is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations including
 * the two.
 *
 * You must obey the GNU General Public License in all respects for all
 * of the code used other than OpenSSL. If you modify file(s) with this
 * exception, you may extend this exception to your version of the
 * file(s), but you are not obligated to do so. If you do not wish to do
 * so, delete this exception statement from your version. If you delete
 * this exception statement from all source files in the program, then
 * also delete it here.
 *
 * amplet2 is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with amplet2. If not, see <http://www.gnu.org/licenses/>.
 */

#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <event2/event.h>
#include <arpa/inet.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <errno.h>
#include <pcap/sll.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>

#include "config.h"
#include "testlib.h"
#include "pcapcapture.h"
#include "debug.h"

struct ifaddrs *ifaddrlist = NULL;
struct ifaddrs *ifaddrorig = NULL;

struct pcapdevice *pcaps = NULL;



/*
 * Find the start of the real addresses in the list of addresses belonging
 * to an interface. This assumes that all the AF_PACKET addresses are at the
 * beginning, followed by the AF_INET and AF_INET6 addresses.
 */
static int get_interface_addresses(void) {
    struct ifaddrs *ifa;

    if ( getifaddrs(&ifaddrorig) == -1 ) {
        Log(LOG_ERR, "Unable to fetch interface addresses, aborting test");
        return -1;
    }

    /* Loop over address list and skip past all the AF_PACKET addresses */
    for ( ifa = ifaddrorig; ifa != NULL; ifa = ifa->ifa_next ) {
        int family;

        if ( ifa->ifa_addr == NULL ) {
            continue;
        }

        family = ifa->ifa_addr->sa_family;

        if ( family == AF_INET || family == AF_INET6 ) {
            ifaddrlist = ifa;
            break;
        }
    }

    return 0;
}



/*
 * Determine which interface a given address belongs to.
 */
static char *find_address_interface(struct sockaddr *sin) {
    struct ifaddrs *ifa;

    for ( ifa = ifaddrlist; ifa != NULL; ifa = ifa->ifa_next ) {
        if ( ifa->ifa_addr == NULL ) {
            continue;
        }

        if ( ifa->ifa_addr->sa_family != sin->sa_family ) {
            continue;
        }

        if ( ifa->ifa_addr->sa_family == AF_INET ) {
            struct sockaddr_in *sin4 = (struct sockaddr_in *)sin;
            struct sockaddr_in *ifa4 = (struct sockaddr_in *)(ifa->ifa_addr);

            if ( sin4->sin_addr.s_addr == ifa4->sin_addr.s_addr ) {
                return ifa->ifa_name;
            }
        }

        if ( ifa->ifa_addr->sa_family == AF_INET6 ) {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sin;
            struct sockaddr_in6 *ifa6 = (struct sockaddr_in6 *)(ifa->ifa_addr);

            if ( memcmp(&sin6->sin6_addr.s6_addr, &ifa6->sin6_addr.s6_addr,
                        sizeof(struct in6_addr)) == 0 ) {
                return ifa->ifa_name;
            }
        }
    }

    return NULL;
}



/*
 * Create a pcap filter that will match only traffic between the ports we
 * are using for this test.
 */
static int create_pcap_filter(struct pcapdevice *p, uint16_t srcportv4,
        uint16_t srcportv6, uint16_t destport, char *device) {

    struct bpf_program fcode;
    char pcaperr[PCAP_ERRBUF_SIZE];
    char filterstring[1024];

#if HAVE_PCAP_IMMEDIATE_MODE
    p->pcap = pcap_create(device, pcaperr);
#else
    /* XXX Hard-coded snaplen -- be wary if repurposing for other tests */
    p->pcap = pcap_open_live(device, 200, 0, 10, pcaperr);
#endif

    if ( p->pcap == NULL ) {
        Log(LOG_ERR, "Failed to open live pcap: %s", pcaperr);
        return 0;
    }

#if HAVE_PCAP_IMMEDIATE_MODE
    if ( pcap_set_immediate_mode(p->pcap, 1) != 0 ) {
        Log(LOG_ERR, "Failed to set pcap immediate mode");
        return 0;
    }
    /* XXX Hard-coded snaplen -- be wary if repurposing for other tests */
    if ( pcap_set_snaplen(p->pcap, 200) != 0 ) {
        Log(LOG_ERR, "Failed to set pcap snaplen");
        return 0;
    }

    if ( pcap_set_promisc(p->pcap, 0) != 0 ) {
        Log(LOG_ERR, "Failed to disable promiscuous mode");
        return 0;
    }

    if ( pcap_set_timeout(p->pcap, 10) != 0 ) {
        Log(LOG_ERR, "Failed to set pcap read timeout");
        return 0;
    }

    if ( pcap_activate(p->pcap) != 0 ) {
        Log(LOG_ERR, "Failed to activate pcap handle:%s", pcap_geterr(p->pcap));
        return 0;
    }
#endif

    snprintf(filterstring, 1024-1,
            //"(tcp and (dst port %d or dst port %d) and src port %d)",
            "(tcp and (dst port %d or dst port %d) and src port %d) or (icmp[0] == 11 or icmp[0] == 3) or (icmp6)",
            srcportv4, srcportv6, destport);

    Log(LOG_DEBUG, "Compiling filter string %s for device %s", filterstring,
        device);

    if ( pcap_compile(p->pcap, &fcode, filterstring, 1,
                PCAP_NETMASK_UNKNOWN) < 0 ) {
        Log(LOG_ERR, "Failed to compile BPF filter for device %s", device);
        return 0;
    }

    if ( pcap_setfilter(p->pcap, &fcode) < 0 ) {
        Log(LOG_ERR, "Failed to set BPF filter for device %s", device);
        return 0;
    }

    /* once it has been installed then the filter program can be freed */
    pcap_freecode(&fcode);

    p->pcap_fd = pcap_fileno(p->pcap);
    return p->pcap_fd;
}



/*
 * Find the source address that would be used to connect to the given
 * desination.
 */
int find_source_address(char *device, struct addrinfo *dest,
        struct sockaddr *saddr) {

    int s;
    socklen_t size;
    struct sockaddr *gendest = NULL;
    struct sockaddr_in6 sin6dest;
    struct sockaddr_in sin4dest;

    /* Find the source address that we should use to test to our dest */
    if ( (s = socket(dest->ai_family, SOCK_DGRAM, IPPROTO_UDP)) < 0 ) {
        Log(LOG_ERR, "Failed to create socket in find_source_address");
        return 0;
    }

    /* bind to device if given, limits the source addresses available to us */
    if ( device ) {
        if ( bind_socket_to_device(s, device) < 0 ) {
            Log(LOG_ERR, "Failed binding to device in find_source_address");
            return 0;
        }
    }

    if ( dest->ai_family == AF_INET ) {
        struct sockaddr_in *destptr;
        size = sizeof(struct sockaddr_in);

        memset(&sin4dest, 0, sizeof(struct sockaddr_in));
        destptr = (struct sockaddr_in *)(dest->ai_addr);

        sin4dest.sin_family = AF_INET;
        sin4dest.sin_addr.s_addr = destptr->sin_addr.s_addr;
        sin4dest.sin_port = htons(53);
        gendest = (struct sockaddr *)&sin4dest;
    } else if ( dest->ai_family == AF_INET6 ) {
        struct sockaddr_in6 *destptr;
        size = sizeof(struct sockaddr_in6);

        memset(&sin6dest, 0, sizeof(struct sockaddr_in6));
        destptr = (struct sockaddr_in6 *)(dest->ai_addr);

        sin6dest.sin6_family = AF_INET6;
        memcpy(&sin6dest.sin6_addr, &destptr->sin6_addr,
                sizeof(struct in6_addr));
        sin6dest.sin6_port = htons(53);
        gendest = (struct sockaddr *)&sin6dest;

    }

    if ( gendest == NULL ) {
        Log(LOG_ERR, "Failed to create target address in find_source_address");
        return 0;
    }

    /*
     * Connecting the datagram socket is enough to determine which source
     * address will be used, testing shows we don't need to actually send any
     * data.
     */
    if ( connect(s, gendest, size) < 0 ) {
        Log(LOG_DEBUG,
                "Failed to connect to destination in find_source_address: %s",
                strerror(errno));
        return 0;
    }

    if ( getsockname(s, (struct sockaddr *)saddr, &size) < 0 ) {
        Log(LOG_ERR, "Failed to get socket information in find_source_address");
        return 0;
    }

    close(s);

    return 1;
}



/*
 * Start the pcap filter running and install the callback for when it receives
 * a packet.
 */
int pcap_listen(struct sockaddr *address, uint16_t srcportv4,
        uint16_t srcportv6, uint16_t destport, char *device,
        struct event_base *base,
        void *callbackdata,
        void(*callback)(evutil_socket_t evsock, short flags, void *evdata)) {

    struct pcapdevice *p;

    /* If we don't have a list of all addresses on this machine, get them. */
    if ( ifaddrorig == NULL && get_interface_addresses() == -1 ) {
        return 0;
    }

    if ( device == NULL ) {
        device = find_address_interface(address);

        if ( device == NULL ) {
            Log(LOG_ERR, "Failed to find interface to add BPF filter");
            return 0;
        }
    }

    /* Find the device in our list of existing pcap devices */
    for ( p = pcaps; p != NULL; p = p->next ) {
        if ( strcmp(p->if_name, device) == 0 ) {
            break;
        }
    }

    /* If it exists already, no need to do anything */
    if ( p != NULL ) {
        return 1;
    }

    /* If not, create a new pcap device with the appropriate filter */
    p = (struct pcapdevice *)malloc(sizeof(struct pcapdevice));

    if ( create_pcap_filter(p, srcportv4, srcportv6, destport, device) == 0 ) {
        Log(LOG_ERR, "Failed to create bpf filter for device %s", device);
        return 0;
    }

    p->callbackdata = callbackdata;
    p->if_name = strdup(device);
    p->next = pcaps;
    pcaps = p;

    /* Add the fd for the new device to our event handler so that our
     * callback will fire whenever a packet arrives */
    p->event = event_new(base, p->pcap_fd, EV_READ|EV_PERSIST, callback, p);
    if ( event_add(p->event, NULL) != 0 ) {
        Log(LOG_ERR, "Failed to add fd event for new pcap device %s", device);
        return 0;
    }

    return 1;
}



/*
 * Naive code to read the next pcap packet and find a TCP header.
 * Assumes the packet is the standard Ethernet:IP:TCP header layout.
 * Doesn't deal with anything like extra link layer headers, IPv6 extension
 * headers, fragmentation etc.
 * TODO libtrace would do a much nicer job of finding the TCP header for us
 */
struct pcaptransport pcap_transport_header(struct pcapdevice *p) {

    char *packet = NULL;
    struct pcap_pkthdr header;
    struct iphdr *ip;
    struct ip6_hdr *ip6;
    struct pcaptransport transport;
    int remaining;
    int datalink;
    int ethertype;

    transport.header = NULL;
    transport.protocol = 0;
    transport.remaining = 0;
    transport.ts.tv_sec = 0;
    transport.ts.tv_usec = 0;

    packet = (char *)pcap_next(p->pcap, &header);
    if ( packet == NULL ) {
        Log(LOG_DEBUG,
                "Null result from pcap_next() -- packet was probably filtered");
        return transport;
    }

    transport.ts = header.ts;
    remaining = header.len;

    datalink = pcap_datalink(p->pcap);

    /* find the start of the packet, which depends on the link layer */
    if ( datalink == DLT_EN10MB ) {
        struct ether_header *eth;
        /* this is an ethernet interface, expect an ethernet header */
        if ( remaining < (int)sizeof(struct ether_header) ) {
            Log(LOG_WARNING, "Too few bytes captured for Ethernet header");
            return transport;
        }

        eth = (struct ether_header *)packet;
        remaining -= sizeof(struct ether_header);
        packet += sizeof(struct ether_header);
        ethertype = ntohs(eth->ether_type);

    } else if ( datalink == DLT_LINUX_SLL ) {
        struct sll_header *sll;
        /* this is a linux sll interface (probably ppp), expect sll header */
        if ( remaining < (int)sizeof(struct sll_header) ) {
            Log(LOG_WARNING, "Too few bytes captured for SLL header");
            return transport;
        }

        sll = (struct sll_header *)packet;
        remaining -= sizeof(struct sll_header);
        packet += sizeof(struct sll_header);
        ethertype = ntohs(sll->sll_protocol);

    } else {
        Log(LOG_DEBUG, "Unknown PCAP link layer %u", datalink);
        return transport;
    }

    /* process any ipv4 or ipv6 packets, ignore everything else */
    if ( ethertype == ETHERTYPE_IP ) {
        ip = (struct iphdr *)packet;
        if ( remaining < (int)sizeof(struct iphdr) ) {
            Log(LOG_WARNING, "Too few bytes captured for IPv4 header");
            return transport;
        }

        if ( remaining < ip->ihl * 4 ) {
            Log(LOG_WARNING, "Too few bytes captured for IPv4 header");
            return transport;
        }

        packet += (ip->ihl * 4);
        remaining -= (ip->ihl * 4);

        transport.header = packet;
        transport.remaining = remaining;
        transport.protocol = ip->protocol;

    } else if ( ethertype == ETHERTYPE_IPV6 ) {

        ip6 = (struct ip6_hdr *)packet;
        if ( remaining < (int)sizeof(struct ip6_hdr) ) {
            Log(LOG_WARNING, "Too few bytes captured for IPv6 header");
            return transport;
        }

        packet += sizeof(struct ip6_hdr);
        remaining -= sizeof(struct ip6_hdr);

        transport.header = packet;
        transport.remaining = remaining;
        transport.protocol = ip6->ip6_nxt;

    } else {
        /*
         * We can sometimes catch other, non-IP traffic before the filter
         * gets applied (e.g. for some reason we are frequently seeing
         * packets with ethertype 0x100 (vlans).
         */
        Log(LOG_DEBUG, "Captured a non IP packet: %u", ethertype);
    }

    return transport;
}



/*
 * Close up any pcap devices used during the test.
 */
void pcap_cleanup(void) {
    struct pcapdevice *p = pcaps;
    struct pcapdevice *tmp;

    while ( p != NULL ) {
        /* Remove each pcap device fd from the event handler */
        event_free(p->event);

        /* Close the pcap device */
        pcap_close(p->pcap);

        /* Free the pcapdevice structure */
        free(p->if_name);
        tmp = p;
        p = p->next;
        free(tmp);
    }

    freeifaddrs(ifaddrorig);
}

/* vim: set sw=4 tabstop=4 softtabstop=4 expandtab : */
