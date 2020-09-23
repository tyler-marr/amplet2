/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Author: Brendon Jones
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

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>	
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <sys/time.h>
#include <assert.h>
#include <arpa/inet.h>
#include <string.h>
#include <signal.h>
#include <event2/event.h>
#include <ifaddrs.h>

#include "config.h"
#include "tests.h"
#include "testlib.h"
#include "srv6.h"
#include "srv6.pb-c.h"
#include "debug.h"
#include "icmpcode.h"
#include "dscp.h"
#include "usage.h"
#include "checksum.h"


/*
 * TODO collect more information than what the original icmp test did.
 * Things like rtt could be interesting to track.
 */

static struct option long_options[] = {
    {"perturbate", required_argument, 0, 'p'},
    {"path", required_argument, 0, 'P'},
    {"random", no_argument, 0, 'r'},
    {"size", required_argument, 0, 's'},
    {"dscp", required_argument, 0, 'Q'},
    {"interpacketgap", required_argument, 0, 'Z'},
    {"interface", required_argument, 0, 'I'},
    {"ipv4", optional_argument, 0, '4'},
    {"ipv6", optional_argument, 0, '6'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {NULL, 0, 0, 0}
};



/*
 * Halt the event loop in the event of a SIGINT (either sent from the terminal
 * if running standalone, or sent by the watchdog if running as part of
 * measured) and report the results that have been collected so far.
 */
static void interrupt_test(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void * evdata) {

    struct event_base *base = (struct event_base *)evdata;
    Log(LOG_INFO, "Received SIGINT, halting ICMP test");
    event_base_loopbreak(base);
}



/*
 * Force the event loop to halt, so we can end the test and report the
 * results that we do have.
 */
static void halt_test(
    __attribute__((unused))evutil_socket_t evsock,
    __attribute__((unused))short flags,
    void *evdata) {
    struct icmpglobals_t *globals = (struct icmpglobals_t *)evdata;

    Log(LOG_DEBUG, "Halting ICMP test due to timeout");
    if ( globals->losstimer ) {
        event_free(globals->losstimer);
        globals->losstimer = NULL;
    }
    event_base_loopbreak(globals->base);
}



/*
 * Get the value of the TTL field in the IPv4 or IPv6 header.
 */
static int get_ttl(int family, char *packet) {
    if ( packet == NULL ) {
        return -1;
    }

    switch ( family ) {
        case AF_INET:
            return ((struct iphdr *)packet)->ttl;
        case AF_INET6:
            return ((struct ip6_hdr*)packet)->ip6_ctlun.ip6_un1.ip6_un1_hlim;
        default:
            return -1;
    };

}



/*
 * Callback used when a packet is received that might be a response to one
 * of our probes.
 */
static void receive_probe_callback(evutil_socket_t evsock,
        short flags, void *evdata) {

    struct timeval now;
    struct ipv6_sr_hdr *srh;
    ssize_t bytes;
    int wait = 0;
    int ttl = -1;
    char buf[RESPONSE_BUFFER_LEN+1];
    char str[INET6_ADDRSTRLEN] = {0};
    struct icmpglobals_t *globals = (struct icmpglobals_t*)evdata;

    assert(evsock > 0);
    assert(flags == EV_READ);
    struct socket_t sockets;
    sockets.socket6 = evsock;
    sockets.socket = -1;

    if (  (bytes = get_SRH_packet(&sockets, buf, RESPONSE_BUFFER_LEN+1,
            &srh, &wait, &now, &ttl)) > 0 ) {
        //TODO add not clause
    }

    struct magic_seq *magic_seq = buf;

    uint16_t seq = magic_seq->seq;
    uint16_t magic = magic_seq->magic;

    /* check that the magic value in the reply matches what we expected */
    if ( magic != globals->info[seq].magic ) {
        Log(LOG_DEBUG, "magic did not match, was [%d]%04x found %04x", 
                seq,
                globals->info[seq].magic, 
                magic
                );
        return;
    }

    if ( srh ) {

        globals->info[seq].srh = malloc(
                sizeof(*srh) + ((1+srh->first_segment) * sizeof(struct in6_addr)));
        memcpy(globals->info[seq].srh, srh,
                sizeof(*srh) + ((1+srh->first_segment) * sizeof(struct in6_addr)));

        //after we are done with the SRH, we need to free it
        free(srh);
    }

    /* reply is good, record the round trip time */
    globals->info[seq].reply = 1;
    globals->outstanding--;

    int64_t delay = DIFF_TV_US(now, globals->info[seq].time_sent);
    if ( delay > 0 ) {
        globals->info[seq].delay = (uint32_t)delay;
    } else {
        globals->info[seq].delay = 0;
    }

    globals->info[seq].ttl = ttl;



    Log(LOG_DEBUG, "Good ICMP6 ECHOREPLY");

    if ( globals->outstanding == 0 && globals->index == globals->path_count ) {
        /* not waiting on any more packets, exit the event loop */
        Log(LOG_DEBUG, "All expected ICMP responses received");
        event_base_loopbreak(globals->base);
    }
}

/*
 * Callback used when a packet is received that might be a response to one
 * of our probes.
 */
static void receive_icmp_callback(evutil_socket_t evsock,
        short flags, void *evdata) {

    char packet[1000];
    struct timeval now;
    struct iphdr *ip;
    ssize_t bytes;
    int wait;
    struct socket_t sockets;
    struct icmpglobals_t *globals = (struct icmpglobals_t*)evdata;
    struct sockaddr_in6 saddr;

    assert(evsock > 0);
    assert(flags == EV_READ);

    wait = 0;

    /* the socket used here doesn't matter as the family isn't used anywhere */
    sockets.socket = -1;
    sockets.socket6 = evsock;

    if ( (bytes=get_packet(&sockets, packet, sizeof(packet), &saddr, &wait,
                    &now)) > 0 ) {
        struct icmp6_hdr *icmp;

        if ( bytes < sizeof(struct icmp6_hdr) ) {
            return -1;
        }

        /* any icmpv6 packets we get have the outer ipv6 header stripped */
        icmp = (struct icmp6_hdr *)packet;

        /* sanity check the various fields of the icmp header */
        if ( icmp->icmp6_type != ICMP6_DST_UNREACH || 
                icmp->icmp6_code != ICMP6_DST_UNREACH_ADDR ) {
            return -1;
            //not an applicable ICMP6 error (can handle more later)
        }

        struct ip6_hdr *ip6 = icmp+1;

        /* we expect to see an SRv6 routing hearder, ie  */
        if ( ip6->ip6_nxt != 43 ) { //TODO RTHDR(43) magic number
           Log(LOG_DEBUG, "IPv6->next != RTHDR");
           return -1;
        }

        /* Routing header */
        struct ipv6_sr_hdr *srv6_hdr = ip6+1;

        //TODO UDP(17) and SRv6(4) magic numbers
        if ( srv6_hdr->nexthdr != 17 || srv6_hdr->type != 4) {
            //error
            Log(LOG_DEBUG, "srv6_hdr->next != UDP || srv6_hdr->type != SRv6");
            return -1;
        }

        struct udphdr *udphdr  = ((void *)(srv6_hdr+1)) + ((srv6_hdr->hdrlen)*8);
        struct magic_seq *magic_seq = (udphdr+1);

        char src_address[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(saddr.sin6_addr), src_address, INET6_ADDRSTRLEN);

        char dst_address[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_address, INET6_ADDRSTRLEN);

        if (magic_seq->magic != globals->info[magic_seq->seq].magic) {
            //not our packet
            return -1;
        }

        Log(LOG_DEBUG, "ICMP6 dest unreachable, %s cant find %s", 
                src_address, dst_address);

        // for (int i = 0; i< 32; i++){
        //     printf("%02x ", *(((uint8_t*)udphdr)+i));
        //     if (!((i+1)%8)) printf(" ");
        //     if (!((i+1)%16)) printf("\n");
        // } printf("\n");
        // printf("ip6_hdr next hdr: %d\n", ip6->ip6_nxt);
        // printf("srv6_hdr next hdr: %d\n",srv6_hdr->nexthdr);
        // printf("srv6_hdr type: %d\n",srv6_hdr->type);
        // printf("srv6_hdr len: %d\n",srv6_hdr->hdrlen);
        // printf("UDP->port: %d\n",ntohs(udphdr->source));
        // printf("UDP->port: %d\n",ntohs(udphdr->dest));
        // printf("UDP->len:\n",udphdr->len);

        // printf("Seq:%d\n",magic_seq->seq);
        // printf("Magic:%d\n",magic_seq->magic);
        // printf("Expected magic: [%d]%d\n",magic_seq->seq, globals->info[magic_seq->seq].magic);
        

        /* reply is good, record the round trip time */
        uint16_t seq = magic_seq->seq;
        globals->info[seq].reply = 1;
        globals->outstanding--;

        globals->info[seq].srh = malloc(
                sizeof(*srv6_hdr) + ((1+srv6_hdr->first_segment) * sizeof(struct in6_addr)));
        memcpy(globals->info[seq].srh, srv6_hdr,
                sizeof(*srv6_hdr) + ((1+srv6_hdr->first_segment) * sizeof(struct in6_addr)));

        int64_t delay = DIFF_TV_US(now, globals->info[seq].time_sent);
        if ( delay > 0 ) {
            globals->info[seq].delay = (uint32_t)delay;
        } else {
            globals->info[seq].delay = 0;
        }

        globals->info[seq].ttl = ip6->ip6_hops;
        globals->info[seq].err_code = icmp->icmp6_code;
        globals->info[seq].err_type = icmp->icmp6_type;

        Log(LOG_DEBUG, "Good ICMP6 error report");

        if ( globals->outstanding == 0 && globals->index == globals->path_count ) {
            /* not waiting on any more packets, exit the event loop */
            Log(LOG_DEBUG, "All expected ICMP responses received");
            event_base_loopbreak(globals->base);
        }
    }
}



static struct ipv6_sr_hdr * build_srh(int *srh_lenp,
        struct addrinfo *path){
    
    int srh_len;
    struct ipv6_sr_hdr *srh;
    int path_length = 0;

    for (struct addrinfo *temp = path; temp; temp = temp->ai_next){
        path_length+=1;
    }

    int seg_num = path_length;
    srh_len = sizeof(*srh) + ((1+seg_num) * sizeof(struct in6_addr));
    srh = malloc(srh_len);
    if (!srh)
        return NULL;

    srh->nexthdr = 0;
    srh->hdrlen = 2 * (1+seg_num);
    srh->type = 4;
    srh->segments_left = seg_num;
    srh->first_segment = seg_num;
    srh->flag_1 = 0;
    srh->flag_2 = 0;
    srh->reserved = 0;

    memset(&srh->segments[0], 0, sizeof(struct in6_addr));
    //for (int i = 0; i< seg_num; i++){
    int i =0;
    for (struct addrinfo *temp = path; temp; temp = temp->ai_next){
        //inet_pton(AF_INET6, globals->dests[i]->ai_addr, &srh->segments[1+i]);
        
        memcpy(&srh->segments[1+i], 
                &((struct sockaddr_in6 *)(temp->ai_addr))->sin6_addr, sizeof(struct in6_addr));
        i++;
    }
    *srh_lenp = srh_len;
    return srh;
}



/*
 * Construct and send an icmp echo request packet.
 */
static void send_packet(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void *evdata) {

    char *packet = NULL;
    int sock;
    int length;
    int delay;
    uint16_t seq;
    int srh_len = 0;
    struct addrinfo *path;
    struct opt_t *opt;
    struct icmpglobals_t *globals;
    struct info_t *info;
    struct timeval timeout;
    struct ipv6_sr_hdr *srh;

    globals = (struct icmpglobals_t *)evdata;
    info = globals->info;
    seq = globals->index;
    path = globals->paths_array[seq];
    opt = &globals->options;
    info[seq].magic = rand();

    /* TODO should we try to send the next packet in this time slot? */
    if ( !path->ai_addr ) {
        Log(LOG_INFO, "No address for target %s, skipping", path->ai_canonname);
        goto next;
    }

    sock = globals->sockets.socket6;

    if ( sock < 0 ) {
        Log(LOG_WARNING, "Unable to test to %s, socket wasn't opened",
                path->ai_canonname);
        goto next;
    }

    srh = build_srh(&srh_len, path);
    if (!srh) {
        Log(LOG_DEBUG, "failed srh");
        close(sock);
        goto next;
    }

    int err = setsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR, srh, srh_len);
    if (err < 0) {
        perror("setsockopt");
        close(sock);
        goto next;
    }

    /* build the probe packet */
    struct magic_seq magic_seq;
    length = sizeof(magic_seq);
    magic_seq.seq = seq;
    magic_seq.magic = info[seq].magic;


    struct addrinfo hop;
    hop.ai_addr =  (struct sockaddr *)&globals->self;
    hop.ai_addrlen =  sizeof(globals->self);

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, &magic_seq, length, &hop,
                    opt->inter_packet_delay, &(info[seq].time_sent))) > 0 ) {
        usleep(delay);
    }

    if ( delay < 0 ) {
        /* mark this as done if the packet failed to send properly */
        info[seq].reply = 1;
        memset(&(info[seq].time_sent), 0, sizeof(struct timeval));
    } else {
        globals->outstanding++;
    }

next:
    globals->index++;

    if ( globals->nextpackettimer ) {
        event_free(globals->nextpackettimer);
        globals->nextpackettimer = NULL;
    }
    /* create timer for sending the next packet if there are still more to go */
    if ( globals->index == globals->path_count ) {
        Log(LOG_DEBUG, "Reached final target: %d", globals->index);
        if ( globals->outstanding == 0 ) {
            /* avoid waiting for LOSS_TIMEOUT if no packets are outstanding */
            event_base_loopbreak(globals->base);
        } else {
            globals->losstimer = event_new(globals->base, -1, 0,
                    halt_test, globals);
             timeout.tv_sec = LOSS_TIMEOUT;
            timeout.tv_usec = 0;
            event_add(globals->losstimer, &timeout);
        }
    } else {
        globals->nextpackettimer = event_new(globals->base, -1, 0,
                send_packet, globals);
        timeout.tv_sec = (int)(globals->options.inter_packet_delay / 1000000);
        timeout.tv_usec = globals->options.inter_packet_delay % 1000000;
        event_add(globals->nextpackettimer, &timeout);
    }
}



/*
 * Open the raw ICMP and ICMPv6 sockets used for this test and configure
 * appropriate filters for the ICMPv6 socket to only receive echo replies.
 */
static int open_sockets(struct socket_t *sockets) {

    int on = 1;

    sockets->socket = -1; //does not use ipv4

    if ( (sockets->socket6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        Log(LOG_WARNING, "Failed to open raw socket for ICMPv6");
    } else {
        if ( setsockopt(sockets->socket6, IPPROTO_IPV6, IPV6_RECVRTHDR,
                &on, sizeof(on)) < 0) {
            Log(LOG_WARNING, "Could not set IPv6 RECVHDR");
        }


        if ( setsockopt(sockets->socket6, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                &on, sizeof(on)) < 0) {
            Log(LOG_WARNING, "Could not set IPV6_RECVHOPLIMIT");
        }


        /* configure ICMPv6 filters to only pass through ICMPv6 echo reply */
        // struct icmp6_filter filter;
        // ICMP6_FILTER_SETBLOCKALL(&filter);
        // ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filter);
        // if ( setsockopt(sockets->socket6, SOL_ICMPV6, ICMP6_FILTER,
        //         &filter, sizeof(struct icmp6_filter)) < 0 ) {
        //     Log(LOG_WARNING, "Could not set ICMPv6 filter");
        // }
    }

    /* make sure at least one type of socket was opened */
    if ( sockets->socket6 < 0 ) {
        return 0;
    }

    return 1;
}



/*
 * Construct a protocol buffer message containing the results for a single
 * destination address.
 */
static Amplet2__Icmp__Item* report_destination(struct info_t *info) {

    Amplet2__Icmp__Item *item =
        (Amplet2__Icmp__Item*)malloc(sizeof(Amplet2__Icmp__Item));
    char str[INET6_ADDRSTRLEN] = {0};

    /* fill the report item with results of a test */
    amplet2__icmp__item__init(item);
    item->has_family = 1;
    item->family = info->addr;
    // if (info->srh) {
    //     inet_ntop(AF_INET6, &(info->srh->segments[info->srh->first_segment-1]), str, sizeof(str));
    //     printf("SUT: %s", str);
    //     item->name = malloc(strlen(str));//address_to_name(info->srh->segments[0]);
    //     memcpy(item->name, str, strlen(str));
    //     //item->has_address = copy_address_to_protobuf(&item->address, info->addr[0]);
    //     //TODO update the protobuf
    //     free(info->srh);
    // }
    // info->srh = NULL;

    if ( info->reply && info->time_sent.tv_sec > 0 &&
            (info->err_type == ICMP_REDIRECT ||
             (info->err_type == 0 && info->err_code == 0)) ) {
        /* report the rtt if we got a valid reply */
        item->has_rtt = 1;
        item->rtt = info->delay;
        item->has_ttl = 1;
        item->ttl = info->ttl;
    } else {
        /* don't send an rtt if there wasn't a valid one recorded */
        item->has_rtt = 0;
        item->has_ttl = 0;
    }

    if ( item->has_rtt || info->err_type > 0 ) {
        /* valid response (0/0) or a useful error, set the type/code fields */
        item->has_err_type = 1;
        item->err_type = info->err_type;
        item->has_err_code = 1;
        item->err_code = info->err_code;
    } else {
        /* missing response, don't include type and code fields */
        item->has_err_type = 0;
        item->has_err_code = 0;
    }

    Log(LOG_DEBUG, "icmp result: %dus, %d/%d\n",
            item->has_rtt?(int)item->rtt:-1, item->err_type, item->err_code);

    return item;
}



/*
 * Construct a protocol buffer message containing all the test options and the
 * results for each destination address.
 */
static amp_test_result_t* report_results(struct timeval *start_time, int count,
        struct info_t info[], struct opt_t *opt) {

    int i;
    amp_test_result_t *result = calloc(1, sizeof(amp_test_result_t));

    Log(LOG_DEBUG, "Building icmp report, count:%d psize:%d rand:%d dscp:%0x\n",
            count, opt->packet_size, opt->random, opt->dscp);

    Amplet2__Icmp__Report msg = AMPLET2__ICMP__REPORT__INIT;
    Amplet2__Icmp__Header header = AMPLET2__ICMP__HEADER__INIT;
    Amplet2__Icmp__Item **reports;

    /* populate the header with all the test options */
    header.has_packet_size = 1;
    header.packet_size = opt->packet_size;
    header.has_random = 1;
    header.random = opt->random;
    header.has_dscp = 1;
    header.dscp = opt->dscp;

    /* build up the repeated reports section with each of the results */
    reports = malloc(sizeof(Amplet2__Icmp__Item*) * count);
    for ( i = 0; i < count; i++ ) {
        reports[i] = report_destination(&info[i]);
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;
    msg.n_reports = count;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__icmp__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__icmp__report__pack(&msg, result->data);

    /* free up all the memory we had to allocate to report items */
    for ( i = 0; i < count; i++ ) {
        free(reports[i]);
    }
    free(reports);

    return result;
}



/*
 * The usage statement when the test is run standalone. All of these options
 * are still valid when run as part of the amplet2-client.
 */
static void usage(void) {
    fprintf(stderr,
            "Usage: amp-srv6 [-hrvx] [-p perturbate] [-s packetsize]\n"
            "                -P [comma seperated list of hops]\n"
            "                [-Q codepoint] [-Z interpacketgap]\n"
            "                [-I interface] [-4 [sourcev4]] [-6 [sourcev6]]\n"
            "                -- destination1 [destination2 ... destinationN]"
            "\n\n");

    /* test specific options */
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -p, --perturbate     <msec>    "
            "Maximum number of milliseconds to delay test\n");
    fprintf(stderr, "  -r, --random                   "
            "Use a random packet size for each test\n");
    fprintf(stderr, "  -s, --size           <bytes>   "
            "Fixed packet size to use for each test\n");

    print_probe_usage();
    print_interface_usage();
    print_generic_usage();
}



int parse_pathlist(char *address_string, struct icmpglobals_t *globals) {
    
    char *str;
    struct addrinfo *addr;
    struct addrinfo *res = NULL;
    char * delim = ',';
    int path_length = 0;

    str = strtok(address_string, &delim);

    while ( str ) {
        if ( (addr = get_numeric_address(str, NULL)) ) {
            struct addrinfo *keeper = calloc(1, sizeof(struct addrinfo));

            keeper->ai_flags = addr->ai_flags;
            keeper->ai_family = addr->ai_family;
            keeper->ai_socktype = addr->ai_socktype;
            keeper->ai_protocol = addr->ai_protocol;
            keeper->ai_addrlen = addr->ai_addrlen;
            keeper->ai_addr = calloc(1, keeper->ai_addrlen);

            assert(keeper->ai_addrlen > 0);
            assert(keeper->ai_addr);

            memcpy(keeper->ai_addr, addr->ai_addr, keeper->ai_addrlen);
            keeper->ai_canonname = strdup(str);
            keeper->ai_next = res;
            res = keeper;

            /* free the getaddrinfo() allocated memory */
            freeaddrinfo(addr);
            str = strtok(NULL, &delim);
            path_length +=1;
            continue;
        }
        //cleanup previous addrs
        return 0;
    }


    globals->path_count += 1;




    globals->paths_array = realloc(
        globals->paths_array, sizeof(struct addrinfo *)*globals->path_count);
    globals->paths_array[globals->path_count-1] = res;

    return 1;
}



/*
 * Main function to run the icmp test, returning a result structure that will
 * later be printed or sent across the network.
 */
amp_test_result_t* run_srv6(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    struct timeval start_time;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    char *address_string;
    struct icmpglobals_t *globals;
    struct event *signal_int;
    struct event *socket6;
    struct event *icmp_socket;
    amp_test_result_t *result;

    Log(LOG_DEBUG, "Starting SRv6 test");

    globals = (struct icmpglobals_t *)malloc(sizeof(struct icmpglobals_t));

    globals->base = event_base_new();

    /* set some sensible defaults */
    globals->options.dscp = DEFAULT_DSCP_VALUE;
    globals->options.inter_packet_delay = MIN_INTER_PACKET_DELAY;
    globals->options.packet_size = DEFAULT_ICMP_ECHO_REQUEST_LEN;
    globals->options.random = 0;
    globals->options.perturbate = 0;
    globals->paths_array = NULL;
    globals->path_count = 0;
    sourcev4 = NULL;
    sourcev6 = NULL; //should be LO address, and specify the port
    device = NULL;

    while ( (opt = getopt_long(argc, argv, "p:P:rs:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case '4': address_string = parse_optional_argument(argv);
                      /* -4 without address is sorted at a higher level */
                      if ( address_string ) {
                          sourcev4 = get_numeric_address(address_string, NULL);
                      };
                      break;
            case '6': address_string = parse_optional_argument(argv);
                      /* -6 without address is sorted at a higher level */
                      if ( address_string ) {
                          sourcev6 = get_numeric_address(address_string, NULL);
                      };
                      break;
            case 'I': device = optarg; break;
            case 'Q': if ( parse_dscp_value(optarg,
                                  &globals->options.dscp) < 0 ) {
                          Log(LOG_WARNING, "Invalid DSCP value, aborting");
                          exit(EXIT_FAILURE);
                      }
                      break;
            case 'Z': globals->options.inter_packet_delay = atoi(optarg); break;
            case 'p': globals->options.perturbate = atoi(optarg); break;
            case 'r': globals->options.random = 1; break;
            case 's': globals->options.packet_size = atoi(optarg); break;
            case 'v': print_package_version(argv[0]); exit(EXIT_SUCCESS);
            case 'x': log_level = LOG_DEBUG;
                      log_level_override = 1;
                      break;
            case 'P':
                      address_string = parse_optional_argument(argv);
                      /* -6 without address is sorted at a higher level */
                      
                      if ( address_string ) {
                          parse_pathlist(address_string, globals);
                      }
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    if ( count > 0 ) {
        Log(LOG_WARNING, "amp-srv6 does not take resolvable destinations!");
        exit(EXIT_FAILURE);
    }

    /* pick a random packet size within allowable boundaries */
    if ( globals->options.random ) {
        globals->options.packet_size = MIN_PACKET_LEN +
            (int)((1500 - MIN_PACKET_LEN) * (random()/(RAND_MAX+1.0)));
        Log(LOG_DEBUG, "Setting packetsize to random value: %d\n",
            globals->options.packet_size);
    }

    /* make sure that the packet size is big enough for our data */
    if ( globals->options.packet_size < MIN_PACKET_LEN ) {
        Log(LOG_WARNING, "Packet size %d below minimum size, raising to %d",
            globals->options.packet_size, MIN_PACKET_LEN);
        globals->options.packet_size = MIN_PACKET_LEN;
    }

    /* delay the start by a random amount if perturbate is set */
    if ( globals->options.perturbate ) {
        int delay;
        delay = globals->options.perturbate * 1000 * (random()/(RAND_MAX+1.0));
        Log(LOG_DEBUG, "Perturbate set to %dms, waiting %dus",
            globals->options.perturbate, delay);
        usleep(delay);
    }

    if ( !open_sockets(&globals->sockets) ) {
        Log(LOG_ERR, "Unable to open raw IP sockets, aborting test");
        exit(EXIT_FAILURE);
    }

    if ( set_default_socket_options(&globals->sockets) < 0 ) {
        Log(LOG_ERR, "Failed to set default socket options, aborting test");
        exit(EXIT_FAILURE);
    }

    const char * destination_address = "fc00:0:19::1"; //r2 //needs to be valid dest
    struct sockaddr_in6 Addr = { 0 };
    inet_pton(AF_INET6, destination_address, &( ( struct sockaddr_in6 * ) &Addr)->sin6_addr);
    Addr.sin6_family = AF_INET6;
    Addr.sin6_port = htons( 9 ); //9 is discard port

    int Handle = socket(AF_INET6, SOCK_DGRAM, 0);
    socklen_t AddrLen = sizeof(Addr);
    connect( Handle, (struct sockaddr*)&Addr, AddrLen);
    getsockname(Handle, (struct sockaddr*)&Addr, &AddrLen);
    close (Handle);

    char source_address[INET6_ADDRSTRLEN];

    if ( inet_ntop(AF_INET6, &(Addr.sin6_addr), source_address, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    if ( device && bind_sockets_to_device(&globals->sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw UDP socket to device, aborting test");
        exit(EXIT_FAILURE);
    }

    if ( bind_sockets_to_address(&globals->sockets, NULL,
            get_numeric_address(source_address, NULL)) < 0 ) {
        Log(LOG_ERR,"Unable to bind raw UDP socket to address, aborting test");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in6 sin;
    socklen_t len = sizeof(sin);
    if (getsockname(globals->sockets.socket6, &sin, &len) == -1) {
        perror("getsockname");
    }
    else{
        printf("port number %d\n", ntohs(sin.sin6_port));
        globals->self = sin;
    }

    globals->icmp_sock = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (globals->icmp_sock < 0){
        perror("sock:");
        exit(EXIT_FAILURE);

    }


    if ( gettimeofday(&start_time, NULL) != 0 ) {
        Log(LOG_ERR, "Could not gettimeofday(), aborting test");
        exit(EXIT_FAILURE);
    }

    /* use part of the current time as an identifier value */
    globals->ident = (uint16_t)start_time.tv_usec;

    /* allocate space to store information about each request sent */
    globals->info = (struct info_t *)calloc(sizeof(struct info_t),globals->path_count);

    globals->index = 0;
    globals->outstanding = 0;


    globals->losstimer = NULL;

    /* catch a SIGINT and end the test early */
    signal_int = event_new(globals->base, SIGINT,
            EV_SIGNAL|EV_PERSIST, interrupt_test, globals->base);
    event_add(signal_int, NULL);

    /* set up callbacks for receiving packets */
    socket6 = event_new(globals->base, globals->sockets.socket6,
            EV_READ|EV_PERSIST, receive_probe_callback, globals);
    event_add(socket6, NULL);

    /* set up callbacks for receiving packets */
    icmp_socket = event_new(globals->base, globals->icmp_sock,
            EV_READ|EV_PERSIST, receive_icmp_callback, globals);
    event_add(icmp_socket, NULL);

    /* schedule the first probe packet to be sent immediately */
    globals->nextpackettimer = event_new(globals->base, -1,
            EV_PERSIST, send_packet, globals);
    event_active(globals->nextpackettimer, 0, 0);

    /* run the event loop till told to stop or all tests performed */
    event_base_dispatch(globals->base);

    /* tidy up after ourselves */
    if ( globals->losstimer ) {
        event_free(globals->losstimer);
    }

    if ( globals->nextpackettimer ) {
        event_free(globals->nextpackettimer);
    }

    if ( socket6 ) {
        event_free(socket6);
    }

    if ( signal_int ) {
        event_free(signal_int);
    }

    event_base_free(globals->base);

    if ( globals->sockets.socket > 0 ) {
        close(globals->sockets.socket);
    }

    if ( globals->sockets.socket6 > 0 ) {
        close(globals->sockets.socket6);
    }

    if ( sourcev4 ) {
        freeaddrinfo(sourcev4);
    }

    if ( sourcev6 ) {
        freeaddrinfo(sourcev6);
    }

    /* send report */
    count = 1;
    result = report_results(&start_time, globals->path_count, globals->info,
            &globals->options);

    free(globals->info);
    free(globals);

    return result;
}



/*
 * Print icmp test results to stdout, nicely formatted for the standalone test
 */
void print_srv6(amp_test_result_t *result) {
    Amplet2__Icmp__Report *msg;
    Amplet2__Icmp__Item *item;
    unsigned int i;
    char addrstr[INET6_ADDRSTRLEN];

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__icmp__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);

    /* print test header information */
    printf("\nAMP icmp test, %zu destinations, %u byte packets ",
            msg->n_reports, msg->header->packet_size);

    if ( msg->header->random ) {
        printf("(random size)");
    } else {
        printf("(fixed size)");
    }

    printf(", DSCP %s (0x%0x)\n", dscp_to_str(msg->header->dscp),
            msg->header->dscp);

    /* print each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        item = msg->reports[i];

        printf("%s", item->name);

        if ( !item->has_address ) {
            /* couldn't resolve the target, didn't test to it */
            snprintf(addrstr, INET6_ADDRSTRLEN, "unresolved %s",
                    family_to_string(item->family));
            printf(" (%s) not tested", addrstr);
            //continue;
        }

        //inet_ntop(item->family, item->address.data, addrstr, INET6_ADDRSTRLEN);
        //printf(" (%s)", addrstr);

        if ( item->has_rtt ) {
            printf(" %dus", item->rtt);
        } else {
            if ( item->err_type == 0 ) {
                printf(" missing");
            } else {
                printf(" %s (icmp %u/%u)",
                        icmp_code_str(item->family,
                            item->err_type, item->err_code),
                        item->err_type, item->err_code);
            }
        }
        if ( item->has_ttl ) {
            printf(" TTL:%d", item->ttl);
        }
        printf("\n");
    }
    printf("\n");

    amplet2__icmp__report__free_unpacked(msg, NULL);
}



/*
 * Register a test to be part of AMP.
 */
test_t *register_test() {
    test_t *new_test = (test_t *)malloc(sizeof(test_t));

    /* the test id is defined by the enum in tests.h */
    new_test->id = AMP_TEST_ICMP;

    /* name is used to schedule the test and report results */
    new_test->name = strdup("icmp");

    /* how many targets a single instance of this test can have */
    new_test->max_targets = 0;

    /* minimum number of targets required to run this test */
    new_test->min_targets = 1;

    /* maximum duration this test should take before being killed */
    new_test->max_duration = 120;

    /* function to call to setup arguments and run the test */
    new_test->run_callback = run_srv6;

    /* function to call to pretty print the results of the test */
    new_test->print_callback = print_srv6;

    /* the icmp test doesn't require us to run a custom server */
    new_test->server_callback = NULL;

    /* don't give the icmp test a SIGINT warning, it should not take long! */
    new_test->sigint = 0;

    return new_test;
}



#if UNIT_TEST
int amp_test_process_ipv4_packet(struct icmpglobals_t *globals, char *packet,
        uint32_t bytes, struct timeval *now) {
    return process_ipv4_packet(globals, packet, bytes, now);
}

amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt) {
    return report_results(start_time, count, info, opt);
}
#endif
