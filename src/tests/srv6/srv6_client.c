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
#include "controlmsg.h"
#include "../../measured/control.h"//XXX just for control port define
#include "ssl.h"
#include "ampresolv.h"
#include "global.h"
#include "../../measured/nametable.h"


/*
 * TODO collect more information than what the original icmp test did.
 * Things like rtt could be interesting to track.
 */

static struct option long_options[] = {
    {"perturbate", required_argument, 0, 'p'},
    {"path", required_argument, 0, 'P'},
    {"boomerang", required_argument, 0, 'B'},
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
 * Callback used when an ICMP is received that might be a 
 * response to one of our probes.
 */
static void receive_icmp_callback(evutil_socket_t evsock,
        short flags, void *evdata) {

    char packet[1000];
    struct timeval now;
    size_t bytes;
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

    if ( (bytes=get_packet(
            &sockets, packet, sizeof(packet), 
            (struct sockaddr *)&saddr, &wait,
            &now)) > 0 ) {
        struct icmp6_hdr *icmp;

        if ( bytes < sizeof(struct icmp6_hdr) ) {
            return;
        }

        /* any icmpv6 packets we get have the outer ipv6 header stripped */
        icmp = (struct icmp6_hdr *)packet;

        /* sanity check the various fields of the icmp header */
        if ( icmp->icmp6_type != ICMP6_DST_UNREACH || 
                icmp->icmp6_code != ICMP6_DST_UNREACH_ADDR ) {
            return;
            //not an applicable ICMP6 error (can handle more later)
        }

        struct ip6_hdr *ip6 = (struct ip6_hdr *)&(icmp[1]);

        /* we expect to see an SRv6 routing hearder, ie  */
        if ( ip6->ip6_nxt != 43 ) { //TODO RTHDR(43) magic number
           Log(LOG_DEBUG, "IPv6->next != RTHDR");
           return;
        }

        /* Routing header */
        struct ipv6_sr_hdr *srv6_hdr = (struct ipv6_sr_hdr *)&ip6[1];

        //TODO UDP(17) and SRv6(4) magic numbers
        if ( srv6_hdr->nexthdr != 17 || srv6_hdr->type != 4) {
            //error
            Log(LOG_DEBUG, "srv6_hdr->next != UDP || srv6_hdr->type != SRv6");
            return;
        }

        struct udphdr *udphdr  = ((void *)(srv6_hdr+1)) + ((srv6_hdr->hdrlen)*8);
        struct magic_seq *magic_seq = (struct magic_seq *)&udphdr[1];

        //TODO compare UDP port number to required

        if (magic_seq->magic != globals->shared.info[magic_seq->global_index].magic.magic) {
            //not our packet
            return;
        }

        char src_address[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, 
                &((struct sockaddr_in6*)(&saddr))->sin6_addr,
                src_address, INET6_ADDRSTRLEN);

        char dst_address[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &(ip6->ip6_dst), dst_address, INET6_ADDRSTRLEN);

        Log(LOG_DEBUG, "ICMP6 dest unreachable, %s cant find %s", 
                src_address, dst_address);

        /* reply is good, record the round trip time */
        uint16_t global_index = magic_seq->global_index;
        globals->shared.info[global_index].reply = 1;
        globals->shared.outstanding--;

        globals->shared.info[global_index].srh = malloc(
                sizeof(*srv6_hdr) + ((1+srv6_hdr->first_segment) * sizeof(struct in6_addr)));
        memcpy(globals->shared.info[global_index].srh, srv6_hdr,
                sizeof(*srv6_hdr) + ((1+srv6_hdr->first_segment) * sizeof(struct in6_addr)));

        int64_t delay = DIFF_TV_US(now, globals->shared.info[global_index].time_sent);
        if ( delay > 0 ) {
            globals->shared.info[global_index].delay = (uint32_t)delay;
        } else {
            globals->shared.info[global_index].delay = 0;
        }

        globals->shared.info[global_index].ttl = ip6->ip6_hops;
        globals->shared.info[global_index].err_code = icmp->icmp6_code;
        globals->shared.info[global_index].err_type = icmp->icmp6_type;

        Log(LOG_DEBUG, "Good ICMP6 error report");

        if ( globals->shared.outstanding == 0 && globals->index == globals->path_count ) {
            /* not waiting on any more packets, exit the event loop */
            Log(LOG_DEBUG, "All expected ICMP responses received");
            event_base_loopbreak(globals->shared.base);
        }
    }
}



static struct ipv6_sr_hdr * build_srh(int *srh_lenp,
        struct addrinfo *path){
    
    int srh_len;
    struct ipv6_sr_hdr *srh;
    int path_length = -1;

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
    int i = 0;
    for (struct addrinfo *temp = path->ai_next; temp; temp = temp->ai_next){
        
        memcpy(&srh->segments[1+i], 
                &((struct sockaddr_in6 *)(temp->ai_addr))->sin6_addr,
                sizeof(struct in6_addr));
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

    int sock;
    int delay;
    uint16_t index;
    struct opt_t *opt;
    struct icmpglobals_t *globals;
    struct info_t *curr_test;
    struct timeval timeout;
    struct target_group_t *target;

    globals = (struct icmpglobals_t *)evdata;
    index = globals->index;
    curr_test = &(globals->shared.info[index]);
    opt = &globals->options;
    if ( !curr_test->is_local )  {
        target = &globals->targets[curr_test->magic.target_index];
    } else {
        target = &globals->self_target;
    }

    /* TODO should we try to send the next packet in this time slot? */
    if ( !target->addr ) {
        Log(LOG_INFO, "No address for target %d, skipping",
                curr_test->magic.global_index);
        goto next;
    }

    Log(LOG_DEBUG, "Sending to target[%d] %s:%d\n",
            curr_test->magic.global_index,
            target->name,
            htons(((struct sockaddr_in6*)(target->addr->ai_addr))->sin6_port));
                

    sock = globals->sockets.socket6;

    if ( sock < 0 ) {
        Log(LOG_WARNING, "Unable to test to, socket wasn't opened");
        goto next;
    }

    target->addr->ai_addrlen = sizeof(struct sockaddr_in6);

    int err = setsockopt(sock, IPPROTO_IPV6, IPV6_RTHDR,
            curr_test->srh, curr_test->srh_len);
    if (err < 0) {
        perror("setsockopt SRH");
        close(sock);
        goto next;
    }

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, (void*)&(curr_test->magic), sizeof(curr_test->magic), target->addr,
                    opt->inter_packet_delay, 
                    &(curr_test->time_sent))) > 0 ) {
        usleep(delay);
    }

    if ( delay < 0 ) {
        /* mark this as done if the packet failed to send properly */
        curr_test->reply = 1;
        memset(&(curr_test->time_sent), 0, sizeof(struct timeval));
    } else {
        globals->shared.outstanding++;
    }

next:
    globals->index++;

    if ( globals->nextpackettimer ) {
        event_free(globals->nextpackettimer);
        globals->nextpackettimer = NULL;
    }
    /* create timer for sending the next packet if there are still more to go */
    if ( globals->index == globals->shared.info_count) {
        Log(LOG_DEBUG, "Reached final target: %d", globals->index);
        if ( globals->shared.outstanding == 0 ) {
            /* avoid waiting for LOSS_TIMEOUT if no packets are outstanding */
            event_base_loopbreak(globals->shared.base);
        } else {
            globals->shared.losstimer = event_new(globals->shared.base, -1, 0,
                    halt_test, &(globals->shared));
             timeout.tv_sec = LOSS_TIMEOUT;
            timeout.tv_usec = 0;
            event_add(globals->shared.losstimer, &timeout);
        }
    } else {
        globals->nextpackettimer = event_new(globals->shared.base, -1, 0,
                send_packet, globals);
        timeout.tv_sec = (int)(globals->options.inter_packet_delay / 1000000);
        timeout.tv_usec = globals->options.inter_packet_delay % 1000000;
        event_add(globals->nextpackettimer, &timeout);
    }
}


/*
 * Open the raw IPv6 socket used for this test and configure
 * appropriate filters for the SRv6 header and hoplimit.
 */
static int open_sockets(struct socket_t *sockets) {

    int on = 1;

    sockets->socket = -1; //does not use ipv4

    if ( (sockets->socket6 = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
        Log(LOG_WARNING, "Failed to open raw socket for SRv6");
    } else {
        if ( setsockopt(sockets->socket6, IPPROTO_IPV6, IPV6_RECVRTHDR,
                &on, sizeof(on)) < 0) {
            Log(LOG_WARNING, "Could not set IPv6 RECVHDR");
        }


        if ( setsockopt(sockets->socket6, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
                &on, sizeof(on)) < 0) {
            Log(LOG_WARNING, "Could not set IPV6_RECVHOPLIMIT");
        }
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
static Amplet2__Srv6__Item* report_destination(struct info_t *info) {

    Amplet2__Srv6__Item *item =
        (Amplet2__Srv6__Item*)malloc(sizeof(Amplet2__Srv6__Item));

    /* fill the report item with results of a test */
    amplet2__srv6__item__init(item);
    item->has_family = 1;
    item->family = ((struct sockaddr_in6* )info->addr)->sin6_family ;
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

    Log(LOG_DEBUG, "SRv6 connectivity result: %dus, %d/%d\n",
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

    Log(LOG_DEBUG, "Building SRv6 report, count:%d psize:%d rand:%d dscp:%0x\n",
            count, opt->packet_size, opt->random, opt->dscp);

    Amplet2__Srv6__Report msg = AMPLET2__SRV6__REPORT__INIT;
    Amplet2__Srv6__Header header = AMPLET2__SRV6__HEADER__INIT;
    Amplet2__Srv6__Item **reports;

    /* populate the header with all the test options */
    header.has_packet_size = 1;
    header.packet_size = opt->packet_size;
    header.has_random = 1;
    header.random = opt->random;
    header.has_dscp = 1;
    header.dscp = opt->dscp;

    /* build up the repeated reports section with each of the results */
    reports = malloc(sizeof(Amplet2__Srv6__Item*) * count);
    for ( i = 0; i < count; i++ ) {
        reports[i] = report_destination(&info[i]);
    }

    /* populate the top level report object with the header and reports */
    msg.header = &header;
    msg.reports = reports;
    msg.n_reports = count;

    /* pack all the results into a buffer for transmitting */
    result->timestamp = (uint64_t)start_time->tv_sec;
    result->len = amplet2__srv6__report__get_packed_size(&msg);
    result->data = malloc(result->len);
    amplet2__srv6__report__pack(&msg, result->data);

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

    /////////
        fprintf(stderr, "Usage: amp-throughput -s [OPTIONS]\n");
    fprintf(stderr, "       amp-throughput -c host [OPTIONS]\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Server/Client options:\n");
    fprintf(stderr, "  -p, --port           <port>    "
            "Port number to use (default %d)\n", 0);
    print_interface_usage();
    fprintf(stderr, "\n");

    fprintf(stderr, "Server specific options:\n");
    fprintf(stderr, "  -s, --server                   Run in server mode\n");
    fprintf(stderr, "\n");

    fprintf(stderr, "Client specific options:\n");
    fprintf(stderr, "  -c, --client         <host>    "
            "Run in client mode, connecting to <host>\n");
    fprintf(stderr, "  -i, --rcvbuf         <bytes>   "
            "Maximum size of the receive (input) buffer\n");
    fprintf(stderr, "  -M, --mss            <bytes>   "
            "Set TCP maximum segment size\n");
    fprintf(stderr, "  -N, --nodelay                  "
            "Disable Nagle's Algorithm (set TCP_NODELAY)\n");
    fprintf(stderr, "  -o, --sndbuf         <bytes>   "
            "Maximum size of the send (output) buffer\n");
    fprintf(stderr, "  -P, --test-port      <port>    "
            "Port number to test on (default %d)\n", 0);
    fprintf(stderr, "  -r, --randomise                "
            "Randomise data in every packet sent\n");
    fprintf(stderr, "  -S, --schedule       <seq>     "
            "Test schedule (see below)\n");
    fprintf(stderr, "  -t, --time           <sec>     "
            "Time in seconds to transmit (default 10s)\n");
    fprintf(stderr, "  -u, --protocol       <proto>   "
            "Protocol to imitate (default:none, options: none, http)\n");
    fprintf(stderr, "  -z, --write-size     <bytes>   "
            "Length of buffer to write (default %d)\n",
            (int)0 );
    fprintf(stderr, "\n");

    fprintf(stderr, "Miscellaneous:\n");
    print_generic_usage();
    fprintf(stderr, "\n");

    fprintf(stderr, "Socket options such as rcvbuf, sndbuf, mss and nodelay "
            "will be set on both\nthe client and the server.");
    fprintf(stderr, "\n\n");

    /* TODO make schedules like iperf? just do one way for a period */
    fprintf(stderr, "A schedule is a sequence of tests. Each test starts with single character\n");
    fprintf(stderr, "representing its type. Tests are separated by a single comma ','.\n");
    fprintf(stderr, "Valid types are:\n");
    fprintf(stderr, "  s<num_bytes> run a server -> client test, sending a fixed number of bytes\n");
    fprintf(stderr, "  S<num_bytes> run a client -> server test, sending a fixed number of bytes\n");
    fprintf(stderr, "  t<ms>        run a server -> client test, for the time given in milliseconds\n");
    fprintf(stderr, "  T<ms>        run a client -> server test, for the time given in milliseconds\n");
    fprintf(stderr, " e.g. -S \"t1000,T1000\"    Run two tests each for 1 second first S2C then C2S\n");
    fprintf(stderr, " e.g. -S \"s10000,S10000\"  Run two tests S2C then C2S each sending 10,000 bytes\n");
}


///TODO split this method for use in a -B and a -P version 
static void parse_targetlist(char *address_string,
        struct icmpglobals_t *globals,
        int is_local) {
    char *str;
    struct addrinfo *addr = NULL;
    struct addrinfo *res = NULL;
    struct info_t *curr_test = NULL;
    struct target_group_t *target = NULL;
    nametable_t *namet = NULL;
    int target_index = 0;

    str = strtok(address_string, ",");

    while ( str ) { //while there are more tokens to parse
        addr = get_numeric_address(str, NULL);

        if ( addr == NULL ) {
            //check if standalone or not
            //no need to check nametable if we dont have one
            if (1) {
                namet = name_to_address(str);
                if (namet){
                    addr = ((nametable_t*)namet)->addr;
                } else {
                    Log(LOG_ERR, "%s target not in nametable", str);
                    return;
                }
            } else {
                Log(LOG_ERR, "%s target is invalid", str);
                    return;
            }
        } else {
            //if numeric address passes cannon name is just the ip str
            addr->ai_canonname = strdup(str);
        }


        addr->ai_next = res;
        res = addr;


        char dst_address[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6,
            &((struct sockaddr_in6*)addr->ai_addr)->sin6_addr,
            dst_address, 
            INET6_ADDRSTRLEN);

        str = strtok(NULL, ",");


        continue;

        return;
    }
    //addr is now the head of a list of hops in reverse order
    
    
    if ( is_local ) {
        //push empty placeholder addr onto list 
        //(this will later be an addr to self)
        addr = calloc(1,sizeof(*addr));
        addr->ai_next = res;
        res = addr;
        target = &globals->self_target;

    } else {

        int unique = 1;
        //search globals->target_list for entrys
        for (target_index = 0; target_index < globals->target_count; 
                target_index++){

            target = &globals->targets[target_index];
            if ( memcmp(
                    &((struct sockaddr_in6*)target->addr->ai_addr)->sin6_addr,
                    &((struct sockaddr_in6*)addr->ai_addr)->sin6_addr,
                    sizeof(struct in6_addr)) == 0) {

                //add to existing target
                
                unique = 0;
                break;
            }
        }
        if (unique) {
            //create new target
            //expand target array to fit new target
            //increase target count
            //set addr of target, and num tests

            target_index = globals->target_count;
            globals->target_count += 1;
            globals->targets = realloc(globals->targets, 
                    sizeof(*globals->targets) * globals->target_count);
            target = &globals->targets[globals->target_count-1];
            target->addr = addr;
            target->num_tests = 0;
            target->tests = NULL;
            target->name = malloc(INET6_ADDRSTRLEN);
            inet_ntop(
                    AF_INET6, 
                    &((struct sockaddr_in6*)addr->ai_addr)->sin6_addr, 
                    target->name, 
                    INET6_ADDRSTRLEN);
        }
    }

    //create new test info
    //realloc space for new test in both global space and target sapce
    //increment counters
    //build info

    globals->shared.info = realloc(globals->shared.info,
            sizeof(*globals->shared.info) * (globals->shared.info_count+1));


    curr_test = &globals->shared.info[globals->shared.info_count];

    target->num_tests++;
    target->tests = realloc(target->tests, 
            sizeof(*target->tests)*target->num_tests);
    
    target->tests[target->num_tests-1] = globals->shared.info_count;

    if ( !is_local ) {
        //for a local address, addr will be NULL so need to check for this
        curr_test->addr = &((struct sockaddr_in6*)target->addr->ai_addr)
                ->sin6_addr;
        //Log(LOG_INFO, "Adding global test %d", globals->shared.info_count);
    } else {
        //Log(LOG_INFO, "Adding local test %d", globals->shared.info_count);
    }

    curr_test->magic.magic = rand();
    curr_test->magic.global_index = globals->shared.info_count;
    curr_test->magic.target_index = target_index;
    curr_test->srh = build_srh(&curr_test->srh_len, addr);
    curr_test->is_local = is_local;

    globals->shared.info_count += 1;
}



static Amplet2__Srv6__Probe *build_probe_payloads(struct info_t * test) {
    
    Amplet2__Srv6__Probe *probe = malloc(sizeof(Amplet2__Srv6__Probe));
    
    amplet2__srv6__probe__init(probe);

    probe->magic = test->magic.magic;
    probe->has_magic = 1;
    probe->global_index = test->magic.global_index;
    probe->has_global_index= 1;
    probe->target_index= test->magic.target_index;
    probe->has_target_index = 1;

    return probe;
}


/*
 * Build a HELLO protocol buffer message containing test options.
 */
static ProtobufCBinaryData* build_hello(struct opt_t *options, 
        struct target_group_t *target, struct icmpglobals_t *globals) {
    ProtobufCBinaryData *data = malloc(sizeof(ProtobufCBinaryData));
    Amplet2__Srv6__Hello hello = AMPLET2__SRV6__HELLO__INIT;
    Amplet2__Srv6__Probe **probe_payloads = NULL;

    hello.random = (uint32_t)options->random;
    hello.has_random = 1;
    hello.perturbate = (uint32_t)options->perturbate;
    hello.has_perturbate = 1;
    hello.packet_size = (uint32_t)options->packet_size;
    hello.has_packet_size = 1;
    hello.inter_packet_delay = (uint32_t)options->inter_packet_delay;
    hello.has_inter_packet_delay = 1;
    hello.dscp = (uint32_t)options->dscp;
    hello.has_dscp = 1;

    int i;

    for ( i = 0; i < target->num_tests; i++ ) {
        probe_payloads = realloc(probe_payloads, 
                sizeof(Amplet2__Srv6__Probe *) * (i+1));
        probe_payloads[i] = build_probe_payloads(
                &globals->shared.info[target->tests[i]]);
    }

    

    /* populate the top level report object with the header and reports */
    hello.probes = probe_payloads;
    hello.n_probes = i;


    data->len = amplet2__srv6__hello__get_packed_size(&hello);
    data->data = malloc(data->len);
    amplet2__srv6__hello__pack(&hello, data->data);

    return data;
}



static int contact_targets(struct target_group_t *target,
        struct icmpglobals_t *globals){

    char dst_address[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6,
        &((struct sockaddr_in6*)target->addr->ai_addr)->sin6_addr,
        dst_address, 
        INET6_ADDRSTRLEN);
    Log(LOG_DEBUG, "Attempting to connect to: %s",dst_address);

    if ( target->addr ){
        struct sockopt_t sockopts = {};
        //create new CTRL socket here 
        //before we connect to control server we need to start it (maybe)
        if ( (target->ctrl = connect_control_server(
                    target->addr,
                    atoi(DEFAULT_AMPLET_CONTROL_PORT),
                    &sockopts)) 
                    == NULL ) {
            Log(LOG_WARNING,
                    "Failed to connect control server on port %d",
                    atoi(DEFAULT_AMPLET_CONTROL_PORT));
            return 0;
        }


        /* start the server if required (connected to an amplet) */
        //if ( ssl_ctx && target->name == NULL ) {//todo
        {
            Amplet2__Measured__Response response;

            if ( start_remote_server(target->ctrl, AMP_TEST_SRV6, NULL) < 0 ) {
                Log(LOG_WARNING, "Failed to start remote server");
                return 0;
            }

            /* make sure the server was started properly */
            if ( read_measured_response(target->ctrl, &response) < 0 ) {
                Log(LOG_WARNING, "Failed to read server control response");
                return 0;
            }

            /* TODO return something useful if this was remotely triggered? */
            if ( response.code != MEASURED_CONTROL_OK ) {
                Log(LOG_WARNING, "Failed to start server: %d %s", response.code,
                        response.message);
                return 0;
            }
        }

        /* start the server if required (connected to an amplet) */
        if ( send_control_hello(
                    AMP_TEST_SRV6,
                    target->ctrl,
                    build_hello(
                        &globals->options, 
                        target, 
                        globals)
                    ) < 0 ) {
            Log(LOG_WARNING, "Failed to send HELLO packet, aborting");
            return 0;
        }

        if ( read_control_ready(AMP_TEST_THROUGHPUT, 
                    target->ctrl,
                    &(target->port)) < 0 ) {
            Log(LOG_WARNING, "Failed to read READY packet, aborting");
            return 0;
        }

        Log(LOG_DEBUG, "Read ready packet port:%d", 
                target->port);

        ((struct sockaddr_in6 *)target->addr->ai_addr)
                ->sin6_port = htons(target->port);

        return 1;
    }
    Log(LOG_ERR, "Target has no address, aborting");
    return 0;
}



/*
 * Main function to run the srv6 test, returning a result structure that will
 * later be printed or sent across the network.
 * 
 * Includes setting up listeners for local ICMP6 errors and "boomerang" probes
 * Figures out where other packets will be sent and asks for listeners on them
 */
amp_test_result_t* run_srv6_client(int argc, char *argv[], int count,
        __attribute__((unused))struct addrinfo **dests) {
    int opt;
    int is_local = 0;
    struct timeval start_time;
    struct addrinfo *sourcev4, *sourcev6;
    char *device;
    char *address_string;
    struct icmpglobals_t *globals;
    struct event *signal_int;
    struct event *socket6;
    struct event *icmp_socket;
    amp_test_result_t *result;

    Log(LOG_DEBUG, "Starting SRv6 client");

    globals = (struct icmpglobals_t *)malloc(sizeof(struct icmpglobals_t));

    globals->shared.base = event_base_new();

    /* set some sensible defaults */
    globals->options.dscp = DEFAULT_DSCP_VALUE;
    globals->options.inter_packet_delay = MIN_INTER_PACKET_DELAY;
    globals->options.packet_size = DEFAULT_ICMP_ECHO_REQUEST_LEN;
    globals->options.random = 77;
    globals->options.perturbate = 0;
    globals->paths_array = NULL;
    globals->path_count = 0;
    globals->target_count = 0;
    globals->targets = NULL;
    globals->shared.info = NULL;
    globals->shared.info_count = 0;
    memset(&globals->self_target, 0, sizeof(globals->self_target));
    sourcev4 = NULL;
    sourcev6 = NULL; //should be LO address, and specify the port
    device = NULL;

    while ( (opt = getopt_long(argc, argv, "p:P:B:rs:I:Q:Z:4::6::hvx",
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
            case 'B':
                      is_local = 1;
                      __attribute__ ((fallthrough));
            case 'P':
                      address_string = parse_optional_argument(argv);
                      /* -6 without address is sorted at a higher level */
                      
                      if ( address_string ) {
                          parse_targetlist(address_string, globals, is_local);
                      }
                      is_local = 0;
                      break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    if ( count > 0 ) {
        Log(LOG_WARNING, "amp-srv6 does not take resolvable destinations!");
        exit(EXIT_FAILURE);
    }

    if (globals->self_target.num_tests && !sourcev6) {
        Log(LOG_WARNING, 
                "-B was provided but no local v6 address is set"
                " with -6 exiting");
        exit(EXIT_FAILURE);
    }

    if (globals->shared.info_count == 0) {
        Log(LOG_WARNING, "No valid tests were provided, aborting");
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

    if ( device && bind_sockets_to_device(&globals->sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw UDP socket to device, aborting test");
        exit(EXIT_FAILURE);
    }


    if ( !sourcev6 ) {
        //if no address is provided bind to ::
        sourcev6 = get_numeric_address("::", NULL);
    }
    if ( bind_sockets_to_address(&globals->sockets, NULL,
            sourcev6 ) < 0 ) {
        Log(LOG_ERR,"Unable to bind raw UDP socket to address, aborting test");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in6 sin;
    socklen_t len = sizeof(sin);
    if (getsockname(globals->sockets.socket6, &sin, &len) == -1) {
        perror("getsockname");
    }

    // globals->self = sin;
    globals->self_target.addr = malloc(sizeof(*globals->self_target.addr));
    globals->self_target.addr->ai_addr = (struct sockaddr*)&sin;
    globals->self_target.addr->ai_addrlen = sizeof(struct sockaddr);
    globals->self_target.addr->ai_family = AF_INET6;

    

    char source_address[INET6_ADDRSTRLEN];
    if ( inet_ntop(AF_INET6, &(sin.sin6_addr), source_address, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }
    Log(LOG_DEBUG, "Bound to %s:%d\n",source_address, ntohs(sin.sin6_port));
    Log(LOG_DEBUG, "Registered %d local test(s)", globals->self_target.num_tests);
    Log(LOG_DEBUG, "Registered %d remote(s) with %d test(s) total",
            globals->target_count,
            globals->shared.info_count);


    for (int i = 0; i< globals->target_count; i++){

        if ( contact_targets(&globals->targets[i], globals) != 0 ){
            globals->targets[i].state = AMP_SRV6_TARGET_STATE_POST_CONNECTION;
        } else {
            Log(LOG_ERR, "Failed to connect and start to remote server");
            globals->targets[i].state = AMP_SRV6_TARGET_STATE_FAILED_CONNECT;
        }

    }


    //globals->self.sin6_port = htons(globals->self.sin6_port);


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
    //globals->info = (struct info_t *)calloc(sizeof(struct info_t),globals->path_count);

    globals->index = 0;
    globals->shared.outstanding = 0;


    globals->shared.losstimer = NULL;


    // connect_to_endpoints(globals);

    /* catch a SIGINT and end the test early */
    signal_int = event_new(globals->shared.base, SIGINT,
            EV_SIGNAL|EV_PERSIST, interrupt_test, &globals->shared);
    event_add(signal_int, NULL);

    /* set up callbacks for receiving packets */
    socket6 = event_new(globals->shared.base, globals->sockets.socket6,
            EV_READ|EV_PERSIST, receive_probe_callback, &globals->shared);
    event_add(socket6, NULL);

    /* set up callbacks for receiving ICMP6 errors */
    icmp_socket = event_new(globals->shared.base, globals->icmp_sock,
            EV_READ|EV_PERSIST, receive_icmp_callback, globals);
    event_add(icmp_socket, NULL);

    //TODO add event for recieving results

    /* schedule the first probe packet to be sent immediately */
    globals->nextpackettimer = event_new(globals->shared.base, -1,
            EV_PERSIST, send_packet, globals);
    event_active(globals->nextpackettimer, 0, 0);

    /* run the event loop till told to stop or all tests performed */
    event_base_dispatch(globals->shared.base);

    /* tidy up after ourselves */
    if ( globals->shared.losstimer ) {
        event_free(globals->shared.losstimer);
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

    event_base_free(globals->shared.base);

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

    //TODO this needs to be put into the event loop too
    //recieve results from targets
    for (int i  = 0; i< globals->target_count; i++){
        struct target_group_t *curr_target = &globals->targets[i];
        if ( curr_target->state == AMP_SRV6_TARGET_STATE_FAILED_CONNECT ) {

        } else {
            ProtobufCBinaryData data;
            if ( read_control_result(
                    AMP_TEST_SRV6,
                    curr_target->ctrl,
                    &data) < 0 ) {
                Log(LOG_WARNING, "Failed to read RESULT packet, aborting");
                continue;
            }
            Amplet2__Srv6__Goodbye *goodbye = amplet2__srv6__goodbye__unpack(
                    NULL,
                    data.len, 
                    data.data);

            //struct info_t *curr_info = curr_target->tests[goodbye->results
            for (int j = 0; j < curr_target->num_tests; j++){
                struct info_t *curr_info = &(globals->shared.info[curr_target->tests[j]]);
                //goodbye->results[j]->ttl
                curr_info->ttl = goodbye->results[j]->ttl;
            }
            amplet2__srv6__goodbye__free_unpacked(goodbye, NULL);
        }
    }

    /* send report */
    count = 1;
    result = report_results(&start_time, globals->path_count, globals->shared.info,
            &globals->options);

    free(globals->shared.info);
    free(globals);

    return result;
}









