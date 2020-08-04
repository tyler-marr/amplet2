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
 * Callback used when a packet is received that might be a response to one
 * of our probes.
 */
static void receive_probe_callback(evutil_socket_t evsock,
        short flags, void *evdata) {

    struct timeval now;
    struct ipv6_sr_hdr *srh;
    ssize_t bytes;
    int wait = 0;
    char buf[RESPONSE_BUFFER_LEN];
    char str[INET6_ADDRSTRLEN] = {0};
    struct icmpglobals_t *globals = (struct icmpglobals_t*)evdata;

    assert(evsock > 0);
    assert(flags == EV_READ);
    struct socket_t sockets;
    sockets.socket6 = evsock;
    sockets.socket = -1;

    if (  (bytes = get_SRH_packet(&sockets, buf, RESPONSE_BUFFER_LEN,
            &srh, &wait, &now)) > 0 ) {
        //TODO add not clause
    }

    int seq = 0; //this should always be 0,
    //or in future mapped to the index of the packet 

    uint16_t magic = *((uint16_t*)(buf));

    /* check that the magic value in the reply matches what we expected */
    if ( magic != globals->info[seq].magic ) {
        Log(LOG_DEBUG, "magic did not match, was %d found %d", 
                globals->info[seq].magic, 
                magic
                );
        return;
    }

    if ( srh ) {
        globals->info[seq].addr = malloc(
                sizeof(struct in6_addr) * srh->first_segment);
        memcpy(globals->info[seq].addr, &srh->segments[0],
                sizeof(struct in6_addr) * srh->first_segment);
        

        printf("header len is %d\n", srh->hdrlen);
        printf("header type is %d\n", srh->type);
        printf("next header %d\n", srh->nexthdr);
        printf("first segment is %d\n", srh->first_segment);
        printf("reserved is %d\n", srh->reserved);
        for (int i = 0; i < srh->first_segment; i++){
            inet_ntop(AF_INET6, &srh->segments[i], str, sizeof(str));
            printf("%s \n", str);
        }
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



    Log(LOG_DEBUG, "Good ICMP6 ECHOREPLY");

    if ( globals->outstanding == 0 && globals->index == globals->count ) {
        /* not waiting on any more packets, exit the event loop */
        Log(LOG_DEBUG, "All expected ICMP responses received");
        event_base_loopbreak(globals->base);
    }
}



static struct ipv6_sr_hdr * build_srh(int *srh_lenp,
        struct icmpglobals_t *globals){
    
    int srh_len;
    struct ipv6_sr_hdr *srh;

    // const char *segment[2];
    // int seg_num = sizeof(segment) / sizeof(*segment);
    // segment[0] = "fc00:0:e::1"; //R3 //these values need to be taken from input (topology file)
    // segment[1] = "fc00:0:d::1"; //R2

    int seg_num = globals->count;
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
    for (int i = 0; i< seg_num; i++){
        //inet_pton(AF_INET6, globals->dests[i]->ai_addr, &srh->segments[1+i]);
        
        memcpy(&srh->segments[1+i], &((struct sockaddr_in6 *)(globals->dests[i]->ai_addr))->sin6_addr, sizeof(struct in6_addr));
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
    int seq;
    int srh_len = 0;
    struct addrinfo *dest;
    struct opt_t *opt;
    struct icmpglobals_t *globals;
    struct info_t *info;
    struct timeval timeout;
    struct ipv6_sr_hdr *srh;

    globals = (struct icmpglobals_t *)evdata;
    info = globals->info;
    seq = globals->index;
    dest = globals->dests[seq];
    opt = &globals->options;
    info[seq].magic = rand();

    /* TODO should we try to send the next packet in this time slot? */
    if ( !dest->ai_addr ) {
        Log(LOG_INFO, "No address for target %s, skipping", dest->ai_canonname);
        goto next;
    }

    sock = globals->sockets.socket6;

    if ( sock < 0 ) {
        Log(LOG_WARNING, "Unable to test to %s, socket wasn't opened",
                dest->ai_canonname);
        goto next;
    }

    srh = build_srh(&srh_len, globals);
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
    packet = calloc(1, opt->packet_size);
    length = sizeof(info[seq].magic);
    memcpy(packet, &info[seq].magic, length);

    struct addrinfo hop;
    hop.ai_addr =  (struct sockaddr *)&globals->self;
    hop.ai_addrlen =  sizeof(globals->self);

    /* send packet with appropriate inter packet delay */
    while ( (delay = delay_send_packet(sock, packet, length, &hop,
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
    //globals->index++;
    globals->index = globals->count; // this test only sends one packet now

    if ( globals->nextpackettimer ) {
        event_free(globals->nextpackettimer);
        globals->nextpackettimer = NULL;
    }
    /* create timer for sending the next packet if there are still more to go */
    if ( globals->index == globals->count ) {
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

    if ( packet ) {
        free(packet);
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

    /* fill the report item with results of a test */
    amplet2__icmp__item__init(item);
    item->has_family = 1;
    // item->family = (info->addr[0])->ai_family;
    // item->name = address_to_name(info->addr[0]);
    // item->has_address = copy_address_to_protobuf(&item->address, info->addr[0]);
    //TODO update the protobuf

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
            "Usage: amp-icmp [-hrvx] [-p perturbate] [-s packetsize]\n"
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
    sourcev4 = NULL;
    sourcev6 = NULL; //should be LO address, and specify the port
    device = NULL;

    while ( (opt = getopt_long(argc, argv, "p:rs:I:Q:Z:4::6::hvx",
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
            case 'h': usage(); exit(EXIT_SUCCESS);
            default: usage(); exit(EXIT_FAILURE);
        };
    }

    if ( count < 1 ) {
        Log(LOG_WARNING, "No resolvable destinations were specified!");
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

    if ( set_dscp_socket_options(&globals->sockets,globals->options.dscp) < 0 ){
        Log(LOG_ERR, "Failed to set DSCP socket options, aborting test");
        exit(EXIT_FAILURE);
    }

    const char * destination_address = "fc00:0:d::1"; //r2 //needs to be valid dest
    struct sockaddr_in6 Addr = { 0 };
    inet_pton(AF_INET6, destination_address, &( ( struct sockaddr_in6 * ) &Addr)->sin6_addr);
    Addr.sin6_family = AF_INET6;
    Addr.sin6_port = htons( 9 ); //9 is discard port

    int Handle = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
    socklen_t AddrLen = sizeof(Addr);

    connect( Handle, (struct sockaddr*)&Addr, AddrLen);
    
    getsockname(Handle, (struct sockaddr*)&Addr, &AddrLen);
    char source_address[INET6_ADDRSTRLEN];

    struct in6_addr ipv6 = Addr.sin6_addr;

    if ( inet_ntop(AF_INET6, &(ipv6), source_address, INET6_ADDRSTRLEN) == NULL) {
        perror("inet_ntop");
        exit(EXIT_FAILURE);
    }

    if ( device && bind_sockets_to_device(&globals->sockets, device) < 0 ) {
        Log(LOG_ERR, "Unable to bind raw UDP socket to device, aborting test");
        exit(EXIT_FAILURE);
    }
    
    if ( bind_sockets_to_address(&globals->sockets, sourcev4,
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


    if ( gettimeofday(&start_time, NULL) != 0 ) {
        Log(LOG_ERR, "Could not gettimeofday(), aborting test");
        exit(EXIT_FAILURE);
    }

    /* use part of the current time as an identifier value */
    globals->ident = (uint16_t)start_time.tv_usec;

    /* allocate space to store information about each request sent */
    globals->info = (struct info_t *)malloc(sizeof(struct info_t) * count);

    globals->index = 0;
    globals->outstanding = 0;
    globals->count = count;
    globals->dests = dests;
    globals->losstimer = NULL;

    /* catch a SIGINT and end the test early */
    signal_int = event_new(globals->base, SIGINT,
            EV_SIGNAL|EV_PERSIST, interrupt_test, globals->base);
    event_add(signal_int, NULL);

    /* set up callbacks for receiving packets */
    socket6 = event_new(globals->base, globals->sockets.socket6,
            EV_READ|EV_PERSIST, receive_probe_callback, globals);
    event_add(socket6, NULL);

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
    result = report_results(&start_time, count, globals->info,
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
            printf(" (%s) not tested\n", addrstr);
            continue;
        }

        inet_ntop(item->family, item->address.data, addrstr, INET6_ADDRSTRLEN);
        printf(" (%s)", addrstr);

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
