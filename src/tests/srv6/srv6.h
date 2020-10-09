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

#ifndef _TESTS_ICMP_H
#define _TESTS_ICMP_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/ip_icmp.h>
#include <stdint.h>
#include <sys/time.h>
#include <event2/event.h>

#include "testlib.h"
#include "serverlib.h"



/* by default use an 84 byte packet, because that's what it has always been */
#define DEFAULT_ICMP_ECHO_REQUEST_LEN 84

#define DEFAULT_CONTROL_PORT  8815
#define MAX_CONTROL_PORT  8825
#define DEFAULT_TEST_PORT 8826
#define MAX_TEST_PORT 8836
//borrowed from throughput test for now, should change later?

/*
 * We can mix ipv4 and ipv6 targets in our tests, so set the minimum packet
 * size to be the ipv6 header length + icmp header length + our "magic" two
 * bytes that are used to store test information.
 */
#define MIN_PACKET_LEN ( \
        sizeof(struct ip6_hdr) + sizeof(struct icmphdr) + sizeof(uint16_t))

/*
 * Initial ipv4 hlen + maximum ipv4 hlen + response icmp header + 8 bytes.
 * We don't get the ipv6 header, so the ipv4 version is the bigger of the two.
 */
#define RESPONSE_BUFFER_LEN ( \
        sizeof(struct iphdr) + 60 + sizeof(struct icmphdr) + 8) \
        + sizeof (uint8_t)

/* timeout (seconds) to wait after the last probe packet, currently 10s */
#define LOSS_TIMEOUT 10



/*
 * User defined test options that control packet size and timing.
 */
struct opt_t {
    int random;			/* use random packet sizes (bytes) */
    int perturbate;		/* delay sending by up to this time (usec) */
    uint8_t dscp;               /* diffserv codepoint to set */
    uint16_t packet_size;	/* use this packet size (bytes) */
    uint32_t inter_packet_delay;/* minimum gap between packets (usec) */
};


struct magic_seq {
    uint16_t global_index; /* this tests index in global->array */
    uint16_t target_index; /* this tests index in global->targets */
    uint16_t magic;
};


/*
 * Information block recording data for each icmp echo request test packet
 * that is sent, and when the response is received.
 */
struct info_t {
    struct in6_addr *addr;      /* address list probe was sent to */
    struct ipv6_sr_hdr *srh;    /* premade srh header */
    int srh_len;                /* lenght of the SRv6 header */
    struct timeval time_sent;   /* when the probe was sent */
    uint32_t delay;             /* delay in receiving response, microseconds */   
    uint8_t reply;              /* set to 1 once we have a reply */
    uint8_t err_type;           /* type of ICMP error reply or 0 if no error */
    uint8_t err_code;           /* code of ICMP error reply, else undefined */
    uint8_t ttl;                /* TTL or hop limit of response packet */
    int is_local;               /* if the target is the local amplet */
    /* a random number and indices to confirm response */
    struct magic_seq magic;
};

struct target_group_t {
    //struct in6_addr *addr; //endpoints addrs, 
    struct addrinfo *addr;
    int is_local;
    //could change this to a sock_addr to include the port number


    //each index in globals->info that contains this targets test
    int *tests;
    int num_tests;              //number of tests
    uint16_t port;
    BIO* ctrl;
};



struct path {
    struct addrinfo *first_hop;
    int path_length;
    struct path *next;
};


struct srv6_shared_globals {
    struct info_t *info;
    int info_count;
    int outstanding;
    struct event_base *base;
    struct event *losstimer;
};


/*
 * Global test options and pointers to the probe information blocks.
 */
struct icmpglobals_t {
    struct opt_t options;
    struct socket_t sockets;
    struct addrinfo **dests;
    struct addrinfo **paths_array;
    struct path *paths;
    struct addrinfo **endpoints;

    int unique_endpoints;

    uint16_t index;
    int path_count;

    uint16_t ident;

    int count;

    struct sockaddr_in6 self;
    int icmp_sock;
    struct target_group_t *targets;
    int target_count;
    struct target_group_t self_target;

    struct event *nextpackettimer;
    struct srv6_shared_globals shared;
};


struct server_global_t {
    struct srv6_shared_globals shared;
};


amp_test_result_t* run_srv6(int argc, char *argv[], int count,
        struct addrinfo **dests);
void print_srv6(amp_test_result_t *result);
test_t *register_test(void);
amp_test_result_t* run_srv6_client(int argc, char *argv[], int count,
        struct addrinfo **dests);
amp_test_result_t* run_srv6_server(int argc, char *argv[], BIO *ctrl);
void receive_probe_callback(evutil_socket_t evsock,
        short flags, void *evdata);
void interrupt_test(
        __attribute__((unused))evutil_socket_t evsock,
        __attribute__((unused))short flags,
        void * evdata);
void halt_test(
    __attribute__((unused))evutil_socket_t evsock,
    __attribute__((unused))short flags,
    void *evdata);

#if UNIT_TEST
int amp_test_process_ipv4_packet(struct icmpglobals_t *globals, char *packet,
        uint32_t bytes, struct timeval *now);
amp_test_result_t* amp_test_report_results(struct timeval *start_time,
        int count, struct info_t info[], struct opt_t *opt);
#endif


#endif
