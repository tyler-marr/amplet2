/*
 * This file is part of amplet2.
 *
 * Copyright (c) 2013-2016 The University of Waikato, Hamilton, New Zealand.
 *
 * Authors: Richard Sanger
 *          Brendon Jones
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

#include <getopt.h>
#include <stdio.h>
#include <string.h>
#include <event2/event.h>

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



struct option long_options[] =
{
    {"client", required_argument, 0, 'c'},
    {"direction", required_argument, 0, 'd'},
    {"rcvbuf", required_argument, 0, 'i'},
    {"mss", required_argument, 0, 'M'},
    {"nodelay", no_argument, 0, 'N'},
    {"sndbuf", required_argument, 0, 'o'},
    {"port", required_argument, 0, 'p'},
    {"test-port", required_argument, 0, 'P'},
    {"randomise", no_argument, 0, 'r'},
    {"server", no_argument, 0, 's'},
    {"sequence", required_argument, 0, 'S'},
    {"time", required_argument, 0, 't'},
    {"protocol", required_argument, 0, 'u'},
    {"write-size", required_argument, 0, 'z'},
    {"dscp", required_argument, 0, 'Q'},
    {"interpacketgap", required_argument, 0, 'Z'},
    {"interface", required_argument, 0, 'I'},
    {"ipv4", optional_argument, 0, '4'},
    {"ipv6", optional_argument, 0, '6'},
    {"help", no_argument, 0, 'h'},
    {"version", no_argument, 0, 'v'},
    {"debug", no_argument, 0, 'x'},
    {NULL,0,0,0}
};


/*
 * Callback used when a packet is received that might be a response to one
 * of our probes.
 */
void receive_probe_callback(evutil_socket_t evsock,
        short flags, void *evdata) {

    struct timeval now;
    struct ipv6_sr_hdr *srh = NULL;
    ssize_t bytes;
    int wait = 0;
    int ttl = 77;
    char buf[RESPONSE_BUFFER_LEN+1];
    //struct icmpglobals_t *globals = (struct icmpglobals_t*)evdata;
    struct srv6_shared_globals *shared = evdata;

    assert(evsock > 0);
    assert(flags == EV_READ);
    struct socket_t sockets;
    sockets.socket6 = evsock;
    sockets.socket = -1;

    struct info_t *curr_test;

    if (  (bytes = get_SRH_packet(&sockets, buf, RESPONSE_BUFFER_LEN+1,
            &srh, &wait, &now, &ttl)) > 0 ) {
        //TODO add not clause
    }

    struct magic_seq *magic_seq = (void *)buf;

    uint16_t global_index = magic_seq->global_index;
    uint16_t magic = magic_seq->magic;

    curr_test = &shared->info[global_index];


    /* check that the magic value in the reply matches what we expected */
    if ( magic != curr_test->magic.magic ) {
        Log(LOG_DEBUG, "magic did not match, was [%d]%04x found %04x", 
                global_index,
                curr_test->magic, 
                magic
                );
        return;
    }

    printf("MAGIC MATCH, was [%d]%04d found %04d\n", 
                global_index,
                curr_test->magic.magic, 
                magic
                );

    if ( srh ) {

        curr_test->srh = malloc(
                sizeof(*srh) + ((srh->first_segment) * sizeof(struct in6_addr)));
        memcpy(curr_test->srh, srh,
                sizeof(*srh) + ((srh->first_segment) * sizeof(struct in6_addr)));

        //after we are done with the SRH, we need to free it
        free(srh);
    }

    /* reply is good, record the round trip time */
    curr_test->reply = 1;
    shared->outstanding--;

    int64_t delay = DIFF_TV_US(now, curr_test->time_sent);
    if ( delay > 0 ) {
        curr_test->delay = (uint32_t)delay;
    } else {
        curr_test->delay = 0;
    }

    curr_test->ttl = ttl;



    Log(LOG_DEBUG, "Good ICMP6 ECHOREPLY, packets left:%d",shared->outstanding);

    if ( shared->outstanding == 0 /*&& globals->index == globals->path_count*/ ) {
        /* not waiting on any more packets, exit the event loop */
        Log(LOG_DEBUG, "All expected ICMP responses received");
        event_base_loopbreak(shared->base);
    }
}

/*
 * Halt the event loop in the event of a SIGINT (either sent from the terminal
 * if running standalone, or sent by the watchdog if running as part of
 * measured) and report the results that have been collected so far.
 */
void interrupt_test(
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
void halt_test(
    __attribute__((unused))evutil_socket_t evsock,
    __attribute__((unused))short flags,
    void *evdata) {
    struct srv6_shared_globals *shared = evdata;

    Log(LOG_DEBUG, "Halting ICMP test due to timeout");
    if ( shared->losstimer ) {
        event_free(shared->losstimer);
        shared->losstimer = NULL;
    }
    event_base_loopbreak(shared->base);
}



/*
 * Combined entry point for throughput tests that will run the appropriate
 * part of the test - server or client.
 */
amp_test_result_t* run_srv6(int argc, char *argv[], int count,
        struct addrinfo **dests) {
    int opt;
    int server_flag_index = 0;

    Log(LOG_DEBUG, "Starting SRv6 test");

    /* this option string needs to be kept up to date with server and client */
    while ( (opt = getopt_long(argc, argv,
                    "c:d:i:Nm:o:p:P:rsS:t:u:z:I:Q:Z:4::6::hvx",
                    long_options, NULL)) != -1 ) {
        switch ( opt ) {
            case 's': server_flag_index = optind - 1; break;
            default: /* pass all other options through */ break;
        };
    }

    /* reset optind so the next function can parse its own arguments */
    optind = 1;

    if ( server_flag_index ) {
        /* remove the -s option before calling the server function */
        memmove(argv + server_flag_index, argv + server_flag_index + 1,
                (argc - server_flag_index - 1) * sizeof(char *));
        run_srv6_server(argc-1, argv, NULL);
        return NULL;
    }


    amp_test_result_t* result = run_srv6_client(argc, argv, count, dests);
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
