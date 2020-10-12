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


/*
 * Parse a HELLO protocol buffer message containing test options and return
 * them.
 */
static void* parse_hello(ProtobufCBinaryData *data) {

    struct server_global_t *globals;
    Amplet2__Icmp__Hello *hello;
    struct info_t *new_test;

    hello = amplet2__icmp__hello__unpack(NULL, data->len, data->data);
    globals = calloc(1, sizeof(*globals));

    globals->shared.info_count = hello->n_probes;
    globals->shared.outstanding = globals->shared.info_count;
    globals->shared.info = calloc(globals->shared.info_count,
            sizeof(*globals->shared.info));

    for (size_t i = 0; i < hello->n_probes; i++ ) {

        new_test = &globals->shared.info[i];

        new_test->magic.magic = hello->probes[i]->magic;
        new_test->magic.global_index = hello->probes[i]->global_index;
        new_test->magic.target_index = hello->probes[i]->target_index;
        
    }

    amplet2__icmp__hello__free_unpacked(hello, NULL);

    return globals;
}

// static int start_socket(void){
//     int fd = 0;
//     int on = 1;
//     if ( (fd = socket(AF_INET6, SOCK_DGRAM, 0)) < 0 ) {
//         Log(LOG_WARNING, "Failed to open raw socket for ICMPv6");
//     } else {
//         // if ( setsockopt(fd, IPPROTO_IPV6, IPV6_RECVRTHDR,
//         //         &on, sizeof(on)) < 0) {
//         //     Log(LOG_WARNING, "Could not set IPv6 RECVHDR");
//         // }

//         if ( setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
//                 &on, sizeof(on)) < 0) {
//             Log(LOG_WARNING, "Could not set IPV6_RECVHOPLIMIT");
//         }
//     }
//     return fd;
// }

static uint16_t getSocketPort(int sock_fd) {
    struct sockaddr_storage ss;
    socklen_t len = sizeof(ss);

    assert(sock_fd > 0);

    getsockname(sock_fd, (struct sockaddr*)&ss,  &len);
    if ( ((struct sockaddr *)&ss)->sa_family == AF_INET ) {
        return ntohs((((struct sockaddr_in*)&ss)->sin_port));
    } else {
        return ntohs((((struct sockaddr_in6*)&ss)->sin6_port));
    }
}



static int serveTest(BIO *ctrl, struct server_global_t *globals) {

    struct info_t *curr_test;


    struct sockopt_t sockopts = {};
    sockopts.socktype = SOCK_DGRAM;
    sockopts.protocol = IPPROTO_UDP;
    sockopts.reuse_addr = 1;


    /* Read the hello and check we are compatible */
    Log(LOG_DEBUG, "Waiting for HELLO message");
    if ( read_control_hello(AMP_TEST_SRV6, ctrl, (void**)&globals,
                parse_hello) < 0 ) {
        Log(LOG_DEBUG, "HELLO error");
    }

    Log(LOG_DEBUG, "Recieved HELLO message %ld", globals->shared.info_count);
    for (int i = 0; i < globals->shared.info_count; i++){

        curr_test = &globals->shared.info[i];

        printf("probe[%d] %d %d %d\n", 
            i,
            curr_test->magic.magic, 
            curr_test->magic.global_index,
            curr_test->magic.target_index);
    }

    

    //start a listening socket
    struct socket_t sock;

    /* If test port has been manually set, only try that port. If it is
     * still the default, try a few ports till we hopefully find a free one.
     */
    // if ( options->tport == DEFAULT_TEST_PORT ) {
    //     portmax = MAX_TEST_PORT;
    // } else {
    //     portmax = options->tport;
    // }

    int res;
    int tport = DEFAULT_TEST_PORT;

    sockopts.sourcev6 = get_numeric_address("::", NULL);

    Log(LOG_DEBUG, "Starting test socket");
    do {
        res = start_listening(&sock, tport, &sockopts);
    } while ( res == EADDRINUSE && tport++ < MAX_TEST_PORT );

    if ( res != 0 ) {
        Log(LOG_WARNING, "Failed to start listening for test traffic");
    }

    if (sock.socket6 < 0) {
        printf("scok didnt open\n");

    }
    int on = 1;
    if ( setsockopt(sock.socket6, IPPROTO_IPV6, IPV6_RECVRTHDR,
            &on, sizeof(on)) < 0) {
        Log(LOG_WARNING, "Could not set IPv6 RECVHDR");
    }


    if ( setsockopt(sock.socket6, IPPROTO_IPV6, IPV6_RECVHOPLIMIT,
            &on, sizeof(on)) < 0) {
        Log(LOG_WARNING, "Could not set IPV6_RECVHOPLIMIT");
    }

    //reply to ctrl socket with port number
    uint16_t port = getSocketPort(sock.socket6);
    send_control_ready(AMP_TEST_THROUGHPUT, ctrl, port);
    Log(LOG_DEBUG, "Waiting for probes on test socket, port:%d", port);




    //TODO start event loop
    // do {
        
    //     test_sock = accept(sock.socket6, NULL, NULL);
    // } while (test_sock == -1 && errno == EINTR ); /* Repeat if interrupted */


    globals->shared.base = event_base_new();
    globals->shared.outstanding = globals->shared.info_count;

    /* catch a SIGINT and end the test early */
    struct event * signal_int = event_new(globals->shared.base, SIGINT,
            EV_SIGNAL | EV_PERSIST, interrupt_test, globals->shared.base);
    event_add(signal_int, NULL);

    /* set up callbacks for receiving packets */
    struct event *socket6 = event_new(globals->shared.base, sock.socket6,
            EV_READ|EV_PERSIST, receive_probe_callback, &globals->shared);
    event_add(socket6, NULL);


    struct event *losstimer = event_new(globals->shared.base, -1, 0,
            halt_test, &globals->shared);
    struct timeval timeout;
    timeout.tv_sec = LOSS_TIMEOUT;
    timeout.tv_usec = 0;
    event_add(losstimer, &timeout);

    event_base_dispatch(globals->shared.base);

    //return from event loop


    Log(LOG_DEBUG, "Finished %ld tests", 
            globals->shared.info_count - globals->shared.outstanding);

    //build items for each test, maybe could build them earlier?
    Amplet2__Icmp__Goodbye goodbye = AMPLET2__ICMP__GOODBYE__INIT;
    goodbye.n_results = globals->shared.info_count;
    goodbye.results = calloc(
            sizeof(*goodbye.results),
            goodbye.n_results);

    for (int i = 0; i < globals->shared.info_count; i++){

        goodbye.results[i] = malloc(sizeof(*goodbye.results[i]));
        Amplet2__Icmp__Result *curr_result = goodbye.results[i];


        curr_test = &globals->shared.info[i];

        amplet2__icmp__result__init(curr_result);

        curr_result->has_ttl = 1;
        curr_result->ttl = curr_test->ttl;
        curr_result->has_was_recieved = 1;
        curr_result->was_recieved = curr_test->reply;
        curr_result->n_path = 0;
        curr_result->path = NULL;
        //paths doesnt matter on this end, the client can work that out


        printf("Test[%d]", i);

        if ( curr_test->reply != 1 ) {
            //test was not responded to,
            //will still need to tell amp about this 
            printf(" MISSING\n");
            continue;
        }
        printf(" HOPLIM:%d\n", curr_test->ttl);
    }

    ProtobufCBinaryData *data = malloc(sizeof(ProtobufCBinaryData));
    data->len = amplet2__icmp__goodbye__get_packed_size(&goodbye);
    data->data = malloc(data->len);
    amplet2__icmp__goodbye__pack(&goodbye, data->data);

    /* send result to the client for reporting */
    if ( send_control_result(AMP_TEST_SRV6, ctrl, data) < 0 ) {
        
        return -1;
    }


    Log(LOG_DEBUG, "Ending test gracfully");

    return 0;
}



void run_srv6_server(
        __attribute__((unused))int argc, 
        __attribute__((unused))char *argv[],
        BIO *ctrl) {


    Log(LOG_DEBUG, "Starting SRv6 server");

    struct server_global_t globals = {};
    int port = DEFAULT_CONTROL_PORT;
    uint16_t portmax = MAX_CONTROL_PORT;
    struct sockopt_t sockopts = {};
    sockopts.socktype = SOCK_STREAM;
    sockopts.protocol = IPPROTO_TCP;
    sockopts.reuse_addr = 1;

    if ( !ctrl ) {
        /* The server was started standalone, wait for a control connection */

        sockopts.sourcev6 = get_numeric_address("::", NULL);

        /*
         * listen_control_server() will close the ports afterwards and unset
         * the address family that wasn't used for the control connection,
         * so only the active family gets used for the test traffic.
         */
        Log(LOG_DEBUG, "SRv6 server trying to listen on port %d", port);
        if ( (ctrl=listen_control_server(port, portmax, &sockopts)) == NULL ) {
            Log(LOG_WARNING, "Failed to establish control connection");
            return;
        }
    }

    serveTest(ctrl, &globals);
    //build results and return them
    return;

}