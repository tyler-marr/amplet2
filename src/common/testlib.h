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

#ifndef _COMMON_TESTLIB_H
#define _COMMON_TESTLIB_H

#include <stdint.h>
#include <netdb.h>
#include <sys/time.h>
#include <google/protobuf-c/protobuf-c.h>
#include <netinet/in.h>


/*
 * maximum length of a string in a report - the python code uses one byte
 * to determine how much to read from the buffer
 */
#define MAX_STRING_FIELD 255

/* minimum time in usec allowed between sending test packets */
#define MIN_INTER_PACKET_DELAY 100

#define DEFAULT_DSCP_VALUE 0

/* max number of attempts to make when retrying control connections */
#define MAX_CONNECT_ATTEMPTS 3
/* time in seconds to wait between attempts to establish control connects */
#define CONTROL_CONNECT_DELAY 2

#define US_FROM_US(x) ((x) % 1000000)
#define S_FROM_US(x)  ((int)((x)/1000000))
#define DIFF_TV_US(tva, tvb) ( \
        (int64_t) ( (((tva).tv_sec - (tvb).tv_sec) * 1000000) + \
            ((tva).tv_usec - (tvb).tv_usec) ) \
        )

/* maximum value of fd that will track packet sent counts (for TX timestamps) */
#define MAX_TX_TIMESTAMP_FD 64

/*
 * Structure combining the ipv4 and ipv6 network sockets so that they can be
 * passed around and operated on together as a single item.
 */
struct socket_t {
    int socket;                 /* ipv4 socket, if available */
    int socket6;                /* ipv6 socket, if available */
};

/* Structure representing the SO_TIMESTAMPING return value within CMSG. */
struct timestamping_t {
    struct timespec software;   /* software timestamp, if avaliabe */
    struct timespec deprecated; /* deprecated */
    struct timespec hardware;   /* hardware timestamp, if avaliabe */
};

/* 
 * Structure representing the SRv6 header
 * should be defined somewhere but this works for now, TODO
 */
struct ipv6_sr_hdr {
        uint8_t    nexthdr;
        uint8_t    hdrlen;
        uint8_t    type;
        uint8_t    segments_left;
        uint8_t    first_segment;
        uint8_t    flag_1;
        uint8_t    flag_2;
        uint8_t    reserved;

        /*
         * when allocating this struct, leave enough room on the end for 
         * struct in6_addr[first_segment-1]
         * ie malloc(sizeof(struct ipv6_sr_hdr)+
         *     ((first_segment-1)*sizeof(struct in6_addr)))
         */
        struct in6_addr segments[0];
};

void set_proc_name(char *testname);
void free_duped_environ(void);
int unblock_signals(void);
int wait_for_data(struct socket_t *sockets, int *maxwait);
int get_packet(struct socket_t *sockets, char *buf, int buflen,
	struct sockaddr *saddr, int *timeout, struct timeval *now);
int get_SRH_packet(struct socket_t *sockets, char *buf, int buflen,
        struct ipv6_sr_hdr **srh, int *timeout, struct timeval *now,
        int *hoplimit);
int delay_send_packet(int sock, char *packet, int size, struct addrinfo *dest,
        uint32_t inter_packet_delay, struct timeval *sent);
char *address_to_name(struct addrinfo *address);
int compare_addresses(const struct sockaddr *a,
        const struct sockaddr *b, int len);
struct addrinfo *get_numeric_address(char *interface, char *port);
int bind_socket_to_device(int sock, char *device);
int bind_sockets_to_device(struct socket_t *sockets, char *device);
int bind_socket_to_address(int sock, struct addrinfo *address);
int bind_sockets_to_address(struct socket_t *sockets,
        struct addrinfo *sourcev4, struct addrinfo *sourcev6);
int set_default_socket_options(struct socket_t *sockets);
int set_dscp_socket_options(struct socket_t *sockets, uint8_t dscp);
int check_exists(char *path, int strict);
int copy_address_to_protobuf(ProtobufCBinaryData *dst,
        const struct addrinfo *src);
char *parse_optional_argument(char *argv[]);
#endif
