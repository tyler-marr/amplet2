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
#include <assert.h>
#include <string.h>
#include <netinet/ip_icmp.h>
#include <stdlib.h>

#include "modules.h"
#include "testlib.h"
#include "tests.h"
#include "srv6.h"
#include "srv6.pb-c.h"


/* these are globals as we need to get them into the print callback */
struct info_t *info;
struct opt_t options;
unsigned int count;



/*
 * Check that the protocol buffer header has the same values as the options
 * the test tried to report.
 */
static void verify_header(struct opt_t *a, Amplet2__Srv6__Header *b) {
    assert(b->has_random);
    assert(b->has_packet_size);
    assert(a->random == b->random);
    assert(a->packet_size == b->packet_size);
}



/*
 * Check that the address in the result item matches the address that the
 * test tried to report.
 */
static void verify_address(struct addrinfo *a, Amplet2__Srv6__Header *b) {
    assert(b->has_family);
    assert(b->has_address);

    /* ensure family matches */
    assert(a->ai_family == b->family);

    /* ensure address length and address match */
    switch ( a->ai_family ) {
        case AF_INET:
            assert(b->address.len == sizeof(struct in_addr));
            assert(memcmp(b->address.data,
                        &((struct sockaddr_in*)a->ai_addr)->sin_addr,
                        sizeof(struct in_addr)) == 0);
            break;

        case AF_INET6:
            assert(b->address.len == sizeof(struct in6_addr));
            assert(memcmp(b->address.data,
                        &((struct sockaddr_in6*)a->ai_addr)->sin6_addr,
                        sizeof(struct in6_addr)) == 0);
            break;

        default: assert(0);
    };

    /* ensure the target names match */
    assert(strcmp(b->name, a->ai_canonname) == 0);
}



/*
 * Check that the RTT/TTL are present or not and have the correct values,
 * based on the same logic used when reporting.
 */
static void verify_response(struct info_t *a, Amplet2__Srv6__Item *b) {
    /* ensure rtt is only set if there was a valid response */
    if ( a->reply && a->time_sent.tv_sec > 0 &&
                (a->err_type == ICMP_REDIRECT ||
                 (a->err_type == 0 && a->err_code == 0)) ) {
        assert(b->has_rtt);
        assert(a->delay == b->rtt);
        assert(b->has_ttl);
        assert(a->ttl == b->ttl);
    } else {
        assert(!b->has_rtt);
        assert(!b->has_ttl);
    }
}



/*
 * Check that the srv6 error codes are present and set correctly.
 */
static void verify_errors(struct info_t *a, Amplet2__Srv6__Item *b) {
    if ( b->has_rtt || a->err_type > 0 ) {
        assert(b->has_err_type);
        assert(b->has_err_code);
        assert(a->err_type == b->err_type);
        assert(a->err_code == b->err_code);
    } else {
        assert(!b->has_err_type);
        assert(!b->has_err_code);
    }
}



/*
 * Verify that the message received and unpacked matches the original data
 * that was used to generate it.
 */
static void verify_message(amp_test_result_t *result) {
    Amplet2__Srv6__Report *msg;
    unsigned int i;

    assert(result);
    assert(result->data);

    /* unpack all the data */
    msg = amplet2__srv6__report__unpack(NULL, result->len, result->data);

    assert(msg);
    assert(msg->header);
    assert(msg->n_reports == count);

    verify_header(&options, msg->header);

    /* check each of the test results */
    for ( i = 0; i < msg->n_reports; i++ ) {
        verify_address(info[i].addr, msg->reports[i]);
        verify_response(&info[i], msg->reports[i]);
        verify_errors(&info[i], msg->reports[i]);
    }

    amplet2__srv6__report__free_unpacked(msg, NULL);
}



/*
 *
 */
static void build_info(struct info_t *item, struct addrinfo *addr,
                uint32_t delay, uint8_t reply, uint8_t type, uint8_t code,
                uint8_t ttl, uint32_t seconds) {

    item->addr = addr;
    item->delay = delay;
    item->reply = reply;
    item->err_type = type;
    item->err_code = code;
    item->ttl = ttl;
    item->time_sent.tv_sec = seconds;
    item->time_sent.tv_usec = 0;
}



/*
 *
 */
int main(void) {
    struct timeval start_time;
    struct addrinfo *addr = get_numeric_address("192.168.0.254", NULL);
    addr->ai_canonname = strdup("foo.bar.baz");

    count = 30;
    info = (struct info_t*)malloc(sizeof(struct info_t) * count);

    /* zero rtt, with and without srv6 errors */
    build_info(&info[0], addr, 0, 1, 0, 0, 0, 1);
    build_info(&info[1], addr, 0, 1, 3, 0, 1, 1);
    build_info(&info[2], addr, 0, 1, 3, 1, 2, 1);
    build_info(&info[0], addr, 0, 1, 0, 0, 0, 0);
    build_info(&info[1], addr, 0, 1, 3, 0, 1, 0);
    build_info(&info[2], addr, 0, 1, 3, 1, 2, 0);

    /* -1 rtt, with some sort of srv6 response */
    build_info(&info[3], addr, -1, 1, 11, 0, 3, 1);
    build_info(&info[4], addr, -1, 1, 11, 1, 4, 1);
    build_info(&info[5], addr, -1, 1, 12, 1, 5, 1);
    build_info(&info[6], addr, -1, 1, 12, 2, 6, 1);
    build_info(&info[3], addr, -1, 1, 11, 0, 3, 0);
    build_info(&info[4], addr, -1, 1, 11, 1, 4, 0);
    build_info(&info[5], addr, -1, 1, 12, 1, 5, 0);
    build_info(&info[6], addr, -1, 1, 12, 2, 6, 0);

    /* good rtt value, without srv6 errors */
    build_info(&info[7], addr, 1, 1, 0, 0, 7, 1);
    build_info(&info[8], addr, 2, 1, 0, 0, 8, 1);
    build_info(&info[9], addr, 4, 1, 0, 0, 9, 1);
    build_info(&info[10], addr, 100, 1, 0, 0, 10, 1);
    build_info(&info[11], addr, 1000, 1, 0, 0, 11, 1);
    build_info(&info[12], addr, 10000, 1, 0, 0, 12, 1);
    build_info(&info[13], addr, 100000, 1, 0, 0, 13, 1);
    build_info(&info[7], addr, 1, 1, 0, 0, 7, 0);
    build_info(&info[8], addr, 2, 1, 0, 0, 8, 0);
    build_info(&info[9], addr, 4, 1, 0, 0, 9, 0);
    build_info(&info[10], addr, 100, 1, 0, 0, 10, 0);
    build_info(&info[11], addr, 1000, 1, 0, 0, 11, 0);
    build_info(&info[12], addr, 10000, 1, 0, 0, 12, 0);
    build_info(&info[13], addr, 100000, 1, 0, 0, 13, 0);

    /* no reply, with various rtt values and srv6 errors */
    build_info(&info[14], addr, -1, 0, 0, 0, 14, 1);
    build_info(&info[15], addr, 0, 0, 0, 0, 15, 1);
    build_info(&info[16], addr, 1, 0, 0, 0, 16, 1);
    build_info(&info[17], addr, -1, 0, 3, 0, 17, 1);
    build_info(&info[18], addr, 0, 0, 3, 1, 18, 1);
    build_info(&info[19], addr, 1, 0, 3, 13, 19, 1);
    build_info(&info[20], addr, 100, 0, 0, 0, 20, 1);
    build_info(&info[21], addr, 10000, 0, 0, 0, 21, 1);
    build_info(&info[14], addr, -1, 0, 0, 0, 14, 0);
    build_info(&info[15], addr, 0, 0, 0, 0, 15, 0);
    build_info(&info[16], addr, 1, 0, 0, 0, 16, 0);
    build_info(&info[17], addr, -1, 0, 3, 0, 17, 0);
    build_info(&info[18], addr, 0, 0, 3, 1, 18, 0);
    build_info(&info[19], addr, 1, 0, 3, 13, 19, 0);
    build_info(&info[20], addr, 100, 0, 0, 0, 20, 0);
    build_info(&info[21], addr, 10000, 0, 0, 0, 21, 0);

    /* good rtt value with redirect errors */
    build_info(&info[22], addr, 0, 1, 5, 0, 22, 1);
    build_info(&info[23], addr, 100, 1, 5, 1, 23, 1);
    build_info(&info[24], addr, 100000, 1, 5, 2, 24, 1);
    build_info(&info[25], addr, 100000, 1, 5, 3, 25, 1);
    build_info(&info[26], addr, 0, 1, 5, 0, 22, 0);
    build_info(&info[27], addr, 100, 1, 5, 1, 23, 0);
    build_info(&info[28], addr, 100000, 1, 5, 2, 24, 0);
    build_info(&info[29], addr, 100000, 1, 5, 3, 25, 0);

    /* try some different combinations of header options */
    options.packet_size = 84;
    options.random = 0;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    options.packet_size = 0;
    options.random = 0;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    options.packet_size = 1500;
    options.random = 0;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    options.packet_size = 9000;
    options.random = 0;
    verify_message(amp_test_report_results(&start_time, count, info, &options));
    options.random = 1;
    verify_message(amp_test_report_results(&start_time, count, info, &options));

    free(info);
    freeaddrinfo(addr);
    return 0;
}
