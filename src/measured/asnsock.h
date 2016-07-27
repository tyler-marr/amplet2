#ifndef _MEASURED_ASNSOCK_H
#define _MEASURED_ASNSOCK_H

#include <time.h>
#include <pthread.h>
#include <libwandevent.h>

#include "iptrie.h"
#include "asn.h"

/*
 * Ideally the cache could refresh individual items and expunge those
 * that haven't been used for a while. In the meantime, lets just empty
 * the whole cache and start again every 24 hours + 0-60 minutes.
 */
#define MIN_ASN_CACHE_REFRESH 86400
#define MAX_ASN_CACHE_REFRESH_OFFSET 3600

void asn_socket_event_callback(
        __attribute__((unused))wand_event_handler_t *ev_hdl, int eventfd,
        void *data, __attribute__((unused))enum wand_eventtype_t ev);

struct amp_asn_info* initialise_asn_info(void);
void amp_asn_info_delete(struct amp_asn_info *info);
#endif
