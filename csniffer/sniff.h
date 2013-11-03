#ifndef SNIFF_H
#define SNIFF_H

#include <pcap.h>
#include <time.h>
#include "limits.h"

typedef void (*sniffed_pkt_handler_fn)(char *payload, int len, u_int seq, u_int ack, struct timeval ts);
typedef void (*sniff_metrics_handler_fn)(int count_ok, int count_to, int count_err, int *parse_result_ctrs);

struct SniffSettings {
    const char *device;
    const char *filter;
    sniff_metrics_handler_fn metrics_handler;
    sniffed_pkt_handler_fn pkt_handler;
};

void start_sniffing(struct SniffSettings ss);
void clear_and_report_parse_result_ctrs(int *parse_result_ctrs);


#endif
