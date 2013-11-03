#ifndef SNIFF_H
#define SNIFF_H

#include <pcap.h>
#include <time.h>
#include "limits.h"

int parse_packet(const u_char *packet, char **payload, u_int *ack, u_int *seq, int *payload_len);

#define PARSE_OK 0
#define PARSE_BROKEN_IP_HEADER 1
#define PARSE_EMPTY_PAYLOAD 2
#define PARSE_WRONG_ETHERTYPE 3
#define PARSE_WRONG_IPPROTO 4
#define PARSE_BROKEN_TCP_HEADER 5

#define PARSE_N_RESULTS 6

typedef void (*sniffed_pkt_handler_fn)(char *payload, int len, u_int seq, u_int ack, struct timeval ts);
typedef void (*sniff_metrics_handler_fn)(int count_ok, int count_to, int count_err, int *parse_result_ctrs, struct pcap_stat *pcapstat);

struct SniffSettings {
    const char *device;
    const char *filter;
    sniff_metrics_handler_fn metrics_handler;
    sniffed_pkt_handler_fn pkt_handler;
};

void start_sniffing(struct SniffSettings ss);
void clear_and_report_parse_result_ctrs(int *parse_result_ctrs);


#endif
