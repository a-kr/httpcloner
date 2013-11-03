#ifndef PKTPARSE_H
#define PKTPARSE_H

#include <pcap.h>

int parse_packet(const u_char *packet, char **payload, u_int *ack, u_int *seq, int *payload_len);

#define PARSE_OK 0
#define PARSE_BROKEN_IP_HEADER 1
#define PARSE_EMPTY_PAYLOAD 2
#define PARSE_WRONG_ETHERTYPE 3
#define PARSE_WRONG_IPPROTO 4
#define PARSE_BROKEN_TCP_HEADER 5

#define PARSE_N_RESULTS 6

#endif
