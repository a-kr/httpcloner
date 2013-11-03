#ifndef REQUESTASM_H
#define REQUESTASM_H

#include <time.h>
#include <stdint.h>
#include "limits.h"

typedef unsigned int u_int;

// A TCP segment
struct Packet {
    u_int seq;
    int len;
    bool used;
    char payload[1];
};



// A message (continuous sequence of TCP segments sent by one side)
class Message {
public:
    u_int ack;
    uint64_t ms_since_epoch;
    int n_packets;
    int total_len;
    struct Packet *packets[MAX_PACKETS_PER_MSG];
    bool truncated;

    Message() {
        ack = 0;
        n_packets = 0;
        total_len = 0;
        ms_since_epoch = 0;
        truncated = false;
    }
};


typedef void (*rasm_metrics_handler_fn)(int output_rps_factual, int output_rps_written, int write_errors, int truncated_messages);


struct RasmSettings {
    int rps_limit;
    int multiply;
    rasm_metrics_handler_fn metrics_handler;
    bool print;
    int pool_size;
    int pool_fds[MAX_POOL_SIZE];
};


void rasm_packet_handler(char *payload, int len, u_int seq, u_int ack, struct timeval ts);
void rasm_monitor(struct RasmSettings settings);


#endif
