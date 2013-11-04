/*
 * Collecting sniffed packets into messages and sending them via unix sockets happens here.
 * 
*/
#include <stdlib.h>
#include <stdio.h>
#include <unordered_map>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <chrono>
#include <string.h>
#include <sys/time.h>
#include <sys/prctl.h>
#include <sys/select.h>
#include <fcntl.h>
#include "requestasm.h"
#include "queues.h"

// Maps TCP ack numbers to messages. Message = 1 or more packets.
// Using ack number as a key works because while the client is sending the request,
// the server is silent (so client's TCP segments acknowledge the same server sequence number).
std::unordered_map<u_int, Message*> message_map;

// message_map is accessed from two threads, so we must take care of synchronization.
// Could have tried to use a more fine-grained locking, or lock-free thread-safe map or whatever,
// but a simple mutex works well enough (at our workloads anyway).
std::mutex message_map_mutex;

SwitchingQueue<struct Packet *> new_queue;
SwitchingQueue<Message *> completed_queue;

uint64_t ms_from_timeval(struct timeval *ts) {
    return (uint64_t)ts->tv_sec * 1000 + (uint64_t)ts->tv_usec / 1000;
}


/* We just sniffed one packet. Find the message it belongs to and store it into message_map.
 * 
 * This function executes in the sniffing thread.
*/
void rasm_packet_handler(char *payload, int len, u_int seq, u_int ack, struct timeval ts) {
    struct Packet *pkt = (struct Packet *)malloc(sizeof(struct Packet) + len);
    pkt->len = len;
    pkt->ack = ack;
    pkt->ms_since_epoch = ms_from_timeval(&ts);
    pkt->seq = seq;
    pkt->used = false;
    memcpy(pkt->payload, payload, len);

    new_queue.put(pkt);
}

inline void update_message_map(struct Packet *pkt) {
    Message *msg = message_map[pkt->ack];
    if (!msg) {
        msg = new Message();
    }
    msg->ms_since_epoch = pkt->ms_since_epoch;
    msg->ack = pkt->ack;

    if (msg->n_packets < MAX_PACKETS_PER_MSG - 1) {
        msg->packets[msg->n_packets] = pkt;
        msg->n_packets++;
        msg->total_len += pkt->len;
    } else {
        msg->truncated = true;
    }
    message_map[pkt->ack] = msg;
}

void rasm_free_message(Message *msg) {
    for (int i = 0; i < msg->n_packets; i++) {
        free(msg->packets[i]);
    }
    delete msg;
}


/* --- message reassembling routines follow --- */

/* In theory, we should assemble packets by ordering them
 * by ascending sequence numbers... */

/* find packet with min(seq) */
int find_min_unused_packet(Message *msg) {
    u_int min_seq = UINT32_MAX;
    int min_i = -1;
    for (int i = 0; i < msg->n_packets; i++) {
        if (msg->packets[i]->used) continue;
        if (msg->packets[i]->seq < min_seq) {
            min_seq = msg->packets[i]->seq;
            min_i = i;
        }
    }
    return min_i;
}


/* This function seems to contain a bug.
 * Anyway, it sometimes assembles messages backwards.
 * Turns out, just concatenating packets in sniff order works with
 * much less errors.
*/
void reasm_payload_smart(Message *msg, char *buf, int *payload_len) {
    char *cur = buf;
    int total_len = 0;
    int len;
    int min_i;

    for (int i = 0; i < msg->n_packets; i++) {
        msg->packets[i]->used = false;
    }

    while ((min_i = find_min_unused_packet(msg)) != -1) {
        len = msg->packets[min_i]->len;
        if (total_len + len >= PAYLOAD_MAX_BUFFER) {
            len = PAYLOAD_MAX_BUFFER - total_len;
        }
        msg->packets[min_i]->used = true;
        memcpy(cur, msg->packets[min_i]->payload, len);
        total_len += len;
        cur += len;
    }
    *payload_len = total_len;
}

/* To hell with reordering. Just concatenate packets as they were stored. */

void reasm_payload(Message *msg, char *buf, int *payload_len) {
    char *cur = buf;
    int total_len = 0;
    int len;
    int min_i;

    for (min_i = 0; min_i < msg->n_packets; min_i++) {
        len = msg->packets[min_i]->len;
        if (total_len + len >= PAYLOAD_MAX_BUFFER) {
            len = PAYLOAD_MAX_BUFFER - total_len;
        }
        msg->packets[min_i]->used = true;
        memcpy(cur, msg->packets[min_i]->payload, len);
        total_len += len;
        cur += len;
    }
    *payload_len = total_len;
}

/* Send payload to a socket (and optionally to stdout */
int write_payload(Message *msg, int fd, bool print_it) {
    char buf[PAYLOAD_MAX_BUFFER];
    char *payload;
    int payload_len;
    if (msg->n_packets > 1) {
        payload = buf;
        reasm_payload(msg, buf, &payload_len);
    } else {
        // one-packet requests are very common and don't need reassembling.
        // So this is a fast path.
        payload = msg->packets[0]->payload;
        payload_len = msg->packets[0]->len;
    }

    int result = 0;
        if (fd) {
        ssize_t r = write(fd, payload, payload_len);
        if (r < 0) {
            result = -1;
            perror("write");
        }
    }

    if (print_it) {
        payload[payload_len] = '\0';
        printf("==============\n%s\n", payload);
    }

    return result;
}

/* Among several file descriptors, choose one ready for writing 
 * while respecting round-robin balancing as much as possible.
*/
int rr_select(fd_set socket_set, int maxfd, int *fds, int fd_count, int rr_index) {
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;
    fd_set ready_to_write_set = socket_set;
    int r = select(maxfd, NULL, &ready_to_write_set, NULL, &timeout);
    if (r < 0) {
        printf("select perror\n");
        perror("select");
        return -1;
    }
    if (r == 0) { // timed out
        printf("select timed out\n");
        return -1;
    }
    for (int i = 0; i < fd_count; i++) {
        rr_index = (rr_index + 1) % fd_count;
        int fd = fds[rr_index];
        if (!FD_ISSET(fd, &ready_to_write_set)) {
            continue;
        }
        return rr_index;
    }
    printf("no fds ready to write\n");
    return -1;
}

/* Read packets from new_queue and put into message_map.
 * Periodically check message_map for completed messages, remove them from map
 * and put into completed_queue.
 *
 * Completed message == message which was not updated (added new packets) in MESSAGE_TIMEOUT ms.
 *
 * This function runs in the reassembly thread and does not return.
*/
void rasm_monitor(struct RasmSettings settings) {
    long lasttime = 0;
    prctl(PR_SET_NAME, "cap rasm_monitor", 0, 0, 0);
    printf("rasm_monitor started\n");

    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);
    uint64_t oldest_packet = ms_from_timeval(&now_tv);

    while (1) {
        new_queue.wait();
        std::queue<struct Packet*> to_process;
        gettimeofday(&now_tv, NULL);
        uint64_t now_ms = ms_from_timeval(&now_tv);
        uint64_t collect_ms = now_ms - MESSAGE_TIMEOUT;

        // Join new packets
        new_queue.startwork();
        while (!new_queue.empty()) {
            struct Packet *p = new_queue.get();
            to_process.push(p);
        }
        new_queue.endwork();

        while (!to_process.empty()) {
            struct Packet *p = to_process.front();
            to_process.pop();
            update_message_map(p);
        }

        if (oldest_packet < collect_ms) {
            std::queue<Message*> to_process;
            uint64_t new_oldest = now_ms;
            // Scan for completed messages.
            // We should minimize locking duration as much as possible,
            // so we only move completed messages to `to_process` vector
            // for further processing.
            for (auto it = message_map.cbegin(); it != message_map.cend(); ) {
                uint64_t ms = it->second->ms_since_epoch;
                if (ms < collect_ms) {
                    to_process.push(it->second);
                    message_map.erase(it++);
                } else {
                    if (ms < new_oldest) {
                        new_oldest = ms;
                    }
                    ++it;
                }
            }
            oldest_packet = new_oldest;


            completed_queue.putmany(to_process);
        }

    }
}

/* Periodically check message_map for completed messages, remove them from map
 * and transmit via socket pool.
 *
 * Completed message == message which was not updated (added new packets) in MESSAGE_TIMEOUT ms.
 *
 * This function runs in the reassembly thread and does not return.
*/
void rasm_writer(struct RasmSettings settings) {
    std::chrono::milliseconds sleep_dur(MONITOR_PERIOD);
    long lasttime = 0;
    int output_rps_factual = 0;
    int output_rps_written = 0;
    int write_errors = 0;
    int truncated_messages = 0;
    prctl(PR_SET_NAME, "cap rasm_monitor", 0, 0, 0);
    printf("rasm_monitor started\n");

    int rr_index = 0;
    fd_set socket_set, ready_to_write_set;
    FD_ZERO(&socket_set);
    FD_ZERO(&ready_to_write_set);
    int maxfd = 0;

    for (int i = 0; i < settings.pool_size; i++) {
        int fd = settings.pool_fds[i];
        fcntl(fd, F_SETFL, O_NONBLOCK|O_ASYNC);
        FD_SET(fd, &socket_set);
        if (fd > maxfd) {
            maxfd = fd;
        }
    }

    while (1) {
        completed_queue.wait_for(sleep_dur);
        std::queue<Message*> to_process;
        struct timeval now_tv;
        gettimeofday(&now_tv, NULL);

        if (now_tv.tv_sec != lasttime) {
            lasttime = now_tv.tv_sec;
            if (settings.metrics_handler) {
                settings.metrics_handler(output_rps_factual, output_rps_written,
                     write_errors, truncated_messages);
            }
            output_rps_factual = 0;
            output_rps_written = 0;
            write_errors = 0;
            truncated_messages = 0;
        }

        completed_queue.startwork();
        while (!completed_queue.empty()) {
            Message *m = completed_queue.get();
            output_rps_factual++;
            to_process.push(m);
        }
        completed_queue.endwork();


        while (!to_process.empty()) {
            Message *msg = to_process.front();
            to_process.pop();
            for (int i = 0; i < settings.multiply; i++) {
                if (settings.rps_limit > 0 && output_rps_written >= settings.rps_limit) {
                    continue;
                }

                if ((msg->truncated) || (msg->total_len > PAYLOAD_MAX_BUFFER)) {
                    truncated_messages++;
                }

                int fd = 0;
                if (settings.pool_size) {
                    // choosing in round-robin fashion among ready-to-write sockets
                    rr_index = rr_select(
                        socket_set, maxfd + 1, settings.pool_fds, settings.pool_size, rr_index
                    );
                    if (rr_index == -1) {
                        write_errors++;
                    } else {
                        fd = settings.pool_fds[rr_index];
                    }
                }

                if (write_payload(msg, fd, settings.print) != 0) {
                    write_errors++;
                }
                output_rps_written++;
            }
            rasm_free_message(msg);
        }
    }
}
