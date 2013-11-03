#include <pcap.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <thread>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <string.h>

#include "pktparse.h"
#include "sniff.h"
#include "requestasm.h"
#include "options.h"
#include "statsd.h"

// one per thread, to avoid contention
StatsClient statsd_sniff;
StatsClient statsd_rasm;

void sniff_metrics_handler(int count_ok, int count_to, int count_err, int *parse_result_ctrs) {
    double la[3];
    getloadavg(la, 3);
    fprintf(stderr, "Packets per second: %d, with payload: %d, timeouts %d, errors %d. load average %.2lf\n", count_ok, parse_result_ctrs[PARSE_OK], count_to, count_err, la[0]);
    statsd_sniff.start_message();
    statsd_sniff.incr("packets", count_ok);
    statsd_sniff.gauge("la", la[0]);
    statsd_sniff.finish_message();
}

void rasm_metrics_handler(int real_rps, int output_rps, int write_errors, int truncated_messages) {
    fprintf(stderr, "Real RPS %d, Output RPS %d, %d write errors, %d truncated\n", real_rps, output_rps, write_errors, truncated_messages);
    statsd_rasm.start_message();
    statsd_rasm.incr("real", real_rps);
    statsd_rasm.incr("output", output_rps);
    statsd_rasm.incr("truncated", truncated_messages);
    statsd_rasm.finish_message();
}

int connect_to_unix_dgram_socket(char *filename) {
    struct sockaddr_un server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sun_family = AF_UNIX;
    strncpy(server_addr.sun_path, filename, 104);
    int fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd <= 0) {
        perror("socket"); exit(1);
    }
    if (connect(fd, (struct sockaddr *) &server_addr, sizeof(server_addr)) != 0) {
        perror("connect"); exit(1);
    }
    return fd;
}

void setup_unix_sockets(struct RasmSettings *rs) {
    rs->pool_size = 1;
    if (options[REPLAY].count() == 0) {
        fprintf(stderr, "No replay socket was specified\n");
        rs->pool_size = 0;
        return;
    }
    if (options[REPLAYCOUNT].count() > 0) {
        rs->pool_size = atoi(options[REPLAYCOUNT].arg);
        if (rs->pool_size > MAX_POOL_SIZE) {
            rs->pool_size = MAX_POOL_SIZE;
        }
        fprintf(stderr, "Using pool of replay sockets of size %d\n", rs->pool_size);
    }
    for (int i = 0; i < rs->pool_size; i++) {
        char name[105];
        sprintf(name, "%s.%d", options[REPLAY].arg, i);
        fprintf(stderr, "Opening unix datagram socket %s for writing\n", name);
        rs->pool_fds[i] = connect_to_unix_dgram_socket(name);
    }
}

int main(int argc,char **argv)
{
    parse_options(argc, argv);

    if (options[STATSD].count() > 0) {
        std::string statsd_prefix = std::string("gor.") + gethostname() + std::string(".listen");
        if (statsd_sniff.connect(options[STATSD].arg, statsd_prefix) != 0) {
            fprintf(stderr, "(1) Could not setup statsd (%s) with prefix %s\n", options[STATSD].arg, statsd_prefix.c_str());
        } else {
            fprintf(stderr, "(1) Sending metrics to statsd (%s) with prefix %s\n", options[STATSD].arg, statsd_prefix.c_str());
        }
        if (statsd_rasm.connect(options[STATSD].arg, statsd_prefix) != 0) {
            fprintf(stderr, "(2) Could not setup statsd (%s) with prefix %s\n", options[STATSD].arg, statsd_prefix.c_str());
        } else {
            fprintf(stderr, "(2) Sending metrics to statsd (%s) with prefix %s\n", options[STATSD].arg, statsd_prefix.c_str());
        }
    }

    struct SniffSettings ss;
    ss.device = options[IFACE].arg;
    ss.filter = options[FILTER].arg;
    ss.metrics_handler = sniff_metrics_handler;
    ss.pkt_handler = rasm_packet_handler;

    struct RasmSettings rs;
    rs.rps_limit = (options[RPSLIMIT].count() > 0) ? atoi(options[RPSLIMIT].arg) : 0;
    rs.multiply = (options[MULTIPLY].count() > 0) ? atoi(options[MULTIPLY].arg) : 1;
    rs.metrics_handler = rasm_metrics_handler;
    rs.print = (options[PRINT].count() > 0) ? true : false;

    setup_unix_sockets(&rs);

    fprintf(stderr, "Listening on %s with filter %s\n", ss.device, ss.filter);
    fprintf(stderr, "Multiplier %d && rate limit %d\n", rs.multiply, rs.rps_limit);
    fprintf(stderr, "Sending metrics to statsd: %s\n", options[STATSD].arg);

    std::thread t_sniff(start_sniffing, ss);
    std::thread t_walk(rasm_monitor, rs);
    //t_walk.detach();

    t_sniff.join();
    return 0;
}
