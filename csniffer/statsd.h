#ifndef STATSD_H
#define STATSD_H

#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "utils.h"

#define MAX_STATSD_PREFIX 100
#define MAX_STATSD_MSGBUF 1024

class StatsClient {
private:
    int sock;
    struct sockaddr_in si_dest;
    char *msgbuf;
    char *msgcur;
    int msglen;
    std::string prefix;
public:
    StatsClient() {
        sock = 0; msgbuf = NULL;
    }

    int connect(const std::string addr, std::string prefix) {
        this->prefix = prefix;
        std::vector<std::string> parts = split(addr, ':');
        int port = atoi(parts[1].c_str());

        // create socket and check for errors
        if ((this->sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
            perror("Statsd: Could not create a socket.");
            this->sock = 0;
            return -1;
        }

        // inet_aton
        memset((void *)&this->si_dest, 0, sizeof(this->si_dest));
        this->si_dest.sin_family = AF_INET;
        this->si_dest.sin_port = htons(port);

        if (inet_aton(parts[0].c_str(), &this->si_dest.sin_addr) == 0) {
            perror("Statsd: inet_aton failed.");
            this->sock = 0;
            return -1;
        }
        return 0;
    }

    void start_message() {
        if (!this->sock) {
            return;
        }
        if (this->msgbuf) {
            free(this->msgbuf);
        }
        this->msgbuf = (char *)malloc(MAX_STATSD_MSGBUF);
        this->msgcur = this->msgbuf;
        this->msglen = 0;
    }

    void incr(std::string metric, double value) {
        int len;
        if (!this->sock || !this->msgbuf) {
            return;
        }
        len = sprintf(this->msgcur, "%s.%s:%f|c\n", this->prefix.c_str(), metric.c_str(), value);
        this->msgcur += len;
        this->msglen += len;
    }

    void gauge(std::string metric, double value) {
        int len;
        if (!this->sock || !this->msgbuf) {
            return;
        }
        len = sprintf(this->msgcur, "%s.%s:%f|g\n", this->prefix.c_str(), metric.c_str(), value);
        this->msgcur += len;
        this->msglen += len;
    }

    void finish_message() {
        if (!this->sock || !this->msgbuf) {
            return;
        }
        if (sendto(
                    this->sock, this->msgbuf, this->msglen, 0,
                    (const struct sockaddr *)&this->si_dest,
                    sizeof(this->si_dest)
                ) == -1) {
            perror("Statsd: sendto failed.");
        }
        free(this->msgbuf);
        this->msgbuf = NULL;
    }

};

#endif
