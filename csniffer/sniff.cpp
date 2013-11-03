#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sniff.h"
#include "pktparse.h"

pcap_t *setup_capture(const char *device, const char *filter) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* descr;
    struct bpf_program fp;        /* to hold compiled program */

    memset(errbuf, 0, PCAP_ERRBUF_SIZE);

    // Now, open device for sniffing
    descr = pcap_open_live(device, CAPTURE_SIZE, 1, 10, errbuf);
    if(descr == NULL) {
        fprintf(stderr, "pcap_open_live() failed due to [%s]\n", errbuf);
        exit(1);
    }

    // Compile the filter expression
    if(pcap_compile(descr, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "\npcap_compile() failed\n");
        exit(1);
    }

    // Set the filter compiled above

    if(pcap_setfilter(descr, &fp) == -1) {
        fprintf(stderr, "\npcap_setfilter() failed\n");
        exit(1);
    }

    return descr;
}


void clear_and_report_parse_result_ctrs(int *parse_result_ctrs) {
    int i;
    for (i = 0; i < PARSE_N_RESULTS; i++) {
        /*
        int v = parse_result_ctrs[i];
        switch(i) {
            case 0: printf("OK: %d ", v); break;
            case 1: printf("br.IP: %d ", v); break;
            case 2: printf("empty: %d ", v); break;
            case 3: printf("wr.ET: %d ", v); break;
            case 4: printf("wr.IPP: %d ", v); break;
            case 5: printf("br.TCP: %d ", v); break;
        }
        */
        parse_result_ctrs[i] = 0;
    }
    //printf("\n");
}

void start_sniffing(struct SniffSettings ss) {
    pcap_t *descr = setup_capture(ss.device, ss.filter);
    struct pcap_pkthdr *header;
    const u_char *data;

    int count_ok = 0;
    int count_to = 0;
    int count_err = 0;

    long lasttime = 0;

    int parse_result_ctrs[PARSE_N_RESULTS];

    char *pkt_payload;
    int payload_len;
    u_int ack;
    u_int seq;

    clear_and_report_parse_result_ctrs(parse_result_ctrs);

    while (1) {
        int r = pcap_next_ex(descr, &header, &data);
        if (r == 0) {
            count_to++; continue;
        } else if (r == -1) {
            count_err == -1; continue;
        }

        int pr = parse_packet(data, &pkt_payload, &ack, &seq, &payload_len);
        parse_result_ctrs[pr]++;
        if (pr == PARSE_OK && ss.pkt_handler) {
            if (pkt_payload - (char *)data + payload_len > header->caplen) {
                if (header->len > header->caplen) {
                    printf("Got a frame of size %d truncated to %d\n", header->len, header->caplen);
                }
                payload_len = header->caplen - (pkt_payload - (char *)data);
            }
            ss.pkt_handler(pkt_payload, payload_len, seq, ack, header->ts);
        }

        long t = header->ts.tv_sec;
        if (t != lasttime) {
            lasttime = t;
            if (ss.metrics_handler) {
                ss.metrics_handler(count_ok, count_to, count_err, parse_result_ctrs);
            }
            count_ok = 0;
            count_to = 0;
            count_err = 0;
            clear_and_report_parse_result_ctrs(parse_result_ctrs);
        }
        count_ok++;
    }
}

