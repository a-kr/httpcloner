#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "sniff.h"
#include "pktheaders.h"

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

    struct pcap_stat pcapstat_prev;
    struct pcap_stat pcapstat_cur;
    struct pcap_stat pcapstat_delta;

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
                pcap_stats(descr, &pcapstat_cur);
                pcapstat_delta.ps_recv = pcapstat_cur.ps_recv - pcapstat_prev.ps_recv;
                pcapstat_delta.ps_drop = pcapstat_cur.ps_drop - pcapstat_prev.ps_drop;
                pcapstat_prev = pcapstat_cur;
                ss.metrics_handler(count_ok, count_to, count_err, parse_result_ctrs, &pcapstat_delta);
            }
            count_ok = 0;
            count_to = 0;
            count_err = 0;
            clear_and_report_parse_result_ctrs(parse_result_ctrs);
        }
        count_ok++;
    }
}


void sniffing_callback(u_char *user, const struct pcap_pkthdr *header, const u_char *data) {
    struct SniffSettings *ss = (struct SniffSettings *)user;
    pcap_t *descr = ss->descr;

    static int count_ok = 0;
    static int count_to = 0;
    static int count_err = 0;

    static long lasttime = 0;

    static int parse_result_ctrs[PARSE_N_RESULTS] = {0,0,0,0,0,0};

    char *pkt_payload;
    int payload_len;
    u_int ack;
    u_int seq;

    static struct pcap_stat pcapstat_prev;
    static struct pcap_stat pcapstat_cur;
    static struct pcap_stat pcapstat_delta;

    //clear_and_report_parse_result_ctrs(parse_result_ctrs);


    int pr = parse_packet(data, &pkt_payload, &ack, &seq, &payload_len);
    parse_result_ctrs[pr]++;
    if (pr == PARSE_OK && ss->pkt_handler) {
        if (pkt_payload - (char *)data + payload_len > header->caplen) {
            if (header->len > header->caplen) {
                printf("Got a frame of size %d truncated to %d\n", header->len, header->caplen);
            }
            payload_len = header->caplen - (pkt_payload - (char *)data);
        }
        ss->pkt_handler(pkt_payload, payload_len, seq, ack, header->ts);
    }

    long t = header->ts.tv_sec;
    if (t != lasttime) {
        lasttime = t;
        if (ss->metrics_handler) {
            pcap_stats(descr, &pcapstat_cur);
            pcapstat_delta.ps_recv = pcapstat_cur.ps_recv - pcapstat_prev.ps_recv;
            pcapstat_delta.ps_drop = pcapstat_cur.ps_drop - pcapstat_prev.ps_drop;
            pcapstat_prev = pcapstat_cur;
            ss->metrics_handler(count_ok, count_to, count_err, parse_result_ctrs, &pcapstat_delta);
        }
        count_ok = 0;
        count_to = 0;
        count_err = 0;
        clear_and_report_parse_result_ctrs(parse_result_ctrs);
    }
    count_ok++;
}

void start_sniffing_loop(struct SniffSettings ss) {
    pcap_t *descr = setup_capture(ss.device, ss.filter);
    ss.descr = descr;
    pcap_loop(descr, -1, sniffing_callback, (u_char *)&ss);
}

inline int parse_packet(const u_char *packet, char **payload, u_int *ack, u_int *seq, int *payload_len) {
    struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
    const struct sniff_ip *ip;              /* The IP header */
    const struct sniff_tcp *tcp;            /* The TCP header */

    int size_ip;
    int size_tcp;
    int size_payload;
    
    /* define ethernet header */
    ethernet = (struct sniff_ethernet*)(packet);

    if (ntohs(ethernet->ether_type) != ETHERTYPE_IP) {
        return PARSE_WRONG_ETHERTYPE;
    }
    
    /* define/compute ip header offset */
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        return PARSE_BROKEN_IP_HEADER;
    }
    
    /* determine protocol */    
    if (ip->ip_p != IPPROTO_TCP) {
        return PARSE_WRONG_IPPROTO;
    }
    
    /*
     *  OK, this packet is TCP.
     */
    
    /* define/compute tcp header offset */
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        return PARSE_BROKEN_TCP_HEADER;
    }
    
    /* define/compute tcp payload (segment) offset */
    *payload = (char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    
    /* compute tcp payload (segment) size */
    *payload_len = ntohs(ip->ip_len) - (size_ip + size_tcp);
    *ack = tcp->th_ack;
    *seq = tcp->th_seq;

    if (*payload_len <= 0) {
        return PARSE_EMPTY_PAYLOAD;
    }
    return PARSE_OK;
}
