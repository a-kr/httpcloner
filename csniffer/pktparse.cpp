#include "pktparse.h"
#include "pktheaders.h"


int parse_packet(const u_char *packet, char **payload, u_int *ack, u_int *seq, int *payload_len) {
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
